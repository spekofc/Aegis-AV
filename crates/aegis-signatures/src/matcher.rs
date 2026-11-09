//! Signature matching engine.

use crate::database::SignatureDatabase;
use crate::format::{PatternRecord, SignatureRecord};
use aegis_core::{
    AegisError, AegisResult, DetectionEngine, Disposition, PatternMatch, ScanContext, ScanResult,
    Sha256, SignatureMatch, ThreatType,
};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use sha2::Digest;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, trace};

/// Signature matcher using multiple detection engines.
pub struct SignatureMatcher {
    db: Arc<SignatureDatabase>,
    hash_index: Arc<HashIndex>,
    pattern_matcher: Arc<PatternMatcher>,
}

impl SignatureMatcher {
    pub fn new(db: Arc<SignatureDatabase>) -> Self {
        Self {
            hash_index: Arc::new(HashIndex::new()),
            pattern_matcher: Arc::new(PatternMatcher::new()),
            db,
        }
    }

    /// Reload matchers from database.
    pub async fn reload(&self) -> AegisResult<()> {
        // Load all hashes into hash index
        let signatures = self.db.get_all_signatures().await?;
        let mut hashes = Vec::new();
        for sig in &signatures {
            if let Some(hash) = sig.hash {
                hashes.push((hash, sig.id));
            }
        }
        self.hash_index.build(hashes);

        // Load all patterns into Aho-Corasick
        let patterns = self.db.get_all_patterns().await?;
        let mut ac_patterns = Vec::new();
        for pat in &patterns {
            ac_patterns.push((pat.pattern.clone(), pat.id));
        }
        self.pattern_matcher.build(ac_patterns);

        Ok(())
    }

    /// Match a file hash against signature database.
    pub async fn match_hash(&self, hash: &Sha256) -> AegisResult<Option<SignatureMatch>> {
        if let Some(sig_id) = self.hash_index.lookup(hash) {
            if let Some(sig) = self.db.get_signature(sig_id).await? {
                return Ok(Some(SignatureMatch {
                    id: sig.id,
                    hash: sig.hash,
                    sig_type: sig.sig_type as u8,
                    family: sig.family,
                    threat_type: sig.threat_type,
                    seAEGIS: sig.seAEGIS,
                    platforms: sig.platforms,
                    description: sig.description,
                    engine: DetectionEngine::Hash,
                }));
            }
        }
        Ok(None)
    }

    /// Match patterns in file data.
    pub async fn match_patterns(&self, data: &[u8]) -> AegisResult<Vec<PatternMatch>> {
        let matches = self.pattern_matcher.search(data);
        let mut results = Vec::new();

        for (pattern_id, offset) in matches {
            if let Some(pat) = self.db.get_pattern(pattern_id).await? {
                results.push(PatternMatch {
                    id: pat.id,
                    offset: offset as u64,
                    length: pat.pattern.len() as u32,
                    signature_id: pat.signature_id,
                });
            }
        }

        Ok(results)
    }

    /// Full scan with all engines.
    pub async fn scan(
        &self,
        data: &[u8],
        hash: &Sha256,
        ctx: &ScanContext,
    ) -> AegisResult<ScanResult> {
        // 1. Hash lookup (fastest)
        if let Some(hash_match) = self.match_hash(hash).await? {
            return Ok(ScanResult {
                disposition: aegis_core::Disposition::Malicious,
                threat_type: Some(hash_match.threat_type),
                threat_name: Some(hash_match.family.clone()),
                confidence: 1.0,
                engine: DetectionEngine::Hash,
                matched_ids: vec![hash_match.id],
                details: serde_json::json!({ "method": "hash" }),
                duration: std::time::Duration::from_millis(0),
            });
        }

        // 2. Pattern matching
        let pattern_matches = self.match_patterns(data).await?;
        if !pattern_matches.is_empty() {
            // Get the most severe match
            let mut max_seAEGIS = 0;
            let mut threat_type = ThreatType::Unknown;
            let mut family = String::new();
            let mut matched_ids = Vec::new();

            for pm in &pattern_matches {
                if let Some(sig) = self.db.get_signature(pm.signature_id).await? {
                    if sig.seAEGIS > max_seAEGIS {
                        max_seAEGIS = sig.seAEGIS;
                        threat_type = sig.threat_type;
                        family = sig.family.clone();
                    }
                    matched_ids.push(pm.signature_id);
                }
            }

            return Ok(ScanResult {
                disposition: if max_seAEGIS >= 3 {
                    aegis_core::Disposition::Malicious
                } else {
                    aegis_core::Disposition::Suspicious
                },
                threat_type: Some(threat_type),
                threat_name: if family.is_empty() {
                    None
                } else {
                    Some(family)
                },
                confidence: 0.9,
                engine: DetectionEngine::Pattern,
                matched_ids,
                details: serde_json::json!({
                    "method": "pattern",
                    "matches": pattern_matches.len()
                }),
                duration: std::time::Duration::from_millis(0),
            });
        }

        Ok(ScanResult {
            disposition: aegis_core::Disposition::Clean,
            threat_type: None,
            threat_name: None,
            confidence: 1.0,
            engine: DetectionEngine::Hash,
            matched_ids: Vec::new(),
            details: serde_json::json!({ "method": "none" }),
            duration: std::time::Duration::from_millis(0),
        })
    }
}

/// Hash index for O(1) hash lookups.
struct HashIndex {
    index: parking_lot::RwLock<HashMap<Sha256, u64>>,
}

impl HashIndex {
    fn new() -> Self {
        Self {
            index: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    fn build(&self, entries: Vec<(Sha256, u64)>) {
        let mut index = self.index.write();
        index.clear();
        index.reserve(entries.len());
        for (hash, id) in entries {
            index.insert(hash, id);
        }
    }

    fn lookup(&self, hash: &Sha256) -> Option<u64> {
        self.index.read().get(hash).copied()
    }
}

/// Pattern matcher using Aho-Corasick.
struct PatternMatcher {
    automaton: parking_lot::RwLock<Option<AhoCorasick>>,
    pattern_ids: parking_lot::RwLock<Vec<u64>>, // pattern_id -> signature_id
}

impl PatternMatcher {
    fn new() -> Self {
        Self {
            automaton: parking_lot::RwLock::new(None),
            pattern_ids: parking_lot::RwLock::new(Vec::new()),
        }
    }

    fn build(&self, patterns: Vec<(Vec<u8>, u64)>) {
        if patterns.is_empty() {
            *self.automaton.write() = None;
            *self.pattern_ids.write() = Vec::new();
            return;
        }

        let mut builder = AhoCorasickBuilder::new();
        builder.match_kind(MatchKind::Standard);
        builder.ascii_case_insensitive(false);

        let pattern_bytes: Vec<&[u8]> = patterns.iter().map(|(p, _)| p.as_slice()).collect();
        let automaton = builder.build(pattern_bytes).unwrap();

        let mut ids = self.pattern_ids.write();
        ids.clear();
        ids.extend(patterns.iter().map(|(_, id)| *id));

        *self.automaton.write() = Some(automaton);
    }

    fn search(&self, data: &[u8]) -> Vec<(u64, usize)> {
        let automaton = self.automaton.read();
        let ids = self.pattern_ids.read();
        let ids: &Vec<u64> = &*ids;
        let len = ids.len();

        if let Some(ac) = automaton.as_ref() {
            let mut results = Vec::new();
            for mat in ac.find_iter(data) {
                let pattern_idx = mat.pattern();
                let idx: usize = pattern_idx.as_usize();
                if idx < len {
                    results.push((ids[idx], mat.start()));
                }
            }
            results
        } else {
            Vec::new()
        }
    }
}

// Extension methods for SignatureDatabase
impl SignatureDatabase {
    async fn get_all_signatures(&self) -> AegisResult<Vec<SignatureRecord>> {
        let rows = sqlx::query("SELECT * FROM signatures ORDER BY id")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AegisError::Database(e))?;

        rows.into_iter().map(|r| self.row_to_signature(r)).collect()
    }

    async fn get_all_patterns(&self) -> AegisResult<Vec<PatternRecord>> {
        let rows = sqlx::query("SELECT * FROM patterns ORDER BY id")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AegisError::Database(e))?;

        rows.into_iter().map(|r| self.row_to_pattern(r)).collect()
    }

    pub async fn get_signature(&self, id: u64) -> AegisResult<Option<SignatureRecord>> {
        let row = sqlx::query("SELECT * FROM signatures WHERE id = ?")
            .bind(id as i64)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AegisError::Database(e))?;

        row.map(|r| self.row_to_signature(r)).transpose()
    }

    async fn get_pattern(&self, id: u64) -> AegisResult<Option<PatternRecord>> {
        let row = sqlx::query("SELECT * FROM patterns WHERE id = ?")
            .bind(id as i64)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AegisError::Database(e))?;

        row.map(|r| self.row_to_pattern(r)).transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::SignatureDatabase;
    use aegis_core::Sha256;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_hash_matching() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let key = [0xde; 32];

        let db = Arc::new(SignatureDatabase::create(&db_path, &key).await.unwrap());

        // Add hash signature
        let sig = crate::format::SignatureRecord {
            id: 0,
            hash: Some(Sha256([0xab; 32])),
            sig_type: crate::format::SignatureType::Hash,
            family: "TestTrojan".to_string(),
            threat_type: aegis_core::ThreatType::Trojan,
            seAEGIS: 4,
            platforms: crate::format::CURRENT_PLATFORM,
            min_engine_version: aegis_core::Version::new(0, 1, 0, 0),
            created_at: aegis_core::Timestamp::now(),
            updated_at: aegis_core::Timestamp::now(),
            description: "Test hash signature".to_string(),
            tags: vec![],
            metadata: serde_json::json!({}),
        };

        db.add_signature(sig).await.unwrap();

        let matcher = SignatureMatcher::new(db.clone());
        matcher.reload().await.unwrap();

        // Match
        let result = matcher.match_hash(&Sha256([0xab; 32])).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().family, "TestTrojan");

        // Non-existent
        let result = matcher.match_hash(&Sha256([0xcd; 32])).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_pattern_matching() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let key = [0xde; 32];

        let db = Arc::new(SignatureDatabase::create(&db_path, &key).await.unwrap());

        // Add pattern signature
        let sig = crate::format::SignatureRecord {
            id: 0,
            hash: None,
            sig_type: crate::format::SignatureType::Pattern,
            family: "TestWorm".to_string(),
            threat_type: aegis_core::ThreatType::Worm,
            seAEGIS: 3,
            platforms: crate::format::CURRENT_PLATFORM,
            min_engine_version: aegis_core::Version::new(0, 1, 0, 0),
            created_at: aegis_core::Timestamp::now(),
            updated_at: aegis_core::Timestamp::now(),
            description: "Test pattern signature".to_string(),
            tags: vec![],
            metadata: serde_json::json!({
                "patterns": [{
                    "pattern": "68656c6c6f20776f726c64", // "hello world" in hex
                    "description": "Hello world string",
                    "offset": null
                }]
            }),
        };

        let sig_id = db.add_signature(sig).await.unwrap();

        let matcher = SignatureMatcher::new(db.clone());
        matcher.reload().await.unwrap();

        // Search for pattern
        let data = b"this is a test hello world string";
        let matches = matcher.match_patterns(data).await.unwrap();
        assert!(!matches.is_empty());

        // Full scan
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        let hash = Sha256::from_slice(hasher.finalize().as_slice()).unwrap();
        let ctx = ScanContext {
            scan_id: uuid::Uuid::new_v7(uuid::Timestamp::from_unix(
                uuid::NoContext,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                0,
            )),
            initiator_pid: std::process::id(),
            initiator_name: "test".to_string(),
            trigger: aegis_core::ScanTrigger::Manual,
            priority: 128,
            deadline: None,
            metadata: serde_json::json!({}),
        };

        let result = matcher.scan(data, &hash, &ctx).await.unwrap();
        assert!(
            result.disposition == aegis_core::Disposition::Malicious
                || result.disposition == aegis_core::Disposition::Suspicious
        );
    }
}
