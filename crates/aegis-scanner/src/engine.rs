//! Main scanner engine.

use crate::heuristic::HeuristicEngine;
use crate::pe::PeAnalyzer;
use aegis_core::{
    AegisError, AegisResult, DetectionEngine, Disposition, ScanContext, ScanResult, ScanTrigger,
    ScannerStats, Sha256, SignatureMatch, ThreatType, Timestamp,
};
use aegis_signatures::{SignatureDatabase, SignatureMatcher};
use sha2::{Digest, Sha256 as Sha256Hasher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;
use tracing::{debug, info, trace, warn};
use uuid;
use walkdir::WalkDir;

/// Scanner configuration.
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub max_concurrent_scans: usize,
    pub scan_timeout_secs: u64,
    pub ml_threshold: f32,
    pub heuristic_level: u8,
    pub enable_ml: bool,
    pub max_file_size: u64,
    pub excluded_paths: Vec<PathBuf>,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_scans: 4,
            scan_timeout_secs: 300,
            ml_threshold: 0.5,
            heuristic_level: 2,
            enable_ml: false,
            max_file_size: 100 * 1024 * 1024,
            excluded_paths: vec![
                PathBuf::from("C:\\Windows"),
                PathBuf::from("C:\\Program Files"),
                PathBuf::from("C:\\Program Files (x86)"),
            ],
        }
    }
}

/// Scan statistics.
#[derive(Debug, Default, Clone)]
pub struct ScanStats {
    pub files_scanned: u64,
    pub detections: u64,
    pub bytes_scanned: u64,
    pub scan_errors: u64,
    pub avg_scan_time_ms: f64,
}

/// Main scanner engine orchestrating all detection layers.
pub struct ScannerEngine {
    config: ScannerConfig,
    sig_db: Arc<SignatureDatabase>,
    matcher: Arc<SignatureMatcher>,
    pe_analyzer: PeAnalyzer,
    heuristic: HeuristicEngine,
    semaphore: Arc<Semaphore>,
    stats: Arc<parking_lot::RwLock<ScanStats>>,
}

impl ScannerEngine {
    /// Create a new scanner engine.
    pub fn new(
        config: ScannerConfig,
        sig_db: Arc<SignatureDatabase>,
        matcher: Arc<SignatureMatcher>,
    ) -> AegisResult<Self> {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_scans));
        Ok(Self {
            config,
            sig_db,
            matcher,
            pe_analyzer: PeAnalyzer::new(),
            heuristic: HeuristicEngine::new(),
            semaphore,
            stats: Arc::new(parking_lot::RwLock::new(ScanStats::default())),
        })
    }

    /// Reload signature matchers from database.
    pub async fn reload_signatures(&self) -> AegisResult<()> {
        self.matcher.reload().await
    }

    /// Scan a single file.
    pub async fn scan_file(&self, path: &Path, _ctx: ScanContext) -> AegisResult<ScanResult> {
        let _permit = self
            .semaphore
            .acquire()
            .await
            .map_err(|_| AegisError::Internal("Semaphore closed".into()))?;

        let start = Instant::now();

        // Check file size
        let metadata = std::fs::metadata(path).map_err(|e| AegisError::Io(e))?;
        if metadata.len() > self.config.max_file_size {
            return Ok(ScanResult::skipped("File too large"));
        }

        // Read file data
        let data = std::fs::read(path).map_err(|e| AegisError::Io(e))?;

        // Hash lookup (fastest)
        let hash = {
            let mut hasher = Sha256Hasher::new();
            hasher.update(&data);
            let digest = hasher.finalize();
            Sha256::from_slice(digest.as_slice()).unwrap()
        };

        if let Some(hash_match) = self.matcher.match_hash(&hash).await? {
            return Ok(ScanResult {
                disposition: Disposition::Malicious,
                threat_type: Some(hash_match.threat_type),
                threat_name: Some(hash_match.family.clone()),
                confidence: 1.0,
                engine: DetectionEngine::Hash,
                matched_ids: vec![hash_match.id],
                details: serde_json::json!({ "method": "hash" }),
                duration: start.elapsed(),
            });
        }

        // Pattern matching
        let pattern_matches = self.matcher.match_patterns(&data).await?;
        if !pattern_matches.is_empty() {
            let mut max_seAEGIS = 0;
            let mut threat_type = ThreatType::Unknown;
            let mut family = String::new();
            let mut matched_ids = Vec::new();

            for pm in &pattern_matches {
                if let Some(sig) = self.sig_db.get_signature(pm.signature_id).await? {
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
                    Disposition::Malicious
                } else {
                    Disposition::Suspicious
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
                details: serde_json::json!({ "method": "pattern", "matches": pattern_matches.len() }),
                duration: start.elapsed(),
            });
        }

        // Heuristic analysis
        if let Some(heuristic_result) = self.heuristic.analyze(path, &ScanResult::clean()).await? {
            return Ok(heuristic_result);
        }

        // PE analysis (for Windows executables)
        if let Some(pe_result) = self.scan_pe(path).await? {
            return Ok(pe_result);
        }

        Ok(ScanResult::clean())
    }

    /// Scan a PE file.
    async fn scan_pe(&self, path: &Path) -> AegisResult<Option<ScanResult>> {
        let pe_info = match self.pe_analyzer.analyze(path).await {
            Ok(info) => info,
            Err(_) => return Ok(None), // Not a PE file, skip
        };
        if pe_info.is_pe {
            let mut suspicious_score = 0;
            // Check for suspicious imports
            for import in &pe_info.imports {
                if import.dll.to_lowercase() == "ntdll.dll" {
                    suspicious_score += 1;
                }
            }
            // Check for high entropy sections
            for section in &pe_info.sections {
                if section.entropy > 7.5 {
                    suspicious_score += 2;
                }
            }

            if suspicious_score >= 3 {
                return Ok(Some(ScanResult {
                    disposition: Disposition::Suspicious,
                    threat_type: Some(ThreatType::Packer),
                    threat_name: Some("Suspicious PE".to_string()),
                    confidence: 0.6,
                    engine: DetectionEngine::Heuristic,
                    matched_ids: Vec::new(),
                    details: serde_json::json!({ "method": "pe_analysis", "suspicious_score": suspicious_score }),
                    duration: Duration::from_millis(0),
                }));
            }
        }
        Ok(None)
    }

    /// Scan a directory recursively.
    pub async fn scan_directory(
        &self,
        path: &Path,
        ctx: &ScanContext,
    ) -> AegisResult<Vec<ScanResult>> {
        let mut results = Vec::new();

        for entry in WalkDir::new(path).follow_links(false) {
            if let Ok(entry) = entry {
                if entry.file_type().is_file() {
                    let file_path = entry.path();

                    // Check excluded paths
                    if self
                        .config
                        .excluded_paths
                        .iter()
                        .any(|p| file_path.starts_with(p))
                    {
                        continue;
                    }

                    let file_ctx = ScanContext {
                        scan_id: uuid::Uuid::new_v7(uuid::Timestamp::from_unix(
                            uuid::NoContext,
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs(),
                            0,
                        )),
                        initiator_pid: ctx.initiator_pid,
                        initiator_name: ctx.initiator_name.clone(),
                        trigger: ScanTrigger::Scheduled,
                        priority: ctx.priority,
                        deadline: None,
                        metadata: serde_json::json!({}),
                    };

                    match self.scan_file(file_path, file_ctx).await {
                        Ok(result) => {
                            results.push(result);
                        }
                        Err(e) => {
                            warn!("Scan error for {:?}: {}", file_path, e);
                            let mut stats = self.stats.write();
                            stats.scan_errors += 1;
                        }
                    }
                }
            }
        }

        Ok(results)
    }

    /// Get scanner statistics.
    pub fn stats(&self) -> ScanStats {
        self.stats.read().clone()
    }

    /// Reset statistics.
    pub fn reset_stats(&self) {
        *self.stats.write() = ScanStats::default();
    }
}

#[async_trait::async_trait]
impl aegis_core::traits::Scanner for ScannerEngine {
    async fn scan_file(&self, path: &Path, ctx: ScanContext) -> AegisResult<ScanResult> {
        self.scan_file(path, ctx).await
    }

    async fn scan_memory(
        &self,
        _pid: u32,
        _address: usize,
        _size: usize,
    ) -> AegisResult<ScanResult> {
        Err(AegisError::Unsupported(
            "Memory scanning not implemented".into(),
        ))
    }

    async fn scan_process(&self, _pid: u32) -> AegisResult<Vec<ScanResult>> {
        Err(AegisError::Unsupported(
            "Process scanning not implemented".into(),
        ))
    }

    async fn lookup_hash(&self, hash: &Sha256) -> AegisResult<Option<SignatureMatch>> {
        self.matcher.match_hash(hash).await
    }

    async fn stats(&self) -> AegisResult<ScannerStats> {
        let s = self.stats();
        Ok(ScannerStats {
            files_scanned: s.files_scanned,
            detections: s.detections,
            bytes_scanned: s.bytes_scanned,
            scan_errors: s.scan_errors,
            avg_scan_time_ms: s.avg_scan_time_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_scanner_config() {
        let config = ScannerConfig::default();
        assert_eq!(config.max_concurrent_scans, 4);
        assert!(!config.enable_ml);
    }
}
