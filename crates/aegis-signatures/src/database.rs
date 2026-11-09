//! Signature database implementation.

use crate::format::{
    schema::INIT_SQL, DatabaseMeta, PatternRecord, SignatureRecord, SignatureType, CURRENT_PLATFORM,
};
use crate::integrity::{IntegrityVerifier, MerkleTree};
use aegis_core::{
    AegisError, AegisResult, DetectionEngine, Sha256, ThreatType, Timestamp, Version,
};
use getrandom::getrandom;
use sqlx::{Row, SqlitePool};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Signature database with encryption.
pub struct SignatureDatabase {
    pub pool: SqlitePool,
    meta: Arc<RwLock<DatabaseMeta>>,
    verifier: IntegrityVerifier,
    key: [u8; 32],
}

impl SignatureDatabase {
    /// Open an existing database.
    pub async fn open(path: &Path, key: &[u8; 32]) -> AegisResult<Self> {
        let pool = Self::create_pool(path, key).await?;

        // Run migrations
        sqlx::query(INIT_SQL)
            .execute(&pool)
            .await
            .map_err(|e| AegisError::Database(e))?;

        // Load metadata
        let meta = Self::load_meta(&pool).await?;

        // Verify integrity
        let verifier = IntegrityVerifier::new(key);
        verifier.verify_database(&pool, &meta).await?;

        let db = Self {
            pool,
            meta: Arc::new(RwLock::new(meta)),
            verifier,
            key: *key,
        };

        info!(
            "Signature database opened: {} signatures",
            db.meta.read().await.signature_count
        );
        Ok(db)
    }

    /// Create a new database.
    pub async fn create(path: &Path, key: &[u8; 32]) -> AegisResult<Self> {
        if path.exists() {
            return Err(AegisError::InvalidArgument(
                "Database already exists".into(),
            ));
        }

        let pool = Self::create_pool(path, key).await?;
        sqlx::query(INIT_SQL)
            .execute(&pool)
            .await
            .map_err(|e| AegisError::Database(e))?;

        let meta = DatabaseMeta {
            version: Version::new(0, 1, 0, 0),
            signature_count: 0,
            pattern_count: 0,
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
            merkle_root: Sha256::default(),
            manifest_hash: None,
            min_client_version: Version::new(0, 1, 0, 0),
            format_version: 1,
        };

        // Initialize meta
        Self::save_meta(&pool, &meta).await?;

        let db = Self {
            pool,
            meta: Arc::new(RwLock::new(meta)),
            verifier: IntegrityVerifier::new(key),
            key: *key,
        };

        db.recompute_merkle_root().await?;
        info!("New signature database created at {:?}", path);
        Ok(db)
    }

    async fn create_pool(path: &Path, key: &[u8; 32]) -> AegisResult<SqlitePool> {
        let path_str = path
            .to_str()
            .ok_or_else(|| AegisError::InvalidArgument("Invalid path".into()))?;

        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(path_str)
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
            .pragma("cache_size", "-32768")
            .pragma("temp_store", "MEMORY");

        let pool = SqlitePool::connect_with(options)
            .await
            .map_err(|e| AegisError::Database(e))?;

        Ok(pool)
    }

    async fn load_meta(pool: &SqlitePool) -> AegisResult<DatabaseMeta> {
        let row = sqlx::query("SELECT key, value FROM meta")
            .fetch_all(pool)
            .await
            .map_err(|e| AegisError::Database(e))?;

        let mut meta_map = HashMap::new();
        for r in row {
            let key: String = r.get("key");
            let value: String = r.get("value");
            meta_map.insert(key, value);
        }

        let version = Version::parse(meta_map.get("version").unwrap_or(&"0.1.0".to_string()))
            .unwrap_or_default();
        let min_client_version = Version::parse(
            meta_map
                .get("min_client_version")
                .unwrap_or(&"0.1.0".to_string()),
        )
        .unwrap_or_default();

        let merkle_root = meta_map
            .get("merkle_root")
            .and_then(|s| Sha256::from_hex(s))
            .unwrap_or_default();

        let manifest_hash = meta_map
            .get("manifest_hash")
            .and_then(|s| Sha256::from_hex(s));

        Ok(DatabaseMeta {
            version,
            signature_count: meta_map
                .get("signature_count")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            pattern_count: meta_map
                .get("pattern_count")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            created_at: Timestamp::from_secs(
                meta_map
                    .get("created_at")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0),
            ),
            updated_at: Timestamp::from_secs(
                meta_map
                    .get("updated_at")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0),
            ),
            merkle_root,
            manifest_hash,
            min_client_version,
            format_version: meta_map
                .get("format_version")
                .and_then(|s| s.parse().ok())
                .unwrap_or(1),
        })
    }

    pub async fn save_meta(pool: &SqlitePool, meta: &DatabaseMeta) -> AegisResult<()> {
        let mut tx = pool.begin().await.map_err(|e| AegisError::Database(e))?;

        let metas = vec![
            ("version", meta.version.to_string()),
            ("format_version", meta.format_version.to_string()),
            ("signature_count", meta.signature_count.to_string()),
            ("pattern_count", meta.pattern_count.to_string()),
            ("created_at", meta.created_at.0.to_string()),
            ("updated_at", meta.updated_at.0.to_string()),
            ("merkle_root", meta.merkle_root.to_hex()),
            (
                "manifest_hash",
                meta.manifest_hash.map(|h| h.to_hex()).unwrap_or_default(),
            ),
            ("min_client_version", meta.min_client_version.to_string()),
        ];

        for (key, value) in metas {
            sqlx::query("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)")
                .bind(key)
                .bind(value)
                .execute(&mut *tx)
                .await
                .map_err(|e| AegisError::Database(e))?;
        }

        tx.commit().await.map_err(|e| AegisError::Database(e))?;
        Ok(())
    }

    /// Get a signature by hash.
    pub async fn get_by_hash(&self, hash: &Sha256) -> AegisResult<Option<SignatureRecord>> {
        let row = sqlx::query("SELECT * FROM signatures WHERE hash = ?")
            .bind(hash.as_bytes())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AegisError::Database(e))?;

        row.map(|r| self.row_to_signature(r)).transpose()
    }

    /// Get signatures by family.
    pub async fn get_by_family(&self, family: &str) -> AegisResult<Vec<SignatureRecord>> {
        let rows = sqlx::query("SELECT * FROM signatures WHERE family = ?")
            .bind(family)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AegisError::Database(e))?;

        rows.into_iter().map(|r| self.row_to_signature(r)).collect()
    }

    /// Get patterns for a signature.
    pub async fn get_patterns(&self, signature_id: u64) -> AegisResult<Vec<PatternRecord>> {
        let rows = sqlx::query("SELECT * FROM patterns WHERE signature_id = ?")
            .bind(signature_id as i64)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AegisError::Database(e))?;

        rows.into_iter().map(|r| self.row_to_pattern(r)).collect()
    }

    /// Add a new signature.
    pub async fn add_signature(&self, mut sig: SignatureRecord) -> AegisResult<u64> {
        // Validate platform compatibility
        if sig.platforms & CURRENT_PLATFORM == 0 && sig.platforms != 0 {
            warn!("Signature {} not for current platform", sig.id);
        }

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| AegisError::Database(e))?;

        let id = sqlx::query(
            r#"INSERT INTO signatures (
                hash, sig_type, family, threat_type, seAEGIS, platforms,
                min_engine_version_major, min_engine_version_minor, min_engine_version_patch, min_engine_version_build,
                created_at, updated_at, description, tags, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#
        )
        .bind(sig.hash.as_ref().map(|h| h.as_bytes()))
        .bind(sig.sig_type as i32)
        .bind(&sig.family)
        .bind(sig.threat_type as i32)
        .bind(sig.seAEGIS as i32)
        .bind(sig.platforms as i64)
        .bind(sig.min_engine_version.major as i32)
        .bind(sig.min_engine_version.minor as i32)
        .bind(sig.min_engine_version.patch as i32)
        .bind(sig.min_engine_version.build as i32)
        .bind(sig.created_at.0 as i64)
        .bind(sig.updated_at.0 as i64)
        .bind(&sig.description)
        .bind(serde_json::to_string(&sig.tags).unwrap_or_default())
        .bind(serde_json::to_string(&sig.metadata).unwrap_or_default())
        .execute(&mut *tx).await
        .map_err(|e| AegisError::Database(e))?
        .last_insert_rowid();

        // Add patterns if any
        let patterns: &[serde_json::Value] = sig
            .metadata
            .get("patterns")
            .and_then(|v| v.as_array())
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        for pattern in patterns {
            if let (Some(pattern_bytes), Some(desc)) = (
                pattern.get("pattern").and_then(|v| v.as_str()),
                pattern.get("description").and_then(|v| v.as_str()),
            ) {
                let pattern_bytes = hex::decode(pattern_bytes).unwrap_or_default();
                let mask = pattern
                    .get("mask")
                    .and_then(|v| v.as_str())
                    .map(hex::decode)
                    .transpose()
                    .unwrap_or_default();

                sqlx::query(
                    "INSERT INTO patterns (signature_id, offset, pattern, mask, description) VALUES (?, ?, ?, ?, ?)"
                )
                .bind(id)
                .bind(pattern.get("offset").and_then(|v| v.as_i64()))
                .bind(&pattern_bytes)
                .bind(&mask)
                .bind(desc)
                .execute(&mut *tx).await
                .map_err(|e| AegisError::Database(e))?;
            }
        }

        tx.commit().await.map_err(|e| AegisError::Database(e))?;

        // Update meta
        self.update_meta_counts().await?;
        self.recompute_merkle_root().await?;

        Ok(id as u64)
    }

    /// Bulk insert signatures (for updates).
    pub async fn bulk_insert(&self, signatures: Vec<SignatureRecord>) -> AegisResult<u64> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| AegisError::Database(e))?;
        let mut count = 0;

        for sig in signatures {
            let id = sqlx::query(
                r#"INSERT INTO signatures (
                    hash, sig_type, family, threat_type, seAEGIS, platforms,
                    min_engine_version_major, min_engine_version_minor, min_engine_version_patch, min_engine_version_build,
                    created_at, updated_at, description, tags, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"#
            )
            .bind(sig.hash.as_ref().map(|h| h.as_bytes()))
            .bind(sig.sig_type as i32)
            .bind(&sig.family)
            .bind(sig.threat_type as i32)
            .bind(sig.seAEGIS as i32)
            .bind(sig.platforms as i64)
            .bind(sig.min_engine_version.major as i32)
            .bind(sig.min_engine_version.minor as i32)
            .bind(sig.min_engine_version.patch as i32)
            .bind(sig.min_engine_version.build as i32)
            .bind(sig.created_at.0 as i64)
            .bind(sig.updated_at.0 as i64)
            .bind(&sig.description)
            .bind(serde_json::to_string(&sig.tags).unwrap_or_default())
            .bind(serde_json::to_string(&sig.metadata).unwrap_or_default())
            .execute(&mut *tx).await
            .map_err(|e| AegisError::Database(e))?
            .last_insert_rowid();

            count += 1;

            // Batch commit every 1000
            if count % 1000 == 0 {
                tx.commit().await.map_err(|e| AegisError::Database(e))?;
                tx = self
                    .pool
                    .begin()
                    .await
                    .map_err(|e| AegisError::Database(e))?;
            }
        }

        tx.commit().await.map_err(|e| AegisError::Database(e))?;
        self.update_meta_counts().await?;
        self.recompute_merkle_root().await?;

        Ok(count)
    }

    async fn update_meta_counts(&self) -> AegisResult<()> {
        let mut meta = self.meta.write().await;
        let sig_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM signatures")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AegisError::Database(e))?;
        let pat_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM patterns")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AegisError::Database(e))?;

        meta.signature_count = sig_count as u64;
        meta.pattern_count = pat_count as u64;
        meta.updated_at = Timestamp::now();

        Self::save_meta(&self.pool, &meta).await?;
        Ok(())
    }

    async fn recompute_merkle_root(&self) -> AegisResult<()> {
        let root = MerkleTree::compute_database_root(&self.pool).await?;
        let mut meta = self.meta.write().await;
        meta.merkle_root = root;
        meta.updated_at = Timestamp::now();
        Self::save_meta(&self.pool, &meta).await?;
        Ok(())
    }

    pub fn row_to_signature(&self, row: sqlx::sqlite::SqliteRow) -> AegisResult<SignatureRecord> {
        let hash: Option<Vec<u8>> = row.get("hash");
        let tags: String = row.get("tags");
        let metadata: String = row.get("metadata");

        let id: i64 = row.get("id");
        let created_at: i64 = row.get("created_at");
        let updated_at: i64 = row.get("updated_at");

        Ok(SignatureRecord {
            id: id as u64,
            hash: hash.map(|h| Sha256::from_slice(&h[..]).unwrap()),
            sig_type: SignatureType::try_from(row.get::<i32, _>("sig_type") as u8)
                .unwrap_or(SignatureType::Hash),
            family: row.get("family"),
            threat_type: ThreatType::try_from(row.get::<i32, _>("threat_type") as u8)
                .unwrap_or(ThreatType::Unknown),
            seAEGIS: row.get("seAEGIS"),
            platforms: row.get("platforms"),
            min_engine_version: Version::new(
                row.get("min_engine_version_major"),
                row.get("min_engine_version_minor"),
                row.get("min_engine_version_patch"),
                row.get("min_engine_version_build"),
            ),
            created_at: Timestamp::from_secs(created_at as u64),
            updated_at: Timestamp::from_secs(updated_at as u64),
            description: row.get("description"),
            tags: serde_json::from_str(&tags).unwrap_or_default(),
            metadata: serde_json::from_str(&metadata).unwrap_or_default(),
        })
    }

    pub fn row_to_pattern(&self, row: sqlx::sqlite::SqliteRow) -> AegisResult<PatternRecord> {
        let id: i64 = row.get("id");
        let signature_id: i64 = row.get("signature_id");
        let offset: Option<i64> = row.get("offset");

        Ok(PatternRecord {
            id: id as u64,
            signature_id: signature_id as u64,
            offset: offset.map(|o| o as u64),
            pattern: row.get("pattern"),
            mask: row.get("mask"),
            description: row.get("description"),
        })
    }

    /// Get database metadata.
    pub fn meta(&self) -> Arc<RwLock<DatabaseMeta>> {
        self.meta.clone()
    }

    /// Get database statistics.
    pub async fn stats(&self) -> AegisResult<DatabaseStats> {
        let meta = self.meta.read().await;
        Ok(DatabaseStats {
            signature_count: meta.signature_count,
            pattern_count: meta.pattern_count,
            version: meta.version,
            merkle_root: meta.merkle_root,
            size_bytes: self.get_db_size().await?,
        })
    }

    async fn get_db_size(&self) -> AegisResult<u64> {
        // Get file size
        let options = self.pool.connect_options();
        let options_inner = (*options).clone();
        let path = options_inner.get_filename().into_owned();
        let metadata = std::fs::metadata(path).map_err(|e| AegisError::Io(e))?;
        Ok(metadata.len())
    }

    /// Verify database integrity.
    pub async fn verify_integrity(&self) -> AegisResult<bool> {
        let meta = self.meta.read().await;
        self.verifier.verify_database(&self.pool, &meta).await
    }

    /// Close the database.
    pub async fn close(self) -> AegisResult<()> {
        self.pool.close().await;
        Ok(())
    }
}

/// Database statistics.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DatabaseStats {
    pub signature_count: u64,
    pub pattern_count: u64,
    pub version: Version,
    pub merkle_root: Sha256,
    pub size_bytes: u64,
}

/// Builder for creating databases.
pub struct SignatureDatabaseBuilder {
    path: std::path::PathBuf,
    key: Option<[u8; 32]>,
}

impl SignatureDatabaseBuilder {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            key: None,
        }
    }

    pub fn key(mut self, key: [u8; 32]) -> Self {
        self.key = Some(key);
        self
    }

    pub async fn create(self) -> AegisResult<SignatureDatabase> {
        let key = self.key.unwrap_or_else(|| {
            // Generate a random key for new databases
            let mut key = [0u8; 32];
            getrandom::getrandom(&mut key).unwrap();
            key
        });
        SignatureDatabase::create(&self.path, &key).await
    }

    pub async fn open(self) -> AegisResult<SignatureDatabase> {
        let key = self
            .key
            .ok_or_else(|| AegisError::InvalidArgument("Key required to open database".into()))?;
        SignatureDatabase::open(&self.path, &key).await
    }
}

use std::collections::HashMap;

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_database_create_and_open() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let key = [0xde; 32];

        // Create
        let db = SignatureDatabase::create(&db_path, &key).await.unwrap();
        let stats = db.stats().await.unwrap();
        assert_eq!(stats.signature_count, 0);

        // Add a signature
        let sig = SignatureRecord {
            id: 0,
            hash: Some(Sha256([0xab; 32])),
            sig_type: SignatureType::Hash,
            family: "TestFamily".to_string(),
            threat_type: ThreatType::Trojan,
            seAEGIS: 3,
            platforms: CURRENT_PLATFORM,
            min_engine_version: Version::new(0, 1, 0, 0),
            created_at: Timestamp::now(),
            updated_at: Timestamp::now(),
            description: "Test signature".to_string(),
            tags: vec!["test".to_string()],
            metadata: serde_json::json!({}),
        };

        let id = db.add_signature(sig).await.unwrap();
        assert!(id > 0);

        // Verify
        let stats = db.stats().await.unwrap();
        assert_eq!(stats.signature_count, 1);

        // Lookup by hash
        let found = db.get_by_hash(&Sha256([0xab; 32])).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().family, "TestFamily");

        // Close and reopen
        db.close().await.unwrap();

        let db2 = SignatureDatabase::open(&db_path, &key).await.unwrap();
        let stats2 = db2.stats().await.unwrap();
        assert_eq!(stats2.signature_count, 1);
    }
}
