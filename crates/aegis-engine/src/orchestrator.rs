//! Engine orchestrator for AEGIS AV.

use aegis_core::{
    AegisError, AegisResult, DetectionEngine, Disposition, ScanContext, ScanResult, Scanner,
    ScannerStats, Sha256, ThreatType,
};
use aegis_scanner::ScannerEngine;
use aegis_signatures::{
    DatabaseStats, SignatureDatabase, SignatureDatabaseBuilder, SignatureMatcher,
};
use std::path::Path;
use std::sync::Arc;
use tracing::warn;

/// Engine configuration.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub scanner_config: aegis_scanner::ScannerConfig,
    pub signature_db_path: std::path::PathBuf,
    pub signature_db_key: [u8; 32],
}

impl Default for EngineConfig {
    fn default() -> Self {
        // Use a local path for development/testing that doesn't require admin
        let local_db = std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .join("data")
            .join("signatures.db");

        Self {
            scanner_config: aegis_scanner::ScannerConfig::default(),
            signature_db_path: local_db,
            signature_db_key: [0u8; 32],
        }
    }
}

/// Main AEGIS engine orchestrating all components.
pub struct AegisEngine {
    config: EngineConfig,
    scanner: Arc<ScannerEngine>,
    signature_db: Arc<SignatureDatabase>,
}

impl AegisEngine {
    /// Create a new AEGIS engine.
    pub async fn new(config: EngineConfig) -> AegisResult<Self> {
        // Create database if it doesn't exist, otherwise open it
        let signature_db = if config.signature_db_path.exists() {
            Arc::new(
                SignatureDatabase::open(&config.signature_db_path, &config.signature_db_key)
                    .await?,
            )
        } else {
            Arc::new(
                SignatureDatabaseBuilder::new(&config.signature_db_path)
                    .key(config.signature_db_key)
                    .create()
                    .await?,
            )
        };

        let matcher = Arc::new(SignatureMatcher::new(Arc::clone(&signature_db)));
        // Load signatures into matcher
        matcher.reload().await?;
        let scanner = Arc::new(ScannerEngine::new(
            config.scanner_config.clone(),
            Arc::clone(&signature_db),
            matcher,
        )?);

        Ok(Self {
            config,
            scanner,
            signature_db,
        })
    }

    /// Scan a file.
    pub async fn scan_file(&self, path: &Path, context: ScanContext) -> AegisResult<ScanResult> {
        self.scanner.scan_file(path, context).await
    }

    /// Scan a directory.
    pub async fn scan_directory(
        &self,
        path: &Path,
        context: ScanContext,
    ) -> AegisResult<Vec<ScanResult>> {
        self.scanner.scan_directory(path, &context).await
    }

    /// Quick hash lookup.
    pub async fn lookup_hash(
        &self,
        hash: &aegis_core::Sha256,
    ) -> AegisResult<Option<aegis_core::SignatureMatch>> {
        Scanner::lookup_hash(self.scanner.as_ref(), hash).await
    }

    /// Get engine statistics.
    pub fn stats(&self) -> ScannerStats {
        let s = self.scanner.stats();
        ScannerStats {
            files_scanned: s.files_scanned,
            detections: s.detections,
            bytes_scanned: s.bytes_scanned,
            scan_errors: s.scan_errors,
            avg_scan_time_ms: s.avg_scan_time_ms,
        }
    }

    /// Update signature database.
    pub async fn update_signatures(&self) -> AegisResult<()> {
        // In production, this would download and apply updates
        warn!("Signature update not implemented");
        Ok(())
    }

    /// Get signature database statistics.
    pub async fn signature_stats(&self) -> AegisResult<ScannerStats> {
        let db_stats = self.signature_db.stats().await?;
        Ok(ScannerStats {
            files_scanned: db_stats.signature_count + db_stats.pattern_count,
            detections: 0,
            bytes_scanned: db_stats.size_bytes,
            scan_errors: 0,
            avg_scan_time_ms: 0.0,
        })
    }

    /// Reload signature matchers from database.
    pub async fn reload_signatures(&self) -> AegisResult<()> {
        self.scanner.reload_signatures().await
    }
}
