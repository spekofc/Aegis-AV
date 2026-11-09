//! Real-time filter client.

use aegis_core::{
    AegisError, AegisResult, Disposition, ScanContext, ScanResult, ThreatType, Timestamp,
};
use aegis_scanner::ScannerEngine;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info};

/// Real-time protection configuration.
#[derive(Debug, Clone)]
pub struct RealtimeConfig {
    pub enable_on_read: bool,
    pub enable_on_write: bool,
    pub enable_on_execute: bool,
    pub scan_timeout_ms: u64,
    pub max_file_size_mb: u64,
}

impl Default for RealtimeConfig {
    fn default() -> Self {
        Self {
            enable_on_read: true,
            enable_on_write: true,
            enable_on_execute: true,
            scan_timeout_ms: 5000,
            max_file_size_mb: 100,
        }
    }
}

/// Real-time protection client.
pub struct RealtimeClient {
    config: RealtimeConfig,
    scanner: Arc<ScannerEngine>,
    event_tx: mpsc::Sender<FileEvent>,
}

#[derive(Debug, Clone)]
pub struct FileEvent {
    pub path: std::path::PathBuf,
    pub event_type: FileEventType,
    pub process_id: u32,
    pub process_name: String,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileEventType {
    Read,
    Write,
    Execute,
    Create,
    Delete,
    Rename,
}

impl RealtimeClient {
    /// Create a new real-time client.
    pub fn new(
        config: RealtimeConfig,
        scanner: Arc<ScannerEngine>,
    ) -> AegisResult<(Self, mpsc::Receiver<FileEvent>)> {
        let (event_tx, event_rx) = mpsc::channel(1000);
        let client = Self {
            config,
            scanner,
            event_tx,
        };
        Ok((client, event_rx))
    }

    /// Submit a file event for scanning.
    pub async fn submit_event(&self, event: FileEvent) -> AegisResult<()> {
        self.event_tx
            .send(event)
            .await
            .map_err(|_| AegisError::Internal("Event channel closed".into()))?;
        Ok(())
    }

    /// Scan a file synchronously.
    pub async fn scan_file(&self, path: &Path, context: &ScanContext) -> AegisResult<ScanResult> {
        if !self.should_scan(path) {
            return Ok(ScanResult::clean());
        }

        // Check file size
        let metadata = std::fs::metadata(path).map_err(|e| AegisError::Io(e))?;
        if metadata.len() > self.config.max_file_size_mb * 1024 * 1024 {
            return Ok(ScanResult::skipped("File too large"));
        }

        self.scanner.scan_file(path, context.clone()).await
    }

    /// Determine if a file should be scanned.
    fn should_scan(&self, path: &Path) -> bool {
        // Skip system directories, etc.
        if let Some(parent) = path.parent() {
            let parent_str = parent.to_string_lossy().to_lowercase();
            if parent_str.contains("windows\\system32") || parent_str.contains("program files") {
                return false;
            }
        }
        true
    }
}
