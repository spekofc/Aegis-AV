//! Core traits for AEGIS AV components.

use crate::{error::AegisError, types::*, AegisResult};
use async_trait::async_trait;
use std::path::{Path, PathBuf};

/// Scanner trait for file/memory/process scanning.
#[async_trait]
pub trait Scanner: Send + Sync {
    /// Scan a file.
    async fn scan_file(&self, path: &Path, ctx: ScanContext) -> AegisResult<ScanResult>;

    /// Scan a memory region in a process.
    async fn scan_memory(&self, pid: u32, address: usize, size: usize) -> AegisResult<ScanResult>;

    /// Scan an entire process.
    async fn scan_process(&self, pid: u32) -> AegisResult<Vec<ScanResult>>;

    /// Quick hash-based lookup only.
    async fn lookup_hash(&self, hash: &Sha256) -> AegisResult<Option<SignatureMatch>>;

    /// Get scanner statistics.
    async fn stats(&self) -> AegisResult<ScannerStats>;
}

/// Scanner statistics.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ScannerStats {
    pub files_scanned: u64,
    pub detections: u64,
    pub bytes_scanned: u64,
    pub scan_errors: u64,
    pub avg_scan_time_ms: f64,
}

/// Signature database provider trait.
#[async_trait]
pub trait SignatureProvider: Send + Sync {
    /// Look up a hash in the signature database.
    async fn lookup_hash(&self, hash: &Sha256) -> AegisResult<Option<SignatureMatch>>;

    /// Look up patterns in data.
    async fn lookup_patterns(&self, data: &[u8]) -> AegisResult<Vec<PatternMatch>>;

    /// Get database version.
    fn version(&self) -> Version;

    /// Get signature count.
    fn signature_count(&self) -> u64;

    /// Reload signatures (for updates).
    async fn reload(&self) -> AegisResult<()>;
}

/// Real-time protection trait.
#[async_trait]
pub trait RealTimeProtection: Send + Sync {
    /// Start real-time monitoring.
    async fn start(&self) -> AegisResult<()>;

    /// Stop real-time monitoring.
    async fn stop(&self) -> AegisResult<()>;

    /// Check if running.
    fn is_running(&self) -> bool;

    /// Add exclusion path.
    async fn add_exclusion(&self, path: &Path) -> AegisResult<()>;

    /// Remove exclusion path.
    async fn remove_exclusion(&self, path: &Path) -> AegisResult<()>;

    /// List exclusions.
    async fn list_exclusions(&self) -> AegisResult<Vec<PathBuf>>;

    /// Set callback for disposition decisions.
    fn set_disposition_callback(&self, callback: Box<dyn DispositionCallback>);
}

/// Callback for real-time disposition decisions.
pub trait DispositionCallback: Send + Sync {
    /// Called when a file operation needs a disposition decision.
    fn decide(&self, request: DispositionRequest) -> DispositionResponse;
}

/// Request for disposition decision.
#[derive(Debug, Clone)]
pub struct DispositionRequest {
    pub message_id: u64,
    pub event_type: RealtimeEventType,
    pub process: ProcessInfo,
    pub file_path: PathBuf,
    pub file_hash: Option<Sha256>,
}

/// Response with disposition decision.
#[derive(Debug, Clone)]
pub struct DispositionResponse {
    pub message_id: u64,
    pub disposition: Disposition,
    pub quarantine: bool,
    pub reason: Option<String>,
}

/// Real-time event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u32)]
pub enum RealtimeEventType {
    FileCreate = 1,
    FileWrite = 2,
    FileSetInfo = 3,
    FileDelete = 4,
    FileRename = 5,
    ProcessCreate = 10,
    ProcessExit = 11,
    ThreadCreate = 12,
    ThreadExit = 13,
    ImageLoad = 20,
    RegistrySetValue = 30,
    RegistryDeleteKey = 31,
    RegistryDeleteValue = 32,
}

/// Quarantine management trait.
#[async_trait]
pub trait Quarantine: Send + Sync {
    /// Isolate a file.
    async fn isolate(
        &self,
        source: &Path,
        metadata: QuarantineMetadata,
    ) -> AegisResult<QuarantineId>;

    /// Restore a quarantined file.
    async fn restore(&self, id: QuarantineId, destination: &Path) -> AegisResult<()>;

    /// Permanently destroy a quarantined file.
    async fn destroy(&self, id: QuarantineId) -> AegisResult<()>;

    /// List quarantine entries.
    async fn list(&self, filter: QuarantineFilter) -> AegisResult<Vec<QuarantineEntry>>;

    /// Get quarantine entry by ID.
    async fn get(&self, id: QuarantineId) -> AegisResult<Option<QuarantineEntry>>;

    /// Get quarantine statistics.
    async fn stats(&self) -> AegisResult<QuarantineStats>;
}

/// Quarantine filter for listing.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct QuarantineFilter {
    pub status: Option<QuarantineStatus>,
    pub threat_type: Option<ThreatType>,
    pub date_from: Option<Timestamp>,
    pub date_to: Option<Timestamp>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

/// Quarantine statistics.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct QuarantineStats {
    pub total_entries: u64,
    pub active_entries: u64,
    pub total_size_bytes: u64,
    pub by_threat_type: std::collections::HashMap<ThreatType, u64>,
}

/// Update engine trait.
#[async_trait]
pub trait UpdateEngine: Send + Sync {
    /// Check for updates.
    async fn check_updates(&self) -> AegisResult<UpdateInfo>;

    /// Download and apply updates.
    async fn apply_updates(&self, progress: Box<dyn UpdateProgress>) -> AegisResult<()>;

    /// Get current version.
    fn current_version(&self) -> Version;

    /// Rollback to previous version.
    async fn rollback(&self) -> AegisResult<()>;
}

/// Update information.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UpdateInfo {
    pub available: bool,
    pub current_version: Version,
    pub latest_version: Version,
    pub components: Vec<ComponentUpdateInfo>,
    pub release_notes: Option<String>,
    pub requires_reboot: bool,
}

/// Component update information.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComponentUpdateInfo {
    pub name: String,
    pub current_version: Version,
    pub new_version: Version,
    pub size_bytes: u64,
    pub required: bool,
}

/// Update progress callback.
pub trait UpdateProgress: Send + Sync {
    fn on_download_start(&self, total_bytes: u64);
    fn on_download_progress(&self, downloaded: u64, total: u64);
    fn on_component_start(&self, name: &str);
    fn on_component_progress(&self, name: &str, progress: f32);
    fn on_complete(&self, success: bool, message: Option<String>);
}

/// Configuration trait.
#[async_trait]
pub trait ConfigProvider: Send + Sync {
    /// Get typed configuration value.
    fn get<T: serde::de::DeserializeOwned>(&self, key: &str) -> AegisResult<T>;

    /// Set configuration value.
    async fn set(&self, key: &str, value: &serde_json::Value) -> AegisResult<()>;

    /// Watch for configuration changes.
    async fn watch(
        &self,
        key: &str,
    ) -> AegisResult<tokio::sync::watch::Receiver<serde_json::Value>>;

    /// Reload configuration from disk.
    async fn reload(&self) -> AegisResult<()>;

    /// Validate configuration.
    fn validate(&self) -> AegisResult<()>;
}

/// Telemetry/metrics trait.
pub trait Telemetry: Send + Sync {
    /// Record a counter metric.
    fn increment_counter(&self, name: &str, labels: &[(&str, &str)], value: u64);

    /// Record a gauge metric.
    fn set_gauge(&self, name: &str, labels: &[(&str, &str)], value: f64);

    /// Record a histogram metric.
    fn record_histogram(&self, name: &str, labels: &[(&str, &str)], value: f64);

    /// Record an event/log.
    fn record_event(&self, event: TelemetryEvent);
}

/// Telemetry event.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TelemetryEvent {
    pub timestamp: Timestamp,
    pub level: TelemetryLevel,
    pub component: String,
    pub message: String,
    pub fields: serde_json::Value,
}

/// Telemetry level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TelemetryLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Critical,
}

/// Health check trait.
#[async_trait]
pub trait HealthCheck: Send + Sync {
    /// Perform health check.
    async fn check(&self) -> AegisResult<HealthStatus>;

    /// Component name.
    fn name(&self) -> &'static str;
}

/// Health status.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HealthStatus {
    pub healthy: bool,
    pub component: String,
    pub checks: Vec<HealthCheckResult>,
    pub timestamp: Timestamp,
}

/// Individual health check result.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HealthCheckResult {
    pub name: String,
    pub healthy: bool,
    pub message: Option<String>,
    pub latency_ms: u64,
}

/// Lifecycle management trait.
#[async_trait]
pub trait Lifecycle: Send + Sync {
    /// Initialize the component.
    async fn init(&self) -> AegisResult<()>;

    /// Start the component.
    async fn start(&self) -> AegisResult<()>;

    /// Stop the component gracefully.
    async fn stop(&self) -> AegisResult<()>;

    /// Shutdown and cleanup.
    async fn shutdown(&self) -> AegisResult<()>;
}

/// Component registration for dependency injection.
pub trait Component: Send + Sync {
    fn name(&self) -> &'static str;
    fn version(&self) -> Version;
    fn dependencies(&self) -> Vec<&'static str>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trait_bounds() {
        // Ensure traits are object-safe where needed
        fn _assert_send_sync<T: Send + Sync + ?Sized>() {}
        _assert_send_sync::<dyn Scanner>();
        _assert_send_sync::<dyn SignatureProvider>();
        _assert_send_sync::<dyn RealTimeProtection>();
        _assert_send_sync::<dyn Quarantine>();
        _assert_send_sync::<dyn UpdateEngine>();
        _assert_send_sync::<dyn Telemetry>();
        _assert_send_sync::<dyn HealthCheck>();
        _assert_send_sync::<dyn Lifecycle>();
        // ConfigProvider is not dyn-compatible due to generic method get<T>()
    }
}
