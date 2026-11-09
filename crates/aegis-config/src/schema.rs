//! Configuration schema for AEGIS AV.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Complete AEGIS AV configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AegisConfig {
    /// Service configuration.
    pub service: ServiceConfig,

    /// Scanner configuration.
    pub scanner: ScannerConfig,

    /// Real-time protection configuration.
    pub realtime: RealtimeConfig,

    /// Quarantine configuration.
    pub quarantine: QuarantineConfig,

    /// Updater configuration.
    pub updater: UpdaterConfig,

    /// Telemetry configuration.
    pub telemetry: TelemetryConfig,

    /// License configuration.
    pub license: LicenseConfig,

    /// Anti-exploit configuration.
    pub antiexploit: AntiExploitConfig,

    /// Network/VPN configuration.
    pub network: NetworkConfig,
}

/// Service/runtime configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Private working set limit (MB).
    pub working_set_private_mb: u64,

    /// Stable working set limit (MB).
    pub working_set_stable_mb: u64,

    /// Total working set limit (MB).
    pub working_set_total_mb: u64,

    /// Delay service start.
    pub delay_start: bool,

    /// Delay interval (seconds).
    pub delay_interval_secs: u64,

    /// Enable dump collection on crash.
    pub enable_dump_collection: bool,

    /// Data directory path.
    pub data_path: PathBuf,

    /// Log directory path.
    pub log_path: PathBuf,

    /// Maximum log file size (MB).
    pub log_max_size_mb: u64,

    /// Maximum log backups.
    pub log_max_backups: u32,

    /// Maximum log level.
    pub max_log_level: String,

    /// Product build type.
    pub product_build: String,

    /// Product code.
    pub product_code: String,

    /// Idle CPU threshold (percent).
    pub idle_max_cpu_percent: u8,

    /// Idle IO threshold (percent).
    pub idle_max_io_percent: u8,

    /// Idle time span (seconds).
    pub idle_time_span_secs: u64,
}

/// Scanner configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerConfig {
    /// Maximum concurrent scans.
    pub max_concurrent_scans: usize,

    /// Scan timeout (seconds).
    pub scan_timeout_secs: u64,

    /// ML classification threshold.
    pub ml_threshold: f32,

    /// Heuristic level (1-4).
    pub heuristic_level: u8,

    /// Enable ML classifier.
    pub enable_ml: bool,

    /// Enable heuristic engine.
    pub enable_heuristics: bool,

    /// Enable cloud lookup.
    pub enable_cloud: bool,

    /// Cloud API endpoint.
    pub cloud_endpoint: Option<String>,

    /// Enable PE analysis.
    pub enable_pe_analysis: bool,

    /// Enable script analysis.
    pub enable_script_analysis: bool,

    /// Maximum file size to scan (MB).
    pub max_file_size_mb: u64,

    /// Enable archive scanning.
    pub enable_archive_scan: bool,

    /// Archive recursion depth.
    pub archive_max_depth: u8,

    /// Enable ADS scanning.
    pub enable_ads_scan: bool,
}

/// Real-time protection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeConfig {
    /// Enable real-time protection.
    pub enabled: bool,

    /// Monitor file creates.
    pub monitor_creates: bool,

    /// Monitor file writes.
    pub monitor_writes: bool,

    /// Monitor file executes.
    pub monitor_executes: bool,

    /// Monitor process creation.
    pub monitor_process: bool,

    /// Monitor registry changes.
    pub monitor_registry: bool,

    /// Monitor network activity.
    pub monitor_network: bool,

    /// Early block mode (block before scan completes).
    pub early_block_mode: bool,

    /// Game mode (reduced scanning).
    pub game_mode: bool,

    /// Network share scanning.
    pub network_share_detection: bool,

    /// Doppleganger process detection.
    pub doppelganger_detection: bool,

    /// Absolute timeout (ms).
    pub absolute_timeout_ms: u32,

    /// Message timeout (ms).
    pub message_timeout_ms: u32,

    /// Exclusion paths.
    pub exclusions: Vec<PathBuf>,
}

/// Quarantine configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineConfig {
    /// Maximum entries.
    pub max_entries: u64,

    /// Maximum total size (GB).
    pub max_size_gb: u64,

    /// Encrypt quarantined files.
    pub encrypt: bool,

    /// Compress quarantined files.
    pub compress: bool,

    /// Quarantine directory.
    pub directory: PathBuf,

    /// Auto-destroy after days (0 = never).
    pub auto_destroy_days: u32,

    /// Require admin for restore.
    pub require_admin_restore: bool,
}

/// Updater configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdaterConfig {
    /// Enable automatic updates.
    pub enabled: bool,

    /// Check interval (hours).
    pub check_interval_hours: u64,

    /// Automatically apply updates.
    pub auto_apply: bool,

    /// Require reboot for updates.
    pub require_reboot: bool,

    /// Verify update signatures.
    pub verify_signatures: bool,

    /// Prevent downgrade attacks.
    pub anti_downgrade: bool,

    /// Update server URL.
    pub server_url: String,

    /// Fallback servers.
    pub fallback_servers: Vec<String>,

    /// Certificate pinning (SHA-256 of cert).
    pub cert_pins: Vec<String>,

    /// Use transparency log.
    pub transparency_log: bool,
}

/// Telemetry configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// Enable telemetry.
    pub enabled: bool,

    /// Log level.
    pub level: String,

    /// Enable ETW.
    pub etw_enabled: bool,

    /// ETW provider name.
    pub etw_provider: String,

    /// Prometheus metrics port.
    pub prometheus_port: u16,

    /// Sentry DSN (optional).
    pub sentry_dsn: Option<String>,

    /// Sample rate (0.0 - 1.0).
    pub sample_rate: f32,
}

/// License configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseConfig {
    /// License type.
    pub license_type: String,

    /// Encrypted license key.
    pub license_key: Option<String>,

    /// Entitlements bitmask.
    pub entitlements: u64,

    /// Expiration timestamp.
    pub expires_at: Option<u64>,

    /// Hardware ID (encrypted).
    pub hardware_id: Option<String>,
}

/// Anti-exploit configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiExploitConfig {
    /// Enable anti-exploit.
    pub enabled: bool,

    /// Enable heap monitoring.
    pub heap_monitoring: bool,

    /// Enable stack protection.
    pub stack_protection: bool,

    /// Enable CFG/CET.
    pub cfg_cet: bool,

    /// Enable API hooking.
    pub api_hooking: bool,

    /// Protected processes (by name).
    pub protected_processes: Vec<String>,

    /// Mitigation level.
    pub mitigation_level: u8,
}

/// Network/VPN configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Enable VPN.
    pub vpn_enabled: bool,

    /// VPN server.
    pub vpn_server: Option<String>,

    /// VPN protocol.
    pub vpn_protocol: String,

    /// WireGuard config.
    pub wireguard: Option<WireGuardConfig>,
}

/// WireGuard configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardConfig {
    pub private_key: Option<String>,
    pub peer_public_key: Option<String>,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
}

impl Default for AegisConfig {
    fn default() -> Self {
        Self {
            service: ServiceConfig::default(),
            scanner: ScannerConfig::default(),
            realtime: RealtimeConfig::default(),
            quarantine: QuarantineConfig::default(),
            updater: UpdaterConfig::default(),
            telemetry: TelemetryConfig::default(),
            license: LicenseConfig::default(),
            antiexploit: AntiExploitConfig::default(),
            network: NetworkConfig::default(),
        }
    }
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            working_set_private_mb: 150,
            working_set_stable_mb: 4,
            working_set_total_mb: 200,
            delay_start: false,
            delay_interval_secs: 15,
            enable_dump_collection: true,
            data_path: PathBuf::from(r"C:\ProgramData\AEGIS"),
            log_path: PathBuf::from(r"C:\ProgramData\AEGIS\logs"),
            log_max_size_mb: 10,
            log_max_backups: 10,
            max_log_level: "info".to_string(),
            product_build: "consumer".to_string(),
            product_code: "AEGIS-C".to_string(),
            idle_max_cpu_percent: 25,
            idle_max_io_percent: 25,
            idle_time_span_secs: 300,
        }
    }
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_scans: 4,
            scan_timeout_secs: 30,
            ml_threshold: 0.85,
            heuristic_level: 2,
            enable_ml: true,
            enable_heuristics: true,
            enable_cloud: false,
            cloud_endpoint: None,
            enable_pe_analysis: true,
            enable_script_analysis: true,
            max_file_size_mb: 100,
            enable_archive_scan: true,
            archive_max_depth: 5,
            enable_ads_scan: true,
        }
    }
}

impl Default for RealtimeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            monitor_creates: true,
            monitor_writes: true,
            monitor_executes: true,
            monitor_process: true,
            monitor_registry: true,
            monitor_network: false,
            early_block_mode: false,
            game_mode: false,
            network_share_detection: true,
            doppelganger_detection: true,
            absolute_timeout_ms: 5000,
            message_timeout_ms: 2000,
            exclusions: Vec::new(),
        }
    }
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        Self {
            max_entries: 10000,
            max_size_gb: 10,
            encrypt: true,
            compress: false,
            directory: PathBuf::from(r"C:\ProgramData\AEGIS\Quarantine"),
            auto_destroy_days: 0,
            require_admin_restore: true,
        }
    }
}

impl Default for UpdaterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_interval_hours: 4,
            auto_apply: false,
            require_reboot: false,
            verify_signatures: true,
            anti_downgrade: true,
            server_url: "https://updates.aegis.example.com".to_string(),
            fallback_servers: Vec::new(),
            cert_pins: Vec::new(),
            transparency_log: true,
        }
    }
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            level: "info".to_string(),
            etw_enabled: true,
            etw_provider: "AEGIS-AV-Security-Engine".to_string(),
            prometheus_port: 9090,
            sentry_dsn: None,
            sample_rate: 1.0,
        }
    }
}

impl Default for LicenseConfig {
    fn default() -> Self {
        Self {
            license_type: "trial".to_string(),
            license_key: None,
            entitlements: 0x7, // scan | realtime | quarantine
            expires_at: None,
            hardware_id: None,
        }
    }
}

impl Default for AntiExploitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            heap_monitoring: true,
            stack_protection: true,
            cfg_cet: true,
            api_hooking: true,
            protected_processes: Vec::new(),
            mitigation_level: 2,
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            vpn_enabled: false,
            vpn_server: None,
            vpn_protocol: "wireguard".to_string(),
            wireguard: None,
        }
    }
}

impl AegisConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> crate::AegisResult<()> {
        // Basic validation - ensure required fields are present
        if self.service.data_path.as_os_str().is_empty() {
            return Err(crate::AegisError::Config(
                "service.data_path is required".into(),
            ));
        }
        if self.service.log_path.as_os_str().is_empty() {
            return Err(crate::AegisError::Config(
                "service.log_path is required".into(),
            ));
        }
        if self.scanner.max_concurrent_scans == 0 {
            return Err(crate::AegisError::Config(
                "scanner.max_concurrent_scans must be > 0".into(),
            ));
        }
        if self.scanner.scan_timeout_secs == 0 {
            return Err(crate::AegisError::Config(
                "scanner.scan_timeout_secs must be > 0".into(),
            ));
        }
        if self.realtime.enabled && self.realtime.absolute_timeout_ms == 0 {
            return Err(crate::AegisError::Config(
                "realtime.absolute_timeout_ms must be > 0".into(),
            ));
        }
        Ok(())
    }
}

/// Create default configuration.
pub fn default_config() -> AegisConfig {
    AegisConfig::default()
}

/// Load configuration from file.
pub fn load_config(path: &PathBuf) -> crate::AegisResult<AegisConfig> {
    let content = std::fs::read_to_string(path).map_err(crate::AegisError::Io)?;

    if path.extension().and_then(|s| s.to_str()) == Some("yaml")
        || path.extension().and_then(|s| s.to_str()) == Some("yml")
    {
        serde_yaml::from_str(&content).map_err(|e| crate::AegisError::Config(e.to_string()))
    } else {
        serde_json::from_str(&content).map_err(|e| crate::AegisError::Config(e.to_string()))
    }
}

/// Save configuration to file.
pub fn save_config(config: &AegisConfig, path: &PathBuf) -> crate::AegisResult<()> {
    let content = if path.extension().and_then(|s| s.to_str()) == Some("yaml")
        || path.extension().and_then(|s| s.to_str()) == Some("yml")
    {
        serde_yaml::to_string(config).map_err(|e| crate::AegisError::Config(e.to_string()))?
    } else {
        serde_json::to_string_pretty(config)
            .map_err(|e| crate::AegisError::Config(e.to_string()))?
    };

    std::fs::write(path, content).map_err(crate::AegisError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AegisConfig::default();
        assert_eq!(config.service.working_set_private_mb, 150);
        assert!(config.realtime.enabled);
        assert!(config.scanner.enable_ml);
    }

    #[test]
    fn test_config_serialization() {
        let config = AegisConfig::default();
        let json = serde_json::to_string_pretty(&config).unwrap();
        let parsed: AegisConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(
            config.service.working_set_private_mb,
            parsed.service.working_set_private_mb
        );
    }
}
