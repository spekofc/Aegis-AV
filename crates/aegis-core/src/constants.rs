//! Constants used throughout AEGIS AV.

use crate::types::Version;

/// Maximum message payload size for IPC (64 KB).
pub const MAX_IPC_PAYLOAD: usize = 64 * 1024;

/// Maximum filter port message size (128 KB).
pub const MAX_FILTER_MESSAGE: usize = 128 * 1024;

/// Default scan timeout (30 seconds).
pub const DEFAULT_SCAN_TIMEOUT_SECS: u64 = 30;

/// Maximum scan timeout (5 minutes).
pub const MAX_SCAN_TIMEOUT_SECS: u64 = 300;

/// Default update check interval (4 hours).
pub const DEFAULT_UPDATE_INTERVAL_SECS: u64 = 4 * 60 * 60;

/// Quarantine root directory name.
pub const QUARANTINE_DIR_NAME: &str = "Quarantine";

/// Signature database file name.
pub const SIGNATURE_DB_NAME: &str = "signatures.db";

/// Heuristic database file name.
pub const HEURISTIC_DB_NAME: &str = "heuristics.db";

/// Trust/allowlist database file name.
pub const TRUST_DB_NAME: &str = "trust.db";

/// Configuration file name.
pub const CONFIG_FILE_NAME: &str = "aegis.yaml";

/// Service name.
pub const SERVICE_NAME: &str = "AEGIS";

/// Service display name.
pub const SERVICE_DISPLAY_NAME: &str = "AEGIS AV";

/// Named pipe prefix.
pub const NAMED_PIPE_PREFIX: &str = r"\\.\pipe\aegis";

/// Filter communication port name.
pub const FILTER_PORT_NAME: &str = r"\\AegisFilterPort";

/// Anti-exploit ALPC port name.
pub const ANTIEXPLOIT_PORT_NAME: &str = r"\\AegisAntiExploitPort";

/// Named pipe default instance count.
pub const PIPE_INSTANCES: u32 = 255;

/// Named pipe buffer sizes.
pub const PIPE_IN_BUFFER: u32 = 65536;
pub const PIPE_OUT_BUFFER: u32 = 65536;

/// Default working set limits.
pub const DEFAULT_WORKING_SET_PRIVATE: u64 = 150 * 1024 * 1024; // 150 MB
pub const DEFAULT_WORKING_SET_STABLE: u64 = 4 * 1024 * 1024; // 4 MB
pub const DEFAULT_WORKING_SET_TOTAL: u64 = 200 * 1024 * 1024; // 200 MB

/// Idle thresholds.
pub const IDLE_MAX_CPU_PERCENT: u8 = 25;
pub const IDLE_MAX_IO_PERCENT: u8 = 25;
pub const IDLE_TIME_SPAN_SECS: u64 = 300;

/// ML classification threshold (0.0 - 1.0).
pub const DEFAULT_ML_THRESHOLD: f32 = 0.85;

/// Heuristic aggression levels.
pub const HEURISTIC_LEVEL_LOW: u8 = 1;
pub const HEURISTIC_LEVEL_MEDIUM: u8 = 2;
pub const HEURISTIC_LEVEL_HIGH: u8 = 3;
pub const HEURISTIC_LEVEL_AGGRESSIVE: u8 = 4;

/// Maximum exclusions.
pub const MAX_EXCLUSIONS: usize = 10000;

/// Maximum quarantine entries.
pub const MAX_QUARANTINE_ENTRIES: u64 = 100000;

/// Quarantine max total size (10 GB).
pub const MAX_QUARANTINE_SIZE: u64 = 10 * 1024 * 1024 * 1024;

/// Log rotation: max file size (10 MB).
pub const LOG_MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

/// Log rotation: max backup files.
pub const LOG_MAX_BACKUPS: u32 = 10;

/// Cryptographic constants.
pub mod crypto {
    /// AES-256-GCM key size.
    pub const AES256_KEY_SIZE: usize = 32;
    /// AES-256-GCM nonce size (96 bits).
    pub const AES256_GCM_NONCE_SIZE: usize = 12;
    /// AES-256-GCM tag size (128 bits).
    pub const AES256_GCM_TAG_SIZE: usize = 16;
    /// Ed25519 public key size.
    pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
    /// Ed25519 signature size.
    pub const ED25519_SIGNATURE_SIZE: usize = 64;
    /// SHA-256 output size.
    pub const SHA256_SIZE: usize = 32;
    /// HKDF output size for key derivation.
    pub const HKDF_OUTPUT_SIZE: usize = 32;
    /// Argon2id memory cost (KB).
    pub const ARGON2ID_MEMORY_COST_KB: u32 = 65536; // 64 MB
    /// Argon2id time cost (iterations).
    pub const ARGON2ID_TIME_COST: u32 = 3;
    /// Argon2id parallelism.
    pub const ARGON2ID_PARALLELISM: u32 = 4;
    /// PBKDF2 iterations for SQLCipher.
    pub const SQLCIPHER_KDF_ITER: u32 = 256000;
}

/// PE parsing constants.
pub mod pe {
    /// Maximum PE file size to analyze (100 MB).
    pub const MAX_PE_SIZE: u64 = 100 * 1024 * 1024;
    /// Maximum sections to parse.
    pub const MAX_SECTIONS: usize = 96;
    /// Maximum imports to parse.
    pub const MAX_IMPORTS: usize = 5000;
    /// Entropy threshold for packed detection.
    pub const PACKED_ENTROPY_THRESHOLD: f64 = 7.0;
    /// Maximum overlay size to analyze.
    pub const MAX_OVERLAY_SIZE: u64 = 10 * 1024 * 1024;
}

/// Minifilter constants.
pub mod minifilter {
    /// Filter altitude (must be unique).
    pub const FILTER_ALTITUDE: &str = "380000";
    /// Max file name length.
    pub const MAX_FILE_NAME: usize = 260 * 2; // Wide chars
    /// Transaction timeout (ms).
    pub const TRANSACTION_TIMEOUT_MS: u32 = 5000;
    /// Max pending callbacks.
    pub const MAX_PENDING_CALLBACKS: usize = 1000;
}

/// Anti-exploit constants.
pub mod antiexploit {
    /// Max API hooks.
    pub const MAX_HOOKS: usize = 64;
    /// Max monitored processes.
    pub const MAX_MONITORED_PROCESSES: usize = 10000;
    /// Heap allocation threshold for detection (1 MB).
    pub const HEAP_ALLOC_THRESHOLD: usize = 1024 * 1024;
    /// Max virtual allocation size for single call.
    pub const MAX_VIRTUAL_ALLOC: usize = 256 * 1024 * 1024;
}

/// TPM/secure storage constants.
pub mod tpm {
    /// PCR for secure boot.
    pub const PCR_SECURE_BOOT: u32 = 7;
    /// PCR for boot policy.
    pub const PCR_BOOT_POLICY: u32 = 8;
    /// PCR for kernel measurement.
    pub const PCR_KERNEL: u32 = 0;
    /// Sealed data max size.
    pub const MAX_SEALED_DATA: usize = 4096;
}

/// Default configuration values.
pub fn default_config() -> serde_json::Value {
    serde_json::json!({
        "service": {
            "working_set_private_mb": 150,
            "working_set_stable_mb": 4,
            "working_set_total_mb": 200,
            "delay_start": false,
            "delay_interval_secs": 15,
            "idle_max_cpu_percent": 25,
            "idle_max_io_percent": 25,
            "idle_time_span_secs": 300,
        },
        "scanner": {
            "max_concurrent_scans": 4,
            "scan_timeout_secs": 30,
            "ml_threshold": 0.85,
            "heuristic_level": 2,
            "enable_ml": true,
            "enable_heuristics": true,
            "enable_cloud": false,
        },
        "realtime": {
            "enabled": true,
            "monitor_creates": true,
            "monitor_writes": true,
            "monitor_executes": true,
            "monitor_process": true,
            "monitor_registry": true,
            "monitor_network": false,
            "early_block_mode": false,
            "game_mode": false,
        },
        "quarantine": {
            "max_entries": 10000,
            "max_size_gb": 10,
            "encrypt": true,
            "compress": false,
        },
        "updater": {
            "enabled": true,
            "check_interval_hours": 4,
            "auto_apply": false,
            "require_reboot": false,
            "verify_signatures": true,
            "anti_downgrade": true,
        },
        "telemetry": {
            "enabled": true,
            "level": "info",
            "etw_enabled": true,
            "prometheus_port": 9090,
        },
        "license": {
            "type": "trial",
            "features": ["scan", "realtime", "quarantine"],
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(MAX_IPC_PAYLOAD, 64 * 1024);
        assert_eq!(QUARANTINE_DIR_NAME, "Quarantine");
        assert!(DEFAULT_ML_THRESHOLD > 0.0 && DEFAULT_ML_THRESHOLD <= 1.0);
    }

    #[test]
    fn test_default_config() {
        let config = default_config();
        assert!(
            config["service"]["working_set_private_mb"]
                .as_u64()
                .unwrap()
                == 150
        );
        assert!(config["scanner"]["ml_threshold"].as_f64().unwrap() == 0.85);
    }
}
