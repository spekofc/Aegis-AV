//! Signature database format and records.

use aegis_core::{DetectionEngine, Sha256, ThreatType, Timestamp, Version};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryFrom;

/// Signature type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum SignatureType {
    Hash = 1,
    Pattern = 2,
    Behavioral = 3,
    Heuristic = 4,
    ML = 5,
}

impl TryFrom<u8> for SignatureType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(SignatureType::Hash),
            2 => Ok(SignatureType::Pattern),
            3 => Ok(SignatureType::Behavioral),
            4 => Ok(SignatureType::Heuristic),
            5 => Ok(SignatureType::ML),
            _ => Err(()),
        }
    }
}

/// Signature record in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureRecord {
    /// Unique signature ID.
    pub id: u64,
    /// Signature hash (for hash-based signatures).
    pub hash: Option<Sha256>,
    /// Signature type.
    pub sig_type: SignatureType,
    /// Threat family name.
    pub family: String,
    /// Threat type.
    pub threat_type: ThreatType,
    /// SeAEGIS (1-5).
    pub seAEGIS: u8,
    /// Target platforms (bitmask).
    pub platforms: u32,
    /// Minimum engine version required.
    pub min_engine_version: Version,
    /// Signature creation timestamp.
    pub created_at: Timestamp,
    /// Last update timestamp.
    pub updated_at: Timestamp,
    /// Description.
    pub description: String,
    /// Tags for categorization.
    pub tags: Vec<String>,
    /// Extended metadata (JSON).
    pub metadata: serde_json::Value,
}

/// Pattern record for pattern-based signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternRecord {
    /// Pattern ID.
    pub id: u64,
    /// Parent signature ID.
    pub signature_id: u64,
    /// Offset in file (None = anywhere).
    pub offset: Option<u64>,
    /// Pattern bytes.
    pub pattern: Vec<u8>,
    /// Mask for wildcard matching (None = exact).
    pub mask: Option<Vec<u8>>,
    /// Pattern description.
    pub description: String,
}

/// Database metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseMeta {
    /// Database version.
    pub version: Version,
    /// Signature count.
    pub signature_count: u64,
    /// Pattern count.
    pub pattern_count: u64,
    /// Database creation timestamp.
    pub created_at: Timestamp,
    /// Last update timestamp.
    pub updated_at: Timestamp,
    /// Merkle root hash.
    pub merkle_root: Sha256,
    /// Signed manifest hash.
    pub manifest_hash: Option<Sha256>,
    /// Minimum accepted client version.
    pub min_client_version: Version,
    /// Database format version.
    pub format_version: u32,
}

/// Signature database schema (SQL).
pub mod schema {
    pub const INIT_SQL: &str = r#"
-- Enable WAL mode for better concurrency
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA cache_size = -32768; -- 32MB cache
PRAGMA temp_store = MEMORY;
PRAGMA mmap_size = 268435456; -- 256MB mmap

-- Signatures table
CREATE TABLE IF NOT EXISTS signatures (
    id INTEGER PRIMARY KEY,
    hash BLOB(32) UNIQUE,
    sig_type INTEGER NOT NULL,
    family TEXT NOT NULL,
    threat_type INTEGER NOT NULL,
    seAEGIS INTEGER NOT NULL CHECK (seAEGIS >= 1 AND seAEGIS <= 5),
    platforms INTEGER NOT NULL DEFAULT 0,
    min_engine_version_major INTEGER NOT NULL DEFAULT 0,
    min_engine_version_minor INTEGER NOT NULL DEFAULT 0,
    min_engine_version_patch INTEGER NOT NULL DEFAULT 0,
    min_engine_version_build INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    description TEXT,
    tags TEXT, -- JSON array
    metadata TEXT -- JSON object
);

CREATE INDEX IF NOT EXISTS idx_signatures_hash ON signatures(hash);
CREATE INDEX IF NOT EXISTS idx_signatures_family ON signatures(family);
CREATE INDEX IF NOT EXISTS idx_signatures_threat_type ON signatures(threat_type);
CREATE INDEX IF NOT EXISTS idx_signatures_seAEGIS ON signatures(seAEGIS);
CREATE INDEX IF NOT EXISTS idx_signatures_platforms ON signatures(platforms);

-- Patterns table
CREATE TABLE IF NOT EXISTS patterns (
    id INTEGER PRIMARY KEY,
    signature_id INTEGER NOT NULL,
    offset INTEGER,
    pattern BLOB NOT NULL,
    mask BLOB,
    description TEXT,
    FOREIGN KEY (signature_id) REFERENCES signatures(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_patterns_signature ON patterns(signature_id);

-- Metadata table
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Insert default metadata
INSERT OR IGNORE INTO meta (key, value) VALUES
    ('version', '0.1.0'),
    ('format_version', '1'),
    ('signature_count', '0'),
    ('pattern_count', '0'),
    ('created_at', '0'),
    ('updated_at', '0'),
    ('merkle_root', ''),
    ('min_client_version', '0.1.0');

-- Triggers for automatic metadata updates
CREATE TRIGGER IF NOT EXISTS update_signature_count
AFTER INSERT ON signatures
BEGIN
    UPDATE meta SET value = (SELECT COUNT(*) FROM signatures) WHERE key = 'signature_count';
    UPDATE meta SET value = CAST(strftime('%s', 'now') AS TEXT) WHERE key = 'updated_at';
END;

CREATE TRIGGER IF NOT EXISTS update_pattern_count
AFTER INSERT ON patterns
BEGIN
    UPDATE meta SET value = (SELECT COUNT(*) FROM patterns) WHERE key = 'pattern_count';
END;
"#;

    pub const MIGRATION_V1_TO_V2: &str = r#"
-- Add support for ML signatures
ALTER TABLE signatures ADD COLUMN model_id TEXT;
CREATE INDEX IF NOT EXISTS idx_signatures_model ON signatures(model_id);
"#;
}

/// Platform bitmasks.
pub mod platforms {
    pub const WINDOWS_X86: u32 = 1 << 0;
    pub const WINDOWS_X64: u32 = 1 << 1;
    pub const LINUX_X86: u32 = 1 << 2;
    pub const LINUX_X64: u32 = 1 << 3;
    pub const LINUX_ARM: u32 = 1 << 4;
    pub const LINUX_ARM64: u32 = 1 << 5;
    pub const MACOS_X64: u32 = 1 << 6;
    pub const MACOS_ARM64: u32 = 1 << 7;
    pub const ANDROID_ARM: u32 = 1 << 8;
    pub const ANDROID_ARM64: u32 = 1 << 9;
    pub const IOS_ARM64: u32 = 1 << 10;

    pub const ALL_WINDOWS: u32 = WINDOWS_X86 | WINDOWS_X64;
    pub const ALL_LINUX: u32 = LINUX_X86 | LINUX_X64 | LINUX_ARM | LINUX_ARM64;
    pub const ALL_MACOS: u32 = MACOS_X64 | MACOS_ARM64;
    pub const ALL_MOBILE: u32 = ANDROID_ARM | ANDROID_ARM64 | IOS_ARM64;
    pub const ALL: u32 = 0xFFFFFFFF;
}

/// Default platform for current build.
#[cfg(target_os = "windows")]
pub const CURRENT_PLATFORM: u32 = platforms::WINDOWS_X64;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub const CURRENT_PLATFORM: u32 = platforms::LINUX_X64;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub const CURRENT_PLATFORM: u32 = platforms::LINUX_ARM64;

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub const CURRENT_PLATFORM: u32 = platforms::MACOS_X64;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub const CURRENT_PLATFORM: u32 = platforms::MACOS_ARM64;

#[cfg(not(any(
    target_os = "windows",
    all(target_os = "linux", target_arch = "x86_64"),
    all(target_os = "linux", target_arch = "aarch64"),
    all(target_os = "macos", target_arch = "x86_64"),
    all(target_os = "macos", target_arch = "aarch64"),
)))]
pub const CURRENT_PLATFORM: u32 = 0;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_constants() {
        assert_eq!(
            platforms::ALL_WINDOWS,
            platforms::WINDOWS_X86 | platforms::WINDOWS_X64
        );
        assert!(CURRENT_PLATFORM != 0);
    }
}
