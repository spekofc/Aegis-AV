//! Shared types used across AEGIS AV crates.

use bytes::Bytes;
use chrono::{DateTime, Utc};
use hex;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// SHA-256 hash (32 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Sha256(pub [u8; 32]);

impl Sha256 {
    /// Create from raw bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create from slice (must be 32 bytes).
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(slice);
            Some(Self(arr))
        } else {
            None
        }
    }

    /// Get as byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Get as hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string.
    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() == 64 {
            let mut arr = [0u8; 32];
            if hex::decode_to_slice(s, &mut arr).is_ok() {
                return Some(Self(arr));
            }
        }
        None
    }
}

impl fmt::Display for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self([0u8; 32])
    }
}

impl fmt::LowerHex for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl From<[u8; 32]> for Sha256 {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Sha256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Ed25519 public key (32 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Ed25519PublicKey(pub [u8; 32]);

/// Ed25519 signature (64 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ed25519Signature(pub [u8; 64]);

impl serde::Serialize for Ed25519Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> serde::Deserialize<'de> for Ed25519Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("Invalid Ed25519 signature length"));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Ed25519Signature(arr))
    }
}

/// AES-256-GCM key (32 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Aes256Key(pub [u8; 32]);

/// AES-256-GCM nonce (12 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AesGcmNonce(pub [u8; 12]);

/// AES-256-GCM tag (16 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AesGcmTag(pub [u8; 16]);

/// Version with semver-compatible ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
    pub build: u16,
}

impl Version {
    pub const fn new(major: u16, minor: u16, patch: u16, build: u16) -> Self {
        Self {
            major,
            minor,
            patch,
            build,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() >= 3 {
            Some(Self {
                major: parts[0].parse().ok()?,
                minor: parts[1].parse().ok()?,
                patch: parts[2].parse().ok()?,
                build: parts.get(3).and_then(|s| s.parse().ok()).unwrap_or(0),
            })
        } else {
            None
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.build > 0 {
            write!(
                f,
                "{}.{}.{}.{}",
                self.major, self.minor, self.patch, self.build
            )
        } else {
            write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
        }
    }
}

impl Default for Version {
    fn default() -> Self {
        Self::new(0, 0, 0, 0)
    }
}

/// Timestamp in nanoseconds since Unix epoch.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub struct Timestamp(pub u64);

impl Timestamp {
    pub fn now() -> Self {
        let dur = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        Self(dur.as_nanos() as u64)
    }

    pub fn from_secs(secs: u64) -> Self {
        Self(secs.saturating_mul(1_000_000_000))
    }

    pub fn from_millis(millis: u64) -> Self {
        Self(millis.saturating_mul(1_000_000))
    }

    pub fn as_secs(&self) -> u64 {
        self.0 / 1_000_000_000
    }

    pub fn as_millis(&self) -> u64 {
        self.0 / 1_000_000
    }

    pub fn to_datetime(&self) -> DateTime<Utc> {
        DateTime::from_timestamp(self.as_secs() as i64, (self.0 % 1_000_000_000) as u32)
            .unwrap_or_default()
    }
}

impl From<Duration> for Timestamp {
    fn from(d: Duration) -> Self {
        Self(d.as_nanos() as u64)
    }
}

impl From<SystemTime> for Timestamp {
    fn from(t: SystemTime) -> Self {
        t.duration_since(UNIX_EPOCH)
            .map(|d| Self(d.as_nanos() as u64))
            .unwrap_or_default()
    }
}

/// Scan disposition/verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum Disposition {
    /// File/process is clean.
    Clean = 0,
    /// Malicious - block and quarantine.
    Malicious = 1,
    /// Suspicious - monitor/alert.
    Suspicious = 2,
    /// Potentially unwanted application.
    Pua = 3,
    /// Unknown - needs further analysis.
    Unknown = 4,
    /// Error during scan.
    Error = 5,
    /// Deferred - will rescan later.
    Deferred = 6,
}

impl Disposition {
    pub fn is_actionable(&self) -> bool {
        matches!(self, Disposition::Malicious | Disposition::Pua)
    }

    pub fn seAEGIS(&self) -> u8 {
        match self {
            Disposition::Clean => 0,
            Disposition::Unknown => 1,
            Disposition::Suspicious => 2,
            Disposition::Pua => 3,
            Disposition::Malicious => 4,
            Disposition::Error => 5,
            Disposition::Deferred => 1,
        }
    }
}

/// Threat classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum ThreatType {
    Unknown = 0,
    Virus = 1,
    Worm = 2,
    Trojan = 3,
    Ransomware = 4,
    Rootkit = 5,
    Spyware = 6,
    Adware = 7,
    Dropper = 8,
    Loader = 9,
    Backdoor = 10,
    Keylogger = 11,
    Stealer = 12,
    Banker = 13,
    Cryptominer = 14,
    Exploit = 15,
    Packer = 16,
    Obfuscator = 17,
    Pua = 18,
    HackTool = 19,
}

impl TryFrom<u8> for ThreatType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ThreatType::Unknown),
            1 => Ok(ThreatType::Virus),
            2 => Ok(ThreatType::Worm),
            3 => Ok(ThreatType::Trojan),
            4 => Ok(ThreatType::Ransomware),
            5 => Ok(ThreatType::Rootkit),
            6 => Ok(ThreatType::Spyware),
            7 => Ok(ThreatType::Adware),
            8 => Ok(ThreatType::Dropper),
            9 => Ok(ThreatType::Loader),
            10 => Ok(ThreatType::Backdoor),
            11 => Ok(ThreatType::Keylogger),
            12 => Ok(ThreatType::Stealer),
            13 => Ok(ThreatType::Banker),
            14 => Ok(ThreatType::Cryptominer),
            15 => Ok(ThreatType::Exploit),
            16 => Ok(ThreatType::Packer),
            17 => Ok(ThreatType::Obfuscator),
            18 => Ok(ThreatType::Pua),
            19 => Ok(ThreatType::HackTool),
            _ => Err(()),
        }
    }
}

/// Scan context providing environmental information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanContext {
    /// Unique scan ID.
    pub scan_id: Uuid,
    /// Process ID that initiated the scan.
    pub initiator_pid: u32,
    /// Process name.
    pub initiator_name: String,
    /// Scan trigger reason.
    pub trigger: ScanTrigger,
    /// Scan priority (0 = low, 255 = high).
    pub priority: u8,
    /// Deadline for scan completion.
    pub deadline: Option<Timestamp>,
    /// Additional metadata.
    pub metadata: serde_json::Value,
}

/// What triggered the scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ScanTrigger {
    Manual = 0,
    Scheduled = 1,
    RealTimeCreate = 2,
    RealTimeWrite = 3,
    RealTimeExecute = 4,
    OnDemand = 5,
    CloudLookup = 6,
    Remediation = 7,
}

/// Result of a scan operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Scan disposition.
    pub disposition: Disposition,
    /// Threat type if malicious.
    pub threat_type: Option<ThreatType>,
    /// Threat family/name.
    pub threat_name: Option<String>,
    /// Confidence score (0.0 - 1.0).
    pub confidence: f32,
    /// Detection engine that triggered.
    pub engine: DetectionEngine,
    /// Matched signature/rule IDs.
    pub matched_ids: Vec<u64>,
    /// Additional details.
    pub details: serde_json::Value,
    /// Scan duration.
    pub duration: Duration,
}

impl ScanResult {
    /// Create a clean scan result.
    pub fn clean() -> Self {
        Self {
            disposition: Disposition::Clean,
            threat_type: None,
            threat_name: None,
            confidence: 1.0,
            engine: DetectionEngine::Hash,
            matched_ids: Vec::new(),
            details: serde_json::json!({}),
            duration: Duration::from_millis(0),
        }
    }

    /// Create a skipped scan result.
    pub fn skipped(reason: impl Into<String>) -> Self {
        Self {
            disposition: Disposition::Clean,
            threat_type: None,
            threat_name: None,
            confidence: 0.0,
            engine: DetectionEngine::Hash,
            matched_ids: Vec::new(),
            details: serde_json::json!({ "skipped": reason.into() }),
            duration: Duration::from_millis(0),
        }
    }
}

/// Detection engine identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum DetectionEngine {
    Hash = 1,
    Pattern = 2,
    Heuristic = 3,
    MachineLearning = 4,
    Behavioral = 5,
    Cloud = 6,
    Reputation = 7,
}

/// Signature match result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureMatch {
    /// Signature database ID.
    pub id: u64,
    /// Signature hash (for hash-based signatures).
    pub hash: Option<Sha256>,
    /// Signature type.
    pub sig_type: u8,
    /// Threat family.
    pub family: String,
    /// Threat type.
    pub threat_type: ThreatType,
    /// SeAEGIS (1-5).
    pub seAEGIS: u8,
    /// Target platforms (bitmask).
    pub platforms: u32,
    /// Description.
    pub description: String,
    /// Detection engine.
    pub engine: DetectionEngine,
}

/// Pattern match result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatch {
    /// Pattern ID.
    pub id: u64,
    /// Offset in file where match occurred.
    pub offset: u64,
    /// Matched bytes length.
    pub length: u32,
    /// Signature this pattern belongs to.
    pub signature_id: u64,
}

/// Quarantine metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineMetadata {
    /// Original file path.
    pub original_path: PathBuf,
    /// Original file size.
    pub original_size: u64,
    /// File SHA-256.
    pub file_hash: Sha256,
    /// Threat information.
    pub threat_name: Option<String>,
    pub threat_type: Option<ThreatType>,
    /// Scan result that triggered quarantine.
    pub scan_result: ScanResult,
    /// Quarantine timestamp.
    pub quarantined_at: Timestamp,
    /// User/SID who initiated.
    pub initiator_sid: Option<String>,
    /// Original file attributes.
    pub file_attributes: u32,
    /// Original creation time.
    pub creation_time: Option<Timestamp>,
    /// Original modification time.
    pub modification_time: Option<Timestamp>,
}

/// Quarantine entry for listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: Uuid,
    pub metadata: QuarantineMetadata,
    pub status: QuarantineStatus,
}

/// Quarantine entry status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuarantineStatus {
    Active,
    Restored,
    Destroyed,
    PendingRestore,
}

/// Quarantine identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QuarantineId(pub Uuid);

impl QuarantineId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for QuarantineId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for QuarantineId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Process information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub path: Option<PathBuf>,
    pub command_line: Option<String>,
    pub user_sid: Option<String>,
    pub integrity_level: IntegrityLevel,
    pub start_time: Timestamp,
    pub is_protected: bool,
    pub is_wow64: bool,
}

/// Integrity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum IntegrityLevel {
    Untrusted = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    System = 4,
    ProtectedProcess = 5,
    SecureProcess = 6,
}

/// File information for scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub path: PathBuf,
    pub size: u64,
    pub hash: Option<Sha256>,
    pub attributes: u32,
    pub creation_time: Timestamp,
    pub modification_time: Timestamp,
    pub is_pe: bool,
    pub pe_info: Option<PeInfo>,
}

/// PE file information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeInfo {
    pub is_pe: bool,
    pub is_64bit: bool,
    pub machine: u16,
    pub entry_point: u64,
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<String>,
    pub authenticode: Option<AuthenticodeInfo>,
    pub overlay: Option<OverlayInfo>,
    pub rich_header: Option<RichHeaderInfo>,
}

/// PE section information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub characteristics: u32,
    pub entropy: f64,
}

/// PE import information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportInfo {
    pub dll: String,
    pub functions: Vec<String>,
    pub name: Option<String>,
    pub ordinal: Option<u16>,
}

/// Authenticode signature information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticodeInfo {
    pub is_signed: bool,
    pub publisher: Option<String>,
    pub issuer: Option<String>,
    pub timestamp: Option<Timestamp>,
    pub chain_valid: bool,
}

/// Overlay information (appended data).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayInfo {
    pub offset: u64,
    pub size: u64,
    pub entropy: f64,
}

/// Rich header information (Visual Studio build info).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichHeaderInfo {
    pub entries: Vec<RichEntry>,
}

/// Rich header entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichEntry {
    pub id: u16,
    pub build: u16,
    pub count: u32,
}

/// Engine status for health checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineStatus {
    pub version: Version,
    pub uptime: Duration,
    pub signatures_version: Version,
    pub signatures_count: u64,
    pub last_update: Option<Timestamp>,
    pub realtime_active: bool,
    pub quarantine_count: u64,
    pub memory_usage_mb: u64,
    pub cpu_usage_percent: f32,
    pub errors_last_hour: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hex() {
        let hash = Sha256([0xde; 32]);
        let hex = hash.to_hex();
        assert_eq!(hex.len(), 64);
        let parsed = Sha256::from_hex(&hex).unwrap();
        assert_eq!(hash, parsed);
    }

    #[test]
    fn test_version_parse() {
        let v = Version::parse("1.2.3.4").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
        assert_eq!(v.build, 4);

        let v = Version::parse("1.2.3").unwrap();
        assert_eq!(v.build, 0);
    }

    #[test]
    fn test_version_ordering() {
        assert!(Version::new(1, 0, 0, 0) < Version::new(2, 0, 0, 0));
        assert!(Version::new(1, 2, 0, 0) < Version::new(1, 3, 0, 0));
        assert!(Version::new(1, 2, 3, 0) < Version::new(1, 2, 4, 0));
        assert!(Version::new(1, 2, 3, 4) < Version::new(1, 2, 3, 5));
    }

    #[test]
    fn test_timestamp() {
        let ts = Timestamp::from_secs(100);
        assert_eq!(ts.as_secs(), 100);
        assert_eq!(ts.as_millis(), 100_000);
    }

    #[test]
    fn test_disposition() {
        assert!(Disposition::Malicious.is_actionable());
        assert!(Disposition::Pua.is_actionable());
        assert!(!Disposition::Suspicious.is_actionable());
        assert!(!Disposition::Clean.is_actionable());
    }

    #[test]
    fn test_quarantine_id() {
        let id1 = QuarantineId::new();
        let id2 = QuarantineId::new();
        assert_ne!(id1, id2);
    }
}
