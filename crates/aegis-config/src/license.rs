//! License management for AEGIS AV.

use aegis_core::{types::Sha256, AegisError, AegisResult};
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hostname;
use rand::thread_rng;
use sha2::{Digest, Sha256 as Sha256Digest};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

/// License entitlements bitmask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entitlements(u64);

impl Entitlements {
    pub const SCAN: u64 = 1 << 0;
    pub const REALTIME: u64 = 1 << 1;
    pub const QUARANTINE: u64 = 1 << 2;
    pub const ANTIEXPLOIT: u64 = 1 << 3;
    pub const VPN: u64 = 1 << 4;
    pub const CLOUD_LOOKUP: u64 = 1 << 5;
    pub const ENTERPRISE_API: u64 = 1 << 6;
    pub const CUSTOM_RULES: u64 = 1 << 7;
    pub const PRIORITY_SUPPORT: u64 = 1 << 8;

    pub fn new(bits: u64) -> Self {
        Self(bits)
    }

    pub fn has(&self, entitlement: u64) -> bool {
        (self.0 & entitlement) != 0
    }

    pub fn bits(&self) -> u64 {
        self.0
    }
}

impl Default for Entitlements {
    fn default() -> Self {
        Self(Self::SCAN | Self::REALTIME | Self::QUARANTINE)
    }
}

impl std::fmt::Display for Entitlements {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut names = Vec::new();
        if self.has(Self::SCAN) {
            names.push("scan");
        }
        if self.has(Self::REALTIME) {
            names.push("realtime");
        }
        if self.has(Self::QUARANTINE) {
            names.push("quarantine");
        }
        if self.has(Self::ANTIEXPLOIT) {
            names.push("antiexploit");
        }
        if self.has(Self::VPN) {
            names.push("vpn");
        }
        if self.has(Self::CLOUD_LOOKUP) {
            names.push("cloud_lookup");
        }
        if self.has(Self::ENTERPRISE_API) {
            names.push("enterprise_api");
        }
        if self.has(Self::CUSTOM_RULES) {
            names.push("custom_rules");
        }
        if self.has(Self::PRIORITY_SUPPORT) {
            names.push("priority_support");
        }
        write!(f, "{}", names.join(", "))
    }
}

/// License information.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LicenseInfo {
    pub license_type: String,
    pub entitlements: u64,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    #[serde(
        serialize_with = "serialize_sha256",
        deserialize_with = "deserialize_sha256"
    )]
    pub hardware_id: Sha256,
    pub signature: Vec<u8>, // Ed25519 signature
}

/// License manager for validation and enforcement.
pub struct LicenseManager {
    public_key: VerifyingKey,
    current_license: Option<LicenseInfo>,
}

fn serialize_sha256<S>(sha: &Sha256, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&sha.to_hex())
}

fn deserialize_sha256<'de, D>(deserializer: D) -> Result<Sha256, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = <String as serde::Deserialize>::deserialize(deserializer)?;
    Sha256::from_hex(&s).ok_or_else(|| serde::de::Error::custom("Invalid SHA256 hex string"))
}

impl LicenseManager {
    /// Create a new license manager with the vendor's public key.
    pub fn new(public_key_pem: &str) -> AegisResult<Self> {
        // Parse PEM public key
        let key_bytes = parse_pem_public_key(public_key_pem)?;
        let public_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| AegisError::Crypto(format!("Invalid public key: {}", e)))?;

        Ok(Self {
            public_key,
            current_license: None,
        })
    }

    /// Load and validate a license.
    pub fn load_license(&mut self, license: LicenseInfo) -> AegisResult<()> {
        // Verify signature
        self.verify_license_signature(&license)?;

        // Check expiration
        if let Some(expires) = license.expires_at {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            if now > expires {
                return Err(AegisError::VerificationFailed("License expired".into()));
            }
        }

        // Verify hardware ID (simplified - in production use TPM)
        let current_hwid = get_hardware_id()?;
        if license.hardware_id != current_hwid {
            warn!("License hardware ID mismatch");
            return Err(AegisError::VerificationFailed(
                "Hardware ID mismatch".into(),
            ));
        }

        self.current_license = Some(license);
        info!("License loaded successfully");
        Ok(())
    }

    /// Verify license signature.
    fn verify_license_signature(&self, license: &LicenseInfo) -> AegisResult<()> {
        // Create the data that was signed (all fields except signature)
        let mut data = Vec::new();
        data.extend_from_slice(license.license_type.as_bytes());
        data.extend_from_slice(&license.entitlements.to_le_bytes());
        data.extend_from_slice(&license.issued_at.to_le_bytes());
        if let Some(exp) = license.expires_at {
            data.extend_from_slice(&exp.to_le_bytes());
        } else {
            data.extend_from_slice(&0u64.to_le_bytes());
        }
        data.extend_from_slice(license.hardware_id.as_bytes());

        let signature = Signature::from_slice(&license.signature)
            .map_err(|e| AegisError::Crypto(format!("Invalid signature format: {}", e)))?;

        self.public_key.verify(&data, &signature).map_err(|e| {
            AegisError::VerificationFailed(format!("Signature verification failed: {}", e))
        })?;

        Ok(())
    }

    /// Check if a specific entitlement is granted.
    pub fn has_entitlement(&self, entitlement: u64) -> bool {
        self.current_license
            .as_ref()
            .map(|l| Entitlements::new(l.entitlements).has(entitlement))
            .unwrap_or(false)
    }

    /// Get current license info.
    pub fn license_info(&self) -> Option<&LicenseInfo> {
        self.current_license.as_ref()
    }

    /// Get entitlements.
    pub fn entitlements(&self) -> Entitlements {
        self.current_license
            .as_ref()
            .map(|l| Entitlements::new(l.entitlements))
            .unwrap_or_default()
    }

    /// Check if license is valid (not expired).
    pub fn is_valid(&self) -> bool {
        self.current_license
            .as_ref()
            .map(|l| {
                if let Some(exp) = l.expires_at {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    now <= exp
                } else {
                    true
                }
            })
            .unwrap_or(false)
    }

    /// Get days until expiration.
    pub fn days_until_expiration(&self) -> Option<u64> {
        self.current_license.as_ref().and_then(|l| {
            l.expires_at.map(|exp| {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if exp > now {
                    (exp - now) / 86400
                } else {
                    0
                }
            })
        })
    }
}

/// Parse PEM-encoded Ed25519 public key.
fn parse_pem_public_key(pem: &str) -> AegisResult<[u8; 32]> {
    let lines: Vec<&str> = pem.lines().collect();
    if lines.len() < 3 {
        return Err(AegisError::Crypto("Invalid PEM format".into()));
    }

    // Find base64 content between BEGIN/END markers
    let mut b64 = String::new();
    let mut in_key = false;
    for line in lines {
        if line.contains("BEGIN PUBLIC KEY") || line.contains("BEGIN ED25519 PUBLIC KEY") {
            in_key = true;
            continue;
        }
        if line.contains("END PUBLIC KEY") || line.contains("END ED25519 PUBLIC KEY") {
            break;
        }
        if in_key {
            b64.push_str(line.trim());
        }
    }

    let der = general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| AegisError::Crypto(format!("Base64 decode failed: {}", e)))?;

    // Parse SPKI (SubjectPublicKeyInfo) to extract raw key
    // Ed25519 OID: 1.3.101.112
    // For simplicity, assume raw key is last 32 bytes of DER
    if der.len() >= 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&der[der.len() - 32..]);
        Ok(key)
    } else {
        Err(AegisError::Crypto("Key too short".into()))
    }
}

/// Get hardware ID for license binding.
fn get_hardware_id() -> AegisResult<Sha256> {
    // In production: use TPM EK cert, motherboard serial, CPU ID, etc.
    // For now, generate a stable machine ID
    use std::process::Command;

    #[cfg(windows)]
    {
        // Try to get machine GUID from registry
        let output = Command::new("cmd")
            .args([
                "/c",
                "reg query HKLM\\SOFTWARE\\Microsoft\\Cryptography /v MachineGuid",
            ])
            .output()
            .map_err(|e| AegisError::Io(e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        if let Some(guid_line) = stdout.lines().find(|l| l.contains("MachineGuid")) {
            if let Some(guid) = guid_line.split_whitespace().last() {
                let mut hasher = Sha256Digest::new();
                hasher.update(guid.as_bytes());
                let result = hasher.finalize();
                let mut hwid = [0u8; 32];
                hwid.copy_from_slice(&result);
                return Ok(Sha256(hwid));
            }
        }
    }

    // Fallback: hash of hostname + MAC addresses
    let hostname = hostname::get()
        .map_err(|e| AegisError::Crypto(e.to_string()))?
        .to_string_lossy()
        .to_string();

    let mut hasher = Sha256Digest::new();
    hasher.update(hostname.as_bytes());
    hasher.update(b"aegis-hwid-salt");
    let result = hasher.finalize();
    let mut hwid = [0u8; 32];
    hwid.copy_from_slice(&result);
    Ok(Sha256(hwid))
}

/// Create a license (vendor side).
pub fn create_license(
    license_type: String,
    entitlements: Entitlements,
    expires_at: Option<u64>,
    hardware_id: Sha256,
    private_key: &SigningKey,
) -> LicenseInfo {
    let issued_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut data = Vec::new();
    data.extend_from_slice(license_type.as_bytes());
    data.extend_from_slice(&entitlements.bits().to_le_bytes());
    data.extend_from_slice(&issued_at.to_le_bytes());
    data.extend_from_slice(&expires_at.unwrap_or(0).to_le_bytes());
    data.extend_from_slice(hardware_id.as_bytes());

    let signature = private_key.sign(&data);

    LicenseInfo {
        license_type,
        entitlements: entitlements.bits(),
        issued_at,
        expires_at,
        hardware_id,
        signature: signature.to_bytes().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::thread_rng;

    #[test]
    fn test_entitlements() {
        let e = Entitlements::new(Entitlements::SCAN | Entitlements::REALTIME);
        assert!(e.has(Entitlements::SCAN));
        assert!(e.has(Entitlements::REALTIME));
        assert!(!e.has(Entitlements::QUARANTINE));
    }

    #[test]
    fn test_license_creation_and_verification() {
        let mut csprng = thread_rng();
        let signing_key_bytes: [u8; 32] = rand::Rng::gen(&mut csprng);
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);
        let verifying_key = signing_key.verifying_key();

        // Use actual hardware ID for test
        let hwid = get_hardware_id().unwrap();
        let license = create_license(
            "pro".to_string(),
            Entitlements::new(
                Entitlements::SCAN | Entitlements::REALTIME | Entitlements::QUARANTINE,
            ),
            Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + 86400 * 365,
            ),
            hwid,
            &signing_key,
        );

        // Verify using the manager
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            general_purpose::STANDARD.encode(verifying_key.to_bytes())
        );

        let mut manager = LicenseManager::new(&pem).unwrap();
        manager.load_license(license.clone()).unwrap();

        assert!(manager.has_entitlement(Entitlements::SCAN));
        assert!(manager.has_entitlement(Entitlements::REALTIME));
        assert!(manager.has_entitlement(Entitlements::QUARANTINE));
        assert!(!manager.has_entitlement(Entitlements::VPN));
        assert!(manager.is_valid());
    }

    #[test]
    fn test_expired_license() {
        let mut csprng = thread_rng();
        let signing_key_bytes: [u8; 32] = rand::Rng::gen(&mut csprng);
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);
        let verifying_key = signing_key.verifying_key();

        // Use actual hardware ID for test
        let hwid = get_hardware_id().unwrap();
        let license = create_license(
            "trial".to_string(),
            Entitlements::default(),
            Some(1), // Expired
            hwid,
            &signing_key,
        );

        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            general_purpose::STANDARD.encode(verifying_key.to_bytes())
        );

        let mut manager = LicenseManager::new(&pem).unwrap();
        let result = manager.load_license(license);
        assert!(result.is_err());
    }
}
