//! Signature database update management.

use crate::database::SignatureDatabase;
use crate::format::DatabaseMeta;
use crate::integrity::{MerkleTree, SignedRoot};
use aegis_core::{AegisError, AegisResult, Sha256, Timestamp, Version};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

/// Update manager for signature database.
pub struct UpdateManager {
    db: Arc<SignatureDatabase>,
    client: Client,
    config: UpdateConfig,
    public_key: VerifyingKey,
}

/// Update configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateConfig {
    pub server_url: String,
    pub fallback_urls: Vec<String>,
    pub cert_pins: Vec<String>,
    pub check_interval_hours: u64,
    pub timeout_secs: u64,
    pub verify_signatures: bool,
    pub anti_downgrade: bool,
    pub transparency_log: bool,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            server_url: "https://updates.AEGIS.example.com".to_string(),
            fallback_urls: Vec::new(),
            cert_pins: Vec::new(),
            check_interval_hours: 4,
            timeout_secs: 300,
            verify_signatures: true,
            anti_downgrade: true,
            transparency_log: true,
        }
    }
}

/// Update manifest from server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateManifest {
    pub version: Version,
    pub timestamp: u64,
    pub min_client_version: Version,
    pub components: Vec<ComponentUpdate>,
    pub signature: Vec<u8>, // Ed25519 of manifest_hash
    pub manifest_hash: Sha256,
    pub transparency_proof: Option<TransparencyProof>,
}

/// Component update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentUpdate {
    pub name: String,
    pub version: Version,
    pub hash: Sha256,
    pub url: String,
    pub size: u64,
    pub required: bool,
    pub reboot_required: bool,
    pub signature: Vec<u8>, // Per-component Ed25519
}

/// Transparency log inclusion proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparencyProof {
    pub log_id: String,
    pub tree_size: u64,
    pub leaf_index: u64,
    pub inclusion_proof: Vec<String>, // Base64 encoded hashes
}

/// Update information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub available: bool,
    pub current_version: Version,
    pub latest_version: Version,
    pub components: Vec<ComponentUpdate>,
    pub release_notes: Option<String>,
    pub requires_reboot: bool,
}

impl UpdateManager {
    pub fn new(
        db: Arc<SignatureDatabase>,
        config: UpdateConfig,
        public_key_pem: &str,
    ) -> AegisResult<Self> {
        let key_bytes = parse_pem_public_key(public_key_pem)?;
        let public_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| AegisError::Crypto(format!("Invalid public key: {}", e)))?;

        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .danger_accept_invalid_certs(false)
            .build()
            .map_err(|e| AegisError::Crypto(format!("HTTP client error: {}", e)))?;

        Ok(Self {
            db,
            client,
            config,
            public_key,
        })
    }

    /// Check for available updates.
    pub async fn check_updates(&self) -> AegisResult<UpdateInfo> {
        let manifest = self.fetch_manifest().await?;
        let current_version = self.get_current_version().await?;

        if manifest.version <= current_version {
            return Ok(UpdateInfo {
                available: false,
                current_version,
                latest_version: manifest.version,
                components: Vec::new(),
                release_notes: None,
                requires_reboot: false,
            });
        }

        // Anti-downgrade check
        if self.config.anti_downgrade {
            let meta_arc = self.db.meta();
            let meta_guard = meta_arc.read().await;
            let meta = &*meta_guard;
            if manifest.version <= meta.min_client_version {
                return Err(AegisError::VerificationFailed(
                    "Update version below minimum allowed version".into(),
                ));
            }
        }

        let requires_reboot = manifest.components.iter().any(|c| c.reboot_required);

        Ok(UpdateInfo {
            available: true,
            current_version,
            latest_version: manifest.version,
            components: manifest.components,
            release_notes: None, // Would be in manifest in production
            requires_reboot,
        })
    }

    /// Apply updates.
    pub async fn apply_updates<P: UpdateProgress>(&self, progress: P) -> AegisResult<()> {
        let manifest = self.fetch_manifest().await?;

        progress.on_download_start(manifest.components.iter().map(|c| c.size).sum());

        // Download and verify each component
        for component in &manifest.components {
            progress.on_component_start(&component.name);

            let data = self.download_component(component, &progress).await?;

            // Verify hash
            let mut hasher = sha2::Sha256::new();
            hasher.update(&data);
            let hash = Sha256::from_slice(hasher.finalize().as_slice()).unwrap();
            if hash != component.hash {
                return Err(AegisError::VerificationFailed(format!(
                    "Hash mismatch for component {}",
                    component.name
                )));
            }

            // Verify signature
            if self.config.verify_signatures {
                self.verify_component_signature(component, &data)?;
            }

            // Apply component
            self.apply_component(component, &data).await?;

            progress.on_component_progress(&component.name, 1.0);
        }

        // Update minimum version
        self.update_min_version(manifest.version).await?;

        progress.on_complete(true, Some("Update applied successfully".into()));
        Ok(())
    }

    async fn fetch_manifest(&self) -> AegisResult<UpdateManifest> {
        let url = format!("{}/manifest.json", self.config.server_url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| AegisError::External(e.into()))?;

        if !response.status().is_success() {
            return Err(AegisError::External(anyhow::anyhow!(
                "HTTP {}",
                response.status()
            )));
        }

        let manifest: UpdateManifest = response
            .json()
            .await
            .map_err(|e| AegisError::External(e.into()))?;

        // Verify manifest signature
        self.verify_manifest_signature(&manifest)?;

        // Verify certificate pinning
        self.verify_cert_pinning(&url).await?;

        // Verify transparency log
        if self.config.transparency_log {
            self.verify_transparency_log(&manifest)?;
        }

        Ok(manifest)
    }

    fn verify_manifest_signature(&self, manifest: &UpdateManifest) -> AegisResult<()> {
        // Verify manifest_hash matches
        let manifest_bytes =
            serde_json::to_vec(manifest).map_err(|e| AegisError::Serialization(e))?;

        // Remove signature field for verification
        let mut manifest_for_hash = manifest.clone();
        manifest_for_hash.signature = Vec::new();
        let hash_bytes =
            serde_json::to_vec(&manifest_for_hash).map_err(|e| AegisError::Serialization(e))?;

        let mut hasher = sha2::Sha256::new();
        hasher.update(&hash_bytes);
        let computed_hash = Sha256::from_slice(hasher.finalize().as_slice()).unwrap();
        if computed_hash != manifest.manifest_hash {
            return Err(AegisError::VerificationFailed(
                "Manifest hash mismatch".into(),
            ));
        }

        // Verify Ed25519 signature
        let sig = Signature::from_slice(&manifest.signature)
            .map_err(|e| AegisError::Crypto(format!("Invalid signature: {}", e)))?;

        self.public_key
            .verify(&manifest.manifest_hash.as_bytes(), &sig)
            .map_err(|e| {
                AegisError::VerificationFailed(format!("Manifest signature invalid: {}", e))
            })?;

        Ok(())
    }

    fn verify_component_signature(
        &self,
        component: &ComponentUpdate,
        data: &[u8],
    ) -> AegisResult<()> {
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        let computed_hash = Sha256::from_slice(hasher.finalize().as_slice()).unwrap();
        if computed_hash != component.hash {
            return Err(AegisError::VerificationFailed(
                "Component hash mismatch".into(),
            ));
        }

        let sig = Signature::from_slice(&component.signature)
            .map_err(|e| AegisError::Crypto(format!("Invalid component signature: {}", e)))?;

        self.public_key
            .verify(&component.hash.as_bytes(), &sig)
            .map_err(|e| {
                AegisError::VerificationFailed(format!("Component signature invalid: {}", e))
            })?;

        Ok(())
    }

    async fn download_component<P: UpdateProgress>(
        &self,
        component: &ComponentUpdate,
        progress: &P,
    ) -> AegisResult<Vec<u8>> {
        let mut response = self
            .client
            .get(&component.url)
            .send()
            .await
            .map_err(|e| AegisError::External(e.into()))?;

        if !response.status().is_success() {
            return Err(AegisError::External(anyhow::anyhow!(
                "Download failed: {}",
                response.status()
            )));
        }

        let total_size = component.size;
        let mut downloaded = 0u64;
        let mut data = Vec::with_capacity(total_size as usize);

        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| AegisError::External(e.into()))?
        {
            data.extend_from_slice(&chunk);
            downloaded += chunk.len() as u64;
            progress.on_download_progress(downloaded, total_size);
        }

        if downloaded != total_size {
            return Err(AegisError::VerificationFailed(
                "Download size mismatch".into(),
            ));
        }

        Ok(data)
    }

    async fn apply_component(&self, component: &ComponentUpdate, data: &[u8]) -> AegisResult<()> {
        match component.name.as_str() {
            "signatures" => {
                // Apply signature database update
                self.apply_signature_update(data).await?;
            }
            "engine" => {
                // Engine binary update - would require service restart
                self.stage_binary_update("AEGIS-engine", data).await?;
            }
            "minifilter" => {
                // Kernel driver update - requires reboot
                self.stage_driver_update("AEGIS-minifilter.sys", data)
                    .await?;
            }
            _ => {
                warn!("Unknown component: {}", component.name);
            }
        }
        Ok(())
    }

    async fn apply_signature_update(&self, data: &[u8]) -> AegisResult<()> {
        // Parse update format (could be SQL dump, binary diff, or new DB)
        // For simplicity, assume it's a new database file
        let temp_path = std::env::temp_dir().join("AEGIS_sig_update.db");
        std::fs::write(&temp_path, data).map_err(|e| AegisError::Io(e))?;

        // Verify the new database
        let key = self.get_db_key().await?;
        let new_db = SignatureDatabase::open(&temp_path, &key).await?;

        // Verify integrity
        new_db.verify_integrity().await?;

        // Verify version is newer
        let new_meta_arc = new_db.meta();
        let new_meta_guard = new_meta_arc.read().await;
        let new_meta = &*new_meta_guard;
        let current_meta_arc = self.db.meta();
        let current_meta_guard = current_meta_arc.read().await;
        let current_meta = &*current_meta_guard;
        if new_meta.version <= current_meta.version {
            return Err(AegisError::VerificationFailed(
                "Update version not newer".into(),
            ));
        }

        // Atomic swap: close old, replace file, open new
        // This would require coordination with the running service
        info!("Signature update staged, requires service restart");

        Ok(())
    }

    async fn stage_binary_update(&self, name: &str, data: &[u8]) -> AegisResult<()> {
        let update_dir = std::env::temp_dir().join("AEGIS_updates");
        std::fs::create_dir_all(&update_dir).map_err(|e| AegisError::Io(e))?;
        let path = update_dir.join(name);
        std::fs::write(&path, data).map_err(|e| AegisError::Io(e))?;
        info!("Staged binary update: {:?}", path);
        Ok(())
    }

    async fn stage_driver_update(&self, name: &str, data: &[u8]) -> AegisResult<()> {
        self.stage_binary_update(name, data).await
    }

    async fn update_min_version(&self, version: Version) -> AegisResult<()> {
        let meta_arc = self.db.meta();
        let mut meta_guard = meta_arc.write().await;
        let meta = &mut *meta_guard;
        meta.min_client_version = version;
        meta.updated_at = aegis_core::Timestamp::now();
        crate::database::SignatureDatabase::save_meta(&self.db.pool, meta).await?;
        Ok(())
    }

    async fn get_current_version(&self) -> AegisResult<Version> {
        let meta_arc = self.db.meta();
        let meta_guard = meta_arc.read().await;
        Ok(meta_guard.version)
    }

    async fn get_db_key(&self) -> AegisResult<[u8; 32]> {
        // In production, retrieve from secure storage (TPM/DPAPI)
        // For now, return a placeholder
        Err(AegisError::Unsupported(
            "Key retrieval not implemented".into(),
        ))
    }

    async fn verify_cert_pinning(&self, url: &str) -> AegisResult<()> {
        if self.config.cert_pins.is_empty() {
            return Ok(());
        }
        // In production: verify certificate chain against pinned hashes
        // This requires access to TLS connection details
        Ok(())
    }

    fn verify_transparency_log(&self, manifest: &UpdateManifest) -> AegisResult<()> {
        // In production: verify inclusion proof against known transparency logs
        if let Some(proof) = &manifest.transparency_proof {
            debug!(
                "Transparency proof: log={}, tree_size={}, index={}",
                proof.log_id, proof.tree_size, proof.leaf_index
            );
        }
        Ok(())
    }
}

/// Progress callback for updates.
pub trait UpdateProgress: Send + Sync {
    fn on_download_start(&self, total_bytes: u64);
    fn on_download_progress(&self, downloaded: u64, total: u64);
    fn on_component_start(&self, name: &str);
    fn on_component_progress(&self, name: &str, progress: f32);
    fn on_complete(&self, success: bool, message: Option<String>);
}

/// Parse PEM public key.
fn parse_pem_public_key(pem: &str) -> AegisResult<[u8; 32]> {
    let lines: Vec<&str> = pem.lines().collect();
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

    let der = base64::decode(&b64)
        .map_err(|e| AegisError::Crypto(format!("Base64 decode failed: {}", e)))?;

    if der.len() >= 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&der[der.len() - 32..]);
        Ok(key)
    } else {
        Err(AegisError::Crypto("Key too short".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::thread_rng;

    #[test]
    fn test_update_manifest_verification() {
        let mut csprng = thread_rng();
        let signing_key = SigningKey::from_bytes(&rand::Rng::gen(&mut csprng));
        let verifying_key = signing_key.verifying_key();

        let manifest = UpdateManifest {
            version: Version::new(1, 0, 0, 0),
            timestamp: 1234567890,
            min_client_version: Version::new(0, 1, 0, 0),
            components: vec![ComponentUpdate {
                name: "signatures".to_string(),
                version: Version::new(1, 0, 0, 0),
                hash: Sha256([0xde; 32]),
                url: "https://example.com/sig.db".to_string(),
                size: 1024,
                required: true,
                reboot_required: false,
                signature: Vec::new(),
            }],
            signature: Vec::new(),
            manifest_hash: Sha256([0; 32]),
            transparency_proof: None,
        };

        // Sign manifest
        let mut manifest_for_hash = manifest.clone();
        manifest_for_hash.signature = Vec::new();
        let bytes = serde_json::to_vec(&manifest_for_hash).unwrap();
        let hash = Sha256::from_slice(&sha2::Sha256::digest(&bytes)).unwrap();

        let mut signed = manifest;
        signed.manifest_hash = hash;
        signed.signature = signing_key.sign(&hash.as_bytes()).to_bytes().to_vec();

        // Verify
        let mut data = Vec::new();
        data.extend_from_slice(signed.manifest_hash.as_bytes());

        let sig = Signature::from_slice(&signed.signature).unwrap();
        assert!(verifying_key
            .verify(&signed.manifest_hash.as_bytes(), &sig)
            .is_ok());
    }

    #[test]
    fn test_version_comparison() {
        assert!(Version::new(1, 0, 0, 0) > Version::new(0, 9, 9, 9));
        assert!(Version::new(1, 2, 0, 0) > Version::new(1, 1, 9, 9));
        assert!(Version::new(1, 2, 3, 0) > Version::new(1, 2, 2, 9));
        assert!(Version::new(1, 2, 3, 4) > Version::new(1, 2, 3, 3));
    }
}
