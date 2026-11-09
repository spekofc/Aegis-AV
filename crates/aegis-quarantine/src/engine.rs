//! Quarantine engine implementation.

use aegis_core::{types::QuarantineId, AegisError, AegisResult, Sha256, ThreatType, Timestamp};
use getrandom::getrandom;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

/// Quarantine configuration.
#[derive(Debug, Clone)]
pub struct QuarantineConfig {
    pub root_path: PathBuf,
    pub max_size_bytes: u64,
    pub max_items: usize,
    pub encrypt_files: bool,
}

impl Default for QuarantineConfig {
    fn default() -> Self {
        let local_quarantine = std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .join("data")
            .join("Quarantine");

        Self {
            root_path: local_quarantine,
            max_size_bytes: 10 * 1024 * 1024 * 1024, // 10 GB
            max_items: 10000,
            encrypt_files: true,
        }
    }
}

/// Quarantined item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineItem {
    pub id: QuarantineId,
    pub path: PathBuf,
    pub original_path: PathBuf,
    pub threat_name: String,
    pub threat_type: ThreatType,
    pub size: u64,
    pub hash: Sha256,
    pub quarantined_at: Timestamp,
    pub encrypted: bool,
}

/// Internal metadata for persisted quarantine items.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct QuarantineMetadata {
    items: HashMap<String, QuarantineItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    encryption_key: Option<[u8; 32]>,
}

/// Quarantine engine for managing quarantined items.
pub struct QuarantineEngine {
    config: QuarantineConfig,
    crypto: Option<crate::crypto::QuarantineCrypto>,
    metadata: Arc<RwLock<QuarantineMetadata>>,
    metadata_path: PathBuf,
}

impl QuarantineEngine {
    /// Create a new quarantine engine.
    pub fn new(config: QuarantineConfig) -> AegisResult<Self> {
        std::fs::create_dir_all(&config.root_path).map_err(|e| AegisError::Io(e))?;

        let metadata_path = config.root_path.join("metadata.json");
        let metadata = if metadata_path.exists() {
            let content = std::fs::read_to_string(&metadata_path).map_err(|e| AegisError::Io(e))?;
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            QuarantineMetadata::default()
        };

        // Get or generate encryption key
        let encryption_key = if config.encrypt_files {
            if let Some(key) = metadata.encryption_key {
                Some(key)
            } else {
                let mut key = [0u8; 32];
                getrandom::getrandom(&mut key)
                    .map_err(|e| AegisError::Crypto(format!("Failed to generate key: {}", e)))?;
                Some(key)
            }
        } else {
            None
        };

        let crypto = if config.encrypt_files {
            Some(crate::crypto::QuarantineCrypto::with_key(
                encryption_key.unwrap(),
            )?)
        } else {
            None
        };

        // Save metadata with key if newly generated
        let mut metadata = metadata;
        if config.encrypt_files && metadata.encryption_key.is_none() {
            metadata.encryption_key = encryption_key;
            let content = serde_json::to_string_pretty(&metadata)
                .map_err(|e| AegisError::Serialization(e))?;
            std::fs::write(&metadata_path, content).map_err(|e| AegisError::Io(e))?;
        }

        Ok(Self {
            config,
            crypto,
            metadata: Arc::new(RwLock::new(metadata)),
            metadata_path,
        })
    }

    fn save_metadata(&self, metadata: &QuarantineMetadata) -> AegisResult<()> {
        let content =
            serde_json::to_string_pretty(metadata).map_err(|e| AegisError::Serialization(e))?;
        std::fs::write(&self.metadata_path, content).map_err(|e| AegisError::Io(e))?;
        Ok(())
    }

    /// Quarantine a file.
    pub async fn quarantine(&self, mut item: QuarantineItem) -> AegisResult<QuarantineItem> {
        info!("Quarantining item: {:?}", item.original_path);

        // Create destination path in quarantine
        let quarantine_filename = format!(
            "{}{}",
            item.id,
            item.original_path
                .extension()
                .map(|e| format!(".{}", e.to_string_lossy()))
                .unwrap_or_default()
        );
        let quarantine_path = self.config.root_path.join(&quarantine_filename);

        // Copy/move file to quarantine
        if let Some(crypto) = &self.crypto {
            // Encrypt the file
            crypto.encrypt_file(&item.original_path, &quarantine_path)?;
            item.path = quarantine_path;
            item.encrypted = true;
        } else {
            // Just move the file
            std::fs::rename(&item.original_path, &quarantine_path)
                .map_err(|e| AegisError::Io(e))?;
            item.path = quarantine_path;
            item.encrypted = false;
        }

        // Update metadata
        let mut metadata = self.metadata.write().await;
        metadata.items.insert(item.id.to_string(), item.clone());
        self.save_metadata(&metadata)?;

        info!(
            "Quarantined item: {} -> {}",
            item.original_path.display(),
            item.path.display()
        );
        Ok(item)
    }

    /// Restore a quarantined item.
    pub async fn restore(&self, item_id: &str, destination: &std::path::Path) -> AegisResult<()> {
        info!("Restoring item {} to {:?}", item_id, destination);

        let mut metadata = self.metadata.write().await;
        let item = metadata.items.get_mut(item_id).ok_or_else(|| {
            AegisError::NotFound(format!("Quarantine item not found: {}", item_id))
        })?;

        if item.encrypted {
            if let Some(crypto) = &self.crypto {
                crypto.decrypt_file(&item.path, destination)?;
            } else {
                return Err(AegisError::Crypto(
                    "File is encrypted but no crypto available".into(),
                ));
            }
        } else {
            std::fs::copy(&item.path, destination).map_err(|e| AegisError::Io(e))?;
        }

        // Optionally remove from quarantine after successful restore
        metadata.items.remove(item_id);
        self.save_metadata(&metadata)?;

        info!("Restored item {} to {:?}", item_id, destination);
        Ok(())
    }

    /// Delete a quarantined item permanently.
    pub async fn delete(&self, item_id: &str) -> AegisResult<()> {
        info!("Deleting quarantined item: {}", item_id);

        let mut metadata = self.metadata.write().await;
        let item = metadata.items.remove(item_id).ok_or_else(|| {
            AegisError::NotFound(format!("Quarantine item not found: {}", item_id))
        })?;

        // Delete the physical file
        if item.path.exists() {
            std::fs::remove_file(&item.path).map_err(|e| AegisError::Io(e))?;
        }

        self.save_metadata(&metadata)?;
        info!("Deleted quarantined item: {}", item_id);
        Ok(())
    }

    /// List all quarantined items.
    pub async fn list(&self) -> AegisResult<Vec<QuarantineItem>> {
        let metadata = self.metadata.read().await;
        Ok(metadata.items.values().cloned().collect())
    }

    /// Get quarantine statistics.
    pub async fn stats(&self) -> AegisResult<QuarantineStats> {
        let metadata = self.metadata.read().await;
        let mut stats = QuarantineStats::default();

        for item in metadata.items.values() {
            stats.total_items += 1;
            stats.total_size_bytes += item.size;
            stats.active_items += 1;
            *stats.by_threat_type.entry(item.threat_type).or_insert(0) += 1;
        }

        Ok(stats)
    }
}

/// Quarantine statistics.
#[derive(Debug, Default, Clone)]
pub struct QuarantineStats {
    pub total_items: u64,
    pub total_size_bytes: u64,
    pub active_items: u64,
    pub by_threat_type: std::collections::HashMap<aegis_core::ThreatType, u64>,
}

impl Default for QuarantineMetadata {
    fn default() -> Self {
        Self {
            items: HashMap::new(),
            encryption_key: None,
        }
    }
}
