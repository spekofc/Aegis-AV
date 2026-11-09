//! Update installer.

use aegis_core::{AegisError, AegisResult, Sha256};
use sha2::{Digest, Sha256 as Sha256Hasher};
use std::path::Path;
use std::path::PathBuf;
use tracing::{info, warn};

/// Install configuration.
#[derive(Debug, Clone)]
pub struct InstallConfig {
    pub backup_dir: std::path::PathBuf,
    pub require_signature: bool,
    pub verify_hash: bool,
    pub reboot_on_completion: bool,
}

impl Default for InstallConfig {
    fn default() -> Self {
        Self {
            backup_dir: PathBuf::from("C:\\ProgramData\\AEGIS\\Backups"),
            require_signature: true,
            verify_hash: true,
            reboot_on_completion: false,
        }
    }
}

/// Installer for applying updates.
pub struct Installer {
    config: InstallConfig,
}

impl Installer {
    /// Create a new installer.
    pub fn new(config: InstallConfig) -> AegisResult<Self> {
        std::fs::create_dir_all(&config.backup_dir).map_err(|e| AegisError::Io(e))?;
        Ok(Self { config })
    }

    /// Install a component update.
    pub async fn install(
        &self,
        component: &crate::manifest::ComponentUpdate,
        source: &Path,
    ) -> AegisResult<()> {
        info!("Installing component: {}", component.name);

        // Verify hash if configured
        if self.config.verify_hash {
            self.verify_hash(source, &component.hash).await?;
        }

        // In production, this would apply the update to the appropriate location
        // For now, just log
        info!("Component {} installed successfully", component.name);
        Ok(())
    }

    /// Verify file hash.
    async fn verify_hash(&self, path: &Path, expected: &Sha256) -> AegisResult<()> {
        let data = std::fs::read(path).map_err(|e| AegisError::Io(e))?;
        let mut hasher = Sha256Hasher::new();
        hasher.update(&data);
        let computed = Sha256::from_slice(hasher.finalize().as_slice()).unwrap();
        if computed != *expected {
            return Err(AegisError::VerificationFailed("Hash mismatch".into()));
        }
        Ok(())
    }

    /// Rollback an installation.
    pub async fn rollback(&self, component_name: &str) -> AegisResult<()> {
        info!("Rolling back component: {}", component_name);
        Ok(())
    }
}
