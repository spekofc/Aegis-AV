//! Test fixtures for AEGIS AV.

use aegis_core::{types::Sha256, AegisError, AegisResult};
use std::path::PathBuf;
use tempfile::TempDir;

/// Test fixture configuration.
#[derive(Debug, Clone)]
pub struct FixtureConfig {
    pub temp_dir: Option<PathBuf>,
    pub create_test_files: bool,
}

impl Default for FixtureConfig {
    fn default() -> Self {
        Self {
            temp_dir: None,
            create_test_files: true,
        }
    }
}

/// Test fixtures manager.
pub struct TestFixtures {
    temp_dir: TempDir,
    config: FixtureConfig,
}

impl TestFixtures {
    /// Create new test fixtures.
    pub fn new(config: FixtureConfig) -> AegisResult<Self> {
        let temp_dir = if let Some(ref path) = config.temp_dir {
            TempDir::new_in(path).map_err(|e| AegisError::Io(e))?
        } else {
            TempDir::new().map_err(|e| AegisError::Io(e))?
        };

        Ok(Self { temp_dir, config })
    }

    /// Get the temporary directory path.
    pub fn path(&self) -> &std::path::Path {
        self.temp_dir.path()
    }

    /// Create a test file with specific content.
    pub fn create_file(&self, name: &str, content: &[u8]) -> AegisResult<PathBuf> {
        let file_path = self.temp_dir.path().join(name);
        std::fs::write(&file_path, content).map_err(|e| AegisError::Io(e))?;
        Ok(file_path)
    }

    /// Create a PE test file (minimal valid PE).
    pub fn create_pe_file(&self, name: &str) -> AegisResult<PathBuf> {
        // Minimal PE header (DOS + PE signature)
        let mut pe_data = vec![0x4D, 0x5A]; // MZ signature
        pe_data.extend_from_slice(&[0u8; 58]); // DOS stub
        pe_data.extend_from_slice(&[0x50, 0x45, 0x00, 0x00]); // PE signature
        pe_data.extend_from_slice(&[0u8; 200]); // Minimal PE headers

        self.create_file(name, &pe_data)
    }

    /// Get SHA256 of a file.
    pub fn file_hash(&self, name: &str) -> AegisResult<Sha256> {
        let path = self.temp_dir.path().join(name);
        let data = std::fs::read(path).map_err(|e| AegisError::Io(e))?;
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&data);
        Ok(aegis_core::Sha256::from_slice(hasher.finalize().as_slice()).unwrap())
    }
}
