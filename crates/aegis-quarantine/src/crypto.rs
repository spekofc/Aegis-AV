//! Quarantine encryption utilities.

use aegis_core::{AegisError, AegisResult};
use aes_gcm::{
    aead::{Aead, AeadCore},
    Aes256Gcm, KeyInit,
};
use hkdf::Hkdf;
use rand::thread_rng;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Quarantine crypto for file encryption.
pub struct QuarantineCrypto {
    key: [u8; 32],
}

impl QuarantineCrypto {
    /// Create a new quarantine crypto instance with a random key.
    pub fn new() -> AegisResult<Self> {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key)
            .map_err(|e| AegisError::Crypto(format!("Failed to generate key: {}", e)))?;
        Ok(Self { key })
    }

    /// Create a quarantine crypto instance with a specific key.
    pub fn with_key(key: [u8; 32]) -> AegisResult<Self> {
        Ok(Self { key })
    }

    /// Encrypt a file.
    pub fn encrypt_file(
        &self,
        source: &std::path::Path,
        dest: &std::path::Path,
    ) -> AegisResult<()> {
        let data = std::fs::read(source).map_err(|e| AegisError::Io(e))?;
        let encrypted = self.encrypt(&data)?;
        std::fs::write(dest, encrypted).map_err(|e| AegisError::Io(e))?;
        Ok(())
    }

    /// Decrypt a file.
    pub fn decrypt_file(
        &self,
        source: &std::path::Path,
        dest: &std::path::Path,
    ) -> AegisResult<()> {
        let data = std::fs::read(source).map_err(|e| AegisError::Io(e))?;
        let decrypted = self.decrypt(&data)?;
        std::fs::write(dest, decrypted).map_err(|e| AegisError::Io(e))?;
        Ok(())
    }

    /// Encrypt data.
    pub fn encrypt(&self, data: &[u8]) -> AegisResult<Vec<u8>> {
        let cipher =
            Aes256Gcm::new_from_slice(&self.key).map_err(|e| AegisError::Crypto(e.to_string()))?;
        let nonce = Aes256Gcm::generate_nonce(&mut thread_rng());
        let ciphertext = cipher
            .encrypt(&nonce, data)
            .map_err(|e| AegisError::Crypto(e.to_string()))?;
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt data.
    pub fn decrypt(&self, data: &[u8]) -> AegisResult<Vec<u8>> {
        if data.len() < 12 {
            return Err(AegisError::Crypto("Data too short".into()));
        }
        let cipher =
            Aes256Gcm::new_from_slice(&self.key).map_err(|e| AegisError::Crypto(e.to_string()))?;
        let (nonce, ciphertext) = data.split_at(12);
        let plaintext = cipher
            .decrypt(nonce.into(), ciphertext)
            .map_err(|e| AegisError::Crypto(e.to_string()))?;
        Ok(plaintext)
    }
}

/// File encryption metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileCrypto {
    pub algorithm: String,
    pub key_id: String,
    pub nonce: Vec<u8>,
    pub tag: Vec<u8>,
}

impl FileCrypto {
    /// Create new file crypto metadata.
    pub fn new(algorithm: String, key_id: String, nonce: Vec<u8>, tag: Vec<u8>) -> Self {
        Self {
            algorithm,
            key_id,
            nonce,
            tag,
        }
    }
}
