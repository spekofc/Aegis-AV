//! Secure configuration storage using TPM/DPAPI.

#![allow(unsafe_code)]

use crate::{AegisError, AegisResult};
use base64::{engine::general_purpose, Engine as _};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secure configuration store using Windows DPAPI (with TPM backing when available).
pub struct SecureConfigStore {
    /// Entropy for additional protection.
    entropy: Vec<u8>,
}

impl SecureConfigStore {
    /// Create a new secure store.
    pub fn new() -> AegisResult<Self> {
        // Generate per-machine entropy
        let mut entropy = vec![0u8; 32];
        getrandom::getrandom(&mut entropy)
            .map_err(|e| AegisError::Crypto(format!("Failed to generate entropy: {}", e)))?;

        Ok(Self { entropy })
    }

    /// Create with custom entropy (for testing).
    pub fn with_entropy(entropy: Vec<u8>) -> Self {
        Self { entropy }
    }

    /// Seal (encrypt) data using DPAPI.
    /// Data is encrypted to the current user/machine with optional entropy.
    pub fn seal(&self, data: &[u8]) -> AegisResult<Vec<u8>> {
        #[cfg(windows)]
        {
            use windows::Win32::Foundation::LocalFree;
            use windows::Win32::Security::Cryptography::{
                CryptProtectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPT_INTEGER_BLOB,
            };

            let mut data_blob = CRYPT_INTEGER_BLOB {
                cbData: data.len() as u32,
                pbData: data.as_ptr() as *mut u8,
            };

            let mut entropy_blob = CRYPT_INTEGER_BLOB {
                cbData: self.entropy.len() as u32,
                pbData: self.entropy.as_ptr() as *mut u8,
            };

            let mut out_blob = CRYPT_INTEGER_BLOB::default();

            unsafe {
                CryptProtectData(
                    &mut data_blob,
                    None,
                    Some(&mut entropy_blob),
                    None,
                    None,
                    CRYPTPROTECT_LOCAL_MACHINE,
                    &mut out_blob,
                )
                .map_err(|e| AegisError::Crypto(format!("DPAPI seal failed: {}", e)))?;
            }

            let result = unsafe {
                std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec()
            };

            // Free the allocated memory
            unsafe {
                LocalFree(Some(windows::Win32::Foundation::HLOCAL(
                    out_blob.pbData as _,
                )));
            }

            Ok(result)
        }
        #[cfg(not(windows))]
        {
            // Fallback: encrypt with AES-256-GCM using a key derived from entropy
            use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
            use hkdf::Hkdf;
            use rand::thread_rng;
            use sha2::Sha256;

            let hkdf = Hkdf::<Sha256>::new(None, &self.entropy);
            let mut key = [0u8; 32];
            hkdf.expand(b"aegis-seal", &mut key)
                .map_err(|e| AegisError::Crypto(e.to_string()))?;

            let cipher =
                Aes256Gcm::new_from_slice(&key).map_err(|e| AegisError::Crypto(e.to_string()))?;

            let nonce = Aes256Gcm::generate_nonce(&mut thread_rng());
            let ciphertext = cipher
                .encrypt(&nonce, data)
                .map_err(|e| AegisError::Crypto(e.to_string()))?;

            // Prepend nonce to ciphertext
            let mut result = nonce.to_vec();
            result.extend_from_slice(&ciphertext);
            Ok(result)
        }
    }

    /// Unseal (decrypt) data using DPAPI.
    pub fn unseal(&self, sealed_data: &[u8]) -> AegisResult<Vec<u8>> {
        #[cfg(windows)]
        {
            use windows::Win32::Foundation::LocalFree;
            use windows::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};

            let mut data_blob = CRYPT_INTEGER_BLOB {
                cbData: sealed_data.len() as u32,
                pbData: sealed_data.as_ptr() as *mut u8,
            };

            let mut entropy_blob = CRYPT_INTEGER_BLOB {
                cbData: self.entropy.len() as u32,
                pbData: self.entropy.as_ptr() as *mut u8,
            };

            let mut out_blob = CRYPT_INTEGER_BLOB::default();

            unsafe {
                CryptUnprotectData(
                    &mut data_blob,
                    None,
                    Some(&mut entropy_blob),
                    None,
                    None,
                    0,
                    &mut out_blob,
                )
                .map_err(|e| AegisError::Crypto(format!("DPAPI unseal failed: {}", e)))?;
            }

            let result = unsafe {
                std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec()
            };

            unsafe {
                LocalFree(Some(windows::Win32::Foundation::HLOCAL(
                    out_blob.pbData as _,
                )));
            }

            Ok(result)
        }
        #[cfg(not(windows))]
        {
            use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
            use hkdf::Hkdf;
            use sha2::Sha256;

            if sealed_data.len() < 12 {
                return Err(AegisError::Crypto("Sealed data too short".into()));
            }

            let hkdf = Hkdf::<Sha256>::new(None, &self.entropy);
            let mut key = [0u8; 32];
            hkdf.expand(b"aegis-seal", &mut key)
                .map_err(|e| AegisError::Crypto(e.to_string()))?;

            let cipher =
                Aes256Gcm::new_from_slice(&key).map_err(|e| AegisError::Crypto(e.to_string()))?;

            let (nonce, ciphertext) = sealed_data.split_at(12);
            let plaintext = cipher
                .decrypt(nonce.into(), ciphertext)
                .map_err(|e| AegisError::Crypto(e.to_string()))?;

            Ok(plaintext)
        }
    }

    /// Seal a string.
    pub fn seal_string(&self, s: &str) -> AegisResult<String> {
        let sealed = self.seal(s.as_bytes())?;
        Ok(general_purpose::STANDARD.encode(sealed))
    }

    /// Unseal a string.
    pub fn unseal_string(&self, s: &str) -> AegisResult<String> {
        let sealed = general_purpose::STANDARD
            .decode(s)
            .map_err(|e| AegisError::Crypto(e.to_string()))?;
        let plaintext = self.unseal(&sealed)?;
        String::from_utf8(plaintext).map_err(|e| AegisError::Crypto(e.to_string()))
    }
}

/// Secure string that zeroizes on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureString(String);

impl SecureString {
    pub fn new(s: String) -> Self {
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<String> for SecureString {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for SecureString {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl std::fmt::Debug for SecureString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecureString(***)")
    }
}

impl std::ops::Deref for SecureString {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Secure bytes that zeroize on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureBytes(Vec<u8>);

impl SecureBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        Self(slice.to_vec())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for SecureBytes {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl AsRef<[u8]> for SecureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecureBytes(***)")
    }
}

/// TPM-backed key storage (when available).
pub struct TpmKeyStore {
    /// TPM context (placeholder for tpm2-tss integration).
    context: Option<TpmContext>,
}

struct TpmContext {
    // TPM2-TSS context would go here
}

impl TpmKeyStore {
    /// Create a new TPM key store.
    pub fn new() -> AegisResult<Self> {
        // In production, initialize TPM2-TSS context here
        // For now, return empty context
        Ok(Self { context: None })
    }

    /// Generate and seal a key to TPM.
    pub fn generate_sealed_key(&self, _key_name: &str) -> AegisResult<Vec<u8>> {
        // In production: TPM2_Create + TPM2_EvictControl
        Err(AegisError::Unsupported(
            "TPM key generation not implemented".into(),
        ))
    }

    /// Unseal a key from TPM.
    pub fn unseal_key(&self, _sealed: &[u8]) -> AegisResult<Vec<u8>> {
        // In production: TPM2_Unseal
        Err(AegisError::Unsupported(
            "TPM key unsealing not implemented".into(),
        ))
    }

    /// Seal data to specific PCRs.
    pub fn seal_to_pcrs(&self, _data: &[u8], _pcrs: &[u32]) -> AegisResult<Vec<u8>> {
        Err(AegisError::Unsupported(
            "TPM PCR sealing not implemented".into(),
        ))
    }
}

impl Default for SecureConfigStore {
    fn default() -> Self {
        Self::new().expect("Failed to create SecureConfigStore")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_string() {
        let mut s = SecureString::new("secret".to_string());
        assert_eq!(s.as_str(), "secret");
        s.zeroize();
        assert_eq!(s.as_str(), "");
    }

    #[test]
    fn test_secure_bytes() {
        let mut b = SecureBytes::new(vec![1, 2, 3, 4]);
        assert_eq!(b.as_slice(), &[1, 2, 3, 4]);
        b.zeroize();
        assert_eq!(b.as_slice(), &[] as &[u8]);
    }

    #[test]
    fn test_seal_unseal() {
        let store = SecureConfigStore::new().unwrap();
        let data = b"test secret data";

        let sealed = store.seal(data).unwrap();
        assert_ne!(sealed, data);

        let unsealed = store.unseal(&sealed).unwrap();
        assert_eq!(unsealed, data);
    }

    #[test]
    fn test_seal_string() {
        let store = SecureConfigStore::new().unwrap();
        let s = "secret string";

        let sealed = store.seal_string(s).unwrap();
        assert!(!sealed.is_empty());

        let unsealed = store.unseal_string(&sealed).unwrap();
        assert_eq!(unsealed, s);
    }

    #[test]
    fn test_wrong_entropy_fails() {
        let store1 = SecureConfigStore::new().unwrap();
        let store2 = SecureConfigStore::new().unwrap();

        let data = b"test";
        let sealed = store1.seal(data).unwrap();

        // Different entropy should fail to unseal
        let result = store2.unseal(&sealed);
        assert!(result.is_err());
    }
}
