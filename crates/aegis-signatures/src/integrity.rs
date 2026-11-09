//! Database integrity verification using Merkle trees.

use crate::format::DatabaseMeta;
use aegis_core::{types::Sha256, AegisError, AegisResult};
use ed25519_dalek::{Signer, Verifier};
use sha2::{Digest, Sha256 as Sha256Hasher};
use sqlx::{Row, SqlitePool};
use std::collections::HashMap;
use tracing::{debug, warn};

/// Integrity verifier for signature database.
pub struct IntegrityVerifier {
    key: [u8; 32],
}

impl IntegrityVerifier {
    pub fn new(key: &[u8; 32]) -> Self {
        Self { key: *key }
    }

    /// Verify database integrity against stored Merkle root.
    pub async fn verify_database(
        &self,
        pool: &SqlitePool,
        meta: &DatabaseMeta,
    ) -> AegisResult<bool> {
        let computed_root = MerkleTree::compute_database_root(pool).await?;

        if computed_root != meta.merkle_root {
            warn!("Database integrity check failed: Merkle root mismatch");
            warn!("Expected: {}", meta.merkle_root);
            warn!("Computed: {}", computed_root);
            return Ok(false);
        }

        debug!("Database integrity verified");
        Ok(true)
    }

    /// Verify a specific signature's inclusion proof.
    pub async fn verify_signature_inclusion(
        &self,
        pool: &SqlitePool,
        signature_id: u64,
    ) -> AegisResult<InclusionProof> {
        MerkleTree::generate_inclusion_proof(pool, signature_id).await
    }

    /// Verify manifest hash.
    pub fn verify_manifest(
        &self,
        manifest_bytes: &[u8],
        expected_hash: &Sha256,
    ) -> AegisResult<bool> {
        let mut hasher = Sha256Hasher::new();
        hasher.update(manifest_bytes);
        let computed = Sha256::from_slice(hasher.finalize().as_slice()).unwrap();
        Ok(computed == *expected_hash)
    }
}

/// Merkle tree for database integrity.
pub struct MerkleTree;

impl MerkleTree {
    /// Compute the Merkle root of the entire database.
    pub async fn compute_database_root(pool: &SqlitePool) -> AegisResult<Sha256> {
        // Get all signature hashes in deterministic order
        let rows = sqlx::query(
            "SELECT id, hash, family, threat_type, seAEGIS, created_at FROM signatures ORDER BY id",
        )
        .fetch_all(pool)
        .await
        .map_err(|e| AegisError::Database(e))?;

        let mut leaf_hashes = Vec::new();

        for row in rows {
            let id: i64 = row.get("id");
            let hash: Option<Vec<u8>> = row.get("hash");
            let family: String = row.get("family");
            let threat_type: i32 = row.get("threat_type");
            let seAEGIS: i32 = row.get("seAEGIS");
            let created_at: i64 = row.get("created_at");

            // Create leaf data: ID + hash + metadata
            let mut leaf_data = Vec::new();
            leaf_data.extend_from_slice(&id.to_le_bytes());
            if let Some(h) = hash {
                leaf_data.extend_from_slice(&h);
            } else {
                leaf_data.extend_from_slice(&[0u8; 32]);
            }
            leaf_data.extend_from_slice(family.as_bytes());
            leaf_data.extend_from_slice(&threat_type.to_le_bytes());
            leaf_data.extend_from_slice(&seAEGIS.to_le_bytes());
            leaf_data.extend_from_slice(&created_at.to_le_bytes());

            // Hash the leaf
            let mut hasher = Sha256Hasher::new();
            hasher.update(&leaf_data);
            leaf_hashes.push(Sha256::from_slice(hasher.finalize().as_slice()).unwrap());
        }

        // Also include pattern data
        let pat_rows = sqlx::query("SELECT id, signature_id, pattern FROM patterns ORDER BY id")
            .fetch_all(pool)
            .await
            .map_err(|e| AegisError::Database(e))?;

        for row in pat_rows {
            let id: i64 = row.get("id");
            let sig_id: i64 = row.get("signature_id");
            let pattern: Vec<u8> = row.get("pattern");

            let mut leaf_data = Vec::new();
            leaf_data.extend_from_slice(&id.to_le_bytes());
            leaf_data.extend_from_slice(&sig_id.to_le_bytes());
            leaf_data.extend_from_slice(&pattern);

            let mut hasher = Sha256Hasher::new();
            hasher.update(&leaf_data);
            leaf_hashes.push(Sha256::from_slice(hasher.finalize().as_slice()).unwrap());
        }

        // Compute Merkle root
        let root = Self::compute_root(&leaf_hashes);
        Ok(root)
    }

    /// Generate inclusion proof for a signature.
    pub async fn generate_inclusion_proof(
        pool: &SqlitePool,
        signature_id: u64,
    ) -> AegisResult<InclusionProof> {
        // Find the leaf index
        let rows = sqlx::query("SELECT id FROM signatures ORDER BY id")
            .fetch_all(pool)
            .await
            .map_err(|e| AegisError::Database(e))?;

        let mut leaf_index = None;
        for (idx, row) in rows.iter().enumerate() {
            let id: i64 = row.get("id");
            if id == signature_id as i64 {
                leaf_index = Some(idx);
                break;
            }
        }

        let leaf_index =
            leaf_index.ok_or_else(|| AegisError::NotFound("Signature not found".into()))?;

        // Build all leaves
        let mut leaf_hashes = Vec::new();
        for row in rows {
            let id: i64 = row.get("id");
            let hash: Option<Vec<u8>> = row.get("hash");
            let family: String = row.get("family");
            let threat_type: i32 = row.get("threat_type");
            let seAEGIS: i32 = row.get("seAEGIS");
            let created_at: i64 = row.get("created_at");

            let mut leaf_data = Vec::new();
            leaf_data.extend_from_slice(&id.to_le_bytes());
            if let Some(h) = hash {
                leaf_data.extend_from_slice(&h);
            } else {
                leaf_data.extend_from_slice(&[0u8; 32]);
            }
            leaf_data.extend_from_slice(family.as_bytes());
            leaf_data.extend_from_slice(&threat_type.to_le_bytes());
            leaf_data.extend_from_slice(&seAEGIS.to_le_bytes());
            leaf_data.extend_from_slice(&created_at.to_le_bytes());

            let mut hasher = Sha256Hasher::new();
            hasher.update(&leaf_data);
            leaf_hashes.push(Sha256::from_slice(hasher.finalize().as_slice()).unwrap());
        }

        // Generate proof
        let proof = Self::generate_proof(&leaf_hashes, leaf_index);
        let root = Self::compute_root(&leaf_hashes);

        Ok(InclusionProof {
            leaf_index,
            leaf_hash: leaf_hashes[leaf_index],
            root,
            siblings: proof,
        })
    }

    /// Compute Merkle root from leaf hashes.
    fn compute_root(leaves: &[Sha256]) -> Sha256 {
        if leaves.is_empty() {
            return Sha256::default();
        }

        let mut current: Vec<Sha256> = leaves.to_vec();

        while current.len() > 1 {
            let mut next = Vec::new();
            for chunk in current.chunks(2) {
                let mut hasher = Sha256Hasher::new();
                hasher.update(chunk[0].as_bytes());
                if chunk.len() == 2 {
                    hasher.update(chunk[1].as_bytes());
                } else {
                    // Odd number - duplicate last
                    hasher.update(chunk[0].as_bytes());
                }
                next.push(Sha256::from_slice(hasher.finalize().as_slice()).unwrap());
            }
            current = next;
        }

        current[0]
    }

    /// Generate Merkle proof (sibling hashes).
    fn generate_proof(leaves: &[Sha256], index: usize) -> Vec<Sha256> {
        let mut proof = Vec::new();
        let mut current_index = index;
        let mut current_level = leaves.to_vec();

        while current_level.len() > 1 {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            if sibling_index < current_level.len() {
                proof.push(current_level[sibling_index]);
            } else {
                // No sibling (odd number at this level)
                proof.push(current_level[current_index]);
            }

            current_index /= 2;

            // Build next level
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                let mut hasher = Sha256Hasher::new();
                hasher.update(chunk[0].as_bytes());
                if chunk.len() == 2 {
                    hasher.update(chunk[1].as_bytes());
                } else {
                    hasher.update(chunk[0].as_bytes());
                }
                next_level.push(Sha256::from_slice(hasher.finalize().as_slice()).unwrap());
            }
            current_level = next_level;
        }

        proof
    }

    /// Verify an inclusion proof.
    pub fn verify_proof(proof: &InclusionProof) -> bool {
        let mut current = proof.leaf_hash;
        let mut index = proof.leaf_index;

        for sibling in &proof.siblings {
            let mut hasher = Sha256Hasher::new();
            if index % 2 == 0 {
                hasher.update(current.as_bytes());
                hasher.update(sibling.as_bytes());
            } else {
                hasher.update(sibling.as_bytes());
                hasher.update(current.as_bytes());
            }
            current = Sha256::from_slice(hasher.finalize().as_slice()).unwrap();
            index /= 2;
        }

        current == proof.root
    }
}

/// Inclusion proof for a signature.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct InclusionProof {
    pub leaf_index: usize,
    pub leaf_hash: Sha256,
    pub root: Sha256,
    pub siblings: Vec<Sha256>,
}

impl InclusionProof {
    pub fn verify(&self) -> bool {
        MerkleTree::verify_proof(self)
    }
}

/// Signed Merkle root for update manifests.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedRoot {
    pub root: Sha256,
    pub timestamp: u64,
    pub version: u32,
    pub signature: Vec<u8>, // Ed25519
}

impl SignedRoot {
    pub fn new(root: Sha256, version: u32, private_key: &ed25519_dalek::SigningKey) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut data = Vec::new();
        data.extend_from_slice(root.as_bytes());
        data.extend_from_slice(&timestamp.to_le_bytes());
        data.extend_from_slice(&version.to_le_bytes());

        let signature = private_key.sign(&data);

        Self {
            root,
            timestamp,
            version,
            signature: signature.to_bytes().to_vec(),
        }
    }

    pub fn verify(&self, public_key: &ed25519_dalek::VerifyingKey) -> bool {
        let mut data = Vec::new();
        data.extend_from_slice(self.root.as_bytes());
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data.extend_from_slice(&self.version.to_le_bytes());

        let signature = ed25519_dalek::Signature::from_slice(&self.signature);
        if let Ok(sig) = signature {
            public_key.verify(&data, &sig).is_ok()
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::thread_rng;

    #[test]
    fn test_merkle_root() {
        let leaves = vec![
            Sha256([0x01; 32]),
            Sha256([0x02; 32]),
            Sha256([0x03; 32]),
            Sha256([0x04; 32]),
        ];

        let root = MerkleTree::compute_root(&leaves);
        assert_ne!(root, Sha256::default());
    }

    #[test]
    fn test_inclusion_proof() {
        let leaves = vec![
            Sha256([0x01; 32]),
            Sha256([0x02; 32]),
            Sha256([0x03; 32]),
            Sha256([0x04; 32]),
        ];

        let proof = MerkleTree::generate_proof(&leaves, 1);
        let root = MerkleTree::compute_root(&leaves);

        let inc_proof = InclusionProof {
            leaf_index: 1,
            leaf_hash: leaves[1],
            root,
            siblings: proof,
        };

        assert!(inc_proof.verify());
    }

    #[test]
    fn test_invalid_proof() {
        let leaves = vec![Sha256([0x01; 32]), Sha256([0x02; 32])];

        let proof = MerkleTree::generate_proof(&leaves, 0);
        let root = MerkleTree::compute_root(&leaves);

        let mut inc_proof = InclusionProof {
            leaf_index: 0,
            leaf_hash: Sha256([0x99; 32]), // Wrong leaf
            root,
            siblings: proof,
        };

        assert!(!inc_proof.verify());
    }

    #[test]
    fn test_signed_root() {
        let mut csprng = thread_rng();
        let signing_key = SigningKey::from_bytes(&rand::Rng::gen(&mut csprng));
        let verifying_key = signing_key.verifying_key();

        let root = Sha256([0xde; 32]);
        let signed = SignedRoot::new(root, 1, &signing_key);

        assert!(signed.verify(&verifying_key));

        // Tamper
        let mut tampered = signed.clone();
        tampered.root = Sha256([0x00; 32]);
        assert!(!tampered.verify(&verifying_key));
    }
}
