//! Update manifest definitions.

use aegis_core::{Sha256, Version};
use serde::{Deserialize, Serialize};

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
