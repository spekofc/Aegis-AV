//! AEGIS AV Signature Database

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod database;
pub mod format;
pub mod integrity;
pub mod matcher;
pub mod update;

pub use database::{DatabaseStats, SignatureDatabase, SignatureDatabaseBuilder};
pub use format::{DatabaseMeta, PatternRecord, SignatureRecord, SignatureType, CURRENT_PLATFORM};
pub use integrity::{IntegrityVerifier, MerkleTree, SignedRoot};
pub use matcher::SignatureMatcher;
pub use update::{ComponentUpdate, UpdateManager, UpdateManifest};
