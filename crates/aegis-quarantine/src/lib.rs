//! AEGIS AV - Quarantine Management

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod crypto;
pub mod engine;

pub use crypto::{FileCrypto, QuarantineCrypto};
pub use engine::{QuarantineConfig, QuarantineEngine, QuarantineItem, QuarantineStats};
