//! AEGIS AV - Core Library
//!
//! This crate provides the foundational types, error hierarchy, and core traits
//! used throughout the AEGIS AV Security Engine.

#![deny(unsafe_code)]
#![warn(missing_docs, clippy::unwrap_used, clippy::expect_used)]

pub mod constants;
pub mod error;
pub mod traits;
pub mod types;
pub mod version;

pub use constants::*;
pub use error::{AegisError, AegisResult};
pub use traits::*;
pub use types::*;
pub use version::*;
