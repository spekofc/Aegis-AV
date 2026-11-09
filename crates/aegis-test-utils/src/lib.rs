//! AEGIS AV - Test Utilities

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod assertions;
pub mod fixtures;
pub mod generators;

pub use assertions::{assert_quarantine_integrity, assert_scan_result};
pub use fixtures::{FixtureConfig, TestFixtures};
pub use generators::{DataGenerator, GeneratorConfig};
