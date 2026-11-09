//! AEGIS AV Configuration Management

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod license;
pub mod provider;
pub mod schema;
pub mod secure;

pub use aegis_core::{traits::ConfigProvider, AegisError, AegisResult};
pub use license::{Entitlements, LicenseInfo, LicenseManager};
pub use provider::{ConfigWatcher, FileConfigProvider};
pub use schema::{default_config, load_config, save_config, AegisConfig};
pub use secure::SecureConfigStore;
