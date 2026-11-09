//! Version information for AEGIS AV.

use crate::types::Version;
use std::sync::OnceLock;

/// Current AEGIS AV version.
pub const VERSION: Version = Version::new(0, 1, 0, 0);

/// Protocol version for IPC.
pub const PROTOCOL_VERSION: u32 = 1;

/// Minimum compatible protocol version.
pub const MIN_PROTOCOL_VERSION: u32 = 1;

/// AEGIS AV product name.
pub const PRODUCT_NAME: &str = "AEGIS AV";

/// AEGIS AV vendor.
pub const VENDOR: &str = "AEGIS AV Project";

/// Build information (initialized lazily at runtime).
pub mod build {
    use std::sync::OnceLock;

    fn get_env(key: &str) -> &'static str {
        static CACHE: OnceLock<Option<&'static str>> = OnceLock::new();
        let opt = CACHE.get_or_init(|| match std::env::var(key) {
            Ok(s) => Some(Box::leak(s.into_boxed_str())),
            Err(_) => None,
        });
        opt.unwrap_or_else(|| {
            let s = "unknown".to_string();
            Box::leak(s.into_boxed_str())
        })
    }

    pub fn target() -> &'static str {
        get_env("TARGET")
    }

    pub fn profile() -> &'static str {
        get_env("PROFILE")
    }

    pub fn build_timestamp() -> &'static str {
        get_env("VERGEN_BUILD_TIMESTAMP")
    }

    pub fn git_sha() -> &'static str {
        get_env("VERGEN_GIT_SHA")
    }

    pub fn git_branch() -> &'static str {
        get_env("VERGEN_GIT_BRANCH")
    }

    pub fn rustc_version() -> &'static str {
        get_env("VERGEN_RUSTC_VERSION")
    }

    pub fn cargo_version() -> &'static str {
        get_env("VERGEN_CARGO_VERSION")
    }
}

/// Version compatibility check.
pub fn check_protocol_version(peer_version: u32) -> Result<(), crate::error::AegisError> {
    if peer_version < MIN_PROTOCOL_VERSION || peer_version > PROTOCOL_VERSION {
        return Err(crate::error::AegisError::InvalidArgument(format!(
            "Unsupported protocol version: {} (supported: {}-{})",
            peer_version, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_constants() {
        assert_eq!(VERSION.major, 0);
        assert_eq!(VERSION.minor, 1);
        assert_eq!(VERSION.patch, 0);
    }

    #[test]
    fn test_protocol_version_check() {
        assert!(check_protocol_version(1).is_ok());
        assert!(check_protocol_version(0).is_err());
        assert!(check_protocol_version(2).is_err());
    }
}
