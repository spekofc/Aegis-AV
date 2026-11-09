//! ETW (Event Tracing for Windows) provider for AEGIS AV.

use crate::AegisResult;
use tracing::info;

/// ETW provider configuration.
#[derive(Debug, Clone)]
pub struct EtwConfig {
    pub provider_name: String,
    pub provider_guid: String,
}

/// ETW provider for structured logging.
pub struct EtwProvider {
    config: EtwConfig,
}

impl EtwProvider {
    /// Create a new ETW provider.
    pub fn new(config: EtwConfig) -> AegisResult<Self> {
        info!("ETW provider initialized: {}", config.provider_name);
        Ok(Self { config })
    }
}
