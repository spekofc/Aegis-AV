//! ALPC (Advanced Local Procedure Call) IPC implementation.

use aegis_core::{AegisError, AegisResult};

/// ALPC server.
pub struct AlpcServer {
    port_name: String,
}

/// ALPC client.
pub struct AlpcClient {
    port_name: String,
}

impl AlpcServer {
    /// Create a new ALPC server.
    pub fn new(port_name: impl AsRef<str>) -> Self {
        Self {
            port_name: port_name.as_ref().to_string(),
        }
    }

    /// Start the ALPC server.
    pub async fn listen(&mut self) -> AegisResult<()> {
        Err(AegisError::Unsupported(
            "ALPC server not implemented".into(),
        ))
    }
}

impl AlpcClient {
    /// Create a new ALPC client.
    pub fn new(port_name: impl AsRef<str>) -> Self {
        Self {
            port_name: port_name.as_ref().to_string(),
        }
    }

    /// Connect to the ALPC server.
    pub async fn connect(&mut self) -> AegisResult<()> {
        Err(AegisError::Unsupported(
            "ALPC client not implemented".into(),
        ))
    }
}
