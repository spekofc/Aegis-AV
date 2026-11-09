//! Named pipe IPC implementation.

use aegis_core::{AegisError, AegisResult};

/// Named pipe server.
pub struct NamedPipeServer {
    pipe_name: String,
}

/// Named pipe client.
pub struct NamedPipeClient {
    pipe_name: String,
}

impl NamedPipeServer {
    /// Create a new named pipe server.
    pub fn new(pipe_name: impl AsRef<str>) -> Self {
        Self {
            pipe_name: pipe_name.as_ref().to_string(),
        }
    }

    /// Start listening for connections.
    pub async fn listen(&mut self) -> AegisResult<()> {
        Err(AegisError::Unsupported(
            "Named pipe server not implemented".into(),
        ))
    }
}

impl NamedPipeClient {
    /// Create a new named pipe client.
    pub fn new(pipe_name: impl AsRef<str>) -> Self {
        Self {
            pipe_name: pipe_name.as_ref().to_string(),
        }
    }

    /// Connect to the named pipe server.
    pub async fn connect(&mut self) -> AegisResult<()> {
        Err(AegisError::Unsupported(
            "Named pipe client not implemented".into(),
        ))
    }
}
