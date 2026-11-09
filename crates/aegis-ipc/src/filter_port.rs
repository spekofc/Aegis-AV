//! Filter port IPC implementation.

use aegis_core::{AegisError, AegisResult};

/// Filter port for kernel-user communication.
pub struct FilterPort {
    port_name: String,
}

/// Message sent through filter port.
#[derive(Debug, Clone)]
pub struct FilterMessage {
    pub message_id: u64,
    pub data: Vec<u8>,
}

/// Reply received from filter port.
#[derive(Debug, Clone)]
pub struct FilterReply {
    pub message_id: u64,
    pub status: u32,
    pub data: Vec<u8>,
}

impl FilterPort {
    /// Create a new filter port.
    pub fn new(port_name: impl AsRef<str>) -> Self {
        Self {
            port_name: port_name.as_ref().to_string(),
        }
    }

    /// Send a message through the filter port.
    pub async fn send(&self, _message: FilterMessage) -> AegisResult<FilterReply> {
        Err(AegisError::Unsupported(
            "Filter port not implemented".into(),
        ))
    }
}
