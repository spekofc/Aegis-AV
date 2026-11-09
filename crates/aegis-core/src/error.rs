//! Error types for the AEGIS AV Security Engine.

use std::fmt;
use thiserror::Error;

/// Result type alias for AEGIS AV operations.
pub type AegisResult<T> = Result<T, AegisError>;

/// Main error type for the AEGIS AV Security Engine.
#[derive(Debug, Error)]
pub enum AegisError {
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Cryptographic error.
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// Database error.
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Serialization/deserialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// IPC/communication error.
    #[error("IPC error: {0}")]
    Ipc(#[from] IpcError),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Permission denied.
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Resource not found.
    #[error("Not found: {0}")]
    NotFound(String),

    /// Invalid argument.
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    /// Invalid state for operation.
    #[error("Invalid state: {0}")]
    InvalidState(String),

    /// Resource exhausted (memory, handles, etc.).
    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    /// Timeout.
    #[error("Operation timed out: {0}")]
    Timeout(String),

    /// Verification failed (signature, hash, integrity).
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// Parse error.
    #[error("Parse error: {0}")]
    Parse(String),

    /// PE/format parsing error.
    #[error("Parsing error: {0}")]
    Parsing(String),

    /// Unsupported operation.
    #[error("Unsupported: {0}")]
    Unsupported(String),

    /// Internal engine error.
    #[error("Internal error: {0}")]
    Internal(String),

    /// External dependency error.
    #[error("External error: {0}")]
    External(#[from] anyhow::Error),

    /// Notify error.
    #[error("Notify error: {0}")]
    Notify(#[from] notify::Error),
}

/// IPC-specific errors.
#[derive(Debug, Error)]
pub enum IpcError {
    /// Connection failed.
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// Message send failed.
    #[error("Send failed: {0}")]
    SendFailed(String),

    /// Message receive failed.
    #[error("Receive failed: {0}")]
    ReceiveFailed(String),

    /// Protocol version mismatch.
    #[error("Protocol version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: u32, actual: u32 },

    /// Message validation failed.
    #[error("Message validation failed: {0}")]
    ValidationFailed(String),

    /// Message too large.
    #[error("Message too large: {size} bytes (max {max})")]
    MessageTooLarge { size: usize, max: usize },

    /// Sequence number mismatch (replay detection).
    #[error("Sequence mismatch: expected {expected}, got {actual}")]
    SequenceMismatch { expected: u64, actual: u64 },

    /// Checksum mismatch.
    #[error("Checksum mismatch")]
    ChecksumMismatch,

    /// Connection closed.
    #[error("Connection closed")]
    ConnectionClosed,

    /// Timeout waiting for response.
    #[error("Response timeout")]
    Timeout,

    /// Invalid message type.
    #[error("Invalid message type: {0}")]
    InvalidMessageType(u32),

    /// Access denied.
    #[error("Access denied: {0}")]
    AccessDenied(String),

    /// Pipe/port not found.
    #[error("Endpoint not found: {0}")]
    NotFound(String),

    /// Impersonation failed.
    #[error("Impersonation failed: {0}")]
    ImpersonationFailed(String),

    /// Filter driver communication error.
    #[error("Filter driver error: {0}")]
    FilterDriver(String),
}

impl AegisError {
    /// Check if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            AegisError::Timeout(_)
                | AegisError::Ipc(IpcError::Timeout)
                | AegisError::Ipc(IpcError::ConnectionClosed)
                | AegisError::ResourceExhausted(_)
        )
    }

    /// Check if this error indicates a security violation.
    pub fn is_security_violation(&self) -> bool {
        matches!(
            self,
            AegisError::VerificationFailed(_)
                | AegisError::Ipc(IpcError::ValidationFailed(_))
                | AegisError::Ipc(IpcError::ChecksumMismatch)
                | AegisError::Ipc(IpcError::SequenceMismatch { .. })
                | AegisError::PermissionDenied(_)
                | AegisError::Ipc(IpcError::AccessDenied(_))
        )
    }

    /// Get error category for metrics.
    pub fn category(&self) -> &'static str {
        match self {
            AegisError::Io(_) => "io",
            AegisError::Crypto(_) => "crypto",
            AegisError::Database(_) => "database",
            AegisError::Serialization(_) => "serialization",
            AegisError::Ipc(_) => "ipc",
            AegisError::Config(_) => "config",
            AegisError::PermissionDenied(_) => "permission",
            AegisError::NotFound(_) => "not_found",
            AegisError::InvalidArgument(_) => "invalid_argument",
            AegisError::InvalidState(_) => "invalid_state",
            AegisError::ResourceExhausted(_) => "resource_exhausted",
            AegisError::Timeout(_) => "timeout",
            AegisError::VerificationFailed(_) => "verification_failed",
            AegisError::Parse(_) => "parse",
            AegisError::Parsing(_) => "parsing",
            AegisError::Unsupported(_) => "unsupported",
            AegisError::Internal(_) => "internal",
            AegisError::External(_) => "external",
            AegisError::Notify(_) => "notify",
        }
    }
}

/// Convenience macro for creating internal errors with context.
#[macro_export]
macro_rules! internal_err {
    ($($arg:tt)*) => {
        $crate::AegisError::Internal(format!($($arg)*))
    };
}

/// Convenience macro for creating config errors with context.
#[macro_export]
macro_rules! config_err {
    ($($arg:tt)*) => {
        $crate::AegisError::Config(format!($($arg)*))
    };
}

/// Convenience macro for creating verification errors with context.
#[macro_export]
macro_rules! verify_err {
    ($($arg:tt)*) => {
        $crate::AegisError::VerificationFailed(format!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_categories() {
        let err = AegisError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "test"));
        assert_eq!(err.category(), "io");

        let err = AegisError::VerificationFailed("sig".into());
        assert!(err.is_security_violation());
        assert!(!err.is_retryable());

        let err = AegisError::Timeout("test".into());
        assert!(err.is_retryable());
        assert!(!err.is_security_violation());
    }

    #[test]
    fn test_ipc_error_display() {
        let err = IpcError::VersionMismatch {
            expected: 1,
            actual: 2,
        };
        assert!(err.to_string().contains("1"));
        assert!(err.to_string().contains("2"));
    }
}
