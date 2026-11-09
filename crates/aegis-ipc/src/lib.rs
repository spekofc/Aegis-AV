//! AEGIS AV - Inter-Process Communication

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod alpc;
pub mod filter_port;
pub mod named_pipe;

pub use alpc::{AlpcClient, AlpcServer};
pub use filter_port::{FilterMessage, FilterPort, FilterReply};
pub use named_pipe::{NamedPipeClient, NamedPipeServer};
