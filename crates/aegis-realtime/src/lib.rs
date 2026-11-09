//! AEGIS AV - Real-Time Protection

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod dispatcher;
pub mod filter_client;

pub use dispatcher::{Dispatcher, DispositionCallback};
pub use filter_client::{RealtimeClient, RealtimeConfig};
