//! AEGIS AV - Engine Orchestration

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod orchestrator;

pub use orchestrator::{AegisEngine, EngineConfig};
