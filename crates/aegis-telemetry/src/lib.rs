//! AEGIS AV - Telemetry and Metrics

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod etw;
pub mod events;
pub mod metrics;

pub use aegis_core::{AegisError, AegisResult};
pub use etw::{EtwConfig, EtwProvider};
pub use events::{EventCollector, EventConfig, EventLevel, EventRecord};
pub use metrics::{increment_counter, init, record_histogram, set_gauge};
