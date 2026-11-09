//! AEGIS Scanner Engine

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod archive;
pub mod engine;
pub mod heuristic;
pub mod ml;
pub mod pe;

pub use engine::{ScanStats, ScannerConfig, ScannerEngine};
pub use heuristic::HeuristicEngine;
pub use ml::ShurikenClassifier;
pub use pe::PeAnalyzer;
