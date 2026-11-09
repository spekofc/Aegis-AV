//! Event collection for AEGIS AV.

use crate::{AegisError, AegisResult};
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::sync::{Arc, Mutex};

/// Event collector for structured events.
pub struct EventCollector {
    events: Arc<Mutex<Vec<EventRecord>>>,
    max_events: usize,
}

/// Individual event record.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EventRecord {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub level: EventLevel,
    pub component: String,
    pub message: String,
    pub fields: Value,
}

/// Event severity levels.
#[derive(Debug, Clone, Copy, serde::Serialize)]
pub enum EventLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Critical,
}

/// Configuration for event collector.
#[derive(Debug, Clone)]
pub struct EventConfig {
    pub max_events: usize,
}

impl EventCollector {
    /// Create a new event collector.
    pub fn new(config: EventConfig) -> Self {
        Self {
            events: Arc::new(Mutex::new(Vec::with_capacity(config.max_events))),
            max_events: config.max_events,
        }
    }

    /// Record an event.
    pub fn record(&self, event: EventRecord) {
        let mut events = self.events.lock().unwrap();
        if events.len() >= self.max_events {
            events.remove(0);
        }
        events.push(event);
    }

    /// Get recent events.
    pub fn get_events(&self) -> Vec<EventRecord> {
        self.events.lock().unwrap().clone()
    }
}
