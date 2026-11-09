//! Real-time event dispatcher.

use crate::filter_client::FileEvent;
use aegis_core::{
    AegisError, AegisResult, Disposition, ScanContext, ScanResult, ScanTrigger, ThreatType,
};
use aegis_scanner::ScannerEngine;
use serde_json;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn};
use uuid;

/// Disposition callback type.
pub type DispositionCallback = Box<dyn Fn(ScanResult) + Send + Sync>;

/// Event dispatcher for real-time protection.
pub struct Dispatcher {
    scanner: Arc<ScannerEngine>,
    callback: Option<DispositionCallback>,
    event_rx: mpsc::Receiver<FileEvent>,
}

impl Dispatcher {
    /// Create a new dispatcher.
    pub fn new(scanner: Arc<ScannerEngine>, event_rx: mpsc::Receiver<FileEvent>) -> Self {
        Self {
            scanner,
            callback: None,
            event_rx,
        }
    }

    /// Set the disposition callback.
    pub fn set_callback(&mut self, callback: DispositionCallback) {
        self.callback = Some(callback);
    }

    /// Run the dispatcher loop.
    pub async fn run(mut self) {
        while let Some(event) = self.event_rx.recv().await {
            let context = ScanContext {
                scan_id: uuid::Uuid::new_v7(uuid::Timestamp::from_unix(
                    uuid::NoContext,
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    0,
                )),
                initiator_pid: event.process_id,
                initiator_name: event.process_name,
                trigger: ScanTrigger::RealTimeWrite,
                priority: 200,
                deadline: None,
                metadata: serde_json::json!({}),
            };

            let result = self
                .scanner
                .scan_file(&event.path, context)
                .await
                .unwrap_or_else(|e| ScanResult::skipped(e.to_string()));

            if let Some(ref callback) = self.callback {
                callback(result.clone());
            }

            // Take action based on disposition
            match result.disposition {
                Disposition::Malicious => {
                    warn!("Malicious file detected: {:?}", event.path);
                    // In production: block access, quarantine, alert
                }
                Disposition::Suspicious => {
                    warn!("Suspicious file detected: {:?}", event.path);
                }
                _ => {}
            }
        }
    }
}
