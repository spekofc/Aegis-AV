//! Metrics collection for AEGIS AV.

use crate::AegisResult;
use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::PrometheusBuilder;
use std::sync::OnceLock;

static METRICS_INIT: OnceLock<()> = OnceLock::new();

/// Initialize the metrics subsystem.
pub fn init() -> AegisResult<()> {
    METRICS_INIT.get_or_init(|| {
        let (recorder, _exporter) = PrometheusBuilder::new()
            .build()
            .expect("Failed to create Prometheus recorder");
        metrics::set_global_recorder(recorder).ok();
    });
    Ok(())
}

/// Record a counter increment.
pub fn increment_counter(name: &'static str, labels: &[(&'static str, &'static str)], value: u64) {
    let labels: Vec<(&str, &str)> = labels.iter().map(|(k, v)| (*k, *v)).collect();
    metrics::counter!(name, &labels).increment(value);
}

/// Record a gauge value.
pub fn set_gauge(name: &'static str, labels: &[(&'static str, &'static str)], value: f64) {
    let labels: Vec<(&str, &str)> = labels.iter().map(|(k, v)| (*k, *v)).collect();
    metrics::gauge!(name, &labels).set(value);
}

/// Record a histogram value.
pub fn record_histogram(name: &'static str, labels: &[(&'static str, &'static str)], value: f64) {
    let labels: Vec<(&str, &str)> = labels.iter().map(|(k, v)| (*k, *v)).collect();
    metrics::histogram!(name, &labels).record(value);
}
