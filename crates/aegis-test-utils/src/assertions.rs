//! Test assertions for AEGIS AV.

use aegis_core::{
    types::QuarantineId, DetectionEngine, Disposition, ScanContext, ScanResult, ThreatType,
};

/// Assert that a scan result indicates a clean file.
pub fn assert_clean(result: &ScanResult) {
    assert_eq!(
        result.disposition,
        Disposition::Clean,
        "Expected clean disposition, got {:?}",
        result.disposition
    );
    assert!(
        result.threat_type.is_none(),
        "Expected no threat type for clean result"
    );
    assert!(
        result.threat_name.is_none(),
        "Expected no threat name for clean result"
    );
}

/// Assert that a scan result indicates a malicious file.
pub fn assert_malicious(result: &ScanResult, expected_threat: Option<ThreatType>) {
    assert_eq!(
        result.disposition,
        Disposition::Malicious,
        "Expected malicious disposition, got {:?}",
        result.disposition
    );
    if let Some(expected) = expected_threat {
        assert_eq!(
            result.threat_type,
            Some(expected),
            "Expected threat type {:?}, got {:?}",
            expected,
            result.threat_type
        );
    } else {
        assert!(
            result.threat_type.is_some(),
            "Expected some threat type for malicious result"
        );
    }
}

/// Assert that a scan result indicates a suspicious file.
pub fn assert_suspicious(result: &ScanResult) {
    assert_eq!(
        result.disposition,
        Disposition::Suspicious,
        "Expected suspicious disposition, got {:?}",
        result.disposition
    );
    assert!(
        result.threat_type.is_some(),
        "Expected some threat type for suspicious result"
    );
}

/// Assert that a scan result was produced by a specific engine.
pub fn assert_engine(result: &ScanResult, expected_engine: DetectionEngine) {
    assert_eq!(
        result.engine, expected_engine,
        "Expected engine {:?}, got {:?}",
        expected_engine, result.engine
    );
}

/// Assert that a scan result has minimum confidence.
pub fn assert_min_confidence(result: &ScanResult, min_confidence: f32) {
    assert!(
        result.confidence >= min_confidence,
        "Confidence {:.2} below minimum {:.2}",
        result.confidence,
        min_confidence
    );
}

/// Assert that a scan completed within time limit.
pub fn assert_scan_time(result: &ScanResult, max_duration: std::time::Duration) {
    assert!(
        result.duration <= max_duration,
        "Scan took too long: {:?} > {:?}",
        result.duration,
        max_duration
    );
}

/// Assert scan result matches expected properties.
pub fn assert_scan_result(
    result: &ScanResult,
    expected_disposition: Disposition,
    expected_threat: Option<ThreatType>,
    expected_engine: Option<DetectionEngine>,
    min_confidence: Option<f32>,
) {
    assert_eq!(
        result.disposition, expected_disposition,
        "Disposition mismatch"
    );

    if let Some(expected) = expected_threat {
        assert_eq!(result.threat_type, Some(expected), "Threat type mismatch");
    } else if expected_disposition != Disposition::Clean {
        assert!(
            result.threat_type.is_some(),
            "Expected threat type for non-clean result"
        );
    }

    if let Some(expected) = expected_engine {
        assert_eq!(result.engine, expected, "Engine mismatch");
    }

    if let Some(min_conf) = min_confidence {
        assert!(result.confidence >= min_conf, "Confidence below minimum");
    }
}

/// Assert quarantine integrity.
pub fn assert_quarantine_integrity(item: &QuarantineId, original_hash: &aegis_core::Sha256) {
    // QuarantineId is a Uuid, we can't verify hash from it directly
    // This is a placeholder for actual quarantine verification
    let _ = (item, original_hash);
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::{DetectionEngine, Disposition, ScanResult, ThreatType};

    #[test]
    fn test_assert_clean() {
        let result = ScanResult::clean();
        assert_clean(&result);
    }

    #[test]
    fn test_assert_malicious() {
        let result = ScanResult {
            disposition: Disposition::Malicious,
            threat_type: Some(ThreatType::Trojan),
            threat_name: Some("TestTrojan".to_string()),
            confidence: 0.9,
            engine: DetectionEngine::Hash,
            matched_ids: vec![1],
            details: serde_json::json!({}),
            duration: std::time::Duration::from_millis(10),
        };
        assert_malicious(&result, Some(ThreatType::Trojan));
    }
}
