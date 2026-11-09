//! Data generators for testing.

use aegis_core::{
    types::{
        DetectionEngine, Disposition, PatternMatch, ScanContext, ScanResult, Sha256,
        SignatureMatch, ThreatType,
    },
    AegisError, AegisResult,
};
use std::collections::HashMap;
use uuid::Uuid;

/// Generator configuration.
#[derive(Debug, Clone)]
pub struct GeneratorConfig {
    pub seed: u64,
    pub num_signatures: usize,
    pub num_patterns: usize,
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        Self {
            seed: 42,
            num_signatures: 100,
            num_patterns: 50,
        }
    }
}

/// Data generator for test data.
pub struct DataGenerator {
    config: GeneratorConfig,
    rng: fastrand::Rng,
}

impl DataGenerator {
    /// Create a new data generator.
    pub fn new(config: GeneratorConfig) -> Self {
        let rng = fastrand::Rng::with_seed(config.seed);
        Self { config, rng }
    }

    /// Generate a random SHA256 hash.
    pub fn random_hash(&mut self) -> Sha256 {
        let mut bytes = [0u8; 32];
        self.rng.fill(&mut bytes);
        Sha256::new(bytes)
    }

    /// Generate a random threat type.
    pub fn random_threat_type(&mut self) -> ThreatType {
        let variants = [
            ThreatType::Virus,
            ThreatType::Worm,
            ThreatType::Trojan,
            ThreatType::Ransomware,
            ThreatType::Rootkit,
            ThreatType::Spyware,
            ThreatType::Adware,
            ThreatType::Dropper,
            ThreatType::Loader,
            ThreatType::Backdoor,
        ];
        variants[self.rng.usize(..variants.len())]
    }

    /// Generate a random detection engine.
    pub fn random_engine(&mut self) -> DetectionEngine {
        let variants = [
            DetectionEngine::Hash,
            DetectionEngine::Pattern,
            DetectionEngine::Heuristic,
            DetectionEngine::MachineLearning,
            DetectionEngine::Behavioral,
            DetectionEngine::Cloud,
            DetectionEngine::Reputation,
        ];
        variants[self.rng.usize(..variants.len())]
    }

    /// Generate a random disposition.
    pub fn random_disposition(&mut self) -> Disposition {
        let variants = [
            Disposition::Clean,
            Disposition::Unknown,
            Disposition::Suspicious,
            Disposition::Pua,
            Disposition::Malicious,
            Disposition::Error,
            Disposition::Deferred,
        ];
        variants[self.rng.usize(..variants.len())]
    }

    /// Generate a random scan result.
    pub fn random_scan_result(&mut self) -> ScanResult {
        let disposition = self.random_disposition();
        ScanResult {
            disposition,
            threat_type: if disposition == Disposition::Clean {
                None
            } else {
                Some(self.random_threat_type())
            },
            threat_name: if disposition == Disposition::Clean {
                None
            } else {
                Some(format!("TestThreat{}", self.rng.u32(..1000)))
            },
            confidence: self.rng.f32(),
            engine: self.random_engine(),
            matched_ids: vec![],
            details: serde_json::json!({}),
            duration: std::time::Duration::from_millis(self.rng.u64(..1000)),
        }
    }

    /// Generate a random scan context.
    pub fn random_scan_context(&mut self) -> ScanContext {
        ScanContext {
            scan_id: Uuid::now_v7(),
            initiator_pid: self.rng.u32(..65535),
            initiator_name: format!("test_process_{}", self.rng.u32(..1000)),
            trigger: aegis_core::ScanTrigger::Manual,
            priority: self.rng.u8(..255),
            deadline: None,
            metadata: serde_json::json!({}),
        }
    }

    /// Generate signature matches for testing.
    pub fn generate_signature_matches(&mut self, count: usize) -> Vec<SignatureMatch> {
        (0..count)
            .map(|_| SignatureMatch {
                id: self.rng.u64(..10000),
                hash: Some(self.random_hash()),
                sig_type: self.rng.u8(1..=5),
                family: format!("Family{}", self.rng.u32(..100)),
                threat_type: self.random_threat_type(),
                seAEGIS: self.rng.u8(1..=5),
                platforms: self.rng.u32(..),
                description: format!("Test signature {}", self.rng.u32(..1000)),
                engine: self.random_engine(),
            })
            .collect()
    }

    /// Generate pattern matches for testing.
    pub fn generate_pattern_matches(&mut self, count: usize) -> Vec<PatternMatch> {
        (0..count)
            .map(|_| PatternMatch {
                id: self.rng.u64(..10000),
                offset: self.rng.u64(..1000000),
                length: self.rng.u32(1..100),
                signature_id: self.rng.u64(..10000),
            })
            .collect()
    }

    /// Generate a test signature database.
    pub fn generate_signatures(&mut self) -> HashMap<u64, SignatureMatch> {
        let mut map = HashMap::new();
        for sig in self.generate_signature_matches(self.config.num_signatures) {
            map.insert(sig.id, sig);
        }
        map
    }
}
