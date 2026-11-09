//! Heuristic analysis engine.

use aegis_core::{
    types::PeInfo, AegisError, AegisResult, DetectionEngine, Disposition, ScanResult, ThreatType,
};
use std::path::Path;
use tracing::{debug, trace};

/// Heuristic analysis engine.
pub struct HeuristicEngine {
    rules: Vec<HeuristicRule>,
}

impl HeuristicEngine {
    pub fn new() -> Self {
        Self {
            rules: Self::default_rules(),
        }
    }

    /// Analyze a file using heuristic rules.
    pub async fn analyze(
        &self,
        path: &Path,
        base_result: &ScanResult,
    ) -> AegisResult<Option<ScanResult>> {
        if base_result.disposition != Disposition::Clean {
            return Ok(None);
        }

        let mut detections = Vec::new();
        let mut max_confidence = 0.0f32;
        let mut threat_type = ThreatType::Unknown;

        // File-based heuristics
        for rule in &self.rules {
            if let Some(detection) = rule.check_file(path).await {
                detections.push(detection.description.clone());
                max_confidence = max_confidence.max(detection.confidence);
                threat_type = detection.threat_type;
            }
        }

        if detections.is_empty() {
            return Ok(None);
        }

        Ok(Some(ScanResult {
            disposition: if max_confidence >= 0.7 {
                Disposition::Malicious
            } else {
                Disposition::Suspicious
            },
            threat_type: Some(threat_type),
            threat_name: Some("Heuristic".to_string()),
            confidence: max_confidence,
            engine: DetectionEngine::Heuristic,
            matched_ids: Vec::new(),
            details: serde_json::json!({
                "method": "heuristic",
                "detections": detections,
            }),
            duration: std::time::Duration::from_millis(0),
        }))
    }

    fn default_rules() -> Vec<HeuristicRule> {
        vec![
            // Suspicious file locations (executables in temp directories)
            HeuristicRule {
                name: "temp_directory_executable".to_string(),
                description: "Executable running from temp directory".to_string(),
                threat_type: ThreatType::Trojan,
                confidence: 0.6,
                check: Box::new(|path: &Path| {
                    let path_str = path.to_string_lossy().to_lowercase();
                    let is_executable = path
                        .extension()
                        .and_then(|e| e.to_str())
                        .map(|e| {
                            matches!(
                                e.to_lowercase().as_str(),
                                "exe"
                                    | "dll"
                                    | "scr"
                                    | "bat"
                                    | "cmd"
                                    | "com"
                                    | "pif"
                                    | "msi"
                                    | "ps1"
                                    | "vbs"
                                    | "js"
                                    | "jar"
                            )
                        })
                        .unwrap_or(false);

                    let in_temp = path_str.contains("\\temp\\")
                        || path_str.contains("\\tmp\\")
                        || path_str.contains("\\appdata\\local\\temp\\");

                    in_temp && is_executable
                }),
            },
            // Suspicious file names
            HeuristicRule {
                name: "suspicious_filename".to_string(),
                description: "Suspicious file name pattern".to_string(),
                threat_type: ThreatType::Trojan,
                confidence: 0.5,
                check: Box::new(|path: &Path| {
                    let name = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("")
                        .to_lowercase();
                    name.contains("crack")
                        || name.contains("keygen")
                        || name.contains("patch")
                        || name.contains("loader")
                        || name.contains("inject")
                        || name.contains("bypass")
                        || name.ends_with(".exe.tmp")
                        || name.ends_with(".dll.tmp")
                }),
            },
            // Double extension
            HeuristicRule {
                name: "double_extension".to_string(),
                description: "Double file extension".to_string(),
                threat_type: ThreatType::Trojan,
                confidence: 0.7,
                check: Box::new(|path: &Path| {
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    name.matches('.').count() >= 2
                        && (name.ends_with(".exe")
                            || name.ends_with(".scr")
                            || name.ends_with(".bat")
                            || name.ends_with(".cmd")
                            || name.ends_with(".com")
                            || name.ends_with(".pif"))
                }),
            },
            // Suspicious size (very small executables)
            HeuristicRule {
                name: "tiny_executable".to_string(),
                description: "Unusually small executable".to_string(),
                threat_type: ThreatType::Trojan,
                confidence: 0.4,
                check: Box::new(|path: &Path| {
                    if let Ok(meta) = std::fs::metadata(path) {
                        meta.len() < 1024
                            && path.extension().and_then(|e| e.to_str()) == Some("exe")
                    } else {
                        false
                    }
                }),
            },
            // Hidden/system file
            HeuristicRule {
                name: "hidden_system_file".to_string(),
                description: "Hidden or system executable".to_string(),
                threat_type: ThreatType::Rootkit,
                confidence: 0.5,
                check: Box::new(|path: &Path| {
                    use std::os::windows::fs::MetadataExt;
                    if let Ok(meta) = std::fs::metadata(path) {
                        let attrs = meta.file_attributes();
                        (attrs & 0x2) != 0 || (attrs & 0x4) != 0 // HIDDEN | SYSTEM
                    } else {
                        false
                    }
                }),
            },
        ]
    }
}

/// Heuristic rule definition.
struct HeuristicRule {
    name: String,
    description: String,
    threat_type: ThreatType,
    confidence: f32,
    check: Box<dyn Fn(&Path) -> bool + Send + Sync>,
}

impl HeuristicRule {
    async fn check_file(&self, path: &Path) -> Option<HeuristicDetection> {
        if (self.check)(path) {
            Some(HeuristicDetection {
                rule_name: self.name.clone(),
                description: self.description.clone(),
                threat_type: self.threat_type,
                confidence: self.confidence,
            })
        } else {
            None
        }
    }
}

/// Heuristic detection result.
#[derive(Debug, Clone)]
struct HeuristicDetection {
    rule_name: String,
    description: String,
    threat_type: ThreatType,
    confidence: f32,
}

/// PE-specific heuristic rules.
pub struct PeHeuristics;

impl PeHeuristics {
    /// Check PE-specific heuristics.
    pub fn check(info: &PeInfo) -> Vec<PeHeuristicDetection> {
        let mut detections = Vec::new();

        // Entry point in unusual section
        for section in &info.sections {
            let sec_start = section.virtual_address;
            let sec_end = sec_start + section.virtual_size;
            if info.entry_point >= sec_start as u64 && info.entry_point < sec_end as u64 {
                if section.name != ".text" && section.name != "CODE" {
                    detections.push(PeHeuristicDetection {
                        name: "entry_point_in_non_code_section".to_string(),
                        description: format!("Entry point in section '{}'", section.name),
                        confidence: 0.8,
                    });
                }
            }
        }

        // Import table anomalies
        let import_count: usize = info.imports.iter().map(|i| i.functions.len()).sum();
        if import_count == 0 && info.is_64bit {
            detections.push(PeHeuristicDetection {
                name: "no_imports".to_string(),
                description: "64-bit executable with no imports".to_string(),
                confidence: 0.7,
            });
        }

        // Suspicious section names
        for section in &info.sections {
            let name_lower = section.name.to_lowercase();
            if name_lower == ".data" && (section.characteristics & 0x20000000) != 0 {
                // Executable .data
                detections.push(PeHeuristicDetection {
                    name: "executable_data_section".to_string(),
                    description: "Executable .data section".to_string(),
                    confidence: 0.9,
                });
            }
            if name_lower.contains("pack")
                || name_lower.contains("crypt")
                || name_lower.contains("enc")
            {
                detections.push(PeHeuristicDetection {
                    name: "suspicious_section_name".to_string(),
                    description: format!("Suspicious section name: {}", section.name),
                    confidence: 0.8,
                });
            }
        }

        // Resource section anomalies
        for section in &info.sections {
            if section.name == ".rsrc" && section.entropy > 6.5 {
                detections.push(PeHeuristicDetection {
                    name: "high_entropy_resources".to_string(),
                    description: "High entropy in resource section".to_string(),
                    confidence: 0.6,
                });
            }
        }

        detections
    }
}

/// PE heuristic detection.
#[derive(Debug, Clone)]
pub struct PeHeuristicDetection {
    pub name: String,
    pub description: String,
    pub confidence: f32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heuristic_rules() {
        let rules = HeuristicEngine::default_rules();
        assert!(!rules.is_empty());

        for rule in &rules {
            assert!(!rule.name.is_empty());
            assert!(!rule.description.is_empty());
            assert!(rule.confidence > 0.0 && rule.confidence <= 1.0);
        }
    }
}
