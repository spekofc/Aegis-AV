//! PE file analysis for suspicious characteristics.

use aegis_core::{
    types::{
        AuthenticodeInfo, ImportInfo, OverlayInfo, PeInfo, RichEntry, RichHeaderInfo, SectionInfo,
    },
    AegisError, AegisResult, DetectionEngine, ThreatType,
};
use goblin::pe::PE;
use std::path::Path;
use tracing::{debug, trace};

/// PE analyzer for static analysis.
pub struct PeAnalyzer;

impl PeAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Analyze a PE file.
    pub async fn analyze(&self, path: &Path) -> AegisResult<PeInfo> {
        let data = std::fs::read(path).map_err(|e| AegisError::Io(e))?;
        let pe = PE::parse(&data).map_err(|e| AegisError::Parsing(e.to_string()))?;

        let is_64bit = pe.is_64;
        let is_pe = is_64bit || !pe.sections.is_empty();
        let machine = pe.header.coff_header.machine;
        let entry_point = pe.entry as u64;

        let mut sections = Vec::new();
        for section in &pe.sections {
            let name = std::str::from_utf8(&section.name)
                .unwrap_or("unknown")
                .trim_end_matches('\0')
                .to_string();
            sections.push(SectionInfo {
                name,
                virtual_address: section.virtual_address,
                virtual_size: section.virtual_size,
                raw_size: section.size_of_raw_data,
                characteristics: section.characteristics,
                entropy: self.calculate_entropy(
                    &data,
                    section.pointer_to_raw_data as usize,
                    section.size_of_raw_data as usize,
                ),
            });
        }

        let mut imports = Vec::new();
        for import in &pe.imports {
            let dll = import.dll.to_string();
            // Note: goblin Import API may vary by version; functions field may not be available
            let functions = Vec::new();
            imports.push(ImportInfo {
                dll: dll.clone(),
                functions,
                name: None,
                ordinal: None,
            });
        }

        let exports = pe
            .exports
            .iter()
            .filter_map(|e| e.name)
            .map(|s| s.to_string())
            .collect();

        let authenticode = None; // Simplified
        let overlay = None; // Simplified
        let rich_header = None; // Simplified

        Ok(PeInfo {
            is_pe,
            is_64bit,
            machine,
            entry_point,
            sections,
            imports,
            exports,
            authenticode,
            overlay,
            rich_header,
        })
    }

    fn calculate_entropy(&self, data: &[u8], offset: usize, size: usize) -> f64 {
        if offset + size > data.len() {
            return 0.0;
        }
        let section_data = &data[offset..offset + size];
        let mut freq = [0u32; 256];
        for &b in section_data {
            freq[b as usize] += 1;
        }
        let len = section_data.len() as f64;
        let mut entropy = 0.0;
        for count in freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }
}

impl Default for PeAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
