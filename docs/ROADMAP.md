# Roadmap

## Version Strategy

| Version | Type | Target | Focus |
|---------|------|--------|-------|
| 0.1.x | Alpha | 2024 | Core engine, quarantine, signatures |
| 0.2.x | Alpha | 2025 | Real-time protection |
| 0.3.x | Beta | 2025 | Anti-exploit, YARA |
| 0.4.x | Beta | 2025 | ML, behavioral, cloud |
| 1.0.0 | Stable | 2026+ | Production hardening |

---

## v0.1 — Foundation (Current Alpha)

### ✅ Completed

| Feature | Status |
|---------|--------|
| SHA-256 hash detection | ✅ |
| Aho-Corasick pattern matching | ✅ |
| Heuristic analysis (temp-dir executables) | ✅ |
| PE static analysis | ✅ |
| Quarantine engine (AES-256-GCM) | ✅ |
| Signature database (SQLite + Merkle) | ✅ |
| CLI with JSON output | ✅ |
| Self-test (clean + EICAR) | ✅ |
| 38 unit/integration tests | ✅ |
| CI pipeline (Windows + Linux) | ✅ |

### 📋 In Progress

- Documentation completeness
- Logo/branding
- License decision

---

## v0.2 — Real-Time Protection (Q1 2025)

### Real-Time Filesystem Monitor

| Component | Status |
|-----------|--------|
| Windows minifilter driver | 📋 Planned |
| On-access scanning | 📋 Planned |
| On-execute scanning | 📋 Planned |
| Process attribution | 📋 Planned |
| Exclusion lists | 📋 Planned |

### Architecture

```
┌─────────────────────────────────────────────┐
│           Real-Time Layer                    │
│  ┌─────────────┐  ┌─────────────────────┐   │
│  │ Minifilter  │──►│ Scan Dispatcher     │   │
│  │ (IRP_MJ_    │   │ - OnRead            │   │
│  │  CREATE)    │   │ - OnWrite           │   │
│  └─────────────┘   │ - OnExecute         │   │
│                    └─────────┬───────────┘   │
└─────────────────────────────┼───────────────┘
                              ▼
                    ┌─────────────────┐
                    │  Scan Engine    │
                    │  (async queue)  │
                    └─────────────────┘
```

### Deliverables

- [ ] Windows minifilter driver skeleton
- [ ] IRP_MJ_CREATE/WRITE/CLOSE handling
- [ ] Async scan dispatcher with priority queue
- [ ] Process image path resolution
- [ ] Exclusion configuration (path, process, extension)
- [ ] Real-time status CLI command
- [ ] Integration tests with EICAR drop

---

## v0.3 — Anti-Exploit & YARA (Q2 2025)

### Anti-Exploit Engine

| Mitigation | Status |
|------------|--------|
| DEP (NX) enforcement | 📋 Planned |
| ASLR enforcement | 📋 Planned |
| SEHOP | 📋 Planned |
| CET (Shadow Stacks) | 📋 Planned |
| ROP/JOP detection | 📋 Planned |
| Stack pivot detection | 📋 Planned |
| Heap spray detection | 📋 Planned |

### YARA Integration

| Component | Status |
|-----------|--------|
| libyara-sys binding | 📋 Planned |
| Rule compiler | 📋 Planned |
| Matcher integration | 📋 Planned |
| Rule management CLI | 📋 Planned |
| Performance optimization | 📋 Planned |

### Deliverables

- [ ] Anti-exploit crate with Windows APIs
- [ ] CET shadow stack verification
- [ ] ROP chain detection via CFG
- [ ] YARA rule compiler and matcher
- [ ] Rule repository management
- [ ] Performance benchmarks

---

## v0.4 — Intelligence & Cloud (Q3 2025)

### ML Classification

| Component | Status |
|-----------|--------|
| Feature extraction (PE metadata) | 📋 Planned |
| ONNX Runtime integration | 📋 Planned |
| LightGBM/XGBoost model | 📋 Planned |
| Confidence calibration | 📋 Planned |
| Model versioning | 📋 Planned |

### Behavioral Analysis

| Component | Status |
|-----------|--------|
| API call tracing | 📋 Planned |
| Process tree analysis | 📋 Planned |
| Network IOC correlation | 📋 Planned |
| MITRE ATT&CK mapping | 📋 Planned |

### Cloud Lookup

| Component | Status |
|-----------|--------|
| Hash reputation API | 📋 Planned |
| Rate limiting / caching | 📋 Planned |
| Privacy-preserving queries | 📋 Planned |
| Offline fallback | 📋 Planned |

### Deliverables

- [ ] ML model for PE classification
- [ ] Behavioral engine with ETW tracing
- [ ] Cloud reputation service (optional)
- [ ] MITRE ATT&CK technique tagging

---

## v0.5 — Enterprise Features (Q4 2025)

### Management

| Feature | Status |
|---------|--------|
| Central policy server | 📋 Planned |
| Agent enrollment | 📋 Planned |
| Policy distribution | 📋 Planned |
| Audit logging | 📋 Planned |

### Reporting

| Feature | Status |
|---------|--------|
| Detection dashboard | 📋 Planned |
| MITRE heatmap | 📋 Planned |
| Executive summaries | 📋 Planned |
| SIEM integration (CEF/LEEF) | 📋 Planned |

### Platform Expansion

| Platform | Status |
|----------|--------|
| Linux (ELF scanning) | 📋 Planned |
| macOS (Mach-O scanning) | 📋 Planned |
| Container scanning | 📋 Planned |

---

## v1.0 — Production Release (2026+)

### Hardening

| Area | Target |
|------|--------|
| Fuzzing (cargo fuzz) | 100% parser coverage |
| Penetration testing | External audit |
| Supply chain (SBOM) | CycloneDX |
| Reproducible builds | ✅ |

### Compliance

| Standard | Target |
|----------|--------|
| Common Criteria EAL2+ | 📋 Planned |
| FIPS 140-3 (crypto) | 📋 Planned |
| SOC 2 Type II | 📋 Planned |

### Performance

| Metric | Target |
|--------|--------|
| Scan throughput | > 500 MB/s |
| Memory usage | < 100 MB |
| Startup time | < 500 ms |
| False positive rate | < 0.01% |

---

## Technical Debt

| Item | Priority | Effort |
|------|----------|--------|
| Remove `unwrap()`/`expect()` in prod paths | High | Medium |
| Complete documentation coverage | Medium | Low |
| Benchmark suite | Medium | Medium |
| Fuzzing harnesses | High | Medium |
| Windows driver signing | High | High |
| Cross-platform CI | Medium | Low |

---

## Decision Log

| Decision | Date | Rationale |
|----------|------|-----------|
| Rust 1.80 MSVC | 2024-11 | Windows-native, best ecosystem |
| SQLite + Merkle | 2024-11 | Local, embedded, verifiable |
| AES-256-GCM quarantine | 2024-11 | Authenticated encryption standard |
| Ed25519 updates | 2024-11 | Small keys, fast verification |
| Aho-Corasick patterns | 2024-11 | Multi-pattern, linear time |
| No unsafe in parsers | 2024-11 | Memory safety guarantee |
| Apach-2.0 license | 2024-11 | Permissive, patent grant |
| Windows x64 first | 2024-11 | Target market, team expertise |

---

## Contribution Focus Areas

We welcome contributions in:

1. **Fuzzing** - Add harnesses for PE, ELF, pattern matchers
2. **Documentation** - Expand CLI examples, architecture diagrams
3. **Tests** - Integration tests for engine workflows
4. **Benchmarks** - Performance regression detection
5. **YARA/ML** - Prototype implementations

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.