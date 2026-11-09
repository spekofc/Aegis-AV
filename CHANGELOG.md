# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Professional README with architecture diagram
- SECURITY.md policy
- CONTRIBUTING.md guidelines
- CHANGELOG.md

### Changed
- Repository restructured to professional standards
- Documentation organized under `docs/`

### Security
- SECURITY.md with vulnerability reporting process

## [0.1.0-alpha.1] - 2024-11-09

### Added
- **Core Engine**: Async orchestrator with pluggable scanner
- **Hash Detection**: SHA-256 lookup with instant matching
- **Pattern Matching**: Aho-Corasick multi-pattern engine
- **Heuristic Analysis**: Temp-directory executable detection
- **PE Analysis**: Section entropy, import analysis, structure validation
- **Quarantine Engine**: AES-256-GCM encryption, JSON metadata persistence
  - Add, List, Restore (with decryption), Destroy operations
  - Integrity verification on restore via SHA-256
- **Signature Database**: SQLite with Merkle tree integrity
  - Hash and pattern signature types
  - Ed25519 signed metadata
  - CLI add/status commands
- **Scanner Engine**: Multi-engine async scanning
  - Hash → Pattern → Heuristic → PE pipeline
  - Per-file and recursive directory scanning
  - JSON output for automation
- **Self-Test**: Clean file + EICAR detection verification
- **CLI**: Full command set
  - `scan`, `quarantine`, `signatures`, `status`, `selftest`
  - Global `--json` flag for structured output
- **Signature Matcher**: Hash index + Aho-Corasick pattern matcher
- **Merkle Integrity**: Signed root, inclusion proofs for signatures
- **Update Framework**: Ed25519 signed manifests, component updates, transparency log
- **IPC Layer**: ALPC, Named Pipes, Filter Port abstractions
- **Telemetry**: ETW provider, metrics, structured events
- **Anti-Exploit**: DEP/ASLR/SEHOP/CET enforcement stubs
- **Test Suite**: 38 tests across all crates
- **CI Pipeline**: GitHub Actions (Windows + Linux)

### Fixed
- PE parser gracefully handles non-PE files
- Heuristic only flags executables in temp directories
- Quarantine key persistence across restarts
- Signature matcher auto-reloads on database changes

### Security
- AES-256-GCM for quarantine encryption
- Ed25519 for update manifest signing
- SHA-256 for all hash operations
- Prepared statements for all SQLite queries
- No `unsafe` in parsing code

### Known Issues
- Windows x64 only
- Real-time protection not implemented
- Signature database empty by default
- Linux/macOS not supported
- Alpha quality - not for production use