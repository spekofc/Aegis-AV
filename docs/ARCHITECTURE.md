# Architecture

## System Overview

AEGIS AV follows a modular, plugin-based architecture with clear separation of concerns. Each detection layer is implemented as an independent crate, orchestrated by the central engine.

```
┌─────────────────────────────────────────────────────────────┐
│                      AEGIS Core                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │ Scanner  │  │Quarantine│  │Signatures│  │  Config  │    │
│  │ Engine   │  │ Engine   │  │  Engine  │  │  Manager │    │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘    │
└───────┼──────────────┼──────────────┼──────────────┼────────┘
        │              │              │              │
        ▼              ▼              ▼              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Supporting Crates                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │  Core    │ │  IPC     │ │Telemetry │ │ Updater  │       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### Engine Orchestrator (`aegis-engine`)

Central coordinator that:
- Initializes all subsystems
- Manages async scanning workflow
- Provides unified API for CLI and future GUI/SDK
- Handles signature database lifecycle

```rust
pub struct AegisEngine {
    config: EngineConfig,
    scanner: Arc<ScannerEngine>,
    signature_db: Arc<SignatureDatabase>,
}
```

### Scanner Engine (`aegis-scanner`)

Multi-stage detection pipeline executed sequentially:

```
File Input
    │
    ▼
┌─────────────────┐
│  Hash Lookup    │ ──► SHA-256 match → Malicious (100% confidence)
│  (Fastest)      │
└────────┬────────┘
         │ No match
         ▼
┌─────────────────┐
│ Pattern Match   │ ──► Aho-Corasick → Suspicious/Malicious
│ (Aho-Corasick)  │     (90% confidence)
└────────┬────────┘
         │ No match
         ▼
┌─────────────────┐
│ Heuristic       │ ──► Temp-dir executable → Suspicious
│ Analysis        │     (60% confidence)
└────────┬────────┘
         │ No match
         ▼
┌─────────────────┐
│ PE Analysis     │ ──► Sections, imports, entropy
│ (Windows only)  │
└────────┬────────┘
         │
         ▼
     Clean
```

### Signature Database (`aegis-signatures`)

SQLite-based with cryptographic integrity:

```
signatures.db
├── signatures (hash signatures)
├── patterns (byte patterns)
├── meta (version, counts, Merkle root)
└── merkle_tree (leaf hashes, signed root)
```

**Integrity Model:**
- Merkle tree over all signature records
- Ed25519 signed root stored in `meta`
- Inclusion proofs for individual records
- Auto-verification on load

### Quarantine Engine (`aegis-quarantine`)

```rust
pub struct QuarantineItem {
    id: QuarantineId,
    path: PathBuf,           // Encrypted file location
    original_path: PathBuf,  // Original location
    threat_name: String,
    threat_type: ThreatType,
    size: u64,
    hash: Sha256,            // SHA-256 of original
    quarantined_at: Timestamp,
    encrypted: bool,
}
```

**Encryption:** AES-256-GCM with per-installation key (stored in metadata.json)
**Persistence:** JSON metadata + encrypted files in `data/Quarantine/`

### Configuration (`aegis-config`)

- Secure serialization with entropy-bound sealing
- File-based provider with schema validation
- License management with Ed25519 verification

## Data Flow

### Scan Request

```
CLI/API
    │
    ▼
Engine::scan_file(path, context)
    │
    ▼
ScannerEngine::scan_file()
    │
    ├── Hash Lookup
    ├── Pattern Match
    ├── Heuristic Analysis
    └── PE Analysis (if applicable)
    │
    ▼
ScanResult { disposition, threat_type, confidence, ... }
    │
    ▼
Engine returns result → CLI formats output
```

### Signature Update

```
Remote Server
    │
    ▼
Signed Manifest (Ed25519)
    │
    ▼
Updater verifies signature
    │
    ▼
Component hashes verified
    │
    ▼
Atomic DB replacement
    │
    ▼
Matcher.reload() → Engine hot-reload
```

## Concurrency Model

- **ScannerEngine**: `Semaphore` limits concurrent scans (configurable)
- **Database**: SQLite WAL mode, connection pool via `sqlx`
- **Quarantine**: `RwLock<HashMap>` for metadata, file ops async
- **Matcher**: Read-mostly, `Arc<HashIndex>` + `Arc<PatternMatcher>`

## Extension Points

| Trait | Purpose | Implementors |
|-------|---------|--------------|
| `DetectionEngine` | New detection methods | Scanner modules |
| `ScannerModule` | Custom scan stages | YARA, ML, Cloud |
| `SignatureType` | New signature formats | YARA, Fuzzy hash |

## Security Boundaries

| Boundary | Protection |
|----------|------------|
| File input → Parser | Input validation, bounds checking |
| Parser → Engine | Safe types, no `unsafe` |
| Engine → Quarantine | Encryption, integrity verification |
| Network → Updater | Signature verification, pinning |
| IPC → Engine | Capability-based, authenticated |

## Future Architecture

### Planned: Sandboxed Scanning

```
┌─────────────────┐
│  Host Process   │
│  (Engine)       │
└────────┬────────┘
         │ IPC (capability-based)
         ▼
┌─────────────────┐
│  Scanner Sandbox│  (restricted token, job object)
│  - No network   │
│  - No file write│
│  - Read-only    │
└─────────────────┘
```

### Planned: Plugin System

```
aegis-engine
    │
    ├── builtin: Hash, Pattern, Heuristic, PE
    └── plugins: YARA, ML, Cloud, Behavioral
```

Plugins loaded as dynamic libraries with capability-based API.