# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x (alpha) | ⚠️ Limited - security fixes on best-effort basis |
| Future releases | ✅ Planned |

## Reporting a Vulnerability

**Do not create public issues for security vulnerabilities.**

Send details to: **security@aegis-av.org** (or create a private GitHub Security Advisory)

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if known)

## Response Timeline

| Severity | Acknowledgment | Fix Target |
|----------|----------------|------------|
| Critical | 24 hours | 7 days |
| High | 48 hours | 14 days |
| Medium | 7 days | 30 days |
| Low | 14 days | Next release |

## Security Architecture

### Threat Model

AEGIS AV assumes:
- Untrusted input files (malicious binaries, crafted PE files)
- Local attacker with file write access
- Supply chain attacks on dependencies

### Defense in Depth

| Layer | Protection |
|-------|------------|
| **Input Validation** | All parsers validate structure before processing |
| **Memory Safety** | Rust ownership model, no unsafe in parsers |
| **Crypto** | AES-256-GCM (quarantine), Ed25519 (updates), SHA-256 (hashes) |
| **Integrity** | Merkle tree for signature DB, signed update manifests |
| **Sandboxing** | Planned: scanner sandbox, filter driver isolation |

### Known Attack Surface

| Component | Risk | Mitigation |
|-----------|------|------------|
| PE Parser | High | Input validation, fuzzing |
| SQLite DB | Medium | Prepared statements, read-only where possible |
| Crypto | Low | Audited crates (aes-gcm, ed25519-dalek) |
| IPC | Medium | Capability-based access |

## Secure Development

- All code compiled with `-D warnings`
- `cargo audit` in CI
- Dependencies pinned in `Cargo.lock`
- No `unsafe` in parsing logic
- Fuzzing via `cargo fuzz` (planned)

## Disclosure

Coordinated disclosure preferred. Public disclosure after fix release + 30 days.