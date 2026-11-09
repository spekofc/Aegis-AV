# Contributing to AEGIS AV

Thank you for contributing to AEGIS AV!

## Code of Conduct

By participating, you agree to maintain a respectful, inclusive environment. Harassment, discrimination, or abusive behavior will not be tolerated.

## Getting Started

### Prerequisites

- Rust 1.80+ (MSVC toolchain)
- Windows 10+ x64 for development
- Git

### Development Setup

```bash
git clone https://github.com/spekofc/Aegis-AV.git
cd Aegis-AV
cargo build --workspace
cargo test --workspace
```

## Code Standards

### Formatting

```bash
cargo fmt --all
```

All code must pass `cargo fmt --check`.

### Linting

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

No warnings allowed in CI.

### Rust Edition

- 2021 edition
- Minimum Rust version: 1.80

## Architecture Principles

| Principle | Description |
|-----------|-------------|
| **Modularity** | Crates are independently compilable, minimal deps |
| **Zero unsafe in parsers** | All parsing uses safe Rust |
| **Result<T> for fallible ops** | No panics in library code |
| **Trait-based design** | Engines implement core traits |
| **Async where appropriate** | Scanning, I/O use async/await |

## Pull Request Process

### Before Submitting

1. Run full test suite: `cargo test --workspace`
2. Check formatting: `cargo fmt --check`
3. Run clippy: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
4. Build release: `cargo build --release --workspace`

### PR Requirements

| Requirement | Mandatory |
|-------------|-----------|
| Tests for new functionality | ✅ |
| Documentation for public APIs | ✅ |
| `CHANGELOG.md` entry | ✅ |
| No warnings | ✅ |
| All tests pass | ✅ |

### Commit Format

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `ci`, `security`

Examples:
```
feat(scanner): add YARA rule support
fix(quarantine): restore fails on corrupted metadata
docs(cli): add --json examples
refactor(core): unify error types
```

### Branch Naming

```
feat/short-description
fix/short-description
refactor/short-description
docs/short-description
```

## Testing

### Running Tests

```bash
# All tests
cargo test --workspace

# Specific crate
cargo test -p aegis-scanner

# With output
cargo test --workspace -- --nocapture
```

### Test Requirements

- All new functionality requires tests
- Unit tests for pure logic
- Integration tests for engine workflows
- Fixtures in `tests/fixtures/`
- No flaky tests

### Test Categories

| Category | Location | Purpose |
|----------|----------|---------|
| Unit | `crates/*/src/**/*_test.rs` | Pure logic |
| Integration | `tests/` | Engine workflows |
| Fixtures | `tests/fixtures/` | Real binaries |

## Architecture Decisions

### Adding a New Crate

1. Create under `crates/` with `Cargo.toml`
2. Add to workspace `Cargo.toml`
3. Define public API in `src/lib.rs`
4. Implement `aegis_core::traits` where applicable
4. Add tests
5. Update `README.md` crate table

### Engine Extensions

| Extension Point | Trait | Location |
|-----------------|-------|----------|
| Detection engine | `DetectionEngine` | `aegis-core/src/traits.rs` |
| Scanner module | `ScannerModule` | `aegis-scanner/src/lib.rs` |
| Signature type | `SignatureType` | `aegis-signatures/src/format.rs` |

### Configuration

- Use `aegis-config` for structured config
- Serialize with `serde`
- Validate on load

## Documentation

### Requirements

- All public items: `///` doc comments
- Module-level docs: `//!`
- Examples in doc comments where helpful
- CLI commands: update `docs/CLI.md`

### Building Docs

```bash
cargo doc --workspace --no-deps --open
```

## Performance

### Benchmarks

```bash
cargo bench --workspace
```

### Guidelines

- Avoid allocations in hot paths
- Use `Bytes`/`BytesMut` for I/O
- Profile with `cargo flamegraph`

## Security

### Reporting Issues

See [SECURITY.md](SECURITY.md)

### Dependencies

- Audit with `cargo audit` before PR
- Pin versions in `Cargo.lock`
- Minimize transitive dependencies

## Review Checklist

### For Authors

- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] `CHANGELOG.md` entry added
- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy` passes
- [ ] `cargo test --workspace` passes
- [ ] `cargo build --release --workspace` succeeds

### For Reviewers

- [ ] Architecture aligns with principles
- [ ] No `unsafe` in parsing code
- [ ] Error handling uses `Result<T>`
- [ ] Tests are meaningful
- [ ] Documentation is clear
- [ ] No performance regressions

## License

By contributing, you agree your contributions are licensed under Apache License 2.0.