# Building AEGIS AV

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Rust | 1.80+ | [rustup.rs](https://rustup.rs/) |
| Cargo | 1.80+ | Included with Rust |
| Windows | 10+ x64 | Target platform |
| Git | 2.40+ | For cloning |

### Rust Toolchain

```bash
# Install stable toolchain
rustup install stable
rustup default stable

# Add components
rustup component add rustfmt clippy

# Verify
rustc --version
cargo --version
```

## Building

### Debug Build

```bash
git clone https://github.com/spekofc/Aegis-AV.git
cd Aegis-AV

cargo build --workspace
```

Output: `target/debug/aegis.exe`

### Release Build

```bash
cargo build --release --workspace
```

Output: `target/release/aegis.exe` (optimized, stripped)

### Build with Features

```bash
# All features (default)
cargo build --release --workspace

# Specific crate
cargo build --release -p aegis-cli
```

## Testing

### Run All Tests

```bash
cargo test --workspace
```

Expected: **38 tests passing**

### Per-Crate Tests

```bash
cargo test -p aegis-core
cargo test -p aegis-config
cargo test -p aegis-scanner
cargo test -p aegis-signatures
cargo test -p aegis-test-utils
```

### Test Output

```bash
# Verbose
cargo test --workspace -- --nocapture

# Specific test
cargo test -p aegis-scanner test_heuristic_rules
```

## Code Quality

### Formatting

```bash
# Check
cargo fmt --check

# Fix
cargo fmt
```

### Linting

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

### Documentation

```bash
# Build and open
cargo doc --workspace --no-deps --open

# Check for missing docs
cargo doc --workspace 2>&1 | grep -i warning
```

## CI Pipeline

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs on every push/PR:

```yaml
Jobs:
  - build-test (Windows)
    - cargo fmt --check
    - cargo check --workspace
    - cargo clippy --workspace --all-targets --all-features
    - cargo test --workspace
    - cargo build --release --workspace
    - Verify binary runs

  - build-linux (Ubuntu, continue-on-error)
    - cargo check --workspace
    - cargo test --workspace
```

## Windows-Specific Notes

### MSVC Toolchain (Required)

```bash
# Verify MSVC is default
rustup show
# Should show: stable-x86_64-pc-windows-msvc (default)
```

### Visual Studio Dependencies

Install **Visual Studio 2022** with:
- Desktop development with C++
- Windows 10/11 SDK

Or install **Build Tools for Visual Studio 2022** (smaller):
```bash
# Download from visualstudio.microsoft.com
# Select: MSVC v143, Windows 10 SDK, C++ CMake tools
```

### Linker

Uses `link.exe` (MSVC). For faster incremental builds, consider `lld-link`:
```bash
# .cargo/config.toml
[target.x86_64-pc-windows-msvc]
linker = "lld-link"
```

## Troubleshooting

### `error: linker link.exe not found`

Install Visual Studio Build Tools with C++ workload.

### `error: failed to run custom build command for openssl-sys`

Install Perl and NASM:
```bash
# Via Chocolatey
choco install strawberryperl nasm

# Or manual: install Perl from strawberryperl.com, NASM from nasm.us
```

### `cargo test` hangs on Windows

```bash
# Increase timeout
cargo test --workspace -- --test-threads=1
```

### Out of memory during release build

```bash
# Limit parallel jobs
cargo build --release --workspace -j 4
```

## Development Workflow

### Hot Reload (Not Available)

Rust requires recompilation. For faster iteration:
```bash
# Check only (no codegen)
cargo check --workspace

# Specific crate
cargo check -p aegis-scanner
```

### Adding a Crate

1. `cargo new --lib crates/aegis-new`
2. Add to workspace `Cargo.toml` members
3. Define public API in `src/lib.rs`
4. Add tests
5. Update `README.md` crate table

## Release Process

```bash
# 1. Update version in Cargo.toml workspace
# 2. Update CHANGELOG.md
# 3. cargo test --workspace
# 4. cargo build --release --workspace
# 5. Test binary manually
# 6. git tag v0.1.0-alpha.X
# 7. git push origin main --tags
# 8. GitHub Actions creates release
# 9. Attach binary to release
```

## Cross-Compilation (Not Supported Yet)

Currently Windows x64 only. Linux/macOS support planned.

## IDE Setup

### VS Code (Recommended)

Extensions:
- `rust-analyzer`
- `Even Better TOML`
- `CodeLLDB` (debugging)

Settings (`.vscode/settings.json`):
```json
{
  "rust-analyzer.checkOnSave": true,
  "rust-analyzer.check.command": "clippy",
  "files.trimTrailingWhitespace": true
}
```

### CLion / IntelliJ Rust

- Enable `cargo check` on save
- Configure `rustfmt` on save