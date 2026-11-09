## Description

Brief summary of changes.

## Type

- [ ] Bug fix
- [ ] New feature
- [ ] Refactoring
- [ ] Documentation
- [ ] Test
- [ ] CI/CD
- [ ] Security

## Related Issues

Closes #

## Changes

### Crates Modified

- [ ] aegis-core
- [ ] aegis-config
- [ ] aegis-scanner
- [ ] aegis-signatures
- [ ] aegis-quarantine
- [ ] aegis-engine
- [ ] aegis-cli
- [ ] aegis-updater
- [ ] aegis-realtime
- [ ] aegis-antiexploit
- [ ] aegis-ipc
- [ ] aegis-telemetry
- [ ] aegis-test-utils

### Summary

-
-
-

## Testing

- [ ] All existing tests pass (`cargo test --workspace`)
- [ ] New tests added for new functionality
- [ ] Manual testing performed:

```bash
# Commands run
aegis scan ...
aegis quarantine ...
```

## Code Quality

- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` passes
- [ ] `cargo build --release --workspace` succeeds
- [ ] No new `unsafe` blocks in parsing code
- [ ] Error handling uses `Result<T>` appropriately

## Documentation

- [ ] Public APIs documented with `///`
- [ ] Module-level docs (`//!`) where appropriate
- [ ] CLI.md updated if CLI changed
- [ ] ARCHITECTURE.md updated if architecture changed
- [ ] CHANGELOG.md entry added under `[Unreleased]`

## Security

- [ ] No secrets/tokens in code
- [ ] No new attack surface without mitigation
- [ ] Dependencies audited (`cargo audit`)

## Breaking Changes

- [ ] No breaking changes
- [ ] Breaking changes documented and justified

## Screenshots / Logs

(If applicable)

---

## Reviewer Checklist

- [ ] Architecture aligns with project principles
- [ ] Tests are meaningful and comprehensive
- [ ] Error handling is consistent
- [ ] Performance impact assessed
- [ ] Documentation is clear and complete