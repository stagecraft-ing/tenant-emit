---
id: testing
title: Testing
sidebar_position: 2
---

# Testing

The project maintains strict quality gates that must pass before any commit is merged.

## Running the Test Suite

You can run the full test suite using Cargo:

```bash
cargo test --workspace --locked
```

The test suite includes both unit tests in the core crate and end-to-end integration tests in the CLI crate.

### Integration Tests

The integration tests (`crates/tenant-emit-cli/tests/tenant_emission_integration.rs`) are particularly important. They drive the actual `tenant-emit` binary against a dynamically generated sample run directory.

These tests assert the core spec contracts:
- The operator key requirement (`--require-operator-key` refuses ephemeral keys).
- The halt-before-emit posture when a signer is missing in tenant mode.
- The determinism of artifact hashes across re-emissions.
- The correctness of the corpus binding read-path.

## Linting and Formatting

All code must pass Clippy with no warnings, and must be formatted with `rustfmt`.

```bash
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all --check
```

The Clippy configuration (`clippy.toml`) is load-bearing. It contains specific `disallowed-methods` rules that ban the invocation of any `spec-spine` functions capable of compiling or re-attesting a corpus, enforcing the read-never-recompute invariant.
