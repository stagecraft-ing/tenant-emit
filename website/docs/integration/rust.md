---
id: rust
title: Rust Projects
sidebar_position: 3
---

# Integration: Rust

For Rust projects, or for users on unsupported platforms (like Alpine Linux / musl), you can install the CLI directly from crates.io using Cargo.

## Installation

Install the `tenant-emit-cli` crate:

```bash
cargo install tenant-emit-cli
```

This will compile the binary from source and place it in your `~/.cargo/bin` directory.

## Usage

Once installed, the binary is available on your path as `tenant-emit`.

```bash
tenant-emit build-certificate .factory/runs/latest \
  --tenant-mode \
  --signer-subject "dev" \
  --signer-identity-provider "local" \
  --stage-ids auto
```

## Integration via `cargo-run-bin` or `cargo-binstall`

To ensure reproducible builds across your team and CI, you can manage the binary version using tools like `cargo-binstall` or `cargo-run-bin` rather than a global `cargo install`.

```bash
cargo binstall tenant-emit-cli
```
