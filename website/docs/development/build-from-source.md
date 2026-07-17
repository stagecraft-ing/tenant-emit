---
id: build-from-source
title: Build from Source
sidebar_position: 1
---

# Build from Source

`tenant-emit` is a standard Rust workspace. Building it from source requires a Rust toolchain.

## Prerequisites

- Rust edition 2024
- `rustc` version 1.85 or higher
- Cargo

## Building the CLI

Clone the repository and build the `tenant-emit-cli` package in release mode:

```bash
git clone https://github.com/statecrafting/tenant-emit.git
cd tenant-emit
cargo build --release -p tenant-emit-cli
```

The compiled binary will be available at `target/release/tenant-emit`.

## Workspace Structure

The repository is organized as a three-crate Cargo workspace:

- `crates/tenant-emit-types`: The serializable Data Transfer Objects (DTOs) for the certificate.
- `crates/tenant-emit-core`: The emit engine, builder, and cryptographic hashing/signing logic.
- `crates/tenant-emit-cli`: The CLI binary containing the `build-certificate` verb.

No `unsafe` code is permitted anywhere in the workspace. This is enforced by a workspace-wide `unsafe_code = "forbid"` lint.
