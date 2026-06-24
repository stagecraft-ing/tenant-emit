---
id: extraction-and-relicensing
title: Extraction and Relicensing
sidebar_position: 4
---

# Extraction and Relicensing

`tenant-emit` is not a clean-room implementation of a certificate emitter. It is a direct, authorized extraction from the upstream Open Agentic Platform (OAP) factory engine.

## The Extraction Boundary

The OAP factory engine is licensed under `AGPL-3.0-or-later`. It contains the complete logic for pipeline orchestration, certificate emission, and certificate verification.

To create `tenant-emit`, the specific source files responsible for the certificate Data Transfer Objects (DTOs) and the emit engine were extracted:

- `crates/factory-engine/src/bin/build_certificate.rs` → `crates/tenant-emit-cli/src/main.rs`
- `crates/factory-engine/src/governance_certificate.rs` → `crates/tenant-emit-types/src/certificate.rs` and `crates/tenant-emit-core/src/certificate.rs`

The verification logic, platform sealing, and key minting were explicitly excluded and stripped from the extracted files.

## Relicensing to Apache-2.0

Because the extracted code is intended to be run by tenants in their own CI pipelines, it requires a permissive license.

The sole copyright holder explicitly authorized the relicensing of this extracted, emit-only source code from `AGPL-3.0-or-later` to `Apache-2.0`.

This relicensing allows `tenant-emit` to be freely distributed via npm, PyPI, and crates.io, and integrated into proprietary tenant pipelines without triggering copyleft obligations. The upstream OAP engine remains AGPL-3.0.
