---
id: determinism
title: Determinism
sidebar_position: 3
---

# Determinism

`tenant-emit` provides a strict determinism guarantee for the artifact hashes it computes.

## Re-Emission Guarantee

If you run `tenant-emit build-certificate` multiple times against the exact same run directory, the deterministic content of the certificate will be identical across every run.

Specifically, the `stages` array, the `artifactHashes` within each stage, the `intent` block, and the `buildSpec` block will be byte-for-byte identical.

## Non-Deterministic Fields

The only fields that change between re-emissions are those that carry per-run identity:

1. **`timestamp`**: The exact time the certificate was emitted.
2. **`certSignature`**: The Ed25519 signature (which covers the new timestamp).
3. **`certificateHash`**: The self-hash (which covers the new timestamp).

If the same operator key and signer identity are provided, the `signer` and `signingPublicKey` fields will also remain identical.

This determinism allows auditors to verify that the artifact hashes recorded in the certificate perfectly represent the state of the filesystem at the time of emission, without race conditions or non-deterministic ordering.
