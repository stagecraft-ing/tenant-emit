---
id: corpus-binding-advanced
title: Corpus Binding (Advanced)
sidebar_position: 5
---

# Corpus Binding (Advanced)

Corpus binding links a governance certificate to the exact set of rules (the specification corpus) that governed the run. This section details how `--corpus-attestation` works under the hood and the cryptographic guarantees it provides.

## The Corpus Attestation

A corpus attestation is a JSON artifact produced by `spec-spine attest`. It contains the hash of the specification registry and the verification verdicts (e.g., compile, lint) for that corpus.

```json
{
  "schemaVersion": "1.0.0",
  "tool": {
    "name": "spec-spine",
    "version": "0.10.0"
  },
  "inputsManifestHash": "...",
  "registryHash": "...",
  "verdicts": {
    "compile": { "ok": true },
    "lint": { "ok": true, "findingsHash": "..." }
  }
}
```

## The Read-Path Guarantee

When you pass `--corpus-attestation <path>`, `tenant-emit` reads this JSON file.

**It does not recompute the attestation.** It does not invoke `spec-spine compile` or `spec-spine attest`.

Instead, it reads the file and passes the payload through a public reader seam (`spec_spine_core::attest::attestation_hash`). This function computes the canonical SHA-256 hash of the attestation bytes.

This hash, along with the `spec-spine` version, is then recorded in the certificate:

```json
"corpusBinding": {
  "corpusAttestationHash": "...",
  "specSpineVersion": "0.10.0"
}
```

This read-never-recompute boundary is enforced at the compiler level. The `tenant-emit` workspace uses `clippy.toml` and `deny.toml` to ban the invocation of any `spec-spine` functions that compile or attest a corpus.

## Round-Trip Verification

When `tenant-tail verify-certificate` runs, it must verify this binding.

If the certificate contains a `corpusBinding`, the verifier requires the user to supply the exact same corpus attestation file. The verifier hashes the provided file and checks that the hash matches the `corpusAttestationHash` recorded in the certificate.

If the attestation file has been tampered with, or if the wrong attestation is provided, the hashes will mismatch, and verification will fail (exit 1). Because the binding is inside the certificate's signed payload, the binding itself cannot be altered without invalidating the Ed25519 signature.
