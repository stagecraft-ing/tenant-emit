---
id: certificate-json-shape
title: Certificate JSON Shape
sidebar_position: 2
---

# Certificate JSON Shape

The `governance-certificate.json` file is the cryptographic proof of a factory run. Its shape is defined by the `GovernanceCertificate` Data Transfer Object (DTO).

## Core Structure

The JSON payload contains several key sections:

- **Metadata**: `certificateVersion` (pinned to `1.5.0`), `pipelineRunId`, `timestamp`, and `status`.
- **Intent & Specs**: `intent` (requirements hash) and `buildSpec` (hash of the frozen build specification).
- **Stages**: An array of `StageRecord` objects. Each stage contains an `artifactHashes` map, which is a lexicographic dictionary of every file in that stage and its SHA-256 hash.
- **Signer**: The identity of the principal that drove the run (`subject`, `identityProvider`, `sessionId`).
- **Corpus Binding**: (Optional) The hash of the spec-spine corpus attestation in effect during the run.

## Cryptographic Fields

The integrity of the certificate is secured by three fields at the bottom of the JSON payload:

1. `certificateHash`: The SHA-256 hash of the canonical JSON of the certificate.
2. `signingPublicKey`: The base64-encoded Ed25519 public key.
3. `certSignature`: The base64-encoded Ed25519 signature.

### Canonicalization

To compute the `certificateHash` and the `certSignature`, the emitter and verifier must agree on the exact byte representation of the JSON.

Before hashing or signing, the payload is canonicalized:
1. The `certificateHash` and `certSignature` fields are set to empty strings.
2. The `platformCountersign` field (if present) is zeroed.
3. The JSON object keys are sorted lexicographically.
4. The JSON is serialized without whitespace.

The signature is computed over this canonical byte string, and the resulting hash and signature are then injected back into the final JSON written to disk.
