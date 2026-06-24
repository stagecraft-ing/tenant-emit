---
id: corpus-binding
title: Corpus Binding
sidebar_position: 4
---

# Corpus Binding

Corpus binding links the governance certificate to the specific version of the specification corpus that was in effect during the run.

## Read, Never Recompute

The most critical invariant of corpus binding in `tenant-emit` is **read, never recompute**.

When you supply a corpus attestation via `--corpus-attestation` (or the `OAP_CORPUS_ATTESTATION_PATH` environment variable), the emitter reads the JSON file and binds its hash into the certificate.

The emitter **never** compiles or re-attests the corpus itself. The surface area required to recompute the attestation is intentionally banned at the compiler and crate level to ensure the emitter cannot invent or alter the governance rules.

## The Binding

The binding is recorded in the `corpusBinding` block of the certificate:

```json
"corpusBinding": {
  "corpusAttestationHash": "...",
  "specSpineVersion": "0.8.0"
}
```

This block is included inside the content-binding hash and the Ed25519 signature.

## Optional and Additive

Corpus binding is an optional, additive feature. If no attestation is provided, the certificate is emitted in an "unbound" state. This is a named state, not a failure condition. An unbound certificate serializes identically to a pre-binding payload, maintaining compatibility with the strict `1.5.0` version pin.
