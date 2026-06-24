---
id: governance-certificate
title: Governance Certificate
sidebar_position: 1
---

# Governance Certificate

A governance certificate is a self-authenticating JSON artifact that proves the full chain from intent to auditable output for a factory pipeline run.

## Structure

The certificate is structured as a top-level `GovernanceCertificate` object containing sub-records for the run's intent, build specification, stage artifacts, verification outcomes, and the cryptographic proof chain.

The certificate is content-addressed and signed. The `certificateHash` is the SHA-256 of the canonical JSON of the certificate (with the hash and signature fields zeroed). The `certSignature` is an Ed25519 signature over that canonical JSON.

## Version `1.5.0`

`tenant-emit` and `tenant-tail` are tightly coupled to a specific certificate format version.

The certificate version is strictly pinned to **`1.5.0`**.

This version string is a fixed value that the verifier checks by strict equality. It is load-bearing: bumping the version would cause the verifier to reject the certificate.

Version `1.5.0` carries the additive `corpusBinding` field. Because this field is skipped in serialization when absent, an unbound certificate serializes identically to a pre-binding payload, meaning the version pin remains stable regardless of whether corpus binding is used.

## Verifiable-but-unsealed

A tenant-emitted certificate carries no platform countersign.

The `platformCountersign` field exists in the schema (for serialization parity with the upstream platform) but is always omitted by `tenant-emit`. A tenant run occurs outside the platform's admission and grant flow, so there is no platform seal to apply.

This makes the certificate **verifiable-but-unsealed**. It is visibly unsealed, never silently equivalent to a platform-sealed certificate, and round-trips perfectly offline.
