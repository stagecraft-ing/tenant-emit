---
id: emit-only-design
title: Emit-Only Design
sidebar_position: 1
---

# Emit-Only Design

The fundamental architectural principle of `tenant-emit` is that it is **emit-only by construction**.

## Separation of Powers

In the Open Agentic Platform (OAP), the factory engine both orchestrates the pipeline and verifies the artifacts. However, in a tenant environment, the pipeline is run by the tenant, on tenant infrastructure.

If the tool that produced the certificate also verified it, a compromised pipeline could simply instruct the tool to output "Verification Passed" regardless of the actual state of the artifacts.

To solve this, the capability to emit the certificate and the capability to verify it are split into two completely separate distributables:

1. **`tenant-emit`**: Scans the run directory, computes hashes, signs the payload, and writes the JSON. It has no verify verb.
2. **`tenant-tail`**: Reads the JSON, checks the signature, and re-derives the hashes. It has no emit verb.

## The Verify/Emit Boundary

This verify/emit boundary is load-bearing. It ensures that an auditor can take a certificate produced by `tenant-emit` and verify it using `tenant-tail` on an air-gapped machine, without ever trusting the CI pipeline that ran `tenant-emit`.

By excluding the verification logic from `tenant-emit`, the binary remains small, focused, and incapable of silently approving a tampered run.
