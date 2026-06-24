---
id: signer-and-identity
title: Signer and Identity
sidebar_position: 3
---

# Signer and Identity

A governance certificate must be attributable to the principal that drove the run.

## Tenant Mode

When `tenant-emit` is invoked with the `--tenant-mode` flag, it requires a signer to be attached to the certificate. If no signer is provided, the binary will halt before emitting and exit with code `2`.

Anonymous signing is forbidden in tenant mode.

## Signer Identity

A signer is composed of three fields:

1. **Subject**: The principal identifier (e.g., a JWT subject, a user email, or a machine identity).
2. **Identity Provider**: The system that attested the subject (e.g., `rauthy@<tenant-org>` or `github-actions@<repo>`).
3. **Session ID** (Optional): A run-scoped session identifier.

These are provided to the CLI via the `--signer-subject`, `--signer-identity-provider`, and `--signer-session-id` flags.

If you provide a subject, you must provide an identity provider, and vice versa.

## Example

```bash
tenant-emit build-certificate .factory/runs/run-it-001 \
  --tenant-mode \
  --signer-subject "alice@example.com" \
  --signer-identity-provider "okta@example-org" \
  --signer-session-id "sess-12345"
```

This binds the identity into the `signer` block of the certificate, which is then covered by the content-binding hash and the Ed25519 signature.
