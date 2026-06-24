---
id: cli-reference
title: CLI Reference
sidebar_position: 4
---

# CLI Reference

`tenant-emit` has exactly one verb: `build-certificate`.

## `build-certificate`

Reconstructs a signed `governance-certificate.json` from a finished run directory.

```bash
tenant-emit build-certificate <run-dir> [FLAGS]
```

### Arguments

| Argument | Description |
|---|---|
| `<run-dir>` | Path to the factory run directory (e.g., `.factory/runs/<run_id>`). |

### Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `--tenant-mode` | Flag | `false` | Requires a signer. The binary halts before emission if no signer is provided. |
| `--require-operator-key` | Flag | `false` | Refuses the ephemeral dev-only key fallback. Exits with code 2 if the key resolves to ephemeral. |
| `--signer-subject` | String | None | Principal identifier (e.g., a JWT subject). Required if `--tenant-mode` is set. |
| `--signer-identity-provider` | String | None | The system that attested the subject. Required if `--signer-subject` is set. |
| `--signer-session-id` | String | None | Optional run-scoped session ID. |
| `--corpus-attestation` | Path | None | Binds a precomputed corpus attestation by hash. Read, never recompute. Falls back to `OAP_CORPUS_ATTESTATION_PATH`. |
| `--stage-ids` | String | None | Comma-separated stage IDs, or `auto` for filesystem discovery. Defaults to OAP's `s0..s5` if omitted. |
| `--adapter` | String | `"unknown"` | Adapter name recorded in the pipeline state. |
| `--business-docs` | Paths... | None | Optional requirement documents. Their concatenated SHA-256 is recorded as the requirements hash. |
| `--requirements-hash` | String | None | Direct requirements hash. Ignored if `--business-docs` is given. |
| `--out` | Path | `<run-dir>` | Override certificate output path. Defaults to `<run-dir>/governance-certificate.json`. |
| `--repo-root` | Path | `.` | Kept for upstream parity; a no-op on the tenant path since tenant certs carry no `spec_id`. |

### Environment Variables

| Variable | Description |
|---|---|
| `OAP_SIGNING_KEY` | Base64-encoded 32-byte Ed25519 seed used to sign the certificate. |
| `OAP_SIGNING_KEY_PATH` | Path to a file containing the base64-encoded Ed25519 seed. Checked if `OAP_SIGNING_KEY` is unset. |
| `OAP_CORPUS_ATTESTATION_PATH` | Path to a spec-spine `CorpusAttestation` JSON to bind into the certificate. |

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success. Certificate written. |
| `1` | Validation or runtime error (e.g., failed to persist certificate). |
| `2` | Configuration error. Raised if `--require-operator-key` refused an ephemeral key, if `--tenant-mode` had no signer, or if the run directory does not exist. |

## Examples

**Basic tenant emission with auto-discovered stages:**

```bash
tenant-emit build-certificate .factory/runs/run-123 \
  --tenant-mode \
  --signer-subject "bot@ci" \
  --signer-identity-provider "github-actions" \
  --stage-ids auto
```

**Production emission enforcing operator key and binding a corpus:**

```bash
tenant-emit build-certificate .factory/runs/run-123 \
  --tenant-mode \
  --signer-subject "alice@example.com" \
  --signer-identity-provider "okta" \
  --corpus-attestation ./attestation.json \
  --require-operator-key \
  --stage-ids auto
```

**Custom output path and specific stages:**

```bash
tenant-emit build-certificate .factory/runs/run-123 \
  --stage-ids "s0-preflight,tenant-build" \
  --out ./dist/cert.json
```
