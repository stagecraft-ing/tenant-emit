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
| `--corpus-attestation` | Path | None | Binds a precomputed corpus attestation by hash. Read, never recompute. Falls back to `OAP_CORPUS_ATTESTATION_PATH`. Applied only on the signer path. |
| `--require-corpus-binding` | Flag | `false` | Refuses to emit (exit 2) unless a corpus binding is actually applied (a corpus attestation resolved **and** a signer is present). Mirrors `--require-operator-key`. |
| `--sbom-dir` | Path | None | Produced-app root whose `.factory/sbom.cdx.json` and `.factory/audit.json` are bound into the certificate by content hash. Read, never recompute. Falls back to `OAP_SBOM_DIR`. Applied only on the signer path. |
| `--require-sbom-binding` | Flag | `false` | Refuses to emit (exit 2) unless an SBOM artifact binding is actually applied. Mirrors `--require-corpus-binding`. |
| `--stage-ids` | String | None | Comma-separated stage IDs, or `auto` for filesystem discovery. Empty entries are ignored. Defaults to OAP's `s0..s5` if omitted. |
| `--adapter` | String | `"unknown"` | Adapter name recorded in the pipeline state. |
| `--business-docs` | Paths... | None | Optional requirement documents. A domain-separated SHA-256 over them (each document length-prefixed) is recorded as the requirements hash. An unreadable document is a hard error (exit 2), never a partial hash. |
| `--requirements-hash` | String | None | Direct requirements hash. Ignored if `--business-docs` is given. |
| `--out` | Path | `<run-dir>/governance-certificate.json` | Full output file path (including the file name) for the emitted certificate. Parent directories are created as needed. |
| `--repo-root` | Path | `.` | Kept for upstream parity; a no-op on the tenant path since tenant certs carry no `spec_id`. |

### Environment Variables

| Variable | Description |
|---|---|
| `OAP_SIGNING_KEY` | Base64-encoded 32-byte Ed25519 seed used to sign the certificate. |
| `OAP_SIGNING_KEY_PATH` | Path to a file containing the base64-encoded Ed25519 seed. Checked if `OAP_SIGNING_KEY` is unset. The path itself is never written into the certificate: the signing attestation records only the source (`source=OAP_SIGNING_KEY_PATH`), not the file location. |
| `OAP_CORPUS_ATTESTATION_PATH` | Path to a spec-spine `CorpusAttestation` JSON to bind into the certificate. Fallback for `--corpus-attestation`. |
| `OAP_SBOM_DIR` | Produced-app root for the SBOM artifact binding. Fallback for `--sbom-dir`. |

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success. Certificate written. |
| `1` | Runtime I/O failure **after** the certificate was built (e.g., the certificate could not be persisted). |
| `2` | Configuration or input error, detected before anything is written: the run directory does not exist; `--tenant-mode` had no signer; an operator-supplied signing key is malformed; `--require-operator-key` resolved to an ephemeral key; a required binding (`--require-corpus-binding` / `--require-sbom-binding`) could not be applied; or a `--business-docs` file is unreadable. |

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
