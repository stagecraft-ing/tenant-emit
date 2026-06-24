---
id: business-docs
title: Business Docs & Requirements
sidebar_position: 5
---

# Business Docs & Requirements Hashing

The governance certificate includes an `intent` block that captures the initial requirements or business documents that drove the run.

```json
"intent": {
  "requirementsHash": "..."
}
```

You can populate this hash in two ways during emission.

## Hashing Files Directly

If you have the business requirement documents available on disk at emission time, you can pass them to the `--business-docs` flag. The emitter will read the files, concatenate their contents, compute a single SHA-256 hash, and record it in the certificate.

```bash
tenant-emit build-certificate <run-dir> \
  --business-docs ./docs/PRD.md ./docs/security-requirements.pdf \
  --stage-ids auto
```

## Providing a Precomputed Hash

If the requirements were hashed earlier in the pipeline and the files are no longer available, you can provide the precomputed hash directly using the `--requirements-hash` flag.

```bash
tenant-emit build-certificate <run-dir> \
  --requirements-hash "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" \
  --stage-ids auto
```

If both `--business-docs` and `--requirements-hash` are provided, the `--business-docs` flag takes precedence, and the explicit hash is ignored.
