---
id: key-custody
title: Key Custody
sidebar_position: 3
---

# Key Custody

The Ed25519 signing key used to sign the governance certificate is an operator-supplied tenant secret. It is the root of trust for the emitted certificate.

:::warning
Signing keys live completely outside the repository and outside any agent's write scope. The platform mints the key and sets it as the repository CI secret at project creation.
:::

## Environment Variables

The emitter resolves the signing key from the environment, checking variables in the following order:

1. `OAP_SIGNING_KEY`: The base64-encoded 32-byte Ed25519 seed directly.
2. `OAP_SIGNING_KEY_PATH`: A file path pointing to the base64-encoded seed.

If neither is found, the emitter will fall back to generating a dev-only ephemeral key for the lifetime of the run.

## The `--require-operator-key` flag

In a production pipeline, a certificate signed by an ephemeral key is untrusted and useless. To prevent a pipeline from silently emitting an untrusted certificate due to a misconfigured environment variable, use the `--require-operator-key` flag.

```bash
tenant-emit build-certificate <run-dir> ... --require-operator-key
```

When this flag is set, the binary will exit with code `2` and refuse to write the certificate if the signing material resolves to an ephemeral key.

## Trust Posture

The certificate records the origin of the key in the `signingAttestation.kind` field:

- `"operator"`: The key was supplied via `OAP_SIGNING_KEY` or `OAP_SIGNING_KEY_PATH`. The operator vouches for runs using this key.
- `"ephemeral"`: A key was generated for this run. Trust is limited to "the run was internally consistent." Suitable for local development only.

The accompanying `signingAttestation.note` records only the *source* of the key (for example `source=OAP_SIGNING_KEY_PATH`), never the key file's filesystem path: the certificate is a shareable, offline-verifiable artifact, so it must not leak where the operator keeps the signing key.

A malformed operator-supplied key is a hard configuration error (exit code 2), never a silent fall-back to an ephemeral key: an operator who tried to supply a key is told it was rejected rather than getting an untrusted certificate.

The `tenant-tail` verifier will inspect this field when evaluating the certificate's trust posture.
