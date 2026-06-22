# tenant-emit

**The vended tenant emission surface. Spine to tail to emit: spec-spine compiles
the corpus, tenant-tail verifies the factory's run-side paperwork, and
tenant-emit produces it.**

tenant-emit is an emit-only CLI a produced application pins (one exact-version
npm devDependency, next to `spec-spine` and `tenant-tail`) to build a signed
`governance-certificate.json` from a finished run directory. It is the emit-side
counterpart of tenant-tail: post-hoc (no pipeline orchestration), identity-bearing
(an attributable signer and an operator-supplied key), and offline. The emitted
certificate carries no platform countersign (a tenant run is outside OAP's
admission/grant flow); it is verifiable-but-unsealed and round-trips offline under
`tenant-tail verify-certificate`.

## Verb

- `build-certificate <run-dir>` -- reconstruct a signed certificate from
  `<run-dir>/<stage-id>/<artifacts>`: scan each stage directory, SHA-256 every
  file, lift the frozen Build Spec hash, attach the signer, resolve the Ed25519
  key, and write a self-authenticating certificate.

```sh
npm i -D tenant-emit
npx --no-install tenant-emit build-certificate <run-dir> \
  --tenant-mode \
  --signer-subject <subject> --signer-identity-provider <provider> \
  [--corpus-attestation <attestation.json>] \
  --require-operator-key
```

The verifier (`verify-certificate`) is deliberately NOT here: it is vended
separately as tenant-tail. tenant-emit is emit-only by construction (no verify
verb, no verifier dependency); the verify/emit boundary is load-bearing
(spec 220 AC-6, spec 219 verify-only-by-construction), so the two tools stay
distinct distributables.

## Key custody and signing

The Ed25519 signing key is an operator-supplied tenant secret resolved via
`OAP_SIGNING_KEY` / `OAP_SIGNING_KEY_PATH`, held outside the repository and
outside any agent's write scope. `--require-operator-key` refuses the ephemeral
dev fallback (exit 2 if signing resolves to ephemeral). `--tenant-mode` with no
signer halts before emitting (anonymous signing forbidden). The platform mints
the key and sets it as the repo CI secret at project creation.

## Corpus binding (read, never recompute)

`--corpus-attestation <file>` (or `OAP_CORPUS_ATTESTATION_PATH`) binds the
tenant's own `spec-spine attest` output into the certificate by hash, via the
public reader seam `spec_spine_core::attest::attestation_hash`. The emitter never
compiles or re-attests the corpus; the attestation-emit / corpus-recompute
surface is banned at the symbol level (`clippy.toml`) and the crate level
(`deny.toml`), mirroring OAP's spec 218 FR-002 guard.

## Governing artifacts

- **OAP spec 220-tenant-emit-governance-certificate** -- the decision to vend,
  the scope, and the OAP-side extraction source.
- **This repo's `specs/` corpus** -- governs tenant-emit's own code, compiled by
  the pinned `spec-spine` library (see `spec-spine.toml`).

## Layout

```
crates/
  tenant-emit-types/   the emit-surface DTOs (certificate, signer, manifest, state)
  tenant-emit-core/    the emit engine (builder, signing, run-dir scan, hashing)
  tenant-emit-cli/     the `tenant-emit` binary (the build-certificate verb)
npm/                   prebuilt-binary npm wrapper (mirror of spec-spine's)
py/                    prebuilt-binary PyPI wrapper (uvx tenant-emit ...)
specs/                 this repo's spec corpus (governed by spec-spine)
standards/spec/        authoring templates
.github/workflows/     ci (dogfood) + release (per-triple binaries + npm + PyPI)
```

## License

Apache-2.0 (matching spec-spine and tenant-tail). The emit core is extracted from
OAP's AGPL-3.0 factory-engine; relicensing the extracted emit-only source to
Apache-2.0 is the prerogative of the sole copyright holder and is an explicit,
authorized act (see NOTICE and the tenant-emit handoff).
