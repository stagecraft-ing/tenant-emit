---
id: "000-tenant-emit-bootstrap"
title: "tenant-emit bootstrap (emit-only toolkit skeleton)"
status: approved
created: "2026-06-22"
authors: ["tenant-emit"]
kind: tooling
implementation: complete
risk: low
summary: >
  Bootstrap spec for the tenant-emit repository: an emit-only toolkit that
  produces a factory's run-side governance certificate (the post-hoc
  build-certificate path), signed by an attributable tenant signer, with no
  pipeline orchestration. It is the emit-side counterpart of tenant-tail, which
  verifies the same paperwork. This spec establishes the workspace skeleton (a
  three-crate Cargo workspace mirroring spec-spine, plus the npm + PyPI
  binary-distribution wrappers) and seeds this repo's own spec corpus, governed
  by the pinned spec-spine library. The emit core and the verb that exposes it
  are claimed by subsequent specs as the extraction lands; see OAP spec
  220-tenant-emit-governance-certificate for the decision to vend and the
  extraction map.
depends_on: []
establishes:
  - { kind: file, path: "Cargo.toml" }
  - { kind: directory, path: "crates/tenant-emit-types" }
  - { kind: directory, path: "crates/tenant-emit-core" }
  - { kind: directory, path: "crates/tenant-emit-cli" }
  - { kind: directory, path: "npm" }
  - { kind: directory, path: "py" }
references:
  - { unit: { kind: file, path: "README.md" }, role: context }
---

# 000: tenant-emit bootstrap

## 1. Purpose

tenant-emit is the vended tenant emission surface. Spine to tail to emit:
spec-spine compiles the corpus, tenant-tail verifies the factory's run-side
telltales, and tenant-emit produces them. It is an emit-only CLI a produced
application pins (one exact-version npm devDependency, next to spec-spine and
tenant-tail) to build a signed `governance-certificate.json` from a finished run
directory. It is identity-bearing (it requires an attributable signer and an
operator-supplied key) but carries no verifier and needs no network: the spec
102 do-not-trust-the-producer posture, turned tenant-ward and emit-side.

This bootstrap spec exists so the repository has a governed seed: the workspace
skeleton compiles, this corpus is non-empty, and spec-spine can dogfood it. The
substance lands in the feature specs: the certificate emit core
(`001-certificate-emit-core`) and the verb surface + npm/PyPI wrappers + release
matrix (`002-distribution`). This spec retains the crate skeleton it seeded: the
per-crate manifests and crate roots that wire the substance together.

## 2. Territory

This spec establishes the skeleton, mapped to the establishes edges above. The
directory edges are a coupling floor: the substance files within them are
claimed by the feature specs (001-002), while the crate skeleton (each crate's
`Cargo.toml` manifest and `src/lib.rs` root) and the workspace root remain
bootstrap territory.

- `Cargo.toml`: the three-crate workspace root (types / core / cli), mirroring
  spec-spine's shape; the CLI binary is `tenant-emit`, its verb `build-certificate`.
- `crates/tenant-emit-types`: the emit-surface DTOs (certificate, signer,
  inter-stage manifest, pipeline-state carrier types).
- `crates/tenant-emit-core`: the emit engine (builder, signing-key resolution,
  run-dir scan, hashing/signing, persistence).
- `crates/tenant-emit-cli`: the `tenant-emit` binary (the `build-certificate` verb).
- `npm`: the prebuilt-binary distribution wrapper (main package +
  `@tenant-emit/cli-<os>-<cpu>` optional dependencies + exec-forward launcher +
  publish-time platform-package generator).
- `py`: the parallel PyPI channel (five per-platform wheels + an sdist refusal
  fallback, the same prebuilt binary).

## 3. Behavior

- The repository MUST build as a single Cargo workspace
  (`cargo build --workspace`).
- The toolkit MUST remain emit-only: no verify verb, no verifier dependency. The
  verify/emit boundary is load-bearing (spec 220 AC-6, spec 219
  verify-only-by-construction): tenant-emit never verifies, tenant-tail never
  emits, and the two stay distinct distributables.
- This repo's own `specs/` corpus MUST be governed by the pinned spec-spine
  library (compile / lint / index check / couple), the same dogfooding pattern
  spec-spine, OAP, and tenant-tail follow.
- Each crate's `src/lib.rs` root composes and re-exports the emit surface its
  modules implement (the certificate DTOs, the builder and signing entrypoints).
  When a feature spec adds a type to that surface, the crate root re-exports it
  too; the root stays bootstrap territory while the substance stays with the
  owning feature spec.

## 4. Out of scope

- The emit core itself, the verb, behavior parity with the OAP in-tree emitter,
  and the release matrix. Each is owned by a subsequent spec in this corpus.
- The verifier (the certificate signature re-check, the stage-artifact
  re-derivation, the platform-seal adjudication, the corpus-binding verify):
  excluded by construction and vended separately as tenant-tail (spec 219).
- The firing step (seeded CI invoking the emitter at run completion, spec 220
  FR-002) and the kernel pin: OAP-side Leg C, not this repo. tenant-emit need
  only be the installable, round-tripping emitter.
