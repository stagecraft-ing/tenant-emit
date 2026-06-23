---
id: "002-distribution"
title: "Distribution: the build-certificate verb, npm + PyPI binary shims, release pipeline"
status: draft
created: "2026-06-22"
authors: ["tenant-emit"]
kind: tooling
implementation: complete
risk: medium
summary: >
  How the tenant-emit emitter reaches a produced application: the CLI verb
  surface (`build-certificate`, with `--tenant-mode`, the signer flags,
  `--require-operator-key`, and the `--corpus-attestation` read-path), the
  prebuilt-binary npm shim a TS/JS app pins next to spec-spine and tenant-tail
  (one exact-version devDependency), and the tag-gated release pipeline that
  builds the five per-triple archives (with CycloneDX SBOM + .sha256 sidecars +
  SLSA provenance) and assembles the `@tenant-emit/cli-<os>-<cpu>` platform
  packages. The shim is a launcher, not a native addon, and mirrors spec-spine's
  npm/ shape. A parallel PyPI channel (`uvx tenant-emit ...`) ships the same
  prebuilt binary as five per-platform wheels plus an sdist refusal fallback,
  from the same release archives (no second Rust build). The read-never-recompute
  guard (clippy.toml + deny.toml) keeps the corpus read-path honest.
depends_on:
  - "000-tenant-emit-bootstrap"
  - "001-certificate-emit-core"
establishes:
  - { kind: file, path: "crates/tenant-emit-cli/src/main.rs" }
  - { kind: file, path: "clippy.toml" }
  - { kind: file, path: "deny.toml" }
  - { kind: file, path: "npm/bin/tenant-emit.js" }
  - { kind: file, path: "npm/lib/platform.js" }
  - { kind: file, path: "npm/scripts/generate-platform-packages.js" }
  - { kind: file, path: "npm/scripts/smoke-test.sh" }
  - { kind: file, path: "npm/test/platform.test.js" }
  - { kind: file, path: "npm/package.json" }
  - { kind: file, path: ".github/workflows/release.yml" }
  - { kind: file, path: ".github/workflows/ci.yml" }
  - { kind: file, path: ".github/workflows/determinism.yml" }
  - { kind: file, path: ".github/workflows/ai-pr-review.yml" }
  - { kind: file, path: "py/scripts/generate_wheels.py" }
references:
  - { unit: { kind: file, path: "npm/README.md" }, role: context }
  - { unit: { kind: file, path: "py/README.md" }, role: context }
---

# 002: Distribution

## 1. Purpose

`cargo install tenant-emit-cli` puts the binary on a machine, but a produced
TypeScript/JS application's reflex is `npm i -D tenant-emit`, pinned next to
`spec-spine` and `tenant-tail`, and it will not install a Rust toolchain to
produce its own paperwork. This spec governs the verb surface that application
invokes and the machinery that delivers it: the npm and PyPI binary shims and
the release pipeline.

## 2. Territory

- `crates/tenant-emit-cli/src/main.rs`: the verb surface. `build-certificate` is
  the single verb (a subcommand of the `tenant-emit` binary). It carries the
  positional `<run-dir>`, the signer flags (`--tenant-mode`, `--signer-subject`,
  `--signer-identity-provider`, `--signer-session-id`), `--stage-ids`,
  `--require-operator-key` (spec 220 FR-003), `--corpus-attestation` (spec 220
  FR-007, read via the public `spec_spine_core::attest::attestation_hash` seam),
  `--out`, and `--adapter`. No verify verb is reachable.
- `clippy.toml`, `deny.toml`: the read-never-recompute guard. clippy bans the
  attestation-emit / corpus-recompute symbols (`attest`, `verify_recompute`,
  `attest_json`, `verify_attestation_json`); cargo-deny bans depending on the
  `spec-spine-cli` crate. The emit CLI calls only the reader seam.
- `npm/`: the prebuilt-binary distribution shim (launcher + platform resolver +
  publish-time platform-package generator + its unit test and smoke test). A
  faithful mirror of spec-spine's `npm/`.
- `py/`: the parallel PyPI channel (wheels + sdist refusal), mirroring spec-spine.
- `.github/workflows/`: CI (build/test/clippy/fmt + spec-spine self-governance +
  determinism), the determinism golden, the tag-gated release pipeline, and the
  AI PR review (`ai-pr-review.yml`), a reusable workflow ci.yml dispatches into
  `ci-gate` so a failed or absent review blocks merge (green ci-gate => actually
  reviewed or visibly skipped).

## 3. Behavior

- `npx --no-install tenant-emit build-certificate <run-dir> ...` MUST run the
  emitter offline, forwarding argv unchanged to the prebuilt binary (the launcher
  is a pure translation layer; it adds no flags).
- The five platform targets (darwin-arm64, darwin-x64, linux-x64, linux-arm64,
  win32-x64) are a single fact kept in lockstep across the npm platform map, the
  py platform map, the generators, and the release matrix.
- The release pipeline MUST be tag-gated, build one archive per triple with a
  `.sha256` sidecar, a CycloneDX SBOM, and a SLSA build-provenance attestation,
  and publish idempotently to crates.io + npm + PyPI. The PyPI channel reuses the
  same release archives (no second Rust build).
- CI MUST run clippy with `-D warnings` so the read-never-recompute clippy.toml
  ban is enforced as a hard error, and MUST run the spec-spine dogfood gate
  (compile / index check / lint / couple) over this repo's own corpus.
- The AI PR review MUST classify a Claude CLI failure rather than fail blindly:
  an unset `CLAUDE_CODE_OAUTH_TOKEN` or an auth/permission error hard-fails (a
  broken token must be fixed, not masked, preserving the anti-silent-green
  guard), while any other API failure (overloaded, rate-limit, 5xx, timeout,
  network) passes `ci-gate` with a loud, visible PR notice so a third-party
  Anthropic incident does not block merges. The pass is never silent.
- The cross-tool round-trip is the acceptance contract: a certificate emitted by
  `build-certificate` verifies clean under `tenant-tail verify-certificate`
  (including `--corpus-attestation`), and tampering any artifact or the
  attestation fails verification (exit 1).

## 4. Out of scope

- The emit engine itself (owned by `001-certificate-emit-core`).
- The firing step that invokes the emitter at run completion (spec 220 FR-002)
  and the kernel pin: OAP-side Leg C. Once tenant-emit cuts a release, OAP pins it.
- The npm/PyPI publish credentials and the actual publish event: an operator /
  release-trigger concern, not source.
