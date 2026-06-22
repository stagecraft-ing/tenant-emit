# CLAUDE.md: tenant-emit

Project overview, invariants, and conventions. Read by `/init` at the start of
every session (see AGENTS.md for the init protocol).

## What this is

tenant-emit is the vended, emit-only tenant CLI: it produces a signed
`governance-certificate.json` from a finished `.factory/runs/<run-id>/` directory.
It is the emit-side counterpart of tenant-tail (which verifies the same artifact).
Both are extracted from OAP's `factory-engine` and relicensed Apache-2.0 (see
NOTICE); both are pinned by the born-with kernel next to `spec-spine`.

The product binary is `tenant-emit`; its single verb is `build-certificate`.
Governance runs through the pinned `spec-spine` npm devDependency
(`npx --no-install spec-spine ...`), never an in-tree spec-spine build.

## Load-bearing invariants

- **Emit-only by construction.** No verify verb, no verifier dependency. The
  verify/emit boundary is the whole point (spec 220 AC-6, spec 219
  verify-only-by-construction): tenant-emit never verifies, tenant-tail never
  emits, and the two stay separate distributables. Never add a `verify-*` verb.
- **The cross-tool round-trip is the definition of correct.** A certificate
  emitted by `tenant-emit build-certificate` MUST verify clean under
  `tenant-tail verify-certificate` (including `--corpus-attestation`), and
  tampering any artifact or the attestation MUST fail verification (exit 1).
- **Certificate version is pinned to "1.5.0".** tenant-tail's verifier checks the
  version by strict equality, and carries the additive `corpusBinding` field at
  1.5.0. The emitter pins the same string so the round-trip exits 0. Do NOT bump
  to OAP's 1.6.0: that would fail the verifier's version gate. `corpusBinding` is
  additive (skipped when absent), not a version bump for this emit/verify pair.
- **Read, never recompute (corpus binding).** `--corpus-attestation` hashes the
  supplied attestation via the public reader seam
  `spec_spine_core::attest::attestation_hash` only. The attestation-emit /
  corpus-recompute surface (`attest`, `verify_recompute`, `attest_json`,
  `verify_attestation_json`) is banned at the symbol level (`clippy.toml`
  disallowed-methods, enforced by `-D warnings`) and the crate level (cargo-deny
  bans depending on `spec-spine-cli`). The CLI test
  `banned_attestation_emit_paths_still_resolve` keeps `clippy.toml` honest.
- **Anonymous signing forbidden, ephemeral refused in production.**
  `--tenant-mode` with no signer halts before emitting (exit 2);
  `--require-operator-key` exits 2 if signing resolves to an ephemeral key. The
  Ed25519 key is operator-supplied (`OAP_SIGNING_KEY` / `OAP_SIGNING_KEY_PATH`),
  outside any agent's write scope. The emitter signs the certificate, not the
  corpus attestation.
- **Determinism.** Re-emitting from the same run directory yields identical
  artifact and certificate content modulo the signer + timestamp (spec 220 AC-7).
- **`unsafe_code` is forbidden workspace-wide.**

## Layout

```
crates/
  tenant-emit-types/   the emit-surface DTOs (certificate, signer, manifest, state)
  tenant-emit-core/    the emit engine (builder, signing, run-dir scan, hashing)
  tenant-emit-cli/     the `tenant-emit` binary (the build-certificate verb)
npm/ , py/             prebuilt-binary distribution shims (mirror spec-spine's)
specs/                 this repo's spec corpus (governed by spec-spine)
clippy.toml, deny.toml the read-never-recompute guard
```

The cert DTOs (types crate) are preserved byte-for-byte from OAP so the canonical
JSON, the self-hash, and the Ed25519 signature stay identical to what tenant-tail
re-derives. The engine (core crate) builds and signs them; the CLI (cli crate)
exposes the verb and the corpus read-path.

## Working in this repo

- Build the product binary: `cargo build --release -p tenant-emit-cli`.
- Gate before commit: `cargo test --workspace`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo fmt --all --check`, and the spec-spine
  dogfood (`npx --no-install spec-spine compile && spec-spine index check &&
  spec-spine lint --fail-on-warn`).
- Read compiled artifacts (`.derived/**`) through `spec-spine` subcommands, never
  via ad-hoc `jq`/`python`/`sed` (see `.claude/rules/governed-artifact-reads.md`).
- OAP stays the source of truth for the emit core; this repo carries an extracted
  copy in behavior parity. Changes that affect certificate content must preserve
  the round-trip with tenant-tail.

## Out of scope (OAP-side Leg C, not this repo)

- The firing step that invokes the emitter at run completion (spec 220 FR-002).
- The kernel pin that installs tenant-emit next to tenant-tail and spec-spine.
- The platform countersign / tenant-to-OAP uplink (a tenant cert is unsealed by
  design).

## House style

No em dash (U+2014) anywhere: chat, code, comments, docs, commits. Use a colon,
comma, parentheses, or two sentences. A PreToolUse hook blocks file writes that
introduce U+2014.
