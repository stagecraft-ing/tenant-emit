---
id: "001-certificate-emit-core"
title: "Certificate emit core (builder, signing, run-dir scan, corpus binding)"
status: approved
created: "2026-06-22"
authors: ["tenant-emit"]
kind: tooling
implementation: complete
risk: medium
summary: >
  The certificate emit engine, extracted from OAP's build_certificate.rs +
  governance_certificate.rs (the emit path) and kept in behavior parity. It
  reconstructs a signed governance-certificate.json from a finished
  `.factory/runs/<run-id>/<stage-id>/<artifacts>` directory: it scans each stage
  directory, computes SHA-256 over every file, lifts the frozen Build Spec hash,
  attaches an attributable signer, resolves an Ed25519 signing key (operator
  env-var or ephemeral fallback), computes the content-binding hash and the
  Ed25519 signature, and persists the certificate. It optionally binds the
  tenant's own corpus attestation by hash, its SBOM artifacts by content hash,
  and the produced app's declared agentic posture read off the frozen Build Spec
  (all read, never recompute). The emitted certificate carries the cert DTOs at
  `certificate_version` 1.5.0 with the additive corpusBinding, sbomArtifactBinding
  and agenticPostureBinding fields, so it round-trips offline under tenant-tail
  verify-certificate.
depends_on:
  - "000-tenant-emit-bootstrap"
establishes:
  - { kind: file, path: "crates/tenant-emit-types/src/certificate.rs" }
  - { kind: file, path: "crates/tenant-emit-types/src/build_spec.rs" }
  - { kind: file, path: "crates/tenant-emit-types/src/inter_stage_manifest.rs" }
  - { kind: file, path: "crates/tenant-emit-types/src/pipeline_state.rs" }
  - { kind: file, path: "crates/tenant-emit-types/src/lib.rs" }
  - { kind: file, path: "crates/tenant-emit-core/src/certificate.rs" }
  - { kind: file, path: "crates/tenant-emit-core/src/lib.rs" }
references:
  - { unit: { kind: file, path: "NOTICE" }, role: context }
---

# 001: Certificate emit core

## 1. Purpose

The governance certificate is the load-bearing artifact: a self-authenticating
`governance-certificate.json` an auditor verifies without trusting the system
that produced it (spec 102 FR-007). tenant-tail vended the ability to verify one;
this spec vends the ability to produce one. The emit core is post-hoc, which is
what makes tenant emission tractable without shipping OAP's pipeline engine: it
needs only a laid-out run directory and a signing key, not a live pipeline.

## 2. Territory

- `crates/tenant-emit-types/src/certificate.rs`: the certificate DTOs
  (`GovernanceCertificate` and its sub-records, `Signer`, `CorpusBinding`,
  `SbomArtifactBinding`, `AgenticPostureBinding` / `CertAgenticSurface`,
  `SigningAttestation(Kind)`), preserved verbatim from OAP so the canonical JSON,
  the self-hash, and the Ed25519 signature stay byte-identical to what the
  verifier re-derives. Pinned at `certificate_version` 1.5.0 with the additive
  `corpusBinding`, `sbomArtifactBinding` and `agenticPostureBinding` fields (all
  optional, skipped when absent, so unbound certificates stay byte-identical).
- `crates/tenant-emit-types/src/build_spec.rs`: the minimal parse-side mirror of
  the produced app's frozen Build Spec, carrying only the `agentic_posture`
  subtree (`AgenticPosture`, `PostureLevel`, `AgenticSurface`, `SurfaceKind`) plus
  the `BuildSpecPostureProjection` the CLI deserialises. tenant-emit is Apache-2.0
  and does not depend on OAP's AGPL `factory-contracts`; this local mirror matches
  those shapes byte-for-byte (kebab-case wire strings) so a real produced-app
  Build Spec parses identically. `AgenticPostureBinding::from_build_spec` is the
  single construction seam.
- `crates/tenant-emit-types/src/inter_stage_manifest.rs`,
  `crates/tenant-emit-types/src/pipeline_state.rs`: the carrier types the cert
  references (manifest-chain DTOs; the minimal run-state slice the emitter reads).
- `crates/tenant-emit-core/src/certificate.rs`: the engine. `CertificateBuilder`,
  `resolve_signing_material`, `compute_certificate_hash` /
  `compute_certificate_signature`, the run-directory scan
  (`generate_certificate*`, the stage-record collectors), and persistence.
- The crate `src/lib.rs` roots re-export the surface above.

## 3. Behavior

- The emitter MUST reconstruct stages from `<run-dir>/<stage-id>/<artifacts>` by
  SHA-256 over each file, accept the tenant's own stage grammar (`--stage-ids` or
  filesystem auto-discovery), and produce byte-identical artifact hashes on
  re-emit from the same directory (spec 220 FR-006 / AC-7), modulo the signer and
  timestamp.
- Emission MUST require an attributable signer on the tenant path: the `Signer`
  constructor rejects an empty/whitespace subject, and `build_tenant` halts when
  no signer is attached (spec 168 FR-007: anonymous signing forbidden).
- The signing key MUST resolve from `OAP_SIGNING_KEY` / `OAP_SIGNING_KEY_PATH`
  (operator) or an ephemeral fallback (dev-only, marked `signing_attestation.kind:
  ephemeral`). The emitter signs the certificate, not the corpus attestation.
- The corpus binding (spec 220 FR-007) MUST be read, never recomputed: the
  builder is GIVEN a hash and never compiles or re-attests the corpus. The
  binding sits inside the content-binding hash and the signature, so it is
  applied only on the signer (tenant) build path; an unbound certificate is a
  valid state, and it is the CLI's `--require-corpus-binding` guard (spec 002 §3),
  not the engine, that turns a missing binding into a refusal.
- The SBOM artifact binding (spec 203 FR-003) MUST likewise be read, never
  recomputed: the builder is GIVEN the produced app's BOM and audit content
  hashes (via `sbom_artifact_binding`) and never regenerates the BOM. Like the
  corpus binding it is additive and optional (an unbound certificate is the named
  unbound state) and sits inside the content-binding hash and the signature, so
  it too is applied only on the signer path; the CLI's `--require-sbom-binding`
  guard (spec 002 §3) is the symmetric refusal when a production emission must
  carry it.
- The agentic-posture binding (spec 210 FR-002) MUST likewise be read, never
  recomputed: the builder is GIVEN an `AgenticPostureBinding` the CLI resolved
  from the produced app's declared `agentic_posture` on the frozen Build Spec
  (via `agentic_posture_binding`), and never re-derives the posture. The binding
  distinguishes an authored posture (`defaulted: false`) from a Build Spec that
  omitted `agentic_posture` (`defaulted: true`), so a defaulted `none` is visibly
  defaulted, never silently equivalent to an authored `none`. The emitter records
  verbatim and never validates well-formedness; the verifier (tenant-tail) is
  authoritative on internal consistency, the SBOM cross-check, and the governed
  envelope shape. Like the other bindings it is additive and optional (a cert
  whose run had no readable Build Spec carries no binding: the named unstated
  state) and sits inside the content-binding hash and the signature, so it is
  applied only on the signer (tenant) build path.
- A tenant certificate MUST carry no platform countersign (a tenant run is
  outside OAP's admission/grant flow); it is verifiable-but-unsealed and verifies
  offline under tenant-tail verify-certificate.

## 4. Out of scope

- The verifier: the signature re-check, the stage-artifact re-derivation, the
  platform-seal adjudication, and the corpus-binding verify are excluded by
  construction and vended as tenant-tail (spec 219).
- The CLI verb surface and its flags (the `build-certificate` command,
  `--require-operator-key`, the corpus read-path, and the SBOM read-path
  (`--sbom-dir`) wiring): owned by `002-distribution`.
- The certificate format and verdict logic (specs 102/168/170/198/218): tenant-
  emit changes who emits and where the key lives, not what a valid certificate is.
