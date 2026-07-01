//! Governance Certificate -- the single JSON artifact proving the full
//! intent-to-spec-to-code-to-audit chain for a factory pipeline run.
//!
//! These are the emit-surface data types, extracted from OAP's
//! `factory-engine/src/governance_certificate.rs` and relicensed Apache-2.0
//! from AGPL-3.0 by the sole copyright holder (see NOTICE). The types are the
//! DTOs the emitter builds and signs; the engine (the certificate builder,
//! signing-key resolution, run-dir scan, hashing/signing) lives in
//! `tenant-emit-core`. The data types are preserved verbatim so the canonical
//! JSON, the recomputed self-hash, and the Ed25519 signature stay byte-identical
//! to what the verifier (tenant-tail) re-derives.
//!
//! Version pinning: this emit/verify pair operates at `certificate_version`
//! "1.5.0" with the additive `corpusBinding` field carried (spec 218). The
//! verifier (tenant-tail) checks the version by strict equality, so the emitter
//! pins the same string; `corpusBinding` is an optional, additive field, not a
//! version bump (it serialises identically to a pre-binding payload when absent).

use crate::inter_stage_manifest::{InterStageManifest, RunKeyChain};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Schema version for the governance certificate format.
///
/// 1.3.0 introduces two optional top-level fields landing in parallel:
///   * `signer` (spec 168 §FR-003) -- named identity for the principal that
///     drove the run (Rauthy JWT subject or analogous identity per spec
///     106 / 137).
///   * `interStageChain` (spec 170 §FR-007) -- signed inter-stage manifest
///     chain produced by [`crate::inter_stage_manifest`].
///
/// Both fields are `skip_serializing_if = "Option::is_none"` so a
/// certificate built without them serialises byte-identically to a
/// pre-1.3.0 payload -- only the version string differs. Legacy 1.2.0 /
/// 1.1.0 / 1.0.0 fixtures still pass through the verifier.
///
/// 1.2.0 (spec 162 §FR-008) introduced the optional `sandboxExecution`
/// per-stage record. 1.1.0 added Ed25519 signing (spec 102 FR-008.1);
/// the hash check is no longer the authoritative provenance check after
/// that point, but it remains as a content fingerprint inside the signed
/// payload.
///
/// 1.4.0 (spec 198 FR-005/FR-009/FR-014) added the admission-binding
/// fields -- `admittedEnvelopeHash`, `goalId`, `intentCapsuleHash`, all
/// inside the hash + signature (bound at emission) -- and the
/// post-emission `platformCountersign`, which is EXCLUDED from both the
/// self-hash and the engine signature (zeroed before canonicalisation)
/// so platform sealing on sync-back never invalidates the offline chain.
///
/// 1.5.0 (spec 198 FR-013 c) added `consumedOverrides` -- the overrides of
/// admitted factory content the run consumed, with provenance + verified
/// state, inside the hash + signature. Empty lists are skipped in
/// serialization so override-free certificates stay byte-identical to
/// 1.4.0 payloads (only the version string differs).
///
/// The additive `corpusBinding` block (spec 218) is carried at this same
/// version: it is an optional cert field that serialises identically to a
/// pre-binding payload when absent (the named "unbound" state), so it is not a
/// version bump for the emit/verify pair. See [`CorpusBinding`].
///
/// The additive `sbomArtifactBinding` block (spec 203) is carried at this same
/// version for the same reason: an optional cert field that serialises
/// identically to a pre-binding payload when absent (the named "unbound"
/// state), so it is not a version bump for the emit/verify pair. See
/// [`SbomArtifactBinding`].
pub const CERTIFICATE_VERSION: &str = "1.5.0";

// ── Top-level Certificate ────────────────────────────────────────────

/// A Governance Certificate proves the full chain from intent to auditable output.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernanceCertificate {
    pub certificate_version: String,
    pub pipeline_run_id: String,
    pub timestamp: DateTime<Utc>,
    pub status: CertificateStatus,

    pub intent: IntentRecord,
    pub build_spec: BuildSpecRecord,
    pub stages: Vec<StageRecord>,
    pub verification: VerificationRecord,
    pub proof_chain: ProofChainSummary,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance: Option<ComplianceRecord>,

    /// Spec 168 §FR-003 / §FR-007 -- identity attribution for the principal
    /// that drove the run. Required for tenant-emit mode (per-project
    /// certificates); optional on OAP-self runs to preserve byte-for-byte
    /// compatibility with pre-1.3.0 fixtures. Anonymous signing is
    /// forbidden: when set, `Signer::subject` is non-empty after trim
    /// (constructed via `Signer::new`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<Signer>,

    /// Spec 170 §FR-007 -- signed inter-stage manifest chain. Optional
    /// for runs that did not produce signed hand-offs (legacy / pre-1.3.0
    /// fixtures); `skip_serializing_if = "Option::is_none"` keeps the
    /// canonical JSON byte-identical for those payloads so their
    /// certificate hash is unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inter_stage_chain: Option<InterStageChainRecord>,

    /// Spec 198 FR-009 -- hash of the admitted governance envelope this run
    /// executed under. Inside the hash + signature (bound at emission), so
    /// the certificate is reconcilable to its admission contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admitted_envelope_hash: Option<String>,

    /// Spec 198 FR-005 -- stable goal identifier from the run's intent
    /// capsule (ASI01 m7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub goal_id: Option<String>,

    /// Spec 198 FR-005/FR-009 -- SHA-256 of the run's canonical intent
    /// capsule, as presented at grant issuance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent_capsule_hash: Option<String>,

    /// Spec 198 FR-013(c) -- overrides of admitted factory content this run
    /// consumed, as presented by the platform's admission-gated bundle
    /// (already predicate-checked against `overrides.require_verified`).
    /// Inside the hash + signature (bound at emission) so every consumed
    /// override is traceable and revocable via its content hash (FR-010).
    /// Skipped when empty so override-free certificates serialise
    /// byte-identically to pre-1.5.0 payloads.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub consumed_overrides: Vec<ConsumedOverride>,

    /// Spec 218 FR-001 -- the corpus attestation in effect at the run, by
    /// reference. Additive and optional: absence is a named "unbound" state,
    /// not a failure. Inside the hash + signature (a normal cert field);
    /// skipped when absent so unbound certificates serialise byte-identically
    /// to pre-binding payloads. See [`CorpusBinding`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corpus_binding: Option<CorpusBinding>,

    /// Spec 203 FR-003 -- the produced application's BOM + dependency-audit
    /// content binding, by content hash. Additive and optional: absence is a
    /// named "unbound" state, not a failure. Inside the hash + signature (a
    /// normal cert field, unlike `platform_countersign`); skipped when absent
    /// so unbound certificates serialise byte-identically to pre-binding
    /// payloads. See [`SbomArtifactBinding`].
    ///
    /// The emitter is GIVEN both hashes and never recomputes them (read,
    /// never recompute, mirroring `corpus_binding`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sbom_artifact_binding: Option<SbomArtifactBinding>,

    /// SHA-256 of the canonical JSON of this certificate with `certificate_hash`
    /// AND `cert_signature` set to empty string. Content-binding fingerprint
    /// inside the signed payload -- not the authoritative provenance check
    /// after spec 102 FR-008.1 (see `cert_signature`).
    pub certificate_hash: String,

    /// Base64-encoded Ed25519 public key (32 bytes) -- verifier checks
    /// `cert_signature` against this. Empty for pre-1.1.0 fixtures and
    /// unsigned certificates; HIAS-mode verifiers reject empty.
    /// Spec 102 FR-008.2.
    #[serde(default)]
    pub signing_public_key: String,

    /// Base64-encoded Ed25519 signature (64 bytes) over canonical JSON
    /// of the certificate with `cert_signature` set to empty string and
    /// `certificate_hash` populated. Spec 102 FR-008.1.
    #[serde(default)]
    pub cert_signature: String,

    /// Trust-posture descriptor for `signing_public_key`. Spec 102 FR-008.3.
    #[serde(default)]
    pub signing_attestation: SigningAttestation,

    /// Spec 198 FR-014 -- the platform countersign applied on sync-back,
    /// after stagecraft verified the engine's chain against the run-grant
    /// sequence it issued. EXCLUDED from `certificate_hash` and
    /// `cert_signature` (zeroed before canonicalisation) so sealing never
    /// invalidates the offline chain. `None` = verifiable-but-unsealed --
    /// visibly so, never silently equivalent. A tenant run carries none (it is
    /// outside OAP's admission/grant flow); the field is preserved for
    /// serialization parity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform_countersign: Option<PlatformCountersign>,
}

/// Spec 198 FR-014 -- the platform seal on an emitted certificate. The
/// compact JWS (`typ: oap-cert-countersign+jws`) carries the claims
/// (`certificate_sha256`, `run_id`, `grant_count`, `grant_chain_sha256`,
/// `envelope_hash`, ...); `kid` resolves against the platform JWKS.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PlatformCountersign {
    pub countersign_jws: String,
    pub kid: String,
    pub countersigned_at: DateTime<Utc>,
}

/// Spec 218 FR-001 -- the corpus attestation in effect at the run, recorded by
/// reference. `corpus_attestation_hash` is the SHA-256 of the upstream corpus
/// attestation artifact; `spec_spine_version` records the spec-spine that
/// produced it.
///
/// Additive and optional: a certificate without this block is a named "unbound"
/// state, not a failure (FR-004). `skip_serializing_if = "Option::is_none"`
/// keeps unbound certificates byte-identical to pre-binding payloads, so their
/// certificate hash is unchanged. When present the block is INSIDE the hash and
/// signature (a normal cert field, unlike `platform_countersign`).
///
/// The emitter is GIVEN this value and never recomputes it (spec 220 FR-007,
/// the read-never-recompute boundary): the hash is the SHA-256 of the supplied
/// `CorpusAttestation` payload, produced by the CLI via the public reader seam
/// `spec_spine_core::attest::attestation_hash`. The emit core never compiles or
/// re-attests the corpus.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CorpusBinding {
    pub corpus_attestation_hash: String,
    pub spec_spine_version: String,
}

/// Spec 203 FR-003 -- the produced application's BOM + dependency-audit
/// content binding. `bom_hash` and `audit_hash` are SHA-256 hex of the byte
/// content of the CycloneDX BOM (`.factory/sbom.cdx.json`) and the
/// dependency-audit artifact (`.factory/audit.json`) respectively;
/// `bom_tool_version` is the `@cyclonedx/cyclonedx-npm` semver used to
/// generate the BOM.
///
/// Additive and optional: a certificate without this block is a named
/// "unbound" state, not a failure. `skip_serializing_if = "Option::is_none"`
/// keeps unbound certificates byte-identical to pre-binding payloads, so
/// their certificate hash is unchanged. When present the block is INSIDE the
/// hash and signature (a normal cert field, unlike `platform_countersign`).
///
/// The emitter is GIVEN both hashes and never recomputes them (read, never
/// recompute: the emit CLI hashes the on-disk artifact bytes as-is; it never
/// regenerates the BOM).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SbomArtifactBinding {
    pub bom_hash: String,
    pub audit_hash: String,
    pub bom_tool_version: String,
}

/// Spec 203 FR-003: relative path of the produced app's CycloneDX BOM, under
/// the produced-app root supplied via `--sbom-dir`.
pub const SBOM_BOM_RELPATH: &str = ".factory/sbom.cdx.json";

/// Spec 203 FR-003: relative path of the produced app's dependency-audit
/// artifact, under the produced-app root supplied via `--sbom-dir`.
pub const SBOM_AUDIT_RELPATH: &str = ".factory/audit.json";

/// Spec 198 FR-013(c) -- one override of admitted factory content the run
/// consumed: artifact identity, content hash, author provenance (FR-013 b)
/// and the verified state at consumption time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConsumedOverride {
    pub artifact_id: String,
    pub path: String,
    pub content_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<String>,
    pub verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_by: Option<String>,
}

/// Trust posture for the signing public key (spec 102 FR-008.3).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SigningAttestation {
    pub kind: SigningAttestationKind,
    /// Free-form note: operator email, key-rotation epoch, CI run URL, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SigningAttestationKind {
    /// No `signing_public_key` was set -- pre-1.1.0 fixture or unsigned cert.
    /// HIAS-strict and non-strict verification both reject these once
    /// signing material is required by the runtime.
    #[default]
    Unsigned,
    /// Key generated for this run's lifetime; trust is "the run was
    /// internally consistent." Suitable for local dev.
    Ephemeral,
    /// Operator-supplied key via `OAP_SIGNING_KEY` or `OAP_SIGNING_KEY_PATH`.
    /// Trust is "the operator vouches for runs using this key."
    Operator,
    /// Signed by a Sigstore Fulcio-issued certificate and anchored to the
    /// Rekor transparency log. Required by HIAS-strict. Implementation
    /// landed in P0-3b (spec 102 FR-008.5).
    SigstoreRekor,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CertificateStatus {
    Complete,
    Incomplete,
}

// ── Inter-stage manifest chain (spec 170 FR-007) ─────────────────────

/// Run-level record of the signed inter-stage manifest chain.
///
/// Embeds the per-run key chain (root verifying key + stage ephemeral
/// verifying keys) alongside the ordered list of signed manifests. The
/// post-hoc emitter does not produce this chain (it reconstructs only the
/// artifact-hash stages from disk), so a tenant certificate carries none; the
/// type is preserved for serialization parity with the verifier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InterStageChainRecord {
    pub key_chain: RunKeyChain,
    #[serde(default)]
    pub manifests: Vec<InterStageManifest>,
}

// ── Signer (spec 168 FR-003 / FR-007) ────────────────────────────────

/// Identity attribution for the principal that drove the pipeline run.
///
/// The `subject` is the principal identifier (typically a Rauthy JWT `sub`
/// for human-driven runs, or an agent identity for agent-driven runs per
/// spec 106 / 137). The `identityProvider` names the system that attested
/// the subject (e.g. `rauthy@<tenant-org>`, `github-actions@<repo>`,
/// `oap-self`). The `sessionId` is an optional run-scoped correlation id.
///
/// Constructed only via [`Signer::new`], which rejects empty/whitespace
/// `subject` so that anonymous signing cannot bypass FR-007 by submitting
/// an empty string.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Signer {
    pub subject: String,
    pub identity_provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

impl Signer {
    /// Construct a `Signer`. Returns `Err` if `subject` is empty or
    /// whitespace-only (FR-007: anonymous signing forbidden) or
    /// `identity_provider` is empty.
    pub fn new(
        subject: impl Into<String>,
        identity_provider: impl Into<String>,
    ) -> Result<Self, SignerError> {
        let subject = subject.into();
        let identity_provider = identity_provider.into();
        if subject.trim().is_empty() {
            return Err(SignerError::EmptySubject);
        }
        if identity_provider.trim().is_empty() {
            return Err(SignerError::EmptyIdentityProvider);
        }
        Ok(Self {
            subject,
            identity_provider,
            session_id: None,
        })
    }

    /// Attach an optional run-scoped session id.
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    #[error("signer subject is empty or whitespace (FR-007); anonymous signing forbidden")]
    EmptySubject,
    #[error("signer identity_provider is empty")]
    EmptyIdentityProvider,
}

// ── Intent ───────────────────────────────────────────────────────────

/// Records the original intent that initiated the pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntentRecord {
    /// SHA-256 hash of the concatenated input requirements documents.
    pub requirements_hash: String,
    /// The governing spec ID (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_id: Option<String>,
    /// SHA-256 hash of the governing spec.md at pipeline start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spec_hash: Option<String>,
}

// ── Build Spec ───────────────────────────────────────────────────────

/// Records the frozen Build Spec and its approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildSpecRecord {
    /// SHA-256 hash of the frozen Build Spec YAML.
    pub hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_record: Option<ApprovalRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    pub approved_at: DateTime<Utc>,
    pub gate_type: String,
}

// ── Stages ───────────────────────────────────────────────────────────

/// Per-stage record in the certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StageRecord {
    pub stage_id: String,
    pub status: StageOutcome,
    /// SHA-256 hashes of all output artifacts, keyed by artifact name.
    pub artifact_hashes: BTreeMap<String, String>,
    pub gate_result: Option<GateResultRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Spec 162 §FR-008 -- sandbox-execution record. Populated when the
    /// stage exercised adapter-emitted code through a `SandboxClient`
    /// (lint / test / build / run-once). The post-hoc emitter scans only
    /// artifact hashes from disk, so it never populates this field;
    /// `skip_serializing_if = "Option::is_none"` keeps the canonical JSON
    /// byte-identical for those stages. The type is preserved for parity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_execution: Option<SandboxExecutionRecord>,
}

/// Per-stage sandbox-execution binding (spec 162 §FR-008).
///
/// Backend-agnostic by construction: `isolation_tier` is normalised to
/// 1/2/3 (1 = sandbox runtime, 2 = restricted container, 3 = forbidden);
/// `runtime_descriptor` is treated by the verifier as an opaque
/// base64-encoded fingerprint of backend identity + version + selected
/// runtime. Backends choose their own pre-encoded bytes, so long as the
/// bytes are deterministic for a given build.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SandboxExecutionRecord {
    /// Executed command -- argv echoed back; the verifier binds this
    /// exact form (FR-008).
    pub command: Vec<String>,
    /// Pre-execution input artifact hashes, keyed by sandbox-mount-relative
    /// path.
    pub input_artifact_hashes: BTreeMap<String, String>,
    /// Post-execution output artifact hashes, keyed by sandbox-mount-relative
    /// path.
    pub output_artifact_hashes: BTreeMap<String, String>,
    /// Peak resource utilisation observed during the execution.
    pub resource_peak: SandboxResourcePeak,
    /// Realised isolation tier -- 1 = sandbox runtime (gVisor /
    /// Firecracker / Kata), 2 = restricted container (rootless OCI,
    /// RO rootfs, seccomp default). MUST NOT be 3 for a successful
    /// outcome (162 §2.2 -- Tier 3 is reserved for refusal diagnostics).
    pub isolation_tier: u8,
    /// Opaque backend identity + version + runtime fingerprint, base64.
    /// Verifier treats this as bytes -- no parsing.
    pub runtime_descriptor: String,
    /// True iff the TTL fired and the execution was terminated.
    pub deadline_hit: bool,
    /// Process exit code from the sandboxed command.
    pub exit_code: i32,
}

/// Peak resource utilisation observed during a sandbox execution
/// (spec 162 §FR-008).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct SandboxResourcePeak {
    pub cpu_milli_peak: u32,
    pub memory_bytes_peak: u64,
    pub pid_peak: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StageOutcome {
    Passed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GateResultRecord {
    pub passed: bool,
    pub checks_run: u32,
    pub checks_failed: u32,
}

// ── Verification ─────────────────────────────────────────────────────

/// Aggregate verification outcomes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationRecord {
    pub compile: VerificationOutcome,
    pub test: VerificationOutcome,
    pub lint: VerificationOutcome,
    pub typecheck: VerificationOutcome,
    pub security_scan: VerificationOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VerificationOutcome {
    Passed,
    Failed,
    Skipped,
}

// ── Proof Chain ──────────────────────────────────────────────────────

/// Summary of the proof chain from policy-kernel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofChainSummary {
    pub record_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_record_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_record_hash: Option<String>,
    pub chain_integrity: ChainIntegrity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ChainIntegrity {
    Verified,
    Unverified,
    Empty,
}

// ── Compliance ───────────────────────────────────────────────────────

/// Compliance mapping for the pipeline run.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceRecord {
    pub frameworks: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mappings: Vec<ComplianceMapping>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceMapping {
    pub control: String,
    pub mechanism: String,
    pub status: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signer_constructor_rejects_empty_or_whitespace_subject() {
        assert!(matches!(
            Signer::new("", "rauthy"),
            Err(SignerError::EmptySubject)
        ));
        assert!(matches!(
            Signer::new("   \t  ", "rauthy"),
            Err(SignerError::EmptySubject)
        ));
        assert!(matches!(
            Signer::new("alice@example.com", ""),
            Err(SignerError::EmptyIdentityProvider)
        ));
    }

    #[test]
    fn signer_with_session_id_round_trips_camel_case() {
        let signer = Signer::new("bart@tenant.example", "rauthy@tenant-org")
            .unwrap()
            .with_session_id("sess-42");
        let json = serde_json::to_string(&signer).unwrap();
        assert!(json.contains("\"subject\":\"bart@tenant.example\""));
        assert!(json.contains("\"identityProvider\":\"rauthy@tenant-org\""));
        assert!(json.contains("\"sessionId\":\"sess-42\""));
    }
}
