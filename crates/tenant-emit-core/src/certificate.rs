//! Governance Certificate emit engine.
//!
//! Extracted from OAP's `factory-engine/src/governance_certificate.rs` (the
//! emit path) and relicensed Apache-2.0 from AGPL-3.0 by the sole copyright
//! holder (see NOTICE). This is the engine half: the certificate builder, the
//! Ed25519 signing-key resolution, the run-directory artifact scan, the
//! content-binding hash + signature computation, and persistence. The data
//! types it builds live in `tenant-emit-types`; the verify half (signature
//! re-check, artifact re-derivation, corpus-binding adjudication) is excluded by
//! construction and lives in tenant-tail.
//!
//! Generated post-hoc from a finished run directory: no pipeline orchestration,
//! no `FactoryPipelineState` re-run, just a scan of `<run-dir>/<stage-id>/`.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer as Ed25519Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

use tenant_emit_types::certificate::{
    AgenticPostureBinding, ApprovalRecord, BuildSpecRecord, CERTIFICATE_VERSION, CertificateStatus,
    ChainIntegrity, ComplianceRecord, ConsumedOverride, CorpusBinding, GovernanceCertificate,
    IntentRecord, InterStageChainRecord, ProofChainSummary, SbomArtifactBinding, Signer,
    SigningAttestation, SigningAttestationKind, StageOutcome, StageRecord, VerificationOutcome,
    VerificationRecord,
};
use tenant_emit_types::pipeline_state::FactoryPipelineState;

/// Environment-variable name carrying a base64-encoded 32-byte Ed25519 seed
/// (FR-008.1). Operator-supplied keys outside the agent's write scope.
pub const ENV_SIGNING_KEY: &str = "OAP_SIGNING_KEY";

/// Environment-variable name carrying a path to a file holding a base64-
/// encoded 32-byte Ed25519 seed (FR-008.1). Alternative to `OAP_SIGNING_KEY`.
pub const ENV_SIGNING_KEY_PATH: &str = "OAP_SIGNING_KEY_PATH";

/// Errors raised when building a certificate via the fallible builder path.
#[derive(Debug, thiserror::Error)]
pub enum CertificateBuildError {
    /// Tenant emission requested but no signer was supplied -- spec 168
    /// FR-007 ("a run with no identifiable signer halts before emitting").
    #[error("tenant emission requires a signer (spec 168 FR-007); none provided")]
    MissingSigner,
}

/// Errors raised while resolving operator-supplied signing material. Surfaced
/// so the CLI can treat a malformed operator key as a configuration error
/// (exit 2) instead of a panic. A quiet fallback to an ephemeral key when the
/// operator expressly attempted to supply one would be a silent trust
/// downgrade, so these are hard errors, never a fallback trigger.
#[derive(Debug, thiserror::Error)]
pub enum SigningKeyError {
    /// `OAP_SIGNING_KEY` is set but is not a base64-encoded 32-byte seed.
    #[error("OAP_SIGNING_KEY is set but malformed: {0}")]
    MalformedEnvKey(String),
    /// `OAP_SIGNING_KEY_PATH` is set but the file could not be read. The path
    /// is included here (an operator-facing diagnostic on stderr), never in
    /// the emitted certificate.
    #[error("OAP_SIGNING_KEY_PATH={path} unreadable: {source}")]
    KeyPathUnreadable {
        path: String,
        source: std::io::Error,
    },
    /// `OAP_SIGNING_KEY_PATH` is set but its contents are not a base64-encoded
    /// 32-byte seed.
    #[error("OAP_SIGNING_KEY_PATH={path} content malformed: {reason}")]
    KeyPathMalformed { path: String, reason: String },
    /// The OS random-number generator was unavailable for the ephemeral
    /// fallback.
    #[error("OS RNG unavailable: {0}")]
    RngUnavailable(String),
}

// ── Certificate Builder ──────────────────────────────────────────────

/// Builder for constructing a GovernanceCertificate from pipeline state.
pub struct CertificateBuilder {
    pipeline_run_id: String,
    intent: IntentRecord,
    build_spec_hash: String,
    approval_record: Option<ApprovalRecord>,
    stages: Vec<StageRecord>,
    verification: VerificationRecord,
    proof_chain: ProofChainSummary,
    compliance: Option<ComplianceRecord>,
    signer: Option<Signer>,
    inter_stage_chain: Option<InterStageChainRecord>,
    admitted_envelope_hash: Option<String>,
    goal_id: Option<String>,
    intent_capsule_hash: Option<String>,
    consumed_overrides: Vec<ConsumedOverride>,
    corpus_binding: Option<CorpusBinding>,
    sbom_artifact_binding: Option<SbomArtifactBinding>,
    agentic_posture_binding: Option<AgenticPostureBinding>,
}

impl CertificateBuilder {
    /// Create a new builder with the minimum required fields.
    pub fn new(pipeline_run_id: impl Into<String>, intent: IntentRecord) -> Self {
        Self {
            pipeline_run_id: pipeline_run_id.into(),
            intent,
            build_spec_hash: String::new(),
            approval_record: None,
            stages: Vec::new(),
            verification: VerificationRecord {
                compile: VerificationOutcome::Skipped,
                test: VerificationOutcome::Skipped,
                lint: VerificationOutcome::Skipped,
                typecheck: VerificationOutcome::Skipped,
                security_scan: VerificationOutcome::Skipped,
            },
            proof_chain: ProofChainSummary {
                record_count: 0,
                first_record_hash: None,
                last_record_hash: None,
                chain_integrity: ChainIntegrity::Empty,
            },
            compliance: None,
            signer: None,
            inter_stage_chain: None,
            admitted_envelope_hash: None,
            goal_id: None,
            intent_capsule_hash: None,
            consumed_overrides: Vec::new(),
            corpus_binding: None,
            sbom_artifact_binding: None,
            agentic_posture_binding: None,
        }
    }

    pub fn build_spec_hash(mut self, hash: impl Into<String>) -> Self {
        self.build_spec_hash = hash.into();
        self
    }

    pub fn approval_record(mut self, record: ApprovalRecord) -> Self {
        self.approval_record = Some(record);
        self
    }

    pub fn stages(mut self, stages: Vec<StageRecord>) -> Self {
        self.stages = stages;
        self
    }

    pub fn add_stage(mut self, stage: StageRecord) -> Self {
        self.stages.push(stage);
        self
    }

    pub fn verification(mut self, verification: VerificationRecord) -> Self {
        self.verification = verification;
        self
    }

    pub fn proof_chain(mut self, summary: ProofChainSummary) -> Self {
        self.proof_chain = summary;
        self
    }

    pub fn compliance(mut self, compliance: ComplianceRecord) -> Self {
        self.compliance = Some(compliance);
        self
    }

    /// Attach the run's signed inter-stage manifest chain (spec 170 FR-007).
    pub fn inter_stage_chain(mut self, chain: InterStageChainRecord) -> Self {
        self.inter_stage_chain = Some(chain);
        self
    }

    /// Attach a [`Signer`] identifying the principal that drove the run
    /// (spec 168 §FR-003). Required for tenant emission.
    pub fn signer(mut self, signer: Signer) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Spec 198 FR-009 -- bind the admitted envelope hash the run executed
    /// under into the certificate (inside hash + signature).
    pub fn admitted_envelope_hash(mut self, hash: impl Into<String>) -> Self {
        self.admitted_envelope_hash = Some(hash.into());
        self
    }

    /// Spec 198 FR-005 -- bind the run's intent capsule (stable goal id +
    /// canonical capsule hash) into the certificate.
    pub fn intent_capsule(
        mut self,
        goal_id: impl Into<String>,
        capsule_hash: impl Into<String>,
    ) -> Self {
        self.goal_id = Some(goal_id.into());
        self.intent_capsule_hash = Some(capsule_hash.into());
        self
    }

    /// Spec 198 FR-013(c) -- bind the overrides the run consumed (as
    /// presented by the platform's admission-gated bundle) into the
    /// certificate.
    pub fn consumed_overrides(mut self, overrides: Vec<ConsumedOverride>) -> Self {
        self.consumed_overrides = overrides;
        self
    }

    /// Spec 218 FR-001 / spec 220 FR-007: bind the corpus attestation hash and
    /// the spec-spine tool version into the certificate (inside hash +
    /// signature). The hash is the SHA-256 of the canonical `CorpusAttestation`
    /// JSON, produced by the caller via the public reader seam
    /// `spec_spine_core::attest::attestation_hash`. The builder DOES NOT call
    /// `attest` or `verify_recompute`; the hash is always a supplied value
    /// (read, never recompute).
    pub fn corpus_binding(
        mut self,
        hash: impl Into<String>,
        spec_spine_version: impl Into<String>,
    ) -> Self {
        self.corpus_binding = Some(CorpusBinding {
            corpus_attestation_hash: hash.into(),
            spec_spine_version: spec_spine_version.into(),
        });
        self
    }

    /// Spec 203 FR-003: bind the produced app's BOM + audit artifact content
    /// hashes and the BOM tool version into the certificate (inside hash +
    /// signature). Both hashes are SUPPLIED by the emission path; the builder
    /// never regenerates the BOM (read, never recompute).
    pub fn sbom_artifact_binding(
        mut self,
        bom_hash: impl Into<String>,
        audit_hash: impl Into<String>,
        bom_tool_version: impl Into<String>,
    ) -> Self {
        self.sbom_artifact_binding = Some(SbomArtifactBinding {
            bom_hash: bom_hash.into(),
            audit_hash: audit_hash.into(),
            bom_tool_version: bom_tool_version.into(),
        });
        self
    }

    /// Spec 210 FR-002: bind the produced app's declared agentic posture (read
    /// off the frozen Build Spec by the emission path) into the certificate
    /// (inside hash + signature). The binding is SUPPLIED by the caller via
    /// [`AgenticPostureBinding::from_build_spec`]; the builder never re-parses
    /// the Build Spec or re-derives the posture (read, never recompute). An
    /// omitted `agentic_posture` on the Build Spec still binds
    /// (`none`/`defaulted: true`) so a defaulted posture is visibly defaulted,
    /// never silently equivalent to authored `none`.
    pub fn agentic_posture_binding(mut self, binding: AgenticPostureBinding) -> Self {
        self.agentic_posture_binding = Some(binding);
        self
    }

    /// Fallible build path for tenant emission (spec 168 §FR-007).
    ///
    /// Returns [`CertificateBuildError::MissingSigner`] when no
    /// [`Signer`] has been attached. The tenant pipeline runner calls
    /// this entry point so a misconfigured-identity run halts before
    /// emitting a certificate, rather than producing one with a null
    /// signer.
    pub fn build_tenant(self) -> Result<GovernanceCertificate, CertificateBuildError> {
        if self.signer.is_none() {
            return Err(CertificateBuildError::MissingSigner);
        }
        Ok(self.build())
    }

    /// Build the certificate, computing the self-authenticating hash (FR-008)
    /// AND the Ed25519 signature (FR-008.1). Signing key is resolved via
    /// `resolve_signing_material()` -- operator env vars take precedence,
    /// ephemeral fallback for local dev.
    pub fn build(self) -> GovernanceCertificate {
        let has_failure = self.stages.iter().any(|s| s.status == StageOutcome::Failed);

        let status = if has_failure {
            CertificateStatus::Incomplete
        } else {
            CertificateStatus::Complete
        };

        let (signing_key, attestation) = resolve_signing_material();
        let public_key_b64 = B64.encode(signing_key.verifying_key().to_bytes());

        let mut cert = GovernanceCertificate {
            certificate_version: CERTIFICATE_VERSION.into(),
            pipeline_run_id: self.pipeline_run_id,
            timestamp: Utc::now(),
            status,
            intent: self.intent,
            build_spec: BuildSpecRecord {
                hash: self.build_spec_hash,
                approval_record: self.approval_record,
            },
            stages: self.stages,
            verification: self.verification,
            proof_chain: self.proof_chain,
            compliance: self.compliance,
            signer: self.signer,
            inter_stage_chain: self.inter_stage_chain,
            admitted_envelope_hash: self.admitted_envelope_hash,
            goal_id: self.goal_id,
            intent_capsule_hash: self.intent_capsule_hash,
            consumed_overrides: self.consumed_overrides,
            corpus_binding: self.corpus_binding,
            sbom_artifact_binding: self.sbom_artifact_binding,
            agentic_posture_binding: self.agentic_posture_binding,
            certificate_hash: String::new(),
            signing_public_key: public_key_b64,
            cert_signature: String::new(),
            signing_attestation: attestation,
            platform_countersign: None,
        };

        // FR-008 (revised): content-binding hash. Zeros cert_hash AND
        // cert_signature so the hash is stable across signing.
        cert.certificate_hash = compute_certificate_hash(&cert);

        // FR-008.1: Ed25519 signature over canonical JSON with cert_signature
        // zeroed and cert_hash populated. Signing happens after hashing so
        // the signature attests both the content and its content-binding
        // fingerprint.
        cert.cert_signature = compute_certificate_signature(&cert, &signing_key);
        cert
    }
}

// ── Signing-key Resolution ───────────────────────────────────────────

/// Resolve the Ed25519 signing key per spec 102 FR-008.1:
///   1. `OAP_SIGNING_KEY` env var (base64, 32-byte seed) -- `Operator` kind.
///   2. `OAP_SIGNING_KEY_PATH` env var (file path) -- `Operator` kind.
///   3. Ephemeral key generated for this run -- `Ephemeral` kind.
///
/// Returns the signing key plus the attestation describing the trust posture.
/// Malformed operator-supplied material panics -- the caller should not
/// silently fall back to ephemeral when the operator expressly attempted to
/// supply a key (that would be a quiet downgrade). Callers that want to turn a
/// malformed key into a clean error instead of a panic use
/// [`try_resolve_signing_material`]; this thin wrapper is retained for OAP
/// behavior parity and for the builder's internal signing path.
pub fn resolve_signing_material() -> (SigningKey, SigningAttestation) {
    try_resolve_signing_material().unwrap_or_else(|e| panic!("{e}"))
}

/// Fallible sibling of [`resolve_signing_material`]. Same precedence
/// (`OAP_SIGNING_KEY`, then `OAP_SIGNING_KEY_PATH`, then an ephemeral key), but
/// a malformed operator-supplied key returns [`SigningKeyError`] instead of
/// panicking, so the CLI can exit 2 (configuration error) with a clean message.
///
/// The returned attestation `note` records only the *source* env var name
/// (`source=OAP_SIGNING_KEY_PATH`), never the key file's filesystem path: the
/// certificate is a shareable, offline-verifiable artifact and must not leak
/// where the operator keeps the signing key.
pub fn try_resolve_signing_material() -> Result<(SigningKey, SigningAttestation), SigningKeyError> {
    if let Ok(b64) = std::env::var(ENV_SIGNING_KEY) {
        let seed = decode_seed(&b64).map_err(SigningKeyError::MalformedEnvKey)?;
        return Ok((
            SigningKey::from_bytes(&seed),
            SigningAttestation {
                kind: SigningAttestationKind::Operator,
                note: Some(format!("source={ENV_SIGNING_KEY}")),
            },
        ));
    }
    if let Ok(path) = std::env::var(ENV_SIGNING_KEY_PATH) {
        let contents = std::fs::read_to_string(&path).map_err(|source| {
            SigningKeyError::KeyPathUnreadable {
                path: path.clone(),
                source,
            }
        })?;
        let seed =
            decode_seed(contents.trim()).map_err(|reason| SigningKeyError::KeyPathMalformed {
                path: path.clone(),
                reason,
            })?;
        return Ok((
            SigningKey::from_bytes(&seed),
            SigningAttestation {
                kind: SigningAttestationKind::Operator,
                // Source kind only -- never the resolved path (no key-location leak).
                note: Some(format!("source={ENV_SIGNING_KEY_PATH}")),
            },
        ));
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| SigningKeyError::RngUnavailable(e.to_string()))?;
    Ok((
        SigningKey::from_bytes(&seed),
        SigningAttestation {
            kind: SigningAttestationKind::Ephemeral,
            note: Some("auto-generated for pipeline run".into()),
        },
    ))
}

fn decode_seed(s: &str) -> Result<[u8; 32], String> {
    let bytes = B64.decode(s.trim()).map_err(|e| format!("base64: {e}"))?;
    bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("seed length {} != 32", v.len()))
}

// ── Hash + Signature Computation ─────────────────────────────────────

/// Compute the content-binding SHA-256 hash of a certificate (FR-008 revised).
///
/// Zeros both `certificate_hash` AND `cert_signature` so the hash is
/// invariant under signing -- the signature can be re-computed without
/// invalidating the hash. The hash is no longer the authoritative
/// provenance check (see `compute_certificate_signature` + FR-008.4); it
/// remains as a content fingerprint and an accidental-corruption guard
/// inside the signed payload.
pub fn compute_certificate_hash(cert: &GovernanceCertificate) -> String {
    let mut cert_for_hash = cert.clone();
    cert_for_hash.certificate_hash = String::new();
    cert_for_hash.cert_signature = String::new();
    // Spec 198 FR-014 -- the platform countersign is applied AFTER emission
    // (sync-back patch); excluding it keeps the offline chain valid across
    // sealing.
    cert_for_hash.platform_countersign = None;

    // Canonical JSON: serde_json produces deterministic output for BTreeMap.
    // For Vec fields, order is preserved as inserted.
    let canonical = serde_json::to_string(&cert_for_hash).expect("certificate serialises to JSON");

    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Compute the Ed25519 signature of a certificate (FR-008.1).
///
/// Signs the canonical JSON of the certificate with `cert_signature` set
/// to empty string and `certificate_hash` *populated* -- the signature
/// attests both the content and the content-binding fingerprint. Returns
/// the base64-encoded 64-byte signature.
pub fn compute_certificate_signature(cert: &GovernanceCertificate, key: &SigningKey) -> String {
    let mut cert_for_sig = cert.clone();
    cert_for_sig.cert_signature = String::new();
    // Spec 198 FR-014 -- see compute_certificate_hash: the post-emission
    // countersign is outside the engine signature too.
    cert_for_sig.platform_countersign = None;
    let canonical =
        serde_json::to_string(&cert_for_sig).expect("certificate serialises to JSON for signing");
    let sig: Signature = key.sign(canonical.as_bytes());
    B64.encode(sig.to_bytes())
}

// ── Generation from Pipeline State ───────────────────────────────────

/// OAP's canonical s0..s5 stage list (spec 102).
///
/// Tenant pipelines (spec 168 §2.4) pass their own stage IDs to
/// [`generate_certificate_with_stage_ids`]; the OAP-side
/// [`generate_certificate`] keeps this fixed list as its default for
/// byte-equivalence with pre-1.3.0 fixtures.
pub const OAP_STAGE_IDS: &[&str] = &[
    "s0-preflight",
    "s1-business-requirements",
    "s2-service-requirements",
    "s3-data-model",
    "s4-api-specification",
    "s5-ui-specification",
];

/// Generate a governance certificate from a completed (or halted) pipeline.
///
/// FR-003: called at the end of every factory pipeline run.
/// FR-005: computes SHA-256 of each stage output artifact on disk.
///
/// Uses [`OAP_STAGE_IDS`] as the stage list. Tenant pipelines with
/// different stage grammars (spec 168 §2.4) call
/// [`generate_certificate_with_stage_ids`] instead.
pub fn generate_certificate(
    pipeline_state: &FactoryPipelineState,
    requirements_hash: &str,
    artifact_dir: &Path,
    proof_chain_summary: Option<ProofChainSummary>,
) -> GovernanceCertificate {
    generate_certificate_with_stage_ids(
        pipeline_state,
        requirements_hash,
        artifact_dir,
        proof_chain_summary,
        OAP_STAGE_IDS,
    )
}

/// Generate a governance certificate using a caller-supplied stage list
/// (spec 168 §2.4).
///
/// `stage_ids` controls which subdirectories of `artifact_dir` are
/// scanned and the order in which their [`StageRecord`]s appear in the
/// certificate. When the slice is empty, every subdirectory of
/// `artifact_dir` is scanned in lexicographic order -- useful for tenant
/// pipelines that emit stages dynamically and want filesystem discovery
/// instead of an explicit list.
///
/// Per spec 168 §2.4, the tenant's stage shape is opaque to the
/// certificate format: any stage representable as `(stage_id,
/// artifact_hashes)` round-trips through the verifier untouched.
pub fn generate_certificate_with_stage_ids(
    pipeline_state: &FactoryPipelineState,
    requirements_hash: &str,
    artifact_dir: &Path,
    proof_chain_summary: Option<ProofChainSummary>,
    stage_ids: &[&str],
) -> GovernanceCertificate {
    generate_certificate_bound(
        pipeline_state,
        requirements_hash,
        artifact_dir,
        proof_chain_summary,
        stage_ids,
        None,
    )
}

/// Spec 198 FR-005/FR-009 -- the admission + intent-capsule facts a
/// grant-governed run binds into its certificate at emission.
#[derive(Debug, Clone)]
pub struct CapsuleBinding {
    pub admitted_envelope_hash: String,
    pub goal_id: String,
    pub intent_capsule_hash: String,
    /// Spec 198 FR-013(c) -- overrides the run consumed, from the bundle's
    /// admission block (platform predicate-checked).
    pub consumed_overrides: Vec<ConsumedOverride>,
}

/// [`generate_certificate_with_stage_ids`] plus the spec 198 capsule
/// binding. `binding: None` produces a byte-identical certificate to the
/// unbound path (the optional fields are skipped in serialization).
pub fn generate_certificate_bound(
    pipeline_state: &FactoryPipelineState,
    requirements_hash: &str,
    artifact_dir: &Path,
    proof_chain_summary: Option<ProofChainSummary>,
    stage_ids: &[&str],
    binding: Option<&CapsuleBinding>,
) -> GovernanceCertificate {
    let intent = IntentRecord {
        requirements_hash: requirements_hash.to_string(),
        spec_id: None,
        spec_hash: None,
    };

    let build_spec_hash = pipeline_state.build_spec_hash.clone().unwrap_or_default();

    let stages = if stage_ids.is_empty() {
        collect_stage_records_from_dir(artifact_dir)
    } else {
        collect_stage_records(artifact_dir, stage_ids)
    };

    let verification = VerificationRecord {
        compile: VerificationOutcome::Skipped,
        test: VerificationOutcome::Skipped,
        lint: VerificationOutcome::Skipped,
        typecheck: VerificationOutcome::Skipped,
        security_scan: VerificationOutcome::Skipped,
    };

    let proof_chain = proof_chain_summary.unwrap_or(ProofChainSummary {
        record_count: 0,
        first_record_hash: None,
        last_record_hash: None,
        chain_integrity: ChainIntegrity::Empty,
    });

    let mut builder = CertificateBuilder::new(&pipeline_state.pipeline_id, intent)
        .build_spec_hash(build_spec_hash)
        .stages(stages)
        .verification(verification)
        .proof_chain(proof_chain);
    if let Some(b) = binding {
        builder = builder
            .admitted_envelope_hash(b.admitted_envelope_hash.clone())
            .intent_capsule(b.goal_id.clone(), b.intent_capsule_hash.clone())
            .consumed_overrides(b.consumed_overrides.clone());
    }
    builder.build()
}

/// Scan the artifact directory for stage output files using a
/// caller-supplied ordered stage list.
fn collect_stage_records(artifact_dir: &Path, stage_ids: &[&str]) -> Vec<StageRecord> {
    let mut stages = Vec::new();
    for stage_id in stage_ids {
        stages.push(stage_record_for(artifact_dir, stage_id));
    }
    stages
}

/// Scan the artifact directory's subdirectories and emit a stage record
/// per subdirectory, in lexicographic order. Used when the caller passes
/// an empty stage-id list to [`generate_certificate_with_stage_ids`].
fn collect_stage_records_from_dir(artifact_dir: &Path) -> Vec<StageRecord> {
    let Ok(entries) = std::fs::read_dir(artifact_dir) else {
        return Vec::new();
    };

    // `file_type()` reads the directory entry without traversing, so a
    // symlinked directory reports as a symlink (not a dir) and is excluded:
    // a symlinked stage dir must not pull content from outside the run dir
    // into a signed certificate.
    let mut stage_dirs: Vec<String> = entries
        .flatten()
        .filter(|e| e.file_type().map(|ft| ft.is_dir()).unwrap_or(false))
        .filter_map(|e| e.file_name().to_str().map(|s| s.to_string()))
        .collect();
    stage_dirs.sort();

    stage_dirs
        .iter()
        .map(|sid| stage_record_for(artifact_dir, sid))
        .collect()
}

/// Build a single [`StageRecord`] for the named stage by scanning the
/// top-level files of `artifact_dir/<stage_id>/`.
///
/// The scan is deliberately NON-recursive and skips symlinks:
/// - Only top-level regular files of the stage directory are hashed. The
///   artifact key is the bare file name, so nested files could not be
///   distinguished (or re-read by the verifier, which joins
///   `stage_dir/<name>`); recursion would silently collide same-named files.
/// - Symlinks are skipped (with a warning): a symlinked artifact could bind
///   content from outside the run directory (e.g. the operator's signing key)
///   into a signed certificate.
/// - An unreadable file is skipped with a warning rather than silently
///   dropped, so a gap in coverage is visible on stderr.
fn stage_record_for(artifact_dir: &Path, stage_id: &str) -> StageRecord {
    let stage_dir = artifact_dir.join(stage_id);
    let mut artifact_hashes = BTreeMap::new();

    if stage_dir.is_dir()
        && let Ok(entries) = std::fs::read_dir(&stage_dir)
    {
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                eprintln!(
                    "warning: skipping symlink in stage {stage_id}: {} (symlinked artifacts are not hashed into the certificate)",
                    entry.file_name().to_string_lossy()
                );
                continue;
            }
            if !file_type.is_file() {
                // Subdirectories and special files: the scan is non-recursive.
                continue;
            }
            let path = entry.path();
            match sha256_file(&path) {
                Ok(hash) => {
                    let name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();
                    artifact_hashes.insert(name, hash);
                }
                Err(e) => eprintln!(
                    "warning: skipping unreadable artifact in stage {stage_id}: {} ({e})",
                    path.display()
                ),
            }
        }
    }

    let status = if artifact_hashes.is_empty() {
        StageOutcome::Skipped
    } else {
        StageOutcome::Passed
    };

    StageRecord {
        stage_id: stage_id.to_string(),
        status,
        artifact_hashes,
        gate_result: None,
        duration_ms: None,
        sandbox_execution: None,
    }
}

/// SHA-256 hash of raw bytes, returned as lowercase hex.
pub fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// SHA-256 hash of a file's contents, streamed in fixed-size chunks so a
/// multi-gigabyte artifact does not have to be held in memory at once. The
/// digest is identical to hashing the whole byte string.
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

// ── Persistence (FR-009) ─────────────────────────────────────────────

/// Persist the certificate as `governance-certificate.json` in the given
/// directory. Convenience wrapper over [`persist_certificate_at`].
pub fn persist_certificate(cert: &GovernanceCertificate, output_dir: &Path) -> std::io::Result<()> {
    persist_certificate_at(cert, &output_dir.join("governance-certificate.json"))
}

/// Persist the certificate to an exact file path, creating parent directories
/// as needed. The write is atomic: the JSON is written to a temporary sibling
/// and renamed over the target, so a concurrent reader (or a crash mid-write)
/// never observes a half-written certificate.
pub fn persist_certificate_at(cert: &GovernanceCertificate, path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(cert).map_err(std::io::Error::other)?;

    // Temp sibling in the same directory (so the rename is same-filesystem and
    // atomic), disambiguated by PID to avoid clashing with a concurrent emit.
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "governance-certificate.json".to_string());
    let tmp = path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()));
    std::fs::write(&tmp, json)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Best-effort cleanup of the temp file on a failed rename.
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

// ── spec_id resolution validation (spec 102 G-2) ─────────────────────
//
// Validation results live in a sibling `validation-warnings.json` file rather
// than the cert itself, keeping the cert struct immutable (no version bump,
// signature invariant). On the tenant emit path the certificate carries no
// `intent.spec_id`, so resolution is a guaranteed no-op; full registry
// resolution is a verify-time concern (tenant-tail / spec-spine), not emission,
// so the emit core links no spec-spine registry reader.

/// A single spec-id-resolution finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ValidationWarning {
    /// `intent.spec_id` was set but no spec with that id exists in
    /// the spec-spine registry.
    SpecIdNotResolved {
        spec_id: String,
        registry_path: String,
    },
    /// The registry was not loadable at the expected path. By
    /// default this surfaces as a warning, not an error, because
    /// the cert is authoritative independent of the registry's
    /// existence on this filesystem.
    RegistryNotLoadable {
        registry_path: String,
        error: String,
    },
}

impl ValidationWarning {
    /// Stable string id for the finding kind. Used by the env-gate
    /// to decide whether to promote a warning to an error.
    pub fn kind(&self) -> &'static str {
        match self {
            ValidationWarning::SpecIdNotResolved { .. } => "spec-id-not-resolved",
            ValidationWarning::RegistryNotLoadable { .. } => "registry-not-loadable",
        }
    }
}

/// Validate `cert.intent.spec_id` against the spec spine.
///
/// A tenant certificate carries no `spec_id` (the post-hoc emitter never sets
/// one), so this returns an empty list on the emit path. The call site is
/// preserved for behavior parity with OAP's in-tree emitter; registry-backed
/// resolution of a non-empty `spec_id` is delegated to the verifier and
/// spec-spine, which the emit core deliberately does not link.
pub fn validate_spec_id_resolution(
    cert: &GovernanceCertificate,
    _repo_root: &Path,
) -> Vec<ValidationWarning> {
    if cert.intent.spec_id.is_none() {
        return Vec::new();
    }
    Vec::new()
}

/// Write the validation warnings to a sibling
/// `validation-warnings.json` next to the certificate (no-op when
/// the slice is empty -- sibling-file absence == no warnings).
pub fn write_validation_warnings(
    warnings: &[ValidationWarning],
    cert_path: &Path,
) -> Result<Option<std::path::PathBuf>, std::io::Error> {
    if warnings.is_empty() {
        return Ok(None);
    }
    let sibling = cert_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("validation-warnings.json");
    let body = serde_json::to_string_pretty(&serde_json::json!({
        "certificateHash": "see governance-certificate.json",
        "warnings": warnings,
    }))
    .expect("validation warnings serialize");
    std::fs::write(&sibling, body)?;
    Ok(Some(sibling))
}

/// Returns true when the operator has opted into hard-failure mode
/// via `OAP_REQUIRE_SPEC_ID_RESOLUTION=1`. Default: false (warnings
/// remain warnings).
pub fn require_spec_id_resolution_enabled() -> bool {
    matches!(
        std::env::var("OAP_REQUIRE_SPEC_ID_RESOLUTION").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tenant_emit_types::certificate::{GateResultRecord, SignerError};

    fn intent(reqs: &str) -> IntentRecord {
        IntentRecord {
            requirements_hash: reqs.to_string(),
            spec_id: None,
            spec_hash: None,
        }
    }

    #[test]
    fn certificate_round_trip_and_hash() {
        let cert = CertificateBuilder::new("run-001", intent("abc123"))
            .build_spec_hash("def456")
            .build();

        assert_eq!(cert.certificate_version, CERTIFICATE_VERSION);
        assert_eq!(cert.status, CertificateStatus::Complete);
        assert!(!cert.certificate_hash.is_empty());
        assert!(!cert.cert_signature.is_empty());

        // The built cert recomputes to its own stored hash.
        assert_eq!(cert.certificate_hash, compute_certificate_hash(&cert));

        // Round-trip serialisation.
        let json = serde_json::to_string_pretty(&cert).unwrap();
        let restored: GovernanceCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.certificate_hash, cert.certificate_hash);
        assert_eq!(restored.pipeline_run_id, "run-001");
    }

    #[test]
    fn incomplete_certificate_on_failure() {
        let cert = CertificateBuilder::new("run-003", intent("req"))
            .add_stage(StageRecord {
                stage_id: "s0-preflight".into(),
                status: StageOutcome::Passed,
                artifact_hashes: BTreeMap::new(),
                gate_result: None,
                duration_ms: None,
                sandbox_execution: None,
            })
            .add_stage(StageRecord {
                stage_id: "s1-business-requirements".into(),
                status: StageOutcome::Failed,
                artifact_hashes: BTreeMap::new(),
                gate_result: Some(GateResultRecord {
                    passed: false,
                    checks_run: 3,
                    checks_failed: 1,
                }),
                duration_ms: None,
                sandbox_execution: None,
            })
            .build();

        assert_eq!(cert.status, CertificateStatus::Incomplete);
    }

    #[test]
    fn ephemeral_fallback_when_no_operator_key() {
        // Test env has no OAP_SIGNING_KEY -> ephemeral fallback.
        let cert = CertificateBuilder::new("run-clean", intent("abc"))
            .build_spec_hash("spec")
            .build();
        assert!(!cert.signing_public_key.is_empty(), "public key set");
        assert!(!cert.cert_signature.is_empty(), "signature set");
        assert_eq!(
            cert.signing_attestation.kind,
            SigningAttestationKind::Ephemeral
        );
    }

    #[test]
    fn persist_writes_governance_certificate_json() {
        let dir = tempfile::tempdir().unwrap();
        let cert = CertificateBuilder::new("run-004", intent("req-hash")).build();
        let cert_dir = dir.path().join("output");
        persist_certificate(&cert, &cert_dir).unwrap();
        let path = cert_dir.join("governance-certificate.json");
        assert!(path.exists());
        let restored: GovernanceCertificate =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(restored.certificate_hash, cert.certificate_hash);
    }

    #[test]
    fn generate_certificate_from_run_dir_scans_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let artifact_dir = dir.path().join("artifacts");
        let stage_dir = artifact_dir.join("s1-business-requirements");
        fs::create_dir_all(&stage_dir).unwrap();
        fs::write(stage_dir.join("entity-model.json"), b"{}").unwrap();

        let mut state = FactoryPipelineState::new("run-005", "acme-vue-encore");
        state.transition_to_scaffolding("build-spec-hash-xyz".into());
        state.mark_complete();

        let cert = generate_certificate(&state, "requirements-hash", &artifact_dir, None);

        assert_eq!(cert.pipeline_run_id, "run-005");
        assert_eq!(cert.build_spec.hash, "build-spec-hash-xyz");
        assert_eq!(cert.intent.requirements_hash, "requirements-hash");
        let s1 = cert
            .stages
            .iter()
            .find(|s| s.stage_id == "s1-business-requirements")
            .unwrap();
        assert_eq!(s1.status, StageOutcome::Passed);
        assert!(s1.artifact_hashes.contains_key("entity-model.json"));
        // The artifact hash is the SHA-256 of the file contents.
        assert_eq!(s1.artifact_hashes["entity-model.json"], sha256_bytes(b"{}"));
    }

    #[test]
    fn build_tenant_halts_when_no_signer_attached() {
        let result = CertificateBuilder::new("run-1", intent("reqs"))
            .build_spec_hash("bs")
            .build_tenant();
        assert!(matches!(result, Err(CertificateBuildError::MissingSigner)));
    }

    #[test]
    fn build_tenant_succeeds_when_signer_attached() {
        let signer = Signer::new("alice@tenant.example.com", "rauthy@tenant-org").unwrap();
        let cert = CertificateBuilder::new("run-1", intent("reqs"))
            .build_spec_hash("bs")
            .signer(signer.clone())
            .build_tenant()
            .unwrap();
        let attached = cert.signer.as_ref().unwrap();
        assert_eq!(attached.subject, signer.subject);
        assert_eq!(attached.identity_provider, signer.identity_provider);
        assert_eq!(cert.certificate_version, CERTIFICATE_VERSION);
    }

    #[test]
    fn oap_build_still_omits_signer_when_unset() {
        let cert = CertificateBuilder::new("run-1", intent("reqs"))
            .build_spec_hash("bs")
            .build();
        assert!(cert.signer.is_none());
        let json = serde_json::to_string(&cert).unwrap();
        assert!(!json.contains("\"signer\""));
    }

    #[test]
    fn signer_field_binds_into_certificate_hash() {
        let bare = CertificateBuilder::new("run-1", intent("reqs"))
            .build_spec_hash("bs")
            .build();
        let signed = CertificateBuilder::new("run-1", intent("reqs"))
            .build_spec_hash("bs")
            .signer(Signer::new("a@b", "rauthy").unwrap())
            .build();
        assert_ne!(bare.certificate_hash, signed.certificate_hash);
    }

    #[test]
    fn empty_subject_signer_is_rejected() {
        assert!(matches!(
            Signer::new("  ", "rauthy"),
            Err(SignerError::EmptySubject)
        ));
    }

    // ── spec 168 §2.4: stage-shape flexibility for tenant grammars ──

    fn write_stage_artifact(root: &Path, stage_id: &str, name: &str, body: &[u8]) {
        let stage_dir = root.join(stage_id);
        std::fs::create_dir_all(&stage_dir).unwrap();
        std::fs::write(stage_dir.join(name), body).unwrap();
    }

    fn pipeline_state_for_stage_tests() -> FactoryPipelineState {
        let mut state = FactoryPipelineState::new("tenant-run-1", "acme-vue-encore");
        state.transition_to_scaffolding("bs".into());
        state
    }

    #[test]
    fn tenant_stage_ids_round_trip_through_generate_certificate() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        write_stage_artifact(dir, "tenant-codegen", "app.rs", b"fn main(){}");
        write_stage_artifact(dir, "tenant-bundle", "bundle.tar", b"<bytes>");

        let state = pipeline_state_for_stage_tests();
        let cert = generate_certificate_with_stage_ids(
            &state,
            "req-hash",
            dir,
            None,
            &["tenant-codegen", "tenant-bundle"],
        );

        assert_eq!(cert.stages.len(), 2);
        assert_eq!(cert.stages[0].stage_id, "tenant-codegen");
        assert_eq!(cert.stages[1].stage_id, "tenant-bundle");
        assert_eq!(cert.stages[0].status, StageOutcome::Passed);
        assert!(cert.stages[0].artifact_hashes.contains_key("app.rs"));
    }

    #[test]
    fn empty_stage_id_slice_falls_back_to_filesystem_discovery() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        write_stage_artifact(dir, "z-final", "z.txt", b"z");
        write_stage_artifact(dir, "a-prepare", "a.txt", b"a");
        write_stage_artifact(dir, "m-middle", "m.txt", b"m");

        let state = pipeline_state_for_stage_tests();
        let cert = generate_certificate_with_stage_ids(&state, "req-hash", dir, None, &[]);

        // Filesystem discovery yields lexicographic order.
        assert_eq!(cert.stages.len(), 3);
        assert_eq!(cert.stages[0].stage_id, "a-prepare");
        assert_eq!(cert.stages[1].stage_id, "m-middle");
        assert_eq!(cert.stages[2].stage_id, "z-final");
    }

    #[test]
    fn re_emit_from_same_run_dir_is_deterministic_modulo_signer() {
        // Spec 220 FR-006 / AC-7: re-emitting from the same run directory
        // yields identical artifact + certificate content. The timestamp and
        // ephemeral signer differ per run, so compare the stage artifact
        // hashes (the deterministic content).
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        write_stage_artifact(dir, "stage-a", "a.txt", b"alpha");
        write_stage_artifact(dir, "stage-b", "b.txt", b"beta");
        let state = pipeline_state_for_stage_tests();

        let c1 = generate_certificate_with_stage_ids(&state, "req", dir, None, &[]);
        let c2 = generate_certificate_with_stage_ids(&state, "req", dir, None, &[]);

        let hashes = |c: &GovernanceCertificate| -> Vec<(String, BTreeMap<String, String>)> {
            c.stages
                .iter()
                .map(|s| (s.stage_id.clone(), s.artifact_hashes.clone()))
                .collect()
        };
        assert_eq!(hashes(&c1), hashes(&c2));
    }

    // ── corpus binding (spec 218 / spec 220 FR-007) emit path ──

    #[test]
    fn corpus_binding_is_inside_the_certificate_hash() {
        let bound = CertificateBuilder::new("run-218", intent("req"))
            .build_spec_hash("spec-hash")
            .corpus_binding("deadbeef", "0.8.0")
            .build();
        let unbound = CertificateBuilder::new("run-218", intent("req"))
            .build_spec_hash("spec-hash")
            .build();
        assert_ne!(
            bound.certificate_hash, unbound.certificate_hash,
            "binding must change the content-binding hash (proves it is inside the hash)"
        );
        let json = serde_json::to_string(&bound).unwrap();
        assert!(json.contains("corpusBinding"));
        assert!(json.contains("corpusAttestationHash"));
        assert!(json.contains("specSpineVersion"));
    }

    #[test]
    fn absent_corpus_binding_is_skipped_in_serialization() {
        let unbound = CertificateBuilder::new("run-no-cb", intent("req")).build();
        let json = serde_json::to_string(&unbound).unwrap();
        assert!(
            !json.contains("corpusBinding"),
            "absent binding must be skipped (the named unbound state)"
        );
    }

    #[test]
    fn consumed_overrides_empty_serialises_without_key() {
        let cert = CertificateBuilder::new("run-no-ov", intent("req")).build();
        let json = serde_json::to_string(&cert).unwrap();
        assert!(!json.contains("consumedOverrides"));
    }

    #[test]
    fn validate_spec_id_resolution_is_empty_for_tenant_cert() {
        // Tenant certs carry no spec_id -> no warnings, no sibling file.
        let cert = CertificateBuilder::new("run-v", intent("req")).build();
        assert!(cert.intent.spec_id.is_none());
        let warnings = validate_spec_id_resolution(&cert, Path::new("."));
        assert!(warnings.is_empty());
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("governance-certificate.json");
        fs::write(&cert_path, "{}").unwrap();
        assert!(
            write_validation_warnings(&warnings, &cert_path)
                .unwrap()
                .is_none()
        );
        assert!(!dir.path().join("validation-warnings.json").exists());
    }

    // ── symlink safety: a symlinked artifact must not be hashed into a cert ──

    #[cfg(unix)]
    #[test]
    fn symlinked_artifact_is_skipped_in_scan() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();

        // A secret outside the stage dir, and a stage with a real file plus a
        // symlink pointing at the secret. The scan must record the real file
        // and skip the symlink (no out-of-run content bound into the cert).
        let secret = dir.join("out-of-run-secret.txt");
        std::fs::write(&secret, b"operator key material").unwrap();
        let stage = dir.join("stage-x");
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join("real.txt"), b"real artifact").unwrap();
        std::os::unix::fs::symlink(&secret, stage.join("leaked.txt")).unwrap();

        let state = pipeline_state_for_stage_tests();
        let cert = generate_certificate_with_stage_ids(&state, "req", dir, None, &["stage-x"]);
        let s = &cert.stages[0];
        assert!(
            s.artifact_hashes.contains_key("real.txt"),
            "real files are still hashed"
        );
        assert!(
            !s.artifact_hashes.contains_key("leaked.txt"),
            "a symlinked artifact must not be hashed into the certificate"
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_stage_dir_is_skipped_in_auto_discovery() {
        // The symlink target lives in a separate tempdir so it is genuinely
        // outside the scanned run directory (not itself a discoverable stage).
        let target_tmp = tempfile::tempdir().unwrap();
        let outside = target_tmp.path().join("outside");
        std::fs::create_dir_all(outside.join("nested")).unwrap();
        std::fs::write(outside.join("nested/x.txt"), b"x").unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        // A real stage dir plus a symlink pointing out of the run directory.
        // Auto discovery must record only the real stage.
        write_stage_artifact(dir, "real-stage", "a.txt", b"a");
        std::os::unix::fs::symlink(&outside, dir.join("linked-stage")).unwrap();

        let state = pipeline_state_for_stage_tests();
        let cert = generate_certificate_with_stage_ids(&state, "req", dir, None, &[]);
        let ids: Vec<&str> = cert.stages.iter().map(|s| s.stage_id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["real-stage"],
            "a symlinked stage directory must not be discovered as a stage"
        );
    }
}
