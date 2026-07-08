//! tenant-emit: the emit-only CLI.
//!
//! One verb builds a factory's run-side governance certificate from a finished
//! run directory, with no pipeline orchestration and no trust handed to the
//! producer beyond the operator key it signs with:
//!
//!   * `build-certificate` -- reconstruct a signed `governance-certificate.json`
//!     from `<run-dir>/<stage-id>/<artifacts>`. It scans each stage directory,
//!     computes SHA-256 over every file, lifts the frozen Build Spec hash, and
//!     writes a self-authenticating, Ed25519-signed certificate. Optionally
//!     binds the tenant's own corpus attestation by hash (read, never recompute).
//!
//! The emitter is identity-bearing and never a tenant-tail verb: the verify/emit
//! boundary is load-bearing (spec 220 AC-6, spec 219 verify-only-by-construction).
//! The certificate this emits carries no platform countersign (a tenant run is
//! outside OAP's admission/grant flow); it is "verifiable-but-unsealed" and
//! round-trips offline under `tenant-tail verify-certificate`.
//!
//! Spec 220:
//!   * `--require-operator-key` refuses the ephemeral signing-key fallback: the
//!     binary exits non-zero if signing material resolves to an ephemeral key
//!     rather than an operator-supplied one (OAP_SIGNING_KEY /
//!     OAP_SIGNING_KEY_PATH). Production tenant emission must pass this (FR-003).
//!   * `--corpus-attestation <path>` (or OAP_CORPUS_ATTESTATION_PATH) binds a
//!     spec-spine CorpusAttestation into the certificate by hash, via the public
//!     reader seam `spec_spine_core::attest::attestation_hash` (FR-007). Read,
//!     never recompute: the emit-side attestation-emit / corpus-recompute
//!     functions are banned workspace-wide (clippy.toml + deny.toml).
//!
//! Exit codes:
//!   * `0` -- success; the certificate was written.
//!   * `1` -- runtime I/O failure after the certificate was built (e.g. the
//!     certificate could not be persisted to disk).
//!   * `2` -- configuration or input error, detected before anything is
//!     written: the run directory is missing, the signer flags are partial or
//!     `--tenant-mode` has no signer, an operator-supplied signing key is
//!     malformed, `--require-operator-key` resolved to an ephemeral key, a
//!     required binding (`--require-corpus-binding` / `--require-sbom-binding`)
//!     could not be applied, or a `--business-docs` file is unreadable.

use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::ExitCode;
use tenant_emit_core::{
    AgenticPostureBinding, CertificateBuildError, CertificateBuilder, ChainIntegrity,
    CorpusBinding, FactoryPipelineState, GovernanceCertificate, IntentRecord, OAP_STAGE_IDS,
    ProofChainSummary, SBOM_AUDIT_RELPATH, SBOM_BOM_RELPATH, SbomArtifactBinding, Signer,
    SigningAttestationKind, VerificationOutcome, VerificationRecord,
    generate_certificate_with_stage_ids, persist_certificate_at, sha256_bytes, sha256_file,
    try_resolve_signing_material, validate_spec_id_resolution, write_validation_warnings,
};
use tenant_emit_types::build_spec::BuildSpecPostureProjection;

#[derive(Parser)]
#[command(
    name = "tenant-emit",
    version,
    about = "Emit a factory's run-side governance certificate from a finished run directory. Post-hoc, identity-bearing, never a verifier (spec 220)."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build a signed governance certificate from a factory run directory
    /// (spec 102 FR-003; spec 168 FR-002; spec 220).
    BuildCertificate(BuildCertificateArgs),
}

#[derive(Parser)]
struct BuildCertificateArgs {
    /// Path to the factory run directory (`.factory/runs/<run_id>`).
    run_dir: PathBuf,

    /// Adapter name. Defaults to `unknown` if not supplied.
    #[arg(long, default_value = "unknown")]
    adapter: String,

    /// SHA-256 of the input requirements documents. If `--business-docs`
    /// is supplied, the hash is computed from those files and this flag
    /// is ignored.
    #[arg(long)]
    requirements_hash: Option<String>,

    /// Optional requirement document paths. When supplied, their concatenated
    /// SHA-256 is recorded as `intent.requirementsHash`.
    #[arg(long, num_args = 1..)]
    business_docs: Vec<PathBuf>,

    /// Full output file path (including the file name) for the emitted
    /// certificate. Parent directories are created as needed. Defaults to
    /// `<run-dir>/governance-certificate.json` when omitted.
    #[arg(long)]
    out: Option<PathBuf>,

    /// Repository root used to locate the committed spec registry for
    /// `intent.spec_id` resolution validation. Defaults to the current
    /// working directory. A tenant certificate carries no `spec_id`, so this
    /// is a no-op on the emit path (kept for parity with OAP's emitter).
    #[arg(long)]
    repo_root: Option<PathBuf>,

    /// Spec 168 §FR-007 -- when set, the binary halts before emission if
    /// no signer is provided. Required for tenant-emit runs.
    #[arg(long, default_value_t = false)]
    tenant_mode: bool,

    /// Spec 168 §FR-003 -- principal identifier (typically a Rauthy JWT
    /// subject for human-driven tenant runs).
    #[arg(long)]
    signer_subject: Option<String>,

    /// Spec 168 §FR-003 -- system that attested the subject (e.g.
    /// `rauthy@<tenant-org>` or `github-actions@<repo>`).
    #[arg(long)]
    signer_identity_provider: Option<String>,

    /// Spec 168 §FR-003 -- optional run-scoped session id.
    #[arg(long)]
    signer_session_id: Option<String>,

    /// Spec 168 §2.4 -- comma-separated stage IDs to record in the
    /// certificate, in the given order. Use `auto` to trigger
    /// filesystem discovery (every subdirectory of `<run-dir>`,
    /// lexicographic). Omit to use OAP's default s0..s5 list.
    #[arg(long)]
    stage_ids: Option<String>,

    /// Spec 220 FR-003: refuse the ephemeral signing-key fallback. When set,
    /// the binary exits non-zero (code 2) if signing material resolves to an
    /// ephemeral key rather than an operator-supplied one (OAP_SIGNING_KEY /
    /// OAP_SIGNING_KEY_PATH). A production tenant emission must pass this so
    /// it can never silently emit an untrusted certificate.
    #[arg(long, default_value_t = false)]
    require_operator_key: bool,

    /// Spec 220 FR-007: path to a spec-spine CorpusAttestation JSON to bind
    /// into the certificate by hash (read, never recompute). Falls back to
    /// the OAP_CORPUS_ATTESTATION_PATH env var. Applied on the tenant
    /// (signer) build path.
    #[arg(long)]
    corpus_attestation: Option<PathBuf>,

    /// Refuse to emit unless a corpus binding is actually applied. When set,
    /// the binary exits 2 if no corpus attestation resolved (missing,
    /// unreadable, or malformed) or if there is no signer to bind it onto,
    /// so a production emission can never silently drop the binding behind a
    /// warning. Mirrors `--require-operator-key`.
    #[arg(long, default_value_t = false)]
    require_corpus_binding: bool,

    /// Spec 203 FR-003: produced-app root whose `.factory/sbom.cdx.json` and
    /// `.factory/audit.json` are bound into the certificate by content hash
    /// (read, never recompute). Falls back to the OAP_SBOM_DIR env var.
    /// Applied on the tenant (signer) build path. The BOM tool version is
    /// read from the BOM's own `metadata.tools`. When unset (or a file is
    /// unreadable) the cert is emitted unbound, exactly like the corpus
    /// binding.
    #[arg(long)]
    sbom_dir: Option<PathBuf>,

    /// Refuse to emit unless an SBOM artifact binding is actually applied.
    /// When set, the binary exits 2 if the BOM/audit artifacts did not resolve
    /// or if there is no signer to bind them onto. Mirrors
    /// `--require-corpus-binding`.
    #[arg(long, default_value_t = false)]
    require_sbom_binding: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::BuildCertificate(args) => build_certificate_cmd(args),
    }
}

fn build_certificate_cmd(cli: BuildCertificateArgs) -> ExitCode {
    if !cli.run_dir.is_dir() {
        eprintln!(
            "error: run directory does not exist: {}",
            cli.run_dir.display()
        );
        return ExitCode::from(2);
    }

    let pipeline_id = cli
        .run_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let mut state = FactoryPipelineState::new(&pipeline_id, &cli.adapter);

    // Lift the build-spec hash from disk if the frozen artifact is present.
    let build_spec_path = cli
        .run_dir
        .join("s5-ui-specification")
        .join("build-spec.yaml");
    if build_spec_path.is_file() {
        match sha256_file(&build_spec_path) {
            Ok(hash) => state.transition_to_scaffolding(hash),
            Err(e) => eprintln!(
                "warning: could not hash build-spec at {}: {e}",
                build_spec_path.display()
            ),
        }
    }

    let requirements_hash = if !cli.business_docs.is_empty() {
        let mut hasher = Sha256::new();
        for p in &cli.business_docs {
            match std::fs::read(p) {
                Ok(bytes) => {
                    // Domain separation: length-prefix each document so shifting
                    // bytes across a file boundary cannot collide (e.g. ["ab","c"]
                    // and ["a","bc"] hash differently).
                    hasher.update((bytes.len() as u64).to_le_bytes());
                    hasher.update(&bytes);
                }
                Err(e) => {
                    // A requirements hash computed over partial content is worse
                    // than none: fail loudly rather than silently under-hash.
                    eprintln!(
                        "error: could not read --business-docs file {}: {e}",
                        p.display()
                    );
                    return ExitCode::from(2);
                }
            }
        }
        format!("{:x}", hasher.finalize())
    } else {
        let hash = cli.requirements_hash.clone().unwrap_or_default();
        if hash.is_empty() {
            eprintln!(
                "warning: neither --requirements-hash nor --business-docs supplied; \
                 intent.requirementsHash will be empty"
            );
        }
        hash
    };

    let signer = match build_signer(&cli) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    let has_signer = signer.is_some();

    if cli.tenant_mode && signer.is_none() {
        eprintln!(
            "error: --tenant-mode requires --signer-subject and \
             --signer-identity-provider (spec 168 FR-007: anonymous \
             signing forbidden -- a run with no identifiable signer halts \
             before emitting)"
        );
        return ExitCode::from(2);
    }

    // Resolve the signing material up front so a malformed operator-supplied
    // key is a clean configuration error (exit 2), not a panic (spec 220
    // FR-003). The build path re-resolves the same operator key from the
    // environment; only the ephemeral fallback differs per resolution, and the
    // certificate uses the build path's key. The resolved trust posture (kind)
    // is stable across both resolutions since the environment does not change.
    let signing_kind = match try_resolve_signing_material() {
        Ok((_key, attestation)) => attestation.kind,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    // Spec 220 FR-003: a production tenant emission must use an operator key.
    // Checked before anything is built or written, so exiting here emits nothing.
    if cli.require_operator_key && matches!(signing_kind, SigningAttestationKind::Ephemeral) {
        eprintln!(
            "error: --require-operator-key was set but the signing material \
             resolved to an ephemeral key (spec 220 FR-003). A production \
             tenant emission must supply an operator key via OAP_SIGNING_KEY \
             or OAP_SIGNING_KEY_PATH; refusing to emit an untrusted certificate."
        );
        return ExitCode::from(2);
    }

    let corpus_binding = resolve_corpus_binding(&cli);
    let sbom_binding = resolve_sbom_binding(&cli);
    let posture_binding = resolve_posture_binding(&cli);

    // A binding is only applied on the signer build path, so requiring one also
    // requires a signer. Fail before emitting so a production cert can never
    // silently ship without the binding it was told to carry.
    if cli.require_corpus_binding && (corpus_binding.is_none() || !has_signer) {
        eprintln!(
            "error: --require-corpus-binding was set but no corpus binding could \
             be applied (a corpus attestation must resolve AND a signer must be \
             present); refusing to emit a certificate without the required \
             corpus binding."
        );
        return ExitCode::from(2);
    }
    if cli.require_sbom_binding && (sbom_binding.is_none() || !has_signer) {
        eprintln!(
            "error: --require-sbom-binding was set but no SBOM artifact binding \
             could be applied (the BOM/audit artifacts must resolve AND a signer \
             must be present); refusing to emit a certificate without the \
             required SBOM binding."
        );
        return ExitCode::from(2);
    }

    let cert = match build_certificate(
        &cli,
        &state,
        &requirements_hash,
        signer,
        corpus_binding,
        sbom_binding,
        posture_binding,
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    // The certificate is written to the exact `--out` path (including its file
    // name) when supplied, else to `<run-dir>/governance-certificate.json`.
    let cert_path = match cli.out.as_ref() {
        Some(p) => p.clone(),
        None => cli.run_dir.join("governance-certificate.json"),
    };

    if let Err(e) = persist_certificate_at(&cert, &cert_path) {
        eprintln!(
            "error: failed to persist certificate at {}: {e}",
            cert_path.display()
        );
        return ExitCode::from(1);
    }

    println!(
        "governance certificate written: {} (status={:?}, stages={}, hash={}...)",
        cert_path.display(),
        cert.status,
        cert.stages.len(),
        &cert.certificate_hash[..16]
    );

    let repo_root = cli
        .repo_root
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    let warnings = validate_spec_id_resolution(&cert, &repo_root);
    match write_validation_warnings(&warnings, &cert_path) {
        Ok(Some(p)) => eprintln!(
            "validation warnings written: {} ({} warning(s))",
            p.display(),
            warnings.len()
        ),
        Ok(None) => {}
        Err(e) => eprintln!(
            "warning: failed to write validation warnings next to {}: {e}",
            cert_path.display()
        ),
    }

    ExitCode::SUCCESS
}

/// Env var carrying the path to a spec-spine `CorpusAttestation` JSON
/// (spec 220 FR-007, mirroring factory_run.rs / spec 218 FR-002). When set
/// (or `--corpus-attestation` is passed), the cert is bound to the
/// attestation's hash; when unset, the cert is emitted unbound.
const ENV_CORPUS_ATTESTATION_PATH: &str = "OAP_CORPUS_ATTESTATION_PATH";

/// Spec 220 FR-007: resolve the corpus binding from `--corpus-attestation`
/// or the `OAP_CORPUS_ATTESTATION_PATH` env var. Read, never recompute: the
/// supplied `CorpusAttestation` payload is hashed via the public
/// `spec_spine_core::attest::attestation_hash` reader seam; the emitter never
/// compiles or re-attests the corpus. Returns `None` (cert stays unbound)
/// when no path is given or the artifact is unreadable / malformed; failures
/// warn but never block emission (an unbound cert beats no cert).
fn resolve_corpus_binding(cli: &BuildCertificateArgs) -> Option<CorpusBinding> {
    let path: String = cli
        .corpus_attestation
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .or_else(|| std::env::var(ENV_CORPUS_ATTESTATION_PATH).ok())?;
    let raw = match std::fs::read_to_string(&path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("warning: corpus attestation {path} unreadable: {e} (cert unbound)");
            return None;
        }
    };
    let attestation: spec_spine_types::attest::CorpusAttestation = match serde_json::from_str(&raw)
    {
        Ok(a) => a,
        Err(e) => {
            eprintln!("warning: {path} is not a CorpusAttestation: {e} (cert unbound)");
            return None;
        }
    };
    match spec_spine_core::attest::attestation_hash(&attestation) {
        Ok(hash) => Some(CorpusBinding {
            corpus_attestation_hash: hash,
            spec_spine_version: attestation.tool.version,
        }),
        Err(e) => {
            eprintln!("warning: attestation_hash failed: {e} (cert unbound)");
            None
        }
    }
}

/// Env var carrying the produced-app root whose `.factory/sbom.cdx.json` and
/// `.factory/audit.json` are bound into the certificate (spec 203 FR-003).
/// Alternative to `--sbom-dir`.
const ENV_SBOM_DIR: &str = "OAP_SBOM_DIR";

/// Spec 203 FR-003: resolve the SBOM artifact binding from `--sbom-dir` or the
/// `OAP_SBOM_DIR` env var. Read, never recompute: the produced BOM and audit
/// artifacts are hashed as bytes; the emitter never regenerates the BOM. The
/// BOM tool version is read from the BOM's own `metadata.tools`. Returns `None`
/// (cert stays unbound) when no dir is given or either artifact is unreadable;
/// failures warn but never block emission (an unbound cert beats no cert),
/// mirroring `resolve_corpus_binding`.
fn resolve_sbom_binding(cli: &BuildCertificateArgs) -> Option<SbomArtifactBinding> {
    let root: PathBuf = cli
        .sbom_dir
        .clone()
        .or_else(|| std::env::var(ENV_SBOM_DIR).ok().map(PathBuf::from))?;
    let bom_path = root.join(SBOM_BOM_RELPATH);
    let audit_path = root.join(SBOM_AUDIT_RELPATH);
    let bom_bytes = match std::fs::read(&bom_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "warning: SBOM {} unreadable: {e} (cert unbound)",
                bom_path.display()
            );
            return None;
        }
    };
    let audit_hash = match sha256_file(&audit_path) {
        Ok(h) => h,
        Err(e) => {
            eprintln!(
                "warning: audit artifact {} unreadable: {e} (cert unbound)",
                audit_path.display()
            );
            return None;
        }
    };
    Some(SbomArtifactBinding {
        bom_hash: sha256_bytes(&bom_bytes),
        audit_hash,
        bom_tool_version: read_bom_tool_version(&bom_bytes),
    })
}

/// Spec 210 FR-002: resolve the agentic-posture binding from the frozen Build
/// Spec at `<run-dir>/s5-ui-specification/build-spec.yaml` (read, never
/// recompute). Mirrors OAP's `build_certificate.rs::resolve_posture_binding`.
/// Returns:
/// - `None` when no Build Spec is present or it does not parse (the posture is
///   left UNSTATED on the cert, never silently equivalent to authored `none`).
/// - `Some(none/defaulted)` when the Build Spec is read but omits
///   `agentic_posture` ("nobody asked").
/// - `Some(authored)` when the Build Spec declares a posture.
///
/// Bound on the tenant (signer) build path, mirroring `resolve_sbom_binding`:
/// the posture is a property of the produced application, whose trust artifact
/// is the tenant certificate. The emitter reads verbatim and never validates
/// well-formedness; the verifier (tenant-tail) is authoritative on consistency.
fn resolve_posture_binding(cli: &BuildCertificateArgs) -> Option<AgenticPostureBinding> {
    let build_spec_path = cli
        .run_dir
        .join("s5-ui-specification")
        .join("build-spec.yaml");
    let raw = std::fs::read_to_string(&build_spec_path).ok()?;
    let projection: BuildSpecPostureProjection = match serde_yaml::from_str(&raw) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "warning: Build Spec at {} did not parse for agentic_posture: {e} \
                 (posture unstated)",
                build_spec_path.display()
            );
            return None;
        }
    };
    Some(AgenticPostureBinding::from_build_spec(
        projection.agentic_posture.as_ref(),
    ))
}

/// Read the BOM generator's version from a CycloneDX BOM's `metadata.tools`,
/// tolerating both the 1.5+ `tools.components[]` shape and the legacy `tools[]`
/// array. Prefers a tool whose name contains "cyclonedx"; falls back to the
/// first entry carrying a version, then to "unknown". Reading one field for
/// provenance does not recompute the BOM: the byte hash above still spans the
/// full file.
fn read_bom_tool_version(bom_bytes: &[u8]) -> String {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(bom_bytes) else {
        return "unknown".to_string();
    };
    let tools = &v["metadata"]["tools"];
    let entries = tools["components"].as_array().or_else(|| tools.as_array());
    if let Some(arr) = entries {
        let pick = arr
            .iter()
            .find(|c| {
                c["name"]
                    .as_str()
                    .is_some_and(|n| n.to_ascii_lowercase().contains("cyclonedx"))
            })
            .or_else(|| arr.iter().find(|c| c["version"].is_string()));
        if let Some(ver) = pick.and_then(|c| c["version"].as_str()) {
            return ver.to_string();
        }
    }
    "unknown".to_string()
}

/// Parse the signer flags, returning `Ok(None)` when no signer was supplied,
/// `Ok(Some(_))` when fully populated, and an error string when partial.
fn build_signer(cli: &BuildCertificateArgs) -> Result<Option<Signer>, String> {
    match (
        cli.signer_subject.as_deref(),
        cli.signer_identity_provider.as_deref(),
    ) {
        (None, None) => Ok(None),
        (Some(_), None) => Err("--signer-subject requires --signer-identity-provider \
             (spec 168 FR-003)"
            .into()),
        (None, Some(_)) => Err("--signer-identity-provider requires --signer-subject \
             (spec 168 FR-003)"
            .into()),
        (Some(subject), Some(provider)) => {
            let mut s = Signer::new(subject, provider).map_err(|e| e.to_string())?;
            if let Some(sid) = cli.signer_session_id.as_deref() {
                s = s.with_session_id(sid);
            }
            Ok(Some(s))
        }
    }
}

/// Build the certificate, dispatching on stage_ids and tenant_mode flags.
fn build_certificate(
    cli: &BuildCertificateArgs,
    state: &FactoryPipelineState,
    requirements_hash: &str,
    signer: Option<Signer>,
    corpus_binding: Option<CorpusBinding>,
    sbom_binding: Option<SbomArtifactBinding>,
    posture_binding: Option<AgenticPostureBinding>,
) -> Result<GovernanceCertificate, String> {
    if signer.is_none() && corpus_binding.is_some() {
        eprintln!(
            "warning: a corpus attestation was supplied but no signer; corpus \
             binding is applied only on the tenant (signer) build path (spec \
             220 FR-007). Emitting without corpus binding."
        );
    }
    if signer.is_none() && sbom_binding.is_some() {
        eprintln!(
            "warning: an SBOM directory was supplied but no signer; the SBOM \
             binding is applied only on the tenant (signer) build path (spec \
             203 FR-003). Emitting without SBOM binding."
        );
    }

    // Split the comma list, dropping empty entries so `--stage-ids ""` or a
    // stray comma (`a,,b`) never yields an empty stage id (which would resolve
    // to the run dir itself and record top-level files under an empty stage_id).
    let stage_ids_owned: Option<Vec<String>> = cli
        .stage_ids
        .as_deref()
        .filter(|s| !s.eq_ignore_ascii_case("auto"))
        .map(|s| {
            s.split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect()
        });

    // No signer + no custom stages -> keep the existing fast path.
    if signer.is_none() && cli.stage_ids.is_none() {
        return Ok(generate_certificate_with_stage_ids(
            state,
            requirements_hash,
            &cli.run_dir,
            None,
            OAP_STAGE_IDS,
        ));
    }

    // Build via the builder so we can attach signer + tenant stage IDs.
    let stage_ids_slice: Vec<&str> = match stage_ids_owned.as_ref() {
        Some(v) => v.iter().map(|s| s.as_str()).collect(),
        // `--stage-ids auto` or no explicit list with a signer attached --
        // default to filesystem discovery for tenant mode so we don't
        // silently bake OAP's s0..s5 list into a tenant certificate.
        None if cli.tenant_mode || cli.stage_ids.is_some() => Vec::new(),
        None => OAP_STAGE_IDS.to_vec(),
    };

    let cert = generate_certificate_with_stage_ids(
        state,
        requirements_hash,
        &cli.run_dir,
        None,
        &stage_ids_slice,
    );

    if let Some(signer) = signer {
        // Re-bake the certificate via the builder so the signer is
        // present in the canonical content the hash + signature attest.
        let intent = IntentRecord {
            requirements_hash: requirements_hash.to_string(),
            spec_id: None,
            spec_hash: None,
        };
        let proof_chain = ProofChainSummary {
            record_count: 0,
            first_record_hash: None,
            last_record_hash: None,
            chain_integrity: ChainIntegrity::Empty,
        };
        let verification = VerificationRecord {
            compile: VerificationOutcome::Skipped,
            test: VerificationOutcome::Skipped,
            lint: VerificationOutcome::Skipped,
            typecheck: VerificationOutcome::Skipped,
            security_scan: VerificationOutcome::Skipped,
        };
        let mut builder = CertificateBuilder::new(&state.pipeline_id, intent)
            .build_spec_hash(state.build_spec_hash.clone().unwrap_or_default())
            .stages(cert.stages.clone())
            .verification(verification)
            .proof_chain(proof_chain)
            .signer(signer);
        // Spec 220 FR-007: bind the tenant's corpus attestation (read, never
        // recompute) when one was supplied.
        if let Some(cb) = corpus_binding {
            builder = builder.corpus_binding(cb.corpus_attestation_hash, cb.spec_spine_version);
        }
        // Spec 203 FR-003: bind the produced app's SBOM + audit artifact hashes
        // (read, never recompute) when a --sbom-dir was supplied.
        if let Some(sb) = sbom_binding {
            builder =
                builder.sbom_artifact_binding(sb.bom_hash, sb.audit_hash, sb.bom_tool_version);
        }
        // Spec 210 FR-002: bind the produced app's declared agentic posture,
        // read off the frozen Build Spec (read, never recompute). Present
        // whenever a Build Spec was read: an omitted `agentic_posture` binds
        // `none`/`defaulted: true` (visibly defaulted, never silently equivalent
        // to authored `none`).
        if let Some(pb) = posture_binding {
            builder = builder.agentic_posture_binding(pb);
        }
        let signed = builder
            .build_tenant()
            .map_err(|e: CertificateBuildError| e.to_string())?;
        return Ok(signed);
    }

    Ok(cert)
}

#[cfg(test)]
mod tests {
    /// Spec 218 FR-002 durability guard (mirrored from OAP). clippy only WARNS
    /// (never errors) on a `disallowed-methods` path that stops resolving, so a
    /// future spec-spine rename would silently make the attestation-emit ban
    /// inert; the emit CLI never references those functions, so nothing else
    /// would catch it. These imports fail to COMPILE if any banned path stops
    /// resolving, forcing `clippy.toml` to be updated in lockstep. Importing
    /// (not calling) does not trip `disallowed_methods`, which is call-site only.
    #[test]
    fn banned_attestation_emit_paths_still_resolve() {
        #[allow(unused_imports)]
        use spec_spine_core::attest::{attest, verify_recompute};
        #[allow(unused_imports)]
        use spec_spine_core::{attest_json, verify_attestation_json};
    }
}
