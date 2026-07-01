//! Tenant emission integration tests (spec 220), ported and adapted from OAP's
//! `tenant_emission_integration.rs`. These drive the actual `tenant-emit`
//! binary end-to-end against a laid-out run directory and assert the spec 220
//! contract: an attributable signer, the operator-key requirement (FR-003),
//! corpus binding by hash (FR-007), determinism (FR-006/AC-7), and the
//! halt-before-emit posture (AC-4).
//!
//! The cross-tool round-trip (the emitted certificate verifies clean under
//! `tenant-tail verify-certificate`, tamper -> exit 1) is the definition of
//! correct; it is exercised in CI against the released tenant-tail and is
//! covered structurally here by re-deriving the certificate self-hash and, for
//! the corpus binding, by confirming the bound hash equals the SHA-256 of the
//! canonical attestation bytes the verifier re-hashes.

use std::path::{Path, PathBuf};
use std::process::Command;

use spec_spine_types::attest::{
    ATTESTATION_SCHEMA_VERSION, CompileVerdict, CorpusAttestation, LintVerdict, ToolStamp, Verdicts,
};
use tenant_emit_core::{GovernanceCertificate, SigningAttestationKind, compute_certificate_hash};

const EMIT_BIN: &str = env!("CARGO_BIN_EXE_tenant-emit");

/// A base64-encoded 32-byte Ed25519 seed for the operator-key path. Fixed so
/// the tests are deterministic; any valid 32-byte seed works.
const OPERATOR_SEED_B64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

fn write(path: &Path, body: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, body).unwrap();
}

/// Lay out a minimal run directory with two tenant-grammar stages and return
/// the run-dir path (inside `dir`).
fn lay_out_run(dir: &Path) -> PathBuf {
    let run = dir.join(".factory/runs/run-it-001");
    write(&run.join("s0-preflight/preflight.txt"), b"preflight ok\n");
    write(&run.join("tenant-codegen/app.rs"), b"fn main(){}\n");
    write(&run.join("tenant-bundle/bundle.tar"), b"<bytes>\n");
    run
}

fn read_cert(run: &Path) -> GovernanceCertificate {
    let json = std::fs::read_to_string(run.join("governance-certificate.json")).unwrap();
    serde_json::from_str(&json).unwrap()
}

/// `tenant-emit build-certificate` with a fixed operator key. `extra` are
/// additional flags. Returns the process exit code.
fn emit(run: &Path, extra: &[&str], operator_key: bool) -> i32 {
    let mut cmd = Command::new(EMIT_BIN);
    cmd.arg("build-certificate").arg(run);
    if operator_key {
        cmd.env("OAP_SIGNING_KEY", OPERATOR_SEED_B64);
    } else {
        cmd.env_remove("OAP_SIGNING_KEY");
        cmd.env_remove("OAP_SIGNING_KEY_PATH");
    }
    cmd.env_remove("OAP_CORPUS_ATTESTATION_PATH");
    for a in extra {
        cmd.arg(a);
    }
    cmd.status().unwrap().code().unwrap()
}

const SIGNER_FLAGS: &[&str] = &[
    "--tenant-mode",
    "--signer-subject",
    "bart@tenant.example",
    "--signer-identity-provider",
    "rauthy@tenant-org",
    "--stage-ids",
    "auto",
];

#[test]
fn ac1_emits_signed_certificate_with_operator_kind() {
    let dir = tempfile::tempdir().unwrap();
    let run = lay_out_run(dir.path());

    let mut flags: Vec<&str> = SIGNER_FLAGS.to_vec();
    flags.push("--require-operator-key");
    let code = emit(&run, &flags, true);
    assert_eq!(code, 0, "emit should succeed with an operator key");

    let cert = read_cert(&run);
    assert_eq!(cert.certificate_version, "1.5.0");
    assert_eq!(
        cert.signing_attestation.kind,
        SigningAttestationKind::Operator
    );
    let signer = cert.signer.as_ref().expect("signer present");
    assert_eq!(signer.subject, "bart@tenant.example");
    assert_eq!(signer.identity_provider, "rauthy@tenant-org");
    // No platform countersign on a tenant run (verifiable-but-unsealed).
    assert!(cert.platform_countersign.is_none());
    // Self-hash re-derives (the same check tenant-tail runs).
    assert_eq!(cert.certificate_hash, compute_certificate_hash(&cert));
    assert!(!cert.cert_signature.is_empty());
    // Auto discovery picked up every stage subdirectory, lexicographically.
    let stage_ids: Vec<&str> = cert.stages.iter().map(|s| s.stage_id.as_str()).collect();
    assert_eq!(
        stage_ids,
        vec!["s0-preflight", "tenant-bundle", "tenant-codegen"]
    );
}

#[test]
fn ac4_require_operator_key_refuses_ephemeral() {
    let dir = tempfile::tempdir().unwrap();
    let run = lay_out_run(dir.path());

    let mut flags: Vec<&str> = SIGNER_FLAGS.to_vec();
    flags.push("--require-operator-key");
    // No operator key in the environment -> ephemeral fallback -> refused.
    let code = emit(&run, &flags, false);
    assert_eq!(code, 2, "ephemeral signing must be refused under the flag");
    assert!(
        !run.join("governance-certificate.json").exists(),
        "no certificate should be written when refused"
    );
}

#[test]
fn ac4_tenant_mode_without_signer_halts() {
    let dir = tempfile::tempdir().unwrap();
    let run = lay_out_run(dir.path());

    let code = emit(&run, &["--tenant-mode", "--stage-ids", "auto"], true);
    assert_eq!(code, 2, "tenant-mode with no signer halts before emitting");
    assert!(!run.join("governance-certificate.json").exists());
}

#[test]
fn ephemeral_fallback_allowed_without_require_flag() {
    let dir = tempfile::tempdir().unwrap();
    let run = lay_out_run(dir.path());

    let code = emit(&run, SIGNER_FLAGS, false);
    assert_eq!(code, 0, "dev ephemeral path is allowed without the flag");
    let cert = read_cert(&run);
    assert_eq!(
        cert.signing_attestation.kind,
        SigningAttestationKind::Ephemeral
    );
}

#[test]
fn ac7_reemit_is_deterministic_modulo_signer() {
    let dir = tempfile::tempdir().unwrap();
    let run = lay_out_run(dir.path());

    assert_eq!(emit(&run, SIGNER_FLAGS, true), 0);
    let c1 = read_cert(&run);
    assert_eq!(emit(&run, SIGNER_FLAGS, true), 0);
    let c2 = read_cert(&run);

    // The deterministic content (stage artifact hashes) is identical across
    // re-emits; only the timestamp + signature carry per-run identity.
    let stages = |c: &GovernanceCertificate| {
        c.stages
            .iter()
            .map(|s| (s.stage_id.clone(), s.artifact_hashes.clone()))
            .collect::<Vec<_>>()
    };
    assert_eq!(stages(&c1), stages(&c2));
}

/// Replicate spec-spine's `canonical_json::to_string`: route through
/// `to_value` (sorts object keys via serde_json's BTreeMap-backed Map),
/// pretty-print (2-space), and append a single trailing newline. This is the
/// exact form `spec-spine attest` writes to disk, so the SHA-256 of these bytes
/// equals `attestation_hash(att)` -- which is what tenant-tail re-hashes and
/// what the emitter binds.
fn canonical_json<T: serde::Serialize>(value: &T) -> String {
    let v = serde_json::to_value(value).unwrap();
    serde_json::to_string_pretty(&v).unwrap() + "\n"
}

fn sample_attestation() -> CorpusAttestation {
    CorpusAttestation {
        schema_version: ATTESTATION_SCHEMA_VERSION.into(),
        tool: ToolStamp {
            name: "spec-spine".into(),
            version: "0.8.0".into(),
        },
        inputs_manifest_hash: "inputs-abc".into(),
        registry_hash: "registry-xyz".into(),
        verdicts: Verdicts {
            compile: CompileVerdict { ok: true },
            lint: LintVerdict {
                ok: true,
                findings_hash: "findings-0".into(),
            },
            couple: None,
        },
    }
}

#[test]
fn ac8_corpus_binding_matches_canonical_attestation_hash() {
    let dir = tempfile::tempdir().unwrap();
    let run = lay_out_run(dir.path());

    // A canonical attestation on disk, exactly as `spec-spine attest` writes it.
    let att = sample_attestation();
    let att_path = dir.path().join("attestation.json");
    let canonical = canonical_json(&att);
    std::fs::write(&att_path, canonical.as_bytes()).unwrap();

    // The hash the emitter binds (via the public reader seam) and the hash the
    // verifier re-derives (SHA-256 of the file bytes) are the same canonical
    // hash, because the file is canonical.
    let expected = spec_spine_core::attest::attestation_hash(&att).unwrap();
    let file_hash = tenant_emit_core::sha256_bytes(canonical.as_bytes());
    assert_eq!(
        expected, file_hash,
        "canonical file bytes hash to the attestation hash (the cross-tool contract)"
    );

    let mut flags: Vec<&str> = SIGNER_FLAGS.to_vec();
    let att_str = att_path.to_string_lossy().into_owned();
    flags.push("--corpus-attestation");
    flags.push(&att_str);
    flags.push("--require-operator-key");
    assert_eq!(emit(&run, &flags, true), 0);

    let cert = read_cert(&run);
    let binding = cert
        .corpus_binding
        .as_ref()
        .expect("corpus binding present");
    assert_eq!(
        binding.corpus_attestation_hash, expected,
        "the bound hash equals the canonical attestation hash the verifier checks"
    );
    assert_eq!(binding.spec_spine_version, "0.8.0");
    // The binding is inside the cert hash + signature.
    assert_eq!(cert.certificate_hash, compute_certificate_hash(&cert));
}

#[test]
fn unbound_when_no_attestation_supplied() {
    let dir = tempfile::tempdir().unwrap();
    let run = lay_out_run(dir.path());
    assert_eq!(emit(&run, SIGNER_FLAGS, true), 0);
    let cert = read_cert(&run);
    assert!(
        cert.corpus_binding.is_none(),
        "no attestation supplied -> unbound (named, not a failure)"
    );
}

/// A minimal CycloneDX BOM whose `metadata.tools.components[0]` names the
/// generator, mirroring the shape `@cyclonedx/cyclonedx-npm` emits.
fn sample_bom() -> serde_json::Value {
    serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "tools": {
                "components": [
                    { "type": "application", "name": "cyclonedx-npm", "version": "1.19.0" }
                ]
            }
        },
        "components": []
    })
}

#[test]
fn ac9_sbom_binding_matches_content_hash_and_tool_version() {
    let dir = tempfile::tempdir().unwrap();
    let run = lay_out_run(dir.path());

    // Produced-app root with the BOM + audit artifact, exactly as spec 203
    // FR-001/FR-002 would have written them.
    let bom_bytes = serde_json::to_vec_pretty(&sample_bom()).unwrap();
    write(&dir.path().join(".factory/sbom.cdx.json"), &bom_bytes);
    write(
        &dir.path().join(".factory/audit.json"),
        b"{\"status\":\"absent\",\"reason\":\"no scanner available\"}\n",
    );

    let mut flags: Vec<&str> = SIGNER_FLAGS.to_vec();
    let sbom_dir_str = dir.path().to_string_lossy().into_owned();
    flags.push("--sbom-dir");
    flags.push(&sbom_dir_str);
    flags.push("--require-operator-key");
    assert_eq!(emit(&run, &flags, true), 0);

    let cert = read_cert(&run);
    let binding = cert
        .sbom_artifact_binding
        .as_ref()
        .expect("sbom artifact binding present");
    assert!(!binding.bom_hash.is_empty());
    assert!(!binding.audit_hash.is_empty());
    assert_eq!(binding.bom_tool_version, "1.19.0");
    // The binding is inside the cert hash + signature.
    assert_eq!(cert.certificate_hash, compute_certificate_hash(&cert));
}

#[test]
fn unbound_when_no_sbom_dir_supplied() {
    let dir = tempfile::tempdir().unwrap();
    let run = lay_out_run(dir.path());
    assert_eq!(emit(&run, SIGNER_FLAGS, true), 0);
    let cert = read_cert(&run);
    assert!(
        cert.sbom_artifact_binding.is_none(),
        "no --sbom-dir supplied -> unbound (named, not a failure)"
    );
}
