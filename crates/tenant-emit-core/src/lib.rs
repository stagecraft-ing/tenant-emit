//! tenant-emit-core: the emit engine.
//!
//! The certificate builder, Ed25519 signing-key resolution, run-directory
//! artifact scan, content-binding hash + signature, and persistence, extracted
//! standalone from OAP and kept in behavior parity with its in-tree counterpart,
//! relicensed Apache-2.0 from AGPL-3.0 by the sole copyright holder (see NOTICE).
//!
//! The verifier is excluded by construction: no signature re-check, no artifact
//! re-derivation, no corpus-binding adjudication. tenant-emit produces a
//! certificate the factory's verifier (tenant-tail) then re-checks; it never
//! verifies one of its own. The corpus binding (spec 220 FR-007) is read, never
//! recomputed: the builder is GIVEN a hash the CLI produced via the public
//! reader seam `spec_spine_core::attest::attestation_hash`.

pub mod certificate;

// Emit engine surface, re-exported at the crate root for the CLI verb and tests.
pub use certificate::{
    CapsuleBinding, CertificateBuildError, CertificateBuilder, ENV_SIGNING_KEY,
    ENV_SIGNING_KEY_PATH, OAP_STAGE_IDS, ValidationWarning, compute_certificate_hash,
    compute_certificate_signature, generate_certificate, generate_certificate_bound,
    generate_certificate_with_stage_ids, persist_certificate, require_spec_id_resolution_enabled,
    resolve_signing_material, sha256_bytes, sha256_file, validate_spec_id_resolution,
    write_validation_warnings,
};

// Emit-surface DTOs, re-exported so the CLI consumes a flat surface (mirroring
// OAP's `factory_engine::{..}` re-export shape).
pub use tenant_emit_types::{
    ApprovalRecord, BuildSpecRecord, CERTIFICATE_VERSION, CertificateStatus, ChainIntegrity,
    ComplianceMapping, ComplianceRecord, ConsumedOverride, CorpusBinding, FactoryPhase,
    FactoryPipelineState, GateResultRecord, GovernanceCertificate, IntentRecord,
    InterStageChainRecord, InterStageManifest, ManifestSigner, PlatformCountersign,
    ProofChainSummary, RunKeyChain, SandboxExecutionRecord, SandboxResourcePeak, Signer,
    SignerError, SigningAttestation, SigningAttestationKind, StageKeyRecord, StageOutcome,
    StageRecord, VerificationOutcome, VerificationRecord,
};
