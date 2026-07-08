//! tenant-emit-types: the emit-surface DTOs.
//!
//! The data types the emitter builds, signs, and serialises into a
//! `governance-certificate.json`, extracted standalone from OAP and kept in
//! behavior parity with their in-tree counterparts, relicensed Apache-2.0 from
//! AGPL-3.0 by the sole copyright holder (see NOTICE):
//!
//!   * `certificate` -- the certificate DTOs (intent, build spec, stages,
//!     verification, proof chain, signer, corpus binding, signing attestation).
//!   * `inter_stage_manifest` -- the signed-handoff carrier types (DTOs only;
//!     the emitter never mints or signs a manifest chain).
//!   * `pipeline_state` -- the minimal run state the post-hoc emitter reads.
//!
//! No crypto, no key handling, no orchestration lives here: this crate is pure
//! serde data. The engine that hashes and signs these types is `tenant-emit-core`.

pub mod build_spec;
pub mod certificate;
pub mod inter_stage_manifest;
pub mod pipeline_state;

pub use build_spec::{AgenticPosture, AgenticSurface, PostureLevel, SurfaceKind};
pub use certificate::{
    AgenticPostureBinding, ApprovalRecord, BuildSpecRecord, CERTIFICATE_VERSION,
    CertAgenticSurface, CertificateStatus, ChainIntegrity, ComplianceMapping, ComplianceRecord,
    ConsumedOverride, CorpusBinding, GateResultRecord, GovernanceCertificate, IntentRecord,
    InterStageChainRecord, PlatformCountersign, ProofChainSummary, SBOM_AUDIT_RELPATH,
    SBOM_BOM_RELPATH, SandboxExecutionRecord, SandboxResourcePeak, SbomArtifactBinding, Signer,
    SignerError, SigningAttestation, SigningAttestationKind, StageOutcome, StageRecord,
    VerificationOutcome, VerificationRecord,
};
pub use inter_stage_manifest::{InterStageManifest, ManifestSigner, RunKeyChain, StageKeyRecord};
pub use pipeline_state::{FactoryPhase, FactoryPipelineState};
