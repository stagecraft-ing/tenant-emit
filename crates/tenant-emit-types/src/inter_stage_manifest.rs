//! Signed inter-stage manifests for the factory-engine two-phase pipeline
//! (spec 170 §2).
//!
//! These are the emit-surface DTOs only, extracted from OAP's
//! `factory-engine/src/inter_stage_manifest.rs` and relicensed Apache-2.0 from
//! AGPL-3.0 by the sole copyright holder (see NOTICE). The post-hoc emitter
//! reconstructs only the artifact-hash stages from a finished run directory; it
//! does not mint keys or sign hand-off manifests, so a tenant certificate
//! carries no inter-stage chain. The signing side (key chains, `sign_manifest`,
//! the handoff session) and the verify side (`verify_manifest`) are both
//! excluded by construction; only the carrier types are kept so the
//! `interStageChain` field of a certificate round-trips through serialization
//! byte-identically to what the verifier (tenant-tail) re-derives.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// JSON shape of an inter-stage manifest (spec 170 §2).
///
/// `signature` is the base64-encoded Ed25519 signature over the canonical
/// JSON of the manifest with `signature` set to empty string. The signing
/// key is the dispatching stage's ephemeral key, derived from the run's
/// root key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InterStageManifest {
    pub run_id: String,
    pub from_stage: String,
    pub to_stage: String,
    pub produced_at: DateTime<Utc>,
    pub artifact_hashes: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, serde_json::Value>,
    pub signer: ManifestSigner,
    pub signature: String,
}

/// Identity of the agent that signed the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ManifestSigner {
    /// Agent identifier (URI). Today this is `factory-engine/stage/<id>`;
    /// future distributed factory may carry a richer identity.
    pub agent_id: String,
    /// Fingerprint of the ephemeral key (SHA-256 of the public-key bytes,
    /// base64-encoded). The receiving stage resolves this against the run's
    /// key chain (§2.1).
    pub ephemeral_key_id: String,
}

/// Per-run key chain: the root verifying key plus the registry of stage
/// ephemeral keys established as the run progresses.
///
/// Persisted under the run directory so receiving stages can resolve a
/// manifest's `ephemeral_key_id` offline (FR-006). The signing keys
/// themselves never appear in the chain -- only verifying material.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RunKeyChain {
    pub run_id: String,
    /// Base64-encoded Ed25519 verifying key (32 bytes). Anchored in the
    /// run's governance certificate at run completion (spec 170 §2.1,
    /// spec 102 FR-007 composition).
    pub root_public_key_b64: String,
    pub stage_keys: BTreeMap<String, StageKeyRecord>,
}

/// One stage's registered ephemeral public key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StageKeyRecord {
    pub stage_id: String,
    /// Base64-encoded Ed25519 verifying key.
    pub ephemeral_public_key_b64: String,
    /// SHA-256 of the verifying-key bytes, base64-encoded. Stable identifier
    /// referenced by `ManifestSigner.ephemeral_key_id`.
    pub key_fingerprint: String,
}
