//! Build-Spec source types: the minimal parse-side mirror of the produced
//! application's frozen Build Spec (`s5-ui-specification/build-spec.yaml`).
//!
//! tenant-emit reads exactly one field off the Build Spec -- `agentic_posture`
//! (spec 210 FR-002) -- so this module carries only that subtree, not the full
//! Build Spec contract. The shapes mirror OAP's
//! `factory_contracts::build_spec::{AgenticPosture, PostureLevel, AgenticSurface,
//! SurfaceKind}` byte-for-byte (kebab-case enum wire strings, identical field
//! names) so a real produced-app Build Spec parses identically to how OAP's
//! in-tree emitter parses it. tenant-emit is Apache-2.0 and does not depend on
//! OAP's AGPL `factory-contracts`; this local mirror is the substitute.
//!
//! The certificate binding these produce is [`crate::certificate::AgenticPostureBinding`]
//! via [`crate::certificate::AgenticPostureBinding::from_build_spec`].

use serde::{Deserialize, Serialize};

/// The `agentic_posture` block of a produced application's Build Spec
/// (spec 210 FR-001).
///
/// Least Agency applied to outputs: a produced app's autonomy is a stated
/// choice, never a silent acquisition. Absent from a Build Spec means `none`,
/// and the governance certificate records that default AS defaulted (spec 210
/// FR-002), so an auditor can tell "authored none" (someone decided) from
/// "defaulted none" (nobody asked).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgenticPosture {
    /// Declared agentic level.
    pub posture: PostureLevel,
    /// Enumerated agentic surfaces. Non-empty for `declared`/`governed`, empty
    /// for `none` (well-formedness is the verifier's concern; the emitter reads
    /// verbatim, never recompute).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub surfaces: Vec<AgenticSurface>,
}

/// Declared agentic level of a produced application (spec 210 FR-001).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PostureLevel {
    /// No model calls, agent loops, tool surfaces, or persistent agent memory.
    None,
    /// Agentic surfaces exist and are enumerated.
    Declared,
    /// Declared, plus every surface carries a governance envelope.
    Governed,
}

impl PostureLevel {
    /// Canonical wire string (matches the schema enum and serde form).
    pub fn as_str(&self) -> &'static str {
        match self {
            PostureLevel::None => "none",
            PostureLevel::Declared => "declared",
            PostureLevel::Governed => "governed",
        }
    }
}

/// One enumerated agentic surface (spec 210 FR-001).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgenticSurface {
    pub kind: SurfaceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Inline governance envelope (the spec 198 schema, reused at application
    /// level). Required for every surface under `governed`; carried as a raw
    /// value so the certificate binding can bind it verbatim (read, never
    /// recompute). Shape validation is the verifier's concern (tenant-tail).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_envelope: Option<serde_json::Value>,
}

/// Kind of an agentic surface (spec 210 FR-001).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SurfaceKind {
    ModelApi,
    ToolSurface,
    MemoryPersistence,
    HumanApprovalPoint,
}

impl SurfaceKind {
    /// Canonical wire string (matches the schema enum and serde form).
    pub fn as_str(&self) -> &'static str {
        match self {
            SurfaceKind::ModelApi => "model-api",
            SurfaceKind::ToolSurface => "tool-surface",
            SurfaceKind::MemoryPersistence => "memory-persistence",
            SurfaceKind::HumanApprovalPoint => "human-approval-point",
        }
    }
}

/// The minimal Build Spec projection tenant-emit deserialises: only the
/// `agentic_posture` field is read; every other Build Spec field is ignored
/// (serde drops unknown fields), so a full produced-app Build Spec parses into
/// this without carrying the whole contract.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct BuildSpecPostureProjection {
    #[serde(default)]
    pub agentic_posture: Option<AgenticPosture>,
}
