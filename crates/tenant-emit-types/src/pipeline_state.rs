//! Factory-specific pipeline state, the minimal slice the post-hoc emitter
//! needs.
//!
//! Extracted and trimmed from OAP's `factory-engine/src/pipeline_state.rs` and
//! relicensed Apache-2.0 from AGPL-3.0 by the sole copyright holder (see
//! NOTICE). The post-hoc `build-certificate` path constructs a state, lifts the
//! frozen build-spec hash into it, and reads `pipeline_id` + `build_spec_hash`
//! when assembling the certificate; the live-pipeline scaffolding progress and
//! extraction-summary machinery are not part of emission and are left behind.

use serde::{Deserialize, Serialize};

/// Current phase of a factory pipeline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FactoryPhase {
    /// Process stages (s0-s5): deriving the Build Spec.
    Process,
    /// Scaffolding (s6a-s6g): generating code from the Build Spec.
    Scaffolding,
    /// Pipeline completed successfully.
    Complete,
    /// Pipeline failed and halted.
    Failed,
}

/// Factory-specific state carried alongside the run (FR-009).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FactoryPipelineState {
    /// Unique pipeline identifier (matches the workflow's `run_id`).
    pub pipeline_id: String,
    /// Adapter name.
    pub adapter: String,
    /// SHA-256 hash of the frozen Build Spec (set after stage 5 approval).
    pub build_spec_hash: Option<String>,
    /// Current pipeline phase.
    pub phase: FactoryPhase,
}

impl FactoryPipelineState {
    /// Create initial state for a new pipeline.
    pub fn new(pipeline_id: impl Into<String>, adapter: impl Into<String>) -> Self {
        Self {
            pipeline_id: pipeline_id.into(),
            adapter: adapter.into(),
            build_spec_hash: None,
            phase: FactoryPhase::Process,
        }
    }

    /// Transition to scaffolding phase after Build Spec freeze, recording the
    /// frozen build-spec hash.
    pub fn transition_to_scaffolding(&mut self, build_spec_hash: String) {
        self.build_spec_hash = Some(build_spec_hash);
        self.phase = FactoryPhase::Scaffolding;
    }

    /// Mark pipeline as complete.
    pub fn mark_complete(&mut self) {
        self.phase = FactoryPhase::Complete;
    }

    /// Mark pipeline as failed.
    pub fn mark_failed(&mut self) {
        self.phase = FactoryPhase::Failed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state() {
        let state = FactoryPipelineState::new("run-123", "acme-vue-encore");
        assert_eq!(state.phase, FactoryPhase::Process);
        assert!(state.build_spec_hash.is_none());
    }

    #[test]
    fn phase_transitions() {
        let mut state = FactoryPipelineState::new("run-123", "acme-vue-encore");
        state.transition_to_scaffolding("abc123def".into());
        assert_eq!(state.phase, FactoryPhase::Scaffolding);
        assert_eq!(state.build_spec_hash.as_deref(), Some("abc123def"));
        state.mark_complete();
        assert_eq!(state.phase, FactoryPhase::Complete);
    }

    #[test]
    fn round_trip_serialization() {
        let mut state = FactoryPipelineState::new("run-456", "acme-vue-encore");
        state.transition_to_scaffolding("hash".into());
        let json = serde_json::to_string(&state).unwrap();
        let restored: FactoryPipelineState = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.pipeline_id, "run-456");
        assert_eq!(restored.build_spec_hash.as_deref(), Some("hash"));
    }
}
