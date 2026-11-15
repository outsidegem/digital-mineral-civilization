//! Audit event schema and in-memory sequencing foundation (M1.1).
//!
//! # Security Note (M1.1)
//! - Public unsequenced event construction is prohibited. All [`AuditEvent`] instances must
//!   have a non-zero monotonic sequence number and a unique [`AuditEventId`].
//! - [`InMemoryAuditSequencer`] uses checked arithmetic (`checked_add(1)`) so sequence overflow
//!   at `u64::MAX` fails safely with [`AuditError::SequenceOverflow`] without mutating state.
//! - Durable append-only storage and cryptographic tamper-evidence are deferred to M3.

use std::collections::BTreeSet;

use dmc_types::{
    validate_canonical_resource_uri, AgentId, ArtifactId, AuditEventId, Decision, DelegationId,
    ExecutionId, IdValidationError, PolicyRequest, RdaProcessId, ResourceScopeError,
};
pub use titan_identity::{AuthorizedPolicyRequest, ResolvedAgentIdentity};
pub use titan_policy_core::{PolicyResult, PolicyTrustLevel};

/// Explicit classification of audit events with stable canonical names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditEventKind {
    PolicyAuthorizationDecision,
    IdentityResolution,
    DelegationValidation,
    ProvenanceVerification,
}

impl AuditEventKind {
    /// Returns the permanent, serialization-safe event type identifier.
    pub fn stable_name(&self) -> &'static str {
        match self {
            Self::PolicyAuthorizationDecision => "policy.authorization_decision",
            Self::IdentityResolution => "identity.resolution",
            Self::DelegationValidation => "delegation.validation",
            Self::ProvenanceVerification => "provenance.verification",
        }
    }
}

/// Validation errors for [`AuditEvent`] construction and sequencing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditError {
    InvalidEventId(IdValidationError),
    InvalidZeroSequence,
    SequenceOverflow,
    EmptyAction,
    EmptyResource,
    InvalidResource(ResourceScopeError),
    EmptyPolicyVersion,
    EmptyReason,
    DuplicateArtifactReference(ArtifactId),
    DuplicateEventId(AuditEventId),
    NonMonotonicSequence {
        last_sequence: u64,
        attempted_sequence: u64,
    },
}

/// Structured audit event record.
///
/// `event_id` and `sequence` are private with read-only accessors so callers cannot construct
/// unsequenced [`AuditEvent`] instances via struct literals or mutate sequencing metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    event_id: AuditEventId,
    sequence: u64,
    pub event_kind: AuditEventKind,
    pub agent_id: Option<String>,
    pub resolved_agent_id: Option<AgentId>,
    pub process_id: Option<RdaProcessId>,
    pub execution_id: Option<ExecutionId>,
    pub delegation_id: Option<DelegationId>,
    pub action: String,
    pub resource: String,
    pub decision: Decision,
    pub reason: String,
    pub policy_version: String,
    pub artifact_ids: Vec<ArtifactId>,
}

impl AuditEvent {
    pub fn event_id(&self) -> &AuditEventId {
        &self.event_id
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Constructs a sequenced [`AuditEvent`] from a legacy [`PolicyRequest`] and [`PolicyResult`].
    /// Rejects `sequence == 0` and validates `request.resource` via the shared canonical URI validator.
    pub fn from_legacy_request_sequenced(
        event_id: AuditEventId,
        sequence: u64,
        request: &PolicyRequest,
        result: &PolicyResult,
    ) -> Result<Self, AuditError> {
        if sequence == 0 {
            return Err(AuditError::InvalidZeroSequence);
        }
        let canonical_resource = map_resource_validation(&request.resource)?;
        let agent_id_str = request.agent.as_ref().map(|a| a.agent_id.clone());
        let resolved_agent_id = agent_id_str
            .as_deref()
            .and_then(|raw| AgentId::new(raw).ok());
        let event = Self {
            event_id,
            sequence,
            event_kind: AuditEventKind::PolicyAuthorizationDecision,
            agent_id: agent_id_str,
            resolved_agent_id,
            process_id: None,
            execution_id: None,
            delegation_id: None,
            action: request.action.stable_name(),
            resource: canonical_resource,
            decision: result.decision,
            reason: result.reason.clone(),
            policy_version: result.policy_version.clone(),
            artifact_ids: Vec::new(),
        };
        event.validate()?;
        Ok(event)
    }

    /// Constructs a sequenced M1.1 [`AuditEvent`] from an [`AuthorizedPolicyRequest`],
    /// [`PolicyResult`], and optional execution/artifact provenance references.
    /// Rejects `sequence == 0` and validates `request.resource` via the shared canonical URI validator.
    pub fn from_authorized_request(
        event_id: AuditEventId,
        sequence: u64,
        request: &AuthorizedPolicyRequest,
        result: &PolicyResult,
        execution_id: Option<ExecutionId>,
        artifact_ids: Vec<ArtifactId>,
    ) -> Result<Self, AuditError> {
        if sequence == 0 {
            return Err(AuditError::InvalidZeroSequence);
        }
        let canonical_resource = map_resource_validation(&request.resource)?;
        let resolved_agent_id = request.identity.as_ref().map(|id| id.agent_id().clone());
        let agent_id = resolved_agent_id.as_ref().map(|id| id.as_str().to_owned());
        let process_id = request.process.as_ref().map(|p| p.process_id.clone());
        let delegation_id = request
            .delegation
            .as_ref()
            .map(|d| d.delegation_id.clone())
            .or_else(|| {
                request
                    .process
                    .as_ref()
                    .and_then(|p| p.delegation_id().cloned())
            });

        let event = Self {
            event_id,
            sequence,
            event_kind: AuditEventKind::PolicyAuthorizationDecision,
            agent_id,
            resolved_agent_id,
            process_id,
            execution_id,
            delegation_id,
            action: request.action.stable_name(),
            resource: canonical_resource,
            decision: result.decision,
            reason: result.reason.clone(),
            policy_version: result.policy_version.clone(),
            artifact_ids,
        };
        event.validate()?;
        Ok(event)
    }

    /// Validates required fields, non-zero sequence, canonical resource URI, and duplicate
    /// artifact references.
    pub fn validate(&self) -> Result<(), AuditError> {
        if self.sequence == 0 {
            return Err(AuditError::InvalidZeroSequence);
        }
        if self.action.trim().is_empty() {
            return Err(AuditError::EmptyAction);
        }
        let _ = map_resource_validation(&self.resource)?;
        if self.policy_version.trim().is_empty() {
            return Err(AuditError::EmptyPolicyVersion);
        }
        if self.reason.trim().is_empty() {
            return Err(AuditError::EmptyReason);
        }
        let mut seen = BTreeSet::new();
        for art in &self.artifact_ids {
            if !seen.insert(art.clone()) {
                return Err(AuditError::DuplicateArtifactReference(art.clone()));
            }
        }
        Ok(())
    }

    /// Stable canonical name for the event kind.
    pub fn event_kind_name(&self) -> &'static str {
        self.event_kind.stable_name()
    }

    /// Stable canonical name for the decision (`"allow"` or `"deny"`).
    pub fn decision_name(&self) -> &'static str {
        self.decision.stable_name()
    }
}

fn map_resource_validation(raw: &str) -> Result<String, AuditError> {
    validate_canonical_resource_uri(raw).map_err(|err| {
        if err == ResourceScopeError::EmptyResourcePattern {
            AuditError::EmptyResource
        } else {
            AuditError::InvalidResource(err)
        }
    })
}

/// Non-durable, in-memory audit event sequencer for M1.1.
#[derive(Debug, Clone, Default)]
pub struct InMemoryAuditSequencer {
    last_sequence: u64,
    seen_event_ids: BTreeSet<AuditEventId>,
    events: Vec<AuditEvent>,
}

impl InMemoryAuditSequencer {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn with_starting_sequence_for_test(last_sequence: u64) -> Self {
        Self {
            last_sequence,
            seen_event_ids: BTreeSet::new(),
            events: Vec::new(),
        }
    }

    fn next_sequence_and_id(&self) -> Result<(u64, AuditEventId), AuditError> {
        let next_seq = self
            .last_sequence
            .checked_add(1)
            .ok_or(AuditError::SequenceOverflow)?;
        let event_id =
            AuditEventId::new(format!("evt-{next_seq:08}")).map_err(AuditError::InvalidEventId)?;
        Ok((next_seq, event_id))
    }

    /// Records a legacy [`PolicyRequest`] decision with a unique event ID and checked monotonic
    /// sequence number. Does not mutate sequencer state on error or overflow.
    pub fn record_legacy_decision(
        &mut self,
        request: &PolicyRequest,
        result: &PolicyResult,
    ) -> Result<AuditEvent, AuditError> {
        let (next_seq, event_id) = self.next_sequence_and_id()?;
        let event = AuditEvent::from_legacy_request_sequenced(event_id, next_seq, request, result)?;
        self.append(event.clone())?;
        Ok(event)
    }

    /// Records an [`AuthorizedPolicyRequest`] decision with a unique event ID and checked
    /// monotonic sequence number. Does not mutate sequencer state on error or overflow.
    pub fn record_authorized_decision(
        &mut self,
        request: &AuthorizedPolicyRequest,
        result: &PolicyResult,
        execution_id: Option<ExecutionId>,
        artifact_ids: Vec<ArtifactId>,
    ) -> Result<AuditEvent, AuditError> {
        let (next_seq, event_id) = self.next_sequence_and_id()?;
        let event = AuditEvent::from_authorized_request(
            event_id,
            next_seq,
            request,
            result,
            execution_id,
            artifact_ids,
        )?;
        self.append(event.clone())?;
        Ok(event)
    }

    /// Appends a validated [`AuditEvent`], enforcing unique `event_id` and strictly increasing
    /// non-zero `sequence` before mutating internal state.
    pub fn append(&mut self, event: AuditEvent) -> Result<(), AuditError> {
        event.validate()?;
        if self.seen_event_ids.contains(&event.event_id) {
            return Err(AuditError::DuplicateEventId(event.event_id));
        }
        if event.sequence <= self.last_sequence {
            return Err(AuditError::NonMonotonicSequence {
                last_sequence: self.last_sequence,
                attempted_sequence: event.sequence,
            });
        }
        self.last_sequence = event.sequence;
        self.seen_event_ids.insert(event.event_id.clone());
        self.events.push(event);
        Ok(())
    }

    pub fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmc_types::{
        Action, AgentIdentity, AgentIdentityClaim, AutonomyLevel, DelegationRecord,
        ProcessAuthorityBinding, ProcessCreationContext, ProcessProvenance, ResourceScope,
        RevocationStatus, TaskId,
    };
    use titan_identity::{ProvisionalAgentEntry, ProvisionalIdentityRegistry};

    #[test]
    fn legacy_decisions_are_sequenced_with_unique_ids_and_stable_names() {
        let req = PolicyRequest {
            agent: Some(AgentIdentity {
                agent_id: "agent-01".into(),
                department: "Research".into(),
                autonomy: AutonomyLevel::E2Sandbox,
            }),
            action: Action::CreateSandboxReport,
            resource: "sandbox://research/report".into(),
            policy_version: "m1.1-0.1".into(),
        };
        let res = PolicyResult::new_legacy_unverified(Decision::Allow, "allowed", "m1.1-0.1");

        let mut sequencer = InMemoryAuditSequencer::new();
        let ev1 = sequencer.record_legacy_decision(&req, &res).unwrap();
        let ev2 = sequencer.record_legacy_decision(&req, &res).unwrap();

        assert_eq!(ev1.event_id().as_str(), "evt-00000001");
        assert_eq!(ev1.sequence(), 1);
        assert_eq!(ev1.action, "create_sandbox_report");
        assert_eq!(ev2.event_id().as_str(), "evt-00000002");
        assert_eq!(ev2.sequence(), 2);

        // Zero sequence is rejected
        assert_eq!(
            AuditEvent::from_legacy_request_sequenced(
                AuditEventId::new("evt-zero").unwrap(),
                0,
                &req,
                &res
            ),
            Err(AuditError::InvalidZeroSequence)
        );
    }

    #[test]
    fn sequence_overflow_fails_safely_without_mutating_state() {
        let req = PolicyRequest {
            agent: Some(AgentIdentity {
                agent_id: "agent-01".into(),
                department: "Research".into(),
                autonomy: AutonomyLevel::E2Sandbox,
            }),
            action: Action::ReadKnowledge,
            resource: "sandbox://research/doc".into(),
            policy_version: "m1.1-0.1".into(),
        };
        let res = PolicyResult::new_legacy_unverified(Decision::Allow, "allowed", "m1.1-0.1");

        let mut max_seq = InMemoryAuditSequencer::with_starting_sequence_for_test(u64::MAX);
        assert_eq!(
            max_seq.record_legacy_decision(&req, &res),
            Err(AuditError::SequenceOverflow)
        );
        assert_eq!(max_seq.last_sequence(), u64::MAX);
        assert!(max_seq.events().is_empty());
    }

    #[test]
    fn audit_sequencer_assigns_stable_ids_sequences_and_provenance_refs() {
        let mut registry = ProvisionalIdentityRegistry::new("local-registry");
        let agent_id = AgentId::new("agent-01").unwrap();
        registry
            .register_agent(ProvisionalAgentEntry {
                agent_id: agent_id.clone(),
                department: "Research".into(),
                max_autonomy: AutonomyLevel::E2Sandbox,
                revocation_reason: None,
            })
            .unwrap();
        let resolved = registry
            .resolve_claim(&AgentIdentityClaim {
                agent_id: "agent-01".into(),
                department: "Research".into(),
                claimed_autonomy: AutonomyLevel::E2Sandbox,
            })
            .unwrap();

        let scope = ResourceScope::new(vec!["sandbox://research".into()]).unwrap();
        let del_id = DelegationId::new("del-01").unwrap();
        let proc_id = RdaProcessId::new("proc-01").unwrap();
        let exec_id = ExecutionId::new("exec-01").unwrap();
        let art_id = ArtifactId::new("art-01").unwrap();

        let delegation = DelegationRecord {
            delegation_id: del_id.clone(),
            issuer: AgentId::new("agent-lead").unwrap(),
            recipient: agent_id.clone(),
            recipient_process: Some(proc_id.clone()),
            max_autonomy: AutonomyLevel::E2Sandbox,
            permitted_actions: vec![Action::CreateSandboxReport],
            resource_scope: scope.clone(),
            issued_at_epoch_secs: 100,
            expires_at_epoch_secs: 500,
            revocation_status: RevocationStatus::Active,
            parent_delegation_id: None,
        };

        let process = ProcessProvenance {
            process_id: proc_id.clone(),
            parent_agent_id: agent_id,
            parent_process_id: None,
            originating_task_id: TaskId::new("task-01").unwrap(),
            creation_context: ProcessCreationContext {
                created_at_epoch_secs: 110,
                environment: "termux".into(),
                purpose: "report generation".into(),
            },
            authority: ProcessAuthorityBinding::DelegatedAuthority {
                delegation_id: del_id.clone(),
                effective_autonomy: AutonomyLevel::E2Sandbox,
                permitted_actions: vec![Action::CreateSandboxReport],
                resource_scope: scope,
            },
        };

        let req = AuthorizedPolicyRequest {
            identity: Some(resolved),
            process: Some(process),
            parent_process: None,
            delegation: Some(delegation),
            parent_delegation: None,
            action: Action::CreateSandboxReport,
            resource: "sandbox://research/report-1".into(),
            policy_version: "m1.1-0.1".into(),
            evaluation_epoch_secs: 200,
        };
        let res =
            PolicyResult::new_provisional_identity_only(Decision::Allow, "permitted", "m1.1-0.1");

        let mut sequencer = InMemoryAuditSequencer::new();
        let ev1 = sequencer
            .record_authorized_decision(&req, &res, Some(exec_id.clone()), vec![art_id.clone()])
            .unwrap();
        assert_eq!(ev1.event_id().as_str(), "evt-00000001");
        assert_eq!(ev1.sequence(), 1);
        assert_eq!(ev1.process_id, Some(proc_id));
        assert_eq!(ev1.execution_id, Some(exec_id));
        assert_eq!(ev1.delegation_id, Some(del_id));
        assert_eq!(ev1.artifact_ids, vec![art_id]);

        assert_eq!(
            sequencer.append(ev1),
            Err(AuditError::DuplicateEventId(
                AuditEventId::new("evt-00000001").unwrap()
            ))
        );
    }

    #[test]
    fn both_audit_constructors_enforce_shared_canonical_resource_validator() {
        let mut registry = ProvisionalIdentityRegistry::new("audit-resource-registry");
        let agent_id = AgentId::new("agent-01").unwrap();
        registry
            .register_agent(ProvisionalAgentEntry {
                agent_id: agent_id.clone(),
                department: "Research".into(),
                max_autonomy: AutonomyLevel::E2Sandbox,
                revocation_reason: None,
            })
            .unwrap();
        let resolved = registry
            .resolve_claim(&AgentIdentityClaim {
                agent_id: "agent-01".into(),
                department: "Research".into(),
                claimed_autonomy: AutonomyLevel::E2Sandbox,
            })
            .unwrap();

        let legacy_res = PolicyResult::new_legacy_unverified(Decision::Deny, "denied", "m1.1-0.1");
        let auth_res =
            PolicyResult::new_provisional_identity_only(Decision::Deny, "denied", "m1.1-0.1");

        let invalid_cases: &[(&str, AuditError)] = &[
            // Traversal segments ("../" and dot-segments)
            (
                "sandbox://research/../treasury",
                AuditError::InvalidResource(ResourceScopeError::TraversalSegmentNotAllowed),
            ),
            (
                "sandbox://research/./doc",
                AuditError::InvalidResource(ResourceScopeError::TraversalSegmentNotAllowed),
            ),
            (
                "sandbox://research/reports/..",
                AuditError::InvalidResource(ResourceScopeError::TraversalSegmentNotAllowed),
            ),
            // Double or trailing separators
            (
                "sandbox://research//doc",
                AuditError::InvalidResource(ResourceScopeError::EmptyPathSegment),
            ),
            (
                "sandbox://research/",
                AuditError::InvalidResource(ResourceScopeError::EmptyPathSegment),
            ),
            (
                "sandbox:///research",
                AuditError::InvalidResource(ResourceScopeError::EmptyPathSegment),
            ),
            // Backslashes and percent-encoded traversal
            (
                "sandbox://research\\..\\treasury",
                AuditError::InvalidResource(ResourceScopeError::ForbiddenUriCharacters),
            ),
            (
                "sandbox://research/%2e%2e/treasury",
                AuditError::InvalidResource(ResourceScopeError::ForbiddenUriCharacters),
            ),
            (
                "sandbox://research/%2fdoc",
                AuditError::InvalidResource(ResourceScopeError::ForbiddenUriCharacters),
            ),
            // Query, fragment, and wildcard forms
            (
                "sandbox://research/doc?admin=1",
                AuditError::InvalidResource(ResourceScopeError::ForbiddenUriCharacters),
            ),
            (
                "sandbox://research/doc#frag",
                AuditError::InvalidResource(ResourceScopeError::ForbiddenUriCharacters),
            ),
            (
                "sandbox://research/*",
                AuditError::InvalidResource(ResourceScopeError::UnboundedWildcardNotAllowed),
            ),
            // Other malformed resource identifiers rejected by the shared validator
            ("", AuditError::EmptyResource),
            (
                "   ",
                AuditError::InvalidResource(ResourceScopeError::InvalidResourceCharacters),
            ),
            (
                " sandbox://research/doc",
                AuditError::InvalidResource(ResourceScopeError::InvalidResourceCharacters),
            ),
            (
                "/relative/path",
                AuditError::InvalidResource(ResourceScopeError::MissingOrInvalidScheme),
            ),
            (
                "UPPER://research/doc",
                AuditError::InvalidResource(ResourceScopeError::MissingOrInvalidScheme),
            ),
            (
                "sandbox://research:8080/doc",
                AuditError::InvalidResource(ResourceScopeError::MissingOrInvalidScheme),
            ),
        ];

        for (bad_resource, expected_err) in invalid_cases {
            let legacy_req = PolicyRequest {
                agent: Some(AgentIdentity {
                    agent_id: "agent-01".into(),
                    department: "Research".into(),
                    autonomy: AutonomyLevel::E2Sandbox,
                }),
                action: Action::ReadKnowledge,
                resource: (*bad_resource).to_owned(),
                policy_version: "m1.1-0.1".into(),
            };
            assert_eq!(
                AuditEvent::from_legacy_request_sequenced(
                    AuditEventId::new("evt-test-legacy").unwrap(),
                    1,
                    &legacy_req,
                    &legacy_res,
                ),
                Err(expected_err.clone()),
                "legacy constructor failed to reject resource: {bad_resource:?}"
            );

            let auth_req = AuthorizedPolicyRequest {
                identity: Some(resolved.clone()),
                process: None,
                parent_process: None,
                delegation: None,
                parent_delegation: None,
                action: Action::ReadKnowledge,
                resource: (*bad_resource).to_owned(),
                policy_version: "m1.1-0.1".into(),
                evaluation_epoch_secs: 1_000,
            };
            assert_eq!(
                AuditEvent::from_authorized_request(
                    AuditEventId::new("evt-test-auth").unwrap(),
                    1,
                    &auth_req,
                    &auth_res,
                    None,
                    vec![],
                ),
                Err(expected_err.clone()),
                "authorized constructor failed to reject resource: {bad_resource:?}"
            );
        }

        // Confirm valid canonical resource identifiers remain accepted by both constructors
        for valid_resource in [
            "sandbox://research",
            "sandbox://research/reports/q1_v1.0-final",
        ] {
            let legacy_req = PolicyRequest {
                agent: Some(AgentIdentity {
                    agent_id: "agent-01".into(),
                    department: "Research".into(),
                    autonomy: AutonomyLevel::E2Sandbox,
                }),
                action: Action::ReadKnowledge,
                resource: valid_resource.to_owned(),
                policy_version: "m1.1-0.1".into(),
            };
            let ev_legacy = AuditEvent::from_legacy_request_sequenced(
                AuditEventId::new("evt-valid-legacy").unwrap(),
                1,
                &legacy_req,
                &legacy_res,
            )
            .unwrap();
            assert_eq!(ev_legacy.resource, valid_resource);

            let auth_req = AuthorizedPolicyRequest {
                identity: Some(resolved.clone()),
                process: None,
                parent_process: None,
                delegation: None,
                parent_delegation: None,
                action: Action::ReadKnowledge,
                resource: valid_resource.to_owned(),
                policy_version: "m1.1-0.1".into(),
                evaluation_epoch_secs: 1_000,
            };
            let ev_auth = AuditEvent::from_authorized_request(
                AuditEventId::new("evt-valid-auth").unwrap(),
                2,
                &auth_req,
                &auth_res,
                None,
                vec![],
            )
            .unwrap();
            assert_eq!(ev_auth.resource, valid_resource);
        }
    }
}
