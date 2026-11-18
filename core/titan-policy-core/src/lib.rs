//! Deterministic, fail-closed starter policy engine. No I/O or model calls.
//!
//! # M1.1 Security Boundaries
//! - [`policy_evaluate`] is the isolated M1 legacy claim simulation API. It always returns
//!   [`crate::PolicyTrustLevel::LegacyUnverifiedSimulationOnly`] with
//!   `execution_authorized() == false`.
//! - [`policy_evaluate_authorized`] performs detached structural checks without live registry or
//!   provenance tracker state. It always returns
//!   [`crate::PolicyTrustLevel::ProvisionalIdentityOnly`] with `execution_authorized() == false`.
//! - [`policy_evaluate_strict_provenance`] is the **only** path that can produce a
//!   [`crate::PolicyTrustLevel::LiveProvenanceVerified`] result with
//!   `execution_authorized() == true`, requiring live verification against both
//!   [`titan_identity::ProvisionalIdentityRegistry`] and [`titan_identity::ProvenanceTracker`].

use dmc_types::{validate_canonical_resource_uri, AgentId, AutonomyLevel, Decision, PolicyRequest};
use titan_identity::{
    validate_process_provenance, LiveProvenanceVerificationSeal, ProvenanceTracker,
    ProvisionalIdentityRegistry,
};
pub use titan_identity::{AuthorizedPolicyRequest, ResolvedAgentIdentity};

/// Trust level of a policy evaluation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyTrustLevel {
    /// Produced by the legacy M1 unverified-claim evaluator (`policy_evaluate`).
    /// Never valid for execution authorization.
    LegacyUnverifiedSimulationOnly,
    /// Produced by detached structural evaluation without live registry/tracker verification.
    /// Never valid for execution authorization.
    ProvisionalIdentityOnly,
    /// Produced by `policy_evaluate_strict_provenance` against live `ProvisionalIdentityRegistry`
    /// and `ProvenanceTracker` state. Note: still provisional (non-cryptographic) in M1.1.
    LiveProvenanceVerified,
}

/// Result of a policy evaluation.
///
/// `execution_authorized` and `trust_level` are private to `titan-policy-core` with read-only
/// accessors, and `new_live_provenance_allowed` is private to this module so no external caller
/// can construct a `LiveProvenanceVerified` result or mutate a boolean capability flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyResult {
    pub decision: Decision,
    pub reason: String,
    pub audit_required: bool,
    pub policy_version: String,
    execution_authorized: bool,
    trust_level: PolicyTrustLevel,
}

impl PolicyResult {
    /// Constructs a legacy M1 simulation result. `execution_authorized` is always `false`.
    pub fn new_legacy_unverified(
        decision: Decision,
        reason: impl Into<String>,
        policy_version: impl Into<String>,
    ) -> Self {
        Self {
            decision,
            reason: reason.into(),
            audit_required: true,
            policy_version: policy_version.into(),
            execution_authorized: false,
            trust_level: PolicyTrustLevel::LegacyUnverifiedSimulationOnly,
        }
    }

    /// Constructs a detached provisional result. `execution_authorized` is always `false`.
    pub fn new_provisional_identity_only(
        decision: Decision,
        reason: impl Into<String>,
        policy_version: impl Into<String>,
    ) -> Self {
        Self {
            decision,
            reason: reason.into(),
            audit_required: true,
            policy_version: policy_version.into(),
            execution_authorized: false,
            trust_level: PolicyTrustLevel::ProvisionalIdentityOnly,
        }
    }

    /// Constructs a denied result on the strict live-provenance path.
    pub fn new_live_provenance_denied(
        reason: impl Into<String>,
        policy_version: impl Into<String>,
    ) -> Self {
        Self {
            decision: Decision::Deny,
            reason: reason.into(),
            audit_required: true,
            policy_version: policy_version.into(),
            execution_authorized: false,
            trust_level: PolicyTrustLevel::LiveProvenanceVerified,
        }
    }

    fn new_live_provenance_allowed(
        _seal: LiveProvenanceVerificationSeal,
        reason: impl Into<String>,
        policy_version: impl Into<String>,
    ) -> Self {
        Self {
            decision: Decision::Allow,
            reason: reason.into(),
            audit_required: true,
            policy_version: policy_version.into(),
            execution_authorized: true,
            trust_level: PolicyTrustLevel::LiveProvenanceVerified,
        }
    }

    /// Read-only accessor indicating whether this result authorizes execution under live M1.1
    /// provisional provenance checks. Always returns `false` if `decision` is not `Allow` or
    /// `trust_level` is not `LiveProvenanceVerified`.
    pub fn execution_authorized(&self) -> bool {
        self.execution_authorized
            && self.decision == Decision::Allow
            && self.trust_level == PolicyTrustLevel::LiveProvenanceVerified
    }

    /// Alias for [`Self::execution_authorized`].
    pub fn is_execution_authorized(&self) -> bool {
        self.execution_authorized()
    }

    /// Read-only accessor for the evaluation trust level.
    pub fn trust_level(&self) -> PolicyTrustLevel {
        self.trust_level
    }
}

/// Evaluates an M1 baseline [`PolicyRequest`] in legacy simulation mode.
///
/// # Isolation Guarantee
/// Results produced by this function always have `execution_authorized() == false` and
/// `trust_level() == PolicyTrustLevel::LegacyUnverifiedSimulationOnly`.
pub fn policy_evaluate(request: &PolicyRequest) -> PolicyResult {
    let version = request.policy_version.clone();
    if version.trim().is_empty() || validate_canonical_resource_uri(&request.resource).is_err() {
        return PolicyResult::new_legacy_unverified(
            Decision::Deny,
            "missing or invalid required policy context (version or canonical resource)",
            version,
        );
    }

    let Some(agent) = request.agent.as_ref() else {
        return PolicyResult::new_legacy_unverified(
            Decision::Deny,
            "missing agent identity",
            version,
        );
    };

    if AgentId::new(&agent.agent_id).is_err()
        || agent.department.trim().is_empty()
        || agent.department.chars().any(|c| c.is_control())
    {
        return PolicyResult::new_legacy_unverified(
            Decision::Deny,
            "malformed agent identity claim",
            version,
        );
    }

    // E5 is reserved for a separate Founder-controlled approval path.
    if agent.autonomy == AutonomyLevel::E5ReservedAuthority {
        return PolicyResult::new_legacy_unverified(
            Decision::Deny,
            "reserved authority requires separate Founder approval",
            version,
        );
    }

    if request.action.is_allowed_for_autonomy(agent.autonomy) {
        PolicyResult::new_legacy_unverified(
            Decision::Allow,
            "action permitted by M1 baseline policy (simulation only)",
            version,
        )
    } else {
        PolicyResult::new_legacy_unverified(
            Decision::Deny,
            "action not permitted by M1 baseline policy",
            version,
        )
    }
}

/// Evaluates an [`AuthorizedPolicyRequest`] using detached structural checks only.
///
/// Because live registry and provenance tracker state are not consulted here, this function
/// never authorizes execution (`execution_authorized() == false`,
/// `trust_level() == PolicyTrustLevel::ProvisionalIdentityOnly`).
pub fn policy_evaluate_authorized(request: &AuthorizedPolicyRequest) -> PolicyResult {
    let version = request.policy_version.clone();
    if version.trim().is_empty() || validate_canonical_resource_uri(&request.resource).is_err() {
        return PolicyResult::new_provisional_identity_only(
            Decision::Deny,
            "missing or invalid required policy context (version or canonical resource)",
            version,
        );
    }

    let Some(identity) = request.identity.as_ref() else {
        return PolicyResult::new_provisional_identity_only(
            Decision::Deny,
            "missing resolved agent identity",
            version,
        );
    };

    if !identity.is_trusted_for_policy() {
        return PolicyResult::new_provisional_identity_only(
            Decision::Deny,
            "resolved identity is not in an active trusted status",
            version,
        );
    }

    if identity.department().trim().is_empty() {
        return PolicyResult::new_provisional_identity_only(
            Decision::Deny,
            "malformed resolved agent identity",
            version,
        );
    }

    if !request.action.is_allowed_for_autonomy(identity.autonomy()) {
        return PolicyResult::new_provisional_identity_only(
            Decision::Deny,
            "action not permitted for resolved identity autonomy",
            version,
        );
    }

    if request.process.is_none()
        && (request.parent_process.is_some()
            || request.delegation.is_some()
            || request.parent_delegation.is_some())
    {
        return PolicyResult::new_provisional_identity_only(
            Decision::Deny,
            "inconsistent provenance: delegation or parent process supplied without active process provenance",
            version,
        );
    }

    if let Some(process) = request.process.as_ref() {
        if &process.parent_agent_id != identity.agent_id() {
            return PolicyResult::new_provisional_identity_only(
                Decision::Deny,
                "inconsistent provenance: process parent_agent_id does not match resolved identity",
                version,
            );
        }

        if process.effective_autonomy() > identity.autonomy() {
            return PolicyResult::new_provisional_identity_only(
                Decision::Deny,
                "process effective autonomy exceeds resolved agent autonomy",
                version,
            );
        }

        if validate_process_provenance(
            process,
            request.parent_process.as_ref(),
            request.delegation.as_ref(),
            request.parent_delegation.as_ref(),
            request.evaluation_epoch_secs,
        )
        .is_err()
        {
            return PolicyResult::new_provisional_identity_only(
                Decision::Deny,
                "process provenance or delegation validation failed",
                version,
            );
        }

        if !request
            .action
            .is_allowed_for_autonomy(process.effective_autonomy())
        {
            return PolicyResult::new_provisional_identity_only(
                Decision::Deny,
                "action not permitted for process effective autonomy",
                version,
            );
        }

        if !process.permitted_actions().contains(&request.action) {
            return PolicyResult::new_provisional_identity_only(
                Decision::Deny,
                "action not permitted by process assigned authority",
                version,
            );
        }

        if !process.resource_scope().matches_resource(&request.resource) {
            return PolicyResult::new_provisional_identity_only(
                Decision::Deny,
                "resource outside process assigned resource scope",
                version,
            );
        }
    }

    PolicyResult::new_provisional_identity_only(
        Decision::Allow,
        "action permitted by detached provisional policy check (not execution-authorized)",
        version,
    )
}

/// Evaluates an [`AuthorizedPolicyRequest`] against live [`ProvisionalIdentityRegistry`] and
/// [`ProvenanceTracker`] state.
///
/// This is the **only** function capable of producing a [`PolicyResult`] with
/// [`crate::PolicyTrustLevel::LiveProvenanceVerified`] and `execution_authorized() == true`.
/// Fails closed if the identity or any ancestor agent/issuer is revoked, if the identity came
/// from a different registry instance, if process/delegation records are unregistered or forged,
/// or if any scope/action/expiration constraint is violated.
pub fn policy_evaluate_strict_provenance(
    request: &AuthorizedPolicyRequest,
    registry: &ProvisionalIdentityRegistry,
    tracker: &ProvenanceTracker,
) -> PolicyResult {
    let version = request.policy_version.clone();
    if version.trim().is_empty() || validate_canonical_resource_uri(&request.resource).is_err() {
        return PolicyResult::new_live_provenance_denied(
            "missing or invalid required policy context (version or canonical resource)",
            version,
        );
    }

    let Some(identity) = request.identity.as_ref() else {
        return PolicyResult::new_live_provenance_denied(
            "missing resolved agent identity",
            version,
        );
    };

    let Some(process) = request.process.as_ref() else {
        return PolicyResult::new_live_provenance_denied(
            "missing required process provenance",
            version,
        );
    };

    // If caller supplied parent_process or parent_delegation in the request struct, verify they
    // match the process/delegation links and live tracker records.
    if let Some(expected_parent_pid) = &process.parent_process_id {
        let Some(supplied_parent) = request.parent_process.as_ref() else {
            return PolicyResult::new_live_provenance_denied(
                "missing parent process record for child process",
                version,
            );
        };
        if &supplied_parent.process_id != expected_parent_pid
            || tracker.get_process(expected_parent_pid) != Some(supplied_parent)
        {
            return PolicyResult::new_live_provenance_denied(
                "parent process does not match live registered provenance",
                version,
            );
        }
    } else if request.parent_process.is_some() {
        return PolicyResult::new_live_provenance_denied(
            "inconsistent provenance: parent_process supplied for root process",
            version,
        );
    }

    if let Some(del_id) = process.delegation_id() {
        let Some(supplied_del) = request.delegation.as_ref() else {
            return PolicyResult::new_live_provenance_denied(
                "missing delegation record for delegated process",
                version,
            );
        };
        if &supplied_del.delegation_id != del_id {
            return PolicyResult::new_live_provenance_denied(
                "delegation ID mismatch on process",
                version,
            );
        }
        if let Some(expected_parent_del_id) = &supplied_del.parent_delegation_id {
            if let Some(supplied_parent_del) = request.parent_delegation.as_ref() {
                if &supplied_parent_del.delegation_id != expected_parent_del_id
                    || tracker.get_delegation(expected_parent_del_id) != Some(supplied_parent_del)
                {
                    return PolicyResult::new_live_provenance_denied(
                        "parent delegation does not match live registered delegation",
                        version,
                    );
                }
            }
        } else if request.parent_delegation.is_some() {
            return PolicyResult::new_live_provenance_denied(
                "inconsistent provenance: parent_delegation supplied for root delegation",
                version,
            );
        }
    } else if request.delegation.is_some() || request.parent_delegation.is_some() {
        return PolicyResult::new_live_provenance_denied(
            "inconsistent provenance: delegation supplied for non-delegated process",
            version,
        );
    }

    let seal = match tracker.verify_live_process_and_delegation_lineage(
        registry,
        identity,
        process,
        request.delegation.as_ref(),
        request.evaluation_epoch_secs,
    ) {
        Ok(seal) => seal,
        Err(_) => {
            return PolicyResult::new_live_provenance_denied(
                "live identity, delegation ancestry, or process lineage verification failed",
                version,
            );
        }
    };

    if !request.action.is_allowed_for_autonomy(identity.autonomy())
        || !request
            .action
            .is_allowed_for_autonomy(process.effective_autonomy())
    {
        return PolicyResult::new_live_provenance_denied(
            "action not permitted for effective autonomy",
            version,
        );
    }

    if !process.permitted_actions().contains(&request.action) {
        return PolicyResult::new_live_provenance_denied(
            "action not permitted by process assigned authority",
            version,
        );
    }

    if !process.resource_scope().matches_resource(&request.resource) {
        return PolicyResult::new_live_provenance_denied(
            "resource outside process assigned resource scope",
            version,
        );
    }

    if let Some(del_id) = process.delegation_id() {
        let Some(registered_del) = tracker.get_delegation(del_id) else {
            return PolicyResult::new_live_provenance_denied(
                "missing registered delegation in tracker",
                version,
            );
        };
        if !registered_del.permitted_actions.contains(&request.action) {
            return PolicyResult::new_live_provenance_denied(
                "action not permitted by explicit delegation",
                version,
            );
        }
        if !registered_del
            .resource_scope
            .matches_resource(&request.resource)
        {
            return PolicyResult::new_live_provenance_denied(
                "resource outside delegated resource scope",
                version,
            );
        }
    }

    PolicyResult::new_live_provenance_allowed(
        seal,
        "action permitted by M1.1 live provenance policy evaluation",
        version,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use dmc_types::{
        Action, AgentIdentity, AgentIdentityClaim, DelegationId, DelegationRecord, PolicyRequest,
        ProcessAuthorityBinding, ProcessCreationContext, ProcessProvenance, RdaProcessId,
        ResourceScope, RevocationStatus, TaskId,
    };
    use titan_identity::ProvisionalAgentEntry;

    fn request(level: AutonomyLevel, action: Action) -> PolicyRequest {
        PolicyRequest {
            agent: Some(AgentIdentity {
                agent_id: "agent-research-001".into(),
                department: "Research".into(),
                autonomy: level,
            }),
            action,
            resource: "sandbox://research".into(),
            policy_version: "m1-baseline-0.1".into(),
        }
    }

    #[test]
    fn e2_can_create_sandbox_report() {
        assert_eq!(
            policy_evaluate(&request(
                AutonomyLevel::E2Sandbox,
                Action::CreateSandboxReport
            ))
            .decision,
            Decision::Allow
        );
    }

    #[test]
    fn e2_cannot_transfer_treasury_funds() {
        assert_eq!(
            policy_evaluate(&request(
                AutonomyLevel::E2Sandbox,
                Action::TransferTreasuryFunds
            ))
            .decision,
            Decision::Deny
        );
    }

    #[test]
    fn missing_identity_fails_closed() {
        let mut req = request(AutonomyLevel::E2Sandbox, Action::ReadKnowledge);
        req.agent = None;
        assert_eq!(policy_evaluate(&req).decision, Decision::Deny);
    }

    #[test]
    fn e5_reserved_authority_fails_closed() {
        assert_eq!(
            policy_evaluate(&request(
                AutonomyLevel::E5ReservedAuthority,
                Action::ReadKnowledge
            ))
            .decision,
            Decision::Deny
        );
    }

    #[test]
    fn unknown_action_fails_closed() {
        assert_eq!(
            policy_evaluate(&request(
                AutonomyLevel::E3InternalOperations,
                Action::Unknown("shell_exec".into())
            ))
            .decision,
            Decision::Deny
        );
    }

    #[test]
    fn every_decision_requires_audit() {
        assert!(
            policy_evaluate(&request(
                AutonomyLevel::E2Sandbox,
                Action::CreateSandboxReport
            ))
            .audit_required
        );
        assert!(
            policy_evaluate(&request(
                AutonomyLevel::E2Sandbox,
                Action::TransferTreasuryFunds
            ))
            .audit_required
        );
    }

    #[test]
    fn legacy_and_detached_apis_never_grant_execution_authorization() {
        let legacy_res = policy_evaluate(&request(
            AutonomyLevel::E2Sandbox,
            Action::CreateSandboxReport,
        ));
        assert_eq!(legacy_res.decision, Decision::Allow);
        assert!(!legacy_res.execution_authorized());
        assert_eq!(
            legacy_res.trust_level(),
            PolicyTrustLevel::LegacyUnverifiedSimulationOnly
        );

        let mut registry = ProvisionalIdentityRegistry::new("test-reg");
        registry
            .register_agent(ProvisionalAgentEntry {
                agent_id: AgentId::new("agent-01").unwrap(),
                department: "Research".into(),
                max_autonomy: AutonomyLevel::E2Sandbox,
                revocation_reason: None,
            })
            .unwrap();
        let identity = registry
            .resolve_claim(&AgentIdentityClaim {
                agent_id: "agent-01".into(),
                department: "Research".into(),
                claimed_autonomy: AutonomyLevel::E2Sandbox,
            })
            .unwrap();

        let detached_req = AuthorizedPolicyRequest {
            identity: Some(identity),
            process: None,
            parent_process: None,
            delegation: None,
            parent_delegation: None,
            action: Action::CreateSandboxReport,
            resource: "sandbox://research/report".into(),
            policy_version: "m1.1-0.1".into(),
            evaluation_epoch_secs: 1_000,
        };
        let detached_res = policy_evaluate_authorized(&detached_req);
        assert_eq!(detached_res.decision, Decision::Allow);
        assert!(!detached_res.execution_authorized());
        assert_eq!(
            detached_res.trust_level(),
            PolicyTrustLevel::ProvisionalIdentityOnly
        );

        // Mutating `decision` on a denied live result cannot flip `execution_authorized()` to true.
        let mut denied_live = PolicyResult::new_live_provenance_denied("denied", "m1.1-0.1");
        denied_live.decision = Decision::Allow;
        assert!(!denied_live.execution_authorized());
    }

    #[test]
    fn strict_provenance_enforces_live_revocation_propagation_forged_provenance_and_traversal() {
        let mut registry = ProvisionalIdentityRegistry::new("m1.1-strict-registry");
        let lead_id = AgentId::new("agent-lead-01").unwrap();
        let worker_id = AgentId::new("agent-worker-02").unwrap();

        registry
            .register_agent(ProvisionalAgentEntry {
                agent_id: lead_id.clone(),
                department: "Research".into(),
                max_autonomy: AutonomyLevel::E3InternalOperations,
                revocation_reason: None,
            })
            .unwrap();
        registry
            .register_agent(ProvisionalAgentEntry {
                agent_id: worker_id.clone(),
                department: "Research".into(),
                max_autonomy: AutonomyLevel::E2Sandbox,
                revocation_reason: None,
            })
            .unwrap();

        let lead = registry
            .resolve_claim(&AgentIdentityClaim {
                agent_id: "agent-lead-01".into(),
                department: "Research".into(),
                claimed_autonomy: AutonomyLevel::E3InternalOperations,
            })
            .unwrap();
        let worker = registry
            .resolve_claim(&AgentIdentityClaim {
                agent_id: "agent-worker-02".into(),
                department: "Research".into(),
                claimed_autonomy: AutonomyLevel::E2Sandbox,
            })
            .unwrap();

        let mut tracker = ProvenanceTracker::new();
        let parent_scope = ResourceScope::new(vec!["sandbox://research".into()]).unwrap();
        let child_scope = ResourceScope::new(vec!["sandbox://research/reports".into()]).unwrap();

        let parent_proc = ProcessProvenance {
            process_id: RdaProcessId::new("proc-parent-01").unwrap(),
            parent_agent_id: lead_id.clone(),
            parent_process_id: None,
            originating_task_id: TaskId::new("task-root").unwrap(),
            creation_context: ProcessCreationContext {
                created_at_epoch_secs: 1_000,
                environment: "termux".into(),
                purpose: "parent research".into(),
            },
            authority: ProcessAuthorityBinding::DirectAgentAuthority {
                effective_autonomy: AutonomyLevel::E3InternalOperations,
                permitted_actions: vec![
                    Action::ReadKnowledge,
                    Action::CreateSandboxReport,
                    Action::RunUnitTests,
                ],
                resource_scope: parent_scope,
            },
        };
        tracker
            .register_process(parent_proc.clone(), 1_000)
            .unwrap();

        let del_id = DelegationId::new("del-research-reports").unwrap();
        let delegation = DelegationRecord {
            delegation_id: del_id.clone(),
            issuer: lead_id.clone(),
            recipient: worker_id.clone(),
            recipient_process: Some(RdaProcessId::new("proc-child-02").unwrap()),
            max_autonomy: AutonomyLevel::E2Sandbox,
            permitted_actions: vec![Action::CreateSandboxReport],
            resource_scope: child_scope.clone(),
            issued_at_epoch_secs: 1_000,
            expires_at_epoch_secs: 2_000,
            revocation_status: RevocationStatus::Active,
            parent_delegation_id: None,
        };
        tracker
            .register_delegation(delegation.clone(), &lead, 1_050)
            .unwrap();

        let child_proc = ProcessProvenance {
            process_id: RdaProcessId::new("proc-child-02").unwrap(),
            parent_agent_id: worker_id.clone(),
            parent_process_id: Some(parent_proc.process_id.clone()),
            originating_task_id: TaskId::new("task-child").unwrap(),
            creation_context: ProcessCreationContext {
                created_at_epoch_secs: 1_100,
                environment: "termux".into(),
                purpose: "create report".into(),
            },
            authority: ProcessAuthorityBinding::DelegatedAuthority {
                delegation_id: del_id,
                effective_autonomy: AutonomyLevel::E2Sandbox,
                permitted_actions: vec![Action::CreateSandboxReport],
                resource_scope: child_scope,
            },
        };
        tracker.register_process(child_proc.clone(), 1_100).unwrap();

        let valid_req = AuthorizedPolicyRequest {
            identity: Some(worker.clone()),
            process: Some(child_proc.clone()),
            parent_process: Some(parent_proc.clone()),
            delegation: Some(delegation.clone()),
            parent_delegation: None,
            action: Action::CreateSandboxReport,
            resource: "sandbox://research/reports/q1".into(),
            policy_version: "m1.1-0.1".into(),
            evaluation_epoch_secs: 1_500,
        };

        let ok_res = policy_evaluate_strict_provenance(&valid_req, &registry, &tracker);
        assert_eq!(ok_res.decision, Decision::Allow);
        assert!(ok_res.execution_authorized());
        assert_eq!(
            ok_res.trust_level(),
            PolicyTrustLevel::LiveProvenanceVerified
        );

        // 1. Foreign registry instance -> DENY
        let other_registry = ProvisionalIdentityRegistry::new("m1.1-strict-registry");
        let foreign_res = policy_evaluate_strict_provenance(&valid_req, &other_registry, &tracker);
        assert_eq!(foreign_res.decision, Decision::Deny);
        assert!(!foreign_res.execution_authorized());

        // 2. Forged/modified ProcessProvenance (not matching tracker) -> DENY
        let mut forged_proc_req = valid_req.clone();
        forged_proc_req.process = Some(ProcessProvenance {
            process_id: RdaProcessId::new("proc-child-02").unwrap(),
            parent_agent_id: worker_id.clone(),
            parent_process_id: Some(parent_proc.process_id.clone()),
            originating_task_id: TaskId::new("task-child").unwrap(),
            creation_context: ProcessCreationContext {
                created_at_epoch_secs: 1_100,
                environment: "termux".into(),
                purpose: "forged wider permissions".into(),
            },
            authority: ProcessAuthorityBinding::DelegatedAuthority {
                delegation_id: DelegationId::new("del-research-reports").unwrap(),
                effective_autonomy: AutonomyLevel::E2Sandbox,
                permitted_actions: vec![Action::CreateSandboxReport, Action::RunUnitTests],
                resource_scope: ResourceScope::new(vec!["sandbox://research".into()]).unwrap(),
            },
        });
        assert_eq!(
            policy_evaluate_strict_provenance(&forged_proc_req, &registry, &tracker).decision,
            Decision::Deny
        );

        // 3. Traversal attempt in request.resource -> DENY
        let mut traversal_req = valid_req.clone();
        traversal_req.resource = "sandbox://research/reports/../../treasury".into();
        assert_eq!(
            policy_evaluate_strict_provenance(&traversal_req, &registry, &tracker).decision,
            Decision::Deny
        );

        // 4. Revoking the delegating issuer (`agent-lead-01`) in `registry` immediately
        // invalidates child process execution even though `worker` itself is not revoked!
        registry
            .revoke_agent(&lead_id, "issuer key compromised")
            .unwrap();
        let issuer_revoked_res = policy_evaluate_strict_provenance(&valid_req, &registry, &tracker);
        assert_eq!(issuer_revoked_res.decision, Decision::Deny);
        assert!(!issuer_revoked_res.execution_authorized());
    }
}
