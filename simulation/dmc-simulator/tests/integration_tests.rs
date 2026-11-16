//! Integration tests for the DMC Simulation Foundation runtime.

use dmc_simulator::report::{report_suite_to_json, report_to_json};
use dmc_simulator::scenarios::foundation::run_foundation_scenario;
use dmc_simulator::scenarios::security::run_all_security_scenarios;

#[test]
fn test_foundation_scenario_end_to_end() {
    let report = run_foundation_scenario();

    assert!(report.overall_pass, "Foundation scenario failed");
    assert_eq!(report.scenario_id, "DMC-FOUNDATION-ENG-001");
    assert_eq!(report.department, "Engineering");
    assert_eq!(report.requested_action, "run_unit_tests");
    assert_eq!(report.policy_decision, "allow");
    assert!(report.execution_authorized);
    assert_eq!(report.execution_outcome, "ExecutedSuccessfully");

    assert_eq!(report.audit_events.len(), 1);
    let ev = &report.audit_events[0];
    assert_eq!(ev.sequence, 1);
    assert_eq!(ev.decision, "allow");
    assert_eq!(
        ev.resource,
        "dmc://engineering/workspaces/ci/test-runner/suite"
    );

    assert_eq!(report.acceptance_criteria.len(), 6);
    for criterion in &report.acceptance_criteria {
        assert!(
            criterion.passed,
            "Criterion failed: {} - {}",
            criterion.name, criterion.detail
        );
    }
}

#[test]
fn test_security_scenarios_enforce_all_defenses() {
    let sec_reports = run_all_security_scenarios();
    assert_eq!(sec_reports.len(), 9);

    for r in &sec_reports {
        assert!(
            r.overall_pass,
            "Security scenario failed: {} - {:?}",
            r.scenario_id, r.acceptance_criteria
        );
    }

    // Verify critical invariant: Scenarios 1 to 6 all resulted in policy denial and prevented execution
    for r in &sec_reports[0..6] {
        assert_eq!(r.policy_decision, "deny");
        assert!(!r.execution_authorized);
        assert_eq!(r.execution_outcome, "PreventedByPolicy");
    }

    // Scenario 7 (Audit consistency) verified monotonic sequences
    let r7 = &sec_reports[6];
    assert_eq!(r7.scenario_id, "DMC-SEC-007-AUDIT-CONSISTENCY");
    assert_eq!(r7.audit_events.len(), 2);
    assert_eq!(r7.audit_events[0].sequence, 1);
    assert_eq!(r7.audit_events[1].sequence, 2);

    // Scenario 8 (Execution failure) captured failure accurately
    let r8 = &sec_reports[7];
    assert_eq!(r8.scenario_id, "DMC-SEC-008-EXECUTION-FAILURE");
    assert!(r8.execution_outcome.starts_with("ExecutionFailed"));

    // Scenario 9 (Audit failure) blocked success reporting
    let r9 = &sec_reports[8];
    assert_eq!(r9.scenario_id, "DMC-SEC-009-AUDIT-FAILURE");
    assert_eq!(
        r9.execution_outcome,
        "AuditFailurePreventedSuccessfulCompletion"
    );
}

#[test]
fn test_json_reporting_serialization() {
    let report = run_foundation_scenario();
    let json = report_to_json(&report);

    assert!(json.contains("\"scenario_id\": \"DMC-FOUNDATION-ENG-001\""));
    assert!(json.contains("\"policy_decision\": \"allow\""));
    assert!(json.contains("\"execution_authorized\": true"));
    assert!(json.contains("\"overall_pass\": true"));

    let suite = vec![report];
    let suite_json = report_suite_to_json(&suite);
    assert!(suite_json.contains("\"suite_total\": 1"));
    assert!(suite_json.contains("\"suite_passed\": 1"));
    assert!(suite_json.contains("\"all_passed\": true"));

    let empty_json = report_suite_to_json(&[]);
    assert!(empty_json.contains("\"suite_total\": 0"));
    assert!(empty_json.contains("\"suite_passed\": 0"));
    assert!(empty_json.contains("\"all_passed\": false"));
    assert!(empty_json.contains("\"scenarios\": []"));
}

#[test]
fn test_delegating_ancestor_revocation_fails_closed() {
    use dmc_types::{
        Action, AgentId, AgentIdentityClaim, AutonomyLevel, Decision, DelegationId,
        DelegationRecord, ProcessAuthorityBinding, ProcessCreationContext, ProcessProvenance,
        RdaProcessId, ResourceScope, RevocationStatus, TaskId,
    };
    use titan_identity::{
        AuthorizedPolicyRequest, ProvenanceTracker, ProvisionalAgentEntry,
        ProvisionalIdentityRegistry,
    };
    use titan_policy_core::policy_evaluate_strict_provenance;

    let mut registry = ProvisionalIdentityRegistry::new("test-ancestor-revocation-reg");
    let lead_id = AgentId::new("test-lead").unwrap();
    let worker_id = AgentId::new("test-worker").unwrap();

    registry
        .register_agent(ProvisionalAgentEntry {
            agent_id: lead_id.clone(),
            department: "Engineering".to_string(),
            max_autonomy: AutonomyLevel::E3InternalOperations,
            revocation_reason: None,
        })
        .unwrap();

    registry
        .register_agent(ProvisionalAgentEntry {
            agent_id: worker_id.clone(),
            department: "Engineering".to_string(),
            max_autonomy: AutonomyLevel::E2Sandbox,
            revocation_reason: None,
        })
        .unwrap();

    let lead_resolved = registry
        .resolve_claim(&AgentIdentityClaim {
            agent_id: "test-lead".to_string(),
            department: "Engineering".to_string(),
            claimed_autonomy: AutonomyLevel::E3InternalOperations,
        })
        .unwrap();

    let worker_resolved = registry
        .resolve_claim(&AgentIdentityClaim {
            agent_id: "test-worker".to_string(),
            department: "Engineering".to_string(),
            claimed_autonomy: AutonomyLevel::E2Sandbox,
        })
        .unwrap();

    let mut tracker = ProvenanceTracker::new();
    let root_scope = ResourceScope::new(vec!["dmc://engineering/workspaces".to_string()]).unwrap();
    let root_proc_id = RdaProcessId::new("proc-test-root").unwrap();
    let root_process = ProcessProvenance {
        process_id: root_proc_id.clone(),
        parent_agent_id: lead_id.clone(),
        parent_process_id: None,
        originating_task_id: TaskId::new("task-test-root").unwrap(),
        creation_context: ProcessCreationContext {
            created_at_epoch_secs: 1_000,
            environment: "test".to_string(),
            purpose: "root proc".to_string(),
        },
        authority: ProcessAuthorityBinding::DirectAgentAuthority {
            effective_autonomy: AutonomyLevel::E3InternalOperations,
            permitted_actions: vec![Action::RunUnitTests],
            resource_scope: root_scope,
        },
    };
    tracker
        .register_process(root_process.clone(), 1_000)
        .unwrap();

    let worker_proc_id = RdaProcessId::new("proc-test-worker").unwrap();
    let del_id = DelegationId::new("del-test-01").unwrap();
    let delegation_scope =
        ResourceScope::new(vec!["dmc://engineering/workspaces/ci".to_string()]).unwrap();

    let delegation = DelegationRecord {
        delegation_id: del_id.clone(),
        issuer: lead_id.clone(),
        recipient: worker_id.clone(),
        recipient_process: Some(worker_proc_id.clone()),
        max_autonomy: AutonomyLevel::E2Sandbox,
        permitted_actions: vec![Action::RunUnitTests],
        resource_scope: delegation_scope.clone(),
        issued_at_epoch_secs: 1_050,
        expires_at_epoch_secs: 3_000,
        revocation_status: RevocationStatus::Active,
        parent_delegation_id: None,
    };
    tracker
        .register_delegation(delegation.clone(), &lead_resolved, 1_050)
        .unwrap();

    let worker_process = ProcessProvenance {
        process_id: worker_proc_id,
        parent_agent_id: worker_id,
        parent_process_id: Some(root_proc_id),
        originating_task_id: TaskId::new("task-test-worker").unwrap(),
        creation_context: ProcessCreationContext {
            created_at_epoch_secs: 1_100,
            environment: "test".to_string(),
            purpose: "worker proc".to_string(),
        },
        authority: ProcessAuthorityBinding::DelegatedAuthority {
            delegation_id: del_id,
            effective_autonomy: AutonomyLevel::E2Sandbox,
            permitted_actions: vec![Action::RunUnitTests],
            resource_scope: delegation_scope,
        },
    };
    tracker
        .register_process(worker_process.clone(), 1_100)
        .unwrap();

    // REVOCATION ATTACK: Revoking the delegating superior (Lead agent)
    registry
        .revoke_agent(&lead_id, "lead agent compromised")
        .unwrap();

    let request = AuthorizedPolicyRequest {
        identity: Some(worker_resolved),
        process: Some(worker_process),
        parent_process: Some(root_process),
        delegation: Some(delegation),
        parent_delegation: None,
        action: Action::RunUnitTests,
        resource: "dmc://engineering/workspaces/ci/test".to_string(),
        policy_version: "dmc-v1".to_string(),
        evaluation_epoch_secs: 1_200,
    };

    let result = policy_evaluate_strict_provenance(&request, &registry, &tracker);
    assert_eq!(result.decision, Decision::Deny);
    assert!(!result.execution_authorized());
}

#[test]
fn test_delegation_expiration_fails_closed() {
    use dmc_types::{
        Action, AgentId, AgentIdentityClaim, AutonomyLevel, Decision, DelegationId,
        DelegationRecord, ProcessAuthorityBinding, ProcessCreationContext, ProcessProvenance,
        RdaProcessId, ResourceScope, RevocationStatus, TaskId,
    };
    use titan_identity::{
        AuthorizedPolicyRequest, ProvenanceTracker, ProvisionalAgentEntry,
        ProvisionalIdentityRegistry,
    };
    use titan_policy_core::policy_evaluate_strict_provenance;

    let mut registry = ProvisionalIdentityRegistry::new("test-expiration-reg");
    let lead_id = AgentId::new("lead-exp").unwrap();
    let worker_id = AgentId::new("worker-exp").unwrap();

    registry
        .register_agent(ProvisionalAgentEntry {
            agent_id: lead_id.clone(),
            department: "Engineering".to_string(),
            max_autonomy: AutonomyLevel::E3InternalOperations,
            revocation_reason: None,
        })
        .unwrap();

    registry
        .register_agent(ProvisionalAgentEntry {
            agent_id: worker_id.clone(),
            department: "Engineering".to_string(),
            max_autonomy: AutonomyLevel::E2Sandbox,
            revocation_reason: None,
        })
        .unwrap();

    let lead_resolved = registry
        .resolve_claim(&AgentIdentityClaim {
            agent_id: "lead-exp".to_string(),
            department: "Engineering".to_string(),
            claimed_autonomy: AutonomyLevel::E3InternalOperations,
        })
        .unwrap();

    let worker_resolved = registry
        .resolve_claim(&AgentIdentityClaim {
            agent_id: "worker-exp".to_string(),
            department: "Engineering".to_string(),
            claimed_autonomy: AutonomyLevel::E2Sandbox,
        })
        .unwrap();

    let mut tracker = ProvenanceTracker::new();
    let root_proc_id = RdaProcessId::new("proc-root-exp").unwrap();
    let root_scope = ResourceScope::new(vec!["dmc://engineering".to_string()]).unwrap();
    let root_process = ProcessProvenance {
        process_id: root_proc_id.clone(),
        parent_agent_id: lead_id.clone(),
        parent_process_id: None,
        originating_task_id: TaskId::new("task-root-exp").unwrap(),
        creation_context: ProcessCreationContext {
            created_at_epoch_secs: 1_000,
            environment: "test".to_string(),
            purpose: "root exp".to_string(),
        },
        authority: ProcessAuthorityBinding::DirectAgentAuthority {
            effective_autonomy: AutonomyLevel::E3InternalOperations,
            permitted_actions: vec![Action::RunUnitTests],
            resource_scope: root_scope,
        },
    };
    tracker
        .register_process(root_process.clone(), 1_000)
        .unwrap();

    let worker_proc_id = RdaProcessId::new("proc-worker-exp").unwrap();
    let del_id = DelegationId::new("del-exp-01").unwrap();
    let del_scope = ResourceScope::new(vec!["dmc://engineering/workspaces".to_string()]).unwrap();

    let delegation = DelegationRecord {
        delegation_id: del_id.clone(),
        issuer: lead_id,
        recipient: worker_id.clone(),
        recipient_process: Some(worker_proc_id.clone()),
        max_autonomy: AutonomyLevel::E2Sandbox,
        permitted_actions: vec![Action::RunUnitTests],
        resource_scope: del_scope.clone(),
        issued_at_epoch_secs: 1_050,
        expires_at_epoch_secs: 2_000, // Expires at epoch 2000
        revocation_status: RevocationStatus::Active,
        parent_delegation_id: None,
    };
    tracker
        .register_delegation(delegation.clone(), &lead_resolved, 1_050)
        .unwrap();

    let worker_process = ProcessProvenance {
        process_id: worker_proc_id,
        parent_agent_id: worker_id,
        parent_process_id: Some(root_proc_id),
        originating_task_id: TaskId::new("task-worker-exp").unwrap(),
        creation_context: ProcessCreationContext {
            created_at_epoch_secs: 1_100,
            environment: "test".to_string(),
            purpose: "worker exp".to_string(),
        },
        authority: ProcessAuthorityBinding::DelegatedAuthority {
            delegation_id: del_id,
            effective_autonomy: AutonomyLevel::E2Sandbox,
            permitted_actions: vec![Action::RunUnitTests],
            resource_scope: del_scope,
        },
    };
    tracker
        .register_process(worker_process.clone(), 1_100)
        .unwrap();

    // REQUEST AT EXPIRED TIMESTAMP: epoch 2_001 > expires_at 2_000
    let request = AuthorizedPolicyRequest {
        identity: Some(worker_resolved),
        process: Some(worker_process),
        parent_process: Some(root_process),
        delegation: Some(delegation),
        parent_delegation: None,
        action: Action::RunUnitTests,
        resource: "dmc://engineering/workspaces/test".to_string(),
        policy_version: "dmc-v1".to_string(),
        evaluation_epoch_secs: 2_001,
    };

    let result = policy_evaluate_strict_provenance(&request, &registry, &tracker);
    assert_eq!(result.decision, Decision::Deny);
    assert!(!result.execution_authorized());
}

#[test]
fn test_e5_reserved_authority_fails_closed() {
    use dmc_types::{
        Action, AgentId, AgentIdentity, AgentIdentityClaim, AutonomyLevel, Decision, PolicyRequest,
    };
    use titan_identity::{
        AuthorizedPolicyRequest, IdentityError, ProvenanceTracker, ProvisionalAgentEntry,
        ProvisionalIdentityRegistry,
    };
    use titan_policy_core::{policy_evaluate, policy_evaluate_strict_provenance};

    let mut registry = ProvisionalIdentityRegistry::new("test-e5-reg");
    let founder_id = AgentId::new("founder-sim").unwrap();

    // Invariant 1: Registering an agent at E5 fails closed
    let reg_res = registry.register_agent(ProvisionalAgentEntry {
        agent_id: founder_id.clone(),
        department: "Executive".to_string(),
        max_autonomy: AutonomyLevel::E5ReservedAuthority,
        revocation_reason: None,
    });
    assert_eq!(reg_res, Err(IdentityError::ReservedAuthorityNotResolvable));

    // Invariant 2: Resolving an E5 claim fails closed
    let resolve_res = registry.resolve_claim(&AgentIdentityClaim {
        agent_id: "founder-sim".to_string(),
        department: "Executive".to_string(),
        claimed_autonomy: AutonomyLevel::E5ReservedAuthority,
    });
    assert_eq!(
        resolve_res,
        Err(IdentityError::ReservedAuthorityNotResolvable)
    );

    // Invariant 3: Legacy PolicyRequest with E5 fails closed (Decision::Deny)
    let legacy_req = PolicyRequest {
        agent: Some(AgentIdentity {
            agent_id: "founder-sim".to_string(),
            department: "Executive".to_string(),
            autonomy: AutonomyLevel::E5ReservedAuthority,
        }),
        action: Action::ReadKnowledge,
        resource: "dmc://executive/constitution".to_string(),
        policy_version: "v0.1-m1".to_string(),
    };
    let legacy_res = policy_evaluate(&legacy_req);
    assert_eq!(legacy_res.decision, Decision::Deny);
    assert!(!legacy_res.execution_authorized());

    // Invariant 4: Strict evaluation without resolved identity fails closed
    let tracker = ProvenanceTracker::new();
    let auth_req = AuthorizedPolicyRequest {
        identity: None,
        process: None,
        parent_process: None,
        delegation: None,
        parent_delegation: None,
        action: Action::ReadKnowledge,
        resource: "dmc://executive/constitution".to_string(),
        policy_version: "dmc-v1".to_string(),
        evaluation_epoch_secs: 1_200,
    };
    let strict_res = policy_evaluate_strict_provenance(&auth_req, &registry, &tracker);
    assert_eq!(strict_res.decision, Decision::Deny);
    assert!(!strict_res.execution_authorized());
}

#[test]
fn test_custom_output_dir_configuration() {
    use dmc_simulator::report::save_report;
    use std::fs;

    let temp_dir = "output/test_custom_dir_tmp";
    std::env::set_var("DMC_OUTPUT_DIR", temp_dir);

    let res = save_report("custom_test.json", "{\"test\": true}");
    assert!(res.is_ok());
    let path = res.unwrap();
    assert!(path.exists());
    assert_eq!(fs::read_to_string(&path).unwrap(), "{\"test\": true}");

    // Cleanup
    let _ = fs::remove_file(&path);
    let _ = fs::remove_dir(temp_dir);
    std::env::remove_var("DMC_OUTPUT_DIR");
}
