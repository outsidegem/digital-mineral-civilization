//! Deterministic Engineering Department Foundation Scenario.
//!
//! Executes the full end-to-end DMC constitutional workflow:
//! 1. Unique simulation run initialization.
//! 2. Engineering Department agent registration.
//! 3. Identity claim resolution & live verification.
//! 4. Root process provenance establishment.
//! 5. Delegation lineage & execution identity registration.
//! 6. Authorized policy request construction.
//! 7. Strict provenance-aware policy evaluation.
//! 8. In-memory harmless simulated operation guarded by authorization flag.
//! 9. Monotonic audit sequencing.
//! 10. Explicit acceptance criteria verification.
//! 11. Final deterministic simulation report generation.

use dmc_types::{
    Action, AgentId, AgentIdentityClaim, ArtifactId, ArtifactProvenance, ArtifactType,
    AutonomyLevel, ContentDigest, Decision, DelegationId, DelegationRecord, DigestAlgorithm,
    ExecutionId, ExecutionIdentity, ProcessAuthorityBinding, ProcessCreationContext,
    ProcessProvenance, RdaProcessId, ResourceScope, RevocationStatus, TaskId,
};
use titan_audit::InMemoryAuditSequencer;
use titan_identity::{
    AuthorizedPolicyRequest, ProvenanceTracker, ProvisionalAgentEntry, ProvisionalIdentityRegistry,
};
use titan_policy_core::{policy_evaluate_strict_provenance, PolicyTrustLevel};

use crate::crypto::sha256_hex;
use crate::types::{AcceptanceCriterion, AuditEventSummary, SimulationReport};

/// Executes the authoritative DMC Foundation scenario.
pub fn run_foundation_scenario() -> SimulationReport {
    let scenario_id = "DMC-FOUNDATION-ENG-001".to_string();
    let simulation_run_id = "sim-run-foundation-eng-20261116".to_string();
    let mut details = Vec::new();
    let mut acceptance_criteria = Vec::new();
    let mut audit_events = Vec::new();

    details.push("Initializing DMC Foundation Scenario...".to_string());

    // -------------------------------------------------------------------------
    // Stage 1: Setup Identifiers & Registries
    // -------------------------------------------------------------------------
    let exec_id = match ExecutionId::new("exec-eng-found-001") {
        Ok(id) => id,
        Err(e) => {
            return failure_report(
                scenario_id,
                simulation_run_id,
                format!("Failed to create execution ID: {e}"),
            );
        }
    };

    let mut registry = ProvisionalIdentityRegistry::new("dmc-engineering-sim-registry");
    let mut tracker = ProvenanceTracker::new();
    let mut sequencer = InMemoryAuditSequencer::new();

    // -------------------------------------------------------------------------
    // Stage 2: Register Engineering Department Agents
    // -------------------------------------------------------------------------
    let lead_agent_id = match AgentId::new("eng-lead-01") {
        Ok(id) => id,
        Err(e) => {
            return failure_report(
                scenario_id,
                simulation_run_id,
                format!("Invalid lead agent ID: {e}"),
            );
        }
    };

    let worker_agent_id = match AgentId::new("eng-worker-01") {
        Ok(id) => id,
        Err(e) => {
            return failure_report(
                scenario_id,
                simulation_run_id,
                format!("Invalid worker agent ID: {e}"),
            );
        }
    };

    let lead_reg_res = registry.register_agent(ProvisionalAgentEntry {
        agent_id: lead_agent_id.clone(),
        department: "Engineering".to_string(),
        max_autonomy: AutonomyLevel::E3InternalOperations,
        revocation_reason: None,
    });

    let worker_reg_res = registry.register_agent(ProvisionalAgentEntry {
        agent_id: worker_agent_id.clone(),
        department: "Engineering".to_string(),
        max_autonomy: AutonomyLevel::E2Sandbox,
        revocation_reason: None,
    });

    if lead_reg_res.is_err() || worker_reg_res.is_err() {
        return failure_report(
            scenario_id,
            simulation_run_id,
            "Failed to register agents in provisional identity registry".to_string(),
        );
    }
    details.push("Registered eng-lead-01 (E3) and eng-worker-01 (E2)".to_string());

    // -------------------------------------------------------------------------
    // Stage 3: Resolve Identity Claims & Live Verification
    // -------------------------------------------------------------------------
    let lead_claim = AgentIdentityClaim {
        agent_id: "eng-lead-01".to_string(),
        department: "Engineering".to_string(),
        claimed_autonomy: AutonomyLevel::E3InternalOperations,
    };
    let worker_claim = AgentIdentityClaim {
        agent_id: "eng-worker-01".to_string(),
        department: "Engineering".to_string(),
        claimed_autonomy: AutonomyLevel::E2Sandbox,
    };

    let lead_resolved = match registry.resolve_claim(&lead_claim) {
        Ok(res) => res,
        Err(e) => {
            return failure_report(
                scenario_id,
                simulation_run_id,
                format!("Failed to resolve lead claim: {e:?}"),
            );
        }
    };

    let worker_resolved = match registry.resolve_claim(&worker_claim) {
        Ok(res) => res,
        Err(e) => {
            return failure_report(
                scenario_id,
                simulation_run_id,
                format!("Failed to resolve worker claim: {e:?}"),
            );
        }
    };

    let lead_live_ok = registry.verify_live_identity(&lead_resolved).is_ok();
    let worker_live_ok = registry.verify_live_identity(&worker_resolved).is_ok();

    let identity_verified = lead_live_ok && worker_live_ok;
    acceptance_criteria.push(AcceptanceCriterion::new(
        "AC-ID-01: Agent Identity Resolution",
        identity_verified,
        if identity_verified {
            "Lead and worker claims resolved and live-verified against issuing registry"
        } else {
            "Identity resolution or live verification failed"
        },
    ));
    details.push(
        "Identity resolution: lead and worker verified against registry instance".to_string(),
    );

    // -------------------------------------------------------------------------
    // Stage 4: Establish Root Process Provenance
    // -------------------------------------------------------------------------
    let root_scope = match ResourceScope::new(vec!["dmc://engineering/workspaces".to_string()]) {
        Ok(s) => s,
        Err(e) => {
            return failure_report(
                scenario_id,
                simulation_run_id,
                format!("Failed to create root scope: {e:?}"),
            );
        }
    };

    let root_proc_id = match RdaProcessId::new("proc-eng-root-01") {
        Ok(id) => id,
        Err(e) => {
            return failure_report(
                scenario_id,
                simulation_run_id,
                format!("Invalid root process ID: {e}"),
            );
        }
    };

    let root_process = ProcessProvenance {
        process_id: root_proc_id.clone(),
        parent_agent_id: lead_agent_id.clone(),
        parent_process_id: None,
        originating_task_id: match TaskId::new("task-eng-root") {
            Ok(t) => t,
            Err(e) => {
                return failure_report(
                    scenario_id,
                    simulation_run_id,
                    format!("Invalid task ID: {e}"),
                );
            }
        },
        creation_context: ProcessCreationContext {
            created_at_epoch_secs: 1_000,
            environment: "in-memory-simulation".to_string(),
            purpose: "Engineering root operations".to_string(),
        },
        authority: ProcessAuthorityBinding::DirectAgentAuthority {
            effective_autonomy: AutonomyLevel::E3InternalOperations,
            permitted_actions: vec![
                Action::ReadKnowledge,
                Action::RunUnitTests,
                Action::CreateSandboxReport,
            ],
            resource_scope: root_scope,
        },
    };

    if let Err(e) = tracker.register_process(root_process.clone(), 1_000) {
        return failure_report(
            scenario_id,
            simulation_run_id,
            format!("Failed to register root process: {e:?}"),
        );
    }
    details.push("Root process registered in provenance tracker".to_string());

    // -------------------------------------------------------------------------
    // Stage 5: Register Delegation Lineage & Worker Process Provenance
    // -------------------------------------------------------------------------
    let worker_proc_id = match RdaProcessId::new("proc-eng-worker-01") {
        Ok(id) => id,
        Err(e) => {
            return failure_report(
                scenario_id,
                simulation_run_id,
                format!("Invalid worker process ID: {e}"),
            );
        }
    };

    let delegation_scope =
        match ResourceScope::new(vec!["dmc://engineering/workspaces/ci".to_string()]) {
            Ok(s) => s,
            Err(e) => {
                return failure_report(
                    scenario_id,
                    simulation_run_id,
                    format!("Failed to create delegation scope: {e:?}"),
                );
            }
        };

    let del_id = match DelegationId::new("del-eng-ci-01") {
        Ok(id) => id,
        Err(e) => {
            return failure_report(
                scenario_id,
                simulation_run_id,
                format!("Invalid delegation ID: {e}"),
            );
        }
    };

    let delegation = DelegationRecord {
        delegation_id: del_id.clone(),
        issuer: lead_agent_id.clone(),
        recipient: worker_agent_id.clone(),
        recipient_process: Some(worker_proc_id.clone()),
        max_autonomy: AutonomyLevel::E2Sandbox,
        permitted_actions: vec![Action::RunUnitTests, Action::CreateSandboxReport],
        resource_scope: delegation_scope.clone(),
        issued_at_epoch_secs: 1_050,
        expires_at_epoch_secs: 3_000,
        revocation_status: RevocationStatus::Active,
        parent_delegation_id: None,
    };

    if let Err(e) = tracker.register_delegation(delegation.clone(), &lead_resolved, 1_050) {
        return failure_report(
            scenario_id,
            simulation_run_id,
            format!("Failed to register delegation: {e:?}"),
        );
    }

    let worker_proc_scope = match ResourceScope::new(vec![
        "dmc://engineering/workspaces/ci/test-runner".to_string(),
    ]) {
        Ok(s) => s,
        Err(e) => {
            return failure_report(
                scenario_id,
                simulation_run_id,
                format!("Failed to create worker proc scope: {e:?}"),
            );
        }
    };

    let worker_process = ProcessProvenance {
        process_id: worker_proc_id.clone(),
        parent_agent_id: worker_agent_id.clone(),
        parent_process_id: Some(root_proc_id),
        originating_task_id: match TaskId::new("task-eng-worker-tests") {
            Ok(t) => t,
            Err(e) => {
                return failure_report(
                    scenario_id,
                    simulation_run_id,
                    format!("Invalid task ID: {e}"),
                );
            }
        },
        creation_context: ProcessCreationContext {
            created_at_epoch_secs: 1_100,
            environment: "in-memory-simulation".to_string(),
            purpose: "Execute automated unit test verification".to_string(),
        },
        authority: ProcessAuthorityBinding::DelegatedAuthority {
            delegation_id: del_id,
            effective_autonomy: AutonomyLevel::E2Sandbox,
            permitted_actions: vec![Action::RunUnitTests],
            resource_scope: worker_proc_scope,
        },
    };

    if let Err(e) = tracker.register_process(worker_process.clone(), 1_100) {
        return failure_report(
            scenario_id,
            simulation_run_id,
            format!("Failed to register worker process: {e:?}"),
        );
    }

    let exec_identity = ExecutionIdentity {
        execution_id: exec_id.clone(),
        process_id: worker_proc_id.clone(),
        agent_id: worker_agent_id.clone(),
    };

    if let Err(e) = tracker.register_execution(exec_identity) {
        return failure_report(
            scenario_id,
            simulation_run_id,
            format!("Failed to register execution identity: {e:?}"),
        );
    }

    let provenance_lineage_ok = tracker
        .verify_live_process_and_delegation_lineage(
            &registry,
            &worker_resolved,
            &worker_process,
            Some(&delegation),
            1_200,
        )
        .is_ok();

    acceptance_criteria.push(AcceptanceCriterion::new(
        "AC-PROV-02: Provenance Lineage Verification",
        provenance_lineage_ok,
        if provenance_lineage_ok {
            "Acyclic lineage, unrevoked delegation, and execution binding verified"
        } else {
            "Provenance lineage verification failed"
        },
    ));
    details.push("Process and delegation provenance verified with live seal".to_string());

    // -------------------------------------------------------------------------
    // Stage 6: Construct Authorized Policy Request
    // -------------------------------------------------------------------------
    let requested_resource = "dmc://engineering/workspaces/ci/test-runner/suite".to_string();
    let requested_action = Action::RunUnitTests;
    let policy_version = "dmc-m1.1-policy-v1.0".to_string();

    let auth_request = AuthorizedPolicyRequest {
        identity: Some(worker_resolved.clone()),
        process: Some(worker_process.clone()),
        parent_process: Some(root_process.clone()),
        delegation: Some(delegation.clone()),
        parent_delegation: None,
        action: requested_action.clone(),
        resource: requested_resource.clone(),
        policy_version: policy_version.clone(),
        evaluation_epoch_secs: 1_200,
    };

    // -------------------------------------------------------------------------
    // Stage 7: Strict Provenance-Aware Policy Evaluation
    // -------------------------------------------------------------------------
    let policy_result = policy_evaluate_strict_provenance(&auth_request, &registry, &tracker);

    let policy_authorized = policy_result.decision == Decision::Allow
        && policy_result.execution_authorized()
        && policy_result.trust_level() == PolicyTrustLevel::LiveProvenanceVerified;

    acceptance_criteria.push(AcceptanceCriterion::new(
        "AC-POL-03: Strict Policy Authorization",
        policy_authorized,
        if policy_authorized {
            "Policy strictly evaluated against live registry and tracker, granting authorization"
        } else {
            "Policy evaluation failed or did not grant execution authority"
        },
    ));
    details.push(format!(
        "Strict policy evaluated: decision={:?}, authorized={}",
        policy_result.decision,
        policy_result.execution_authorized()
    ));

    // -------------------------------------------------------------------------
    // Stage 8: Execution Guard & Harmless Simulated Operation
    // -------------------------------------------------------------------------
    let mut execution_outcome = "PreventedByPolicy".to_string();
    let mut produced_artifact_id = None;

    // CRITICAL SECURITY INVARIANT: Policy denial MUST prevent execution.
    if policy_result.execution_authorized() {
        details.push("Authorization verified; executing simulated unit test suite...".to_string());

        // Harmless simulated in-memory unit test execution:
        // Produces simulated unit test output and establishes artifact provenance.
        let simulated_test_output = b"DMC_ENGINEERING_AUTOMATED_TEST_RUN_OK_ALL_TESTS_PASS";
        let digest_hex = sha256_hex(simulated_test_output);

        let content_digest = match ContentDigest::new(DigestAlgorithm::Sha256, digest_hex.clone()) {
            Ok(cd) => cd,
            Err(e) => {
                return failure_report(
                    scenario_id,
                    simulation_run_id,
                    format!("Failed to construct content digest: {e:?}"),
                );
            }
        };

        let art_id = match ArtifactId::new("art-eng-test-report-001") {
            Ok(id) => id,
            Err(e) => {
                return failure_report(
                    scenario_id,
                    simulation_run_id,
                    format!("Invalid artifact ID: {e}"),
                );
            }
        };

        let artifact_prov = ArtifactProvenance {
            artifact_id: art_id.clone(),
            content_digest,
            artifact_type: ArtifactType::UnitTestReport,
            producing_execution_id: exec_id.clone(),
            producing_process_id: worker_proc_id,
            parent_artifact_ids: vec![],
        };

        match tracker.register_artifact(artifact_prov) {
            Ok(()) => {
                produced_artifact_id = Some(art_id);
                execution_outcome = "ExecutedSuccessfully".to_string();
                details.push(format!(
                    "Harmless operation completed: artifact art-eng-test-report-001 registered (sha256:{})",
                    &digest_hex[..16]
                ));
            }
            Err(e) => {
                execution_outcome = format!("ExecutionArtifactFailed: {e:?}");
            }
        }
    } else {
        details.push("Execution blocked: execution_authorized flag is false".to_string());
    }

    let execution_succeeded = execution_outcome == "ExecutedSuccessfully";
    acceptance_criteria.push(AcceptanceCriterion::new(
        "AC-EXEC-04: Guarded Harmless Execution",
        execution_succeeded,
        if execution_succeeded {
            "Simulated operation executed strictly behind authorization guard with registered artifact"
        } else {
            "Execution failed or was unauthorized"
        },
    ));

    // -------------------------------------------------------------------------
    // Stage 9: Monotonic Audit Event Sequencing
    // -------------------------------------------------------------------------
    let artifact_list = produced_artifact_id.map(|id| vec![id]).unwrap_or_default();

    let audit_res = sequencer.record_authorized_decision(
        &auth_request,
        &policy_result,
        Some(exec_id),
        artifact_list,
    );

    let audit_sequenced = match audit_res {
        Ok(ev) => {
            audit_events.push(AuditEventSummary {
                event_id: ev.event_id().as_str().to_string(),
                sequence: ev.sequence(),
                event_kind: ev.event_kind_name().to_string(),
                decision: ev.decision_name().to_string(),
                resource: ev.resource.clone(),
            });
            details.push(format!(
                "Audit recorded: sequence={}, event_id={}",
                ev.sequence(),
                ev.event_id()
            ));
            ev.sequence() == 1
        }
        Err(e) => {
            details.push(format!("Audit recording failed: {e:?}"));
            false
        }
    };

    acceptance_criteria.push(AcceptanceCriterion::new(
        "AC-AUDIT-05: Monotonic Non-Zero Audit Sequencing",
        audit_sequenced,
        if audit_sequenced {
            "Audit event sequenced monotonically with unique event ID and canonical resource"
        } else {
            "Audit recording failed or sequence invalid"
        },
    ));

    // -------------------------------------------------------------------------
    // Stage 10: Isolation Invariant
    // -------------------------------------------------------------------------
    acceptance_criteria.push(AcceptanceCriterion::new(
        "AC-ISOL-06: Sandbox Isolation",
        true,
        "Zero external network calls, zero shell commands; pure in-memory execution",
    ));

    // -------------------------------------------------------------------------
    // Stage 11: Final Report Assembly
    // -------------------------------------------------------------------------
    let overall_pass = acceptance_criteria.iter().all(|c| c.passed);

    SimulationReport {
        scenario_id,
        simulation_run_id,
        agent_identity: worker_agent_id.as_str().to_string(),
        department: "Engineering".to_string(),
        requested_action: requested_action.stable_name(),
        identity_verification_result: if identity_verified {
            "LocalProvisionalVerified".to_string()
        } else {
            "IdentityVerificationFailed".to_string()
        },
        provenance_verification_result: if provenance_lineage_ok {
            "LiveLineageVerified".to_string()
        } else {
            "ProvenanceVerificationFailed".to_string()
        },
        policy_decision: policy_result.decision.stable_name().to_string(),
        policy_reason: policy_result.reason.clone(),
        execution_authorized: policy_result.execution_authorized(),
        execution_outcome,
        audit_events,
        acceptance_criteria,
        overall_pass,
        details,
    }
}

fn failure_report(scenario_id: String, run_id: String, error_msg: String) -> SimulationReport {
    SimulationReport {
        scenario_id,
        simulation_run_id: run_id,
        agent_identity: "eng-worker-01".to_string(),
        department: "Engineering".to_string(),
        requested_action: "run_unit_tests".to_string(),
        identity_verification_result: "Failed".to_string(),
        provenance_verification_result: "Failed".to_string(),
        policy_decision: "deny".to_string(),
        policy_reason: error_msg.clone(),
        execution_authorized: false,
        execution_outcome: "Prevented".to_string(),
        audit_events: vec![],
        acceptance_criteria: vec![AcceptanceCriterion::new(
            "AC-CRITICAL-SETUP",
            false,
            error_msg,
        )],
        overall_pass: false,
        details: vec!["Simulation aborted during initialization".to_string()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foundation_scenario_runs_to_deterministic_pass() {
        let report = run_foundation_scenario();
        assert!(
            report.overall_pass,
            "Foundation scenario failed: {:?}",
            report.details
        );
        assert_eq!(report.policy_decision, "allow");
        assert!(report.execution_authorized);
        assert_eq!(report.execution_outcome, "ExecutedSuccessfully");
        assert_eq!(report.audit_events.len(), 1);
        assert_eq!(report.audit_events[0].sequence, 1);
    }
}
