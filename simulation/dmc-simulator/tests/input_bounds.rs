//! Tests for input identifier bounds.

use dmc_simulator::report::validate_report_identifiers;
use dmc_simulator::types::SimulationReport;

#[test]
fn test_identifier_exceeds_max_length() {
    // Create a report with an excessively long scenario_id (UTF-8 byte length > 128).
    let long_str = "a".repeat(200); // 200 bytes > 128.
    let report = SimulationReport {
        scenario_id: long_str.clone(),
        simulation_run_id: "run1".into(),
        agent_identity: "agent1".into(),
        department: "dept".into(),
        requested_action: "action".into(),
        identity_verification_result: "ok".into(),
        provenance_verification_result: "ok".into(),
        policy_decision: "allow".into(),
        policy_reason: "reason".into(),
        execution_authorized: true,
        execution_outcome: "outcome".into(),
        audit_events: Vec::new(),
        acceptance_criteria: Vec::new(),
        overall_pass: true,
        details: Vec::new(),
    };
    let res = validate_report_identifiers(&report);
    assert!(
        res.is_err(),
        "Identifier length validation should fail for overly long strings"
    );
}
