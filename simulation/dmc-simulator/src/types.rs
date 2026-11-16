//! Domain types and report structures for DMC simulation scenarios.

/// Individual acceptance criterion evaluation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptanceCriterion {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

impl AcceptanceCriterion {
    pub fn new(name: impl Into<String>, passed: bool, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            passed,
            detail: detail.into(),
        }
    }
}

/// Concise summary of an audit event emitted during a simulation run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEventSummary {
    pub event_id: String,
    pub sequence: u64,
    pub event_kind: String,
    pub decision: String,
    pub resource: String,
}

/// Comprehensive report produced by executing a simulation scenario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimulationReport {
    pub scenario_id: String,
    pub simulation_run_id: String,
    pub agent_identity: String,
    pub department: String,
    pub requested_action: String,
    pub identity_verification_result: String,
    pub provenance_verification_result: String,
    pub policy_decision: String,
    pub policy_reason: String,
    pub execution_authorized: bool,
    pub execution_outcome: String,
    pub audit_events: Vec<AuditEventSummary>,
    pub acceptance_criteria: Vec<AcceptanceCriterion>,
    pub overall_pass: bool,
    pub details: Vec<String>,
}

impl SimulationReport {
    /// Evaluates `overall_pass` by checking that all acceptance criteria passed.
    pub fn compute_overall_pass(&self) -> bool {
        !self.acceptance_criteria.is_empty() && self.acceptance_criteria.iter().all(|c| c.passed)
    }

    /// Constructs a new [`SimulationReport`], automatically computing `overall_pass` from acceptance criteria.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scenario_id: impl Into<String>,
        simulation_run_id: impl Into<String>,
        agent_identity: impl Into<String>,
        department: impl Into<String>,
        requested_action: impl Into<String>,
        identity_verification_result: impl Into<String>,
        provenance_verification_result: impl Into<String>,
        policy_decision: impl Into<String>,
        policy_reason: impl Into<String>,
        execution_authorized: bool,
        execution_outcome: impl Into<String>,
        audit_events: Vec<AuditEventSummary>,
        acceptance_criteria: Vec<AcceptanceCriterion>,
        details: Vec<String>,
    ) -> Self {
        let mut report = Self {
            scenario_id: scenario_id.into(),
            simulation_run_id: simulation_run_id.into(),
            agent_identity: agent_identity.into(),
            department: department.into(),
            requested_action: requested_action.into(),
            identity_verification_result: identity_verification_result.into(),
            provenance_verification_result: provenance_verification_result.into(),
            policy_decision: policy_decision.into(),
            policy_reason: policy_reason.into(),
            execution_authorized,
            execution_outcome: execution_outcome.into(),
            audit_events,
            acceptance_criteria,
            overall_pass: false,
            details,
        };
        report.overall_pass = report.compute_overall_pass();
        report
    }
}
