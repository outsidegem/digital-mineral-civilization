//! Serialization, formatting, and file export for simulation reports.

use std::fs;
use std::path::{Path, PathBuf};

use crate::types::{AcceptanceCriterion, AuditEventSummary, SimulationReport};

/// Escapes a string slice for inclusion in a JSON string literal.
pub fn escape_json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 32 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Converts an [`AcceptanceCriterion`] to a pretty-printed JSON fragment.
fn criterion_to_json(c: &AcceptanceCriterion, indent: &str) -> String {
    format!(
        "{indent}{{\n\
         {indent}  \"name\": \"{}\",\n\
         {indent}  \"passed\": {},\n\
         {indent}  \"detail\": \"{}\"\n\
         {indent}}}",
        escape_json_str(&c.name),
        c.passed,
        escape_json_str(&c.detail)
    )
}

/// Converts an [`AuditEventSummary`] to a pretty-printed JSON fragment.
fn audit_event_to_json(e: &AuditEventSummary, indent: &str) -> String {
    format!(
        "{indent}{{\n\
         {indent}  \"event_id\": \"{}\",\n\
         {indent}  \"sequence\": {},\n\
         {indent}  \"event_kind\": \"{}\",\n\
         {indent}  \"decision\": \"{}\",\n\
         {indent}  \"resource\": \"{}\"\n\
         {indent}}}",
        escape_json_str(&e.event_id),
        e.sequence,
        escape_json_str(&e.event_kind),
        escape_json_str(&e.decision),
        escape_json_str(&e.resource)
    )
}

/// Serializes a [`SimulationReport`] into a pretty-printed JSON string.
pub fn report_to_json(report: &SimulationReport) -> String {
    let criteria_block = if report.acceptance_criteria.is_empty() {
        "[]".to_string()
    } else {
        let mut criteria_json = Vec::with_capacity(report.acceptance_criteria.len());
        for c in &report.acceptance_criteria {
            criteria_json.push(criterion_to_json(c, "    "));
        }
        format!("[\n{}\n  ]", criteria_json.join(",\n"))
    };

    let audit_block = if report.audit_events.is_empty() {
        "[]".to_string()
    } else {
        let mut audit_json = Vec::with_capacity(report.audit_events.len());
        for a in &report.audit_events {
            audit_json.push(audit_event_to_json(a, "    "));
        }
        format!("[\n{}\n  ]", audit_json.join(",\n"))
    };

    let details_block = if report.details.is_empty() {
        "[]".to_string()
    } else {
        let mut details_json = Vec::with_capacity(report.details.len());
        for d in &report.details {
            details_json.push(format!("    \"{}\"", escape_json_str(d)));
        }
        format!("[\n{}\n  ]", details_json.join(",\n"))
    };

    format!(
        "{{\n\
         \"scenario_id\": \"{}\",\n\
         \"simulation_run_id\": \"{}\",\n\
         \"agent_identity\": \"{}\",\n\
         \"department\": \"{}\",\n\
         \"requested_action\": \"{}\",\n\
         \"identity_verification_result\": \"{}\",\n\
         \"provenance_verification_result\": \"{}\",\n\
         \"policy_decision\": \"{}\",\n\
         \"policy_reason\": \"{}\",\n\
         \"execution_authorized\": {},\n\
         \"execution_outcome\": \"{}\",\n\
         \"audit_events\": {},\n\
         \"acceptance_criteria\": {},\n\
         \"overall_pass\": {},\n\
         \"details\": {}\n\
         }}\n",
        escape_json_str(&report.scenario_id),
        escape_json_str(&report.simulation_run_id),
        escape_json_str(&report.agent_identity),
        escape_json_str(&report.department),
        escape_json_str(&report.requested_action),
        escape_json_str(&report.identity_verification_result),
        escape_json_str(&report.provenance_verification_result),
        escape_json_str(&report.policy_decision),
        escape_json_str(&report.policy_reason),
        report.execution_authorized,
        escape_json_str(&report.execution_outcome),
        audit_block,
        criteria_block,
        report.overall_pass,
        details_block,
    )
}

/// Serializes a slice of [`SimulationReport`] into a unified summary JSON string.
pub fn report_suite_to_json(reports: &[SimulationReport]) -> String {
    let all_passed = !reports.is_empty() && reports.iter().all(|r| r.overall_pass);
    let scenarios_block = if reports.is_empty() {
        "[]".to_string()
    } else {
        let mut report_strings = Vec::with_capacity(reports.len());
        for r in reports {
            let json_single = report_to_json(r);
            let indented: String = json_single
                .lines()
                .map(|line| format!("    {line}"))
                .collect::<Vec<_>>()
                .join("\n");
            report_strings.push(indented);
        }
        format!("[\n{}\n  ]", report_strings.join(",\n"))
    };

    format!(
        "{{\n\
         \"suite_total\": {},\n\
         \"suite_passed\": {},\n\
         \"all_passed\": {},\n\
         \"scenarios\": {}\n\
         }}\n",
        reports.len(),
        reports.iter().filter(|r| r.overall_pass).count(),
        all_passed,
        scenarios_block
    )
}

/// Writes a report JSON file to the target output directory, creating parents as needed.
pub fn save_report(filename: &str, content: &str) -> std::io::Result<PathBuf> {
    let output_dir_str = std::env::var("DMC_OUTPUT_DIR").unwrap_or_else(|_| "output".to_string());
    let output_dir = Path::new(&output_dir_str);
    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
    }
    let target_path = output_dir.join(filename);
    fs::write(&target_path, content)?;
    Ok(target_path)
}

/// Prints a human-readable terminal summary of a simulation report.
pub fn print_terminal_summary(report: &SimulationReport) {
    let status_badge = if report.overall_pass {
        "\x1b[32m[PASS]\x1b[0m"
    } else {
        "\x1b[31m[FAIL]\x1b[0m"
    };

    println!("================================================================================");
    println!(
        "  DMC SIMULATION REPORT: {} {}",
        report.scenario_id, status_badge
    );
    println!("================================================================================");
    println!("  Run ID               : {}", report.simulation_run_id);
    println!("  Agent Identity       : {}", report.agent_identity);
    println!("  Department           : {}", report.department);
    println!("  Requested Action     : {}", report.requested_action);
    println!(
        "  Identity Status      : {}",
        report.identity_verification_result
    );
    println!(
        "  Provenance Status    : {}",
        report.provenance_verification_result
    );
    println!("  Policy Decision      : {}", report.policy_decision);
    println!("  Execution Authorized : {}", report.execution_authorized);
    println!("  Execution Outcome    : {}", report.execution_outcome);
    println!("--------------------------------------------------------------------------------");
    println!("  Acceptance Criteria:");
    for c in &report.acceptance_criteria {
        let mark = if c.passed { "  ✓" } else { "  ✗" };
        println!("  {} {:<30} : {}", mark, c.name, c.detail);
    }
    if !report.audit_events.is_empty() {
        println!(
            "--------------------------------------------------------------------------------"
        );
        println!("  Audit Events ({}):", report.audit_events.len());
        for ev in &report.audit_events {
            println!(
                "    [Seq {:04}] ID: {:<14} | Decision: {:<5} | Resource: {}",
                ev.sequence, ev.event_id, ev.decision, ev.resource
            );
        }
    }
    println!("================================================================================\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escaping_handles_special_characters() {
        assert_eq!(escape_json_str("simple"), "simple");
        assert_eq!(escape_json_str("quote\"slash\\"), "quote\\\"slash\\\\");
        assert_eq!(escape_json_str("newline\nand\ttab"), "newline\\nand\\ttab");
    }

    #[test]
    fn report_to_json_generates_valid_structure() {
        let report = SimulationReport {
            scenario_id: "test-01".into(),
            simulation_run_id: "run-01".into(),
            agent_identity: "eng-agent".into(),
            department: "Engineering".into(),
            requested_action: "run_unit_tests".into(),
            identity_verification_result: "Verified".into(),
            provenance_verification_result: "Verified".into(),
            policy_decision: "Allow".into(),
            policy_reason: "allowed for test".into(),
            execution_authorized: true,
            execution_outcome: "Executed".into(),
            audit_events: vec![AuditEventSummary {
                event_id: "evt-01".into(),
                sequence: 1,
                event_kind: "policy.authorization_decision".into(),
                decision: "allow".into(),
                resource: "dmc://engineering/test".into(),
            }],
            acceptance_criteria: vec![AcceptanceCriterion::new(
                "auth_check",
                true,
                "Authorization granted",
            )],
            overall_pass: true,
            details: vec!["execution completed".into()],
        };

        let json = report_to_json(&report);
        assert!(json.contains("\"scenario_id\": \"test-01\""));
        assert!(json.contains("\"overall_pass\": true"));
        assert!(json.contains("\"audit_events\": ["));
        assert!(json.contains("\"sequence\": 1"));
    }
}
