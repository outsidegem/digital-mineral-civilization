//! Orchestrator for simulation execution and report generation.

use crate::report::{print_terminal_summary, report_suite_to_json, report_to_json, save_report};
use crate::scenarios::foundation::run_foundation_scenario;
use crate::scenarios::security::run_all_security_scenarios;
use crate::types::SimulationReport;

/// Executes the foundation scenario, writes reports, and outputs results.
pub fn execute_foundation(json_mode: bool) -> i32 {
    let report = run_foundation_scenario();
    let json_content = report_to_json(&report);

    // Save report to disk (ignored directory)
    match save_report("foundation_report.json", &json_content) {
        Ok(path) => {
            if !json_mode {
                println!("Report saved to: {}", path.display());
            }
        }
        Err(e) => {
            eprintln!("Warning: Failed to save report to disk: {e}");
        }
    }

    if json_mode {
        print!("{json_content}");
    } else {
        print_terminal_summary(&report);
    }

    if report.overall_pass {
        0
    } else {
        1
    }
}

/// Executes all scenarios (foundation + 9 security regression scenarios), writes reports, and outputs results.
pub fn execute_all(json_mode: bool) -> i32 {
    let mut reports: Vec<SimulationReport> = Vec::new();

    // 1. Foundation scenario
    let found_report = run_foundation_scenario();
    reports.push(found_report);

    // 2. All security regression scenarios
    let mut sec_reports = run_all_security_scenarios();
    reports.append(&mut sec_reports);

    let suite_json = report_suite_to_json(&reports);

    // Save suite report to disk
    match save_report("all_scenarios_report.json", &suite_json) {
        Ok(path) => {
            if !json_mode {
                println!("Suite report saved to: {}", path.display());
            }
        }
        Err(e) => {
            eprintln!("Warning: Failed to save report to disk: {e}");
        }
    }

    if json_mode {
        print!("{suite_json}");
    } else {
        for r in &reports {
            print_terminal_summary(r);
        }

        let total = reports.len();
        let passed = reports.iter().filter(|r| r.overall_pass).count();
        let failed = total - passed;

        println!(
            "================================================================================"
        );
        println!("  DMC SIMULATION SUITE EXECUTION SUMMARY");
        println!(
            "================================================================================"
        );
        println!("  Total Scenarios  : {total}");
        println!("  Passed           : {passed}");
        println!("  Failed           : {failed}");
        if failed == 0 {
            println!("  Overall Result   : \x1b[32mALL SCENARIOS PASSED\x1b[0m");
        } else {
            println!("  Overall Result   : \x1b[31mSOME SCENARIOS FAILED\x1b[0m");
        }
        println!(
            "================================================================================\n"
        );
    }

    if reports.iter().all(|r| r.overall_pass) {
        0
    } else {
        1
    }
}
