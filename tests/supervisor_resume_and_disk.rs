// Integration tests for resume and disk‑space guard.

use std::process::Command;
use tempfile::tempdir;
use std::fs;
use std::path::Path;

#[test]
fn test_resume_functionality() {
    let dir = tempdir().unwrap();
    let out_path = dir.path().join("out");
    // First run: 1 cycle.
    let status = Command::new("cargo")
        .args(&["run", "--bin", "dmc-supervisor", "--", "--max-cycles", "1", "--output-dir", out_path.to_str().unwrap()])
        .status()
        .expect("failed to execute supervisor");
    assert!(status.success());
    // Ensure first cycle file exists.
    let first_cycle = out_path.join("cycle_0000.json");
    assert!(first_cycle.exists(), "first cycle file missing");
    // Second run: resume with max-cycles 2 (should produce only second cycle).
    let status = Command::new("cargo")
        .args(&["run", "--bin", "dmc-supervisor", "--", "--max-cycles", "2", "--resume", "true", "--output-dir", out_path.to_str().unwrap()])
        .status()
        .expect("failed to execute supervisor resume");
    assert!(status.success());
    // Second cycle file should now exist.
    let second_cycle = out_path.join("cycle_0001.json");
    assert!(second_cycle.exists(), "second cycle file missing after resume");
    // Ensure no duplicate first cycle.
    let metadata = fs::metadata(first_cycle).unwrap();
    assert!(metadata.is_file());
}

#[test]
fn test_disk_guard_skips_when_insufficient_space() {
    let dir = tempdir().unwrap();
    let out_path = dir.path().join("out");
    // Use an unrealistically high free‑disk requirement.
    let status = Command::new("cargo")
        .args(&["run", "--bin", "dmc-supervisor", "--", "--min-free-disk-mb", "999999", "--output-dir", out_path.to_str().unwrap()])
        .status()
        .expect("failed to execute supervisor");
    // Should exit successfully (no error), but no evidence files should be created.
    assert!(status.success());
    assert!(!out_path.join("event.log").exists(), "event.log should not be created when disk guard triggers");
    assert!(!out_path.join("cycle_0000.json").exists(), "cycle file should not be created when disk guard triggers");
}
