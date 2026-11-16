//! Tests for transactional behavior of report persistence.

use std::env;
use std::fs;
use std::path::Path;
use std::os::unix::fs::PermissionsExt;

use dmc_simulator::runner::execute_foundation;

#[test]
fn test_no_partial_temp_file_left_on_failure() {
    // Setup a temporary output directory that is read‑only to force write failure.
    let tmp_dir = env::temp_dir().join("dmc_txn_test");
    let _ = fs::create_dir_all(&tmp_dir);
    let perm = fs::Permissions::from_mode(0o500);
    let _ = fs::set_permissions(&tmp_dir, perm);
    env::set_var("DMC_OUTPUT_DIR", &tmp_dir);

    // Capture existing entries (should be empty).
    let before: Vec<_> = fs::read_dir(&tmp_dir).unwrap().map(|e| e.unwrap().file_name()).collect();

    // Run foundation – it will fail to write the report.
    let _ = execute_foundation(false);

    // Restore permissions for cleanup.
    let perm_writable = fs::Permissions::from_mode(0o700);
    let _ = fs::set_permissions(&tmp_dir, perm_writable);

    // After execution there should be no new files (including temp files).
    let after: Vec<_> = fs::read_dir(&tmp_dir).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(before, after, "No temporary files should remain after a failed report write");
    let _ = fs::remove_dir_all(&tmp_dir);
}
