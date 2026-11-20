// Integration test for dmc-supervisor

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use tempfile::tempdir;
    use dmc_supervisor::config::Config;
    use dmc_supervisor::runner::run_supervisor;
    use dmc_supervisor::uuid_util::new_suite_uuid;

    #[test]
    fn test_supervisor_basic_cycle() {
        // Create temporary output directory
        let dir = tempdir().expect("tempdir");
        let out_path = dir.path().to_path_buf();

        // Build config directly
        let config = Config {
            suite_mode: "foundation".to_string(),
            max_cycles: 1,
            simulator_bin: PathBuf::from("target/debug/dmc-simulator"),
            output_dir: out_path.clone(),
            json_output: false,
            resume: false,
            min_free_disk_mb: 0,
            max_mem_mb: 0,
        };

        // Run supervisor
        run_supervisor(config).expect("run_supervisor");

        // Verify files exist
        let cycle_file = out_path.join("cycle_0000.json");
        let log_file = out_path.join("event.log");
        let ck_file = out_path.join("checkpoint.json");

        assert!(cycle_file.exists(), "cycle file missing");
        assert!(log_file.exists(), "event log missing");
        assert!(ck_file.exists(), "checkpoint missing");

        // Validate JSON structure of cycle file
        let data = fs::read_to_string(&cycle_file).expect("read cycle");
        let v: serde_json::Value = serde_json::from_str(&data).expect("parse json");
        assert!(v.get("suite_id").is_some(), "suite_id missing");
        assert!(v.get("suite_timestamp").is_some(), "suite_timestamp missing");
        assert!(v.get("supervisor_version").is_some(), "version missing");
        assert!(v.get("report").is_some(), "report missing");
    }
}
