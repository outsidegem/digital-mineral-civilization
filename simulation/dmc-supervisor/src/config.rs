// No imports needed here

/// Configuration parsed from CLI.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Config {
    /// Suite mode – forced to "all" for endurance runner.
    pub suite_mode: String,
    /// Number of cycles (default 1).
    pub max_cycles: u32,
    /// Path to the dmc‑simulator binary.
    pub simulator_bin: std::path::PathBuf,
    /// Output directory for reports and logs.
    pub output_dir: std::path::PathBuf,
    /// Print JSON to stdout instead of writing files (unused here).
    #[allow(dead_code)]
#[allow(dead_code)] // json_output retained for CLI compatibility but not used in current supervisor logic
    pub json_output: bool,
    /// Resume from a previous checkpoint.
    pub resume: bool,
    /// Minimum free disk space (MiB) required to continue.
    pub min_free_disk_mb: u64,
    /// Unique identifier for this run (generated automatically).
    pub run_id: String,
    /// Maximum memory allowed for child process (MiB).
    pub max_mem_mb: u64,

}

impl Config {
    pub fn from_cli(cli: crate::cli::Cli) -> Self {
        // Use supplied run_id if valid, otherwise generate a new UUID.
        let run_id = match cli.run_id {
            Some(id) => {
                // Reject unsafe components – must be a valid UUID.
                if uuid::Uuid::parse_str(&id).is_err() {
                    panic!("Invalid run_id supplied; must be a UUID without path components");
                }
                id
            }
            None => uuid::Uuid::new_v4().to_string(),
        };
        Self {
            suite_mode: cli.suite_mode,
            max_cycles: cli.max_cycles,
            simulator_bin: std::path::PathBuf::from(cli.simulator_bin),
            output_dir: std::path::PathBuf::from(cli.output_dir),
            json_output: cli.json,
            resume: cli.resume,
            min_free_disk_mb: cli.min_free_disk_mb,
            max_mem_mb: cli.max_mem_mb,
            run_id,
        }
    }
}
