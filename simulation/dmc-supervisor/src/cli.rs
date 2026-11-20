//! Command‑line interface definitions for the supervisor.
use clap::Parser;

/// Command‑line arguments for the supervisor.
#[derive(Parser, Debug)]
#[command(name = "dmc-supervisor", version = "0.1.0", about = "Persistent Simulation Supervisor for DMC", long_about = None)]
pub struct Cli {
    /// Suite mode: "foundation" or "all"
    #[arg(long, default_value = "all")]
    pub suite_mode: String,

    /// Maximum number of cycles (0 is disallowed unless --unlimited is set)
    #[arg(long, default_value_t = 1)]
    pub max_cycles: u32,

    /// Output directory for reports and logs
    #[arg(long, default_value = "simulation-runs")]
    pub output_dir: String,

    /// Resume from a previous checkpoint.
    #[arg(long, default_value_t = false)]
    pub resume: bool,

    /// Minimum free disk space (MiB) required to continue.
    #[arg(long, default_value_t = 0)]
    pub min_free_disk_mb: u64,
    /// Optional explicit run identifier (UUID). If omitted, a UUID is generated.
    #[arg(long)]
    pub run_id: Option<String>,
    /// Maximum memory usage (MiB) allowed for child process.
    #[arg(long, default_value_t = 0)]
    pub max_mem_mb: u64,

    /// Print report JSON to stdout instead of writing files.
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Path to the dmc‑simulator binary.
    #[arg(long, default_value = "target/debug/dmc-simulator")]
    pub simulator_bin: String,
}
