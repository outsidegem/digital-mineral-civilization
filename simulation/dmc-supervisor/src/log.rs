// Placeholder for logging module
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

#[derive(Serialize, Debug)]
pub enum Event {
    SuiteStarted {
        suite_id: String,
        ts: String,
        config: String,
    },
    ScenarioCompleted {
        suite_id: String,
        scenario_id: u64,
        scenario_index: usize,
        event_id: String,
        ts: String,
        status: String,
    },
    SuiteCompleted {
        suite_id: String,
        ts: String,
        duration_ms: u64,
    },
    SuiteInterrupted {
        suite_id: String,
        ts: String,
    },
    ResourceSkipped {
        suite_id: String,
        reason: String,
    },
    Shutdown {
        ts: String,
    },
}

pub fn append(event: &Event, log_path: &Path) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    let line = serde_json::to_string(event)? + "\n";
    file.write_all(line.as_bytes())?;
    file.flush()?;
    Ok(())
}
