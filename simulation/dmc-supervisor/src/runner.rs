// Updated runner: launches external simulator binary, parses JSON, validates suite, persists evidence, handles resume, checkpoint, and interruption.

use crate::config::Config;
use crate::envelope::SupervisorEnvelope;
use crate::log::{append, Event};
use ctrlc;
use crate::resources::{ResourceProvider, SysInfoProvider};
use crate::uuid_util::{new_scenario_uuid, new_suite_uuid};
use chrono::Utc;
use serde_json::Value;
use std::fs::{create_dir_all, rename};
// Unused imports removed

use crate::persistence::write_envelope;
use std::process::{Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Instant;
use uuid::Uuid;

/// Runs the supervisor according to the supplied configuration.
/// Implements disk‑space guard, optional resume, per‑cycle simulator execution,
/// JSON validation, evidence persistence, and SIGINT handling.
pub fn run_supervisor(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let suite_start = Instant::now();
    // Ctrl‑C handling.
    let interrupted = Arc::new(AtomicBool::new(false));
    {
        let interrupted = Arc::clone(&interrupted);
        // Ignore error if a handler is already set (tests may invoke multiple times).
        let _ = ctrlc::set_handler(move || {
            interrupted.store(true, Ordering::SeqCst);
        });
    }

    // Disk‑space guard.
    if config.min_free_disk_mb > 0 {
        let rp = SysInfoProvider::new();
        let free = rp.free_disk_mb(&config.output_dir);
        if free < config.min_free_disk_mb {
            let log_path = config.output_dir.join("event.log");
            append(
                &Event::ResourceSkipped {
                    suite_id: "N/A".to_string(),
                    reason: format!(
                        "Insufficient free disk space: {} MB < {} MB",
                        free, config.min_free_disk_mb
                    ),
                },
                &log_path,
            )?;
            return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("Insufficient free disk space: {} MB < {} MB", free, config.min_free_disk_mb))))?;
        }
    }

    // Determine start cycle and suite identifiers.
    let mut start_cycle = 0u32;
    let mut suite_id = new_suite_uuid();
    let mut suite_ts = Utc::now().to_rfc3339();
    if config.resume {
        let ck_path = config.output_dir.join("checkpoint.json");
        if ck_path.exists() {
            let data = std::fs::read_to_string(&ck_path)?;
            let cp: Value = serde_json::from_str(&data)?;
            if let Some(c) = cp.get("next_cycle").and_then(|v| v.as_u64()) {
                start_cycle = c as u32;
            }
            if let Some(sid) = cp.get("suite_id").and_then(|v| v.as_str()) {
                suite_id = sid.to_string();
            }
            if let Some(sts) = cp.get("suite_timestamp").and_then(|v| v.as_str()) {
                suite_ts = sts.to_string();
            }
        }
    }

    // Ensure output directory exists.
    create_dir_all(&config.output_dir)?;
    let log_path = config.output_dir.join("event.log");

    // Log SuiteStarted (fresh or resumed).
    append(
        &Event::SuiteStarted {
            suite_id: suite_id.clone(),
            ts: suite_ts.clone(),
            config: config.suite_mode.clone(),
        },
        &log_path,
    )?;

    let total_cycles = if config.max_cycles == 0 {
        u32::MAX
    } else {
        config.max_cycles
    };
    for cycle in start_cycle..total_cycles {
        if interrupted.load(Ordering::SeqCst) {
            append(
                &Event::SuiteInterrupted {
                    suite_id: suite_id.clone(),
                    ts: Utc::now().to_rfc3339(),
                },
                &log_path,
            )?;
            break;
        }

        // Launch simulator binary.
        let mut cmd = {
            // If the simulator path points to a shell script, invoke it via `sh` to avoid interpreter path issues on Termux.
            if config.simulator_bin.extension().and_then(|e| e.to_str()) == Some("sh") {
                let mut c = Command::new("sh");
                c.arg(&config.simulator_bin);
                c
            } else {
                Command::new(&config.simulator_bin)
            }
        };
        cmd.arg("run")
            .arg("all")
            .arg("--json")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let start = Instant::now();
        use std::sync::{Arc, Mutex};
        use std::thread;
        // Spawn child process.
        let mut child = cmd.spawn()?;
        // Take stdout and stderr handles.
        let stdout_handle = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("Failed to capture stdout"))?;
        let stderr_handle = child
            .stderr
            .take()
            .ok_or_else(|| std::io::Error::other("Failed to capture stderr"))?;
        // Shared buffers for concurrent reading.
        let stdout_buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let stderr_buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        // Thread to read stdout.
        let out_buf_clone = Arc::clone(&stdout_buf);
        let stdout_thread = thread::spawn(move || {
            let mut reader = std::io::BufReader::new(stdout_handle);
            let mut local = Vec::new();
            let _ = std::io::copy(&mut reader, &mut local);
            let mut guard = out_buf_clone.lock().unwrap();
            guard.extend(local);
        });
        // Thread to read stderr.
        let err_buf_clone = Arc::clone(&stderr_buf);
        let stderr_thread = thread::spawn(move || {
            let mut reader = std::io::BufReader::new(stderr_handle);
            let mut local = Vec::new();
            let _ = std::io::copy(&mut reader, &mut local);
            let mut guard = err_buf_clone.lock().unwrap();
            guard.extend(local);
        });
        // Monitoring loop.
        // Allow unused assignment for exit_status which may be overwritten before read
        #[allow(unused_assignments)]
        let mut exit_status = None;
        loop {
            // Check for interrupt.
            if interrupted.load(Ordering::SeqCst) {
                // Kill child and break.
                let _ = child.kill();
                exit_status = Some(child.wait()?);
                break;
            }
            // Memory and disk checks (reuse existing config and providers).
            if config.max_mem_mb > 0 {
                let rp = SysInfoProvider::new();
                if let Some(mem) = rp.memory_mb_of_pid(child.id()) {
                    if mem > config.max_mem_mb {
                        let _ = child.kill();
                        exit_status = Some(child.wait()?);
                        append(
                            &Event::ResourceSkipped {
                                suite_id: suite_id.clone(),
                                reason: format!(
                                    "Memory usage {} MB exceeds limit {} MB",
                                    mem, config.max_mem_mb
                                ),
                            },
                            &log_path,
                        )?;
                        break;
                    }
                } else {
                    let _ = child.kill();
                    exit_status = Some(child.wait()?);
                    append(
                        &Event::ResourceSkipped {
                            suite_id: suite_id.clone(),
                            reason: "Failed to obtain memory usage".to_string(),
                        },
                        &log_path,
                    )?;
                    break;
                }
            }
            if config.min_free_disk_mb > 0 {
                let rp = SysInfoProvider::new();
                let free = rp.free_disk_mb(&config.output_dir);
                if free < config.min_free_disk_mb {
                    let _ = child.kill();
                    exit_status = Some(child.wait()?);
                    append(
                        &Event::ResourceSkipped {
                            suite_id: suite_id.clone(),
                            reason: format!(
                                "Free disk {} MB below minimum {} MB",
                                free, config.min_free_disk_mb
                            ),
                        },
                        &log_path,
                    )?;
                    break;
                }
            }
            // Try to see if child has exited.
            match child.try_wait()? {
                Some(status) => {
                    exit_status = Some(status);
                    break;
                }
                None => {
                    // Sleep briefly before next poll.
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
            }
        }
        // Ensure reader threads have finished.
        let _ = stdout_thread.join();
        let _ = stderr_thread.join();
        let stdout_bytes = stdout_buf.lock().unwrap();
        let stderr_bytes = stderr_buf.lock().unwrap();
        let stdout = String::from_utf8_lossy(&stdout_bytes);
        let stderr = String::from_utf8_lossy(&stderr_bytes);
        let _duration_ms = start.elapsed().as_millis() as u64;
        // Handle non‑zero exit.
        let status = exit_status
            .ok_or_else(|| std::io::Error::other("Child process did not return a status"))?;
        if !status.success() {
            append(
                &Event::ResourceSkipped {
                    suite_id: suite_id.clone(),
                    reason: format!("Simulator failed with code {:?}: {}", status.code(), stderr),
                },
                &log_path,
            )?;
            return Err(Box::new(std::io::Error::other("Simulator process failed")));
        }

        // Parse JSON.
        let report_json: Value = serde_json::from_str(&stdout).map_err(|e| {
            append(
                &Event::ResourceSkipped {
                    suite_id: suite_id.clone(),
                    reason: format!("Malformed JSON from simulator: {}", e),
                },
                &log_path,
            )
            .ok();
            std::io::Error::other("JSON parse error")
        })?;

        // Validate suite.
        let suite_total = report_json
            .get("suite_total")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| {
                append(
                    &Event::ResourceSkipped {
                        suite_id: suite_id.clone(),
                        reason: "suite_total missing".to_string(),
                    },
                    &log_path,
                )
                .ok();
                std::io::Error::other("suite_total missing")
            })?;
        let suite_passed = report_json
            .get("suite_passed")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| {
                append(
                    &Event::ResourceSkipped {
                        suite_id: suite_id.clone(),
                        reason: "suite_passed missing".to_string(),
                    },
                    &log_path,
                )
                .ok();
                std::io::Error::other("suite_passed missing")
            })?;
        let all_passed = report_json
            .get("all_passed")
            .and_then(|v| v.as_bool())
            .ok_or_else(|| {
                append(
                    &Event::ResourceSkipped {
                        suite_id: suite_id.clone(),
                        reason: "all_passed missing".to_string(),
                    },
                    &log_path,
                )
                .ok();
                std::io::Error::other("all_passed missing")
            })?;
        let scenarios = report_json
            .get("scenarios")
            .and_then(|v| v.as_array())
            .cloned()
            .ok_or_else(|| {
                append(
                    &Event::ResourceSkipped {
                        suite_id: suite_id.clone(),
                        reason: "scenarios missing".to_string(),
                    },
                    &log_path,
                )
                .ok();
                std::io::Error::other("scenarios missing")
            })?;
        if suite_total != 10 || suite_passed != 10 || !all_passed || scenarios.len() != 10 {
            append(
                &Event::ResourceSkipped {
                    suite_id: suite_id.clone(),
                    reason: "Suite validation failed".to_string(),
                },
                &log_path,
            )?;
            return Err(Box::new(std::io::Error::other("Suite validation failed")));
        }
        for sc in &scenarios {
            if sc.get("overall_pass") != Some(&Value::Bool(true)) {
                append(
                    &Event::ResourceSkipped {
                        suite_id: suite_id.clone(),
                        reason: "Scenario overall_pass false".to_string(),
                    },
                    &log_path,
                )?;
                return Err(Box::new(std::io::Error::other(
                    "Scenario validation failed",
                )));
            }
        }

        // Build envelope.
        let envelope = SupervisorEnvelope {
            suite_id: suite_id.clone(),
            suite_timestamp: suite_ts.clone(),
            supervisor_version: env!("CARGO_PKG_VERSION"),
            report_json,
            schema_version: Some("1.0"),
        };
        // Persist envelope using write_envelope for atomic safety.
        write_envelope(&envelope, &config.output_dir, cycle)?;

        // Log scenario completed events for each scenario, preserving IDs and ordering.
        for (idx, sc) in scenarios.iter().enumerate() {
            // Extract simulator scenario ID (expected integer).
            let sim_scenario_id = sc.get("id").and_then(|v| v.as_u64()).ok_or_else(|| {
                append(
                    &Event::ResourceSkipped {
                        suite_id: suite_id.clone(),
                        reason: "Scenario missing id field".to_string(),
                    },
                    &log_path,
                )
                .ok();
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Scenario id missing")
            })?;
            let event_id = new_scenario_uuid(); // reuse UUID generator for event ID
            append(
                &Event::ScenarioCompleted {
                    suite_id: suite_id.clone(),
                    scenario_id: sim_scenario_id,
                    scenario_index: idx,
                    event_id: event_id.to_string(),
                    ts: Utc::now().to_rfc3339(),
                    status: "success".to_string(),
                },
                &log_path,
            )?;
        }

        // Write checkpoint atomically.
        let checkpoint = serde_json::json!({
            "suite_id": suite_id,
            "suite_timestamp": suite_ts,
            "next_cycle": cycle + 1,
            "max_cycles": config.max_cycles,
        });
        let ck_path = config.output_dir.join("checkpoint.json");
        let ck_tmp = config
            .output_dir
            .join(format!("checkpoint.json.tmp-{}", Uuid::new_v4()));
        std::fs::write(&ck_tmp, serde_json::to_string_pretty(&checkpoint)?)?;
        rename(&ck_tmp, &ck_path)?;

        if config.max_cycles == 1 {
            break;
        }
    }

    // Suite completed event.
    let suite_duration = suite_start.elapsed().as_millis() as u64;
    append(
        &Event::SuiteCompleted {
            suite_id: suite_id.clone(),
            ts: Utc::now().to_rfc3339(),
            duration_ms: suite_duration,
        },
        &log_path,
    )?;
    append(
        &Event::Shutdown {
            ts: Utc::now().to_rfc3339(),
        },
        &log_path,
    )?;
    Ok(())
}
