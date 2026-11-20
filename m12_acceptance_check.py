#!/usr/bin/env python3
"""M1.2 Acceptance Checker

Usage: python3 m12_acceptance_check.py <output_dir> [--expected-cycles N]

It validates that a supervisor run in <output_dir> meets all integrity and completeness
requirements. The script emits a JSON result on stdout and a concise human‑readable
summary on stderr. Exit status 0 indicates acceptance; any non‑zero status indicates
failure.
"""

import argparse
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Dict, List, Set, Tuple

SUPPORTED_SCHEMA_VERSIONS = {"1.0"}

def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)

def validate_uuid(u: str) -> bool:
    try:
        uuid.UUID(u)
        return True
    except Exception:
        return False

def error(msg: str, details: dict = None):
    out = {"status": "error", "message": msg}
    if details:
        out["details"] = details
    print(json.dumps(out))
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)

def warning(msg: str, details: dict = None):
    out = {"status": "warning", "message": msg}
    if details:
        out["details"] = details
    print(json.dumps(out))
    print(f"WARNING: {msg}", file=sys.stderr)

def main():
    parser = argparse.ArgumentParser(description="M1.2 Acceptance Checker")
    parser.add_argument("output_dir", type=Path, help="Supervisor output directory")
    parser.add_argument("--expected-cycles", type=int, default=None,
                        help="Number of cycles expected (optional)")
    args = parser.parse_args()
    out_dir: Path = args.output_dir
    if not out_dir.is_dir():
        error(f"Output directory does not exist: {out_dir}")

    # Load checkpoint if present
    checkpoint_path = out_dir / "checkpoint.json"
    checkpoint = None
    if checkpoint_path.exists():
        try:
            checkpoint = load_json(checkpoint_path)
        except Exception as e:
            error("Failed to parse checkpoint.json", {"exception": str(e)})
    else:
        warning("Missing checkpoint.json; will infer from artifacts")

    # Discover cycle artifact files
    cycle_files = sorted(out_dir.glob("cycle_*.json"))
    if not cycle_files:
        error("No cycle artifacts found")

    # Verify naming and extract indices
    cycle_indices: List[int] = []
    for p in cycle_files:
        stem = p.stem  # e.g., cycle_0000
        try:
            idx = int(stem.split("_")[1])
        except Exception:
            error(f"Invalid cycle filename: {p.name}")
        cycle_indices.append(idx)
        if idx != cycle_indices[-1]:  # Ensure sequential ordering
            # out of order is allowed only if duplicate later; we'll check later
            pass
    # Detect duplicates
    if len(set(cycle_indices)) != len(cycle_indices):
        error("Duplicate cycle artifact filenames detected")

    # Ensure indices are contiguous starting at 0
    expected_seq = list(range(min(cycle_indices), max(cycle_indices)+1))
    if cycle_indices != expected_seq:
        error("Non‑contiguous cycle indices", {"found": cycle_indices, "expected": expected_seq})

    # Load event log
    event_log_path = out_dir / "event.log"
    if not event_log_path.is_file():
        error("Missing event.log")
    events: List[dict] = []
    with event_log_path.open("r", encoding="utf-8") as f:
        for line in f:
            line=line.strip()
            if not line:
                continue
            try:
                ev=json.loads(line)
                events.append(ev)
            except Exception as e:
                error("Malformed JSON in event.log", {"line": line, "exception": str(e)})

    # Index events by cycle
    scenario_events_by_cycle: Dict[int, List[dict]] = {}
    event_uuids: Set[str] = set()
    for ev in events:
        if ev.get("ScenarioCompleted"):
            sc = ev["ScenarioCompleted"]
            cid = sc.get("cycle_index")
            if cid is None:
                error("ScenarioCompleted missing cycle_index", sc)
            scenario_events_by_cycle.setdefault(cid, []).append(sc)
            ev_id = sc.get("event_id")
            if not ev_id or not validate_uuid(ev_id):
                error("Invalid or missing event_id", sc)
            if ev_id in event_uuids:
                error("Duplicate event_id across runs", {"event_id": ev_id})
            event_uuids.add(ev_id)

    # Validate each cycle artifact against events
    suite_id_global = None
    for p in cycle_files:
        env = load_json(p)
        # Validate schema version
        schema_version = env.get("schema_version")
        if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
            error("Unsupported or missing schema_version", {"file": p.name, "schema_version": schema_version})
        # Suite identity
        suite_id = env.get("suite_id")
        if not suite_id:
            error("Missing suite_id in envelope", {"file": p.name})
        if suite_id_global is None:
            suite_id_global = suite_id
        elif suite_id != suite_id_global:
            error("Inconsistent suite_id across cycles", {"expected": suite_id_global, "found": suite_id, "file": p.name})
        # Cycle index consistency
        cycle_idx = env.get("cycle_index")
        if cycle_idx is None:
            error("Missing cycle_index in envelope", {"file": p.name})
        # Verify filename matches cycle_index
        filename_idx = int(p.stem.split("_")[1])
        if cycle_idx != filename_idx:
            error("cycle_index mismatch between filename and envelope", {"file": p.name, "cycle_index": cycle_idx, "filename_idx": filename_idx})
        # Validate report structure
        report = env.get("report")
        if not report:
            error("Missing report field in envelope", {"file": p.name})
        for field in ["suite_total", "suite_passed", "all_passed", "scenarios"]:
            if field not in report:
                error(f"Report missing required field '{field}'", {"file": p.name})
        if not isinstance(report["scenarios"], list) or len(report["scenarios"]) != 10:
            error("Report must contain exactly ten scenarios", {"file": p.name, "found": len(report.get("scenarios", []))})
        # Verify all_passed and suite_passed
        if not report.get("all_passed") or report.get("suite_passed") != 10:
            error("Suite not fully passed", {"file": p.name, "suite_passed": report.get("suite_passed"), "all_passed": report.get("all_passed")})
        # Build map of scenario_id -> index
        scenario_map = {sc.get("id"): idx for idx, sc in enumerate(report["scenarios"]) if "id" in sc}
        if len(scenario_map) != 10:
            error("Scenario IDs missing or duplicated in report", {"file": p.name})
        # Verify events for this cycle
        evs = scenario_events_by_cycle.get(cycle_idx, [])
        if len(evs) != 10:
            error("Incorrect number of ScenarioCompleted events for cycle", {"cycle": cycle_idx, "expected": 10, "found": len(evs)})
        # Check each event maps to a scenario
        for ev in evs:
            sid = ev.get("scenario_id")
            if sid not in scenario_map:
                error("Event scenario_id does not exist in report", {"cycle": cycle_idx, "scenario_id": sid})
            # Verify ordering matches scenario_index
            if ev.get("scenario_index") != scenario_map[sid]:
                error("Event scenario_index out of order", {"cycle": cycle_idx, "scenario_id": sid, "expected_index": scenario_map[sid], "found_index": ev.get("scenario_index")})
            # Verify status is success
            if ev.get("status") != "success":
                error("ScenarioCompleted event with non‑success status", ev)

    # Check checkpoint continuity
    if checkpoint:
        next_cycle = checkpoint.get("next_cycle")
        if next_cycle is None:
            error("Checkpoint missing next_cycle", checkpoint)
        expected_next = max(cycle_indices) + 1
        if next_cycle != expected_next:
            error("Checkpoint next_cycle does not match completed cycles", {"checkpoint_next": next_cycle, "expected": expected_next})
        # Suite ID consistency
        if checkpoint.get("suite_id") != suite_id_global:
            error("Checkpoint suite_id mismatch", {"checkpoint": checkpoint.get("suite_id"), "suite": suite_id_global})
    else:
        warning("No checkpoint.json; inferred next_cycle from artifacts")

    # Verify no stray temporary files remain
    temp_files = list(out_dir.glob("*.tmp-*"))
    if temp_files:
        warning("Temporary files left behind", {"files": [p.name for p in temp_files]})

    # All checks passed
    result = {
        "status": "accepted",
        "suite_id": suite_id_global,
        "cycles": len(cycle_files),
        "events": len(event_uuids),
    }
    print(json.dumps(result))
    print(f"ACCEPTED: suite {suite_id_global}, {len(cycle_files)} cycles, {len(event_uuids)} events", file=sys.stderr)
    sys.exit(0)

if __name__ == "__main__":
    main()
