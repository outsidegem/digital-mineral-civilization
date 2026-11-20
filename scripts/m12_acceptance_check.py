
#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys
import uuid
import re
from pathlib import Path
from collections import Counter

FOUNDATION = "simulation/dmc-simulator/src/scenarios/foundation.rs"

def validate_uuid(value):
    try:
        parsed = uuid.UUID(value)
        return (
            str(parsed) == value.lower()
            and parsed.version == 4
            and parsed.variant == uuid.RFC_4122
        ), parsed.version, parsed.variant
    except (ValueError, AttributeError, TypeError):
        return False, None, None

def walk(obj):
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key in ("suite_execution_id", "scenario_execution_id"):
                if isinstance(value, str):
                    yield key, value
            yield from walk(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from walk(item)

def git(*args):
    return subprocess.run(
        ["git", *args],
        capture_output=True, text=True
    )

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--crash-log", default=None)
    parser.add_argument("--expected-suites", type=int, default=3)
    parser.add_argument("--expected-scenarios", type=int, default=30)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    run_dir = (root / args.run_dir).resolve()
    crash_log = Path(args.crash_log).resolve() if args.crash_log else None

    if not run_dir.is_dir():
        print("FAIL: Evidence directory or crash log missing.")
        return 2

    ids = {"suite_execution_id": [], "scenario_execution_id": []}
    errors = []

    for file in sorted(run_dir.rglob("*.json")):
        try:
            data = json.loads(file.read_text())
        except Exception as exc:
            errors.append(f"Invalid JSON: {file}: {exc}")
            continue

        for key, value in walk(data):
            ids[key].append((value, str(file)))

    print("\n=== REPORT UUID VALIDATION ===")
    for key, records in ids.items():
        counts = Counter(value for value, _ in records)
        print(f"\n{key}: {len(records)} occurrences, "
              f"{len(counts)} distinct")

        for value, count in sorted(counts.items()):
            valid, version, variant = validate_uuid(value)
            print(f"{value} | count={count} | "
                  f"version={version} | variant={variant} | "
                  f"{'PASS' if valid else 'FAIL'}")
            if not valid:
                errors.append(f"Invalid UUID: {key}: {value}")

    suite_count = len(set(v for v, _ in ids["suite_execution_id"]))
    scenario_count = len(set(v for v, _ in ids["scenario_execution_id"]))

    if suite_count != args.expected_suites:
        errors.append(f"Expected {args.expected_suites} distinct suites; "
                      f"found {suite_count}")

    if scenario_count != args.expected_scenarios:
        errors.append(f"Expected {args.expected_scenarios} distinct scenarios; "
                      f"found {scenario_count}")

    scenario_counts = Counter(v for v, _ in ids["scenario_execution_id"])
    for value, count in scenario_counts.items():
        if count != 1:
            errors.append(f"Scenario ID occurs {count} times: {value}")

    print("\\n=== CRASH RECOVERY UUIDS ===")
    if args.crash_log:
        crash_log = Path(args.crash_log).resolve() if args.crash_log else None
        if crash_log.is_file():
            crash_text = crash_log.read_text(errors="replace")
            crash_ids = re.findall(
                r'"suite_id"\\s*:\\s*"([^"]+)"', crash_text
            )
            for value in crash_ids:
                valid, version, variant = validate_uuid(value)
                print(
                    f"{value} | version={version} | "
                    f"variant={variant} | "
                    f"{'PASS' if valid else 'FAIL'}"
                )
                if not valid:
                    errors.append(
                        f"Invalid crash-recovery UUID: {value}"
                    )
            if len(set(crash_ids)) < 2:
                errors.append(
                    "Expected distinct partial and recovery suite IDs."
                )
            if len(set(crash_ids)) != len(crash_ids):
                errors.append("Duplicate crash-recovery suite IDs.")
        else:
            print("NOT CHECKED: crash log path does not exist.")
    else:
        print("NOT CHECKED: no crash log supplied.")

    print("\n=== GIT INTEGRITY ===")
    head = git("rev-parse", "HEAD")
    status = git("status", "--short")
    diff = git("diff", "--quiet", "HEAD", "--", FOUNDATION)

    print("HEAD:", head.stdout.strip() or head.stderr.strip())
    print("Working tree:")
    print(status.stdout.strip() or "(clean)")
    print("Foundation source differs from HEAD:",
          "YES" if diff.returncode == 1 else
          "NO" if diff.returncode == 0 else "UNKNOWN")

    if diff.returncode != 0:
        errors.append("Foundation source has uncommitted changes "
                      "or Git comparison failed.")

    if errors:
        print("\n=== ACCEPTANCE: FAIL ===")
        for error in errors:
            print("-", error)
        return 1

    print("\n=== ACCEPTANCE: PASS ===")
    return 0

if __name__ == "__main__":
    sys.exit(main())
