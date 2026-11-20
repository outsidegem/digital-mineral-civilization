#!/usr/bin/env sh
# Mock dmc-simulator that prints a valid suite JSON to stdout
cat <<'EOF'
{
  "suite_total": 10,
  "suite_passed": 10,
  "all_passed": true,
  "scenarios": [
    {"id":1,"overall_pass":true},
    {"id":2,"overall_pass":true},
    {"id":3,"overall_pass":true},
    {"id":4,"overall_pass":true},
    {"id":5,"overall_pass":true},
    {"id":6,"overall_pass":true},
    {"id":7,"overall_pass":true},
    {"id":8,"overall_pass":true},
    {"id":9,"overall_pass":true},
    {"id":10,"overall_pass":true}
  ]
}
EOF
