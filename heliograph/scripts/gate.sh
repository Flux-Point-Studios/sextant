#!/usr/bin/env bash
# The session gate (HANDOFF §7/§10) — the single source of truth `make gate` and CI both run.
# Phase 0: scaffold integrity. The gate GROWS with the code (fmt + clippy -D warnings + tests +
# equality invariant + journal zoo + golden journals land with the workspace) and never shrinks.
set -euo pipefail
cd "$(dirname "$0")/.."

test -f HANDOFF.md || { echo "gate: HANDOFF.md missing" >&2; exit 1; }
test -f STATUS.md || { echo "gate: STATUS.md missing" >&2; exit 1; }
test -f LICENSE || { echo "gate: LICENSE missing" >&2; exit 1; }

# The mutant-class ledger (HANDOFF §7): every table row must carry a status —
# covered:<test>, locked-at:<milestone>, or argued:<doc>. A row without one is
# an untracked zoo gap and fails the gate.
coverage_ledger_gate() {
  local ledger="docs/journal-coverage.md"
  test -f "$ledger" || { echo "gate: $ledger missing" >&2; exit 1; }
  local bad
  bad=$(awk -F'|' '/^\|/ && $2 !~ /^ *Class *$/ && $2 !~ /^-/ {
    if ($(NF-1) !~ /(covered|locked-at|argued):[^ ]/) print
  }' "$ledger")
  if [ -n "$bad" ]; then
    echo "gate: journal-coverage rows without a status:" >&2
    echo "$bad" >&2
    exit 1
  fi
}

if [ -f Cargo.toml ]; then
  cargo fmt --all -- --check
  cargo clippy --all-targets --all-features -- -D warnings
  cargo test --all-features
  coverage_ledger_gate
else
  echo "gate: phase-0 scaffold OK (no workspace yet — gate grows with the code)"
fi
