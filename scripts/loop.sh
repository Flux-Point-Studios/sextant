#!/usr/bin/env bash
# Outer Ralph loop: a fresh Claude context per iteration; all state lives in
# LOOP.md and git. Promotion is decided by the harness, never by the agent.
# Unattended runs belong in a sandboxed container with allow-listed egress
# and zero reachable key material; only there is
#   PERMISSION_ARGS="--dangerously-skip-permissions"
# acceptable. Halt any time with: touch .claude/fluxpoint-loop/STOP
set -euo pipefail
MAX_ITER="${MAX_ITER:-25}"
MAX_TURNS="${MAX_TURNS:-40}"
PERMISSION_ARGS="${PERMISSION_ARGS:---permission-mode acceptEdits}"

sd=".claude/fluxpoint-loop"
mkdir -p "$sd/logs"
rm -f "$sd/STOP"

for ((i = 1; i <= MAX_ITER; i++)); do
  if [ -f "$sd/STOP" ]; then
    echo "loop: STOP file present, halting after $((i - 1)) iteration(s)"
    exit 0
  fi
  echo "loop: iteration $i/$MAX_ITER"
  # shellcheck disable=SC2086
  claude -p "$(cat LOOP_PROMPT.md)" $PERMISSION_ARGS --max-turns "$MAX_TURNS" \
    --output-format stream-json --verbose \
    >"$sd/logs/iter-$i.jsonl" 2>&1 ||
    echo "loop: claude exited non-zero on iteration $i (see logs)" >&2
  git add -A
  git commit -q -m "loop: iteration $i" || true
  if bash scripts/harness.sh --full && grep -q '^STATUS: DONE' LOOP.md; then
    echo "loop: harness green and STATUS DONE after iteration $i"
    exit 0
  fi
done
echo "loop: iteration budget exhausted, harness red or STATUS still ACTIVE. Checkpoint." >&2
exit 1
