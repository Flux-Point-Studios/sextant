#!/usr/bin/env bash
# Outer Ralph loop: a fresh Claude context per iteration; all durable state
# lives in LOOP.md and git. Promotion is decided by the harness, never by the
# agent.
#
# The default branch is only ever a mirror of its remote: each iteration
# starts from a clean `origin/$DEFAULT_BRANCH`, and the agent's own reviewed,
# harness-green PR merge (to the remote) is the single path that advances it.
# Whatever an iteration leaves behind — uncommitted edits or local commits it
# never merged — is snapshotted onto a `loop/iter-N` branch for inspection and
# then discarded from the default branch, so an unfinished or red iteration
# can never pollute it.
#
# Unattended runs belong in a sandboxed container with allow-listed egress and
# zero reachable key material; only there is
#   PERMISSION_ARGS="--dangerously-skip-permissions"
# acceptable. Halt any time with: touch .claude/fluxpoint-loop/STOP
set -euo pipefail
MAX_ITER="${MAX_ITER:-25}"
MAX_TURNS="${MAX_TURNS:-40}"
PERMISSION_ARGS="${PERMISSION_ARGS:---permission-mode acceptEdits}"
DEFAULT_BRANCH="${DEFAULT_BRANCH:-main}"

sd=".claude/fluxpoint-loop"
mkdir -p "$sd/logs"
rm -f "$sd/STOP"

sync_default() {
  git fetch -q origin "$DEFAULT_BRANCH" 2>/dev/null || true
  git checkout -q "$DEFAULT_BRANCH" 2>/dev/null ||
    git checkout -q -b "$DEFAULT_BRANCH" "origin/$DEFAULT_BRANCH"
  git reset -q --hard "origin/$DEFAULT_BRANCH"
}

for ((i = 1; i <= MAX_ITER; i++)); do
  if [ -f "$sd/STOP" ]; then
    echo "loop: STOP file present, halting after $((i - 1)) iteration(s)"
    exit 0
  fi
  echo "loop: iteration $i/$MAX_ITER"

  # Start every iteration from a clean mirror of the remote default branch.
  sync_default

  # shellcheck disable=SC2086
  claude -p "$(cat LOOP_PROMPT.md)" $PERMISSION_ARGS --max-turns "$MAX_TURNS" \
    --output-format stream-json --verbose \
    >"$sd/logs/iter-$i.jsonl" 2>&1 ||
    echo "loop: claude exited non-zero on iteration $i (see logs)" >&2

  # Preserve anything the agent left that it did not merge upstream — off the
  # default branch — then restore the default branch to the remote's state.
  git add -A 2>/dev/null || true
  if [ -n "$(git status --porcelain)" ] ||
    [ -n "$(git log "origin/$DEFAULT_BRANCH"..HEAD --oneline 2>/dev/null)" ]; then
    git commit -q -m "loop: iteration $i (unmerged WIP)" 2>/dev/null || true
    git branch -qf "loop/iter-$i" HEAD 2>/dev/null || true
    echo "loop: iteration $i left unmerged work on branch loop/iter-$i" >&2
  fi
  sync_default

  if bash scripts/harness.sh --full && grep -q '^STATUS: DONE' LOOP.md; then
    echo "loop: harness green and STATUS DONE after iteration $i"
    exit 0
  fi
done
echo "loop: iteration budget exhausted, harness red or STATUS still ACTIVE. Checkpoint." >&2
exit 1
