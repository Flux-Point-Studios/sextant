#!/usr/bin/env bash
set -u
S="$1"; K="$S/skeptic"; CL="$K/sextant"; export CARGO_TARGET_DIR="$K/target"
run() {  # $1 label
  ( cd "$CL" && nice -n 19 cargo test -j 3 --test watchkey_governance > "$K/$1.gov.log" 2>&1; echo "gov_exit=$?" ) | tr '\n' ' '
  grep -h "test result" "$K/$1.gov.log" | tr '\n' ' '
  ( cd "$CL" && SK_IN="$K/minimal.tsv" SK_OUT="$K/$1.min.tsv" nice -n 19 cargo test -j 3 --test skeptic_min > "$K/$1.min.log" 2>&1 )
  echo; sed 's/^/    /' "$K/$1.min.tsv"
}
git -C "$CL" checkout -q -- src/watchkey.rs; echo "== UNMUTATED"; run unmutated
for m in M22_removal_first_only M23_add_map_first_only M24_treasury_first_only M25_proposals_first_only M26_treasury_header_e0_only; do
  git -C "$CL" checkout -q -- src/watchkey.rs
  python3 - "$S" "$CL/src/watchkey.rs" "$m" <<'PY'
import sys
sys.path.insert(0, sys.argv[1] + "/rt")
from mutants import MUTANTS
src = open(sys.argv[2]).read()
o, r = next((o, r) for n, o, r in MUTANTS if n == sys.argv[3])
assert src.count(o) == 1
open(sys.argv[2], "w").write(src.replace(o, r))
PY
  echo "== $m  (diff: $(git -C "$CL" diff --shortstat))"; run "$m"
done
git -C "$CL" checkout -q -- src/watchkey.rs; git -C "$CL" status --short
