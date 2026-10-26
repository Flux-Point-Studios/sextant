#!/usr/bin/env bash
# usage: run_mutants.sh <scratch>   -- runs every mutant in mutants.py against the official suites
set -u
S="$1"; CL="$S/sextant-gov"; export CARGO_TARGET_DIR="$S/target"
OUT="$S/mutation"; mkdir -p "$OUT"; : > "$OUT/summary.tsv"
names=$(python3 -c "import sys; sys.path.insert(0,'$S/rt'); from mutants import MUTANTS; print(' '.join(m[0] for m in MUTANTS))")
for name in $names; do
  git -C "$CL" checkout -q -- src/watchkey.rs
  python3 - "$S" "$name" <<'APPLY' || { echo -e "$name\tAPPLY_FAILED\t-\t-" >> "$OUT/summary.tsv"; continue; }
import sys
sys.path.insert(0, sys.argv[1] + "/rt")
from mutants import MUTANTS
path = sys.argv[1] + "/sextant-gov/src/watchkey.rs"
src = open(path).read()
name = sys.argv[2]
orig, repl = next((o, r) for n, o, r in MUTANTS if n == name)
assert src.count(orig) == 1, f"{name}: snippet occurs {src.count(orig)} times"
open(path, "w").write(src.replace(orig, repl))
APPLY
  log="$OUT/$name.log"
  ( cd "$CL" && nice -n 19 cargo test -j 3 --lib 2>&1; echo "LIB_EXIT=$?"; nice -n 19 cargo test -j 3 --no-fail-fast --test watchkey_governance --test watchkey_golden --test watchkey_coverage --test watchkey_inputs --test watchkey_scripts 2>&1; echo "INT_EXIT=$?" ) > "$log" 2>&1
  if grep -q "error\[E\|error: could not compile" "$log"; then status=NOT_VIABLE_COMPILE
  elif grep -q "LIB_EXIT=0" "$log" && grep -q "INT_EXIT=0" "$log"; then status=SURVIVED
  else status=KILLED; fi
  failing=$(grep -E "^test .* FAILED$" "$log" | sed -E 's/^test (.*) \.\.\. FAILED$/\1/' | tr '\n' ',' | sed 's/,$//')
  # extended behaviour check with the 117 red-team vectors
  ( cd "$CL" && RT_PROBE_IN="$S/extra.tsv" RT_PROBE_OUT="$OUT/$name.extra.tsv" nice -n 19 cargo test -j 3 --test rt_probe > "$OUT/$name.probe.log" 2>&1 )
  ext=$(python3 - "$S/extra.rust.tsv" "$OUT/$name.extra.tsv" <<'EXT'
import sys
base = {l.split("\t")[0]: l.split("\t")[3] for l in open(sys.argv[1])}
try:
    mut = {l.split("\t")[0]: l.split("\t")[3] for l in open(sys.argv[2])}
except FileNotFoundError:
    print("no-probe"); raise SystemExit
diff = [k for k in base if mut.get(k) != base[k]]
print(f"{len(diff)}:" + ",".join(diff[:6]))
EXT
)
  echo -e "$name\t$status\t${failing:--}\t$ext" >> "$OUT/summary.tsv"
  echo "$name $status"
done
git -C "$CL" checkout -q -- src/watchkey.rs
git -C "$CL" status --short
