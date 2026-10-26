# U1 review evidence: red-team of f928b45, and Gemtek native runs

Review artifacts only. Nothing here is production code. This branch is based on the reviewed commit
f928b457bfd7774551ace34aafb0b9d06b4ff950, so the red-team tests compile and run against it.

## Red-team of f928b45 (verdict BLOCK: H1 governance, H2 mint policy IDs)
- `tests/rt_attacks.rs`, `tests/rt_fuzz.rs`, `tests/rt_common/mod.rs`: the attacks and controls.
  `exploit_*` tests pass by demonstrating each finding at f928b45. `defended_*` tests pin what held.
- `tests/skeptic.rs` with `review/redteam-f928b45/skeptic/`: an independent rebuild of all 25 vectors.
  `vectors.json` comes from `build_vectors.py`, using fresh hashes.
- `review/redteam-f928b45/tools/mutate.py` and `triage.py`: the mutation harness and the cbor2 triage of fuzz survivors.
- `review/redteam-f928b45/logs/`: `mutation_results.json` (32 mutants), `mutation_run.log`, `mutation_triage.txt`.

Run at f928b45, from the repository root:

    cargo test --test rt_attacks -- --nocapture --test-threads 1
    RT_FUZZ_ITERS=20000 cargo test --release --test rt_fuzz grammar_fuzz -- --nocapture
    RT_FUZZ_ITERS=10000 RT_FUZZ_OUT=mutation_triage.txt cargo test --release --test rt_fuzz mutation_fuzz -- --nocapture
    cargo test --release --test rt_fuzz -- deep_nesting large_inputs duplicate_keys --nocapture --test-threads 1
    SKEPTIC_VECTORS=review/redteam-f928b45/skeptic/vectors.json cargo test --test skeptic -- --nocapture

`mutate.py` and `triage.py` hold paths from the reviewer's scratch layout. Point their path variables
at a clone before rerunning them.

## Gemtek native runs (`review/gemtek-native-logs/<commit>/`)
- Host: Linux x86_64. Toolchain: rustc 1.94.1 (e408947bf 2026-03-25), cargo 1.94.1. Python reference: python3 with cbor2.
- Each directory's `exits` file is its source binding. Its first line is the commit checked out (detached).
  It then lists every command's exit status and, where taken, fixture SHA-256s.
- Logs are the commands' raw output:
  - `1-test.log`: `cargo test --no-fail-fast`;
  - `2-allfeatures.log`: the same with `--all-features`;
  - `3-clippy.log`: `cargo clippy --all-targets -- -D warnings`;
  - `4-fmt.log`: `cargo fmt --check`;
  - `5-nostd.log`: `cargo check --no-default-features`;
  - `0-python.log`: `python3 scripts/test_r57_first_use.py` at the paired r57-live head.
- The 651148e and f928b45 directories predate this layout; their files are named per step.
- `MANIFEST.sha256` (in `review/`) lists the SHA-256 of every file under `review/` and of the test files above.
