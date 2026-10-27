#!/usr/bin/env bash
# M0 executor-tier runs for the RISC Zero arm (BENCH.md §2, §4.1 "execute",
# §2.4 tamper control). Extends the S-0001 spike: builds the instrumented
# guest twice (vanilla blst / risc0 accelerated blst), a host-side executor
# runner, and the native differential binary, all inside the pinned
# guest-builder container; then runs the 8-row matrix
# {F-PP1, F-MN1} x {blst-vanilla, blst-risczero-fork} x {golden, tampered}
# plus native differential rows, writing evidence to
# fixtures/bench/evidence/R-0001..R-0008 (+ R-0000-toolchain).
#
# Requires: Docker (linux/amd64). Run from this directory.
# Usage: ./run-m0.sh {up|build-guests|build-host|tamper|run-row <row>|down}
set -euo pipefail

IMG="risczero/risc0-guest-builder:r0.1.88.0@sha256:3e12f71bacd27527a61dea96fa0e53e468c99aa261d3a1019b593f6dbd943eb3"
CTR="hg-m0-risc0"

# Windows Git Bash mangles /paths in -v mounts; MSYS_NO_PATHCONV=1 disables it
# and `pwd -W` yields the Windows-native path Docker Desktop accepts.
export MSYS_NO_PATHCONV=1
REPO_DIR="$(cd ../.. && (pwd -W 2>/dev/null || pwd))"

# The exact guest-build environment risc0-build v3.0.5 constructs
# (cargo_command_internal + encode_rust_flags), same as ../build.sh.
GUEST_ENV='
export CARGO_ENCODED_RUSTFLAGS=$(printf -- "-C\037passes=lower-atomic\037-C\037link-arg=-Ttext=0x00200800\037-C\037link-arg=--fatal-warnings\037-C\037panic=abort\037--cfg\037getrandom_backend=\"custom\"")
export CC_riscv32im_risc0_zkvm_elf=/root/.risc0/cpp/bin/riscv32-unknown-elf-gcc
export CFLAGS_riscv32im_risc0_zkvm_elf="-march=rv32im -nostdlib"
export RISC0_FEATURE_bigint2=
'

case "${1:?usage: run-m0.sh up|build-guests|build-host|tamper|run-row|down}" in
up)
  # Long-lived container so cargo caches and target dirs survive across phases.
  docker run -d --name "$CTR" --entrypoint bash -v "$REPO_DIR:/repo" "$IMG" -c 'sleep 86400'
  ;;
build-guests)
  docker exec "$CTR" bash -euo pipefail -c "$GUEST_ENV"'
    cd /repo/spikes/risc0-mithril/guest
    mkdir -p /tmp/out
    echo "=== guest: vanilla blst (unaccelerated control, BENCH.md §6.2 branch 2)"
    CARGO_TARGET_DIR=/tmp/t-guest-vanilla cargo +risc0 build --release \
      --target riscv32im-risc0-zkvm-elf --features mithril
    cp /tmp/t-guest-vanilla/riscv32im-risc0-zkvm-elf/release/risc0-mithril-guest /tmp/out/guest-vanilla.elf
    cargo tree --target riscv32im-risc0-zkvm-elf --features mithril > /tmp/tree-vanilla.txt
    grep -m1 " blst " /tmp/tree-vanilla.txt > /tmp/out/blst-vanilla.txt
    echo "=== guest: risc0/blst v0.3.16-risczero.0 (accelerated, branch 1; built last so the committed Cargo.lock stays the layer-3 resolution)"
    CARGO_TARGET_DIR=/tmp/t-guest-accel cargo +risc0 build --release \
      --target riscv32im-risc0-zkvm-elf --features mithril \
      --config /repo/spikes/risc0-mithril/risc0-blst-patch.toml
    cp /tmp/t-guest-accel/riscv32im-risc0-zkvm-elf/release/risc0-mithril-guest /tmp/out/guest-accel.elf
    cargo tree --target riscv32im-risc0-zkvm-elf --features mithril \
      --config /repo/spikes/risc0-mithril/risc0-blst-patch.toml > /tmp/tree-accel.txt
    grep -m1 " blst " /tmp/tree-accel.txt > /tmp/out/blst-accel.txt
    sha256sum /tmp/out/*.elf
    cat /tmp/out/blst-vanilla.txt /tmp/out/blst-accel.txt
  '
  ;;
build-host)
  # Host-side (x86) builds: fresh exec shell, so none of the guest env leaks.
  docker exec "$CTR" bash -euo pipefail -c '
    rustc +stable --version && cargo +stable --version && gcc --version | head -1
    echo "=== host: executor runner (risc0-zkvm =3.0.5, prove feature, execution only)"
    cd /repo/spikes/risc0-mithril/runner
    CARGO_TARGET_DIR=/tmp/t-host cargo +stable build --release
    echo "=== host: native differential (sextant 90b2672 features=[mithril])"
    cd /repo/spikes/risc0-mithril/native
    CARGO_TARGET_DIR=/tmp/t-host cargo +stable build --release
    echo "=== host: imageid (identity evidence)"
    cd /repo/spikes/risc0-mithril/imageid
    CARGO_TARGET_DIR=/tmp/t-host cargo +stable build --release
  '
  ;;
tamper)
  # Host-side: the builder container ships no python3.
  (cd ../../fixtures/bench/m0 &&
    python make-tampered.py F-PP1.json F-PP1.tampered.json &&
    python make-tampered.py F-MN1.json F-MN1.tampered.json)
  ;;
run-row)
  # run-row <R-000X> <guest-vanilla.elf|guest-accel.elf> <fixture-file>
  row="${2:?row id}" elf="${3:?elf}" fixture="${4:?fixture}"
  docker exec "$CTR" bash -euo pipefail -c "
    mkdir -p /repo/fixtures/bench/evidence/$row
    ( /tmp/t-host/release/hg-m0-runner /tmp/out/$elf /repo/fixtures/bench/m0/$fixture \
        /repo/fixtures/bench/evidence/$row || echo HG_RUNNER_EXIT=\$? ) 2>&1 \
      | tee /repo/fixtures/bench/evidence/$row/executor.log
    /tmp/t-host/release/hg-m0-native /repo/fixtures/bench/m0/$fixture 2>&1 \
      | tee /repo/fixtures/bench/evidence/$row/native.log
  "
  ;;
down)
  docker rm -f "$CTR"
  ;;
*)
  echo "unknown phase: $1" >&2
  exit 2
  ;;
esac
