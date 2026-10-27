#!/usr/bin/env bash
# S-0001 (BENCH.md §6.2, §8.6): RISC Zero guest compile spike for Sextant's
# mithril leg. Reproduces the container run exactly; compile-only, no proving.
#
# Requires: Docker (linux/amd64). Run from this directory.
# The container is the vendor's own canonical guest-builder (the image
# `cargo risczero build` runs its docker builds in — risc0-build v3.0.5
# DEFAULT_DOCKER_TAG), pinned by immutable digest per ADR-004 D1.
set -euo pipefail

IMG="risczero/risc0-guest-builder:r0.1.88.0@sha256:3e12f71bacd27527a61dea96fa0e53e468c99aa261d3a1019b593f6dbd943eb3"

# Windows Git Bash mangles /paths in -v mounts; MSYS_NO_PATHCONV=1 disables it
# and `pwd -W` yields the Windows-native path Docker Desktop accepts.
export MSYS_NO_PATHCONV=1
SPIKE_DIR="$(pwd -W 2>/dev/null || pwd)"

# The image sets ENTRYPOINT /bin/sh, which would swallow a bare `bash -c`.
docker run --rm --entrypoint bash -v "$SPIKE_DIR:/spike" -w /spike/guest "$IMG" -euo pipefail -c '
  # The exact guest-build environment risc0-build v3.0.5 constructs
  # (risc0/build/src/lib.rs cargo_command_internal + encode_rust_flags):
  export CARGO_ENCODED_RUSTFLAGS=$(printf -- "-C\037passes=lower-atomic\037-C\037link-arg=-Ttext=0x00200800\037-C\037link-arg=--fatal-warnings\037-C\037panic=abort\037--cfg\037getrandom_backend=\"custom\"")
  export CC_riscv32im_risc0_zkvm_elf=/root/.risc0/cpp/bin/riscv32-unknown-elf-gcc
  export CFLAGS_riscv32im_risc0_zkvm_elf="-march=rv32im -nostdlib"
  export RISC0_FEATURE_bigint2=
  export CARGO_TARGET_DIR=/tmp/target
  ELF=/tmp/target/riscv32im-risc0-zkvm-elf/release/risc0-mithril-guest

  echo "=== layer 1: sextant default-features=false only (no mithril)"
  cargo +risc0 build --release --target riscv32im-risc0-zkvm-elf

  echo "=== layer 2: + features=[mithril] (vanilla blst 0.3.16 portable C)"
  cargo +risc0 build --release --target riscv32im-risc0-zkvm-elf --features mithril

  echo "=== layer 3: + [patch.crates-io] blst = risc0/blst v0.3.16-risczero.0"
  cargo +risc0 build --release --target riscv32im-risc0-zkvm-elf --features mithril \
    --config /spike/risc0-blst-patch.toml

  echo "=== image ID (risc0-build v3.0.5 derivation: user ELF + v1compat kernel)"
  cd /spike/imageid
  # Host-side build: shed the guest rustflags/target env or the host cc chokes.
  env -u CARGO_ENCODED_RUSTFLAGS -u CC_riscv32im_risc0_zkvm_elf \
      -u CFLAGS_riscv32im_risc0_zkvm_elf \
      CARGO_TARGET_DIR=/tmp/target-imageid cargo +stable run --release -- "$ELF"
'
