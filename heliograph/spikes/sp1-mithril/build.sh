#!/usr/bin/env bash
# S-0002 driver: SP1 guest compile bisect in a pinned Linux container.
# Host: Windows Git Bash + Docker Desktop (MSYS_NO_PATHCONV guards -v mounts).
# Reuses a named container + named volumes so the sp1up toolchain install
# survives re-runs. Three layers:
#   1. sextant default-features=false                 -> compiles
#   2. + mithril, stock toolchain                     -> blst cc wall (expected)
#   3. + mithril, CC_riscv64im_succinct_zkvm_elf set  -> compiles
set -uo pipefail
export MSYS_NO_PATHCONV=1

IMG=rust:1.93-bookworm
CTR=hg-sp1-spike
ELF=/var/target/elf-compilation/riscv64im-succinct-zkvm-elf/release/sp1-mithril-guest
DIR="$(cd "$(dirname "$0")" && pwd)"
LOGS="$DIR/logs"
mkdir -p "$LOGS"

docker volume create hg-sp1-cargo-registry >/dev/null
docker volume create hg-sp1-home >/dev/null

if ! docker ps --format '{{.Names}}' | grep -qx "$CTR"; then
  docker rm -f "$CTR" >/dev/null 2>&1 || true
  docker run -d --name "$CTR" \
    -v "$DIR:/work" \
    -v hg-sp1-cargo-registry:/usr/local/cargo/registry \
    -v hg-sp1-home:/root/.sp1 \
    -w /work "$IMG" sleep infinity
fi

run() { docker exec "$CTR" bash -c "export PATH=/root/.sp1/bin:\$PATH CARGO_TARGET_DIR=/var/target; $*"; }
# Force the blst build script to re-run so the compiler choice is exercised,
# not replayed from cache.
purge_blst() { run 'rm -rf /var/target/elf-compilation/*/release/build/blst-* /var/target/elf-compilation/*/release/.fingerprint/blst-*'; }

set -e
# The rustup link for the succinct toolchain lives in the container layer, not
# the volumes — re-run sp1up whenever it is missing, not just on first install.
run 'test -x /root/.sp1/bin/cargo-prove && rustup toolchain list | grep -q succinct || { curl -sL https://sp1.succinct.xyz | bash && /root/.sp1/bin/sp1up; }'
run 'command -v riscv64-unknown-elf-gcc >/dev/null || { apt-get update -qq && apt-get install -y -qq gcc-riscv64-unknown-elf; }'
{
  run 'cargo prove --version; rustup run succinct rustc --version; riscv64-unknown-elf-gcc --version | head -1'
  docker inspect --format '{{index .RepoDigests 0}}' "$IMG"
} 2>&1 | tee "$LOGS/versions.txt"
set +e

run 'cd /work && cargo prove build' 2>&1 | tee "$LOGS/layer1-default.txt"
L1=${PIPESTATUS[0]}

purge_blst
run 'cd /work && cargo prove build --features mithril' 2>&1 | tee "$LOGS/layer2-mithril-blocked.txt"
L2=${PIPESTATUS[0]}

purge_blst
run 'export CC_riscv64im_succinct_zkvm_elf=riscv64-unknown-elf-gcc; cd /work && cargo prove build --features mithril' 2>&1 | tee "$LOGS/layer3-mithril-crossgcc.txt"
L3=${PIPESTATUS[0]}
run "sha256sum $ELF; cd /work && cargo prove vkey --elf $ELF" 2>&1 | tee -a "$LOGS/layer3-mithril-crossgcc.txt"

echo "layer1(default)=$L1 layer2(mithril,stock)=$L2 layer3(mithril,cross-gcc)=$L3"
