#!/usr/bin/env bash
# Flux Point harness contract for cardano-verifier-client — the single
# source of "done":
#   scripts/harness.sh --changed <file>   fast scoped check after one edit
#   scripts/harness.sh --full             everything the DoD gates on
# Exit 0 is green; anything else blocks the Stop-hook gate and the outer
# loop. Every read-path verdict the DoD names (header VRF/KES, nonce
# evolution, Mithril certificate chain, tampered-UTxO rejection,
# differential parity with pallas) lands as a `cargo test` case and runs
# under --full; the wasm32 build guards the DoD's second artifact target.
set -euo pipefail
cd "$(dirname "$0")/.."

mode="${1:---full}"
file="${2:-}"

changed() {
  case "$file" in
    *.rs | *.toml) cargo check --quiet ;;
    *) : ;;
  esac
}

full() {
  cargo fmt --all -- --check
  cargo clippy --all-targets --all-features -- -D warnings
  cargo build --release
  cargo test --all-features
  cargo build --release --target wasm32-unknown-unknown
}

case "$mode" in
  --changed) changed ;;
  --full) full ;;
  *)
    echo "usage: harness.sh --changed <file> | --full" >&2
    exit 64
    ;;
esac
