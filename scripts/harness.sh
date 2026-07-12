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
  header_gate
}

# The C-ABI header (include/sextant.h) is the consumable boundary; guard it:
#  * no native panic=abort (it would silently no-op the FFI catch_unwind guard and
#    re-open the abort-the-host hole);
#  * the committed header matches what cbindgen regenerates from src/ffi.rs;
#  * the mithril prototype stays behind its #ifdef and no feature-gated crate's
#    symbols leak into the header.
header_gate() {
  # Match both TOML string forms — basic ("abort") and literal ('abort') are
  # semantically identical, so the guard must reject either.
  if grep -Eq "^[[:space:]]*panic[[:space:]]*=[[:space:]]*['\"]abort['\"]" Cargo.toml; then
    echo "harness: Cargo.toml sets panic=abort, which defeats the FFI panic guard" >&2
    exit 1
  fi

  command -v cbindgen >/dev/null 2>&1 || cargo install cbindgen --version '^0.28' --locked

  local generated
  generated="$(mktemp)"
  if ! cbindgen --config cbindgen.toml --crate sextant --lang c --output "$generated" 2>/dev/null; then
    rm -f "$generated"
    echo "harness: cbindgen failed to generate the C header" >&2
    exit 1
  fi
  if diff -u include/sextant.h "$generated"; then
    rm -f "$generated"
  else
    rm -f "$generated"
    echo "harness: include/sextant.h is stale — run 'make header' and commit it" >&2
    exit 1
  fi

  grep -q '#if defined(SEXTANT_MITHRIL)' include/sextant.h ||
    { echo "harness: SEXTANT_MITHRIL guard missing from the C header" >&2; exit 1; }
  if grep -Eiq 'blst|mithril_stm' include/sextant.h; then
    echo "harness: a feature-gated crate token leaked into the C header" >&2
    exit 1
  fi
}

case "$mode" in
  --changed) changed ;;
  --full) full ;;
  *)
    echo "usage: harness.sh --changed <file> | --full" >&2
    exit 64
    ;;
esac
