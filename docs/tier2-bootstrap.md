# Tier-2 bootstrap: certified-state, not from-genesis replay

The decision record for how Sextant's Tier-2 UTxO set is bootstrapped. Settled after the T1/T2/
T2b primitives (the engine + own-path extraction + collateral delta) and T-compose (the
extract→apply inner loop) landed and the from-genesis-replay framing was reconsidered.

## Decision

**T3 = certified-state bootstrap, behind a storage trait.** Download the Mithril-certified
Cardano-node database — which *contains* the ledger state, UTxO set included — parse its
UTxO-HD on-disk store (keys are `TxIn`s, values are `TxOut`s) into `UTxOSet(S)`, pin the
supported node/Mithril distribution version, and differentially audit the parse. The genesis
anchor verify (`src/mithril.rs`) authenticates the artifact; from there Tier-2's `(S, tip]`
window is the shipped follower.

**From-genesis replay is demoted to an optional nightly audit mode (`T3-audit`), not the
product path.** Own-path Byron decode is rejected as scope.

## Why certified-state removes zero assumptions

A from-genesis replay does **not** eliminate the Mithril assumption, because Mithril is already
load-bearing for *canonicity*: a header-verified segment proves internal validity but not that
it is *the* chain — that rests on the genesis-anchored certificate (see the README trust
model). And Byron cannot be Praos-verified at all (different consensus, no VRF/KES), so even a
"from genesis, own path" replay authenticates Byron bytes only by hash-linkage back from the
first verified Shelley header plus the certified immutable prefix — never assumption-free.

So spending weeks on a Byron decoder and multi-hour syncs to avoid trusting an artifact the
system *already* trusts for a stronger property is negative-value purity. Certified-state
bootstrap is the path consistent with Sextant's own architecture — the "era amnesia by design"
of the original commitment-note scope (`docs/mithril-utxo-commitment-note.md`).

## The three walls, dissolved

1. **Byron** exits the critical path entirely (no from-genesis replay in the product).
2. **Sync time** becomes minutes for a user (download + parse a snapshot) instead of ~20 h.
3. **Scale** (~11M UTxOs) is real regardless — addressed by the storage trait below.

## The storage-trait discipline (non-negotiable)

The trust core owns no files (the sans-io property `src/follow.rs` and `src/utxoset.rs` already
hold). redb/sqlite **must not** enter `src/`. The shape:

- `UtxoSet` writes through a **storage trait** (`contains` / `insert` / `remove`), with the
  in-memory `BTreeSet` as the default, wasm-safe implementation.
- A native on-disk implementation (redb) lives in a **host adapter outside `src/`**, and the
  whole full-set capability is **feature-gated** (like `full-validation`).
- This preserves the wasm/mobile footprint story: browsers and phones keep the inclusion +
  windowed tiers and never carry an 11M-entry set; native hosts and the enclave opt in.

If T3 smuggles direct file I/O into `src/`, the sans-io property dies quietly. It must not.

## The audit mode is a headline artifact, not a cost

`T3-audit` recomputes the UTxO set from genesis on Sextant's own extraction path and asserts it
**byte-matches the certified ledger state at slot S**. That is simultaneously a differential
test of cardano-node itself, the strongest validation of T1/T2/T2b, and the conformance
infrastructure the node-diversity effort keeps asking for. Runs nightly in CI (20 h is fine for
a nightly job); publish the hash; re-run per release. Inside this offline tool — which is *not*
the trust substrate — leaning on pallas for the Byron decode is approved.

## Convergence with Mithril's ledger-state certification

Mithril's ledger-state certification PoC is in flight (`docs/mithril-utxo-commitment-note.md`).
Design T3's bootstrap as **`certified-UTxO-source → storage trait`** so that when the native
Mithril UTxO-set artifact ships, it is a drop-in source replacing the DB-parse — and Tier-2 of
the spend-status ladder lights up almost for free.
