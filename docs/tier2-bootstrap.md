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

## What certified-state does and does NOT remove — precise trust accounting

A from-genesis replay does **not** eliminate the Mithril assumption for *canonicity*: a
header-verified segment proves internal validity but not that it is *the* chain — that rests on
the genesis-anchored certificate (see the README trust model). And Byron cannot be Praos-verified
at all (different consensus, no VRF/KES), so even a "from genesis, own path" replay authenticates
Byron bytes only by hash-linkage back from the first verified Shelley header plus the certified
immutable prefix — never assumption-free. So a Byron decoder and multi-hour syncs to avoid the
*canonicity* anchor the system already trusts would be negative-value purity.

But "certified-state removes zero assumptions" would be **trust-laundering**, and the research
that scoped T3 is where it surfaced: the two artifacts are certified by DIFFERENT trust classes,
not the same assumption twice.

- The Cardano **immutable blocks** are certified by the Mithril **STM stake-threshold
  multi-signature** — a decentralized SPO quorum. This is the basis Sextant's README advertises.
- The cardano-database **ancillary** (the ledger-state snapshot the bootstrap is fastest from) is
  signed by a **single Ed25519 key IOG operates** (the ancillary-key trail, GHSA-qv97-5qr8-2266).

Bootstrapping `UTxOSet(S)` from the ancillary swaps the anchor's **STATE** onto that single key
while the chain above stays quorum-certified. Sextant's constitution surfaces assumptions as
data, never absorbs them — so this one is named mechanically ([`AnchorBasis`], next section), not
hand-waved as "already trusted."

## AnchorBasis: the single-key state dependency, named — and dischargeable

`src/utxoset.rs` defines [`AnchorBasis`] (`StmCertified` vs `AncillarySigned`) and
[`SnapshotAnchor`] (`tip` + `basis`), banded distinctly like the spend-status ladder and carried
by the eventual Tier-2 verdict, so a consumer always sees whether S's state rests on the SPO
quorum or on IOG's ops key, and can never mistake one for the other.

The elegant part: **the substrate already built the discharge mechanism.** Because the blocks are
STM-certified, the verified extraction path (`extract_block_effects` applied through the T1
engine — the primitive T-compose proved) can recompute `UTxOSet(S)` from certified blocks
independently of the ancillary:

- **once**, a full from-genesis replay (`T3-audit`), then
- **incrementally**, take the last audited state and run extraction over the certified blocks up
  to the new snapshot, comparing the UTxO-set hash — literally T-compose at scale.

Once that loop runs, a snapshot whose hash matches is `StmCertified`, the IOG ancillary key is
demoted from a safety dependency to a bootstrap convenience, and Sextant publishes the cross-check
hash per snapshot. The `AnchorBasis` metadata + this discharge/audit hook are designed into T3
**now** (the types change signatures and are cheapest to get right before the parser); the audit
itself ships later. This finding and its discharge path also belong in the commitment note
(`docs/mithril-utxo-commitment-note.md`) — precise trust accounting with a working discharge is
the reputation this project is building.

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

## The concrete artifact (preprod, as scoped)

The certified ledger state is the cardano-database **ancillary**: **756 MB compressed / 1.88 GB
uncompressed**, a *separate* download from the ~18 GB of immutable blocks, in the **InMemory
UTxO-HD** flavor (Mithril has shipped this flavor since cardano-node v10.4.1), cardano-node
**11.0.1**, Conway. The UTxO map is keyed by `TxIn`, valued by `TxOut` — decoders `src/utxo.rs`
already has.

## T3 slice plan (amended)

1. **T3-fetch** — download + zstd/untar the ancillary; commit a small golden fixture (a handful
   of real UTxO entries + the file header + the manifest + certificate) so the parser AND the
   verify are testable offline without the 1.88 GB blob in git. `zstd` stays in the tools
   workspace, out of the trust core.
2. **T3-parse** — the encoder in ouroboros-consensus **is the spec**: pin cardano-node 11.0.1's
   exact consensus package, write the parser against the Haskell source, and commit a format note
   with source permalinks. **Transcription, not archaeology.** Assert the `InMemory` backing-store
   flavor explicitly; navigate *past* the rest of `ExtLedgerState` and decode ONLY the UTxO
   `LedgerTables`. **Hard-fail on unknown version fields** (a mutant that bumps the version asserts
   refusal). Differential-test the outpoint set against **three oracles of different provenance**:
   the one-time definitive full-set hash from an actual cardano-node 11.0.1 `query utxo
   --whole-utxo` (golden the whole-UTxO hash), plus cheap Koios spot-samples, plus the
   subset-consistency check against extraction over a certified window ending at S.
3. **T3-verify** — verify the cardano-database certificate + digests Merkle root + ancillary
   signature (composes `src/mithril.rs`), and pin the ancillary vkey per network with the same
   provenance discipline as the genesis keys.
4. **T3-load** — stream the parsed set into `RedbUtxoStore` → `UTxOSet(S)` tagged
   `AnchorBasis::AncillarySigned`. **Wiring, not order:** T3-load is *gated on a T3-verify
   verdict* in the composition — no code path where parsed-but-unverified state reaches the store.
   Then T5 composes membership@S + the window, surfacing the [`SnapshotAnchor`].
