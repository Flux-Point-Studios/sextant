# A consumer-grade UTxO-set commitment for Mithril

**From:** Flux Point Studios — Sextant, https://github.com/Flux-Point-Studios/sextant
**To:** the Mithril team
**Re:** ledger-state certification (issues #2525, #2720, #3269) — a request for a queryable commitment, and a commitment to be its first verifying consumer
**Contact:** fluxpointstudios@gmail.com

---

## 1. Who is asking

Sextant is a shipped, open-source, read-path verifying Cardano client. It verifies on its own code path — a byte provider supplies input, never a verdict:

- **Mithril certificate chain to genesis** (`src/mithril.rs`): recomputes every certificate's content hash byte-for-byte against `mithril-common`'s hashing (including the `U8F24` `phi_f` fixed-point and chrono nanosecond timestamps), verifies the genesis Ed25519 root libsodium-strict on its own Ed25519 path, verifies every standard certificate's STM multi-signature, and enforces the AVK binding across epochs — with DoS bounds on hostile AVK/signature blobs.
- **CardanoTransactions membership** (`src/inclusion.rs`): a pure-Rust recompute of your `MKMapProof<BlockRange>` — BLAKE2s-256 MMR, sub-proof roots bound into the master tree as `merge("start-end", sub_root)` leaves, stated `inner_root` fields deliberately never deserialized. It runs in the default, wasm32-safe dependency graph (blake2 + minicbor + serde_json; no blst).
- **Praos headers** (`src/chain.rs`, `src/vrf.rs`, `src/kes.rs`, `src/nonce.rs`): leader VRF (ECVRF-ED25519-SHA512-Elligator2), operational certificate + KES body signature, hash-linked gap-free segments, and nonce evolution proven across a real 299→300 epoch boundary.
- **A windowed liveness follower** (`src/window.rs`): a batch verdict that no spend of a watched outpoint appears in any body of a header-verified, body-committed (recomputed `hashAlonzoSegWits`), gap-free window inside the Mithril-certified region — fail-closed on every gap, truncation, or stale tip.

Every verdict is pinned by golden fixtures harvested from preprod/mainnet and differential tests against independent implementations (pallas, ckb-merkle-mountain-range, cardano-crypto). A C ABI (`include/sextant.h`) and the wasm build make the verifier embeddable; a mechanical CI gate forbids the ABI from ever claiming liveness vocabulary the cryptography cannot back.

We are, we believe, the consumer profile the ledger-state certification roadmap items are for — and we are already running against your production certificates.

## 2. What we understand of the current state (please correct us)

- **Shipped:** the Cardano node database certification multi-signs SHA-256 hashes of the immutable files; your docs state the last immutable file, the ledger state, and the volatile "cannot be signed as the Cardano node does not deterministically compute them" (https://mithril.network/doc/mithril/advanced/mithril-certification/cardano-node-database). The ledger-state ancillary files ship under an IOG-operated Ed25519 ancillary signature rather than the multi-signature (per the ancillary-key advisory trail, GHSA-qv97-5qr8-2266). This is a bootstrap artifact: it certifies a download, not a query.
- **In flight:** the ledger-state certification PoC (prepared ~May 2026): prototype #3269 introduces a `CardanoNodeLedgerState` signed entity over a *hash of the snapshot files*, and #2525 attacks the determinism blocker via UTxO-HD InMemory deterministic snapshots. (https://github.com/input-output-hk/mithril/issues/3269, https://github.com/input-output-hk/mithril/issues/2525, https://www.essentialcardano.io/development-update/weekly-development-report-as-of-2026-05-15)
- **The opening:** #2720 targets certification of the **Canonical Ledger State** (CIP-0165 SCLS) — ordered, namespaced key-value entries with a Merkle verification scheme, node-implementation-agnostic. (https://github.com/input-output-hk/mithril/issues/2720, https://github.com/tweag/cardano-cls)
- **SNARK track:** recursive SNARK aggregation in mithril-stm, a SNARK-friendly protocol message and genesis certificate. (https://updates.cardano.intersectmbo.org/2026-06-17-mithril/)

Our reading: nothing yet commits to a **per-entry, queryable commitment over the UTxO set with a client-facing membership proof**. A snapshot-image hash cannot answer "is this outpoint in the set?" for a client that will never download the snapshot. This note is a request to make the canonical-ledger-state certification produce exactly that — and an offer of a first consumer with a shipped verifier, so the format is validated against real consumption from day one.

## 3. The consumer insight: liveness at a snapshot is a MEMBERSHIP proof

The UTxO set at height S contains, by definition, exactly the outputs unspent at S. So the flagship consumer claim — *"outpoint O was unspent as of S"* — is simply **O ∈ UTxOSet(S)**: a positive membership proof. The easy direction. The same shape as the CardanoTransactions inclusion proof we already verify. No sparse-tree non-membership, no accumulator deletions, no absence proofs are required for this to be transformative.

(We are explicitly **not** asking for non-membership — "this outpoint never existed" is the hard direction, and no consumer path of ours needs it.)

## 4. Why this multiplies an already-shipped verifier

Today Sextant's windowed follower must observe the outpoint's **creation** inside the verified window — otherwise a provider could start the window after a spend. For an outpoint created years ago, that window is unbounded: verifying it means re-verifying headers and bodies from creation to tip.

A certified UTxO-set commitment **re-bases the window**:

> certified membership of O at snapshot S (Mithril quorum)
> + no spend of O observed in (S, tip] (header-verified, body-committed, gap-free window — shipped)
> + the caller's own freshness bound over the verified tip

The window shrinks from *creation→tip* (unbounded) to *snapshot→tip* — whose length is set entirely by your **certification cadence** (see §5.5). The composed claim is: **liveness at the snapshot plus no spend observed through a verified tip, under the Mithril-quorum and data-completeness assumptions, with the caller's own freshness bound — for any outpoint of any age, with no single trusted party.** Every piece of that pipeline except the commitment already ships. Your commitment is the missing multiplier, not the first brick of a new stack.

## 5. What a consumer-grade proof format needs

Concrete asks, deliberately minimal. Where we state a preference we will consume the alternative too; what we cannot consume is ambiguity.

**5.1 A deterministic outpoint key encoding, pinned by one vector.** Suggestion: raw 34 bytes — `tx_id` (32 bytes, Blake2b-256 of the transaction body bytes) ‖ big-endian `u16` output index (Conway encodes the index as `uint .size 2`). If SCLS's key encoding for the UTxO namespace differs, that is fine — one spec sentence and one test vector remove all canonical-CBOR ambiguity.

**5.2 A pinned leaf content decision.** Two workable options: (a) the bare outpoint key — proves liveness only; a client needing the output's value/address/datum pairs it with a CardanoTransactions inclusion proof of the creating transaction (works today); (b) key ‖ Blake2b-256(output wire bytes) — one proof yields liveness *and* authentic output content. We mildly prefer (b); we will consume either. Please pin which, with a vector.

**5.3 A hash-based commitment first; a SNARK verifier as the fallback ask.** Preference: a BLAKE2 binary Merkle tree or MMR over the canonically ordered entries — it mirrors the MKMap/MKTree pattern we already verify, costs a consumer ~200 lines with zero new dependencies, and verifies in microseconds inside wasm. If the recursive-SNARK track supersedes hash trees, our ask reduces to: an embeddable verifier (pure-Rust or cleanly wasm-compilable, no GMP-class native deps, no verifier-side trusted-setup surprises), a stable proof serialization, and vectors. Both are acceptable; the hash path lands in consumers first.

**5.4 Protocol-message binding that mirrors `cardano_transactions_merkle_root`.** Today we bind your transactions commitment like this: the part key is hashed in `ProtocolMessagePartKey` enum order; `SignedEntityType::CardanoTransactions(epoch, block_number)` is fed big-endian into the certificate hash; our accessor pairs the root with its `(epoch, block_number)` read from the same hashed content, so a verified certificate cannot disagree with what it signed. The ask: a new part key (e.g. `cardano_ledger_state_utxo_merkle_root`) plus a signed entity type carrying the snapshot coordinates, in exactly that pattern. If mirrored, a consumer's cost is one enum variant, one part key, one accessor — the entire STM / genesis / AVK-binding machinery is untouched.

**5.5 Snapshot coordinates inside the signed content: epoch, block_number, AND block_hash — and a stated cadence.** Three sub-asks, each load-bearing for the composed verdict:
- **The snapshot block's hash, not just its number.** The residual window's first block must be provably on *the chain the snapshot was taken on*: a consumer binds `first_block.prev_hash == snapshot_block_hash`. Without the hash in the signed content, a genuinely valid orphaned sibling block at S+1 (a real slot-leader block on a discarded fork) satisfies a number-only continuity check while describing a different chain. One 32-byte field closes it.
- **Boundary semantics, in one spec sentence + one vector:** is UTxOSet(S) the state *after* applying block S (includes outputs created in S, excludes outputs spent in S)? The residual window starts at S+1, so pre-state semantics would leave spends inside block S itself covered by neither the membership proof nor the window. We expect post-state; please pin it.
- **Cadence, stated with its consumer cost curve.** The residual window's length — and therefore the consumer's per-query cost — is exactly *tip − snapshot*: on the order of a hundred header verifications if block-cadenced like CardanoTransactions, up to ~21,600 (a full epoch of Praos VRF+KES verifies, on-device) if epoch-cadenced. We are not asking you to pre-commit to block cadence for an 11M-entry commitment without pricing it; we are asking that the cadence be a stated, first-class parameter of the design, because it is the single knob that sets the feature's practical value to a verifying client.

**5.6 Proof-size envelope at mainnet scale.** ~10–11M UTxO entries → binary tree depth 24 → 24 × 32 = **768 bytes of path per outpoint**; a few KB with serialization overhead; batch proofs amortize shared nodes. Any structure inside this envelope is fine — what matters is that the bound is logarithmic and stated.

**5.7 An aggregator proof endpoint mirroring `GET /proof/cardano-transaction`:** e.g. `GET /proof/cardano-ledger-state-utxo?outpoints=…` → `{ certificate_hash, proof, latest_block_number }`, batch-capable. The provider supplies bytes, never verdicts: the client recomputes the root from the proof and checks it against a certificate it independently anchored to the genesis key.

**5.8 Vectors first, stability later.** Unknown signed entity types must fail closed in existing clients (they do in ours: an unknown part key is a clean deserialization error, never a silent skip). Golden vectors for the key encoding, one leaf, one full proof, and one certificate binding the root — published with the PoC, even while unstable — are what let consumers arm their test suites before the format freezes, which is exactly the feedback you want before it freezes.

## 6. What Sextant commits to as first consumer

- **A running verifier fast** — within days of commitment-shaped PoC artifacts (vectors + a per-entry root in the signed message) on a testing network: membership verification in our wasm-safe default graph, composed with the shipped genesis-anchored certificate verify — end-to-end, no trusted party.
- **A reserved ABI slot, already committed.** Our C ABI bands every verdict basis: 1–9 cryptographic (watched-window = 1; **the ledger-state tier is reserved in 2–9**), 100+ economic/attested — so an attestation can never be numerically mistaken for a proof. Your commitment lands as an additive constant for every downstream integrator, never a breaking change.
- **Golden-fixture and differential-test discipline:** byte-exact fixtures harvested from your aggregator, adversarial mutation tests (tampered path node, substituted root, non-member outpoint), and differential checks against an independent implementation — the same harness that today cross-checks our MMR, VRF, KES, and Ed25519 paths against pallas, ckb-mmr, and cardano-crypto. Reproducible issues, filed early, while the format can still move.
- **Honest-scope reporting.** Our CI mechanically rejects any ABI surface that claims liveness the cryptography cannot back — which means when Sextant ships "certified member of the UTxO set at height S," that claim is exactly as strong as your certificate, no stronger, and visibly so to every reviewer.

## 6.5 In the meantime, we bootstrap from the ancillary — with honest trust accounting

Until the queryable commitment of §5 exists, we bootstrap `UTxOSet(S)` by parsing the cardano-database **ancillary** (the InMemory UTxO-HD ledger snapshot). We are explicit, in our own types and verdict metadata, that this is a **different trust class** from the rest of the chain of trust, and we do not launder the two together:

- The immutable **blocks** are certified by the **STM stake-threshold multi-signature** — the decentralized SPO quorum.
- The **ancillary** ledger state is signed by a **single IOG-operated Ed25519 key** (per the ancillary-key trail, GHSA-qv97-5qr8-2266).

So a Tier-2 membership answer carries an `AnchorBasis`: `AncillarySigned` (the single-key snapshot) vs `StmCertified` (the quorum). Crucially, `AncillarySigned` is **dischargeable** by us without any change on your side: because the blocks are STM-certified, our shipped extraction path recomputes `UTxOSet(S)` from certified blocks independently of the ancillary — a from-genesis audit once, then incremental audits — and where the recomputed UTxO-set hash matches the ancillary snapshot, the basis upgrades to `StmCertified` and we publish the cross-check hash per snapshot. The IOG key is thereby a bootstrap *convenience*, not a standing safety dependency.

The queryable per-entry commitment you would land (§5) makes this exact: a stake-quorum-certified membership proof replaces the ancillary snapshot as the `StmCertified` source directly, and the discharge audit becomes unnecessary. That is the convergence — our discharge path is the interim, your commitment is the destination.

## 7. What we are NOT asking for

Non-membership proofs. Tip-state liveness (our window covers the snapshot→tip residue). Any particular tree — Merkle, MMR, or JMT are all fine inside the envelope. A stable API before a PoC — vectors first.

## 8. Closing

The certification framework, the STM machinery, the aggregator, and the canonical-format track already exist on your side; the genesis-anchored verifier, the inclusion-proof pattern, the windowed follower, and the reserved ABI slot already exist on ours. A queryable UTxO-set commitment is the one missing piece between them — and it turns a snapshot people download into a ledger state anyone, on any device, can *verify a single coin against*. We would like to help you land it, starting with the first PoC bytes you publish.

— Flux Point Studios (Sextant)
