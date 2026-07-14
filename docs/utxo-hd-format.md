# The Mithril cardano-database ancillary — InMemory UTxO-HD format (as observed)

The concrete format T3 bootstraps from, established by unpacking a real preprod ancillary
(epoch 300, immutable 5936, cardano-node **11.0.1**). This is the "spec by observation" that
T3-parse promotes to "spec by transcription": the exact key/value encoding is confirmed against
the ouroboros-consensus encoder for the pinned node version, and the parser hard-fails any codec
version it was not written against.

## Archive layout (`ancillary.tar.zst`)

756 MB compressed / 1.88 GB uncompressed, unpacked by `tools/snapshot`:

```
ancillary_manifest.json                 984 B   file→SHA-256 digests + Ed25519 signature
immutable/05937.{chunk,primary,secondary}       the last immutable chunk (small)
ledger/<slot>/meta                       69 B   backend + codec version (JSON)
ledger/<slot>/state                    ~31 MB   ExtLedgerState WITHOUT the UTxO tables
ledger/<slot>/tables                  ~909 MB   the UTxO map  ← the only file T3-parse reads
```

Two ledger snapshots ship (two consecutive slots); the parser takes the newer, whose slot is
S. **The UTxO map is a SEPARATE file (`tables`)** from the rest of the ledger state (`state`) —
so T3-parse decodes `tables` directly and never navigates `ExtLedgerState`. That is the amendment
"navigate past the rest of ExtLedgerState": there is nothing to navigate.

## `meta` — the version gate

```json
{"backend":"utxohd-mem","checksum":4044459344,"tablesCodecVersion":1}
```

T3-parse **asserts** `backend == "utxohd-mem"` (the InMemory flavor — the only one Mithril ships,
since cardano-node v10.4.1) and pins `tablesCodecVersion == 1`. Any other value fails closed
(a mutant that bumps the version asserts refusal) — the churn guard the fork required.

## `tables` — the UTxO map (`tablesCodecVersion` 1)

A single-element array wrapping an indefinite CBOR map of `bytes → bytes`:

```
81                      array(1)
  bf                    map(indefinite)
    58 22 <34 bytes>    key   = TxIn  : tx_id (32) ‖ big-endian u16 index
    59 xxxx <N bytes>   value = TxOut : serialized output (NOT needed for membership)
    …                   (entries are SORTED by key)
    ff                  break
```

The 34-byte key is **byte-identical to `RedbUtxoStore`'s own outpoint key** (`tx_id ‖ BE u16`,
the commitment-note §5.1 shape), verified on the real file: entries 0 and 1 share a `tx_id` with
index `0x0000` then `0x0001`, and the map's leading keys begin with low `tx_id` bytes because it
is sorted. For the Tier-2 **membership** set the parser reads ONLY the keys — each 34-byte key is
an `OutPoint`; the `TxOut` value is skipped (a consumer needing the output content pairs it with a
CardanoTransactions inclusion proof, per commitment-note §5.2).

## T3-parse — status and verification (three oracles, per the amended plan)

`tools/snapshot`'s `tables` module parses this on Sextant's own minicbor path (`snapshot-parse
<meta> <tables>`). On the real preprod snapshot it decodes **4,176,148 outpoints in ~0.8 s**
(memory-mapped, streamed — the set is never materialized), gated by the `meta` version.

1. **Cheap independence — DONE.** Koios spot-samples: the first parsed outpoints all exist on
   preprod and are `is_spent=false` — currently unspent, which is *consistent* with membership at
   S (unspent-now ⇒ unspent-at-S). The parser produces real, consistent outpoints, not garbage.
2. **Definitive, one-time — PENDING (needs a node).** Load this exact snapshot in a cardano-node
   11.0.1, `query utxo --whole-utxo`, and golden the full-UTxO-set hash against the parser's. Our
   deterministic fingerprint of the parsed set is `sha256` over the sorted 34-byte keys; the node
   differential is the T3-verify slice's headline check.
3. **Substrate cross-check — the discharge audit.** The subset-consistency check against
   `extract_block_effects` over a certified window ending at S (the incremental audit that
   discharges `AncillarySigned → StmCertified`).

## Committed fixtures

`tests/vectors/utxohd-meta.json` and `tests/vectors/utxohd-ancillary-manifest.json` are the real
(tiny) meta + manifest, so the version gate and the T3-verify digest/signature checks are testable
offline. The 909 MB `tables` blob is not committed; T3-parse's full differential runs against a
locally-fetched snapshot, and a small hand-built valid sub-map fixtures the parse shape in CI.
