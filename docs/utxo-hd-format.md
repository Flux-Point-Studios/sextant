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

## T3-parse verification (three oracles, per the amended plan)

1. **Definitive, one-time:** load this exact snapshot in a cardano-node 11.0.1, `query utxo
   --whole-utxo`, and golden the full-UTxO-set hash against the parser's output hash.
2. **Cheap independence:** Koios spot-samples — a parsed outpoint is unspent on preprod.
3. **Substrate cross-check:** the subset-consistency check against `extract_block_effects` over a
   certified window ending at S (the discharge audit in miniature).

## Committed fixtures

`tests/vectors/utxohd-meta.json` and `tests/vectors/utxohd-ancillary-manifest.json` are the real
(tiny) meta + manifest, so the version gate and the T3-verify digest/signature checks are testable
offline. The 909 MB `tables` blob is not committed; T3-parse's full differential runs against a
locally-fetched snapshot, and a small hand-built valid sub-map fixtures the parse shape in CI.
