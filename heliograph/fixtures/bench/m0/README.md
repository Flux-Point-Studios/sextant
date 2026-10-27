# M0 fixture registry — `fixtures/bench/m0/`

Pinned inputs for the M0 bakeoff (BENCH.md §3, §8.3). The **file bytes are the
pin**: both fixtures are verbatim HTTP response bodies from the public Mithril
aggregators — no reformatting, no re-serialization. Byte-exactness is
load-bearing for the content-hash recompute (BENCH.md §2.1 step 2). A
measurement row referencing a fixture not registered here is invalid.

Harvest was mainnet-read-only per HANDOFF §5: bytes read from the public
aggregator, committed to the repo; no mainnet deployment, no mainnet anchors in
shipped configs.

Counts below were parsed from the fixture JSON itself (`multi_signature` and
`aggregate_verification_key` are hex-encoded JSON documents; single signatures
= `len(signatures)`, lottery indices = `sum(len(entry.indexes))`, AVK leaves =
`mt_commitment.nr_leaves`).

## F-PP1 — preprod standard certificate

| field | value |
|---|---|
| file | `F-PP1.json` |
| source URL | `https://aggregator.release-preprod.api.mithril.network/aggregator/certificate/489d87708a169ac6ebdff3f6f4fd389f16e9a96425c01a83fcb8b8d92f31117e` |
| fetch date (UTC) | 2026-07-14 |
| file SHA-256 | `e181255a5721a0d5e7005109aabefe47000f838492d36b746b52e2c3e2a116b0` |
| size (bytes) | 5,155 |
| cert content hash (declared `hash`) | `489d87708a169ac6ebdff3f6f4fd389f16e9a96425c01a83fcb8b8d92f31117e` |
| network / magic | preprod / 1 |
| epoch | 290 |
| signed entity | `MithrilStakeDistribution(290)` |
| params k / m / phi_f | 5 / 100 / 0.7 |
| single signatures | 1 |
| lottery indices | 37 |
| AVK leaves (`nr_leaves`) | 24 |
| listed signers (metadata) | 9 |
| `previous_hash` | `ed9cb74a1a9fe460fc4e5ccf089ac5e924603ab6124482365cb5639b17f74856` |
| cert `sealed_at` | 2026-05-21T00:05:09.023283031Z |
| provenance | Same certificate as the Sextant golden vector `tests/vectors/mithril-cert-489d…117e.json` (Sextant @ `3a68b2f`); the aggregator fetch reproduced the pinned BENCH.md §3.1 file SHA-256 byte-for-byte, so the aggregator bytes and the Sextant vector are identical. |

BENCH.md §3.1 names the destination `preprod-cert-489d…117e.json`; the
orchestrated harvest fixed the filename as `F-PP1.json` (fixture-id naming).
The SHA-256 pin — the actual identity — is unchanged.

## F-MN1 — mainnet-read-only standard certificate

| field | value |
|---|---|
| file | `F-MN1.json` |
| source URL | `https://aggregator.release-mainnet.api.mithril.network/aggregator/certificate/f4ca8ecc280fa43cf9c4b6e20c9de24b36dbd410c34475f29fa59e9c8beea55c` |
| selected from | `GET …/aggregator/certificates` (tip listing, epoch 643), 2026-07-14 |
| fetch date (UTC) | 2026-07-14 |
| file SHA-256 | `2b00e86a10affd1f8092bf307c9f3cfef533772d2ac3b60bb8adffd2c360922e` |
| size (bytes) | 113,553 |
| cert content hash (declared `hash`) | `f4ca8ecc280fa43cf9c4b6e20c9de24b36dbd410c34475f29fa59e9c8beea55c` |
| network / magic | mainnet / 764824073 |
| epoch | 643 |
| signed entity | `CardanoTransactions(643, 13678859)` (epoch, latest block number) |
| params k / m / phi_f | 1944 / 16948 / 0.2 |
| single signatures | 59 |
| lottery indices | 1,971 |
| AVK leaves (`nr_leaves`) | 244 |
| listed signers (metadata) | 127 |
| total stake | 4,347,602,524,734,609 |
| `previous_hash` | `81fe209996c86832c40faeb2b4610cadc6c59a6967dbf163bb1b836f0bb727b3` |
| cert `sealed_at` | 2026-07-14T22:40:46.734029222Z |
| provenance | release-mainnet aggregator, read-only harvest per BENCH.md §3.2 |

Selection per BENCH.md §3.2: standard certificate (`genesis_signature` empty,
`multi_signature` non-empty), `CardanoTransactions` entity, single-signature
count exactly at the chain median (59). Lottery-index count is 1,971 vs the
2,434 median measured 2026-07-14 in `docs/notes/mithril-recursion-watch.md` §3;
all four tip candidates inspected at harvest clustered at 1,959–1,972 indices
(k = 1,944 quorum satisfied), so 1,971 is representative of current emission.
File size 113,553 B sits inside the ~126 KB median band (candidates ranged
108–128 KB).

## Sanity gate (run at harvest, 2026-07-14 — both green)

Per fixture: (1) the JSON parses; (2) the declared `hash` field is present;
(3) `multi_signature` is non-empty; (4) `genesis_signature` is empty (standard,
non-genesis certificate).

## Not yet done (blocking first run, per BENCH.md)

- Native Sextant `verify_standard` differential run on both fixtures
  (BENCH.md §3.2 step 4, §4.3) and the F-MN1 golden journal
  (`golden-journal-F-MN1.bin`, network_id `764824073`).
- Appending the F-MN1 pin row to BENCH.md §8.3 (fixture registry) — the ledger
  append travels with the orchestrator commit, not this README.
