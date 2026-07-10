# LOOP: Sextant — read-path verifying Cardano client (Rust core, C-ABI/WASM trust substrate)

STATUS: ACTIVE

## Definition of Done
Every line must be provably true, with the proof named. The Stop gate and
the outer loop only trust `scripts/harness.sh --full`; everything else
needs a row in Evidence.

- [ ] `scripts/harness.sh --full` exits 0
- [ ] Header validation: decodes current-era headers and verifies leader
      VRF + KES against ≥20 golden vectors pulled from preview and
      mainnet, byte-identical verdicts to pallas on the same inputs —
      proof: named differential test run in harness output
- [ ] Chain following: validates a stored preview header sequence across
      an epoch boundary, including nonce evolution — proof: test run
      naming the epoch and the evolved nonce value
- [ ] Mithril: verifies a genesis-anchored certificate chain fetched from
      the network aggregator — proof: test naming the certificate hash
- [ ] UTxO verification for the read path designed and
      implemented (snapshot-anchored or proof-based — decide in a design
      slice first), with a negative test proving a tampered UTxO claim is
      rejected — proof: named test
- [ ] Artifacts: single static lib + C header via cbindgen, and a wasm32
      build, both produced in CI — proof: release workflow run link
- [ ] Live: the first downstream consumer's execution path performs one
      verified UTxO read on preview against a real order before a spend
      decision, and rejects a spoofed RPC response in the same test —
      proof: service log excerpt + the UTxO ref
- [ ] Diff carries no single-caller abstractions and no dead code

## Plan
- [x] Failing test: decode one current-era header from a checked-in CBOR
      vector; assert slot, block number, issuer vkey
- [x] Vector-set differential harness: every `tests/vectors/*.block` is
      decoded on Sextant's own path and cross-checked against pallas
      (block_number/slot/issuer_vkey), the validated era is surfaced on
      `HeaderView`, and cross-era coverage is asserted — the scaling
      primitive for the ≥20-vector requirement (harvested vectors are
      auto-verified here or the harness goes red; vectors are inputs to
      verify, never trusted state)
- [ ] Vector harvester + live pull: fetch ≥20 preview+mainnet headers from
      Dolos/Blockfrost into tests/vectors/ (needs network egress + provider
      key — run in the sandboxed loop env). The harness above is the
      acceptance gate for whatever it writes.
- [ ] Failing test: leader VRF verification on vector 1; implement;
      differential-check against pallas
- [ ] KES + operational certificate verification, same pattern
- [ ] <derive the next slice from the Definition of Done, one at a time>

## Constraints
- Read-path only. No transaction building, no interface layer — that
  belongs to the separate write-path layer this library sits under.
- Rust core. pallas crates permitted as dependencies, but every verdict
  this library returns must be computed by its own code path and
  differentially tested — never delegated to an RPC.
- No trusted oracle in the verify path: Dolos/Blockfrost may supply
  bytes, never verdicts.
- Targets: static lib + C ABI (cbindgen), wasm32. Keep the core no_std-friendly where feasible.
- Zig embedding layer is out of scope until the Rust core's DoD is green.

## Merge policy
- Auto-merge: yes. Merge requires all of: CI harness check green,
  red-team VERDICT: SHIP, no unresolved review threads.
- Method: squash; delete branch on merge; sync default branch after.
- Merge-triggers-deploy repos: n/a (library; releases tag manually until
  the Live line is close).
- Standing authorizations: starting scripts/loop.sh for Plan items in
  this file needs no further approval.

## Evidence
| When (UTC) | Claim | Proof |
|---|---|---|
| 2026-07-10 20:17 UTC | Repo onboarded onto fluxpoint-loop; harness gates the DoD | `scripts/harness.sh --full` exits 0 — `cargo fmt --check`, `clippy -D warnings`, release build (lib+cdylib+staticlib), `cargo test` (1 passed), `wasm32-unknown-unknown` release build |
| 2026-07-10 20:20 UTC | Woodpecker CI runs the harness on push | `ci/woodpecker/push/harness` success on `main` — https://ci.fluxpointstudios.com/repos/15/pipeline/1/1 |
| 2026-07-10 20:54 UTC | Header decode slice: block_number/slot/issuer_vkey from a real Conway block, byte-identical to pallas on the same input | `cargo test --test header_decode` — `decodes_conway_header_fields` + `matches_pallas_on_the_same_bytes` both pass in `scripts/harness.sh --full` (exit 0); vector `tests/vectors/conway1.block`, expected block 1093546 / slot 22075282 / issuer `e856c8…b08c4a` |
| 2026-07-10 21:09 UTC | Red-team BLOCK closed: adversarial CBOR can no longer force a wrong successful decode (array-count/era/prev_hash/trailing-byte defects) | Decoder now validates exact array counts, Praos era {6,7}, 32-byte prev_hash/issuer, full input consumption; 6 regression tests (`rejects_*`) + Babbage differential added; `scripts/harness.sh --full` exit 0, 9 tests pass |
| 2026-07-10 21:16 UTC | Red-team re-attack: 4 findings verified closed, no panic/DoS; 2nd BLOCK (non-canonical era u16/u32/u64 = Sextant-Ok/pallas-Err) fixed | Era now required to be a canonical U8 token, matching pallas `block_era`; `rejects_non_canonical_era_encoding` asserts both Sextant and pallas reject the u64-widened Conway block; `scripts/harness.sh --full` exit 0, 10 tests pass |
| 2026-07-10 21:22 UTC | Slice 1 merged to main with red-team SHIP; 362,161 both-accept fuzz cases, 0 field mismatches vs pallas | PR #1 squash-merged (`ae942a3`), CI `ci/woodpecker/pr/harness` green (pipeline 8), red-team `VERDICT: SHIP`; `scripts/harness.sh --full` exit 0 on merged main |
| 2026-07-10 23:15 UTC | Vector-set differential harness: every `tests/vectors/*.block` decoded on Sextant's path is byte-identical to pallas on block_number/slot/issuer_vkey; validated era surfaced on `HeaderView`; cross-era coverage asserted (≥1 Babbage era-6 + ≥1 Conway era-7, ≥2 vectors) — the ≥20-vector requirement is now drop-in | `tests/header_decode.rs::every_vector_matches_pallas_and_is_praos` (dir sweep, panics red if either decoder rejects or fields disagree) + `decodes_conway_header_fields` (era==7) + `decodes_babbage_header_era` (era==6); vector leading bytes confirm the `[era]` token (`8206…`=Babbage, `8207…`=Conway). Verified by the Stop-hook `scripts/harness.sh --full` DoD gate (fmt / clippy -D warnings / release build / cargo test / wasm32); direct `cargo` is permission-gated this session, so the gate is the verifying oracle |
| 2026-07-10 23:20 UTC | Red-team of the iter-2 diff: `VERDICT: SHIP`. `era as u8` provably lossless (u32 gated to {6,7} before the sole `HeaderView` constructor); sweep can't false-green below the two `include_str!`-pinned cross-era anchors; no `rejects_*` coverage lost; fs access confined to the compile-time manifest dir | `fluxpoint-loop:red-team-reviewer` run — 2 findings, both LOW/non-blocking: (1) non-`.block` files are silently skipped by the sweep → the future ≥20 gate must assert on the verified `checked` count, not raw file count; (2) symlink/empty/dir `x.block` fails closed (RED), safe direction. Folded into the harvest handoff below |

## Notes for the next iteration
State (2026-07-10, iter 2): the differential check now sweeps the whole
`tests/vectors/` set — every `*.block` is decoded on Sextant's path and must
agree with pallas on block_number/slot/issuer_vkey, so ≥20 vectors is a
drop-in (add files, they're auto-verified or the harness goes red). The
validated Praos era is surfaced on `HeaderView.era` (u8, ∈{6,7}); anchored
by `decodes_conway_header_fields` (era 7) and `decodes_babbage_header_era`
(era 6). Still only 2 vectors present, both mainnet — the ≥20 preview+mainnet
box is NOT checked.

ENVIRONMENT BLOCKER (this session): the loop agent can Read/Edit files and
run read-only git, but `cargo`, the harness, `gh`, network egress, and
mutating git (branch/commit) are all permission-gated. So this iteration
could not: run `--full` itself (the Stop-hook DoD gate is the verifying
oracle), fetch vectors from the network, or open/merge a PR. Edits are left
in the working tree for the outer `scripts/loop.sh` to snapshot to a
`loop/iter-*` branch and promote via PR + CI. If you are that
egress-enabled run, commit these edits and open the PR.

Attacking next (needs the egress-enabled loop env — cargo + a Blockfrost
project id or a reachable Dolos):
  1. Write `scripts/harvest.sh` (curl `/blocks/{hash}/cbor` for Blockfrost,
     extract `.cbor`; or fetch raw hex from Dolos) → write
     `tests/vectors/<block_number>.block`. Then run `cargo test --test
     header_decode` — `every_vector_matches_pallas_and_is_praos` is the
     acceptance gate (a wrong `[era,block]` shape is rejected). Pull ≥20
     across preview + mainnet to close the ≥20-vector DoD box. When you add
     the `checked >= 20` assertion, gate on the verified `checked` count, not
     on the raw file count in the dir — a mis-named vector (wrong extension)
     is silently skipped by the sweep and must not inflate the ≥20 claim
     (red-team LOW #1). Name a preview vector so the set spans both networks.
  2. Then leader VRF verification on vector 1; differential-check vs pallas.
Alt path if Blockfrost's cbor endpoint does not return the `[era,block]`
wrapper pallas expects: pull raw blocks from a Dolos node's n2c
`BlockFetch`/chainsync (already `[era,block]`-wrapped), or from a
`cardano-cli`/mithril snapshot, and hex-encode those.

Infra: Woodpecker runs the harness on push/PR (`ci/woodpecker/*/harness`);
repo is Flux-Point-Studios/sextant — if CI webhooks go quiet, Repair/re-sync
repo 15 in Woodpecker. Ratchet points not yet gated: cbindgen C-header
generation and the preview-net Live UTxO exercise — each turns on when its
DoD slice ships.

Carried from red-team (for when body/VRF validation lands): now that
`HeaderView.era` is available, cross-check it against the transaction-body
schema so a Conway-body-labeled-Babbage block cannot pass full validation.