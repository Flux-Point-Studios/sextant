# U1 governance audit: sextant 8efa0d5 with the r57-live 77bb8225 oracle (verdict BLOCK, on the oracle only)

Review artifacts only. This branch sits on the reviewed commit 8efa0d59ddf5df2ad096bd1564ccf4e0dc14ad5c.
The auditor did not write the oracle, the Python reference or the Rust, so the labels here are independent.

## Result
- All 17 governance labels match an independent derivation from the Conway CDDL (IntersectMBO/cardano-ledger
  master b21c518e, conway.cddl sha256 316ed8ee…, plus its Haskell decoders; pallas was not used as the reference).
  The comparison is in `logs/audit17.log`.
- No false NO_USE and no panic in Rust across 117 hand-labelled vectors and 30,000 seeded fuzz cases (seed 20261025).
- On 77 real preprod proposal transactions (131 proposals; each body re-hashed to its transaction id), 129/129 typed
  credentials were found. See `realdata/`.
- **BLOCK, MEDIUM:** every oracle vector has one element, one proposal and a 0xE0 header. So the Rust mutants
  M22–M26 return a false NO_USE on ledger-valid shapes that preprod already contains, yet pass every suite:
  first-removed-member only, first-added-member only, first-treasury-recipient only, first-proposal only,
  and E0-header only. The same holds at dd79ec68 (`logs/forward_*.log`).
  **Fix:** add these existing vectors from `vectors/extra.json`, ids unchanged:
  - A01–A06 and A09–A14;
  - refusals C08, C16, C17, C20–C22, C25 and C27.

## Layout
- `vectors/extra.json`: the 117 vectors, each with id, kind, label, hex and description.
  - `extra.tsv` holds the model's labels; `extra.rust.tsv` and `extra.rust.rebuilt.tsv` hold the Rust verdicts.
  - `extra.compare.txt` compares labels with verdicts.
- `rt/`: the auditor's tools.
  - `rtcbor.py` and `rtenc.py`: a strict CBOR decoder and encoder.
  - `model.py`: the contract model.
  - `gen_extra.py`, `fuzz_gen.py` and `gen_resource.py`: generators.
  - `mutants.py` and `run_mutants.sh`: the Rust mutants.
- `logs/`:
  - `mutation/`: one log and verdict table per Rust mutant (18 of 31 killed by the project suites).
  - `forward_*.log`: M22–M26 re-run at dd79ec68.
  - `composition*.tsv` and `fuzz.compare.txt`.
- `skeptic/`: a self-reproduction from hand-assembled hex in a fresh clone (`run.sh`, `minimal.py`, `minimal.tsv`).
  It still needs an independent rerun. Run `skeptic/run.sh` against 8efa0d5.

The Python-reference side of this audit (its mutants, probes and results) is on the review branch of the same
name in the private r57-live repository.
