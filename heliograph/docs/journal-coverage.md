# Journal mutant-class coverage ledger

The unbound-input-zoo obligation (HANDOFF §7; ADR-003 mutant zoo; THREAT_MODEL
T-A1-1): every journal field earns a mutant, every mutant class is tracked
here, and `make gate` fails if any class row lacks a status. Rows are never
deleted — a class that cannot be exercised yet says when it locks.

Status vocabulary: `covered:<test>` (a named, passing test pins it) |
`locked-at:<milestone>` (cannot exist yet; the milestone that builds it) |
`argued:<doc>` (a filed, reviewed verdict-irrelevance argument).

| Class | What it kills | Status |
|---|---|---|
| every-byte flip (all goldens × every offset × 2 flips) | silent don't-care bytes; unbound input ranges (A1) | covered:journal_abi::mutation |
| endianness | LE/BE transcription drift vs ADR-003 D1 | covered:journal_abi::mutation (explicit endianness mutant) |
| length-gate (every prefix + every extension) | R1 holes; trailing-byte acceptance | covered:journal_abi::truncation |
| presence-flag ∉ {0,1} | R7 flag confusion | covered:journal_abi::fail_closed |
| gated-payload nonzero while flag 0 | D3 zeroed-when-absent violations (silent canonicality split) | covered:journal_abi::fail_closed |
| discriminant out of range (anchor_mode, datum_kind) | R7 enum confusion | covered:journal_abi::fail_closed |
| band violation (spend_status ≠ 0 on 0x0005) | tier coercion via the codec (A12) | covered:journal_abi::fail_closed |
| unknown version / draft-in-production | R2 downgrade + draft leak (A4) | covered:journal_abi::fail_closed |
| unknown claim type / unknown verdict code | R3/D6 dispatch confusion | covered:journal_abi::fail_closed |
| verdict-table equality vs native Sextant | lossy verdict-code collapsing (rejection parity) | locked-at:M1 (needs hg-guest + the Sextant corpus; T-A12-1) |
| commitment-preimage bytes (S5/S6 AVK wire) | wrong preimage transcription from mithril-stm 0.10.5 | locked-at:M1 (formula frozen in ADR-003 D5; bytes lock with the golden vector at M1) |
| no-silent-canonicalization (router digest == decoded bytes) | decode→re-encode→hash round-trip (T-A4-5, V-BLOB-VUL-004) | locked-at:M4 (needs the Solidity router; the Rust side is structural — views borrow the original buffer, no re-encode exists) |
| cross-surface gate-precedence parity (unknown version + unknown type) | mirrors diverging on rejection attribution | locked-at:M4 (normative order documented in `hg-claims::decode`; fixture lands with the router/SDK mirror) |
| rejection-journal population (identity/anchor populated, only unreached payload zeroed) | CLAIMS §4.2 obligation evaporating in hg-guest | locked-at:M1 (encoder demonstrates it in golden reject vectors; ENFORCEMENT is hg-guest's — pinned by T-A12-1 equality) |
