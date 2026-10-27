# RISC Zero — Phase-0 recon note

**Version pins for everything cited below** (recon date 2026-07-14):

| Component | Pin |
| --- | --- |
| `risc0/risc0` (zkVM) | v3.0.5 (latest release, 2026-02-03) |
| `risc0/risc0-ethereum` (verifier contracts) | v3.0.1 (2025-11-06) |
| Vendor docs | `website/api_versioned_docs/version-3.0` in `risc0/risc0` @ main (rendered at dev.risczero.com/api) |
| `risc0/blst` fork | tag `v0.3.16-risczero.0` (default branch `risc0`, upstream v0.3.16 merged) |
| `risc0/zkcrypto-bls12_381` fork | tag `bls12_381/v0.8.0-risczero.1` |
| Audit registry | `risc0/rz-security` @ main, `audits/README.md` |

Sources are vendor docs (docs source files in-repo, cited by path) and vendor code (cited by file/line at the pinned tag). Where docs and code disagree, noted inline and flagged for `docs/notes/upstream-issues.md`.

---

## 1. Guest toolchain

- **Target:** `riscv32im-risc0-zkvm-elf` — `const RISC0_TARGET_TRIPLE` in [`risc0/build/src/lib.rs:56`](https://github.com/risc0/risc0/blob/v3.0.5/risc0/build/src/lib.rs#L56). C code in guests compiles via `riscv32-unknown-elf-gcc` with `-march=rv32im -nostdlib` (same file, ~L418–430) — this is what makes C libraries like blst buildable in-guest.
- **std IS supported in-guest.** `risc0-zkvm` exposes a `std` feature ([`risc0/zkvm/Cargo.toml`](https://github.com/risc0/risc0/blob/v3.0.5/risc0/zkvm/Cargo.toml) `[features]`), and vendor example guests build with it — e.g. the BLS12-381 example guest depends on `risc0-zkvm = { …, features = ["std"] }` with no `#![no_std]` ([`examples/bls12_381/methods/guest/Cargo.toml`](https://github.com/risc0/risc0/blob/v3.0.5/examples/bls12_381/methods/guest/Cargo.toml)). **Docs/code disagreement:** the docs page `zkvm/guest-code-101.md` (version-3.0) still presents `#![no_std]` as standard boilerplate and cites the long-dead `risc0_zkvm_guest::entry!` macro (v3.0.5 code uses `risc0_zkvm::guest::entry!`). Trust the code; file in upstream-issues. `no_std` remains available and is the right choice for `hg-guest` anyway (Sextant `guest` feature is `no_std + alloc`).
- **Journal mechanism:** guest reads untrusted input via `env::read` / `env::read_slice` / `env::stdin`; writes *private* host-visible output via `env::write`/`env::stdout`; commits *public* output via `env::commit` / `env::commit_slice` which appends to the **journal** (docs `zkvm/guest-code-101.md`, version-3.0). The receipt = journal + seal; the **ReceiptClaim** (the statement proven) "contains the journal, and it additionally includes information about the imageID, exit status … and the memory state at the end of execution" (docs `terminology`). This matches HANDOFF's journal-as-ABI doctrine: anything verdict-relevant must flow through `env::commit`.
- **Image ID — how computed:** [`ProgramBinary::compute_image_id`, `risc0/binfmt/src/elf.rs:394-397` @ v3.0.5](https://github.com/risc0/risc0/blob/v3.0.5/risc0/binfmt/src/elf.rs#L394):
  ```rust
  let merkle_root = self.to_image()?.image_id();
  Ok(SystemState { pc: 0, merkle_root }.digest::<Impl>())
  ```
  where `Impl` is `risc0_zkp::core::hash::sha::Impl` (SHA-256, elf.rs:21) and `merkle_root` is the root of the Merkle tree over the initial **memory image of the combined user ELF + kernel ELF** (since the v2 rv32im circuit, guests are a user/kernel pair; `MemoryImage` exposes `image_id()`/`user_id()`/`kernel_id()`, [`binfmt/src/image.rs:253-265`](https://github.com/risc0/risc0/blob/v3.0.5/risc0/binfmt/src/image.rs#L253)). Public API: `risc0_zkvm::compute_image_id(&[u8]) -> Result<Digest>` over the combined binary (docs.rs risc0-zkvm 3.0.5).
- **Reproducible builds (ADR-004):** the supported path is the Docker toolchain — `cargo risczero build` / `risc0-build` `use_docker` (`docker_build` in [`risc0/build/src/docker.rs`](https://github.com/risc0/risc0/blob/v3.0.5/risc0/build/src/docker.rs); output under `target/riscv-guest/riscv32im-risc0-zkvm-elf/docker/`). Vendor FAQ (`website/docs/faq.md`): "These ImageIDs will stay consistent across all builds due to a containerized process", with a worked `cargo risczero build` example printing ImageIDs. **Critical caveat from code:** a comment in `risc0/zkvm/Cargo.toml` (v3.0.5, `docker` test feature) states that without Docker "the rust build system will generate binaries that [are] not identical across all architectures." So the HANDOFF §3 requirement (two independent builds → identical image ID) is achievable **only via the pinned container**; non-docker builds must be treated as non-canonical.

## 2. Precompiles / accelerators — the decisive section

**Architecture.** There is no per-curve monolithic precompile. The rv32im v2 circuit has extension circuits for **SHA-256**, **Keccak** (separate keccak circuit, v1.2.1+), and a programmable big-integer engine (**bigint2**) that executes small "blob" programs for modular/EC arithmetic. Docs: `zkvm/precompiles.md` (version-3.0). The accelerator registry in code is the **`risc0-bigint2` crate** ([`risc0/bigint2/src`](https://github.com/risc0/risc0/tree/v3.0.5/risc0/bigint2/src) @ v3.0.5):

- `field/` — `modadd/modsub/modmul/modinv` at **256-bit and 384-bit** widths; `modmul_4096` (RSA); extension-field ops `extfield_deg2_{add,sub,mul}` at **256 and 384 bits**, `extfield_deg4_mul_256`, and `extfield_xxone_mul_{256,384}` (Fp2 mul for towers over x²+1). Checked wrappers `assert!(is_less(result, modulus))` because *the host computes, the circuit verifies* — dishonest-prover-hardened ([`field/mod.rs`](https://github.com/risc0/risc0/blob/v3.0.5/risc0/bigint2/src/field/mod.rs)).
- `ec/` — generic short-Weierstrass `ec_add`/`ec_double` at **256-bit and 384-bit** widths (`WeierstrassCurve<WIDTH>`); named curve configs shipped: `Secp256k1Curve`, `Secp384r1Curve` ([`ec/mod.rs`](https://github.com/risc0/risc0/blob/v3.0.5/risc0/bigint2/src/ec/mod.rs)).
- bigint2 was externally audited: Veridise, "bigint2 precompile", `veridise_bigint2_240324.pdf` (rz-security audit log).

**Patched-crate registry** (docs `zkvm/precompiles.md` version-3.0, table verbatim): `sha2` (0.10.8/0.10.7/0.10.6/0.9.9), `tiny-keccak` 2.0.2 (requires `unstable` flag), `k256` (0.13.1–0.13.4), `p256` 0.13.2, `curve25519-dalek` (4.1.0–4.1.3, i.e. **ed25519 accelerated**), `rsa` 0.9.6, `substrate-bn` 0.6.0 (**BN254**), `bls12_381` 0.8.0, `blst` 0.3.14, `crypto-bigint` (0.5.2–0.5.5), `c-kzg` (1.0.3, 2.1.x). Applied via `[patch.crates-io]` git tags. So: **sha256 yes (circuit), keccak yes (circuit, unstable), ed25519 yes, secp256k1 yes, bn254 yes, bigint/modmul yes — and BLS12-381 yes, with the qualification below.**

**BLS12-381 answer (the decisive question):**

- **There is NO pairing precompile and no G2 precompile.** What exists in the circuit: 384-bit Fp `modmul/modinv/modadd/modsub`, 384-bit **Fp2** ops (`extfield_deg2_*_384`, `extfield_xxone_mul_384`), and 384-bit G1 `ec_add`/`ec_double`.
- **Pairing runs as guest software over those accelerated ops.** In the `risc0/blst` fork, [`src/risc0.h`](https://github.com/risc0/blst/blob/risc0/src/risc0.h) remaps blst's field arithmetic onto `risc0_bigint_modmul_384` / `modinv_384` / `extfield_xxone_mul_384` etc. and blst's SHA-256 onto the `sys_sha_buffer` syscall; the Miller loop, final exponentiation, G2 arithmetic, and hash-to-curve remain compiled C (`pairing.c`, `fp12_tower.c`, `e2.c`, …) executing over accelerated limbs.
- The vendor's own [`examples/bls12_381`](https://github.com/risc0/risc0/tree/v3.0.5/examples/bls12_381) (v3.0.5) runs a **full `bls12_381::pairing(&G1, &G2)` in-guest** against a known-answer test, pinning the zkcrypto fork at rev `dead6adb067eb9fb95b1afc9582ec429b25e4cc6`. So pairings in-guest are a supported, exercised vendor path.
- **No vendor-published cycle counts for BLS12-381 pairing exist** in the version-3.0 docs, CHANGELOG, or fork READMEs (searched). The only vendor-documented bigint2 speedup datapoint: RSA JWT validation went **~15M → ~166k cycles** (CHANGELOG, v1.2.0, 2024-12-04). The benchmarks docs page publishes no numbers and says to run `cargo run --release --example datasheet` locally. **M0 must produce the STM-verification cycle/time/cost numbers ourselves.**

**Mithril seam (heliograph-specific):** `mithril-stm` pins `blst = { version = "0.3.16", features = ["portable"] }` (input-output-hk/mithril `mithril-stm/Cargo.toml` @ main, 2026-07), and RISC Zero ships tag **`v0.3.16-risczero.0`** in the blst fork (docs table says 0.3.14 but explicitly defers to the fork's `/releases`; the newer tag exists — minor docs lag). A single `[patch.crates-io]` line plausibly gets accelerated STM verification in-guest without forking mithril-stm. Unverified: interaction of blst's `portable` feature (runtime ADX detection) with the risc0 C build path — flag as an M0 spike item.

**Timing caveat (vendor):** precompiles "do not currently provide strict guarantees about constant-time execution" — irrelevant to heliograph (all inputs public), but note it in THREAT_MODEL for completeness.

## 3. Proving pipeline

Per docs `recursion.md` (version-3.0): execute → **Segments** → per-segment STARK proof (rv32im circuit) → `lift` → **SuccinctReceipt** (recursion circuit) → pairwise `join` until one succinct receipt → `identity_p254` (Poseidon254 re-hash) → `compress` → **Groth16Receipt** for on-chain. Three circuits: RISC-V STARK, recursion STARK, and a STARK-to-SNARK R1CS (circom) circuit. SuccinctReceipt ≈ **200 kB**; Groth16Receipt is "a very small validity proof, used primarily for on-chain verification" (terminology). Receipt kind selected via `ReceiptKind::{Composite,Succinct,Groth16}` in `Prover::prove_with_opts`.

- **Local proving:** fully open-source; CPU (x86/ARM) or CUDA GPU. **The Groth16 wrap only works on x86** — "Apple Silicon is currently unsupported (even via Docker)" (docs `generating-proofs/local-proving.md`, issues #1520/#1749). Dev iteration uses `RISC0_DEV_MODE` fake receipts (`generating-proofs/dev-mode.md`).
- **Hosted proving:** version-3.0 docs route remote proving to **Boundless** (decentralized proving marketplace, docs.beboundless.xyz); the Bonsai SDK still exists in-tree (`bonsai/sdk`) but the v3.0 remote-proving page describes only Boundless. No fixed vendor pricing is published — proving cost is market/hardware-dependent; BENCH.md must carry our own measured numbers.
- **Trusted-setup provenance (Groth16 wrap):** RISC Zero ran a public ceremony for the STARK-verify circom circuit — docs `trusted-setup-ceremony.md` (version-3.0). Facts: phase-1 is the **Hermez `powersOfTau28_hez_final_23.ptau` (2^23)**; circuit is `compact_proof/groth16/stark_verify.circom` (+`risc0.circom`), circom v2.2.2; `stark_verify.r1cs` SHA-256 `84d3c34b7c0eb55ad1b16b24f75e0b9de307f7b74089ea4a20a998390ee24178`; phase-2 run with PSE's **p0tion/DefinitelySetup**, transcript zkey on ceremony.pse.dev with per-contributor GitHub Gist attestations; full third-party re-verification procedure (snarkjs `zkey verify`) documented. Artifacts dated 2024-04-04 / 2024-05-17. This is exactly the "trusted-setup provenance" line THREAT_MODEL v1 needs — documented, reproducible, externally coordinated.

## 4. On-chain verification (EVM)

Repo: **`risc0/risc0-ethereum`** @ v3.0.1, license Apache-2.0. Contracts in `contracts/src/`:

- **Interface & image-ID binding:** `IRiscZeroVerifier.verify(bytes seal, bytes32 imageId, bytes32 journalDigest)` where `journalDigest = sha256(journal)` (vendor EvenNumber example, docs `blockchain-integration/contracts/verifier.md`). The Groth16 verifier reconstructs the claim on-chain: `_verifyIntegrity(seal, ReceiptClaimLib.ok(imageId, journalDigest).digest())` — image ID is bound into the proven claim, not merely compared ([`RiscZeroGroth16Verifier.sol:145-147`](https://github.com/risc0/risc0-ethereum/blob/v3.0.1/contracts/src/groth16/RiscZeroGroth16Verifier.sol)). The contract pins `CONTROL_ROOT_0/1` + `BN254_CONTROL_ID` as immutables — these commit to the zkVM circuit version; the 4-byte `SELECTOR` = truncated SHA-256 tagged hash `risc0.Groth16ReceiptVerifierParameters(control_root, bn254_control_id, vkey_digest)` and is checked against `seal[:4]`.
- **Router:** `RiscZeroVerifierRouter` maps `bytes4 selector → IRiscZeroVerifier`; `addVerifier`/`removeVerifier` are `onlyOwner`; removal writes a **tombstone so a selector can never be reused** ([`RiscZeroVerifierRouter.sol`](https://github.com/risc0/risc0-ethereum/blob/v3.0.1/contracts/src/RiscZeroVerifierRouter.sol)). Governance per [`contracts/version-management-design.md`](https://github.com/risc0/risc0-ethereum/blob/v3.0.1/contracts/version-management-design.md): router owned by a `TimelockController`, RISC Zero multisig as proposer; base verifiers are stateless/immutable.
- **Emergency stop:** `RiscZeroVerifierEmergencyStop` (Ownable2Step + Pausable proxy per base verifier). Two triggers: guardian `estop()`, and a **permissionless circuit breaker** — `estop(Receipt)` accepts anyone presenting a verifying receipt whose `claimDigest == bytes32(0)`, whose existence "demonstrates a critical vulnerability in the proof system". **Once stopped it can never be restarted** ([`RiscZeroVerifierEmergencyStop.sol`](https://github.com/risc0/risc0-ethereum/blob/v3.0.1/contracts/src/RiscZeroVerifierEmergencyStop.sol)). Heliograph's router design should decide consciously whether to sit on the managed router (inherits RISC Zero's timelock/multisig trust) or run an app-owned router over the same audited base verifier — the vendor design doc explicitly supports both.
- **Audits** (`rz-security/audits/README.md`): Hexens zkVM (2023-10), Hexens STARK-to-SNARK circuit (report 2024-05-20), **Hexens SNARK Verifier Contract (2024-06)**, Veridise zkVM (2024-06→2024-12, report 2025-02), Veridise bigint2 precompile (2024-12), Veridise keccak precompile (2025-02), zkSecurity Solana Groth16 verifier (2025-03), Hexens PoVW (2025-08). PDFs vendored in that repo.
- **Deployed addresses** (docs `verifier.md` version-3.0; same `RiscZeroGroth16Verifier` address across chains): Ethereum Mainnet router `0x8EaB2D97Dfce405A1692a21b3ff3A172d593D319`, verifier `0x2a098988600d87650Fb061FfAff08B97149Fa84D`; **Ethereum Sepolia** router `0x925d8331ddc0a1F0d96E68CF073DFE1d92b69187`; **Base Sepolia (84532, our suggested {{EVM_TESTNET}})** router `0x0b144e07a0826182b6b59788c34b32bfa86fb711`, verifier `0x2a098988600d87650Fb061FfAff08B97149Fa84D`, estop `0x724d375B5b622e15f0E64e9Deb76a4cB17877797`; plus Arbitrum, Avalanche, Linea, Base mainnets etc. Machine-readable registry: `contracts/deployment.toml` in risc0-ethereum.
- **Gas:** **no authoritative vendor gas figure found** in the version-3.0 docs, contracts README, or FAQ. Treat verify-gas as an M4 measurement (fork tests), not a citable number. (Folk numbers of ~250–300k gas for Groth16 verification circulate but are not vendor data — do not put them in an ADR.)

## 5. Licensing

| Component | License | Source |
| --- | --- | --- |
| `risc0/risc0` (zkvm, build, bigint2, binfmt, groth16, r0vm) | **Apache-2.0 OR MIT** (dual) | README @ main; per-file headers Apache-2.0 |
| `risc0/risc0-ethereum` (verifier contracts, Steel) | **Apache-2.0** | GitHub license detection + SPDX headers |
| `risc0/blst` fork | **Apache-2.0** (upstream supranational/blst) | GitHub license detection |
| `risc0/zkcrypto-bls12_381` fork | **MIT OR Apache-2.0** (upstream zkcrypto) | fork README license section |
| `risc0/paritytech-bn` (substrate-bn/BN254) | **Apache-2.0** | GitHub license detection |
| `risc0/RustCrypto-{hashes,elliptic-curves,crypto-bigint,RSA}` | **Apache-2.0 OR MIT** (upstream RustCrypto) | upstream licensing; crypto-bigint detected Apache-2.0 |
| `risc0/curve25519-dalek` | **BSD-3-Clause** (upstream dalek) | upstream licensing |
| `risc0/tiny-keccak` | **CC0-1.0** | GitHub license detection |
| `risc0/c-kzg-4844` | **Apache-2.0** | GitHub license detection |

All are Apache-2.0/MIT-compatible permissive licenses (BSD-3 and CC0 included); no copyleft anywhere in the dependency surface. `cargo deny` policy per HANDOFF §6 should pass without deviation. Verifier contracts are Apache-2.0 and can be vendored byte-identical.

## 6. Recursion / composition (ADR-002 feasibility)

- **Mechanism** (docs `zkvm/composition.md` version-3.0 + `examples/composition` @ v3.0.5): guest calls `env::verify(IMAGE_ID, journal_bytes)` → adds an **assumption** to the outer ReceiptClaim (a "conditional receipt"); host supplies the inner receipt via `ExecutorEnv::builder().add_assumption(receipt)`; the **`resolve`** recursion program discharges assumptions — automatically when proving with `ReceiptKind::Succinct` or `Groth16`. Crucially, this is *not* re-executing a verifier in RISC-V: "RISC Zero's approach to composition relies on adding assumptions to the ReceiptClaim and then resolving them" in the recursion circuit, so in-guest receipt verification costs ~zero guest cycles. Deferred assumptions supported since v1.2.0 (CHANGELOG).
- **Extend-by-one-certificate checkpointing (ADR-002) is architecturally supported.** The composition example passes the inner guest's image ID as an ordinary runtime `Digest` argument (`env::verify(MULTIPLY_ID, …)`, [`examples/composition/methods/guest/src/main.rs`](https://github.com/risc0/risc0/blob/v3.0.5/examples/composition/methods/guest/src/main.rs)) — nothing requires it to be a compile-time constant. For *self*-recursion (checkpoint guest verifying a prior receipt of itself) a compile-time self-ID is impossible (hash cycle); the workable pattern is: take the trusted image ID as guest input, `env::verify(that_id, prior_journal)`, and **commit that ID into the journal** so the top-level verifier (contract/SDK) checks journal-carried ID == pinned ID. This pattern is *not* explicitly documented by the vendor — treat as an M1 spike with a minimal two-step chain before committing ADR-002 wording. Alternative that avoids self-reference entirely: a fixed-depth pair of guests (step guest + aggregator guest), at the cost of two image IDs in the trust anchor set.
- On-chain, only the final (resolved) Groth16 receipt is verified; assumptions must all be resolved before `compress` — conditional receipts are not verifiable on-chain.

## 7. Honest unknowns / M0–M1 measurement obligations

1. **No vendor cycle counts for BLS12-381 pairing or STM-style multi-sig verification.** The M0 bakeoff must measure: cycles, wall time, and $ for one real preprod Mithril STM certificate verification (both zkVMs, per HANDOFF §4).
2. **blst-fork ↔ mithril-stm integration untested:** version match is exact (0.3.16) but the `portable` feature path and mithril-stm's use of blst APIs beyond what the fork accelerates need a compile-and-run spike.
3. **Verify-gas not vendor-documented** — measure in M4 fork tests.
4. **Self-recursion pattern undocumented** by vendor — M1 spike before ADR-002 freeze.
5. **Boundless proving costs** are marketplace-dependent; no vendor price sheet exists.
6. **Docs lag code** (candidates for `docs/notes/upstream-issues.md`): `guest-code-101.md` shows `#![no_std]` boilerplate + defunct `risc0_zkvm_guest::entry!` macro; precompiles table lists blst 0.3.14 while the fork ships `v0.3.16-risczero.0` (the docs do defer to fork `/releases`); the docs `terminology` page does not specify the image-ID hash construction (code does — §1).
7. **Groth16 wrap is x86-only** — constrains {{BENCH_HARDWARE}} and any dev on Apple Silicon.
