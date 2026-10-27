# SP1 (Succinct Labs zkVM) — Phase-0 recon

Researched 2026-07-14 against vendor sources only: docs.succinct.xyz and
github.com/succinctlabs (docs + code). Version context: SP1 **v6 "Hypercube"**
line; latest repo release **v6.3.1** (2026-06-25); docs recommend `sp1-zkvm = "6.1.0"`;
`sp1-contracts` latest release **v6.1.1** (2026-04-28); patched-crate tags are the
`*-sp1-6.0.0` series. All claims below should be re-pinned to exact crate versions
at bakeoff (M0) time.

## 1. Guest toolchain

- **Language/target.** Guests are Rust programs compiled to a custom RISC-V
  target. `sp1up` installs the `cargo prove` CLI and "the `succinct` Rust
  toolchain which has support for the `riscv64im-succinct-zkvm-elf` compilation
  target" ([install](https://docs.succinct.xyz/docs/sp1/getting-started/install)).
  Code confirms: `pub const DEFAULT_TARGET: &str = "riscv64im-succinct-zkvm-elf";`
  in [`crates/build/src/lib.rs`](https://github.com/succinctlabs/sp1/blob/main/crates/build/src/lib.rs)
  on `main`. **Docs/code disagreement:** the
  [compiling page](https://docs.succinct.xyz/docs/sp1/writing-programs/compiling)
  still says `riscv32im-succinct-zkvm-elf` (the pre-Hypercube 32-bit target).
  Per doctrine, trust the code: v6 is RV64IM. → file in `docs/notes/upstream-issues.md`.
- **std vs no_std.** The custom `succinct` toolchain exists precisely to build
  the Rust standard library for the zkVM target; guests are ordinary `main`
  programs wrapped by `sp1_zkvm::entrypoint!` ([setup](https://docs.succinct.xyz/docs/sp1/writing-programs/setup)).
  The docs pages fetched do not state an explicit no_std requirement — full-std
  guests are the marketed norm. (The Sextant `guest` feature should still be
  `no_std + alloc`-clean for cross-zkVM portability; that requirement comes from
  RISC Zero/portability, not SP1.)
- **Build & reproducibility.** `cargo prove build` calls `cargo build` for the
  zkVM target. The docs warn: "Running `cargo prove build` may not generate a
  reproducible ELF"; production builds use `cargo prove build --docker
  [--tag vX.Y.Z]`, which produces "a reproducible ELF that will be identical
  across all platforms" (verify by SHA-512 of the ELF)
  ([compiling](https://docs.succinct.xyz/docs/sp1/writing-programs/compiling)).
  The Docker image is `ghcr.io/succinctlabs/sp1`, default tag = the `sp1-build`
  crate version (code: `crates/build/src/lib.rs`). This is the ADR-004 recipe:
  pinned image tag → identical ELF → identical vkey.
- **Journal / public values.** SP1's journal equivalent is **public values**:
  `sp1_zkvm::io::read::<T>` for (private-by-default) inputs,
  `sp1_zkvm::io::commit::<T>` / `commit_slice` to commit outputs. "Committing
  to data makes the data public to the verifier"; "The public values bind a
  proof to a sub-set of the inputs of the program," read in commit order
  ([inputs-and-outputs](https://docs.succinct.xyz/docs/sp1/writing-programs/inputs-and-outputs)).
  On-chain, public values arrive as a raw `bytes` blob — a natural carrier for
  the `hg-claims` canonical encoding. `COMMIT` is a dedicated syscall
  (`0x00_00_00_10` in the registry, below).
- **Image-ID equivalent.** The **program verifying key**, exposed as a
  `bytes32` (`vk.bytes32()` from `client.setup(ELF)`, or offline via
  `cargo prove vkey --elf <path>`)
  ([solidity-sdk](https://docs.succinct.xyz/docs/sp1/verification/solidity-sdk)).
  It is derived deterministically from the ELF, so reproducible-ELF ⇒
  reproducible vkey. This bytes32 is heliograph's trust anchor on the SP1 path.
- **Determinism.** No explicit "execution is deterministic" guarantee was found
  in the fetched docs (honest gap). Structurally, nondeterminism enters only
  via the input stream and the **hint/unconstrained mechanism**
  (`ENTER_UNCONSTRAINED`/`EXIT_UNCONSTRAINED`, `HINT_LEN`/`HINT_READ`
  syscalls): hinted data is *not* constrained by the proof and must be
  validated in-guest. Patched crates use hints internally; the docs warn that
  "users using SP1's patched crates must ensure that their code is secure when
  compiled with the original crates" and that safe-usage requirements for
  precompiles "must be ensured by the developers"
  ([precompiles](https://docs.succinct.xyz/docs/sp1/optimizing-programs/precompiles)).
  → THREAT_MODEL: hints are an unbound-input class of their own.

## 2. Precompiles (decisive)

Authoritative registry in code:
[`crates/core/executor/src/syscall_code.rs`](https://github.com/succinctlabs/sp1/blob/main/crates/core/executor/src/syscall_code.rs)
(main, v6.x; guest-side wrappers in
[`crates/zkvm/lib/src/lib.rs`](https://github.com/succinctlabs/sp1/blob/main/crates/zkvm/lib/src/lib.rs)).
Full list of crypto syscalls:

| Family | Syscalls (hex code) |
|---|---|
| SHA-256 | `SHA_EXTEND` (0x00_30_01_05), `SHA_COMPRESS` (0x00_01_01_06) |
| Keccak | `KECCAK_PERMUTE` (0x00_01_01_09) |
| Poseidon2 | `POSEIDON2` (0x00_00_01_33) |
| Ed25519 | `ED_ADD` (0x00_01_01_07), `ED_DECOMPRESS` (0x00_00_01_08) |
| secp256k1 | `SECP256K1_ADD` (0x0A), `SECP256K1_DOUBLE` (0x0B), `SECP256K1_DECOMPRESS` (0x0C) |
| secp256r1/P-256 | `SECP256R1_ADD` (0x2C), `SECP256R1_DOUBLE` (0x2D), `SECP256R1_DECOMPRESS` (0x2E) |
| BN254 | `BN254_ADD` (0x0E), `BN254_DOUBLE` (0x0F), `BN254_FP_{ADD,SUB,MUL}` (0x26–0x28), `BN254_FP2_{ADD,SUB,MUL}` (0x29–0x2B) |
| **BLS12-381** | `BLS12381_ADD` (0x1E), `BLS12381_DOUBLE` (0x1F), `BLS12381_DECOMPRESS` (0x1C), `BLS12381_FP_{ADD,SUB,MUL}` (0x20–0x22), `BLS12381_FP2_{ADD,SUB,MUL}` (0x23–0x25) |
| Big-int | `UINT256_MUL` (0x1D), `UINT256_ADD_CARRY` (0x30), `UINT256_MUL_CARRY` (0x31), `U256XU2048_MUL` (0x2F) |
| Recursion | `VERIFY_SP1_PROOF` (0x1B), `COMMIT_DEFERRED_PROOFS` (0x1A) |

**BLS12-381 verdict: NO pairing precompile, NO dedicated G2 point ops, NO MSM.**
Only G1 add/double/decompress plus Fp and Fp2 modular arithmetic. The pairing
(Miller loop + final exponentiation) runs as guest software. Mitigation path,
per vendor docs and code:

- The vendor-maintained patched crate
  [`sp1-patches/bls12_381`](https://github.com/sp1-patches/bls12_381)
  (fork of zkcrypto `bls12_381` 0.8.0; tag `patch-0.8.0-sp1-6.0.0`, `-v2`
  variant exists) routes base-field and Fp2 arithmetic through the syscalls
  above. Since G2 coordinates are Fp2 and the Fp12 pairing tower is built on
  Fp2/Fp6, G2 arithmetic and the pairing are *partially* accelerated even
  without dedicated syscalls
  ([precompiles docs](https://docs.succinct.xyz/docs/sp1/optimizing-programs/precompiles)).
- **Concrete in-guest pairing cost (vendor-published):**
  [`succinctlabs/kzg-rs`](https://github.com/succinctlabs/kzg-rs) (built on the
  patched `bls12_381`) documents `verify_kzg_proof` = **9,390,640 cycles** —
  that is one KZG check ≈ one 2-pairing product plus G1/G2 mults — and
  `verify_blob_kzg_proof` = 27.2M cycles. Order-of-magnitude for planning:
  **a few million cycles per pairing** with the patched crate. No
  vendor-documented cycle count for a *bare* pairing or for an STM
  multi-signature verification exists; M0 must measure Sextant's actual
  Mithril workload.
- Full patched-crate list (docs, `-sp1-6.0.0` tags): `sha2` 0.10.9, `sha3`
  0.11.0, `crypto-bigint` 0.5.5, `tiny-keccak` 2.0.2, `curve25519-dalek`
  4.1.3, `curve25519-dalek-ng` 4.1.1, `k256` 13.4, `p256` 13.2, `secp256k1`
  0.29.1, `substrate-bn` 0.6.0, `bls12_381` 0.8.0, `rsa` 0.9.6, plus
  `sp1-verifier` (Groth16/PLONK verification in-guest via BN254 precompiles).
- **Integration implication for Sextant's Mithril leg:** if the STM
  verification path binds `blst` (C + asm — unusable in the guest), the guest
  build needs the pure-Rust `bls12_381` (patched) backend instead. Verify
  Sextant's BLS backend before writing the upstream-needs note; this may be
  the largest single item in the `guest` feature request.

## 3. Proving pipeline

Stages ([proof-types](https://docs.succinct.xyz/docs/sp1/generating-proofs/proof-types),
[security-model](https://docs.succinct.xyz/docs/sp1/security/security-model)):

1. **Core** (default): "a list of STARK proofs that in aggregate have size
   proportional to the size of the execution."
2. **Compressed**: constant-size STARK proof via recursion; the only type
   verifiable in-guest (→ §6).
3. **Groth16 wrap** (recommended): "~260 bytes… verified onchain for around
   ~270k gas."
4. **PLONK wrap**: "~868 bytes… around ~300k gas"; ~1.5 min slower to generate
   than compressed; "3-4x" higher proving cost than Groth16 per the security
   model page.

Proof system (v6 Hypercube): STARKs over the **KoalaBear** field
(P = 2^31 − 2^24 + 1) with Poseidon2 (width 16, S-box degree 3); recursion
compresses shards, then wraps to a BN254 SNARK for on-chain use. Stated
assumptions: random-oracle model for Poseidon2; FRI in the "unique decoding
regime" for Hypercube (Turbo relied on proximity-gap conjectures at "100 bits
of security"); "Recursive proofs do not incur a loss in security as the number
of recursive steps increases"
([security-model](https://docs.succinct.xyz/docs/sp1/security/security-model)).

**Trusted setup provenance** (security-model page):
- **Groth16** (circuit-specific): "Succinct conducted a circuit-specific
  trusted setup ceremony among several contributors" — 18 named participants
  (incl. representatives of Etherealize, Polygon, OP Labs, Offchain Labs,
  Coinbase), run on Semaphore's ceremony tooling (originally Worldcoin). Docs:
  users uncomfortable with this should "use PLONK instead."
- **PLONK** (universal): "SP1 uses the Aztec Ignition ceremony, which is a
  universal trusted setup designed for reuse across multiple circuits." (Docs
  phrase this as "PLONK does not require a trusted setup" — read: no
  *circuit-specific* ceremony; the universal SRS assumption remains.)
- Wrap-circuit artifacts are versioned (`SP1_CIRCUIT_VERSION` in
  `crates/build/src/`) and downloaded; local Groth16/PLONK proving requires
  **Docker + ≥16 GB RAM**
  ([hardware-requirements](https://docs.succinct.xyz/docs/sp1/getting-started/hardware-requirements)).

**What runs where:** local CPU; local **CUDA** prover (GPU with CUDA compute
capability ≥ 8.6, ≥24 GB VRAM recommended, plus ≥4 cores/16 GB RAM host)
([hardware-requirements](https://docs.succinct.xyz/docs/sp1/getting-started/hardware-requirements));
or the **Succinct Prover Network** — mainnet, paid in **$PROVE** deposited via
the Succinct Explorer, auction-priced (example params: base fee 0.2 PROVE, max
price per bPGU 2.0 PROVE; bPGU = billions of "prover gas units", SP1's cost
metric), authenticated by `NETWORK_PRIVATE_KEY`
([prover-network quickstart](https://docs.succinct.xyz/docs/sp1/prover-network/quickstart)).
**Unknowns (honest):** no canonical vendor $/proof or wall-time table for
reference workloads was found in the docs; prover-network **input privacy is
not documented** (assume inputs are visible to provers — fine for heliograph,
whose prover is untrusted by design, but note it for any confidential use).

## 4. On-chain verification

- Repo: [`succinctlabs/sp1-contracts`](https://github.com/succinctlabs/sp1-contracts)
  (release v6.1.1, 2026-04-28). Contains `SP1VerifierGroth16`,
  `SP1VerifierPlonk`, and the `SP1VerifierGateway` which "automatically routes
  proofs to the correct verifier based on their version"; verifiers can be
  **frozen** permanently ("Once frozen, a verifier cannot be unfrozen and can
  no longer be routed to"). Gateway routing + ownership is the admin surface
  heliograph's threat model must cover (who owns the gateway is NOT documented
  on the fetched pages — check `deployments/` + on-chain owner before M4).
- Interface (`contracts/src/ISP1Verifier.sol`, SPDX MIT, `pragma ^0.8.20`):

  ```solidity
  function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes) external view;
  ```

  "The first 4 bytes of proofBytes must match the first 4 bytes of target
  verifier's `VERIFIER_HASH`" — proof bytes are version-bound to a specific
  verifier build (`ISP1VerifierWithHash.VERIFIER_HASH()`). The `programVKey`
  is the guest binding: consumer contracts pin it as a constant and pass it on
  every call — exactly heliograph's image-ID registry pattern.
- Gas: ~270k (Groth16) / ~300k (PLONK) per the
  [proof-types docs](https://docs.succinct.xyz/docs/sp1/generating-proofs/proof-types).
- Deployments ([contract-addresses](https://docs.succinct.xyz/docs/sp1/verification/contract-addresses)):
  gateways on Ethereum, Arbitrum, Base, Optimism, BNB (+ testnets Sepolia,
  Arbitrum/Base/Optimism Sepolia, and others). Groth16 gateway
  `0x397A5f7f3dBd538f23DE225B51f532c34448dA9B` (same address on Ethereum
  mainnet, Sepolia, **Base Sepolia** — the suggested `{{EVM_TESTNET}}`); PLONK
  gateway `0x3B6041173B80E77f038f3F2C0f9744f04837185e` (mainnet, Base Sepolia)
  / `0xd685a80aF2d1761648e56716af4868d850Dae49B` (Sepolia). A "TEE PLONK"
  verifier also exists on Sepolia (`0x857364919fD97a1aF7d9C5E8F905C7d222af3D02`).
- Audits: [`sp1/audits/`](https://github.com/succinctlabs/sp1/tree/main/audits)
  contains cantina.pdf, code4rena.pdf, **hypercube-zellic.pdf** (v6 proof
  system), kalos.md, rkm0959.md, sp1-v4.md, veridise.pdf, zellic.pdf.
  `sp1-contracts` has its own `audits/` dir; its README states the contracts
  have "undergone an audit from Veridise."

## 5. Licensing (cargo-deny: Apache-2.0/MIT-compatible only)

- **`succinctlabs/sp1`** (workspace: `sp1-sdk`, `sp1-zkvm`, `sp1-verifier`,
  `sp1-build`, prover, recursion, …): **dual MIT / Apache-2.0** —
  `LICENSE-MIT` + `LICENSE-APACHE` at repo root; GitHub license API reports
  Apache-2.0. ✅ compatible.
- **`succinctlabs/sp1-contracts`**: Solidity sources carry
  `SPDX-License-Identifier: MIT` headers (verified `ISP1Verifier.sol`), **but
  the repo has no root LICENSE file** (checked root and `contracts/`). ⚠️
  Flag: SPDX-per-file is a workable license grant but a repo-level LICENSE is
  the clean story; confirm before vendoring the verifier byte-identical
  (§6 dependency policy) — worth an upstream issue.
- **Patched crates (`sp1-patches/*`)**: forks that inherit upstream licenses —
  zkcrypto `bls12_381` (MIT/Apache-2.0), RustCrypto crates (MIT/Apache-2.0),
  `rust-secp256k1` (CC0-1.0), `substrate-bn` (MIT/Apache-2.0). Not
  individually re-verified this pass; `cargo deny` will adjudicate exactly at
  M0 when the lockfile exists. CC0 needs an explicit allow if that path is used.
- **`kzg-rs`**: MIT (per repo). Host-side gnark (Apache-2.0) is not linked
  into our artifacts — wrap-circuit artifacts are downloaded binaries.
- Nothing GPL/AGPL/BUSL-licensed surfaced in any component heliograph would
  link or vendor. ✅ no §9 license deviation anticipated on the SP1 path.

## 6. Recursion / composition (ADR-002 feasibility)

- **First-class verify-inside-guest.** Syscall `VERIFY_SP1_PROOF`
  (0x00_00_00_1B) + `COMMIT_DEFERRED_PROOFS` (0x00_00_00_1A); guest API
  `sp1_zkvm::lib::verify::verify_sp1_proof(vkey_digest, public_values_digest)`
  with the `verify` feature on `sp1-zkvm`
  ([proof-aggregation](https://docs.succinct.xyz/docs/sp1/writing-programs/proof-aggregation)).
  The inner proof is not passed in-guest: host writes it with
  `stdin.write_proof(proof, vk)` and "the proof will automatically be read
  from the proof input stream by the prover" — verification is *deferred* and
  discharged during recursion/compression.
- **Compressed proofs only** can be aggregated: "you must generate a
  'compressed' SP1 proof" for in-guest verification. So the checkpoint cache
  is a compressed proof; Groth16/PLONK wrap happens only at the edge for EVM.
- Working vendor example: [`examples/aggregation`](https://github.com/succinctlabs/sp1/tree/main/examples/aggregation)
  (also `bls12381`, `fp2`, `fptower`, `tendermint`, `groth16` examples exist on main).
- **Extend-by-one-certificate loop is feasible as specified:** guest N+1 takes
  (compressed proof of checkpoint N, certificate N+1), calls
  `verify_sp1_proof(vk_digest, pv_digest_N)`, verifies the new certificate
  natively, commits journal N+1. Design note for ADR-002: with
  *self*-recursion the guest cannot embed its own vkey as a compile-time
  constant (circular dependency). Standard resolution: the inner vkey digest
  is an *input*, committed verbatim into the journal, and the chain invariant
  (inner vkey == outer vkey == registry-pinned image) is enforced by the
  router/consumer. That makes the vkey chain part of the journal ABI —
  fold into ADR-003.
- Vendor guidance: aggregation adds "some small overhead" per proof versus
  proving one big program — amortization only pays when re-proving the whole
  chain is worse, which is exactly the checkpoint case.

## Open items / unknowns carried forward

1. No vendor-published cycle count for a bare BLS12-381 pairing or an STM
   verification — kzg-rs numbers are the closest proxy; M0 measures the real
   Sextant workload.
2. Determinism is structural, not stated: get an explicit statement or test
   (identical inputs ⇒ identical journal across hosts) into the M0 harness;
   hints/unconstrained mode go in the unbound-input zoo.
3. `riscv32im` vs `riscv64im` docs/code split (v6 is 64-bit per code) — file
   upstream; matters for any cycle-count comparisons against RISC Zero (rv32).
4. `sp1-contracts` missing root LICENSE file — confirm/raise upstream before
   vendoring.
5. Gateway ownership/admin keys for the canonical deployments not documented
   on fetched pages — resolve before M4 (router design assumes we know who
   can re-route or freeze verifiers).
6. Prover-network input privacy undocumented (acceptable for heliograph's
   untrusted-prover model; note in THREAT_MODEL anyway).
