use crate::consts;
use crate::error::DecodeError;
use crate::raw;

/// Read-only view over the 209-byte `CheckpointState` group (CLAIMS §2.4),
/// shared by 0x0001 (body offset 0) and 0x0002 (body offset 73). Borrows the
/// parent journal buffer — no owned copy. S11-S13 are presence-gated by S10
/// and only reachable through [`Self::certified_transactions`] (D3).
#[derive(Debug, Clone, Copy)]
pub struct CheckpointState<'a> {
    group: &'a [u8],
}

impl<'a> CheckpointState<'a> {
    /// R7: S10 in {0,1}; D3: S11-S13 present-but-zeroed when S10 == 0 —
    /// presenting them nonzero with the flag down rejects (CLAIMS §4.6).
    pub(crate) fn read(journal: &'a [u8], off: usize) -> Result<Self, DecodeError> {
        let group = &journal[off..off + consts::CS_LEN];
        match group[consts::CS_OFF_HAS_CERT_TXS] {
            0 => {
                if !raw::is_zero(&group[consts::CS_OFF_CTX_MERKLE_ROOT..]) {
                    return Err(DecodeError::NonzeroGatedPayload {
                        field: "certified_transactions",
                    });
                }
            }
            1 => {}
            value => {
                return Err(DecodeError::IllegalPresenceFlag {
                    field: "has_certified_transactions",
                    value,
                });
            }
        }
        Ok(Self { group })
    }

    // S1/S2 are carried VERBATIM from Sextant compute_hash (D5, no re-hash).
    pub fn root_hash(&self) -> &'a [u8; 32] {
        raw::arr32(self.group, consts::CS_OFF_ROOT_HASH)
    }

    pub fn tip_hash(&self) -> &'a [u8; 32] {
        raw::arr32(self.group, consts::CS_OFF_TIP_HASH)
    }

    pub fn tip_epoch(&self) -> u64 {
        raw::be_u64(self.group, consts::CS_OFF_TIP_EPOCH)
    }

    pub fn chain_length(&self) -> u32 {
        raw::be_u32(self.group, consts::CS_OFF_CHAIN_LENGTH)
    }

    /// S5: `Blake2b256(mt_root || BE64(total_stake))` — preimage formula
    /// frozen by D5, bytes lock at M1 (mithril-stm AVK wire order).
    pub fn avk_commitment(&self) -> &'a [u8; 32] {
        raw::arr32(self.group, consts::CS_OFF_AVK_COMMITMENT)
    }

    /// S6: `Blake2b256(next_avk_signed_bytes)`, read from the SIGNED
    /// protocol-message parts only (D5; sextant-legs Leg 2).
    pub fn next_avk_commitment(&self) -> &'a [u8; 32] {
        raw::arr32(self.group, consts::CS_OFF_NEXT_AVK_COMMIT)
    }

    pub fn stm_k(&self) -> u64 {
        raw::be_u64(self.group, consts::CS_OFF_STM_K)
    }

    pub fn stm_m(&self) -> u64 {
        raw::be_u64(self.group, consts::CS_OFF_STM_M)
    }

    /// S9: `phi_f` as U8F24 fixed-point — no float in the journal (CLAIMS S9).
    pub fn stm_phi_f_fixed(&self) -> u32 {
        raw::be_u32(self.group, consts::CS_OFF_STM_PHI_F_FIXED)
    }

    pub fn has_certified_transactions(&self) -> bool {
        // Validated to {0,1} at construction (R7).
        self.group[consts::CS_OFF_HAS_CERT_TXS] == 1
    }

    /// S11-S13 as one gated accessor: `Some` iff S10 == 1 (D3). Returning
    /// them together makes it impossible to read one without the flag having
    /// gated all three.
    pub fn certified_transactions(&self) -> Option<CertifiedTxAnchor<'a>> {
        if !self.has_certified_transactions() {
            return None;
        }
        Some(CertifiedTxAnchor {
            ctx_merkle_root: raw::arr32(self.group, consts::CS_OFF_CTX_MERKLE_ROOT),
            ctx_epoch: raw::be_u64(self.group, consts::CS_OFF_CTX_EPOCH),
            ctx_block_number: raw::be_u64(self.group, consts::CS_OFF_CTX_BLOCK_NUMBER),
        })
    }
}

/// The S11-S13 payload, only obtainable when S10 == 1. Every downstream
/// tx-inclusion / utxo-read anchor cites these (CLAIMS §2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertifiedTxAnchor<'a> {
    pub ctx_merkle_root: &'a [u8; 32],
    pub ctx_epoch: u64,
    pub ctx_block_number: u64,
}

/// Owned `CheckpointState` — the encode input from `hg-guest`. The tx group
/// is an `Option`, so S11-S13 populated while S10 == 0 is unrepresentable
/// (D3): `Some` writes flag 1 + payload; `None` leaves flag 0 + zeroed slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointStateFields {
    pub root_hash: [u8; 32],
    pub tip_hash: [u8; 32],
    pub tip_epoch: u64,
    pub chain_length: u32,
    pub avk_commitment: [u8; 32],
    pub next_avk_commitment: [u8; 32],
    pub stm_k: u64,
    pub stm_m: u64,
    pub stm_phi_f_fixed: u32,
    pub certified_transactions: Option<CertifiedTxFields>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertifiedTxFields {
    pub ctx_merkle_root: [u8; 32],
    pub ctx_epoch: u64,
    pub ctx_block_number: u64,
}

impl CheckpointStateFields {
    /// Write the 209-byte group into `out[off..off+209]`, big-endian.
    pub(crate) fn encode_into(&self, out: &mut [u8], off: usize) {
        let group = &mut out[off..off + consts::CS_LEN];
        raw::put_arr32(group, consts::CS_OFF_ROOT_HASH, &self.root_hash);
        raw::put_arr32(group, consts::CS_OFF_TIP_HASH, &self.tip_hash);
        raw::put_u64(group, consts::CS_OFF_TIP_EPOCH, self.tip_epoch);
        raw::put_u32(group, consts::CS_OFF_CHAIN_LENGTH, self.chain_length);
        raw::put_arr32(group, consts::CS_OFF_AVK_COMMITMENT, &self.avk_commitment);
        raw::put_arr32(
            group,
            consts::CS_OFF_NEXT_AVK_COMMIT,
            &self.next_avk_commitment,
        );
        raw::put_u64(group, consts::CS_OFF_STM_K, self.stm_k);
        raw::put_u64(group, consts::CS_OFF_STM_M, self.stm_m);
        raw::put_u32(group, consts::CS_OFF_STM_PHI_F_FIXED, self.stm_phi_f_fixed);
        if let Some(ctx) = &self.certified_transactions {
            group[consts::CS_OFF_HAS_CERT_TXS] = 1;
            raw::put_arr32(group, consts::CS_OFF_CTX_MERKLE_ROOT, &ctx.ctx_merkle_root);
            raw::put_u64(group, consts::CS_OFF_CTX_EPOCH, ctx.ctx_epoch);
            raw::put_u64(group, consts::CS_OFF_CTX_BLOCK_NUMBER, ctx.ctx_block_number);
        }
        // None: S10 and the S11-S13 slots stay zeroed (D3).
    }
}
