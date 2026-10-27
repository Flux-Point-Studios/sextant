use alloc::vec;
use alloc::vec::Vec;

use crate::anchor::{AnchorBinding, AnchorField};
use crate::claim_type::ClaimType;
use crate::consts;
use crate::error::DecodeError;
use crate::header::{HeaderFields, JournalHeader};
use crate::raw;

/// `0x0004` tx-inclusion (CLAIMS §3.4): membership of `tx_hash` in the
/// Mithril-certified transaction set with root `certified_root` — a monotone
/// "created" predicate, NOT unspent, NOT "currently exists". Verdicts: the
/// 400 band, journaled, not panicked.
#[derive(Debug, Clone, Copy)]
pub struct TxInclusionView<'a> {
    header: JournalHeader<'a>,
    anchor: AnchorBinding<'a>,
}

impl<'a> TxInclusionView<'a> {
    pub(crate) fn read(header: JournalHeader<'a>) -> Result<Self, DecodeError> {
        let anchor =
            AnchorBinding::read(header.journal(), consts::BODY_OFF + consts::TX_OFF_ANCHOR)?;
        Ok(Self { header, anchor })
    }

    pub fn header(&self) -> &JournalHeader<'a> {
        &self.header
    }

    pub fn anchor(&self) -> AnchorBinding<'a> {
        self.anchor
    }

    fn body(&self) -> &'a [u8] {
        &self.header.journal()[consts::BODY_OFF..]
    }

    /// I3: identity of the checkpoint claim supplying the root — bound per
    /// R6 (mode 1: verifier state; mode 2: inner journal S2).
    pub fn anchor_tip_hash(&self) -> &'a [u8; 32] {
        raw::arr32(self.body(), consts::TX_OFF_ANCHOR_TIP_HASH)
    }

    /// I4: the root membership is proven against — the whole trust story.
    pub fn certified_root(&self) -> &'a [u8; 32] {
        raw::arr32(self.body(), consts::TX_OFF_CERTIFIED_ROOT)
    }

    /// I5: the fact being claimed.
    pub fn tx_hash(&self) -> &'a [u8; 32] {
        raw::arr32(self.body(), consts::TX_OFF_TX_HASH)
    }

    pub fn certified_epoch(&self) -> u64 {
        raw::be_u64(self.body(), consts::TX_OFF_CERTIFIED_EPOCH)
    }

    pub fn certified_block_number(&self) -> u64 {
        raw::be_u64(self.body(), consts::TX_OFF_CERTIFIED_BLOCK_NUMBER)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxInclusionFields {
    pub header: HeaderFields,
    pub anchor: AnchorField,
    pub anchor_tip_hash: [u8; 32],
    pub certified_root: [u8; 32],
    pub tx_hash: [u8; 32],
    pub certified_epoch: u64,
    pub certified_block_number: u64,
}

impl TxInclusionFields {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; consts::LEN_TX_INCLUSION];
        self.header.encode_into(ClaimType::TxInclusion, &mut out);
        self.anchor
            .encode_into(&mut out, consts::BODY_OFF + consts::TX_OFF_ANCHOR);
        let body = &mut out[consts::BODY_OFF..];
        raw::put_arr32(body, consts::TX_OFF_ANCHOR_TIP_HASH, &self.anchor_tip_hash);
        raw::put_arr32(body, consts::TX_OFF_CERTIFIED_ROOT, &self.certified_root);
        raw::put_arr32(body, consts::TX_OFF_TX_HASH, &self.tx_hash);
        raw::put_u64(body, consts::TX_OFF_CERTIFIED_EPOCH, self.certified_epoch);
        raw::put_u64(
            body,
            consts::TX_OFF_CERTIFIED_BLOCK_NUMBER,
            self.certified_block_number,
        );
        out
    }
}
