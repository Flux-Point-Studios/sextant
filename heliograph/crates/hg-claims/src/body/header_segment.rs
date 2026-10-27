use alloc::vec;
use alloc::vec::Vec;

use crate::claim_type::ClaimType;
use crate::consts;
use crate::error::DecodeError;
use crate::header::{HeaderFields, JournalHeader};
use crate::raw;

/// `0x0003` header-segment (CLAIMS §3.3): header + P1-P7. No anchor prefix —
/// H4 `genesis_vkey` is the declared trust context for composition. A valid
/// segment is NOT proven canonical (that rests on the Mithril anchor).
/// `reject_index` = offending block index.
#[derive(Debug, Clone, Copy)]
pub struct HeaderSegmentView<'a> {
    header: JournalHeader<'a>,
}

impl<'a> HeaderSegmentView<'a> {
    pub(crate) fn read(header: JournalHeader<'a>) -> Result<Self, DecodeError> {
        // No discriminants or gated payloads in this body: R1 + the header
        // gates are the whole structural surface.
        Ok(Self { header })
    }

    pub fn header(&self) -> &JournalHeader<'a> {
        &self.header
    }

    fn body(&self) -> &'a [u8] {
        &self.header.journal()[consts::BODY_OFF..]
    }

    /// P1: the assumed epoch nonce, committed verbatim — an unjournaled eta0
    /// would let a prover verify against a nonce of its choosing invisibly.
    pub fn eta0(&self) -> &'a [u8; 32] {
        raw::arr32(self.body(), consts::HS_OFF_ETA0)
    }

    pub fn block_count(&self) -> u32 {
        raw::be_u32(self.body(), consts::HS_OFF_BLOCK_COUNT)
    }

    pub fn seg_first_hash(&self) -> &'a [u8; 32] {
        raw::arr32(self.body(), consts::HS_OFF_SEG_FIRST_HASH)
    }

    pub fn seg_first_number(&self) -> u64 {
        raw::be_u64(self.body(), consts::HS_OFF_SEG_FIRST_NUMBER)
    }

    pub fn seg_tip_hash(&self) -> &'a [u8; 32] {
        raw::arr32(self.body(), consts::HS_OFF_SEG_TIP_HASH)
    }

    pub fn seg_tip_number(&self) -> u64 {
        raw::be_u64(self.body(), consts::HS_OFF_SEG_TIP_NUMBER)
    }

    pub fn seg_tip_slot(&self) -> u64 {
        raw::be_u64(self.body(), consts::HS_OFF_SEG_TIP_SLOT)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderSegmentFields {
    pub header: HeaderFields,
    pub eta0: [u8; 32],
    pub block_count: u32,
    pub seg_first_hash: [u8; 32],
    pub seg_first_number: u64,
    pub seg_tip_hash: [u8; 32],
    pub seg_tip_number: u64,
    pub seg_tip_slot: u64,
}

impl HeaderSegmentFields {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; consts::LEN_HEADER_SEGMENT];
        self.header.encode_into(ClaimType::HeaderSegment, &mut out);
        let body = &mut out[consts::BODY_OFF..];
        raw::put_arr32(body, consts::HS_OFF_ETA0, &self.eta0);
        raw::put_u32(body, consts::HS_OFF_BLOCK_COUNT, self.block_count);
        raw::put_arr32(body, consts::HS_OFF_SEG_FIRST_HASH, &self.seg_first_hash);
        raw::put_u64(body, consts::HS_OFF_SEG_FIRST_NUMBER, self.seg_first_number);
        raw::put_arr32(body, consts::HS_OFF_SEG_TIP_HASH, &self.seg_tip_hash);
        raw::put_u64(body, consts::HS_OFF_SEG_TIP_NUMBER, self.seg_tip_number);
        raw::put_u64(body, consts::HS_OFF_SEG_TIP_SLOT, self.seg_tip_slot);
        out
    }
}
