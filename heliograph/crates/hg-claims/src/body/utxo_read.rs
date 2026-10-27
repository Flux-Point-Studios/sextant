use alloc::vec;
use alloc::vec::Vec;

use crate::anchor::{AnchorBinding, AnchorField};
use crate::claim_type::ClaimType;
use crate::consts;
use crate::error::DecodeError;
use crate::header::{HeaderFields, JournalHeader};
use crate::raw;

/// U10 typed discriminant (ffi model). NOT a boolean — fixed slot, explicit
/// value, earns a mutant (ADR-003 D3). Selects which D5 rule U11 obeys:
/// Hash = the on-chain datum hash verbatim; Inline = Blake2b256 of the raw
/// inline-datum CBOR bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DatumKind {
    None = 0,
    Hash = 1,
    Inline = 2,
}

impl DatumKind {
    pub fn from_u8(raw: u8) -> Result<Self, DecodeError> {
        match raw {
            0 => Ok(Self::None),
            1 => Ok(Self::Hash),
            2 => Ok(Self::Inline),
            _ => Err(DecodeError::UnknownDatumKind(raw)),
        }
    }

    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// U12. On 0x0005 the ONLY legal value is `NotEstablished` (0), pinned in the
/// Sextant return type (utxo.rs:269). The higher bands (certified, attested)
/// exist only in the deferred claim types; the single-variant enum makes the
/// tier band uncoercible in the type (CLAIMS §1.5) — a proof does not upgrade
/// Tier 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SpendStatus {
    NotEstablished = 0,
}

impl SpendStatus {
    /// R7 band gate: any nonzero value on 0x0005 rejects (CLAIMS U12/§4.6).
    pub fn from_u8_utxo_read(raw: u8) -> Result<Self, DecodeError> {
        match raw {
            0 => Ok(Self::NotEstablished),
            _ => Err(DecodeError::IllegalSpendStatusOnUtxoRead(raw)),
        }
    }

    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// `0x0005` utxo-read (CLAIMS §3.5): verified output bytes of a
/// Mithril-certified transaction as of `certified_at_block` (model:
/// `SextantVerifiedOutput`). It does NOT prove the output is unspent.
#[derive(Debug, Clone, Copy)]
pub struct UtxoReadView<'a> {
    header: JournalHeader<'a>,
    anchor: AnchorBinding<'a>,
    datum_kind: DatumKind,
}

impl<'a> UtxoReadView<'a> {
    pub(crate) fn read(header: JournalHeader<'a>) -> Result<Self, DecodeError> {
        let journal = header.journal();
        let anchor = AnchorBinding::read(journal, consts::BODY_OFF + consts::UR_OFF_ANCHOR)?;
        let body = &journal[consts::BODY_OFF..];
        let datum_kind = DatumKind::from_u8(body[consts::UR_OFF_DATUM_KIND])?;
        // D3: the commitment slot is present-but-zeroed when kind == None.
        if datum_kind == DatumKind::None
            && !raw::is_zero(
                &body[consts::UR_OFF_DATUM_COMMITMENT
                    ..consts::UR_OFF_DATUM_COMMITMENT + consts::CS_W_HASH],
            )
        {
            return Err(DecodeError::NonzeroGatedPayload {
                field: "datum_commitment",
            });
        }
        // R7 band gate (CLAIMS U12): spend_status MUST be 0 on this type.
        SpendStatus::from_u8_utxo_read(body[consts::UR_OFF_SPEND_STATUS])?;
        Ok(Self {
            header,
            anchor,
            datum_kind,
        })
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

    pub fn anchor_tip_hash(&self) -> &'a [u8; 32] {
        raw::arr32(self.body(), consts::UR_OFF_ANCHOR_TIP_HASH)
    }

    pub fn certified_root(&self) -> &'a [u8; 32] {
        raw::arr32(self.body(), consts::UR_OFF_CERTIFIED_ROOT)
    }

    /// U5: `Blake2b256(tx_bytes)` computed in-guest — the guest, not the
    /// prover, names the transaction.
    pub fn tx_id(&self) -> &'a [u8; 32] {
        raw::arr32(self.body(), consts::UR_OFF_TX_ID)
    }

    /// U6: u16 BE, Sextant's outpoint key convention (utxoset.rs:386).
    pub fn out_index(&self) -> u16 {
        raw::be_u16(self.body(), consts::UR_OFF_OUT_INDEX)
    }

    pub fn lovelace(&self) -> u64 {
        raw::be_u64(self.body(), consts::UR_OFF_LOVELACE)
    }

    /// U8: `Blake2b256(raw_address_bytes)`; the raw address travels in the
    /// proof artifact and is checked against this commitment plus U9.
    pub fn address_hash(&self) -> &'a [u8; 32] {
        raw::arr32(self.body(), consts::UR_OFF_ADDRESS_HASH)
    }

    pub fn address_len(&self) -> u16 {
        raw::be_u16(self.body(), consts::UR_OFF_ADDRESS_LEN)
    }

    pub fn datum_kind(&self) -> DatumKind {
        self.datum_kind
    }

    /// U11, gated by U10 (D3): `None` when kind == None — the zeroed slot
    /// MUST NOT be consumed, enforced by this accessor's type.
    pub fn datum_commitment(&self) -> Option<&'a [u8; 32]> {
        match self.datum_kind {
            DatumKind::None => None,
            DatumKind::Hash | DatumKind::Inline => {
                Some(raw::arr32(self.body(), consts::UR_OFF_DATUM_COMMITMENT))
            }
        }
    }

    /// U12: always `NotEstablished` — validated at decode (R7).
    pub fn spend_status(&self) -> SpendStatus {
        SpendStatus::NotEstablished
    }

    pub fn certified_epoch(&self) -> u64 {
        raw::be_u64(self.body(), consts::UR_OFF_CERTIFIED_EPOCH)
    }

    pub fn certified_at_block(&self) -> u64 {
        raw::be_u64(self.body(), consts::UR_OFF_CERTIFIED_AT_BLOCK)
    }
}

/// Ties U10 and U11 together so Hash/Inline ALWAYS carry a commitment and
/// `None` NEVER does — the D3 gate is unrepresentable in the wrong state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatumField {
    None,
    Hash([u8; 32]),
    Inline([u8; 32]),
}

/// Encode input. `spend_status` is deliberately NOT a field: the encoder
/// writes 0 unconditionally — the tier band is not the guest's to choose on
/// this claim type (CLAIMS U12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtxoReadFields {
    pub header: HeaderFields,
    pub anchor: AnchorField,
    pub anchor_tip_hash: [u8; 32],
    pub certified_root: [u8; 32],
    pub tx_id: [u8; 32],
    pub out_index: u16,
    pub lovelace: u64,
    pub address_hash: [u8; 32],
    pub address_len: u16,
    pub datum: DatumField,
    pub certified_epoch: u64,
    pub certified_at_block: u64,
}

impl UtxoReadFields {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; consts::LEN_UTXO_READ];
        self.header.encode_into(ClaimType::UtxoRead, &mut out);
        self.anchor
            .encode_into(&mut out, consts::BODY_OFF + consts::UR_OFF_ANCHOR);
        let body = &mut out[consts::BODY_OFF..];
        raw::put_arr32(body, consts::UR_OFF_ANCHOR_TIP_HASH, &self.anchor_tip_hash);
        raw::put_arr32(body, consts::UR_OFF_CERTIFIED_ROOT, &self.certified_root);
        raw::put_arr32(body, consts::UR_OFF_TX_ID, &self.tx_id);
        raw::put_u16(body, consts::UR_OFF_OUT_INDEX, self.out_index);
        raw::put_u64(body, consts::UR_OFF_LOVELACE, self.lovelace);
        raw::put_arr32(body, consts::UR_OFF_ADDRESS_HASH, &self.address_hash);
        raw::put_u16(body, consts::UR_OFF_ADDRESS_LEN, self.address_len);
        match &self.datum {
            DatumField::None => {
                // U10 and the U11 slot stay zeroed (D3).
            }
            DatumField::Hash(c) => {
                body[consts::UR_OFF_DATUM_KIND] = DatumKind::Hash.as_u8();
                raw::put_arr32(body, consts::UR_OFF_DATUM_COMMITMENT, c);
            }
            DatumField::Inline(c) => {
                body[consts::UR_OFF_DATUM_KIND] = DatumKind::Inline.as_u8();
                raw::put_arr32(body, consts::UR_OFF_DATUM_COMMITMENT, c);
            }
        }
        // U12 spend_status: the zeroed slot IS the encoding of NotEstablished.
        raw::put_u64(body, consts::UR_OFF_CERTIFIED_EPOCH, self.certified_epoch);
        raw::put_u64(
            body,
            consts::UR_OFF_CERTIFIED_AT_BLOCK,
            self.certified_at_block,
        );
        out
    }
}
