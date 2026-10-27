use crate::consts;
use crate::error::DecodeError;

/// Selects body layout and semantics (CLAIMS §2.1). Second journal field so a
/// shared image with claim dispatch is fail-closed on unknown type (ADR-003 D2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ClaimType {
    Checkpoint = consts::CLAIM_TYPE_CHECKPOINT,
    CheckpointExtension = consts::CLAIM_TYPE_CHECKPOINT_EXTENSION,
    HeaderSegment = consts::CLAIM_TYPE_HEADER_SEGMENT,
    TxInclusion = consts::CLAIM_TYPE_TX_INCLUSION,
    UtxoRead = consts::CLAIM_TYPE_UTXO_READ,
}

impl ClaimType {
    /// Fail-closed decode (R3 codec half). `0x0000`, the deferred band
    /// `0x0006..=0x0008`, the bench band `0x0F00..=0x0FFF`, and every other
    /// value reject — reserved ids are banded, not decodable.
    pub fn from_u16(raw: u16) -> Result<Self, DecodeError> {
        match raw {
            consts::CLAIM_TYPE_CHECKPOINT => Ok(Self::Checkpoint),
            consts::CLAIM_TYPE_CHECKPOINT_EXTENSION => Ok(Self::CheckpointExtension),
            consts::CLAIM_TYPE_HEADER_SEGMENT => Ok(Self::HeaderSegment),
            consts::CLAIM_TYPE_TX_INCLUSION => Ok(Self::TxInclusion),
            consts::CLAIM_TYPE_UTXO_READ => Ok(Self::UtxoRead),
            _ => Err(DecodeError::UnknownClaimType(raw)),
        }
    }

    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// `true` iff this claim type carries the `{anchor_mode, inner_image_id}`
    /// body prefix (CLAIMS §2.3).
    pub const fn has_anchor_binding(self) -> bool {
        matches!(
            self,
            Self::CheckpointExtension | Self::TxInclusion | Self::UtxoRead
        )
    }

    /// Byte length of a complete journal of this type; the R1 length gate
    /// reads this before trusting any field.
    pub const fn expected_len(self) -> usize {
        match self {
            Self::Checkpoint => consts::LEN_CHECKPOINT,
            Self::CheckpointExtension => consts::LEN_CHECKPOINT_EXTENSION,
            Self::HeaderSegment => consts::LEN_HEADER_SEGMENT,
            Self::TxInclusion => consts::LEN_TX_INCLUSION,
            Self::UtxoRead => consts::LEN_UTXO_READ,
        }
    }
}
