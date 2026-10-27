use crate::consts;
use crate::error::DecodeError;

/// Journal schema version (CLAIMS H1/§1.3): a single monotonic `u16` covering
/// the entire schema — any change to field set, order, types, semantics,
/// verdict codes, or encoding increments it. No minor versions.
///
/// `Draft` (0) is pre-freeze development only: every production verifier
/// rejects it unconditionally; only `decode_structural_draft` decodes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ClaimVersion {
    Draft = 0,
    V1 = 1,
}

impl ClaimVersion {
    /// Fail-closed decode (R2 codec half): no best-effort decode of an
    /// unknown layout, higher or lower.
    pub fn from_u16(raw: u16) -> Result<Self, DecodeError> {
        match raw {
            consts::CLAIM_VERSION_DRAFT => Ok(Self::Draft),
            consts::CLAIM_VERSION_V1 => Ok(Self::V1),
            _ => Err(DecodeError::UnknownVersion(raw)),
        }
    }

    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}
