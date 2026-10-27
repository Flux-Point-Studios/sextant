use core::fmt;

use crate::version::ClaimVersion;

/// Verifier-side structural rejections (CLAIMS §4.6): no proof is accepted and
/// nothing is journaled. Journal verdicts are [`crate::Verdict`], never this
/// type. Every fail-closed reason is a distinct variant — no catch-all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Buffer shorter than the 4-byte `(claim_version, claim_type)` prelude,
    /// so R1 cannot even key the length table.
    TruncatedHeader { actual: usize },
    /// R1: buffer length != `LEN[claim_type]`.
    LengthMismatch { expected: usize, actual: usize },
    /// R2 (codec): `claim_version` outside the known set {0, 1}.
    UnknownVersion(u16),
    /// R2 (draft gate): the version decodes but this entry point does not
    /// accept it — Draft 0 only via `decode_structural_draft` (CLAIMS §1.3).
    VersionNotAccepted(ClaimVersion),
    /// R3 (codec): `claim_type` outside 0x0001..=0x0005. Deferred
    /// (0x0006..=0x0008) and bench (0x0F00..=0x0FFF) bands reject here.
    UnknownClaimType(u16),
    /// H5 carries a code outside the D6 verdict table.
    UnknownVerdict(u16),
    /// R7: `anchor_mode` not in {1, 2}.
    UnknownAnchorMode(u8),
    /// R7: `datum_kind` not in {0, 1, 2}.
    UnknownDatumKind(u8),
    /// R7 band violation: `spend_status` != 0 on 0x0005 (CLAIMS U12).
    IllegalSpendStatusOnUtxoRead(u8),
    /// R7: a presence flag not in {0, 1}.
    IllegalPresenceFlag { field: &'static str, value: u8 },
    /// D3: a gated payload slot is nonzero while its gate is absent
    /// (flag 0 / External mode / `DatumKind::None`).
    NonzeroGatedPayload { field: &'static str },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader { actual } => {
                write!(
                    f,
                    "journal of {actual} bytes cannot carry the (version, claim_type) prelude"
                )
            }
            Self::LengthMismatch { expected, actual } => {
                write!(
                    f,
                    "journal length {actual} != {expected} required by its claim_type (R1)"
                )
            }
            Self::UnknownVersion(raw) => write!(f, "unknown claim_version {raw} (R2)"),
            Self::VersionNotAccepted(v) => {
                write!(
                    f,
                    "claim_version {} not accepted by this entry point (R2)",
                    v.as_u16()
                )
            }
            Self::UnknownClaimType(raw) => write!(f, "unknown claim_type {raw:#06x} (R3)"),
            Self::UnknownVerdict(raw) => write!(f, "verdict code {raw} outside the D6 table"),
            Self::UnknownAnchorMode(raw) => write!(f, "anchor_mode {raw} not in {{1,2}} (R7)"),
            Self::UnknownDatumKind(raw) => write!(f, "datum_kind {raw} not in {{0,1,2}} (R7)"),
            Self::IllegalSpendStatusOnUtxoRead(raw) => {
                write!(f, "spend_status {raw} != 0 on claim type 0x0005 (R7)")
            }
            Self::IllegalPresenceFlag { field, value } => {
                write!(f, "presence flag {field} = {value} not in {{0,1}} (R7)")
            }
            Self::NonzeroGatedPayload { field } => {
                write!(
                    f,
                    "gated payload {field} is nonzero while its gate is absent (D3)"
                )
            }
        }
    }
}

impl core::error::Error for DecodeError {}
