use crate::body::checkpoint::CheckpointView;
use crate::body::checkpoint_extension::CheckpointExtensionView;
use crate::body::header_segment::HeaderSegmentView;
use crate::body::tx_inclusion::TxInclusionView;
use crate::body::utxo_read::UtxoReadView;
use crate::claim_type::ClaimType;
use crate::error::DecodeError;
use crate::header::JournalHeader;
use crate::version::ClaimVersion;

/// A structurally valid journal — one variant per claim type. Each variant
/// borrows the ORIGINAL buffer, so holding a `Claim` is proof that the
/// structural gates passed over exactly the bytes the caller holds (D0):
/// there is no second buffer, and no view-to-bytes re-encode exists (T-A4-5).
#[derive(Debug, Clone, Copy)]
pub enum Claim<'a> {
    Checkpoint(CheckpointView<'a>),
    CheckpointExtension(CheckpointExtensionView<'a>),
    HeaderSegment(HeaderSegmentView<'a>),
    TxInclusion(TxInclusionView<'a>),
    UtxoRead(UtxoReadView<'a>),
}

impl<'a> Claim<'a> {
    pub fn header(&self) -> &JournalHeader<'a> {
        match self {
            Self::Checkpoint(v) => v.header(),
            Self::CheckpointExtension(v) => v.header(),
            Self::HeaderSegment(v) => v.header(),
            Self::TxInclusion(v) => v.header(),
            Self::UtxoRead(v) => v.header(),
        }
    }
}

/// Structural decode (ADR-003 D7, codec half): R1 exact length, R2 version
/// known with Draft rejected, R3 claim type known, R7 band/presence validity
/// over one flat buffer. R4/R5/R6/R8 are verifier policy over the returned
/// view (network/genesis pins, image-ID allowlists, anchor binding, reading
/// H5) — they need state the codec cannot know and do NOT live here.
///
/// NORMATIVE gate precedence — every mirror (M4 Solidity router, hg-sdk-ts)
/// MUST replicate this exact order so cross-surface error parity holds
/// (T-A4-4/T-A12-1 class): 4-byte prelude present → claim_type known (the LEN
/// table is keyed on it) → R1 exact length → R2 version known (+ draft gate)
/// → D6 verdict known → R7 bands/presence. Consequence: a buffer with BOTH an
/// unknown version and an unknown claim_type reports `UnknownClaimType`, not
/// `UnknownVersion` — deliberate, because length cannot be checked before the
/// type is known, and version is still checked before any body byte is
/// interpreted. A cross-surface fixture pinning this case lands with the M4
/// mirror.
pub fn decode_structural(buf: &[u8]) -> Result<Claim<'_>, DecodeError> {
    decode(buf, false)
}

/// Pre-freeze development entry point: identical gates, but the accepted
/// version set widens to {Draft, V1} (CLAIMS §1.3). Never a production path —
/// every production verifier rejects Draft unconditionally.
pub fn decode_structural_draft(buf: &[u8]) -> Result<Claim<'_>, DecodeError> {
    decode(buf, true)
}

fn decode(buf: &[u8], allow_draft: bool) -> Result<Claim<'_>, DecodeError> {
    let header = JournalHeader::read(buf)?;
    // R2 (draft gate): Draft 0 only through the explicit draft constructor.
    if header.claim_version() == ClaimVersion::Draft && !allow_draft {
        return Err(DecodeError::VersionNotAccepted(ClaimVersion::Draft));
    }
    // R7 body gates run in each view's constructor.
    Ok(match header.claim_type() {
        ClaimType::Checkpoint => Claim::Checkpoint(CheckpointView::read(header)?),
        ClaimType::CheckpointExtension => {
            Claim::CheckpointExtension(CheckpointExtensionView::read(header)?)
        }
        ClaimType::HeaderSegment => Claim::HeaderSegment(HeaderSegmentView::read(header)?),
        ClaimType::TxInclusion => Claim::TxInclusion(TxInclusionView::read(header)?),
        ClaimType::UtxoRead => Claim::UtxoRead(UtxoReadView::read(header)?),
    })
}
