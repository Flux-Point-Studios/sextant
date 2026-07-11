//! Chain following: verify that a sequence of block headers forms a valid chain
//! segment on Sextant's own path.
//!
//! A segment is a run of consecutive blocks. Following it composes two guarantees:
//!
//! * **Linkage** — each header's `prev_hash` equals its predecessor's
//!   [`HeaderView::block_hash`] (Blake2b-256 over the header CBOR). Blake2b-256
//!   collision resistance makes this the load-bearing integrity check: a
//!   reordered, gapped, or spliced sequence cannot preserve the links.
//! * **Authorship** — every header's operational certificate (cold → hot
//!   delegation), leader-election VRF (against the epoch nonce), and KES body
//!   signature verify, exactly as the [`crate::kes`] and [`crate::vrf`] slices
//!   prove on each vector individually.
//!
//! The first block's own parent lies outside the segment, so its link is not
//! checked here; anchoring a segment to a trusted root (genesis / Mithril) is a
//! separate concern. Every block's crypto — including the first — is verified.
//!
//! Single epoch: `eta0` is the epoch nonce in force for the whole segment. A
//! segment that crosses an epoch boundary switches nonce at the boundary; that
//! is the nonce-evolution proof built on top of this primitive.

use crate::header::{DecodeError, HeaderView};
use crate::kes::{self, KesError};
use crate::vrf::{self, VrfError};

/// Why a chain segment failed to verify. Each variant carries the 0-based index
/// of the offending block so a caller can point at it. Untrusted bytes make
/// every failure an ordinary recoverable outcome, never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// A block's CBOR did not decode as a Praos header.
    Decode { index: usize, err: DecodeError },
    /// A block's `prev_hash` did not equal its predecessor's `block_hash` — the
    /// segment is reordered, has a gap, or a foreign block was spliced in.
    BrokenLink { index: usize },
    /// A block's operational certificate did not verify against its cold key.
    OpCert { index: usize, err: KesError },
    /// A block's leader-election VRF proof did not verify against the epoch nonce.
    Vrf { index: usize, err: VrfError },
    /// A block's KES body signature did not verify.
    Kes { index: usize, err: KesError },
}

impl core::fmt::Display for ChainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ChainError::Decode { index, err } => write!(f, "block {index}: {err}"),
            ChainError::BrokenLink { index } => {
                write!(
                    f,
                    "block {index}: prev_hash does not link to its predecessor"
                )
            }
            ChainError::OpCert { index, err } => write!(f, "block {index}: {err}"),
            ChainError::Vrf { index, err } => write!(f, "block {index}: {err}"),
            ChainError::Kes { index, err } => write!(f, "block {index}: {err}"),
        }
    }
}

impl std::error::Error for ChainError {}

/// Verify that `blocks` (ledger `[era, block]` CBOR, in on-chain order) form a
/// valid single-epoch chain segment: each header links to its predecessor by
/// hash, and every header's operational certificate, leader-VRF (against
/// `eta0`), and KES body signature verify. Returns the offending block's index
/// on the first failure.
pub fn verify_segment<B: AsRef<[u8]>>(blocks: &[B], eta0: &[u8; 32]) -> Result<(), ChainError> {
    let mut prev: Option<HeaderView> = None;
    for (index, block) in blocks.iter().enumerate() {
        let view = HeaderView::from_block_cbor(block.as_ref())
            .map_err(|err| ChainError::Decode { index, err })?;
        if let Some(parent) = &prev
            && view.prev_hash != Some(parent.block_hash)
        {
            return Err(ChainError::BrokenLink { index });
        }
        verify_header(&view, eta0, index)?;
        prev = Some(view);
    }
    Ok(())
}

/// Authenticate one header: cold → hot (opcert), then hot → block (leader-VRF
/// and KES). VRF is checked before KES so a tampered VRF field, which also
/// invalidates the KES signature over the same header body, surfaces as the VRF
/// failure it is.
fn verify_header(view: &HeaderView, eta0: &[u8; 32], index: usize) -> Result<(), ChainError> {
    kes::verify_opcert(&view.issuer_vkey, &view.opcert)
        .map_err(|err| ChainError::OpCert { index, err })?;
    vrf::verify_praos_leader(&view.vrf_vkey, view.slot, eta0, &view.vrf_proof)
        .map_err(|err| ChainError::Vrf { index, err })?;
    kes::verify_header_kes(view).map_err(|err| ChainError::Kes { index, err })?;
    Ok(())
}
