//! Body-commitment binding for the read path.
//!
//! [`crate::chain::verify_segment`] authenticates block *headers*. The spend
//! signal a windowed-unspent verdict scans lives in the transaction *bodies*,
//! which a header does not itself carry — so a hostile provider could hand
//! authentic, hash-linked headers with SWAPPED bodies and a naive scan would read
//! a false verdict. This module closes that gap: it recomputes the header's
//! `block_body_hash` commitment from a block's four raw body segments and requires
//! it to match, binding the scanned bodies to the header-verified chain.
//!
//! ## The bytes are hashed verbatim
//! Cardano block CBOR is non-canonical, so the four segments are hashed exactly as
//! they appear on the wire (captured as byte ranges in [`crate::header::HeaderView::decode_block`]),
//! never re-encoded — the same discipline the header KES path follows for the
//! header body it signs.

use crate::hash::blake2b256;
use crate::header::{BlockBodySpans, DecodeError, HeaderView};

/// Why a block's transaction bodies did not bind to its header commitment.
/// Untrusted bytes make every failure an ordinary recoverable outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindError {
    /// The block CBOR did not decode as a Praos block.
    Decode(DecodeError),
    /// The recomputed `hashAlonzoSegWits` did not equal the header's committed
    /// `block_body_hash`: the bodies were swapped, tampered, or truncated.
    BodyCommitmentMismatch,
}

impl core::fmt::Display for BindError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BindError::Decode(e) => write!(f, "{e}"),
            BindError::BodyCommitmentMismatch => {
                f.write_str("block body does not hash to its header commitment")
            }
        }
    }
}

impl std::error::Error for BindError {}

/// Verify that a block's transaction bodies are the ones its header commits to,
/// and return the decoded [`HeaderView`]. The recomputed body commitment must
/// equal header_body index 7; any mismatch — swapped or tampered bodies — is
/// rejected before the bodies are trusted for a spend scan.
///
/// This is the load-bearing bind for a windowed spend scan: only once a block's
/// bodies are bound to a header-verified, hash-linked chain is a
/// [`crate::utxo::decode_spends`] over those bodies trustworthy evidence.
pub fn verify_body_commitment(block_bytes: &[u8]) -> Result<HeaderView, BindError> {
    let (view, spans) = HeaderView::decode_block(block_bytes).map_err(BindError::Decode)?;
    if hash_alonzo_seg_wits(block_bytes, &spans) != view.block_body_hash {
        return Err(BindError::BodyCommitmentMismatch);
    }
    Ok(view)
}

/// Recompute the segregated-witness block body hash from the raw body spans, per
/// cardano-ledger's `hashAlonzoTxSeq`: the outer Blake2b-256 over the four inner
/// segment hashes concatenated in block order —
/// `blake2b256( blake2b256(tx_bodies) ‖ blake2b256(tx_witness_sets) ‖
/// blake2b256(auxiliary_data) ‖ blake2b256(invalid_transactions) )`.
fn hash_alonzo_seg_wits(block_bytes: &[u8], spans: &BlockBodySpans) -> [u8; 32] {
    let mut preimage = [0u8; 128];
    preimage[0..32].copy_from_slice(&blake2b256(&block_bytes[spans.tx_bodies.clone()]));
    preimage[32..64].copy_from_slice(&blake2b256(&block_bytes[spans.tx_witness_sets.clone()]));
    preimage[64..96].copy_from_slice(&blake2b256(&block_bytes[spans.auxiliary_data.clone()]));
    preimage[96..128].copy_from_slice(&blake2b256(
        &block_bytes[spans.invalid_transactions.clone()],
    ));
    blake2b256(&preimage)
}
