//! Canonical journal codec for heliograph claims (ADR-003). The buffer is
//! the ABI: one encode and one decode per claim type over one flat,
//! big-endian, fixed-offset buffer. No serde, no framing, no runtime
//! dependencies — and no view-to-bytes re-encode, so there is never a second
//! buffer to diverge from the one the verifier digests (D0 / T-A4-5).
//!
//! Encoding is a one-way street from typed `*Fields` to bytes; reading is a
//! one-way street from bytes to a borrowing view, obtainable only through the
//! fail-closed [`decode_structural`] entry point (Draft-version journals only
//! through [`decode_structural_draft`]).

#![no_std]

extern crate alloc;

pub mod consts;

mod anchor;
mod body;
mod claim_type;
mod decode;
mod error;
mod header;
mod network;
mod raw;
mod state;
mod verdict;
mod version;

pub use anchor::{AnchorBinding, AnchorField, AnchorMode};
pub use body::checkpoint::{CheckpointFields, CheckpointView};
pub use body::checkpoint_extension::{CheckpointExtensionFields, CheckpointExtensionView};
pub use body::header_segment::{HeaderSegmentFields, HeaderSegmentView};
pub use body::tx_inclusion::{TxInclusionFields, TxInclusionView};
pub use body::utxo_read::{DatumField, DatumKind, SpendStatus, UtxoReadFields, UtxoReadView};
pub use claim_type::ClaimType;
pub use decode::{Claim, decode_structural, decode_structural_draft};
pub use error::DecodeError;
pub use header::{HeaderFields, JournalHeader};
pub use network::NetworkId;
pub use state::{CertifiedTxAnchor, CertifiedTxFields, CheckpointState, CheckpointStateFields};
pub use verdict::Verdict;
pub use version::ClaimVersion;
