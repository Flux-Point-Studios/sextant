use alloc::vec;
use alloc::vec::Vec;

use crate::claim_type::ClaimType;
use crate::consts;
use crate::error::DecodeError;
use crate::header::{HeaderFields, JournalHeader};
use crate::state::{CheckpointState, CheckpointStateFields};

/// `0x0001` checkpoint (CLAIMS §3.1): header + `CheckpointState`, nothing
/// else. The trust terminus — everything Mithril-anchored cites it.
/// `reject_index` = offending certificate index on chain-band failures.
#[derive(Debug, Clone, Copy)]
pub struct CheckpointView<'a> {
    header: JournalHeader<'a>,
    state: CheckpointState<'a>,
}

impl<'a> CheckpointView<'a> {
    pub(crate) fn read(header: JournalHeader<'a>) -> Result<Self, DecodeError> {
        let state = CheckpointState::read(header.journal(), consts::BODY_OFF)?;
        Ok(Self { header, state })
    }

    pub fn header(&self) -> &JournalHeader<'a> {
        &self.header
    }

    pub fn state(&self) -> CheckpointState<'a> {
        self.state
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointFields {
    pub header: HeaderFields,
    pub state: CheckpointStateFields,
}

impl CheckpointFields {
    /// The one encoding of this value (D0): a 255-byte buffer the guest
    /// commits verbatim — the exact bytes the verifier digests.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; consts::LEN_CHECKPOINT];
        self.header.encode_into(ClaimType::Checkpoint, &mut out);
        self.state.encode_into(&mut out, consts::BODY_OFF);
        out
    }
}
