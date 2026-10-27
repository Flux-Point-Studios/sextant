use alloc::vec;
use alloc::vec::Vec;

use crate::anchor::{AnchorBinding, AnchorField};
use crate::claim_type::ClaimType;
use crate::consts;
use crate::error::DecodeError;
use crate::header::{HeaderFields, JournalHeader};
use crate::raw;
use crate::state::{CheckpointState, CheckpointStateFields};

/// `0x0002` checkpoint-extension (CLAIMS §3.2): header + anchor prefix +
/// `prev_tip` identity + the new `CheckpointState`. A state-TRANSITION claim,
/// never absolute — the base case is its own type (0x0001).
#[derive(Debug, Clone, Copy)]
pub struct CheckpointExtensionView<'a> {
    header: JournalHeader<'a>,
    anchor: AnchorBinding<'a>,
    new_state: CheckpointState<'a>,
}

impl<'a> CheckpointExtensionView<'a> {
    pub(crate) fn read(header: JournalHeader<'a>) -> Result<Self, DecodeError> {
        let journal = header.journal();
        let anchor = AnchorBinding::read(journal, consts::BODY_OFF + consts::EXT_OFF_ANCHOR)?;
        let new_state =
            CheckpointState::read(journal, consts::BODY_OFF + consts::EXT_OFF_NEW_STATE)?;
        Ok(Self {
            header,
            anchor,
            new_state,
        })
    }

    pub fn header(&self) -> &JournalHeader<'a> {
        &self.header
    }

    pub fn anchor(&self) -> AnchorBinding<'a> {
        self.anchor
    }

    /// E3: identity of the prior checkpoint this extension builds on. The
    /// verifier binds it per R6 (stored checkpoint / inner journal S2).
    pub fn prev_tip_hash(&self) -> &'a [u8; 32] {
        raw::arr32(
            self.header.journal(),
            consts::BODY_OFF + consts::EXT_OFF_PREV_TIP_HASH,
        )
    }

    pub fn prev_tip_epoch(&self) -> u64 {
        raw::be_u64(
            self.header.journal(),
            consts::BODY_OFF + consts::EXT_OFF_PREV_TIP_EPOCH,
        )
    }

    pub fn new_state(&self) -> CheckpointState<'a> {
        self.new_state
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointExtensionFields {
    pub header: HeaderFields,
    pub anchor: AnchorField,
    pub prev_tip_hash: [u8; 32],
    pub prev_tip_epoch: u64,
    /// `chain_length == prev + 1`, `root_hash` carried through unchanged —
    /// checked in `hg-guest`, journaled as data (CLAIMS E5-E17).
    pub new_state: CheckpointStateFields,
}

impl CheckpointExtensionFields {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; consts::LEN_CHECKPOINT_EXTENSION];
        self.header
            .encode_into(ClaimType::CheckpointExtension, &mut out);
        self.anchor
            .encode_into(&mut out, consts::BODY_OFF + consts::EXT_OFF_ANCHOR);
        raw::put_arr32(
            &mut out,
            consts::BODY_OFF + consts::EXT_OFF_PREV_TIP_HASH,
            &self.prev_tip_hash,
        );
        raw::put_u64(
            &mut out,
            consts::BODY_OFF + consts::EXT_OFF_PREV_TIP_EPOCH,
            self.prev_tip_epoch,
        );
        self.new_state
            .encode_into(&mut out, consts::BODY_OFF + consts::EXT_OFF_NEW_STATE);
        out
    }
}
