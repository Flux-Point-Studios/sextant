use crate::consts;
use crate::error::DecodeError;
use crate::raw;

/// CLAIMS §2.3: `1` = external (the verifier binds the anchor to
/// independently verified state — R6, out of codec scope); `2` = composed
/// (the guest verified an inner proof; the inner journal supplied the anchor).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AnchorMode {
    External = 1,
    Composed = 2,
}

impl AnchorMode {
    pub fn from_u8(raw: u8) -> Result<Self, DecodeError> {
        match raw {
            1 => Ok(Self::External),
            2 => Ok(Self::Composed),
            _ => Err(DecodeError::UnknownAnchorMode(raw)),
        }
    }

    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Validated view over the 33-byte `{anchor_mode, inner_image_id}` body
/// prefix shared by 0x0002/0x0004/0x0005 (CLAIMS §2.3).
#[derive(Debug, Clone, Copy)]
pub struct AnchorBinding<'a> {
    buf: &'a [u8],
    mode: AnchorMode,
}

impl<'a> AnchorBinding<'a> {
    /// R7: mode in {1,2}; D3: the `inner_image_id` slot is present-but-zeroed
    /// in External mode — presenting it nonzero rejects.
    pub(crate) fn read(journal: &'a [u8], off: usize) -> Result<Self, DecodeError> {
        let buf = &journal[off..off + consts::ANCHOR_LEN];
        let mode = AnchorMode::from_u8(buf[consts::ANCHOR_OFF_MODE])?;
        if mode == AnchorMode::External && !raw::is_zero(&buf[consts::ANCHOR_OFF_INNER_IMAGE_ID..])
        {
            return Err(DecodeError::NonzeroGatedPayload {
                field: "inner_image_id",
            });
        }
        Ok(Self { buf, mode })
    }

    pub fn mode(&self) -> AnchorMode {
        self.mode
    }

    /// The verified inner proof's image ID, committed verbatim (an inner
    /// image ID that arrives as an input MUST be journaled — CLAIMS §1.2).
    /// `None` in External mode: the zeroed slot MUST NOT be consumed, and
    /// this accessor's type — not caller discipline — enforces that (D3).
    pub fn inner_image_id(&self) -> Option<&'a [u8; 32]> {
        match self.mode {
            AnchorMode::External => None,
            AnchorMode::Composed => Some(raw::arr32(self.buf, consts::ANCHOR_OFF_INNER_IMAGE_ID)),
        }
    }
}

/// Encode-side anchor group: mode and payload in one value, so
/// External-with-nonzero-inner-id is unrepresentable (D3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorField {
    External,
    Composed([u8; 32]),
}

impl AnchorField {
    pub(crate) fn encode_into(&self, out: &mut [u8], off: usize) {
        match self {
            Self::External => {
                out[off + consts::ANCHOR_OFF_MODE] = AnchorMode::External.as_u8();
                // inner_image_id slot stays zeroed (D3).
            }
            Self::Composed(id) => {
                out[off + consts::ANCHOR_OFF_MODE] = AnchorMode::Composed.as_u8();
                raw::put_arr32(out, off + consts::ANCHOR_OFF_INNER_IMAGE_ID, id);
            }
        }
    }
}
