use crate::claim_type::ClaimType;
use crate::consts;
use crate::error::DecodeError;
use crate::network::NetworkId;
use crate::raw;
use crate::verdict::Verdict;
use crate::version::ClaimVersion;

// The (version, claim_type) prelude R1 keys the length table on.
const PRELUDE: usize = consts::HDR_W_VERSION + consts::HDR_W_CLAIM_TYPE;

/// Zero-copy, validated view over the 46-byte common header of one journal
/// buffer (ADR-003 D2). Borrows the ORIGINAL buffer — there is no owned copy,
/// so there is no second buffer to diverge (D0/T-A4-5).
#[derive(Debug, Clone, Copy)]
pub struct JournalHeader<'a> {
    buf: &'a [u8],
    version: ClaimVersion,
    claim_type: ClaimType,
    verdict: Verdict,
}

impl<'a> JournalHeader<'a> {
    /// D7 order: read the prelude, key R1 off the decoded type, then decode
    /// the remaining self-contained header enums. Fail-closed on the first
    /// violation. Version *acceptance* (the draft gate) is the entry point's;
    /// network/genesis pins (R3 policy/R4) are the verifier's, not the codec's.
    pub(crate) fn read(buf: &'a [u8]) -> Result<Self, DecodeError> {
        if buf.len() < PRELUDE {
            return Err(DecodeError::TruncatedHeader { actual: buf.len() });
        }
        // R3 (codec): the length table is keyed on a KNOWN type.
        let claim_type = ClaimType::from_u16(raw::be_u16(buf, consts::HDR_OFF_CLAIM_TYPE))?;
        // R1: exact length before any other field is trusted.
        let expected = claim_type.expected_len();
        if buf.len() != expected {
            return Err(DecodeError::LengthMismatch {
                expected,
                actual: buf.len(),
            });
        }
        // R2 (codec): version must be known.
        let version = ClaimVersion::from_u16(raw::be_u16(buf, consts::HDR_OFF_VERSION))?;
        // H5 must be a D6-table code.
        let verdict = Verdict::from_u16(raw::be_u16(buf, consts::HDR_OFF_VERDICT))?;
        Ok(Self {
            buf,
            version,
            claim_type,
            verdict,
        })
    }

    /// The full journal buffer this header (and its body views) borrow from.
    pub(crate) fn journal(&self) -> &'a [u8] {
        self.buf
    }

    pub fn claim_version(&self) -> ClaimVersion {
        self.version
    }

    pub fn claim_type(&self) -> ClaimType {
        self.claim_type
    }

    pub fn network_id(&self) -> NetworkId {
        NetworkId::from_u32(raw::be_u32(self.buf, consts::HDR_OFF_NETWORK_ID))
    }

    pub fn genesis_vkey(&self) -> &'a [u8; 32] {
        raw::arr32(self.buf, consts::HDR_OFF_GENESIS_VKEY)
    }

    pub fn verdict(&self) -> Verdict {
        self.verdict
    }

    /// Meaningful only when `verdict != Ok` and the claim type defines it
    /// (CLAIMS H6); zero otherwise.
    pub fn reject_index(&self) -> u32 {
        raw::be_u32(self.buf, consts::HDR_OFF_REJECT_INDEX)
    }
}

/// Owned header field set — the encode input from `hg-guest`. Typed fields,
/// so the guest cannot commit an out-of-set version/network/verdict. There is
/// deliberately no `claim_type` field: each claim encoder writes its own type
/// id, so a mismatched type tag is unrepresentable (one encoding per value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderFields {
    pub version: ClaimVersion,
    pub network_id: NetworkId,
    pub genesis_vkey: [u8; 32],
    pub verdict: Verdict,
    pub reject_index: u32,
}

impl HeaderFields {
    pub(crate) fn encode_into(&self, claim_type: ClaimType, out: &mut [u8]) {
        raw::put_u16(out, consts::HDR_OFF_VERSION, self.version.as_u16());
        raw::put_u16(out, consts::HDR_OFF_CLAIM_TYPE, claim_type.as_u16());
        raw::put_u32(out, consts::HDR_OFF_NETWORK_ID, self.network_id.as_u32());
        raw::put_arr32(out, consts::HDR_OFF_GENESIS_VKEY, &self.genesis_vkey);
        raw::put_u16(out, consts::HDR_OFF_VERDICT, self.verdict.as_u16());
        raw::put_u32(out, consts::HDR_OFF_REJECT_INDEX, self.reject_index);
    }
}
