use crate::claim_type::ClaimType;
use crate::error::DecodeError;

/// H5 verdict (CLAIMS H5/§4): `Ok` = accepted; nonzero = a journaled
/// rejection (data, not a panic). Adopts the Sextant `SextantStatus`
/// band values 1:1, verbatim, no lossy collapsing (ADR-003 D6;
/// ffi.rs:83-136, `SEXTANT_ABI_VERSION = 5`).
///
/// `u16`, not `i32`: Sextant's negative boundary/panic codes never journal —
/// a guest panic yields no proof — so "no negative verdict is journalable"
/// is a type-level fact (ADR-003 D6, Alt-7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Verdict {
    Ok = 0,

    // header-leaf band (reachable on 0x0003)
    DecodeMalformedCbor = 100,
    DecodeUnsupportedEra = 101,
    DecodeBadHashLen = 102,
    DecodeTrailingBytes = 103,
    VrfInvalidGamma = 110,
    VrfInvalidPublicKey = 111,
    VrfSmallOrderPublicKey = 112,
    VrfVerificationFailed = 113,
    KesOpCertInvalidSignature = 120,
    KesInvalidSignature = 121,
    KesPeriodOutOfRange = 122,

    // praos-chain band (0x0003)
    ChainDecode = 200,
    ChainBrokenLink = 201,
    ChainOpCert = 202,
    ChainVrf = 203,
    ChainKes = 204,

    // mithril-chain band (0x0001, 0x0002)
    MithrilChainEmpty = 300,
    MithrilChainHash = 301,
    MithrilChainBrokenLink = 302,
    MithrilChainAvkBinding = 303,

    // mithril-genesis band (0x0001)
    MithrilGenesisNotGenesis = 310,
    MithrilGenesisMalformedSignature = 311,
    MithrilGenesisMessageMismatch = 312,
    MithrilGenesisInvalidSignature = 313,

    // mithril-standard band (0x0001, 0x0002)
    MithrilStdNotStandard = 320,
    MithrilStdMessageMismatch = 321,
    MithrilStdWeakParameters = 322,
    MithrilStdImplausibleAvk = 323,
    MithrilStdMalformedAvk = 324,
    MithrilStdMalformedSignature = 325,
    MithrilStdInvalidMultiSignature = 326,
    MithrilStdMalformedCertJson = 327,

    // inclusion band (0x0004, 0x0005)
    UtxoInclusionNotIncluded = 400,
    UtxoInclusionRootMismatch = 401,
    UtxoInclusionMalformedProof = 402,

    // utxo band (0x0005)
    UtxoMalformedTx = 410,
    UtxoOutputIndexOutOfRange = 411,
}

impl Verdict {
    /// Every code in the D6 table, for the golden corpus and the
    /// verdict-table mutants (T-A12-1).
    pub const ALL: [Verdict; 38] = [
        Verdict::Ok,
        Verdict::DecodeMalformedCbor,
        Verdict::DecodeUnsupportedEra,
        Verdict::DecodeBadHashLen,
        Verdict::DecodeTrailingBytes,
        Verdict::VrfInvalidGamma,
        Verdict::VrfInvalidPublicKey,
        Verdict::VrfSmallOrderPublicKey,
        Verdict::VrfVerificationFailed,
        Verdict::KesOpCertInvalidSignature,
        Verdict::KesInvalidSignature,
        Verdict::KesPeriodOutOfRange,
        Verdict::ChainDecode,
        Verdict::ChainBrokenLink,
        Verdict::ChainOpCert,
        Verdict::ChainVrf,
        Verdict::ChainKes,
        Verdict::MithrilChainEmpty,
        Verdict::MithrilChainHash,
        Verdict::MithrilChainBrokenLink,
        Verdict::MithrilChainAvkBinding,
        Verdict::MithrilGenesisNotGenesis,
        Verdict::MithrilGenesisMalformedSignature,
        Verdict::MithrilGenesisMessageMismatch,
        Verdict::MithrilGenesisInvalidSignature,
        Verdict::MithrilStdNotStandard,
        Verdict::MithrilStdMessageMismatch,
        Verdict::MithrilStdWeakParameters,
        Verdict::MithrilStdImplausibleAvk,
        Verdict::MithrilStdMalformedAvk,
        Verdict::MithrilStdMalformedSignature,
        Verdict::MithrilStdInvalidMultiSignature,
        Verdict::MithrilStdMalformedCertJson,
        Verdict::UtxoInclusionNotIncluded,
        Verdict::UtxoInclusionRootMismatch,
        Verdict::UtxoInclusionMalformedProof,
        Verdict::UtxoMalformedTx,
        Verdict::UtxoOutputIndexOutOfRange,
    ];

    /// Total, lossless mapping: every code maps back to exactly one variant;
    /// an unrecognized code is fail-closed (a code the guest could not have
    /// proved is a codec/guest defect).
    pub fn from_u16(raw: u16) -> Result<Self, DecodeError> {
        match raw {
            0 => Ok(Self::Ok),
            100 => Ok(Self::DecodeMalformedCbor),
            101 => Ok(Self::DecodeUnsupportedEra),
            102 => Ok(Self::DecodeBadHashLen),
            103 => Ok(Self::DecodeTrailingBytes),
            110 => Ok(Self::VrfInvalidGamma),
            111 => Ok(Self::VrfInvalidPublicKey),
            112 => Ok(Self::VrfSmallOrderPublicKey),
            113 => Ok(Self::VrfVerificationFailed),
            120 => Ok(Self::KesOpCertInvalidSignature),
            121 => Ok(Self::KesInvalidSignature),
            122 => Ok(Self::KesPeriodOutOfRange),
            200 => Ok(Self::ChainDecode),
            201 => Ok(Self::ChainBrokenLink),
            202 => Ok(Self::ChainOpCert),
            203 => Ok(Self::ChainVrf),
            204 => Ok(Self::ChainKes),
            300 => Ok(Self::MithrilChainEmpty),
            301 => Ok(Self::MithrilChainHash),
            302 => Ok(Self::MithrilChainBrokenLink),
            303 => Ok(Self::MithrilChainAvkBinding),
            310 => Ok(Self::MithrilGenesisNotGenesis),
            311 => Ok(Self::MithrilGenesisMalformedSignature),
            312 => Ok(Self::MithrilGenesisMessageMismatch),
            313 => Ok(Self::MithrilGenesisInvalidSignature),
            320 => Ok(Self::MithrilStdNotStandard),
            321 => Ok(Self::MithrilStdMessageMismatch),
            322 => Ok(Self::MithrilStdWeakParameters),
            323 => Ok(Self::MithrilStdImplausibleAvk),
            324 => Ok(Self::MithrilStdMalformedAvk),
            325 => Ok(Self::MithrilStdMalformedSignature),
            326 => Ok(Self::MithrilStdInvalidMultiSignature),
            327 => Ok(Self::MithrilStdMalformedCertJson),
            400 => Ok(Self::UtxoInclusionNotIncluded),
            401 => Ok(Self::UtxoInclusionRootMismatch),
            402 => Ok(Self::UtxoInclusionMalformedProof),
            410 => Ok(Self::UtxoMalformedTx),
            411 => Ok(Self::UtxoOutputIndexOutOfRange),
            _ => Err(DecodeError::UnknownVerdict(raw)),
        }
    }

    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    pub const fn is_accept(self) -> bool {
        matches!(self, Self::Ok)
    }

    /// `true` iff this code is reachable on `t` (the D6 "reachable on"
    /// column). For the golden corpus and the verdict-table mutants, not a
    /// runtime gate — the router does not whitelist codes-per-type (that
    /// would be a second encoding of reachability the guest enforces).
    pub const fn reachable_on(self, t: ClaimType) -> bool {
        match self {
            Self::Ok => true,
            // header-leaf + praos-chain bands
            Self::DecodeMalformedCbor
            | Self::DecodeUnsupportedEra
            | Self::DecodeBadHashLen
            | Self::DecodeTrailingBytes
            | Self::VrfInvalidGamma
            | Self::VrfInvalidPublicKey
            | Self::VrfSmallOrderPublicKey
            | Self::VrfVerificationFailed
            | Self::KesOpCertInvalidSignature
            | Self::KesInvalidSignature
            | Self::KesPeriodOutOfRange
            | Self::ChainDecode
            | Self::ChainBrokenLink
            | Self::ChainOpCert
            | Self::ChainVrf
            | Self::ChainKes => matches!(t, ClaimType::HeaderSegment),
            // mithril-chain + mithril-standard bands
            Self::MithrilChainEmpty
            | Self::MithrilChainHash
            | Self::MithrilChainBrokenLink
            | Self::MithrilChainAvkBinding
            | Self::MithrilStdNotStandard
            | Self::MithrilStdMessageMismatch
            | Self::MithrilStdWeakParameters
            | Self::MithrilStdImplausibleAvk
            | Self::MithrilStdMalformedAvk
            | Self::MithrilStdMalformedSignature
            | Self::MithrilStdInvalidMultiSignature
            | Self::MithrilStdMalformedCertJson => {
                matches!(t, ClaimType::Checkpoint | ClaimType::CheckpointExtension)
            }
            // mithril-genesis band
            Self::MithrilGenesisNotGenesis
            | Self::MithrilGenesisMalformedSignature
            | Self::MithrilGenesisMessageMismatch
            | Self::MithrilGenesisInvalidSignature => matches!(t, ClaimType::Checkpoint),
            // inclusion band
            Self::UtxoInclusionNotIncluded
            | Self::UtxoInclusionRootMismatch
            | Self::UtxoInclusionMalformedProof => {
                matches!(t, ClaimType::TxInclusion | ClaimType::UtxoRead)
            }
            // utxo band
            Self::UtxoMalformedTx | Self::UtxoOutputIndexOutOfRange => {
                matches!(t, ClaimType::UtxoRead)
            }
        }
    }
}
