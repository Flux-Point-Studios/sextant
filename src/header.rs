//! Block-header decoding for the read path.
//!
//! `block_number`, `slot`, and `issuer_vkey` sit at fixed indices 0, 1, and 3
//! of `header_body` in both the TPraos and Praos header encodings, so this
//! decode path is stable across current and recent eras. Later slices verify
//! VRF/KES over the same header body.

use minicbor::Decoder;
use minicbor::data::Type;

/// The read-path fields Sextant extracts from a block header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderView {
    pub block_number: u64,
    pub slot: u64,
    pub issuer_vkey: [u8; 32],
}

/// Why a header failed to decode. Byte providers are untrusted, so malformed
/// or unexpected input is an ordinary recoverable outcome, never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The CBOR was malformed or did not match the `[era, block]` header shape.
    MalformedCbor,
    /// The issuer verification key was not the expected 32 bytes.
    IssuerVkeyLen(usize),
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecodeError::MalformedCbor => f.write_str("malformed or unexpected header CBOR"),
            DecodeError::IssuerVkeyLen(n) => write!(f, "issuer vkey was {n} bytes, expected 32"),
        }
    }
}

impl std::error::Error for DecodeError {}

impl HeaderView {
    /// Decode the read-path fields from ledger `[era, block]` CBOR
    /// (Shelley-era onwards).
    pub fn from_block_cbor(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Decoder::new(bytes);
        d.array().map_err(|_| DecodeError::MalformedCbor)?; // [era, block]
        d.u32().map_err(|_| DecodeError::MalformedCbor)?; //  era discriminator
        d.array().map_err(|_| DecodeError::MalformedCbor)?; // block: [header, ..]
        d.array().map_err(|_| DecodeError::MalformedCbor)?; // header: [header_body, sig]
        d.array().map_err(|_| DecodeError::MalformedCbor)?; // header_body

        let block_number = d.u64().map_err(|_| DecodeError::MalformedCbor)?;
        let slot = d.u64().map_err(|_| DecodeError::MalformedCbor)?;
        skip_prev_hash(&mut d)?; // $hash32 / null at genesis
        let issuer = d.bytes().map_err(|_| DecodeError::MalformedCbor)?;

        let issuer_vkey = issuer
            .try_into()
            .map_err(|_| DecodeError::IssuerVkeyLen(issuer.len()))?;

        Ok(Self {
            block_number,
            slot,
            issuer_vkey,
        })
    }
}

fn skip_prev_hash(d: &mut Decoder<'_>) -> Result<(), DecodeError> {
    match d.datatype().map_err(|_| DecodeError::MalformedCbor)? {
        Type::Null => d.skip().map_err(|_| DecodeError::MalformedCbor),
        _ => d
            .bytes()
            .map(|_| ())
            .map_err(|_| DecodeError::MalformedCbor),
    }
}
