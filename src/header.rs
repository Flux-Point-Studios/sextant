//! Block-header decoding for the read path.
//!
//! Byte providers are untrusted, so this decoder validates the full ledger
//! `[era, block]` CBOR shape — exact array element counts, a supported Praos
//! era, a 32-byte prev_hash or genesis null, and no trailing bytes — before
//! returning any field. Malformed or reshaped input fails closed. Later
//! slices verify VRF/KES over the same header body.

use minicbor::Decoder;
use minicbor::data::Type;

/// header_body element count for the Praos header (Babbage, Conway).
const PRAOS_HEADER_BODY_LEN: u64 = 10;
/// header_body fields read by name before the remainder is skipped:
/// block_number, slot, prev_hash, issuer_vkey.
const HEADER_BODY_FIELDS_READ: u64 = 4;
/// block = [header, tx_bodies, tx_witness_sets, auxiliary_data, invalid_txs].
const BLOCK_LEN: u64 = 5;

/// The read-path fields Sextant extracts from a block header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderView {
    pub block_number: u64,
    pub slot: u64,
    pub issuer_vkey: [u8; 32],
}

/// Why a header failed to decode. Byte providers are untrusted, so every
/// deviation is an ordinary recoverable outcome, never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// CBOR was malformed, indefinite where a fixed shape is required, or an
    /// array carried the wrong element count.
    MalformedCbor,
    /// Era discriminator is not a supported Praos era (Babbage or Conway).
    UnsupportedEra(u32),
    /// A 32-byte hash field (prev_hash or issuer_vkey) had the wrong length.
    BadHashLen(usize),
    /// A valid header was followed by unconsumed trailing bytes.
    TrailingBytes,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecodeError::MalformedCbor => f.write_str("malformed or unexpected header CBOR"),
            DecodeError::UnsupportedEra(e) => write!(f, "unsupported era discriminator {e}"),
            DecodeError::BadHashLen(n) => write!(f, "hash field was {n} bytes, expected 32"),
            DecodeError::TrailingBytes => f.write_str("trailing bytes after header"),
        }
    }
}

impl std::error::Error for DecodeError {}

impl HeaderView {
    /// Decode the read-path fields from ledger `[era, block]` CBOR for the
    /// Praos eras (Babbage, Conway). Any structural deviation is rejected.
    pub fn from_block_cbor(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Decoder::new(bytes);

        expect_array(&mut d, 2)?; // [era, block]
        // Match pallas's era probe exactly: the discriminator must be a U8
        // token (canonical `0x00`-`0x17` or `0x18 XX`). minicbor's widening
        // reader would also accept a u16/u32/u64-encoded era that pallas
        // rejects — a differential-parse wedge — so reject the wider forms.
        if d.datatype().map_err(|_| DecodeError::MalformedCbor)? != Type::U8 {
            return Err(DecodeError::MalformedCbor);
        }
        let era = d.u32().map_err(|_| DecodeError::MalformedCbor)?;
        if !matches!(era, 6 | 7) {
            return Err(DecodeError::UnsupportedEra(era));
        }

        expect_array(&mut d, BLOCK_LEN)?; // block
        expect_array(&mut d, 2)?; // header: [header_body, body_signature]
        expect_array(&mut d, PRAOS_HEADER_BODY_LEN)?; // header_body

        let block_number = d.u64().map_err(|_| DecodeError::MalformedCbor)?;
        let slot = d.u64().map_err(|_| DecodeError::MalformedCbor)?;
        read_optional_hash32(&mut d)?; // prev_hash: 32-byte hash or genesis null
        let issuer_vkey = read_hash32(&mut d)?;

        // Consume the remainder so trailing or malformed bytes anywhere in the
        // input are rejected, not silently ignored.
        for _ in 0..(PRAOS_HEADER_BODY_LEN - HEADER_BODY_FIELDS_READ) {
            d.skip().map_err(|_| DecodeError::MalformedCbor)?; // rest of header_body
        }
        d.skip().map_err(|_| DecodeError::MalformedCbor)?; // body_signature
        for _ in 0..(BLOCK_LEN - 1) {
            d.skip().map_err(|_| DecodeError::MalformedCbor)?; // rest of block
        }
        if d.position() != bytes.len() {
            return Err(DecodeError::TrailingBytes);
        }

        Ok(Self {
            block_number,
            slot,
            issuer_vkey,
        })
    }
}

/// Read a definite CBOR array header and require exactly `want` elements,
/// rejecting indefinite-length arrays and any other count.
fn expect_array(d: &mut Decoder<'_>, want: u64) -> Result<(), DecodeError> {
    match d.array().map_err(|_| DecodeError::MalformedCbor)? {
        Some(n) if n == want => Ok(()),
        _ => Err(DecodeError::MalformedCbor),
    }
}

/// Read a definite 32-byte string.
fn read_hash32(d: &mut Decoder<'_>) -> Result<[u8; 32], DecodeError> {
    if d.datatype().map_err(|_| DecodeError::MalformedCbor)? != Type::Bytes {
        return Err(DecodeError::MalformedCbor);
    }
    let b = d.bytes().map_err(|_| DecodeError::MalformedCbor)?;
    b.try_into().map_err(|_| DecodeError::BadHashLen(b.len()))
}

/// Read a 32-byte prev_hash, or `null` for the genesis block's absent parent.
fn read_optional_hash32(d: &mut Decoder<'_>) -> Result<(), DecodeError> {
    match d.datatype().map_err(|_| DecodeError::MalformedCbor)? {
        Type::Null => d.skip().map_err(|_| DecodeError::MalformedCbor),
        Type::Bytes => {
            let b = d.bytes().map_err(|_| DecodeError::MalformedCbor)?;
            if b.len() == 32 {
                Ok(())
            } else {
                Err(DecodeError::BadHashLen(b.len()))
            }
        }
        _ => Err(DecodeError::MalformedCbor),
    }
}
