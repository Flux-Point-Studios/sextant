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
/// operational_cert (header_body index 8) element count: `[hot_vkey,
/// sequence_number, kes_period, sigma]`.
const OPCERT_LEN: u64 = 4;
/// block = [header, tx_bodies, tx_witness_sets, auxiliary_data, invalid_txs].
const BLOCK_LEN: u64 = 5;

/// The read-path fields Sextant extracts from a block header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderView {
    /// Ledger era discriminator, validated to a supported Praos era (Babbage
    /// = 6, Conway = 7). Later slices key body/VRF schema on this so a header
    /// cannot be validated under the wrong era's rules.
    pub era: u8,
    pub block_number: u64,
    pub slot: u64,
    /// The pool's cold verification key. It signs the operational certificate,
    /// so `kes::verify_opcert(&issuer_vkey, &opcert)` authenticates the header's
    /// hot KES key against the pool's registered identity.
    pub issuer_vkey: [u8; 32],
    /// Praos leader-election VRF public key (compressed Edwards point).
    pub vrf_vkey: [u8; 32],
    /// The 64-byte certified VRF output (beta) the block producer committed;
    /// `vrf::proof_to_hash(vrf_proof)` must reproduce it byte-for-byte.
    pub vrf_output: [u8; 64],
    /// The 80-byte ECVRF proof pi = Gamma(32) || c(16) || s(32).
    pub vrf_proof: [u8; 80],
    /// The operational certificate (header_body index 8) binding the hot KES
    /// key to the cold `issuer_vkey`.
    pub opcert: OpCert,
}

/// A Praos header's operational certificate (header_body index 8): the pool's
/// ephemeral hot KES verification key, the certificate sequence number, the KES
/// period it was issued at, and the cold key's Ed25519 signature over them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpCert {
    /// Hot KES verification key (the Sum6-KES Merkle root).
    pub hot_vkey: [u8; 32],
    /// Monotonic certificate counter; a re-issued cert increments it.
    pub sequence_number: u64,
    /// KES period the certificate was issued at (`c0`); the header's own KES
    /// period offset is measured from this.
    pub kes_period: u64,
    /// The cold key's Ed25519 signature over
    /// `hot_vkey ‖ BE64(sequence_number) ‖ BE64(kes_period)`.
    pub sigma: [u8; 64],
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
    /// A fixed-width byte field (prev_hash, a 32-byte key, or a VRF
    /// certificate element) had the wrong length.
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
        let issuer_vkey = read_bytes_exact::<32>(&mut d)?;
        let vrf_vkey = read_bytes_exact::<32>(&mut d)?;
        expect_array(&mut d, 2)?; // vrf_result = [vrf_output, vrf_proof]
        let vrf_output = read_bytes_exact::<64>(&mut d)?;
        let vrf_proof = read_bytes_exact::<80>(&mut d)?;
        d.skip().map_err(|_| DecodeError::MalformedCbor)?; // idx 6: block_body_size
        d.skip().map_err(|_| DecodeError::MalformedCbor)?; // idx 7: block_body_hash
        let opcert = read_opcert(&mut d)?; // idx 8: operational_cert
        d.skip().map_err(|_| DecodeError::MalformedCbor)?; // idx 9: protocol_version

        // Consume the remainder so trailing or malformed bytes anywhere in the
        // input are rejected, not silently ignored.
        d.skip().map_err(|_| DecodeError::MalformedCbor)?; // body_signature
        for _ in 0..(BLOCK_LEN - 1) {
            d.skip().map_err(|_| DecodeError::MalformedCbor)?; // rest of block
        }
        if d.position() != bytes.len() {
            return Err(DecodeError::TrailingBytes);
        }

        Ok(Self {
            era: era as u8, // validated to 6 | 7 above
            block_number,
            slot,
            issuer_vkey,
            vrf_vkey,
            vrf_output,
            vrf_proof,
            opcert,
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

/// Read a definite byte string of exactly `N` bytes, rejecting any other
/// length or a non-bytes token. Used for the header's fixed-width fields:
/// the 32-byte keys and the 64/80-byte VRF certificate elements.
fn read_bytes_exact<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N], DecodeError> {
    if d.datatype().map_err(|_| DecodeError::MalformedCbor)? != Type::Bytes {
        return Err(DecodeError::MalformedCbor);
    }
    let b = d.bytes().map_err(|_| DecodeError::MalformedCbor)?;
    b.try_into().map_err(|_| DecodeError::BadHashLen(b.len()))
}

/// Read the operational certificate at header_body index 8:
/// `[hot_vkey(32), sequence_number: uint, kes_period: uint, sigma(64)]`. The
/// exact 4-element shape and fixed key/signature widths are enforced so a
/// reshaped certificate cannot smuggle attacker-chosen fields past the decoder.
fn read_opcert(d: &mut Decoder<'_>) -> Result<OpCert, DecodeError> {
    expect_array(d, OPCERT_LEN)?;
    let hot_vkey = read_bytes_exact::<32>(d)?;
    let sequence_number = d.u64().map_err(|_| DecodeError::MalformedCbor)?;
    let kes_period = d.u64().map_err(|_| DecodeError::MalformedCbor)?;
    let sigma = read_bytes_exact::<64>(d)?;
    Ok(OpCert {
        hot_vkey,
        sequence_number,
        kes_period,
        sigma,
    })
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
