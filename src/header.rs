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
/// body_signature (header array index 1) length: a `Sum6Kes` signature —
/// `sigma5(384) ‖ vk0(32) ‖ vk1(32)`, the same width across the Praos eras.
const KES_SIGNATURE_LEN: usize = 448;
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
    /// The parent block's header hash (`block_hash` of the predecessor), or
    /// `None` for the genesis block whose parent is absent. A chain follower
    /// checks this against the previous header's [`HeaderView::block_hash`].
    pub prev_hash: Option<[u8; 32]>,
    /// This header's own Blake2b-256 hash over its CBOR (`[header_body,
    /// body_signature]`) — the value the next block's `prev_hash` references,
    /// matching cardano-node's `HashHeader`.
    pub block_hash: [u8; 32],
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
    /// The header's commitment to its block body (header_body index 7): the
    /// `hashAlonzoSegWits` over the block's four raw body segments. Binding the
    /// scanned transaction bodies to a header-verified chain requires recomputing
    /// this from the raw block spans and matching it — see
    /// [`crate::window::verify_body_commitment`].
    pub block_body_hash: [u8; 32],
    /// The operational certificate (header_body index 8) binding the hot KES
    /// key to the cold `issuer_vkey`.
    pub opcert: OpCert,
    /// The raw CBOR bytes of `header_body` (header array index 0), exactly as
    /// serialized in the block — the message the hot KES key signs. Captured as
    /// an owned byte span so `kes::verify_header_kes` can check `body_signature`
    /// against the exact bytes cardano-node signed, with no re-encoding.
    pub header_body: Vec<u8>,
    /// The 448-byte `Sum6Kes` body signature (header array index 1) the hot KES
    /// key produced over `header_body` at the header's KES evolution period.
    pub body_signature: [u8; KES_SIGNATURE_LEN],
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

/// The raw CBOR spans of a block's four body segments (block array indices
/// 1..=4) as byte ranges into the original block CBOR: `transaction_bodies`,
/// `transaction_witness_sets`, `auxiliary_data_set`, and `invalid_transactions`.
///
/// These are the exact wire bytes the header's `block_body_hash` commits to.
/// Cardano block CBOR is non-canonical, so the body-commitment bind hashes these
/// spans *verbatim* — a re-encode could differ byte-for-byte and break the bind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockBodySpans {
    /// `transaction_bodies` (block index 1): the sequence of raw tx bodies.
    pub tx_bodies: core::ops::Range<usize>,
    /// `transaction_witness_sets` (block index 2).
    pub tx_witness_sets: core::ops::Range<usize>,
    /// `auxiliary_data_set` (block index 3): the tx-index → auxiliary-data map.
    pub auxiliary_data: core::ops::Range<usize>,
    /// `invalid_transactions` (block index 4): the tx-index array.
    pub invalid_transactions: core::ops::Range<usize>,
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
        Self::decode_block(bytes).map(|(view, _)| view)
    }

    /// Decode the header ([`HeaderView`]) and the raw spans of the block's four
    /// body segments ([`BlockBodySpans`]) in one pass. The spans are byte ranges
    /// into `bytes`, so the body-commitment bind can hash the wire bytes verbatim
    /// without a re-encode. Any structural deviation is rejected.
    pub fn decode_block(bytes: &[u8]) -> Result<(Self, BlockBodySpans), DecodeError> {
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
        // The block hash is Blake2b256 over the header CBOR (`[header_body,
        // body_signature]`); record its span from the opening array token.
        let header_start = d.position();
        expect_array(&mut d, 2)?; // header: [header_body, body_signature]
        // The KES-signed message is the raw CBOR of header_body; record the span
        // from the opening array token through the last consumed element.
        let body_start = d.position();
        expect_array(&mut d, PRAOS_HEADER_BODY_LEN)?; // header_body

        let block_number = d.u64().map_err(|_| DecodeError::MalformedCbor)?;
        let slot = d.u64().map_err(|_| DecodeError::MalformedCbor)?;
        let prev_hash = read_optional_hash32(&mut d)?; // 32-byte parent hash or genesis null
        let issuer_vkey = read_bytes_exact::<32>(&mut d)?;
        let vrf_vkey = read_bytes_exact::<32>(&mut d)?;
        expect_array(&mut d, 2)?; // vrf_result = [vrf_output, vrf_proof]
        let vrf_output = read_bytes_exact::<64>(&mut d)?;
        let vrf_proof = read_bytes_exact::<80>(&mut d)?;
        d.skip().map_err(|_| DecodeError::MalformedCbor)?; // idx 6: block_body_size
        let block_body_hash = read_bytes_exact::<32>(&mut d)?; // idx 7: block_body_hash
        let opcert = read_opcert(&mut d)?; // idx 8: operational_cert
        d.skip().map_err(|_| DecodeError::MalformedCbor)?; // idx 9: protocol_version
        let header_body = bytes[body_start..d.position()].to_vec();

        // header array index 1: the Sum6-KES body signature over header_body.
        let body_signature = read_bytes_exact::<KES_SIGNATURE_LEN>(&mut d)?;
        // The header CBOR is now fully consumed; hash it for the chain link.
        let block_hash = crate::hash::blake2b256(&bytes[header_start..d.position()]);

        // Capture the raw spans of the block's four body segments (block indices
        // 1..=4) verbatim; the body-commitment bind hashes these exact bytes. This
        // also consumes the remainder, so trailing or malformed bytes anywhere in
        // the input are rejected, not silently ignored.
        let tx_bodies = capture_span(&mut d)?;
        let tx_witness_sets = capture_span(&mut d)?;
        let auxiliary_data = capture_span(&mut d)?;
        let invalid_transactions = capture_span(&mut d)?;
        if d.position() != bytes.len() {
            return Err(DecodeError::TrailingBytes);
        }

        Ok((
            Self {
                era: era as u8, // validated to 6 | 7 above
                block_number,
                slot,
                prev_hash,
                block_hash,
                issuer_vkey,
                vrf_vkey,
                vrf_output,
                vrf_proof,
                block_body_hash,
                opcert,
                header_body,
                body_signature,
            },
            BlockBodySpans {
                tx_bodies,
                tx_witness_sets,
                auxiliary_data,
                invalid_transactions,
            },
        ))
    }
}

/// Skip one CBOR item and return the byte range it occupied. Used to capture a
/// block-body segment's raw wire span for the body-commitment bind.
fn capture_span(d: &mut Decoder<'_>) -> Result<core::ops::Range<usize>, DecodeError> {
    let start = d.position();
    d.skip().map_err(|_| DecodeError::MalformedCbor)?;
    Ok(start..d.position())
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
fn read_optional_hash32(d: &mut Decoder<'_>) -> Result<Option<[u8; 32]>, DecodeError> {
    match d.datatype().map_err(|_| DecodeError::MalformedCbor)? {
        Type::Null => {
            d.skip().map_err(|_| DecodeError::MalformedCbor)?;
            Ok(None)
        }
        Type::Bytes => {
            let b = d.bytes().map_err(|_| DecodeError::MalformedCbor)?;
            b.try_into()
                .map(Some)
                .map_err(|_| DecodeError::BadHashLen(b.len()))
        }
        _ => Err(DecodeError::MalformedCbor),
    }
}
