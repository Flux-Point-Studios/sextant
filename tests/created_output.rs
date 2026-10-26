//! `effects::verify_created_output`: an output a block created, read from the bytes bound to an
//! independently trusted block hash. The creating transaction's phase-2 outcome decides what it
//! created, from the block's body-committed `invalid_transactions`; no caller-supplied validity
//! or transaction bytes enter. Canonical membership of the block stays the caller's to prove.
//! The fixture is mainnet block 13,591,743, whose transaction 7 failed phase 2.

use std::fs;
use std::path::PathBuf;

use pallas_crypto::hash::Hasher;
use pallas_traverse::MultiEraBlock;
use sextant::effects::{CreatedOutputError, verify_created_output};

const BLOCK_HASH: &str = "f258395bec389a78f685862811adafe031122566df38fa2895d6c256a0c2c7e1";
const TX0: &str = "1ae09b7f678f8053665727c23a6d0ebb232c40f699e56dcc40de261f72c2bde9";
const TX7: &str = "6532eb693c0a1170a07061a38e6dbaac8a3acfa57e43d497a33e0d072d40379a";

fn block() -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/invalid-mainnet-13591743.block");
    hex::decode(fs::read_to_string(path).expect("fixture").trim()).expect("hex")
}

fn hash32(hex_str: &str) -> [u8; 32] {
    hex::decode(hex_str)
        .expect("hex")
        .try_into()
        .expect("32 bytes")
}

fn blake2b(data: &[u8]) -> [u8; 32] {
    <[u8; 32]>::try_from(Hasher::<256>::hash(data).as_ref()).expect("32 bytes")
}

/// pallas's reading of output `index` of transaction `tx`, as (address, lovelace).
fn pallas_output(tx: usize, index: usize) -> (Vec<u8>, u64) {
    let block = block();
    let decoded = MultiEraBlock::decode(&block).expect("pallas");
    let txs = decoded.txs();
    let (_, output) = txs[tx]
        .produces()
        .into_iter()
        .find(|(i, _)| *i == index)
        .expect("produced");
    (
        output.address().expect("address").to_vec(),
        output.value().coin(),
    )
}

/// The block's five top-level items as spans: header, bodies, witness sets, auxiliary data and
/// invalid_transactions, inside `[era, [..]]`.
fn segments(block: &[u8]) -> Vec<std::ops::Range<usize>> {
    let mut d = minicbor::Decoder::new(block);
    d.array().expect("[era, block]");
    d.u8().expect("era");
    d.array().expect("block");
    (0..5)
        .map(|_| {
            let start = d.position();
            d.skip().expect("segment");
            start..d.position()
        })
        .collect()
}

/// `block` with `segment` replaced, and the header's block_body_hash recomputed over the four
/// body segments, so only a trusted expected hash can tell it from the original.
fn forged(block: &[u8], segment: usize, replacement: &[u8]) -> Vec<u8> {
    let spans = segments(block);
    let old_body_hash = body_hash(block, &spans);
    let mut out = [
        &block[..spans[segment].start],
        replacement,
        &block[spans[segment].end..],
    ]
    .concat();
    let spans = segments(&out);
    let new_body_hash = body_hash(&out, &spans);
    let header = spans[0].clone();
    let at = out[header.clone()]
        .windows(32)
        .position(|w| w == old_body_hash)
        .expect("body hash in header");
    out[header.start + at..header.start + at + 32].copy_from_slice(&new_body_hash);
    out
}

fn body_hash(block: &[u8], spans: &[std::ops::Range<usize>]) -> [u8; 32] {
    let parts: Vec<u8> = spans[1..]
        .iter()
        .flat_map(|span| blake2b(&block[span.clone()]))
        .collect();
    blake2b(&parts)
}

#[test]
fn a_valid_transactions_output_is_created_with_its_block_provenance() {
    let created =
        verify_created_output(&block(), &hash32(BLOCK_HASH), &hash32(TX0), 0).expect("created");
    assert_eq!(
        (created.address.clone(), created.lovelace),
        pallas_output(0, 0)
    );
    assert!(created.phase2_valid);
    assert_eq!(
        (created.block_hash, created.block_number),
        (hash32(BLOCK_HASH), 13_591_743)
    );
}

#[test]
fn a_phase_2_invalid_transaction_creates_only_its_collateral_return() {
    let block = block();
    for index in [0, 1, 2, 4] {
        assert_eq!(
            verify_created_output(&block, &hash32(BLOCK_HASH), &hash32(TX7), index)
                .map(|c| c.address),
            Err(CreatedOutputError::NotCreated),
            "{index}"
        );
    }
    let created = verify_created_output(&block, &hash32(BLOCK_HASH), &hash32(TX7), 3)
        .expect("collateral return");
    assert_eq!(
        (created.address.clone(), created.lovelace),
        pallas_output(7, 3)
    );
    assert!(!created.phase2_valid);
}

#[test]
fn bytes_that_do_not_hash_to_the_trusted_block_hash_refuse() {
    let block = block();
    let mut other = hash32(BLOCK_HASH);
    other[0] ^= 1;
    assert_eq!(
        verify_created_output(&block, &other, &hash32(TX0), 0).map(|c| c.address),
        Err(CreatedOutputError::HeaderHashMismatch)
    );
}

#[test]
fn a_body_the_header_does_not_commit_to_refuses() {
    let block = block();
    let spans = segments(&block);
    let mut tampered = block.clone();
    tampered[spans[1].end - 1] ^= 1;
    assert_eq!(
        verify_created_output(&tampered, &hash32(BLOCK_HASH), &hash32(TX0), 0).map(|c| c.address),
        Err(CreatedOutputError::BodyCommitmentMismatch)
    );
}

#[test]
fn a_forged_block_with_a_recomputed_commitment_refuses_under_the_trusted_hash() {
    let block = block();
    let spans = segments(&block);
    // Phase 2 rewritten as valid: transaction 7's regular outputs would read created.
    let forged = forged(&block, 4, &[0x80]);
    assert_eq!(
        verify_created_output(&forged, &hash32(BLOCK_HASH), &hash32(TX7), 0).map(|c| c.address),
        Err(CreatedOutputError::HeaderHashMismatch)
    );
    assert_ne!(forged[spans[0].clone()], block[spans[0].clone()]);
}

/// The ledger reads `invalid_transactions` only as a list, with no tag, of strictly
/// ascending indices below the transaction count: a repeat, a descent, an index past the 21
/// transactions, a negative or non-uint entry, a map, and a tag-258 set all refuse.
#[test]
fn a_validity_record_the_ledger_refuses_refuses() {
    let block = block();
    for invalid in [
        &[0x82, 0x07, 0x07][..],
        &[0x82, 0x08, 0x07],
        &[0x81, 0x15],
        &[0x81, 0x18, 0x40],
        &[0x81, 0x20],
        &[0x81, 0x41, 0x00],
        &[0xa0],
        &[0xd9, 0x01, 0x02, 0x81, 0x07],
    ] {
        let forged = forged(&block, 4, invalid);
        let (view, _) = sextant::header::HeaderView::decode_block(&forged).expect("block");
        assert_eq!(
            verify_created_output(&forged, &view.block_hash, &hash32(TX0), 0).map(|c| c.address),
            Err(CreatedOutputError::MalformedValidity),
            "{}",
            hex::encode(invalid)
        );
    }
}

#[test]
fn a_transaction_the_block_does_not_carry_refuses() {
    assert_eq!(
        verify_created_output(&block(), &hash32(BLOCK_HASH), &[0x11; 32], 0).map(|c| c.address),
        Err(CreatedOutputError::TransactionAbsent)
    );
}

/// `block` with its first transaction's body and witness set each carried twice, under
/// a recomputed commitment.
fn with_the_first_transaction_twice(block: &[u8]) -> Vec<u8> {
    let spans = segments(block);
    let twice = |segment: &std::ops::Range<usize>| {
        let region = &block[segment.clone()];
        let mut d = minicbor::Decoder::new(region);
        let count = d.array().expect("array").expect("definite");
        let first = d.position();
        d.skip().expect("item 0");
        let header = vec![0x80 | (u8::try_from(count).expect("small") + 1)];
        [
            header.as_slice(),
            &region[first..d.position()],
            &region[first..],
        ]
        .concat()
    };
    forged(&forged(block, 1, &twice(&spans[1])), 2, &twice(&spans[2]))
}

#[test]
fn a_block_that_carries_the_transaction_twice_refuses() {
    let forged = with_the_first_transaction_twice(&block());
    let (view, _) = sextant::header::HeaderView::decode_block(&forged).expect("block");
    assert_eq!(
        verify_created_output(&forged, &view.block_hash, &hash32(TX0), 0).map(|c| c.address),
        Err(CreatedOutputError::TransactionRepeated)
    );
}

/// `[7, 8]`, adjacent and ascending, reads as the set it names: transaction 8 is now
/// phase-2-invalid, so its first regular output is not created, while transaction 7 still
/// creates only its collateral return and transaction 0 its outputs.
#[test]
fn adjacent_ascending_indices_read_as_the_set_they_name() {
    let block = block();
    let decoded = MultiEraBlock::decode(&block).expect("pallas");
    let tx8: [u8; 32] = *decoded.txs()[8].hash();
    let forged = forged(&block, 4, &[0x82, 0x07, 0x08]);
    let (view, _) = sextant::header::HeaderView::decode_block(&forged).expect("block");
    let read = |tx: &[u8; 32], index| {
        verify_created_output(&forged, &view.block_hash, tx, index).map(|c| c.phase2_valid)
    };
    assert_eq!(read(&tx8, 0), Err(CreatedOutputError::NotCreated));
    assert_eq!(read(&hash32(TX7), 0), Err(CreatedOutputError::NotCreated));
    assert_eq!(read(&hash32(TX7), 3), Ok(false));
    assert_eq!(read(&hash32(TX0), 0), Ok(true));
}

#[test]
fn a_block_that_does_not_decode_refuses() {
    assert_eq!(
        verify_created_output(&[0x00], &hash32(BLOCK_HASH), &hash32(TX0), 0).map(|c| c.address),
        Err(CreatedOutputError::Decode(
            sextant::header::DecodeError::MalformedCbor
        ))
    );
}

/// An index past every output the transaction created refuses, for a valid transaction
/// and for the invalid one past its collateral return.
#[test]
fn an_index_past_what_the_transaction_created_refuses() {
    let block = block();
    for (tx, index) in [(TX0, 99), (TX0, u16::MAX), (TX7, 5), (TX7, u16::MAX)] {
        assert_eq!(
            verify_created_output(&block, &hash32(BLOCK_HASH), &hash32(tx), index)
                .map(|c| c.address),
            Err(CreatedOutputError::NotCreated),
            "{tx} {index}"
        );
    }
}

/// `block`'s transaction bodies with body `position` replaced by `body`, as a bodies
/// segment in the block's own definite form.
fn bodies_with(block: &[u8], position: usize, body: &[u8]) -> Vec<u8> {
    let spans = segments(block);
    let region = &block[spans[1].clone()];
    let mut d = minicbor::Decoder::new(region);
    let count = d.array().expect("bodies").expect("definite");
    let header = region[..d.position()].to_vec();
    let mut items: Vec<Vec<u8>> = (0..count)
        .map(|_| {
            let start = d.position();
            d.skip().expect("body");
            region[start..d.position()].to_vec()
        })
        .collect();
    items[position] = body.to_vec();
    [header, items.concat()].concat()
}

/// The block with `body` in place of the body at `position`, under its own recomputed
/// commitment and header hash, and the read of `index` of that body's transaction.
fn read_synthetic(
    position: usize,
    body: &[u8],
    index: u16,
) -> Result<(Vec<u8>, u64, bool), CreatedOutputError> {
    let block = block();
    let forged = forged(&block, 1, &bodies_with(&block, position, body));
    let (view, _) = sextant::header::HeaderView::decode_block(&forged).expect("block");
    verify_created_output(&forged, &view.block_hash, &blake2b(body), index)
        .map(|c| (c.address, c.lovelace, c.phase2_valid))
}

/// Both phase-2 directions through a real block: at position 0 (valid) a body creates its
/// regular outputs and not its return; at position 7 (invalid) it creates only its return,
/// at the index after its outputs — 0 when it has none — and nothing without one.
#[test]
fn each_phase_2_outcome_creates_by_its_own_rule_in_a_real_block() {
    // o = [h'00', 7] and r = [h'01', 8], legacy outputs.
    let o = [0x82, 0x41, 0x00, 0x07];
    let r = [0x82, 0x41, 0x01, 0x08];
    let both = [&[0xa2, 0x01, 0x81][..], &o, &[0x10], &r].concat();
    assert_eq!(read_synthetic(0, &both, 0), Ok((vec![0x00], 7, true)));
    assert_eq!(
        read_synthetic(0, &both, 1),
        Err(CreatedOutputError::NotCreated)
    );
    assert_eq!(
        read_synthetic(7, &both, 0),
        Err(CreatedOutputError::NotCreated)
    );
    assert_eq!(read_synthetic(7, &both, 1), Ok((vec![0x01], 8, false)));
    // {1: [], 16: r}: the return at 0. {1: [o]}: nothing created when invalid.
    let return_only = [&[0xa2, 0x01, 0x80, 0x10][..], &r].concat();
    assert_eq!(
        read_synthetic(7, &return_only, 0),
        Ok((vec![0x01], 8, false))
    );
    let no_return = [&[0xa1, 0x01, 0x81][..], &o].concat();
    assert_eq!(
        read_synthetic(7, &no_return, 0),
        Err(CreatedOutputError::NotCreated)
    );
    assert_eq!(read_synthetic(0, &no_return, 0), Ok((vec![0x00], 7, true)));
}

/// A creating body the read path refuses is a malformed body, never an absent output: a
/// return no read could return, a repeated return, a repeated outputs key, no outputs key.
#[test]
fn a_creating_body_the_read_path_refuses_is_malformed() {
    let o = [0x82, 0x41, 0x00, 0x07];
    let r = [0x82, 0x41, 0x01, 0x08];
    for body in [
        [&[0xa2, 0x01, 0x81][..], &o, &[0x10, 0x41, 0x00]].concat(),
        [&[0xa3, 0x01, 0x80, 0x10][..], &r, &[0x10], &r].concat(),
        [&[0xa2, 0x01, 0x81][..], &o, &[0x01, 0x81], &o].concat(),
        [&[0xa1, 0x10][..], &r].concat(),
    ] {
        for position in [0, 7] {
            assert_eq!(
                read_synthetic(position, &body, 0),
                Err(CreatedOutputError::MalformedBody),
                "{position} {}",
                hex::encode(&body)
            );
        }
    }
}

/// Every committed Babbage/Conway block, read whole: each output pallas's `produces()`
/// lists reads with pallas's address, coin and datum presence and the block's phase-2
/// record, and every other index up to one past the last refuses as not created. The
/// expected hash is the block's own here: this is a decoder differential, not a trust
/// claim.
#[test]
fn every_committed_created_output_reads_as_pallas_reads_it() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .expect("vectors")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("block"))
        .collect();
    paths.sort();
    let (mut blocks, mut created, mut refused, mut invalid) = (0, 0, 0, 0);
    for path in paths {
        let bytes = hex::decode(fs::read_to_string(&path).expect("read").trim()).expect("hex");
        let Ok((view, _)) = sextant::header::HeaderView::decode_block(&bytes) else {
            continue;
        };
        blocks += 1;
        let decoded = MultiEraBlock::decode(&bytes).expect("pallas");
        for tx in decoded.txs() {
            let tx_id: [u8; 32] = *tx.hash();
            invalid += usize::from(!tx.is_valid());
            let produced = tx.produces();
            let past = produced.iter().map(|(i, _)| i + 1).max().unwrap_or(0);
            for index in 0..=past {
                let read = verify_created_output(
                    &bytes,
                    &view.block_hash,
                    &tx_id,
                    u16::try_from(index).expect("u16"),
                );
                match produced.iter().find(|(i, _)| *i == index) {
                    Some((_, output)) => {
                        let read = read.unwrap_or_else(|e| panic!("{path:?} {index}: {e}"));
                        assert_eq!(
                            (
                                read.address,
                                read.lovelace,
                                read.datum.is_some(),
                                read.phase2_valid
                            ),
                            (
                                output.address().expect("address").to_vec(),
                                output.value().coin(),
                                output.datum().is_some(),
                                tx.is_valid()
                            ),
                            "{path:?} {index}"
                        );
                        created += 1;
                    }
                    None => {
                        assert_eq!(
                            read.map(|c| c.address),
                            Err(CreatedOutputError::NotCreated),
                            "{path:?} {index}"
                        );
                        refused += 1;
                    }
                }
            }
        }
    }
    // The committed corpus: 65 blocks, 2,654 created outputs, 333 refused indices, and
    // the one phase-2-invalid transaction (13,591,743's transaction 7).
    assert_eq!((blocks, created, refused, invalid), (65, 2_654, 333, 1));
}

/// The C-ABI export `sextant_verify_created_output`, called in-process: it marshals the
/// same record the Rust read returns, by the caller-sizing (`-3`) protocol, and every
/// refusal maps to its own 420-band code and leaves the out-struct and both buffers as
/// the caller left them.
mod ffi {
    use super::{
        BLOCK_HASH, TX0, TX7, blake2b, block, bodies_with, forged, hash32, segments,
        with_the_first_transaction_twice,
    };
    use pallas_traverse::MultiEraBlock;
    use sextant::effects::verify_created_output;
    use sextant::ffi::{
        SextantCreatedOutput, SextantErrorDetail, SextantStatus, sextant_status_message,
        sextant_verify_created_output,
    };
    use sextant::utxo::Datum;
    use std::mem::{MaybeUninit, size_of};
    use std::ptr;

    const STRUCT_SENTINEL: u8 = 0x5a;
    const BUFFER_SENTINEL: u8 = 0xaa;

    /// An out-struct with every byte set to [`STRUCT_SENTINEL`], so any write shows.
    fn sentinel() -> SextantCreatedOutput {
        let mut out = MaybeUninit::<SextantCreatedOutput>::uninit();
        // SAFETY: every byte is written, and the struct is a padding-free `#[repr(C)]`
        // aggregate of integers that takes any bit pattern.
        unsafe {
            out.as_mut_ptr().write_bytes(STRUCT_SENTINEL, 1);
            out.assume_init()
        }
    }

    fn struct_bytes(out: &SextantCreatedOutput) -> &[u8] {
        // SAFETY: the struct is padding-free, so all of its bytes are initialised.
        unsafe {
            std::slice::from_raw_parts(
                (out as *const SextantCreatedOutput).cast::<u8>(),
                size_of::<SextantCreatedOutput>(),
            )
        }
    }

    /// One call's out-params, each starting at its sentinel.
    struct Call {
        rc: i32,
        out: SextantCreatedOutput,
        address: Vec<u8>,
        datum: Vec<u8>,
        detail: SextantErrorDetail,
    }

    /// Call the export into sentinel-filled outputs: `caps` sizes the two buffers, and a
    /// `None` cap passes `NULL`/`0` for that buffer.
    fn call(
        block: &[u8],
        expected: &[u8; 32],
        tx_id: &[u8; 32],
        index: u16,
        caps: (Option<usize>, Option<usize>),
    ) -> Call {
        let mut out = sentinel();
        let mut address = vec![BUFFER_SENTINEL; caps.0.unwrap_or(0)];
        let mut datum = vec![BUFFER_SENTINEL; caps.1.unwrap_or(0)];
        let mut detail = SextantErrorDetail {
            index: 77,
            detail: 77,
        };
        let buffer = |buf: &mut Vec<u8>, cap: Option<usize>| match cap {
            Some(cap) => (buf.as_mut_ptr(), cap),
            None => (ptr::null_mut(), 0),
        };
        let (address_ptr, address_cap) = buffer(&mut address, caps.0);
        let (datum_ptr, datum_cap) = buffer(&mut datum, caps.1);
        let rc = unsafe {
            sextant_verify_created_output(
                block.as_ptr(),
                block.len(),
                expected.as_ptr(),
                tx_id.as_ptr(),
                index,
                &mut out,
                address_ptr,
                address_cap,
                datum_ptr,
                datum_cap,
                &mut detail,
            )
        };
        Call {
            rc,
            out,
            address,
            datum,
            detail,
        }
    }

    fn untouched(call: &Call) -> bool {
        struct_bytes(&call.out)
            .iter()
            .all(|b| *b == STRUCT_SENTINEL)
            && call
                .address
                .iter()
                .chain(&call.datum)
                .all(|b| *b == BUFFER_SENTINEL)
    }

    /// Every output 13,591,743 created — every regular output of its 20 valid
    /// transactions and transaction 7's collateral return — crosses the boundary as the
    /// Rust read returns it: scalars, the header hash, the phase-2 byte, zeroed reserved
    /// bytes, and the address and datum bytes in the buffers.
    #[test]
    fn every_created_output_crosses_the_boundary_as_the_rust_read_returns_it() {
        let block = block();
        let expected = hash32(BLOCK_HASH);
        let decoded = MultiEraBlock::decode(&block).expect("pallas");
        let mut kinds = [0usize; 3];
        for tx in decoded.txs() {
            let tx_id: [u8; 32] = *tx.hash();
            for (index, _) in tx.produces() {
                let index = u16::try_from(index).expect("u16");
                let rust = verify_created_output(&block, &expected, &tx_id, index).expect("rust");
                let c = call(&block, &expected, &tx_id, index, (Some(128), Some(4096)));
                assert_eq!(c.rc, SextantStatus::Ok as i32);
                let (kind, datum): (u8, &[u8]) = match &rust.datum {
                    None => (0, &[]),
                    Some(Datum::Hash(h)) => (1, h.as_slice()),
                    Some(Datum::Inline(bytes)) => (2, bytes.as_slice()),
                };
                kinds[kind as usize] += 1;
                assert_eq!(
                    (
                        c.out.lovelace,
                        c.out.block_number,
                        c.out.slot,
                        c.out.block_hash,
                        c.out.datum_kind,
                        c.out.phase2_valid,
                        c.out._reserved
                    ),
                    (
                        rust.lovelace,
                        rust.block_number,
                        rust.slot,
                        rust.block_hash,
                        kind,
                        u8::from(rust.phase2_valid),
                        [0u8; 6]
                    )
                );
                assert_eq!(&c.address[..c.out.address_len], rust.address.as_slice());
                assert_eq!(&c.datum[..c.out.datum_len], datum);
                assert_eq!((c.detail.index, c.detail.detail), (-1, 0));
            }
        }
        assert!(kinds.iter().all(|n| *n > 0), "{kinds:?}");
    }

    /// The sizing protocol: a `NULL`/`0` probe and a buffer one byte short both report
    /// `-3` with the true lengths in a fully written struct, and copy nothing; exact caps
    /// succeed.
    #[test]
    fn the_sizing_protocol_reports_true_lengths_and_copies_nothing_short() {
        let block = block();
        let (expected, tx7) = (hash32(BLOCK_HASH), hash32(TX7));
        let probe = call(&block, &expected, &tx7, 3, (None, None));
        assert_eq!(probe.rc, SextantStatus::ErrBufferTooSmall as i32);
        let (address_len, datum_len) = (probe.out.address_len, probe.out.datum_len);
        assert!(address_len > 0);
        assert_eq!((probe.out.phase2_valid, probe.out._reserved), (0, [0u8; 6]));

        let exact = call(
            &block,
            &expected,
            &tx7,
            3,
            (Some(address_len), Some(datum_len)),
        );
        assert_eq!(exact.rc, SextantStatus::Ok as i32);
        assert!(exact.address.iter().any(|b| *b != BUFFER_SENTINEL));

        let short = call(
            &block,
            &expected,
            &tx7,
            3,
            (Some(address_len - 1), Some(datum_len)),
        );
        assert_eq!(short.rc, SextantStatus::ErrBufferTooSmall as i32);
        assert_eq!(short.out.address_len, address_len);
        assert!(
            short
                .address
                .iter()
                .chain(&short.datum)
                .all(|b| *b == BUFFER_SENTINEL),
            "no truncated prefix"
        );
    }

    /// Each refusal has its own code, writes `{-1, detail}` (a decode failure's leaf code
    /// as the detail), and leaves the struct and buffers untouched — even where a sizing
    /// probe would have answered `-3`.
    #[test]
    fn each_refusal_has_its_code_and_writes_no_output() {
        let block = block();
        let (expected, tx0, tx7) = (hash32(BLOCK_HASH), hash32(TX0), hash32(TX7));
        let mut other = expected;
        other[0] ^= 0x01;
        let mut tampered = block.clone();
        tampered[segments(&block)[1].end - 1] ^= 0x01;
        let own_hash = |bytes: &[u8]| {
            sextant::header::HeaderView::from_block_cbor(bytes)
                .expect("block")
                .block_hash
        };
        let repeated = forged(&block, 4, &[0x82, 0x07, 0x07]);
        let tagged = forged(&block, 4, &[0xd9, 0x01, 0x02, 0x81, 0x07]);
        let twice = with_the_first_transaction_twice(&block);
        // {1: [h'00']}: an output no read could return.
        let bad_body = [0xa1, 0x01, 0x81, 0x41, 0x00];
        let malformed = forged(&block, 1, &bodies_with(&block, 0, &bad_body));
        use SextantStatus as S;
        for (case, bytes, hash, tx, index, status, detail) in [
            (
                "not created",
                &block,
                &expected,
                &tx7,
                0,
                S::CreatedNotCreated,
                0,
            ),
            (
                "absent",
                &block,
                &expected,
                &[0x11; 32],
                0,
                S::CreatedTransactionAbsent,
                0,
            ),
            (
                "other hash",
                &block,
                &other,
                &tx0,
                0,
                S::CreatedHeaderHashMismatch,
                0,
            ),
            (
                "tampered",
                &tampered,
                &expected,
                &tx0,
                0,
                S::CreatedBodyCommitmentMismatch,
                0,
            ),
            (
                "repeated index",
                &repeated,
                &own_hash(&repeated),
                &tx0,
                0,
                S::CreatedMalformedValidity,
                0,
            ),
            (
                "tagged record",
                &tagged,
                &own_hash(&tagged),
                &tx0,
                0,
                S::CreatedMalformedValidity,
                0,
            ),
            (
                "repeated tx",
                &twice,
                &own_hash(&twice),
                &tx0,
                0,
                S::CreatedTransactionRepeated,
                0,
            ),
            (
                "malformed body",
                &malformed,
                &own_hash(&malformed),
                &blake2b(&bad_body),
                0,
                S::CreatedMalformedBody,
                0,
            ),
            (
                "garbage",
                &vec![0x00],
                &expected,
                &tx0,
                0,
                S::CreatedDecode,
                S::DecodeMalformedCbor as u64,
            ),
        ] {
            for caps in [(Some(128), Some(4096)), (None, None)] {
                let c = call(bytes, hash, tx, index, caps);
                assert_eq!(c.rc, status as i32, "{case}");
                assert!(untouched(&c), "{case}");
                assert_eq!((c.detail.index, c.detail.detail), (-1, detail), "{case}");
            }
        }
    }

    /// The refusal codes are new, distinct, and named by the status table.
    #[test]
    fn the_created_band_is_distinct_and_named() {
        use SextantStatus as S;
        let band = [
            S::CreatedDecode,
            S::CreatedHeaderHashMismatch,
            S::CreatedBodyCommitmentMismatch,
            S::CreatedMalformedValidity,
            S::CreatedMalformedBody,
            S::CreatedTransactionAbsent,
            S::CreatedTransactionRepeated,
            S::CreatedNotCreated,
        ];
        assert_eq!(
            band.map(|s| s as i32),
            [420, 421, 422, 423, 424, 425, 426, 427]
        );
        for status in band.map(|s| s as i32).into_iter().chain([412]) {
            let n = unsafe { sextant_status_message(status, ptr::null_mut(), 0) };
            let mut text = vec![0u8; n];
            unsafe { sextant_status_message(status, text.as_mut_ptr(), n) };
            assert_ne!(
                String::from_utf8(text).expect("utf8"),
                "unknown status",
                "{status}"
            );
        }
    }

    /// Null required pointers and an empty block are caller errors: reported ahead of
    /// any read, a null ahead of an empty one, with the struct and detail untouched.
    #[test]
    fn null_and_empty_guards() {
        let block = block();
        let (expected, tx0) = (hash32(BLOCK_HASH), hash32(TX0));
        let mut out = sentinel();
        let mut detail = SextantErrorDetail {
            index: 77,
            detail: 77,
        };
        let guard = |block: *const u8,
                     len: usize,
                     expected: *const u8,
                     tx_id: *const u8,
                     out: *mut SextantCreatedOutput,
                     detail: &mut SextantErrorDetail| unsafe {
            sextant_verify_created_output(
                block,
                len,
                expected,
                tx_id,
                0,
                out,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                0,
                detail,
            )
        };
        let null = SextantStatus::ErrNullPointer as i32;
        let (b, n, e, t) = (block.as_ptr(), block.len(), expected.as_ptr(), tx0.as_ptr());
        assert_eq!(guard(ptr::null(), 0, e, t, &mut out, &mut detail), null);
        assert_eq!(guard(b, n, ptr::null(), t, &mut out, &mut detail), null);
        assert_eq!(guard(b, n, e, ptr::null(), &mut out, &mut detail), null);
        assert_eq!(guard(b, n, e, t, ptr::null_mut(), &mut detail), null);
        assert_eq!(
            guard(b, 0, e, t, &mut out, &mut detail),
            SextantStatus::ErrEmptyInput as i32
        );
        assert!(struct_bytes(&out).iter().all(|b| *b == STRUCT_SENTINEL));
        assert_eq!((detail.index, detail.detail), (77, 77));
    }
}
