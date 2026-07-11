//! Praos epoch-nonce evolution formula, differentially checked against
//! pallas-crypto's independent nonce implementation and its golden vectors.
//!
//! The Praos (Babbage+) nonce machinery is three byte-level primitives:
//!
//! * the combine `⭒` (`Blake2b256(a‖b)`), which is both the rolling-fold step
//!   and the epoch-boundary combine;
//! * a block's contribution `Blake2b256(Blake2b256(0x4E ‖ vrf_output))` — the
//!   `0x4E` domain tag and the *double* hash are the Praos-specific shape, absent
//!   from the legacy TPraos rolling nonce;
//! * the rolling fold `η_v' = η_v ⭒ contribution`.
//!
//! pallas-crypto ships an independent implementation with published golden
//! vectors. Its `generate_epoch_nonce(nc, nh, ee)` *is* the combine (`nc ⭒ nh`,
//! then optional `⭒ ee`), so its `test_epoch_nonce` vectors pin Sextant's
//! [`nonce::epoch_nonce`] and the `⭒` operator to hard-coded ground truth. Its
//! `generate_rolling_nonce(prev, x) = Blake2b256(prev ‖ Blake2b256(x))`, so
//! feeding it the extended input `Blake2b256(0x4E ‖ vrf_output)` reproduces the
//! full Praos fold — an oracle for [`nonce::evolve`] on the real preprod VRF
//! outputs, non-circular because the test assembles the tagged input itself with
//! pallas's own (independent) Blake2b.

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use pallas_crypto::hash::{Hash, Hasher};
use pallas_crypto::nonce::{generate_epoch_nonce, generate_rolling_nonce};
use sextant::header::HeaderView;
use sextant::nonce;

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim()).expect("valid hex")
}

fn h32(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("32-byte hex")
}

fn h64(s: &str) -> [u8; 64] {
    unhex(s).try_into().expect("64-byte hex")
}

/// pallas `Hash<32>` → the fixed array Sextant's primitives return.
fn arr32(h: Hash<32>) -> [u8; 32] {
    h.as_ref().try_into().expect("Hash<32> is 32 bytes")
}

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

/// The certified 64-byte VRF output of every preprod vector, ordered by slot so
/// the folded sequence is deterministic across platforms.
fn preprod_vrf_outputs() -> Vec<(u64, [u8; 64])> {
    let mut out = Vec::new();
    for entry in fs::read_dir(vectors_dir()).expect("read vectors dir") {
        let path = entry.expect("dir entry").path();
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if !name.starts_with("preprod-")
            || path.extension().and_then(|e| e.to_str()) != Some("block")
        {
            continue;
        }
        let view = HeaderView::from_block_cbor(&unhex(&fs::read_to_string(&path).expect("read")))
            .unwrap_or_else(|e| panic!("decode {}: {e:?}", path.display()));
        out.push((view.slot, view.vrf_output));
    }
    out.sort_by_key(|(slot, _)| *slot);
    out
}

/// The epoch-boundary combine and the `⭒` operator, byte-exact against
/// pallas-crypto's `test_epoch_nonce` golden vectors and its live function.
/// The `None` case is `candidate ⭒ prevHashNonce`; the `Some` case folds a
/// 32-byte extra-entropy nonce on top.
#[test]
fn epoch_nonce_matches_pallas_test_epoch_nonce() {
    // (candidate nc, prevHashNonce nh, extra_entropy, expected η0) — verbatim
    // from pallas-crypto's nonce::tests::test_epoch_nonce.
    let nc = [
        h32("e86e133bd48ff5e79bec43af1ac3e348b539172f33e502d2c96735e8c51bd04d"),
        h32("d1340a9c1491f0face38d41fd5c82953d0eb48320d65e952414a0c5ebaf87587"),
    ];
    let nh = [
        h32("d7a1ff2a365abed59c9ae346cba842b6d3df06d055dba79a113e0704b44cc3e9"),
        h32("ee91d679b0a6ce3015b894c575c799e971efac35c7a8cbdc2b3f579005e69abd"),
    ];
    let ee = h32("d982e06fd33e7440b43cefad529b7ecafbaa255e38178ad4189a37e4ce9bf1fa");
    let extra: [Option<&[u8; 32]>; 2] = [None, Some(&ee)];
    let expected = [
        h32("e536a0081ddd6d19786e9d708a85819a5c3492c0da7349f59c8ad3e17e4acd98"),
        h32("0022cfa563a5328c4fb5c8017121329e964c26ade5d167b1bd9b2ec967772b60"),
    ];

    for i in 0..2 {
        let got = nonce::epoch_nonce(&nc[i], &nh[i], extra[i]);
        assert_eq!(got, expected[i], "case {i}: epoch nonce ≠ golden");

        // Live parity against pallas's own independent implementation.
        let oracle = generate_epoch_nonce(
            Hash::from(&nc[i][..]),
            Hash::from(&nh[i][..]),
            extra[i].map(|e| &e[..]),
        );
        assert_eq!(got, arr32(oracle), "case {i}: epoch nonce ≠ pallas oracle");
    }
}

/// The `⭒` operator and its left-associative fold, byte-exact against
/// pallas-crypto's `test_rolling_nonce` golden: 30 blocks folded from the
/// shelley-genesis seed. That vector is TPraos-shaped (per-block contribution is
/// a *single* `Blake2b256(eta_vrf)`), so it exercises `combine` and the fold
/// chaining with the contribution supplied explicitly — pinning `⭒` to ground
/// truth independently of the Praos double-hash.
#[test]
fn combine_and_fold_match_pallas_test_rolling_nonce() {
    let eta_vrf = [
        "36ec5378d1f5041a59eb8d96e61de96f0950fb41b49ff511f7bc7fd109d4383e1d24be7034e6749c6612700dd5ceb0c66577b88a19ae286b1321d15bce1ab736",
        "e0bf34a6b73481302f22987cde4c12807cbc2c3fea3f7fcb77261385a50e8ccdda3226db3efff73e9fb15eecf841bbc85ce37550de0435ebcdcb205e0ed08467",
        "7107ef8c16058b09f4489715297e55d145a45fc0df75dfb419cab079cd28992854a034ad9dc4c764544fb70badd30a9611a942a03523c6f3d8967cf680c4ca6b",
        "6f561aad83884ee0d7b19fd3d757c6af096bfd085465d1290b13a9dfc817dfcdfb0b59ca06300206c64d1ba75fd222a88ea03c54fbbd5d320b4fbcf1c228ba4e",
        "3d3ba80724db0a028783afa56a85d684ee778ae45b9aa9af3120f5e1847be1983bd4868caf97fcfd82d5a3b0b7c1a6d53491d75440a75198014eb4e707785cad",
        "0b07976bc04321c2e7ba0f1acb3c61bd92b5fc780a855632e30e6746ab4ac4081490d816928762debd3e512d22ad512a558612adc569718df1784261f5c26aff",
        "5e9e001fb1e2ddb0dc7ff40af917ecf4ba9892491d4bcbf2c81db2efc57627d40d7aac509c9bcf5070d4966faaeb84fd76bb285af2e51af21a8c024089f598c1",
        "182e83f8c67ad2e6bddead128e7108499ebcbc272b50c42783ef08f035aa688fecc7d15be15a90dbfe7fe5d7cd9926987b6ec12b05f2eadfe0eb6cad5130aca4",
        "275e7404b2385a9d606d67d0e29f5516fb84c1c14aaaf91afa9a9b3dcdfe09075efdadbaf158cfa1e9f250cc7c691ed2db4a29288d2426bd74a371a2a4b91b57",
        "0f35c7217792f8b0cbb721ae4ae5c9ae7f2869df49a3db256aacc10d23997a09e0273261b44ebbcecd6bf916f2c1cd79cf25b0c2851645d75dd0747a8f6f92f5",
        "14c28bf9b10421e9f90ffc9ab05df0dc8c8a07ffac1c51725fba7e2b7972d0769baea248f93ed0f2067d11d719c2858c62fc1d8d59927b41d4c0fbc68d805b32",
        "e4ce96fee9deb9378a107db48587438cddf8e20a69e21e5e4fbd35ef0c56530df77eba666cb152812111ba66bbd333ed44f627c727115f8f4f15b31726049a19",
        "b38f315e3ce369ea2551bf4f44e723dd15c7d67ba4b3763997909f65e46267d6540b9b00a7a65ae3d1f3a3316e57a821aeaac33e4e42ded415205073134cd185",
        "4bcbf774af9c8ff24d4d96099001ec06a24802c88fea81680ea2411392d32dbd9b9828a690a462954b894708d511124a2db34ec4179841e07a897169f0f1ac0e",
        "65247ace6355f978a12235265410c44f3ded02849ec8f8e6db2ac705c3f57d322ea073c13cf698e15d7e1d7f2bc95e7b3533be0dee26f58864f1664df0c1ebba",
        "d0c2bb451d0a3465a7fef7770718e5e49bf092a85dbf5af66ea26ec9c1b359026905fc1457e2b98b01ede7ba42aedcc525301f747a0ed9a9b61c37f27f9d8812",
        "250d9ec7ebec73e885798ae9427e1ea47b5ae66059b465b7c0fd132d17a9c2dcae29ba72863c1861cfb776d342812c4e9000981c4a40819430d0e84aa8bfeb0d",
        "0549cc0a5e5b9920796b88784c49b7d9a04cf2e86ab18d5af7b00780e60fb0fb5a7129945f4f918201dbad5348d4ccface4370f266540f8e072cdb46d3705930",
        "e543a26031dbdc8597b1beeba48a4f1cf6ab90c0e5b9343936b6e948a791198fc4fa22928e21edec812a04d0c9629772bf78e475d91a323cd8a8a6e005f92b4d",
        "4e4be69ad170fb8b3b17835913391ee537098d49e4452844a71ab2147ac55e45871c8943271806034ee9450b31c9486db9d26942946f48040ece7eea81424af1",
        "cb8a528288f902349250f9e8015e8334b0e24c2eeb9bb7d75e73c39024685804577565e62aca35948d2686ea38e9f8de97837ea30d2fb08347768394416e4a38",
        "fce94c47196a56a5cb94d5151ca429daf1c563ae889d0a42c2d03cfe43c94a636221c7e21b0668de9e5b6b32ee1e78b2c9aabc16537bf79c7b85eb956f433ac7",
        "fc8a125c9e2418c87907db4437a0ad6a378bba728ac8e0ce0e64f2a2f4b8201315e1b08d7983ce597cb68be2a2400d6d0d59b7359fe3dc9daca73d468da48972",
        "49290417311420d67f029a80b013b754150dd0097aa64de1c14a2467ab2e26cc2724071c04cb90cb0cf6c6353cf31f63235af7849d6ba023fd0fc0bc79d32f0b",
        "45c65effdc8007c9f2fc9057af986e94eb5c12b755465058d4b933ee37638452c5eeca4b43b8cbddabc60f29cbe5676b0bc55c0da88f8d0c36068e7d17ee603a",
        "a51e4e0f28aee3024207d87a5a1965313bdba4df44c6b845f7ca3408e5dabfe873df6b6ba26000e841f83f69e1de7857122ba538b42f255da2d013208af806ba",
        "5dbd891bf3bcfd5d054274759c13552aeaa187949875d81ee62ed394253ae25182e78b3a4a1976a7674e425bab860931d57f8a1d4fdc81fa4c3e8e8bf9016d5d",
        "3b5b044026e9066d62ce2f5a1fb01052a8cfe200dea28d421fc70f42c4d2b890b90ffef5675de1e47e4a20c9ca8700ceea23a61338ac759a098d167fa71642cb",
        "bb4017880cfa1e37f256dfe2a9cdb1349ed5dea8f69de75dc5933540dcf49e69afc33c837ba8a791857e16fad8581c4e9046778c49ca1ecd1fb675983be6d721",
        "517bbdb6e9e5f4702193064543204e780f5d33a866d0dcd65ada19f05715dea60ca81b842de5dca8f6b84a9cf469c8fb81991369dba21571476cc9c8d4ff2136",
    ];
    let expected = [
        "2af15f57076a8ff225746624882a77c8d2736fe41d3db70154a22b50af851246",
        "a815ff978369b57df09b0072485c26920dc0ec8e924a852a42f0715981cf0042",
        "f112d91435b911b6b5acaf27198762905b1cdec8c5a7b712f925ce3c5c76bb5f",
        "5450d95d9be4194a0ded40fbb4036b48d1f1d6da796e933fefd2c5c888794b4b",
        "c5c0f406cb522ad3fead4ecc60bce9c31e80879bc17eb1bb9acaa9b998cdf8bf",
        "5857048c728580549de645e087ba20ef20bb7c51cc84b5bc89df6b8b0ed98c41",
        "d6f40ef403687115db061b2cb9b1ab4ddeb98222075d5a3e03c8d217d4d7c40e",
        "5489d75a9f4971c1824462b5e2338609a91f121241f21fee09811bd5772ae0a8",
        "04716326833ecdb595153adac9566a4b39e5c16e8d02526cb4166e4099a00b1a",
        "39db709f50c8a279f0a94adcefb9360dbda6cdce168aed4288329a9cd53492b6",
        "c784b8c8678e0a04748a3ad851dd7c34ed67141cd9dc0c50ceaff4df804699a7",
        "cc1a5861358c075de93a26a91c5a951d5e71190d569aa2dc786d4ca8fc80cc38",
        "514979c89313c49e8f59fb8445113fa7623e99375cc4917fe79df54f8d4bdfce",
        "6a783e04481b9e04e8f3498a3b74c90c06a1031fb663b6793ce592a6c26f56f4",
        "1190f5254599dcee4f3cf1afdf4181085c36a6db6c30f334bfe6e6f320a6ed91",
        "91c777d6db066fe58edd67cd751fc7240268869b365393f6910e0e8f0fa58af3",
        "c545d83926c011b5c68a72de9a4e2f9da402703f4aab1b967456eae73d9f89b3",
        "ec31d2348bf543482842843a61d5b32691dedf801f198d68126c423ddf391e8b",
        "de223867d5c972895dd99ac0280a3e02947a7fb018ed42ed048266f913d2dfc2",
        "4dd9801752aade9c6e06bf03e9d2ec8a30ef7c6f30106790a23a9599e90ee08a",
        "fcb183abd512271f40408a5872827ce79cc2dda685a986a7dbdc61d842495a91",
        "e834d8ffd6dd042167b13e38512c62afdaf4d635d5b1ab0d513e08e9bef0ef63",
        "270a78257a958cd5fdb26f0b9ab302df2d2196fd04989f7ca1bb703e4dd904f0",
        "7e324f67af787dfddee10354128c60c60bf601bd8147c867d2471749a7b0f334",
        "54521ed42e0e782b5268ec55f80cff582162bc23fdcee5cdaa0f1a2ce7fa1f02",
        "557c296a71d8c9cb3fe7dcd95fbf4d70f6a3974d93c71b450d62a41b9a85d5a1",
        "20e078301ca282857378bbf10ac40965445c4c9fa73a160e0a116b4cf808b4b4",
        "b5a741dd3ff6a5a3d27b4d046dfb7a3901aacd37df7e931ba05e1320ad155c1c",
        "8b445f35f4a7b76e5d279d71fa9e05376a7c4533ca8b2b98fd2dbaf814d3bf8f",
        "08e7b5277abc139deb50f61264375fa091c580f8a85f259be78a002f7023c31f",
    ];

    let mut prev = h32("1a3be38bcbb7911969283716ad7aa550250226b76a61fc51cc9a9a35d9276d81");
    for (v, exp) in eta_vrf.iter().zip(expected.iter()) {
        // The TPraos per-block contribution is a single Blake2b256 of the VRF
        // output; supply it explicitly so this exercises `⭒` + the fold, not the
        // Praos double-hash.
        let contribution = arr32(Hasher::<256>::hash(&unhex(v)));
        let got = nonce::combine(&prev, &contribution);
        assert_eq!(hex::encode(got), *exp, "rolling fold ≠ golden");
        prev = got;
    }
}

/// The full Praos rolling fold on the real preprod VRF outputs, byte-exact
/// against pallas as an independent oracle. `generate_rolling_nonce(prev, x) =
/// Blake2b256(prev ‖ Blake2b256(x))`, so passing the extended input
/// `Blake2b256(0x4E ‖ vrf_output)` — assembled here with pallas's own Blake2b —
/// reproduces `combine(prev, Blake2b256(Blake2b256(0x4E ‖ vrf_output)))`, which
/// is exactly `nonce::evolve`. Non-circular: the tag and the extended input are
/// built by the test, not by the code under test.
#[test]
fn praos_evolve_matches_pallas_rolling_on_real_preprod_vectors() {
    let outputs = preprod_vrf_outputs();
    let distinct: HashSet<[u8; 64]> = outputs.iter().map(|(_, o)| *o).collect();
    assert!(
        distinct.len() >= 20,
        "DoD needs ≥20 distinct real VRF outputs to fold, found {}",
        distinct.len(),
    );

    let mut prev = h32("1a3be38bcbb7911969283716ad7aa550250226b76a61fc51cc9a9a35d9276d81");
    for (slot, vrf_output) in &outputs {
        // Extended nonce input, built independently of the code under test.
        let mut tagged = Vec::with_capacity(65);
        tagged.push(0x4E);
        tagged.extend_from_slice(vrf_output);
        let extended = Hasher::<256>::hash(&tagged);

        // The single block's contribution decomposes as the outer Blake2b256 of
        // the extended input — pin that directly, then the full fold via pallas.
        let contribution = nonce::block_nonce_contribution(vrf_output);
        assert_eq!(
            contribution,
            arr32(Hasher::<256>::hash(extended.as_ref())),
            "slot {slot}: block contribution ≠ Blake2b256(Blake2b256(0x4E‖vrf))",
        );

        let got = nonce::evolve(&prev, vrf_output);
        let oracle = generate_rolling_nonce(Hash::from(&prev[..]), extended.as_ref());
        assert_eq!(got, arr32(oracle), "slot {slot}: evolve ≠ pallas rolling");
        assert_eq!(
            got,
            nonce::combine(&prev, &contribution),
            "slot {slot}: evolve ≠ combine∘contribution",
        );
        prev = got;
    }
}

/// The block contribution is the Praos double-hash with the `0x4E` tag, not the
/// legacy TPraos single-hash and not some other tag. Both distinctions are
/// load-bearing for a correct epoch nonce, so guard them against silent
/// regression.
#[test]
fn block_contribution_is_praos_double_hash_with_tag() {
    let vrf = h64(
        "af9ff8cb146880eba1b12beb72d86be46fbc98f6b88110cd009bd6746d255a14\
         bb0637e3a29b7204bff28236c1b9f73e501fed1eb5634bd741be120332d25e5e",
    );
    let contribution = nonce::block_nonce_contribution(&vrf);

    // Not the legacy single hash of the raw output.
    assert_ne!(
        contribution,
        arr32(Hasher::<256>::hash(&vrf)),
        "contribution must not be the TPraos single hash",
    );
    // Not the single hash of the tagged output (the inner hash alone).
    let mut tagged = Vec::with_capacity(65);
    tagged.push(0x4E);
    tagged.extend_from_slice(&vrf);
    assert_ne!(
        contribution,
        arr32(Hasher::<256>::hash(&tagged)),
        "contribution must be the *double* hash",
    );
    // A different domain tag yields a different contribution.
    let mut wrong_tag = tagged.clone();
    wrong_tag[0] = 0x4D;
    assert_ne!(
        contribution,
        arr32(Hasher::<256>::hash(
            Hasher::<256>::hash(&wrong_tag).as_ref()
        )),
        "the 0x4E tag is load-bearing",
    );
}

/// `⭒` is not commutative and extra entropy is genuinely optional: swapping the
/// combine operands, or folding a non-neutral extra-entropy nonce, changes the
/// result. Guards against an accidental order-insensitive or entropy-ignoring
/// implementation.
#[test]
fn combine_is_order_sensitive_and_extra_entropy_is_optional() {
    let a = h32("e86e133bd48ff5e79bec43af1ac3e348b539172f33e502d2c96735e8c51bd04d");
    let b = h32("d7a1ff2a365abed59c9ae346cba842b6d3df06d055dba79a113e0704b44cc3e9");
    assert_ne!(
        nonce::combine(&a, &b),
        nonce::combine(&b, &a),
        "⭒ is ordered"
    );

    let ee = h32("d982e06fd33e7440b43cefad529b7ecafbaa255e38178ad4189a37e4ce9bf1fa");
    let without = nonce::epoch_nonce(&a, &b, None);
    let with = nonce::epoch_nonce(&a, &b, Some(&ee));
    assert_eq!(without, nonce::combine(&a, &b), "None must be the identity");
    assert_ne!(with, without, "extra entropy must change the epoch nonce");
    assert_eq!(
        with,
        nonce::combine(&without, &ee),
        "extra entropy folds via ⭒"
    );
}
