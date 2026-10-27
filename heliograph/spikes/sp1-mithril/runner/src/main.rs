//! M0 executor runner — SP1 arm. Executes the guest ELF (no proving) over a
//! fixture, optionally tampered (one flipped byte inside the `multi_signature`
//! hex), and differentials the committed verdict against native Sextant with
//! the same mapping: 0 accept / 1 parse / 2 content-hash / 3 verify_standard.
//! Emits a JSON summary on stdout (last line) and to `<out>/summary.json`.

use sha2::{Digest, Sha256};
use sp1_sdk::blocking::{Prover, ProverClient};
use sp1_sdk::{Elf, SP1Stdin};
use std::time::Instant;

fn native_verdict(bytes: &[u8]) -> u32 {
    use sextant::mithril::{verify_standard, Certificate};
    let cert = match Certificate::from_json(bytes) {
        Ok(c) => c,
        Err(_) => return 1,
    };
    if cert.compute_hash() != cert.hash {
        return 2;
    }
    match verify_standard(&cert) {
        Ok(()) => 0,
        Err(_) => 3,
    }
}

/// Flip one byte inside the `multi_signature` hex value: 16 bytes past the
/// opening quote, mapped to a different valid hex digit so JSON parsing and
/// hex decoding still succeed and only the signature bytes change.
fn tamper(bytes: &mut [u8]) -> (usize, char, char) {
    let key = b"\"multi_signature\"";
    let kpos = bytes
        .windows(key.len())
        .position(|w| w == key)
        .expect("fixture has no multi_signature key");
    let mut i = kpos + key.len();
    while bytes[i] != b'"' {
        i += 1;
    }
    let offset = i + 1 + 16;
    let old = bytes[offset];
    assert!(old.is_ascii_hexdigit(), "offset not inside hex value");
    let new = if old == b'0' { b'1' } else { b'0' };
    bytes[offset] = new;
    (offset, old as char, new as char)
}

fn main() {
    sp1_sdk::utils::setup_logger();
    let args: Vec<String> = std::env::args().collect();
    let usage = "usage: sp1-mithril-runner <elf> <fixture.json> golden|tampered <out-dir>";
    let [_, elf_path, fixture_path, variant, out_dir] = &args[..] else {
        panic!("{usage}");
    };
    assert!(variant == "golden" || variant == "tampered", "{usage}");

    let elf = std::fs::read(elf_path).expect("read elf");
    let mut input = std::fs::read(fixture_path).expect("read fixture");
    let fixture_sha256 = hex::encode(Sha256::digest(&input));

    let tamper_info = (variant == "tampered").then(|| tamper(&mut input));
    let input_sha256 = hex::encode(Sha256::digest(&input));

    let t0 = Instant::now();
    let native = native_verdict(&input);
    let native_seconds = t0.elapsed().as_secs_f64();

    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&input);
    let client = ProverClient::from_env();
    let t1 = Instant::now();
    let (public_values, report) = client
        .execute(Elf::from(elf.clone()), stdin)
        .run()
        .expect("guest execution");
    let exec_seconds = t1.elapsed().as_secs_f64();

    let pv_bytes = public_values.as_slice().to_vec();
    // An in-guest panic completes execution with a nonzero exit code and an
    // empty public-value stream; represent "no committed verdict" as null.
    let guest: Option<u32> = (pv_bytes.len() >= 4).then(|| {
        let mut pv = public_values;
        pv.read()
    });

    let cycle_tracker: std::collections::BTreeMap<&String, &u64> =
        report.cycle_tracker.iter().collect();
    let invocation_tracker: std::collections::BTreeMap<&String, &u64> =
        report.invocation_tracker.iter().collect();

    let summary = serde_json::json!({
        "elf": elf_path,
        "elf_sha256": hex::encode(Sha256::digest(&elf)),
        "fixture": fixture_path,
        "fixture_sha256": fixture_sha256,
        "variant": variant,
        "tamper": tamper_info.map(|(offset, old, new)| serde_json::json!({
            "offset": offset, "old": old.to_string(), "new": new.to_string(),
            "tampered_input_sha256": input_sha256,
        })),
        "guest_verdict": guest,
        "native_verdict": native,
        "verdicts_match": guest == Some(native),
        "public_values_hex": hex::encode(&pv_bytes),
        "total_instruction_count": report.total_instruction_count(),
        "total_syscall_count": report.total_syscall_count(),
        "gas": report.gas(),
        "exit_code": report.exit_code,
        "cycle_tracker": cycle_tracker,
        "invocation_tracker": invocation_tracker,
        "exec_wall_seconds": exec_seconds,
        "native_wall_seconds": native_seconds,
    });
    let rendered = serde_json::to_string_pretty(&summary).expect("render summary");
    std::fs::create_dir_all(out_dir).expect("create out dir");
    std::fs::write(format!("{out_dir}/summary.json"), &rendered).expect("write summary");
    println!("{rendered}");
}
