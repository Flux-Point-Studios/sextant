//! M0 executor runner: run the mithril guest in the RISC Zero local executor
//! (no proving) over exact fixture bytes; record user cycles, total cycles,
//! segment count, wall time, and the journaled verdict as evidence files.
//!
//! Usage: hg-m0-runner <user-elf> <fixture.json> <evidence-dir>

use std::time::Instant;

use anyhow::Context;
use risc0_zkvm::{ExecutorEnv, ExecutorImpl, NullSegmentRef};
use sha2::{Digest, Sha256};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: hg-m0-runner <user-elf> <fixture.json> <evidence-dir>";
    let elf_path = args.next().context(usage)?;
    let fixture_path = args.next().context(usage)?;
    let out_dir = args.next().context(usage)?;

    let user_elf = std::fs::read(&elf_path).with_context(|| format!("read {elf_path}"))?;
    let fixture = std::fs::read(&fixture_path).with_context(|| format!("read {fixture_path}"))?;
    std::fs::create_dir_all(&out_dir)?;

    // Combine with the v1compat kernel exactly as risc0-build v3.0.5 does —
    // hosts load the combined ProgramBinary, and the image ID is over it.
    let binary = risc0_binfmt::ProgramBinary::new(&user_elf, risc0_zkos_v1compat::V1COMPAT_ELF);
    let combined = binary.encode();
    let image_id = risc0_binfmt::compute_image_id(&combined)?;
    let elf_sha256 = hex::encode(Sha256::digest(&user_elf));

    println!("HG_RUN elf={elf_path} fixture={fixture_path}");
    println!("HG_RUN user_elf_sha256={elf_sha256} image_id={image_id}");

    let env = ExecutorEnv::builder()
        .session_limit(None)
        .write(&fixture)?
        .build()?;
    let mut exec = ExecutorImpl::from_elf(env, &combined)?;

    let t0 = Instant::now();
    // Segments are counted but not retained: proving is out of scope and
    // retaining full segment data for multi-billion-cycle sessions is a
    // needless memory sink.
    let result = exec.run_with_callback(|_| Ok(Box::new(NullSegmentRef)));
    let wall_s = t0.elapsed().as_secs_f64();

    let out = std::path::Path::new(&out_dir);
    match result {
        Ok(session) => {
            let journal = session
                .journal
                .as_ref()
                .map(|j| j.bytes.clone())
                .unwrap_or_default();
            let verdict = match <[u8; 4]>::try_from(journal.as_slice()) {
                Ok(w) => i64::from(u32::from_le_bytes(w)),
                Err(_) => -1,
            };
            let journal_hex = hex::encode(&journal);
            println!(
                "HG_RESULT status=ok verdict={verdict} user_cycles={} total_cycles={} \
                 paging_cycles={} reserved_cycles={} segments={} exit_code={:?} \
                 exec_wall_s={wall_s:.3} journal={journal_hex}",
                session.user_cycles,
                session.total_cycles,
                session.paging_cycles,
                session.reserved_cycles,
                session.segments.len(),
                session.exit_code,
            );
            std::fs::write(out.join("journal.hex"), format!("{journal_hex}\n"))?;
            let json = serde_json::json!({
                "status": "ok",
                "elf": elf_path,
                "user_elf_sha256": elf_sha256,
                "image_id": image_id.to_string(),
                "fixture": fixture_path,
                "fixture_sha256": hex::encode(Sha256::digest(&fixture)),
                "verdict": verdict,
                "user_cycles": session.user_cycles,
                "total_cycles": session.total_cycles,
                "paging_cycles": session.paging_cycles,
                "reserved_cycles": session.reserved_cycles,
                "segments": session.segments.len(),
                "exit_code": format!("{:?}", session.exit_code),
                "exec_wall_s": wall_s,
                "journal_hex": journal_hex,
            });
            std::fs::write(out.join("result.json"), serde_json::to_string_pretty(&json)?)?;
        }
        Err(err) => {
            // A guest fault (e.g. a panic inside a dependency) is data, not a
            // crash of the harness: record it and exit nonzero.
            println!("HG_RESULT status=guest_error exec_wall_s={wall_s:.3} error={err:#}");
            let json = serde_json::json!({
                "status": "guest_error",
                "elf": elf_path,
                "user_elf_sha256": elf_sha256,
                "image_id": image_id.to_string(),
                "fixture": fixture_path,
                "fixture_sha256": hex::encode(Sha256::digest(&fixture)),
                "exec_wall_s": wall_s,
                "error": format!("{err:#}"),
            });
            std::fs::write(out.join("result.json"), serde_json::to_string_pretty(&json)?)?;
            std::process::exit(3);
        }
    }
    Ok(())
}
