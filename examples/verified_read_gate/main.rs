//! Verified-read provenance example — the body-only composition over Sextant's certified
//! inclusion read. Runs the authentic path (found included, refused for want of its
//! phase-2 outcome) then the spoof path (refused as not included) over committed preprod
//! fixtures and prints the structured log lines. Exits nonzero on any unexpected outcome
//! (fail-closed).
//!
//!   cargo run --example verified_read_gate --features mithril

mod gate;

fn main() {
    std::process::exit(gate::run_demo());
}
