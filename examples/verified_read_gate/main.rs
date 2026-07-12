//! Verified-read spend gate example — the first downstream consumer of Sextant's
//! read verdict. Runs the accept path then the spoof path over committed preprod
//! fixtures and prints the structured log lines; this stdout IS the DoD "service
//! log excerpt". Exits nonzero on any unexpected outcome (fail-closed).
//!
//!   cargo run --example verified_read_gate --features mithril

mod gate;

fn main() {
    std::process::exit(gate::run_demo());
}
