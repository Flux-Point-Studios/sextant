//! Windowed spend gate example — the downstream consumer of Sextant's windowed watch
//! verdict and created-output read. Runs the honest PROCEED leg then four refusals (an
//! output below the order floor, a definite spend, a withheld mid-window block, a
//! truncated window) over committed preprod fixtures and prints the structured log lines;
//! this stdout IS the service-log excerpt. Exits nonzero on any unexpected outcome
//! (fail-closed).
//!
//!   cargo run --example windowed_spend_gate --features mithril

mod gate;

fn main() {
    std::process::exit(gate::run_demo());
}
