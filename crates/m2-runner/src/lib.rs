//! M2 conformance runner: orchestrates spec+key generation, NUT launch,
//! connectivity, scenario execution and report/findings/trace output.
#![deny(unsafe_code)]

pub mod cli;
pub mod keygen;
pub mod report;

/// Session directory layout as in `scripts/fuzz-workflow.py`:
/// `sessions/<id>/{logs,traces,report}`.
pub const SESSION_LAYOUT: [&str; 3] = ["logs", "traces", "report"];
