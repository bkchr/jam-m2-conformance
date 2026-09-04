//! Scenario model and scheduler for the JAM M2 harness.
//!
//! A scenario is a conversation script: every stimulus the harness sends has
//! an expected *answer* — a sequence of messages that must appear in the
//! observation log in response. Sequences are hard-coded Rust checks; the DSL
//! matches expectations as a subsequence with event-relative timing windows.
#![deny(unsafe_code)]

pub mod dsl;
pub mod scenarios;
