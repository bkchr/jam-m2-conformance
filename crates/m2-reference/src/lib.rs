//! Reference oracle for the JAM M2 harness.
//!
//! Wraps the polkajam `hazmat` reference engine: builds the 6-validator tiny
//! reference chain, authors blocks for emulated slots, signs tickets /
//! guarantees / assurances / judgments with the five emulated keysets, refines
//! work packages, erasure-codes bundles, and imports + diffs NUT blocks.
//! `m2-emu` never executes core logic: every value and decision is computed
//! once here and injected.
#![deny(unsafe_code)]

pub mod chain;
