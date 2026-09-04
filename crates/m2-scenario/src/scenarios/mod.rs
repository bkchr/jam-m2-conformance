//! Hard-coded scenario lanes (DESIGN.md §5, §11).
//!
//! Each lane module is a set of [`dsl::Check`] functions — the conformance
//! assertions. The runner executes them against the `m2-emu` observation log.

pub mod l0;
pub mod l1;
pub mod l2;
pub mod obs;
