//! Hard-coded scenario lanes (DESIGN.md §5, §11).
//!
//! Each lane module is a set of [`dsl::Check`] functions — the conformance
//! assertions. The runner executes them against the `m2-emu` observation log.

pub mod n0;
pub mod n1;
pub mod n2;
pub mod obs;
