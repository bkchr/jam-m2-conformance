//! Reference oracle for the JAM M2 harness.
//!
//! Wraps the polkajam `hazmat` reference engine. What is implemented today:
//! the 6-validator tiny reference chain ([`chain`]), authoring blocks for the
//! emulated slots, importing NUT blocks and diffing the resulting state
//! ([`import`], [`state`]), and generating, planning and verifying Safrole
//! tickets, including the deliberately broken ones ([`tickets`]).
//!
//! `m2-emu` never executes core logic: every value and decision is computed
//! once here and injected.
//!
//! **Not here yet.** DESIGN §3 describes this crate as also signing guarantees,
//! assurances and judgments, refining work packages, and erasure-coding
//! bundles. None of that exists: those are N3's and N4's, and DESIGN §8 lists
//! the polkajam `hazmat` changes they need first -- public, RNG-parameterised
//! provisioners, a keyset-subset constructor, `compose_guarantee` returning a
//! signed artefact rather than submitting it, and an export for bundle ->
//! shards + justifications + segment proofs, whose surface §8 says still needs
//! inspection. This paragraph is here because the sentence it replaces read as
//! though the work was done.
#![deny(unsafe_code)]

pub mod chain;
pub mod import;
pub mod reports;
pub mod state;
pub mod tickets;
