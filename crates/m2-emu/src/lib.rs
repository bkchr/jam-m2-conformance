//! The five emulated validators plus an optional builder peer.
//!
//! One `jamnp-s` endpoint each; reactive handlers (serve CE 128/129/...,
//! accept UP 0, CE 133/...); every inbound and outbound message goes to the
//! observation log. Behaviour is data-driven by the scenario: `m2-emu`
//! executes no core protocol logic.
#![deny(unsafe_code)]

pub mod emu;
pub mod nut_block;
pub mod ticket_io;
