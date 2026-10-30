//! N1/N2 detail observations the emulator emits (DESIGN.md §11 N1/N2).
//!
//! Like the N0 codes (`scenarios/n0.rs`), these ride the
//! [`dsl::ObsKind::Other`] extension slot. The runner wires the emulator to
//! emit them; the lane checks match on the numeric code.
//!
//! | code | meaning |
//! |------|---------|
//! | 41 | NUT received a CE 131 ticket distribution |
//! | 42 | NUT received a CE 132 ticket distribution |
//! | 43 | ticket for an unknown epoch → stream reset |
//! | 44 | bad ticket proof ignored (not held/forwarded) |
//! | 45 | emulator sent a ticket via CE 131 (to the NUT as proxy) |
//! | 46 | emulator sent a ticket via CE 132 (broadcast incl. the NUT) |
//! | 47 | emulator withheld a planned ticket: the NUT could not accept it |

/// NUT received a CE 131 ticket distribution.
pub const RECV_CE131: u8 = 41;
/// NUT received a CE 132 ticket distribution.
pub const RECV_CE132: u8 = 42;
/// Ticket for an unknown epoch → the stream is reset.
pub const UNKNOWN_EPOCH_RESET: u8 = 43;
/// Bad ticket proof ignored (not held, not forwarded).
pub const BAD_PROOF_IGNORED: u8 = 44;
/// Emulator delivered a ticket via CE 131 (NUT as proxy).
pub const EMU_SENT_131: u8 = 45;
/// Emulator delivered a ticket via CE 132 (broadcast incl. the NUT).
pub const EMU_SENT_132: u8 = 46;
/// Emulator withheld a planned ticket because the NUT was not in a state to
/// accept it; see `ticket_io::node_can_accept_tickets`.
pub const TICKET_WITHHELD: u8 = 47;
