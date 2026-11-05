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
//! | 43 | NUT refused a ticket the emulator sent: it reset the stream |
//! | 45 | emulator sent a ticket via CE 131 (to the NUT as proxy) |
//! | 46 | emulator sent a ticket via CE 132 (broadcast incl. the NUT) |
//! | 47 | emulator withheld a planned ticket: the NUT could not accept it |
//! | 48 | NUT sent a CE 131/132 frame that would not decode |
//!
//! Code 44 is retired. It meant two unrelated things -- the NUT refusing a
//! ticket, and the NUT sending a frame the harness could not decode -- and
//! because the lanes read it with an unscoped `obs.first`, any undecodable
//! frame anywhere in a run satisfied a check about a refusal. The refusal is
//! now recorded per delivery on `ctx::DeliveredTicket`, where it names which
//! ticket was refused; 48 is the encoding fault, which is the NUT's defect
//! and nothing to do with refusals. The number is not reused, so an old trace
//! cannot be read as if it meant either of them.

/// NUT received a CE 131 ticket distribution.
pub const RECV_CE131: u8 = 41;
/// NUT received a CE 132 ticket distribution.
pub const RECV_CE132: u8 = 42;
/// The NUT refused a ticket the emulator sent, by resetting its stream.
///
/// Why it refused is not inferred here: the reset carries no reason, and the
/// cause is whatever the harness deliberately put in that ticket. The lanes
/// read the refusal off the delivery record, which names the ticket; this
/// code exists so the observation log and the report show that a refusal
/// happened at all.
pub const TICKET_REFUSED: u8 = 43;
/// Emulator delivered a ticket via CE 131 (NUT as proxy).
pub const EMU_SENT_131: u8 = 45;
/// Emulator delivered a ticket via CE 132 (broadcast incl. the NUT).
pub const EMU_SENT_132: u8 = 46;
/// Emulator withheld a planned ticket because the NUT was not in a state to
/// accept it; see `ticket_io::node_can_accept_tickets`.
pub const TICKET_WITHHELD: u8 = 47;
/// The NUT sent a CE 131/132 frame the harness could not decode.
///
/// An encoding defect on the node's side. It used to share a code with the
/// refusal above, which let any such frame satisfy a check about a refused
/// ticket -- and the CE 131 decoder defect closed on 2026-10-30 was a
/// generator of exactly these.
pub const NUT_SENT_UNDECODABLE: u8 = 48;
