//! N2 Safrole-ticket I/O for the emulated validators (CE 131/132).
//!
//! Inbound: the NUT's ticket streams (`TicketDistribution`, `simple.md:305-349`)
//! are classified by kind and recorded as observations; an undecodable stream
//! is treated as a bad-proof signal (soft) — the NUT is the sender, so the
//! emulator never resets the stream. Outbound: `spawn_ticket_sender` delivers
//! the runner-computed plan's tickets to the NUT on their slot boundaries,
//! holding each one back until the node is in a state to accept it.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use jam_types::{Decode, Encode, JAM_COMMON_ERA};
use jamnp_s::{
    codec::ce131_136::{Ticket, TicketDistribution},
    framing::{frame, CE131, CE132},
    trace::{wall_ts, Direction as TraceDir, Trace},
};
use m2_reference::tickets::{ScheduledTicket, TicketDelivery, TicketFault};
use m2_scenario::ctx::{DeliveredTicket, TICKET_ARRIVAL_LEAD_MS};
use m2_scenario::dsl::{ObsKind, ObsLog};
use m2_scenario::scenarios::obs::{
    EMU_SENT_131, EMU_SENT_132, NUT_SENT_UNDECODABLE, RECV_CE131, RECV_CE132, TICKET_REFUSED,
    TICKET_WITHHELD,
};

use crate::emu::NO_ADVERTISED_FINAL;

/// Seconds per slot (JAM common slot period).
const SLOT_PERIOD_SEC: u64 = 6;

/// Slack on top of [`TICKET_ARRIVAL_LEAD_MS`] when timing a delivery.
///
/// A ticket has to be in the node's hands a clear 2 s before the slot it is
/// expected in. Delivering *at* the slot boundary — which is what the sender
/// used to do — is the one time that can never be true: the node is authoring
/// that same instant, and its next slot is several slots away.
const DELIVERY_MARGIN_MS: u64 = 500;

/// How often the readiness gate re-reads the node's advertised final slot.
///
/// Well under a slot: the gate is usually satisfied within a slot or two of
/// launch, and a coarse poll would spend most of a ticket's delivery window
/// asleep after the node was already ready.
const READINESS_POLL_MS: u64 = 250;

/// An inbound NUT ticket stream, classified by kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketInbound {
    /// A well-formed CE 131 ticket distribution.
    Ce131(TicketDistribution),
    /// A well-formed CE 132 ticket distribution.
    Ce132(TicketDistribution),
    /// Undecodable payload or a kind other than CE 131/132.
    Invalid,
}

/// Classify an inbound CE 131/132 payload as a ticket distribution.
pub fn classify_received(kind: u8, payload: &[u8]) -> TicketInbound {
    let mut input: &[u8] = payload;
    let Ok(distribution) = TicketDistribution::decode(&mut input) else {
        return TicketInbound::Invalid;
    };
    // A well-formed distribution is exactly `u32 ++ u8 ++ [u8; 784]`: any
    // trailing bytes are a malformed "epoch shape".
    if !input.is_empty() {
        return TicketInbound::Invalid;
    }
    match kind {
        CE131 => TicketInbound::Ce131(distribution),
        CE132 => TicketInbound::Ce132(distribution),
        _ => TicketInbound::Invalid,
    }
}

/// Record an inbound NUT ticket stream: `RECV_CE131`/`RECV_CE132` for a
/// decodable distribution, `NUT_SENT_UNDECODABLE` for one that will not
/// decode.
///
/// This is the node's encoding, not its judgement of anything the harness
/// sent. The two shared a code until 2026-11-02, which let an undecodable
/// frame anywhere in a run satisfy a lane check about a refused ticket.
pub async fn handle_inbound_ticket(kind: u8, payload: &[u8], peer: u16, obs: &Mutex<ObsLog>) {
    let recorded = match classify_received(kind, payload) {
        TicketInbound::Ce131(_) => RECV_CE131,
        TicketInbound::Ce132(_) => RECV_CE132,
        TicketInbound::Invalid => NUT_SENT_UNDECODABLE,
    };
    crate::emu::record(obs, peer, ObsKind::Other(recorded));
}

/// Deliver `plan`'s tickets to the NUT over `connection` on their slot
/// boundaries, recording the send and any NUT stream reset.
///
/// A ticket goes out only once the node can act on it; one it cannot is
/// withheld rather than sent into a refusal, and recorded as
/// [`TICKET_WITHHELD`] so the lanes report the rule as unexercised instead of
/// failing the node for it.
pub async fn spawn_ticket_sender(
    connection: quinn::Connection,
    plan: Vec<ScheduledTicket>,
    trace: Arc<Mutex<Trace>>,
    obs: Arc<Mutex<ObsLog>>,
    deliveries: Arc<Mutex<Vec<DeliveredTicket>>>,
    nut_final_slot: Arc<AtomicU32>,
    peer: u16,
) {
    for scheduled in plan {
        let (kind, sent) = match scheduled.delivery {
            TicketDelivery::Ce131 => (CE131, EMU_SENT_131),
            TicketDelivery::Ce132 => (CE132, EMU_SENT_132),
        };
        sleep_until_delivery(scheduled.slot).await;
        if !hold_until_the_node_can_accept(&nut_final_slot, scheduled.target_epoch, scheduled.fault)
            .await
        {
            crate::emu::record(&obs, peer, ObsKind::Other(TICKET_WITHHELD));
            continue;
        }
        let Ok((mut send, mut recv)) = connection.open_bi().await else {
            continue;
        };
        let epoch_index = scheduled.target_epoch;
        let distribution = TicketDistribution {
            epoch_index,
            ticket: Ticket {
                attempt: scheduled.ticket.attempt,
                proof: scheduled.ticket.proof,
            },
        };
        let wire = frame(kind, &distribution.encode());
        crate::emu::trace_record(
            peer,
            kind,
            u64::from(send.id()),
            &wire,
            &trace,
            TraceDir::Rx,
        );
        crate::emu::record(&obs, peer, ObsKind::Other(sent));
        if send.write_all(&wire).await.is_err() {
            continue;
        }
        // Recorded only once the bytes are on the wire, and stamped with the
        // wall clock: the N1 lane compares this against slot starts, which are
        // absolute, so a run-relative timestamp would make every ticket look
        // as though it had arrived before the run began.
        let delivery = {
            let mut recorded = crate::emu::lock(&deliveries);
            recorded.push(DeliveredTicket {
                plan_index: scheduled.plan_index,
                id: scheduled.ticket.id,
                delivered_at_ms: wall_ts(),
                target_epoch: scheduled.target_epoch,
                // Read off the injected fault rather than guessed from the
                // epoch. The guess held only while the unknown-epoch probe
                // was the single ticket a node was meant to reject.
                probe: scheduled.fault.is_some_and(|f| !f.still_owed_inclusion()),
                // Not known until the node answers, below.
                refused: false,
            });
            recorded.len() - 1
        };
        let _ = send.finish();
        // Await the NUT's decision: a clean FIN accepts the ticket; a stream
        // reset rejects it (`:329-337`). Only a reset counts. A connection
        // that died for its own reasons also fails this read, and recording
        // that as a rejection would let a run credit the node with a refusal
        // it never made.
        //
        // The refusal goes on the delivery it answers rather than into the
        // observation log alone. A reset carries no reason, so the log can
        // only say that one happened; which ticket the node refused is a fact
        // only this loop holds, and a lane that has to ask "did *this* ticket
        // get refused" cannot be answered by an unscoped `obs.first`. The
        // code recorded alongside is for the report and the trace.
        let mut buf = [0u8; 1024];
        if let Err(quinn::ReadError::Reset(_)) = recv.read(&mut buf).await {
            crate::emu::lock(&deliveries)[delivery].refused = true;
            crate::emu::record(&obs, peer, ObsKind::Other(TICKET_REFUSED));
        }
    }
}

/// Whether the NUT is in a state to accept a ticket at all.
///
/// A node validates an incoming ticket against finalized state, so one whose
/// finalized head is still behind the current epoch refuses every ticket it is
/// offered. polkajam says so outright — `ticket_preflight`
/// (`chain/authoring/ticket_communication.rs`) returns `FinalityLagging` when
/// `final_slot / epoch_period < curr_slot / epoch_period` — and any client
/// that checks a ring proof against finalized state has the same gap.
///
/// It is the normal state for a second or two after the harness seeds a chain
/// the node has to import, which is exactly when the first tickets used to go
/// out. The node refused all of them and the lanes then graded it for not
/// forwarding or including them: two hard failures per run, both the harness's.
///
/// The test is on the *epoch*, not on the seeded head: finality trails the
/// chain head by a slot or two indefinitely, so waiting for the node's
/// finalized head to reach the head we seeded can wait for something that will
/// not happen, while the node has long since been able to accept tickets.
pub fn node_can_accept_tickets(nut_final_slot: u32, now_slot: u32) -> bool {
    let period = jam_types::epoch_period();
    nut_final_slot != NO_ADVERTISED_FINAL && nut_final_slot / period >= now_slot / period
}

/// Whether a ticket is still worth putting on the wire at `now_slot`.
///
/// Holding a ticket is only ever worth doing inside the window where the node
/// could still act on it. Past the lottery's last submittable phase nothing may
/// be submitted at all, and a ticket whose target epoch is no longer the next
/// one is stale — the node is obliged to refuse both, so sending them
/// manufactures the same false failure the gate exists to prevent.
///
/// The unknown-epoch probe (`simple.md:335-337`) names a far epoch on purpose,
/// so it is exempt from the staleness test; it is the one ticket whose refusal
/// is the point.
fn still_worth_sending(now_slot: u32, target_epoch: u32, fault: Option<TicketFault>) -> bool {
    // A fault goes out whatever the clock says. Half the catalogue is itself
    // a statement about timing or epoch -- `Late` is *defined* by arriving
    // after the window shuts, `StaleEpoch` and `UnknownEpoch` by naming an
    // epoch the window does not belong to -- so a gate that withheld anything
    // out of season would suppress exactly the deliveries it was given to
    // make. The readiness test still applies: the node must be in a state to
    // process the stimulus, or its answer says nothing about the rule.
    if fault.is_some() {
        return true;
    }
    let period = jam_types::epoch_period();
    // Before the lottery's last submittable phase, and still in the epoch
    // this ticket may be submitted during. Either alone is not enough: the
    // phase test says nothing about which epoch the phase belongs to.
    now_slot % period < jam_types::epoch_tail_start().saturating_sub(1)
        && now_slot / period + 1 == target_epoch
}

/// Hold a ticket until the node can accept it, or until it is no longer worth
/// sending. `true` when it should go out now.
async fn hold_until_the_node_can_accept(
    nut_final_slot: &AtomicU32,
    target_epoch: u32,
    fault: Option<TicketFault>,
) -> bool {
    loop {
        let now_slot = m2_reference::chain::wall_clock_slot();
        // Asked before readiness, not after: a node that became ready only
        // once the window had shut would otherwise be sent a ticket it is
        // required to refuse.
        if !still_worth_sending(now_slot, target_epoch, fault) {
            return false;
        }
        if node_can_accept_tickets(nut_final_slot.load(Ordering::SeqCst), now_slot) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(READINESS_POLL_MS)).await;
    }
}

/// When a ticket due in `slot` must be on the wire.
fn delivery_deadline_ms(slot: u32) -> u64 {
    let slot_start_ms = (JAM_COMMON_ERA + u64::from(slot) * SLOT_PERIOD_SEC) * 1000;
    slot_start_ms.saturating_sub(TICKET_ARRIVAL_LEAD_MS + DELIVERY_MARGIN_MS)
}

/// Wait until a ticket due in `slot` should go out: far enough before the slot
/// starts that the node has it in hand with the full arrival lead to spare.
async fn sleep_until_delivery(slot: u32) {
    let target_ms = delivery_deadline_ms(slot);
    loop {
        let now = wall_ts();
        if now >= target_ms {
            return;
        }
        tokio::time::sleep(Duration::from_millis(target_ms - now)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jam_types::Encode;
    use jamnp_s::codec::ce131_136::{Ticket, TicketDistribution};
    use jamnp_s::framing::{CE129, CE131, CE132};
    use m2_scenario::dsl::ObsLog;
    use m2_scenario::scenarios::obs;

    fn td(epoch: u32, attempt: u8, seed: u8) -> TicketDistribution {
        TicketDistribution {
            epoch_index: epoch,
            ticket: Ticket {
                attempt,
                proof: core::array::from_fn(|i| (i as u8).wrapping_add(seed)),
            },
        }
    }

    mod m2_emu_classify {
        use super::*;

        #[test]
        fn classify_ce131_ce132_roundtrip() {
            let t = td(7, 1, 3);
            let payload = t.encode();
            assert_eq!(classify_received(CE131, &payload), TicketInbound::Ce131(t));
            assert_eq!(classify_received(CE132, &payload), TicketInbound::Ce132(t));
            assert_eq!(
                classify_received(CE131, &[0xde, 0xad]),
                TicketInbound::Invalid
            );
            assert_eq!(classify_received(CE132, &[]), TicketInbound::Invalid);
        }
    }

    mod m2_emu_classify_invalid {
        use super::*;

        #[test]
        fn classify_invalid_epoch_marker() {
            // Epoch index + attempt + a truncated proof.
            let mut bad = vec![0u8; 4];
            bad.extend_from_slice(&[0u8; 10]);
            assert_eq!(classify_received(CE131, &bad), TicketInbound::Invalid);
            // Trailing bytes after a well-formed distribution are invalid too.
            let mut extra = td(1, 0, 0).encode();
            extra.push(0xff);
            assert_eq!(classify_received(CE132, &extra), TicketInbound::Invalid);
            // An otherwise-valid payload under a non-ticket kind is invalid.
            let valid = td(1, 0, 0).encode();
            assert_eq!(classify_received(CE129, &valid), TicketInbound::Invalid);
        }
    }

    mod m2_emu_plan_peer {
        use super::*;

        /// A ticket goes out well before the slot it is expected in, not at
        /// the slot boundary: the node needs it in hand a clear
        /// `TICKET_ARRIVAL_LEAD_MS` beforehand, and at the boundary itself it
        /// is already authoring.
        #[test]
        fn delivery_leads_the_slot_it_is_expected_in() {
            let slot = 1000u32;
            let slot_start_ms = (JAM_COMMON_ERA + u64::from(slot) * SLOT_PERIOD_SEC) * 1000;
            let target = delivery_deadline_ms(slot);
            assert!(
                slot_start_ms - target >= TICKET_ARRIVAL_LEAD_MS,
                "delivery must clear the arrival lead"
            );
            assert_eq!(
                target,
                slot_start_ms - TICKET_ARRIVAL_LEAD_MS - DELIVERY_MARGIN_MS
            );
        }
    }

    mod m2_emu_readiness_gate {
        use super::*;

        /// Epoch-relative so the test holds under any parameter set: these
        /// are process-wide and whichever test ran first decides them.
        fn slot_in(epoch: u32, phase: u32) -> u32 {
            epoch * jam_types::epoch_period() + phase
        }

        /// The shape of the failure this gate exists for. The node had
        /// finalized slot 9574199 while the clock was at 9574201 — two slots
        /// apart, with an epoch boundary between them — refused all four
        /// tickets with `finality lagging`, and was then graded for not
        /// forwarding or including them.
        #[test]
        fn a_node_whose_finality_is_an_epoch_behind_is_not_ready() {
            let now = slot_in(100, 1);
            let lagging = slot_in(99, jam_types::epoch_period() - 1);
            assert!(
                !node_can_accept_tickets(lagging, now),
                "a finalized head in the previous epoch cannot accept tickets"
            );
            assert!(
                node_can_accept_tickets(slot_in(100, 0), now),
                "a finalized head in the current epoch can"
            );
        }

        /// Before the node has said anything, the harness knows nothing about
        /// its progress — which is not the same as knowing it is ready.
        #[test]
        fn a_silent_node_is_not_ready() {
            assert!(!node_can_accept_tickets(
                NO_ADVERTISED_FINAL,
                slot_in(100, 1)
            ));
        }

        /// Holding a ticket is only worth doing while the node could still
        /// act on it; past that, sending manufactures the refusal the gate
        /// exists to avoid.
        #[test]
        fn a_ticket_is_held_only_while_it_could_still_be_submitted() {
            let target = 101;
            assert!(
                still_worth_sending(slot_in(100, 1), target, None),
                "early in the submission epoch"
            );
            assert!(
                !still_worth_sending(
                    slot_in(100, jam_types::epoch_tail_start() - 1),
                    target,
                    None
                ),
                "the lottery's last submittable phase has passed"
            );
            assert!(
                !still_worth_sending(slot_in(101, 1), target, None),
                "the target epoch has begun, so the ticket is stale"
            );
        }

        /// A fault is sent whatever the clock says. Being out of season is
        /// the stimulus for half the catalogue, so the gate that protects
        /// honest tickets must not suppress them.
        #[test]
        fn a_fault_is_never_held_back_for_being_out_of_season() {
            let target = 101;
            for fault in [
                TicketFault::Late,
                TicketFault::StaleEpoch,
                TicketFault::UnknownEpoch,
                TicketFault::BadProof,
                TicketFault::WrongProxy,
                TicketFault::BadAttempt,
                TicketFault::Duplicate,
            ] {
                assert!(
                    still_worth_sending(
                        slot_in(100, jam_types::epoch_tail_start()),
                        target,
                        Some(fault)
                    ),
                    "{fault:?} must still go out after the window shuts"
                );
                assert!(
                    still_worth_sending(slot_in(101, 1), target, Some(fault)),
                    "{fault:?} must still go out once the target epoch has begun"
                );
            }
        }

        /// The unknown-epoch probe names an epoch no validator can hold
        /// entropy for, on purpose. Judging it stale would withhold the one
        /// A fault naming an epoch outside the window is not "stale": the
        /// epoch it names is the stimulus.
        ///
        /// It is exempt from the lottery window too. A fault delivered in the
        /// tail may be refused for lateness rather than for its own defect,
        /// but the verdicts assert only that the node refused it, so the two
        /// reasons are not told apart and nothing is confounded. The honest
        /// deliveries keep both guards.
        #[test]
        fn a_fault_naming_another_epoch_is_not_stale() {
            let target = 101;
            assert!(still_worth_sending(
                slot_in(100, 1),
                target + 1,
                Some(TicketFault::UnknownEpoch)
            ));
            assert!(
                still_worth_sending(
                    slot_in(100, jam_types::epoch_tail_start()),
                    target + 1,
                    Some(TicketFault::UnknownEpoch)
                ),
                "and is not bound by the window an honest ticket is"
            );
            assert!(
                !still_worth_sending(slot_in(100, 1), target + 1, None),
                "an honest ticket for another epoch is still stale"
            );
        }
    }

    mod m2_emu_inbound_obs {
        use super::*;

        #[tokio::test]
        async fn inbound_records_obs() {
            let obs = Mutex::new(ObsLog::new());
            let payload = td(3, 0, 0).encode();
            handle_inbound_ticket(CE131, &payload, 1, &obs).await;
            assert!(
                obs.lock()
                    .unwrap()
                    .first(ObsKind::Other(obs::RECV_CE131))
                    .is_some(),
                "a CE 131 distribution must record RECV_CE131"
            );

            let obs = Mutex::new(ObsLog::new());
            handle_inbound_ticket(CE132, &payload, 1, &obs).await;
            assert!(
                obs.lock()
                    .unwrap()
                    .first(ObsKind::Other(obs::RECV_CE132))
                    .is_some(),
                "a CE 132 distribution must record RECV_CE132"
            );

            let obs = Mutex::new(ObsLog::new());
            handle_inbound_ticket(CE131, &[0xde, 0xad], 1, &obs).await;
            assert!(
                obs.lock()
                    .unwrap()
                    .first(ObsKind::Other(obs::NUT_SENT_UNDECODABLE))
                    .is_some(),
                "an undecodable stream is the node's encoding defect, and must \
                 record NUT_SENT_UNDECODABLE rather than a refusal"
            );
            assert!(
                obs.lock()
                    .unwrap()
                    .first(ObsKind::Other(obs::TICKET_REFUSED))
                    .is_none(),
                "and must not look like the node refusing a ticket we sent"
            );
        }
    }
}
