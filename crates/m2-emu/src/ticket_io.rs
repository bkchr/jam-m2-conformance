//! L2 Safrole-ticket I/O for the emulated validators (CE 131/132).
//!
//! Inbound: the NUT's ticket streams (`TicketDistribution`, `simple.md:305-349`)
//! are classified by kind and recorded as observations; an undecodable stream
//! is treated as a bad-proof signal (soft) — the NUT is the sender, so the
//! emulator never resets the stream. Outbound: `spawn_ticket_sender` delivers
//! the runner-computed plan's tickets to the NUT on their slot boundaries.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use jam_types::{Decode, Encode, JAM_COMMON_ERA};
use jamnp_s::{
    codec::ce131_136::{Ticket, TicketDistribution},
    framing::{frame, CE131, CE132},
    trace::{wall_ts, Direction as TraceDir, Trace},
};
use m2_reference::tickets::{ScheduledTicket, TicketDelivery};
use m2_scenario::dsl::{ObsKind, ObsLog};
use m2_scenario::scenarios::obs::{
    BAD_PROOF_IGNORED, EMU_SENT_131, EMU_SENT_132, RECV_CE131, RECV_CE132, UNKNOWN_EPOCH_RESET,
};

/// Seconds per slot (JAM common slot period).
const SLOT_PERIOD_SEC: u64 = 6;

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

/// Which observation a NUT stream reset maps to: a ticket targeted at a
/// different epoch than the plan's is the unknown-epoch probe (`:335-337`);
/// any other rejected ticket is a bad proof (`:329-332`).
fn reset_obs(epoch_index: u32, plan_epoch: u32) -> ObsKind {
    if epoch_index == plan_epoch {
        ObsKind::Other(BAD_PROOF_IGNORED)
    } else {
        ObsKind::Other(UNKNOWN_EPOCH_RESET)
    }
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

/// Filter a plan down to the tickets authored by `peer_author`.
pub fn plan_for_peer(plan: &[ScheduledTicket], peer_author: usize) -> Vec<ScheduledTicket> {
    plan.iter()
        .filter(|scheduled| scheduled.ticket.author == peer_author)
        .cloned()
        .collect()
}

/// Record an inbound NUT ticket stream: `RECV_CE131`/`RECV_CE132` for a
/// decodable distribution, `BAD_PROOF_IGNORED` (soft) for an invalid one.
pub async fn handle_inbound_ticket(kind: u8, payload: &[u8], peer: u16, obs: &Mutex<ObsLog>) {
    let recorded = match classify_received(kind, payload) {
        TicketInbound::Ce131(_) => RECV_CE131,
        TicketInbound::Ce132(_) => RECV_CE132,
        TicketInbound::Invalid => BAD_PROOF_IGNORED,
    };
    crate::emu::record(obs, peer, ObsKind::Other(recorded));
}

/// Deliver `plan`'s tickets to the NUT over `connection` on their slot
/// boundaries, recording the send and any NUT stream reset.
pub async fn spawn_ticket_sender(
    connection: quinn::Connection,
    plan: Vec<ScheduledTicket>,
    trace: Arc<Mutex<Trace>>,
    obs: Arc<Mutex<ObsLog>>,
    peer: u16,
) {
    let Some(first) = plan.first() else {
        return;
    };
    let plan_epoch = first.target_epoch;
    for scheduled in plan {
        let (kind, sent) = match scheduled.delivery {
            TicketDelivery::Ce131 => (CE131, EMU_SENT_131),
            TicketDelivery::Ce132 => (CE132, EMU_SENT_132),
        };
        sleep_until_slot(scheduled.slot).await;
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
        let _ = send.finish();
        // Await the NUT's decision: a clean FIN accepts the ticket; a stream
        // reset rejects it (unknown epoch `:335-337` or bad proof `:329-332`).
        let mut buf = [0u8; 1024];
        if recv.read(&mut buf).await.is_err() {
            crate::emu::record(&obs, peer, reset_obs(epoch_index, plan_epoch));
        }
    }
}

async fn sleep_until_slot(slot: u32) {
    let target_ms = (JAM_COMMON_ERA + u64::from(slot) * SLOT_PERIOD_SEC) * 1000;
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
    use m2_reference::tickets::EmulatedTicket;
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

        fn scheduled(author: usize, attempt: u8) -> ScheduledTicket {
            ScheduledTicket {
                target_epoch: 9,
                ticket: EmulatedTicket {
                    id: [attempt; 32],
                    author,
                    attempt,
                    proof: [0u8; 784],
                    proxy: 0,
                },
                delivery: TicketDelivery::Ce132,
                slot: 100,
            }
        }

        #[test]
        fn plan_for_peer_filters_by_author() {
            let plan = vec![scheduled(1, 0), scheduled(2, 1), scheduled(3, 2)];
            let for_2 = plan_for_peer(&plan, 2);
            assert_eq!(for_2.len(), 1);
            assert_eq!(for_2[0].ticket.author, 2);
            assert_eq!(for_2[0].ticket.attempt, 1);
            assert!(plan_for_peer(&plan, 9).is_empty());
            // The input plan is untouched.
            assert_eq!(plan.len(), 3);
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
                    .first(ObsKind::Other(obs::BAD_PROOF_IGNORED))
                    .is_some(),
                "an undecodable stream must record BAD_PROOF_IGNORED"
            );
        }
    }
}
