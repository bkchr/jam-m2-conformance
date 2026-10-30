//! Real-run N1/N2 context builders (m2-runner §4.4): reference-chain facts,
//! NUT-block imports, and ticket deliveries for the N1/N2 scenario lanes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use codec::Decode;
use jamnp_s::codec::ce131_136::TicketDistribution;
use jamnp_s::framing::{CE131, CE132};
use jamnp_s::trace::{Direction as TraceDir, Trace};
use m2_reference::chain::RefChain;
use m2_reference::tickets::{
    first_delivery_slot, plan_tickets, verify_ticket, EmulatedTicket, ScheduledTicket, TicketCtx,
    TicketDelivery as ReferenceDelivery,
};
use m2_scenario::ctx::{
    DeliveredTicket, EmuTicket, ImportFact, N1Ctx, N2Ctx, NutBlock, NutTicketFacts,
    TicketDelivery as CtxDelivery, SLOT_PERIOD_MS,
};

use crate::scenario::RunCtx;

/// Reference-side facts the N1/N2 context builders read after the observation
/// window: the reference chain, the fetched NUT blocks, and the N2 ticket plan.
pub(crate) struct RealRunData {
    pub(crate) ref_chain: Arc<RefChain>,
    pub(crate) nut_blocks: Arc<Mutex<Vec<NutBlock>>>,
    pub(crate) deliveries: Arc<Mutex<Vec<DeliveredTicket>>>,
    pub(crate) ticket_ctx: TicketCtx,
    pub(crate) plan: Vec<ScheduledTicket>,
    pub(crate) target_epoch: u32,
    pub(crate) nut_index: usize,
    pub(crate) emu_indices: Vec<usize>,
    pub(crate) epoch_contexts: EpochContexts,
}

/// Ticket contexts the slot driver captured, one per epoch the run crossed,
/// keyed by the epoch whose tickets each one seals.
pub(crate) type EpochContexts = Arc<Mutex<Vec<(u32, TicketCtx)>>>;

/// The emulated validators' tickets for the epoch after the current one.
///
/// Ring-VRF proving is the single most expensive thing the harness does —
/// five authors times four attempts, tens of seconds — so it is split from
/// [`schedule_tickets`] and run while the node is still starting up.
///
/// The tickets are bound to the tickets-entropy *of the chain as it stands
/// when this is called*, so the caller must have the reference chain seeded
/// up to the current slot first, and `target_epoch` is the epoch that
/// entropy seals. Proving that is overtaken by an epoch boundary leaves
/// tickets whose submission window has already closed; relabelling them for
/// the new epoch would be a lie, since they were never built against its
/// entropy, so the caller regenerates instead (`plan_tickets_for_this_run`).
pub(crate) fn generate_tickets(
    ref_chain: &RefChain,
) -> Result<(TicketCtx, Vec<EmulatedTicket>, u32), m2_reference::chain::ChainError> {
    let ticket_ctx = ref_chain.ticket_ctx()?;
    let target_epoch = ref_chain.next_slot() / jam_types::epoch_period() + 1;
    let tickets = ref_chain.generate_tickets(&ticket_ctx)?;
    Ok((ticket_ctx, tickets, target_epoch))
}

/// Schedule the generated tickets into the submission window still open for
/// `target_epoch`, as of now.
///
/// Empty when that window has already closed — see
/// [`m2_reference::tickets::plan_tickets`].
pub(crate) fn schedule_tickets(
    ref_chain: &RefChain,
    tickets: &[EmulatedTicket],
    nut_index: usize,
    target_epoch: u32,
) -> Vec<ScheduledTicket> {
    let now_slot = ref_chain.next_slot();
    plan_tickets(
        tickets,
        nut_index,
        first_delivery_slot(now_slot),
        target_epoch,
    )
}

/// The ticket plan split per emulated validator, keyed by peer index, each
/// peer's tickets in the order they are to be delivered.
///
/// The sort is not cosmetic. A peer's sender walks its plan one entry at a
/// time, sleeping until each ticket's slot, so a ticket listed before one
/// scheduled earlier holds that earlier one back. The plan is built in ticket
/// order, and a peer's CE 132 slot is spread by author index while its CE 131
/// slot is the window's first — so for every author but the first, the ticket
/// proxied to the NUT sat behind a broadcast scheduled several slots later and
/// arrived that late. Observed: authors 0, 3 and 4 delivering their CE 131
/// tickets in epoch phases 3, 6 and 7 against a plan that said 3 for all of
/// them, which put them past the window any proxy could still forward in.
pub(crate) fn plans_by_peer(plan: &[ScheduledTicket]) -> HashMap<u16, Vec<ScheduledTicket>> {
    let mut plans: HashMap<u16, Vec<ScheduledTicket>> = HashMap::new();
    for scheduled in plan {
        plans
            .entry(scheduled.ticket.author as u16)
            .or_default()
            .push(scheduled.clone());
    }
    for peer_plan in plans.values_mut() {
        peer_plan.sort_by_key(|s| s.slot);
    }
    plans
}

/// Build the N1/N2 contexts for a real run from the post-window facts.
pub(crate) fn build_real_run_ctx(
    data: &RealRunData,
    trace: &Trace,
    n0: m2_scenario::scenarios::n0::N0Ctx,
) -> RunCtx {
    let nut_blocks = lock(&data.nut_blocks);
    let contexts = ticket_contexts(data);
    let nut_tickets = collect_nut_tickets(trace, &contexts);
    // Every ticket the node announced is one it legitimately held, whether it
    // ran the lottery for it or is forwarding it as proxy. Both lanes need
    // this to tell "the node invented a ticket" from "the node is a validator".
    let own_ticket_ids: Vec<[u8; 32]> = nut_tickets
        .iter()
        .map(|f| m2_reference::tickets::ticket_id(&f.ticket.proof))
        .collect();
    let n1 = build_n1_ctx(
        &data.ref_chain,
        &nut_blocks,
        &lock(&data.deliveries),
        own_ticket_ids.clone(),
    );
    let n2 = build_n2_ctx(&contexts, data, nut_tickets, &nut_blocks, own_ticket_ids);
    RunCtx {
        n0,
        n1: Some(n1),
        n2: Some(n2),
    }
}

/// Every ticket context the harness can verify a proof against, by the epoch
/// whose tickets it seals.
///
/// A ring-VRF ticket proof is bound to the tickets-entropy of the epoch it
/// targets, so one context judges one epoch, and the entropy for epoch
/// `e + 1` can only be read while the chain is in epoch `e`. A run spans
/// several epochs and the node generates afresh in each, so one context is
/// never enough: the set is the one the harness generated its own tickets
/// against, plus the one the slot driver captured on each boundary it
/// crossed, plus a last read now. An epoch missing from the set is a ticket
/// the lane reports as unjudged rather than as unverified.
fn ticket_contexts(data: &RealRunData) -> TicketContexts {
    let mut by_epoch = vec![(data.target_epoch, data.ticket_ctx.clone())];
    by_epoch.extend(lock(&data.epoch_contexts).iter().cloned());
    let late_epoch = data.ref_chain.next_slot() / jam_types::epoch_period() + 1;
    if let Ok(late) = data.ref_chain.ticket_ctx() {
        by_epoch.push((late_epoch, late));
    }
    // First entry per epoch wins, and the generation-time context leads, so a
    // later read never displaces the one the emulator's own tickets were
    // built against.
    let mut seen = Vec::new();
    by_epoch.retain(|(epoch, _)| {
        let fresh = !seen.contains(epoch);
        seen.push(*epoch);
        fresh
    });
    TicketContexts { by_epoch }
}

/// The ticket contexts a run can verify proofs against, keyed by target epoch.
pub(crate) struct TicketContexts {
    by_epoch: Vec<(u32, TicketCtx)>,
}

impl TicketContexts {
    /// Whether a ticket for `epoch` verifies, or `None` when no context
    /// covers that epoch — which is not the same answer as "it did not
    /// verify", and the lane keeps the two apart.
    fn verify(&self, epoch: u32, attempt: u8, proof: &[u8; 784]) -> Option<bool> {
        let (_, ctx) = self.by_epoch.iter().find(|(e, _)| *e == epoch)?;
        Some(verify_ticket(ctx, attempt, proof))
    }

    /// The context the emulator's own tickets were generated against.
    fn planned(&self) -> &TicketCtx {
        &self.by_epoch[0].1
    }
}

/// N1 facts: the reference chain with its slots, the fetched NUT blocks with
/// their import outcomes, and the tickets the emulator delivered to the NUT.
///
/// The chain is read before the imports run, so the reference best block is
/// the one the run actually ended on and not one re-imported here.
fn build_n1_ctx(
    ref_chain: &RefChain,
    nut_blocks: &[NutBlock],
    deliveries: &[DeliveredTicket],
    own_ticket_ids: Vec<[u8; 32]>,
) -> N1Ctx {
    let chain = ref_chain.chain_blocks();
    let reference_best = chain
        .last()
        .map(|block| block.header.hash().0)
        .unwrap_or_else(|| ref_chain.genesis_hash());
    let reference_block_hashes: Vec<[u8; 32]> =
        chain.iter().map(|block| block.header.hash().0).collect();
    let reference_chain = chain
        .iter()
        .map(|block| (block.header.slot, block.header.hash().0))
        .collect();
    let imports = nut_blocks
        .iter()
        .map(|nut| {
            let outcome = ref_chain.import_nut_block(&nut.block);
            ImportFact {
                header_root: outcome.header_root,
                parent: outcome.parent,
                declared_parent_root: outcome.declared_parent_root,
                reference_parent_root: outcome.reference_parent_root,
                ok: outcome.ok,
                root: outcome.root,
                error: outcome.error,
            }
        })
        .collect();
    N1Ctx {
        reference_best,
        reference_block_hashes,
        reference_chain,
        nut_blocks: nut_blocks.to_vec(),
        imports,
        delivered_tickets: deliveries.to_vec(),
        own_ticket_ids,
        slot_period_ms: SLOT_PERIOD_MS,
        epoch_period: jam_types::epoch_period(),
        epoch_tail_start: jam_types::epoch_tail_start(),
        max_tickets_per_block: jam_types::max_tickets_per_block(),
    }
}

/// N2 facts: the emulator's ticket plan plus every ticket the NUT distributed
/// back (CE 131/132 frames), and the NUT-authored block's ticket extrinsic.
fn build_n2_ctx(
    contexts: &TicketContexts,
    data: &RealRunData,
    nut_tickets: Vec<NutTicketFacts>,
    nut_blocks: &[NutBlock],
    own_ticket_ids: Vec<[u8; 32]>,
) -> N2Ctx {
    let target_epoch = data.target_epoch;
    let epoch_start_slot = target_epoch * jam_types::epoch_period();
    // Tickets for `target_epoch` can only be submitted during the epoch before
    // it, so the block to judge is one authored in *that* epoch. Taking simply
    // the newest block judged a block from a later epoch against tickets it
    // could not legally have carried -- a check no node could pass once a run
    // outlived the epoch it generated for.
    let submission_epoch = target_epoch.saturating_sub(1);
    let (nut_block_ticket_ids, nut_block_slot) = nut_blocks
        .iter()
        .filter(|nut| nut.block.header.slot / jam_types::epoch_period() == submission_epoch)
        .max_by_key(|nut| nut.block.header.slot)
        .map(|nut| {
            let ids = nut
                .block
                .extrinsic
                .tickets
                .iter()
                .map(|t| t.id().0)
                .collect();
            (ids, Some(nut.block.header.slot))
        })
        .unwrap_or_default();
    N2Ctx {
        target_epoch,
        epoch_start_slot,
        emu_plan: plan_emu_tickets(&data.plan, contexts.planned(), &lock(&data.deliveries)),
        nut_tickets,
        nut_block_ticket_ids,
        own_ticket_ids,
        nut_block_slot,
        nut_index: data.nut_index as u16,
        emulated_peers: data.emu_indices.iter().map(|&i| i as u16).collect(),
        slot_period_ms: SLOT_PERIOD_MS,
        epoch_period: jam_types::epoch_period(),
        epoch_tail_start: jam_types::epoch_tail_start(),
        tickets_per_validator: jam_types::tickets_per_validator(jam_types::max_val_count()),
        max_tickets_per_block: jam_types::max_tickets_per_block(),
    }
}

/// Map the reference ticket plan onto the N2 lane's [`EmuTicket`] facts.
///
/// `deliveries` is what the emulator actually put on the wire, which is a
/// subset of the plan: the sender withholds a ticket the node is in no state
/// to accept, and a connection can die mid-run. The lane needs the difference,
/// because a rule about a ticket the NUT never received was not exercised
/// rather than broken.
fn plan_emu_tickets(
    plan: &[ScheduledTicket],
    ticket_ctx: &TicketCtx,
    deliveries: &[DeliveredTicket],
) -> Vec<EmuTicket> {
    plan.iter()
        .map(|scheduled| {
            let ticket = &scheduled.ticket;
            EmuTicket {
                // Keyed on the epoch as well as the id: the unknown-epoch
                // probe reuses a real ticket's proof, so the two entries share
                // an id and differ only in the epoch they name. Matching on
                // the id alone marked the probe delivered whenever the ticket
                // it borrowed from was.
                delivered_at_ms: deliveries
                    .iter()
                    .find(|d| d.id == ticket.id && d.target_epoch == scheduled.target_epoch)
                    .map(|d| d.delivered_at_ms),
                id: ticket.id,
                author: ticket.author as u16,
                attempt: ticket.attempt,
                proof: ticket.proof,
                proxy: ticket.proxy as u16,
                valid: verify_ticket(ticket_ctx, ticket.attempt, &ticket.proof),
                delivery: match scheduled.delivery {
                    ReferenceDelivery::Ce131 => CtxDelivery::Ce131,
                    ReferenceDelivery::Ce132 => CtxDelivery::Ce132,
                },
                slot: scheduled.slot,
                target_epoch: scheduled.target_epoch,
            }
        })
        .collect()
}

/// Every ticket the NUT distributed to the emulators (CE 131/132 frames the
/// NUT sent), verified against the reference ticket context.
fn collect_nut_tickets(trace: &Trace, contexts: &TicketContexts) -> Vec<NutTicketFacts> {
    trace
        .records()
        .iter()
        .filter(|rec| rec.direction == TraceDir::Tx && matches!(rec.stream_kind, CE131 | CE132))
        .filter_map(|rec| {
            let Ok(distribution) = TicketDistribution::decode(&mut &rec.bytes[..]) else {
                return None;
            };
            let ticket = distribution.ticket;
            let epoch = distribution.epoch_index;
            Some(NutTicketFacts {
                epoch,
                ticket,
                peer: rec.peer_index,
                // The stream kind the node chose, not a guess from the peer
                // it reached: CE 131 names a proxy, CE 132 names everyone.
                delivery: match rec.stream_kind {
                    CE131 => CtxDelivery::Ce131,
                    _ => CtxDelivery::Ce132,
                },
                verified: contexts.verify(epoch, ticket.attempt, &ticket.proof),
                received_at_ms: rec.wall_ts,
            })
        })
        .collect()
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::Encode;
    use jamnp_s::codec::ce131_136::Ticket;
    use jamnp_s::trace::TraceRecord;
    use m2_reference::chain::ChainError;

    /// The ticket contexts a test run holds: one, covering `epoch`.
    fn contexts_for(epoch: u32, ctx: TicketCtx) -> TicketContexts {
        TicketContexts {
            by_epoch: vec![(epoch, ctx)],
        }
    }

    fn record(
        direction: TraceDir,
        peer: u16,
        kind: u8,
        bytes: Vec<u8>,
        wall_ts: u64,
    ) -> TraceRecord {
        TraceRecord {
            direction,
            peer_index: peer,
            stream_kind: kind,
            stream_id: 0,
            mono_ts: 0,
            wall_ts,
            bytes,
        }
    }

    #[test]
    fn run_collect_nut_tickets() -> Result<(), ChainError> {
        let ref_chain = RefChain::tiny(0)?;
        let ticket_ctx = ref_chain.ticket_ctx()?;
        let tickets = ref_chain.generate_tickets(&ticket_ctx)?;
        let ticket = &tickets[0];
        let distribution = TicketDistribution {
            epoch_index: 7,
            ticket: Ticket {
                attempt: ticket.attempt,
                proof: ticket.proof,
            },
        };

        let mut trace = Trace::default();
        trace.push(record(TraceDir::Tx, 2, CE131, distribution.encode(), 1234));
        let contexts = contexts_for(7, ticket_ctx);
        let facts = collect_nut_tickets(&trace, &contexts);
        assert_eq!(
            facts.len(),
            1,
            "one NUT CE 131 distribution yields one fact"
        );
        assert_eq!(facts[0].epoch, 7);
        assert_eq!(facts[0].peer, 2);
        assert_eq!(facts[0].ticket.attempt, ticket.attempt);
        assert_eq!(facts[0].received_at_ms, 1234);
        assert_eq!(facts[0].delivery, CtxDelivery::Ce131);
        assert_eq!(
            facts[0].verified,
            Some(true),
            "a generated ticket verifies against its own epoch's context"
        );

        // A non-decodable CE 131 frame from the NUT is skipped, not a fact.
        let mut bad = Trace::default();
        bad.push(record(TraceDir::Tx, 2, CE131, vec![0xde, 0xad], 1));
        assert!(
            collect_nut_tickets(&bad, &contexts).is_empty(),
            "garbage CE 131 is skipped"
        );
        Ok(())
    }

    /// A proof is bound to the entropy of the epoch it targets, so a ticket
    /// for an epoch the harness holds no context for cannot be judged at all.
    /// Verifying it against the wrong epoch's ring would report a conforming
    /// node's ticket as a forged one.
    #[test]
    fn run_nut_tickets_for_an_uncovered_epoch_are_unjudged() -> Result<(), ChainError> {
        let ref_chain = RefChain::tiny(0)?;
        let ticket_ctx = ref_chain.ticket_ctx()?;
        let tickets = ref_chain.generate_tickets(&ticket_ctx)?;
        let ticket = &tickets[0];
        let distribution = TicketDistribution {
            epoch_index: 9,
            ticket: Ticket {
                attempt: ticket.attempt,
                proof: ticket.proof,
            },
        };
        let mut trace = Trace::default();
        trace.push(record(TraceDir::Tx, 2, CE132, distribution.encode(), 1));
        let facts = collect_nut_tickets(&trace, &contexts_for(7, ticket_ctx));
        assert_eq!(facts[0].verified, None, "epoch 9 has no context");
        assert_eq!(facts[0].delivery, CtxDelivery::Ce132);
        Ok(())
    }

    /// Trace convention (`jamnp_s::trace::Direction`): `Tx` is NUT → peer,
    /// `Rx` is peer → NUT. N2 judges the NUT, so tickets the emulator itself
    /// sent (`Rx`) must never be counted as NUT behaviour.
    #[test]
    fn run_collect_nut_tickets_ignores_harness_sent_frames() -> Result<(), ChainError> {
        let ref_chain = RefChain::tiny(0)?;
        let ticket_ctx = ref_chain.ticket_ctx()?;
        let tickets = ref_chain.generate_tickets(&ticket_ctx)?;
        let nut_ticket = &tickets[0];
        let emu_ticket = &tickets[1];
        let distribution = |t: &m2_reference::tickets::EmulatedTicket, epoch| TicketDistribution {
            epoch_index: epoch,
            ticket: Ticket {
                attempt: t.attempt,
                proof: t.proof,
            },
        };

        let mut trace = Trace::default();
        trace.push(record(
            TraceDir::Tx,
            2,
            CE131,
            distribution(nut_ticket, 7).encode(),
            1234,
        ));
        trace.push(record(
            TraceDir::Rx,
            3,
            CE132,
            distribution(emu_ticket, 7).encode(),
            2345,
        ));

        let facts = collect_nut_tickets(&trace, &contexts_for(7, ticket_ctx));

        assert_eq!(
            facts.len(),
            1,
            "only the NUT-sent (Tx) ticket is a NUT fact; the harness-sent \
             (Rx) ticket must be ignored"
        );
        assert_eq!(facts[0].peer, 2);
        assert_eq!(facts[0].received_at_ms, 1234);
        Ok(())
    }

    #[test]
    fn run_build_n1_from_nut_blocks() -> Result<(), ChainError> {
        let ref_chain = RefChain::tiny(0)?;
        let start = ref_chain.next_slot();
        let mut authored = None;
        for slot in start..start + 12 {
            if let Some(block) = ref_chain.author_block(slot)? {
                authored = Some(block);
                break;
            }
        }
        let block =
            authored.ok_or_else(|| ChainError::Chain("no emulated slot in 12 slots".into()))?;
        let nut_blocks = vec![NutBlock {
            block: block.clone(),
            announced_wall_ms: 1000,
        }];
        let n1 = build_n1_ctx(&ref_chain, &nut_blocks, &[], Vec::new());

        assert_eq!(n1.imports.len(), 1, "one import per NUT block");
        assert!(n1.imports[0].ok, "a re-authored block imports OK");
        assert_eq!(n1.imports[0].header_root, block.header.hash().0);
        assert_eq!(n1.imports[0].parent, block.header.parent.0);
        assert_eq!(
            n1.imports[0].reference_parent_root,
            Some(n1.imports[0].declared_parent_root),
            "the reference agrees with the header about the parent's root"
        );
        assert_eq!(n1.nut_blocks.len(), 1);
        assert_eq!(n1.slot_period_ms, SLOT_PERIOD_MS);
        assert_eq!(
            n1.reference_block_hashes.len(),
            ref_chain.chain_blocks().len(),
            "reference block hashes cover the whole chain"
        );
        assert_eq!(
            n1.reference_chain.len(),
            n1.reference_block_hashes.len(),
            "the chain timeline covers the same blocks, with their slots"
        );
        assert!(
            n1.reference_chain.windows(2).all(|w| w[0].0 < w[1].0),
            "the chain timeline is ascending by slot"
        );
        // The block was authored on the chain head, so the head as of its slot
        // is its parent.
        assert_eq!(
            n1.reference_best_at(block.header.slot),
            Some(block.header.parent.0)
        );
        Ok(())
    }

    /// The per-peer split is what lets whichever side connects first deliver a
    /// peer's tickets; every ticket must land in exactly one peer's plan.
    #[test]
    fn run_plans_split_by_author() -> Result<(), ChainError> {
        let ref_chain = RefChain::tiny(0)?;
        let ticket_ctx = ref_chain.ticket_ctx()?;
        let tickets = ref_chain.generate_tickets(&ticket_ctx)?;
        let period = jam_types::epoch_period();
        let plan = plan_tickets(&tickets, 5, 41 * period, 42);
        assert!(!plan.is_empty());

        let plans = plans_by_peer(&plan);

        assert_eq!(
            plans.values().map(Vec::len).sum::<usize>(),
            plan.len(),
            "every scheduled ticket lands in exactly one peer's plan"
        );
        for (peer, peer_plan) in &plans {
            assert!(
                peer_plan.iter().all(|s| s.ticket.author as u16 == *peer),
                "peer {peer} only delivers its own tickets"
            );
            // The sender walks the plan in order and sleeps until each slot,
            // so an out-of-order plan delays every ticket behind the late one.
            assert!(
                peer_plan.windows(2).all(|w| w[0].slot <= w[1].slot),
                "peer {peer}'s plan is in delivery order: {:?}",
                peer_plan.iter().map(|s| s.slot).collect::<Vec<_>>()
            );
        }
        Ok(())
    }

    #[test]
    fn run_plan_maps_to_emu_tickets() -> Result<(), ChainError> {
        let ref_chain = RefChain::tiny(0)?;
        let ticket_ctx = ref_chain.ticket_ctx()?;
        let tickets = ref_chain.generate_tickets(&ticket_ctx)?;
        let nut_index = 5;
        let plan = plan_tickets(&tickets, nut_index, 1001, 84);
        // Only the first ticket reached the wire: the rest stand for the ones
        // the sender withheld, and the lane must be able to tell them apart.
        let deliveries = vec![DeliveredTicket {
            id: plan[0].ticket.id,
            delivered_at_ms: 1,
            target_epoch: plan[0].target_epoch,
            probe: false,
        }];

        let emu_plan = plan_emu_tickets(&plan, &ticket_ctx, &deliveries);

        assert_eq!(emu_plan.len(), plan.len());
        assert_eq!(
            emu_plan[0].delivered_at_ms,
            Some(1),
            "the delivered ticket carries the time it went out"
        );
        assert!(
            emu_plan[1..].iter().all(|t| !t.delivered()),
            "a planned ticket the emulator never sent is not marked delivered"
        );
        // The probe borrows the first ticket's proof and so shares its id,
        // differing only in the epoch it names. Delivering the ticket must not
        // mark the probe delivered too, or a run that withheld the probe would
        // still demand the stream reset it never asked for.
        let probe = emu_plan.last().expect("the plan ends with the probe");
        assert_eq!(
            probe.id, emu_plan[0].id,
            "the probe reuses the first ticket"
        );
        assert_ne!(probe.target_epoch, emu_plan[0].target_epoch);
        assert!(!probe.delivered(), "the probe was not delivered");
        for (emu, scheduled) in emu_plan.iter().zip(&plan) {
            assert_eq!(emu.id, scheduled.ticket.id);
            assert_eq!(emu.author as usize, scheduled.ticket.author);
            assert_eq!(emu.proxy as usize, scheduled.ticket.proxy);
            assert_eq!(emu.slot, scheduled.slot);
            assert!(emu.valid, "generated tickets verify");
            let ce131 = scheduled.delivery == ReferenceDelivery::Ce131;
            assert_eq!(
                ce131,
                scheduled.ticket.proxy == nut_index,
                "Ce131 iff proxy is the NUT"
            );
            assert_eq!(emu.delivery == CtxDelivery::Ce131, ce131);
        }
        Ok(())
    }
}
