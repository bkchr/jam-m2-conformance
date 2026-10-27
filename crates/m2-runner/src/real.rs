//! Real-run L1/L2 context builders (m2-runner §4.4): reference-chain facts,
//! NUT-block imports, and ticket deliveries for the L1/L2 scenario lanes.

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
    DeliveredTicket, EmuTicket, ImportFact, L1Ctx, L2Ctx, NutBlock, NutTicketFacts,
    TicketDelivery as CtxDelivery, SLOT_PERIOD_MS,
};

use crate::scenario::RunCtx;

/// Reference-side facts the L1/L2 context builders read after the observation
/// window: the reference chain, the fetched NUT blocks, and the L2 ticket plan.
pub(crate) struct RealRunData {
    pub(crate) ref_chain: Arc<RefChain>,
    pub(crate) nut_blocks: Arc<Mutex<Vec<NutBlock>>>,
    pub(crate) deliveries: Arc<Mutex<Vec<DeliveredTicket>>>,
    pub(crate) ticket_ctx: TicketCtx,
    pub(crate) plan: Vec<ScheduledTicket>,
    pub(crate) target_epoch: u32,
}

/// The emulated validators' tickets for the epoch after the current one.
///
/// Ring-VRF proving is the single most expensive thing the harness does — five
/// authors times four attempts, tens of seconds — so it is split from
/// [`schedule_tickets`] and run while the node is still starting up. The
/// tickets are bound to the tickets-entropy of the epoch they are generated
/// in, which is why `target_epoch` is fixed here and not re-derived later: a
/// run that crossed an epoch boundary mid-generation would otherwise label
/// them for an epoch whose entropy they were never built against.
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

/// The ticket plan split per emulated validator, keyed by peer index.
pub(crate) fn plans_by_peer(plan: &[ScheduledTicket]) -> HashMap<u16, Vec<ScheduledTicket>> {
    let mut plans: HashMap<u16, Vec<ScheduledTicket>> = HashMap::new();
    for scheduled in plan {
        plans
            .entry(scheduled.ticket.author as u16)
            .or_default()
            .push(scheduled.clone());
    }
    plans
}

/// Build the L1/L2 contexts for a real run from the post-window facts.
pub(crate) fn build_real_run_ctx(
    data: &RealRunData,
    trace: &Trace,
    l0: m2_scenario::scenarios::l0::L0Ctx,
) -> RunCtx {
    let nut_blocks = lock(&data.nut_blocks);
    let l1 = build_l1_ctx(&data.ref_chain, &nut_blocks, &lock(&data.deliveries));
    let nut_tickets = collect_nut_tickets(trace, &data.ticket_ctx);
    let l2 = build_l2_ctx(
        &data.ticket_ctx,
        &data.plan,
        nut_tickets,
        &nut_blocks,
        data.target_epoch,
    );
    RunCtx {
        l0,
        l1: Some(l1),
        l2: Some(l2),
    }
}

/// L1 facts: the reference chain with its slots, the fetched NUT blocks with
/// their import outcomes, and the tickets the emulator delivered to the NUT.
///
/// The chain is read before the imports run, so the reference best block is
/// the one the run actually ended on and not one re-imported here.
fn build_l1_ctx(
    ref_chain: &RefChain,
    nut_blocks: &[NutBlock],
    deliveries: &[DeliveredTicket],
) -> L1Ctx {
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
    L1Ctx {
        reference_best,
        reference_block_hashes,
        reference_chain,
        nut_blocks: nut_blocks.to_vec(),
        imports,
        delivered_tickets: deliveries.to_vec(),
        slot_period_ms: SLOT_PERIOD_MS,
        epoch_period: jam_types::epoch_period(),
        epoch_tail_start: jam_types::epoch_tail_start(),
        max_tickets_per_block: jam_types::max_tickets_per_block(),
    }
}

/// L2 facts: the emulator's ticket plan plus every ticket the NUT distributed
/// back (CE 131/132 frames), and the NUT-authored block's ticket extrinsic.
fn build_l2_ctx(
    ticket_ctx: &TicketCtx,
    plan: &[ScheduledTicket],
    nut_tickets: Vec<NutTicketFacts>,
    nut_blocks: &[NutBlock],
    target_epoch: u32,
) -> L2Ctx {
    let epoch_start_slot = target_epoch * jam_types::epoch_period();
    let (nut_block_ticket_ids, nut_block_slot) = nut_blocks
        .iter()
        .max_by_key(|nut| nut.block.header.slot)
        .map(|nut| {
            let ids = nut
                .block
                .extrinsic
                .tickets
                .iter()
                .map(|t| t.id().0)
                .collect();
            (ids, nut.block.header.slot)
        })
        .unwrap_or_default();
    L2Ctx {
        target_epoch,
        epoch_start_slot,
        emu_plan: plan_emu_tickets(plan, ticket_ctx),
        nut_tickets,
        nut_block_ticket_ids,
        nut_block_slot,
    }
}

/// Map the reference ticket plan onto the L2 lane's [`EmuTicket`] facts.
fn plan_emu_tickets(plan: &[ScheduledTicket], ticket_ctx: &TicketCtx) -> Vec<EmuTicket> {
    plan.iter()
        .map(|scheduled| {
            let ticket = &scheduled.ticket;
            EmuTicket {
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
            }
        })
        .collect()
}

/// Every ticket the NUT distributed to the emulators (CE 131/132 frames the
/// NUT sent), verified against the reference ticket context.
fn collect_nut_tickets(trace: &Trace, ticket_ctx: &TicketCtx) -> Vec<NutTicketFacts> {
    trace
        .records()
        .iter()
        .filter(|rec| rec.direction == TraceDir::Tx && matches!(rec.stream_kind, CE131 | CE132))
        .filter_map(|rec| {
            let Ok(distribution) = TicketDistribution::decode(&mut &rec.bytes[..]) else {
                return None;
            };
            let ticket = distribution.ticket;
            Some(NutTicketFacts {
                epoch: distribution.epoch_index,
                ticket,
                peer: rec.peer_index,
                verified: verify_ticket(ticket_ctx, ticket.attempt, &ticket.proof),
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
        let facts = collect_nut_tickets(&trace, &ticket_ctx);
        assert_eq!(
            facts.len(),
            1,
            "one NUT CE 131 distribution yields one fact"
        );
        assert_eq!(facts[0].epoch, 7);
        assert_eq!(facts[0].peer, 2);
        assert_eq!(facts[0].ticket.attempt, ticket.attempt);
        assert_eq!(facts[0].received_at_ms, 1234);
        assert!(facts[0].verified, "a generated ticket verifies");

        // A non-decodable CE 131 frame from the NUT is skipped, not a fact.
        let mut bad = Trace::default();
        bad.push(record(TraceDir::Tx, 2, CE131, vec![0xde, 0xad], 1));
        assert!(
            collect_nut_tickets(&bad, &ticket_ctx).is_empty(),
            "garbage CE 131 is skipped"
        );
        Ok(())
    }

    /// Trace convention (`jamnp_s::trace::Direction`): `Tx` is NUT → peer,
    /// `Rx` is peer → NUT. L2 judges the NUT, so tickets the emulator itself
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

        let facts = collect_nut_tickets(&trace, &ticket_ctx);

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
    fn run_build_l1_from_nut_blocks() -> Result<(), ChainError> {
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
        let l1 = build_l1_ctx(&ref_chain, &nut_blocks, &[]);

        assert_eq!(l1.imports.len(), 1, "one import per NUT block");
        assert!(l1.imports[0].ok, "a re-authored block imports OK");
        assert_eq!(l1.imports[0].header_root, block.header.hash().0);
        assert_eq!(l1.imports[0].parent, block.header.parent.0);
        assert_eq!(
            l1.imports[0].reference_parent_root,
            Some(l1.imports[0].declared_parent_root),
            "the reference agrees with the header about the parent's root"
        );
        assert_eq!(l1.nut_blocks.len(), 1);
        assert_eq!(l1.slot_period_ms, SLOT_PERIOD_MS);
        assert_eq!(
            l1.reference_block_hashes.len(),
            ref_chain.chain_blocks().len(),
            "reference block hashes cover the whole chain"
        );
        assert_eq!(
            l1.reference_chain.len(),
            l1.reference_block_hashes.len(),
            "the chain timeline covers the same blocks, with their slots"
        );
        assert!(
            l1.reference_chain.windows(2).all(|w| w[0].0 < w[1].0),
            "the chain timeline is ascending by slot"
        );
        // The block was authored on the chain head, so the head as of its slot
        // is its parent.
        assert_eq!(
            l1.reference_best_at(block.header.slot),
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

        let emu_plan = plan_emu_tickets(&plan, &ticket_ctx);

        assert_eq!(emu_plan.len(), plan.len());
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
