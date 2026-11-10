//! Can the N2 inclusion checks fail? The node pools what it is sent and the
//! blocks it authors carry it -- or don't. Honest and faulty are one line
//! apart and both seal validly, since nothing here forges a block body.
//!
//! The calendar is why this drives whole epochs: tickets for epoch *E* are
//! submittable only during *E−1*, the pool files them under the epoch the
//! chain's next slot implies, and the node authors about two slots in six.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ed25519_consensus::{SigningKey, VerificationKey};
use jam_std_common::SecretKeyset;
use jamnp_s::cert::san_for_key;
use jamnp_s::clock::{self, VirtualClock};
use jamnp_s::transport::mock::MockNetwork;
use jamnp_s::transport::Transport;
use m2_reference::chain::RefChain;
use m2_reference::tickets::plan_tickets;
use m2_runner::real::plan_emu_tickets;
use m2_scenario::ctx::{N2Ctx, NutBlockTickets};
use m2_scenario::dsl::Outcome;
use m2_scenario::scenarios::n2;
use m2_sim::{SimFault, SimNode};

const NUT_INDEX: usize = 2;
const EMU_INDICES: [usize; 5] = [0, 1, 3, 4, 5];
/// The phase the plan is handed over at: late enough that the connections are
/// up and the node has announced a head, early enough that the deliveries and
/// one of the node's own slots both still fit in the epoch.
const PLAN_AT_PHASE: u32 = 1;
/// Which epoch of the run the tickets are planned in, counting from the first
/// boundary the run reaches.
///
/// The second, and the reason is worth stating because it looks arbitrary.
/// Which slots a validator authors follows from the entropy and rotates every
/// epoch, so whether the node has a slot *after* the deliveries is not
/// something a test can choose. At this clock anchor the node authors phase 0
/// of the first epoch and nothing else -- a block legitimately empty, since no
/// ticket had arrived -- and phases 0, 1, 4, 5, 9 and 11 of the second. So the
/// run warms up through one epoch and plans in the next.
///
/// Planning in both is not an option: a peer's plan is *taken* by the first
/// connection to it and the sender runs once, so a second `set_ticket_plans`
/// is never sent. That is what the first attempt at this test did, and it
/// graded an epoch whose tickets had gone out an epoch earlier.
const PLAN_IN_EPOCH: u32 = 1;

fn san_of(index: usize) -> String {
    let secret = SecretKeyset::trivial(index as u32).ed25519;
    san_for_key(&VerificationKey::from(&SigningKey::from(secret.to_bytes())))
}

fn slot_ms() -> u64 {
    jam_types::slot_period_sec() * 1000
}

async fn at_slot(slot: u32) {
    let target = m2_reference::chain::slot_start_ms(slot);
    if let Some(wait) = target.checked_sub(clock::current().wall_ms()) {
        clock::current().sleep(Duration::from_millis(wait)).await;
    }
}

async fn grade(fault: SimFault) -> Vec<(&'static str, Outcome)> {
    let net = MockNetwork::new();
    let transport = Arc::new(net) as Arc<dyn Transport>;
    let harness_chain = Arc::new(RefChain::tiny(NUT_INDEX).expect("the harness chain"));
    let node_chain = Arc::new(RefChain::tiny_for(NUT_INDEX).expect("the node's chain"));
    let genesis = harness_chain.genesis_hash();

    let node = Arc::new(SimNode::at_index(Arc::clone(&node_chain), fault, NUT_INDEX));
    let (nut_addr, serving) = Arc::clone(&node)
        .listen(
            Arc::clone(&transport),
            SigningKey::from([0x90u8; 32]),
            "127.0.0.1:9400".parse::<SocketAddr>().expect("an address"),
        )
        .await
        .expect("the simulated node binds");

    let emu = m2_emu::emu::Emulator::n0_on(
        Arc::clone(&transport),
        EMU_INDICES.to_vec(),
        genesis,
        40_500,
    )
    .await
    .expect("the emulated validators bind");
    let shared = emu.shared(Arc::clone(&harness_chain));
    let accepting = emu.accept_loop(Arc::clone(&harness_chain));
    let dialing = tokio::spawn(m2_emu::emu::dial_nut(
        EMU_INDICES[0],
        genesis,
        nut_addr,
        san_of(EMU_INDICES[0]),
        shared,
    ));
    let peers: Vec<(u16, SocketAddr, String)> = EMU_INDICES
        .iter()
        .zip(emu.local_addrs())
        .map(|(&index, addr)| (index as u16, addr, san_of(index)))
        .collect();
    node.connect_to(&transport, SigningKey::from([0x91u8; 32]), &peers)
        .await;

    // Drive whole epochs from a boundary, so each epoch's submission window
    // and the node's own slots sit in the same epoch.
    let period = jam_types::epoch_period();
    let first_epoch_start = (m2_reference::chain::wall_clock_slot() / period + 1) * period;
    let mut plan = Vec::new();
    let mut ticket_ctx = None;
    for epoch in 0..=PLAN_IN_EPOCH {
        let epoch_start = first_epoch_start + epoch * period;
        for phase in 0..period {
            let slot = epoch_start + phase;
            at_slot(slot).await;
            if epoch == PLAN_IN_EPOCH && phase == PLAN_AT_PHASE {
                let ctx = harness_chain.ticket_ctx().expect("a ticket context");
                let tickets = harness_chain.generate_tickets(&ctx).expect("tickets");
                plan = plan_tickets(&tickets, NUT_INDEX, slot + 1, slot / period + 1);
                let mut by_peer = std::collections::HashMap::new();
                for entry in &plan {
                    by_peer
                        .entry(entry.ticket.author as u16)
                        .or_insert_with(Vec::new)
                        .push(entry.clone());
                }
                emu.set_ticket_plans(by_peer);
                // The node runs its own lottery too. It is a validator: its
                // own tickets belong in its own blocks, and the lane allows
                // them through `own_ticket_ids`, which a live run fills from
                // the node's CE 131/132 frames. Without this the node's
                // blocks carry tickets the harness has no account of and
                // `n2_inclusion_no_extra` fails on a node doing its job.
                node.run_lottery(slot / period + 1).await;
                ticket_ctx = Some(ctx);
            }
            match harness_chain.author_block(slot) {
                Ok(Some(block)) => {
                    let _ = emu
                        .announce_tx()
                        .send(m2_emu::emu::announcement_wire(&block, &harness_chain));
                    node_chain.import_nut_block(&block);
                }
                // The node's own slot: it authors and announces, and nothing
                // here imports the block into the harness's chain. The
                // emulator does that itself once it has fetched it, and
                // importing early would make the block *known* --
                // `should_fetch` would decline, the fetch would never happen,
                // and the lane would see a node that authored nothing.
                Ok(None) => {
                    if let Ok(Some(authored)) = node_chain.author_block(slot) {
                        node.publish(authored);
                    }
                }
                Err(_) => {}
            }
        }
    }
    // One more slot so a block authored in the epoch's last phase is fetched.
    clock::current()
        .sleep(Duration::from_millis(2 * slot_ms()))
        .await;

    let submission_epoch = (first_epoch_start + PLAN_IN_EPOCH * period) / period;
    let target_epoch = submission_epoch + 1;
    let nut_blocks = emu.nut_blocks();
    let mut blocks: Vec<_> = nut_blocks
        .lock()
        .expect("the NUT blocks")
        .iter()
        .filter(|nut| nut.block.header.slot / period == submission_epoch)
        .map(|nut| NutBlockTickets {
            slot: nut.block.header.slot,
            ticket_ids: nut
                .block
                .extrinsic
                .tickets
                .iter()
                .map(|t| t.id().0)
                .collect(),
        })
        .collect();
    blocks.sort_by_key(|b| b.slot);

    let deliveries = emu.deliveries();
    let deliveries = deliveries.lock().expect("the deliveries").clone();
    // Every ticket the node put on the wire, through the harness's own
    // collector: these are the ones it is entitled to carry itself.
    let own_ids: Vec<[u8; 32]> = {
        let trace = emu.trace();
        let trace = trace.lock().expect("the trace").clone();
        let contexts = m2_runner::real::TicketContexts::from_epochs(vec![(
            target_epoch,
            node_chain.ticket_ctx().expect("a ticket context"),
        )]);
        m2_runner::real::collect_nut_tickets(&trace, &contexts)
            .iter()
            .map(|f| m2_reference::tickets::ticket_id(&f.ticket.proof))
            .collect()
    };
    let ctx = N2Ctx {
        target_epoch,
        epoch_start_slot: target_epoch * period,
        emu_plan: plan_emu_tickets(&plan, &ticket_ctx.expect("a context"), &deliveries),
        nut_tickets: Vec::new(),
        nut_blocks: blocks,
        nut_finals: Vec::new(),
        own_ticket_ids: own_ids,
        nut_index: NUT_INDEX as u16,
        emulated_peers: EMU_INDICES.iter().map(|&i| i as u16).collect(),
        slot_period_ms: slot_ms(),
        epoch_period: period,
        epoch_tail_start: jam_types::epoch_tail_start(),
        tickets_per_validator: jam_types::tickets_per_validator(jam_types::max_val_count()),
        max_tickets_per_block: jam_types::max_tickets_per_block(),
    };
    // N1's seal row on the same blocks, so the coupling a rewritten body
    // creates is measured rather than asserted in a comment.
    let n1_ctx = m2_runner::real::build_n1_ctx(
        &harness_chain,
        &nut_blocks.lock().expect("the NUT blocks"),
        &deliveries,
        Vec::new(),
    );
    use m2_scenario::scenarios::n1;
    // The whole N1 lane on the same blocks: several N2 faults disturb it, and
    // which ones is a fact worth holding rather than a comment.
    let n1_rows: Vec<(&'static str, Outcome)> = [
        n1::n1_timing(&n1_ctx),
        n1::n1_parent(&n1_ctx),
        n1::n1_header_seal(&n1_ctx),
        n1::n1_state_root(&n1_ctx),
        n1::n1_extrinsic_completeness(&n1_ctx),
        n1::n1_skipped_slots(&n1_ctx),
    ]
    .into_iter()
    .flat_map(|c| (c.run)(&m2_scenario::dsl::ObsLog::new()))
    .map(|r| (r.name, r.outcome))
    .collect();
    let rows = [
        n2::n2_inclusion(&ctx),
        // `plan_tickets` injects the Faults column itself, so the same blocks
        // answer whether the node kept a broken ticket out of them.
        n2::n2_fault_handling(&ctx),
    ]
    .into_iter()
    .flat_map(|check| (check.run)(&m2_scenario::dsl::ObsLog::new()))
    .map(|row| (row.name, row.outcome))
    .chain(n1_rows)
    .collect();

    dialing.abort();
    accepting.abort();
    serving.abort();
    rows
}

fn outcomes_of<'a>(rows: &'a [(&'static str, Outcome)], row: &str) -> Vec<&'a Outcome> {
    rows.iter()
        .filter(|(name, _)| *name == row)
        .map(|(_, o)| o)
        .collect()
}

fn passed(rows: &[(&'static str, Outcome)], row: &str) -> bool {
    let seen = outcomes_of(rows, row);
    !seen.is_empty() && seen.iter().all(|o| matches!(o, Outcome::Pass))
}

fn failed(rows: &[(&'static str, Outcome)], row: &str) -> bool {
    outcomes_of(rows, row)
        .iter()
        .any(|o| matches!(o, Outcome::Fail(_)))
}

#[tokio::test(start_paused = true)]
async fn the_inclusion_checks_catch_a_node_that_mishandles_its_extrinsic() {
    clock::install(Arc::new(VirtualClock::starting_at(1_800_000_000_000)))
        .expect("nothing has read the clock yet");

    let honest = grade(SimFault::None).await;
    for row in [
        "n1_header_seal_import_ok",
        "n1_parent_is_reference_best",
        "n1_extrinsic_includes_delivered",
        "n1_extrinsic_no_repeat",
        "n1_extrinsic_empty_at_tail",
        "n1_state_root_prior_matches",
    ] {
        assert!(
            passed(&honest, row),
            "the honest node must pass {row}; it reported {:?}",
            outcomes_of(&honest, row)
        );
    }
    assert!(
        passed(&honest, "n2_inclusion_covers_valid"),
        "the honest node must carry the tickets it was sent; it reported {:?}",
        outcomes_of(&honest, "n2_inclusion_covers_valid")
    );

    // `n2_inclusion_no_extra` was recorded as unprovable here, blamed on the
    // authoring engine pooling its own lottery tickets. That was wrong. The
    // node was pooling tickets it should have refused -- one misrouted to it
    // over CE 131, and one over the attempt cap -- and those were the ids the
    // harness could not account for. With both refused the row passes, and a
    // node that pools a ticket nobody sent it is what makes it fail.
    assert!(
        passed(&honest, "n2_inclusion_no_extra"),
        "the honest node must carry nothing it was not sent; it reported {:?}",
        outcomes_of(&honest, "n2_inclusion_no_extra")
    );
    // No fault here makes it fail yet. The node's blocks carry only what it
    // was sent, so planting an unaccounted id means getting one into the
    // authoring pool that the harness has no record of -- and withholding one
    // of the node's own winnings does not do it, because the engine does not
    // pool them in the first place.

    assert!(
        passed(&honest, "n2_fault_not_included"),
        "the honest node must keep a broken ticket out of its block; it reported {:?}",
        outcomes_of(&honest, "n2_fault_not_included")
    );

    // Accepting a forgery is also pooling it, and a block of the node's own
    // then carries a ticket the harness deliberately broke.
    let forged = grade(SimFault::AcceptsBadProof).await;
    assert!(
        failed(&forged, "n2_fault_not_included"),
        "a node that pools the forgery must fail the inclusion prohibition; it reported {:?}",
        outcomes_of(&forged, "n2_fault_not_included")
    );

    // Two rows the authoring engine cannot be made to break: its pool
    // rejects duplicates and orders by id, and past the tail it offers no
    // tickets at all. Reaching them means rewriting the body the node serves,
    // which also breaks N1's seal row -- so these two fail in company, and the
    // test says so rather than claiming an isolation it does not have.
    for row in ["n2_inclusion_sorted_dedup", "n2_inclusion_empty_at_tail"] {
        assert!(
            passed(&honest, row),
            "the honest node must pass {row}; it reported {:?}",
            outcomes_of(&honest, row)
        );
    }
    let duplicated = grade(SimFault::ServesDuplicateTicket).await;
    assert!(
        failed(&duplicated, "n2_inclusion_sorted_dedup"),
        "a block carrying the same ticket twice must fail; it reported {:?}",
        outcomes_of(&duplicated, "n2_inclusion_sorted_dedup")
    );
    let in_tail = grade(SimFault::ServesTicketsInTail).await;
    assert!(
        failed(&in_tail, "n2_inclusion_empty_at_tail"),
        "a tail block carrying a ticket must fail; it reported {:?}",
        outcomes_of(&in_tail, "n2_inclusion_empty_at_tail")
    );

    // N1 on the same blocks. Only one of these is isolated; the rest fail in
    // company with the seal row, because a rewritten body is the only way to
    // produce the extrinsic they describe.
    assert!(
        failed(&in_tail, "n1_extrinsic_empty_at_tail")
            && failed(&in_tail, "n1_header_seal_import_ok"),
        "a tail block with a ticket fails N1's tail row, and the rewritten body fails \
         the seal row with it: {:?} / {:?}",
        outcomes_of(&in_tail, "n1_extrinsic_empty_at_tail"),
        outcomes_of(&in_tail, "n1_header_seal_import_ok")
    );
    assert!(
        failed(&in_tail, "n1_extrinsic_no_repeat"),
        "and the tail block repeats a ticket an earlier one carried; it reported {:?}",
        outcomes_of(&in_tail, "n1_extrinsic_no_repeat")
    );
    assert!(
        failed(&duplicated, "n1_header_seal_import_ok"),
        "the duplicate-ticket body must fail the seal row too, which is the company \
         these rows keep; it reported {:?}",
        outcomes_of(&duplicated, "n1_header_seal_import_ok")
    );

    let omitted = grade(SimFault::OmitsDeliveredTickets).await;
    // Isolated, and the only N1 row that is: leaving a delivered ticket out of
    // the block touches nothing else.
    assert!(
        failed(&omitted, "n1_extrinsic_includes_delivered"),
        "a node that pools nothing must fail N1's completeness row; it reported {:?}",
        outcomes_of(&omitted, "n1_extrinsic_includes_delivered")
    );
    for row in [
        "n1_header_seal_import_ok",
        "n1_parent_is_reference_best",
        "n1_extrinsic_no_repeat",
        "n1_extrinsic_empty_at_tail",
    ] {
        assert!(
            passed(&omitted, row),
            "omitting a ticket must not disturb {row}; it reported {:?}",
            outcomes_of(&omitted, row)
        );
    }
    assert!(
        failed(&omitted, "n2_inclusion_covers_valid"),
        "a node that pools nothing must fail the coverage row; it reported {:?}",
        outcomes_of(&omitted, "n2_inclusion_covers_valid")
    );
}
