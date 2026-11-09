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
        emu_plan: {
            let p = plan_emu_tickets(&plan, &ticket_ctx.expect("a context"), &deliveries);
            eprintln!(
                "PLAN {fault:?}: {} entries, delivered {}, valid {}, epochs {:?}, blocks {:?}",
                p.len(),
                p.iter().filter(|t| t.delivered_at_ms.is_some()).count(),
                p.iter().filter(|t| t.valid).count(),
                p.iter()
                    .map(|t| t.target_epoch)
                    .collect::<std::collections::BTreeSet<_>>(),
                blocks
                    .iter()
                    .map(|b| (b.slot, b.ticket_ids.len()))
                    .collect::<Vec<_>>(),
            );
            p
        },
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
    let rows = [n2::n2_inclusion(&ctx)]
        .into_iter()
        .flat_map(|check| (check.run)(&m2_scenario::dsl::ObsLog::new()))
        .map(|row| (row.name, row.outcome))
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
    assert!(
        passed(&honest, "n2_inclusion_covers_valid"),
        "the honest node must carry the tickets it was sent; it reported {:?}",
        outcomes_of(&honest, "n2_inclusion_covers_valid")
    );

    let omitted = grade(SimFault::OmitsDeliveredTickets).await;
    assert!(
        failed(&omitted, "n2_inclusion_covers_valid"),
        "a node that pools nothing must fail the coverage row; it reported {:?}",
        outcomes_of(&omitted, "n2_inclusion_covers_valid")
    );
}

/// `n2_inclusion_no_extra` is **not** provable with this stand-in, and the
/// reason is worth recording rather than leaving as a gap.
///
/// The row asks that a block carry nothing the node was neither sent nor
/// announced. The authoring engine runs the Safrole lottery for its own
/// keystore and pools the result itself, independently of anything the
/// simulated node chooses to distribute -- so its blocks carry tickets of its
/// own whose ids the harness has no account of, and the row fails on a node
/// that is behaving correctly. Making the node announce exactly those would
/// mean reading the engine's own pool, which `hazmat` does not expose.
///
/// This test holds the shape of the problem so it is not rediscovered: the
/// honest node *does* fail the row, on one block out of six.
#[tokio::test(start_paused = true)]
#[ignore = "documents a limitation; see the doc comment"]
async fn no_extra_cannot_be_isolated_with_this_stand_in() {
    let honest = grade(SimFault::None).await;
    assert!(
        failed(&honest, "n2_inclusion_no_extra"),
        "if this ever passes, the engine stopped pooling its own tickets and the row \
         became provable: {:?}",
        outcomes_of(&honest, "n2_inclusion_no_extra")
    );
}
