//! Can the N2 proxy-duty checks fail? The harness delivers tickets and grades
//! what the node does with them: refuse what it cannot act on by resetting the
//! stream, forward what it proxies over CE 132.
//!
//! A proxy-duty verdict compares what the emulator believes it delivered
//! (`plan_emu_tickets`) with the node's own frames off the wire
//! (`collect_nut_tickets`). Both come from the runner, not a copy -- grading a
//! hand-built pair would prove only the comparison.

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
use m2_reference::tickets::{plan_tickets, TicketDelivery, TicketFault};
use m2_runner::real::plan_emu_tickets;
use m2_scenario::ctx::N2Ctx;
use m2_scenario::dsl::Outcome;
use m2_scenario::scenarios::n2;
use m2_sim::{SimFault, SimNode};

/// The simulated node's validator index; see `n2_sim_it` for why it is 2.
const NUT_INDEX: usize = 2;
/// Every other validator is emulated, so the proxy rule's modulus is the real
/// six.
const EMU_INDICES: [usize; 5] = [0, 1, 3, 4, 5];
/// Slots to drive before the tickets go out, so the node has announced a
/// finalized head inside the current epoch. The emulator withholds tickets
/// from a node whose advertised head is behind: one it cannot accept would be
/// sent into a refusal and graded as a defect.
const WARMUP_SLOTS: u32 = 3;

fn san_of(index: usize) -> String {
    let secret = SecretKeyset::trivial(index as u32).ed25519;
    san_for_key(&VerificationKey::from(&SigningKey::from(secret.to_bytes())))
}

fn slot_ms() -> u64 {
    jam_types::slot_period_sec() * 1000
}

/// Sleep until `slot` begins on the installed clock.
async fn at_slot(slot: u32) {
    let target = m2_reference::chain::slot_start_ms(slot);
    if let Some(wait) = target.checked_sub(clock::current().wall_ms()) {
        clock::current().sleep(Duration::from_millis(wait)).await;
    }
}

/// Deliver one honest and one forged ticket to the node, and return the rows
/// `n2_proxy_duty` earned.
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
            "127.0.0.1:9300".parse::<SocketAddr>().expect("an address"),
        )
        .await
        .expect("the simulated node binds");

    let emu = m2_emu::emu::Emulator::n0_on(
        Arc::clone(&transport),
        EMU_INDICES.to_vec(),
        genesis,
        40_400,
    )
    .await
    .expect("the emulated validators bind");
    let shared = emu.shared(Arc::clone(&harness_chain));
    let accepting = emu.accept_loop(Arc::clone(&harness_chain));

    // Both directions, as in a live run: the emulator dials so UP 0 exists and
    // the node's announcements reach it, and the node dials so it has a way to
    // forward.
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

    // Author and announce a few slots, so the node advertises a head the
    // emulator's readiness gate accepts.
    let start = harness_chain.next_slot() + 1;
    for slot in start..start + WARMUP_SLOTS {
        at_slot(slot).await;
        if let Ok(Some(block)) = harness_chain.author_block(slot) {
            // Announced as well as authored. The node learns the emulated
            // validators' head from UP 0 and re-announces it, and that
            // re-announcement is the only thing that tells the harness what
            // the node considers final -- which its ticket sender gates on.
            // Authoring without announcing leaves the gate shut and every
            // delivery withheld.
            let _ = emu
                .announce_tx()
                .send(m2_emu::emu::announcement_wire(&block, &harness_chain));
            node_chain.import_nut_block(&block);
        }
        // The node imports and re-announces here but authors nothing. A block
        // of its own that the harness never imported would move its chain's
        // entropy away from the harness's, and the ring proofs the harness
        // generates would then fail to verify against the node's context --
        // so the node would refuse every honest ticket, for a reason that has
        // nothing to do with the duty under test.
    }
    // Let the re-announcement land before the plan is handed over.
    clock::current()
        .sleep(Duration::from_millis(slot_ms()))
        .await;

    // One honest ticket proxied to the node, and one forged copy of it. The
    // forged one is what `n2_proxy_duty_bad_proof_ignored` judges: a node must
    // refuse a proof that does not verify by resetting its stream.
    let ctx = harness_chain.ticket_ctx().expect("a ticket context");
    let tickets = harness_chain.generate_tickets(&ctx).expect("tickets");
    let now = m2_reference::chain::wall_clock_slot();
    let target_epoch = now / jam_types::epoch_period() + 1;
    let mut plan = plan_tickets(&tickets, NUT_INDEX, now + 1, target_epoch);
    plan.retain(|s| s.delivery == TicketDelivery::Ce131);
    assert!(
        !plan.is_empty(),
        "the entropy must proxy at least one emulated ticket to the node"
    );
    let forged = {
        let mut forged = plan[0].clone();
        // Past the first 32 bytes, so the id and therefore the proxy are
        // unchanged and only the proof is wrong.
        forged.ticket.proof[100] ^= 0xff;
        forged.fault = Some(TicketFault::BadProof);
        forged.slot = plan[0].slot + 1;
        forged
    };
    plan.push(forged);
    // A ticket for an epoch no validator can hold the entropy for yet
    // (`simple.md:335-337`). The node must refuse it by resetting the stream,
    // and the lane judges each probe's own refusal.
    let probe = {
        let mut probe = plan[0].clone();
        probe.target_epoch = target_epoch + 1;
        probe.slot = plan[0].slot + 2;
        // Marked as the injected fault it is. The sender withholds a ticket
        // whose target epoch is not the next one -- sending a stale ticket
        // would manufacture a refusal the node was right to make -- and lets a
        // deliberate fault through regardless, because being wrong is the
        // stimulus.
        probe.fault = Some(TicketFault::UnknownEpoch);
        probe
    };
    plan.push(probe);
    for (index, entry) in plan.iter_mut().enumerate() {
        entry.plan_index = index;
    }
    let mut by_peer = std::collections::HashMap::new();
    for entry in &plan {
        by_peer
            .entry(entry.ticket.author as u16)
            .or_insert_with(Vec::new)
            .push(entry.clone());
    }
    emu.set_ticket_plans(by_peer);

    // Let the deliveries go out and the forwards come back.
    clock::current()
        .sleep(Duration::from_millis(8 * slot_ms()))
        .await;

    let deliveries = emu.deliveries();
    let deliveries = deliveries.lock().expect("the deliveries").clone();
    let ctx = N2Ctx {
        target_epoch,
        epoch_start_slot: target_epoch * jam_types::epoch_period(),
        emu_plan: plan_emu_tickets(&plan, &ctx, &deliveries),
        nut_tickets: nut_tickets(&emu, target_epoch, &node_chain),
        nut_blocks: Vec::new(),
        nut_finals: Vec::new(),
        own_ticket_ids: Vec::new(),
        nut_index: NUT_INDEX as u16,
        emulated_peers: EMU_INDICES.iter().map(|&i| i as u16).collect(),
        slot_period_ms: slot_ms(),
        epoch_period: jam_types::epoch_period(),
        epoch_tail_start: jam_types::epoch_tail_start(),
        tickets_per_validator: jam_types::tickets_per_validator(jam_types::max_val_count()),
        max_tickets_per_block: jam_types::max_tickets_per_block(),
    };
    let rows = [n2::n2_proxy_duty(&ctx), n2::n2_unknown_epoch_reset(&ctx)]
        .into_iter()
        .flat_map(|check| (check.run)(&m2_scenario::dsl::ObsLog::new()))
        .map(|row| (row.name, row.outcome))
        .collect();

    dialing.abort();
    accepting.abort();
    serving.abort();
    rows
}

/// The node's own frames off the wire, through the harness's collector.
fn nut_tickets(
    emu: &m2_emu::emu::Emulator,
    target_epoch: u32,
    node_chain: &Arc<RefChain>,
) -> Vec<m2_scenario::ctx::NutTicketFacts> {
    let trace = emu.trace();
    let trace = trace.lock().expect("the trace").clone();
    let contexts = m2_runner::real::TicketContexts::from_epochs(vec![(
        target_epoch,
        node_chain.ticket_ctx().expect("a ticket context"),
    )]);
    m2_runner::real::collect_nut_tickets(&trace, &contexts)
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
async fn the_proxy_duty_checks_catch_a_node_that_mishandles_a_delivery() {
    clock::install(Arc::new(VirtualClock::starting_at(1_800_000_000_000)))
        .expect("nothing has read the clock yet");

    let honest = grade(SimFault::None).await;
    assert!(
        passed(&honest, "n2_proxy_duty_forwarded"),
        "the honest node must forward what it is proxy for; it reported {:?}",
        outcomes_of(&honest, "n2_proxy_duty_forwarded")
    );
    assert!(
        passed(&honest, "n2_proxy_duty_bad_proof_ignored"),
        "the honest node must refuse the forged ticket by resetting its stream; it \
         reported {:?}",
        outcomes_of(&honest, "n2_proxy_duty_bad_proof_ignored")
    );

    assert!(
        passed(&honest, "n2_unknown_epoch_reset_observed"),
        "the honest node must refuse a ticket for an epoch past its horizon; it \
         reported {:?}",
        outcomes_of(&honest, "n2_unknown_epoch_reset_observed")
    );

    for (fault, broken) in [
        (SimFault::NeverForwards, "n2_proxy_duty_forwarded"),
        (SimFault::AcceptsBadProof, "n2_proxy_duty_bad_proof_ignored"),
        (
            SimFault::AcceptsUnknownEpoch,
            "n2_unknown_epoch_reset_observed",
        ),
    ] {
        let rows = grade(fault).await;
        assert!(
            failed(&rows, broken),
            "{fault:?} must make {broken} fail; it reported {:?}",
            outcomes_of(&rows, broken)
        );
    }
}
