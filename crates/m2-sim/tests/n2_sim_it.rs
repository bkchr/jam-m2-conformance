//! Can the N2 generation checks fail? The node runs a real Safrole lottery --
//! ring signatures over its own key, from its own chain's entropy -- and sends
//! each ticket where the proxy rule says: CE 131 to the designated proxy,
//! CE 132 to everyone for the ones it proxies itself.
//!
//! Facts come from `m2_runner::real::collect_nut_tickets`, the harness's own
//! trace-to-facts step. That is the step that has actually failed: the CE 131
//! decoder defect closed on 2026-10-30 made the node's whole ticket output
//! invisible, and every check above it read the silence as a node that had
//! sent nothing.

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
use m2_runner::real::{collect_nut_tickets, TicketContexts};
use m2_scenario::ctx::N2Ctx;
use m2_scenario::dsl::Outcome;
use m2_scenario::scenarios::n2;
use m2_sim::{SimFault, SimNode};

/// The simulated node's validator index.
///
/// Two, and not for neatness: the proxy a ticket goes to follows from its id,
/// so which rules a run exercises is decided by the entropy. At this clock
/// anchor validator 2 proxies two of its four tickets itself and sends the
/// other two on, which is the one index of the six that exercises the CE 131
/// path *and* the CE 132 broadcast in the same run. Validator 0's four tickets
/// all go to other validators, and a run as that node leaves
/// `n2_self_proxy_ce132_all_peers` unexercised.
const NUT_INDEX: usize = 2;
/// Every other validator is emulated by the harness.
///
/// All five of them, not a subset: the lane derives the validator count from
/// how many peers it was told about, and the proxy rule is a modulo over that
/// count. Emulating four would have the harness grading the rule over a
/// five-validator set while the node applied it over six.
const EMU_INDICES: [usize; 5] = [0, 1, 3, 4, 5];

fn san_of(index: usize) -> String {
    let secret = SecretKeyset::trivial(index as u32).ed25519;
    let key = SigningKey::from(secret.to_bytes());
    san_for_key(&VerificationKey::from(&key))
}

/// Run the lottery once against a simulated node and return the N2 generation
/// rows it earned.
async fn grade(
    harness_chain: &Arc<RefChain>,
    node_chain: &Arc<RefChain>,
    fault: SimFault,
) -> Vec<(&'static str, Outcome)> {
    let net = MockNetwork::new();
    let transport = Arc::new(net) as Arc<dyn Transport>;
    let (harness_chain, node_chain) = (Arc::clone(harness_chain), Arc::clone(node_chain));
    let genesis = harness_chain.genesis_hash();

    let node = Arc::new(SimNode::at_index(Arc::clone(&node_chain), fault, NUT_INDEX));
    let node_key = SigningKey::from([0x90u8; 32]);
    let (_nut_addr, serving) = Arc::clone(&node)
        .listen(
            Arc::clone(&transport),
            node_key,
            "127.0.0.1:9200".parse::<SocketAddr>().expect("an address"),
        )
        .await
        .expect("the simulated node binds");

    let emu = m2_emu::emu::Emulator::n0_on(
        Arc::clone(&transport),
        EMU_INDICES.to_vec(),
        genesis,
        40_300,
    )
    .await
    .expect("the emulated validators bind");
    let accepting = emu.accept_loop(Arc::clone(&harness_chain));

    // The node dials every emulated validator, so a ticket can go to the one
    // the proxy rule names rather than to whoever happens to be connected.
    let peers: Vec<(u16, SocketAddr, String)> = EMU_INDICES
        .iter()
        .zip(emu.local_addrs())
        .map(|(&index, addr)| (index as u16, addr, san_of(index)))
        .collect();
    node.connect_to(&transport, SigningKey::from([0x91u8; 32]), &peers)
        .await;

    // Start the lottery at an epoch boundary, so the honest node's wait for
    // phase 1 is the thing that keeps it legal.
    let period = jam_types::epoch_period();
    let now = m2_reference::chain::wall_clock_slot();
    let boundary = (now / period + 1) * period;
    let target = m2_reference::chain::slot_start_ms(boundary);
    if let Some(wait) = target.checked_sub(clock::current().wall_ms()) {
        clock::current().sleep(Duration::from_millis(wait)).await;
    }
    let target_epoch = boundary / period + 1;
    node.run_lottery(target_epoch).await;
    clock::current()
        .sleep(Duration::from_millis(jam_types::slot_period_sec() * 1000))
        .await;

    let trace = emu.trace();
    let trace = trace.lock().expect("the trace").clone();
    let contexts = TicketContexts::from_epochs(vec![(
        target_epoch,
        node_chain.ticket_ctx().expect("a ticket context"),
    )]);
    let nut_tickets = collect_nut_tickets(&trace, &contexts);
    let own_ticket_ids = nut_tickets
        .iter()
        .map(|f| m2_reference::tickets::ticket_id(&f.ticket.proof))
        .collect();
    let ctx = N2Ctx {
        target_epoch,
        epoch_start_slot: target_epoch * period,
        emu_plan: Vec::new(),
        nut_tickets,
        nut_blocks: Vec::new(),
        nut_finals: Vec::new(),
        own_ticket_ids,
        nut_index: NUT_INDEX as u16,
        emulated_peers: EMU_INDICES.iter().map(|&i| i as u16).collect(),
        slot_period_ms: jam_types::slot_period_sec() * 1000,
        epoch_period: jam_types::epoch_period(),
        epoch_tail_start: jam_types::epoch_tail_start(),
        tickets_per_validator: jam_types::tickets_per_validator(jam_types::max_val_count()),
        max_tickets_per_block: jam_types::max_tickets_per_block(),
    };

    let obs = emu.obs();
    let obs = obs.lock().expect("the observation log");
    let rows = [n2::n2_generation_step1(&ctx), n2::n2_self_proxy(&ctx)]
        .into_iter()
        .flat_map(|check| (check.run)(&obs))
        .map(|row| (row.name, row.outcome))
        .collect();

    accepting.abort();
    serving.abort();
    rows
}

/// Every outcome reported under `row`.
///
/// A plural, because most checks report one row *per subject* -- per ticket,
/// per block -- so a name can appear many times in one grading. Reading only
/// the first is how a fault that broke one subject out of four looked like a
/// pass.
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

/// Present **and** failing: a row the grading never produced caught nothing.
fn failed(rows: &[(&'static str, Outcome)], row: &str) -> bool {
    outcomes_of(rows, row)
        .iter()
        .any(|o| matches!(o, Outcome::Fail(_)))
}

#[tokio::test(start_paused = true)]
async fn the_n2_generation_checks_catch_a_node_that_distributes_wrongly() {
    clock::install(Arc::new(VirtualClock::starting_at(1_800_000_000_000)))
        .expect("nothing has read the clock yet");

    // One pair of chains for every variant: nothing here authors, so the
    // ring-VRF setup is the same for all of them and rebuilding it per variant
    // was most of the test's runtime.
    let harness_chain = Arc::new(RefChain::tiny(NUT_INDEX).expect("the harness chain"));
    let node_chain = Arc::new(RefChain::tiny_for(NUT_INDEX).expect("the node's chain"));

    let honest = grade(&harness_chain, &node_chain, SimFault::None).await;
    for row in [
        "n2_gen_ce131_observed",
        "n2_gen_epoch_target",
        "n2_gen_attempt_in_range",
        "n2_gen_proof_verified",
        "n2_gen_not_before_epoch_start",
        "n2_gen_proxy_matches_rule",
        "n2_gen_one_proxy_per_ticket",
        "n2_gen_within_attempts_per_epoch",
        // The broadcast half: this node proxies two of its own tickets.
        "n2_self_proxy_ce132_all_peers",
        "n2_self_proxy_proof_verified",
    ] {
        assert!(
            passed(&honest, row),
            "the honest node must pass {row}; it reported {:?}",
            outcomes_of(&honest, row)
        );
    }

    for (fault, broken) in [
        (SimFault::TicketWrongEpoch, "n2_gen_epoch_target"),
        (SimFault::TicketAttemptOverCap, "n2_gen_attempt_in_range"),
        (
            SimFault::TicketAtEpochStart,
            "n2_gen_not_before_epoch_start",
        ),
        (SimFault::TicketWrongProxy, "n2_gen_proxy_matches_rule"),
        (
            SimFault::SelfProxyMissesAPeer,
            "n2_self_proxy_ce132_all_peers",
        ),
        (SimFault::SendsNoTickets, "n2_gen_ce131_observed"),
        (SimFault::TicketBadProof, "n2_gen_proof_verified"),
        (SimFault::SelfProxyBadProof, "n2_self_proxy_proof_verified"),
        (SimFault::TicketToTwoProxies, "n2_gen_one_proxy_per_ticket"),
    ] {
        let rows = grade(&harness_chain, &node_chain, fault).await;
        assert!(
            failed(&rows, broken),
            "{fault:?} must make {broken} fail; it reported {:?}",
            outcomes_of(&rows, broken)
        );
    }

    // Two faults above cannot be isolated, and saying so is part of the
    // result.
    //
    // A bad proof is isolable only because the ticket id is the *first* 32
    // bytes of the ring signature: corrupting a byte past them breaks
    // verification while leaving the id, and therefore the designated proxy,
    // exactly where it was. Corrupting the id instead would move the ticket to
    // another proxy and fail the routing rows too.
    let bad_proof = grade(&harness_chain, &node_chain, SimFault::TicketBadProof).await;
    assert!(
        passed(&bad_proof, "n2_gen_proxy_matches_rule")
            && passed(&bad_proof, "n2_gen_one_proxy_per_ticket"),
        "a bad proof must not disturb the routing rows: {:?} / {:?}",
        outcomes_of(&bad_proof, "n2_gen_proxy_matches_rule"),
        outcomes_of(&bad_proof, "n2_gen_one_proxy_per_ticket"),
    );

    // Sending one ticket to two validators cannot be isolated at all: both
    // `n2_gen_one_proxy_per_ticket` and `n2_gen_proxy_matches_rule` require
    // `peers.len() == 1`, so the second necessarily fails with the first. That
    // is a property of the two checks, not of this node.
    let two = grade(&harness_chain, &node_chain, SimFault::TicketToTwoProxies).await;
    assert!(
        failed(&two, "n2_gen_proxy_matches_rule"),
        "the proxy row fails with the one-proxy row, by construction; it reported {:?}",
        outcomes_of(&two, "n2_gen_proxy_matches_rule")
    );
}
