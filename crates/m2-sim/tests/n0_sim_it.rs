//! Can the N0 checks fail?
//!
//! Break exactly one behaviour, grade the node, and require that **the row for
//! it fails and the rest keep passing**. A fault that failed everything would
//! prove nothing about which check caught it.
//!
//! Not covered here, on purpose: the mock transport has no TLS, certificate or
//! ALPN, so `tls_cert`, `alpn` and the builder probe belong to the QUIC
//! carrier.

use std::sync::Arc;
use std::time::Duration;

use ed25519_consensus::{SigningKey, VerificationKey};
use jamnp_s::cert::san_for_key;
use jamnp_s::clock::{self, VirtualClock};
use jamnp_s::transport::mock::MockNetwork;
use m2_emu::emu::{dial_nut, Emulator};
use m2_reference::chain::RefChain;
use m2_scenario::dsl::Outcome;
use m2_scenario::scenarios::n0;
use m2_sim::{SimFault, SimNode};

/// The emulated validator that does the grading, and the one the simulated
/// node talks to.
const EMU_INDEX: usize = 1;

/// Blocks the reference chain authors before anything connects, so the node
/// has something to serve and the peer has something to announce.
const BLOCKS: u32 = 6;

/// Long enough for the CE 128/129 probes, which wait for the node to sync
/// before asking it to serve. Virtual seconds: this costs nothing.
const SETTLE: Duration = Duration::from_secs(m2_emu::sync_probe::PROBE_DELAY_SECS + 6);

/// Grade one simulated node and return every row the N0 checks produced.
///
/// Only the checks the in-process carrier can exercise are run. The others
/// are not skipped because they are inconvenient -- they grade TLS and ALPN,
/// which this transport does not have.
async fn grade(chain: &Arc<RefChain>, fault: SimFault) -> Vec<(&'static str, Outcome)> {
    let net = MockNetwork::new();
    let transport = Arc::new(net.clone());
    let genesis = chain.genesis_hash();

    let node_key = SigningKey::from([0x90u8; 32]);
    let node_san = san_for_key(&VerificationKey::from(&node_key));
    let (nut_addr, node) = Arc::new(SimNode::new(Arc::clone(chain), fault))
        .listen(
            Arc::clone(&transport) as Arc<dyn jamnp_s::transport::Transport>,
            node_key,
            "127.0.0.1:9000".parse().expect("an address"),
        )
        .await
        .expect("the simulated node binds");

    let emu = Emulator::n0_on(
        Arc::clone(&transport) as Arc<dyn jamnp_s::transport::Transport>,
        vec![EMU_INDEX],
        genesis,
        40_100,
    )
    .await
    .expect("the emulated validator binds");
    let shared = emu.shared(Arc::clone(chain));
    let accepting = emu.accept_loop(Arc::clone(chain));

    // Spawned, not awaited: `dial_nut` serves the connection it opened for as
    // long as it lives, so awaiting it would wait out the run.
    let dialing = tokio::spawn(dial_nut(EMU_INDEX, genesis, nut_addr, node_san, shared));
    clock::current().sleep(SETTLE).await;

    let obs = emu.obs();
    let obs = obs.lock().expect("the observation log");
    let ce128 = emu.ce128_probes();
    let ce128 = ce128.lock().expect("the CE 128 probes").clone();
    let ce129 = emu.ce129_probes();
    let ce129 = ce129.lock().expect("the CE 129 probes").clone();
    let reference_chain: Vec<[u8; 32]> = chain
        .chain_blocks()
        .iter()
        .skip(1)
        .map(|block| block.header.hash().0)
        .collect();
    let checks = vec![
        n0::up0_handshake(),
        n0::up0_announce(),
        n0::ce128_serve(reference_chain, ce128),
        n0::ce129_serve(ce129),
    ];
    let rows = checks
        .into_iter()
        .flat_map(|check| (check.run)(&obs))
        .map(|row| (row.name, row.outcome))
        .collect();

    dialing.abort();
    accepting.abort();
    node.abort();
    rows
}

/// Whether `row` passed, or `None` if the grading never produced it.
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

/// Whether `row` was produced *and* failed.
///
/// Not `!passed`: a row the grading never produced is not a row that caught
/// anything, and accepting its absence as proof would be the same vacuous
/// pass the lanes' own controls exist to prevent.
fn failed(rows: &[(&'static str, Outcome)], row: &str) -> bool {
    outcomes_of(rows, row)
        .iter()
        .any(|o| matches!(o, Outcome::Fail(_)))
}

#[tokio::test(start_paused = true)]
async fn the_n0_checks_catch_a_node_that_gets_one_thing_wrong() {
    // A fixed date well inside the JAM common era, so the slot numbers the
    // chain anchors itself to are real ones and the whole run is reproducible:
    // the calendar is the clock's, not the machine's.
    clock::install(Arc::new(VirtualClock::starting_at(1_800_000_000_000)))
        .expect("nothing has read the clock yet");

    let chain = Arc::new(RefChain::tiny(0).expect("a reference chain"));
    let start = chain.next_slot();
    for slot in start..start + BLOCKS {
        chain.author_block(slot).expect("the chain authors");
    }

    // The honest node first: a row that cannot pass proves nothing when it
    // later fails.
    let honest = grade(&chain, SimFault::None).await;
    for row in [
        "up0_kind_byte_0",
        "up0_final_is_genesis",
        "nut_reannounces_learned_block",
        "ce128_ascending_covers_reference",
        "ce128_ascending_ordered",
        "ce128_respects_max",
        "ce128_both_halves_fin",
        // The reference chain exports no state, so an honest CE 129 answer is
        // empty and these pass vacuously. The faults below supply content that
        // breaks one rule each, which is what makes the rows mean anything.
        "ce129_served",
        "ce129_keys_sorted",
        "ce129_boundary_parent_before_child",
        "ce129_size_cap",
        // Always passes: `probe.decoded` is true exactly when `probe.error` is
        // none, and the row is only reported when it is -- so no response can
        // fail it. Recorded in M2-status 4.2 beside `n2_self_proxy_none`.
        "ce129_len_prefixed_values",
    ] {
        assert!(
            passed(&honest, row),
            "the honest node must pass {row}; it reported {:?}",
            outcomes_of(&honest, row)
        );
    }

    // Each fault, and the one row it must cost. Timed, because the point of
    // the virtual clock is that six gradings of a node that each wait out a
    // 26-second probe delay do not cost 156 seconds.
    let before = std::time::Instant::now();
    for (fault, broken) in [
        (SimFault::SilentOnUp0, "up0_kind_byte_0"),
        (SimFault::FinalIsNotGenesis, "up0_final_is_genesis"),
        (SimFault::NeverReannounces, "nut_reannounces_learned_block"),
        (SimFault::Ce128Descending, "ce128_ascending_ordered"),
        (SimFault::Ce128Silent, "ce128_ascending_covers_reference"),
        (SimFault::Ce128OverMax, "ce128_respects_max"),
        (SimFault::Ce128DirtyClose, "ce128_both_halves_fin"),
        (SimFault::Ce129Refuses, "ce129_served"),
        (SimFault::Ce129UnsortedKeys, "ce129_keys_sorted"),
        (
            SimFault::Ce129ChildBeforeParent,
            "ce129_boundary_parent_before_child",
        ),
        (SimFault::Ce129OverSize, "ce129_size_cap"),
    ] {
        let rows = grade(&chain, fault).await;
        assert!(
            failed(&rows, broken),
            "{fault:?} must make {broken} fail; it reported {:?}",
            outcomes_of(&rows, broken)
        );
        // And the node is still graded on everything else: a fault that took
        // the whole lane down with it would make the row above meaningless.
        assert!(
            passed(&rows, "emulated_author_announces"),
            "{fault:?} must not stop the rest of N0 being graded"
        );
    }
    assert!(
        before.elapsed() < Duration::from_secs(60),
        "five gradings waited {} virtual seconds between them and must not have \
         spent them, but took {:?}",
        5 * SETTLE.as_secs(),
        before.elapsed(),
    );
}
