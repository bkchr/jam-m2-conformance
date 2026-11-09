//! Can the N1 checks fail? The node authors a block and the harness grades it.
//!
//! The node keeps its own reference chain, imports what the emulated
//! validators produce and authors its own slot on top. The harness learns of
//! the block the only way it can: an announcement over UP 0, then a fetch by
//! hash over CE 128.
//!
//! Facts come from `m2_runner::real::build_n1_ctx`, the function a live run
//! uses. The lane's unit tests already prove the predicates; the step that has
//! twice gone wrong here is turning the wire into the facts a lane reads.

use std::sync::Arc;
use std::time::Duration;

use ed25519_consensus::{SigningKey, VerificationKey};
use jamnp_s::cert::san_for_key;
use jamnp_s::clock::{self, VirtualClock};
use jamnp_s::transport::mock::MockNetwork;
use jamnp_s::transport::Transport;
use m2_emu::emu::{dial_nut, Emulator};
use m2_reference::chain::RefChain;
use m2_scenario::dsl::Outcome;
use m2_scenario::scenarios::n1;
use m2_sim::{SimFault, SimNode};

/// The simulated node's validator index: the one the harness treats as the
/// node under test and therefore never authors for.
const NUT_INDEX: usize = 0;
/// The emulated validator that dials the node and does the grading.
const EMU_INDEX: usize = 1;
/// Slots to drive. Long enough that the node authors at least one of them.
const SLOTS: u32 = 14;

fn slot_ms() -> u64 {
    jam_types::slot_period_sec() * 1000
}

/// Drive `SLOTS` slots of a run against a simulated node and return the N1
/// rows it earned.
async fn grade(fault: SimFault) -> Vec<(&'static str, Outcome)> {
    let net = MockNetwork::new();
    let transport = Arc::new(net) as Arc<dyn Transport>;

    // Two chains over one genesis: the harness's, which never authors the
    // node's slots, and the node's, which can.
    let harness_chain = Arc::new(RefChain::tiny(NUT_INDEX).expect("the harness chain"));
    let node_chain = Arc::new(RefChain::tiny_for(NUT_INDEX).expect("the node's chain"));
    let genesis = harness_chain.genesis_hash();
    assert_eq!(
        genesis,
        node_chain.genesis_hash(),
        "both chains must start from one genesis"
    );

    let node = Arc::new(SimNode::new(Arc::clone(&node_chain), fault));
    let node_key = SigningKey::from([0x90u8; 32]);
    let node_san = san_for_key(&VerificationKey::from(&node_key));
    let (nut_addr, serving) = Arc::clone(&node)
        .listen(
            Arc::clone(&transport),
            node_key,
            "127.0.0.1:9100".parse().expect("an address"),
        )
        .await
        .expect("the simulated node binds");

    let emu = Emulator::n0_on(Arc::clone(&transport), vec![EMU_INDEX], genesis, 40_200)
        .await
        .expect("the emulated validator binds");
    let shared = emu.shared(Arc::clone(&harness_chain));
    let accepting = emu.accept_loop(Arc::clone(&harness_chain));
    let dialing = tokio::spawn(dial_nut(EMU_INDEX, genesis, nut_addr, node_san, shared));

    // One slot at a time, on the clock, so each block is announced inside the
    // slot it is for. Authoring the lot at once would put every announcement
    // at the same instant and the timing row would fail on the honest node.
    let start = harness_chain.next_slot() + 1;
    for slot in start..start + SLOTS {
        let target = m2_reference::chain::slot_start_ms(slot);
        if let Some(wait) = target.checked_sub(clock::current().wall_ms()) {
            clock::current().sleep(Duration::from_millis(wait)).await;
        }
        match harness_chain.author_block(slot) {
            // An emulated validator's slot: the node learns it the way a node
            // does, by importing what it is told about.
            Ok(Some(block)) => {
                node_chain.import_nut_block(&block);
            }
            // The node's own slot.
            Ok(None) => {
                if let Ok(Some(authored)) = node_chain.author_block(slot) {
                    node.publish(authored);
                }
            }
            Err(_) => {}
        }
    }
    // Let the last announcement be fetched, and a late one arrive.
    clock::current()
        .sleep(Duration::from_millis(4 * slot_ms()))
        .await;

    let nut_blocks = emu.nut_blocks();
    let nut_blocks = nut_blocks.lock().expect("the NUT blocks").clone();
    let ctx = m2_runner::real::build_n1_ctx(&harness_chain, &nut_blocks, &[], Vec::new());
    let rows = n1::all(&ctx)
        .into_iter()
        .flat_map(|check| (check.run)(&m2_scenario::dsl::ObsLog::new()))
        .map(|row| (row.name, row.outcome))
        .collect();

    dialing.abort();
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

/// A row must be **present and failing**, not merely absent: a row the grading
/// never produced caught nothing.
fn failed(rows: &[(&'static str, Outcome)], row: &str) -> bool {
    outcomes_of(rows, row)
        .iter()
        .any(|o| matches!(o, Outcome::Fail(_)))
}

#[tokio::test(start_paused = true)]
async fn the_n1_checks_grade_a_block_the_simulated_node_authored() {
    clock::install(Arc::new(VirtualClock::starting_at(1_800_000_000_000)))
        .expect("nothing has read the clock yet");

    let honest = grade(SimFault::None).await;
    assert!(
        !honest.is_empty(),
        "the node must author and announce at least one block, or N1 grades nothing"
    );
    for row in [
        "n1_timing_within_slot",
        "n1_parent_is_known",
        "n1_parent_no_equivocation",
        "n1_header_seal_import_ok",
        "n1_state_root_prior_matches",
    ] {
        assert!(
            passed(&honest, row),
            "the honest node must pass {row}; it reported {:?}",
            outcomes_of(&honest, row)
        );
    }

    // Announcing two slots late touches nothing but the timing: the block is
    // byte-for-byte the one the honest node published, so every other row has
    // to stay exactly where it was.
    let late = grade(SimFault::AnnouncesLate).await;
    assert!(
        failed(&late, "n1_timing_within_slot"),
        "a late announcement must fail the timing row; it reported {:?}",
        outcomes_of(&late, "n1_timing_within_slot")
    );
    for row in [
        "n1_parent_is_known",
        "n1_parent_no_equivocation",
        "n1_header_seal_import_ok",
        "n1_state_root_prior_matches",
    ] {
        assert!(
            passed(&late, row),
            "a late announcement must not disturb {row}; it reported {:?}",
            outcomes_of(&late, row)
        );
    }
}
