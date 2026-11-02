//! Scenario evaluation for a run: the N0 checks against an observation log
//! and the deterministic dry-run baseline log.

use std::sync::{Arc, Mutex};

use jam_types::JAM_COMMON_ERA;
use jamnp_s::codec::ce131_136::Ticket as Ce131Ticket;
use jamnp_s::trace::Trace;
use m2_emu::emu::Emulator;
use m2_reference::chain::RefChain;
use m2_scenario::ctx::{
    DeliveredTicket, EmuTicket, ImportFact, N1Ctx, N2Ctx, NutBlock, NutTicketFacts, TicketDelivery,
    SLOT_PERIOD_MS, TICKET_ARRIVAL_LEAD_MS,
};
use m2_scenario::dsl::{Check, Obs, ObsKind, ObsLog, Outcome, Scheduler, Severity};
use m2_scenario::scenarios::n0::{Ce128Probe, Ce129Probe};
use m2_scenario::scenarios::obs::{
    EMU_SENT_131, EMU_SENT_132, RECV_CE131, RECV_CE132, UNKNOWN_EPOCH_RESET,
};
use m2_scenario::scenarios::{n0, n1, n2};

use crate::cli::LaneSet;
use crate::report::{CheckOutcome, Finding};

/// Per-lane facts a run's scenario evaluation reads.
pub(crate) struct RunCtx {
    pub n0: n0::N0Ctx,
    pub n1: Option<N1Ctx>,
    pub n2: Option<N2Ctx>,
}

/// The outcome of a run's scenario evaluation.
pub(crate) struct Evaluation {
    pub outcomes: Vec<CheckOutcome>,
    pub findings: Vec<Finding>,
    pub all_hard_passed: bool,
}

/// Where a run's checks read observations from.
pub(crate) enum ObsSource {
    /// Live emulator log (real run); `_emu` keeps its runtime alive.
    Emulator {
        obs: Arc<Mutex<ObsLog>>,
        trace: Arc<Mutex<Trace>>,
        ce128_probes: Arc<Mutex<Vec<Ce128Probe>>>,
        ce129_probes: Arc<Mutex<Vec<Ce129Probe>>>,
        _emu: Emulator,
    },
    /// Deterministic fabricated log + empty trace (dry-run).
    Fabricated { log: ObsLog, trace: Trace },
}

/// Run the selected lanes' checks against `obs` and reduce to report outcomes
/// and findings. A lane fires only when it was asked for *and* its context is
/// present.
pub(crate) fn evaluate(obs: &ObsLog, run_ctx: &RunCtx, selected: LaneSet) -> Evaluation {
    let mut outcomes = Vec::new();
    let mut findings = Vec::new();
    let mut all_hard_passed = true;
    // Two conditions, and they mean different things. `selected` is what the
    // operator asked to grade; the context being present is whether the run
    // produced anything to grade it on. A lane nobody asked for is absent
    // from the report rather than passed.
    let mut lanes: Vec<(&str, Vec<Check>)> = Vec::new();
    if selected.n0 {
        lanes.push(("N0", n0::all(&run_ctx.n0)));
    }
    if let (true, Some(ctx)) = (selected.n1, &run_ctx.n1) {
        lanes.push(("N1", n1::all(ctx)));
    }
    if let (true, Some(ctx)) = (selected.n2, &run_ctx.n2) {
        lanes.push(("N2", n2::all(ctx)));
    }
    for (lane, checks) in lanes {
        let (out, finds, hard) = run_lane(lane, &checks, obs);
        outcomes.extend(out);
        findings.extend(finds);
        all_hard_passed &= hard;
    }
    Evaluation {
        outcomes,
        findings,
        all_hard_passed,
    }
}

fn run_lane(lane: &str, checks: &[Check], obs: &ObsLog) -> (Vec<CheckOutcome>, Vec<Finding>, bool) {
    let mut scheduler = Scheduler::new();
    let mut outcomes = Vec::new();
    let mut findings = Vec::new();
    let mut all_hard_passed = true;
    for check in checks {
        for result in scheduler.fire(check, obs) {
            let passed = result.outcome == Outcome::Pass;
            let soft = match result.outcome {
                Outcome::Pass => check.severity == Severity::Soft,
                Outcome::Fail(severity) => severity == Severity::Soft,
            };
            if !passed && !soft {
                all_hard_passed = false;
            }
            if !passed {
                findings.push(Finding {
                    severity: if soft { "soft" } else { "hard" }.into(),
                    spec_citation: format!("{lane} {}", check.id),
                    slot: None,
                    evidence: "traces/jamnp.bin".into(),
                    message: match &result.detail {
                        Some(detail) => format!("{}: {}: {detail}", check.id, result.name),
                        None => format!("{}: {}", check.id, result.name),
                    },
                });
            }
            outcomes.push(CheckOutcome {
                id: format!("{}.{}", check.id, result.name),
                lane: lane.into(),
                severity: if soft { "soft" } else { "hard" }.into(),
                passed,
                soft,
                details: match (passed, &result.detail) {
                    (true, _) => "ok".into(),
                    (false, Some(detail)) => detail.clone(),
                    (false, None) => format!("{:?}", result.outcome),
                },
            });
        }
    }
    (outcomes, findings, all_hard_passed)
}

/// The deterministic conforming observation log the dry-run baseline reports
/// on: peer 1 exhibits every N0 contract event (codes 20..=40 plus the named
/// kinds) in an order that satisfies all nine checks.
pub(crate) fn fabricated_obs_log(reference_block_count: usize) -> ObsLog {
    use n0::{
        ALPN_ACCEPTED, ALPN_BUILDER_OK, ALPN_OFFERED, BUILDERS_ACCEPTED, CE128_FIN_BOTH,
        CE128_MAX_RESPECTED, CE129_BOUNDARY_ORDER, CE129_LEN_PREFIXED, CE129_SIZE_CAP,
        CE129_SORTED, CE133_ON_BUILDER, CERT_ED25519, CERT_KEY_MATCH, CERT_SAN_OK, ENDPOINT_DIALED,
        NUT_INITIATED, REANNOUNCED, UP0_FINAL_GENESIS, UP0_KIND0,
    };
    let mut log = ObsLog::new();
    let mut at = 0u64;
    let mut push = |peer: u16, kind: ObsKind| {
        log.push(
            at,
            Obs {
                peer,
                kind,
                at_ms: at,
            },
        );
        at += 10;
    };
    push(n0::PEER_1, ObsKind::Accept);
    push(n0::PEER_1, ObsKind::Other(CERT_ED25519));
    push(n0::PEER_1, ObsKind::Other(CERT_KEY_MATCH));
    push(n0::PEER_1, ObsKind::Other(CERT_SAN_OK));
    push(n0::PEER_1, ObsKind::OpenUp0);
    push(n0::PEER_1, ObsKind::Other(ALPN_ACCEPTED));
    push(n0::PEER_1, ObsKind::Other(ALPN_OFFERED));
    push(n0::PEER_1, ObsKind::Other(ALPN_BUILDER_OK));
    push(n0::PEER_1, ObsKind::Other(NUT_INITIATED));
    push(n0::PEER_1, ObsKind::Other(ENDPOINT_DIALED));
    push(n0::PEER_1, ObsKind::Other(BUILDERS_ACCEPTED));
    push(n0::PEER_1, ObsKind::Other(CE133_ON_BUILDER));
    push(n0::PEER_1, ObsKind::Other(UP0_KIND0));
    push(n0::PEER_1, ObsKind::Other(UP0_FINAL_GENESIS));
    push(n0::PEER_1, ObsKind::Up0Announce);
    push(n0::PEER_1, ObsKind::Other(REANNOUNCED));
    for _ in 0..reference_block_count {
        push(n0::PEER_1, ObsKind::ServesCe128);
    }
    push(n0::PEER_1, ObsKind::Other(CE128_FIN_BOTH));
    push(n0::PEER_1, ObsKind::Other(CE128_MAX_RESPECTED));
    push(n0::PEER_1, ObsKind::Other(CE129_SORTED));
    push(n0::PEER_1, ObsKind::Other(CE129_BOUNDARY_ORDER));
    push(n0::PEER_1, ObsKind::Other(CE129_SIZE_CAP));
    push(n0::PEER_1, ObsKind::Other(CE129_LEN_PREFIXED));
    // N1: the NUT announced an authored block.
    push(n0::PEER_1, ObsKind::AuthorsBlock);
    // N2: the NUT received its CE 131/132 ticket distributions and the
    // emulator's sends; the CE 132 broadcast reaches all five emulated peers.
    push(n0::PEER_1, ObsKind::Other(RECV_CE131));
    for peer in 1..=5u16 {
        push(peer, ObsKind::Other(RECV_CE132));
    }
    push(n0::PEER_1, ObsKind::Other(EMU_SENT_131));
    push(n0::PEER_1, ObsKind::Other(EMU_SENT_132));
    // N2: the NUT reset the stream carrying the unknown-epoch probe.
    push(n0::PEER_1, ObsKind::Other(UNKNOWN_EPOCH_RESET));
    log
}

/// The deterministic conforming [`RunCtx`] for the dry-run baseline: the N1
/// lane is built around one real reference-authored NUT block (genuine header
/// and extrinsic types), with its import fact and delivered tickets matching
/// that block; the N2 lane carries a conforming emulator plan and verified NUT
/// ticket facts.
pub(crate) fn fabricated_run_ctx(
    reference_block_count: usize,
) -> Result<RunCtx, m2_reference::chain::ChainError> {
    let chain = RefChain::tiny(0)?;
    let start = chain.next_slot();
    // Two blocks, the second built on the first: one NUT block on its own can
    // never witness its own posterior state root, which only the header of a
    // block built on top of it commits to.
    let mut authored: Vec<jam_std_common::Block> = Vec::new();
    for slot in start..start + 24 {
        if let Some(block) = chain.author_block(slot)? {
            authored.push(block);
            if authored.len() == 2 {
                break;
            }
        }
    }
    let [first, second] = <[_; 2]>::try_from(authored).map_err(|_| {
        m2_reference::chain::ChainError::Chain("no two emulated slots in 24 slots".into())
    })?;

    // Everything up to and including `first` is reference history; `second` is
    // the block under test, so its parent is the reference best at its slot.
    let history: Vec<(u32, [u8; 32])> = chain
        .chain_blocks()
        .iter()
        .take_while(|block| block.header.slot <= first.header.slot)
        .map(|block| (block.header.slot, block.header.hash().0))
        .collect();
    let first_root = first.header.hash().0;
    let second_root = second.header.hash().0;
    let slot = first.header.slot;
    let second_slot = second.header.slot;
    // The N0 sync probes: what a conforming node would answer. The reference
    // the CE 128 reply is compared against stops at `first`, since that is all
    // the harness treats as history here; the node is allowed to be ahead.
    let genesis = chain.genesis_hash();
    let reference_chain: Vec<[u8; 32]> = history.iter().skip(1).map(|(_, hash)| *hash).collect();
    let probed_blocks: Vec<n0::ProbedBlock> = chain
        .chain_blocks()
        .iter()
        .skip(1)
        .map(|block| n0::ProbedBlock {
            slot: block.header.slot,
            hash: block.header.hash().0,
            parent: block.header.parent.0,
        })
        .collect();
    let included_ids: Vec<[u8; 32]> = first.extrinsic.tickets.iter().map(|t| t.id().0).collect();
    let slot_start = |slot: u32| JAM_COMMON_ERA * 1000 + slot as u64 * SLOT_PERIOD_MS;
    let import = |block: &jam_std_common::Block, root: Option<[u8; 32]>| ImportFact {
        header_root: block.header.hash().0,
        parent: block.header.parent.0,
        declared_parent_root: block.header.parent_state_root.0,
        reference_parent_root: Some(block.header.parent_state_root.0),
        ok: true,
        root,
        error: None,
    };
    let n1 = N1Ctx {
        // The fabricated node's blocks carry only tickets the emulator
        // delivered, so there are none of its own to account for. The
        // own-ticket allowance is exercised by the N1 lane's own tests.
        own_ticket_ids: Vec::new(),
        reference_best: first_root,
        reference_block_hashes: history.iter().map(|(_, hash)| *hash).collect(),
        reference_chain: history,
        imports: vec![
            // `second` declares `first`'s posterior root, so the witnessed
            // path is the one this baseline exercises. `second` itself has no
            // block built on it, which is a soft "not witnessed" — inherent to
            // the last block of any chain, and reported as such.
            import(&first, Some(second.header.parent_state_root.0)),
            import(&second, Some(second_root)),
        ],
        nut_blocks: vec![
            // Each block is announced at the start of *its own* slot. The two
            // are not necessarily adjacent -- the reference only authors the
            // slots it wins, so the NUT may own the one in between -- and
            // timing the second as `first + one slot period` put its
            // announcement before its slot had begun whenever that happened,
            // failing `n1_timing_within_slot` for one wall-clock slot in
            // several. A fabricated baseline must not depend on the clock.
            NutBlock {
                block: first,
                announced_wall_ms: slot_start(slot),
            },
            NutBlock {
                block: second,
                announced_wall_ms: slot_start(second_slot),
            },
        ],
        delivered_tickets: included_ids
            .into_iter()
            .map(|id| DeliveredTicket {
                id,
                delivered_at_ms: slot_start(slot) - TICKET_ARRIVAL_LEAD_MS,
                target_epoch: slot / jam_types::epoch_period() + 1,
                probe: false,
            })
            .collect(),
        slot_period_ms: SLOT_PERIOD_MS,
        epoch_period: jam_types::epoch_period(),
        epoch_tail_start: jam_types::epoch_tail_start(),
        max_tickets_per_block: jam_types::max_tickets_per_block(),
    };

    // The fabricated NUT sits at validator index 0, so the emulated peers —
    // the index space the observation log and the ticket facts share — are
    // the other five validators.
    const FAB_NUT_INDEX: u16 = 0;
    const FAB_TARGET_EPOCH: u32 = 3;
    let emu_peers: Vec<u16> = (1..=5).collect();
    // Emulator-sent tickets carry proofs in the low range; the node's own
    // carry the high range, so a forward is never mistaken for a ticket the
    // node generated, and vice versa.
    let emu = |id: u8, proxy: u16, delivery: TicketDelivery, target_epoch: u32| EmuTicket {
        id: [id; 32],
        author: 1,
        attempt: 0,
        proof: [id; 784],
        proxy,
        valid: true,
        delivery,
        slot: 1,
        target_epoch,
        // The baseline is a conforming run, so every planned ticket reached
        // the node on the slot it was planned for: the dry run has nothing to
        // withhold or delay them for.
        delivered_at_ms: Some(JAM_COMMON_ERA * 1000 + SLOT_PERIOD_MS),
    };
    // A ticket the node generates during epoch 2 is for epoch 3, so the facts
    // are stamped inside epoch 2 rather than at an arbitrary instant: the
    // lane derives the epoch it expects from the moment the frame went out.
    let sent_in_epoch_2 =
        JAM_COMMON_ERA * 1000 + u64::from(2 * jam_types::epoch_period()) * SLOT_PERIOD_MS;
    let sent =
        |attempt: u8, proof: [u8; 784], peer: u16, delivery: TicketDelivery| NutTicketFacts {
            epoch: FAB_TARGET_EPOCH,
            ticket: Ce131Ticket { attempt, proof },
            peer,
            delivery,
            verified: Some(true),
            received_at_ms: sent_in_epoch_2,
        };
    let own = |attempt: u8, peer: u16, delivery: TicketDelivery| {
        sent(attempt, [0x80 + attempt; 784], peer, delivery)
    };
    let proxied_to_the_nut = emu(1, FAB_NUT_INDEX, TicketDelivery::Ce131, FAB_TARGET_EPOCH);
    // Two tickets of its own proxied to one validator each, one it proxies
    // for itself and so broadcasts, and the forward of the ticket another
    // validator proxied to it.
    let mut nut_tickets = vec![
        own(0, 1, TicketDelivery::Ce131),
        own(1, 2, TicketDelivery::Ce131),
    ];
    for &peer in &emu_peers {
        nut_tickets.push(own(2, peer, TicketDelivery::Ce132));
        nut_tickets.push(sent(
            proxied_to_the_nut.attempt,
            proxied_to_the_nut.proof,
            peer,
            TicketDelivery::Ce132,
        ));
    }
    let n2 = N2Ctx {
        target_epoch: FAB_TARGET_EPOCH,
        epoch_start_slot: 0,
        emu_plan: vec![
            proxied_to_the_nut,
            emu(2, 1, TicketDelivery::Ce132, FAB_TARGET_EPOCH),
            // The unknown-epoch probe (`simple.md:335-337`): an epoch the
            // node cannot know yet, which it must reset the stream on.
            emu(3, 1, TicketDelivery::Ce132, FAB_TARGET_EPOCH + 2),
        ],
        nut_tickets,
        // Two delivered tickets plus one of the node's own: a validator's own
        // ticket belongs in its own block, and the baseline says so.
        nut_block_ticket_ids: vec![[1u8; 32], [2u8; 32], [9u8; 32]],
        own_ticket_ids: vec![[9u8; 32]],
        nut_block_slot: Some(12),
        nut_index: FAB_NUT_INDEX,
        emulated_peers: emu_peers,
        slot_period_ms: SLOT_PERIOD_MS,
        epoch_period: jam_types::epoch_period(),
        epoch_tail_start: jam_types::epoch_tail_start(),
        tickets_per_validator: jam_types::tickets_per_validator(jam_types::max_val_count()),
        max_tickets_per_block: jam_types::max_tickets_per_block(),
    };

    Ok(RunCtx {
        // The fabricated log is written for a NUT at index 0, which initiates
        // to every emulated peer and so never needs a fallback dial.
        n0: n0::N0Ctx {
            reference_block_count,
            reference_chain: reference_chain.clone(),
            // A conforming node: the ascending walk returns the reference
            // chain itself, within the cap, FIN'd; the state slice is sorted,
            // in range and inside the size cap.
            ce128_probes: vec![n0::Ce128Probe {
                peer: n0::PEER_1,
                max_blocks: 64,
                from: genesis,
                returned: probed_blocks,
                finished: true,
                error: None,
            }],
            ce129_probes: vec![n0::Ce129Probe {
                peer: n0::PEER_1,
                start: [0u8; 31],
                end: [0xffu8; 31],
                max_size: 16 * 1024,
                keys: vec![[0u8; 31], [1u8; 31]],
                boundary_nodes: vec![[7u8; 64]],
                response_bytes: 128,
                entry_bytes: vec![64, 64],
                decoded: true,
                error: None,
            }],
            first_emu_peer: n0::PEER_1,
            handshake_completed: true,
            wrong_alpn_rejected: true,
            builder: Some(n0::BuilderProbeFacts {
                attempted: 21,
                accepted: 21,
                ce133_accepted: true,
                ce133_detail: None,
            }),
            nut_preferred_peers: vec![n0::PEER_1],
            emu_preferred_peers: Vec::new(),
        },
        n1: Some(n1),
        n2: Some(n2),
    })
}

#[cfg(test)]
mod tests {

    use super::*;

    /// Every implemented lane, which is what a run grades unless told
    /// otherwise.
    const ALL_LANES: LaneSet = LaneSet {
        n0: true,
        n1: true,
        n2: true,
    };

    #[test]
    fn evaluate_reports_lanes() {
        let run_ctx = fabricated_run_ctx(3).expect("fabricated run ctx builds");
        let log = fabricated_obs_log(3);
        let eval = evaluate(&log, &run_ctx, ALL_LANES);

        let hard_failures: Vec<&str> = eval
            .outcomes
            .iter()
            .filter(|o| !o.passed)
            .map(|o| o.id.as_str())
            .collect();
        assert!(
            eval.all_hard_passed,
            "fabricated log must pass all lanes; failed: {hard_failures:?}"
        );
        for lane in ["N0", "N1", "N2"] {
            let outcomes: Vec<&CheckOutcome> =
                eval.outcomes.iter().filter(|o| o.lane == lane).collect();
            assert!(!outcomes.is_empty(), "lane {lane} must produce outcomes");
            let failed: Vec<&str> = outcomes
                .iter()
                .filter(|o| !o.passed)
                .map(|o| o.id.as_str())
                .collect();
            assert!(
                failed.is_empty(),
                "lane {lane} must all pass; failed: {failed:?}"
            );
        }

        // The N1 and N2 verdicts come from the ctx facts, not from markers in
        // the log, so the negative case has to change what the node did: drop
        // every CE 132 frame it sent and the broadcast and forwarding duties
        // both go unmet.
        let mut silent = run_ctx;
        let n2 = silent
            .n2
            .as_mut()
            .expect("the fabricated run has an N2 lane");
        n2.nut_tickets
            .retain(|f| f.delivery != m2_scenario::ctx::TicketDelivery::Ce132);
        let eval = evaluate(&log, &silent, ALL_LANES);
        assert!(
            !eval.all_hard_passed,
            "a node that broadcast no CE 132 at all must fail the run"
        );
        let failed: Vec<&str> = eval
            .outcomes
            .iter()
            .filter(|o| o.lane == "N2" && !o.passed)
            .map(|o| o.id.as_str())
            .collect();
        assert!(
            failed
                .iter()
                .any(|id| id.contains("n2_proxy_duty_forwarded")),
            "the unforwarded ticket must be named: {failed:?}"
        );
    }
}
