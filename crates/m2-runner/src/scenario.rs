//! Scenario evaluation for a run: the L0 checks against an observation log
//! and the deterministic dry-run baseline log.

use std::sync::{Arc, Mutex};

use jam_types::JAM_COMMON_ERA;
use jamnp_s::codec::ce131_136::Ticket as Ce131Ticket;
use jamnp_s::trace::Trace;
use m2_emu::emu::Emulator;
use m2_reference::chain::RefChain;
use m2_scenario::ctx::{
    DeliveredTicket, EmuTicket, ImportFact, L1Ctx, L2Ctx, NutBlock, NutTicketFacts, TicketDelivery,
    NUT_INDEX, SLOT_PERIOD_MS, TICKET_ARRIVAL_LEAD_MS,
};
use m2_scenario::dsl::{Check, Obs, ObsKind, ObsLog, Outcome, Scheduler, Severity};
use m2_scenario::scenarios::obs::{EMU_SENT_131, EMU_SENT_132, RECV_CE131, RECV_CE132};
use m2_scenario::scenarios::{l0, l1, l2};

use crate::report::{CheckOutcome, Finding};

/// Per-lane facts a run's scenario evaluation reads.
pub(crate) struct RunCtx {
    pub l0_reference_block_count: usize,
    /// Lowest emulated validator index: 1 only when the NUT is at index 0.
    pub l0_first_emu_peer: u16,
    pub l1: Option<L1Ctx>,
    pub l2: Option<L2Ctx>,
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
        _emu: Emulator,
    },
    /// Deterministic fabricated log + empty trace (dry-run).
    Fabricated { log: ObsLog, trace: Trace },
}

/// Run the L0/L1/L2 checks against `obs` and reduce to report outcomes +
/// findings. L1/L2 lanes fire only when their context is present.
pub(crate) fn evaluate(obs: &ObsLog, run_ctx: &RunCtx) -> Evaluation {
    let mut outcomes = Vec::new();
    let mut findings = Vec::new();
    let mut all_hard_passed = true;
    let mut lanes: Vec<(&str, Vec<Check>)> =
        vec![(
            "L0",
            l0::all(run_ctx.l0_reference_block_count, run_ctx.l0_first_emu_peer),
        )];
    if let Some(ctx) = &run_ctx.l1 {
        lanes.push(("L1", l1::all(ctx)));
    }
    if let Some(ctx) = &run_ctx.l2 {
        lanes.push(("L2", l2::all(ctx)));
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
                    message: format!("{}: {}", check.id, result.name),
                });
            }
            outcomes.push(CheckOutcome {
                id: format!("{}.{}", check.id, result.name),
                lane: lane.into(),
                severity: if soft { "soft" } else { "hard" }.into(),
                passed,
                soft,
                details: if passed {
                    "ok".into()
                } else {
                    format!("{result:?}")
                },
            });
        }
    }
    (outcomes, findings, all_hard_passed)
}

/// The deterministic conforming observation log the dry-run baseline reports
/// on: peer 1 exhibits every L0 contract event (codes 20..=40 plus the named
/// kinds) in an order that satisfies all nine checks.
pub(crate) fn fabricated_obs_log(reference_block_count: usize) -> ObsLog {
    use l0::{
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
    push(l0::PEER_1, ObsKind::Accept);
    push(l0::PEER_1, ObsKind::Other(CERT_ED25519));
    push(l0::PEER_1, ObsKind::Other(CERT_KEY_MATCH));
    push(l0::PEER_1, ObsKind::Other(CERT_SAN_OK));
    push(l0::PEER_1, ObsKind::OpenUp0);
    push(l0::PEER_1, ObsKind::Other(ALPN_ACCEPTED));
    push(l0::PEER_1, ObsKind::Other(ALPN_OFFERED));
    push(l0::PEER_1, ObsKind::Other(ALPN_BUILDER_OK));
    push(l0::PEER_1, ObsKind::Other(NUT_INITIATED));
    push(l0::PEER_1, ObsKind::Other(ENDPOINT_DIALED));
    push(l0::PEER_1, ObsKind::Other(BUILDERS_ACCEPTED));
    push(l0::PEER_1, ObsKind::Other(CE133_ON_BUILDER));
    push(l0::PEER_1, ObsKind::Other(UP0_KIND0));
    push(l0::PEER_1, ObsKind::Other(UP0_FINAL_GENESIS));
    push(l0::PEER_1, ObsKind::Up0Announce);
    push(l0::PEER_1, ObsKind::Other(REANNOUNCED));
    for _ in 0..reference_block_count {
        push(l0::PEER_1, ObsKind::ServesCe128);
    }
    push(l0::PEER_1, ObsKind::Other(CE128_FIN_BOTH));
    push(l0::PEER_1, ObsKind::Other(CE128_MAX_RESPECTED));
    push(l0::PEER_1, ObsKind::Other(CE129_SORTED));
    push(l0::PEER_1, ObsKind::Other(CE129_BOUNDARY_ORDER));
    push(l0::PEER_1, ObsKind::Other(CE129_SIZE_CAP));
    push(l0::PEER_1, ObsKind::Other(CE129_LEN_PREFIXED));
    // L1: the NUT announced an authored block.
    push(l0::PEER_1, ObsKind::AuthorsBlock);
    // L2: the NUT received its CE 131/132 ticket distributions and the
    // emulator's sends; the CE 132 broadcast reaches all five emulated peers.
    push(l0::PEER_1, ObsKind::Other(RECV_CE131));
    for peer in 1..=5u16 {
        push(peer, ObsKind::Other(RECV_CE132));
    }
    push(l0::PEER_1, ObsKind::Other(EMU_SENT_131));
    push(l0::PEER_1, ObsKind::Other(EMU_SENT_132));
    log
}

/// The deterministic conforming [`RunCtx`] for the dry-run baseline: the L1
/// lane is built around one real reference-authored NUT block (genuine header
/// and extrinsic types), with its import fact and delivered tickets matching
/// that block; the L2 lane carries a conforming emulator plan and verified NUT
/// ticket facts.
pub(crate) fn fabricated_run_ctx(
    reference_block_count: usize,
) -> Result<RunCtx, m2_reference::chain::ChainError> {
    let mut chain = RefChain::tiny(0)?;
    let start = chain.next_slot();
    let mut authored = None;
    for slot in start..start + 12 {
        if let Some(block) = chain.author_block(slot)? {
            authored = Some(block);
            break;
        }
    }
    let block = authored.ok_or_else(|| {
        m2_reference::chain::ChainError::Chain("no emulated slot to author in 12 slots".into())
    })?;

    let header_root = block.header.hash().0;
    let parent = block.header.parent.0;
    let slot = block.header.slot;
    let included_ids: Vec<[u8; 32]> = block.extrinsic.tickets.iter().map(|t| t.id().0).collect();
    let slot_start = JAM_COMMON_ERA * 1000 + slot as u64 * SLOT_PERIOD_MS;
    let l1 = L1Ctx {
        reference_best: parent,
        reference_block_hashes: vec![parent],
        nut_blocks: vec![NutBlock {
            block,
            announced_wall_ms: slot_start,
        }],
        imports: vec![ImportFact {
            header_root,
            ok: true,
            root: Some(header_root),
            error: None,
        }],
        delivered_tickets: included_ids
            .into_iter()
            .map(|id| DeliveredTicket {
                id,
                delivered_at_ms: slot_start - TICKET_ARRIVAL_LEAD_MS,
            })
            .collect(),
        slot_period_ms: SLOT_PERIOD_MS,
    };

    let emu = |id: u8, proxy: u16, delivery: TicketDelivery| EmuTicket {
        id: [id; 32],
        author: 1,
        attempt: 0,
        proof: [0u8; 784],
        proxy,
        valid: true,
        delivery,
        slot: 1,
    };
    let nut = |attempt: u8, peer: u16| NutTicketFacts {
        epoch: 3,
        ticket: Ce131Ticket {
            attempt,
            proof: [0u8; 784],
        },
        peer,
        verified: true,
        received_at_ms: 100,
    };
    let l2 = L2Ctx {
        target_epoch: 3,
        epoch_start_slot: 0,
        emu_plan: vec![
            emu(1, NUT_INDEX, TicketDelivery::Ce131),
            emu(2, 1, TicketDelivery::Ce132),
        ],
        nut_tickets: vec![nut(0, 1), nut(1, 2)],
        nut_block_ticket_ids: vec![[1u8; 32], [2u8; 32]],
        nut_block_slot: 12,
    };

    Ok(RunCtx {
        l0_reference_block_count: reference_block_count,
        // The fabricated log is written for a NUT at index 0.
        l0_first_emu_peer: l0::PEER_1,
        l1: Some(l1),
        l2: Some(l2),
    })
}

#[cfg(test)]
mod tests {
    use m2_scenario::scenarios::obs::RECV_CE132;

    use super::*;

    #[test]
    fn evaluate_reports_lanes() {
        let run_ctx = fabricated_run_ctx(3).expect("fabricated run ctx builds");
        let log = fabricated_obs_log(3);
        let eval = evaluate(&log, &run_ctx);

        assert!(eval.all_hard_passed, "fabricated log must pass all lanes");
        for lane in ["L0", "L1", "L2"] {
            let outcomes: Vec<&CheckOutcome> =
                eval.outcomes.iter().filter(|o| o.lane == lane).collect();
            assert!(!outcomes.is_empty(), "lane {lane} must produce outcomes");
            assert!(
                outcomes.iter().all(|o| o.passed),
                "lane {lane} must all pass"
            );
        }

        // L1 facts come from the ctx, not the log (every L1 check ignores
        // `obs`), so a log change cannot fail L1; strip instead the CE 132
        // distribution every L2 proxy/self-proxy check requires.
        let mut no_ce132 = ObsLog::new();
        for (t, o) in fabricated_obs_log(3).events() {
            if o.kind != ObsKind::Other(RECV_CE132) {
                no_ce132.push(*t, *o);
            }
        }
        let eval = evaluate(&no_ce132, &run_ctx);
        assert!(!eval.all_hard_passed, "missing CE 132 must fail the run");
        assert!(
            eval.outcomes.iter().any(|o| o.lane == "L2" && !o.passed),
            "L2 must have a failing outcome"
        );
    }
}
