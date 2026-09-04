//! Scenario evaluation for a run: the L0 checks against an observation log
//! and the deterministic dry-run baseline log.

use std::sync::{Arc, Mutex};

use jamnp_s::trace::Trace;
use m2_emu::emu::Emulator;
use m2_scenario::dsl::{Obs, ObsKind, ObsLog, Outcome, Scheduler, Severity};
use m2_scenario::scenarios::l0;

use crate::report::{CheckOutcome, Finding};

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

/// Run the L0 checks against `obs` and reduce to report outcomes + findings.
pub(crate) fn evaluate(obs: &ObsLog, reference_block_count: usize) -> Evaluation {
    let checks = l0::all(reference_block_count);
    let mut scheduler = Scheduler::new();
    let mut outcomes = Vec::new();
    let mut findings = Vec::new();
    let mut all_hard_passed = true;
    for check in &checks {
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
                    spec_citation: format!("L0 {}", check.id),
                    slot: None,
                    evidence: "traces/jamnp.bin".into(),
                    message: format!("{}: {}", check.id, result.name),
                });
            }
            outcomes.push(CheckOutcome {
                id: format!("{}.{}", check.id, result.name),
                lane: "L0".into(),
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
    Evaluation {
        outcomes,
        findings,
        all_hard_passed,
    }
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
    let mut push = |kind: ObsKind| {
        log.push(
            at,
            Obs {
                peer: l0::PEER_1,
                kind,
                at_ms: at,
            },
        );
        at += 10;
    };
    push(ObsKind::Accept);
    push(ObsKind::Other(CERT_ED25519));
    push(ObsKind::Other(CERT_KEY_MATCH));
    push(ObsKind::Other(CERT_SAN_OK));
    push(ObsKind::OpenUp0);
    push(ObsKind::Other(ALPN_ACCEPTED));
    push(ObsKind::Other(ALPN_OFFERED));
    push(ObsKind::Other(ALPN_BUILDER_OK));
    push(ObsKind::Other(NUT_INITIATED));
    push(ObsKind::Other(ENDPOINT_DIALED));
    push(ObsKind::Other(BUILDERS_ACCEPTED));
    push(ObsKind::Other(CE133_ON_BUILDER));
    push(ObsKind::Other(UP0_KIND0));
    push(ObsKind::Other(UP0_FINAL_GENESIS));
    push(ObsKind::Up0Announce);
    push(ObsKind::Other(REANNOUNCED));
    for _ in 0..reference_block_count {
        push(ObsKind::ServesCe128);
    }
    push(ObsKind::Other(CE128_FIN_BOTH));
    push(ObsKind::Other(CE128_MAX_RESPECTED));
    push(ObsKind::Other(CE129_SORTED));
    push(ObsKind::Other(CE129_BOUNDARY_ORDER));
    push(ObsKind::Other(CE129_SIZE_CAP));
    push(ObsKind::Other(CE129_LEN_PREFIXED));
    log
}
