//! Scenario DSL: hard-coded expected-answer sequences (DESIGN.md §5).
//!
//! The harness drives a node under test; every stimulus it sends has an
//! expected *answer* — a sequence of messages that must appear in the
//! observation log in response. Checks express those answers as a
//! subsequence of the log with event-relative timing windows, plus embedded
//! [`log::check`] assertions that run alongside the sequence.

/// How hard a failed expectation hits the scenario (DESIGN.md §5 "Severity").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    /// Fails the scenario outright.
    Hard,
    /// Reported only (timing-tolerance and "should" clauses).
    Soft,
}

/// The result of a check or an expectation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The expectation was met.
    Pass,
    /// The expectation was not met, at the given severity.
    Fail(Severity),
}

/// The kind of a NUT-side observation (DESIGN.md §5 "Expected-answer events").
///
/// An open enum: lanes extend it with payload-bearing variants and funnel
/// anything the generic DSL need not detail through [`ObsKind::Other`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ObsKind {
    Accept,
    OpenUp0,
    Up0Announce,
    ServesCe128,
    ServesCe129,
    SendsTickets,
    Ce134Msg1,
    Ce134Msg2,
    Ce135Report,
    ServesCe137,
    ServesCe148,
    Ce141Assurance,
    Ce142Announce,
    Ce143Request,
    Ce144Announce,
    Ce145Judgment,
    AuthorsBlock,
    ResetsStream,
    Ignores,
    StateRootMatches,
    /// Extension slot for lane-specific event kinds.
    Other(u8),
}

impl ObsKind {
    /// Stable numeric code for reporting; named kinds take `0..=19` and the
    /// extension slot reports its embedded code.
    pub fn code(&self) -> u8 {
        match self {
            ObsKind::Accept => 0,
            ObsKind::OpenUp0 => 1,
            ObsKind::Up0Announce => 2,
            ObsKind::ServesCe128 => 3,
            ObsKind::ServesCe129 => 4,
            ObsKind::SendsTickets => 5,
            ObsKind::Ce134Msg1 => 6,
            ObsKind::Ce134Msg2 => 7,
            ObsKind::Ce135Report => 8,
            ObsKind::ServesCe137 => 9,
            ObsKind::ServesCe148 => 10,
            ObsKind::Ce141Assurance => 11,
            ObsKind::Ce142Announce => 12,
            ObsKind::Ce143Request => 13,
            ObsKind::Ce144Announce => 14,
            ObsKind::Ce145Judgment => 15,
            ObsKind::AuthorsBlock => 16,
            ObsKind::ResetsStream => 17,
            ObsKind::Ignores => 18,
            ObsKind::StateRootMatches => 19,
            ObsKind::Other(n) => *n,
        }
    }

    /// Stable human-readable name for reporting.
    pub fn name(&self) -> &'static str {
        match self {
            ObsKind::Accept => "accept",
            ObsKind::OpenUp0 => "open_up0",
            ObsKind::Up0Announce => "up0_announce",
            ObsKind::ServesCe128 => "serves_ce128",
            ObsKind::ServesCe129 => "serves_ce129",
            ObsKind::SendsTickets => "sends_tickets",
            ObsKind::Ce134Msg1 => "ce134_msg1",
            ObsKind::Ce134Msg2 => "ce134_msg2",
            ObsKind::Ce135Report => "ce135_report",
            ObsKind::ServesCe137 => "serves_ce137",
            ObsKind::ServesCe148 => "serves_ce148",
            ObsKind::Ce141Assurance => "ce141_assurance",
            ObsKind::Ce142Announce => "ce142_announce",
            ObsKind::Ce143Request => "ce143_request",
            ObsKind::Ce144Announce => "ce144_announce",
            ObsKind::Ce145Judgment => "ce145_judgment",
            ObsKind::AuthorsBlock => "authors_block",
            ObsKind::ResetsStream => "resets_stream",
            ObsKind::Ignores => "ignores",
            ObsKind::StateRootMatches => "state_root_matches",
            ObsKind::Other(_) => "other",
        }
    }
}

/// A single observation: something the NUT did, from `peer`, at a time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Obs {
    pub peer: u16,
    pub kind: ObsKind,
    pub at_ms: u64,
}

/// The observation log: timestamped events in observation order.
#[derive(Default)]
pub struct ObsLog {
    records: Vec<(u64, Obs)>,
}

impl ObsLog {
    pub fn new() -> Self {
        ObsLog {
            records: Vec::new(),
        }
    }

    /// Record an observation at `at_ms` (milliseconds since scenario start).
    pub fn push(&mut self, at_ms: u64, obs: Obs) {
        self.records.push((at_ms, obs));
    }

    pub fn events(&self) -> &[(u64, Obs)] {
        &self.records
    }

    /// First record of `kind`, in observation order.
    pub fn first<K: Into<ObsKind>>(&self, kind: K) -> Option<&Obs> {
        let kind = kind.into();
        self.records
            .iter()
            .find(|(_, o)| o.kind == kind)
            .map(|(_, o)| o)
    }

    /// First record of `kind` from `peer`, in observation order.
    ///
    /// [`ObsLog::first`] ignores the peer, which is wrong for any per-connection
    /// decision: one peer's observation would answer for all of them.
    pub fn first_from<K: Into<ObsKind>>(&self, peer: u16, kind: K) -> Option<&Obs> {
        let kind = kind.into();
        self.records
            .iter()
            .find(|(_, o)| o.peer == peer && o.kind == kind)
            .map(|(_, o)| o)
    }

    /// Every peer with a record of `kind`, ascending and deduplicated.
    pub fn peers_with<K: Into<ObsKind>>(&self, kind: K) -> Vec<u16> {
        let kind = kind.into();
        let mut peers: Vec<u16> = self
            .records
            .iter()
            .filter(|(_, o)| o.kind == kind)
            .map(|(_, o)| o.peer)
            .collect();
        peers.sort_unstable();
        peers.dedup();
        peers
    }

    /// Last record of `kind`, in observation order.
    pub fn last<K: Into<ObsKind>>(&self, kind: K) -> Option<&Obs> {
        let kind = kind.into();
        self.records
            .iter()
            .rev()
            .find(|(_, o)| o.kind == kind)
            .map(|(_, o)| o)
    }

    /// Index of the next record at/after `from` matching `expected`'s peer+kind.
    pub fn matches(&self, expected: &Obs, from: usize) -> Option<usize> {
        self.records
            .iter()
            .enumerate()
            .skip(from)
            .find_map(|(i, (_, o))| {
                (o.peer == expected.peer && o.kind == expected.kind).then_some(i)
            })
    }
}

/// Predicate over the matched record: receives the whole log and the record's
/// index. Attached to an expectation with [`ExpectedObs::verify`].
pub type VerifyPred = dyn Fn(&ObsLog, usize) -> bool + Send + Sync;

/// One expected event in a [`expect_subseq`] sequence.
///
/// `window_ms` is measured from the previous matched event's timestamp (or
/// the start of the scan for the first expectation); `window_before` flips
/// the window to extend backward from that anchor. The default window
/// (`u64::MAX`) never expires.
pub struct ExpectedObs {
    pub peer: u16,
    pub kind: ObsKind,
    pub window_ms: u64,
    pub window_before: bool,
    pub verify: Option<Box<VerifyPred>>,
}

impl ExpectedObs {
    /// A never-expiring expectation on `kind` from `peer`.
    pub fn new(peer: u16, kind: ObsKind) -> Self {
        ExpectedObs {
            peer,
            kind,
            window_ms: u64::MAX,
            window_before: false,
            verify: None,
        }
    }

    /// Constrain the match to `ms` after the previous matched event (or start).
    pub fn within(mut self, ms: u64) -> Self {
        self.window_ms = ms;
        self.window_before = false;
        self
    }

    /// Require `pred` to hold on the matched record (given the whole log and
    /// the record's index).
    pub fn verify(mut self, pred: impl Fn(&ObsLog, usize) -> bool + Send + Sync + 'static) -> Self {
        self.verify = Some(Box::new(pred));
        self
    }
}

/// The outcome of a subsequence match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MatchResult {
    /// Number of expected events matched (a prefix of `expected`).
    pub matched_to: usize,
    /// Index of the last matched record, if any.
    pub last_index: Option<usize>,
    /// `Pass` when every expectation matched; otherwise `Fail(severity)`.
    pub outcome: Outcome,
}

impl MatchResult {
    pub fn passed(&self) -> bool {
        self.outcome == Outcome::Pass
    }
}

/// Match `expected` as a subsequence of `log`, starting the search at `from`.
///
/// Each expectation is matched at the first record at index `>= cursor`
/// (where `cursor` is the previous match's index + 1, or `from`) whose
/// peer+kind match and whose `verify` predicate (if any) passes, within its
/// timing window. Windows are measured from the previous matched record's
/// timestamp — or, for the first expectation, the timestamp of the record at
/// `from`; a window of `u64::MAX` (the default) never expires. Records in
/// between are allowed and recorded, they just do not count towards the
/// check.
///
/// Fails [`Severity::Hard`] when a required event never appears within its
/// window, when it appears in the wrong order, or when a matching record
/// fails its `verify` predicate. With `soft_timing` set, a failure that is
/// *purely* a window expiry — the event appeared too late (or never) rather
/// than out of order or failing its predicate — is reported as
/// [`Severity::Soft`].
pub fn expect_subseq(
    log: &ObsLog,
    from: usize,
    expected: &[ExpectedObs],
    soft_timing: bool,
) -> MatchResult {
    let events = log.events();
    let from = from.min(events.len());
    let mut cursor = from;
    let mut last_index: Option<usize> = None;
    let mut matched_to = 0;

    for (i, exp) in expected.iter().enumerate() {
        // Time anchor: the previous matched record, or the start of the scan.
        let anchor_ms = last_index
            .map(|prev| events[prev].0)
            .or_else(|| events.get(from).map(|(t, _)| *t))
            .unwrap_or(0);

        // Find the first in-window record with matching peer+kind that passes
        // the verify predicate. Out-of-window and non-matching records are
        // skipped (the log is scanned in observation order, so a forward
        // window only ever narrows the tail).
        let mut verify_failed = false;
        let mut found = None;
        for (j, (t, rec)) in events.iter().enumerate().skip(cursor) {
            let in_window = if exp.window_before {
                *t >= anchor_ms.saturating_sub(exp.window_ms) && *t <= anchor_ms
            } else {
                *t <= anchor_ms.saturating_add(exp.window_ms)
            };
            if !in_window || rec.peer != exp.peer || rec.kind != exp.kind {
                continue;
            }
            let passes = exp.verify.as_ref().is_none_or(|f| f(log, j));
            if passes {
                found = Some(j);
                break;
            }
            verify_failed = true;
        }

        match found {
            Some(j) => {
                cursor = j + 1;
                last_index = Some(j);
                matched_to = i + 1;
            }
            None => {
                // Hard: the event appeared before the cursor (ordering
                // violation) or a matching record failed its predicate.
                // Soft: a pure window expiry.
                let too_early = events[from..cursor]
                    .iter()
                    .any(|(_, rec)| rec.peer == exp.peer && rec.kind == exp.kind);
                let severity = if !soft_timing || verify_failed || too_early {
                    Severity::Hard
                } else {
                    Severity::Soft
                };
                return MatchResult {
                    matched_to,
                    last_index,
                    outcome: Outcome::Fail(severity),
                };
            }
        }
    }

    MatchResult {
        matched_to,
        last_index,
        outcome: Outcome::Pass,
    }
}

/// A check body: runs against the observation log and produces its results.
pub type CheckRun = dyn Fn(&ObsLog) -> Vec<CheckResult> + Send + Sync;

/// A named scenario check: a closure over the observation log producing
/// [`CheckResult`]s (DESIGN.md §5).
pub struct Check {
    pub id: &'static str,
    pub severity: Severity,
    pub run: Box<CheckRun>,
}

/// One assertion within a check.
///
/// `detail` carries the values behind a failure — the two state roots that
/// disagreed, the ticket ids that were owed — so a finding says what went
/// wrong rather than only which assertion did (DESIGN.md §11 N1 asks for an
/// "M1-style diff report"). It is built only on failure and only where the
/// check has something useful to say, so most results carry `None`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckResult {
    pub name: &'static str,
    pub outcome: Outcome,
    /// What a failure of *this* row would have cost.
    ///
    /// `Outcome::Fail` carries it too, and for a failure the two agree. The
    /// field exists for the passing case, which otherwise says nothing about
    /// its own severity and left the reporter to fall back on the parent
    /// `Check`'s. A soft row under a hard check then printed as `hard` on the
    /// runs where it passed, which reads as a guarantee the harness does not
    /// make -- `n2_gen_proxy_matches_rule` is soft precisely because the rule
    /// it grades may not be normative (DESIGN §12 question 9).
    pub severity: Severity,
    pub detail: Option<String>,
}

/// Build a [`Check`] from an id, its fail severity, and the check closure.
pub fn check(
    id: &'static str,
    severity: Severity,
    run: impl Fn(&ObsLog) -> Vec<CheckResult> + Send + Sync + 'static,
) -> Check {
    Check {
        id,
        severity,
        run: Box::new(run),
    }
}

/// Embedded `log::check` assertions: plain pass/fail on the observation log,
/// Evidence that the node was doing the positive thing a negative check
/// depends on.
///
/// A rule of the form "the node must **not** do X" is satisfied by a node
/// that does nothing at all: a run where no ticket was forwarded passes every
/// must-not-forward check, and one where no block was authored passes every
/// must-not-include check. Reporting those as passes claims coverage the run
/// did not have, which is the half of the N0 audit that found checks which
/// were passing and could not fail.
///
/// So a negative check is reported only alongside the control that makes it
/// mean something. Where the control is absent the run says the rule was not
/// exercised, which is what it knows, and [`log::negative`] emits
/// [`Control::absent_row`] in place of the check.
///
/// Roughly half the DESIGN §11 catalogue across N2–N7 is fault injection, and
/// every one of those lanes needs this gate, which is why it lives here and
/// not in a lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Control {
    absent_row: &'static str,
    evidence: &'static str,
    present: bool,
}

impl Control {
    /// `absent_row` is the row reported when the control is missing, and
    /// `evidence` completes the sentence "the run never showed …", so it
    /// reads as a noun phrase: "a ticket the NUT forwarded to every peer".
    pub const fn new(absent_row: &'static str, evidence: &'static str, present: bool) -> Self {
        Self {
            absent_row,
            evidence,
            present,
        }
    }

    /// Whether the positive evidence was there.
    pub const fn present(&self) -> bool {
        self.present
    }

    /// The row reported in place of a gated check when it was not.
    pub const fn absent_row(&self) -> &'static str {
        self.absent_row
    }

    /// What the run would have had to show.
    pub const fn evidence(&self) -> &'static str {
        self.evidence
    }

    /// The soft "not exercised" row reported in place of the gated check.
    ///
    /// [`log::negative`] emits this itself, and a lane with one row to gate
    /// never needs it. A lane that judges one row *per* injected fault does:
    /// when the control is missing there may also be nothing to loop over, so
    /// `negative` is never reached and the absence would go unreported. Such a
    /// lane branches on [`Control::present`] and emits this once.
    pub fn absent(&self, name: &'static str) -> CheckResult {
        let evidence = self.evidence;
        log::check_detail(self.absent_row, false, Severity::Soft, || {
            format!(
                "`{name}` asks what the node did not do, and the run never showed \
                 {evidence}, so a pass would claim coverage it did not have"
            )
        })
    }
}

/// run alongside a sequence (DESIGN.md §5 "Extra checks").
pub mod log {
    use super::{CheckResult, Control, Outcome, Severity};

    /// A standalone assertion result: `Pass` when `pass`, else `Fail(severity)`.
    pub fn check(name: &'static str, pass: bool, severity: Severity) -> CheckResult {
        let outcome = if pass {
            Outcome::Pass
        } else {
            Outcome::Fail(severity)
        };
        CheckResult {
            name,
            outcome,
            severity,
            detail: None,
        }
    }

    /// A negative assertion — "the node must **not** do X" — reported only
    /// where `control` shows the node was doing the corresponding positive
    /// thing in the same run.
    ///
    /// `held` is whether the prohibition held. With the control present this
    /// is an ordinary [`check_detail`]; without it, the result is a soft
    /// failure named [`Control::absent_row`], because a silent node must not
    /// collect passes for the rules it never came near. See [`Control`].
    pub fn negative(
        name: &'static str,
        control: &Control,
        held: bool,
        severity: Severity,
        detail: impl FnOnce() -> String,
    ) -> CheckResult {
        if !control.present() {
            return control.absent(name);
        }
        check_detail(name, held, severity, detail)
    }

    /// [`check`], plus a detail string describing *why* it failed.
    ///
    /// `detail` runs only on failure, so a check may format hashes or ticket
    /// ids there without paying for it on the passing path.
    pub fn check_detail(
        name: &'static str,
        pass: bool,
        severity: Severity,
        detail: impl FnOnce() -> String,
    ) -> CheckResult {
        if pass {
            return check(name, pass, severity);
        }
        CheckResult {
            name,
            outcome: Outcome::Fail(severity),
            severity,
            detail: Some(detail()),
        }
    }
}

/// Minimal event-driven scheduler (P0).
///
/// The full scheduler — dependency ordering, fail-fast, triggers, at-slot
/// pinning — arrives with the runner (T13); for now it just runs a check's
/// closure against the observation log.
#[derive(Default)]
pub struct Scheduler {}

impl Scheduler {
    pub fn new() -> Self {
        Scheduler {}
    }

    /// Run `check` against `obs`, returning its results.
    pub fn fire(&mut self, check: &Check, obs: &ObsLog) -> Vec<CheckResult> {
        (check.run)(obs)
    }

    /// Declare that `_check` only fires after `_on` has run.
    ///
    /// The dependency graph is added with the runner; a no-op for now.
    pub fn depends_on(&mut self, _check: &'static str, _on: &'static str) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(peer: u16, kind: ObsKind, at_ms: u64) -> Obs {
        Obs { peer, kind, at_ms }
    }

    #[test]
    fn subsequence_allows_inbetween_messages() {
        let mut obs = ObsLog::new();
        obs.push(10, ev(1, ObsKind::Accept, 10));
        obs.push(20, ev(2, ObsKind::Up0Announce, 20));
        obs.push(25, ev(1, ObsKind::SendsTickets, 25));
        obs.push(30, ev(3, ObsKind::Ce134Msg1, 30));
        obs.push(35, ev(2, ObsKind::AuthorsBlock, 35));
        obs.push(40, ev(4, ObsKind::Ce135Report, 40));

        let expected = [
            ExpectedObs::new(2, ObsKind::Up0Announce),
            ExpectedObs::new(3, ObsKind::Ce134Msg1),
            ExpectedObs::new(4, ObsKind::Ce135Report),
        ];

        let res = expect_subseq(&obs, 0, &expected, false);

        assert_eq!(
            res,
            MatchResult {
                matched_to: 3,
                last_index: Some(5),
                outcome: Outcome::Pass
            }
        );
        let i0 = obs.matches(&ev(2, ObsKind::Up0Announce, 0), 0).unwrap();
        let i1 = obs.matches(&ev(3, ObsKind::Ce134Msg1, 0), 0).unwrap();
        let i2 = obs.matches(&ev(4, ObsKind::Ce135Report, 0), 0).unwrap();
        assert!(i0 < i1 && i1 < i2, "matched indexes must be in order");
    }

    #[test]
    fn subsequence_enforces_order() {
        let mut obs = ObsLog::new();
        obs.push(10, ev(3, ObsKind::Ce134Msg1, 10));
        obs.push(20, ev(4, ObsKind::Ce135Report, 20));

        let expected = [
            ExpectedObs::new(4, ObsKind::Ce135Report),
            ExpectedObs::new(3, ObsKind::Ce134Msg1),
        ];

        let res = expect_subseq(&obs, 0, &expected, false);

        assert_eq!(res.matched_to, 1);
        assert_eq!(res.outcome, Outcome::Fail(Severity::Hard));
        // Ordering violations are hard even with soft timing.
        let res_soft = expect_subseq(&obs, 0, &expected, true);
        assert_eq!(res_soft.outcome, Outcome::Fail(Severity::Hard));
    }

    #[test]
    fn window_expiry_fails_hard() {
        let mut obs = ObsLog::new();
        obs.push(0, ev(2, ObsKind::Up0Announce, 0));
        obs.push(200, ev(3, ObsKind::Ce134Msg1, 200));

        let expected = [
            ExpectedObs::new(2, ObsKind::Up0Announce),
            ExpectedObs::new(3, ObsKind::Ce134Msg1).within(50),
        ];

        let res = expect_subseq(&obs, 0, &expected, false);

        assert_eq!(res.matched_to, 1);
        assert_eq!(res.outcome, Outcome::Fail(Severity::Hard));
    }

    #[test]
    fn window_expiry_soft_when_soft_timing() {
        let mut obs = ObsLog::new();
        obs.push(0, ev(2, ObsKind::Up0Announce, 0));
        obs.push(200, ev(3, ObsKind::Ce134Msg1, 200));

        let expected = [
            ExpectedObs::new(2, ObsKind::Up0Announce),
            ExpectedObs::new(3, ObsKind::Ce134Msg1).within(50),
        ];

        let res = expect_subseq(&obs, 0, &expected, true);

        assert_eq!(res.matched_to, 1);
        assert_eq!(res.outcome, Outcome::Fail(Severity::Soft));
    }

    #[test]
    fn verify_predicate_fails() {
        let mut obs = ObsLog::new();
        obs.push(10, ev(3, ObsKind::Up0Announce, 10));

        let expected =
            [ExpectedObs::new(3, ObsKind::Up0Announce)
                .verify(|obs, i| obs.events()[i].1.peer == 5)];

        // A verify rejection is hard even with soft timing.
        let res = expect_subseq(&obs, 0, &expected, true);

        assert_eq!(res.outcome, Outcome::Fail(Severity::Hard));
    }

    #[test]
    fn log_check_hard_and_soft() {
        assert_eq!(
            log::check("x", false, Severity::Hard),
            CheckResult {
                name: "x",
                outcome: Outcome::Fail(Severity::Hard),
                severity: Severity::Hard,
                detail: None,
            }
        );
        assert_eq!(
            log::check("x", true, Severity::Hard),
            CheckResult {
                name: "x",
                outcome: Outcome::Pass,
                severity: Severity::Hard,
                detail: None,
            }
        );
        assert_eq!(
            log::check("x", false, Severity::Soft),
            CheckResult {
                name: "x",
                outcome: Outcome::Fail(Severity::Soft),
                severity: Severity::Soft,
                detail: None,
            }
        );
    }

    /// The point of the whole mechanism: a node that did nothing collects no
    /// passes for the rules it never came near.
    #[test]
    fn a_negative_check_without_its_control_is_not_a_pass() {
        let absent = Control::new("x_control_absent", "a ticket it forwarded", false);

        // `held` is true -- the prohibition was not violated -- and it still
        // must not pass, because nothing happened that could have violated it.
        let r = log::negative("x_not_forwarded", &absent, true, Severity::Hard, || {
            unreachable!("the gated detail is not built when the control is absent")
        });

        assert_eq!(r.name, "x_control_absent");
        assert_eq!(r.outcome, Outcome::Fail(Severity::Soft));
        assert_eq!(
            r.severity,
            Severity::Soft,
            "an unexercised rule is not a hard failure"
        );
        let detail = r.detail.expect("the absent control explains itself");
        assert!(
            detail.contains("x_not_forwarded"),
            "it names the gated check: {detail}"
        );
        assert!(
            detail.contains("a ticket it forwarded"),
            "and the missing evidence: {detail}"
        );
    }

    /// With the control present it is an ordinary check, at its own severity,
    /// and it can still fail.
    #[test]
    fn a_negative_check_with_its_control_is_judged_normally() {
        let present = Control::new("x_control_absent", "a ticket it forwarded", true);

        let held = log::negative("x_not_forwarded", &present, true, Severity::Hard, || {
            unreachable!("no detail is built for a check that held")
        });
        assert_eq!(held.name, "x_not_forwarded");
        assert_eq!(held.outcome, Outcome::Pass);
        assert_eq!(held.severity, Severity::Hard);

        let broken = log::negative("x_not_forwarded", &present, false, Severity::Hard, || {
            "it forwarded a ticket it was meant to refuse".into()
        });
        assert_eq!(broken.name, "x_not_forwarded");
        assert_eq!(broken.outcome, Outcome::Fail(Severity::Hard));
        assert_eq!(
            broken.detail.as_deref(),
            Some("it forwarded a ticket it was meant to refuse")
        );
    }

    /// A passing row still says what its failure would have cost.
    ///
    /// The reporter reads this rather than the parent `Check`'s severity, so
    /// a soft row under a hard check must not print as hard just because it
    /// passed -- that reads as a guarantee the harness does not make.
    #[test]
    fn a_passing_result_keeps_its_own_severity() {
        assert_eq!(
            log::check("x", true, Severity::Soft).severity,
            Severity::Soft
        );
        assert_eq!(
            log::check("x", true, Severity::Hard).severity,
            Severity::Hard
        );
        assert_eq!(
            log::check_detail("x", true, Severity::Soft, || unreachable!()).severity,
            Severity::Soft
        );
    }

    /// A detail is built only on failure, and reaches the result verbatim.
    #[test]
    fn log_check_detail_only_on_failure() {
        let passed = log::check_detail("x", true, Severity::Hard, || {
            panic!("detail must not be built for a passing check")
        });
        assert_eq!(passed.outcome, Outcome::Pass);
        assert_eq!(passed.detail, None);

        let failed = log::check_detail("x", false, Severity::Hard, || "roots differ".to_string());
        assert_eq!(failed.outcome, Outcome::Fail(Severity::Hard));
        assert_eq!(failed.detail.as_deref(), Some("roots differ"));
    }

    #[test]
    fn first_last_filters_by_kind() {
        let mut obs = ObsLog::new();
        obs.push(5, ev(1, ObsKind::Accept, 5));
        obs.push(10, ev(2, ObsKind::Up0Announce, 10));
        obs.push(15, ev(3, ObsKind::SendsTickets, 15));
        obs.push(20, ev(2, ObsKind::Up0Announce, 20));
        obs.push(25, ev(4, ObsKind::Ce135Report, 25));

        assert_eq!(obs.first(ObsKind::Up0Announce).map(|o| o.at_ms), Some(10));
        assert_eq!(obs.first(ObsKind::Up0Announce).map(|o| o.peer), Some(2));
        assert_eq!(obs.last(ObsKind::Up0Announce).map(|o| o.at_ms), Some(20));
        assert_eq!(obs.last(ObsKind::Up0Announce).map(|o| o.peer), Some(2));
        assert_eq!(obs.first(ObsKind::Ce134Msg1), None);
    }

    #[test]
    fn check_returns_results() {
        let c = check("t", Severity::Hard, |_| {
            vec![
                log::check("a", true, Severity::Hard),
                log::check("b", false, Severity::Hard),
            ]
        });
        let mut sched = Scheduler::new();
        let obs = ObsLog::new();

        let results = sched.fire(&c, &obs);

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].outcome, Outcome::Pass);
        assert_eq!(results[1].outcome, Outcome::Fail(Severity::Hard));
    }
}
