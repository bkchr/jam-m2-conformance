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
/// wrong rather than only which assertion did (DESIGN.md §11 L1 asks for an
/// "M1-style diff report"). It is built only on failure and only where the
/// check has something useful to say, so most results carry `None`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckResult {
    pub name: &'static str,
    pub outcome: Outcome,
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
/// run alongside a sequence (DESIGN.md §5 "Extra checks").
pub mod log {
    use super::{CheckResult, Outcome, Severity};

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
            detail: None,
        }
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
                detail: None,
            }
        );
        assert_eq!(
            log::check("x", true, Severity::Hard),
            CheckResult {
                name: "x",
                outcome: Outcome::Pass,
                detail: None,
            }
        );
        assert_eq!(
            log::check("x", false, Severity::Soft),
            CheckResult {
                name: "x",
                outcome: Outcome::Fail(Severity::Soft),
                detail: None,
            }
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
