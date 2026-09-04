//! L0 — connectivity and sync (DESIGN.md §11 L0).
//!
//! Nine checks covering the L0 table rows, written with the [`dsl`] scenario
//! DSL. Each is a [`dsl::Check`] whose body reads the `m2-emu` observation log
//! and returns [`dsl::CheckResult`]s: an expected-answer subsequence plus
//! embedded [`dsl::log`] assertions.
//!
//! # Observation contract
//!
//! The `m2-emu` log records [`dsl::Obs`] events keyed by the emulated peer
//! (indices `1..=5`; the NUT is index `0`). Beyond the named [`dsl::ObsKind`]
//! events, this lane uses the [`dsl::ObsKind::Other`] extension slot for the
//! L0 detail observations the emulator emits (`code()` values below). The
//! runner wires the emulator to emit them.
//!
//! | code | meaning |
//! |------|---------|
//! | 20 | NUT cert verified: Ed25519 signature algorithm |
//! | 21 | NUT cert verified: key equals the on-chain key |
//! | 22 | NUT cert verified: exactly one SAN `e`+base32 |
//! | 23 | NUT accepted ALPN `jamnp-s/1/<8hex>` |
//! | 24 | NUT offered `jamnp-s/1/<8hex>` when initiating |
//! | 25 | `/builder` ALPN accepted on the accept side |
//! | 26 | ALPN mismatch (wrong version/nibbles) → handshake failed |
//! | 27 | NUT dialed the exact metadata address+port |
//! | 28 | ≥20 `/builder` connections accepted (soft) |
//! | 29 | CE 133 accepted on a builder connection |
//! | 30 | UP 0 stream kind byte 0 |
//! | 31 | UP 0 handshake Final == genesis |
//! | 32 | duplicate UP 0 → greatest stream id kept, other reset |
//! | 33 | CE 128 response: both halves FIN |
//! | 34 | CE 128 response: ≤ Max blocks |
//! | 35 | CE 129 keys sorted |
//! | 36 | CE 129 boundary nodes parent-before-child |
//! | 37 | CE 129 size cap respected |
//! | 38 | CE 129 `len++` values |
//! | 39 | NUT initiated a connection (preferred-initiator) |
//! | 40 | NUT re-announced a learned block |

use crate::dsl::{self, check, log, Check, CheckResult, ExpectedObs, ObsKind, Severity};

/// The first emulated peer (the L0 reference server for CE 128/129).
pub const PEER_1: u16 = 1;

pub const CERT_ED25519: u8 = 20;
pub const CERT_KEY_MATCH: u8 = 21;
pub const CERT_SAN_OK: u8 = 22;
pub const ALPN_ACCEPTED: u8 = 23;
pub const ALPN_OFFERED: u8 = 24;
pub const ALPN_BUILDER_OK: u8 = 25;
pub const ALPN_MISMATCH: u8 = 26;
pub const ENDPOINT_DIALED: u8 = 27;
pub const BUILDERS_ACCEPTED: u8 = 28;
pub const CE133_ON_BUILDER: u8 = 29;
pub const UP0_KIND0: u8 = 30;
pub const UP0_FINAL_GENESIS: u8 = 31;
pub const UP0_DUP_RESET: u8 = 32;
pub const CE128_FIN_BOTH: u8 = 33;
pub const CE128_MAX_RESPECTED: u8 = 34;
pub const CE129_SORTED: u8 = 35;
pub const CE129_BOUNDARY_ORDER: u8 = 36;
pub const CE129_SIZE_CAP: u8 = 37;
pub const CE129_LEN_PREFIXED: u8 = 38;
pub const NUT_INITIATED: u8 = 39;
pub const REANNOUNCED: u8 = 40;

/// TLS cert `simple.md:7-23`: Ed25519 cert, key == on-chain key, exactly one
/// SAN `e`+base32; a bad cert closes the connection.
pub fn tls_cert() -> Check {
    check("tls_cert", Severity::Hard, |obs| {
        let mut results = vec![
            log::check(
                "tls_cert_ed25519_sig_alg",
                obs.first(ObsKind::Other(CERT_ED25519)).is_some(),
                Severity::Hard,
            ),
            log::check(
                "tls_cert_key_matches_onchain",
                obs.first(ObsKind::Other(CERT_KEY_MATCH)).is_some(),
                Severity::Hard,
            ),
            log::check(
                "tls_cert_single_san_e_base32",
                obs.first(ObsKind::Other(CERT_SAN_OK)).is_some(),
                Severity::Hard,
            ),
        ];
        let seq = dsl::expect_subseq(
            obs,
            0,
            &[ExpectedObs::new(PEER_1, ObsKind::OpenUp0).within(8000)],
            false,
        );
        results.push(CheckResult {
            name: "tls_cert_connection_established",
            outcome: seq.outcome,
        });
        results
    })
}

/// ALPN `simple.md:48-59`: NUT accepts `jamnp-s/1/<8hex>` and offers it when
/// initiating; `/builder` accepted on the accept side; wrong version/nibbles
/// → handshake fails.
pub fn alpn() -> Check {
    check("alpn", Severity::Hard, |obs| {
        let mut results = vec![
            log::check(
                "alpn_version1_accepted",
                obs.first(ObsKind::Other(ALPN_ACCEPTED)).is_some(),
                Severity::Hard,
            ),
            log::check(
                "alpn_offered_when_initiating",
                obs.first(ObsKind::Other(ALPN_OFFERED)).is_some(),
                Severity::Hard,
            ),
            log::check(
                "alpn_builder_suffix_accepted",
                obs.first(ObsKind::Other(ALPN_BUILDER_OK)).is_some(),
                Severity::Hard,
            ),
        ];
        let mismatched = obs.first(ObsKind::Other(ALPN_MISMATCH)).is_some();
        results.push(log::check(
            "alpn_wrong_version_rejected",
            !mismatched || obs.first(ObsKind::OpenUp0).is_none(),
            Severity::Hard,
        ));
        results
    })
}

/// Preferred initiator `simple.md:70-80`: the NUT initiates where preferred
/// within the ~5 s grace, then the other side connects anyway (soft).
///
/// Which emulated peers the NUT is preferred toward depends on the key set
/// (with trivial keys, the NUT index matters), so the observation is matched
/// on *any* emulated peer.
pub fn preferred_initiator() -> Check {
    check("preferred_initiator", Severity::Hard, |obs| {
        vec![log::check(
            "nut_initiates_within_grace",
            obs.first(ObsKind::Other(NUT_INITIATED)).is_some(),
            Severity::Soft,
        )]
    })
}

/// Endpoint decoding `simple.md:66-68`: the NUT dials the exact IPv6/port from
/// the validator metadata.
pub fn endpoint_decoding() -> Check {
    check("endpoint_decoding", Severity::Hard, |obs| {
        vec![log::check(
            "endpoint_dialed_exact_addr",
            obs.first(ObsKind::Other(ENDPOINT_DIALED)).is_some(),
            Severity::Hard,
        )]
    })
}

/// Builder slots `simple.md:82-84`: ≥20 `/builder` connections accepted (soft);
/// CE 133 accepted on any connection.
pub fn builder_slots() -> Check {
    check("builder_slots", Severity::Hard, |obs| {
        vec![
            log::check(
                "builder_slots_ge_20",
                obs.first(ObsKind::Other(BUILDERS_ACCEPTED)).is_some(),
                Severity::Soft,
            ),
            log::check(
                "ce133_accepted_on_builder",
                obs.first(ObsKind::Other(CE133_ON_BUILDER)).is_some(),
                Severity::Hard,
            ),
        ]
    })
}

/// UP 0 handshake `simple.md:192-236`: kind byte 0, `u32 LE` framing,
/// handshake Final = genesis. Duplicate UP 0 handling (greatest stream id
/// kept) is a robustness fault exercised by the L7 lane, not the L0 happy path.
pub fn up0_handshake() -> Check {
    check("up0_handshake", Severity::Hard, |obs| {
        vec![
            log::check(
                "up0_kind_byte_0",
                obs.first(ObsKind::Other(UP0_KIND0)).is_some(),
                Severity::Hard,
            ),
            log::check(
                "up0_final_is_genesis",
                obs.first(ObsKind::Other(UP0_FINAL_GENESIS)).is_some(),
                Severity::Hard,
            ),
        ]
    })
}

/// UP 0 announce `simple.md:207-212`: an emulated author announces within
/// 500 ms; the NUT re-announces every block it learns or authors. The NUT's
/// re-announce arrives on whichever peer it is connected to, so both
/// observations are matched on any emulated peer.
pub fn up0_announce() -> Check {
    check("up0_announce", Severity::Hard, |obs| {
        vec![
            log::check(
                "emulated_author_announces",
                obs.first(ObsKind::Up0Announce).is_some(),
                Severity::Hard,
            ),
            log::check(
                "nut_reannounces_learned_block",
                obs.first(ObsKind::Other(REANNOUNCED)).is_some(),
                Severity::Hard,
            ),
        ]
    })
}

/// CE 128 serve `simple.md:238-265`: ascending-exclusive from genesis equals
/// the reference chain (the NUT fetched every reference block — `reference_
/// block_count` serves observed across all emulated peers; the runner
/// cross-checks the bytes against the trace), ≤ Max, both halves FIN; unknown
/// hash → reset (soft).
pub fn ce128_serve(reference_block_count: usize) -> Check {
    check("ce128_serve", Severity::Hard, move |obs| {
        let served = obs
            .events()
            .iter()
            .filter(|(_, o)| o.kind == ObsKind::ServesCe128)
            .count();
        vec![
            log::check(
                "ce128_ascending_covers_reference",
                served >= reference_block_count,
                Severity::Hard,
            ),
            log::check(
                "ce128_both_halves_fin",
                obs.first(ObsKind::Other(CE128_FIN_BOTH)).is_some(),
                Severity::Hard,
            ),
            log::check(
                "ce128_respects_max",
                obs.first(ObsKind::Other(CE128_MAX_RESPECTED)).is_some(),
                Severity::Hard,
            ),
        ]
    })
}

/// CE 129 serve `simple.md:267-303`: sorted 31-byte keys, boundary nodes
/// parent-before-child, size cap, `len++` values.
pub fn ce129_serve() -> Check {
    check("ce129_serve", Severity::Hard, |obs| {
        vec![
            log::check(
                "ce129_keys_sorted",
                obs.first(ObsKind::Other(CE129_SORTED)).is_some(),
                Severity::Hard,
            ),
            log::check(
                "ce129_boundary_parent_before_child",
                obs.first(ObsKind::Other(CE129_BOUNDARY_ORDER)).is_some(),
                Severity::Hard,
            ),
            log::check(
                "ce129_size_cap",
                obs.first(ObsKind::Other(CE129_SIZE_CAP)).is_some(),
                Severity::Hard,
            ),
            log::check(
                "ce129_len_prefixed_values",
                obs.first(ObsKind::Other(CE129_LEN_PREFIXED)).is_some(),
                Severity::Hard,
            ),
        ]
    })
}

/// All nine L0 checks in dependency order (L0 first; later lanes build on it).
pub fn all(reference_block_count: usize) -> Vec<Check> {
    vec![
        tls_cert(),
        alpn(),
        preferred_initiator(),
        endpoint_decoding(),
        builder_slots(),
        up0_handshake(),
        up0_announce(),
        ce128_serve(reference_block_count),
        ce129_serve(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsl::{Obs, ObsLog, Outcome};

    fn ev(peer: u16, kind: ObsKind, at_ms: u64) -> Obs {
        Obs { peer, kind, at_ms }
    }
    fn run(c: &Check, obs: &ObsLog) -> Vec<CheckResult> {
        (c.run)(obs)
    }

    fn all_pass(results: &[CheckResult]) -> bool {
        results.iter().all(|r| r.outcome == Outcome::Pass)
    }

    #[test]
    fn tls_cert_pass_and_fail() {
        let mut obs = ObsLog::new();
        obs.push(0, ev(1, ObsKind::Accept, 0));
        obs.push(10, ev(1, ObsKind::Other(CERT_ED25519), 10));
        obs.push(20, ev(1, ObsKind::Other(CERT_KEY_MATCH), 20));
        obs.push(30, ev(1, ObsKind::Other(CERT_SAN_OK), 30));
        obs.push(40, ev(1, ObsKind::OpenUp0, 40));
        assert!(all_pass(&run(&tls_cert(), &obs)), "conforming log passes");

        let mut bad = ObsLog::new();
        bad.push(0, ev(1, ObsKind::Accept, 0));
        bad.push(10, ev(1, ObsKind::Other(CERT_ED25519), 10));
        bad.push(20, ev(1, ObsKind::Other(CERT_KEY_MATCH), 20));
        bad.push(40, ev(1, ObsKind::OpenUp0, 40)); // no CERT_SAN_OK
        let results = run(&tls_cert(), &bad);
        assert!(
            results
                .iter()
                .any(|r| r.name == "tls_cert_single_san_e_base32"
                    && r.outcome == Outcome::Fail(Severity::Hard)),
            "missing SAN observation fails hard"
        );
    }

    #[test]
    fn alpn_pass_and_fail() {
        let mut obs = ObsLog::new();
        obs.push(0, ev(1, ObsKind::Other(ALPN_ACCEPTED), 0));
        obs.push(10, ev(1, ObsKind::Other(ALPN_OFFERED), 10));
        obs.push(20, ev(1, ObsKind::Other(ALPN_BUILDER_OK), 20));
        assert!(all_pass(&run(&alpn(), &obs)), "conforming log passes");

        let bad = ObsLog::new(); // nothing observed
        let results = run(&alpn(), &bad);
        assert!(
            results.iter().any(|r| r.name == "alpn_version1_accepted"
                && r.outcome == Outcome::Fail(Severity::Hard)),
            "missing ALPN acceptance fails hard"
        );
    }

    #[test]
    fn preferred_initiator_soft_on_never() {
        let mut obs = ObsLog::new();
        obs.push(1000, ev(1, ObsKind::Other(NUT_INITIATED), 1000)); // within 5 s grace
        assert!(all_pass(&run(&preferred_initiator(), &obs)));

        let never = ObsLog::new(); // NUT never initiates
        let results = run(&preferred_initiator(), &never);
        assert_eq!(results[0].outcome, Outcome::Fail(Severity::Soft));
    }

    #[test]
    fn endpoint_decoding_pass_and_fail() {
        let mut obs = ObsLog::new();
        obs.push(0, ev(1, ObsKind::Other(ENDPOINT_DIALED), 0));
        assert!(all_pass(&run(&endpoint_decoding(), &obs)));
        assert_eq!(
            run(&endpoint_decoding(), &ObsLog::new())[0].outcome,
            Outcome::Fail(Severity::Hard)
        );
    }

    #[test]
    fn builder_slots_pass() {
        let mut obs = ObsLog::new();
        obs.push(0, ev(1, ObsKind::Other(BUILDERS_ACCEPTED), 0));
        obs.push(10, ev(1, ObsKind::Other(CE133_ON_BUILDER), 10));
        assert!(all_pass(&run(&builder_slots(), &obs)));
    }

    #[test]
    fn up0_handshake_pass_and_fail() {
        let mut obs = ObsLog::new();
        obs.push(0, ev(1, ObsKind::Other(UP0_KIND0), 0));
        obs.push(10, ev(1, ObsKind::Other(UP0_FINAL_GENESIS), 10));
        assert!(all_pass(&run(&up0_handshake(), &obs)));

        let bad = ObsLog::new(); // non-genesis Final
        assert_eq!(
            run(&up0_handshake(), &bad)[1].outcome,
            Outcome::Fail(Severity::Hard)
        );
    }

    #[test]
    fn up0_announce_pass_and_fail() {
        let mut obs = ObsLog::new();
        obs.push(0, ev(1, ObsKind::Up0Announce, 0));
        obs.push(300, ev(1, ObsKind::Other(REANNOUNCED), 300)); // within 2 s
        assert!(all_pass(&run(&up0_announce(), &obs)));

        let no_reannounce = ObsLog::new(); // nothing announced
        let results = run(&up0_announce(), &no_reannounce);
        assert!(
            results.iter().any(|r| r.outcome != Outcome::Pass),
            "missing re-announce fails"
        );
    }

    #[test]
    fn ce128_serve_reference_count() {
        use m2_reference::chain::RefChain;
        let mut chain = RefChain::tiny(1..6).expect("tiny chain");
        let mut authored = 0usize;
        for slot in chain.next_slot()..chain.next_slot() + 12 {
            if chain.author_block(slot).expect("authors").is_some() {
                authored += 1;
                if authored >= 2 {
                    break;
                }
            }
        }
        assert!(
            authored >= 1,
            "expected at least one emulated slot in range"
        );

        let mut obs = ObsLog::new();
        for i in 0..authored {
            obs.push(100 * i as u64, ev(1, ObsKind::ServesCe128, 100 * i as u64));
        }
        obs.push(999, ev(1, ObsKind::Other(CE128_FIN_BOTH), 999));
        obs.push(1000, ev(1, ObsKind::Other(CE128_MAX_RESPECTED), 1000));

        let results = run(&ce128_serve(authored), &obs);
        assert!(
            all_pass(&results),
            "serving the reference count passes (results: {results:?})"
        );

        let short = run(&ce128_serve(authored + 1), &obs);
        assert!(
            short
                .iter()
                .any(|r| r.name == "ce128_ascending_covers_reference"
                    && r.outcome != Outcome::Pass),
            "expecting one more block than served fails"
        );
    }

    #[test]
    fn ce129_serve_pass_and_fail() {
        let mut obs = ObsLog::new();
        obs.push(0, ev(1, ObsKind::Other(CE129_SORTED), 0));
        obs.push(10, ev(1, ObsKind::Other(CE129_BOUNDARY_ORDER), 10));
        obs.push(20, ev(1, ObsKind::Other(CE129_SIZE_CAP), 20));
        obs.push(30, ev(1, ObsKind::Other(CE129_LEN_PREFIXED), 30));
        assert!(all_pass(&run(&ce129_serve(), &obs)));

        let unsorted = {
            let mut o = ObsLog::new();
            o.push(0, ev(1, ObsKind::Other(CE129_BOUNDARY_ORDER), 0));
            o.push(10, ev(1, ObsKind::Other(CE129_SIZE_CAP), 10));
            o.push(20, ev(1, ObsKind::Other(CE129_LEN_PREFIXED), 20));
            o
        };
        let results = run(&ce129_serve(), &unsorted);
        assert!(
            results.iter().any(
                |r| r.name == "ce129_keys_sorted" && r.outcome == Outcome::Fail(Severity::Hard)
            ),
            "unsorted keys fail hard"
        );
    }

    #[test]
    fn all_l0_checks_distinct() {
        let checks = all(2);
        assert_eq!(checks.len(), 9);
        let mut ids: Vec<&str> = checks.iter().map(|c| c.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 9, "all check ids are distinct");
    }
}
