//! L2 — Safrole tickets (DESIGN.md §11 L2, CE 131/132 `simple.md:305-349`).
//!
//! Five checks over the runner-injected [`L2Ctx`] facts and the L2 detail
//! observations (`scenarios/obs.rs`, codes 41–46): ticket generation via
//! CE 131, self-proxy broadcasting via CE 132, the proxy-forwarding duty,
//! block-inclusion of received tickets, and the unknown-epoch reset.
//!
//! # Context conventions (runner-filled)
//!
//! - A [`NutTicketFacts`] entry records one ticket the NUT distributed to the
//!   emulator. A NUT ticket sent via CE 131 to its proxy has `peer` = that
//!   emulated validator index; a self-proxied NUT ticket (proxy is the NUT)
//!   has `peer == NUT_INDEX`. The emulator's unknown-epoch probe — a ticket
//!   for `target_epoch + 2` the NUT must reset on — is recorded with
//!   `epoch == target_epoch + 2`.
//! - Observation-log peers follow `l0.rs`: emulated peers are `1..=5` (a
//!   different space from validator indices, where the NUT is 5).

use std::collections::BTreeMap;

use crate::ctx::{L2Ctx, TicketDelivery, NUT_INDEX};
use crate::dsl::{check, log, Check, CheckResult, ObsKind, ObsLog, Outcome, Severity};
use crate::scenarios::obs::{BAD_PROOF_IGNORED, RECV_CE131, RECV_CE132, UNKNOWN_EPOCH_RESET};

/// Emulated observation-log peers (`l0.rs`: `1..=5`; the NUT is obs peer 0).
const EMULATED_PEERS: [u16; 5] = [1, 2, 3, 4, 5];

/// Whether `obs` recorded `kind` from `peer`'s connection.
fn saw_from(obs: &ObsLog, kind: ObsKind, peer: u16) -> bool {
    obs.events()
        .iter()
        .any(|(_, o)| o.kind == kind && o.peer == peer)
}

/// Whether every emulated peer's connection saw `kind`.
fn all_peers_saw(obs: &ObsLog, kind: ObsKind) -> bool {
    EMULATED_PEERS.iter().all(|&p| saw_from(obs, kind, p))
}

/// Strictly ascending — sorted and free of duplicates in one pass.
fn is_sorted_dedup(ids: &[[u8; 32]]) -> bool {
    ids.windows(2).all(|w| w[0] < w[1])
}

/// L2 — Generation, step 1 (`simple.md:305-349`): the NUT sends each of its
/// tickets via CE 131 to the validator it proxies for. Every such ticket must
/// be for `target_epoch`, attempt `< 3`, proof-verified, and received by an
/// emulated validator (the proxy — never the NUT itself); at most 3 tickets
/// per epoch.
pub fn l2_generation_step1(ctx: &L2Ctx) -> Check {
    let ctx = ctx.clone();
    check("l2_generation_step1", Severity::Hard, move |obs| {
        let probe_epoch = ctx.target_epoch.wrapping_add(2);
        let ce131 = ctx
            .nut_tickets
            .iter()
            .filter(|f| f.peer != NUT_INDEX && f.epoch != probe_epoch);

        let mut results = vec![log::check(
            "l2_gen_ce131_observed",
            obs.first(ObsKind::Other(RECV_CE131)).is_some(),
            Severity::Hard,
        )];

        for f in ce131 {
            results.push(log::check(
                "l2_gen_epoch_target",
                f.epoch == ctx.target_epoch,
                Severity::Hard,
            ));
            results.push(log::check(
                "l2_gen_attempt_lt_3",
                f.ticket.attempt < 3,
                Severity::Hard,
            ));
            results.push(log::check(
                "l2_gen_proof_verified",
                f.verified,
                Severity::Hard,
            ));
            results.push(log::check(
                "l2_gen_peer_is_proxy",
                f.peer < NUT_INDEX,
                Severity::Hard,
            ));
        }

        let mut per_epoch: BTreeMap<u32, usize> = BTreeMap::new();
        for f in ctx.nut_tickets.iter().filter(|f| f.epoch != probe_epoch) {
            *per_epoch.entry(f.epoch).or_insert(0) += 1;
        }
        results.push(log::check(
            "l2_gen_le_3_per_epoch",
            per_epoch.values().all(|&n| n <= 3),
            Severity::Hard,
        ));
        results
    })
}

/// L2 — Self-proxy (`simple.md:322-325`): a NUT ticket whose proxy is the NUT
/// itself is broadcast via CE 132 to every current validator. Each emulated
/// peer's connection must observe the broadcast.
pub fn l2_self_proxy(ctx: &L2Ctx) -> Check {
    let ctx = ctx.clone();
    check("l2_self_proxy", Severity::Hard, move |obs| {
        let self_proxied = ctx
            .nut_tickets
            .iter()
            .filter(|f| f.peer == NUT_INDEX && f.epoch == ctx.target_epoch)
            .count();
        if self_proxied == 0 {
            return vec![log::check("l2_self_proxy_none", true, Severity::Hard)];
        }
        vec![log::check(
            "l2_self_proxy_ce132_all_peers",
            all_peers_saw(obs, ObsKind::Other(RECV_CE132)),
            Severity::Hard,
        )]
    })
}

/// L2 — Proxy duty (`simple.md:329-332`): a CE 131 ticket the NUT receives as
/// proxy is verified and forwarded via CE 132 to all five emulated peers. A
/// bad-proof ticket is ignored instead (`BAD_PROOF_IGNORED`, soft).
pub fn l2_proxy_duty(ctx: &L2Ctx) -> Check {
    let ctx = ctx.clone();
    check("l2_proxy_duty", Severity::Hard, move |obs| {
        let mut results = Vec::new();
        for t in &ctx.emu_plan {
            if t.delivery != TicketDelivery::Ce131 || !ctx.proxy_is_nut(t) {
                continue;
            }
            if t.valid {
                results.push(log::check(
                    "l2_proxy_duty_forwarded",
                    all_peers_saw(obs, ObsKind::Other(RECV_CE132)),
                    Severity::Hard,
                ));
            } else {
                results.push(log::check(
                    "l2_proxy_duty_bad_proof_ignored",
                    obs.first(ObsKind::Other(BAD_PROOF_IGNORED)).is_some(),
                    Severity::Soft,
                ));
            }
        }
        results
    })
}

/// L2 — Inclusion (DESIGN.md §11 L2): the NUT block's ticket extrinsic holds
/// every valid delivered ticket, sorted and deduplicated; empty when the
/// block's slot is in the epoch tail (`slot % 12 >= 10`).
pub fn l2_inclusion(ctx: &L2Ctx) -> Check {
    let ctx = ctx.clone();
    check("l2_inclusion", Severity::Hard, move |_obs| {
        let mut expected: Vec<[u8; 32]> = ctx
            .emu_plan
            .iter()
            .filter(|t| t.valid)
            .map(|t| t.id)
            .collect();
        expected.sort();
        expected.dedup();

        let tail = ctx.nut_block_slot % 12 >= 10;
        let mut results = vec![log::check(
            "l2_inclusion_empty_at_tail",
            !tail || ctx.nut_block_ticket_ids.is_empty(),
            Severity::Hard,
        )];
        if !tail {
            results.push(log::check(
                "l2_inclusion_covers_valid",
                expected
                    .iter()
                    .all(|id| ctx.nut_block_ticket_ids.contains(id)),
                Severity::Hard,
            ));
            results.push(log::check(
                "l2_inclusion_no_extra",
                ctx.nut_block_ticket_ids
                    .iter()
                    .all(|id| expected.contains(id)),
                Severity::Hard,
            ));
            results.push(log::check(
                "l2_inclusion_sorted_dedup",
                is_sorted_dedup(&ctx.nut_block_ticket_ids),
                Severity::Hard,
            ));
        }
        results
    })
}

/// L2 — Unknown epoch (`simple.md:335-337`): a ticket for `target_epoch + 2`
/// makes the NUT reset the stream; the reset must be observed.
pub fn l2_unknown_epoch_reset(ctx: &L2Ctx) -> Check {
    let ctx = ctx.clone();
    check("l2_unknown_epoch_reset", Severity::Hard, move |obs| {
        let probe = ctx
            .nut_tickets
            .iter()
            .any(|f| f.epoch == ctx.target_epoch.wrapping_add(2));
        if !probe {
            return vec![log::check(
                "l2_unknown_epoch_no_probe",
                true,
                Severity::Hard,
            )];
        }
        vec![log::check(
            "l2_unknown_epoch_reset_observed",
            obs.first(ObsKind::Other(UNKNOWN_EPOCH_RESET)).is_some(),
            Severity::Hard,
        )]
    })
}

/// All five L2 checks in DESIGN.md §11 L2 row order.
pub fn all(ctx: &L2Ctx) -> Vec<Check> {
    vec![
        l2_generation_step1(ctx),
        l2_self_proxy(ctx),
        l2_proxy_duty(ctx),
        l2_inclusion(ctx),
        l2_unknown_epoch_reset(ctx),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctx::{EmuTicket, NutTicketFacts};
    use crate::dsl::Obs;

    fn ev(peer: u16, kind: ObsKind, at_ms: u64) -> Obs {
        Obs { peer, kind, at_ms }
    }
    fn run(c: &Check, obs: &ObsLog) -> Vec<CheckResult> {
        (c.run)(obs)
    }
    fn all_pass(results: &[CheckResult]) -> bool {
        results.iter().all(|r| r.outcome == Outcome::Pass)
    }
    fn proof(seed: u8) -> [u8; 784] {
        let mut p = [0u8; 784];
        for (i, b) in p.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(seed);
        }
        p
    }
    fn emu(id: u8, proxy: u16, valid: bool, delivery: TicketDelivery) -> EmuTicket {
        EmuTicket {
            id: [id; 32],
            author: 1,
            attempt: 0,
            proof: proof(id),
            proxy,
            valid,
            delivery,
            slot: 101,
        }
    }
    fn nut(epoch: u32, attempt: u8, peer: u16, verified: bool) -> NutTicketFacts {
        NutTicketFacts {
            epoch,
            ticket: jamnp_s::codec::ce131_136::Ticket {
                attempt,
                proof: proof(0),
            },
            peer,
            verified,
            received_at_ms: 100,
        }
    }
    fn ctx(
        emu_plan: Vec<EmuTicket>,
        nut_tickets: Vec<NutTicketFacts>,
        nut_block_ticket_ids: Vec<[u8; 32]>,
        nut_block_slot: u32,
    ) -> L2Ctx {
        L2Ctx {
            target_epoch: 3,
            epoch_start_slot: 100,
            emu_plan,
            nut_tickets,
            nut_block_ticket_ids,
            nut_block_slot,
        }
    }

    #[test]
    fn l2_generation_pass_and_bad_proof() {
        let c = ctx(
            vec![],
            vec![nut(3, 0, 1, true), nut(3, 1, 2, true)],
            vec![],
            0,
        );
        let mut obs = ObsLog::new();
        obs.push(0, ev(1, ObsKind::Other(RECV_CE131), 0));
        assert!(
            all_pass(&run(&l2_generation_step1(&c), &obs)),
            "verified CE 131 NUT tickets pass"
        );

        let bad = ctx(vec![], vec![nut(3, 0, 1, false)], vec![], 0);
        let results = run(&l2_generation_step1(&bad), &obs);
        assert!(
            results
                .iter()
                .any(|r| r.name == "l2_gen_proof_verified"
                    && r.outcome == Outcome::Fail(Severity::Hard)),
            "an unverified NUT ticket fails hard"
        );

        let wrong_epoch = ctx(vec![], vec![nut(4, 0, 1, true)], vec![], 0);
        let results = run(&l2_generation_step1(&wrong_epoch), &obs);
        assert!(
            results
                .iter()
                .any(|r| r.name == "l2_gen_epoch_target"
                    && r.outcome == Outcome::Fail(Severity::Hard)),
            "a wrong-epoch NUT ticket fails hard"
        );

        let wrong_peer = ctx(vec![], vec![nut(3, 0, 7, true)], vec![], 0);
        let results = run(&l2_generation_step1(&wrong_peer), &obs);
        assert!(
            results
                .iter()
                .any(|r| r.name == "l2_gen_peer_is_proxy"
                    && r.outcome == Outcome::Fail(Severity::Hard)),
            "a ticket received by a non-proxy peer fails hard"
        );

        let over = ctx(
            vec![],
            vec![
                nut(3, 0, 1, true),
                nut(3, 1, 2, true),
                nut(3, 2, 3, true),
                nut(3, 0, 4, true),
            ],
            vec![],
            0,
        );
        let results = run(&l2_generation_step1(&over), &obs);
        assert!(
            results
                .iter()
                .any(|r| r.name == "l2_gen_le_3_per_epoch"
                    && r.outcome == Outcome::Fail(Severity::Hard)),
            "more than 3 tickets per epoch fails hard"
        );
    }

    #[test]
    fn l2_self_proxy_pass_and_missing_peer() {
        let c = ctx(vec![], vec![nut(3, 0, NUT_INDEX, true)], vec![], 0);
        let mut obs = ObsLog::new();
        for p in 1..=5u16 {
            obs.push(p as u64, ev(p, ObsKind::Other(RECV_CE132), p as u64));
        }
        assert!(
            all_pass(&run(&l2_self_proxy(&c), &obs)),
            "CE 132 on all 5 peers passes"
        );

        let mut missing = ObsLog::new();
        for p in 1..=4u16 {
            missing.push(p as u64, ev(p, ObsKind::Other(RECV_CE132), p as u64));
        }
        let results = run(&l2_self_proxy(&c), &missing);
        assert!(
            results
                .iter()
                .any(|r| r.name == "l2_self_proxy_ce132_all_peers"
                    && r.outcome == Outcome::Fail(Severity::Hard)),
            "a missing peer fails hard"
        );
    }

    #[test]
    fn l2_proxy_duty_pass_and_unforwarded() {
        let c = ctx(
            vec![
                emu(1, NUT_INDEX, true, TicketDelivery::Ce131),
                emu(2, NUT_INDEX, false, TicketDelivery::Ce131),
            ],
            vec![],
            vec![],
            0,
        );
        let mut obs = ObsLog::new();
        for p in 1..=5u16 {
            obs.push(p as u64, ev(p, ObsKind::Other(RECV_CE132), p as u64));
        }
        obs.push(99, ev(1, ObsKind::Other(BAD_PROOF_IGNORED), 99));
        assert!(
            all_pass(&run(&l2_proxy_duty(&c), &obs)),
            "forwarded valid ticket and ignored bad proof pass"
        );

        let mut no_forward = ObsLog::new();
        no_forward.push(99, ev(1, ObsKind::Other(BAD_PROOF_IGNORED), 99));
        let results = run(&l2_proxy_duty(&c), &no_forward);
        assert!(
            results.iter().any(|r| r.name == "l2_proxy_duty_forwarded"
                && r.outcome == Outcome::Fail(Severity::Hard)),
            "a valid ticket not forwarded fails hard"
        );

        let mut no_ignore = ObsLog::new();
        for p in 1..=5u16 {
            no_ignore.push(p as u64, ev(p, ObsKind::Other(RECV_CE132), p as u64));
        }
        let results = run(&l2_proxy_duty(&c), &no_ignore);
        assert!(
            results
                .iter()
                .any(|r| r.name == "l2_proxy_duty_bad_proof_ignored"
                    && r.outcome == Outcome::Fail(Severity::Soft)),
            "a bad proof not observed as ignored is a soft fail"
        );
    }

    #[test]
    fn l2_inclusion_pass_and_missing() {
        let valid = vec![
            emu(1, 0, true, TicketDelivery::Ce132),
            emu(3, 0, true, TicketDelivery::Ce132),
            emu(2, 0, true, TicketDelivery::Ce132),
            emu(2, 0, true, TicketDelivery::Ce132),
        ];
        let c = ctx(valid, vec![], vec![[1u8; 32], [2u8; 32], [3u8; 32]], 0);
        assert!(
            all_pass(&run(&l2_inclusion(&c), &ObsLog::new())),
            "sorted deduplicated inclusion passes"
        );

        let miss = ctx(
            vec![
                emu(1, 0, true, TicketDelivery::Ce132),
                emu(3, 0, true, TicketDelivery::Ce132),
                emu(2, 0, true, TicketDelivery::Ce132),
            ],
            vec![],
            vec![[1u8; 32], [3u8; 32]],
            0,
        );
        let results = run(&l2_inclusion(&miss), &ObsLog::new());
        assert!(
            results.iter().any(|r| r.name == "l2_inclusion_covers_valid"
                && r.outcome == Outcome::Fail(Severity::Hard)),
            "a missing valid ticket fails hard"
        );

        let tail = ctx(
            vec![emu(1, 0, true, TicketDelivery::Ce132)],
            vec![],
            vec![[1u8; 32]],
            10,
        );
        let results = run(&l2_inclusion(&tail), &ObsLog::new());
        assert!(
            results
                .iter()
                .any(|r| r.name == "l2_inclusion_empty_at_tail"
                    && r.outcome == Outcome::Fail(Severity::Hard)),
            "a non-empty extrinsic in the epoch tail fails hard"
        );
    }

    #[test]
    fn l2_unknown_epoch_pass_and_no_reset() {
        let c = ctx(vec![], vec![nut(5, 0, 1, true)], vec![], 0);
        let mut obs = ObsLog::new();
        obs.push(0, ev(1, ObsKind::Other(UNKNOWN_EPOCH_RESET), 0));
        assert!(
            all_pass(&run(&l2_unknown_epoch_reset(&c), &obs)),
            "an observed reset passes"
        );

        let results = run(&l2_unknown_epoch_reset(&c), &ObsLog::new());
        assert!(
            results
                .iter()
                .any(|r| r.name == "l2_unknown_epoch_reset_observed"
                    && r.outcome == Outcome::Fail(Severity::Hard)),
            "a missing reset fails hard"
        );

        let no_probe = ctx(vec![], vec![], vec![], 0);
        assert!(
            all_pass(&run(&l2_unknown_epoch_reset(&no_probe), &ObsLog::new())),
            "no probe trivially passes"
        );
    }

    #[test]
    fn all_l2_checks_distinct() {
        let checks = all(&ctx(vec![], vec![], vec![], 0));
        assert_eq!(checks.len(), 5);
        let mut ids: Vec<&str> = checks.iter().map(|c| c.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 5, "all check ids are distinct");
    }
}
