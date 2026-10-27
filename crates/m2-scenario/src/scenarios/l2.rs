//! L2 — Safrole tickets (DESIGN.md §11 L2, CE 131/132 `simple.md:305-349`).
//!
//! Five checks over the runner-injected [`L2Ctx`] facts and the L2 detail
//! observations (`scenarios/obs.rs`, codes 41–46): ticket generation via
//! CE 131, self-proxy broadcasting via CE 132, the proxy-forwarding duty,
//! block-inclusion of received tickets, and the unknown-epoch reset.
//!
//! # Context conventions (runner-filled)
//!
//! - A [`NutTicketFacts`](crate::ctx::NutTicketFacts) entry records one frame
//!   the NUT sent, so the five copies of one CE 132 broadcast are five facts
//!   sharing an identity. Whether a ticket was proxied or broadcast is read
//!   off `delivery` — the stream kind the NUT chose — and never guessed from
//!   the peer it arrived at.
//! - Peers *are* validator indices. The emulator binds one endpoint per
//!   validator other than the NUT and labels its observations and trace
//!   records with that validator's index (`m2-runner`'s `emulated_indices`),
//!   so `ctx.emulated_peers` is the full set and the NUT's own index never
//!   appears among them.

use std::collections::BTreeMap;

use crate::ctx::{L2Ctx, NutTicketFacts, TicketDelivery};
use crate::dsl::{check, log, Check, CheckResult, ObsKind, Severity};
use crate::scenarios::obs::{BAD_PROOF_IGNORED, RECV_CE131, UNKNOWN_EPOCH_RESET};

/// Strictly ascending — sorted and free of duplicates in one pass.
fn is_sorted_dedup(ids: &[[u8; 32]]) -> bool {
    ids.windows(2).all(|w| w[0] < w[1])
}

/// The distinct tickets among `facts`, each with every peer it reached, in
/// first-seen order.
///
/// A CE 132 broadcast arrives once per emulated validator. Counting frames
/// instead of tickets would read one broadcast ticket as five, and no node
/// could stay under any per-epoch cap.
fn by_ticket(facts: &[&NutTicketFacts]) -> Vec<(NutTicketFacts, Vec<u16>)> {
    let mut out: Vec<(NutTicketFacts, Vec<u16>)> = Vec::new();
    for f in facts {
        match out.iter_mut().find(|(k, _)| k.identity() == f.identity()) {
            Some((_, peers)) => peers.push(f.peer),
            None => out.push(((*f).clone(), vec![f.peer])),
        }
    }
    out
}

/// Short, stable name for a ticket in a detail message.
fn ticket_name(f: &NutTicketFacts) -> String {
    let id: String = f.ticket.proof[..4]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!(
        "epoch {} attempt {} proof {id}..",
        f.epoch, f.ticket.attempt
    )
}

/// L2 — Generation, step 1 (`simple.md:314-316`): the NUT sends each ticket it
/// generates via CE 131 to the one validator that proxies it.
///
/// Each such ticket must name the epoch the NUT was generating for when it
/// sent it (the epoch after the sending slot's), carry an attempt inside the
/// per-validator range, verify against that epoch's ring, and go to exactly
/// one peer. Across an epoch the NUT may generate no more distinct tickets
/// than it has attempts.
pub fn l2_generation_step1(ctx: &L2Ctx) -> Check {
    let ctx = ctx.clone();
    check("l2_generation_step1", Severity::Hard, move |obs| {
        let proxied: Vec<&NutTicketFacts> = ctx
            .nut_tickets
            .iter()
            .filter(|f| f.delivery == TicketDelivery::Ce131)
            .collect();

        let mut results = vec![log::check(
            "l2_gen_ce131_observed",
            obs.first(ObsKind::Other(RECV_CE131)).is_some(),
            Severity::Hard,
        )];

        for (ticket, peers) in by_ticket(&proxied) {
            let expected = ctx.expected_target_epoch(ticket.received_at_ms);
            results.push(log::check_detail(
                "l2_gen_epoch_target",
                ticket.epoch == expected,
                Severity::Hard,
                || {
                    format!(
                        "CE 131 ticket sent in slot {} names epoch {}, but a ticket \
                         generated then is for epoch {expected}",
                        ctx.slot_at_ms(ticket.received_at_ms),
                        ticket.epoch,
                    )
                },
            ));
            results.push(log::check_detail(
                "l2_gen_attempt_in_range",
                ticket.ticket.attempt < ctx.tickets_per_validator,
                Severity::Hard,
                || {
                    format!(
                        "CE 131 ticket has attempt {}, and a validator makes \
                         {} attempt(s) per epoch",
                        ticket.ticket.attempt, ctx.tickets_per_validator,
                    )
                },
            ));
            results.push(proof_verdict(
                "l2_gen_proof_verified",
                "l2_gen_proof_unjudged",
                &ticket,
            ));
            results.push(log::check_detail(
                "l2_gen_one_proxy_per_ticket",
                peers.len() == 1 && peers[0] != ctx.nut_index,
                Severity::Hard,
                || {
                    format!(
                        "CE 131 carries a ticket to the single validator that \
                         proxies it; {} went to peer(s) {peers:?}",
                        ticket_name(&ticket),
                    )
                },
            ));
        }

        // Only the node's own tickets count against its attempts. A proxy
        // also broadcasts other validators' tickets via CE 132, and charging
        // those to the node's own cap would fail it for doing its duty.
        let generated: Vec<&NutTicketFacts> = ctx
            .nut_tickets
            .iter()
            .filter(|f| !ctx.was_delivered_by_the_emulator(f.ticket.attempt, &f.ticket.proof))
            .collect();
        let mut per_epoch: BTreeMap<u32, Vec<(u8, [u8; 784])>> = BTreeMap::new();
        for (ticket, _) in by_ticket(&generated) {
            per_epoch
                .entry(ticket.epoch)
                .or_default()
                .push(ticket.identity());
        }
        let over: Vec<(u32, usize)> = per_epoch
            .iter()
            .map(|(&epoch, ids)| (epoch, ids.len()))
            .filter(|&(_, n)| n > usize::from(ctx.tickets_per_validator))
            .collect();
        results.push(log::check_detail(
            "l2_gen_within_attempts_per_epoch",
            over.is_empty(),
            Severity::Hard,
            || {
                let seen: Vec<String> = over
                    .iter()
                    .map(|(epoch, n)| format!("epoch {epoch}: {n}"))
                    .collect();
                format!(
                    "the NUT may generate at most {} distinct ticket(s) per epoch; {}",
                    ctx.tickets_per_validator,
                    seen.join(", "),
                )
            },
        ));
        results
    })
}

/// The proof verdict for one NUT ticket.
///
/// A ring-VRF proof is bound to the tickets-entropy of the epoch it targets,
/// so the harness can only judge a ticket for an epoch it holds a context
/// for. Where it holds none, saying so as a soft result is the honest answer;
/// reporting an unjudgeable proof as a hard failure blames the node for the
/// harness's blind spot.
fn proof_verdict(
    verified_id: &'static str,
    unjudged_id: &'static str,
    ticket: &NutTicketFacts,
) -> CheckResult {
    match ticket.verified {
        Some(verified) => log::check_detail(verified_id, verified, Severity::Hard, || {
            format!(
                "{} did not verify against that epoch's ring",
                ticket_name(ticket)
            )
        }),
        None => log::check_detail(unjudged_id, false, Severity::Soft, || {
            format!(
                "{} is for an epoch the harness holds no ticket context for, \
                 so its proof was not checked",
                ticket_name(ticket),
            )
        }),
    }
}

/// L2 — Self-proxy (`simple.md:322-325`): a ticket the NUT proxies for itself
/// is broadcast via CE 132 to every current validator, so every emulated
/// validator must receive it.
pub fn l2_self_proxy(ctx: &L2Ctx) -> Check {
    let ctx = ctx.clone();
    check("l2_self_proxy", Severity::Hard, move |_obs| {
        let broadcast: Vec<&NutTicketFacts> = ctx
            .nut_tickets
            .iter()
            .filter(|f| f.delivery == TicketDelivery::Ce132)
            .collect();
        let tickets = by_ticket(&broadcast);
        if tickets.is_empty() {
            // Which tickets a validator proxies for itself follows from the
            // epoch's entropy, so a run where none do is ordinary and not a
            // silence worth failing on.
            return vec![log::check("l2_self_proxy_none", true, Severity::Hard)];
        }
        let mut results = Vec::new();
        for (ticket, peers) in tickets {
            let missing: Vec<u16> = ctx
                .emulated_peers
                .iter()
                .copied()
                .filter(|p| !peers.contains(p))
                .collect();
            results.push(log::check_detail(
                "l2_self_proxy_ce132_all_peers",
                missing.is_empty(),
                Severity::Hard,
                || {
                    format!(
                        "CE 132 broadcasts a self-proxied ticket to every validator; \
                         {} did not reach peer(s) {missing:?}",
                        ticket_name(&ticket),
                    )
                },
            ));
            results.push(proof_verdict(
                "l2_self_proxy_proof_verified",
                "l2_self_proxy_proof_unjudged",
                &ticket,
            ));
        }
        results
    })
}

/// L2 — Proxy duty (`simple.md:329-332`): a CE 131 ticket the NUT receives as
/// proxy is verified and forwarded via CE 132 to every current validator. A
/// bad-proof ticket is ignored instead (`BAD_PROOF_IGNORED`, soft).
///
/// The forward is matched by the ticket's own `(attempt, proof)`, not by the
/// bare fact that some CE 132 arrived: a node broadcasting only the tickets
/// it proxies for *itself* would satisfy an event count while forwarding
/// nothing.
pub fn l2_proxy_duty(ctx: &L2Ctx) -> Check {
    let ctx = ctx.clone();
    check("l2_proxy_duty", Severity::Hard, move |obs| {
        let mut results = Vec::new();
        for t in &ctx.emu_plan {
            if t.delivery != TicketDelivery::Ce131 || !ctx.proxy_is_nut(t) {
                continue;
            }
            if !t.valid {
                results.push(log::check(
                    "l2_proxy_duty_bad_proof_ignored",
                    obs.first(ObsKind::Other(BAD_PROOF_IGNORED)).is_some(),
                    Severity::Soft,
                ));
                continue;
            }
            if !ctx.leaves_room_to_forward(t.slot) {
                results.push(log::check_detail(
                    "l2_proxy_duty_delivered_in_time",
                    false,
                    Severity::Soft,
                    || {
                        format!(
                            "the ticket reached the NUT at phase {} of the lottery, too \
                             late in the epoch to demand a forward, so the duty was not \
                             exercised",
                            t.slot % ctx.epoch_period,
                        )
                    },
                ));
                continue;
            }
            let reached: Vec<u16> = ctx
                .nut_tickets
                .iter()
                .filter(|f| f.delivery == TicketDelivery::Ce132)
                .filter(|f| f.ticket.attempt == t.attempt && f.ticket.proof == t.proof)
                .map(|f| f.peer)
                .collect();
            let missing: Vec<u16> = ctx
                .emulated_peers
                .iter()
                .copied()
                .filter(|p| !reached.contains(p))
                .collect();
            results.push(log::check_detail(
                "l2_proxy_duty_forwarded",
                missing.is_empty(),
                Severity::Hard,
                || {
                    format!(
                        "a ticket proxied to the NUT in slot {} must be forwarded via \
                         CE 132 to every validator; it reached peer(s) {reached:?} and \
                         not {missing:?}",
                        t.slot,
                    )
                },
            ));
        }
        results
    })
}

/// L2 — Inclusion (DESIGN.md §11 L2): the NUT block's ticket extrinsic holds
/// every valid delivered ticket, sorted and deduplicated; empty when the
/// block's slot is in the epoch tail.
pub fn l2_inclusion(ctx: &L2Ctx) -> Check {
    let ctx = ctx.clone();
    check("l2_inclusion", Severity::Hard, move |_obs| {
        let mut expected: Vec<[u8; 32]> = ctx
            .emu_plan
            .iter()
            .filter(|t| t.valid && t.target_epoch == ctx.target_epoch)
            .map(|t| t.id)
            .collect();
        expected.sort();
        expected.dedup();

        // No block in the epoch the tickets were submittable in: nothing to
        // judge. Saying so is the honest reading -- a pass here would credit
        // the node for a block it never authored.
        let Some(block_slot) = ctx.nut_block_slot else {
            return vec![log::check_detail(
                "l2_inclusion_no_block_in_epoch",
                false,
                Severity::Soft,
                || {
                    format!(
                        "the NUT authored no block in epoch {}, where tickets for epoch {} \
                         are submitted, so the inclusion rules were not exercised",
                        ctx.target_epoch.saturating_sub(1),
                        ctx.target_epoch,
                    )
                },
            )];
        };
        let tail = ctx.slot_in_tail(block_slot);
        let mut results = vec![log::check_detail(
            "l2_inclusion_empty_at_tail",
            !tail || ctx.nut_block_ticket_ids.is_empty(),
            Severity::Hard,
            || {
                format!(
                    "slot {} is in the epoch tail, where the ticket extrinsic must be \
                     empty, but the block carried {} ticket(s)",
                    block_slot,
                    ctx.nut_block_ticket_ids.len(),
                )
            },
        )];
        if !tail {
            // A block holds at most `max_tickets_per_block` tickets -- three
            // under the tiny parameters, against the twenty the emulator
            // delivers in an epoch -- so demanding that one block carry every
            // valid ticket is a check no conforming node can pass. What is
            // required is that it fills the block from the valid set as far as
            // the cap allows; the rest stay owed by later blocks.
            let room = ctx.max_tickets_per_block.min(expected.len());
            let taken = expected
                .iter()
                .filter(|id| ctx.nut_block_ticket_ids.contains(id))
                .count();
            results.push(log::check_detail(
                "l2_inclusion_covers_valid",
                taken >= room,
                Severity::Hard,
                || {
                    format!(
                        "the block at slot {block_slot} had {} valid ticket(s) delivered for \
                         epoch {} to choose from and room for {room}, but carried {taken}",
                        expected.len(),
                        ctx.target_epoch,
                    )
                },
            ));
            // The node is a validator itself, so its own tickets belong in its
            // own block just as much as the emulator's do.
            let extra = ctx
                .nut_block_ticket_ids
                .iter()
                .filter(|id| !expected.contains(id) && !ctx.own_ticket_ids.contains(id))
                .count();
            results.push(log::check_detail(
                "l2_inclusion_no_extra",
                extra == 0,
                Severity::Hard,
                || {
                    format!(
                        "the block at slot {} carried {extra} ticket(s) that were \
                         neither delivered to the node nor announced by it",
                        block_slot,
                    )
                },
            ));
            results.push(log::check_detail(
                "l2_inclusion_sorted_dedup",
                is_sorted_dedup(&ctx.nut_block_ticket_ids),
                Severity::Hard,
                || {
                    format!(
                        "the ticket extrinsic must be sorted by id and free of \
                         duplicates; the block at slot {} carried {} id(s) that are not",
                        block_slot,
                        ctx.nut_block_ticket_ids.len(),
                    )
                },
            ));
        }
        results
    })
}

/// L2 — Unknown epoch (`simple.md:335-337`): a ticket for an epoch the NUT
/// cannot know yet makes it reset the stream.
///
/// The probe is the emulator's to send, so whether one went out is read from
/// the plan. A run without one leaves the rule untested, which is a soft
/// result and not a pass.
pub fn l2_unknown_epoch_reset(ctx: &L2Ctx) -> Check {
    let ctx = ctx.clone();
    check("l2_unknown_epoch_reset", Severity::Hard, move |obs| {
        let probes = ctx
            .emu_plan
            .iter()
            .filter(|t| t.target_epoch != ctx.target_epoch)
            .count();
        if probes == 0 {
            return vec![log::check_detail(
                "l2_unknown_epoch_probed",
                false,
                Severity::Soft,
                || {
                    "no unknown-epoch ticket was scheduled, so the reset rule was \
                     not exercised"
                        .to_string()
                },
            )];
        }
        vec![log::check_detail(
            "l2_unknown_epoch_reset_observed",
            obs.first(ObsKind::Other(UNKNOWN_EPOCH_RESET)).is_some(),
            Severity::Hard,
            || {
                format!(
                    "{probes} ticket(s) for an epoch past the NUT's horizon were \
                     delivered, and none made it reset the stream"
                )
            },
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
    use crate::ctx::{EmuTicket, NutTicketFacts, MAX_TICKETS_PER_BLOCK, SLOT_PERIOD_MS};
    use crate::dsl::{CheckResult, Obs, ObsLog, Outcome};
    use jam_types::JAM_COMMON_ERA;

    const EPOCH_PERIOD: u32 = 12;
    const EPOCH_TAIL_START: u32 = 10;
    const TICKETS_PER_VALIDATOR: u8 = 4;
    /// The NUT in these fixtures, with the other five validators emulated.
    const NUT: u16 = 5;
    const TARGET_EPOCH: u32 = 3;

    fn ev(peer: u16, kind: ObsKind, at_ms: u64) -> Obs {
        Obs { peer, kind, at_ms }
    }
    fn run(c: &Check, obs: &ObsLog) -> Vec<CheckResult> {
        (c.run)(obs)
    }
    fn all_pass(results: &[CheckResult]) -> bool {
        results.iter().all(|r| r.outcome == Outcome::Pass)
    }
    fn failed(results: &[CheckResult], name: &str, severity: Severity) -> bool {
        results
            .iter()
            .any(|r| r.name == name && r.outcome == Outcome::Fail(severity))
    }
    fn proof(seed: u8) -> [u8; 784] {
        let mut p = [0u8; 784];
        for (i, b) in p.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(seed);
        }
        p
    }
    /// A moment inside `epoch`, which is what the lane derives the epoch a
    /// ticket sent then must name from.
    fn during(epoch: u32) -> u64 {
        JAM_COMMON_ERA * 1000 + u64::from(epoch * EPOCH_PERIOD) * SLOT_PERIOD_MS
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
            // Early in the lottery, so a ticket proxied to the NUT here
            // leaves it room to forward.
            slot: TARGET_EPOCH * EPOCH_PERIOD + 1,
            target_epoch: TARGET_EPOCH,
        }
    }
    /// The NUT's CE 132 forward of `t`, as it reached `peer`.
    fn forwarded(t: &EmuTicket, peer: u16) -> NutTicketFacts {
        let mut f = nut(t.attempt, peer, TicketDelivery::Ce132);
        f.ticket.proof = t.proof;
        f
    }
    /// One frame the NUT sent: a ticket is identified by `(attempt, proof)`,
    /// so `attempt` doubles as the ticket's name in these fixtures.
    fn nut(attempt: u8, peer: u16, delivery: TicketDelivery) -> NutTicketFacts {
        NutTicketFacts {
            epoch: TARGET_EPOCH,
            ticket: jamnp_s::codec::ce131_136::Ticket {
                attempt,
                proof: proof(attempt),
            },
            peer,
            delivery,
            verified: Some(true),
            received_at_ms: during(TARGET_EPOCH - 1),
        }
    }
    fn ctx(
        emu_plan: Vec<EmuTicket>,
        nut_tickets: Vec<NutTicketFacts>,
        nut_block_ticket_ids: Vec<[u8; 32]>,
        nut_block_slot: u32,
    ) -> L2Ctx {
        L2Ctx {
            target_epoch: TARGET_EPOCH,
            epoch_start_slot: TARGET_EPOCH * EPOCH_PERIOD,
            emu_plan,
            nut_tickets,
            nut_block_ticket_ids,
            own_ticket_ids: Vec::new(),
            nut_block_slot: Some(nut_block_slot),
            nut_index: NUT,
            emulated_peers: (0..NUT).collect(),
            slot_period_ms: SLOT_PERIOD_MS,
            epoch_period: EPOCH_PERIOD,
            epoch_tail_start: EPOCH_TAIL_START,
            tickets_per_validator: TICKETS_PER_VALIDATOR,
            max_tickets_per_block: MAX_TICKETS_PER_BLOCK,
        }
    }
    #[test]
    fn l2_generation_pass_and_bad_proof() {
        let c = ctx(
            vec![],
            vec![
                nut(0, 1, TicketDelivery::Ce131),
                nut(1, 2, TicketDelivery::Ce131),
            ],
            vec![],
            0,
        );
        let mut obs = ObsLog::new();
        obs.push(0, ev(1, ObsKind::Other(RECV_CE131), 0));
        assert!(
            all_pass(&run(&l2_generation_step1(&c), &obs)),
            "verified CE 131 NUT tickets pass"
        );

        let mut unverified = nut(0, 1, TicketDelivery::Ce131);
        unverified.verified = Some(false);
        let bad = ctx(vec![], vec![unverified], vec![], 0);
        assert!(
            failed(
                &run(&l2_generation_step1(&bad), &obs),
                "l2_gen_proof_verified",
                Severity::Hard
            ),
            "an unverified NUT ticket fails hard"
        );

        let mut wrong_epoch = nut(0, 1, TicketDelivery::Ce131);
        wrong_epoch.epoch = TARGET_EPOCH + 1;
        let c = ctx(vec![], vec![wrong_epoch], vec![], 0);
        assert!(
            failed(
                &run(&l2_generation_step1(&c), &obs),
                "l2_gen_epoch_target",
                Severity::Hard
            ),
            "a ticket naming an epoch other than the one being generated for fails hard"
        );

        let mut over_attempt = nut(0, 1, TicketDelivery::Ce131);
        over_attempt.ticket.attempt = TICKETS_PER_VALIDATOR;
        let c = ctx(vec![], vec![over_attempt], vec![], 0);
        assert!(
            failed(
                &run(&l2_generation_step1(&c), &obs),
                "l2_gen_attempt_in_range",
                Severity::Hard
            ),
            "an attempt past the per-validator count fails hard"
        );

        let over = ctx(
            vec![],
            (0..=TICKETS_PER_VALIDATOR)
                .map(|a| nut(a, 1, TicketDelivery::Ce131))
                .collect(),
            vec![],
            0,
        );
        assert!(
            failed(
                &run(&l2_generation_step1(&over), &obs),
                "l2_gen_within_attempts_per_epoch",
                Severity::Hard
            ),
            "more distinct tickets than attempts in one epoch fails hard"
        );
    }

    /// A proof the harness holds no context for is reported as unjudged, not
    /// as a failure: the node is not at fault for the harness's blind spot.
    #[test]
    fn l2_generation_separates_unjudged_proofs_from_bad_ones() {
        let mut unjudged = nut(0, 1, TicketDelivery::Ce131);
        unjudged.verified = None;
        let c = ctx(vec![], vec![unjudged], vec![], 0);
        let mut obs = ObsLog::new();
        obs.push(0, ev(1, ObsKind::Other(RECV_CE131), 0));
        let results = run(&l2_generation_step1(&c), &obs);
        assert!(
            failed(&results, "l2_gen_proof_unjudged", Severity::Soft),
            "an unjudgeable proof is a soft result"
        );
        assert!(
            !results.iter().any(|r| r.name == "l2_gen_proof_verified"),
            "and is never reported as a failed verification"
        );
    }

    /// One broadcast ticket is one ticket, however many validators it reached.
    #[test]
    fn l2_generation_counts_tickets_not_frames() {
        let broadcast: Vec<NutTicketFacts> = (0..NUT)
            .map(|peer| nut(0, peer, TicketDelivery::Ce132))
            .collect();
        let c = ctx(vec![], broadcast, vec![], 0);
        let mut obs = ObsLog::new();
        obs.push(0, ev(1, ObsKind::Other(RECV_CE131), 0));
        let results = run(&l2_generation_step1(&c), &obs);
        assert!(
            !failed(&results, "l2_gen_within_attempts_per_epoch", Severity::Hard),
            "the five copies of one CE 132 broadcast are one ticket against the cap"
        );
    }

    /// A proxy's forwards are other validators' tickets, so they must not
    /// count against the node's own per-epoch attempts.
    #[test]
    fn l2_generation_does_not_charge_forwards_to_the_node() {
        let plan: Vec<EmuTicket> = (0..TICKETS_PER_VALIDATOR)
            .map(|a| {
                let mut t = emu(a, NUT, true, TicketDelivery::Ce131);
                t.attempt = a;
                t.proof = proof(100 + a);
                t
            })
            .collect();
        let mut forwards: Vec<NutTicketFacts> = plan
            .iter()
            .map(|t| {
                let mut f = nut(t.attempt, 1, TicketDelivery::Ce132);
                f.ticket.proof = t.proof;
                f
            })
            .collect();
        // Plus one ticket of the node's own, well inside its attempts.
        forwards.push(nut(0, 1, TicketDelivery::Ce131));
        let c = ctx(plan, forwards, vec![], 0);
        let mut obs = ObsLog::new();
        obs.push(0, ev(1, ObsKind::Other(RECV_CE131), 0));
        assert!(
            !failed(
                &run(&l2_generation_step1(&c), &obs),
                "l2_gen_within_attempts_per_epoch",
                Severity::Hard
            ),
            "forwarding a full epoch of another validator's tickets is not generating them"
        );
    }

    /// The epoch a ticket must name follows the clock, so a run that crosses
    /// an epoch boundary sees the NUT change target and is still conforming.
    #[test]
    fn l2_generation_follows_the_clock_across_an_epoch_boundary() {
        let mut before = nut(0, 1, TicketDelivery::Ce131);
        before.received_at_ms = during(TARGET_EPOCH - 1);
        before.epoch = TARGET_EPOCH;
        let mut after = nut(1, 2, TicketDelivery::Ce131);
        after.received_at_ms = during(TARGET_EPOCH);
        after.epoch = TARGET_EPOCH + 1;
        let c = ctx(vec![], vec![before, after], vec![], 0);
        let mut obs = ObsLog::new();
        obs.push(0, ev(1, ObsKind::Other(RECV_CE131), 0));
        assert!(
            all_pass(&run(&l2_generation_step1(&c), &obs)),
            "each ticket is judged against the epoch it was generated in"
        );
    }

    /// CE 131 names one proxy: the same ticket on two connections is not one.
    #[test]
    fn l2_generation_proxies_each_ticket_to_one_peer() {
        let c = ctx(
            vec![],
            vec![
                nut(0, 1, TicketDelivery::Ce131),
                nut(0, 2, TicketDelivery::Ce131),
            ],
            vec![],
            0,
        );
        let mut obs = ObsLog::new();
        obs.push(0, ev(1, ObsKind::Other(RECV_CE131), 0));
        assert!(
            failed(
                &run(&l2_generation_step1(&c), &obs),
                "l2_gen_one_proxy_per_ticket",
                Severity::Hard
            ),
            "one ticket proxied to two validators fails hard"
        );
    }

    #[test]
    fn l2_self_proxy_pass_and_missing_peer() {
        let broadcast: Vec<NutTicketFacts> = (0..NUT)
            .map(|peer| nut(0, peer, TicketDelivery::Ce132))
            .collect();
        let c = ctx(vec![], broadcast.clone(), vec![], 0);
        assert!(
            all_pass(&run(&l2_self_proxy(&c), &ObsLog::new())),
            "a ticket broadcast to every validator passes"
        );

        let short = ctx(vec![], broadcast[1..].to_vec(), vec![], 0);
        assert!(
            failed(
                &run(&l2_self_proxy(&short), &ObsLog::new()),
                "l2_self_proxy_ce132_all_peers",
                Severity::Hard
            ),
            "a validator the broadcast missed fails hard"
        );
    }

    /// Self-proxying is what CE 132 means, not which peer a frame reached:
    /// reading it off the peer index makes the check unfailable, since the
    /// NUT never holds a connection to itself.
    #[test]
    fn l2_self_proxy_reads_the_stream_kind_not_the_peer() {
        let proxied = ctx(vec![], vec![nut(0, 1, TicketDelivery::Ce131)], vec![], 0);
        let results = run(&l2_self_proxy(&proxied), &ObsLog::new());
        assert!(
            results.iter().all(|r| r.name == "l2_self_proxy_none"),
            "a CE 131 distribution is never a self-proxy broadcast"
        );
    }

    #[test]
    fn l2_proxy_duty_pass_and_unforwarded() {
        let good = emu(1, NUT, true, TicketDelivery::Ce131);
        let bad = emu(2, NUT, false, TicketDelivery::Ce131);
        let forwards: Vec<NutTicketFacts> = (0..NUT).map(|peer| forwarded(&good, peer)).collect();
        let c = ctx(vec![good, bad], forwards.clone(), vec![], 0);
        let mut obs = ObsLog::new();
        obs.push(99, ev(1, ObsKind::Other(BAD_PROOF_IGNORED), 99));
        assert!(
            all_pass(&run(&l2_proxy_duty(&c), &obs)),
            "a forwarded valid ticket and an ignored bad proof pass"
        );

        let short = ctx(vec![good, bad], forwards[1..].to_vec(), vec![], 0);
        assert!(
            failed(
                &run(&l2_proxy_duty(&short), &obs),
                "l2_proxy_duty_forwarded",
                Severity::Hard
            ),
            "a validator the forward missed fails hard"
        );

        let none = ctx(vec![good, bad], vec![], vec![], 0);
        assert!(
            failed(
                &run(&l2_proxy_duty(&none), &obs),
                "l2_proxy_duty_forwarded",
                Severity::Hard
            ),
            "a valid ticket not forwarded at all fails hard"
        );

        assert!(
            failed(
                &run(&l2_proxy_duty(&c), &ObsLog::new()),
                "l2_proxy_duty_bad_proof_ignored",
                Severity::Soft
            ),
            "a bad proof not observed as ignored is a soft fail"
        );
    }

    /// The forward is matched by the ticket it carries. A node that broadcast
    /// only its own tickets would otherwise satisfy a check that merely
    /// counted CE 132 frames.
    #[test]
    fn l2_proxy_duty_matches_the_ticket_not_the_frame() {
        let owed = emu(1, NUT, true, TicketDelivery::Ce131);
        let others: Vec<NutTicketFacts> = (0..NUT)
            .map(|peer| nut(3, peer, TicketDelivery::Ce132))
            .collect();
        let c = ctx(vec![owed], others, vec![], 0);
        assert!(
            failed(
                &run(&l2_proxy_duty(&c), &ObsLog::new()),
                "l2_proxy_duty_forwarded",
                Severity::Hard
            ),
            "broadcasting some other ticket is not forwarding this one"
        );
    }

    /// A proxy forwards within a window, not on receipt, so a ticket the
    /// harness delivered late in the lottery is reported as not exercised
    /// rather than as a node that failed to forward.
    #[test]
    fn l2_proxy_duty_late_delivery_is_untested_not_failed() {
        let mut late = emu(1, NUT, true, TicketDelivery::Ce131);
        late.slot = TARGET_EPOCH * EPOCH_PERIOD + EPOCH_TAIL_START - 1;
        let c = ctx(vec![late], vec![], vec![], 0);
        let results = run(&l2_proxy_duty(&c), &ObsLog::new());
        assert!(
            failed(&results, "l2_proxy_duty_delivered_in_time", Severity::Soft),
            "a late delivery is reported: {results:?}"
        );
        assert!(
            !results.iter().any(|r| r.name == "l2_proxy_duty_forwarded"),
            "and the forward is never judged on it"
        );
    }

    /// The peers a forward must reach are the ones the run emulates. Holding
    /// a fixed set instead leaves the check unable to pass whenever the NUT
    /// sits at an index that set assumed was emulated.
    #[test]
    fn l2_proxy_duty_reaches_the_peers_the_run_emulates() {
        let owed = emu(1, 0, true, TicketDelivery::Ce131);
        let forwards: Vec<NutTicketFacts> = (1..=5).map(|peer| forwarded(&owed, peer)).collect();
        let mut c = ctx(vec![owed], forwards, vec![], 0);
        c.nut_index = 0;
        c.emulated_peers = (1..=5).collect();
        assert!(
            all_pass(&run(&l2_proxy_duty(&c), &ObsLog::new())),
            "a NUT at index 0 forwards to validators 1..=5"
        );
    }

    /// The node under test is a validator: it runs the lottery too, and its
    /// own tickets belong in its own block. Charging them as tickets nobody
    /// delivered failed a node for doing what the protocol asks.
    #[test]
    fn l2_inclusion_allows_the_nodes_own_tickets() {
        let mut c = ctx(
            vec![emu(1, 0, true, TicketDelivery::Ce132)],
            vec![],
            vec![[1u8; 32], [9u8; 32]],
            0,
        );
        assert!(
            failed(
                &run(&l2_inclusion(&c), &ObsLog::new()),
                "l2_inclusion_no_extra",
                Severity::Hard
            ),
            "a ticket from nowhere is still an extra"
        );

        c.own_ticket_ids = vec![[9u8; 32]];
        assert!(
            all_pass(&run(&l2_inclusion(&c), &ObsLog::new())),
            "the same ticket, announced by the node itself, is its own to carry"
        );
    }

    /// A block holds at most `max_tickets_per_block` tickets, so requiring one
    /// block to carry every valid ticket delivered for the epoch is a check no
    /// conforming node can pass once more than the cap have been delivered.
    #[test]
    fn l2_inclusion_asks_only_for_what_a_block_can_hold() {
        let delivered: Vec<EmuTicket> = (1..=5u8)
            .map(|id| emu(id, 0, true, TicketDelivery::Ce132))
            .collect();
        let full: Vec<[u8; 32]> = (1..=MAX_TICKETS_PER_BLOCK as u8)
            .map(|id| [id; 32])
            .collect();
        let c = ctx(delivered.clone(), vec![], full, 0);
        assert!(
            all_pass(&run(&l2_inclusion(&c), &ObsLog::new())),
            "five delivered and a cap of three: carrying three fills the block"
        );

        let short: Vec<[u8; 32]> = (1..MAX_TICKETS_PER_BLOCK as u8)
            .map(|id| [id; 32])
            .collect();
        let c = ctx(delivered, vec![], short, 0);
        assert!(
            failed(
                &run(&l2_inclusion(&c), &ObsLog::new()),
                "l2_inclusion_covers_valid",
                Severity::Hard
            ),
            "leaving room unused while valid tickets wait is still a failure"
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
        assert!(
            failed(
                &run(&l2_inclusion(&miss), &ObsLog::new()),
                "l2_inclusion_covers_valid",
                Severity::Hard
            ),
            "a missing valid ticket fails hard"
        );

        let tail = ctx(
            vec![emu(1, 0, true, TicketDelivery::Ce132)],
            vec![],
            vec![[1u8; 32]],
            EPOCH_TAIL_START,
        );
        assert!(
            failed(
                &run(&l2_inclusion(&tail), &ObsLog::new()),
                "l2_inclusion_empty_at_tail",
                Severity::Hard
            ),
            "a non-empty extrinsic in the epoch tail fails hard"
        );
    }

    /// A block may only carry tickets for the epoch it is submitting into, so
    /// the unknown-epoch probe is not a ticket the node owes inclusion of.
    #[test]
    fn l2_inclusion_ignores_tickets_for_another_epoch() {
        let mut probe = emu(9, 0, true, TicketDelivery::Ce132);
        probe.target_epoch = TARGET_EPOCH + 2;
        let c = ctx(
            vec![emu(1, 0, true, TicketDelivery::Ce132), probe],
            vec![],
            vec![[1u8; 32]],
            0,
        );
        assert!(
            all_pass(&run(&l2_inclusion(&c), &ObsLog::new())),
            "a probe for an epoch the node cannot know is not owed inclusion"
        );
    }

    #[test]
    fn l2_unknown_epoch_pass_and_no_reset() {
        let mut probe = emu(9, 0, true, TicketDelivery::Ce132);
        probe.target_epoch = TARGET_EPOCH + 2;
        let c = ctx(vec![probe], vec![], vec![], 0);
        let mut obs = ObsLog::new();
        obs.push(0, ev(1, ObsKind::Other(UNKNOWN_EPOCH_RESET), 0));
        assert!(
            all_pass(&run(&l2_unknown_epoch_reset(&c), &obs)),
            "an observed reset passes"
        );

        assert!(
            failed(
                &run(&l2_unknown_epoch_reset(&c), &ObsLog::new()),
                "l2_unknown_epoch_reset_observed",
                Severity::Hard
            ),
            "a missing reset fails hard"
        );
    }

    /// A rule nothing exercised is untested, which is a soft result. Passing
    /// it would report coverage the run never had.
    #[test]
    fn l2_unknown_epoch_without_a_probe_is_untested_not_passed() {
        let no_probe = ctx(
            vec![emu(1, 0, true, TicketDelivery::Ce132)],
            vec![],
            vec![],
            0,
        );
        let results = run(&l2_unknown_epoch_reset(&no_probe), &ObsLog::new());
        assert!(
            failed(&results, "l2_unknown_epoch_probed", Severity::Soft),
            "an unexercised reset rule is reported, not passed: {results:?}"
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
