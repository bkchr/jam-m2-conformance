//! N2 — Safrole tickets (DESIGN.md §11 N2, CE 131/132 `simple.md:305-349`).
//!
//! Seven checks over the runner-injected [`N2Ctx`] facts and the N2 detail
//! observations (`scenarios/obs.rs`, codes 41–48): ticket generation via
//! CE 131, self-proxy broadcasting via CE 132, the proxy-forwarding duty,
//! when that duty stops, block-inclusion of received tickets, the
//! unknown-epoch reset, and what the node must do with none of the tickets
//! the harness broke.
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

use crate::ctx::{EmuTicket, N2Ctx, NutTicketFacts, TicketDelivery, TicketFault};
use crate::dsl::{check, log, Check, CheckResult, Control, ObsKind, Severity};
use crate::scenarios::obs::RECV_CE131;

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

/// Every CE 132 frame the NUT sent carrying this exact ticket.
///
/// Matched on `(attempt, proof)`, which is what CE 131/132 actually carry;
/// the id is the proof's VRF output and the wire never sends it. At most one
/// planned entry answers to any pair: the faults that reuse an honest
/// ticket's proof have that ticket's honest delivery withdrawn from the plan,
/// and the one that does not -- the duplicate -- is a second copy of a ticket
/// the node may legitimately forward, which no fault verdict asks about.
fn forwards_of<'a>(ctx: &'a N2Ctx, attempt: u8, proof: &[u8; 784]) -> Vec<&'a NutTicketFacts> {
    ctx.nut_tickets
        .iter()
        .filter(|f| f.delivery == TicketDelivery::Ce132)
        .filter(|f| f.ticket.attempt == attempt && &f.ticket.proof == proof)
        .collect()
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

/// N2 — Generation, step 1 (`simple.md:314-316`): the NUT sends each ticket it
/// generates via CE 131 to the one validator that proxies it.
///
/// Each such ticket must name the epoch the NUT was generating for when it
/// sent it (the epoch after the sending slot's), carry an attempt inside the
/// per-validator range, verify against that epoch's ring, and go to exactly
/// one peer. Across an epoch the NUT may generate no more distinct tickets
/// than it has attempts.
pub fn n2_generation_step1(ctx: &N2Ctx) -> Check {
    let ctx = ctx.clone();
    check("n2_generation_step1", Severity::Hard, move |obs| {
        let proxied: Vec<&NutTicketFacts> = ctx
            .nut_tickets
            .iter()
            .filter(|f| f.delivery == TicketDelivery::Ce131)
            .collect();

        let mut results = vec![log::check(
            "n2_gen_ce131_observed",
            obs.first(ObsKind::Other(RECV_CE131)).is_some(),
            Severity::Hard,
        )];

        for (ticket, peers) in by_ticket(&proxied) {
            let expected = ctx.expected_target_epoch(ticket.received_at_ms);
            results.push(log::check_detail(
                "n2_gen_epoch_target",
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
                "n2_gen_attempt_in_range",
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
                "n2_gen_proof_verified",
                "n2_gen_proof_unjudged",
                &ticket,
            ));
            // Phase 0 is the epoch boundary itself, where the entropy a
            // ticket is sealed against has only just rotated; DESIGN §11 N2
            // asks for `slot >= epoch_start + 1`. polkajam submits no earlier
            // than `connect_buffer + max(epoch_buffer, finalized_phase)`,
            // which is 2 under tiny, so it clears this with a slot to spare.
            let sent_in = ctx.slot_at_ms(ticket.received_at_ms);
            results.push(log::check_detail(
                "n2_gen_not_before_epoch_start",
                ctx.phase_of(sent_in) >= 1,
                Severity::Hard,
                || {
                    format!(
                        "{} was sent in slot {sent_in}, phase {} of its epoch; \
                         generation starts at phase 1",
                        ticket_name(&ticket),
                        ctx.phase_of(sent_in),
                    )
                },
            ));
            // Soft: the selection rule may be polkajam's rather than the
            // protocol's (DESIGN §12 question 9). Set *membership* is what
            // DESIGN states, and it is not gradable here -- the harness holds
            // endpoints only for validators, so a CE 131 to a non-validator
            // never reaches the trace and a check for it could not fail.
            let designated = ctx.designated_proxy(&ticket.id);
            results.push(log::check_detail(
                "n2_gen_proxy_matches_rule",
                peers.len() == 1 && peers[0] == designated,
                Severity::Soft,
                || {
                    format!(
                        "{} is designated to validator {designated} by the proxy rule, \
                         but the NUT sent it to peer(s) {peers:?}",
                        ticket_name(&ticket),
                    )
                },
            ));
            results.push(log::check_detail(
                "n2_gen_one_proxy_per_ticket",
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
            .filter(|f| !ctx.is_an_emulator_ticket(f.ticket.attempt, &f.ticket.proof))
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
            "n2_gen_within_attempts_per_epoch",
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

/// N2 — Self-proxy (`simple.md:322-325`): a ticket the NUT proxies for itself
/// is broadcast via CE 132 to every current validator, so every emulated
/// validator must receive it.
///
/// A ticket the NUT generated *and* is the designated proxy for — both halves.
/// CE 132 also carries the tickets it forwards as other validators' proxy, and
/// those are `n2_proxy_duty`'s to judge. Counting them here graded the same
/// broadcast twice and, worse, let a run that self-proxied nothing report
/// self-proxy coverage on the strength of a forward.
pub fn n2_self_proxy(ctx: &N2Ctx) -> Check {
    let ctx = ctx.clone();
    check("n2_self_proxy", Severity::Hard, move |_obs| {
        let broadcast: Vec<&NutTicketFacts> = ctx
            .nut_tickets
            .iter()
            .filter(|f| f.delivery == TicketDelivery::Ce132)
            .filter(|f| !ctx.is_an_emulator_ticket(f.ticket.attempt, &f.ticket.proof))
            .filter(|f| ctx.designated_proxy(&f.id) == ctx.nut_index)
            .collect();
        let tickets = by_ticket(&broadcast);
        if tickets.is_empty() {
            // Which tickets a validator proxies for itself follows from the
            // epoch's entropy, so a run where none do is ordinary and not a
            // silence worth failing on.
            return vec![log::check("n2_self_proxy_none", true, Severity::Hard)];
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
                "n2_self_proxy_ce132_all_peers",
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
                "n2_self_proxy_proof_verified",
                "n2_self_proxy_proof_unjudged",
                &ticket,
            ));
        }
        results
    })
}

/// N2 — Proxy duty (`simple.md:329-332`): a CE 131 ticket the NUT receives as
/// proxy is verified and forwarded via CE 132 to every current validator. A
/// bad-proof ticket is refused instead, which the node signals by resetting
/// the stream it arrived on (soft).
///
/// The forward is matched by the ticket's own `(attempt, proof)`, not by the
/// bare fact that some CE 132 arrived: a node broadcasting only the tickets
/// it proxies for *itself* would satisfy an event count while forwarding
/// nothing.
///
/// Only a ticket the emulator actually delivered is judged. A planned ticket
/// the sender withheld never made the NUT anyone's proxy, so demanding a
/// forward for it reports a conforming node as broken.
pub fn n2_proxy_duty(ctx: &N2Ctx) -> Check {
    let ctx = ctx.clone();
    // No observation log: every fact this check reads is now attached to the
    // ticket it concerns, which is the point of the per-delivery refusal.
    check("n2_proxy_duty", Severity::Hard, move |_obs| {
        let mut results = Vec::new();
        for t in &ctx.emu_plan {
            if t.delivery != TicketDelivery::Ce131 || !ctx.proxy_is_nut(t) {
                continue;
            }
            let Some(arrived_at_ms) = t.delivered_at_ms else {
                results.push(log::check_detail(
                    "n2_proxy_duty_ticket_delivered",
                    false,
                    Severity::Soft,
                    || {
                        format!(
                            "the harness never put the ticket for slot {} on the wire, so \
                             the NUT was never the proxy for it and the duty was not \
                             exercised",
                            t.slot,
                        )
                    },
                ));
                continue;
            };
            let arrived_in = ctx.slot_at_ms(arrived_at_ms);
            if !t.valid {
                // This ticket's own refusal, not "some refusal happened
                // somewhere in the run". The check used to read an unscoped
                // `obs.first`, which any refused ticket -- or, before the
                // codes were split, any undecodable frame the node sent --
                // was enough to satisfy.
                results.push(log::check_detail(
                    "n2_proxy_duty_bad_proof_ignored",
                    t.refused,
                    Severity::Soft,
                    || {
                        format!(
                            "a ticket whose proof does not verify was proxied to the NUT                              in slot {arrived_in}; it must refuse it by resetting the                              stream, and it did not"
                        )
                    },
                ));
                continue;
            }
            if !ctx.leaves_room_to_forward(arrived_in) {
                results.push(log::check_detail(
                    "n2_proxy_duty_delivered_in_time",
                    false,
                    Severity::Soft,
                    || {
                        format!(
                            "the ticket was planned for slot {} but reached the NUT in \
                             slot {arrived_in}, phase {} of the lottery, too late in the \
                             epoch to demand a forward, so the duty was not exercised",
                            t.slot,
                            arrived_in % ctx.epoch_period,
                        )
                    },
                ));
                continue;
            }
            let forwards = forwards_of(&ctx, t.attempt, &t.proof);
            let reached: Vec<u16> = forwards.iter().map(|f| f.peer).collect();
            let missing: Vec<u16> = ctx
                .emulated_peers
                .iter()
                .copied()
                .filter(|p| !reached.contains(p))
                .collect();
            results.push(log::check_detail(
                "n2_proxy_duty_forwarded",
                missing.is_empty(),
                Severity::Hard,
                || {
                    format!(
                        "a ticket proxied to the NUT in slot {arrived_in} must be \
                         forwarded via CE 132 to every validator; it reached peer(s) \
                         {reached:?} and not {missing:?}",
                    )
                },
            ));
            // Timing, for the forwards that happened. The proxy delays before
            // forwarding, by a margin that is its own to choose (DESIGN §11
            // N2, "Forward window"), so neither the delay nor the window's
            // upper edge is assertable: polkajam's own end is phase 7 under
            // tiny, past the nominal `Y/2` of 5, and legitimately so. What
            // holds whatever the node chooses is that it did not forward
            // before it received, and did not forward after the lottery shut.
            for f in &forwards {
                let forwarded_in = ctx.slot_at_ms(f.received_at_ms);
                results.push(log::check_detail(
                    "n2_proxy_forward_after_arrival",
                    forwarded_in >= arrived_in && !ctx.slot_in_tail(forwarded_in),
                    Severity::Hard,
                    || {
                        format!(
                            "a forward must follow the arrival and stay inside the \
                             lottery; the ticket reached the NUT in slot {arrived_in} \
                             and was forwarded to peer {} in slot {forwarded_in}, \
                             phase {} of {}",
                            f.peer,
                            ctx.phase_of(forwarded_in),
                            ctx.epoch_tail_start,
                        )
                    },
                ));
            }
        }
        results
    })
}

/// N2 — Proxy duty, the stopping rule (DESIGN.md §11 N2, soft): a node has
/// no reason to keep forwarding a ticket once it is in a finalized block,
/// and must not.
///
/// The subject is the node's own account of finality, not the harness's.
/// DESIGN §10 defines "finalized" at depth ≥ 2 for the rules the *harness*
/// applies, but this rule is about a decision the node makes, and the node
/// publishes what it considers final in every UP 0 message it sends. A
/// ticket is finalized-included, for this row, from the first moment the
/// node advertised a `Final` at or past the slot of its own block carrying
/// the ticket.
///
/// Two controls, because two different silences would otherwise be read as
/// obedience:
///
/// - The run has to have reached that moment and gone on past it. A node
///   that was still being watched a slot later could have forwarded again;
///   one whose run ended at the moment of finality could not, and a pass
///   there would be a statement about the observation window.
/// - The node has to repeat a forward *somewhere* in the run. polkajam
///   sends exactly one CE 132 frame per ticket per peer, ever, so "it did
///   not forward again after finality" holds for it however the rule is
///   written, and a pass would say only that it never repeats anything.
///   Against such a node the row reports itself unexercised, which is the
///   honest verdict and the expected one; a node that re-gossips is the one
///   this rule has teeth against.
///
/// Scoped to the tickets the emulator proxied to the NUT, which is the
/// DESIGN row this rule sits in. A ticket the node broadcast for itself is
/// `n2_self_proxy`'s.
pub fn n2_forward_stops(ctx: &N2Ctx) -> Check {
    let ctx = ctx.clone();
    check("n2_forward_stops", Severity::Soft, move |_obs| {
        // A forwarded ticket, the block of the node's own that carried it,
        // and when the node first called that block final.
        let judged: Vec<(&EmuTicket, u32, u64)> = ctx
            .emu_plan
            .iter()
            .filter(|t| {
                t.delivery == TicketDelivery::Ce131
                    && ctx.proxy_is_nut(t)
                    && t.delivered()
                    && t.valid
                    && t.fault.is_none()
            })
            // A ticket the node never forwarded cannot have forwarded it
            // again; whether it should have is `n2_proxy_duty`'s row.
            .filter(|t| !forwards_of(&ctx, t.attempt, &t.proof).is_empty())
            .filter_map(|t| {
                // The earliest block carrying it: the node knew from then on
                // that the ticket was on its chain.
                let block = ctx
                    .nut_blocks
                    .iter()
                    .find(|b| b.ticket_ids.contains(&t.id))?;
                let final_at = ctx.declared_final_at_or_past(block.slot)?;
                ctx.still_advertising_after(final_at)
                    .then_some((t, block.slot, final_at))
            })
            .collect();
        let reached = Control::new(
            "n2_forward_finality_control_absent",
            "a ticket the NUT forwarded reaching a block of its own that it went on to \
             declare final, with the node still advertising a slot later",
            !judged.is_empty(),
        );
        if !reached.present() {
            return vec![reached.absent("n2_forward_stops_at_finality")];
        }
        // Any repeat, not only one of a forwarded ticket: what it establishes
        // is that this node's CE 132 path sends a ticket to a peer more than
        // once at all, which is the behaviour the rule bounds.
        let repeats = ctx.nut_tickets.iter().enumerate().any(|(i, f)| {
            f.delivery == TicketDelivery::Ce132
                && ctx.nut_tickets[..i].iter().any(|g| {
                    g.delivery == TicketDelivery::Ce132
                        && g.peer == f.peer
                        && g.identity() == f.identity()
                })
        });
        let repeating = Control::new(
            "n2_forward_repeat_control_absent",
            "the NUT sending a second CE 132 frame for a ticket it had already forwarded \
             to that peer",
            repeats,
        );
        if !repeating.present() {
            return vec![repeating.absent("n2_forward_stops_at_finality")];
        }
        judged
            .iter()
            .map(|&(t, slot, final_at)| {
                let late: Vec<u32> = forwards_of(&ctx, t.attempt, &t.proof)
                    .iter()
                    .filter(|f| f.received_at_ms > final_at)
                    .map(|f| ctx.slot_at_ms(f.received_at_ms))
                    .collect();
                log::negative(
                    "n2_forward_stops_at_finality",
                    &repeating,
                    late.is_empty(),
                    Severity::Soft,
                    || {
                        format!(
                            "a ticket the NUT forwarded is in its own block at slot \
                             {slot}, which it declared final in slot {}; it forwarded \
                             the ticket again in slot(s) {late:?}",
                            ctx.slot_at_ms(final_at),
                        )
                    },
                )
            })
            .collect()
    })
}

/// N2 — Inclusion (DESIGN.md §11 N2): the NUT blocks' ticket extrinsics hold
/// every valid delivered ticket, sorted and deduplicated; empty when a
/// block's slot is in the epoch tail.
///
/// Judged over *every* block the NUT authored in the epoch the tickets were
/// submittable in, not the newest alone. The rows that are properties of one
/// block — the tail rule, sortedness, and carrying nothing the harness never
/// sent — report once per block. Coverage is the epoch-wide statement, since
/// a node that fills an early block and leaves the last one empty has done
/// its job; reading only the newest block called that a failure.
///
/// Per-block *completeness* against the delivery clock is N1's
/// (`n1_extrinsic_includes_delivered` subtracts what is already on chain and
/// applies the arrival lead, over every NUT block in the run). This lane asks
/// the narrower question its own tickets raise: did the epoch's blocks carry
/// what was owed for the epoch they were submitted for.
pub fn n2_inclusion(ctx: &N2Ctx) -> Check {
    let ctx = ctx.clone();
    check("n2_inclusion", Severity::Hard, move |_obs| {
        // A ticket the harness deliberately broke is one the node must
        // refuse, so a block owes it nothing. `valid` does not express this:
        // it is the ring-signature verdict alone, and a wrong-proxy or late
        // ticket verifies perfectly well. The duplicate is the exception --
        // it is a second copy of a ticket that was honestly delivered, and
        // the block still owes that ticket a place, once.
        let owed = |t: &&EmuTicket| {
            t.delivered()
                && t.valid
                && t.target_epoch == ctx.target_epoch
                && t.fault.is_none_or(|f| f.still_owed_inclusion())
        };
        let mut expected: Vec<[u8; 32]> = ctx.emu_plan.iter().filter(owed).map(|t| t.id).collect();
        expected.sort();
        expected.dedup();

        // Withholding shrinks what inclusion can ask for, so a run that
        // withheld most of its tickets would otherwise pass this lane on a
        // near-empty expectation and look like coverage it never had.
        let mut results = Vec::new();
        let withheld = ctx
            .emu_plan
            .iter()
            .filter(|t| {
                !t.delivered()
                    && t.valid
                    && t.target_epoch == ctx.target_epoch
                    && t.fault.is_none_or(|f| f.still_owed_inclusion())
            })
            .count();
        if withheld > 0 {
            results.push(log::check_detail(
                "n2_inclusion_every_ticket_delivered",
                false,
                Severity::Soft,
                || {
                    format!(
                        "{withheld} of {} planned ticket(s) for epoch {} were never put on \
                         the wire, so inclusion is judged on the {} that were",
                        withheld + expected.len(),
                        ctx.target_epoch,
                        expected.len(),
                    )
                },
            ));
        }

        // No block in the epoch the tickets were submittable in: nothing to
        // judge. Saying so is the honest reading -- a pass here would credit
        // the node for a block it never authored.
        if ctx.nut_blocks.is_empty() {
            results.push(log::check_detail(
                "n2_inclusion_no_block_in_epoch",
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
            ));
            return results;
        }

        // Across the epoch, not within one block: a ticket the node carried
        // in its first block is on chain, and the last block owes it nothing.
        let taken = expected
            .iter()
            .filter(|id| ctx.any_block_carried(id))
            .count();
        // A negative rule, and an empty block satisfies it without the node
        // having chosen anything. Its control is that the node carried
        // something the emulator sent: only then has it made the selection
        // these rows judge. Run-level, because one empty block among several
        // is no evidence either way.
        let carried_a_delivered_ticket = Control::new(
            "n2_inclusion_control_absent",
            "a block carrying a ticket the emulator delivered",
            taken > 0,
        );

        for b in &ctx.nut_blocks {
            let slot = b.slot;
            results.push(log::check_detail(
                "n2_inclusion_empty_at_tail",
                !ctx.slot_in_tail(slot) || b.ticket_ids.is_empty(),
                Severity::Hard,
                || {
                    format!(
                        "slot {slot} is in the epoch tail, where the ticket extrinsic must \
                         be empty, but the block carried {} ticket(s)",
                        b.ticket_ids.len(),
                    )
                },
            ));
            results.push(log::check_detail(
                "n2_inclusion_sorted_dedup",
                is_sorted_dedup(&b.ticket_ids),
                Severity::Hard,
                || {
                    format!(
                        "the ticket extrinsic must be sorted by id and free of \
                         duplicates; the block at slot {slot} carried {} id(s) that are not",
                        b.ticket_ids.len(),
                    )
                },
            ));
            // The node is a validator itself, so its own tickets belong in
            // its own block just as much as the emulator's do.
            let extra = b
                .ticket_ids
                .iter()
                .filter(|id| !expected.contains(id) && !ctx.own_ticket_ids.contains(id))
                .count();
            results.push(log::negative(
                "n2_inclusion_no_extra",
                &carried_a_delivered_ticket,
                extra == 0,
                Severity::Hard,
                || {
                    format!(
                        "the block at slot {slot} carried {extra} ticket(s) that were \
                         neither delivered to the node nor announced by it"
                    )
                },
            ));
        }

        // A block holds at most `max_tickets_per_block` tickets -- three
        // under the tiny parameters, against the twenty the emulator
        // delivers in an epoch -- so demanding that the epoch carry every
        // valid ticket is a check no conforming node can pass. What is
        // required is that it filled from the valid set as far as one
        // block's cap allows; the rest stay owed by later epochs' blocks,
        // which N1 grades per block.
        if let Some(last) = ctx.last_chance_to_include() {
            // Only what the node held in time for that block. The epoch's
            // whole delivery set is not the measure, and reading it as one
            // charged a node whose single block fell at phase 2 with the
            // fourteen tickets that arrived over the rest of the lottery.
            let mut in_hand: Vec<[u8; 32]> = ctx
                .emu_plan
                .iter()
                .filter(owed)
                .filter(|t| ctx.in_hand_for_slot(t, last.slot))
                .map(|t| t.id)
                .collect();
            in_hand.sort();
            in_hand.dedup();
            let room = ctx.max_tickets_per_block.min(in_hand.len());
            let carried = in_hand
                .iter()
                .filter(|id| ctx.any_block_carried(id))
                .count();
            results.push(log::check_detail(
                "n2_inclusion_covers_valid",
                carried >= room,
                Severity::Hard,
                || {
                    format!(
                        "the NUT authored {} block(s) in epoch {}, the last able to carry \
                         tickets at slot {}; of the {} valid ticket(s) for epoch {} it held \
                         by then (of {} delivered in all) there was room for {room}, and \
                         they carried {carried}",
                        ctx.nut_blocks.len(),
                        ctx.target_epoch.saturating_sub(1),
                        last.slot,
                        in_hand.len(),
                        ctx.target_epoch,
                        expected.len(),
                    )
                },
            ));
        }
        results
    })
}

/// N2 — Unknown epoch (`simple.md:335-337`): a ticket for an epoch the NUT
/// cannot know yet makes it reset the stream.
///
/// The probe is the emulator's to send, so whether one went out is read from
/// the plan's delivered entries — scheduling one and withholding it leaves the
/// rule just as untested as never scheduling it. A run without one leaves the
/// rule untested, which is a soft result and not a pass.
pub fn n2_unknown_epoch_reset(ctx: &N2Ctx) -> Check {
    let ctx = ctx.clone();
    check("n2_unknown_epoch_reset", Severity::Hard, move |_obs| {
        let probes: Vec<&EmuTicket> = ctx
            .emu_plan
            .iter()
            .filter(|t| t.delivered() && t.target_epoch != ctx.target_epoch)
            .collect();
        if probes.is_empty() {
            return vec![log::check_detail(
                "n2_unknown_epoch_probed",
                false,
                Severity::Soft,
                || {
                    "no unknown-epoch ticket was scheduled, so the reset rule was \
                     not exercised"
                        .to_string()
                },
            )];
        }
        // Each probe's own refusal. Reading `obs.first` instead asked only
        // whether the node had reset *something*, which a refusal of any
        // other ticket satisfied just as well -- and with more than one
        // deliberately-wrong ticket in a run, that is no longer a rare
        // coincidence but the normal case.
        let unrefused = probes.iter().filter(|t| !t.refused).count();
        vec![log::check_detail(
            "n2_unknown_epoch_reset_observed",
            unrefused == 0,
            Severity::Hard,
            || {
                format!(
                    "{unrefused} of {} ticket(s) for an epoch past the NUT's horizon \
                     were delivered and not refused; it must reset the stream each \
                     arrived on",
                    probes.len(),
                )
            },
        )]
    })
}

/// N2 — Fault handling (DESIGN.md §11 N2, the Faults column): a ticket the
/// harness deliberately broke must leave no trace in what the node sends or
/// in the block it authors.
///
/// Every fault carries that prohibition except the duplicate, which is the
/// deliberate exception — a second copy of a ticket the block still owes a
/// place, once — and which the inclusion lane judges instead.
///
/// Both rows are negatives, so both are gated. A node that forwards nothing
/// and authors nothing satisfies "it did not forward the bad ticket" and "it
/// did not include the bad ticket" without having made a single decision, and
/// reporting that as a pass is the failure the N0 audit was written to catch.
/// Each control is the node doing the matching *positive* thing in the same
/// run: forwarding a ticket it was honestly proxied, and filling a block from
/// the tickets it was sent. The fault planner protects the first of those on
/// purpose — it skips the bad-proof fault rather than spend a run's only
/// NUT-proxied ticket on it.
///
/// Each row names the fault it judged, so a failure says *which* stimulus the
/// node mishandled rather than only that one of several got through.
pub fn n2_fault_handling(ctx: &N2Ctx) -> Check {
    let ctx = ctx.clone();
    check("n2_fault_handling", Severity::Hard, move |_obs| {
        let mut results = Vec::new();
        // Faults that reached the node and that it must leave no trace of. A
        // plan entry the sender withheld never became a stimulus, so it is
        // not a rule the run exercised.
        let forbidden: Vec<(&EmuTicket, TicketFault)> = ctx
            .emu_plan
            .iter()
            .filter(|t| t.delivered())
            .filter_map(|t| {
                t.fault
                    .filter(|f| !f.still_owed_inclusion())
                    .map(|f| (t, f))
            })
            .collect();
        if forbidden.is_empty() {
            return vec![log::check_detail(
                "n2_fault_injected",
                false,
                Severity::Soft,
                || {
                    "no faulted ticket reached the node, so the rules about what it must \
                     not forward and must not include were not exercised"
                        .to_string()
                },
            )];
        }

        // Only the faults proxied over CE 131 are judged for forwarding. A
        // node forwards what it is proxy for; it does not rebroadcast a
        // CE 132 arrival, sound or not. "The faulted broadcast was not
        // forwarded" would therefore hold in every run, including one against
        // a node that drops broadcasts entirely — a check that cannot fail.
        // The broadcast faults are judged by the inclusion row below.
        let proxied: Vec<(&EmuTicket, TicketFault)> = forbidden
            .iter()
            .copied()
            .filter(|(t, _)| t.delivery == TicketDelivery::Ce131)
            .collect();
        let forwards_at_all = ctx.emu_plan.iter().any(|t| {
            t.fault.is_none()
                && t.delivered()
                && t.valid
                && t.delivery == TicketDelivery::Ce131
                && ctx.proxy_is_nut(t)
                && !forwards_of(&ctx, t.attempt, &t.proof).is_empty()
        });
        let forwarding = Control::new(
            "n2_fault_forward_control_absent",
            "the NUT forwarding a ticket it was honestly proxied, alongside a faulted one",
            forwards_at_all && !proxied.is_empty(),
        );
        // One row per fault when the control is there; one row for the run
        // when it is not, since with nothing to loop over the absence would
        // otherwise go unreported.
        if forwarding.present() {
            for &(t, fault) in &proxied {
                let reached: Vec<u16> = forwards_of(&ctx, t.attempt, &t.proof)
                    .iter()
                    .map(|f| f.peer)
                    .collect();
                let arrived = t.delivered_at_ms.map_or(t.slot, |ms| ctx.slot_at_ms(ms));
                results.push(log::negative(
                    "n2_fault_not_forwarded",
                    &forwarding,
                    reached.is_empty(),
                    Severity::Hard,
                    || {
                        format!(
                            "a ticket proxied to the NUT in slot {arrived} must not be \
                             forwarded, because {}; it went out over CE 132 to peer(s) \
                             {reached:?}",
                            fault.describe(),
                        )
                    },
                ));
            }
        } else {
            results.push(forwarding.absent("n2_fault_not_forwarded"));
        }

        // The ids the block was entitled to carry from the emulator, which is
        // `n2_inclusion`'s expected set: a ticket delivered, sound, for the
        // epoch being submitted, and not one the harness broke.
        let owed: Vec<[u8; 32]> = ctx
            .emu_plan
            .iter()
            .filter(|t| {
                t.delivered()
                    && t.valid
                    && t.target_epoch == ctx.target_epoch
                    && t.fault.is_none_or(|f| f.still_owed_inclusion())
            })
            .map(|t| t.id)
            .collect();
        let built_from_deliveries = ctx
            .nut_blocks
            .iter()
            .any(|b| b.ticket_ids.iter().any(|id| owed.contains(id)));
        // A fault that arrived after the last block was sealed could not have
        // been in any of them, so passing on one claims nothing. The
        // prohibition is still judged over every fault — an inclusion is a
        // failure wherever it is seen — but the control asks for at least one
        // the node had in hand while it still had a block to put it in.
        let had_one_in_hand = ctx.nut_blocks.last().is_some_and(|last| {
            forbidden.iter().any(|(t, _)| {
                t.delivered_at_ms
                    .is_some_and(|ms| ctx.slot_at_ms(ms) < last.slot)
            })
        });
        let selection = Control::new(
            "n2_fault_inclusion_control_absent",
            "a block built from the tickets the emulator delivered, with a faulted one \
             already in the node's hands",
            built_from_deliveries && had_one_in_hand,
        );
        // One row per fault, over the whole epoch rather than one block: the
        // rule is that the node's chain never carries the ticket, and judging
        // its last block alone let it bury one in any of the others.
        if selection.present() {
            for &(t, fault) in &forbidden {
                let carried: Vec<u32> = ctx
                    .nut_blocks
                    .iter()
                    .filter(|b| b.ticket_ids.contains(&t.id))
                    .map(|b| b.slot)
                    .collect();
                results.push(log::negative(
                    "n2_fault_not_included",
                    &selection,
                    carried.is_empty(),
                    Severity::Hard,
                    || {
                        format!(
                            "no block of epoch {} may carry a ticket the node was required \
                             to refuse, because {}; it is in the block(s) at slot(s) \
                             {carried:?}",
                            ctx.target_epoch.saturating_sub(1),
                            fault.describe(),
                        )
                    },
                ));
            }
        } else {
            results.push(selection.absent("n2_fault_not_included"));
        }
        results
    })
}

/// The seven N2 checks: DESIGN.md §11 N2 row order, then the Faults column,
/// which spans the rows and so cannot sit inside any one of them.
pub fn all(ctx: &N2Ctx) -> Vec<Check> {
    vec![
        n2_generation_step1(ctx),
        n2_self_proxy(ctx),
        n2_proxy_duty(ctx),
        n2_forward_stops(ctx),
        n2_inclusion(ctx),
        n2_unknown_epoch_reset(ctx),
        n2_fault_handling(ctx),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctx::{
        EmuTicket, NutBlockTickets, NutFinal, NutTicketFacts, MAX_TICKETS_PER_BLOCK, SLOT_PERIOD_MS,
    };
    use crate::dsl::{CheckResult, Obs, ObsLog, Outcome};
    use jam_types::JAM_COMMON_ERA;

    const EPOCH_PERIOD: u32 = 12;
    const EPOCH_TAIL_START: u32 = 10;
    const TICKETS_PER_VALIDATOR: u8 = 4;
    /// The NUT in these fixtures, with the other five validators emulated.
    const NUT: u16 = 5;
    const TARGET_EPOCH: u32 = 3;
    /// Where a ticket for `TARGET_EPOCH` is delivered: the epoch before it, at
    /// phase 1. The same slot `during(TARGET_EPOCH - 1)` names, so a forward
    /// stamped with that helper is not earlier than the arrival it answers.
    const SUBMITTED_IN_SLOT: u32 = (TARGET_EPOCH - 1) * EPOCH_PERIOD + 1;
    /// Slots in the submission epoch a block may be authored at. `JUDGED_BLOCK`
    /// is the next slot after the one `emu` delivers in, which clears the
    /// arrival lead: a block at `SUBMITTED_IN_SLOT` itself is sealed before
    /// the ticket reaches the node and is owed nothing.
    const JUDGED_BLOCK: u32 = SUBMITTED_IN_SLOT + 1;
    const LATER_BLOCK: u32 = SUBMITTED_IN_SLOT + 5;
    /// Phase 10 of the submission epoch: `EPOCH_TAIL_START`, where the ticket
    /// extrinsic must be empty.
    const TAIL_BLOCK: u32 = (TARGET_EPOCH - 1) * EPOCH_PERIOD + EPOCH_TAIL_START;

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
    /// The first slot of `epoch` at which a validator may generate: phase 1,
    /// not phase 0. Generation starts at `epoch_start + 1` (DESIGN §11 N2), so
    /// a fixture stamped on the boundary describes a node breaking that rule.
    /// The epoch the lane derives is unaffected -- both phases divide to the
    /// same epoch.
    fn during(epoch: u32) -> u64 {
        JAM_COMMON_ERA * 1000 + u64::from(epoch * EPOCH_PERIOD + 1) * SLOT_PERIOD_MS
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
            // A ticket for `TARGET_EPOCH` is submitted during the epoch
            // before it, early in that lottery so a ticket proxied to the NUT
            // here leaves it room to forward. These used to sit in
            // `TARGET_EPOCH` itself, which is past the window the ticket
            // could be submitted in at all -- harmless while nothing compared
            // the arrival against anything, and caught the moment
            // `n2_proxy_forward_after_arrival` did.
            slot: SUBMITTED_IN_SLOT,
            target_epoch: TARGET_EPOCH,
            // The fixtures describe tickets the NUT was actually sent, in the
            // slot they were planned for; the withheld and late cases are
            // built explicitly where they are tested.
            delivered_at_ms: Some(
                JAM_COMMON_ERA * 1000 + u64::from(SUBMITTED_IN_SLOT) * SLOT_PERIOD_MS,
            ),
            // The node accepted it; the refusing cases are built where
            // they are tested.
            refused: false,
            fault: None,
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
        // The id designates the peer the frame was sent to, so a fixture is
        // proxy-correct unless it deliberately is not. For a uniform id byte
        // `k` the proxy rule reduces to `k mod 6`, the fixtures' validator
        // count, because `0x01010101 ≡ 1 (mod 6)`.
        nut_with_id(attempt, id_for_proxy(peer), peer, delivery)
    }

    /// An id byte that the proxy rule maps to `proxy` over six validators.
    fn id_for_proxy(proxy: u16) -> [u8; 32] {
        [proxy as u8; 32]
    }

    fn nut_with_id(
        attempt: u8,
        id: [u8; 32],
        peer: u16,
        delivery: TicketDelivery,
    ) -> NutTicketFacts {
        NutTicketFacts {
            epoch: TARGET_EPOCH,
            ticket: jamnp_s::codec::ce131_136::Ticket {
                attempt,
                proof: proof(attempt),
            },
            id,
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
    ) -> N2Ctx {
        ctx_blocks(
            emu_plan,
            nut_tickets,
            vec![NutBlockTickets {
                slot: nut_block_slot,
                ticket_ids: nut_block_ticket_ids,
            }],
        )
    }
    /// The same, for the cases that need more than one block in the epoch.
    fn ctx_blocks(
        emu_plan: Vec<EmuTicket>,
        nut_tickets: Vec<NutTicketFacts>,
        nut_blocks: Vec<NutBlockTickets>,
    ) -> N2Ctx {
        // A node that advertised no finality: the honest default, since only
        // the stopping rule reads these and its own fixtures set them.
        ctx_finals(emu_plan, nut_tickets, nut_blocks, Vec::new())
    }
    /// The same again, for the stopping rule, which is the one check that
    /// reads what the node said it had finalized.
    fn ctx_finals(
        emu_plan: Vec<EmuTicket>,
        nut_tickets: Vec<NutTicketFacts>,
        nut_blocks: Vec<NutBlockTickets>,
        nut_finals: Vec<NutFinal>,
    ) -> N2Ctx {
        N2Ctx {
            target_epoch: TARGET_EPOCH,
            epoch_start_slot: TARGET_EPOCH * EPOCH_PERIOD,
            emu_plan,
            nut_tickets,
            nut_blocks,
            nut_finals,
            own_ticket_ids: Vec::new(),
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
    fn n2_generation_pass_and_bad_proof() {
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
            all_pass(&run(&n2_generation_step1(&c), &obs)),
            "verified CE 131 NUT tickets pass"
        );

        let mut unverified = nut(0, 1, TicketDelivery::Ce131);
        unverified.verified = Some(false);
        let bad = ctx(vec![], vec![unverified], vec![], 0);
        assert!(
            failed(
                &run(&n2_generation_step1(&bad), &obs),
                "n2_gen_proof_verified",
                Severity::Hard
            ),
            "an unverified NUT ticket fails hard"
        );

        let mut wrong_epoch = nut(0, 1, TicketDelivery::Ce131);
        wrong_epoch.epoch = TARGET_EPOCH + 1;
        let c = ctx(vec![], vec![wrong_epoch], vec![], 0);
        assert!(
            failed(
                &run(&n2_generation_step1(&c), &obs),
                "n2_gen_epoch_target",
                Severity::Hard
            ),
            "a ticket naming an epoch other than the one being generated for fails hard"
        );

        let mut over_attempt = nut(0, 1, TicketDelivery::Ce131);
        over_attempt.ticket.attempt = TICKETS_PER_VALIDATOR;
        let c = ctx(vec![], vec![over_attempt], vec![], 0);
        assert!(
            failed(
                &run(&n2_generation_step1(&c), &obs),
                "n2_gen_attempt_in_range",
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
                &run(&n2_generation_step1(&over), &obs),
                "n2_gen_within_attempts_per_epoch",
                Severity::Hard
            ),
            "more distinct tickets than attempts in one epoch fails hard"
        );
    }

    /// A proof the harness holds no context for is reported as unjudged, not
    /// as a failure: the node is not at fault for the harness's blind spot.
    #[test]
    fn n2_generation_separates_unjudged_proofs_from_bad_ones() {
        let mut unjudged = nut(0, 1, TicketDelivery::Ce131);
        unjudged.verified = None;
        let c = ctx(vec![], vec![unjudged], vec![], 0);
        let mut obs = ObsLog::new();
        obs.push(0, ev(1, ObsKind::Other(RECV_CE131), 0));
        let results = run(&n2_generation_step1(&c), &obs);
        assert!(
            failed(&results, "n2_gen_proof_unjudged", Severity::Soft),
            "an unjudgeable proof is a soft result"
        );
        assert!(
            !results.iter().any(|r| r.name == "n2_gen_proof_verified"),
            "and is never reported as a failed verification"
        );
    }

    /// One broadcast ticket is one ticket, however many validators it reached.
    #[test]
    fn n2_generation_counts_tickets_not_frames() {
        let broadcast: Vec<NutTicketFacts> = (0..NUT)
            .map(|peer| nut(0, peer, TicketDelivery::Ce132))
            .collect();
        let c = ctx(vec![], broadcast, vec![], 0);
        let mut obs = ObsLog::new();
        obs.push(0, ev(1, ObsKind::Other(RECV_CE131), 0));
        let results = run(&n2_generation_step1(&c), &obs);
        assert!(
            !failed(&results, "n2_gen_within_attempts_per_epoch", Severity::Hard),
            "the five copies of one CE 132 broadcast are one ticket against the cap"
        );
    }

    /// A proxy's forwards are other validators' tickets, so they must not
    /// count against the node's own per-epoch attempts.
    #[test]
    fn n2_generation_does_not_charge_forwards_to_the_node() {
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
                &run(&n2_generation_step1(&c), &obs),
                "n2_gen_within_attempts_per_epoch",
                Severity::Hard
            ),
            "forwarding a full epoch of another validator's tickets is not generating them"
        );
    }

    /// The epoch a ticket must name follows the clock, so a run that crosses
    /// an epoch boundary sees the NUT change target and is still conforming.
    #[test]
    fn n2_generation_follows_the_clock_across_an_epoch_boundary() {
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
            all_pass(&run(&n2_generation_step1(&c), &obs)),
            "each ticket is judged against the epoch it was generated in"
        );
    }

    /// CE 131 names one proxy: the same ticket on two connections is not one.
    #[test]
    fn n2_generation_proxies_each_ticket_to_one_peer() {
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
                &run(&n2_generation_step1(&c), &obs),
                "n2_gen_one_proxy_per_ticket",
                Severity::Hard
            ),
            "one ticket proxied to two validators fails hard"
        );
    }

    #[test]
    fn n2_self_proxy_pass_and_missing_peer() {
        // One ticket, whose designated proxy is the NUT itself, reaching every
        // peer. `nut` would give each frame an id naming the peer it reached,
        // which describes five different tickets proxied elsewhere -- not a
        // self-proxy broadcast at all.
        let broadcast: Vec<NutTicketFacts> = (0..NUT)
            .map(|peer| nut_with_id(0, id_for_proxy(NUT), peer, TicketDelivery::Ce132))
            .collect();
        let c = ctx(vec![], broadcast.clone(), vec![], 0);
        assert!(
            all_pass(&run(&n2_self_proxy(&c), &ObsLog::new())),
            "a ticket broadcast to every validator passes"
        );

        let short = ctx(vec![], broadcast[1..].to_vec(), vec![], 0);
        assert!(
            failed(
                &run(&n2_self_proxy(&short), &ObsLog::new()),
                "n2_self_proxy_ce132_all_peers",
                Severity::Hard
            ),
            "a validator the broadcast missed fails hard"
        );
    }

    /// Generation starts at `epoch_start + 1` (DESIGN §11 N2), so a ticket
    /// sent on the boundary itself is a failure and not a rounding artefact.
    #[test]
    fn n2_generation_rejects_a_ticket_sent_on_the_epoch_boundary() {
        let mut on_the_boundary = nut(0, 1, TicketDelivery::Ce131);
        on_the_boundary.received_at_ms =
            JAM_COMMON_ERA * 1000 + u64::from((TARGET_EPOCH - 1) * EPOCH_PERIOD) * SLOT_PERIOD_MS;
        let c = ctx(vec![], vec![on_the_boundary], vec![], 0);
        let mut obs = ObsLog::new();
        obs.push(0, ev(1, ObsKind::Other(RECV_CE131), 0));
        assert!(
            failed(
                &run(&n2_generation_step1(&c), &obs),
                "n2_gen_not_before_epoch_start",
                Severity::Hard
            ),
            "a CE 131 at phase 0 fails hard"
        );
    }

    /// The proxy a ticket is destined for follows from its id, so a node that
    /// sends it to some other validator is reported -- softly, because
    /// DESIGN §12 question 9 has not settled whether the rule is normative.
    #[test]
    fn n2_generation_reports_a_ticket_sent_to_the_wrong_proxy() {
        let right = nut_with_id(0, id_for_proxy(2), 2, TicketDelivery::Ce131);
        let c = ctx(vec![], vec![right], vec![], 0);
        let mut obs = ObsLog::new();
        obs.push(0, ev(1, ObsKind::Other(RECV_CE131), 0));
        assert!(
            all_pass(&run(&n2_generation_step1(&c), &obs)),
            "a ticket sent to the validator its id names passes"
        );

        // Same ticket, delivered to a validator that is not its proxy. The
        // hard rows still pass -- it did go to exactly one peer, and not to
        // itself -- so only the rule row can catch this.
        let wrong = nut_with_id(0, id_for_proxy(2), 3, TicketDelivery::Ce131);
        let c = ctx(vec![], vec![wrong], vec![], 0);
        assert!(
            failed(
                &run(&n2_generation_step1(&c), &obs),
                "n2_gen_proxy_matches_rule",
                Severity::Soft
            ),
            "a ticket sent to a validator other than its proxy is reported"
        );
    }

    /// A forward cannot precede the arrival it answers, and cannot land after
    /// the lottery has closed. The window's upper edge inside the lottery is
    /// the node's own to choose (DESIGN §11 N2) and is not asserted.
    #[test]
    fn n2_proxy_duty_rejects_a_forward_outside_the_lottery() {
        let good = emu(1, NUT, true, TicketDelivery::Ce131);
        let at = |slot: u32| {
            let mut f = forwarded(&good, 0);
            f.received_at_ms = JAM_COMMON_ERA * 1000 + u64::from(slot) * SLOT_PERIOD_MS;
            f
        };
        let forwards_at = |slot: u32| {
            let mut all: Vec<NutTicketFacts> =
                (1..NUT).map(|peer| forwarded(&good, peer)).collect();
            all.push(at(slot));
            all
        };

        // Phase 7: past the nominal Y/2 of 5, inside the window polkajam
        // actually uses. A conforming forward, and it must pass.
        let late_but_legal = ctx(
            vec![good],
            forwards_at((TARGET_EPOCH - 1) * EPOCH_PERIOD + 7),
            vec![],
            0,
        );
        assert!(
            all_pass(&run(&n2_proxy_duty(&late_but_legal), &ObsLog::new())),
            "a forward at phase 7 is inside the lottery and passes"
        );

        // Phase 10 is the tail: the lottery has closed.
        let in_the_tail = ctx(
            vec![good],
            forwards_at((TARGET_EPOCH - 1) * EPOCH_PERIOD + EPOCH_TAIL_START),
            vec![],
            0,
        );
        assert!(
            failed(
                &run(&n2_proxy_duty(&in_the_tail), &ObsLog::new()),
                "n2_proxy_forward_after_arrival",
                Severity::Hard
            ),
            "a forward in the epoch tail fails hard"
        );

        // Before the ticket ever reached it.
        let before_arrival = ctx(vec![good], forwards_at(SUBMITTED_IN_SLOT - 1), vec![], 0);
        assert!(
            failed(
                &run(&n2_proxy_duty(&before_arrival), &ObsLog::new()),
                "n2_proxy_forward_after_arrival",
                Severity::Hard
            ),
            "a forward stamped before the arrival fails hard"
        );
    }

    /// CE 132 carries both the tickets the NUT proxies for itself and the ones
    /// it forwards for others. Counting a forward as a self-proxy lets a run
    /// that self-proxied nothing report self-proxy coverage it never had.
    #[test]
    fn n2_self_proxy_ignores_tickets_the_node_merely_forwarded() {
        let forwarded_for_someone_else = emu(1, NUT, true, TicketDelivery::Ce131);
        let broadcast: Vec<NutTicketFacts> = (0..NUT)
            .map(|peer| forwarded(&forwarded_for_someone_else, peer))
            .collect();
        let c = ctx(vec![forwarded_for_someone_else], broadcast, vec![], 0);

        let results = run(&n2_self_proxy(&c), &ObsLog::new());

        assert!(
            results.iter().all(|r| r.name == "n2_self_proxy_none"),
            "a forwarded ticket is the proxy duty's to judge, not the self-proxy row's: {:?}",
            results.iter().map(|r| r.name).collect::<Vec<_>>(),
        );
    }

    /// Self-proxying is what CE 132 means, not which peer a frame reached:
    /// reading it off the peer index makes the check unfailable, since the
    /// NUT never holds a connection to itself.
    #[test]
    fn n2_self_proxy_reads_the_stream_kind_not_the_peer() {
        let proxied = ctx(vec![], vec![nut(0, 1, TicketDelivery::Ce131)], vec![], 0);
        let results = run(&n2_self_proxy(&proxied), &ObsLog::new());
        assert!(
            results.iter().all(|r| r.name == "n2_self_proxy_none"),
            "a CE 131 distribution is never a self-proxy broadcast"
        );
    }

    #[test]
    fn n2_proxy_duty_pass_and_unforwarded() {
        let good = emu(1, NUT, true, TicketDelivery::Ce131);
        // A bad proof the node refused, which is what it owes for one.
        let bad = EmuTicket {
            refused: true,
            ..emu(2, NUT, false, TicketDelivery::Ce131)
        };
        let forwards: Vec<NutTicketFacts> = (0..NUT).map(|peer| forwarded(&good, peer)).collect();
        let c = ctx(vec![good, bad], forwards.clone(), vec![], 0);
        let obs = ObsLog::new();
        assert!(
            all_pass(&run(&n2_proxy_duty(&c), &obs)),
            "a forwarded valid ticket and a refused bad proof pass"
        );

        let short = ctx(vec![good, bad], forwards[1..].to_vec(), vec![], 0);
        assert!(
            failed(
                &run(&n2_proxy_duty(&short), &obs),
                "n2_proxy_duty_forwarded",
                Severity::Hard
            ),
            "a validator the forward missed fails hard"
        );

        let none = ctx(vec![good, bad], vec![], vec![], 0);
        assert!(
            failed(
                &run(&n2_proxy_duty(&none), &obs),
                "n2_proxy_duty_forwarded",
                Severity::Hard
            ),
            "a valid ticket not forwarded at all fails hard"
        );

        // A bad proof the node accepted rather than refused. An empty
        // observation log no longer decides this either way: the refusal is a
        // fact about the ticket, so the same run that refuses one bad ticket
        // can still be caught accepting another.
        let accepted_a_bad_proof = ctx(
            vec![good, emu(2, NUT, false, TicketDelivery::Ce131)],
            forwards,
            vec![],
            0,
        );
        assert!(
            failed(
                &run(&n2_proxy_duty(&accepted_a_bad_proof), &obs),
                "n2_proxy_duty_bad_proof_ignored",
                Severity::Soft
            ),
            "a bad proof the node did not refuse is a soft fail"
        );
    }

    /// `n2_inclusion_no_extra` asks what the block did *not* carry, which an
    /// empty block satisfies without the node having selected anything. The
    /// run says the rule was not exercised instead of passing it.
    #[test]
    fn inclusion_claims_no_coverage_from_an_empty_block() {
        let delivered = emu(1, 0, true, TicketDelivery::Ce132);
        let id = delivered.id;

        // A block carrying the delivered ticket: the control holds, and the
        // row is judged as before.
        let carried = ctx(vec![delivered], vec![], vec![id], JUDGED_BLOCK);
        let results = run(&n2_inclusion(&carried), &ObsLog::new());
        assert!(
            results.iter().any(|r| r.name == "n2_inclusion_no_extra"),
            "a block that selected something is judged on what it left in: {:?}",
            results.iter().map(|r| r.name).collect::<Vec<_>>(),
        );

        // The same run, with an empty block. `extra == 0` holds trivially.
        let empty = ctx(vec![delivered], vec![], vec![], JUDGED_BLOCK);
        let results = run(&n2_inclusion(&empty), &ObsLog::new());
        assert!(
            !results.iter().any(|r| r.name == "n2_inclusion_no_extra"),
            "an empty block must not collect a pass for carrying nothing extra"
        );
        assert!(
            failed(&results, "n2_inclusion_control_absent", Severity::Soft),
            "it reports the rule as unexercised instead: {:?}",
            results.iter().map(|r| r.name).collect::<Vec<_>>(),
        );
    }

    /// A refusal belongs to the ticket it answered. Both of these checks used
    /// to read an unscoped `obs.first`, so one reset anywhere in a run
    /// satisfied every rule that wanted one -- tolerable only while the
    /// unknown-epoch probe was the single ticket a node was meant to reject,
    /// and wrong the moment a run carries more than one.
    #[test]
    fn a_refusal_of_one_ticket_does_not_answer_for_another() {
        let refused_bad_proof = EmuTicket {
            refused: true,
            ..emu(2, NUT, false, TicketDelivery::Ce131)
        };
        let mut accepted_probe = emu(9, 0, true, TicketDelivery::Ce132);
        accepted_probe.target_epoch = TARGET_EPOCH + 2;

        let c = ctx(vec![refused_bad_proof, accepted_probe], vec![], vec![], 0);

        // The node refused the bad proof, so that rule is satisfied...
        assert!(
            all_pass(&run(&n2_proxy_duty(&c), &ObsLog::new())),
            "the refused bad proof passes"
        );
        // ...and the probe it accepted is still caught, which the observation
        // log alone could not distinguish.
        assert!(
            failed(
                &run(&n2_unknown_epoch_reset(&c), &ObsLog::new()),
                "n2_unknown_epoch_reset_observed",
                Severity::Hard
            ),
            "the accepted probe fails even though another ticket was refused"
        );
    }

    /// The forward is matched by the ticket it carries. A node that broadcast
    /// only its own tickets would otherwise satisfy a check that merely
    /// counted CE 132 frames.
    #[test]
    fn n2_proxy_duty_matches_the_ticket_not_the_frame() {
        let owed = emu(1, NUT, true, TicketDelivery::Ce131);
        let others: Vec<NutTicketFacts> = (0..NUT)
            .map(|peer| nut(3, peer, TicketDelivery::Ce132))
            .collect();
        let c = ctx(vec![owed], others, vec![], 0);
        assert!(
            failed(
                &run(&n2_proxy_duty(&c), &ObsLog::new()),
                "n2_proxy_duty_forwarded",
                Severity::Hard
            ),
            "broadcasting some other ticket is not forwarding this one"
        );
    }

    /// The slot a ticket was *planned* for says nothing about when it
    /// arrived. A sender whose connection came up late delivers several slots
    /// on, and judging the plan demanded a forward for tickets that reached
    /// the node after any forwarding window had shut — four hard failures in
    /// one observed run, every one of them the harness's.
    #[test]
    fn n2_proxy_duty_judges_the_arrival_not_the_plan() {
        let mut late = emu(1, NUT, true, TicketDelivery::Ce131);
        // Planned early in the lottery, where a forward is owed ...
        late.slot = TARGET_EPOCH * EPOCH_PERIOD + 1;
        // ... but it did not reach the node until the lottery was nearly over.
        let arrived = TARGET_EPOCH * EPOCH_PERIOD + EPOCH_TAIL_START - 1;
        late.delivered_at_ms = Some(JAM_COMMON_ERA * 1000 + u64::from(arrived) * SLOT_PERIOD_MS);
        let c = ctx(vec![late], vec![], vec![], 0);
        let results = run(&n2_proxy_duty(&c), &ObsLog::new());
        assert!(
            failed(&results, "n2_proxy_duty_delivered_in_time", Severity::Soft),
            "a late arrival is reported: {results:?}"
        );
        assert!(
            !results.iter().any(|r| r.name == "n2_proxy_duty_forwarded"),
            "and the forward is never judged on it"
        );
    }

    /// A proxy forwards within a window, not on receipt, so a ticket the
    /// harness delivered late in the lottery is reported as not exercised
    /// rather than as a node that failed to forward.
    #[test]
    fn n2_proxy_duty_late_delivery_is_untested_not_failed() {
        let mut late = emu(1, NUT, true, TicketDelivery::Ce131);
        let arrived = TARGET_EPOCH * EPOCH_PERIOD + EPOCH_TAIL_START - 1;
        late.slot = arrived;
        late.delivered_at_ms = Some(JAM_COMMON_ERA * 1000 + u64::from(arrived) * SLOT_PERIOD_MS);
        let c = ctx(vec![late], vec![], vec![], 0);
        let results = run(&n2_proxy_duty(&c), &ObsLog::new());
        assert!(
            failed(&results, "n2_proxy_duty_delivered_in_time", Severity::Soft),
            "a late delivery is reported: {results:?}"
        );
        assert!(
            !results.iter().any(|r| r.name == "n2_proxy_duty_forwarded"),
            "and the forward is never judged on it"
        );
    }

    /// A ticket the emulator planned but never put on the wire never made the
    /// NUT anyone's proxy. Grading the plan rather than the deliveries is how
    /// the harness's own ticket-delivery race turned into a hard failure
    /// against a node that had done nothing wrong.
    #[test]
    fn n2_proxy_duty_withheld_ticket_is_untested_not_failed() {
        let mut withheld = emu(1, NUT, true, TicketDelivery::Ce131);
        withheld.delivered_at_ms = None;
        let c = ctx(vec![withheld], vec![], vec![], 0);
        let results = run(&n2_proxy_duty(&c), &ObsLog::new());
        assert!(
            failed(&results, "n2_proxy_duty_ticket_delivered", Severity::Soft),
            "a withheld ticket is reported as unexercised: {results:?}"
        );
        assert!(
            !results.iter().any(|r| r.name == "n2_proxy_duty_forwarded"),
            "and no forward is demanded for a ticket the node never received"
        );
    }

    /// Inclusion is owed for tickets the node was actually sent. A withheld
    /// one is not in any block because it was never offered, which is not the
    /// node leaving a ticket out.
    #[test]
    fn n2_inclusion_ignores_a_withheld_ticket() {
        let sent = emu(1, 0, true, TicketDelivery::Ce132);
        let mut withheld = emu(2, 0, true, TicketDelivery::Ce132);
        withheld.delivered_at_ms = None;
        let c = ctx(vec![sent, withheld], vec![], vec![[1u8; 32]], JUDGED_BLOCK);
        let results = run(&n2_inclusion(&c), &ObsLog::new());
        assert!(
            failed(
                &results,
                "n2_inclusion_every_ticket_delivered",
                Severity::Soft
            ),
            "the withheld ticket is reported rather than silently dropped: {results:?}"
        );
        assert!(
            !failed(&results, "n2_inclusion_covers_valid", Severity::Hard),
            "and the node is not charged for leaving it out"
        );
    }

    /// The unknown-epoch probe is the emulator's to send. Scheduling one and
    /// withholding it leaves the reset rule as untested as never scheduling
    /// one, so the lane must not demand the reset.
    #[test]
    fn n2_unknown_epoch_withheld_probe_is_not_demanded() {
        let mut probe = emu(3, 0, true, TicketDelivery::Ce132);
        probe.target_epoch = TARGET_EPOCH + 2;
        probe.delivered_at_ms = None;
        let c = ctx(vec![probe], vec![], vec![], 0);
        let results = run(&n2_unknown_epoch_reset(&c), &ObsLog::new());
        assert!(
            failed(&results, "n2_unknown_epoch_probed", Severity::Soft),
            "a withheld probe reports the rule unexercised: {results:?}"
        );
        assert!(
            !results
                .iter()
                .any(|r| r.name == "n2_unknown_epoch_reset_observed"),
            "and the reset is never demanded"
        );
    }

    /// The peers a forward must reach are the ones the run emulates. Holding
    /// a fixed set instead leaves the check unable to pass whenever the NUT
    /// sits at an index that set assumed was emulated.
    #[test]
    fn n2_proxy_duty_reaches_the_peers_the_run_emulates() {
        let owed = emu(1, 0, true, TicketDelivery::Ce131);
        let forwards: Vec<NutTicketFacts> = (1..=5).map(|peer| forwarded(&owed, peer)).collect();
        let mut c = ctx(vec![owed], forwards, vec![], 0);
        c.nut_index = 0;
        c.emulated_peers = (1..=5).collect();
        assert!(
            all_pass(&run(&n2_proxy_duty(&c), &ObsLog::new())),
            "a NUT at index 0 forwards to validators 1..=5"
        );
    }

    /// The node under test is a validator: it runs the lottery too, and its
    /// own tickets belong in its own block. Charging them as tickets nobody
    /// delivered failed a node for doing what the protocol asks.
    #[test]
    fn n2_inclusion_allows_the_nodes_own_tickets() {
        let mut c = ctx(
            vec![emu(1, 0, true, TicketDelivery::Ce132)],
            vec![],
            vec![[1u8; 32], [9u8; 32]],
            JUDGED_BLOCK,
        );
        assert!(
            failed(
                &run(&n2_inclusion(&c), &ObsLog::new()),
                "n2_inclusion_no_extra",
                Severity::Hard
            ),
            "a ticket from nowhere is still an extra"
        );

        c.own_ticket_ids = vec![[9u8; 32]];
        assert!(
            all_pass(&run(&n2_inclusion(&c), &ObsLog::new())),
            "the same ticket, announced by the node itself, is its own to carry"
        );
    }

    /// A block holds at most `max_tickets_per_block` tickets, so requiring one
    /// block to carry every valid ticket delivered for the epoch is a check no
    /// conforming node can pass once more than the cap have been delivered.
    #[test]
    fn n2_inclusion_asks_only_for_what_a_block_can_hold() {
        let delivered: Vec<EmuTicket> = (1..=5u8)
            .map(|id| emu(id, 0, true, TicketDelivery::Ce132))
            .collect();
        let full: Vec<[u8; 32]> = (1..=MAX_TICKETS_PER_BLOCK as u8)
            .map(|id| [id; 32])
            .collect();
        let c = ctx(delivered.clone(), vec![], full, JUDGED_BLOCK);
        assert!(
            all_pass(&run(&n2_inclusion(&c), &ObsLog::new())),
            "five delivered and a cap of three: carrying three fills the block"
        );

        let short: Vec<[u8; 32]> = (1..MAX_TICKETS_PER_BLOCK as u8)
            .map(|id| [id; 32])
            .collect();
        let c = ctx(delivered, vec![], short, JUDGED_BLOCK);
        assert!(
            failed(
                &run(&n2_inclusion(&c), &ObsLog::new()),
                "n2_inclusion_covers_valid",
                Severity::Hard
            ),
            "leaving room unused while valid tickets wait is still a failure"
        );
    }

    #[test]
    fn n2_inclusion_pass_and_missing() {
        let valid = vec![
            emu(1, 0, true, TicketDelivery::Ce132),
            emu(3, 0, true, TicketDelivery::Ce132),
            emu(2, 0, true, TicketDelivery::Ce132),
            emu(2, 0, true, TicketDelivery::Ce132),
        ];
        let c = ctx(
            valid,
            vec![],
            vec![[1u8; 32], [2u8; 32], [3u8; 32]],
            JUDGED_BLOCK,
        );
        assert!(
            all_pass(&run(&n2_inclusion(&c), &ObsLog::new())),
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
            JUDGED_BLOCK,
        );
        assert!(
            failed(
                &run(&n2_inclusion(&miss), &ObsLog::new()),
                "n2_inclusion_covers_valid",
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
                &run(&n2_inclusion(&tail), &ObsLog::new()),
                "n2_inclusion_empty_at_tail",
                Severity::Hard
            ),
            "a non-empty extrinsic in the epoch tail fails hard"
        );
    }

    /// A block may only carry tickets for the epoch it is submitting into, so
    /// the unknown-epoch probe is not a ticket the node owes inclusion of.
    #[test]
    fn n2_inclusion_ignores_tickets_for_another_epoch() {
        let mut probe = emu(9, 0, true, TicketDelivery::Ce132);
        probe.target_epoch = TARGET_EPOCH + 2;
        let c = ctx(
            vec![emu(1, 0, true, TicketDelivery::Ce132), probe],
            vec![],
            vec![[1u8; 32]],
            JUDGED_BLOCK,
        );
        assert!(
            all_pass(&run(&n2_inclusion(&c), &ObsLog::new())),
            "a probe for an epoch the node cannot know is not owed inclusion"
        );
    }

    #[test]
    fn n2_unknown_epoch_pass_and_no_reset() {
        let mut probe = emu(9, 0, true, TicketDelivery::Ce132);
        probe.target_epoch = TARGET_EPOCH + 2;
        let refused = EmuTicket {
            refused: true,
            ..probe
        };
        let c = ctx(vec![refused], vec![], vec![], 0);
        assert!(
            all_pass(&run(&n2_unknown_epoch_reset(&c), &ObsLog::new())),
            "a probe the node refused passes"
        );

        // The same probe, not refused. Nothing in the observation log can
        // rescue it: the refusal is a fact about this ticket.
        let c = ctx(vec![probe], vec![], vec![], 0);
        assert!(
            failed(
                &run(&n2_unknown_epoch_reset(&c), &ObsLog::new()),
                "n2_unknown_epoch_reset_observed",
                Severity::Hard
            ),
            "a probe the node accepted fails hard"
        );
    }

    /// A rule nothing exercised is untested, which is a soft result. Passing
    /// it would report coverage the run never had.
    #[test]
    fn n2_unknown_epoch_without_a_probe_is_untested_not_passed() {
        let no_probe = ctx(
            vec![emu(1, 0, true, TicketDelivery::Ce132)],
            vec![],
            vec![],
            0,
        );
        let results = run(&n2_unknown_epoch_reset(&no_probe), &ObsLog::new());
        assert!(
            failed(&results, "n2_unknown_epoch_probed", Severity::Soft),
            "an unexercised reset rule is reported, not passed: {results:?}"
        );
    }

    /// Wall-clock start of `slot`, for fixtures that place a frame or an
    /// advertisement at a named slot rather than a bare instant.
    fn at_slot(slot: u32) -> u64 {
        JAM_COMMON_ERA * 1000 + u64::from(slot) * SLOT_PERIOD_MS
    }
    /// The NUT's CE 132 forward of `t` to `peer`, sent in `slot`.
    fn forwarded_at(t: &EmuTicket, peer: u16, slot: u32) -> NutTicketFacts {
        NutTicketFacts {
            received_at_ms: at_slot(slot),
            ..forwarded(t, peer)
        }
    }
    /// What the node said it had finalized: `slot`, declared in
    /// `declared_in`, and a second advertisement a slot later, which is what
    /// says the run watched on past the moment it is judging.
    fn finals(slot: u32, declared_in: u32) -> Vec<NutFinal> {
        vec![
            NutFinal {
                at_ms: at_slot(declared_in),
                slot,
            },
            NutFinal {
                at_ms: at_slot(declared_in + 1),
                slot: slot + 1,
            },
        ]
    }
    /// The ticket the stopping-rule fixtures turn on: one the emulator
    /// proxied to the NUT over CE 131.
    fn proxied() -> EmuTicket {
        emu(1, NUT, true, TicketDelivery::Ce131)
    }
    /// A run the stopping rule can judge: [`proxied`] forwarded to every peer
    /// in the slot it arrived, carried by the node's block at `JUDGED_BLOCK`,
    /// and declared final two slots after that. `extra` is whatever else the
    /// node sent.
    fn stopping(extra: Vec<NutTicketFacts>) -> N2Ctx {
        let t = proxied();
        let mut frames: Vec<NutTicketFacts> = (0..NUT)
            .map(|peer| forwarded_at(&t, peer, SUBMITTED_IN_SLOT))
            .collect();
        frames.extend(extra);
        ctx_finals(
            vec![t],
            frames,
            vec![NutBlockTickets {
                slot: JUDGED_BLOCK,
                ticket_ids: vec![t.id],
            }],
            finals(JUDGED_BLOCK, JUDGED_BLOCK + 2),
        )
    }

    #[test]
    fn a_node_that_stops_forwarding_once_the_ticket_is_final_passes() {
        // The repeat is what makes the rule judgeable: a node that sends one
        // frame per peer never stopped anything.
        let c = stopping(vec![forwarded_at(&proxied(), 0, SUBMITTED_IN_SLOT + 1)]);
        let results = run(&n2_forward_stops(&c), &ObsLog::new());
        assert!(
            all_pass(&results),
            "a node that repeated a forward before finality and not after it \
             passes: {results:?}"
        );
        assert!(
            results
                .iter()
                .any(|r| r.name == "n2_forward_stops_at_finality"),
            "and passes on the rule itself, not on an absence: {results:?}"
        );
    }

    #[test]
    fn a_forward_after_finality_is_reported() {
        let c = stopping(vec![
            forwarded_at(&proxied(), 0, SUBMITTED_IN_SLOT + 1),
            forwarded_at(&proxied(), 0, JUDGED_BLOCK + 3),
        ]);
        let results = run(&n2_forward_stops(&c), &ObsLog::new());
        assert!(
            failed(&results, "n2_forward_stops_at_finality", Severity::Soft),
            "forwarding a ticket the node had itself declared final is the \
             defect this row is for: {results:?}"
        );
    }

    #[test]
    fn a_node_that_never_repeats_a_forward_earns_no_pass() {
        // polkajam's shape: one CE 132 frame per ticket per peer, ever. The
        // prohibition holds for it however the rule is written, so the row
        // reports itself unexercised instead of claiming the node obeyed it.
        let results = run(&n2_forward_stops(&stopping(vec![])), &ObsLog::new());
        assert!(
            failed(&results, "n2_forward_repeat_control_absent", Severity::Soft),
            "a node that never sends a ticket twice has not shown it stops: {results:?}"
        );
    }

    #[test]
    fn a_run_that_ended_at_the_moment_of_finality_judges_nothing() {
        let mut c = stopping(vec![forwarded_at(&proxied(), 0, SUBMITTED_IN_SLOT + 1)]);
        // The node declared the block final and was never heard from again,
        // so "it did not forward after that" is a fact about the observation
        // window and not about the node.
        c.nut_finals.truncate(1);
        let results = run(&n2_forward_stops(&c), &ObsLog::new());
        assert!(
            failed(
                &results,
                "n2_forward_finality_control_absent",
                Severity::Soft
            ),
            "a run that stopped watching at the moment of finality judges \
             nothing: {results:?}"
        );
    }

    #[test]
    fn a_ticket_no_block_of_the_nodes_carried_is_not_judged() {
        let mut c = stopping(vec![forwarded_at(&proxied(), 0, SUBMITTED_IN_SLOT + 1)]);
        // Nothing the node authored carries it, so there is no inclusion for
        // finality to settle. Whether it was owed a place is `n2_inclusion`'s.
        c.nut_blocks = vec![NutBlockTickets {
            slot: JUDGED_BLOCK,
            ticket_ids: Vec::new(),
        }];
        let results = run(&n2_forward_stops(&c), &ObsLog::new());
        assert!(
            failed(
                &results,
                "n2_forward_finality_control_absent",
                Severity::Soft
            ),
            "an uncarried ticket was never finalized-included: {results:?}"
        );
    }

    #[test]
    fn a_ticket_the_node_never_forwarded_is_not_judged() {
        let t = proxied();
        let c = ctx_finals(
            vec![t],
            Vec::new(),
            vec![NutBlockTickets {
                slot: JUDGED_BLOCK,
                ticket_ids: vec![t.id],
            }],
            finals(JUDGED_BLOCK, JUDGED_BLOCK + 2),
        );
        let results = run(&n2_forward_stops(&c), &ObsLog::new());
        assert!(
            failed(
                &results,
                "n2_forward_finality_control_absent",
                Severity::Soft
            ),
            "a node that never forwarded cannot have forwarded again, and \
             whether it should have is `n2_proxy_duty`'s row: {results:?}"
        );
    }

    #[test]
    fn the_nodes_own_broadcast_is_not_this_rules_subject() {
        // A self-proxied ticket of the node's own, repeated after it declared
        // the block final. DESIGN puts the stopping rule in the proxy-duty
        // row, so this lane reports no subject rather than a failure --
        // grading it here would judge one broadcast under two rules.
        let own = nut_with_id(3, [NUT as u8; 32], 0, TicketDelivery::Ce132);
        let again = NutTicketFacts {
            received_at_ms: at_slot(JUDGED_BLOCK + 3),
            ..own.clone()
        };
        let c = ctx_finals(
            Vec::new(),
            vec![own, again],
            vec![NutBlockTickets {
                slot: JUDGED_BLOCK,
                ticket_ids: vec![[9u8; 32]],
            }],
            finals(JUDGED_BLOCK, JUDGED_BLOCK + 2),
        );
        let results = run(&n2_forward_stops(&c), &ObsLog::new());
        assert!(
            failed(
                &results,
                "n2_forward_finality_control_absent",
                Severity::Soft
            ),
            "the self-proxy broadcast is `n2_self_proxy`'s: {results:?}"
        );
    }

    #[test]
    fn all_n2_checks_distinct() {
        let checks = all(&ctx(vec![], vec![], vec![], 0));
        assert_eq!(checks.len(), 7);
        let mut ids: Vec<&str> = checks.iter().map(|c| c.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 7, "all check ids are distinct");
    }

    /// The slot of the fixtures' block: after the slot `emu` delivers in, so
    /// a faulted ticket is one the node had in hand when it authored.
    const BLOCK_SLOT: u32 = SUBMITTED_IN_SLOT + 1;

    fn faulted(t: EmuTicket, fault: TicketFault) -> EmuTicket {
        EmuTicket {
            fault: Some(fault),
            ..t
        }
    }

    /// A run with both controls: an honestly-proxied ticket the NUT forwarded
    /// to every peer and then carried in its block, alongside one faulted
    /// ticket it did neither with.
    fn with_both_controls(bad: EmuTicket) -> (EmuTicket, N2Ctx) {
        let honest = emu(1, NUT, true, TicketDelivery::Ce131);
        let forwards: Vec<NutTicketFacts> = (0..NUT).map(|p| forwarded(&honest, p)).collect();
        (
            honest,
            ctx(vec![honest, bad], forwards, vec![honest.id], BLOCK_SLOT),
        )
    }

    #[test]
    fn a_fault_the_node_left_no_trace_of_passes() {
        let bad = faulted(
            emu(2, NUT, true, TicketDelivery::Ce131),
            TicketFault::WrongProxy,
        );
        let (_, c) = with_both_controls(bad);
        let results = run(&n2_fault_handling(&c), &ObsLog::new());
        assert!(
            all_pass(&results),
            "a fault neither forwarded nor included passes both rows: {results:?}"
        );
        for row in ["n2_fault_not_forwarded", "n2_fault_not_included"] {
            assert!(
                results.iter().any(|r| r.name == row),
                "{row} is reported, not skipped: {results:?}"
            );
        }
    }

    #[test]
    fn forwarding_a_faulted_ticket_fails_hard() {
        let bad = faulted(
            emu(2, NUT, true, TicketDelivery::Ce131),
            TicketFault::BadProof,
        );
        let (honest, mut c) = with_both_controls(bad);
        let _ = honest;
        c.nut_tickets.push(forwarded(&bad, 0));
        let results = run(&n2_fault_handling(&c), &ObsLog::new());
        assert!(
            failed(&results, "n2_fault_not_forwarded", Severity::Hard),
            "a ticket the node had to refuse must not reach CE 132: {results:?}"
        );
    }

    #[test]
    fn including_a_faulted_ticket_fails_hard() {
        let bad = faulted(
            emu(2, NUT, true, TicketDelivery::Ce131),
            TicketFault::StaleEpoch,
        );
        let (honest, mut c) = with_both_controls(bad);
        c.nut_blocks[0].ticket_ids = vec![honest.id, bad.id];
        let results = run(&n2_fault_handling(&c), &ObsLog::new());
        assert!(
            failed(&results, "n2_fault_not_included", Severity::Hard),
            "a ticket the node had to refuse must not reach its block: {results:?}"
        );
    }

    /// The point of the gate: "it did not forward the bad ticket" is true of
    /// a node that forwards nothing whatever, so without a forward of its own
    /// the run has not tested the rule.
    #[test]
    fn a_node_that_forwards_nothing_earns_no_fault_pass() {
        let bad = faulted(
            emu(2, NUT, true, TicketDelivery::Ce131),
            TicketFault::WrongProxy,
        );
        let honest = emu(1, NUT, true, TicketDelivery::Ce131);
        let c = ctx(vec![honest, bad], vec![], vec![honest.id], BLOCK_SLOT);
        let results = run(&n2_fault_handling(&c), &ObsLog::new());
        assert!(
            failed(&results, "n2_fault_forward_control_absent", Severity::Soft),
            "an unexercised forwarding rule is reported: {results:?}"
        );
        assert!(
            !results.iter().any(|r| r.name == "n2_fault_not_forwarded"),
            "and the gated row is not reported at all: {results:?}"
        );
    }

    /// Likewise for inclusion, where the absence is a matter of timing: a
    /// fault that arrived after the block was sealed could not have been in
    /// it, so the node never made the choice the row judges.
    #[test]
    fn a_fault_that_arrived_after_the_block_does_not_gate_inclusion() {
        let mut bad = faulted(emu(2, NUT, true, TicketDelivery::Ce131), TicketFault::Late);
        bad.delivered_at_ms =
            Some(JAM_COMMON_ERA * 1000 + u64::from(BLOCK_SLOT + 4) * SLOT_PERIOD_MS);
        let (_, c) = with_both_controls(bad);
        let results = run(&n2_fault_handling(&c), &ObsLog::new());
        assert!(
            failed(
                &results,
                "n2_fault_inclusion_control_absent",
                Severity::Soft
            ),
            "a block authored before the fault arrived tests nothing: {results:?}"
        );
        assert!(
            !results.iter().any(|r| r.name == "n2_fault_not_included"),
            "and the gated row is not reported at all: {results:?}"
        );
    }

    /// The duplicate is the one fault a block still owes a place, so this
    /// lane has nothing to say about it; a run carrying only duplicates has
    /// not exercised the prohibition.
    #[test]
    fn the_duplicate_is_not_a_prohibition_this_lane_judges() {
        let dup = faulted(
            emu(2, NUT, true, TicketDelivery::Ce132),
            TicketFault::Duplicate,
        );
        let (_, c) = with_both_controls(dup);
        let results = run(&n2_fault_handling(&c), &ObsLog::new());
        assert!(
            failed(&results, "n2_fault_injected", Severity::Soft),
            "a run with no forbidden fault reports the rule unexercised: {results:?}"
        );
        assert_eq!(results.len(), 1, "and judges nothing else: {results:?}");
    }

    fn block(slot: u32, ticket_ids: Vec<[u8; 32]>) -> NutBlockTickets {
        NutBlockTickets { slot, ticket_ids }
    }

    /// The hole this widening closed: a ticket the node had to refuse, put in
    /// a block that is not the epoch's last.
    #[test]
    fn a_fault_buried_in_an_earlier_block_is_found() {
        let honest = emu(1, NUT, true, TicketDelivery::Ce131);
        let bad = faulted(
            emu(2, NUT, true, TicketDelivery::Ce131),
            TicketFault::StaleEpoch,
        );
        let forwards: Vec<NutTicketFacts> = (0..NUT).map(|p| forwarded(&honest, p)).collect();
        let c = ctx_blocks(
            vec![honest, bad],
            forwards,
            vec![
                block(JUDGED_BLOCK, vec![honest.id, bad.id]),
                block(LATER_BLOCK, vec![]),
            ],
        );
        let results = run(&n2_fault_handling(&c), &ObsLog::new());
        assert!(
            failed(&results, "n2_fault_not_included", Severity::Hard),
            "a refused ticket is forbidden the whole epoch, not just its last block: {results:?}"
        );
    }

    /// The same hole under the other prohibition.
    #[test]
    fn an_unsent_ticket_in_an_earlier_block_is_found() {
        let honest = emu(1, NUT, true, TicketDelivery::Ce132);
        let c = ctx_blocks(
            vec![honest],
            vec![],
            vec![
                block(JUDGED_BLOCK, vec![honest.id, [99u8; 32]]),
                block(LATER_BLOCK, vec![]),
            ],
        );
        let results = run(&n2_inclusion(&c), &ObsLog::new());
        assert!(
            failed(&results, "n2_inclusion_no_extra", Severity::Hard),
            "a ticket from nowhere is found wherever in the epoch it sits: {results:?}"
        );
    }

    /// And the false failure the single-block reading caused: a node that
    /// fills an early block has done its job, however empty the last one is.
    #[test]
    fn coverage_is_the_epochs_not_the_last_blocks() {
        let honest = emu(1, NUT, true, TicketDelivery::Ce132);
        let c = ctx_blocks(
            vec![honest],
            vec![],
            vec![
                block(JUDGED_BLOCK, vec![honest.id]),
                block(LATER_BLOCK, vec![]),
            ],
        );
        let results = run(&n2_inclusion(&c), &ObsLog::new());
        assert!(
            all_pass(&results),
            "a ticket carried early is on chain and the last block owes it nothing: {results:?}"
        );
    }

    #[test]
    fn the_tail_rule_is_judged_on_every_block_of_the_epoch() {
        let honest = emu(1, NUT, true, TicketDelivery::Ce132);
        let c = ctx_blocks(
            vec![honest],
            vec![],
            vec![
                block(JUDGED_BLOCK, vec![honest.id]),
                block(TAIL_BLOCK, vec![[7u8; 32]]),
            ],
        );
        let results = run(&n2_inclusion(&c), &ObsLog::new());
        assert!(
            failed(&results, "n2_inclusion_empty_at_tail", Severity::Hard),
            "a tail block carrying tickets fails wherever it sits in the epoch: {results:?}"
        );
        assert!(
            !failed(&results, "n2_inclusion_covers_valid", Severity::Hard),
            "and coverage is still judged, against the last block that could carry: {results:?}"
        );
    }

    #[test]
    fn sortedness_is_judged_on_every_block_of_the_epoch() {
        let honest = emu(1, NUT, true, TicketDelivery::Ce132);
        let c = ctx_blocks(
            vec![honest],
            vec![],
            vec![
                block(JUDGED_BLOCK, vec![[9u8; 32], [8u8; 32]]),
                block(LATER_BLOCK, vec![honest.id]),
            ],
        );
        let results = run(&n2_inclusion(&c), &ObsLog::new());
        assert!(
            failed(&results, "n2_inclusion_sorted_dedup", Severity::Hard),
            "an unsorted extrinsic fails wherever in the epoch it sits: {results:?}"
        );
    }

    /// The false failure the widening exposed. A run whose only block falls
    /// before the tickets arrive held none of them when it authored, and
    /// charging it for the ones that came later blames it for the schedule.
    #[test]
    fn a_block_sealed_before_the_tickets_arrived_owes_them_nothing() {
        let delivered: Vec<EmuTicket> = (1..=5u8)
            .map(|id| emu(id, 0, true, TicketDelivery::Ce132))
            .collect();
        let c = ctx_blocks(
            delivered,
            vec![],
            vec![block(SUBMITTED_IN_SLOT.saturating_sub(1), vec![])],
        );
        let results = run(&n2_inclusion(&c), &ObsLog::new());
        assert!(
            !failed(&results, "n2_inclusion_covers_valid", Severity::Hard),
            "an empty block authored before any delivery is not incomplete: {results:?}"
        );
        assert!(
            failed(&results, "n2_inclusion_control_absent", Severity::Soft),
            "and the run says the selection rules went untested: {results:?}"
        );
    }

    #[test]
    fn no_block_in_the_epoch_is_untested_not_passed() {
        let c = ctx_blocks(
            vec![emu(1, NUT, true, TicketDelivery::Ce132)],
            vec![],
            vec![],
        );
        let results = run(&n2_inclusion(&c), &ObsLog::new());
        assert!(
            failed(&results, "n2_inclusion_no_block_in_epoch", Severity::Soft),
            "a node that authored nothing in the epoch is not graded on it: {results:?}"
        );
        assert!(
            !results
                .iter()
                .any(|r| r.name == "n2_inclusion_covers_valid"),
            "and nothing is judged against a block that does not exist: {results:?}"
        );
    }

    /// A node does not rebroadcast what arrives on CE 132, sound or not, so
    /// "the faulted broadcast was not forwarded" would pass in every run.
    /// The broadcast faults are judged for inclusion only.
    #[test]
    fn a_broadcast_fault_is_judged_for_inclusion_and_not_for_forwarding() {
        let bad = faulted(
            emu(2, 0, true, TicketDelivery::Ce132),
            TicketFault::BadAttempt,
        );
        let (_, c) = with_both_controls(bad);
        let results = run(&n2_fault_handling(&c), &ObsLog::new());
        assert!(
            failed(&results, "n2_fault_forward_control_absent", Severity::Soft),
            "no CE 131 fault means no forwarding verdict: {results:?}"
        );
        assert!(
            results
                .iter()
                .any(|r| r.name == "n2_fault_not_included" && r.outcome == Outcome::Pass),
            "but the block still owes it nothing: {results:?}"
        );
    }
}
