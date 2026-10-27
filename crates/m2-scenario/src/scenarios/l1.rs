//! L1 — block authoring (DESIGN.md §11 L1).
//!
//! Six checks over the runner-injected [`L1Ctx`] facts: timing, parent
//! ancestry/equivocation, header/seal import, state root, extrinsic
//! completeness, and skipped-slot gap semantics. All facts come from the
//! reference trace (`ctx`), so these checks read the observation log only to
//! satisfy the [`crate::dsl::Check`] signature.
//!
//! # Severity notes
//!
//! `l1_timing` is [`Severity::Soft`]: DESIGN §5 marks timing-tolerance clauses
//! soft. All other checks are Hard.

use std::collections::{HashMap, HashSet};

use crate::ctx::L1Ctx;
use crate::dsl::{check, log, Check, Severity};

/// First eight bytes of a hash, for finding details.
fn short(hash: &[u8; 32]) -> String {
    hash[..8].iter().map(|b| format!("{b:02x}")).collect()
}

fn short_opt(hash: &Option<[u8; 32]>) -> String {
    match hash {
        Some(h) => short(h),
        None => "none".to_string(),
    }
}

/// L1 — Timing: a NUT block for its slot is announced within
/// `[slot_start, slot_start + one slot period]`.
///
/// Timing tolerance → Soft (DESIGN §5).
pub fn l1_timing(ctx: &L1Ctx) -> Check {
    let ctx = ctx.clone();
    check("l1_timing", Severity::Soft, move |_obs| {
        ctx.nut_blocks
            .iter()
            .map(|nut| {
                let start = ctx.slot_start_ms(nut.block.header.slot);
                let in_window = nut.announced_wall_ms >= start
                    && nut.announced_wall_ms <= start + ctx.slot_period_ms;
                log::check_detail("l1_timing_within_slot", in_window, Severity::Soft, || {
                    let drift = nut.announced_wall_ms as i64 - start as i64;
                    format!(
                        "the block for slot {} was announced {drift} ms from that slot's \
                         start, outside the {} ms it lasts",
                        nut.block.header.slot, ctx.slot_period_ms,
                    )
                })
            })
            .collect()
    })
}

/// L1 — Parent: each NUT block's parent is a known reference block or a prior
/// NUT block, is the reference best block *as of that block's slot*, and no
/// two NUT blocks share a parent (equivocation).
///
/// "As of that block's slot" is the whole point. The reference head moves
/// every slot, so comparing against the head read after the observation window
/// closed fails every block that was authored correctly — it was 22 slots
/// behind by the end of a 90 s run. [`L1Ctx::reference_best_at`] resolves the
/// head the node could actually have seen, which also lets the rule apply to
/// every NUT block instead of only the first.
pub fn l1_parent(ctx: &L1Ctx) -> Check {
    let ctx = ctx.clone();
    check("l1_parent", Severity::Hard, move |_obs| {
        let mut known: HashSet<[u8; 32]> = ctx.reference_block_hashes.iter().copied().collect();
        known.insert(ctx.reference_best);
        let mut used_parents: HashSet<[u8; 32]> = HashSet::new();
        let mut results = Vec::new();
        let mut blocks: Vec<_> = ctx.nut_blocks.iter().collect();
        blocks.sort_by_key(|nut| nut.block.header.slot);
        for nut in blocks {
            let slot = nut.block.header.slot;
            let parent = nut.block.header.parent.0;
            let best = ctx.reference_best_at(slot);
            results.push(log::check_detail(
                "l1_parent_is_reference_best",
                best == Some(parent),
                Severity::Hard,
                || {
                    format!(
                        "block at slot {slot} builds on {}, reference best at that slot was {}",
                        short(&parent),
                        short_opt(&best)
                    )
                },
            ));
            results.push(log::check_detail(
                "l1_parent_is_known",
                known.contains(&parent),
                Severity::Hard,
                || {
                    format!(
                        "block at slot {slot} builds on unknown parent {}",
                        short(&parent)
                    )
                },
            ));
            results.push(log::check_detail(
                "l1_parent_no_equivocation",
                used_parents.insert(parent),
                Severity::Hard,
                || {
                    format!(
                        "block at slot {slot} shares parent {} with an earlier NUT block",
                        short(&parent)
                    )
                },
            ));
            known.insert(nut.block.header.hash().0);
        }
        results
    })
}

/// L1 — Header and seal: the reference engine imported every NUT block OK
/// (seal and entropy VRF verify; the import is the ground truth). A failed
/// import is a Hard fail; the DSL's [`crate::dsl::CheckResult`] carries no
/// free-text field, so the import error string is not surfaced.
pub fn l1_header_seal(ctx: &L1Ctx) -> Check {
    let ctx = ctx.clone();
    check("l1_header_seal", Severity::Hard, move |_obs| {
        ctx.nut_blocks
            .iter()
            .map(|nut| {
                let header_root = nut.block.header.hash().0;
                let import = ctx
                    .imports
                    .iter()
                    .find(|imp| imp.header_root == header_root);
                let imported_ok = import.is_some_and(|imp| imp.ok);
                log::check_detail(
                    "l1_header_seal_import_ok",
                    imported_ok,
                    Severity::Hard,
                    || match import.and_then(|imp| imp.error.as_deref()) {
                        Some(error) => format!(
                            "the reference refused the block at slot {}: {error}",
                            nut.block.header.slot
                        ),
                        None => format!(
                            "no import outcome was recorded for the block at slot {} ({})",
                            nut.block.header.slot,
                            short(&header_root),
                        ),
                    },
                )
            })
            .collect()
    })
}

/// L1 — State root (DESIGN.md §11 L1): the reference STF import succeeds and
/// the roots agree, with an M1-style diff when they do not.
///
/// There are two roots to check and they are different quantities, neither of
/// them the block's header hash:
///
/// - *prior*: the block's `parent_state_root` against the reference engine's
///   own posterior root for that parent. polkajam's importer already enforces
///   this (`InvalidParentStateRoot`), so a passing import implies it — but the
///   check states it explicitly and reports the two values on a mismatch,
///   rather than leaving it to a bare import error.
/// - *posterior*: the reference's post-state root for the NUT block against
///   the root the NUT itself computed for it. The node commits to that root
///   only in the `parent_state_root` of a block *it* builds on top, so the
///   assertion needs a NUT block whose parent is another NUT block, which
///   happens when the node wins two slots in a row — often enough to be worth
///   checking, not often enough to rely on. With no such block the check stays
///   silent rather than reporting a finding every run: the prior check above
///   is what compares the two engines on every block. Checking a posterior
///   root unconditionally would need the node's own state, over CE 129 or the
///   fuzz socket's `GetState` (DESIGN.md §11 L1).
///
/// The check this replaces compared the posterior state root to the *header
/// hash*. Those can never be equal, so it failed on every block of every run.
pub fn l1_state_root(ctx: &L1Ctx) -> Check {
    let ctx = ctx.clone();
    check("l1_state_root", Severity::Hard, move |_obs| {
        // Every NUT block, indexed by the parent it builds on: a block is the
        // witness to its parent's posterior state root.
        let children: HashMap<[u8; 32], &crate::ctx::NutBlock> = ctx
            .nut_blocks
            .iter()
            .map(|nut| (nut.block.header.parent.0, nut))
            .collect();
        let mut results = Vec::new();
        for imp in ctx.imports.iter().filter(|imp| imp.ok) {
            results.push(log::check_detail(
                "l1_state_root_prior_matches",
                imp.reference_parent_root == Some(imp.declared_parent_root),
                Severity::Hard,
                || {
                    format!(
                        "block {} declares prior root {} for parent {}, reference computed {}",
                        short(&imp.header_root),
                        short(&imp.declared_parent_root),
                        short(&imp.parent),
                        short_opt(&imp.reference_parent_root)
                    )
                },
            ));
            // Without a NUT block built on it the node never committed to a
            // posterior root for this one, so there is nothing to compare.
            if let Some(child) = children.get(&imp.header_root) {
                let declared = child.block.header.parent_state_root.0;
                results.push(log::check_detail(
                    "l1_state_root_posterior_matches",
                    imp.root == Some(declared),
                    Severity::Hard,
                    || {
                        format!(
                            "block {} posterior root: node says {}, reference says {}",
                            short(&imp.header_root),
                            short(&declared),
                            short_opt(&imp.root)
                        )
                    },
                ));
            }
        }
        results
    })
}

/// L1 — Extrinsic completeness: each NUT block carries as many of the tickets
/// it still owes as it is allowed to hold, nothing it was never given, nothing
/// twice, and nothing at all once the epoch tail starts.
///
/// What a block owes is [`L1Ctx::expected_tickets_for_slot`] minus what is
/// already on chain: tickets in hand at least 2 s before the slot, targeting
/// the epoch this block may still submit for, and only while the slot is
/// before the tail.
///
/// Inclusion is cumulative and capacity-bounded rather than a per-block subset
/// test. A block may hold at most `max_tickets_per_block` tickets — three
/// under the tiny parameters, while the harness generates four per author — so
/// requiring every owed ticket in every block is unsatisfiable the moment more
/// than three are owed at once. The node chooses *which* ones; what is
/// required of it is that it fills the block as far as it can, so the
/// assertion is on the count taken from the owed set, and the remainder is
/// still owed by the next block.
///
/// The count is of *owed* tickets taken, not of tickets carried, so a block
/// that fills itself with ones delivered too late to be obligatory while an
/// obligatory one waits is still incomplete. That is what DESIGN asks for, and
/// the case only arises when more than `max_tickets_per_block` are owed at
/// once and an optional ticket is in hand alongside them — which the delivery
/// schedule now avoids by giving every ticket a clear arrival lead.
///
/// There is deliberately no assertion that the cap itself is respected: the
/// ticket extrinsic is a `BoundedVec` bounded by `MaxTicketsPerBlock`, so an
/// over-cap block does not decode and the check could only ever pass.
pub fn l1_extrinsic_completeness(ctx: &L1Ctx) -> Check {
    let ctx = ctx.clone();
    check("l1_extrinsic_completeness", Severity::Hard, move |_obs| {
        // The node's own tickets count as legitimately in hand: it is a
        // validator and runs the lottery itself. Only the emulator's tickets
        // are *owed*, but a block carrying the node's own is not carrying one
        // from nowhere.
        let delivered: HashSet<[u8; 32]> = ctx.delivered_tickets.iter().map(|t| t.id).collect();
        let in_hand: HashSet<[u8; 32]> = delivered
            .iter()
            .copied()
            .chain(ctx.own_ticket_ids.iter().copied())
            .collect();
        // Oldest block first, so "already on chain" means what it says.
        let mut blocks: Vec<_> = ctx.nut_blocks.iter().collect();
        blocks.sort_by_key(|nut| nut.block.header.slot);
        let mut on_chain: HashSet<[u8; 32]> = HashSet::new();
        let mut results = Vec::new();
        for nut in blocks {
            let slot = nut.block.header.slot;
            let ids: Vec<[u8; 32]> = nut
                .block
                .extrinsic
                .tickets
                .iter()
                .map(|t| t.id().0)
                .collect();
            let included: HashSet<[u8; 32]> = ids.iter().copied().collect();
            let owed: HashSet<[u8; 32]> = ctx
                .expected_tickets_for_slot(slot)
                .into_iter()
                .filter(|id| !on_chain.contains(id))
                .collect();
            let required = owed.len().min(ctx.max_tickets_per_block);
            let taken = included.intersection(&owed).count();
            results.push(log::check_detail(
                "l1_extrinsic_includes_delivered",
                taken >= required,
                Severity::Hard,
                || {
                    format!(
                        "block at slot {slot} owed {} ticket(s), could carry {required}, carried {taken}",
                        owed.len()
                    )
                },
            ));
            results.push(log::check_detail(
                "l1_extrinsic_no_undelivered",
                included.is_subset(&in_hand),
                Severity::Hard,
                || {
                    let extra: Vec<String> = included.difference(&in_hand).map(short).collect();
                    format!(
                        "block at slot {slot} includes ticket(s) that were neither \
                         delivered to the node nor announced by it: {}",
                        extra.join(", ")
                    )
                },
            ));
            results.push(log::check_detail(
                "l1_extrinsic_no_repeat",
                included.is_disjoint(&on_chain),
                Severity::Hard,
                || {
                    let dup: Vec<String> = included.intersection(&on_chain).map(short).collect();
                    format!(
                        "block at slot {slot} repeats ticket(s) already on chain: {}",
                        dup.join(", ")
                    )
                },
            ));
            results.push(log::check_detail(
                "l1_extrinsic_empty_at_tail",
                ctx.slot_accepts_tickets(slot) || ids.is_empty(),
                Severity::Hard,
                || {
                    format!(
                        "block at slot {slot} is in the epoch tail (offset {}) but carries {} tickets",
                        slot % ctx.epoch_period,
                        ids.len()
                    )
                },
            ));
            on_chain.extend(included);
        }
        results
    })
}

/// L1 — Skipped slots: a NUT block whose slot is more than one past its
/// parent's slot is only valid when the parent is a known reference block
/// (the emulated author skipped the intermediate slots). An unknown parent is
/// a Hard fail (already flagged by `l1_parent`; asserted here for the gap).
pub fn l1_skipped_slots(ctx: &L1Ctx) -> Check {
    let ctx = ctx.clone();
    check("l1_skipped_slots", Severity::Hard, move |_obs| {
        let reference: HashSet<[u8; 32]> = ctx.reference_block_hashes.iter().copied().collect();
        let mut slot_by_hash: HashMap<[u8; 32], u32> = HashMap::new();
        let mut results = Vec::new();
        for nut in &ctx.nut_blocks {
            let parent = nut.block.header.parent.0;
            let parent_is_reference = reference.contains(&parent) || parent == ctx.reference_best;
            let pass = match slot_by_hash.get(&parent).copied() {
                Some(parent_slot) => {
                    let gap = nut.block.header.slot > parent_slot + 1;
                    !gap || parent_is_reference
                }
                None => parent_is_reference,
            };
            results.push(log::check_detail(
                "l1_skipped_slots_valid_parent",
                pass,
                Severity::Hard,
                || {
                    format!(
                        "the block at slot {} skipped past its parent {} without that \
                         parent being on the reference chain",
                        nut.block.header.slot,
                        short(&parent),
                    )
                },
            ));
            slot_by_hash.insert(nut.block.header.hash().0, nut.block.header.slot);
        }
        results
    })
}

/// All six L1 checks in order.
pub fn all(ctx: &L1Ctx) -> Vec<Check> {
    if ctx.nut_blocks.is_empty() {
        // No NUT-authored blocks were observed in the window: every L1 check is
        // "not exercised" — an honest soft finding, not a conformance pass.
        let names: [&str; 6] = [
            "l1_timing",
            "l1_parent",
            "l1_header_seal",
            "l1_state_root",
            "l1_extrinsic_completeness",
            "l1_skipped_slots",
        ];
        return names
            .into_iter()
            .map(|id| {
                check(id, Severity::Hard, |_| {
                    vec![log::check("no_nut_blocks_observed", false, Severity::Soft)]
                })
            })
            .collect();
    }
    vec![
        l1_timing(ctx),
        l1_parent(ctx),
        l1_header_seal(ctx),
        l1_state_root(ctx),
        l1_extrinsic_completeness(ctx),
        l1_skipped_slots(ctx),
    ]
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use jam_std_common::{
        bandersnatch::ring_vrf::Signature as RingSignature, Block, Extrinsic, Header,
        TicketEnvelope, TicketsXt,
    };

    use super::*;
    use crate::ctx::{
        DeliveredTicket, ImportFact, NutBlock, EPOCH_PERIOD, EPOCH_TAIL_START,
        MAX_TICKETS_PER_BLOCK, SLOT_PERIOD_MS,
    };
    use crate::dsl::{CheckResult, ObsLog, Outcome};

    fn run(c: &Check, obs: &ObsLog) -> Vec<CheckResult> {
        (c.run)(obs)
    }

    fn all_pass(results: &[CheckResult]) -> bool {
        results.iter().all(|r| r.outcome == Outcome::Pass)
    }

    fn base_ctx() -> L1Ctx {
        L1Ctx {
            reference_best: [0u8; 32],
            reference_block_hashes: Vec::new(),
            reference_chain: Vec::new(),
            nut_blocks: Vec::new(),
            imports: Vec::new(),
            delivered_tickets: Vec::new(),
            own_ticket_ids: Vec::new(),
            slot_period_ms: SLOT_PERIOD_MS,
            epoch_period: EPOCH_PERIOD,
            epoch_tail_start: EPOCH_TAIL_START,
            max_tickets_per_block: MAX_TICKETS_PER_BLOCK,
        }
    }

    /// A delivered ticket for the epoch after `slot`'s, in hand in time for it.
    fn delivered_for(ctx: &L1Ctx, id: [u8; 32], slot: u32, lead_ms: u64) -> DeliveredTicket {
        DeliveredTicket {
            id,
            delivered_at_ms: ctx.slot_start_ms(slot) - lead_ms,
            target_epoch: slot / ctx.epoch_period + 1,
        }
    }

    fn nut_block(slot: u32, parent: [u8; 32], announced_at: u64) -> NutBlock {
        let mut header = Header::genesis();
        header.parent = parent.into();
        header.slot = slot;
        header.author_index = 5;
        NutBlock {
            block: Block {
                header: Arc::new(header.into()),
                extrinsic: Arc::new(Extrinsic::default()),
            },
            announced_wall_ms: announced_at,
        }
    }

    fn nut_block_with_tickets(
        slot: u32,
        parent: [u8; 32],
        tickets: Vec<TicketEnvelope>,
        announced_at: u64,
    ) -> NutBlock {
        let mut header = Header::genesis();
        header.parent = parent.into();
        header.slot = slot;
        header.author_index = 5;
        let mut extrinsic = Extrinsic::default();
        extrinsic.tickets = TicketsXt::truncate_from(tickets);
        NutBlock {
            block: Block {
                header: Arc::new(header.into()),
                extrinsic: Arc::new(extrinsic),
            },
            announced_wall_ms: announced_at,
        }
    }

    #[test]
    fn l1_timing_pass_and_fail() {
        let mut ctx = base_ctx();
        let start = ctx.slot_start_ms(0);
        ctx.nut_blocks = vec![nut_block(0, [1u8; 32], start)];
        assert!(all_pass(&run(&l1_timing(&ctx), &ObsLog::new())));

        ctx.nut_blocks[0].announced_wall_ms = start + 10_000;
        let results = run(&l1_timing(&ctx), &ObsLog::new());
        assert!(
            results
                .iter()
                .any(|r| r.name == "l1_timing_within_slot"
                    && r.outcome == Outcome::Fail(Severity::Soft)),
            "a block announced 10 s past slot start fails soft"
        );
    }

    #[test]
    fn l1_parent_pass_and_fork() {
        let mut ctx = base_ctx();
        ctx.reference_best = [1u8; 32];
        ctx.reference_block_hashes = vec![[1u8; 32]];
        ctx.reference_chain = vec![(0, [1u8; 32])];
        ctx.nut_blocks = vec![nut_block(1, [1u8; 32], 0)];
        assert!(all_pass(&run(&l1_parent(&ctx), &ObsLog::new())));

        ctx.nut_blocks[0] = nut_block(1, [9u8; 32], 0);
        let results = run(&l1_parent(&ctx), &ObsLog::new());
        assert!(
            results
                .iter()
                .any(|r| r.name == "l1_parent_is_known"
                    && r.outcome == Outcome::Fail(Severity::Hard)),
            "an unknown parent fails hard"
        );

        ctx.nut_blocks = vec![nut_block(1, [1u8; 32], 0), nut_block(2, [1u8; 32], 0)];
        let results = run(&l1_parent(&ctx), &ObsLog::new());
        assert!(
            results.iter().any(|r| r.name == "l1_parent_no_equivocation"
                && r.outcome == Outcome::Fail(Severity::Hard)),
            "two blocks with the same parent are equivocation"
        );
    }

    /// The reference head moves every slot. A NUT block must be judged against
    /// the head as of its own slot, not the head left over when the run ended
    /// — which is what failed every correctly-authored block before.
    #[test]
    fn l1_parent_uses_the_head_as_of_the_block_slot() {
        let mut ctx = base_ctx();
        let (early, late) = ([1u8; 32], [2u8; 32]);
        ctx.reference_chain = vec![(4, early), (9, late)];
        ctx.reference_block_hashes = vec![early, late];
        ctx.reference_best = late;
        // Authored at slot 5, when `early` was the head: correct, even though
        // the reference had reached `late` by the time the window closed.
        ctx.nut_blocks = vec![nut_block(5, early, 0)];
        assert!(
            all_pass(&run(&l1_parent(&ctx), &ObsLog::new())),
            "building on the head of the moment is correct"
        );

        // Building on the final head from a slot before it existed is not.
        ctx.nut_blocks = vec![nut_block(5, late, 0)];
        let results = run(&l1_parent(&ctx), &ObsLog::new());
        assert!(
            results
                .iter()
                .any(|r| r.name == "l1_parent_is_reference_best"
                    && r.outcome == Outcome::Fail(Severity::Hard)),
            "a parent that was not yet the head fails hard"
        );

        // The rule applies to every block, not only the first: a second block
        // at slot 10 must build on `late`.
        ctx.nut_blocks = vec![nut_block(5, early, 0), nut_block(10, early, 0)];
        let results = run(&l1_parent(&ctx), &ObsLog::new());
        assert!(
            results
                .iter()
                .any(|r| r.name == "l1_parent_is_reference_best"
                    && r.outcome == Outcome::Fail(Severity::Hard)),
            "a later block that ignored a newer head fails hard"
        );
    }

    #[test]
    fn l1_import_seal_pass_and_fail() {
        let mut ctx = base_ctx();
        ctx.reference_best = [1u8; 32];
        ctx.reference_block_hashes = vec![[1u8; 32]];
        let block = nut_block(1, [1u8; 32], 0);
        let header_root = block.block.header.hash().0;
        ctx.nut_blocks = vec![block];
        ctx.imports = vec![ImportFact {
            header_root,
            parent: [1u8; 32],
            declared_parent_root: [2u8; 32],
            reference_parent_root: Some([2u8; 32]),
            ok: true,
            root: Some([3u8; 32]),
            error: None,
        }];
        assert!(all_pass(&run(&l1_header_seal(&ctx), &ObsLog::new())));

        ctx.imports[0] = ImportFact {
            header_root,
            parent: [1u8; 32],
            declared_parent_root: [2u8; 32],
            reference_parent_root: Some([2u8; 32]),
            ok: false,
            root: None,
            error: Some("BadSealSignature".into()),
        };
        let results = run(&l1_header_seal(&ctx), &ObsLog::new());
        assert!(
            results.iter().any(|r| r.name == "l1_header_seal_import_ok"
                && r.outcome == Outcome::Fail(Severity::Hard)),
            "a failed import fails hard"
        );
    }

    /// A NUT block at `slot` building on `parent` and declaring `declares` as
    /// its parent's posterior state root.
    fn block_declaring(slot: u32, parent: [u8; 32], declares: [u8; 32]) -> NutBlock {
        let mut header = Header::genesis();
        header.parent = parent.into();
        header.parent_state_root = declares.into();
        header.slot = slot;
        NutBlock {
            block: Block {
                header: Arc::new(header.into()),
                extrinsic: Arc::new(Extrinsic::default()),
            },
            announced_wall_ms: 0,
        }
    }

    fn import_fact(
        block: &NutBlock,
        posterior: [u8; 32],
        reference_parent: [u8; 32],
    ) -> ImportFact {
        ImportFact {
            header_root: block.block.header.hash().0,
            parent: block.block.header.parent.0,
            declared_parent_root: block.block.header.parent_state_root.0,
            reference_parent_root: Some(reference_parent),
            ok: true,
            root: Some(posterior),
            error: None,
        }
    }

    #[test]
    fn l1_state_root_prior_match_and_mismatch() {
        let ctx = base_ctx();
        let block = block_declaring(1, [9u8; 32], [2u8; 32]);

        let mut ok = ctx.clone();
        ok.imports = vec![import_fact(&block, [7u8; 32], [2u8; 32])];
        ok.nut_blocks = vec![block.clone()];
        assert!(all_pass(&run(&l1_state_root(&ok), &ObsLog::new())));

        // The reference computed a different root for the same parent.
        let mut mismatch = ctx.clone();
        mismatch.imports = vec![import_fact(&block, [7u8; 32], [5u8; 32])];
        mismatch.nut_blocks = vec![block.clone()];
        let results = run(&l1_state_root(&mismatch), &ObsLog::new());
        let failed = results
            .iter()
            .find(|r| r.name == "l1_state_root_prior_matches")
            .expect("the prior-root assertion runs");
        assert_eq!(failed.outcome, Outcome::Fail(Severity::Hard));
        assert!(
            failed.detail.as_deref().is_some_and(|d| d.contains("0202")),
            "the finding names the roots that disagreed: {:?}",
            failed.detail
        );

        let mut failed_import = ctx.clone();
        failed_import.imports = vec![ImportFact {
            ok: false,
            error: Some("BadSealSignature".into()),
            ..import_fact(&block, [7u8; 32], [2u8; 32])
        }];
        assert!(
            run(&l1_state_root(&failed_import), &ObsLog::new()).is_empty(),
            "failed imports are not state-root checked"
        );
    }

    /// The posterior root is only observable through a block built on top.
    /// Comparing it to the block's own header hash — which is what this check
    /// used to do — can never succeed, because they are different quantities.
    #[test]
    fn l1_state_root_posterior_needs_a_witness() {
        let mut ctx = base_ctx();
        let first = block_declaring(1, [9u8; 32], [2u8; 32]);
        let first_hash = first.block.header.hash().0;
        ctx.imports = vec![import_fact(&first, [7u8; 32], [2u8; 32])];

        // Nothing builds on it, so the node never committed to a posterior
        // root for it and the check says nothing at all — no pass, no finding.
        ctx.nut_blocks = vec![first.clone()];
        assert!(
            !run(&l1_state_root(&ctx), &ObsLog::new())
                .iter()
                .any(|r| r.name.starts_with("l1_state_root_posterior")),
            "an unwitnessed posterior root is silent, not a finding"
        );

        // A child declaring the reference's root for its parent passes.
        let good_child = block_declaring(2, first_hash, [7u8; 32]);
        ctx.nut_blocks = vec![first.clone(), good_child.clone()];
        ctx.imports = vec![
            import_fact(&first, [7u8; 32], [2u8; 32]),
            import_fact(&good_child, [8u8; 32], [7u8; 32]),
        ];
        assert!(all_pass(&run(&l1_state_root(&ctx), &ObsLog::new())));

        // A child declaring something else is a hard fail.
        let bad_child = block_declaring(2, first_hash, [6u8; 32]);
        ctx.nut_blocks = vec![first.clone(), bad_child.clone()];
        ctx.imports = vec![
            import_fact(&first, [7u8; 32], [2u8; 32]),
            import_fact(&bad_child, [8u8; 32], [7u8; 32]),
        ];
        let results = run(&l1_state_root(&ctx), &ObsLog::new());
        assert!(
            results
                .iter()
                .any(|r| r.name == "l1_state_root_posterior_matches"
                    && r.outcome == Outcome::Fail(Severity::Hard)),
            "a posterior root the node and the reference disagree on fails hard"
        );

        // A later NUT block that built somewhere else is not a witness either,
        // and still says nothing: whether the node should have built on its own
        // block is `l1_parent`'s question, not this one's.
        let elsewhere = block_declaring(2, [4u8; 32], [5u8; 32]);
        ctx.nut_blocks = vec![first.clone(), elsewhere.clone()];
        ctx.imports = vec![import_fact(&first, [7u8; 32], [2u8; 32])];
        assert!(
            !run(&l1_state_root(&ctx), &ObsLog::new())
                .iter()
                .any(|r| r.name.starts_with("l1_state_root_posterior")),
            "a block built elsewhere witnesses nothing"
        );

        // And the header hash is not the posterior root: a child declaring it
        // must fail, not pass.
        let hash_child = block_declaring(2, first_hash, first_hash);
        ctx.nut_blocks = vec![first.clone(), hash_child.clone()];
        ctx.imports = vec![import_fact(&first, [7u8; 32], [2u8; 32])];
        let results = run(&l1_state_root(&ctx), &ObsLog::new());
        assert!(results
            .iter()
            .any(|r| r.name == "l1_state_root_posterior_matches"
                && r.outcome == Outcome::Fail(Severity::Hard)));
    }

    /// The node under test is a validator and runs the lottery itself, so its
    /// own tickets belong in its own blocks. Judging every included ticket
    /// against the emulator's deliveries alone failed a conforming node the
    /// moment it included one of its own.
    #[test]
    fn l1_extrinsic_allows_the_nodes_own_tickets() -> Result<(), m2_reference::chain::ChainError> {
        let chain = m2_reference::chain::RefChain::tiny(0)?;
        let tctx = chain.ticket_ctx()?;
        let tickets = chain.generate_tickets(&tctx)?;
        let env = |t: &m2_reference::tickets::EmulatedTicket| TicketEnvelope {
            attempt: t.attempt,
            signature: RingSignature(t.proof),
        };
        let (delivered_t, own_t) = (&tickets[0], &tickets[1]);

        let mut ctx = base_ctx();
        ctx.reference_best = [1u8; 32];
        ctx.reference_block_hashes = vec![[1u8; 32]];
        ctx.delivered_tickets = vec![delivered_for(&ctx, delivered_t.id, 1, 2000)];
        ctx.nut_blocks = vec![nut_block_with_tickets(
            1,
            [1u8; 32],
            vec![env(delivered_t), env(own_t)],
            0,
        )];

        assert!(
            run(&l1_extrinsic_completeness(&ctx), &ObsLog::new())
                .iter()
                .any(|r| r.name == "l1_extrinsic_no_undelivered"
                    && r.outcome == Outcome::Fail(Severity::Hard)),
            "a ticket the node neither received nor announced is unaccounted for"
        );

        ctx.own_ticket_ids = vec![own_t.id];
        assert!(
            all_pass(&run(&l1_extrinsic_completeness(&ctx), &ObsLog::new())),
            "the same ticket, announced by the node itself, is its own to carry"
        );
        Ok(())
    }

    #[test]
    fn l1_extrinsic_pass_and_missing() -> Result<(), m2_reference::chain::ChainError> {
        // Real reference-generated tickets: distinct, valid ring-VRF ids.
        let chain = m2_reference::chain::RefChain::tiny(0)?;
        let tctx = chain.ticket_ctx()?;
        let tickets = chain.generate_tickets(&tctx)?;
        let env = |t: &m2_reference::tickets::EmulatedTicket| TicketEnvelope {
            attempt: t.attempt,
            signature: RingSignature(t.proof),
        };
        let (t1, t2, t3) = (&tickets[0], &tickets[1], &tickets[2]);
        let (id1, id2, id3) = (t1.id, t2.id, t3.id);
        assert_ne!(id1, id2, "reference tickets must have distinct ids");
        assert_ne!(id3, id1, "reference tickets must have distinct ids");
        assert_ne!(id3, id2, "reference tickets must have distinct ids");
        let (env1, env2, env3) = (env(t1), env(t2), env(t3));

        let mut ctx = base_ctx();
        ctx.reference_best = [1u8; 32];
        ctx.reference_block_hashes = vec![[1u8; 32]];
        // Slots 1 and 2 are both well inside the epoch, before the tail.
        ctx.delivered_tickets = vec![
            delivered_for(&ctx, id1, 1, 2000),
            delivered_for(&ctx, id2, 1, 500),
        ];
        ctx.nut_blocks = vec![nut_block_with_tickets(1, [1u8; 32], vec![env1.clone()], 0)];
        assert!(
            all_pass(&run(&l1_extrinsic_completeness(&ctx), &ObsLog::new())),
            "including the delivered ticket passes; a late-delivered one is optional"
        );

        // A ticket already on chain is not owed again. The first block takes
        // the one that was in hand for slot 1; by slot 2 the late one is owed
        // too, and the first must not be repeated.
        ctx.nut_blocks = vec![
            nut_block_with_tickets(1, [1u8; 32], vec![env1.clone()], 0),
            nut_block_with_tickets(2, [1u8; 32], vec![env2.clone()], 0),
        ];
        assert!(
            all_pass(&run(&l1_extrinsic_completeness(&ctx), &ObsLog::new())),
            "a ticket included once is not owed again by later blocks"
        );

        // Order of the blocks must not change the verdict.
        ctx.nut_blocks.reverse();
        assert!(
            all_pass(&run(&l1_extrinsic_completeness(&ctx), &ObsLog::new())),
            "inclusion is resolved by slot order, not by the order fetched"
        );

        // Repeating a ticket already on chain is caught twice over: the late
        // ticket is still owed, and the repeat is a fault in itself.
        ctx.nut_blocks = vec![
            nut_block_with_tickets(1, [1u8; 32], vec![env1.clone()], 0),
            nut_block_with_tickets(2, [1u8; 32], vec![env1.clone()], 0),
        ];
        let repeated = run(&l1_extrinsic_completeness(&ctx), &ObsLog::new());
        assert!(
            repeated
                .iter()
                .any(|r| r.name == "l1_extrinsic_includes_delivered"
                    && r.outcome == Outcome::Fail(Severity::Hard)),
            "the late ticket is still owed by the second block"
        );
        assert!(
            repeated.iter().any(|r| r.name == "l1_extrinsic_no_repeat"
                && r.outcome == Outcome::Fail(Severity::Hard)),
            "a ticket already on chain must not appear again"
        );

        ctx.nut_blocks = vec![nut_block(1, [1u8; 32], 0)];
        let results = run(&l1_extrinsic_completeness(&ctx), &ObsLog::new());
        assert!(
            results
                .iter()
                .any(|r| r.name == "l1_extrinsic_includes_delivered"
                    && r.outcome == Outcome::Fail(Severity::Hard)),
            "a missing delivered-valid ticket fails hard"
        );

        ctx.nut_blocks = vec![nut_block_with_tickets(
            1,
            [1u8; 32],
            vec![env1.clone(), env3],
            0,
        )];
        let results = run(&l1_extrinsic_completeness(&ctx), &ObsLog::new());
        assert!(
            results
                .iter()
                .any(|r| r.name == "l1_extrinsic_no_undelivered"
                    && r.outcome == Outcome::Fail(Severity::Hard)),
            "an un-delivered ticket in the extrinsic fails hard"
        );
        Ok(())
    }

    /// A block holds at most `max_tickets_per_block`, so owing more than that
    /// cannot be a failure to include them all — only a failure to fill the
    /// block. The old per-block subset rule was unsatisfiable here: the tiny
    /// cap is three and the harness generates four tickets per author.
    #[test]
    fn l1_extrinsic_inclusion_is_capped_and_carries_over(
    ) -> Result<(), m2_reference::chain::ChainError> {
        let chain = m2_reference::chain::RefChain::tiny(0)?;
        let tctx = chain.ticket_ctx()?;
        let tickets = chain.generate_tickets(&tctx)?;
        let env = |t: &m2_reference::tickets::EmulatedTicket| TicketEnvelope {
            attempt: t.attempt,
            signature: RingSignature(t.proof),
        };
        let four: Vec<_> = tickets.iter().take(4).collect();

        let mut ctx = base_ctx();
        assert_eq!(ctx.max_tickets_per_block, 3);
        ctx.delivered_tickets = four
            .iter()
            .map(|t| delivered_for(&ctx, t.id, 1, 2000))
            .collect();

        // Three of the four owed tickets fill the block; the fourth carries
        // over to the next block, which must then take it.
        ctx.nut_blocks = vec![
            nut_block_with_tickets(1, [1u8; 32], four[..3].iter().map(|t| env(t)).collect(), 0),
            nut_block_with_tickets(2, [1u8; 32], vec![env(four[3])], 0),
        ];
        assert!(
            all_pass(&run(&l1_extrinsic_completeness(&ctx), &ObsLog::new())),
            "a full block plus the carry-over is complete"
        );

        // Carrying only two when three were owed and three would fit fails.
        ctx.nut_blocks = vec![nut_block_with_tickets(
            1,
            [1u8; 32],
            four[..2].iter().map(|t| env(t)).collect(),
            0,
        )];
        let results = run(&l1_extrinsic_completeness(&ctx), &ObsLog::new());
        assert!(
            results
                .iter()
                .any(|r| r.name == "l1_extrinsic_includes_delivered"
                    && r.outcome == Outcome::Fail(Severity::Hard)),
            "a block that could hold three but took two is incomplete"
        );

        // The cap needs no assertion of its own: the extrinsic is a
        // `BoundedVec` bounded by `MaxTicketsPerBlock`, so a fourth ticket
        // cannot be represented, let alone decoded off the wire.
        let over_cap = jam_std_common::TicketsXt::truncate_from(
            four.iter().map(|t| env(t)).collect::<Vec<_>>(),
        );
        assert_eq!(
            over_cap.len(),
            ctx.max_tickets_per_block,
            "the wire type enforces the per-block cap"
        );
        Ok(())
    }

    /// Two Safrole gates the old check ignored, each of which made it demand
    /// inclusions the node is required to refuse: a block in the epoch tail
    /// carries no tickets at all, and a ticket may only be submitted during
    /// the epoch before the one it targets.
    #[test]
    fn l1_extrinsic_respects_the_tail_and_the_target_epoch(
    ) -> Result<(), m2_reference::chain::ChainError> {
        let chain = m2_reference::chain::RefChain::tiny(0)?;
        let tctx = chain.ticket_ctx()?;
        let tickets = chain.generate_tickets(&tctx)?;
        let t = &tickets[0];
        let envelope = TicketEnvelope {
            attempt: t.attempt,
            signature: RingSignature(t.proof),
        };

        let mut ctx = base_ctx();
        let tail_slot = EPOCH_TAIL_START; // epoch 0, first slot of the tail
        ctx.delivered_tickets = vec![DeliveredTicket {
            id: t.id,
            delivered_at_ms: ctx.slot_start_ms(tail_slot) - 10_000,
            target_epoch: 1,
        }];

        // In the tail nothing is owed, so an empty block is correct...
        ctx.nut_blocks = vec![nut_block(tail_slot, [1u8; 32], 0)];
        assert!(
            all_pass(&run(&l1_extrinsic_completeness(&ctx), &ObsLog::new())),
            "an empty extrinsic in the epoch tail is correct, not incomplete"
        );
        // ...and a non-empty one is a fault.
        ctx.nut_blocks = vec![nut_block_with_tickets(
            tail_slot,
            [1u8; 32],
            vec![envelope.clone()],
            0,
        )];
        let results = run(&l1_extrinsic_completeness(&ctx), &ObsLog::new());
        assert!(
            results
                .iter()
                .any(|r| r.name == "l1_extrinsic_empty_at_tail"
                    && r.outcome == Outcome::Fail(Severity::Hard)),
            "a ticket submitted in the epoch tail fails hard"
        );

        // A ticket for epoch 1 is stale once the chain is in epoch 1 itself.
        let next_epoch_slot = EPOCH_PERIOD;
        ctx.nut_blocks = vec![nut_block(next_epoch_slot, [1u8; 32], 0)];
        assert!(
            all_pass(&run(&l1_extrinsic_completeness(&ctx), &ObsLog::new())),
            "a ticket whose target epoch has begun is no longer owed"
        );
        Ok(())
    }

    #[test]
    fn l1_skipped_gap_pass() {
        let mut ctx = base_ctx();
        // A reference-accepted parent at slot 5 (the NUT's own earlier block,
        // imported into the reference chain) and a NUT block at slot 7: the gap
        // of 2 is valid because the parent is a known reference block (the
        // emulated author skipped slot 6).
        let parent_block = nut_block(5, [0u8; 32], 0);
        let parent_hash = parent_block.block.header.hash().0;
        ctx.reference_best = [0u8; 32];
        ctx.reference_block_hashes = vec![parent_hash];
        ctx.reference_chain = vec![(5, parent_hash)];
        ctx.nut_blocks = vec![parent_block, nut_block(7, parent_hash, 0)];
        assert!(all_pass(&run(&l1_skipped_slots(&ctx), &ObsLog::new())));

        // A gap over a parent the reference never accepted → fail hard.
        let parent_block = nut_block(5, [0u8; 32], 0);
        let parent_hash = parent_block.block.header.hash().0;
        ctx.reference_block_hashes = Vec::new();
        ctx.nut_blocks = vec![parent_block, nut_block(7, parent_hash, 0)];
        let results = run(&l1_skipped_slots(&ctx), &ObsLog::new());
        assert!(
            results
                .iter()
                .any(|r| r.name == "l1_skipped_slots_valid_parent"
                    && r.outcome == Outcome::Fail(Severity::Hard)),
            "a gap over an unaccepted parent fails hard"
        );
    }

    #[test]
    fn all_l1_checks_distinct() {
        let checks = all(&base_ctx());
        assert_eq!(checks.len(), 6);
        let mut ids: Vec<&str> = checks.iter().map(|c| c.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 6, "all check ids are distinct");
    }

    #[test]
    fn all_l1_empty_ctx_is_soft_finding() {
        use crate::ctx::L1Ctx;
        let empty = L1Ctx {
            reference_best: [0u8; 32],
            reference_block_hashes: vec![],
            reference_chain: vec![],
            nut_blocks: vec![],
            imports: vec![],
            delivered_tickets: vec![],
            own_ticket_ids: Vec::new(),
            slot_period_ms: 6000,
            epoch_period: EPOCH_PERIOD,
            epoch_tail_start: EPOCH_TAIL_START,
            max_tickets_per_block: MAX_TICKETS_PER_BLOCK,
        };
        let checks = all(&empty);
        assert_eq!(checks.len(), 6, "six checks even with no NUT blocks");
        let mut sched = crate::dsl::Scheduler::new();
        let obs = ObsLog::new();
        let results: Vec<CheckResult> = checks.iter().flat_map(|c| sched.fire(c, &obs)).collect();
        assert_eq!(results.len(), 6);
        assert!(
            results
                .iter()
                .all(|r| r.outcome == Outcome::Fail(Severity::Soft)),
            "empty lane is an honest soft finding, not a pass"
        );
    }
}
