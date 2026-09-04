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
                log::check("l1_timing_within_slot", in_window, Severity::Soft)
            })
            .collect()
    })
}

/// L1 — Parent: each NUT block's parent is a known reference block or a prior
/// NUT block; the first NUT block builds on `reference_best`; no two NUT
/// blocks share a parent (equivocation).
pub fn l1_parent(ctx: &L1Ctx) -> Check {
    let ctx = ctx.clone();
    check("l1_parent", Severity::Hard, move |_obs| {
        let mut known: HashSet<[u8; 32]> = ctx.reference_block_hashes.iter().copied().collect();
        known.insert(ctx.reference_best);
        let mut used_parents: HashSet<[u8; 32]> = HashSet::new();
        let mut results = Vec::new();
        for (i, nut) in ctx.nut_blocks.iter().enumerate() {
            let parent = nut.block.header.parent.0;
            if i == 0 {
                results.push(log::check(
                    "l1_parent_first_is_reference_best",
                    parent == ctx.reference_best,
                    Severity::Hard,
                ));
            }
            results.push(log::check(
                "l1_parent_is_known",
                known.contains(&parent),
                Severity::Hard,
            ));
            results.push(log::check(
                "l1_parent_no_equivocation",
                used_parents.insert(parent),
                Severity::Hard,
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
                let imported_ok = ctx
                    .imports
                    .iter()
                    .any(|imp| imp.header_root == header_root && imp.ok);
                log::check("l1_header_seal_import_ok", imported_ok, Severity::Hard)
            })
            .collect()
    })
}

/// L1 — State root: every successfully imported block's reference state root
/// equals its header root (DESIGN.md §11 L1 "State root").
pub fn l1_state_root(ctx: &L1Ctx) -> Check {
    let ctx = ctx.clone();
    check("l1_state_root", Severity::Hard, move |_obs| {
        ctx.imports
            .iter()
            .filter(|imp| imp.ok)
            .map(|imp| {
                log::check(
                    "l1_state_root_matches_header",
                    imp.root == Some(imp.header_root),
                    Severity::Hard,
                )
            })
            .collect()
    })
}

/// L1 — Extrinsic completeness: every NUT block's ticket extrinsic is a
/// superset of the tickets delivered ≥ 2 s before the slot (all must be
/// included) and a subset of the delivered tickets (nothing un-delivered or
/// injected-invalid is included).
pub fn l1_extrinsic_completeness(ctx: &L1Ctx) -> Check {
    let ctx = ctx.clone();
    check("l1_extrinsic_completeness", Severity::Hard, move |_obs| {
        let delivered: HashSet<[u8; 32]> = ctx.delivered_tickets.iter().map(|t| t.id).collect();
        let mut results = Vec::new();
        for nut in &ctx.nut_blocks {
            let included: HashSet<[u8; 32]> = nut
                .block
                .extrinsic
                .tickets
                .iter()
                .map(|t| t.id().0)
                .collect();
            let expected: HashSet<[u8; 32]> = ctx
                .expected_tickets_for_slot(nut.block.header.slot)
                .into_iter()
                .collect();
            results.push(log::check(
                "l1_extrinsic_includes_delivered",
                expected.is_subset(&included),
                Severity::Hard,
            ));
            results.push(log::check(
                "l1_extrinsic_no_undelivered",
                included.is_subset(&delivered),
                Severity::Hard,
            ));
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
            results.push(log::check(
                "l1_skipped_slots_valid_parent",
                pass,
                Severity::Hard,
            ));
            slot_by_hash.insert(nut.block.header.hash().0, nut.block.header.slot);
        }
        results
    })
}

/// All six L1 checks in order.
pub fn all(ctx: &L1Ctx) -> Vec<Check> {
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
    use crate::ctx::{DeliveredTicket, ImportFact, NutBlock, SLOT_PERIOD_MS};
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
            nut_blocks: Vec::new(),
            imports: Vec::new(),
            delivered_tickets: Vec::new(),
            slot_period_ms: SLOT_PERIOD_MS,
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
            ok: true,
            root: Some(header_root),
            error: None,
        }];
        assert!(all_pass(&run(&l1_header_seal(&ctx), &ObsLog::new())));

        ctx.imports[0] = ImportFact {
            header_root,
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

    #[test]
    fn l1_state_root_match_and_mismatch() {
        let ctx = base_ctx();
        let mut ok = ctx.clone();
        ok.imports = vec![ImportFact {
            header_root: [1u8; 32],
            ok: true,
            root: Some([1u8; 32]),
            error: None,
        }];
        assert!(all_pass(&run(&l1_state_root(&ok), &ObsLog::new())));

        let mut mismatch = ctx.clone();
        mismatch.imports = vec![ImportFact {
            header_root: [1u8; 32],
            ok: true,
            root: Some([2u8; 32]),
            error: None,
        }];
        let results = run(&l1_state_root(&mismatch), &ObsLog::new());
        assert!(
            results
                .iter()
                .any(|r| r.name == "l1_state_root_matches_header"
                    && r.outcome == Outcome::Fail(Severity::Hard)),
            "a mismatched state root fails hard"
        );

        let mut failed_import = ctx.clone();
        failed_import.imports = vec![ImportFact {
            header_root: [1u8; 32],
            ok: false,
            root: Some([2u8; 32]),
            error: Some("BadSealSignature".into()),
        }];
        let failed = run(&l1_state_root(&failed_import), &ObsLog::new());
        assert!(
            failed.is_empty(),
            "failed imports are not state-root checked"
        );
    }

    #[test]
    fn l1_extrinsic_pass_and_missing() -> Result<(), m2_reference::chain::ChainError> {
        // Real reference-generated tickets: distinct, valid ring-VRF ids.
        let chain = m2_reference::chain::RefChain::tiny(1..6)?;
        let tctx = chain.ticket_ctx()?;
        let tickets = chain.generate_tickets(&tctx)?;
        let (t1, t2, t3) = (&tickets[0], &tickets[1], &tickets[2]);
        let (id1, id2, id3) = (t1.id, t2.id, t3.id);
        assert_ne!(id1, id2, "reference tickets must have distinct ids");
        assert_ne!(id3, id1, "reference tickets must have distinct ids");
        assert_ne!(id3, id2, "reference tickets must have distinct ids");
        let env1 = TicketEnvelope {
            attempt: t1.attempt,
            signature: RingSignature(t1.proof),
        };
        let env3 = TicketEnvelope {
            attempt: t3.attempt,
            signature: RingSignature(t3.proof),
        };

        let mut ctx = base_ctx();
        ctx.reference_best = [1u8; 32];
        ctx.reference_block_hashes = vec![[1u8; 32]];
        let slot_start = ctx.slot_start_ms(1);
        ctx.delivered_tickets = vec![
            DeliveredTicket {
                id: id1,
                delivered_at_ms: slot_start - 2000,
            },
            DeliveredTicket {
                id: id2,
                delivered_at_ms: slot_start - 500,
            },
        ];
        ctx.nut_blocks = vec![nut_block_with_tickets(1, [1u8; 32], vec![env1.clone()], 0)];
        assert!(
            all_pass(&run(&l1_extrinsic_completeness(&ctx), &ObsLog::new())),
            "including the delivered ticket passes; a late-delivered one is optional"
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

        ctx.nut_blocks = vec![nut_block_with_tickets(1, [1u8; 32], vec![env1, env3], 0)];
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
}
