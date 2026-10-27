//! L1/L2 scenario context: runner-injected facts the lane checks read.
//!
//! L1 (block authoring) and L2 (Safrole tickets) checks are richer than the
//! L0 event-subsequence checks: they need *facts* the runner precomputes and
//! injects — the reference chain head, NUT blocks it announced, import
//! outcomes, delivered/verified tickets, epoch boundaries. Those facts live
//! here, decoupled from `m2-reference` (a dev-dependency only): the runner
//! fills the contexts from the reference trace at run time.

use jam_types::JAM_COMMON_ERA;

/// NUT validator index (matches `m2-runner/src/cli.rs`, default 5).
pub const NUT_INDEX: u16 = 5;

/// Default slot period in milliseconds (JAM common: 6 s slots).
pub const SLOT_PERIOD_MS: u64 = 6000;

/// Tickets must arrive this long before a slot's start to be expected in it.
pub const TICKET_ARRIVAL_LEAD_MS: u64 = 2000;

/// Default epoch length in slots (tiny protocol parameters).
pub const EPOCH_PERIOD: u32 = 12;

/// Default first slot of the epoch tail, past which a block's ticket extrinsic
/// must be empty (tiny protocol parameters).
pub const EPOCH_TAIL_START: u32 = 10;

/// Default per-block ticket-extrinsic cap (tiny protocol parameters).
pub const MAX_TICKETS_PER_BLOCK: usize = 3;

/// A block the NUT announced (the block itself, and when it announced it).
#[derive(Clone, Debug)]
pub struct NutBlock {
    pub block: jam_std_common::Block,
    pub announced_wall_ms: u64,
}

/// Outcome of the runner importing a NUT block into the reference chain.
///
/// Three distinct 32-byte values, easy to confuse and checked against each
/// other by the L1 state-root lane: `header_root` identifies the block,
/// `declared_parent_root` is the prior state root its header claims, and
/// `root` is the reference engine's posterior state root for the block itself.
#[derive(Clone, Debug)]
pub struct ImportFact {
    /// Hash of the block's header.
    pub header_root: [u8; 32],
    /// Hash of the block's parent.
    pub parent: [u8; 32],
    /// Prior state root the block's header declares.
    pub declared_parent_root: [u8; 32],
    /// The reference's own posterior state root for the parent.
    pub reference_parent_root: Option<[u8; 32]>,
    pub ok: bool,
    /// Reference posterior state root of this block after a successful import.
    pub root: Option<[u8; 32]>,
    /// Why the import failed, when `ok` is false.
    pub error: Option<String>,
}

/// A ticket the runner delivered to the NUT over the wire.
///
/// `delivered_at_ms` is wall-clock milliseconds since the Unix epoch, the same
/// base as [`L1Ctx::slot_start_ms`]. It has to be: the two are compared, and
/// filling this from the observation log's run-relative timestamps made every
/// ticket look as if it had been delivered before the run began.
#[derive(Clone, Debug)]
pub struct DeliveredTicket {
    pub id: [u8; 32],
    pub delivered_at_ms: u64,
    /// Epoch the ticket is *for*; it may only be included in a block of the
    /// epoch before this one.
    pub target_epoch: u32,
}

/// Facts the L1 (block authoring) lane reads.
///
/// `Clone` lets a `dsl::Check` closure (which must be `'static`) capture an
/// owned snapshot of the facts it reads.
#[derive(Clone)]
pub struct L1Ctx {
    pub reference_best: [u8; 32],
    pub reference_block_hashes: Vec<[u8; 32]>,
    /// The reference best chain as `(slot, header hash)`, ascending by slot.
    ///
    /// What a NUT block's parent must be judged against is the reference head
    /// *at that block's slot*, not the head after the window closed; see
    /// [`L1Ctx::reference_best_at`].
    pub reference_chain: Vec<(u32, [u8; 32])>,
    pub nut_blocks: Vec<NutBlock>,
    pub imports: Vec<ImportFact>,
    pub delivered_tickets: Vec<DeliveredTicket>,
    /// Ids of tickets the NUT itself announced over CE 131/132.
    ///
    /// The node under test is a validator: it runs the lottery too, and its
    /// own tickets belong in its own blocks. Without this the harness sees
    /// them as tickets nobody delivered and fails a node for doing exactly
    /// what the protocol asks of it.
    pub own_ticket_ids: Vec<[u8; 32]>,
    pub slot_period_ms: u64,
    pub epoch_period: u32,
    pub epoch_tail_start: u32,
    pub max_tickets_per_block: usize,
}

impl L1Ctx {
    /// Wall-clock start of `slot`: `JAM_COMMON_ERA + slot * slot_period_ms`.
    pub fn slot_start_ms(&self, slot: u32) -> u64 {
        JAM_COMMON_ERA * 1000 + slot as u64 * self.slot_period_ms
    }

    /// The reference best block as of the start of `slot`: the last block on
    /// the reference chain with a strictly earlier slot.
    ///
    /// The reference chain only ever extends during a run (it adopts the NUT's
    /// blocks rather than forking away from them), so every block on the final
    /// best chain was also the best block at its own slot.
    pub fn reference_best_at(&self, slot: u32) -> Option<[u8; 32]> {
        self.reference_chain
            .iter()
            .rev()
            .find(|(s, _)| *s < slot)
            .map(|(_, hash)| *hash)
    }

    /// Whether a block at `slot` may carry tickets at all: inside the epoch,
    /// before the tail (`slot % epoch_period < epoch_tail_start`).
    pub fn slot_accepts_tickets(&self, slot: u32) -> bool {
        slot % self.epoch_period < self.epoch_tail_start
    }

    /// Tickets the NUT owes a block at `slot`: delivered at least
    /// [`TICKET_ARRIVAL_LEAD_MS`] before the slot started, targeting the epoch
    /// after this block's, and in a slot that still accepts tickets.
    ///
    /// All three conditions matter. A ticket for epoch `e` may only be
    /// submitted during epoch `e - 1`, and nothing at all may be submitted in
    /// the tail — so a check that only applied the 2 s arrival rule demanded
    /// inclusions the node is required to refuse.
    pub fn expected_tickets_for_slot(&self, slot: u32) -> Vec<[u8; 32]> {
        if !self.slot_accepts_tickets(slot) {
            return Vec::new();
        }
        let cutoff = self
            .slot_start_ms(slot)
            .saturating_sub(TICKET_ARRIVAL_LEAD_MS);
        let submittable_epoch = slot / self.epoch_period + 1;
        self.delivered_tickets
            .iter()
            .filter(|t| t.delivered_at_ms <= cutoff)
            .filter(|t| t.target_epoch == submittable_epoch)
            .map(|t| t.id)
            .collect()
    }
}

/// Which distribution step carried a ticket (`simple.md:314-316`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TicketDelivery {
    /// CE 131: the ticket goes to the validator it proxies for (the NUT).
    Ce131,
    /// CE 132: the ticket is broadcast to every validator, incl. the NUT.
    Ce132,
}

/// An emulator-sent ticket the L2 lane expects the NUT to handle.
#[derive(Clone, Copy, Debug)]
pub struct EmuTicket {
    pub id: [u8; 32],
    pub author: u16,
    pub attempt: u8,
    pub proof: [u8; 784],
    pub proxy: u16,
    pub valid: bool,
    pub delivery: TicketDelivery,
    pub slot: u32,
    /// Epoch the ticket is labelled for. Equal to the plan's target epoch for
    /// every real ticket; the unknown-epoch probe (`simple.md:335-337`) is
    /// the one entry that names an epoch the NUT cannot know yet.
    pub target_epoch: u32,
}

/// Facts about a ticket the NUT distributed to the emulator.
///
/// One fact per frame, so a CE 132 broadcast of a single ticket yields one
/// fact per emulated validator it reached. `peer` is the emulated validator
/// the frame arrived at — the same index space the NUT itself lives in — so
/// a CE 131 distribution's `peer` is the proxy the NUT chose for it.
#[derive(Clone, Debug)]
pub struct NutTicketFacts {
    pub epoch: u32,
    pub ticket: jamnp_s::codec::ce131_136::Ticket,
    pub peer: u16,
    /// Which common entry carried it: CE 131 (to the proxy) or CE 132
    /// (broadcast). Read off the stream kind, never inferred from `peer`.
    pub delivery: TicketDelivery,
    /// Whether the ring-VRF proof verified, or `None` when the harness held
    /// no ticket context for the ticket's epoch and so could not judge it.
    pub verified: Option<bool>,
    pub received_at_ms: u64,
}

impl NutTicketFacts {
    /// Identity of the ticket this frame carried, for grouping the copies of
    /// one broadcast together. The wire never names a ticket id, and the
    /// `(attempt, proof)` pair determines it.
    pub fn identity(&self) -> (u8, [u8; 784]) {
        (self.ticket.attempt, self.ticket.proof)
    }
}

/// Facts the L2 (Safrole tickets) lane reads.
///
/// `Clone` lets a `dsl::Check` closure (which must be `'static`) capture an
/// owned snapshot of the facts it reads.
#[derive(Clone)]
pub struct L2Ctx {
    pub target_epoch: u32,
    pub epoch_start_slot: u32,
    pub emu_plan: Vec<EmuTicket>,
    pub nut_tickets: Vec<NutTicketFacts>,
    /// Ticket ids in the NUT's authored block's ticket extrinsic.
    pub nut_block_ticket_ids: Vec<[u8; 32]>,
    /// Ids of tickets the NUT itself announced -- see [`L1Ctx::own_ticket_ids`].
    pub own_ticket_ids: Vec<[u8; 32]>,
    /// Slot of the NUT block judged for inclusion, or `None` when the NUT
    /// authored no block in the epoch the tickets were submittable in.
    ///
    /// Not a sentinel slot: there is no slot value that means "no block", and
    /// judging a block that does not exist credits or blames the node for
    /// something it never did.
    pub nut_block_slot: Option<u32>,
    /// Validator index of the node under test.
    pub nut_index: u16,
    /// Validator indices the harness emulates — every validator but the NUT.
    pub emulated_peers: Vec<u16>,
    pub slot_period_ms: u64,
    pub epoch_period: u32,
    pub epoch_tail_start: u32,
    /// Ticket attempts one validator may make per epoch, and so the most
    /// tickets it may generate for one epoch.
    pub tickets_per_validator: u8,
    /// Most tickets one block's extrinsic may carry.
    pub max_tickets_per_block: usize,
}

impl L2Ctx {
    /// Whether `ticket` was proxied to the NUT itself (proxy == NUT index).
    pub fn proxy_is_nut(&self, ticket: &EmuTicket) -> bool {
        ticket.proxy == self.nut_index
    }

    /// The slot the wall clock was in at `ms`.
    pub fn slot_at_ms(&self, ms: u64) -> u32 {
        let since_era = ms.saturating_sub(JAM_COMMON_ERA * 1000);
        (since_era / self.slot_period_ms) as u32
    }

    /// The epoch a ticket sent at `ms` must be for.
    ///
    /// A validator generates tickets during epoch `e` for epoch `e + 1`
    /// (`simple.md:305-349`), so the expectation moves with the clock. A run
    /// that crosses an epoch boundary — and one spanning a full epoch always
    /// does — sees the NUT switch targets mid-run, which is correct of it.
    pub fn expected_target_epoch(&self, ms: u64) -> u32 {
        self.slot_at_ms(ms) / self.epoch_period + 1
    }

    /// Whether `slot` is in the epoch tail, where a block's ticket extrinsic
    /// must be empty.
    pub fn slot_in_tail(&self, slot: u32) -> bool {
        slot % self.epoch_period >= self.epoch_tail_start
    }

    /// Whether a ticket reaching the NUT in `slot` leaves it room to forward
    /// as proxy before the lottery closes.
    ///
    /// A proxy forwards within a window inside the lottery period, not at the
    /// instant it receives: it delays to avoid revealing when the generator
    /// sent, and stops well before the tail. How long that window is belongs
    /// to the node, so the harness only asserts the duty for a ticket that
    /// arrived in the lottery's first half — early enough that any window
    /// must still be open. A ticket the harness delivered later than that is
    /// reported as not exercised, because a node that does not forward it is
    /// not thereby wrong.
    /// Whether the emulator itself delivered this ticket to the NUT.
    ///
    /// A ticket the NUT sends that the harness first sent it is a forward,
    /// not one the NUT generated — the two are told apart by the ticket, not
    /// by the entry that carried it, since CE 132 carries both.
    pub fn was_delivered_by_the_emulator(&self, attempt: u8, proof: &[u8; 784]) -> bool {
        self.emu_plan
            .iter()
            .any(|t| t.attempt == attempt && t.proof == *proof)
    }

    pub fn leaves_room_to_forward(&self, slot: u32) -> bool {
        slot % self.epoch_period < self.epoch_tail_start / 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jam_std_common::{Block, Extrinsic, Header};
    use std::sync::Arc;

    fn base_l1() -> L1Ctx {
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

    #[test]
    fn ctx_expected_tickets_2s_rule() {
        let mut ctx = base_l1();
        ctx.delivered_tickets = vec![
            DeliveredTicket {
                id: [1u8; 32],
                delivered_at_ms: jam_types::JAM_COMMON_ERA * 1000 - 2000,
                target_epoch: 1,
            },
            DeliveredTicket {
                id: [2u8; 32],
                delivered_at_ms: jam_types::JAM_COMMON_ERA * 1000 - 500,
                target_epoch: 1,
            },
        ];

        let expected = ctx.expected_tickets_for_slot(0);

        assert!(
            expected.contains(&[1u8; 32]),
            "ticket 2 s early is expected"
        );
        assert!(
            !expected.contains(&[2u8; 32]),
            "ticket 500 ms early is excluded"
        );
    }

    /// The arrival rule is not the only one: a slot in the epoch tail owes
    /// nothing, and a ticket whose target epoch has already begun is stale.
    #[test]
    fn ctx_expected_tickets_respect_tail_and_target_epoch() {
        let mut ctx = base_l1();
        let long_ago = 0;
        ctx.delivered_tickets = vec![DeliveredTicket {
            id: [1u8; 32],
            delivered_at_ms: long_ago,
            target_epoch: 1,
        }];

        assert_eq!(
            ctx.expected_tickets_for_slot(EPOCH_TAIL_START - 1),
            vec![[1u8; 32]],
            "the last slot before the tail still owes it"
        );
        assert!(
            ctx.expected_tickets_for_slot(EPOCH_TAIL_START).is_empty(),
            "nothing is owed once the epoch tail starts"
        );
        assert!(
            ctx.expected_tickets_for_slot(EPOCH_PERIOD).is_empty(),
            "a ticket for epoch 1 is stale in epoch 1"
        );
    }

    /// The reference head is resolved as of the block's own slot, so a block
    /// is never judged against a head that did not exist when it was authored.
    #[test]
    fn ctx_reference_best_at_slot() {
        let mut ctx = base_l1();
        ctx.reference_chain = vec![(3, [1u8; 32]), (7, [2u8; 32])];

        assert_eq!(ctx.reference_best_at(0), None);
        assert_eq!(
            ctx.reference_best_at(3),
            None,
            "strictly earlier slots only"
        );
        assert_eq!(ctx.reference_best_at(4), Some([1u8; 32]));
        assert_eq!(ctx.reference_best_at(7), Some([1u8; 32]));
        assert_eq!(ctx.reference_best_at(8), Some([2u8; 32]));
        assert_eq!(ctx.reference_best_at(99), Some([2u8; 32]));
    }

    #[test]
    fn ctx_slot_start_matches_common_era() {
        let ctx = base_l1();

        assert_eq!(ctx.slot_start_ms(0), jam_types::JAM_COMMON_ERA * 1000);
        assert_eq!(
            ctx.slot_start_ms(1),
            jam_types::JAM_COMMON_ERA * 1000 + 6000
        );
    }

    #[test]
    fn ctx_carries_plan_and_facts() {
        let l1 = L1Ctx {
            reference_best: [7u8; 32],
            reference_block_hashes: vec![[1u8; 32], [2u8; 32]],
            reference_chain: vec![(1, [1u8; 32]), (2, [2u8; 32])],
            nut_blocks: vec![NutBlock {
                block: Block {
                    header: Arc::new(Header::genesis().into()),
                    extrinsic: Arc::new(Extrinsic::default()),
                },
                announced_wall_ms: 1000,
            }],
            imports: vec![ImportFact {
                header_root: [3u8; 32],
                parent: [8u8; 32],
                declared_parent_root: [9u8; 32],
                reference_parent_root: Some([9u8; 32]),
                ok: true,
                root: Some([4u8; 32]),
                error: None,
            }],
            delivered_tickets: vec![DeliveredTicket {
                id: [5u8; 32],
                delivered_at_ms: 500,
                target_epoch: 1,
            }],
            own_ticket_ids: Vec::new(),
            slot_period_ms: SLOT_PERIOD_MS,
            epoch_period: EPOCH_PERIOD,
            epoch_tail_start: EPOCH_TAIL_START,
            max_tickets_per_block: MAX_TICKETS_PER_BLOCK,
        };
        assert_eq!(l1.reference_best, [7u8; 32]);
        assert_eq!(l1.reference_block_hashes, vec![[1u8; 32], [2u8; 32]]);
        assert_eq!(l1.nut_blocks.len(), 1);
        assert_eq!(l1.nut_blocks[0].block.header.slot, 0);
        assert_eq!(l1.nut_blocks[0].announced_wall_ms, 1000);
        assert_eq!(l1.imports[0].header_root, [3u8; 32]);
        assert!(l1.imports[0].ok);
        assert_eq!(l1.imports[0].root, Some([4u8; 32]));
        assert_eq!(l1.imports[0].error, None);
        assert_eq!(l1.delivered_tickets[0].id, [5u8; 32]);
        assert_eq!(l1.slot_period_ms, SLOT_PERIOD_MS);

        let emu = EmuTicket {
            id: [6u8; 32],
            author: 2,
            attempt: 0,
            proof: [9u8; 784],
            proxy: NUT_INDEX,
            valid: true,
            delivery: TicketDelivery::Ce132,
            slot: 10,
            target_epoch: 3,
        };
        let l2 = L2Ctx {
            target_epoch: 3,
            epoch_start_slot: 10,
            emu_plan: vec![emu],
            nut_tickets: vec![NutTicketFacts {
                epoch: 3,
                ticket: jamnp_s::codec::ce131_136::Ticket {
                    attempt: 0,
                    proof: [0u8; 784],
                },
                peer: 1,
                delivery: TicketDelivery::Ce131,
                verified: Some(true),
                received_at_ms: 2000,
            }],
            nut_block_ticket_ids: vec![[6u8; 32]],
            own_ticket_ids: Vec::new(),
            nut_block_slot: Some(12),
            nut_index: NUT_INDEX,
            emulated_peers: (0..NUT_INDEX).collect(),
            slot_period_ms: SLOT_PERIOD_MS,
            epoch_period: EPOCH_PERIOD,
            epoch_tail_start: EPOCH_TAIL_START,
            tickets_per_validator: 4,
            max_tickets_per_block: MAX_TICKETS_PER_BLOCK,
        };
        assert_eq!(l2.target_epoch, 3);
        assert_eq!(l2.epoch_start_slot, 10);
        assert_eq!(l2.emu_plan[0].id, [6u8; 32]);
        assert_eq!(l2.emu_plan[0].author, 2);
        assert_eq!(l2.emu_plan[0].attempt, 0);
        assert_eq!(l2.emu_plan[0].proof, [9u8; 784]);
        assert_eq!(l2.emu_plan[0].proxy, NUT_INDEX);
        assert!(l2.emu_plan[0].valid);
        assert_eq!(l2.emu_plan[0].delivery, TicketDelivery::Ce132);
        assert_eq!(l2.emu_plan[0].slot, 10);
        assert_eq!(l2.nut_tickets[0].epoch, 3);
        assert_eq!(l2.nut_tickets[0].ticket.attempt, 0);
        assert_eq!(l2.nut_tickets[0].ticket.proof, [0u8; 784]);
        assert_eq!(l2.nut_tickets[0].peer, 1);
        assert_eq!(l2.nut_tickets[0].verified, Some(true));
        assert_eq!(l2.nut_tickets[0].delivery, TicketDelivery::Ce131);
        assert_eq!(l2.nut_tickets[0].received_at_ms, 2000);
        assert_eq!(l2.nut_block_ticket_ids, vec![[6u8; 32]]);
        assert_eq!(l2.nut_block_slot, Some(12));

        assert!(l2.proxy_is_nut(&emu), "proxy == NUT index is the NUT");
        assert!(
            !l2.proxy_is_nut(&EmuTicket { proxy: 1, ..emu }),
            "proxy != NUT index is not the NUT"
        );
    }
}
