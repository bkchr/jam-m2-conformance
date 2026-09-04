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

/// A block the NUT announced (the block itself, and when it announced it).
#[derive(Clone, Debug)]
pub struct NutBlock {
    pub block: jam_std_common::Block,
    pub announced_wall_ms: u64,
}

/// Outcome of the runner importing a NUT block into the reference chain.
#[derive(Clone, Debug)]
pub struct ImportFact {
    pub header_root: [u8; 32],
    pub ok: bool,
    /// Reference state root after a successful import.
    pub root: Option<[u8; 32]>,
    /// Why the import failed, when `ok` is false.
    pub error: Option<String>,
}

/// A ticket the runner delivered to the NUT over the wire.
#[derive(Clone, Debug)]
pub struct DeliveredTicket {
    pub id: [u8; 32],
    pub delivered_at_ms: u64,
}

/// Facts the L1 (block authoring) lane reads.
pub struct L1Ctx {
    pub reference_best: [u8; 32],
    pub reference_block_hashes: Vec<[u8; 32]>,
    pub nut_blocks: Vec<NutBlock>,
    pub imports: Vec<ImportFact>,
    pub delivered_tickets: Vec<DeliveredTicket>,
    pub slot_period_ms: u64,
}

impl L1Ctx {
    /// Wall-clock start of `slot`: `JAM_COMMON_ERA + slot * slot_period_ms`.
    pub fn slot_start_ms(&self, slot: u32) -> u64 {
        JAM_COMMON_ERA * 1000 + slot as u64 * self.slot_period_ms
    }

    /// Tickets delivered at least [`TICKET_ARRIVAL_LEAD_MS`] before the slot
    /// start — the ones the NUT must already have in hand for `slot`.
    pub fn expected_tickets_for_slot(&self, slot: u32) -> Vec<[u8; 32]> {
        let cutoff = self
            .slot_start_ms(slot)
            .saturating_sub(TICKET_ARRIVAL_LEAD_MS);
        self.delivered_tickets
            .iter()
            .filter(|t| t.delivered_at_ms <= cutoff)
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
}

/// Facts about a ticket the NUT distributed to the emulator.
#[derive(Clone, Debug)]
pub struct NutTicketFacts {
    pub epoch: u32,
    pub ticket: jamnp_s::codec::ce131_136::Ticket,
    pub peer: u16,
    pub verified: bool,
    pub received_at_ms: u64,
}

/// Facts the L2 (Safrole tickets) lane reads.
pub struct L2Ctx {
    pub target_epoch: u32,
    pub epoch_start_slot: u32,
    pub emu_plan: Vec<EmuTicket>,
    pub nut_tickets: Vec<NutTicketFacts>,
}

impl L2Ctx {
    /// Whether `ticket` was proxied to the NUT itself (proxy == NUT index).
    pub fn proxy_is_nut(&self, ticket: &EmuTicket) -> bool {
        ticket.proxy == NUT_INDEX
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
            nut_blocks: Vec::new(),
            imports: Vec::new(),
            delivered_tickets: Vec::new(),
            slot_period_ms: SLOT_PERIOD_MS,
        }
    }

    #[test]
    fn ctx_expected_tickets_2s_rule() {
        let mut ctx = base_l1();
        ctx.delivered_tickets = vec![
            DeliveredTicket {
                id: [1u8; 32],
                delivered_at_ms: jam_types::JAM_COMMON_ERA * 1000 - 2000,
            },
            DeliveredTicket {
                id: [2u8; 32],
                delivered_at_ms: jam_types::JAM_COMMON_ERA * 1000 - 500,
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
            nut_blocks: vec![NutBlock {
                block: Block {
                    header: Arc::new(Header::genesis().into()),
                    extrinsic: Arc::new(Extrinsic::default()),
                },
                announced_wall_ms: 1000,
            }],
            imports: vec![ImportFact {
                header_root: [3u8; 32],
                ok: true,
                root: Some([4u8; 32]),
                error: None,
            }],
            delivered_tickets: vec![DeliveredTicket {
                id: [5u8; 32],
                delivered_at_ms: 500,
            }],
            slot_period_ms: SLOT_PERIOD_MS,
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
        };
        let l2 = L2Ctx {
            target_epoch: 3,
            epoch_start_slot: 10,
            emu_plan: vec![emu.clone()],
            nut_tickets: vec![NutTicketFacts {
                epoch: 3,
                ticket: jamnp_s::codec::ce131_136::Ticket {
                    attempt: 0,
                    proof: [0u8; 784],
                },
                peer: 1,
                verified: true,
                received_at_ms: 2000,
            }],
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
        assert!(l2.nut_tickets[0].verified);
        assert_eq!(l2.nut_tickets[0].received_at_ms, 2000);

        assert!(l2.proxy_is_nut(&emu), "proxy == NUT index is the NUT");
        assert!(
            !l2.proxy_is_nut(&EmuTicket { proxy: 1, ..emu }),
            "proxy != NUT index is not the NUT"
        );
    }
}
