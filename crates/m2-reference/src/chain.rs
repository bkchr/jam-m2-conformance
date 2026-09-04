//! P0 chain-authoring oracle: a reference chain over polkajam's hazmat
//! authoring harness, authoring blocks for the five emulated validators and
//! skipping the NUT's slots (validator index 0).

use std::{
    ops::Range,
    time::{SystemTime, UNIX_EPOCH},
};

use jam_node::hazmat::SecretKeysets;
use jam_std_common::{Block, SecretKeyset};
use jam_types::{FixedVec, HeaderHash};

/// Slot duration in seconds (tiny and full both use 6 s).
const SLOT_PERIOD_SEC: u64 = 6;

/// Errors raised by the reference-chain oracle.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    /// The hazmat authoring harness failed.
    #[error("harness error: {0}")]
    Harness(String),
    /// The underlying reference chain rejected an operation.
    #[error("chain error: {0}")]
    Chain(String),
    /// A block could not be imported into the reference chain.
    #[error("import error: {0}")]
    Import(String),
    /// A safrole ticket operation failed.
    #[error("tickets error: {0}")]
    Tickets(String),
}

/// Current wall-clock slot (`(now - JAM_COMMON_ERA) / 6`).
pub fn wall_clock_slot() -> u32 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    (now.saturating_sub(jam_types::JAM_COMMON_ERA) / SLOT_PERIOD_SEC) as u32
}

/// First slot of the current epoch.
///
/// polkajam gates ticket acceptance and authoring on the finalized block being
/// in the *current* epoch, which a genesis at slot 0 can never satisfy. See the
/// ignored `genesis_is_anchored_to_the_current_epoch` test in `m2-runner`.
pub fn current_epoch_start_slot() -> u32 {
    let now = wall_clock_slot();
    now - (now % jam_types::epoch_period())
}

/// Reference chain over the polkajam hazmat authoring harness.
///
/// Wraps a virtual-time `AuthoringHarness` that only claims slots whose author
/// key it holds. With the five emulated keysets (indices 1..=5) loaded, the
/// NUT's slots (author index 0) are skipped by the harness itself.
pub struct RefChain {
    harness: jam_node::hazmat::AuthoringHarness,
    genesis_hash: [u8; 32],
}

impl RefChain {
    /// Build the 6-validator tiny reference chain holding the emulated keysets.
    ///
    /// `emulated_keyset_indices` selects which trivial keysets the harness
    /// keystore holds (e.g. `1..6` holds validators 1..=5, excluding the NUT at
    /// index 0). The chain spec is the dev spec with the 6-validator tiny set.
    pub fn tiny(emulated_keyset_indices: Range<usize>) -> Result<Self, ChainError> {
        jam_types::ProtocolParameters::tiny().apply().map_err(|e| {
            ChainError::Chain(format!("failed to apply tiny protocol parameters: {e}"))
        })?;
        let chain_spec = jam_node::hazmat::default_dev_spec();
        let genesis_hash = chain_spec.genesis_header.hash();
        let validators = SecretKeysets(FixedVec::from_fn(|i| {
            SecretKeyset::trivial((emulated_keyset_indices.start + i) as u32)
        }));
        let harness = jam_node::hazmat::AuthoringHarness::new(
            chain_spec,
            validators,
            jam_node::hazmat::AuthoringHarnessConfig {
                drop_exports: false,
                // The compiler backend needs a userfaultfd Linux sandbox; the
                // interpreter runs without one.
                pvm_backend: Some(jam_node::PvmBackend::Interpreter),
            },
        );
        let mut this = Self {
            harness,
            genesis_hash: genesis_hash.0,
        };
        // The reference engine is virtual-time: seed it with the current slot.
        this.harness.next_slot = this.next_slot();
        Ok(this)
    }

    /// Hash of the genesis header.
    pub fn genesis_hash(&self) -> [u8; 32] {
        self.genesis_hash
    }

    /// The underlying hazmat authoring harness.
    ///
    /// `pub(crate)`: the tickets/guarantees/etc. oracles need harness access
    /// (storage, keystore) but the field stays private to this module.
    pub(crate) fn harness(&self) -> &jam_node::hazmat::AuthoringHarness {
        &self.harness
    }

    /// Current wall-clock slot (`(now - JAM_COMMON_ERA) / 6`).
    pub fn next_slot(&self) -> u32 {
        wall_clock_slot()
    }

    /// Advance virtual time to `slot` and author a block there if the slot
    /// belongs to an emulated validator; `None` when the author is the NUT.
    pub fn author_block(&mut self, slot: u32) -> Result<Option<Block>, ChainError> {
        let head_slot = self.harness.chain().best_block().1;
        if slot <= head_slot {
            return Err(ChainError::Chain(format!(
                "cannot author slot {slot}: reference chain head is at slot {head_slot}"
            )));
        }
        let maybe_hash = self
            .harness
            .author
            .author_block(slot)
            .map_err(|e| ChainError::Harness(e.to_string()))?;
        self.harness.next_slot = slot + 1;
        match maybe_hash {
            Some(hash) => {
                let block = self
                    .harness
                    .chain()
                    .block(&hash)
                    .map_err(|e| ChainError::Chain(e.to_string()))?
                    .ok_or_else(|| {
                        ChainError::Chain(format!("authored block {hash:?} not found"))
                    })?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    /// The reference chain (genesis + authored blocks) in order.
    pub fn chain_blocks(&self) -> Vec<Block> {
        let chain = self.harness.chain();
        let (head, _) = chain.best_block();
        let mut blocks = Vec::new();
        let mut hash = head;
        loop {
            let Some(block) = chain.block(&hash).ok().flatten() else {
                break;
            };
            let parent = block.header.parent;
            blocks.push(block);
            if parent == HeaderHash::zero() {
                break;
            }
            hash = parent;
        }
        blocks.reverse();
        blocks
    }

    /// State root for the block with the given hash.
    pub fn storage_root(&self, hash: &[u8; 32]) -> Option<[u8; 32]> {
        self.harness
            .chain()
            .state_root(&HeaderHash::from(*hash))
            .ok()?
            .map(|root| root.0)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn harness_builds_and_genesis_hash_stable() -> Result<(), ChainError> {
        let a = RefChain::tiny(1..6)?;
        let ga = a.genesis_hash();
        assert_eq!(ga.len(), 32);
        let b = RefChain::tiny(1..6)?;
        assert_eq!(ga, b.genesis_hash());
        Ok(())
    }

    #[test]
    fn next_slot_tracks_wall_clock() -> Result<(), ChainError> {
        let chain = RefChain::tiny(1..6)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the unix epoch")
            .as_secs();
        let expected = ((now - jam_types::JAM_COMMON_ERA) / SLOT_PERIOD_SEC) as u32;
        assert!(chain.next_slot().abs_diff(expected) <= 1);
        Ok(())
    }

    #[test]
    fn authors_emulated_slots_only() -> Result<(), ChainError> {
        let mut chain = RefChain::tiny(1..6)?;
        let start = chain.next_slot();
        let mut authored = Vec::new();
        for slot in start..start + 12 {
            if let Some(block) = chain.author_block(slot)? {
                assert_eq!(block.header.slot, slot);
                assert_ne!(
                    block.header.author_index, 0,
                    "slot {slot} is a NUT slot and must not be authored"
                );
                authored.push(block.header.hash().0);
            }
        }
        assert!(
            !authored.is_empty(),
            "expected at least one emulated slot within 12 consecutive slots"
        );
        // Genesis + one block per emulated slot, none authored by the NUT.
        let chain_blocks = chain.chain_blocks();
        assert_eq!(chain_blocks.len(), 1 + authored.len());
        assert!(chain_blocks.iter().all(|b| b.header.author_index != 0));
        let present: HashSet<[u8; 32]> = chain_blocks.iter().map(|b| b.header.hash().0).collect();
        assert!(authored.iter().all(|h| present.contains(h)));
        Ok(())
    }

    #[test]
    fn deterministic_for_fixed_seed() -> Result<(), ChainError> {
        let mut a = RefChain::tiny(1..6)?;
        let mut b = RefChain::tiny(1..6)?;
        let start = a.next_slot();
        let mut a_hashes = Vec::new();
        let mut b_hashes = Vec::new();
        for slot in start..start + 8 {
            if let Some(block) = a.author_block(slot)? {
                a_hashes.push(block.header.hash().0);
            }
        }
        for slot in start..start + 8 {
            if let Some(block) = b.author_block(slot)? {
                b_hashes.push(block.header.hash().0);
            }
        }
        assert_eq!(a_hashes, b_hashes);
        Ok(())
    }

    #[test]
    fn storage_root_matches_genesis() -> Result<(), ChainError> {
        let mut chain = RefChain::tiny(1..6)?;
        let genesis = chain.genesis_hash();
        let root = chain
            .storage_root(&genesis)
            .expect("genesis block has a state root in the chain");
        assert_eq!(root.len(), 32);
        // Cross-check against the first authored block: its parent is genesis, so its
        // `parent_state_root` is exactly the genesis state root recovered above.
        let start = chain.next_slot();
        let mut first_block = None;
        for slot in start..start + 12 {
            if let Some(block) = chain.author_block(slot)? {
                first_block = Some(block);
                break;
            }
        }
        let first_block = first_block.expect("an emulated slot appears within 12 slots");
        assert_eq!(first_block.header.parent.0, genesis);
        assert_eq!(first_block.header.parent_state_root.0, root);
        Ok(())
    }
}
