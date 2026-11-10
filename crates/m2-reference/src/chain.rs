//! P0 chain-authoring oracle: a reference chain over polkajam's hazmat
//! authoring harness, authoring blocks for every emulated validator and
//! skipping the NUT's slots.

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
///
/// "Now" is the installed clock's, not the machine's: the slot a run is in has
/// to be the same number the trace's timestamps say, or the lanes would grade
/// frames against a calendar nothing else is keeping.
pub fn wall_clock_slot() -> u32 {
    let now = jamnp_s::clock::current().wall_ms() / 1000;
    (now.saturating_sub(jam_types::JAM_COMMON_ERA) / SLOT_PERIOD_SEC) as u32
}

/// The millisecond `slot` begins, on the same calendar as [`wall_clock_slot`].
pub fn slot_start_ms(slot: u32) -> u64 {
    (jam_types::JAM_COMMON_ERA + u64::from(slot) * SLOT_PERIOD_SEC) * 1000
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

/// The keyset handed to the NUT's slot in the harness keystore.
///
/// The keystore is a fixed-length vector with one slot per validator, so the
/// NUT's slot cannot simply be left out. `trivial(u32::MAX)` is a well-formed
/// keyset that belongs to no genesis validator, so the harness never matches it
/// against an author index and never claims a slot with it.
const NON_VALIDATOR_KEYSET: u32 = u32::MAX;

/// Reference chain over the polkajam hazmat authoring harness.
///
/// Wraps a virtual-time `AuthoringHarness` that only claims slots whose author
/// key it holds. With every keyset but the NUT's loaded, the NUT's slots are
/// skipped by the harness itself and every other slot is authored.
pub struct RefChain {
    /// Behind a mutex so the chain can be authored while it is shared.
    ///
    /// The emulator serves CE 128/129 from an `Arc<RefChain>` on several tasks
    /// at once, and the slot driver authors into the same chain. Keeping the
    /// mutex *inside* means every lock is held for a short synchronous section;
    /// an `Arc<Mutex<RefChain>>` at the call sites would instead put a guard
    /// into the emulator's async serve paths, where holding one across an
    /// `.await` is a deadlock and `Send` hazard.
    harness: std::sync::Mutex<jam_node::hazmat::AuthoringHarness>,
    genesis_slot: u32,
    genesis_hash: [u8; 32],
}

impl RefChain {
    /// Build the 6-validator tiny reference chain emulating every validator
    /// except `nut_index`.
    ///
    /// Validator `i` holds `SecretKeyset::trivial(i)` (`keygen::generate`), so
    /// the harness keystore takes those keysets for every index but the NUT's,
    /// whose slot gets [`NON_VALIDATOR_KEYSET`]. The chain spec is the dev spec
    /// with the 6-validator tiny set, genesis at slot 0.
    ///
    /// A live run uses [`RefChain::with_spec`] instead, so the reference engine
    /// and the node under test start from one and the same genesis.
    pub fn tiny(nut_index: usize) -> Result<Self, ChainError> {
        // Before `default_dev_spec`, not after: it sizes the validator set from
        // the process-wide protocol parameters, so building it under the `full`
        // default would try to fit 1023 validators into the tiny bound of 6.
        jam_types::ProtocolParameters::tiny().apply().map_err(|e| {
            ChainError::Chain(format!("failed to apply tiny protocol parameters: {e}"))
        })?;
        Self::with_spec(nut_index, jam_node::hazmat::default_dev_spec())
    }

    /// Build the reference chain on a caller-supplied chain spec.
    ///
    /// The node under test is started from a spec the runner builds, carrying
    /// the real validator addresses and, for a live run, a genesis anchored to
    /// the current epoch. The reference engine has to start from that same
    /// spec: the anchor slot is part of the genesis header preimage, so a
    /// reference chain left on the slot-0 dev spec would disagree with the node
    /// about the genesis hash, and every UP 0 handshake would mismatch.
    pub fn with_spec(
        nut_index: usize,
        chain_spec: jam_node::ChainSpec,
    ) -> Result<Self, ChainError> {
        Self::with_keysets(chain_spec, |i| i != nut_index, nut_index)
    }

    /// A chain holding **only** validator `index`'s keys: what a node holds,
    /// rather than what the harness holds.
    ///
    /// The difference is not cosmetic. An authoring harness runs the Safrole
    /// lottery for every key in its keystore and puts the results in the
    /// blocks it authors, so a chain built the other way round -- every key
    /// but one -- authors blocks carrying five validators' tickets. A node
    /// simulated on such a chain looks, to the lane grading it, like one
    /// inventing tickets nobody sent it.
    pub fn tiny_for(index: usize) -> Result<Self, ChainError> {
        jam_types::ProtocolParameters::tiny().apply().map_err(|e| {
            ChainError::Chain(format!("failed to apply tiny protocol parameters: {e}"))
        })?;
        Self::with_keysets(jam_node::hazmat::default_dev_spec(), |i| i == index, index)
    }

    /// Build the chain, taking the real keyset for every index `holds`
    /// accepts and [`NON_VALIDATOR_KEYSET`] for the rest.
    fn with_keysets(
        chain_spec: jam_node::ChainSpec,
        holds: impl Fn(usize) -> bool,
        named_index: usize,
    ) -> Result<Self, ChainError> {
        jam_types::ProtocolParameters::tiny().apply().map_err(|e| {
            ChainError::Chain(format!("failed to apply tiny protocol parameters: {e}"))
        })?;
        let validator_count = jam_types::max_val_count() as usize;
        if named_index >= validator_count {
            return Err(ChainError::Chain(format!(
                "validator index {named_index} is outside the {validator_count}-validator set"
            )));
        }
        let genesis_hash = chain_spec.genesis_header.hash();
        let genesis_slot = chain_spec.genesis_header.slot;
        let validators = SecretKeysets(FixedVec::from_fn(|i| {
            if holds(i) {
                SecretKeyset::trivial(i as u32)
            } else {
                SecretKeyset::trivial(NON_VALIDATOR_KEYSET)
            }
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
        let this = Self {
            harness: std::sync::Mutex::new(harness),
            genesis_slot,
            genesis_hash: genesis_hash.0,
        };
        // The reference engine is virtual-time: seed it with the current slot.
        let next = this.next_slot();
        this.harness().next_slot = next;
        Ok(this)
    }

    /// Hash of the genesis header.
    pub fn genesis_hash(&self) -> [u8; 32] {
        self.genesis_hash
    }

    /// Slot the chain's genesis is anchored to (A9), which is where authoring
    /// starts rather than slot 0.
    pub fn genesis_slot(&self) -> u32 {
        self.genesis_slot
    }

    /// The underlying hazmat authoring harness.
    ///
    /// `pub(crate)`: the tickets/guarantees/etc. oracles need harness access
    /// (storage, keystore) but the field stays private to this module.
    pub(crate) fn harness(&self) -> std::sync::MutexGuard<'_, jam_node::hazmat::AuthoringHarness> {
        self.harness
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Current wall-clock slot (`(now - JAM_COMMON_ERA) / 6`).
    pub fn next_slot(&self) -> u32 {
        wall_clock_slot()
    }

    /// Slot of the chain's current best block.
    ///
    /// The slot driver needs it because the chain head no longer moves only
    /// when the driver authors: a NUT block adopted into the chain can put the
    /// head at a slot the driver is about to try, and [`RefChain::author_block`]
    /// refuses to author at or behind the head.
    pub fn best_slot(&self) -> u32 {
        self.harness().chain().best_block().1
    }

    /// Advance virtual time to `slot` and author a block there if the slot
    /// belongs to an emulated validator; `None` when the author is the NUT.
    pub fn author_block(&self, slot: u32) -> Result<Option<Block>, ChainError> {
        let mut harness = self.harness();
        let head_slot = harness.chain().best_block().1;
        if slot <= head_slot {
            return Err(ChainError::Chain(format!(
                "cannot author slot {slot}: reference chain head is at slot {head_slot}"
            )));
        }
        let maybe_hash = harness
            .author
            .author_block(slot)
            .map_err(|e| ChainError::Harness(e.to_string()))?;
        harness.next_slot = slot + 1;
        match maybe_hash {
            Some(hash) => {
                let block = harness
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
        let harness = self.harness();
        let chain = harness.chain();
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
        self.harness()
            .chain()
            .state_root(&HeaderHash::from(*hash))
            .ok()?
            .map(|root| root.0)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use std::collections::HashSet;

    use super::*;

    #[test]
    fn harness_builds_and_genesis_hash_stable() -> Result<(), ChainError> {
        let a = RefChain::tiny(0)?;
        let ga = a.genesis_hash();
        assert_eq!(ga.len(), 32);
        let b = RefChain::tiny(0)?;
        assert_eq!(ga, b.genesis_hash());
        Ok(())
    }

    #[test]
    fn next_slot_tracks_wall_clock() -> Result<(), ChainError> {
        let chain = RefChain::tiny(0)?;
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
        let chain = RefChain::tiny(0)?;
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

    /// Defect 2: the harness must never author in the NUT's slots, wherever the
    /// NUT sits in the keyset. The keystore used to be built from a contiguous
    /// range starting at `0` for every NUT index but `0`, so it held the NUT's
    /// own keyset and the reference chain competed with the node under test --
    /// including at the default index 5.
    #[test]
    fn no_nut_index_is_authored_at_any_position() -> Result<(), ChainError> {
        let validator_count = {
            jam_types::ProtocolParameters::tiny()
                .apply()
                .expect("tiny parameters are valid");
            jam_types::max_val_count() as usize
        };
        assert_eq!(validator_count, 6, "the tiny keyset is six validators");

        for nut_index in 0..validator_count {
            let chain = RefChain::tiny(nut_index)?;
            let start = chain.next_slot();
            let mut authored = 0;
            for slot in start..start + 12 {
                if let Some(block) = chain.author_block(slot)? {
                    assert_ne!(
                        block.header.author_index as usize, nut_index,
                        "slot {slot} belongs to the NUT at index {nut_index} \
                         and must not be authored by the harness"
                    );
                    authored += 1;
                }
            }
            assert!(
                authored > 0,
                "NUT index {nut_index}: the harness authored nothing in 12 slots, \
                 so the assertion above proved nothing"
            );
        }
        Ok(())
    }

    #[test]
    fn nut_index_outside_the_keyset_is_rejected() {
        jam_types::ProtocolParameters::tiny()
            .apply()
            .expect("tiny parameters are valid");
        let count = jam_types::max_val_count() as usize;
        assert!(
            RefChain::tiny(count).is_err(),
            "a NUT index of {count} is outside the keyset and would leave every \
             validator keyset loaded"
        );
    }

    #[test]
    fn deterministic_for_fixed_seed() -> Result<(), ChainError> {
        let a = RefChain::tiny(0)?;
        let b = RefChain::tiny(0)?;
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
        let chain = RefChain::tiny(0)?;
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
