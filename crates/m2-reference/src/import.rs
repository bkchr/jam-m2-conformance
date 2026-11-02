//! N1 block-import oracle: imports a NUT-authored block into the reference
//! chain with fresh execution and reports the outcome (post-state root or
//! the rejected-import error message).

use jam_node::hazmat::ImportBlockParams;
use jam_std_common::Block;
use jam_types::HeaderHash;

use crate::chain::RefChain;

/// Outcome of importing a NUT block into the reference chain.
///
/// Carries both state roots the N1 lane needs, which are different quantities
/// and neither of which is the header hash: `declared_parent_root` is what the
/// block's header claims its parent's posterior root was, and
/// `reference_parent_root` is what the reference engine computed for that same
/// parent. `root` is the reference's posterior root for *this* block, which
/// only a block built on top of it can be checked against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportOutcome {
    /// Hash of the imported block's header.
    pub header_root: [u8; 32],
    /// Hash of the block's parent (`header.parent`).
    pub parent: [u8; 32],
    /// Prior state root the block's header declares (`header.parent_state_root`).
    pub declared_parent_root: [u8; 32],
    /// The reference engine's own posterior state root for the parent, when it
    /// knows the parent at all.
    pub reference_parent_root: Option<[u8; 32]>,
    /// `true` when the block was accepted (imported or already imported).
    pub ok: bool,
    /// Posterior state root of the block when accepted.
    pub root: Option<[u8; 32]>,
    /// Human-readable rejection reason when the block was refused.
    pub error: Option<String>,
}

impl RefChain {
    /// Import a NUT-authored block into the reference chain by fresh execution.
    ///
    /// On success the block joins the reference chain, and because polkajam
    /// picks its best block by highest slot it also becomes the head the
    /// reference authors on next. That is deliberate: a reference that keeps
    /// authoring on its own head instead forks away from the node at every
    /// slot the node claims, and then nothing ever builds on a NUT block, so
    /// no block's posterior state root is ever witnessed.
    pub fn import_nut_block(&self, block: &Block) -> ImportOutcome {
        let chain = self.harness().chain();
        let header_root = block.header.hash().0;
        let hash = HeaderHash::from(header_root);
        let parent = block.header.parent;
        let outcome = |ok, root, error| ImportOutcome {
            header_root,
            parent: parent.0,
            declared_parent_root: block.header.parent_state_root.0,
            reference_parent_root: chain.state_root(&parent).ok().flatten().map(|r| r.0),
            ok,
            root,
            error,
        };
        match chain.import_block(block.clone(), ImportBlockParams::new_exec(hash)) {
            Ok(_) => {
                let root = chain.state_root(&hash).ok().flatten().map(|r| r.0);
                outcome(true, root, None)
            }
            Err(e) => outcome(false, None, Some(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use jam_std_common::{bandersnatch::ring_vrf, Extrinsic, TicketEnvelope};

    use super::*;
    use crate::chain::ChainError;

    const RING_SIGNATURE_SIZE: usize = 784;

    fn authored_head(chain: &mut RefChain) -> Result<Block, ChainError> {
        let start = chain.next_slot();
        for slot in start..start + 24 {
            if let Some(block) = chain.author_block(slot)? {
                return Ok(block);
            }
        }
        panic!("no emulated slot within 24 slots")
    }

    #[test]
    fn import_nut_block_ok_for_chain_head() -> Result<(), ChainError> {
        let chain = RefChain::tiny(0)?;
        let start = chain.next_slot();
        let mut authored = Vec::new();
        for slot in start..start + 60 {
            if let Some(block) = chain.author_block(slot)? {
                authored.push(block);
            }
        }
        let pair = authored
            .windows(2)
            .find(|w| w[1].header.slot > w[0].header.slot + 1)
            .expect("a NUT (un-authored) slot appears within 60 slots");
        let block = pair[1].clone();
        let hash = block.header.hash().0;

        let outcome = chain.import_nut_block(&block);
        assert!(
            outcome.ok,
            "re-import of an authored head succeeds: {:?}",
            outcome.error
        );
        assert!(outcome.error.is_none());
        assert_eq!(outcome.header_root, hash);
        let expected = chain.storage_root(&hash).expect("head has a state root");
        assert_eq!(outcome.root, Some(expected));
        Ok(())
    }

    #[test]
    fn import_nut_block_rejects_bad_extrinsic() -> Result<(), ChainError> {
        let chain = RefChain::tiny(0)?;
        let start = chain.next_slot();
        // Author WITHOUT importing (author_block_no_import): a block produced by
        // author_block is already in the chain, and re-importing a known hash
        // short-circuits to AlreadyImported before any verification runs.
        let mut authored = None;
        for slot in start..start + 24 {
            if let Ok(Some(result)) = chain.harness().author_block_no_import(slot, None) {
                authored = Some(result.block);
                break;
            }
        }
        let mut corrupt = authored.expect("an emulated slot appears within 24 slots");
        // Replace the extrinsic with a garbage ticket so the body no longer matches
        // the header's extrinsic hash.
        let mut bogus = Extrinsic::default();
        bogus
            .tickets
            .try_push(TicketEnvelope {
                attempt: 0,
                signature: ring_vrf::Signature([0xab; RING_SIGNATURE_SIZE]),
            })
            .expect("tiny spec allows 3 tickets per block");
        corrupt.extrinsic = Arc::new(bogus);

        let outcome = chain.import_nut_block(&corrupt);
        assert!(
            !outcome.ok,
            "a corrupt extrinsic must be rejected: {:?}",
            outcome.error
        );
        assert!(
            outcome.error.is_some(),
            "rejection carries an error message"
        );
        assert!(outcome.root.is_none());
        Ok(())
    }

    #[test]
    fn import_nut_block_rejects_obsolete() -> Result<(), ChainError> {
        let mut chain = RefChain::tiny(0)?;
        let block = authored_head(&mut chain)?;

        let first = chain.import_nut_block(&block);
        assert!(first.ok, "first import succeeds: {:?}", first.error);

        // polkajam returns AlreadyImported for a known block, surfacing as ok=true.
        let second = chain.import_nut_block(&block);
        assert!(
            second.ok,
            "re-import of a known block is accepted: {:?}",
            second.error
        );
        assert!(second.error.is_none());
        assert_eq!(second.header_root, first.header_root);
        assert_eq!(second.root, first.root);
        Ok(())
    }

    /// The two roots the N1 state-root check compares are the header's
    /// declared prior root and the reference's own root for the same parent —
    /// never the header hash, which is a different quantity entirely and can
    /// only ever differ.
    #[test]
    fn import_reports_prior_and_posterior_roots_separately() -> Result<(), ChainError> {
        let mut chain = RefChain::tiny(0)?;
        let block = authored_head(&mut chain)?;
        let outcome = chain.import_nut_block(&block);

        assert!(outcome.ok, "import succeeds: {:?}", outcome.error);
        assert_eq!(outcome.parent, block.header.parent.0);
        assert_eq!(
            outcome.reference_parent_root,
            Some(outcome.declared_parent_root),
            "a well-formed block's declared prior root is the reference's own"
        );
        assert_ne!(
            outcome.root,
            Some(outcome.header_root),
            "the posterior state root is not the header hash"
        );
        Ok(())
    }
}
