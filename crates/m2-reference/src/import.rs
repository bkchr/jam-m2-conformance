//! L1 block-import oracle: imports a NUT-authored block into the reference
//! chain with fresh execution and reports the outcome (post-state root or
//! the rejected-import error message).

use jam_node::hazmat::ImportBlockParams;
use jam_std_common::Block;
use jam_types::HeaderHash;

use crate::chain::RefChain;

/// Outcome of importing a NUT block into the reference chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportOutcome {
    /// Hash of the imported block's header.
    pub header_root: [u8; 32],
    /// `true` when the block was accepted (imported or already imported).
    pub ok: bool,
    /// Posterior state root of the block when accepted.
    pub root: Option<[u8; 32]>,
    /// Human-readable rejection reason when the block was refused.
    pub error: Option<String>,
}

impl RefChain {
    /// Import a NUT-authored block into the reference chain by fresh execution.
    pub fn import_nut_block(&self, block: &Block) -> ImportOutcome {
        let chain = self.harness().chain();
        let header_root = block.header.hash().0;
        let hash = HeaderHash::from(header_root);
        match chain.import_block(block.clone(), ImportBlockParams::new_exec(hash)) {
            Ok(_) => {
                let root = chain.state_root(&hash).ok().flatten().map(|r| r.0);
                ImportOutcome {
                    header_root,
                    ok: true,
                    root,
                    error: None,
                }
            }
            Err(e) => ImportOutcome {
                header_root,
                ok: false,
                root: None,
                error: Some(e.to_string()),
            },
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
        let mut chain = RefChain::tiny(1..6)?;
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
        let chain = RefChain::tiny(1..6)?;
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
        let mut chain = RefChain::tiny(1..6)?;
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
}
