//! L1 state snapshot/diff oracle: dumps the reference chain's storage trie at
//! a block hash as a typed `State` and diffs two states key-by-key.

use std::collections::HashMap;

use jam_std_common::StorageKey;
use jam_types::HeaderHash;

use crate::chain::RefChain;

/// A single storage key-value pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyValue {
    pub key: [u8; 31],
    pub value: Vec<u8>,
}

/// Full storage snapshot (root hash + all key-value pairs) at a block hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub root: [u8; 32],
    pub keyvals: Vec<KeyValue>,
}

/// Difference of a single key between an expected and a received state.
///
/// A key missing on one side is represented by an empty `exp`/`got` slice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyValueDiff {
    pub key: [u8; 31],
    pub exp: Vec<u8>,
    pub got: Vec<u8>,
}

/// Difference between an expected and a received state: the two roots plus
/// the union of keys whose values differ.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateDiff {
    pub exp_root: [u8; 32],
    pub got_root: [u8; 32],
    pub keyvals: Vec<KeyValueDiff>,
}

impl RefChain {
    /// Snapshot the full storage state at the given block hash.
    pub fn storage_state(&self, hash: &[u8; 32]) -> Option<State> {
        let chain = self.harness().chain();
        let hash = HeaderHash::from(*hash);
        let storage = chain.storage(&hash)?;
        let root = chain.state_root(&hash).ok()??;
        let keyvals = storage
            .keys()
            .filter_map(|key| {
                storage
                    .get(StorageKey(key))
                    .map(|value| KeyValue { key, value })
            })
            .collect();
        Some(State {
            root: root.0,
            keyvals,
        })
    }
}

/// Diff two states: compare roots and report every key whose value differs
/// across the union of keys (missing side = empty).
pub fn diff(exp: &State, got: &State) -> StateDiff {
    let exp_vals: HashMap<[u8; 31], &[u8]> = exp
        .keyvals
        .iter()
        .map(|kv| (kv.key, kv.value.as_slice()))
        .collect();
    let got_vals: HashMap<[u8; 31], &[u8]> = got
        .keyvals
        .iter()
        .map(|kv| (kv.key, kv.value.as_slice()))
        .collect();
    let mut keys: Vec<[u8; 31]> = exp_vals.keys().chain(got_vals.keys()).copied().collect();
    keys.sort_unstable();
    keys.dedup();
    let keyvals = keys
        .into_iter()
        .filter_map(|key| {
            let exp_val = exp_vals.get(&key).copied().unwrap_or(&[]);
            let got_val = got_vals.get(&key).copied().unwrap_or(&[]);
            (exp_val != got_val).then(|| KeyValueDiff {
                key,
                exp: exp_val.to_vec(),
                got: got_val.to_vec(),
            })
        })
        .collect();
    StateDiff {
        exp_root: exp.root,
        got_root: got.root,
        keyvals,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::ChainError;

    #[test]
    fn state_snapshot_root_matches_storage_root() -> Result<(), ChainError> {
        let chain = RefChain::tiny(0)?;
        let start = chain.next_slot();
        let mut authored = 0;
        for slot in start..start + 24 {
            if chain.author_block(slot)?.is_some() {
                authored += 1;
                if authored == 2 {
                    break;
                }
            }
        }
        assert_eq!(authored, 2, "expected two emulated slots within 24 slots");

        let genesis = chain.genesis_hash();
        let genesis_state = chain.storage_state(&genesis).expect("genesis has state");
        assert_eq!(
            genesis_state.root,
            chain.storage_root(&genesis).expect("genesis root")
        );
        assert!(
            !genesis_state.keyvals.is_empty(),
            "genesis state has key-value pairs"
        );

        let best = chain
            .chain_blocks()
            .last()
            .expect("authored head block")
            .header
            .hash()
            .0;
        let best_state = chain.storage_state(&best).expect("head has state");
        assert_eq!(
            best_state.root,
            chain.storage_root(&best).expect("head root")
        );
        assert!(
            !best_state.keyvals.is_empty(),
            "head state has key-value pairs"
        );
        Ok(())
    }

    #[test]
    fn state_diff_reports_root_and_key_mismatch() -> Result<(), ChainError> {
        let chain = RefChain::tiny(0)?;
        let start = chain.next_slot();
        for slot in start..start + 24 {
            if chain.author_block(slot)?.is_some() {
                break;
            }
        }
        let best = chain
            .chain_blocks()
            .last()
            .expect("authored head block")
            .header
            .hash()
            .0;
        let state_a = chain.storage_state(&best).expect("head has state");
        let state_b = chain.storage_state(&best).expect("head has state");

        let equal = diff(&state_a, &state_b);
        assert_eq!(equal.exp_root, equal.got_root);
        assert!(
            equal.keyvals.is_empty(),
            "identical snapshots have no key diffs"
        );

        let mut corrupt = state_b.clone();
        assert!(
            !corrupt.keyvals.is_empty(),
            "snapshot has key-value pairs to corrupt"
        );
        let victim = corrupt.keyvals[0].key;
        let got_value = vec![corrupt.keyvals[0].value[0] ^ 0xff];
        corrupt.keyvals[0].value = got_value.clone();
        let unequal = diff(&state_a, &corrupt);
        assert_eq!(
            unequal.exp_root, unequal.got_root,
            "manual keyval edit leaves roots equal"
        );
        assert_eq!(unequal.keyvals.len(), 1, "exactly one key differs");
        assert_eq!(unequal.keyvals[0].key, victim);
        assert_eq!(unequal.keyvals[0].got, got_value);
        Ok(())
    }
}
