//! Tiny-spec genesis + spec-file generation for the NUT (DESIGN.md §7).
//!
//! Produces two spec artefacts from one 6-validator tiny `ChainSpec`:
//! - the M2-standard JSON (`spec-m2.json`, `M2Spec`) that the NUT reads, and
//! - polkajam's own spec JSON (`spec.json`, via `ChainSpec::to_file`) that the
//!   reference engine loads.
//!
//! The genesis header is `Header::genesis_with_epoch(epoch0_mark(...))`: slot 0,
//! and its hash is a function of the validators' bandersnatch/ed25519 keys only
//! (`EpochKeySet`), so overriding the on-chain `PeerAddr` metadata never changes
//! the genesis hash — the NUT and the reference agree on genesis.

use std::path::Path;

use codec::{DecodeAll, Encode};
use jam_node::ChainSpec;
use jam_std_common::{StorageKey, SystemKey, ValKeysets};
use jam_types::BoundedFromFn;
use serde::Serialize;

/// Errors raised while building or writing chain specs.
#[derive(Debug, thiserror::Error)]
pub enum SpecError {
    /// Protocol parameters could not be applied.
    #[error("failed to apply protocol parameters: {0}")]
    Parameters(&'static str),
    /// The validator ip/port lists must both hold exactly 6 entries.
    #[error("expected 6 validator ip/port pairs, got {ips} ips and {ports} ports")]
    ValidatorCount { ips: usize, ports: usize },
    /// Genesis storage could not be built.
    #[error("failed to build genesis storage: {0}")]
    Storage(String),
    /// Underlying I/O failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Builds the 6-validator tiny `ChainSpec`: genesis state carries the validator
/// metadata `(ip, port)` pairs (PeerAddr IPv6 + LE port, DESIGN.md §7) and the
/// genesis header is anchored to `anchor_slot`.
///
/// `JAM_COMMON_ERA` is a fixed point in the past, so a genesis left at slot 0
/// starts the chain hundreds of thousands of epochs behind the wall clock. Its
/// finalized block never leaves genesis, and polkajam's ticket lottery refuses
/// to run until the finalized block's epoch catches up with the current one, so
/// no validator ever submits a ticket. Pass
/// `m2_reference::chain::current_epoch_start_slot()` to start in the present,
/// or 0 for the unanchored genesis the tests pin values against.
pub fn tiny_spec(
    validator_ips: &[[u8; 16]],
    ports: &[u16],
    anchor_slot: jam_types::Slot,
) -> Result<ChainSpec, SpecError> {
    if validator_ips.len() != 6 || ports.len() != 6 {
        return Err(SpecError::ValidatorCount {
            ips: validator_ips.len(),
            ports: ports.len(),
        });
    }
    jam_types::ProtocolParameters::tiny()
        .apply()
        .map_err(SpecError::Parameters)?;

    // Reference dev spec: 6 trivial keysets + bootstrap service. Its genesis
    // header hash depends only on bandersnatch/ed25519 keys (EpochKeySet), so
    // overriding the on-chain PeerAddr metadata leaves the hash untouched.
    let base = jam_node::hazmat::dev_spec(jam_node::DEFAULT_DEV_BASE_PORT);
    let mut state = base.build_storage().map_err(SpecError::Storage)?;
    let ChainSpec {
        mut genesis_header,
        bootnodes,
        ..
    } = base;

    // The slot *is* part of the header preimage, so anchoring moves the genesis
    // hash. Take the new hash before patching the state: the one block in the
    // recent-blocks history has to carry it.
    genesis_header.slot = anchor_slot;
    let genesis_hash = genesis_header.hash();

    // Rebuild the validator keysets with the requested metadata and patch the
    // three system keys that each carry a full `ValKeysets` copy.
    let validators = ValKeysets::from_fn_fill(|i| {
        let metadata = crate::keygen::metadata_for(i, validator_ips[i], ports[i]);
        jam_std_common::SecretKeyset::trivial(i as u32).public(metadata)
    });
    let encoded = validators.encode();
    let keys = [
        StorageKey::from(SystemKey::Validators).0,
        StorageKey::from(SystemKey::Designates).0,
        StorageKey::from(SystemKey::PrevValidators).0,
    ];
    // The Safrole state carries a *fourth* copy of the keyset (gamma_k, the
    // next-epoch validators). polkajam resolves upcoming-epoch peer addresses
    // from it, so leaving it unpatched makes the node dial the dev-spec
    // addresses instead of ours and never connect to any emulated validator.
    let safrole_key = StorageKey::from(SystemKey::Safrole).0;
    // `dev_spec` writes both of these for slot 0 (`TheState::genesis`), so
    // anchoring means rewriting them: the state's current time, and the single
    // recent block, which is genesis itself.
    let now_key = StorageKey::from(SystemKey::CurrentTime).0;
    let recent_key = StorageKey::from(SystemKey::RecentBlocks).0;
    for (k, v) in state.iter_mut() {
        if keys.contains(k) {
            *v = Some(encoded.clone());
        } else if *k == safrole_key {
            let Some(bytes) = v.as_ref() else { continue };
            let mut safrole = jam_std_common::SafroleState::decode_all(&mut bytes.as_slice())
                .map_err(|e| SpecError::Storage(format!("decode safrole state: {e}")))?;
            safrole.waiting_validators = validators.clone();
            *v = Some(safrole.encode());
        } else if *k == now_key {
            *v = Some(anchor_slot.encode());
        } else if *k == recent_key {
            let Some(bytes) = v.as_ref() else { continue };
            let mut recent = jam_std_common::RecentBlocks::decode_all(&mut bytes.as_slice())
                .map_err(|e| SpecError::Storage(format!("decode recent blocks: {e}")))?;
            // `BoundedVec` hands out no mutable element access, so rebuild the
            // one-entry history rather than editing it in place.
            let mut genesis_block = recent
                .history
                .first()
                .cloned()
                .ok_or_else(|| SpecError::Storage("genesis has no recent block".into()))?;
            genesis_block.slot = anchor_slot;
            genesis_block.hash = genesis_hash;
            recent.history = jam_types::BoundedVec::try_from(vec![genesis_block])
                .map_err(|_| SpecError::Storage("recent block count is zero".into()))?;
            *v = Some(recent.encode());
        }
    }

    let storage_builder =
        jam_node::hazmat::StorageBuilder::RawFactory(Box::new(move || Ok(state.clone())));
    Ok(ChainSpec {
        storage_builder,
        genesis_header,
        bootnodes,
    })
}

/// The §7 M2-standard spec JSON shape read by the node under test.
#[derive(Debug, Serialize)]
pub struct M2Spec {
    /// Chain id (`m2-<seed>`).
    pub id: String,
    /// Named tiny protocol parameters.
    pub parameters: serde_json::Value,
    /// Hex-SCALE of the genesis header.
    pub genesis_header: String,
    /// Genesis state: 31-byte trie key → hex value.
    pub genesis_state: serde_json::Value,
    /// Bootnodes (empty: validators locate each other via on-chain metadata).
    pub bootnodes: Vec<String>,
}

/// Builds an `M2Spec` from a tiny `ChainSpec`.
pub fn m2_spec(id: &str, chain_spec: &ChainSpec) -> Result<M2Spec, SpecError> {
    let genesis_header = format!("0x{}", hex::encode(chain_spec.genesis_header.encode()));
    let state = chain_spec.build_storage().map_err(SpecError::Storage)?;
    let mut genesis_state = serde_json::Map::new();
    for (k, v) in state.iter() {
        if let Some(v) = v {
            genesis_state.insert(
                format!("0x{}", hex::encode(k.as_ref())),
                serde_json::Value::String(format!("0x{}", hex::encode(v))),
            );
        }
    }
    Ok(M2Spec {
        id: id.to_string(),
        parameters: named_parameters(),
        genesis_header,
        genesis_state: serde_json::Value::Object(genesis_state),
        bootnodes: Vec::new(),
    })
}

/// The §7 named parameters, read from the protocol parameters this run is
/// operating under rather than written out as literals.
///
/// They were literals, and one of them disagreed with the run around it:
/// `tickets_per_validator` said 3 while the harness, the reference engine and
/// the node under test all used 4. The spec file is the environment contract,
/// so a third-party node configured from it would have made three ticket
/// attempts an epoch and been graded against four — and the fourth attempt of
/// every emulated author, which the harness does send, would have looked to it
/// like a ticket over the cap.
///
/// Deriving them closes the only way the contract and the behaviour can
/// disagree, for the same reason `prepare-nut.sh` reads its revision from
/// `Cargo.toml` rather than carrying a copy.
///
/// `tiny_spec` applies [`jam_types::ProtocolParameters::tiny`], and those
/// parameters are process-wide, so every caller that reaches here through it
/// reads the tiny set.
fn named_parameters() -> serde_json::Value {
    serde_json::json!({
        "validators": jam_types::max_val_count(),
        "cores": jam_types::core_count(),
        "epoch_length": jam_types::epoch_period(),
        "ticket_submission_end": jam_types::epoch_tail_start(),
        "tickets_per_validator": attempts_per_validator(),
        "rotation_period": jam_types::rotation_period(),
        "max_lookup_anchor_age": jam_types::max_lookup_anchor_age(),
        "min_turnaround_period": jam_types::min_turnaround_period(),
        "slot_period_sec": jam_types::slot_period_sec(),
    })
}

/// Ticket attempts one validator may make per epoch — 4 under tiny.
///
/// Not a declared parameter but a quantity derived from two that are,
/// `(2 × epoch_period) ÷ val_count` rounded up, which the node applies as the
/// cap at all three points it matters: generation, the CE 131 attempt check,
/// and the Safrole state transition.
///
/// It was a declared `tickets_attempts_number` of 3 until GP 0.8.0 replaced it
/// with this derivation (polkajam `7b7993c8`, #1024). The pin is after that
/// change and so is upstream, so 4 is the live figure; DESIGN §2's `N = 3` is
/// the pre-0.8.0 one. Worth re-reading on a re-pin all the same, because it is
/// the number a parameter rework would move most quietly —
/// `m2_spec_parameters_match_the_engine` is what fails if it does. See
/// DESIGN §10.
fn attempts_per_validator() -> jam_types::TicketAttempt {
    jam_types::tickets_per_validator(jam_types::max_val_count())
}

/// Writes `dir/spec-m2.json` and returns its path. The id is taken from `spec`.
pub fn write_m2_spec(dir: &Path, _id: &str, spec: &M2Spec) -> std::io::Result<std::path::PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join("spec-m2.json");
    let json = serde_json::to_string_pretty(spec).map_err(std::io::Error::other)?;
    std::fs::write(&path, json)?;
    Ok(path)
}

/// Writes polkajam's own spec JSON (`dir/spec.json`) via `ChainSpec::to_file`.
pub fn write_polkajam_spec(
    dir: &Path,
    chain_spec: &ChainSpec,
) -> std::io::Result<std::path::PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join("spec.json");
    chain_spec
        .to_file("m2", &path)
        .map_err(std::io::Error::other)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use codec::{Decode, DecodeAll};
    use jam_std_common::Header;

    use super::{m2_spec, tiny_spec, write_m2_spec, write_polkajam_spec};

    /// IPv4-mapped loopback (`::ffff:127.0.0.1`) per validator, as in DESIGN.md §7.
    fn loopback_ips() -> [[u8; 16]; 6] {
        let mut ips = [[0u8; 16]; 6];
        for ip in ips.iter_mut() {
            ip[10] = 0xff;
            ip[11] = 0xff;
            ip[12] = 127;
            ip[15] = 1;
        }
        ips
    }

    fn ports() -> [u16; 6] {
        [40000, 40001, 40002, 40003, 40004, 40005]
    }

    /// Unique per-test temp dir, removed by `cleanup`.
    fn temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("m2-spec-{tag}-{}", std::process::id()))
    }

    fn cleanup(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The named parameters the node is handed are the ones the run uses.
    ///
    /// Both halves matter and they fail differently. Against `jam_types`: a
    /// parameter that drifts from the engine makes the contract a lie, which
    /// is what `tickets_per_validator: 3` was while everything around it used
    /// 4. Against the literals: those are tiny as this revision defines it, so
    /// a re-pin that moves one says so here rather than in a live run — see
    /// `attempts_per_validator`, the one most likely to move.
    #[test]
    fn m2_spec_parameters_match_the_engine() {
        let chain_spec = tiny_spec(&loopback_ips(), &ports(), 0).expect("tiny spec builds");
        let spec = m2_spec("m2-test", &chain_spec).expect("m2 spec builds");
        let param = |name: &str| {
            spec.parameters[name]
                .as_u64()
                .unwrap_or_else(|| panic!("{name} is a number"))
        };

        assert_eq!(param("validators"), u64::from(jam_types::max_val_count()));
        assert_eq!(param("cores"), u64::from(jam_types::core_count()));
        assert_eq!(param("epoch_length"), u64::from(jam_types::epoch_period()));
        assert_eq!(
            param("ticket_submission_end"),
            u64::from(jam_types::epoch_tail_start())
        );
        assert_eq!(
            param("tickets_per_validator"),
            u64::from(super::attempts_per_validator())
        );
        assert_eq!(
            param("rotation_period"),
            u64::from(jam_types::rotation_period())
        );
        assert_eq!(
            param("max_lookup_anchor_age"),
            u64::from(jam_types::max_lookup_anchor_age())
        );
        assert_eq!(
            param("min_turnaround_period"),
            u64::from(jam_types::min_turnaround_period())
        );
        assert_eq!(param("slot_period_sec"), jam_types::slot_period_sec());

        // Tiny at the pinned revision. A re-pin that moves one of these is a
        // deliberate act (Cargo.toml's re-pin policy) and must be recorded.
        assert_eq!(param("validators"), 6);
        assert_eq!(param("cores"), 2);
        assert_eq!(param("epoch_length"), 12);
        assert_eq!(param("ticket_submission_end"), 10);
        assert_eq!(
            param("tickets_per_validator"),
            4,
            "tiny derives four attempts from (2 x 12) / 6; it was a declared 3 \
             before GP 0.8.0, so this is the parameter a re-pin moves most quietly"
        );
        assert_eq!(param("rotation_period"), 4);
        assert_eq!(param("max_lookup_anchor_age"), 24);
        assert_eq!(param("min_turnaround_period"), 32);
        assert_eq!(param("slot_period_sec"), 6);
    }

    /// The attempt cap the harness generates against is the one the node
    /// enforces, so no emulated author offers a ticket over the cap.
    ///
    /// `m2-reference`'s generator and `m2-runner`'s two context builders all
    /// read `tickets_per_validator(max_val_count())`; this holds the spec file
    /// handed to a third-party node to the same quantity.
    #[test]
    fn the_declared_attempt_cap_is_the_one_tickets_are_generated_against() {
        let chain_spec = tiny_spec(&loopback_ips(), &ports(), 0).expect("tiny spec builds");
        let spec = m2_spec("m2-test", &chain_spec).expect("m2 spec builds");

        let declared = spec.parameters["tickets_per_validator"]
            .as_u64()
            .expect("the attempt cap is a number");
        let generated = jam_types::tickets_per_validator(jam_types::max_val_count());

        assert_eq!(
            declared,
            u64::from(generated),
            "the spec file declares {declared} attempt(s) per validator and the \
             harness generates {generated}; a node configured from the file would \
             be graded against a cap it was never told"
        );
    }

    #[test]
    fn m2_spec_shape_and_consistency() {
        let chain_spec = tiny_spec(&loopback_ips(), &ports(), 0).expect("tiny spec builds");
        let spec = m2_spec("m2-test", &chain_spec).expect("m2 spec builds");

        assert!(spec.genesis_header.starts_with("0x"));
        let bytes = hex::decode(&spec.genesis_header[2..]).expect("valid hex header");
        let header = Header::decode_all(&mut &bytes[..]).expect("header decodes");
        assert_eq!(header.slot, 0);

        let state = spec.genesis_state.as_object().expect("state is an object");
        assert!(!state.is_empty(), "genesis state must be non-empty");
        assert!(state.keys().all(|k| k.starts_with("0x")));

        assert!(spec.bootnodes.is_empty());
    }

    /// KNOWN BUG (unfixed): genesis sits at slot 0, ~8.8M slots behind the
    /// wall clock, so a fresh NUT's finalized block (genesis) is never in the
    /// current epoch and polkajam refuses every ticket
    /// (`finality lagging (final: 0, curr: ...)`) and never authors.
    ///
    /// Anchoring genesis requires rebuilding the genesis *state* too:
    /// `dev_spec` closes over `genesis_header.hash()` when building storage,
    /// and `TheState::genesis` writes that hash into `recent_blocks.history[0]`
    /// (with `now: 0`), so patching the header alone desynchronises state from
    /// header and authoring fails with `BestBlockChanged`.
    #[test]
    fn genesis_is_anchored_to_the_current_epoch() {
        // Before the anchor is computed, not after. `current_epoch_start_slot`
        // divides by `epoch_period()`, which is the full 600 until the tiny
        // parameters are applied, and `tiny_spec` applies them several lines
        // too late to help. The test passed only when another test in the same
        // process had already applied them, so it failed whenever it ran alone
        // or first — a race on process-wide state, not a flake.
        jam_types::ProtocolParameters::tiny()
            .apply()
            .expect("tiny parameters apply");
        let anchor = m2_reference::chain::current_epoch_start_slot();
        let chain_spec = tiny_spec(&loopback_ips(), &ports(), anchor).expect("tiny spec builds");
        let period = jam_types::epoch_period();
        let now = m2_reference::chain::wall_clock_slot();

        let genesis_slot = chain_spec.genesis_header.slot;

        assert_eq!(
            genesis_slot / period,
            now / period,
            "genesis must sit in the current epoch"
        );
    }

    /// Anchoring the header alone would desynchronise state from header: the
    /// state's current time and the one recent block (genesis itself, carrying
    /// the hash the slot just changed) both have to move with it.
    #[test]
    fn anchored_genesis_state_agrees_with_its_header() {
        const ANCHOR: u32 = 9_373_122;

        let chain_spec = tiny_spec(&loopback_ips(), &ports(), ANCHOR).expect("tiny spec builds");
        let state = chain_spec.build_storage().expect("storage builds");
        let value = |key: jam_std_common::SystemKey| {
            state
                .iter()
                .find_map(|(k, v)| {
                    (*k == jam_std_common::StorageKey::from(key).0).then(|| v.clone())
                })
                .flatten()
                .expect("genesis writes every system key")
        };

        let now = value(jam_std_common::SystemKey::CurrentTime);
        assert_eq!(
            u32::decode_all(&mut now.as_slice()).expect("current time decodes"),
            ANCHOR
        );

        let recent = value(jam_std_common::SystemKey::RecentBlocks);
        let recent = jam_std_common::RecentBlocks::decode_all(&mut recent.as_slice())
            .expect("recent blocks decode");
        let genesis_block = recent.history.first().expect("genesis is a recent block");
        assert_eq!(genesis_block.slot, ANCHOR);
        assert_eq!(
            genesis_block.hash,
            chain_spec.genesis_header.hash(),
            "the recent block must carry the anchored header's hash, not the slot-0 one"
        );
    }

    #[test]
    fn genesis_header_hash_consistency() {
        let chain_spec = tiny_spec(&loopback_ips(), &ports(), 0).expect("tiny spec builds");
        let spec = m2_spec("m2-test", &chain_spec).expect("m2 spec builds");

        let bytes = hex::decode(&spec.genesis_header[2..]).expect("valid hex header");
        let header = Header::decode(&mut &bytes[..]).expect("header decodes");
        let hash = header.hash().0;

        let reference = m2_reference::chain::RefChain::tiny(0).expect("reference chain builds");
        assert_eq!(hash, reference.genesis_hash());
    }

    /// The whole point of threading the anchor through both sides: the node is
    /// started from the runner's spec and the reference engine from an
    /// identical one, so they must agree on the genesis hash. They would not if
    /// only one were anchored, the slot being part of the header preimage.
    #[test]
    fn anchored_spec_and_reference_chain_share_a_genesis() {
        const ANCHOR: u32 = 9_373_122;

        let chain_spec = tiny_spec(&loopback_ips(), &ports(), ANCHOR).expect("tiny spec builds");
        let ref_spec = tiny_spec(&loopback_ips(), &ports(), ANCHOR).expect("tiny spec builds");
        let reference =
            m2_reference::chain::RefChain::with_spec(0, ref_spec).expect("reference chain builds");

        assert_eq!(chain_spec.genesis_header.slot, ANCHOR);
        assert_eq!(chain_spec.genesis_header.hash().0, reference.genesis_hash());

        // ... and an unanchored reference chain would not match, which is the
        // failure this guards against.
        let unanchored = m2_reference::chain::RefChain::tiny(0).expect("reference chain builds");
        assert_ne!(
            chain_spec.genesis_header.hash().0,
            unanchored.genesis_hash()
        );
    }

    #[test]
    fn polkajam_spec_parses() {
        let chain_spec = tiny_spec(&loopback_ips(), &ports(), 0).expect("tiny spec builds");
        let dir = temp_dir("parses");
        let path = write_polkajam_spec(&dir, &chain_spec).expect("writes polkajam spec");

        let (_id, parsed) = jam_node::ChainSpec::load_from_file_and_apply_parameters(
            path.to_str().expect("utf-8 path"),
        )
        .expect("polkajam spec re-parses");
        let validators = parsed.genesis_validators().expect("genesis has validators");
        assert_eq!(validators.len(), 6);

        cleanup(&dir);
    }

    #[test]
    fn files_written() {
        let chain_spec = tiny_spec(&loopback_ips(), &ports(), 0).expect("tiny spec builds");
        let spec = m2_spec("m2-test", &chain_spec).expect("m2 spec builds");

        let dir = temp_dir("files");
        let m2_path = write_m2_spec(&dir, "m2-test", &spec).expect("writes m2 spec");
        let pk_path = write_polkajam_spec(&dir, &chain_spec).expect("writes polkajam spec");

        assert_eq!(
            m2_path.file_name().and_then(|n| n.to_str()),
            Some("spec-m2.json")
        );
        assert_eq!(
            pk_path.file_name().and_then(|n| n.to_str()),
            Some("spec.json")
        );
        assert!(m2_path.exists());
        assert!(pk_path.exists());

        cleanup(&dir);
    }
}
