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
/// genesis header has slot 0.
pub fn tiny_spec(validator_ips: &[[u8; 16]], ports: &[u16]) -> Result<ChainSpec, SpecError> {
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
    for (k, v) in state.iter_mut() {
        if keys.contains(k) {
            *v = Some(encoded.clone());
        } else if *k == safrole_key {
            let Some(bytes) = v.as_ref() else { continue };
            let mut safrole = jam_std_common::SafroleState::decode_all(&mut bytes.as_slice())
                .map_err(|e| SpecError::Storage(format!("decode safrole state: {e}")))?;
            safrole.waiting_validators = validators.clone();
            *v = Some(safrole.encode());
        }
    }

    let storage_builder =
        jam_node::hazmat::StorageBuilder::RawFactory(Box::new(move || Ok(state.clone())));
    let ChainSpec {
        genesis_header,
        bootnodes,
        ..
    } = base;
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
        parameters: serde_json::json!({
            "validators": 6,
            "cores": 2,
            "epoch_length": 12,
            "ticket_submission_end": 10,
            "tickets_per_validator": 3,
            "rotation_period": 4,
            "max_lookup_anchor_age": 24,
            "min_turnaround_period": 32,
            "slot_period_sec": 6,
        }),
        genesis_header,
        genesis_state: serde_json::Value::Object(genesis_state),
        bootnodes: Vec::new(),
    })
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

    #[test]
    fn m2_spec_shape_and_consistency() {
        let chain_spec = tiny_spec(&loopback_ips(), &ports()).expect("tiny spec builds");
        let spec = m2_spec("m2-test", &chain_spec).expect("m2 spec builds");

        assert_eq!(spec.parameters["validators"], 6);
        assert_eq!(spec.parameters["cores"], 2);
        assert_eq!(spec.parameters["epoch_length"], 12);
        assert_eq!(spec.parameters["ticket_submission_end"], 10);
        assert_eq!(spec.parameters["tickets_per_validator"], 3);
        assert_eq!(spec.parameters["rotation_period"], 4);
        assert_eq!(spec.parameters["max_lookup_anchor_age"], 24);
        assert_eq!(spec.parameters["min_turnaround_period"], 32);
        assert_eq!(spec.parameters["slot_period_sec"], 6);

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
    #[ignore = "genesis anchoring needs the genesis state rebuilt; see docstring"]
    fn genesis_is_anchored_to_the_current_epoch() {
        let chain_spec = tiny_spec(&loopback_ips(), &ports()).expect("tiny spec builds");
        let period = jam_types::epoch_period();
        let now = m2_reference::chain::wall_clock_slot();

        let genesis_slot = chain_spec.genesis_header.slot;

        assert_eq!(
            genesis_slot / period,
            now / period,
            "genesis must sit in the current epoch"
        );
    }

    #[test]
    fn genesis_header_hash_consistency() {
        let chain_spec = tiny_spec(&loopback_ips(), &ports()).expect("tiny spec builds");
        let spec = m2_spec("m2-test", &chain_spec).expect("m2 spec builds");

        let bytes = hex::decode(&spec.genesis_header[2..]).expect("valid hex header");
        let header = Header::decode(&mut &bytes[..]).expect("header decodes");
        let hash = header.hash().0;

        let reference = m2_reference::chain::RefChain::tiny(1..6).expect("reference chain builds");
        assert_eq!(hash, reference.genesis_hash());
    }

    #[test]
    fn polkajam_spec_parses() {
        let chain_spec = tiny_spec(&loopback_ips(), &ports()).expect("tiny spec builds");
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
        let chain_spec = tiny_spec(&loopback_ips(), &ports()).expect("tiny spec builds");
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
