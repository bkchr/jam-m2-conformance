//! Deterministic key generation and NUT secret handover (DESIGN.md §7).

use std::io::Write;
use std::path::Path;

use jam_std_common::{InjectiveDecode, P256PeerId, PeerAddr, ValidatorMetadata};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

/// Reference `SecretKeyset`, re-exported so callers need no `jam-std-common` import.
pub type SecretKeyset = jam_std_common::SecretKeyset;

/// Everything a run needs to hand the NUT its identity and seed the emulated validators.
pub struct GeneratedKeys {
    /// `SecretKeyset::trivial(i)` for each validator `i`; index 0 is the NUT.
    pub keysets: Vec<SecretKeyset>,
    /// Raw 32-byte seed written to `seed.seed` (polkajam format).
    pub nut_seed: [u8; 32],
    /// Hex of the NUT's 32-byte Ed25519 secret.
    pub nut_ed25519_secret_hex: String,
    /// Hex of the NUT's 32-byte Bandersnatch secret seed.
    pub nut_bandersnatch_secret_hex: String,
    /// The run seed (recorded for scenario reproducibility).
    pub run_seed: u64,
}

/// Deterministically generates keysets for `validator_count` validators and the NUT secret
/// handover (DESIGN.md §4, §7). Validator `i` gets `SecretKeyset::trivial(i)`; validator 0 is
/// the NUT.
pub fn generate(seed: u64, validator_count: usize) -> GeneratedKeys {
    // A run always has the NUT, so `validator_count >= 1` and `keysets[0]` is the NUT.
    let keysets: Vec<SecretKeyset> = (0..validator_count)
        .map(|i| SecretKeyset::trivial(i as u32))
        .collect();

    // The NUT's Ed25519 secret must match the on-chain genesis key of validator 0.
    let nut_ed25519_secret_hex = hex::encode(keysets[0].ed25519.to_bytes());
    // `bandersnatch::Secret` at the pinned rev exposes no raw-byte accessor, so the raw 32-byte
    // seed for validator 0 is handed over instead: a NUT feeds it straight to
    // `bandersnatch::Secret::from_seed` and it derives the same keyset as the genesis entry.
    // The NUT's on-chain identity is fixed (validator index 0), so the seed file does not depend
    // on the run `seed`; the run seed is recorded for scenario reproducibility instead.
    let nut_seed = SecretKeyset::trivial_seed(0);
    let nut_bandersnatch_secret_hex = hex::encode(nut_seed);

    GeneratedKeys {
        keysets,
        nut_seed,
        nut_ed25519_secret_hex,
        nut_bandersnatch_secret_hex,
        run_seed: seed,
    }
}

/// Builds validator metadata for genesis: `PeerAddr` (IPv6 + LE u16 port, bytes 0..18), zero
/// P-256 id, zero filler (DESIGN.md §7).
pub fn metadata_for(_index: usize, ip: [u8; 16], port: u16) -> ValidatorMetadata {
    ValidatorMetadata {
        addr: PeerAddr { ip, port },
        p256_id: InjectiveDecode::Valid(P256PeerId::ZERO),
        rest1: [0; 13],
        rest2: [0; 16],
    }
}

/// Writes the NUT seed handover: raw 32-byte `seed.seed` (polkajam format, mode 0600) plus hex
/// `nut_ed25519.hex` / `nut_bandersnatch.hex` text files.
pub fn write_seed_files(dir: &Path, keys: &GeneratedKeys) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    write_private(&dir.join("seed.seed"), &keys.nut_seed)?;
    write_private(
        &dir.join("nut_ed25519.hex"),
        format!("{}\n", keys.nut_ed25519_secret_hex).as_bytes(),
    )?;
    write_private(
        &dir.join("nut_bandersnatch.hex"),
        format!("{}\n", keys.nut_bandersnatch_secret_hex).as_bytes(),
    )?;
    Ok(())
}

/// Writes a secret file (create/truncate) with mode 0600 on unix.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path)?.write_all(bytes)
}

#[cfg(test)]
mod tests {
    use jam_types::OpaqueValidatorMetadata;

    use super::{generate, metadata_for, write_seed_files};

    #[test]
    fn deterministic_same_seed_same_keys() {
        let a = generate(7, 6);
        let b = generate(7, 6);
        assert_eq!(a.nut_seed, b.nut_seed);
        assert_eq!(a.nut_ed25519_secret_hex, b.nut_ed25519_secret_hex);
        assert_eq!(a.nut_bandersnatch_secret_hex, b.nut_bandersnatch_secret_hex);
    }

    #[test]
    fn validator_count_keysets() {
        assert_eq!(generate(7, 6).keysets.len(), 6);
        assert_eq!(generate(7, 5).keysets.len(), 5);
    }

    #[test]
    fn nut_secrets_are_32_bytes_hex() {
        let keys = generate(7, 6);
        assert_eq!(hex::decode(&keys.nut_ed25519_secret_hex).unwrap().len(), 32);
        assert_eq!(
            hex::decode(&keys.nut_bandersnatch_secret_hex)
                .unwrap()
                .len(),
            32
        );
    }

    #[test]
    fn metadata_layout_matches_spec() {
        let ip = [0u8; 16];
        let metadata = metadata_for(0, ip, 40000);
        let opaque: OpaqueValidatorMetadata = metadata.into();
        assert_eq!(&opaque.0[0..16], ip);
        assert_eq!(&opaque.0[16..18], 40000u16.to_le_bytes());
    }

    #[test]
    fn seed_files_written() {
        let dir = std::env::temp_dir().join(format!("m2-keygen-test-{}", std::process::id()));
        let keys = generate(7, 6);
        write_seed_files(&dir, &keys).unwrap();

        let seed = std::fs::read(dir.join("seed.seed")).unwrap();
        assert_eq!(seed, keys.nut_seed);
        assert_eq!(seed.len(), 32);

        let ed25519 = std::fs::read_to_string(dir.join("nut_ed25519.hex")).unwrap();
        assert_eq!(ed25519.trim().len(), 64);

        let bandersnatch = std::fs::read_to_string(dir.join("nut_bandersnatch.hex")).unwrap();
        assert_eq!(bandersnatch.trim().len(), 64);

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
