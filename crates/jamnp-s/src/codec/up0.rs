//! UP 0: Block announcement (`jam-np/simple.md` `:192-236`).
//!
//! ```text
//! Final        = Header Hash ++ Slot
//! Leaf         = Header Hash ++ Slot
//! Handshake    = Final ++ len++[Leaf]
//! Announcement = Header ++ Final
//! ```

use codec::{Decode, Encode};
use jam_std_common::Header;
use jam_types::{HeaderHash, Slot};

/// `Final = Header Hash ++ Slot`: the latest finalized block.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Encode, Decode)]
pub struct Final {
    pub header_hash: HeaderHash,
    pub slot: Slot,
}

/// `Leaf = Header Hash ++ Slot` — structurally identical to [`Final`].
pub type Leaf = Final;

/// `Handshake = Final ++ len++[Leaf]`: the latest finalized block plus all
/// known leaves (descendants of the finalized block with no known children).
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct Handshake {
    pub final_block: Final,
    pub leaves: Vec<Final>,
}

/// `Announcement = Header ++ Final`: a newly produced/received block together
/// with the latest finalized block at announcement time.
#[derive(Clone, Debug, Encode, Decode)]
pub struct Announcement {
    pub header: Header,
    pub final_block: Final,
}

#[cfg(test)]
mod tests {
    use super::{Announcement, Final, Handshake};
    use codec::{Decode, Encode};
    use jam_std_common::Header;
    use jam_types::HeaderHash;

    /// A `Final` with a recognisable hash (`0x11` x32) and slot `0x0403_0201`
    /// (LE bytes `01 02 03 04`), so byte-exact vectors are easy to eyeball.
    fn final_block() -> Final {
        Final {
            header_hash: HeaderHash::from([0x11; 32]),
            slot: 0x0403_0201,
        }
    }

    /// The SCALE bytes of [`final_block`]: 32 hash bytes + 4 LE slot bytes.
    fn final_bytes() -> Vec<u8> {
        let mut v = vec![0x11; 32];
        v.extend_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        v
    }

    #[test]
    fn final_encodes_as_header_hash_plus_slot() {
        let f = final_block();
        assert_eq!(f.encode(), final_bytes());
        assert_eq!(f.encode().len(), 36);
    }

    #[test]
    fn handshake_empty_leaves_encodes_as_final_plus_compact_zero() {
        let hs = Handshake {
            final_block: final_block(),
            leaves: vec![],
        };
        let mut expected = final_bytes();
        expected.push(0x00); // compact-encoded `len = 0` is a single 0x00 byte
        assert_eq!(hs.encode(), expected);
        assert_eq!(hs.encode().len(), 37);
    }

    #[test]
    fn handshake_one_leaf_encodes_as_final_plus_len_one_plus_final() {
        let leaf = final_block();
        let hs = Handshake {
            final_block: leaf,
            leaves: vec![leaf],
        };
        let mut expected = final_bytes();
        expected.push(0x01); // jam-codec compact-encoded `len = 1`
        expected.extend_from_slice(&final_bytes());
        assert_eq!(hs.encode(), expected);
        assert_eq!(hs.encode().len(), 73);
    }

    #[test]
    fn handshake_two_leaves_encodes_as_final_plus_len_two_plus_two_finals() {
        let leaf = final_block();
        let hs = Handshake {
            final_block: leaf,
            leaves: vec![leaf, leaf],
        };
        let mut expected = final_bytes();
        expected.push(0x02); // jam-codec compact-encoded `len = 2`
        expected.extend_from_slice(&final_bytes());
        expected.extend_from_slice(&final_bytes());
        assert_eq!(hs.encode(), expected);
        assert_eq!(hs.encode().len(), 109);
    }

    #[test]
    fn announcement_encodes_as_header_plus_final() {
        let header = Header::genesis();
        let final_block = final_block();
        let ann = Announcement {
            header: header.clone(),
            final_block,
        };
        let bytes = ann.encode();
        let header_len = header.encode().len();
        assert_eq!(bytes.len(), header_len + final_block.encode().len());
        assert_eq!(&bytes[..header_len], &header.encode()[..]);
        assert_eq!(&bytes[header_len..], &final_block.encode()[..]);
    }

    #[test]
    fn handshake_decode_roundtrips() {
        let hs = Handshake {
            final_block: final_block(),
            leaves: vec![final_block(), final_block()],
        };
        let bytes = hs.encode();
        let decoded = Handshake::decode(&mut &bytes[..]).unwrap();
        assert_eq!(decoded, hs);
    }

    #[test]
    fn announcement_decode_roundtrips() {
        let ann = Announcement {
            header: Header::genesis(),
            final_block: final_block(),
        };
        let bytes = ann.encode();
        let decoded = Announcement::decode(&mut &bytes[..]).unwrap();
        assert_eq!(decoded.encode(), bytes);
    }

    #[test]
    fn decode_of_truncated_or_garbage_input_fails() {
        let good = Handshake {
            final_block: final_block(),
            leaves: vec![final_block()],
        }
        .encode();
        // Truncate the trailing leaf: SCALE decode must fail.
        let truncated = &good[..good.len() - 1];
        assert!(Handshake::decode(&mut &truncated[..]).is_err());
        // A `Final` needs 36 bytes; anything shorter (or empty) fails.
        assert!(Final::decode(&mut &[0u8; 3][..]).is_err());
        assert!(Final::decode(&mut &[][..]).is_err());
        // Garbage length prefix claiming 1000 leaves (`0x83 0xE8` is jam-codec's
        // compact encoding of 1000) must fail: there are no leaves after it.
        let mut garbage = final_bytes();
        garbage.extend_from_slice(&[0x83, 0xE8]);
        assert!(Handshake::decode(&mut &garbage[..]).is_err());
    }
}
