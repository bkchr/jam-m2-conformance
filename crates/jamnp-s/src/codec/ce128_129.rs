//! Codecs for CE 128 (block request) and CE 129 (state request).
//!
//! ```text
//! CE 128: BlockRequest  = Header Hash ++ Direction(1 byte) ++ Maximum Blocks(u32)
//!         BlockResponse = [Block]
//! CE 129: StateRequest  = Header Hash ++ Key(start,31) ++ Key(end,31) ++ Maximum Size(u32)
//!         StateResponse = [Boundary Node] then [Key ++ Value]  (two messages)
//! ```
//!
//! GP types (`Block`, `HeaderHash`) are encoded with the SCALE (`jam-codec`)
//! codec used across the workspace: fixed-size arrays raw, `u32` little-endian,
//! collection lengths jam-codec-compact (`jam-np/simple.md` `:238-303`).

use codec::{Decode, Encode, Input, Output};
use jam_std_common::Block;
use jam_types::HeaderHash;

/// Direction of a CE 128 block request (`simple.md:255`): a single byte on the
/// wire, `0` = ascending exclusive, `1` = descending inclusive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum Direction {
    /// The response starts with a child of the given block, then a grandchild,
    /// and so on (`simple.md:244`).
    AscendingExclusive = 0,
    /// The response starts with the given block, then its parent, grandparent,
    /// and so on (`simple.md:246`).
    DescendingInclusive = 1,
}

/// CE 128 request: `Header Hash ++ Direction ++ Maximum Blocks` (`simple.md:261`).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct BlockRequest {
    pub header_hash: HeaderHash,
    pub direction: Direction,
    pub max_blocks: u32,
}

/// CE 128 response: `[Block]` (`simple.md:263`).
///
/// The block sequence is transmitted with its length implied by the message
/// size (`simple.md:148-153`): blocks are encoded raw, one after another, with
/// no collection length prefix.
#[derive(Clone, Debug)]
pub struct BlockResponse {
    pub blocks: Vec<Block>,
}

impl Encode for BlockResponse {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        for block in &self.blocks {
            block.encode_to(dest);
        }
    }
}

impl Decode for BlockResponse {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        let mut blocks = Vec::new();
        while input.remaining_len()?.is_some_and(|n| n > 0) {
            blocks.push(Block::decode(input)?);
        }
        Ok(Self { blocks })
    }
}

/// A state-trie boundary node returned by CE 129, covering the path from the
/// root to the start key or to a returned entry (`simple.md:275-281`).
///
/// `Boundary Node = As returned by B/L` (`simple.md:293`) — the GP state
/// Merklization node, a **fixed 64-byte** leaf or branch. It carries no length
/// prefix of its own: within [`BoundaryNodes`] the count follows from the
/// message size.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct BoundaryNode(pub [u8; 64]);

impl Default for BoundaryNode {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

/// CE 129 response message 1: `[Boundary Node]` (`simple.md:300`).
///
/// Size-implied like CE 128's `[Block]` (`simple.md:148-153`): the nodes are
/// concatenated with no collection length prefix, and the count follows from
/// the message length. A response with no boundary nodes is an **empty
/// message**, not a zero-length prefix.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BoundaryNodes(pub Vec<BoundaryNode>);

impl Encode for BoundaryNodes {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        for node in &self.0 {
            node.encode_to(dest);
        }
    }
}

impl Decode for BoundaryNodes {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        let mut nodes = Vec::new();
        while input.remaining_len()?.is_some_and(|n| n > 0) {
            nodes.push(BoundaryNode::decode(input)?);
        }
        Ok(Self(nodes))
    }
}

/// CE 129 key/value pair: `Key ++ Value`, `Value = len++[u8]` (`simple.md:291,294`).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct KeyValue {
    /// First 31 bytes of the key only; the final key byte is ignored by the
    /// Merklization function (`simple.md:287-288`).
    pub key: [u8; 31],
    pub value: Vec<u8>,
}

/// CE 129 response message 2: `[Key ++ Value]` (`simple.md:301`).
///
/// Size-implied in the same way as [`BoundaryNodes`]; each pair carries its own
/// value length prefix, the sequence does not.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyValues(pub Vec<KeyValue>);

impl Encode for KeyValues {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        for entry in &self.0 {
            entry.encode_to(dest);
        }
    }
}

impl Decode for KeyValues {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        let mut entries = Vec::new();
        while input.remaining_len()?.is_some_and(|n| n > 0) {
            entries.push(KeyValue::decode(input)?);
        }
        Ok(Self(entries))
    }
}

/// CE 129 request: `Header Hash ++ Key (Start) ++ Key (End) ++ Maximum Size`
/// (`simple.md:298`).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct StateRequest {
    pub header_hash: HeaderHash,
    pub start: [u8; 31],
    pub end: [u8; 31],
    pub max_size: u32,
}

/// A CE 129 response.
///
/// It is **two messages on the stream, then FIN** (`simple.md:300-302`):
///
/// ```text
/// <-- [Boundary Node]
/// <-- [Key ++ Value]
/// <-- FIN
/// ```
///
/// so this is not a single encodable struct — there is no `Encode` for it on
/// purpose. [`StateResponse::messages`] produces the two payloads in order.
/// Packing both into one message, or prefixing either sequence with its length,
/// makes the responder look malformed to a conforming requester, which reads
/// each sequence as items-until-end-of-message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StateResponse {
    pub boundary_nodes: Vec<BoundaryNode>,
    /// Sorted by key (`simple.md:273`).
    pub entries: Vec<KeyValue>,
}

impl StateResponse {
    /// The two response payloads, in the order they go on the stream.
    pub fn messages(&self) -> (Vec<u8>, Vec<u8>) {
        (
            BoundaryNodes(self.boundary_nodes.clone()).encode(),
            KeyValues(self.entries.clone()).encode(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BlockRequest, BlockResponse, BoundaryNode, BoundaryNodes, Direction, KeyValue, KeyValues,
        StateRequest, StateResponse,
    };
    use codec::{Decode, Encode};
    use jam_std_common::{Block, Extrinsic, Header, ImmutableHeader};
    use jam_types::HeaderHash;
    use std::sync::Arc;

    /// A hash of `0xAA` x32 so byte-exact vectors are easy to eyeball.
    fn test_hash() -> HeaderHash {
        HeaderHash::from([0xAA; 32])
    }

    /// A minimal GP block: genesis header + default (empty) extrinsic.
    fn test_block() -> Block {
        Block {
            header: Arc::new(ImmutableHeader::from(Header::genesis())),
            extrinsic: Arc::new(Extrinsic::default()),
        }
    }

    /// SCALE-decodes `T` from `bytes`, mapping any codec error to `()`.
    fn decode<T: Decode>(bytes: &[u8]) -> Result<T, ()> {
        T::decode(&mut &bytes[..]).map_err(|_| ())
    }

    #[test]
    fn direction_encodes_as_single_byte() {
        assert_eq!(Direction::AscendingExclusive.encode(), vec![0x00]);
        assert_eq!(Direction::DescendingInclusive.encode(), vec![0x01]);
    }

    #[test]
    fn block_request_ascending_exclusive_bytes() {
        let req = BlockRequest {
            header_hash: test_hash(),
            direction: Direction::AscendingExclusive,
            max_blocks: 5,
        };
        let mut expected = vec![0xAA; 32];
        expected.push(0x00); // Direction byte
        expected.extend_from_slice(&5u32.to_le_bytes());
        assert_eq!(req.encode(), expected);
    }

    #[test]
    fn block_request_descending_inclusive_bytes() {
        let req = BlockRequest {
            header_hash: test_hash(),
            direction: Direction::DescendingInclusive,
            max_blocks: 5,
        };
        let mut expected = vec![0xAA; 32];
        expected.push(0x01); // Direction byte
        expected.extend_from_slice(&5u32.to_le_bytes());
        assert_eq!(req.encode(), expected);
    }

    #[test]
    fn block_request_roundtrip_each_direction() {
        for direction in [
            Direction::AscendingExclusive,
            Direction::DescendingInclusive,
        ] {
            let req = BlockRequest {
                header_hash: test_hash(),
                direction,
                max_blocks: 7,
            };
            assert_eq!(decode::<BlockRequest>(&req.encode()), Ok(req));
        }
    }

    #[test]
    fn block_response_empty_encodes_empty() {
        let resp = BlockResponse { blocks: vec![] };
        assert_eq!(resp.encode(), Vec::<u8>::new()); // no collection length prefix
    }

    #[test]
    fn block_response_one_block_encodes_raw_block() {
        let block = test_block();
        let resp = BlockResponse {
            blocks: vec![block.clone()],
        };
        assert_eq!(resp.encode(), block.encode());
    }

    #[test]
    fn block_response_two_blocks_encodes_raw_concatenation() {
        let b1 = test_block();
        let b2 = test_block();
        let resp = BlockResponse {
            blocks: vec![b1.clone(), b2.clone()],
        };
        let mut expected = b1.encode();
        expected.extend_from_slice(&b2.encode());
        assert_eq!(resp.encode(), expected);
    }

    #[test]
    fn block_response_decode_roundtrips() {
        let resp = BlockResponse {
            blocks: vec![test_block(), test_block()],
        };
        let bytes = resp.encode();
        let decoded = decode::<BlockResponse>(&bytes).unwrap();
        assert_eq!(decoded.encode(), bytes);
    }

    #[test]
    fn state_request_bytes() {
        let req = StateRequest {
            header_hash: test_hash(),
            start: [0x11; 31],
            end: [0x22; 31],
            max_size: 4096,
        };
        let mut expected = vec![0xAA; 32];
        expected.extend_from_slice(&[0x11; 31]);
        expected.extend_from_slice(&[0x22; 31]);
        expected.extend_from_slice(&4096u32.to_le_bytes());
        assert_eq!(req.encode(), expected);
        assert_eq!(req.encode().len(), 32 + 31 + 31 + 4);
    }

    #[test]
    fn state_request_roundtrip() {
        let req = StateRequest {
            header_hash: test_hash(),
            start: [1; 31],
            end: [2; 31],
            max_size: 99,
        };
        assert_eq!(decode::<StateRequest>(&req.encode()), Ok(req));
    }

    #[test]
    fn key_value_value_length_prefix() {
        let kv = KeyValue {
            key: [0x33; 31],
            value: vec![1, 2, 3, 4],
        };
        let mut expected = vec![0x33; 31];
        expected.push(0x04); // jam-codec compact len 4
        expected.extend_from_slice(&[1, 2, 3, 4]);
        assert_eq!(kv.encode(), expected);
    }

    #[test]
    fn key_value_empty_value_encodes_len_zero() {
        let kv = KeyValue {
            key: [0x33; 31],
            value: vec![],
        };
        let mut expected = vec![0x33; 31];
        expected.push(0x00); // jam-codec compact len 0
        assert_eq!(kv.encode(), expected);
    }

    #[test]
    fn key_value_roundtrip() {
        let kv = KeyValue {
            key: [9; 31],
            value: vec![0, 1, 2],
        };
        assert_eq!(decode::<KeyValue>(&kv.encode()), Ok(kv));
    }

    #[test]
    fn state_response_is_two_size_implied_messages() {
        let entry = KeyValue {
            key: [0x55; 31],
            value: vec![0x66],
        };
        let resp = StateResponse {
            boundary_nodes: vec![BoundaryNode([0x44; 64]), BoundaryNode([0x77; 64])],
            entries: vec![entry.clone()],
        };
        let (nodes, entries) = resp.messages();

        // Message 1 is exactly the nodes, back to back: no collection length
        // prefix, and no per-node length prefix either (`simple.md:300`).
        let mut expected_nodes = vec![0x44; 64];
        expected_nodes.extend_from_slice(&[0x77; 64]);
        assert_eq!(nodes, expected_nodes);
        assert_eq!(nodes.len(), 128);

        // Message 2 is the pairs back to back; each keeps its own value length
        // prefix, the sequence does not (`simple.md:301`).
        assert_eq!(entries, entry.encode());
        assert_eq!(entries[..31], [0x55; 31]);
    }

    #[test]
    fn empty_state_response_is_two_empty_messages() {
        // The regression that kept a node from syncing: an empty reply used to
        // go out as one 2-byte message of compact zeroes, which a conforming
        // requester reads as the start of a 64-byte boundary node and rejects.
        let (nodes, entries) = StateResponse::default().messages();
        assert!(nodes.is_empty(), "no boundary nodes means an empty message");
        assert!(entries.is_empty(), "no entries means an empty message");
    }

    #[test]
    fn state_response_messages_roundtrip() {
        let resp = StateResponse {
            boundary_nodes: vec![BoundaryNode([7; 64]), BoundaryNode([9; 64])],
            entries: vec![
                KeyValue {
                    key: [1; 31],
                    value: vec![2, 3],
                },
                KeyValue {
                    key: [4; 31],
                    value: vec![],
                },
            ],
        };
        let (nodes, entries) = resp.messages();
        assert_eq!(
            decode::<BoundaryNodes>(&nodes),
            Ok(BoundaryNodes(resp.boundary_nodes.clone()))
        );
        assert_eq!(decode::<KeyValues>(&entries), Ok(KeyValues(resp.entries)));
    }

    #[test]
    fn boundary_nodes_reject_a_partial_node() {
        // 64-byte items: anything that is not a whole number of them is a
        // truncated message, not a short last node.
        assert!(decode::<BoundaryNodes>(&[0u8; 63]).is_err());
        assert!(decode::<BoundaryNodes>(&[0u8; 65]).is_err());
        assert_eq!(
            decode::<BoundaryNodes>(&[0u8; 128]),
            Ok(BoundaryNodes(vec![BoundaryNode([0; 64]); 2]))
        );
        assert_eq!(decode::<BoundaryNodes>(&[]), Ok(BoundaryNodes(vec![])));
    }

    #[test]
    fn decode_rejects_invalid_direction_byte() {
        for bad in [2u8, 0xFF] {
            assert!(decode::<Direction>(&[bad]).is_err());
            let mut bytes = vec![0xAA; 32];
            bytes.push(bad);
            bytes.extend_from_slice(&1u32.to_le_bytes());
            assert!(decode::<BlockRequest>(&bytes).is_err());
        }
    }

    #[test]
    fn decode_of_truncated_input_fails() {
        // BlockRequest: fewer than 32 hash bytes, or no max_blocks.
        assert!(decode::<BlockRequest>(&[0xAA; 31]).is_err());
        let mut short = vec![0xAA; 32];
        short.push(0x00);
        assert!(decode::<BlockRequest>(&short).is_err());
        // StateRequest: missing max_size.
        let mut short_state = vec![0xAA; 32];
        short_state.extend_from_slice(&[0x11; 31]);
        short_state.extend_from_slice(&[0x22; 31]);
        assert!(decode::<StateRequest>(&short_state).is_err());
        // KeyValue: key but no value.
        assert!(decode::<KeyValue>(&[0x33; 31]).is_err());
        // BlockResponse: length prefix claims a block that isn't there.
        assert!(decode::<BlockResponse>(&[0x01]).is_err());
        // KeyValues: a trailing key with no value length prefix.
        assert!(decode::<KeyValues>(&[0x33; 31]).is_err());
    }
}
