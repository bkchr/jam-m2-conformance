//! Codecs for CE 137/138 (shard + audit shard requests), 139/140 (segment
//! shard request), 147 (bundle request), 148 (segment request) and 146 (bundle
//! submission) per `jam-np/simple.md`.
//!
//! Shapes only: the harness does not produce real erasure data at this layer,
//! so all shards/segments/bundles are opaque `Vec<u8>` and all roots/hashes are
//! plain `[u8; 32]`.

use codec::{Decode, Encode, Input, Output};

/// 32-byte erasure root of a work-package bundle.
pub type ErasureRoot = [u8; 32];
/// 32-byte segments root of a bundle's imported segments.
pub type SegmentsRoot = [u8; 32];
/// Index of a validator's shard.
pub type ShardIndex = u16;
/// Index of a segment within a bundle.
pub type SegmentIndex = u16;
/// A work-package bundle shard (opaque).
pub type BundleShard = Vec<u8>;
/// An erasure-coded segment shard (opaque).
pub type SegmentShard = Vec<u8>;
/// An imported segment: 4104 bytes in the GP, opaque here.
pub type Segment = Vec<u8>;
/// `Import-Proof = len++[Hash]` (`simple.md:392`).
pub type ImportProof = Vec<[u8; 32]>;

/// CE 146 work-package cap in bytes (`simple.md:383`).
pub const WORK_PACKAGE_MAX: usize = 200 * 1024;
/// CE 139/140 cap: at most `2 * W_M` segment shards per stream, `W_M = 3072`
/// (`simple.md:632-633`).
pub const MAX_SEGMENT_SHARDS_PER_REQUEST: usize = 2 * 3072;
/// CE 148 cap: at most `W_M = 3072` segments per stream (`simple.md:657-658`).
pub const MAX_SEGMENTS_PER_REQUEST: usize = 3072;

/// CE 137/138 justification: the co-path from the erasure-root to a shard
/// (`simple.md:546`, `simple.md:571`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Justification {
    /// `0 ++ Hash`: sibling-only co-path node.
    Left([u8; 32]),
    /// `1 ++ Hash ++ Hash`: the node's hash plus its sibling.
    Right([u8; 32], [u8; 32]),
}

impl Encode for Justification {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        match self {
            Self::Left(h) => {
                dest.push_byte(0);
                dest.write(h);
            }
            Self::Right(a, b) => {
                dest.push_byte(1);
                dest.write(a);
                dest.write(b);
            }
        }
    }
}

impl Decode for Justification {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        match input.read_byte()? {
            0 => {
                let mut h = [0u8; 32];
                input.read(&mut h)?;
                Ok(Self::Left(h))
            }
            1 => {
                let mut a = [0u8; 32];
                input.read(&mut a)?;
                let mut b = [0u8; 32];
                input.read(&mut b)?;
                Ok(Self::Right(a, b))
            }
            _ => Err(codec::Error::from("invalid Justification discriminator")),
        }
    }
}

/// CE 139/140 per-shard justification (`simple.md:637`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SegmentJustification {
    /// `0 ++ Hash`.
    Left([u8; 32]),
    /// `1 ++ Hash ++ Hash`.
    Right([u8; 32], [u8; 32]),
    /// `2 ++ Segment Shard`.
    Shard(SegmentShard),
}

impl Encode for SegmentJustification {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        match self {
            Self::Left(h) => {
                dest.push_byte(0);
                dest.write(h);
            }
            Self::Right(a, b) => {
                dest.push_byte(1);
                dest.write(a);
                dest.write(b);
            }
            Self::Shard(s) => {
                dest.push_byte(2);
                s.encode_to(dest);
            }
        }
    }
}

impl Decode for SegmentJustification {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        match input.read_byte()? {
            0 => {
                let mut h = [0u8; 32];
                input.read(&mut h)?;
                Ok(Self::Left(h))
            }
            1 => {
                let mut a = [0u8; 32];
                input.read(&mut a)?;
                let mut b = [0u8; 32];
                input.read(&mut b)?;
                Ok(Self::Right(a, b))
            }
            2 => Ok(Self::Shard(SegmentShard::decode(input)?)),
            _ => Err(codec::Error::from(
                "invalid SegmentJustification discriminator",
            )),
        }
    }
}

/// CE 137 request: `Erasure-Root ++ Shard Index` (`simple.md:550`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Encode, Decode)]
pub struct ShardRequest {
    /// Erasure root of the work-package bundle.
    pub erasure_root: ErasureRoot,
    /// The shard index assigned to the requesting validator.
    pub shard_index: ShardIndex,
}

/// CE 137 response: `Bundle Shard ++ [Segment Shard] ++ Justification`
/// (`simple.md:552-554`).
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct ShardResponse {
    /// The requested work-package bundle shard.
    pub bundle_shard: BundleShard,
    /// Exported/proof segment shards with the given index.
    pub segment_shards: Vec<SegmentShard>,
    /// Co-path proof of the shards.
    pub justification: Justification,
}

/// CE 138 response: `Bundle Shard ++ Justification` (`simple.md:577-578`).
///
/// The request is the same [`ShardRequest`] as CE 137.
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct AuditShardResponse {
    /// The requested work-package bundle (audit) shard.
    pub bundle_shard: BundleShard,
    /// Co-path proof of the shard.
    pub justification: Justification,
}

/// CE 147 request: `Erasure-Root` (`simple.md:591`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Encode, Decode)]
pub struct BundleRequest {
    /// Erasure root of the requested work-package bundle.
    pub erasure_root: ErasureRoot,
}

/// CE 147 response: `Work-Package Bundle` (`simple.md:593`).
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct BundleResponse {
    /// The encoded work-package bundle.
    pub bundle: Vec<u8>,
}

/// CE 139/140 request: `Erasure-Root ++ Shard Index ++ len++[Segment Index]`
/// (`simple.md:641`; the single-element stream models the inner triple).
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct SegmentShardRequest {
    /// Erasure root of the work-package bundle.
    pub erasure_root: ErasureRoot,
    /// The shard index the segment shards belong to.
    pub shard_index: ShardIndex,
    /// The requested segment indices.
    pub segment_indices: Vec<SegmentIndex>,
}

impl SegmentShardRequest {
    /// Whether the requested shard count is within [`MAX_SEGMENT_SHARDS_PER_REQUEST`].
    pub fn validate_shard_count(&self) -> bool {
        self.segment_indices.len() <= MAX_SEGMENT_SHARDS_PER_REQUEST
    }
}

/// CE 139 response: `[Segment Shard]` (`simple.md:643`).
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct SegmentShardsResponse {
    /// The requested segment shards.
    pub segment_shards: Vec<SegmentShard>,
}

/// CE 140 response: `[Segment Shard]` then one `Justification` per shard
/// (`simple.md:643-646`).
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct ProvenSegmentShardsResponse {
    /// The requested segment shards.
    pub segment_shards: Vec<SegmentShard>,
    /// One justification per returned segment shard.
    pub justifications: Vec<SegmentJustification>,
}

/// CE 148 request: `Segments-Root ++ len++[Segment Index]` (`simple.md:668`;
/// the single-element stream models the inner pair).
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct SegmentRequest {
    /// Segments root of the bundle's imported segments.
    pub segments_root: SegmentsRoot,
    /// The requested segment indices.
    pub segment_indices: Vec<SegmentIndex>,
}

impl SegmentRequest {
    /// Whether the requested segment count is within [`MAX_SEGMENTS_PER_REQUEST`].
    pub fn validate_segment_count(&self) -> bool {
        self.segment_indices.len() <= MAX_SEGMENTS_PER_REQUEST
    }
}

/// CE 148 response: `[Segment] ++ [Import-Proof]` (`simple.md:670-671`).
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct SegmentResponse {
    /// The requested imported segments.
    pub segments: Vec<Segment>,
    /// Import proof for all returned segments.
    pub import_proof: ImportProof,
}

/// CE 146: work-package bundle submission (`simple.md:397-401`).
///
/// Wire: `Core Index ++ Segments-Root Mappings`, then `Work-Package`, then
/// `[Extrinsic]`, then `[Segment]`, then `[Import-Proof]`.
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct BundleSubmission {
    /// Core index the work-package is destined for.
    pub core_index: u16,
    /// `Segments-Root Mappings = len++[Work-Package Hash ++ Segments-Root]`
    /// (`simple.md:393`).
    pub mappings: Vec<([u8; 32], [u8; 32])>,
    /// The GP-encoded work-package.
    pub work_package: Vec<u8>,
    /// Extrinsic data referenced by the work-package.
    pub extrinsics: Vec<Vec<u8>>,
    /// All imported segments.
    pub segments: Vec<Segment>,
    /// Import proofs for all imported segments.
    pub import_proof: ImportProof,
}

impl BundleSubmission {
    /// Whether the work-package is within [`WORK_PACKAGE_MAX`] bytes.
    pub fn validate_work_package_size(&self) -> bool {
        self.work_package.len() <= WORK_PACKAGE_MAX
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::{Decode, Encode};

    /// 32-byte hash filled with `byte`.
    fn h32(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    /// Encode then decode back; asserts the roundtrip preserves the value and
    /// consumes the whole buffer.
    fn roundtrip<T: codec::Codec + core::fmt::Debug + PartialEq>(value: &T) {
        let bytes = value.encode();
        let mut input: &[u8] = &bytes[..];
        let decoded = T::decode(&mut input).unwrap();
        assert!(input.is_empty());
        assert_eq!(&decoded, value);
    }

    /// Decoding the encoding with its last byte dropped must fail.
    fn truncated_errs<T: codec::Codec>(bytes: &[u8]) {
        assert!(!bytes.is_empty());
        let mut input: &[u8] = &bytes[..bytes.len() - 1];
        assert!(T::decode(&mut input).is_err());
    }

    // --- Justification (CE 137/138) -----------------------------------------

    #[test]
    fn justification_left_vector() {
        let j = Justification::Left(h32(0x11));
        let mut expected = vec![0u8];
        expected.extend_from_slice(&h32(0x11));
        assert_eq!(j.encode(), expected);
        assert_eq!(j.encode().len(), 33);
    }

    #[test]
    fn justification_right_vector() {
        let j = Justification::Right(h32(0x11), h32(0x22));
        let mut expected = vec![1u8];
        expected.extend_from_slice(&h32(0x11));
        expected.extend_from_slice(&h32(0x22));
        assert_eq!(j.encode(), expected);
        assert_eq!(j.encode().len(), 65);
    }

    #[test]
    fn justification_roundtrips() {
        roundtrip(&Justification::Left(h32(0x11)));
        roundtrip(&Justification::Right(h32(0x11), h32(0x22)));
    }

    #[test]
    fn justification_bad_discriminator_errs() {
        for bad in [2u8, 3, 0x7f, 0xff] {
            let mut input: &[u8] = &[bad];
            assert!(Justification::decode(&mut input).is_err());
        }
    }

    #[test]
    fn justification_truncated_errs() {
        truncated_errs::<Justification>(&Justification::Left(h32(0x11)).encode());
        truncated_errs::<Justification>(&Justification::Right(h32(0x11), h32(0x22)).encode());
        let mut input: &[u8] = &[];
        assert!(Justification::decode(&mut input).is_err());
    }

    // --- SegmentJustification (CE 139/140) ----------------------------------

    #[test]
    fn segment_justification_vectors() {
        let left = SegmentJustification::Left(h32(0x11));
        let mut expected_left = vec![0u8];
        expected_left.extend_from_slice(&h32(0x11));
        assert_eq!(left.encode(), expected_left);

        let right = SegmentJustification::Right(h32(0x11), h32(0x22));
        let mut expected_right = vec![1u8];
        expected_right.extend_from_slice(&h32(0x11));
        expected_right.extend_from_slice(&h32(0x22));
        assert_eq!(right.encode(), expected_right);

        // Discriminator 2 followed by a SCALE-encoded `[u8]` shard.
        let shard = SegmentJustification::Shard(vec![0xaa, 0xbb, 0xcc]);
        assert_eq!(shard.encode(), vec![2, 0x03, 0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn segment_justification_roundtrips() {
        roundtrip(&SegmentJustification::Left(h32(0x11)));
        roundtrip(&SegmentJustification::Right(h32(0x11), h32(0x22)));
        roundtrip(&SegmentJustification::Shard(vec![0xaa, 0xbb, 0xcc]));
        roundtrip(&SegmentJustification::Shard(vec![]));
    }

    #[test]
    fn segment_justification_bad_discriminator_errs() {
        for bad in [3u8, 0x7f, 0xff] {
            let mut input: &[u8] = &[bad];
            assert!(SegmentJustification::decode(&mut input).is_err());
        }
    }

    #[test]
    fn segment_justification_truncated_errs() {
        truncated_errs::<SegmentJustification>(&SegmentJustification::Left(h32(0x11)).encode());
        truncated_errs::<SegmentJustification>(
            &SegmentJustification::Right(h32(0x11), h32(0x22)).encode(),
        );
        // Shard variant promises 3 bytes but carries only 1.
        let mut input: &[u8] = &[2, 0x03, 0xaa];
        assert!(SegmentJustification::decode(&mut input).is_err());
    }

    // --- CE 137: Shard distribution -----------------------------------------

    #[test]
    fn ce137_request_vector() {
        let req = ShardRequest {
            erasure_root: h32(0x11),
            shard_index: 0x0102,
        };
        let mut expected = h32(0x11).to_vec();
        expected.extend_from_slice(&[0x02, 0x01]); // u16 LE
        assert_eq!(req.encode(), expected);
        assert_eq!(req.encode().len(), 34);
    }

    #[test]
    fn ce137_request_roundtrip() {
        roundtrip(&ShardRequest {
            erasure_root: h32(0x11),
            shard_index: 0x0102,
        });
    }

    #[test]
    fn ce137_request_truncated_errs() {
        let bytes = ShardRequest {
            erasure_root: h32(0x11),
            shard_index: 0x0102,
        }
        .encode();
        truncated_errs::<ShardRequest>(&bytes);
        let mut input: &[u8] = &[];
        assert!(ShardRequest::decode(&mut input).is_err());
    }

    #[test]
    fn ce137_response_vector() {
        let resp = ShardResponse {
            bundle_shard: vec![0xaa, 0xbb, 0xcc],
            segment_shards: vec![],
            justification: Justification::Left(h32(0x11)),
        };
        let mut expected = vec![0x03u8, 0xaa, 0xbb, 0xcc, 0x00, 0x00];
        expected.extend_from_slice(&h32(0x11));
        assert_eq!(resp.encode(), expected);
    }

    #[test]
    fn ce137_response_two_shards_vector() {
        let resp = ShardResponse {
            bundle_shard: vec![],
            segment_shards: vec![vec![0xde], vec![0xad, 0xbe]],
            justification: Justification::Right(h32(0x11), h32(0x22)),
        };
        let mut expected = vec![0x00u8, 0x02, 0x01, 0xde, 0x02, 0xad, 0xbe, 0x01];
        expected.extend_from_slice(&h32(0x11));
        expected.extend_from_slice(&h32(0x22));
        assert_eq!(resp.encode(), expected);
    }

    #[test]
    fn ce137_response_roundtrips() {
        roundtrip(&ShardResponse {
            bundle_shard: vec![0xaa, 0xbb, 0xcc],
            segment_shards: vec![],
            justification: Justification::Left(h32(0x11)),
        });
        roundtrip(&ShardResponse {
            bundle_shard: vec![],
            segment_shards: vec![vec![0xde], vec![0xad, 0xbe]],
            justification: Justification::Right(h32(0x11), h32(0x22)),
        });
    }

    #[test]
    fn ce137_response_truncated_errs() {
        truncated_errs::<ShardResponse>(
            &ShardResponse {
                bundle_shard: vec![0xaa, 0xbb, 0xcc],
                segment_shards: vec![vec![0xde]],
                justification: Justification::Right(h32(0x11), h32(0x22)),
            }
            .encode(),
        );
    }

    // --- CE 138: Audit shard request ----------------------------------------

    #[test]
    fn ce138_response_vector() {
        let resp = AuditShardResponse {
            bundle_shard: vec![0xde, 0xad],
            justification: Justification::Right(h32(0x11), h32(0x22)),
        };
        let mut expected = vec![0x02u8, 0xde, 0xad, 0x01];
        expected.extend_from_slice(&h32(0x11));
        expected.extend_from_slice(&h32(0x22));
        assert_eq!(resp.encode(), expected);
    }

    #[test]
    fn ce138_response_roundtrip() {
        roundtrip(&AuditShardResponse {
            bundle_shard: vec![0xde, 0xad],
            justification: Justification::Left(h32(0x11)),
        });
    }

    #[test]
    fn ce138_response_truncated_errs() {
        truncated_errs::<AuditShardResponse>(
            &AuditShardResponse {
                bundle_shard: vec![0xde, 0xad],
                justification: Justification::Right(h32(0x11), h32(0x22)),
            }
            .encode(),
        );
    }

    // --- CE 147: Bundle request ---------------------------------------------

    #[test]
    fn ce147_request_vector() {
        let req = BundleRequest {
            erasure_root: h32(0x13),
        };
        assert_eq!(req.encode(), h32(0x13).to_vec());
    }

    #[test]
    fn ce147_response_vector() {
        let resp = BundleResponse {
            bundle: vec![0xde, 0xad],
        };
        assert_eq!(resp.encode(), vec![0x02, 0xde, 0xad]);
    }

    #[test]
    fn ce147_roundtrips() {
        roundtrip(&BundleRequest {
            erasure_root: h32(0x13),
        });
        roundtrip(&BundleResponse {
            bundle: vec![0xde, 0xad],
        });
    }

    #[test]
    fn ce147_truncated_errs() {
        truncated_errs::<BundleRequest>(
            &BundleRequest {
                erasure_root: h32(0x13),
            }
            .encode(),
        );
        truncated_errs::<BundleResponse>(
            &BundleResponse {
                bundle: vec![0xde, 0xad],
            }
            .encode(),
        );
    }

    // --- CE 139/140: Segment shard request ----------------------------------

    #[test]
    fn ce139_140_request_vector() {
        let req = SegmentShardRequest {
            erasure_root: h32(0x11),
            shard_index: 0x0102,
            segment_indices: vec![0x0001, 0x0002],
        };
        let mut expected = h32(0x11).to_vec();
        expected.extend_from_slice(&[0x02, 0x01]); // shard index u16 LE
        expected.push(0x02); // compact(2)
        expected.extend_from_slice(&[0x01, 0x00]); // segment index u16 LE
        expected.extend_from_slice(&[0x02, 0x00]);
        assert_eq!(req.encode(), expected);
    }

    #[test]
    fn ce139_140_request_empty_indices_vector() {
        let req = SegmentShardRequest {
            erasure_root: h32(0x11),
            shard_index: 0x0000,
            segment_indices: vec![],
        };
        let mut expected = h32(0x11).to_vec();
        expected.extend_from_slice(&[0x00, 0x00]);
        expected.push(0x00);
        assert_eq!(req.encode(), expected);
    }

    #[test]
    fn ce139_140_request_roundtrip() {
        roundtrip(&SegmentShardRequest {
            erasure_root: h32(0x11),
            shard_index: 0x0102,
            segment_indices: vec![0x0001, 0x0002],
        });
        roundtrip(&SegmentShardRequest {
            erasure_root: h32(0x11),
            shard_index: 0x0000,
            segment_indices: vec![],
        });
    }

    #[test]
    fn ce139_140_request_truncated_errs() {
        truncated_errs::<SegmentShardRequest>(
            &SegmentShardRequest {
                erasure_root: h32(0x11),
                shard_index: 0x0102,
                segment_indices: vec![0x0001, 0x0002],
            }
            .encode(),
        );
    }

    #[test]
    fn ce139_140_response_empty_vector() {
        let resp = SegmentShardsResponse {
            segment_shards: vec![],
        };
        assert_eq!(resp.encode(), vec![0x00]);
    }

    #[test]
    fn ce139_140_response_two_shards_vector() {
        let resp = SegmentShardsResponse {
            segment_shards: vec![vec![0xde], vec![0xad, 0xbe]],
        };
        assert_eq!(resp.encode(), vec![0x02, 0x01, 0xde, 0x02, 0xad, 0xbe]);
    }

    #[test]
    fn ce139_140_response_roundtrip() {
        roundtrip(&SegmentShardsResponse {
            segment_shards: vec![vec![0xde], vec![]],
        });
    }

    #[test]
    fn ce139_140_proven_response_vector() {
        let resp = ProvenSegmentShardsResponse {
            segment_shards: vec![vec![0xde]],
            justifications: vec![
                SegmentJustification::Left(h32(0x11)),
                SegmentJustification::Shard(vec![0xaa, 0xbb]),
            ],
        };
        let mut expected = vec![0x01u8, 0x01, 0xde]; // [Segment Shard]
        expected.push(0x02); // compact(2) justifications
        expected.push(0x00); // Left
        expected.extend_from_slice(&h32(0x11));
        expected.push(0x02); // Shard
        expected.push(0x02);
        expected.push(0xaa);
        expected.push(0xbb);
        assert_eq!(resp.encode(), expected);
    }

    #[test]
    fn ce139_140_proven_response_roundtrip() {
        roundtrip(&ProvenSegmentShardsResponse {
            segment_shards: vec![vec![0xde], vec![0xad, 0xbe]],
            justifications: vec![
                SegmentJustification::Left(h32(0x11)),
                SegmentJustification::Right(h32(0x11), h32(0x22)),
                SegmentJustification::Shard(vec![]),
            ],
        });
    }

    #[test]
    fn ce139_140_proven_response_truncated_errs() {
        truncated_errs::<ProvenSegmentShardsResponse>(
            &ProvenSegmentShardsResponse {
                segment_shards: vec![vec![0xde]],
                justifications: vec![SegmentJustification::Shard(vec![0xaa, 0xbb])],
            }
            .encode(),
        );
    }

    #[test]
    fn ce139_140_shard_count_cap() {
        assert_eq!(MAX_SEGMENT_SHARDS_PER_REQUEST, 2 * 3072);
        let at_cap = SegmentShardRequest {
            erasure_root: h32(0),
            shard_index: 0,
            segment_indices: vec![0; MAX_SEGMENT_SHARDS_PER_REQUEST],
        };
        assert!(at_cap.validate_shard_count());
        let over = SegmentShardRequest {
            erasure_root: h32(0),
            shard_index: 0,
            segment_indices: vec![0; MAX_SEGMENT_SHARDS_PER_REQUEST + 1],
        };
        assert!(!over.validate_shard_count());
    }

    // --- CE 148: Segment request --------------------------------------------

    #[test]
    fn ce148_request_vector() {
        let req = SegmentRequest {
            segments_root: h32(0x21),
            segment_indices: vec![0x0001, 0x0002],
        };
        let mut expected = h32(0x21).to_vec();
        expected.push(0x02); // compact(2)
        expected.extend_from_slice(&[0x01, 0x00]);
        expected.extend_from_slice(&[0x02, 0x00]);
        assert_eq!(req.encode(), expected);
    }

    #[test]
    fn ce148_request_empty_vector() {
        let req = SegmentRequest {
            segments_root: h32(0x21),
            segment_indices: vec![],
        };
        let mut expected = h32(0x21).to_vec();
        expected.push(0x00);
        assert_eq!(req.encode(), expected);
    }

    #[test]
    fn ce148_request_roundtrip() {
        roundtrip(&SegmentRequest {
            segments_root: h32(0x21),
            segment_indices: vec![0x0001, 0x0002],
        });
        roundtrip(&SegmentRequest {
            segments_root: h32(0x21),
            segment_indices: vec![],
        });
    }

    #[test]
    fn ce148_request_truncated_errs() {
        truncated_errs::<SegmentRequest>(
            &SegmentRequest {
                segments_root: h32(0x21),
                segment_indices: vec![0x0001, 0x0002],
            }
            .encode(),
        );
    }

    #[test]
    fn ce148_response_vector() {
        let resp = SegmentResponse {
            segments: vec![vec![0xaa], vec![]],
            import_proof: vec![h32(0x11), h32(0x22)],
        };
        let mut expected = vec![0x02u8, 0x01, 0xaa, 0x00]; // [Segment]
        expected.push(0x02); // compact(2) import proof
        expected.extend_from_slice(&h32(0x11));
        expected.extend_from_slice(&h32(0x22));
        assert_eq!(resp.encode(), expected);
    }

    #[test]
    fn ce148_response_roundtrip() {
        roundtrip(&SegmentResponse {
            segments: vec![vec![0xaa], vec![]],
            import_proof: vec![h32(0x11), h32(0x22)],
        });
    }

    #[test]
    fn ce148_response_truncated_errs() {
        truncated_errs::<SegmentResponse>(
            &SegmentResponse {
                segments: vec![vec![0xaa]],
                import_proof: vec![h32(0x11), h32(0x22)],
            }
            .encode(),
        );
    }

    #[test]
    fn ce148_segment_count_cap() {
        assert_eq!(MAX_SEGMENTS_PER_REQUEST, 3072);
        let at_cap = SegmentRequest {
            segments_root: h32(0),
            segment_indices: vec![0; MAX_SEGMENTS_PER_REQUEST],
        };
        assert!(at_cap.validate_segment_count());
        let over = SegmentRequest {
            segments_root: h32(0),
            segment_indices: vec![0; MAX_SEGMENTS_PER_REQUEST + 1],
        };
        assert!(!over.validate_segment_count());
    }

    // --- CE 146: Bundle submission ------------------------------------------

    #[test]
    fn ce146_vector() {
        let sub = BundleSubmission {
            core_index: 0x0102,
            mappings: vec![(h32(0x11), h32(0x22)), (h32(0x33), h32(0x44))],
            work_package: vec![0xaa, 0xbb],
            extrinsics: vec![vec![0xde], vec![0xad]],
            segments: vec![vec![0x01, 0x02]],
            import_proof: vec![h32(0x55)],
        };
        let mut expected = vec![0x02u8, 0x01]; // Core Index u16 LE
        expected.push(0x02); // compact(2) mappings
        expected.extend_from_slice(&h32(0x11));
        expected.extend_from_slice(&h32(0x22));
        expected.extend_from_slice(&h32(0x33));
        expected.extend_from_slice(&h32(0x44));
        expected.push(0x02); // Work-Package
        expected.push(0xaa);
        expected.push(0xbb);
        expected.push(0x02); // [Extrinsic]
        expected.push(0x01);
        expected.push(0xde);
        expected.push(0x01);
        expected.push(0xad);
        expected.push(0x01); // [Segment]
        expected.push(0x02);
        expected.push(0x01);
        expected.push(0x02);
        expected.push(0x01); // [Import-Proof]
        expected.extend_from_slice(&h32(0x55));
        assert_eq!(sub.encode(), expected);
    }

    #[test]
    fn ce146_empty_vector() {
        let sub = BundleSubmission {
            core_index: 0,
            mappings: vec![],
            work_package: vec![],
            extrinsics: vec![],
            segments: vec![],
            import_proof: vec![],
        };
        assert_eq!(sub.encode(), vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn ce146_roundtrip() {
        roundtrip(&BundleSubmission {
            core_index: 0x0102,
            mappings: vec![(h32(0x11), h32(0x22))],
            work_package: vec![0xaa, 0xbb],
            extrinsics: vec![vec![0xde], vec![]],
            segments: vec![vec![0x01, 0x02]],
            import_proof: vec![h32(0x55)],
        });
        roundtrip(&BundleSubmission {
            core_index: 0,
            mappings: vec![],
            work_package: vec![],
            extrinsics: vec![],
            segments: vec![],
            import_proof: vec![],
        });
    }

    #[test]
    fn ce146_truncated_errs() {
        truncated_errs::<BundleSubmission>(
            &BundleSubmission {
                core_index: 0x0102,
                mappings: vec![(h32(0x11), h32(0x22))],
                work_package: vec![0xaa, 0xbb],
                extrinsics: vec![vec![0xde]],
                segments: vec![vec![0x01, 0x02]],
                import_proof: vec![h32(0x55)],
            }
            .encode(),
        );
    }

    #[test]
    fn ce146_work_package_cap() {
        assert_eq!(WORK_PACKAGE_MAX, 200 * 1024);
        let at_cap = BundleSubmission {
            core_index: 0,
            mappings: vec![],
            work_package: vec![0; WORK_PACKAGE_MAX],
            extrinsics: vec![],
            segments: vec![],
            import_proof: vec![],
        };
        assert!(at_cap.validate_work_package_size());
        let over = BundleSubmission {
            core_index: 0,
            mappings: vec![],
            work_package: vec![0; WORK_PACKAGE_MAX + 1],
            extrinsics: vec![],
            segments: vec![],
            import_proof: vec![],
        };
        assert!(!over.validate_work_package_size());
    }
}
