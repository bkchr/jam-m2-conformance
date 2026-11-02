//! Codecs for CE 131/132 (tickets), 133 (WP submission), 134 (WP sharing),
//! 135 (report distribution) and 136 (WR request) per `jam-np/simple.md`.

use codec::{Decode, Encode, Input, Output};
use jam_std_common::WorkReport;
use jam_types::{WorkPackageHash, WorkReportHash};

/// CE 131/132: Safrole ticket distribution (`simple.md:305-349`).
///
/// `Ticket = Attempt ++ Bandersnatch RingVRF Proof` (`simple.md:340-342`).
/// Protocols 131 and 132 share this wire shape; they differ only in which
/// distribution step they are used for (`simple.md:314-316`).
pub const TICKET_PROOF_LEN: usize = 784;

/// A Safrole ticket: an attempt byte followed by the RingVRF proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ticket {
    /// Ticket attempt.
    ///
    /// How many attempts a validator may make is a protocol parameter
    /// (`tickets_per_validator`), not a wire constant, and the range is judged
    /// by the N2 lane's `n2_gen_attempt_in_range`. The decoder deliberately
    /// does not enforce it: see [`Ticket`]'s `Decode`.
    pub attempt: u8,
    /// Bandersnatch RingVRF proof.
    pub proof: [u8; TICKET_PROOF_LEN],
}

impl Encode for Ticket {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        dest.push_byte(self.attempt);
        dest.write(&self.proof);
    }
}

/// Decodes the wire shape and nothing more. The attempt is *not* range-checked
/// here.
///
/// It used to be, against a hard-coded `attempt <= 1`. Under tiny a validator
/// makes four attempts, so every ticket numbered 2 or 3 failed to decode and
/// was dropped by the caller — silently, because a frame that will not decode
/// is skipped rather than reported. The node had sent it correctly, the
/// harness never saw it, and the lane then recorded that the node had not sent
/// it: `n2_proxy_duty_forwarded` failed in every run that proxied such a
/// ticket (`sessions/fwd-2`: one ticket, attempt 2, forwarded to all five
/// validators one slot after it arrived, graded as reaching none of them), and
/// the N1 and N2 ticket sets were short by the same frames.
///
/// A range the protocol parameters set does not belong in a decoder: the N2
/// lane judges it as `n2_gen_attempt_in_range`, where an out-of-range attempt
/// is a reportable failure instead of an invisible one.
impl Decode for Ticket {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        let attempt = input.read_byte()?;
        let mut proof = [0u8; TICKET_PROOF_LEN];
        input.read(&mut proof)?;
        Ok(Self { attempt, proof })
    }
}

/// CE 131/132 message: `Epoch Index ++ Ticket` (`simple.md:346`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Encode, Decode)]
pub struct TicketDistribution {
    /// Epoch the ticket will be used in.
    pub epoch_index: u32,
    /// The distributed ticket.
    pub ticket: Ticket,
}

/// CE 133: Work-package submission (`simple.md:351-376`).
///
/// The initial message `Core Index ++ Work-Package` is limited to this many
/// bytes so guarantors cannot be forced to download huge work-packages before
/// checking authorization (`simple.md:362-364`).
pub const WORK_PACKAGE_INITIAL_MAX: u32 = 2 + 200 * 1024;

/// CE 133 message set: the initial `Core Index ++ Work-Package` message
/// (`simple.md:372`) and the `[Extrinsic]` message (`simple.md:373`).
///
/// The two protocol messages are separate wire values, so this type offers
/// per-message [`encode_initial`](Self::encode_initial) /
/// [`encode_extrinsics`](Self::encode_extrinsics) with matching decoders
/// rather than a single combined `Encode`/`Decode`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkPackageSubmission {
    /// Core index the work-package is destined for.
    pub core_index: u16,
    /// Raw GP-encoded `Work-Package` (`simple.md:367`).
    // TODO(P1): typed GP WorkPackage once m2-reference exposes it.
    pub work_package: Vec<u8>,
    /// Extrinsic data referenced by the work-package (`simple.md:368`).
    pub extrinsics: Vec<Vec<u8>>,
}

impl WorkPackageSubmission {
    /// Message 1: `Core Index ++ Work-Package` (`simple.md:372`).
    pub fn encode_initial(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + self.work_package.len());
        self.core_index.encode_to(&mut out);
        out.extend_from_slice(&self.work_package);
        out
    }

    /// Decode message 1 into `(core_index, work_package)`.
    pub fn decode_initial(input: &mut &[u8]) -> Result<(u16, Vec<u8>), codec::Error> {
        let core_index = u16::decode(input)?;
        let work_package = core::mem::take(input).to_vec();
        Ok((core_index, work_package))
    }

    /// Message 2: `[Extrinsic]` (`simple.md:373`).
    pub fn encode_extrinsics(&self) -> Vec<u8> {
        self.extrinsics.encode()
    }

    /// Decode message 2 into the extrinsic sequence.
    pub fn decode_extrinsics(input: &mut &[u8]) -> Result<Vec<Vec<u8>>, codec::Error> {
        Vec::<Vec<u8>>::decode(input)
    }

    /// Whether message 1 (`Core Index ++ Work-Package`) is within
    /// [`WORK_PACKAGE_INITIAL_MAX`].
    pub fn validate_initial_size(&self) -> bool {
        self.work_package.len() + 2 <= WORK_PACKAGE_INITIAL_MAX as usize
    }
}

/// CE 134: Work-package sharing (`simple.md:406-458`).
///
/// First message: `Core Index ++ Shard Count ++ Segments-Root Mappings`
/// (`simple.md:453`).
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct SharingContext {
    /// Core index of the shared work-package.
    pub core_index: u16,
    /// Number of erasure-coded shards to generate for the bundle.
    pub shard_count: u16,
    /// Work-package hash to segments-root mappings (`simple.md:449`).
    pub mappings: Vec<(WorkPackageHash, [u8; 32])>,
}

/// CE 134 second message: `Work-Package Bundle` (`simple.md:454`).
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct SharingBundle {
    /// The encoded work-package bundle.
    pub bundle: Vec<u8>,
}

/// CE 134 reply: `Work-Report Hash ++ Ed25519 Signature` (`simple.md:456`).
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct SharingReply {
    /// Hash of the refined work-report.
    pub report_hash: WorkReportHash,
    /// Guarantee signature over the work-report.
    pub signature: [u8; 64],
}

/// CE 135: Work-report distribution (`simple.md:460-485`).
///
/// `Guaranteed Work-Report = Work-Report ++ Slot ++ len++[Validator Index ++
/// Ed25519 Signature]` (`simple.md:478`).
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct GuaranteedWorkReport {
    /// The guaranteed work-report.
    pub report: WorkReport,
    /// Slot in which the report could be included on chain.
    pub slot: u32,
    /// Validator index / signature pairs (`simple.md:478`).
    pub signatures: Vec<(u16, [u8; 64])>,
}

/// CE 136: Work-report request (`simple.md:487-504`).
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct WorkReportRequest {
    /// Hash of the requested work-report.
    pub report_hash: WorkReportHash,
}

/// CE 136 reply: `Work-Report` (`simple.md:502`).
#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct WorkReportReply {
    /// The requested work-report.
    pub report: WorkReport,
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::{Decode, Encode};
    use jam_std_common::{WorkPackageSpec, WorkReport};
    use jam_types::{AuthTrace, RefineContext};

    /// 784-byte proof with `byte[i] = (i + seed) mod 256`.
    fn proof(seed: u8) -> [u8; TICKET_PROOF_LEN] {
        let mut p = [0u8; TICKET_PROOF_LEN];
        for (i, b) in p.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(seed);
        }
        p
    }

    /// 64-byte Ed25519 signature with `sig[i] = (i + offset) mod 256`.
    fn sig64(offset: u8) -> [u8; 64] {
        core::array::from_fn(|i| (i as u8).wrapping_add(offset))
    }

    /// Minimal all-zero `WorkReport`. Encodes to `[0u8; 310]` (pinned below).
    fn sample_work_report() -> WorkReport {
        WorkReport {
            package_spec: WorkPackageSpec {
                hash: [0u8; 32].into(),
                len: 0,
                erasure_root: [0u8; 32].into(),
                erasure_shards: 0,
                exports_root: [0u8; 32].into(),
                exports_count: 0,
            },
            context: RefineContext {
                anchor: [0u8; 32].into(),
                anchor_slot: 0,
                state_root: [0u8; 32].into(),
                beefy_root: [0u8; 32].into(),
                lookup_anchor: [0u8; 32].into(),
                lookup_anchor_slot: 0,
                lookup_anchor_state_root: [0u8; 32].into(),
                prerequisites: Default::default(),
            },
            core_index: 0,
            authorizer_hash: [0u8; 32].into(),
            auth_gas_used: 0,
            auth_output: AuthTrace::new(),
            sr_lookup: Default::default(),
            results: Default::default(),
        }
    }

    // --- CE 131/132: Ticket -------------------------------------------------

    #[test]
    fn ticket_vector_attempt_0() {
        let t = Ticket {
            attempt: 0,
            proof: proof(0),
        };
        let bytes = t.encode();
        assert_eq!(bytes.len(), 1 + TICKET_PROOF_LEN);
        assert_eq!(bytes[0], 0);
        assert_eq!(&bytes[1..], &proof(0)[..]);
    }

    #[test]
    fn ticket_vector_attempt_1() {
        let t = Ticket {
            attempt: 1,
            proof: proof(1),
        };
        let bytes = t.encode();
        assert_eq!(bytes[0], 1);
        assert_eq!(&bytes[1..], &proof(1)[..]);
    }

    /// Any attempt byte decodes. The per-validator attempt count is a
    /// protocol parameter — four under tiny — so a decoder that admits only
    /// 0 and 1 drops conforming tickets, and drops them where nothing can
    /// report it. Whether an attempt is in range is the N2 lane's question.
    #[test]
    fn ticket_decodes_every_attempt_byte() {
        for attempt in [0u8, 1, 2, 3, 0x7f, 0xff] {
            let bytes = Ticket {
                attempt,
                proof: proof(attempt),
            }
            .encode();
            let mut input: &[u8] = &bytes[..];
            let decoded = Ticket::decode(&mut input).expect("every attempt byte decodes");
            assert_eq!(decoded.attempt, attempt);
        }
    }

    /// A truncated proof is still a decode failure: that is a wire-shape
    /// error, not a parameter one.
    #[test]
    fn ticket_rejects_a_short_proof() {
        let mut input: &[u8] = &[0u8, 0xaa, 0xbb];
        assert!(Ticket::decode(&mut input).is_err());
    }

    #[test]
    fn ticket_roundtrip() {
        for attempt in [0u8, 1, 2, 3] {
            let t = Ticket {
                attempt,
                proof: proof(attempt),
            };
            let bytes = t.encode();
            let mut input: &[u8] = &bytes[..];
            let decoded = Ticket::decode(&mut input).unwrap();
            assert!(input.is_empty());
            assert_eq!(decoded, t);
        }
    }

    #[test]
    fn ticket_truncated_decode_errs() {
        // Missing proof entirely.
        let mut input: &[u8] = &[0u8];
        assert!(Ticket::decode(&mut input).is_err());
        // Attempt + only 783 proof bytes.
        let mut bytes = vec![0u8];
        bytes.extend_from_slice(&[0u8; TICKET_PROOF_LEN - 1]);
        let mut input: &[u8] = &bytes[..];
        assert!(Ticket::decode(&mut input).is_err());
        // Empty input.
        let mut input: &[u8] = &[];
        assert!(Ticket::decode(&mut input).is_err());
    }

    #[test]
    fn ticket_distribution_vector() {
        let td = TicketDistribution {
            epoch_index: 0x1122_3344,
            ticket: Ticket {
                attempt: 0,
                proof: proof(0),
            },
        };
        let bytes = td.encode();
        assert_eq!(bytes.len(), 4 + 1 + TICKET_PROOF_LEN);
        assert_eq!(&bytes[..4], &[0x44, 0x33, 0x22, 0x11]); // u32 LE
        assert_eq!(bytes[4], 0); // attempt
        assert_eq!(&bytes[5..], &proof(0)[..]); // proof
    }

    #[test]
    fn ticket_distribution_roundtrip() {
        let td = TicketDistribution {
            epoch_index: 42,
            ticket: Ticket {
                attempt: 1,
                proof: proof(9),
            },
        };
        let bytes = td.encode();
        let mut input: &[u8] = &bytes[..];
        let decoded = TicketDistribution::decode(&mut input).unwrap();
        assert!(input.is_empty());
        assert_eq!(decoded, td);
    }

    // --- CE 133: Work-package submission ------------------------------------

    #[test]
    fn ce133_initial_message_vector() {
        let sub = WorkPackageSubmission {
            core_index: 0x0102,
            work_package: vec![0xaa, 0xbb, 0xcc],
            extrinsics: vec![],
        };
        // `--> Core Index ++ Work-Package` (simple.md:372): u16 LE ++ raw GP bytes.
        assert_eq!(sub.encode_initial(), vec![0x02, 0x01, 0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn ce133_extrinsics_message_vector() {
        let sub = WorkPackageSubmission {
            core_index: 0,
            work_package: vec![],
            extrinsics: vec![vec![0xde, 0xad], vec![], vec![0x01, 0x02, 0x03]],
        };
        // `--> [Extrinsic]` (simple.md:373): compact(3) ++ each compact(len) ++ bytes.
        assert_eq!(
            sub.encode_extrinsics(),
            vec![0x03, 0x02, 0xde, 0xad, 0x00, 0x03, 0x01, 0x02, 0x03]
        );
    }

    #[test]
    fn ce133_decode_initial() {
        let mut input: &[u8] = &[0x02, 0x01, 0xaa, 0xbb, 0xcc];
        let (core_index, work_package) = WorkPackageSubmission::decode_initial(&mut input).unwrap();
        assert!(input.is_empty());
        assert_eq!(core_index, 0x0102);
        assert_eq!(work_package, vec![0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn ce133_decode_extrinsics() {
        let mut input: &[u8] = &[0x03, 0x02, 0xde, 0xad, 0x00, 0x03, 0x01, 0x02, 0x03];
        let extrinsics = WorkPackageSubmission::decode_extrinsics(&mut input).unwrap();
        assert!(input.is_empty());
        assert_eq!(
            extrinsics,
            vec![vec![0xde, 0xad], vec![], vec![0x01, 0x02, 0x03]]
        );
    }

    #[test]
    fn ce133_validate_initial_size() {
        assert_eq!(WORK_PACKAGE_INITIAL_MAX, 2 + 200 * 1024);
        // At the cap: 2 (core index) + 200*1024 (work-package).
        let at_cap = WorkPackageSubmission {
            core_index: 0,
            work_package: vec![0u8; 200 * 1024],
            extrinsics: vec![],
        };
        assert!(at_cap.validate_initial_size());
        // One byte over the cap.
        let over = WorkPackageSubmission {
            core_index: 0,
            work_package: vec![0u8; 200 * 1024 + 1],
            extrinsics: vec![],
        };
        assert!(!over.validate_initial_size());
    }

    #[test]
    fn ce133_initial_truncated_errs() {
        // Only one byte: not enough for the u16 core index.
        let mut input: &[u8] = &[0x02];
        assert!(WorkPackageSubmission::decode_initial(&mut input).is_err());
        // Extrinsics message promises 2 items but carries none.
        let mut input: &[u8] = &[0x08];
        assert!(WorkPackageSubmission::decode_extrinsics(&mut input).is_err());
    }

    // --- CE 134: Work-package sharing ---------------------------------------

    #[test]
    fn ce134_sharing_context_vector() {
        let ctx = SharingContext {
            core_index: 7,
            shard_count: 5,
            mappings: vec![
                (WorkPackageHash::from([1u8; 32]), [2u8; 32]),
                (WorkPackageHash::from([3u8; 32]), [4u8; 32]),
            ],
        };
        let bytes = ctx.encode();
        assert_eq!(bytes.len(), 4 + 1 + 4 * 32);
        assert_eq!(&bytes[..4], &[0x07, 0x00, 0x05, 0x00]); // core ++ shard count (u16 LE)
        assert_eq!(bytes[4], 0x02); // compact(2) mappings
        assert_eq!(&bytes[5..37], &[1u8; 32]);
        assert_eq!(&bytes[37..69], &[2u8; 32]);
        assert_eq!(&bytes[69..101], &[3u8; 32]);
        assert_eq!(&bytes[101..133], &[4u8; 32]);
    }

    #[test]
    fn ce134_sharing_context_roundtrip() {
        let ctx = SharingContext {
            core_index: 3,
            shard_count: 11,
            mappings: vec![(WorkPackageHash::from([7u8; 32]), [8u8; 32])],
        };
        let bytes = ctx.encode();
        let mut input: &[u8] = &bytes[..];
        let decoded = SharingContext::decode(&mut input).unwrap();
        assert!(input.is_empty());
        assert_eq!(decoded, ctx);
    }

    #[test]
    fn ce134_sharing_bundle_vector() {
        let b = SharingBundle {
            bundle: vec![0xaa; 4],
        };
        assert_eq!(b.encode(), vec![0x04, 0xaa, 0xaa, 0xaa, 0xaa]);
    }

    #[test]
    fn ce134_sharing_reply_vector() {
        let reply = SharingReply {
            report_hash: WorkReportHash::from([0x42; 32]),
            signature: sig64(0),
        };
        let bytes = reply.encode();
        assert_eq!(bytes.len(), 32 + 64);
        assert_eq!(&bytes[..32], &[0x42; 32]);
        assert_eq!(&bytes[32..], &sig64(0)[..]);
    }

    #[test]
    fn ce134_sharing_reply_roundtrip() {
        let reply = SharingReply {
            report_hash: WorkReportHash::from([0x24; 32]),
            signature: sig64(0x10),
        };
        let bytes = reply.encode();
        let mut input: &[u8] = &bytes[..];
        let decoded = SharingReply::decode(&mut input).unwrap();
        assert!(input.is_empty());
        assert_eq!(decoded, reply);
    }

    // --- CE 135: Work-report distribution ------------------------------------

    #[test]
    fn ce135_guaranteed_report_vector() {
        let report = sample_work_report();
        let report_bytes = report.encode();
        // Pins the GP Work-Report encoding of the minimal report.
        assert_eq!(report_bytes, vec![0u8; 310]);

        let gwr = GuaranteedWorkReport {
            report,
            slot: 0x0102_0304,
            signatures: vec![
                (0x0102, sig64(0x00)),
                (0x0304, sig64(0x40)),
                (0x0506, sig64(0x80)),
            ],
        };
        let bytes = gwr.encode();
        let mut expected = Vec::new();
        expected.extend_from_slice(&[0u8; 310]); // Work-Report
        expected.extend_from_slice(&[0x04, 0x03, 0x02, 0x01]); // Slot u32 LE
        expected.push(0x03); // compact(3) signatures
        for (idx, off) in [(0x0102u16, 0x00u8), (0x0304, 0x40), (0x0506, 0x80)] {
            expected.extend_from_slice(&idx.to_le_bytes()); // Validator Index
            expected.extend_from_slice(&sig64(off)); // Ed25519 Signature
        }
        assert_eq!(bytes, expected);
    }

    #[test]
    fn ce135_guaranteed_report_roundtrip() {
        let gwr = GuaranteedWorkReport {
            report: sample_work_report(),
            slot: 9,
            signatures: vec![(0x0007, sig64(0x20))],
        };
        let bytes = gwr.encode();
        let mut input: &[u8] = &bytes[..];
        let decoded = GuaranteedWorkReport::decode(&mut input).unwrap();
        assert!(input.is_empty());
        assert_eq!(decoded, gwr);
    }

    // --- CE 136: Work-report request -----------------------------------------

    #[test]
    fn ce136_request_vector() {
        let req = WorkReportRequest {
            report_hash: WorkReportHash::from([0x13; 32]),
        };
        assert_eq!(req.encode(), vec![0x13; 32]);
    }

    #[test]
    fn ce136_reply_vector() {
        let reply = WorkReportReply {
            report: sample_work_report(),
        };
        assert_eq!(reply.encode(), vec![0u8; 310]);
    }

    #[test]
    fn ce136_roundtrips() {
        let req = WorkReportRequest {
            report_hash: WorkReportHash::from([0x31; 32]),
        };
        let bytes = req.encode();
        let mut input: &[u8] = &bytes[..];
        assert_eq!(WorkReportRequest::decode(&mut input).unwrap(), req);
        assert!(input.is_empty());

        let reply = WorkReportReply {
            report: sample_work_report(),
        };
        let bytes = reply.encode();
        let mut input: &[u8] = &bytes[..];
        assert_eq!(WorkReportReply::decode(&mut input).unwrap(), reply);
        assert!(input.is_empty());
    }

    #[test]
    fn ce136_truncated_errs() {
        // Request hash truncated to 16 bytes.
        let mut input: &[u8] = &[0x13; 16];
        assert!(WorkReportRequest::decode(&mut input).is_err());
        // Reply report truncated.
        let bytes = [0u8; 100];
        let mut input: &[u8] = &bytes[..];
        assert!(WorkReportReply::decode(&mut input).is_err());
    }
}
