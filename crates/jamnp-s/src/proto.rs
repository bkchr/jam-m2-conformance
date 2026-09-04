//! Protocol dispatch layer for JAMNP-S.
//!
//! [`Message`] wraps every typed UP/CE codec value from `crate::codec` and
//! dispatches on the stream-kind byte: [`encode_message`] produces
//! `(kind, payload)`, [`decode_message`]/[`from_kind_and_payload`] recover a
//! [`Message`] from `(kind, payload)`, and [`frame_message`] wraps the payload
//! in the wire frame from `crate::framing`. These are the pure helpers the m2
//! emulator drives; the quinn connection wiring lands with m2-emu.
//!
//! ## Per-kind decode target
//!
//! Every protocol whose message is a single SCALE value decodes to exactly that
//! value. Protocols with multiple messages per stream decode as follows:
//!
//! | Kind | Decodes to |
//! |------|------------|
//! | UP 0 | `Handshake` (first message; announcements are separate) |
//! | CE 128/129/136/137/138/139/140/143/147/148 | request side; falls back to the server-response side when the payload is a response |
//! | CE 133 | `initial` (`WorkPackageSubmission::decode_initial`) |
//! | CE 134 | `SharingContext` (message 1; bundle/reply are separate) |
//!
//! Kinds 130 and 149..=152 are spec-known but refused ([`ProtoError::RefusedKind`]);
//! any other byte is [`ProtoError::UnknownKind`].

use codec::Decode;
use std::fmt;

use crate::codec::{ce128_129, ce131_136, ce137_148, ce141_145, up0};
use crate::framing;

/// A decoded UP/CE message, one variant per protocol.
#[derive(Debug, Clone)]
pub enum Message {
    Up0Handshake(up0::Handshake),
    Up0Announcement(up0::Announcement),
    Ce128BlockRequest(ce128_129::BlockRequest),
    Ce128BlockResponse(ce128_129::BlockResponse),
    Ce129StateRequest(ce128_129::StateRequest),
    Ce129StateResponse(ce128_129::StateResponse),
    Ce131Ticket(ce131_136::TicketDistribution),
    Ce132Ticket(ce131_136::TicketDistribution),
    Ce133Submission(ce131_136::WorkPackageSubmission),
    Ce134SharingContext(ce131_136::SharingContext),
    Ce134SharingBundle(ce131_136::SharingBundle),
    Ce134Reply(ce131_136::SharingReply),
    Ce135Report(ce131_136::GuaranteedWorkReport),
    Ce136Request(ce131_136::WorkReportRequest),
    Ce136Reply(ce131_136::WorkReportReply),
    Ce137Request(ce137_148::ShardRequest),
    Ce137Response(ce137_148::ShardResponse),
    Ce138Request(ce137_148::ShardRequest),
    Ce138Response(ce137_148::AuditShardResponse),
    Ce139Request(ce137_148::SegmentShardRequest),
    Ce139Response(ce137_148::SegmentShardsResponse),
    Ce140Request(ce137_148::SegmentShardRequest),
    Ce140Response(ce137_148::ProvenSegmentShardsResponse),
    Ce141Assurance(ce141_145::Assurance),
    Ce142Announce(ce141_145::PreimageAnnouncement),
    Ce143Request(ce141_145::PreimageRequest),
    Ce143Reply(ce141_145::PreimageReply),
    Ce144Announce(ce141_145::AuditAnnouncementMsg),
    Ce145Judgment(ce141_145::Judgment),
    Ce146Submission(ce137_148::BundleSubmission),
    Ce147Request(ce137_148::BundleRequest),
    Ce147Response(ce137_148::BundleResponse),
    Ce148Request(ce137_148::SegmentRequest),
    Ce148Response(ce137_148::SegmentResponse),
}

impl Message {
    /// The UP/CE stream-kind byte for this message.
    pub fn kind(&self) -> u8 {
        use crate::framing::{
            CE128, CE129, CE131, CE132, CE133, CE134, CE135, CE136, CE137, CE138, CE139, CE140,
            CE141, CE142, CE143, CE144, CE145, CE146, CE147, CE148, UP,
        };
        match self {
            Message::Up0Handshake(_) | Message::Up0Announcement(_) => UP,
            Message::Ce128BlockRequest(_) | Message::Ce128BlockResponse(_) => CE128,
            Message::Ce129StateRequest(_) | Message::Ce129StateResponse(_) => CE129,
            Message::Ce131Ticket(_) => CE131,
            Message::Ce132Ticket(_) => CE132,
            Message::Ce133Submission(_) => CE133,
            Message::Ce134SharingContext(_)
            | Message::Ce134SharingBundle(_)
            | Message::Ce134Reply(_) => CE134,
            Message::Ce135Report(_) => CE135,
            Message::Ce136Request(_) | Message::Ce136Reply(_) => CE136,
            Message::Ce137Request(_) | Message::Ce137Response(_) => CE137,
            Message::Ce138Request(_) | Message::Ce138Response(_) => CE138,
            Message::Ce139Request(_) | Message::Ce139Response(_) => CE139,
            Message::Ce140Request(_) | Message::Ce140Response(_) => CE140,
            Message::Ce141Assurance(_) => CE141,
            Message::Ce142Announce(_) => CE142,
            Message::Ce143Request(_) | Message::Ce143Reply(_) => CE143,
            Message::Ce144Announce(_) => CE144,
            Message::Ce145Judgment(_) => CE145,
            Message::Ce146Submission(_) => CE146,
            Message::Ce147Request(_) | Message::Ce147Response(_) => CE147,
            Message::Ce148Request(_) | Message::Ce148Response(_) => CE148,
        }
    }
}

/// Encodes a message as `(kind, payload)`, the inputs to [`frame_message`].
pub fn encode_message(msg: &Message) -> Result<(u8, Vec<u8>), ProtoError> {
    use codec::Encode;
    let payload = match msg {
        Message::Up0Handshake(m) => m.encode(),
        Message::Up0Announcement(m) => m.encode(),
        Message::Ce128BlockRequest(m) => m.encode(),
        Message::Ce128BlockResponse(m) => m.encode(),
        Message::Ce129StateRequest(m) => m.encode(),
        Message::Ce129StateResponse(m) => m.encode(),
        Message::Ce131Ticket(m) | Message::Ce132Ticket(m) => m.encode(),
        Message::Ce133Submission(m) => m.encode_initial(),
        Message::Ce134SharingContext(m) => m.encode(),
        Message::Ce134SharingBundle(m) => m.encode(),
        Message::Ce134Reply(m) => m.encode(),
        Message::Ce135Report(m) => m.encode(),
        Message::Ce136Request(m) => m.encode(),
        Message::Ce136Reply(m) => m.encode(),
        Message::Ce137Request(m) | Message::Ce138Request(m) => m.encode(),
        Message::Ce137Response(m) => m.encode(),
        Message::Ce138Response(m) => m.encode(),
        Message::Ce139Request(m) | Message::Ce140Request(m) => m.encode(),
        Message::Ce139Response(m) => m.encode(),
        Message::Ce140Response(m) => m.encode(),
        Message::Ce141Assurance(m) => m.encode(),
        Message::Ce142Announce(m) => m.encode(),
        Message::Ce143Request(m) => m.encode(),
        Message::Ce143Reply(m) => m.encode(),
        Message::Ce144Announce(m) => m.encode(),
        Message::Ce145Judgment(m) => m.encode(),
        Message::Ce146Submission(m) => m.encode(),
        Message::Ce147Request(m) => m.encode(),
        Message::Ce147Response(m) => m.encode(),
        Message::Ce148Request(m) => m.encode(),
        Message::Ce148Response(m) => m.encode(),
    };
    Ok((msg.kind(), payload))
}

/// Dispatches on the stream-kind byte and SCALE-decodes the payload. See the
/// module docs for which message each kind decodes to.
pub fn from_kind_and_payload(kind: u8, payload: &[u8]) -> Result<Message, ProtoError> {
    use Message::*;
    match kind {
        framing::UP => decode_full::<up0::Handshake>(payload).map(Up0Handshake),
        framing::CE128 => decode_pair(payload, Ce128BlockRequest, Ce128BlockResponse),
        framing::CE129 => decode_pair(payload, Ce129StateRequest, Ce129StateResponse),
        framing::CE131 => decode_full::<ce131_136::TicketDistribution>(payload).map(Ce131Ticket),
        framing::CE132 => decode_full::<ce131_136::TicketDistribution>(payload).map(Ce132Ticket),
        framing::CE133 => ce131_136::WorkPackageSubmission::decode_initial(&mut &payload[..])
            .map(|(core_index, work_package)| {
                Ce133Submission(ce131_136::WorkPackageSubmission {
                    core_index,
                    work_package,
                    extrinsics: Vec::new(),
                })
            })
            .map_err(|e| ProtoError::Decode(e.to_string())),
        framing::CE134 => {
            decode_full::<ce131_136::SharingContext>(payload).map(Ce134SharingContext)
        }
        framing::CE135 => decode_full::<ce131_136::GuaranteedWorkReport>(payload).map(Ce135Report),
        framing::CE136 => decode_pair(payload, Ce136Request, Ce136Reply),
        framing::CE137 => decode_pair(payload, Ce137Request, Ce137Response),
        framing::CE138 => decode_pair(payload, Ce138Request, Ce138Response),
        framing::CE139 => decode_pair(payload, Ce139Request, Ce139Response),
        framing::CE140 => decode_pair(payload, Ce140Request, Ce140Response),
        framing::CE141 => decode_full::<ce141_145::Assurance>(payload).map(Ce141Assurance),
        framing::CE142 => {
            decode_full::<ce141_145::PreimageAnnouncement>(payload).map(Ce142Announce)
        }
        framing::CE143 => decode_pair(payload, Ce143Request, Ce143Reply),
        framing::CE144 => {
            decode_full::<ce141_145::AuditAnnouncementMsg>(payload).map(Ce144Announce)
        }
        framing::CE145 => decode_full::<ce141_145::Judgment>(payload).map(Ce145Judgment),
        framing::CE146 => decode_full::<ce137_148::BundleSubmission>(payload).map(Ce146Submission),
        framing::CE147 => decode_pair(payload, Ce147Request, Ce147Response),
        framing::CE148 => decode_pair(payload, Ce148Request, Ce148Response),
        // CE 130 (reserved) and GRANDPA 149..=152 are spec-known but refused.
        130 | 149..=152 => Err(ProtoError::RefusedKind(kind)),
        _ => Err(ProtoError::UnknownKind(kind)),
    }
}

/// Alias of [`from_kind_and_payload`]; the entry point the emulator uses when a
/// frame `(kind, content)` arrives from a peer.
pub fn decode_message(kind: u8, bytes: &[u8]) -> Result<Message, ProtoError> {
    from_kind_and_payload(kind, bytes)
}

/// Wraps `payload` in a wire frame for `kind` (`[kind] ++ [len: u32 LE] ++
/// [payload]`, see [`framing::frame`]).
pub fn frame_message(kind: u8, payload: &[u8]) -> Vec<u8> {
    framing::frame(kind, payload)
}

/// SCALE-decodes `T` from `payload`, requiring the whole payload to be consumed.
fn decode_full<T: Decode>(payload: &[u8]) -> Result<T, ProtoError> {
    let mut input: &[u8] = payload;
    let value = T::decode(&mut input).map_err(|e| ProtoError::Decode(e.to_string()))?;
    if input.is_empty() {
        Ok(value)
    } else {
        Err(ProtoError::Decode("trailing bytes after message".into()))
    }
}

/// Decodes the request side of a request/response kind, falling back to the
/// server-response side when the payload does not fully decode as a request.
fn decode_pair<R: Decode, S: Decode>(
    payload: &[u8],
    request: fn(R) -> Message,
    response: fn(S) -> Message,
) -> Result<Message, ProtoError> {
    match decode_full::<R>(payload) {
        Ok(req) => Ok(request(req)),
        Err(_) => decode_full::<S>(payload).map(response),
    }
}

/// Errors produced while encoding or decoding protocol messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    /// The stream-kind byte is not part of the harness protocol surface.
    UnknownKind(u8),
    /// Spec-known stream kind refused by the harness (CE 130, GRANDPA 149..=152).
    RefusedKind(u8),
    /// The payload failed to SCALE-decode as the kind's message.
    Decode(String),
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtoError::UnknownKind(kind) => write!(f, "unknown stream kind {kind}"),
            ProtoError::RefusedKind(kind) => write!(f, "refused stream kind {kind}"),
            ProtoError::Decode(err) => write!(f, "message decode failed: {err}"),
        }
    }
}

impl std::error::Error for ProtoError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{
        ce128_129::{BlockRequest, BlockResponse, Direction, StateRequest, StateResponse},
        ce131_136::{
            GuaranteedWorkReport, SharingBundle, SharingContext, SharingReply, Ticket,
            TicketDistribution, WorkPackageSubmission, WorkReportReply, WorkReportRequest,
            TICKET_PROOF_LEN,
        },
        ce137_148::{
            AuditShardResponse, BundleRequest, BundleResponse, BundleSubmission, Justification,
            ProvenSegmentShardsResponse, SegmentJustification, SegmentRequest, SegmentResponse,
            SegmentShardRequest, SegmentShardsResponse, ShardRequest, ShardResponse,
        },
        ce141_145::{
            Announcement as AuditAnnouncement, Assurance, AuditAnnouncementMsg, Judgment,
            PreimageAnnouncement, PreimageReply, PreimageRequest,
        },
        up0::{Announcement as BlockAnnouncement, Final as Up0Final, Handshake as Up0Handshake},
    };
    use codec::Encode;
    use jam_std_common::{Block, Extrinsic, Header, ImmutableHeader, WorkPackageSpec, WorkReport};
    use jam_types::{AuthTrace, HeaderHash, RefineContext, WorkPackageHash, WorkReportHash};
    use std::sync::Arc;

    // --- Minimal codec fixtures (mirrors the codec modules' own test vectors) ---

    fn up0_final() -> Up0Final {
        Up0Final {
            header_hash: HeaderHash::from([0x11; 32]),
            slot: 0x0403_0201,
        }
    }

    fn up0_handshake() -> Up0Handshake {
        Up0Handshake {
            final_block: up0_final(),
            leaves: vec![],
        }
    }

    fn block_announcement() -> BlockAnnouncement {
        BlockAnnouncement {
            header: Header::genesis(),
            final_block: up0_final(),
        }
    }

    fn test_block() -> Block {
        Block {
            header: Arc::new(ImmutableHeader::from(Header::genesis())),
            extrinsic: Arc::new(Extrinsic::default()),
        }
    }

    fn sample_work_report() -> WorkReport {
        WorkReport {
            package_spec: WorkPackageSpec {
                hash: [0u8; 32].into(),
                len: 0,
                erasure_root: [0u8; 32].into(),
                exports_root: [0u8; 32].into(),
                exports_count: 0,
            },
            context: RefineContext {
                anchor: [0u8; 32].into(),
                state_root: [0u8; 32].into(),
                beefy_root: [0u8; 32].into(),
                lookup_anchor: [0u8; 32].into(),
                lookup_anchor_slot: 0,
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

    fn ticket() -> Ticket {
        Ticket {
            attempt: 0,
            proof: [0u8; TICKET_PROOF_LEN],
        }
    }

    fn sig64() -> [u8; 64] {
        [0u8; 64]
    }

    /// Every variant decodable from `(kind, payload)` alone: one per protocol,
    /// including the server-response side for request/response kinds.
    fn all_decodable_messages() -> Vec<Message> {
        use Message::*;
        vec![
            Up0Handshake(up0_handshake()),
            Ce128BlockRequest(BlockRequest {
                header_hash: HeaderHash::from([0xAA; 32]),
                direction: Direction::AscendingExclusive,
                max_blocks: 5,
            }),
            Ce128BlockResponse(BlockResponse { blocks: vec![] }),
            Ce129StateRequest(StateRequest {
                header_hash: HeaderHash::from([0xAA; 32]),
                start: [0x11; 31],
                end: [0x22; 31],
                max_size: 4096,
            }),
            Ce129StateResponse(StateResponse {
                boundary_nodes: vec![],
                entries: vec![],
            }),
            Ce131Ticket(TicketDistribution {
                epoch_index: 42,
                ticket: ticket(),
            }),
            Ce132Ticket(TicketDistribution {
                epoch_index: 43,
                ticket: ticket(),
            }),
            Ce133Submission(WorkPackageSubmission {
                core_index: 0x0102,
                work_package: vec![0xaa, 0xbb, 0xcc],
                extrinsics: vec![],
            }),
            Ce134SharingContext(SharingContext {
                core_index: 7,
                shard_count: 5,
                mappings: vec![(WorkPackageHash::from([1u8; 32]), [2u8; 32])],
            }),
            Ce135Report(GuaranteedWorkReport {
                report: sample_work_report(),
                slot: 0,
                signatures: vec![],
            }),
            Ce136Request(WorkReportRequest {
                report_hash: WorkReportHash::from([0x13; 32]),
            }),
            Ce136Reply(WorkReportReply {
                report: sample_work_report(),
            }),
            Ce137Request(ShardRequest {
                erasure_root: [0x11; 32],
                shard_index: 0x0102,
            }),
            Ce137Response(ShardResponse {
                bundle_shard: vec![0xaa, 0xbb, 0xcc],
                segment_shards: vec![],
                justification: Justification::Left([0x11; 32]),
            }),
            Ce138Request(ShardRequest {
                erasure_root: [0x11; 32],
                shard_index: 0x0102,
            }),
            Ce138Response(AuditShardResponse {
                bundle_shard: vec![0xde, 0xad],
                justification: Justification::Right([0x11; 32], [0x22; 32]),
            }),
            Ce139Request(SegmentShardRequest {
                erasure_root: [0x11; 32],
                shard_index: 0x0102,
                segment_indices: vec![0x0001],
            }),
            Ce139Response(SegmentShardsResponse {
                segment_shards: vec![vec![0xde]],
            }),
            Ce140Request(SegmentShardRequest {
                erasure_root: [0x11; 32],
                shard_index: 0x0102,
                segment_indices: vec![0x0001],
            }),
            Ce140Response(ProvenSegmentShardsResponse {
                segment_shards: vec![vec![0xde]],
                justifications: vec![SegmentJustification::Left([0x11; 32])],
            }),
            Ce141Assurance(Assurance {
                anchor: HeaderHash::from([0x11; 32]),
                bitfield: vec![0xaa],
                signature: sig64(),
            }),
            Ce142Announce(PreimageAnnouncement {
                service_id: 9,
                hash: [0x24; 32],
                length: 1000,
            }),
            Ce143Request(PreimageRequest { hash: [0x13; 32] }),
            Ce143Reply(PreimageReply {
                preimage: vec![0xde, 0xad, 0xbe, 0xef],
            }),
            Ce144Announce(AuditAnnouncementMsg {
                header_hash: HeaderHash::from([0x55; 32]),
                tranche: 0,
                announcement: AuditAnnouncement {
                    entries: vec![],
                    signature: sig64(),
                },
            }),
            Ce145Judgment(Judgment {
                epoch_index: 7,
                validator_index: 0x0005,
                validity: true,
                report_hash: [0xab; 32],
                signature: sig64(),
                guarantee: None,
            }),
            Ce146Submission(BundleSubmission {
                core_index: 0x0102,
                mappings: vec![],
                work_package: vec![],
                extrinsics: vec![],
                segments: vec![],
                import_proof: vec![],
            }),
            Ce147Request(BundleRequest {
                erasure_root: [0x13; 32],
            }),
            Ce147Response(BundleResponse {
                bundle: vec![0xde, 0xad],
            }),
            Ce148Request(SegmentRequest {
                segments_root: [0x21; 32],
                segment_indices: vec![0x0001],
            }),
            Ce148Response(SegmentResponse {
                segments: vec![vec![0xaa]],
                import_proof: vec![[0x11; 32]],
            }),
        ]
    }

    /// Variants reachable only via encoding (their kind's payload decodes to a
    /// different, protocol-order-mandated message).
    fn encode_only_messages() -> Vec<(Message, Vec<u8>)> {
        vec![
            (
                Message::Up0Announcement(block_announcement()),
                block_announcement().encode(),
            ),
            (
                Message::Ce134SharingBundle(SharingBundle {
                    bundle: vec![0xaa; 4],
                }),
                vec![0x04, 0xaa, 0xaa, 0xaa, 0xaa],
            ),
            (
                Message::Ce134Reply(SharingReply {
                    report_hash: WorkReportHash::from([0x42; 32]),
                    signature: sig64(),
                }),
                {
                    let mut v = vec![0x42; 32];
                    v.extend_from_slice(&sig64());
                    v
                },
            ),
        ]
    }

    #[test]
    fn decode_encode_roundtrips_every_protocol() {
        for msg in all_decodable_messages() {
            let (kind, payload) = encode_message(&msg).unwrap();
            let decoded = decode_message(kind, &payload).unwrap();
            assert_eq!(
                std::mem::discriminant(&decoded),
                std::mem::discriminant(&msg),
                "variant mismatch for kind {kind}"
            );
            let (dkind, dpayload) = encode_message(&decoded).unwrap();
            assert_eq!(
                (dkind, dpayload),
                (kind, payload),
                "byte roundtrip failed for kind {kind}"
            );
        }
    }

    #[test]
    fn encode_only_variants_carry_their_kind_and_wire_bytes() {
        for (msg, expected) in encode_only_messages() {
            let (kind, payload) = encode_message(&msg).unwrap();
            assert_eq!(kind, msg.kind());
            assert_eq!(payload, expected, "kind {kind} payload mismatch");
        }
    }

    #[test]
    fn kind_maps_to_stream_byte() {
        let cases: Vec<(Message, u8)> = vec![
            (Message::Up0Handshake(up0_handshake()), 0),
            (Message::Up0Announcement(block_announcement()), 0),
            (
                Message::Ce128BlockRequest(BlockRequest {
                    header_hash: HeaderHash::from([0; 32]),
                    direction: Direction::AscendingExclusive,
                    max_blocks: 1,
                }),
                128,
            ),
            (
                Message::Ce129StateRequest(StateRequest {
                    header_hash: HeaderHash::from([0; 32]),
                    start: [0; 31],
                    end: [0; 31],
                    max_size: 1,
                }),
                129,
            ),
            (
                Message::Ce131Ticket(TicketDistribution {
                    epoch_index: 1,
                    ticket: ticket(),
                }),
                131,
            ),
            (
                Message::Ce132Ticket(TicketDistribution {
                    epoch_index: 1,
                    ticket: ticket(),
                }),
                132,
            ),
            (
                Message::Ce133Submission(WorkPackageSubmission {
                    core_index: 0,
                    work_package: vec![],
                    extrinsics: vec![],
                }),
                133,
            ),
            (
                Message::Ce134SharingBundle(SharingBundle { bundle: vec![] }),
                134,
            ),
            (
                Message::Ce134Reply(SharingReply {
                    report_hash: WorkReportHash::from([0; 32]),
                    signature: [0; 64],
                }),
                134,
            ),
            (
                Message::Ce135Report(GuaranteedWorkReport {
                    report: sample_work_report(),
                    slot: 0,
                    signatures: vec![],
                }),
                135,
            ),
            (
                Message::Ce136Reply(WorkReportReply {
                    report: sample_work_report(),
                }),
                136,
            ),
            (
                Message::Ce137Response(ShardResponse {
                    bundle_shard: vec![],
                    segment_shards: vec![],
                    justification: Justification::Left([0; 32]),
                }),
                137,
            ),
            (
                Message::Ce138Response(AuditShardResponse {
                    bundle_shard: vec![],
                    justification: Justification::Left([0; 32]),
                }),
                138,
            ),
            (
                Message::Ce139Response(SegmentShardsResponse {
                    segment_shards: vec![],
                }),
                139,
            ),
            (
                Message::Ce140Response(ProvenSegmentShardsResponse {
                    segment_shards: vec![],
                    justifications: vec![],
                }),
                140,
            ),
            (
                Message::Ce141Assurance(Assurance {
                    anchor: HeaderHash::from([0; 32]),
                    bitfield: vec![],
                    signature: [0; 64],
                }),
                141,
            ),
            (
                Message::Ce142Announce(PreimageAnnouncement {
                    service_id: 0,
                    hash: [0; 32],
                    length: 0,
                }),
                142,
            ),
            (Message::Ce143Reply(PreimageReply { preimage: vec![] }), 143),
            (
                Message::Ce144Announce(AuditAnnouncementMsg {
                    header_hash: HeaderHash::from([0; 32]),
                    tranche: 0,
                    announcement: AuditAnnouncement {
                        entries: vec![],
                        signature: [0; 64],
                    },
                }),
                144,
            ),
            (
                Message::Ce145Judgment(Judgment {
                    epoch_index: 0,
                    validator_index: 0,
                    validity: true,
                    report_hash: [0; 32],
                    signature: [0; 64],
                    guarantee: None,
                }),
                145,
            ),
            (
                Message::Ce146Submission(BundleSubmission {
                    core_index: 0,
                    mappings: vec![],
                    work_package: vec![],
                    extrinsics: vec![],
                    segments: vec![],
                    import_proof: vec![],
                }),
                146,
            ),
            (
                Message::Ce147Response(BundleResponse { bundle: vec![] }),
                147,
            ),
            (
                Message::Ce148Response(SegmentResponse {
                    segments: vec![],
                    import_proof: vec![],
                }),
                148,
            ),
        ];
        for (msg, expected) in cases {
            assert_eq!(msg.kind(), expected, "kind mismatch");
        }
    }

    #[test]
    fn refused_kinds_are_rejected() {
        for kind in [130u8, 149, 150, 151, 152] {
            assert!(
                matches!(from_kind_and_payload(kind, &[]), Err(ProtoError::RefusedKind(k)) if k == kind),
                "kind {kind} must be refused"
            );
        }
    }

    #[test]
    fn unknown_kind_is_rejected() {
        for kind in [200u8, 0xFE, 5] {
            assert!(
                matches!(from_kind_and_payload(kind, &[]), Err(ProtoError::UnknownKind(k)) if k == kind),
                "kind {kind} must be unknown"
            );
        }
    }

    #[test]
    fn truncated_payload_yields_decode_error() {
        let req = BlockRequest {
            header_hash: HeaderHash::from([0xAA; 32]),
            direction: Direction::AscendingExclusive,
            max_blocks: 5,
        }
        .encode();
        let truncated = &req[..req.len() - 1];
        assert!(matches!(
            from_kind_and_payload(framing::CE128, truncated),
            Err(ProtoError::Decode(_))
        ));

        let assurance = Assurance {
            anchor: HeaderHash::from([0x11; 32]),
            bitfield: vec![0xaa],
            signature: [0u8; 64],
        }
        .encode();
        let truncated = &assurance[..assurance.len() - 1];
        assert!(matches!(
            from_kind_and_payload(framing::CE141, truncated),
            Err(ProtoError::Decode(_))
        ));
    }

    #[test]
    fn frame_message_matches_framing_frame() {
        let payload = vec![0xde, 0xad, 0xbe, 0xef];
        assert_eq!(
            frame_message(framing::CE128, &payload),
            framing::frame(framing::CE128, &payload)
        );
    }
}
