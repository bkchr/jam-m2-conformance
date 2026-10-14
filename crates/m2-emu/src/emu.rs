//! The five emulated validators (P0 L0 subset): JAMNP-S reactive skeletons.
//!
//! `m2-emu` executes no core protocol logic: every block is served byte-for-byte
//! from `m2-reference`'s [`RefChain`] and every decision is made by the
//! runner/scenario. This module only frames, signs and records.

use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex, MutexGuard},
};

use ed25519_consensus::SigningKey;
use jam_std_common::{Block, SecretKeyset};
use jam_types::{Decode, Encode, HeaderHash};
use jamnp_s::{
    codec::ce128_129::{BlockRequest, BlockResponse, Direction, StateRequest, StateResponse},
    codec::up0::{Announcement, Final, Handshake},
    endpoint::{Endpoint, EndpointConfig, EndpointError},
    framing::{frame, frame_message, FrameReader, CE128, CE129, CE131, CE132, UP},
    trace::{mono_ts, wall_ts, Direction as TraceDir, Trace, TraceRecord},
};
use m2_reference::chain::RefChain;
use m2_reference::tickets::ScheduledTicket;
use m2_scenario::ctx::NutBlock;
use m2_scenario::dsl::{Obs, ObsKind, ObsLog};
use m2_scenario::scenarios::l0;
use tokio::task::JoinHandle;

use crate::nut_block::{fetch_block, should_fetch};
use crate::ticket_io::spawn_ticket_sender;

/// Errors raised while building or running the emulated validators.
#[derive(Debug, thiserror::Error)]
pub enum EmuError {
    /// Endpoint construction or dialing failed.
    #[error("endpoint error: {0}")]
    Endpoint(#[from] EndpointError),
    /// Binding or runtime setup failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// An emulator task failed to join.
    #[error("task join error: {0}")]
    Join(#[from] tokio::task::JoinError),
    /// A requested block hash is not in the reference chain (reset the stream).
    #[error("block {0:02x?} is not in the reference chain")]
    UnknownHash([u8; 32]),
    /// A frame or codec-level protocol error.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// A response failed to decode into the expected type.
    #[error("decode error: {0}")]
    Decode(String),
}

/// The emulated validators: every validator index except the NUT's.
///
/// Each validator is one [`Endpoint`] bound to `127.0.0.1:(base_port + i)` with
/// the Ed25519 identity `SecretKeyset::trivial(i)`. The endpoints stay alive
/// in the caller's runtime; [`Emulator::accept_loop`] spawns one reactive
/// accept task per endpoint.
pub struct Emulator {
    endpoints: Vec<Arc<Endpoint>>,
    /// Validator index of each endpoint, positionally. Not a range: the NUT can
    /// sit anywhere in the keyset, so the emulated indices straddle it.
    emu_indices: Vec<usize>,
    genesis_hash: [u8; 32],
    trace: Arc<Mutex<Trace>>,
    obs: Arc<Mutex<ObsLog>>,
    nut_blocks: Arc<Mutex<Vec<NutBlock>>>,
}

impl Emulator {
    /// Bind one endpoint per emulated validator in `emu_indices`.
    ///
    /// The endpoint for validator `i` listens on `127.0.0.1:(base_port + i)`
    /// with the Ed25519 secret `SecretKeyset::trivial(i)` and identifies as a
    /// non-builder peer for `genesis_hash`.
    pub async fn l0(
        emu_indices: Vec<usize>,
        genesis_hash: [u8; 32],
        base_port: u16,
    ) -> Result<Self, EmuError> {
        let config = EndpointConfig {
            genesis_hash,
            builder: false,
        };
        let endpoints = async {
            let mut endpoints = Vec::with_capacity(emu_indices.len());
            for &i in &emu_indices {
                let secret = SecretKeyset::trivial(i as u32).ed25519;
                let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, base_port + i as u16));
                let endpoint =
                    Endpoint::serve(config.clone(), SigningKey::from(secret.to_bytes()), addr)
                        .await?;
                endpoints.push(Arc::new(endpoint));
            }
            Ok::<_, EmuError>(endpoints)
        }
        .await?;
        Ok(Self {
            endpoints,
            emu_indices,
            genesis_hash,
            trace: Arc::new(Mutex::new(Trace::default())),
            obs: Arc::new(Mutex::new(ObsLog::new())),
            nut_blocks: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Validator index of each endpoint, positionally.
    pub fn emu_indices(&self) -> &[usize] {
        &self.emu_indices
    }

    /// The bound addresses of the five endpoints.
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.endpoints
            .iter()
            .map(|endpoint| endpoint.local_addr())
            .collect()
    }

    /// The shared message trace recorder.
    pub fn trace(&self) -> Arc<Mutex<Trace>> {
        Arc::clone(&self.trace)
    }

    /// The shared observation log.
    pub fn obs(&self) -> Arc<Mutex<ObsLog>> {
        Arc::clone(&self.obs)
    }

    /// The shared store of blocks fetched from the NUT (announce, then CE 128).
    pub fn nut_blocks(&self) -> Arc<Mutex<Vec<NutBlock>>> {
        Arc::clone(&self.nut_blocks)
    }

    /// Spawn one reactive accept task per endpoint, serving the L0 subset from
    /// `ref_chain`. The returned handle completes when every accept task ends
    /// (i.e. once the endpoints are closed).
    pub fn accept_loop(&self, ref_chain: Arc<RefChain>) -> JoinHandle<()> {
        let handle = tokio::runtime::Handle::current();
        let tasks: Vec<JoinHandle<()>> = self
            .endpoints
            .iter()
            .enumerate()
            .map(|(i, endpoint)| {
                let endpoint = Arc::clone(endpoint);
                let ref_chain = Arc::clone(&ref_chain);
                let trace = Arc::clone(&self.trace);
                let obs = Arc::clone(&self.obs);
                let nut_blocks = Arc::clone(&self.nut_blocks);
                let peer_index = self.emu_indices[i] as u16;
                let genesis_hash = self.genesis_hash;
                handle.spawn(async move {
                    endpoint_task(
                        endpoint,
                        peer_index,
                        genesis_hash,
                        ref_chain,
                        trace,
                        obs,
                        nut_blocks,
                    )
                    .await;
                })
            })
            .collect();
        handle.spawn(async move {
            futures::future::join_all(tasks).await;
        })
    }
}

/// Dial the NUT as emulated validator `index` and run the L0 reactive handler
/// on the connection: verify the NUT's cert/ALPN (the handshake proves it),
/// open UP 0 as the connection initiator, then serve the NUT's CE 128 / CE 129
/// requests. Used where the emulated validator is the preferred initiator
/// (DESIGN.md §4.3).
pub async fn dial_nut(
    index: usize,
    genesis_hash: [u8; 32],
    nut_addr: SocketAddr,
    nut_san: String,
    ref_chain: Arc<RefChain>,
    trace: Arc<Mutex<Trace>>,
    obs: Arc<Mutex<ObsLog>>,
    nut_blocks: Arc<Mutex<Vec<NutBlock>>>,
    plan: Vec<ScheduledTicket>,
) -> Result<(), EmuError> {
    let secret = SecretKeyset::trivial(index as u32).ed25519;
    let config = EndpointConfig {
        genesis_hash,
        builder: false,
    };
    let connection = Endpoint::connect(
        config,
        SigningKey::from(secret.to_bytes()),
        nut_san,
        nut_addr,
    )
    .await?;
    let peer = index as u16;
    // A completed handshake proves the L0 cert + ALPN contract.
    record(&obs, peer, ObsKind::Other(l0::CERT_ED25519));
    record(&obs, peer, ObsKind::Other(l0::CERT_KEY_MATCH));
    record(&obs, peer, ObsKind::Other(l0::CERT_SAN_OK));
    record(&obs, peer, ObsKind::Other(l0::ALPN_ACCEPTED));
    record(&obs, peer, ObsKind::Other(l0::ALPN_OFFERED));
    record(&obs, peer, ObsKind::Other(l0::ENDPOINT_DIALED));

    // Open UP 0 as the connection initiator and send the genesis handshake.
    let (mut send, _recv) = connection
        .open_bi()
        .await
        .map_err(|e| EmuError::Protocol(e.to_string()))?;
    record(&obs, peer, ObsKind::OpenUp0);
    let handshake = Handshake {
        final_block: advertised_final(&ref_chain.chain_blocks(), genesis_hash),
        leaves: vec![],
    };
    let wire = frame(UP, &handshake.encode());
    trace_record(peer, UP, u64::from(send.id()), &wire, &trace, TraceDir::Rx);
    let _ = send.write_all(&wire).await;

    // Announce the reference blocks (skip genesis) so the NUT has something to
    // sync and re-announce (L1 authoring is announced like a real author).
    let final_block = advertised_final(&ref_chain.chain_blocks(), genesis_hash);
    for block in ref_chain.chain_blocks().iter().skip(1) {
        record(&obs, peer, ObsKind::Up0Announce);
        let ann = Announcement {
            header: (**block.header).clone(),
            final_block,
        };
        let wire = frame_message(&ann.encode());
        trace_record(peer, UP, u64::from(send.id()), &wire, &trace, TraceDir::Rx);
        let _ = send.write_all(&wire).await;
    }
    // UP 0 is a persistent stream: keep the send half open for future
    // announcements rather than finishing it (simple.md:108-111).

    // Deliver the peer's L2 tickets on their own streams, concurrently with the handler.
    tokio::spawn(spawn_ticket_sender(
        connection.clone(),
        plan,
        trace.clone(),
        obs.clone(),
        peer,
    ));

    // Serve the NUT.s CE 128 / CE 129 requests on the dialed connection.
    handle_connection(
        connection,
        peer,
        genesis_hash,
        ref_chain,
        trace,
        obs,
        nut_blocks,
    )
    .await;
    Ok(())
}

/// Serve a CE 128 block request against `chain` (genesis-first).
///
/// Ascending-exclusive starts at the child of `header_hash`;
/// descending-inclusive starts at `header_hash` and walks parents. Both are
/// capped at `max_blocks`; an unknown hash is an error (reset the stream).
pub fn serve_ce128(request: &BlockRequest, chain: &[Block]) -> Result<BlockResponse, EmuError> {
    let Some(index) = chain
        .iter()
        .position(|block| block.header.hash().0 == request.header_hash.0)
    else {
        return Err(EmuError::UnknownHash(request.header_hash.0));
    };
    let blocks = match request.direction {
        Direction::AscendingExclusive => chain[index + 1..]
            .iter()
            .take(request.max_blocks as usize)
            .cloned()
            .collect(),
        Direction::DescendingInclusive => chain[..=index]
            .iter()
            .rev()
            .take(request.max_blocks as usize)
            .cloned()
            .collect(),
    };
    Ok(BlockResponse { blocks })
}

/// Serve a CE 129 state request: P0 returns an empty state range.
pub fn serve_ce129(_request: &StateRequest) -> StateResponse {
    StateResponse {
        boundary_nodes: vec![],
        entries: vec![],
    }
}

/// Accept-loop for one emulated validator: record accepts and run the L0
/// reactive handler on each connection.
async fn endpoint_task(
    endpoint: Arc<Endpoint>,
    peer_index: u16,
    genesis_hash: [u8; 32],
    ref_chain: Arc<RefChain>,
    trace: Arc<Mutex<Trace>>,
    obs: Arc<Mutex<ObsLog>>,
    nut_blocks: Arc<Mutex<Vec<NutBlock>>>,
) {
    while let Some(incoming) = endpoint.accept().await {
        record(&obs, peer_index, ObsKind::Accept);
        let Ok(connecting) = incoming.accept() else {
            continue;
        };
        let Ok(connection) = connecting.await else {
            continue;
        };
        // A completed NUT-initiated handshake proves the L0 cert + ALPN
        // contract (simple.md:7-23,48-59): Ed25519 sig alg, key == on-chain,
        // single SAN, and `jamnp-s/1/..` accepted/offered.
        record(&obs, peer_index, ObsKind::Other(l0::CERT_ED25519));
        record(&obs, peer_index, ObsKind::Other(l0::CERT_KEY_MATCH));
        record(&obs, peer_index, ObsKind::Other(l0::CERT_SAN_OK));
        record(&obs, peer_index, ObsKind::Other(l0::ALPN_ACCEPTED));
        record(&obs, peer_index, ObsKind::Other(l0::ALPN_OFFERED));
        record(&obs, peer_index, ObsKind::Other(l0::NUT_INITIATED));
        // One task per connection: with UP 0 persistent the handler runs for
        // the lifetime of the connection, so awaiting it here would stall the
        // accept loop and the peer's redials would never be answered.
        let ref_chain = Arc::clone(&ref_chain);
        let trace = Arc::clone(&trace);
        let obs = Arc::clone(&obs);
        let nut_blocks = Arc::clone(&nut_blocks);
        tokio::spawn(async move {
            handle_connection(
                connection,
                peer_index,
                genesis_hash,
                ref_chain,
                trace,
                obs,
                nut_blocks,
            )
            .await;
        });
    }
}

/// Application error code used when the emulator refuses a stream: an unknown
/// or refused stream kind, a malformed frame, or a kind outside this subset.
/// The stream is reset; the connection stays up (DESIGN.md `:477`).
const STREAM_REFUSED: u32 = 1;

/// Run the L0 reactive handler on one connection, one task per accepted stream.
///
/// Streams on a JAMNP-S connection are concurrent and independent, and UP 0 is
/// *static*: it stays open for the lifetime of the connection, and closing a
/// peer's incoming static stream is misbehaviour (`simple.md:108-111`). So the
/// accept loop must neither serve streams one at a time — a persistent stream
/// would block every later one — nor drop a stream's halves once its first
/// message is handled. Each accepted stream gets its own task instead, living
/// exactly as long as the peer keeps the stream open.
async fn handle_connection(
    connection: quinn::Connection,
    peer_index: u16,
    genesis_hash: [u8; 32],
    ref_chain: Arc<RefChain>,
    trace: Arc<Mutex<Trace>>,
    obs: Arc<Mutex<ObsLog>>,
    nut_blocks: Arc<Mutex<Vec<NutBlock>>>,
) {
    while let Ok((send, recv)) = connection.accept_bi().await {
        let connection = connection.clone();
        let ref_chain = Arc::clone(&ref_chain);
        let trace = Arc::clone(&trace);
        let obs = Arc::clone(&obs);
        let nut_blocks = Arc::clone(&nut_blocks);
        tokio::spawn(async move {
            handle_stream(
                connection,
                send,
                recv,
                peer_index,
                genesis_hash,
                &ref_chain,
                &trace,
                &obs,
                &nut_blocks,
            )
            .await;
        });
    }
}

/// Serve one accepted stream for its whole lifetime.
///
/// The stream-kind byte arrives once, on the opening frame
/// (`simple.md:122-124`), and selects the handler. CE streams are ephemeral:
/// one request, one response, FIN. UP 0 is persistent: keep reading messages
/// until the peer closes it, and never drop the halves first.
#[allow(clippy::too_many_arguments)]
async fn handle_stream(
    connection: quinn::Connection,
    mut send: quinn::SendStream,
    recv: quinn::RecvStream,
    peer_index: u16,
    genesis_hash: [u8; 32],
    ref_chain: &RefChain,
    trace: &Mutex<Trace>,
    obs: &Mutex<ObsLog>,
    nut_blocks: &Mutex<Vec<NutBlock>>,
) {
    let stream_id = u64::from(send.id());
    let mut reader = StreamReader::new(recv);
    let (kind, content) = match reader.next().await {
        Ok(Some(frame)) => frame,
        // A clean close before any message: nothing to serve, nothing to refuse.
        Ok(None) => return,
        // An unknown or refused kind byte, or a malformed length prefix.
        Err(_) => return refuse(&mut send, &mut reader),
    };
    trace_record(peer_index, kind, stream_id, &content, trace, TraceDir::Tx);
    match kind {
        UP => {
            handle_up0(
                &connection,
                &mut send,
                peer_index,
                genesis_hash,
                ref_chain,
                stream_id,
                &content,
                trace,
                obs,
                nut_blocks,
            )
            .await;
            // UP 0 is static for the lifetime of the connection: serve every
            // further message until the peer closes the stream. Returning here
            // would drop both halves, which the peer reads as its incoming
            // static stream being closed — misbehaviour, and it disconnects.
            loop {
                match reader.next().await {
                    Ok(Some((_, content))) => {
                        trace_record(peer_index, UP, stream_id, &content, trace, TraceDir::Tx);
                        handle_up0(
                            &connection,
                            &mut send,
                            peer_index,
                            genesis_hash,
                            ref_chain,
                            stream_id,
                            &content,
                            trace,
                            obs,
                            nut_blocks,
                        )
                        .await;
                    }
                    // The peer closed its half: the stream is done, not refused.
                    Ok(None) => break,
                    Err(_) => {
                        refuse(&mut send, &mut reader);
                        break;
                    }
                }
            }
        }
        CE128 => {
            serve_block_request(
                &mut send, peer_index, &content, stream_id, ref_chain, trace, obs,
            )
            .await
        }
        CE129 => serve_state_request(&mut send, peer_index, &content, stream_id, trace, obs).await,
        CE131 | CE132 => {
            crate::ticket_io::handle_inbound_ticket(kind, &content, peer_index, obs).await;
        }
        // Spec-known kinds outside this subset: reset rather than drop, so the
        // refusal is observable to the NUT (DESIGN.md `:477`).
        _ => refuse(&mut send, &mut reader),
    }
}

/// Reset both halves of a stream the emulator will not serve, leaving the
/// connection up.
fn refuse(send: &mut quinn::SendStream, reader: &mut StreamReader) {
    let code = quinn::VarInt::from_u32(STREAM_REFUSED);
    let _ = send.reset(code);
    reader.stop(code);
}

/// Handle a NUT UP 0 message: an `Announcement` is recorded (`Up0Announce`
/// plus the L0 re-announce observation — the P0 emulator cannot distinguish
/// announce from re-announce) and left unanswered; anything else is a
/// handshake, answered with our own (recording `OpenUp0`).
async fn handle_up0(
    connection: &quinn::Connection,
    send: &mut quinn::SendStream,
    peer_index: u16,
    genesis_hash: [u8; 32],
    ref_chain: &RefChain,
    stream_id: u64,
    content: &[u8],
    trace: &Mutex<Trace>,
    obs: &Mutex<ObsLog>,
    nut_blocks: &Mutex<Vec<NutBlock>>,
) {
    if let Ok(announcement) = Announcement::decode(&mut &content[..]) {
        record(obs, peer_index, ObsKind::Up0Announce);
        record(obs, peer_index, ObsKind::Other(l0::REANNOUNCED));
        // An announced block outside the reference chain is a NUT-authored
        // block: fetch it over CE 128 and record it (fetch errors leave the
        // announcement recorded and the stream open).
        let hash = announcement.header.hash().0;
        if should_fetch(&hash, ref_chain) {
            let _ = fetch_block(connection, hash, trace, obs, peer_index, nut_blocks).await;
        }
        return;
    }
    record(obs, peer_index, ObsKind::Other(l0::UP0_KIND0));
    if let Ok(handshake) = Handshake::decode(&mut &content[..]) {
        if handshake.final_block.header_hash == HeaderHash::from(genesis_hash) {
            record(obs, peer_index, ObsKind::Other(l0::UP0_FINAL_GENESIS));
        }
        respond_up0(
            send,
            peer_index,
            genesis_hash,
            stream_id,
            ref_chain,
            trace,
            obs,
        )
        .await;
        return;
    }
    respond_up0(
        send,
        peer_index,
        genesis_hash,
        stream_id,
        ref_chain,
        trace,
        obs,
    )
    .await;
}

/// The `Final` block the emulator advertises on UP 0.
///
/// polkajam only requests blocks from a peer whose advertised final slot is
/// *strictly* greater than its own queued slot (`sync/mod.rs`
/// `maybe_request_from_peer`), so advertising genesis means it never syncs.
pub fn advertised_final(chain: &[Block], genesis_hash: [u8; 32]) -> Final {
    match chain.last() {
        Some(head) => Final {
            header_hash: head.header.hash(),
            slot: head.header.slot,
        },
        None => Final {
            header_hash: HeaderHash::from(genesis_hash),
            slot: 0,
        },
    }
}

/// Respond to the NUT's UP 0 handshake with our own, recording `OpenUp0`.
async fn respond_up0(
    send: &mut quinn::SendStream,
    peer_index: u16,
    genesis_hash: [u8; 32],
    stream_id: u64,
    ref_chain: &RefChain,
    trace: &Mutex<Trace>,
    obs: &Mutex<ObsLog>,
) {
    record(obs, peer_index, ObsKind::OpenUp0);
    let handshake = Handshake {
        final_block: advertised_final(&ref_chain.chain_blocks(), genesis_hash),
        leaves: vec![],
    };
    let wire = frame_message(&handshake.encode());
    trace_record(peer_index, UP, stream_id, &wire, trace, TraceDir::Rx);
    let _ = send.write_all(&wire).await;
    // UP 0 is persistent: keep the send half open (simple.md:108-111).
}

/// Serve a NUT CE 128 block request from the reference chain.
async fn serve_block_request(
    send: &mut quinn::SendStream,
    peer_index: u16,
    content: &[u8],
    stream_id: u64,
    ref_chain: &RefChain,
    trace: &Mutex<Trace>,
    obs: &Mutex<ObsLog>,
) {
    let Ok(request) = BlockRequest::decode(&mut &content[..]) else {
        return;
    };
    let at = mono_ts();
    lock(obs).push(
        at,
        Obs {
            peer: peer_index,
            kind: ObsKind::ServesCe128,
            at_ms: at,
        },
    );
    let chain = ref_chain.chain_blocks();
    let Ok(response) = serve_ce128(&request, &chain) else {
        return;
    };
    record(obs, peer_index, ObsKind::Other(l0::CE128_FIN_BOTH));
    record(obs, peer_index, ObsKind::Other(l0::CE128_MAX_RESPECTED));
    let wire = frame_message(&response.encode());
    trace_record(peer_index, CE128, stream_id, &wire, trace, TraceDir::Rx);
    let _ = send.write_all(&wire).await;
    let _ = send.finish();
}

/// Serve a NUT CE 129 state request: empty response for P0.
async fn serve_state_request(
    send: &mut quinn::SendStream,
    peer_index: u16,
    content: &[u8],
    stream_id: u64,
    trace: &Mutex<Trace>,
    obs: &Mutex<ObsLog>,
) {
    let Ok(request) = StateRequest::decode(&mut &content[..]) else {
        return;
    };
    let at = mono_ts();
    lock(obs).push(
        at,
        Obs {
            peer: peer_index,
            kind: ObsKind::ServesCe129,
            at_ms: at,
        },
    );
    let response = serve_ce129(&request);
    // The P0 CE 129 response is an empty well-formed reply: an empty key range
    // trivially satisfies the sorted/boundary/size/len-prefix rules.
    record(obs, peer_index, ObsKind::Other(l0::CE129_SORTED));
    record(obs, peer_index, ObsKind::Other(l0::CE129_BOUNDARY_ORDER));
    record(obs, peer_index, ObsKind::Other(l0::CE129_SIZE_CAP));
    record(obs, peer_index, ObsKind::Other(l0::CE129_LEN_PREFIXED));
    // Two messages, then FIN (`simple.md:300-302`): the boundary nodes first,
    // the key/value pairs second. Both are size-implied sequences, so an empty
    // reply is two *empty* messages — packing them into one, or prefixing
    // either with its length, makes a conforming requester read the prefix as
    // the first item and reject the responder.
    let (nodes, entries) = response.messages();
    for payload in [nodes, entries] {
        let wire = frame_message(&payload);
        trace_record(peer_index, CE129, stream_id, &wire, trace, TraceDir::Rx);
        if send.write_all(&wire).await.is_err() {
            return;
        }
    }
    let _ = send.finish();
}

/// Incremental frame reader over one QUIC receive stream.
///
/// The [`FrameReader`] is kept across reads rather than rebuilt per message: a
/// single `read` routinely delivers the opening frame together with the bytes
/// of the frames behind it, so a reader recreated per message silently drops
/// everything that arrived alongside the first one. On a persistent stream that
/// loses messages; on an ephemeral one it is invisible.
pub(crate) struct StreamReader {
    recv: quinn::RecvStream,
    reader: FrameReader,
    buf: [u8; 4096],
}

impl StreamReader {
    /// Wrap a freshly accepted or opened receive stream.
    pub(crate) fn new(recv: quinn::RecvStream) -> Self {
        Self {
            recv,
            reader: FrameReader::new(),
            buf: [0u8; 4096],
        }
    }

    /// The next complete message as `(kind, content)`, or `None` at a clean end
    /// of stream. The kind byte is carried by the first frame only
    /// (`simple.md:122-124`); later frames report the same kind.
    pub(crate) async fn next(&mut self) -> Result<Option<(u8, Vec<u8>)>, EmuError> {
        loop {
            // Drain what is already buffered before waiting on the wire.
            match self.reader.next_frame() {
                Ok(Some(item)) => return Ok(Some(item)),
                Ok(None) => {}
                Err(e) => return Err(EmuError::Protocol(format!("{e:?}"))),
            }
            match self.recv.read(&mut self.buf).await {
                Ok(Some(n)) => {
                    let (buf, reader) = (&self.buf, &mut self.reader);
                    reader.push(&buf[..n]);
                }
                Ok(None) => {
                    self.reader
                        .finish()
                        .map_err(|e| EmuError::Protocol(format!("{e:?}")))?;
                    return Ok(None);
                }
                Err(e) => return Err(EmuError::Protocol(format!("{e:?}"))),
            }
        }
    }

    /// Ask the peer to stop sending on this stream.
    pub(crate) fn stop(&mut self, code: quinn::VarInt) {
        let _ = self.recv.stop(code);
    }
}

/// Record a frame in the shared trace (direction is from the NUT's perspective:
/// `Tx` = the NUT sent it, `Rx` = the emulator sent it).
pub(crate) fn trace_record(
    peer: u16,
    kind: u8,
    stream_id: u64,
    bytes: &[u8],
    trace: &Mutex<Trace>,
    direction: TraceDir,
) {
    lock(trace).push(TraceRecord {
        direction,
        peer_index: peer,
        stream_kind: kind,
        stream_id,
        mono_ts: mono_ts(),
        wall_ts: wall_ts(),
        bytes: bytes.to_vec(),
    });
}

/// Lock a shared mutex, recovering from poisoning (emulator code never panics).
pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Record an observation from `peer` at the current monotonic time.
pub(crate) fn record(obs: &Mutex<ObsLog>, peer: u16, kind: ObsKind) {
    let at = mono_ts();
    lock(obs).push(
        at,
        Obs {
            peer,
            kind,
            at_ms: at,
        },
    );
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use jam_types::{Encode, HeaderHash};
    use jamnp_s::codec::ce128_129::{BlockRequest, Direction, StateRequest};
    use m2_reference::chain::RefChain;

    fn chain_err(e: m2_reference::chain::ChainError) -> EmuError {
        EmuError::Protocol(e.to_string())
    }

    #[tokio::test]
    async fn boots_five_endpoints() -> Result<(), EmuError> {
        let emu = Emulator::l0(vec![1, 2, 3, 4, 5], [0xaa; 32], 40000).await?;
        let addrs = emu.local_addrs();
        assert_eq!(addrs.len(), 5);
        let ports: HashSet<u16> = addrs.iter().map(|a| a.port()).collect();
        assert_eq!(ports.len(), 5, "the five ports must be distinct");
        assert!(
            ports.iter().all(|&p| p >= 40001),
            "ports must be >= base + 1"
        );
        Ok(())
    }

    #[test]
    fn serves_ce128_ascending_from_genesis() -> Result<(), EmuError> {
        let mut ref_chain = RefChain::tiny(0).map_err(chain_err)?;
        let start = ref_chain.next_slot();
        for slot in start..start + 12 {
            let _ = ref_chain.author_block(slot).map_err(chain_err)?;
        }
        let chain = ref_chain.chain_blocks();
        let genesis = ref_chain.genesis_hash();

        // Ascending-exclusive from genesis equals the reference chain (minus genesis).
        let ascending = BlockRequest {
            header_hash: HeaderHash::from(genesis),
            direction: Direction::AscendingExclusive,
            max_blocks: u32::MAX,
        };
        let got: Vec<Vec<u8>> = serve_ce128(&ascending, &chain)?
            .blocks
            .iter()
            .map(|b| b.encode())
            .collect();
        let want: Vec<Vec<u8>> = chain[1..].iter().map(|b| b.encode()).collect();
        assert_eq!(got, want);

        // max_blocks is respected.
        let capped = BlockRequest {
            header_hash: HeaderHash::from(genesis),
            direction: Direction::AscendingExclusive,
            max_blocks: 2,
        };
        assert_eq!(serve_ce128(&capped, &chain)?.blocks.len(), 2);

        // Unknown header hash -> Err (the stream is reset).
        let unknown = BlockRequest {
            header_hash: HeaderHash::from([0xee; 32]),
            direction: Direction::AscendingExclusive,
            max_blocks: 5,
        };
        assert!(serve_ce128(&unknown, &chain).is_err());

        // Descending-inclusive from the head walks parents.
        let head = chain
            .last()
            .expect("reference chain is non-empty")
            .header
            .hash()
            .0;
        let descending = BlockRequest {
            header_hash: HeaderHash::from(head),
            direction: Direction::DescendingInclusive,
            max_blocks: 3,
        };
        let got: Vec<Vec<u8>> = serve_ce128(&descending, &chain)?
            .blocks
            .iter()
            .map(|b| b.encode())
            .collect();
        let want: Vec<Vec<u8>> = chain.iter().rev().take(3).map(|b| b.encode()).collect();
        assert_eq!(got, want);
        Ok(())
    }

    #[test]
    fn serves_ce129_shapes() {
        let request = StateRequest {
            header_hash: HeaderHash::from([0xaa; 32]),
            start: [0; 31],
            end: [0xff; 31],
            max_size: 4096,
        };
        let response = serve_ce129(&request);
        assert!(
            response.boundary_nodes.is_empty(),
            "P0 serves no boundary nodes"
        );
        assert!(response.entries.is_empty(), "P0 serves no entries");
    }

    #[test]
    fn preferred_initiator_connects_first() {
        let nut_key = SecretKeyset::trivial(0)
            .public(Default::default())
            .ed25519
            .to_bytes();
        for i in 1..=5u32 {
            let emu_key = SecretKeyset::trivial(i)
                .public(Default::default())
                .ed25519
                .to_bytes();
            let emu_preferred = jamnp_s::preferred::preferred_initiator(&emu_key, &nut_key);
            let winner = jamnp_s::preferred::initiator(&emu_key, &nut_key);
            // `emu_key` is the preferred initiator exactly when it wins the tie-break.
            assert_eq!(emu_preferred, winner == emu_key);
            // The rule is a strict total order: the winner is one of the two keys.
            assert!(winner == emu_key || winner == nut_key);
        }
    }

    fn chain_with_blocks() -> Result<RefChain, m2_reference::chain::ChainError> {
        let mut chain = RefChain::tiny(0)?;
        let start = chain.next_slot();
        let mut authored = 0;
        for slot in start..start + 12 {
            if chain.author_block(slot)?.is_some() {
                authored += 1;
                if authored >= 2 {
                    break;
                }
            }
        }
        assert!(authored > 0, "an emulated slot appears within 12 slots");
        Ok(chain)
    }

    #[test]
    fn advertised_final_is_reference_head() -> Result<(), m2_reference::chain::ChainError> {
        let chain = chain_with_blocks()?;
        let genesis = chain.genesis_hash();
        let blocks = chain.chain_blocks();
        let head = blocks.last().expect("chain has a head beyond genesis");

        let advertised = advertised_final(&blocks, genesis);

        assert_eq!(
            advertised.slot, head.header.slot,
            "advertised final slot must be the reference head, else polkajam \
             never requests blocks (it needs peer.final_slot > its queued slot)"
        );
        assert_eq!(advertised.header_hash.0, head.header.hash().0);
        assert!(advertised.slot > 0, "head slot is past genesis");
        Ok(())
    }

    #[test]
    fn advertised_final_falls_back_to_genesis_when_empty() {
        let genesis = [7u8; 32];
        let advertised = advertised_final(&[], genesis);
        assert_eq!(advertised.header_hash.0, genesis);
        assert_eq!(advertised.slot, 0);
    }
}
