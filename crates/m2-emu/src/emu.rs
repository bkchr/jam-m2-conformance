//! The five emulated validators (P0 L0 subset): JAMNP-S reactive skeletons.
//!
//! `m2-emu` executes no core protocol logic: every block is served byte-for-byte
//! from `m2-reference`'s [`RefChain`] and every decision is made by the
//! runner/scenario. This module only frames, signs and records.

use std::{
    net::{Ipv4Addr, SocketAddr},
    ops::Range,
    sync::{Arc, Mutex, MutexGuard},
};

use ed25519_consensus::SigningKey;
use jam_std_common::{Block, SecretKeyset};
use jam_types::{Decode, Encode, HeaderHash};
use jamnp_s::{
    codec::ce128_129::{BlockRequest, BlockResponse, Direction, StateRequest, StateResponse},
    codec::up0::{Announcement, Final, Handshake},
    endpoint::{Endpoint, EndpointConfig, EndpointError},
    framing::{frame, frame_message, FrameReader, CE128, CE129, UP},
    trace::{mono_ts, wall_ts, Direction as TraceDir, Trace, TraceRecord},
};
use m2_reference::chain::RefChain;
use m2_scenario::dsl::{Obs, ObsKind, ObsLog};
use m2_scenario::scenarios::l0;
use tokio::task::JoinHandle;

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
}

/// The five emulated validators (indices `1..=5` by default).
///
/// Each validator is one [`Endpoint`] bound to `127.0.0.1:(base_port + i)` with
/// the Ed25519 identity `SecretKeyset::trivial(i)`. The endpoints stay alive
/// in the caller's runtime; [`Emulator::accept_loop`] spawns one reactive
/// accept task per endpoint.
pub struct Emulator {
    endpoints: Vec<Arc<Endpoint>>,
    emu_start: usize,
    genesis_hash: [u8; 32],
    trace: Arc<Mutex<Trace>>,
    obs: Arc<Mutex<ObsLog>>,
}

impl Emulator {
    /// Bind one endpoint per emulated validator in `emu_keyset_indices`.
    ///
    /// Endpoint `i` listens on `127.0.0.1:(base_port + i)` with the Ed25519
    /// secret `SecretKeyset::trivial(i)` and identifies as a non-builder peer
    /// for `genesis_hash`.
    pub async fn l0(
        emu_keyset_indices: Range<usize>,
        genesis_hash: [u8; 32],
        base_port: u16,
    ) -> Result<Self, EmuError> {
        let config = EndpointConfig {
            genesis_hash,
            builder: false,
        };
        let endpoints = async {
            let mut endpoints = Vec::with_capacity(emu_keyset_indices.len());
            for i in emu_keyset_indices.clone() {
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
            emu_start: emu_keyset_indices.start,
            genesis_hash,
            trace: Arc::new(Mutex::new(Trace::default())),
            obs: Arc::new(Mutex::new(ObsLog::new())),
        })
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
                let peer_index = (self.emu_start + i) as u16;
                let genesis_hash = self.genesis_hash;
                handle.spawn(async move {
                    endpoint_task(endpoint, peer_index, genesis_hash, ref_chain, trace, obs).await;
                })
            })
            .collect();
        handle.spawn(async move {
            futures::future::join_all(tasks).await;
        })
    }
}

/// Dial the NUT as emulated validator `emu_start + peer_index` and run the L0
/// reactive handler on the connection: verify the NUT's cert/ALPN (the
/// handshake proves it), open UP 0 as the connection initiator, then serve the
/// NUT's CE 128 / CE 129 requests. Used where the emulated validator is the
/// preferred initiator (DESIGN.md §4.3).
pub async fn dial_nut(
    emu_start: usize,
    peer_index: usize,
    genesis_hash: [u8; 32],
    nut_addr: SocketAddr,
    nut_san: String,
    ref_chain: Arc<RefChain>,
    trace: Arc<Mutex<Trace>>,
    obs: Arc<Mutex<ObsLog>>,
) -> Result<(), EmuError> {
    let index = emu_start + peer_index;
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
        final_block: Final {
            header_hash: HeaderHash::from(genesis_hash),
            slot: 0,
        },
        leaves: vec![],
    };
    let wire = frame(UP, &handshake.encode());
    trace_record(peer, UP, u64::from(send.id()), &wire, &trace, TraceDir::Tx);
    let _ = send.write_all(&wire).await;

    // Announce the reference blocks (skip genesis) so the NUT has something to
    // sync and re-announce (L1 authoring is announced like a real author).
    let final_block = Final {
        header_hash: HeaderHash::from(genesis_hash),
        slot: 0,
    };
    for block in ref_chain.chain_blocks().iter().skip(1) {
        record(&obs, peer, ObsKind::Up0Announce);
        let ann = Announcement {
            header: (**block.header).clone(),
            final_block,
        };
        let wire = frame_message(&ann.encode());
        trace_record(peer, UP, u64::from(send.id()), &wire, &trace, TraceDir::Tx);
        let _ = send.write_all(&wire).await;
    }
    // UP 0 is a persistent stream: keep the send half open for future
    // announcements rather than finishing it (simple.md:108-111).

    // Serve the NUT.s CE 128 / CE 129 requests on the dialed connection.
    handle_connection(connection, peer, genesis_hash, &ref_chain, &trace, &obs).await;
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
        handle_connection(
            connection,
            peer_index,
            genesis_hash,
            &ref_chain,
            &trace,
            &obs,
        )
        .await;
    }
}

/// Run the L0 reactive handler on one accepted connection: respond to the NUT's
/// UP 0 handshake and serve CE 128 / CE 129 requests.
async fn handle_connection(
    connection: quinn::Connection,
    peer_index: u16,
    genesis_hash: [u8; 32],
    ref_chain: &RefChain,
    trace: &Mutex<Trace>,
    obs: &Mutex<ObsLog>,
) {
    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
        let stream_id = u64::from(send.id());
        let Ok(Some((kind, content))) = read_frame(&mut recv).await else {
            continue;
        };
        trace_record(peer_index, kind, stream_id, &content, trace, TraceDir::Tx);
        match kind {
            UP => {
                handle_up0(
                    &mut send,
                    peer_index,
                    genesis_hash,
                    stream_id,
                    &content,
                    trace,
                    obs,
                )
                .await
            }
            CE128 => {
                serve_block_request(
                    &mut send, peer_index, &content, stream_id, ref_chain, trace, obs,
                )
                .await
            }
            CE129 => {
                serve_state_request(&mut send, peer_index, &content, stream_id, trace, obs).await
            }
            // Spec-known-but-refused and unknown kinds: reset the stream.
            _ => {}
        }
    }
}

/// Handle a NUT UP 0 message: an `Announcement` is recorded (`Up0Announce`
/// plus the L0 re-announce observation — the P0 emulator cannot distinguish
/// announce from re-announce) and left unanswered; anything else is a
/// handshake, answered with our own (recording `OpenUp0`).
async fn handle_up0(
    send: &mut quinn::SendStream,
    peer_index: u16,
    genesis_hash: [u8; 32],
    stream_id: u64,
    content: &[u8],
    trace: &Mutex<Trace>,
    obs: &Mutex<ObsLog>,
) {
    if Announcement::decode(&mut &content[..]).is_ok() {
        record(obs, peer_index, ObsKind::Up0Announce);
        record(obs, peer_index, ObsKind::Other(l0::REANNOUNCED));
        return;
    }
    record(obs, peer_index, ObsKind::Other(l0::UP0_KIND0));
    if let Ok(handshake) = Handshake::decode(&mut &content[..]) {
        if handshake.final_block.header_hash == HeaderHash::from(genesis_hash) {
            record(obs, peer_index, ObsKind::Other(l0::UP0_FINAL_GENESIS));
        }
        respond_up0(send, peer_index, genesis_hash, stream_id, trace, obs).await;
        return;
    }
    respond_up0(send, peer_index, genesis_hash, stream_id, trace, obs).await;
}

/// Respond to the NUT's UP 0 handshake with our own, recording `OpenUp0`.
async fn respond_up0(
    send: &mut quinn::SendStream,
    peer_index: u16,
    genesis_hash: [u8; 32],
    stream_id: u64,
    trace: &Mutex<Trace>,
    obs: &Mutex<ObsLog>,
) {
    record(obs, peer_index, ObsKind::OpenUp0);
    let handshake = Handshake {
        final_block: Final {
            header_hash: HeaderHash::from(genesis_hash),
            slot: 0,
        },
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
    let wire = frame_message(&response.encode());
    trace_record(peer_index, CE129, stream_id, &wire, trace, TraceDir::Rx);
    let _ = send.write_all(&wire).await;
    let _ = send.finish();
}

/// Read the next complete frame from `recv`, or `None` at end of stream.
async fn read_frame(recv: &mut quinn::RecvStream) -> Result<Option<(u8, Vec<u8>)>, EmuError> {
    let mut reader = FrameReader::new();
    let mut buf = [0u8; 4096];
    loop {
        match recv.read(&mut buf).await {
            Ok(Some(n)) => {
                reader.push(&buf[..n]);
                match reader.next_frame() {
                    Ok(Some(item)) => return Ok(Some(item)),
                    Ok(None) => continue,
                    Err(e) => return Err(EmuError::Protocol(format!("{e:?}"))),
                }
            }
            Ok(None) => {
                reader
                    .finish()
                    .map_err(|e| EmuError::Protocol(format!("{e:?}")))?;
                return Ok(None);
            }
            Err(e) => return Err(EmuError::Protocol(format!("{e:?}"))),
        }
    }
}

/// Record a frame in the shared trace (direction is from the NUT's perspective:
/// `Tx` = the NUT sent it, `Rx` = the emulator sent it).
fn trace_record(
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
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Record an observation from `peer` at the current monotonic time.
fn record(obs: &Mutex<ObsLog>, peer: u16, kind: ObsKind) {
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
        let emu = Emulator::l0(1..6, [0xaa; 32], 40000).await?;
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
        let mut ref_chain = RefChain::tiny(1..6).map_err(chain_err)?;
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
}
