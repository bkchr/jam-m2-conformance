//! N0 sync-serving probes: the emulator *asks* the node under test for blocks
//! and state, and records what came back.
//!
//! The CE 128 and CE 129 checks are assertions about the node as a server
//! (`simple.md:238-303`, DESIGN §11). Nothing used to make these requests, so
//! the lane graded the emulator's own replies to the node instead and could
//! neither pass nor fail on anything the node did.

use std::sync::Mutex;

use jam_types::{Decode, Encode, HeaderHash};
use jamnp_s::{
    clock,
    codec::ce128_129::{
        BlockRequest, BlockResponse, BoundaryNodes, Direction, KeyValues, StateRequest,
    },
    framing::{frame, FrameReader, CE128, CE129},
    trace::{Direction as TraceDir, Trace},
    transport::Conn,
};
use m2_scenario::scenarios::n0::{Ce128Probe, Ce129Probe, ProbedBlock};

use crate::emu::{trace_record, EmuError, EmuShared};

/// Blocks asked for in the ascending walk. Larger than any chain a run
/// produces, so a conforming node returns everything it has and the reply can
/// be compared against the reference chain in full rather than truncated.
const CE128_MAX_BLOCKS: u32 = 64;

/// Byte budget for the state request. Small enough that a node holding real
/// state must truncate, which is what makes the size cap observable.
const CE129_MAX_SIZE: u32 = 16 * 1024;

/// Seconds to let the node sync before asking it to serve.
///
/// A node that has not caught up has nothing to answer with, and an empty
/// reply would be graded as a defect rather than as a probe fired too early.
pub const PROBE_DELAY_SECS: u64 = 20;

/// Ask the node for every block after `from`, ascending.
pub async fn probe_ce128(
    connection: &Conn,
    peer: u16,
    from: [u8; 32],
    trace: &Mutex<Trace>,
) -> Ce128Probe {
    let mut probe = Ce128Probe {
        peer,
        max_blocks: CE128_MAX_BLOCKS,
        from,
        returned: Vec::new(),
        finished: false,
        error: None,
    };
    let request = BlockRequest {
        header_hash: HeaderHash::from(from),
        direction: Direction::AscendingExclusive,
        max_blocks: CE128_MAX_BLOCKS,
    };
    match request_frames(connection, peer, CE128, &request.encode(), 1, trace).await {
        Ok((frames, finished)) => {
            probe.finished = finished;
            match frames.first() {
                Some(content) => match BlockResponse::decode(&mut &content[..]) {
                    Ok(response) => {
                        probe.returned = response
                            .blocks
                            .iter()
                            .map(|block| ProbedBlock {
                                slot: block.header.slot,
                                hash: block.header.hash().0,
                                parent: block.header.parent.0,
                            })
                            .collect();
                    }
                    Err(e) => probe.error = Some(format!("undecodable CE 128 response: {e:?}")),
                },
                None => probe.error = Some("the node sent no CE 128 response".into()),
            }
        }
        Err(e) => probe.error = Some(e.to_string()),
    }
    probe
}

/// Ask the node for a slice of the state at one of `candidates`, trying the
/// next when it answers "no data".
///
/// polkajam kills the stream with its `NoData` code (`0x52e4a40fa8e1`) when it
/// holds the block but not its state, which is a legitimate answer rather than
/// a defect: asking at the chain head and reporting the reset as a failure
/// would grade the node on which states it happens to retain. The genesis
/// header is the fallback because every node holds its state.
pub async fn probe_ce129_at(
    connection: &Conn,
    peer: u16,
    candidates: &[[u8; 32]],
    trace: &Mutex<Trace>,
) -> Ce129Probe {
    let mut last = None;
    for candidate in candidates {
        let probe = probe_ce129(connection, peer, *candidate, trace).await;
        let no_data = probe
            .error
            .as_deref()
            .is_some_and(|e| e.contains(NO_DATA_RESET));
        if !no_data {
            return probe;
        }
        last = Some(probe);
    }
    last.unwrap_or_else(|| empty_ce129(peer, "no header to ask about".to_string()))
}

/// polkajam's `NoData` application error code, as the transport reports it.
///
/// Matched inside the rendered error rather than on a variant: the probe keeps
/// what it saw as a string, and `ReadError::Reset` prints its code, so the
/// number is there either way.
const NO_DATA_RESET: &str = "91141958510817";

fn empty_ce129(peer: u16, error: String) -> Ce129Probe {
    Ce129Probe {
        peer,
        start: [0u8; 31],
        end: [0xffu8; 31],
        max_size: CE129_MAX_SIZE,
        keys: Vec::new(),
        boundary_nodes: Vec::new(),
        response_bytes: 0,
        entry_bytes: Vec::new(),
        decoded: false,
        error: Some(error),
    }
}

/// Ask the node for a slice of the state at `header_hash`.
pub async fn probe_ce129(
    connection: &Conn,
    peer: u16,
    header_hash: [u8; 32],
    trace: &Mutex<Trace>,
) -> Ce129Probe {
    let (start, end) = ([0u8; 31], [0xffu8; 31]);
    let mut probe = Ce129Probe {
        peer,
        start,
        end,
        max_size: CE129_MAX_SIZE,
        keys: Vec::new(),
        boundary_nodes: Vec::new(),
        response_bytes: 0,
        entry_bytes: Vec::new(),
        decoded: false,
        error: None,
    };
    let request = StateRequest {
        header_hash: HeaderHash::from(header_hash),
        start,
        end,
        max_size: CE129_MAX_SIZE,
    };
    // Two messages then FIN (`simple.md:300-302`): boundary nodes, then pairs.
    match request_frames(connection, peer, CE129, &request.encode(), 2, trace).await {
        Ok((frames, finished)) => {
            probe.response_bytes = frames.iter().map(Vec::len).sum();
            let [nodes, entries] = frames.as_slice() else {
                probe.error = Some(format!(
                    "CE 129 answered with {} message(s), expected 2",
                    frames.len()
                ));
                return probe;
            };
            if !finished {
                probe.error = Some("the node did not FIN its CE 129 response stream".into());
            }
            match (
                BoundaryNodes::decode(&mut &nodes[..]),
                KeyValues::decode(&mut &entries[..]),
            ) {
                (Ok(nodes), Ok(pairs)) => {
                    probe.decoded = true;
                    probe.boundary_nodes = nodes.0.iter().map(|n| n.0).collect();
                    probe.keys = pairs.0.iter().map(|kv| kv.key).collect();
                    probe.entry_bytes = pairs
                        .0
                        .iter()
                        .map(|kv| kv.key.len() + kv.value.len())
                        .collect();
                }
                (Err(e), _) | (_, Err(e)) => {
                    probe.error = Some(format!("undecodable CE 129 response: {e:?}"));
                }
            }
        }
        Err(e) => probe.error = Some(e.to_string()),
    }
    probe
}

/// Open a stream of `kind`, write `payload`, and read `want` response messages.
///
/// Returns the messages and whether the node closed the stream cleanly after
/// them, which is the "both halves FIN" assertion.
async fn request_frames(
    connection: &Conn,
    peer: u16,
    kind: u8,
    payload: &[u8],
    want: usize,
    trace: &Mutex<Trace>,
) -> Result<(Vec<Vec<u8>>, bool), EmuError> {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|e| EmuError::Protocol(e.to_string()))?;
    let stream_id = send.id();
    let wire = frame(kind, payload);
    trace_record(peer, kind, stream_id, &wire, trace, TraceDir::Rx);
    send.write_all(&wire)
        .await
        .map_err(|e| EmuError::Protocol(e.to_string()))?;
    send.finish();

    // We opened the stream, so we wrote the kind byte; the node's replies are
    // bare `[len: u32 LE] ++ [content]` messages on this half.
    let mut reader = FrameReader::with_kind(kind);
    let mut frames = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match recv.read(&mut buf).await {
            Ok(Some(n)) => {
                reader.push(&buf[..n]);
                loop {
                    match reader.next_frame() {
                        Ok(Some((_, content))) => {
                            trace_record(peer, kind, stream_id, &content, trace, TraceDir::Tx);
                            frames.push(content);
                        }
                        Ok(None) => break,
                        Err(e) => return Err(EmuError::Protocol(format!("{e:?}"))),
                    }
                }
                if frames.len() >= want {
                    // Read on to the FIN so a trailing message or a dirty close
                    // is seen rather than assumed away.
                    continue;
                }
            }
            // Clean end of stream: the node FIN'd.
            Ok(None) => {
                let clean = reader.finish().is_ok();
                return Ok((frames, clean));
            }
            Err(e) => return Err(EmuError::Protocol(format!("{e:?}"))),
        }
    }
}

/// Run both sync probes once per run, on the first connection to offer.
///
/// Once, not per peer: the probes are assertions about the node, and five
/// copies of the same answer would be five identical rows in the report.
pub fn start_sync_probe(connection: &Conn, peer: u16, shared: &EmuShared) {
    if !shared.claim_sync_probe() {
        return;
    }
    let connection = connection.clone();
    let shared = shared.clone();
    tokio::spawn(async move {
        clock::current()
            .sleep(std::time::Duration::from_secs(PROBE_DELAY_SECS))
            .await;
        let genesis = shared.ref_chain.genesis_hash();
        let ce128 = probe_ce128(&connection, peer, genesis, &shared.trace).await;
        // Ask at the newest block the node told us about, falling back to
        // genesis when it holds the block but not its state.
        let mut candidates: Vec<[u8; 32]> =
            ce128.returned.last().map(|b| b.hash).into_iter().collect();
        candidates.push(genesis);
        let ce129 = probe_ce129_at(&connection, peer, &candidates, &shared.trace).await;
        crate::emu::lock(&shared.ce128_probes).push(ce128);
        crate::emu::lock(&shared.ce129_probes).push(ce129);
    });
}
