//! L1 block-fetch behavior: when the NUT announces a block that is not in the
//! reference chain, the emulator fetches it over CE 128 and records it.

use std::sync::Mutex;

use jam_std_common::Block;
use jam_types::{Decode, Encode, HeaderHash};
use jamnp_s::{
    codec::ce128_129::{BlockRequest, BlockResponse, Direction},
    framing::{frame, FrameReader, CE128},
    trace::{wall_ts, Direction as TraceDir, Trace},
};
use m2_reference::chain::RefChain;
use m2_scenario::ctx::NutBlock;
use m2_scenario::dsl::{ObsKind, ObsLog};

use crate::emu::{lock, record, trace_record, EmuError};

/// True when `hash` is neither in the reference chain nor already fetched, so
/// the emulator must fetch the block from the announcing node.
///
/// The NUT announces each of its blocks to every peer it is connected to, so
/// without the second test the same block is fetched once per peer and
/// recorded that many times. Six copies of two blocks then read as four
/// equivocations, because every copy shares its parent with the original.
pub fn should_fetch(
    hash: &[u8; 32],
    ref_chain: &RefChain,
    nut_blocks: &Mutex<Vec<NutBlock>>,
) -> bool {
    let known_locally = ref_chain
        .chain_blocks()
        .iter()
        .any(|block| block.header.hash().0 == *hash);
    !known_locally && !already_fetched(nut_blocks, hash)
}

fn already_fetched(nut_blocks: &Mutex<Vec<NutBlock>>, hash: &[u8; 32]) -> bool {
    lock(nut_blocks)
        .iter()
        .any(|nut| nut.block.header.hash().0 == *hash)
}

/// Fetch the announced block via CE 128 (`DescendingInclusive`, `max_blocks =
/// 1`) and, on exactly one block, record `AuthorsBlock` and store it.
pub async fn fetch_block(
    connection: &quinn::Connection,
    announced_hash: [u8; 32],
    trace: &Mutex<Trace>,
    obs: &Mutex<ObsLog>,
    peer: u16,
    nut_blocks: &Mutex<Vec<NutBlock>>,
) -> Result<(), EmuError> {
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|e| EmuError::Protocol(e.to_string()))?;
    let request = BlockRequest {
        header_hash: HeaderHash::from(announced_hash),
        direction: Direction::DescendingInclusive,
        max_blocks: 1,
    };
    let wire = frame(CE128, &request.encode());
    trace_record(
        peer,
        CE128,
        u64::from(send.id()),
        &wire,
        trace,
        TraceDir::Rx,
    );
    send.write_all(&wire)
        .await
        .map_err(|e| EmuError::Protocol(e.to_string()))?;
    let _ = send.finish();
    let Some(content) = read_response(&mut recv).await? else {
        return Err(EmuError::Protocol(
            "CE 128 response stream ended early".into(),
        ));
    };
    trace_record(
        peer,
        CE128,
        u64::from(send.id()),
        &content,
        trace,
        TraceDir::Tx,
    );
    let response =
        BlockResponse::decode(&mut &content[..]).map_err(|e| EmuError::Decode(format!("{e:?}")))?;
    let [block] = response.blocks.as_slice() else {
        return Err(EmuError::Protocol(format!(
            "CE 128 returned {} blocks for a single fetch",
            response.blocks.len()
        )));
    };
    record_block(obs, peer, nut_blocks, block.clone());
    Ok(())
}

/// Record a successfully fetched NUT block: `AuthorsBlock` + store entry.
///
/// Deduplicated under the store's own lock, which is what actually guarantees
/// one entry per block: two peers can both pass [`should_fetch`] before either
/// has recorded, and then both arrive here with the same block.
fn record_block(obs: &Mutex<ObsLog>, peer: u16, nut_blocks: &Mutex<Vec<NutBlock>>, block: Block) {
    let hash = block.header.hash().0;
    let mut store = lock(nut_blocks);
    if store.iter().any(|nut| nut.block.header.hash().0 == hash) {
        return;
    }
    store.push(NutBlock {
        block,
        announced_wall_ms: wall_ts(),
    });
    drop(store);
    record(obs, peer, ObsKind::AuthorsBlock);
}

/// Read the single response frame on a CE 128 fetch stream. The responder
/// replies without a kind byte (the request established it), so the reader is
/// seeded with the request's kind before reading (simple.md:122-124).
async fn read_response(recv: &mut quinn::RecvStream) -> Result<Option<Vec<u8>>, EmuError> {
    let mut reader = FrameReader::new();
    reader.push(&[CE128]);
    let mut buf = [0u8; 4096];
    loop {
        match recv.read(&mut buf).await {
            Ok(Some(n)) => {
                reader.push(&buf[..n]);
                match reader.next_frame() {
                    Ok(Some((_kind, content))) => return Ok(Some(content)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use jamnp_s::framing::frame_message;
    use m2_reference::chain::RefChain;

    #[test]
    fn should_fetch_known_and_unknown() {
        let ref_chain = RefChain::tiny(0).expect("tiny chain builds");
        let known = ref_chain.chain_blocks()[0].header.hash().0;
        let store = Mutex::new(Vec::new());
        assert!(!should_fetch(&known, &ref_chain, &store));
        assert!(should_fetch(&[0xee; 32], &ref_chain, &store));

        // Announced again by another peer, after the first fetch recorded it:
        // the NUT announces every block to every peer it is connected to.
        record_block(
            &Mutex::new(ObsLog::new()),
            1,
            &store,
            ref_chain.chain_blocks()[0].clone(),
        );
        let fetched = ref_chain.chain_blocks()[0].header.hash().0;
        assert!(
            !should_fetch(&fetched, &ref_chain, &store),
            "a block already fetched is not fetched again"
        );
        assert_eq!(lock(&store).len(), 1);

        // And the duplicate is refused at the store even when two peers race
        // past `should_fetch` together.
        record_block(
            &Mutex::new(ObsLog::new()),
            2,
            &store,
            ref_chain.chain_blocks()[0].clone(),
        );
        assert_eq!(lock(&store).len(), 1, "the store holds one copy per block");
    }

    #[test]
    fn fetch_decodes_served_block() {
        let ref_chain = RefChain::tiny(0).expect("tiny chain builds");
        let block = ref_chain.chain_blocks()[0].clone();
        let response = BlockResponse {
            blocks: vec![block.clone()],
        };
        // The responder replies without a kind byte; the fetch path seeds its
        // FrameReader with the request's kind (simple.md:122-124).
        let mut reader = FrameReader::new();
        reader.push(&[CE128]);
        reader.push(&frame_message(&response.encode()));
        let (kind, content) = reader
            .next_frame()
            .expect("one frame")
            .expect("complete frame");
        assert_eq!(kind, CE128);
        let decoded = BlockResponse::decode(&mut &content[..]).expect("response decodes");
        assert_eq!(decoded.blocks.len(), 1);
        assert_eq!(decoded.blocks[0].header.hash().0, block.header.hash().0);
    }

    #[test]
    fn nut_blocks_store_records_authors() {
        let ref_chain = RefChain::tiny(0).expect("tiny chain builds");
        let block = ref_chain.chain_blocks()[0].clone();
        let obs = Mutex::new(ObsLog::new());
        let nut_blocks = Mutex::new(Vec::new());
        record_block(&obs, 1, &nut_blocks, block.clone());
        let stored = nut_blocks.lock().unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].block.header.hash().0, block.header.hash().0);
        assert!(stored[0].announced_wall_ms > 0);
    }
}
