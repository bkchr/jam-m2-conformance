//! Message trace recorder for JAMNP-S sessions (DESIGN.md §9).
//!
//! Every JAMNP message is recorded as a [`TraceRecord`] with direction, peer
//! index, stream kind/id, timestamps and raw bytes. A [`Trace`] writes three
//! artefacts to a directory:
//!
//! - `jamnp.bin` — the canonical replay artifact: each record as
//!   `u32 LE length ++ record.encode()` (frame length-prefix mirrors
//!   polkajam-fuzz `remote.rs:257-262`).
//! - `jamnp.json` — a readable JSON mirror (array of records).
//! - `tx/{:08}_tx.bin` / `rx/{:08}_rx.bin` — per-direction per-record dumps
//!   following the polkajam-fuzz `FUZZ_PROTOCOL_TRACE_DIR` naming
//!   (`remote.rs:248-253, 299-305`), one encoded record per file.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Message direction for a traced record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Outgoing message (node under test → emulated peer).
    Tx,
    /// Incoming message (emulated peer → node under test).
    Rx,
}

/// A single traced JAMNP message with its metadata.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TraceRecord {
    pub direction: Direction,
    pub peer_index: u16,
    pub stream_kind: u8,
    pub stream_id: u64,
    pub mono_ts: u64,
    pub wall_ts: u64,
    pub bytes: Vec<u8>,
}

impl TraceRecord {
    /// Deterministic binary encoding, round-trippable via [`decode_record`]:
    /// `u8 direction (0=Tx, 1=Rx) ++ u16 LE peer ++ u8 kind ++ u64 LE stream
    /// id ++ u64 LE mono_ts ++ u64 LE wall_ts ++ u32 LE len ++ bytes`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 2 + 1 + 8 + 8 + 8 + 4 + self.bytes.len());
        out.push(match self.direction {
            Direction::Tx => 0,
            Direction::Rx => 1,
        });
        out.extend_from_slice(&self.peer_index.to_le_bytes());
        out.push(self.stream_kind);
        out.extend_from_slice(&self.stream_id.to_le_bytes());
        out.extend_from_slice(&self.mono_ts.to_le_bytes());
        out.extend_from_slice(&self.wall_ts.to_le_bytes());
        out.extend_from_slice(&(self.bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.bytes);
        out
    }
}

/// Decode a record from [`TraceRecord::encode`]; `None` on malformed input.
pub fn decode_record(bytes: &[u8]) -> Option<TraceRecord> {
    const DIR: std::ops::Range<usize> = 0..1;
    const PEER: std::ops::Range<usize> = 1..3;
    const KIND: std::ops::Range<usize> = 3..4;
    const STREAM: std::ops::Range<usize> = 4..12;
    const MONO: std::ops::Range<usize> = 12..20;
    const WALL: std::ops::Range<usize> = 20..28;
    const LEN: std::ops::Range<usize> = 28..32;
    if bytes.len() < LEN.end {
        return None;
    }
    let direction = match bytes[DIR] {
        [0] => Direction::Tx,
        [1] => Direction::Rx,
        _ => return None,
    };
    let len = u32::from_le_bytes(bytes[LEN].try_into().ok()?) as usize;
    let payload = bytes.get(LEN.end..LEN.end + len)?;
    Some(TraceRecord {
        direction,
        peer_index: u16::from_le_bytes(bytes[PEER].try_into().ok()?),
        stream_kind: bytes[KIND][0],
        stream_id: u64::from_le_bytes(bytes[STREAM].try_into().ok()?),
        mono_ts: u64::from_le_bytes(bytes[MONO].try_into().ok()?),
        wall_ts: u64::from_le_bytes(bytes[WALL].try_into().ok()?),
        bytes: payload.to_vec(),
    })
}

/// Monotonic-relative timestamp in milliseconds (origin = first call).
pub fn mono_ts() -> u64 {
    static ORIGIN: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let origin = *ORIGIN.get_or_init(std::time::Instant::now);
    origin.elapsed().as_millis() as u64
}

/// Wall-clock timestamp in milliseconds since the Unix epoch.
pub fn wall_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Ordered trace of JAMNP messages.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Trace {
    records: Vec<TraceRecord>,
}

impl Trace {
    /// Append a record; its position becomes its filename index.
    pub fn push(&mut self, rec: TraceRecord) {
        self.records.push(rec);
    }

    /// Number of records in the trace.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// The traced records, in observation order.
    pub fn records(&self) -> &[TraceRecord] {
        &self.records
    }

    /// Whether the trace holds no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Write the canonical binary, JSON mirror and per-direction dumps.
    pub fn write_dir(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::create_dir_all(dir.join("tx"))?;
        std::fs::create_dir_all(dir.join("rx"))?;

        // Canonical replay artifact: u32 LE length ++ record.encode() per frame.
        let mut bin = Vec::new();
        for rec in &self.records {
            let encoded = rec.encode();
            bin.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            bin.extend_from_slice(&encoded);
        }
        std::fs::write(dir.join("jamnp.bin"), bin)?;

        let json = serde_json::to_vec(&self.records)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(dir.join("jamnp.json"), json)?;

        // Per-direction dumps, `{:08}_{tx|rx}.bin`, counter per direction.
        let (mut tx, mut rx) = (0u32, 0u32);
        for rec in &self.records {
            let (counter, sub) = match rec.direction {
                Direction::Tx => {
                    let c = tx;
                    tx += 1;
                    (c, "tx")
                }
                Direction::Rx => {
                    let c = rx;
                    rx += 1;
                    (c, "rx")
                }
            };
            std::fs::write(
                dir.join(sub).join(format!("{counter:08}_{sub}.bin")),
                rec.encode(),
            )?;
        }
        Ok(())
    }
}

/// Read back the records from the JSON mirror (`jamnp.json`).
///
/// Returns an empty trace if the mirror is missing or malformed.
pub fn read_dir(dir: &Path) -> Vec<TraceRecord> {
    let Ok(raw) = std::fs::read_to_string(dir.join("jamnp.json")) else {
        return Vec::new();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Unique temp directory under `std::env::temp_dir()`, removed on drop.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "jamnp_trace_{name}_{}_{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&path);
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn record(direction: Direction, peer: u16, kind: u8, id: u64, bytes: &[u8]) -> TraceRecord {
        TraceRecord {
            direction,
            peer_index: peer,
            stream_kind: kind,
            stream_id: id,
            mono_ts: 0,
            wall_ts: 0,
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn roundtrip_via_read_dir() {
        let tmp = TempDir::new("roundtrip");
        let mut trace = Trace::default();
        trace.push(record(Direction::Tx, 0, 1, 7, &[1, 2, 3]));
        trace.push(record(Direction::Rx, 1, 2, 8, &[4, 5]));
        trace.push(record(Direction::Tx, 2, 3, 9, &[]));
        trace.write_dir(tmp.path()).expect("write_dir succeeds");
        assert_eq!(read_dir(tmp.path()), trace.records);
    }

    #[test]
    fn json_mirror_is_expected_array() {
        let tmp = TempDir::new("json");
        let mut trace = Trace::default();
        trace.push(record(Direction::Tx, 1, 2, 3, &[9, 8]));
        trace.push(record(Direction::Rx, 4, 5, 6, &[7]));
        trace.push(record(Direction::Tx, 0, 0, 0, &[]));
        trace.write_dir(tmp.path()).expect("write_dir succeeds");
        let raw = std::fs::read_to_string(tmp.path().join("jamnp.json")).expect("mirror exists");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("mirror is valid JSON");
        let arr = value.as_array().expect("mirror is an array");
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0]["direction"], "tx");
        assert_eq!(arr[0]["peer_index"], 1);
        assert_eq!(arr[0]["stream_kind"], 2);
        assert_eq!(arr[0]["stream_id"], 3);
        assert_eq!(arr[1]["direction"], "rx");
        assert_eq!(arr[1]["bytes"], serde_json::json!([7]));
        assert_eq!(arr[2]["direction"], "tx");
        assert!(arr[2]["bytes"].as_array().is_some_and(|b| b.is_empty()));
    }

    #[test]
    fn per_direction_file_naming_and_content() {
        let tmp = TempDir::new("naming");
        let mut trace = Trace::default();
        let tx0 = record(Direction::Tx, 0, 1, 0, &[1]);
        let tx1 = record(Direction::Tx, 0, 1, 0, &[2]);
        let rx0 = record(Direction::Rx, 0, 1, 0, &[3]);
        let tx2 = record(Direction::Tx, 0, 1, 0, &[4]);
        let rx1 = record(Direction::Rx, 0, 1, 0, &[5]);
        for rec in [&tx0, &tx1, &rx0, &tx2, &rx1] {
            trace.push(rec.clone());
        }
        trace.write_dir(tmp.path()).expect("write_dir succeeds");

        let mut tx_names: Vec<String> = std::fs::read_dir(tmp.path().join("tx"))
            .expect("tx dir exists")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        tx_names.sort();
        assert_eq!(
            tx_names,
            ["00000000_tx.bin", "00000001_tx.bin", "00000002_tx.bin"]
        );

        let mut rx_names: Vec<String> = std::fs::read_dir(tmp.path().join("rx"))
            .expect("rx dir exists")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        rx_names.sort();
        assert_eq!(rx_names, ["00000000_rx.bin", "00000001_rx.bin"]);

        let read = |sub: &str, name: &str| {
            decode_record(
                &std::fs::read(tmp.path().join(sub).join(name)).expect("dump file exists"),
            )
            .expect("dump decodes")
        };
        assert_eq!(read("tx", "00000000_tx.bin"), tx0);
        assert_eq!(read("tx", "00000002_tx.bin"), tx2);
        assert_eq!(read("rx", "00000001_rx.bin"), rx1);
    }

    #[test]
    fn empty_trace_writes_valid_outputs() {
        let tmp = TempDir::new("empty");
        Trace::default()
            .write_dir(tmp.path())
            .expect("write_dir succeeds");
        assert_eq!(
            std::fs::read(tmp.path().join("jamnp.bin")).expect("bin exists"),
            b""
        );
        let value: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(tmp.path().join("jamnp.json")).expect("mirror exists"),
        )
        .expect("mirror is valid JSON");
        assert_eq!(value, serde_json::json!([]));
        assert!(read_dir(tmp.path()).is_empty());
    }

    #[test]
    fn deterministic_jamnp_bin() {
        let a = TempDir::new("det_a");
        let b = TempDir::new("det_b");
        let mut trace = Trace::default();
        trace.push(record(Direction::Tx, 1, 2, 3, &[1, 2, 3]));
        trace.push(record(Direction::Rx, 4, 5, 6, &[9, 8, 7, 6]));
        trace.write_dir(a.path()).expect("write_dir succeeds");
        trace.write_dir(b.path()).expect("write_dir succeeds");
        assert_eq!(
            std::fs::read(a.path().join("jamnp.bin")).expect("bin exists"),
            std::fs::read(b.path().join("jamnp.bin")).expect("bin exists")
        );
    }

    #[test]
    fn encode_decode_record_roundtrip() {
        let rec = record(Direction::Rx, u16::MAX, u8::MAX, u64::MAX, &[0, 1, 2, 255]);
        assert_eq!(decode_record(&rec.encode()).expect("decodes"), rec);
        assert!(decode_record(&[]).is_none());
        assert!(decode_record(&[0u8; 10]).is_none());
        assert!(decode_record(&[
            2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0
        ])
        .is_none());
    }

    #[test]
    fn timestamps_are_sane() {
        let m = mono_ts();
        let w = wall_ts();
        // Wall clock is millis since the Unix epoch (year 2026 ≫ ~1.7e12).
        assert!(w > 1_700_000_000_000);
        // Monotonic origin is process start; allow a little headroom.
        assert!(m < 100_000_000);
    }
}
