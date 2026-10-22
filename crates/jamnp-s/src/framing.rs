//! Stream framing for JAMNP-S.
//!
//! Wire model per `jam-np/simple.md:102-130`: the stream initiator sends the
//! single stream-kind byte once when the stream opens (`:122-124`); after that,
//! every message is `[content len: u32 LE] ++ [content]` (`:126-130`). So a
//! stream is `[kind] ++ [len]++[content] ++ [len]++[content] ++ ...`:
//! [`frame`] encodes the stream-opening message (kind + length + content),
//! [`frame_message`] every subsequent one (length + content).
//!
//! Stream kinds are classified into Unique Persistent (UP) kinds (`0..=127`)
//! and Common Ephemeral (CE) kinds (`128..=255`); this spec only defines UP 0.
//! The harness protocol surface is UP 0 and CE 128, 129, 131..=148 (there is no
//! CE 130, DESIGN.md `:54`). CE 130 and the GRANDPA kinds 149..=152 (DESIGN.md
//! `:379`) are spec-known but refused; any other byte is an unknown kind.

/// UP 0: Block announcement (`simple.md:192-236`).
pub const UP: u8 = 0;

/// CE 128: Block request (`simple.md:238-265`).
pub const CE128: u8 = 128;
/// CE 129: State request (`simple.md:267-303`).
pub const CE129: u8 = 129;
// CE 130 is reserved: no protocol in `simple.md`, refused (see `validate_kind`).
/// CE 131: Safrole ticket distribution, step 1 (`simple.md:305-349`).
pub const CE131: u8 = 131;
/// CE 132: Safrole ticket distribution, step 2 (`simple.md:305-349`).
pub const CE132: u8 = 132;
/// CE 133: Work-package submission (`simple.md:351-376`).
pub const CE133: u8 = 133;
/// CE 134: Work-package sharing (`simple.md:406-458`).
pub const CE134: u8 = 134;
/// CE 135: Work-report distribution (`simple.md:460-485`).
pub const CE135: u8 = 135;
/// CE 136: Work-report request (`simple.md:487-504`).
pub const CE136: u8 = 136;
/// CE 137: Shard distribution (`simple.md:523-556`).
pub const CE137: u8 = 137;
/// CE 138: Audit shard request (`simple.md:558-580`).
pub const CE138: u8 = 138;
/// CE 139: Segment shard request without justification (`simple.md:597-648`).
pub const CE139: u8 = 139;
/// CE 140: Segment shard request with justification (`simple.md:597-648`).
pub const CE140: u8 = 140;
/// CE 141: Assurance distribution (`simple.md:675-695`).
pub const CE141: u8 = 141;
/// CE 142: Preimage announcement (`simple.md:697-724`).
pub const CE142: u8 = 142;
/// CE 143: Preimage request (`simple.md:727-741`).
pub const CE143: u8 = 143;
/// CE 144: Audit announcement (`simple.md:743-793`).
pub const CE144: u8 = 144;
/// CE 145: Judgment publication (`simple.md:795-833`).
pub const CE145: u8 = 145;
/// CE 146: Work-package bundle submission (`simple.md:378-404`).
pub const CE146: u8 = 146;
/// CE 147: Bundle request (`simple.md:582-595`).
pub const CE147: u8 = 147;
/// CE 148: Segment request (`simple.md:650-673`).
pub const CE148: u8 = 148;

/// Maximum accepted message content length in bytes.
pub const MAX_FRAME_SIZE: usize = 256 * 1024 * 1024;

/// Spec-known stream kinds refused by the harness: CE 130 (reserved, DESIGN.md
/// `:54`) and the GRANDPA kinds 149..=152 (DESIGN.md `:379`).
const REFUSED_KINDS: [u8; 5] = [130, 149, 150, 151, 152];

/// Whether `kind` is a Unique Persistent (UP) stream kind (`< 128`).
pub fn is_up(kind: u8) -> bool {
    kind < 128
}

/// Whether `kind` is a Common Ephemeral (CE) stream kind (`>= 128`).
pub fn is_ce(kind: u8) -> bool {
    kind >= 128
}

/// Validates a stream-kind byte against the harness protocol surface.
fn validate_kind(kind: u8) -> Result<(), FrameError> {
    let known = kind == UP || ((CE128..=CE148).contains(&kind) && !REFUSED_KINDS.contains(&kind));
    if known {
        Ok(())
    } else if REFUSED_KINDS.contains(&kind) {
        Err(FrameError::RefusedKind(kind))
    } else {
        Err(FrameError::Kind(kind))
    }
}

/// Errors produced while reading frames from a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// A frame's length prefix declared more payload bytes than arrived.
    Truncated,
    /// A frame's length prefix exceeded [`MAX_FRAME_SIZE`].
    Oversize,
    /// Bytes remained after the final complete frame when the stream ended.
    TrailingBytes,
    /// Unknown stream-kind byte.
    Kind(u8),
    /// Spec-known stream-kind refused by the harness (CE 130, GRANDPA 149..=152).
    RefusedKind(u8),
}

/// Encodes the stream-opening message: `[kind] ++ [len: u32 LE] ++ [content]`.
/// The kind byte is sent exactly once per stream (`simple.md:122-124`); every
/// message after the first must use [`frame_message`].
pub fn frame(kind: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + content.len());
    out.push(kind);
    out.extend_from_slice(&(content.len() as u32).to_le_bytes());
    out.extend_from_slice(content);
    out
}

/// Encodes a message after the stream-opening kind byte: `[len: u32 LE] ++
/// [content]` (`simple.md:126-130`).
pub fn frame_message(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + content.len());
    out.extend_from_slice(&(content.len() as u32).to_le_bytes());
    out.extend_from_slice(content);
    out
}

/// Incremental frame reader that buffers pushed bytes and yields complete
/// messages as `(kind, content)`. The stream-opening kind byte is consumed
/// once on the first [`FrameReader::next_frame`] call; subsequent calls read
/// `[len: u32 LE] ++ [content]` messages under that same kind.
#[derive(Debug, Default)]
pub struct FrameReader {
    buf: Vec<u8>,
    kind: Option<u8>,
}

impl FrameReader {
    /// Creates an empty reader.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty reader for the half of a stream that carries no opening
    /// kind byte.
    ///
    /// The kind byte is written once by whoever opens the stream
    /// (`simple.md:122-124`), so on a bidirectional stream only the initiator's
    /// send half carries it. The responder answers with bare
    /// `[len: u32 LE] ++ [content]` messages, which a reader built by
    /// [`FrameReader::new`] would misread: it would take the first byte of the
    /// length prefix for the kind. Reading the initiator's receive half needs
    /// this constructor, told the kind the stream was opened with.
    pub fn with_kind(kind: u8) -> Self {
        Self {
            buf: Vec::new(),
            kind: Some(kind),
        }
    }

    /// Appends bytes to the reader's buffer.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Consumes the stream-opening kind byte if not yet read, then returns the
    /// next complete message, or `None` when more bytes are needed.
    ///
    /// Errors on an invalid or refused kind byte and on an oversize length prefix.
    pub fn next_frame(&mut self) -> Result<Option<(u8, Vec<u8>)>, FrameError> {
        let kind = match self.kind {
            Some(kind) => kind,
            None => {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                let kind = self.buf[0];
                validate_kind(kind)?;
                self.kind = Some(kind);
                self.buf.drain(0..1);
                kind
            }
        };
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_le_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if len > MAX_FRAME_SIZE {
            return Err(FrameError::Oversize);
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        let content = self.buf[4..4 + len].to_vec();
        self.buf.drain(0..4 + len);
        Ok(Some((kind, content)))
    }

    /// Signals end-of-stream: succeeds only when no bytes remain after the last
    /// complete message.
    ///
    /// Reports [`FrameError::TrailingBytes`] when complete message(s) were left
    /// unconsumed and [`FrameError::Truncated`] when a message's declared length
    /// was never satisfied.
    pub fn finish(&mut self) -> Result<(), FrameError> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let complete = match self.kind {
            None => {
                // The leftover starts with the stream-opening kind byte.
                if self.buf.len() < 5 {
                    false
                } else {
                    let kind = self.buf[0];
                    if validate_kind(kind).is_err() {
                        return Err(FrameError::TrailingBytes);
                    }
                    let len =
                        u32::from_le_bytes([self.buf[1], self.buf[2], self.buf[3], self.buf[4]])
                            as usize;
                    len <= MAX_FRAME_SIZE && self.buf.len() >= 5 + len
                }
            }
            Some(_) => {
                if self.buf.len() < 4 {
                    false
                } else {
                    let len =
                        u32::from_le_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]])
                            as usize;
                    len <= MAX_FRAME_SIZE && self.buf.len() >= 4 + len
                }
            }
        };
        if complete {
            Err(FrameError::TrailingBytes)
        } else {
            Err(FrameError::Truncated)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KINDS: [u8; 6] = [UP, CE128, CE129, CE133, CE146, CE148];
    const LENS: [usize; 6] = [0, 1, 255, 256, 65535, 200 * 1024];

    #[test]
    fn kind_classification() {
        assert!(is_up(0));
        assert!(is_up(127));
        assert!(!is_up(128));
        assert!(is_ce(128));
        assert!(is_ce(255));
        assert!(!is_ce(127));
    }

    #[test]
    fn frame_roundtrip_lengths() {
        for kind in KINDS {
            for len in LENS {
                let content: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
                let wire = frame(kind, &content);
                assert_eq!(wire.len(), 5 + len);
                assert_eq!(wire[0], kind);
                let declared = u32::from_le_bytes([wire[1], wire[2], wire[3], wire[4]]) as usize;
                assert_eq!(declared, len);
                assert_eq!(&wire[5..], &content[..]);
            }
        }
    }

    #[test]
    fn frame_message_roundtrip_lengths() {
        for len in LENS {
            let content: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let wire = frame_message(&content);
            assert_eq!(wire.len(), 4 + len);
            let declared = u32::from_le_bytes([wire[0], wire[1], wire[2], wire[3]]) as usize;
            assert_eq!(declared, len);
            assert_eq!(&wire[4..], &content[..]);
        }
    }

    #[test]
    fn reader_accumulates_split_pushes() {
        let content = vec![7u8; 300];
        let wire = frame(CE135, &content);
        let mut r = FrameReader::new();
        let mut got = None;
        for &b in &wire {
            r.push(&[b]);
            if let Some(f) = r.next_frame().unwrap() {
                got = Some(f);
            }
        }
        assert_eq!(got, Some((CE135, content)));
        assert_eq!(r.next_frame().unwrap(), None);
    }

    #[test]
    fn multiple_messages_in_one_push() {
        let mut r = FrameReader::new();
        let mut wire = frame(UP, b"a");
        wire.extend_from_slice(&frame_message(b"bb"));
        wire.extend_from_slice(&frame_message(&[0u8; 64]));
        r.push(&wire);
        // The kind byte is sent once; every message comes back under it.
        assert_eq!(r.next_frame().unwrap(), Some((UP, b"a".to_vec())));
        assert_eq!(r.next_frame().unwrap(), Some((UP, b"bb".to_vec())));
        assert_eq!(r.next_frame().unwrap(), Some((UP, vec![0u8; 64])));
        assert_eq!(r.next_frame().unwrap(), None);
        assert_eq!(r.finish(), Ok(()));
    }

    #[test]
    fn truncated_when_declared_len_shortfall() {
        let mut r = FrameReader::new();
        let wire = frame(CE128, &[1u8; 100]);
        r.push(&wire[..wire.len() - 10]);
        assert_eq!(r.next_frame().unwrap(), None);
        assert_eq!(r.finish(), Err(FrameError::Truncated));
    }

    #[test]
    fn truncated_on_incomplete_header() {
        let mut r = FrameReader::new();
        r.push(&frame(UP, &[1u8; 50])[..3]);
        assert_eq!(r.next_frame().unwrap(), None);
        assert_eq!(r.finish(), Err(FrameError::Truncated));
    }

    #[test]
    fn oversize_rejected_from_prefix() {
        let mut r = FrameReader::new();
        r.push(&[CE128]);
        r.push(&u32::MAX.to_le_bytes());
        assert_eq!(r.next_frame(), Err(FrameError::Oversize));
    }

    #[test]
    fn oversize_just_above_max() {
        let mut r = FrameReader::new();
        r.push(&[CE128]);
        r.push(&((MAX_FRAME_SIZE as u32) + 1).to_le_bytes());
        assert_eq!(r.next_frame(), Err(FrameError::Oversize));
    }

    #[test]
    fn refused_kinds() {
        for kind in REFUSED_KINDS {
            let mut r = FrameReader::new();
            r.push(&frame(kind, b"x"));
            assert_eq!(r.next_frame(), Err(FrameError::RefusedKind(kind)));
        }
    }

    #[test]
    fn unknown_kind_rejected() {
        for kind in [0xFEu8, 5, 200] {
            let mut r = FrameReader::new();
            r.push(&frame(kind, b"x"));
            assert_eq!(r.next_frame(), Err(FrameError::Kind(kind)));
        }
    }

    #[test]
    fn trailing_bytes_after_complete_message() {
        let mut r = FrameReader::new();
        let mut wire = frame(CE129, b"hello");
        wire.extend_from_slice(&frame_message(b"extra"));
        r.push(&wire);
        assert_eq!(r.next_frame().unwrap(), Some((CE129, b"hello".to_vec())));
        assert_eq!(r.finish(), Err(FrameError::TrailingBytes));
    }

    #[test]
    fn clean_finish_after_exact_frame() {
        let mut r = FrameReader::new();
        r.push(&frame(UP, b""));
        assert_eq!(r.next_frame().unwrap(), Some((UP, vec![])));
        assert_eq!(r.finish(), Ok(()));
    }

    #[test]
    fn unconsumed_frame_is_trailing() {
        let mut r = FrameReader::new();
        r.push(&frame(CE133, b"wp"));
        assert_eq!(r.finish(), Err(FrameError::TrailingBytes));
    }

    /// The responder's half of a stream carries no opening kind byte, so it is
    /// read by a reader that already knows the kind.
    #[test]
    fn with_kind_reads_bare_messages() {
        let mut r = FrameReader::with_kind(UP);
        let mut wire = frame_message(b"handshake");
        wire.extend_from_slice(&frame_message(b"announce"));
        r.push(&wire);
        assert_eq!(r.next_frame().unwrap(), Some((UP, b"handshake".to_vec())));
        assert_eq!(r.next_frame().unwrap(), Some((UP, b"announce".to_vec())));
        assert_eq!(r.finish(), Ok(()));
    }

    /// The bug this guards: a `new` reader on that same half takes the first
    /// byte of the length prefix for the kind. Here that byte is the payload
    /// length 9, not a stream kind, so the read fails outright -- and for a
    /// payload whose length happened to be a valid kind it would instead
    /// desynchronise silently.
    #[test]
    fn new_reader_cannot_read_a_half_without_a_kind_byte() {
        let mut r = FrameReader::new();
        r.push(&frame_message(b"handshake"));
        assert!(r.next_frame().is_err());
    }
}
