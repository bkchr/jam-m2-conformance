//! ALPN protocol identifier (jam-np/simple.md `:48-59`).

use crate::PROTOCOL_VERSION;

/// ALPN protocol identifier: `jamnp-s/V/H`, where `V` is the protocol version
/// and `H` is the first 8 nibbles (4 bytes) of the chain genesis header hash,
/// in lowercase hex (simple.md `:48-59`).
pub fn protocol_id(genesis_header_hash: &[u8; 32]) -> Vec<u8> {
    format!(
        "jamnp-s/{PROTOCOL_VERSION}/{}",
        chain_id(genesis_header_hash)
    )
    .into_bytes()
}

/// ALPN protocol identifier with the `/builder` suffix (simple.md `:55`).
pub fn builder_protocol_id(genesis_header_hash: &[u8; 32]) -> Vec<u8> {
    let mut id = protocol_id(genesis_header_hash);
    id.extend_from_slice(b"/builder");
    id
}

/// Parsed ALPN protocol identifier.
#[derive(Debug, PartialEq, Eq)]
pub struct Alpn {
    pub version: u8,
    pub chain_id: String,
    pub builder: bool,
}

impl Alpn {
    /// Parse an ALPN identifier. Accepts exactly 3 or 4 slash-separated
    /// segments, `jamnp-s/V/H[/builder]`, with `V == PROTOCOL_VERSION` and
    /// `H` being 8 lowercase hex nibbles.
    pub fn parse(bytes: &[u8]) -> Option<Alpn> {
        let s = std::str::from_utf8(bytes).ok()?;
        let mut segments = s.split('/');
        if segments.next()? != "jamnp-s" {
            return None;
        }
        let version = segments.next()?;
        if version.len() != 1 || version.parse::<u8>().ok()? != PROTOCOL_VERSION {
            return None;
        }
        let chain_id = segments.next()?;
        if !is_chain_id(chain_id) {
            return None;
        }
        let builder = match segments.next() {
            Some("builder") => true,
            Some(_) => return None,
            None => false,
        };
        if segments.next().is_some() {
            return None;
        }
        Some(Alpn {
            version: PROTOCOL_VERSION,
            chain_id: chain_id.to_string(),
            builder,
        })
    }
}

fn chain_id(genesis_header_hash: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(8);
    for &b in &genesis_header_hash[..4] {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

fn is_chain_id(s: &str) -> bool {
    s.len() == 8
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::{builder_protocol_id, protocol_id, Alpn, PROTOCOL_VERSION};

    const ZERO: [u8; 32] = [0; 32];
    const KNOWN: [u8; 32] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    #[test]
    fn protocol_id_zero_hash() {
        assert_eq!(protocol_id(&ZERO), b"jamnp-s/1/00000000");
    }

    #[test]
    fn protocol_id_known_hash() {
        assert_eq!(protocol_id(&KNOWN), b"jamnp-s/1/01234567");
    }

    #[test]
    fn builder_protocol_id_suffix() {
        assert_eq!(builder_protocol_id(&ZERO), b"jamnp-s/1/00000000/builder");
    }

    #[test]
    fn parse_roundtrip_plain() {
        let id = protocol_id(&KNOWN);
        assert_eq!(
            Alpn::parse(&id),
            Some(Alpn {
                version: PROTOCOL_VERSION,
                chain_id: "01234567".into(),
                builder: false
            })
        );
    }

    #[test]
    fn parse_roundtrip_builder() {
        let id = builder_protocol_id(&KNOWN);
        assert_eq!(
            Alpn::parse(&id),
            Some(Alpn {
                version: PROTOCOL_VERSION,
                chain_id: "01234567".into(),
                builder: true
            })
        );
    }

    #[test]
    fn parse_rejects_version_zero() {
        assert_eq!(Alpn::parse(b"jamnp-s/0/00000000"), None);
    }

    #[test]
    fn parse_rejects_version_two() {
        assert_eq!(Alpn::parse(b"jamnp-s/2/00000000"), None);
    }

    #[test]
    fn parse_rejects_bad_hex() {
        assert_eq!(Alpn::parse(b"jamnp-s/1/zzzzzzzz"), None);
    }

    #[test]
    fn parse_rejects_two_segments() {
        assert_eq!(Alpn::parse(b"jamnp-s/1"), None);
    }

    #[test]
    fn parse_rejects_five_segments() {
        assert_eq!(Alpn::parse(b"jamnp-s/1/00000000/builder/x"), None);
    }

    #[test]
    fn parse_rejects_uppercase_hex() {
        assert_eq!(Alpn::parse(b"jamnp-s/1/0123456F"), None);
    }

    #[test]
    fn parse_rejects_missing_suffix_chars() {
        assert_eq!(Alpn::parse(b"jamnp-s/1/00000000/build"), None);
    }

    #[test]
    fn parse_rejects_wrong_prefix() {
        assert_eq!(Alpn::parse(b"foo/1/00000000"), None);
    }

    #[test]
    fn parse_rejects_short_chain_id() {
        assert_eq!(Alpn::parse(b"jamnp-s/1/0000000"), None);
    }
}
