//! Independent JAMNP-S implementation: QUIC/TLS endpoint, Ed25519 cert + SAN,
//! ALPN, stream framing, typed codecs for every UP/CE message, and a message
//! trace recorder. Policy-free: this crate implements the wire protocol exactly
//! as `jam-np/simple.md` and must not inherit the quirks of any node's stack.
#![deny(unsafe_code)]

pub mod alpn;
pub mod base32;
pub mod cert;
pub mod clock;
pub mod codec;
pub mod endpoint;
pub mod framing;
pub mod preferred;
pub mod proto;
pub mod trace;
pub mod transport;

/// JAMNP-S protocol version (simple.md `:48-59`).
pub const PROTOCOL_VERSION: u8 = 1;
