//! What the harness needs from a connection: [`quic`] carries it over QUIC,
//! [`mock`] between tasks in one process.
//!
//! The surface is the subset the harness uses -- open a stream, accept one,
//! write, finish, reset, read, stop -- not an abstraction over QUIC. Two
//! properties are load-bearing and easy to lose in a wrapper:
//!
//! - **A reset is not an error.** [`ReadError::Reset`] keeps the peer's code.
//!   A node refuses a ticket by resetting its stream (`simple.md:335-337`),
//!   and two N2 checks read that refusal.
//! - **A stream has a number**, unique per connection: traces group by it.
//!
//! Framing is above this and below the protocol -- `FrameReader` takes bytes
//! -- so no codec knows which transport delivered them.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use ed25519_consensus::SigningKey;

use crate::endpoint::{EndpointConfig, EndpointError};

pub mod mock;
pub mod quic;

/// A connection, shared by every task that speaks on it.
///
/// `Arc`, not `Box`: the emulator clones one per stream task, and
/// `quinn::Connection` is itself a cheap handle.
pub type Conn = Arc<dyn Connection>;

/// The send half of a bidirectional stream.
pub type SendHalf = Box<dyn SendStream>;

/// The receive half of a bidirectional stream.
pub type RecvHalf = Box<dyn RecvStream>;

/// Why a read produced no bytes.
///
/// Stringly-typed except for the case the harness must tell apart: a peer
/// resetting the stream. The code appears in both renderings -- the CE 129
/// probe matches polkajam's `NoData` inside the formatted error.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// The peer reset the stream with this application error code.
    #[error("stream reset by peer: Reset({0})")]
    Reset(u64),
    /// The connection went away under the stream.
    #[error("connection lost: {0}")]
    ConnectionLost(String),
    /// Anything else the transport reported.
    #[error("{0}")]
    Other(String),
}

/// Why a write, an open or an accept did not complete.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct TransportError(pub String);

impl TransportError {
    /// Wrap any transport-side error as a message.
    pub fn new(e: impl fmt::Display) -> Self {
        Self(e.to_string())
    }
}

/// How this process reaches peers: one implementation per carrier.
///
/// Listening and dialling together, because a run needs the pair to agree: a
/// mock listener is only reachable by a mock dialer sharing its network.
#[async_trait]
pub trait Transport: Send + Sync + fmt::Debug {
    /// Bind a listener on `addr` presenting `secret`'s identity.
    ///
    /// Port 0 asks for any free port, as it does for a socket; the bound
    /// address is [`Listener::local_addr`].
    async fn listen(
        &self,
        config: EndpointConfig,
        secret: SigningKey,
        addr: SocketAddr,
    ) -> Result<Box<dyn Listener>, EndpointError>;

    /// Dial `addr`, authenticating the peer as `server_name`.
    async fn connect(
        &self,
        config: EndpointConfig,
        secret: SigningKey,
        server_name: String,
        addr: SocketAddr,
    ) -> Result<Conn, EndpointError>;
}

/// A bound listener.
#[async_trait]
pub trait Listener: Send + Sync + fmt::Debug {
    /// The next connection attempt, or `None` once closed.
    ///
    /// Two stages, like QUIC's: the emulator records the accept when the
    /// attempt arrives, so a peer that fails to establish still shows as
    /// having tried.
    async fn accept(&self) -> Option<Box<dyn Incoming>>;

    /// The bound address, with port 0 resolved.
    fn local_addr(&self) -> SocketAddr;

    /// Stop accepting and drop the connections already accepted.
    fn close(&self);
}

/// A connection attempt that has arrived but not yet been established.
#[async_trait]
pub trait Incoming: Send {
    /// Complete the attempt, or report why it did not establish.
    async fn established(self: Box<Self>) -> Result<Conn, TransportError>;
}

/// An established connection.
#[async_trait]
pub trait Connection: Send + Sync + fmt::Debug {
    /// Open a bidirectional stream.
    async fn open_bi(&self) -> Result<(SendHalf, RecvHalf), TransportError>;

    /// Accept the next bidirectional stream the peer opens.
    async fn accept_bi(&self) -> Result<(SendHalf, RecvHalf), TransportError>;
}

/// The send half of a bidirectional stream.
#[async_trait]
pub trait SendStream: Send {
    /// The stream's number, unique for the life of its connection.
    fn id(&self) -> u64;

    /// Write every byte, or report that the stream is gone.
    async fn write_all(&mut self, bytes: &[u8]) -> Result<(), TransportError>;

    /// Finish cleanly: the peer reads end-of-stream after the bytes written.
    /// Finishing a stream already gone is not an error anywhere here.
    fn finish(&mut self);

    /// Abandon the stream; the peer's next read reports
    /// [`ReadError::Reset`] with this code.
    fn reset(&mut self, code: u32);
}

/// The receive half of a bidirectional stream.
#[async_trait]
pub trait RecvStream: Send {
    /// Bytes read into `buf`, or `None` at a clean end of stream.
    async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, ReadError>;

    /// Ask the peer to stop sending, with an application error code.
    fn stop(&mut self, code: u32);
}
