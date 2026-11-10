//! The QUIC carrier: the transport boundary over `quinn`, unchanged in
//! behaviour from the direct use that preceded it.
//!
//! Every type here is a thin wrapper. The TLS configuration, the certificate
//! verifiers and the ALPN negotiation all stay in [`crate::endpoint`], which
//! this module calls rather than reimplements, so there is exactly one copy of
//! the part a conformance run depends on being right.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use ed25519_consensus::SigningKey;

use super::{
    Conn, Connection, Incoming, Listener, ReadError, RecvHalf, RecvStream, SendHalf, SendStream,
    Transport, TransportError,
};
use crate::endpoint::{Endpoint, EndpointConfig, EndpointError};

/// Connections over QUIC, as JAMNP-S specifies them.
#[derive(Clone, Copy, Debug, Default)]
pub struct QuicTransport;

#[async_trait]
impl Transport for QuicTransport {
    async fn listen(
        &self,
        config: EndpointConfig,
        secret: SigningKey,
        addr: SocketAddr,
    ) -> Result<Box<dyn Listener>, EndpointError> {
        let endpoint = Endpoint::serve(config, secret, addr).await?;
        Ok(Box::new(QuicListener { endpoint }))
    }

    async fn connect(
        &self,
        config: EndpointConfig,
        secret: SigningKey,
        server_name: String,
        addr: SocketAddr,
    ) -> Result<Conn, EndpointError> {
        let connection = Endpoint::connect(config, secret, server_name, addr).await?;
        Ok(Arc::new(QuicConnection(connection)))
    }
}

/// A bound QUIC endpoint.
#[derive(Debug)]
struct QuicListener {
    endpoint: Endpoint,
}

#[async_trait]
impl Listener for QuicListener {
    async fn accept(&self) -> Option<Box<dyn Incoming>> {
        let incoming = self.endpoint.accept().await?;
        Some(Box::new(QuicIncoming(incoming)))
    }

    fn local_addr(&self) -> SocketAddr {
        self.endpoint.local_addr()
    }

    fn close(&self) {
        self.endpoint.close();
    }
}

/// An arrived connection attempt, before the handshake has completed.
struct QuicIncoming(quinn::Incoming);

#[async_trait]
impl Incoming for QuicIncoming {
    async fn established(self: Box<Self>) -> Result<Conn, TransportError> {
        let connecting = self.0.accept().map_err(TransportError::new)?;
        let connection = connecting.await.map_err(TransportError::new)?;
        Ok(Arc::new(QuicConnection(connection)))
    }
}

/// An established QUIC connection.
#[derive(Debug)]
struct QuicConnection(quinn::Connection);

#[async_trait]
impl Connection for QuicConnection {
    async fn open_bi(&self) -> Result<(SendHalf, RecvHalf), TransportError> {
        let (send, recv) = self.0.open_bi().await.map_err(TransportError::new)?;
        Ok(halves(send, recv))
    }

    async fn accept_bi(&self) -> Result<(SendHalf, RecvHalf), TransportError> {
        let (send, recv) = self.0.accept_bi().await.map_err(TransportError::new)?;
        Ok(halves(send, recv))
    }
}

fn halves(send: quinn::SendStream, recv: quinn::RecvStream) -> (SendHalf, RecvHalf) {
    (Box::new(QuicSend(send)), Box::new(QuicRecv(recv)))
}

struct QuicSend(quinn::SendStream);

#[async_trait]
impl SendStream for QuicSend {
    fn id(&self) -> u64 {
        u64::from(self.0.id())
    }

    async fn write_all(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.0.write_all(bytes).await.map_err(TransportError::new)
    }

    fn finish(&mut self) {
        // `ClosedStream` means the peer got there first, which is not a
        // failure of anything the caller asked for.
        let _ = self.0.finish();
    }

    fn reset(&mut self, code: u32) {
        let _ = self.0.reset(quinn::VarInt::from_u32(code));
    }
}

struct QuicRecv(quinn::RecvStream);

#[async_trait]
impl RecvStream for QuicRecv {
    async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, ReadError> {
        self.0.read(buf).await.map_err(read_error)
    }

    fn stop(&mut self, code: u32) {
        let _ = self.0.stop(quinn::VarInt::from_u32(code));
    }
}

/// Map `quinn`'s read failures onto the boundary's.
///
/// The reset code survives in both the variant and the rendered message: a
/// caller that only has the formatted error -- the CE 129 probe looks for
/// polkajam's `NoData` code this way -- still finds the number in it.
fn read_error(e: quinn::ReadError) -> ReadError {
    match e {
        quinn::ReadError::Reset(code) => ReadError::Reset(code.into_inner()),
        quinn::ReadError::ConnectionLost(e) => ReadError::ConnectionLost(e.to_string()),
        other => ReadError::Other(format!("{other:?}")),
    }
}
