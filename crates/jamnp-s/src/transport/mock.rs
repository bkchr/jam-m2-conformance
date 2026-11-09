//! Connections between tasks: no sockets, no wire, no handshake. The
//! transport a self-test runs on.
//!
//! **It authenticates nothing** -- no TLS, no certificate, no ALPN. `connect`
//! reaches a listener if one is bound at that address; the identity arguments
//! are ignored. N0's certificate, SAN and ALPN checks are properties of
//! [`super::quic`] and can only be graded there.
//!
//! What it does reproduce is what the lanes read: independent bidirectional
//! streams, a clean end on finish, and a reset carrying the peer's code.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ed25519_consensus::SigningKey;
use tokio::sync::{mpsc, Notify};

use super::{
    Conn, Connection, Incoming, Listener, ReadError, RecvHalf, RecvStream, SendHalf, SendStream,
    Transport, TransportError,
};
use crate::endpoint::{EndpointConfig, EndpointError};

/// A set of addresses that can reach each other, and nothing outside it.
///
/// Clones share one network: that is how a dialer and a listener meet.
#[derive(Clone, Debug, Default)]
pub struct MockNetwork {
    inner: Arc<Mutex<Net>>,
}

#[derive(Debug, Default)]
struct Net {
    bound: HashMap<SocketAddr, mpsc::UnboundedSender<MockIncoming>>,
    /// Hands out ports for binds that asked for "any".
    next_port: u16,
}

impl MockNetwork {
    /// An empty network with nothing bound on it.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether anything is listening at `addr`.
    pub fn is_bound(&self, addr: SocketAddr) -> bool {
        self.inner
            .lock()
            .expect("mock network")
            .bound
            .contains_key(&addr)
    }
}

#[async_trait]
impl Transport for MockNetwork {
    async fn listen(
        &self,
        _config: EndpointConfig,
        _secret: SigningKey,
        addr: SocketAddr,
    ) -> Result<Box<dyn Listener>, EndpointError> {
        let (tx, rx) = mpsc::unbounded_channel();
        let addr = {
            let mut net = self.inner.lock().expect("mock network");
            // Port 0 means "any". The counter starts high enough not to
            // collide with a port a caller named.
            let addr = if addr.port() == 0 {
                net.next_port = net.next_port.max(49152).wrapping_add(1);
                SocketAddr::new(addr.ip(), net.next_port)
            } else {
                addr
            };
            if net.bound.contains_key(&addr) {
                return Err(EndpointError::Io(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("{addr} is already bound on this mock network"),
                )));
            }
            net.bound.insert(addr, tx);
            addr
        };
        Ok(Box::new(MockListener {
            addr,
            incoming: tokio::sync::Mutex::new(rx),
            net: self.clone(),
        }))
    }

    async fn connect(
        &self,
        _config: EndpointConfig,
        _secret: SigningKey,
        _server_name: String,
        addr: SocketAddr,
    ) -> Result<Conn, EndpointError> {
        let listener = {
            let net = self.inner.lock().expect("mock network");
            net.bound.get(&addr).cloned()
        };
        let Some(listener) = listener else {
            return Err(EndpointError::Io(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("nothing is listening at {addr} on this mock network"),
            )));
        };
        let (dialer, accepted) = connection_pair();
        // Handed over before this returns, so a stream opened immediately
        // after `connect` finds someone to accept it.
        listener
            .send(MockIncoming { conn: accepted })
            .map_err(|_| {
                EndpointError::Io(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("the listener at {addr} is gone"),
                ))
            })?;
        Ok(dialer)
    }
}

/// A bound mock address.
#[derive(Debug)]
struct MockListener {
    addr: SocketAddr,
    incoming: tokio::sync::Mutex<mpsc::UnboundedReceiver<MockIncoming>>,
    net: MockNetwork,
}

#[async_trait]
impl Listener for MockListener {
    async fn accept(&self) -> Option<Box<dyn Incoming>> {
        let conn = self.incoming.lock().await.recv().await?;
        Some(Box::new(conn))
    }

    fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    fn close(&self) {
        // Dropping the sender refuses later dials and wakes `accept`.
        self.net
            .inner
            .lock()
            .expect("mock network")
            .bound
            .remove(&self.addr);
    }
}

impl Drop for MockListener {
    fn drop(&mut self) {
        self.close();
    }
}

/// A connection waiting to be accepted. Nothing is negotiated, so completing
/// it cannot fail.
struct MockIncoming {
    conn: Conn,
}

#[async_trait]
impl Incoming for MockIncoming {
    async fn established(self: Box<Self>) -> Result<Conn, TransportError> {
        Ok(self.conn)
    }
}

/// Both ends of one connection.
///
/// Stream numbers come from disjoint series -- the dialer's even, the
/// listener's odd -- so a trace tells them apart by number, as over QUIC.
fn connection_pair() -> (Conn, Conn) {
    let (to_accepted, accepted_incoming) = mpsc::unbounded_channel();
    let (to_dialer, dialer_incoming) = mpsc::unbounded_channel();
    let dialer = Arc::new(MockConnection {
        incoming: tokio::sync::Mutex::new(dialer_incoming),
        peer: to_accepted,
        next_id: AtomicU64::new(0),
        step: 2,
    });
    let accepted = Arc::new(MockConnection {
        incoming: tokio::sync::Mutex::new(accepted_incoming),
        peer: to_dialer,
        next_id: AtomicU64::new(1),
        step: 2,
    });
    (dialer, accepted)
}

/// One end of a connection.
#[derive(Debug)]
struct MockConnection {
    incoming: tokio::sync::Mutex<mpsc::UnboundedReceiver<(SendHalf, RecvHalf)>>,
    peer: mpsc::UnboundedSender<(SendHalf, RecvHalf)>,
    next_id: AtomicU64,
    step: u64,
}

#[async_trait]
impl Connection for MockConnection {
    async fn open_bi(&self) -> Result<(SendHalf, RecvHalf), TransportError> {
        let id = self.next_id.fetch_add(self.step, Ordering::Relaxed);
        // Two pipes: one each way.
        let (out_send, out_recv) = pipe(id);
        let (in_send, in_recv) = pipe(id);
        self.peer
            .send((in_send, out_recv))
            .map_err(|_| TransportError("the peer is gone".to_string()))?;
        Ok((out_send, in_recv))
    }

    async fn accept_bi(&self) -> Result<(SendHalf, RecvHalf), TransportError> {
        self.incoming
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| TransportError("the peer is gone".to_string()))
    }
}

/// One direction of bytes, as a send half and the receive half reading it.
fn pipe(id: u64) -> (SendHalf, RecvHalf) {
    let shared = Arc::new(Pipe::default());
    (
        Box::new(MockSend {
            id,
            pipe: Arc::clone(&shared),
        }),
        Box::new(MockRecv { pipe: shared }),
    )
}

/// Bytes in flight one way, and how the direction ended.
#[derive(Debug, Default)]
struct Pipe {
    state: Mutex<PipeState>,
    /// Woken on every write, finish, reset or stop.
    wake: Notify,
}

#[derive(Debug, Default)]
struct PipeState {
    chunks: VecDeque<Vec<u8>>,
    /// How much of the front chunk the reader has already taken.
    taken: usize,
    /// The writer finished cleanly.
    fin: bool,
    /// The writer reset the stream with this code.
    reset: Option<u64>,
    /// The reader asked the writer to stop with this code.
    stopped: Option<u64>,
}

struct MockSend {
    id: u64,
    pipe: Arc<Pipe>,
}

#[async_trait]
impl SendStream for MockSend {
    fn id(&self) -> u64 {
        self.id
    }

    async fn write_all(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        {
            let mut state = self.pipe.state.lock().expect("mock pipe");
            if let Some(code) = state.stopped {
                return Err(TransportError(format!(
                    "the peer stopped the stream: {code}"
                )));
            }
            if state.reset.is_some() || state.fin {
                return Err(TransportError("the stream is closed".to_string()));
            }
            state.chunks.push_back(bytes.to_vec());
        }
        self.pipe.wake.notify_waiters();
        Ok(())
    }

    fn finish(&mut self) {
        self.pipe.state.lock().expect("mock pipe").fin = true;
        self.pipe.wake.notify_waiters();
    }

    fn reset(&mut self, code: u32) {
        let mut state = self.pipe.state.lock().expect("mock pipe");
        // Discards unread bytes, as RESET_STREAM does.
        state.chunks.clear();
        state.taken = 0;
        state.reset = Some(u64::from(code));
        drop(state);
        self.pipe.wake.notify_waiters();
    }
}

struct MockRecv {
    pipe: Arc<Pipe>,
}

#[async_trait]
impl RecvStream for MockRecv {
    async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, ReadError> {
        loop {
            // Register before looking: a write between the look and the wait
            // would otherwise be missed and both sides would park.
            let waiting = self.pipe.wake.notified();
            tokio::pin!(waiting);
            waiting.as_mut().enable();
            {
                let mut state = self.pipe.state.lock().expect("mock pipe");
                if let Some(code) = state.reset {
                    return Err(ReadError::Reset(code));
                }
                if let Some(chunk) = state.chunks.front() {
                    let taken = state.taken;
                    let n = (chunk.len() - taken).min(buf.len());
                    buf[..n].copy_from_slice(&chunk[taken..taken + n]);
                    if taken + n == chunk.len() {
                        state.chunks.pop_front();
                        state.taken = 0;
                    } else {
                        state.taken = taken + n;
                    }
                    return Ok(Some(n));
                }
                if state.fin {
                    return Ok(None);
                }
            }
            waiting.await;
        }
    }

    fn stop(&mut self, code: u32) {
        self.pipe.state.lock().expect("mock pipe").stopped = Some(u64::from(code));
        self.pipe.wake.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> EndpointConfig {
        EndpointConfig {
            genesis_hash: [0u8; 32],
            builder: false,
        }
    }

    fn key() -> SigningKey {
        SigningKey::from([1u8; 32])
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    async fn connected(net: &MockNetwork, at: SocketAddr) -> (Box<dyn Listener>, Conn, Conn) {
        let listener = net
            .listen(config(), key(), at)
            .await
            .expect("the mock binds");
        let bound = listener.local_addr();
        let dialer = net
            .connect(config(), key(), "peer".to_string(), bound)
            .await
            .expect("the mock connects");
        let accepted = listener
            .accept()
            .await
            .expect("an attempt arrives")
            .established()
            .await
            .expect("it establishes");
        (listener, dialer, accepted)
    }

    #[tokio::test]
    async fn a_stream_carries_bytes_both_ways() {
        let net = MockNetwork::new();
        let (_listener, dialer, accepted) = connected(&net, addr(4000)).await;

        let (mut send, mut recv) = dialer.open_bi().await.expect("the dialer opens");
        send.write_all(b"ping").await.expect("the write lands");
        let (mut peer_send, mut peer_recv) = accepted.accept_bi().await.expect("the peer accepts");

        let mut buf = [0u8; 16];
        let n = peer_recv
            .read(&mut buf)
            .await
            .expect("a read")
            .expect("bytes");
        assert_eq!(&buf[..n], b"ping");

        peer_send.write_all(b"pong").await.expect("the reply lands");
        let n = recv.read(&mut buf).await.expect("a read").expect("bytes");
        assert_eq!(&buf[..n], b"pong");
    }

    /// The property the whole boundary exists to preserve: a refusal has to
    /// stay distinguishable from a broken connection, because two N2 checks
    /// are built on reading one.
    #[tokio::test]
    async fn a_reset_reaches_the_peer_as_a_reset_with_its_code() {
        let net = MockNetwork::new();
        let (_listener, dialer, accepted) = connected(&net, addr(4001)).await;

        let (mut send, _recv) = dialer.open_bi().await.expect("the dialer opens");
        send.write_all(b"half a message").await.expect("it lands");
        let (_peer_send, mut peer_recv) = accepted.accept_bi().await.expect("the peer accepts");
        send.reset(7);

        let mut buf = [0u8; 16];
        match peer_recv.read(&mut buf).await {
            Err(ReadError::Reset(code)) => assert_eq!(code, 7),
            other => panic!("expected a reset carrying its code, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_finished_stream_reads_as_a_clean_end() {
        let net = MockNetwork::new();
        let (_listener, dialer, accepted) = connected(&net, addr(4002)).await;

        let (mut send, _recv) = dialer.open_bi().await.expect("the dialer opens");
        send.write_all(b"all of it").await.expect("it lands");
        send.finish();
        let (_peer_send, mut peer_recv) = accepted.accept_bi().await.expect("the peer accepts");

        let mut buf = [0u8; 64];
        let n = peer_recv
            .read(&mut buf)
            .await
            .expect("a read")
            .expect("bytes");
        assert_eq!(&buf[..n], b"all of it");
        assert!(
            peer_recv.read(&mut buf).await.expect("a read").is_none(),
            "a finished stream ends cleanly rather than erroring"
        );
    }

    /// A read parked before anything was written must wake when it is, or
    /// every persistent stream in the harness deadlocks on this transport.
    #[tokio::test]
    async fn a_read_waiting_on_an_empty_stream_wakes_when_bytes_arrive() {
        let net = MockNetwork::new();
        let (_listener, dialer, accepted) = connected(&net, addr(4003)).await;

        let (mut send, _recv) = dialer.open_bi().await.expect("the dialer opens");
        let (_peer_send, mut peer_recv) = accepted.accept_bi().await.expect("the peer accepts");
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 16];
            let n = peer_recv
                .read(&mut buf)
                .await
                .expect("a read")
                .expect("bytes");
            buf[..n].to_vec()
        });
        // Let the reader park first: the wake-up, not the buffer, is what is
        // under test.
        tokio::task::yield_now().await;
        send.write_all(b"late").await.expect("it lands");
        assert_eq!(reader.await.expect("the reader finishes"), b"late");
    }

    /// Streams are independent: a reset on one says nothing about another, the
    /// way `simple.md`'s stream model requires.
    #[tokio::test]
    async fn one_stream_being_reset_leaves_another_alone() {
        let net = MockNetwork::new();
        let (_listener, dialer, accepted) = connected(&net, addr(4004)).await;

        let (mut first, _) = dialer.open_bi().await.expect("the first opens");
        let (mut second, _) = dialer.open_bi().await.expect("the second opens");
        first.write_all(b"one").await.expect("it lands");
        second.write_all(b"two").await.expect("it lands");
        let (_, mut first_recv) = accepted.accept_bi().await.expect("the peer accepts");
        let (_, mut second_recv) = accepted.accept_bi().await.expect("the peer accepts");
        assert_ne!(first.id(), second.id(), "stream numbers are distinct");

        first.reset(3);
        let mut buf = [0u8; 16];
        assert!(matches!(
            first_recv.read(&mut buf).await,
            Err(ReadError::Reset(3))
        ));
        let n = second_recv
            .read(&mut buf)
            .await
            .expect("the other stream is unaffected")
            .expect("bytes");
        assert_eq!(&buf[..n], b"two");
    }

    #[tokio::test]
    async fn dialing_an_address_nothing_is_bound_to_is_refused() {
        let net = MockNetwork::new();
        let err = net
            .connect(config(), key(), "peer".to_string(), addr(4005))
            .await
            .expect_err("there is nothing there");
        assert!(
            matches!(&err, EndpointError::Io(e) if e.kind() == io::ErrorKind::ConnectionRefused),
            "expected a refused connection, got {err:?}"
        );
    }

    /// A closed listener is as good as an unbound address, which is what the
    /// N0 lane's redial behaviour reads.
    #[tokio::test]
    async fn a_closed_listener_stops_accepting() {
        let net = MockNetwork::new();
        let listener = net
            .listen(config(), key(), addr(4006))
            .await
            .expect("the mock binds");
        let bound = listener.local_addr();
        assert!(net.is_bound(bound));
        listener.close();
        assert!(!net.is_bound(bound));
        assert!(net
            .connect(config(), key(), "peer".to_string(), bound)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn binding_any_port_twice_gives_two_addresses() {
        let net = MockNetwork::new();
        let first = net
            .listen(config(), key(), addr(0))
            .await
            .expect("the mock binds");
        let second = net
            .listen(config(), key(), addr(0))
            .await
            .expect("the mock binds");
        assert_ne!(first.local_addr(), second.local_addr());
        assert_ne!(first.local_addr().port(), 0);
    }
}
