//! The transport contract, asserted against both carriers.
//!
//! `jamnp_s::transport` exists so that everything above it can be run over
//! QUIC or in one process without knowing which. That is only true if both
//! carriers behave the same where the harness looks, so every case here runs
//! twice: once over real QUIC sockets, once over the in-process mock.
//!
//! The certificate, SAN and ALPN rules are *not* here. They are properties of
//! the QUIC carrier alone -- the mock authenticates nothing -- and
//! `endpoint_it.rs` grades them directly.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ed25519_consensus::{SigningKey, VerificationKey};
use jamnp_s::cert::san_for_key;
use jamnp_s::endpoint::EndpointConfig;
use jamnp_s::transport::{mock::MockNetwork, quic::QuicTransport, Conn, ReadError, Transport};

const TIMEOUT: Duration = Duration::from_secs(5);
const GENESIS: [u8; 32] = [0xaa; 32];

fn key(n: u8) -> SigningKey {
    SigningKey::from([n; 32])
}

fn config() -> EndpointConfig {
    EndpointConfig {
        genesis_hash: GENESIS,
        builder: false,
    }
}

fn any_addr() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// The two carriers under test, named so a failure says which one broke.
fn carriers() -> Vec<(&'static str, Arc<dyn Transport>)> {
    vec![
        ("quic", Arc::new(QuicTransport) as Arc<dyn Transport>),
        ("mock", Arc::new(MockNetwork::new()) as Arc<dyn Transport>),
    ]
}

/// Bind a listener, dial it, and return both ends of the established
/// connection.
///
/// The listener is dropped before the connection is used, which is deliberate:
/// over QUIC the connection outlives the endpoint that accepted it, and the
/// mock has to do the same or the emulator's accept loops would take the
/// connections down with them.
async fn pair(transport: &Arc<dyn Transport>) -> (Conn, Conn) {
    let listener = transport
        .listen(config(), key(1), any_addr())
        .await
        .expect("the listener binds");
    let addr = listener.local_addr();
    let san = san_for_key(&VerificationKey::from(&key(1)));

    let accepting = tokio::spawn(async move {
        let incoming = listener.accept().await.expect("an attempt arrives");
        incoming.established().await.expect("it establishes")
    });
    let dialer = tokio::time::timeout(TIMEOUT, transport.connect(config(), key(2), san, addr))
        .await
        .expect("the dial completes in time")
        .expect("the dial succeeds");
    let accepted = tokio::time::timeout(TIMEOUT, accepting)
        .await
        .expect("the accept completes in time")
        .expect("the accept task finishes");
    (dialer, accepted)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stream_carries_bytes_both_ways() {
    for (name, transport) in carriers() {
        let (dialer, accepted) = pair(&transport).await;
        let (mut send, mut recv) = dialer.open_bi().await.expect("the dialer opens a stream");
        // Over QUIC a stream reaches the peer with its first bytes, so the
        // write comes before the accept on both carriers.
        send.write_all(b"ping").await.expect("the write lands");
        let (mut peer_send, mut peer_recv) = tokio::time::timeout(TIMEOUT, accepted.accept_bi())
            .await
            .unwrap_or_else(|_| panic!("{name}: the peer accepts the stream"))
            .expect("the accept succeeds");

        let mut buf = [0u8; 64];
        let n = peer_recv
            .read(&mut buf)
            .await
            .expect("a read")
            .expect("bytes");
        assert_eq!(&buf[..n], b"ping", "{name}: bytes arrive unchanged");

        peer_send.write_all(b"pong").await.expect("the reply lands");
        let n = recv.read(&mut buf).await.expect("a read").expect("bytes");
        assert_eq!(&buf[..n], b"pong", "{name}: and the other way round");
    }
}

/// The property the boundary exists to preserve: a peer refusing a stream
/// reaches the other side as a reset carrying its code, not as a generic
/// failure. Two N2 checks read a node's refusal this way.
#[tokio::test(flavor = "multi_thread")]
async fn a_reset_arrives_as_a_reset_with_its_code() {
    for (name, transport) in carriers() {
        let (dialer, accepted) = pair(&transport).await;
        let (mut send, _recv) = dialer.open_bi().await.expect("the dialer opens a stream");
        send.write_all(b"a request").await.expect("the write lands");
        let (_peer_send, mut peer_recv) = tokio::time::timeout(TIMEOUT, accepted.accept_bi())
            .await
            .unwrap_or_else(|_| panic!("{name}: the peer accepts the stream"))
            .expect("the accept succeeds");
        send.reset(7);

        // Over QUIC the reset races the bytes already written, so read until
        // one or the other settles it.
        let mut buf = [0u8; 64];
        let code = loop {
            match tokio::time::timeout(TIMEOUT, peer_recv.read(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("{name}: the reset arrives"))
            {
                Err(ReadError::Reset(code)) => break code,
                Ok(Some(_)) => continue,
                other => panic!("{name}: expected a reset, got {other:?}"),
            }
        };
        assert_eq!(code, 7, "{name}: the peer's code survives the boundary");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_finished_stream_ends_cleanly() {
    for (name, transport) in carriers() {
        let (dialer, accepted) = pair(&transport).await;
        let (mut send, _recv) = dialer.open_bi().await.expect("the dialer opens a stream");
        send.write_all(b"all of it").await.expect("the write lands");
        send.finish();
        let (_peer_send, mut peer_recv) = tokio::time::timeout(TIMEOUT, accepted.accept_bi())
            .await
            .unwrap_or_else(|_| panic!("{name}: the peer accepts the stream"))
            .expect("the accept succeeds");

        let mut buf = [0u8; 64];
        let mut seen = Vec::new();
        while let Some(n) = tokio::time::timeout(TIMEOUT, peer_recv.read(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("{name}: the stream ends"))
            .expect("no error on a clean end")
        {
            seen.extend_from_slice(&buf[..n]);
        }
        assert_eq!(
            seen, b"all of it",
            "{name}: every byte arrives before the end"
        );
    }
}

/// Streams on one connection are independent and separately numbered, which is
/// what lets a trace group frames by stream.
#[tokio::test(flavor = "multi_thread")]
async fn streams_are_independent_and_distinctly_numbered() {
    for (name, transport) in carriers() {
        let (dialer, accepted) = pair(&transport).await;
        let (mut first, _) = dialer.open_bi().await.expect("the first stream opens");
        first.write_all(b"one").await.expect("the write lands");
        let (_, mut first_recv) = tokio::time::timeout(TIMEOUT, accepted.accept_bi())
            .await
            .unwrap_or_else(|_| panic!("{name}: the peer accepts the first"))
            .expect("the accept succeeds");

        let (mut second, _) = dialer.open_bi().await.expect("the second stream opens");
        second.write_all(b"two").await.expect("the write lands");
        let (_, mut second_recv) = tokio::time::timeout(TIMEOUT, accepted.accept_bi())
            .await
            .unwrap_or_else(|_| panic!("{name}: the peer accepts the second"))
            .expect("the accept succeeds");

        assert_ne!(first.id(), second.id(), "{name}: stream numbers differ");

        first.reset(3);
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(TIMEOUT, second_recv.read(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("{name}: the second stream still reads"))
            .expect("the second stream is unaffected by the first's reset")
            .expect("bytes");
        assert_eq!(
            &buf[..n],
            b"two",
            "{name}: on the stream that was not reset"
        );
        // And the reset one is still reset, rather than merely quiet.
        loop {
            match tokio::time::timeout(TIMEOUT, first_recv.read(&mut buf))
                .await
                .unwrap_or_else(|_| panic!("{name}: the first stream settles"))
            {
                Err(ReadError::Reset(3)) => break,
                Ok(Some(_)) => continue,
                other => panic!("{name}: expected the first stream reset, got {other:?}"),
            }
        }
    }
}
