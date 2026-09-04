//! Integration tests for the QUIC/TLS endpoint (`jamnp_s::endpoint`), per
//! `jam-np/simple.md:5-99`. Each test drives a real server and client endpoint
//! over a loopback UDP socket with an OS-assigned port.

use std::net::SocketAddr;
use std::time::Duration;

use ed25519_consensus::{SigningKey, VerificationKey};
use jamnp_s::cert::san_for_key;
use jamnp_s::endpoint::{Endpoint, EndpointConfig};

/// Handshake/operation timeout for every test.
const TIMEOUT: Duration = Duration::from_secs(5);

/// Deterministic signing key with all-`n` seed bytes.
fn key(n: u8) -> SigningKey {
    SigningKey::from([n; 32])
}

/// JAMNP-S alternative name for `key`'s public key.
fn san(key: &SigningKey) -> String {
    san_for_key(&VerificationKey::from(key))
}

/// Loopback address with an OS-assigned port.
fn any_addr() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// Accept and complete the next incoming connection on `a`.
async fn accept_next(a: Endpoint) -> Result<quinn::Connection, quinn::ConnectionError> {
    let incoming = a.accept().await.expect("A receives incoming connection");
    incoming.accept()?.await
}

/// A and B establish a connection with correct cert and ALPN; both directions
/// carry a byte over a bidirectional stream.
#[tokio::test(flavor = "multi_thread")]
async fn two_endpoints_handshake() {
    let genesis = [0xaa; 32];
    let config = EndpointConfig {
        genesis_hash: genesis,
        builder: false,
    };
    let key_a = key(1);
    let key_b = key(2);
    let san_a = san(&key_a);

    let a = Endpoint::serve(config.clone(), key_a, any_addr())
        .await
        .expect("serve A");
    let addr = a.local_addr();
    let accept_task = tokio::spawn(accept_next(a));

    let b = Endpoint::connect(config, key_b, san_a, addr)
        .await
        .expect("connect B");
    let a_conn = accept_task
        .await
        .expect("accept task")
        .expect("A handshake");

    // B opens a bidirectional stream and writes; A accepts the stream on the
    // established connection and reads.
    let (mut b_tx, mut b_rx) = b.open_bi().await.expect("B opens stream");
    b_tx.write_all(b"x").await.expect("B writes");
    let (mut a_tx, mut a_rx) = a_conn.accept_bi().await.expect("A accepts stream");

    let mut buf = [0u8; 1];
    a_rx.read_exact(&mut buf).await.expect("A reads");
    assert_eq!(buf, [b'x']);

    a_tx.write_all(b"y").await.expect("A writes");
    b_rx.read_exact(&mut buf).await.expect("B reads");
    assert_eq!(buf, [b'y']);
}

/// A serves with key K1; B dials expecting the SAN of a *different* key, so
/// B's server-certificate verifier rejects A's certificate.
#[tokio::test(flavor = "multi_thread")]
async fn wrong_san_closed() {
    let config = EndpointConfig {
        genesis_hash: [0xbb; 32],
        builder: false,
    };
    let key_a = key(3);
    let key_c = key(4);
    let san_c = san(&key_c);

    let a = Endpoint::serve(config.clone(), key_a, any_addr())
        .await
        .expect("serve A");
    let addr = a.local_addr();
    let accept_task = tokio::spawn(accept_next(a));

    let result = tokio::time::timeout(TIMEOUT, Endpoint::connect(config, key_c, san_c, addr)).await;
    assert!(result.is_ok(), "handshake did not fail within {TIMEOUT:?}");
    assert!(
        result.expect("timeout").is_err(),
        "connection established despite wrong SAN"
    );
    let _ = accept_task.await.expect("accept task");
}

/// A serves with ALPN for chain `0x01..`; B offers ALPN for chain `0x02..`,
/// so ALPN negotiation fails and the handshake aborts.
#[tokio::test(flavor = "multi_thread")]
async fn wrong_alpn_fails() {
    let key_a = key(5);
    let key_b = key(6);
    let san_b = san(&key_b);
    let config_a = EndpointConfig {
        genesis_hash: [0x01; 32],
        builder: false,
    };
    let config_b = EndpointConfig {
        genesis_hash: [0x02; 32],
        builder: false,
    };

    let a = Endpoint::serve(config_a, key_a, any_addr())
        .await
        .expect("serve A");
    let addr = a.local_addr();
    let accept_task = tokio::spawn(accept_next(a));

    let result =
        tokio::time::timeout(TIMEOUT, Endpoint::connect(config_b, key_b, san_b, addr)).await;
    assert!(result.is_ok(), "handshake did not fail within {TIMEOUT:?}");
    assert!(
        result.expect("timeout").is_err(),
        "connection established despite ALPN mismatch"
    );
    let _ = accept_task.await.expect("accept task");
}

/// A always offers both the plain and `/builder` ALPNs; B dials with the
/// `/builder` ALPN and the handshake succeeds, negotiating `/builder`.
#[tokio::test(flavor = "multi_thread")]
async fn builder_alpn_accepted() {
    let genesis = [0xcc; 32];
    let key_a = key(7);
    let key_b = key(8);
    let san_a = san(&key_a);
    let config_a = EndpointConfig {
        genesis_hash: genesis,
        builder: false,
    };
    let config_b = EndpointConfig {
        genesis_hash: genesis,
        builder: true,
    };

    let a = Endpoint::serve(config_a, key_a, any_addr())
        .await
        .expect("serve A");
    let addr = a.local_addr();
    let accept_task = tokio::spawn(accept_next(a));

    let b = Endpoint::connect(config_b, key_b, san_a, addr)
        .await
        .expect("connect B");
    let _ = accept_task
        .await
        .expect("accept task")
        .expect("A handshake");

    let handshake_data = b.handshake_data().expect("B handshake data");
    let handshake_data = handshake_data
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .expect("rustls handshake data");
    assert_eq!(
        handshake_data.protocol.as_deref(),
        Some(jamnp_s::alpn::builder_protocol_id(&genesis).as_slice())
    );
}
