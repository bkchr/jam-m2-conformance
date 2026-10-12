//! Connectivity probing and preferred-initiator planning (DESIGN.md §4 step 3,
//! §11 L0 `preferred initiator` row). P0: probe the NUT's QUIC port, split the
//! emulated validators by who dials first, and orchestrate the phase timing.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use ed25519_consensus::SigningKey;
use jamnp_s::endpoint::{Endpoint, EndpointConfig, EndpointError};
use jamnp_s::preferred::preferred_initiator;

/// How long the runner waits for the NUT's QUIC port to come up (§4 step 2).
pub const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

/// Grace period before a non-preferred initiator connects anyway (§4 step 3,
/// jam-np/simple.md:70-80).
pub const INITIATOR_GRACE: Duration = Duration::from_secs(5);

/// Result of dialing a peer's QUIC port and checking its cert/SAN/ALPN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeOutcome {
    /// The QUIC/TLS handshake completed.
    pub connected: bool,
    /// The peer certificate's SAN matched the expected key.
    pub san_matches: bool,
    /// The negotiated ALPN identifier matched.
    pub alpn_matches: bool,
    /// Time spent dialing, up to the probe timeout.
    pub took: Duration,
}

/// Dial `addr` and handshake against `expected_san` with a throwaway emulator
/// identity, recording the handshake/SAN/ALPN outcome.
pub async fn probe_nut(
    addr: SocketAddr,
    expected_san: &str,
    genesis_hash: [u8; 32],
    timeout: Duration,
) -> ProbeOutcome {
    let start = Instant::now();
    let secret = SigningKey::from([0u8; 32]); // throwaway emulator secret
    let result = tokio::time::timeout(
        timeout,
        Endpoint::connect(
            EndpointConfig {
                genesis_hash,
                builder: false,
            },
            secret,
            expected_san.to_string(),
            addr,
        ),
    )
    .await;
    let took = start.elapsed();
    // A completed handshake means the verifier accepted the peer cert (SAN)
    // and ALPN negotiated: the endpoint enforces both.
    let ok = matches!(result, Ok(Ok(_)));
    ProbeOutcome {
        connected: ok,
        san_matches: ok,
        alpn_matches: ok,
        took,
    }
}

/// Connectivity plan: which emulated validators dial the NUT immediately
/// (preferred initiators) vs wait the grace then dial anyway (§4 step 3).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectivityPlan {
    pub initiate_now: Vec<usize>,
    pub wait_then_connect: Vec<usize>,
}

/// For each emulated validator key, `preferred_initiator(emu_key_i, nut_key)`
/// decides the group: `true` → `initiate_now`, otherwise `wait_then_connect`.
pub fn plan_connectivity(emu_keys: &[[u8; 32]], nut_key: &[u8; 32]) -> ConnectivityPlan {
    let mut plan = ConnectivityPlan::default();
    for (i, key) in emu_keys.iter().enumerate() {
        if preferred_initiator(key, nut_key) {
            plan.initiate_now.push(i);
        } else {
            plan.wait_then_connect.push(i);
        }
    }
    plan
}

/// Errors surfaced while probing or driving the connectivity phase.
#[derive(Debug, thiserror::Error)]
pub enum ConnectivityError {
    #[error("endpoint error: {0}")]
    Endpoint(#[from] EndpointError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("operation timed out")]
    Timeout,
}

/// P0 connectivity phase: probe the NUT once per emulated validator, honoring
/// the preferred-initiator timing split (§4 step 3). The actual emulator
/// connection spawning is wired by the runner (T20); here only the NUT's
/// reachability/cert/SAN/ALPN is probed per emulator, immediate for
/// `initiate_now` and after `INITIATOR_GRACE` for `wait_then_connect`.
pub async fn run_connectivity(
    plan: &ConnectivityPlan,
    nut_addr: SocketAddr,
    emu_addrs: &[SocketAddr],
    genesis_hash: [u8; 32],
    nut_san: &str,
) -> Vec<ProbeOutcome> {
    // The NUT's SAN is derived from its *configured* validator index by the
    // caller. Deriving it here from `trivial(0)` — as this did until the CLI
    // default moved to index 5 — makes every probe demand validator 0's
    // certificate, so each one fails `NotValidForName` and the run reports a
    // spurious "could not handshake" finding per emulated validator.
    // `emu_addrs` is reserved for when the runner spawns the emulator
    // connections themselves.
    let mut outcomes = Vec::with_capacity(plan.initiate_now.len() + plan.wait_then_connect.len());
    for _ in &plan.initiate_now {
        outcomes.push(probe_nut(nut_addr, nut_san, genesis_hash, STARTUP_TIMEOUT).await);
    }
    tokio::time::sleep(INITIATOR_GRACE).await;
    for _ in &plan.wait_then_connect {
        outcomes.push(probe_nut(nut_addr, nut_san, genesis_hash, STARTUP_TIMEOUT).await);
    }
    let _ = emu_addrs;
    outcomes
}

#[cfg(test)]
mod tests {
    use super::*;
    use jamnp_s::cert::san_for_key;

    const GENESIS: [u8; 32] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    /// `k[0]` controls lexicographic ordering vs the peer; `k[31]` the `> 127` MSB bit.
    const fn key(first: u8, last: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = first;
        k[31] = last;
        k
    }

    #[test]
    fn plan_initiator_split() {
        // NUT key: all zeros, the lexicographic minimum. For such a NUT,
        // preferred_initiator(emu, nut) == (emu[31] > 127) XOR false XOR false,
        // i.e. the emulator's MSB bit alone decides (hand-computed below).
        let nut = [0u8; 32];
        let emus = [
            key(0x00, 0x00), // 0x00: not > 127 -> wait
            key(0x01, 0x00), // 0x00: not > 127 -> wait
            key(0x00, 0x80), // 0x80 > 127 -> initiate now
            key(0x01, 0x80), // 0x80 > 127 -> initiate now
            key(0x00, 0x7f), // 0x7f == 127: not > 127 -> wait
        ];
        let plan = plan_connectivity(&emus, &nut);
        assert_eq!(plan.initiate_now, vec![2, 3]);
        assert_eq!(plan.wait_then_connect, vec![0, 1, 4]);
        // Cross-check every emulator against the pure preferred-initiator rule.
        for (i, k) in emus.iter().enumerate() {
            let preferred = preferred_initiator(k, &nut);
            assert_eq!(plan.initiate_now.contains(&i), preferred, "emu {i}");
            assert_eq!(plan.wait_then_connect.contains(&i), !preferred, "emu {i}");
        }
    }

    #[tokio::test]
    async fn probe_nut_timeout() {
        // 127.0.0.1:1 is not a bound UDP port; the QUIC handshake cannot
        // complete, so the probe must report disconnected within the timeout.
        let addr: SocketAddr = ([127, 0, 0, 1], 1).into();
        let outcome = probe_nut(addr, "eNOPE", GENESIS, Duration::from_secs(1)).await;
        assert!(!outcome.connected);
        assert!(!outcome.san_matches);
        assert!(!outcome.alpn_matches);
        assert!(outcome.took < Duration::from_secs(2), "probe must not hang");
    }

    #[tokio::test]
    async fn probe_nut_handshake_ok() {
        let secret = SigningKey::from([7u8; 32]);
        let san = san_for_key(&secret.verification_key());
        let endpoint = Endpoint::serve(
            EndpointConfig {
                genesis_hash: GENESIS,
                builder: false,
            },
            secret,
            ([127, 0, 0, 1], 0).into(),
        )
        .await
        .expect("endpoint serves");
        let addr = endpoint.local_addr();
        let server = tokio::spawn(async move {
            while let Some(conn) = endpoint.accept().await {
                let _ = conn.await;
            }
        });
        let outcome = probe_nut(addr, &san, GENESIS, Duration::from_secs(2)).await;
        assert!(outcome.connected);
        assert!(outcome.san_matches);
        assert!(outcome.alpn_matches);
        server.abort();
    }

    #[tokio::test]
    async fn probe_nut_bad_san() {
        let secret = SigningKey::from([7u8; 32]);
        let endpoint = Endpoint::serve(
            EndpointConfig {
                genesis_hash: GENESIS,
                builder: false,
            },
            secret,
            ([127, 0, 0, 1], 0).into(),
        )
        .await
        .expect("endpoint serves");
        let addr = endpoint.local_addr();
        let server = tokio::spawn(async move {
            while let Some(conn) = endpoint.accept().await {
                let _ = conn.await;
            }
        });
        let wrong = SigningKey::from([9u8; 32]);
        let wrong_san = san_for_key(&wrong.verification_key());
        let outcome = probe_nut(addr, &wrong_san, GENESIS, Duration::from_secs(2)).await;
        assert!(!outcome.connected);
        server.abort();
    }

    #[test]
    fn grace_order() {
        let nut = key(0x02, 0x00);
        let emus = [
            key(0x00, 0x00),
            key(0x01, 0x00),
            key(0x03, 0x00),
            key(0x04, 0x00),
        ];
        let plan = plan_connectivity(&emus, &nut);
        let all: Vec<usize> = plan
            .initiate_now
            .iter()
            .chain(plan.wait_then_connect.iter())
            .copied()
            .collect();
        let mut sorted = all.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, all, "no emulator may be in both lists");
        assert_eq!(
            sorted,
            (0..emus.len()).collect::<Vec<_>>(),
            "union covers all emulators"
        );
    }
}
