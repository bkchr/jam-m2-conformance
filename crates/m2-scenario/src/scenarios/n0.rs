//! N0 — connectivity and sync (DESIGN.md §11 N0).
//!
//! Nine checks covering the N0 table rows, written with the [`dsl`] scenario
//! DSL. Each is a [`dsl::Check`] whose body reads the `m2-emu` observation log
//! and returns [`dsl::CheckResult`]s: an expected-answer subsequence plus
//! embedded [`dsl::log`] assertions.
//!
//! # Observation contract
//!
//! The `m2-emu` log records [`dsl::Obs`] events keyed by the emulated peer
//! (indices `1..=5`; the NUT is index `0`). Beyond the named [`dsl::ObsKind`]
//! events, this lane uses the [`dsl::ObsKind::Other`] extension slot for the
//! N0 detail observations the emulator emits (`code()` values below). The
//! runner wires the emulator to emit them.
//!
//! | code | meaning |
//! |------|---------|
//! | 20 | NUT cert verified: Ed25519 signature algorithm |
//! | 21 | NUT cert verified: key equals the on-chain key |
//! | 22 | NUT cert verified: exactly one SAN `e`+base32 |
//! | 23 | NUT accepted ALPN `jamnp-s/1/<8hex>` |
//! | 24 | NUT offered `jamnp-s/1/<8hex>` when initiating |
//! | 25 | `/builder` ALPN accepted on the accept side |
//! | 26 | ALPN mismatch (wrong version/nibbles) → handshake failed |
//! | 27 | NUT dialed the exact metadata address+port |
//! | 28 | ≥20 `/builder` connections accepted (soft) |
//! | 29 | CE 133 accepted on a builder connection |
//! | 30 | UP 0 stream kind byte 0 |
//! | 31 | UP 0 handshake Final == genesis |
//! | 32 | duplicate UP 0 → greatest stream id kept, other reset |
//! | 33 | CE 128 response: both halves FIN |
//! | 34 | CE 128 response: ≤ Max blocks |
//! | 35 | CE 129 keys sorted |
//! | 36 | CE 129 boundary nodes parent-before-child |
//! | 37 | CE 129 size cap respected |
//! | 38 | CE 129 `len++` values |
//! | 39 | NUT initiated a connection (preferred-initiator) |
//! | 40 | NUT re-announced a learned block |

use crate::dsl::{check, log, Check, ObsKind, Severity};

/// The first emulated peer when the NUT sits at validator index 0 — the
/// fabricated dry-run log and the lane's own tests are built around it.
///
/// A real run passes its own first emulated index instead: the emulated set is
/// every validator but the NUT's, so it starts at 1 only when the NUT is at 0.
pub const PEER_1: u16 = 1;

pub const CERT_ED25519: u8 = 20;
pub const CERT_KEY_MATCH: u8 = 21;
pub const CERT_SAN_OK: u8 = 22;
pub const ALPN_ACCEPTED: u8 = 23;
pub const ALPN_OFFERED: u8 = 24;
pub const ALPN_BUILDER_OK: u8 = 25;
pub const ALPN_MISMATCH: u8 = 26;
pub const ENDPOINT_DIALED: u8 = 27;
pub const BUILDERS_ACCEPTED: u8 = 28;
pub const CE133_ON_BUILDER: u8 = 29;
pub const UP0_KIND0: u8 = 30;
pub const UP0_FINAL_GENESIS: u8 = 31;
pub const UP0_DUP_RESET: u8 = 32;
pub const CE128_FIN_BOTH: u8 = 33;
pub const CE128_MAX_RESPECTED: u8 = 34;
pub const CE129_SORTED: u8 = 35;
pub const CE129_BOUNDARY_ORDER: u8 = 36;
pub const CE129_SIZE_CAP: u8 = 37;
pub const CE129_LEN_PREFIXED: u8 = 38;
pub const NUT_INITIATED: u8 = 39;
pub const REANNOUNCED: u8 = 40;
/// The emulator dialled a peer it was *not* the preferred initiator for, after
/// the grace expired without the NUT connecting (`simple.md:70-80`).
pub const FALLBACK_DIAL: u8 = 47;

/// TLS cert `simple.md:7-23`: Ed25519 cert, key == on-chain key, exactly one
/// SAN `e`+base32; a bad cert closes the connection.
/// TLS certificate (`simple.md:7-43`, DESIGN §11).
///
/// `tls_cert_connection_established` is the mutual handshake itself, as the
/// connectivity probe observed it. It used to demand that the node open UP 0
/// to the *lowest-numbered* emulated peer within 8 s, which is a different
/// claim and not one the specification makes: UP 0 goes to grid neighbours
/// (DESIGN §11, UP 0 handshake row), so a node that connects to a peer and
/// opens UP 0 only to its neighbours is conforming and failed this anyway.
pub fn tls_cert(handshake_completed: bool) -> Check {
    check("tls_cert", Severity::Hard, move |obs| {
        let mut results = vec![
            log::check(
                "tls_cert_ed25519_sig_alg",
                obs.first(ObsKind::Other(CERT_ED25519)).is_some(),
                Severity::Hard,
            ),
            log::check(
                "tls_cert_key_matches_onchain",
                obs.first(ObsKind::Other(CERT_KEY_MATCH)).is_some(),
                Severity::Hard,
            ),
            log::check(
                "tls_cert_single_san_e_base32",
                obs.first(ObsKind::Other(CERT_SAN_OK)).is_some(),
                Severity::Hard,
            ),
        ];
        results.push(log::check_detail(
            "tls_cert_connection_established",
            handshake_completed,
            Severity::Hard,
            || "no TLS 1.3 handshake with the node under test completed".to_string(),
        ));
        results
    })
}

/// ALPN `simple.md:48-59`: NUT accepts `jamnp-s/1/<8hex>` and offers it when
/// initiating; `/builder` accepted on the accept side; wrong version/nibbles
/// → handshake fails.
/// ALPN (`simple.md:48-59`, DESIGN §11).
///
/// `wrong_alpn_rejected` comes from a probe that dials with the right version
/// and suffix but the wrong genesis nibbles. It used to come from an
/// `ALPN_MISMATCH` marker that nothing ever wrote, so the check's
/// `!mismatched` term was always true: it passed without any mismatched
/// connection having been attempted.
pub fn alpn(wrong_alpn_rejected: bool) -> Check {
    check("alpn", Severity::Hard, move |obs| {
        let mut results = vec![
            log::check(
                "alpn_version1_accepted",
                obs.first(ObsKind::Other(ALPN_ACCEPTED)).is_some(),
                Severity::Hard,
            ),
            log::check(
                "alpn_offered_when_initiating",
                obs.first(ObsKind::Other(ALPN_OFFERED)).is_some(),
                Severity::Hard,
            ),
        ];
        // The `/builder` suffix is asserted by `builder_slots`, which has the
        // probe that opens such a connection.
        results.push(log::check_detail(
            "alpn_wrong_version_rejected",
            wrong_alpn_rejected,
            Severity::Hard,
            || "the node completed a handshake offering an ALPN for a different chain".to_string(),
        ));
        results
    })
}

/// Preferred initiator `simple.md:70-80`: of each validator pair exactly one
/// side dials, decided by `P(a, b)`.
///
/// Which side that is depends on the key set, so the split is given per run:
/// `nut_preferred` are the emulated peers the NUT should dial, `emu_preferred`
/// the ones the emulator dials. Asserting the two sets is strictly stronger
/// than a flat peer count, which a node that dialled everything, or nothing and
/// got dialled, would both satisfy.
///
/// `FALLBACK_DIAL` marks a peer the emulator dialled only because the grace
/// expired first, so its absence is what "within the grace" means here. Reading
/// it from the log beats comparing timestamps: it is recorded at the decision
/// point, by the code that made the decision.
pub fn preferred_initiator(nut_preferred: Vec<u16>, emu_preferred: Vec<u16>) -> Check {
    check("preferred_initiator", Severity::Hard, move |obs| {
        let initiated = obs.peers_with(ObsKind::Other(NUT_INITIATED));
        let missing: Vec<u16> = nut_preferred
            .iter()
            .copied()
            .filter(|p| !initiated.contains(p))
            .collect();
        let unexpected: Vec<u16> = emu_preferred
            .iter()
            .copied()
            .filter(|p| initiated.contains(p))
            .collect();
        let fell_back = obs.peers_with(ObsKind::Other(FALLBACK_DIAL));
        vec![
            log::check(
                "nut_initiates_where_preferred",
                missing.is_empty(),
                Severity::Hard,
            ),
            log::check(
                "nut_waits_where_not_preferred",
                unexpected.is_empty(),
                Severity::Hard,
            ),
            log::check(
                "nut_initiates_within_grace",
                fell_back.is_empty(),
                Severity::Soft,
            ),
        ]
    })
}

/// Endpoint decoding `simple.md:66-68`: the NUT dials the exact IPv6/port from
/// the validator metadata.
pub fn endpoint_decoding() -> Check {
    check("endpoint_decoding", Severity::Hard, |obs| {
        vec![log::check(
            "endpoint_dialed_exact_addr",
            obs.first(ObsKind::Other(ENDPOINT_DIALED)).is_some(),
            Severity::Hard,
        )]
    })
}

/// Builder slots `simple.md:82-84`: ≥20 `/builder` connections accepted (soft);
/// CE 133 accepted on any connection.
pub fn builder_slots(probe: Option<BuilderProbeFacts>) -> Check {
    check("builder_slots", Severity::Hard, move |_obs| {
        let Some(probe) = probe.clone() else {
            return vec![log::check_detail(
                "builder_slots_ge_20",
                false,
                Severity::Soft,
                || "the builder-role surface was not probed".to_string(),
            )];
        };
        vec![
            log::check_detail(
                "builder_slots_ge_20",
                probe.accepted >= BUILDER_SLOTS_EXPECTED,
                Severity::Soft,
                || {
                    format!(
                        "the node accepted {} of {} `/builder` connection(s); \
                         at least {BUILDER_SLOTS_EXPECTED} are expected",
                        probe.accepted, probe.attempted
                    )
                },
            ),
            log::check_detail(
                "alpn_builder_suffix_accepted",
                probe.accepted > 0,
                Severity::Hard,
                || {
                    "the node accepted no connection carrying the `/builder` ALPN suffix"
                        .to_string()
                },
            ),
            log::check_detail(
                "ce133_accepted_on_builder",
                probe.ce133_accepted,
                Severity::Hard,
                || {
                    probe
                        .ce133_detail
                        .clone()
                        .unwrap_or_else(|| "CE 133 was refused on a builder connection".to_string())
                },
            ),
        ]
    })
}

/// Builder-role connections a conforming node accepts (`simple.md:82-84`).
pub const BUILDER_SLOTS_EXPECTED: usize = 20;

/// What the runner's builder probe observed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuilderProbeFacts {
    pub attempted: usize,
    pub accepted: usize,
    pub ce133_accepted: bool,
    pub ce133_detail: Option<String>,
}

/// UP 0 handshake `simple.md:192-236`: kind byte 0, `u32 LE` framing,
/// handshake Final = genesis. Duplicate UP 0 handling (greatest stream id
/// kept) is a robustness fault exercised by the N7 lane, not the N0 happy path.
pub fn up0_handshake() -> Check {
    check("up0_handshake", Severity::Hard, |obs| {
        vec![
            log::check(
                "up0_kind_byte_0",
                obs.first(ObsKind::Other(UP0_KIND0)).is_some(),
                Severity::Hard,
            ),
            log::check(
                "up0_final_is_genesis",
                obs.first(ObsKind::Other(UP0_FINAL_GENESIS)).is_some(),
                Severity::Hard,
            ),
        ]
    })
}

/// UP 0 announce `simple.md:207-212`: an emulated author announces within
/// 500 ms; the NUT re-announces every block it learns or authors. The NUT's
/// re-announce arrives on whichever peer it is connected to, so both
/// observations are matched on any emulated peer.
pub fn up0_announce() -> Check {
    check("up0_announce", Severity::Hard, |obs| {
        vec![
            log::check(
                "emulated_author_announces",
                obs.first(ObsKind::Up0Announce).is_some(),
                Severity::Hard,
            ),
            log::check(
                "nut_reannounces_learned_block",
                obs.first(ObsKind::Other(REANNOUNCED)).is_some(),
                Severity::Hard,
            ),
        ]
    })
}

/// A block the node under test returned for a CE 128 request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbedBlock {
    pub slot: u32,
    pub hash: [u8; 32],
    pub parent: [u8; 32],
}

/// What the node under test answered for one CE 128 request the emulator made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ce128Probe {
    pub peer: u16,
    /// `Maximum Blocks` asked for (`simple.md:244`).
    pub max_blocks: u32,
    /// The hash the ascending-exclusive walk started from, normally genesis.
    pub from: [u8; 32],
    /// Blocks returned, in reply order.
    pub returned: Vec<ProbedBlock>,
    /// The response was framed and the stream FIN'd, both halves closed.
    pub finished: bool,
    pub error: Option<String>,
}

/// What the node under test answered for one CE 129 request the emulator made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ce129Probe {
    pub peer: u16,
    pub start: [u8; 31],
    pub end: [u8; 31],
    /// `Maximum Size` asked for (`simple.md:298`).
    pub max_size: u32,
    /// Keys returned, in reply order.
    pub keys: Vec<[u8; 31]>,
    /// Boundary nodes returned, in reply order.
    pub boundary_nodes: Vec<[u8; 64]>,
    /// Bytes across both response messages, for findings.
    pub response_bytes: usize,
    /// `key.len() + value.len()` for each returned pair, in reply order:
    /// what `Maximum Size` actually bounds (`simple.md:283-285`).
    pub entry_bytes: Vec<usize>,
    /// Both messages decoded as size-implied sequences. A value that did not
    /// carry its own `len++` prefix cannot decode this way, so a successful
    /// decode is what the length-prefix check rests on.
    pub decoded: bool,
    pub error: Option<String>,
}

/// First eight bytes of a hash, for findings.
fn short(hash: &[u8]) -> String {
    hash.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// CE 128 served *by the NUT* (`simple.md:238-265`, DESIGN §11): ordered,
/// ≤ Max, both halves FIN, and ascending-exclusive from genesis equal to the
/// reference chain.
///
/// The emulator makes the requests; these grade the replies. The previous
/// version graded the harness instead. `ce128_both_halves_fin` and
/// `ce128_respects_max` were recorded by the emulator's own *serve* path, so
/// they were entered whenever the harness answered the NUT and could not fail;
/// `ce128_ascending_covers_reference` counted those serves and compared the
/// count against the number of reference blocks, which is neither the right
/// direction nor the right quantity.
pub fn ce128_serve(reference: Vec<[u8; 32]>, probes: Vec<Ce128Probe>) -> Check {
    check("ce128_serve", Severity::Hard, move |_obs| {
        if probes.is_empty() {
            return vec![log::check_detail(
                "ce128_ascending_covers_reference",
                false,
                Severity::Hard,
                || "no CE 128 request to the node under test completed".to_string(),
            )];
        }
        probes
            .iter()
            .flat_map(|probe| {
                let returned = &probe.returned;
                // An ascending-exclusive walk from `from` is a contiguous
                // chain: the first block's parent is `from`, and each block
                // after it is the child of the one before.
                let chains = returned.first().is_some_and(|b| b.parent == probe.from)
                    && returned.windows(2).all(|w| w[1].parent == w[0].hash);
                let ascending = returned.windows(2).all(|w| w[0].slot < w[1].slot);
                // The reference is what the harness knows the chain to be. The
                // NUT may legitimately be ahead of it, so only the overlap is
                // compared.
                let overlap = reference.len().min(returned.len());
                let agrees = returned[..overlap]
                    .iter()
                    .zip(&reference[..overlap])
                    .all(|(got, want)| got.hash == *want);
                vec![
                    log::check_detail(
                        "ce128_ascending_covers_reference",
                        probe.error.is_none() && !returned.is_empty() && chains && agrees,
                        Severity::Hard,
                        || match &probe.error {
                            Some(e) => format!("CE 128 ascending from genesis failed: {e}"),
                            None if returned.is_empty() => {
                                "CE 128 ascending from genesis returned no blocks".to_string()
                            }
                            None if !chains => format!(
                                "CE 128 reply is not a chain from {}: {}",
                                short(&probe.from),
                                returned
                                    .iter()
                                    .map(|b| format!(
                                        "{}(parent {})",
                                        short(&b.hash),
                                        short(&b.parent)
                                    ))
                                    .collect::<Vec<_>>()
                                    .join(" -> ")
                            ),
                            None => {
                                let at = returned[..overlap]
                                    .iter()
                                    .zip(&reference[..overlap])
                                    .position(|(got, want)| got.hash != *want)
                                    .unwrap_or(0);
                                format!(
                                    "CE 128 reply differs from the reference chain at index {at}: \
                                     got {}, reference has {}",
                                    short(&returned[at].hash),
                                    short(&reference[at])
                                )
                            }
                        },
                    ),
                    log::check_detail("ce128_ascending_ordered", ascending, Severity::Hard, || {
                        format!(
                            "CE 128 reply is not ascending by slot: {:?}",
                            returned.iter().map(|b| b.slot).collect::<Vec<_>>()
                        )
                    }),
                    log::check_detail(
                        "ce128_respects_max",
                        returned.len() as u32 <= probe.max_blocks,
                        Severity::Hard,
                        || {
                            format!(
                                "asked for at most {} block(s), got {}",
                                probe.max_blocks,
                                returned.len()
                            )
                        },
                    ),
                    log::check_detail(
                        "ce128_both_halves_fin",
                        probe.finished,
                        Severity::Hard,
                        || "the node did not FIN its CE 128 response stream".to_string(),
                    ),
                ]
            })
            .collect()
    })
}

/// CE 129 served *by the NUT* (`simple.md:267-303`, DESIGN §11): sorted 31-byte
/// keys inside the requested range, boundary nodes parent-before-child with no
/// duplicates, the size cap respected, and `len++` values.
///
/// As with CE 128, these used to be recorded by the emulator's own serve path
/// — and with a comment saying an empty reply "trivially satisfies" all four.
/// They therefore asserted nothing about the node, and once genesis was
/// anchored to the current epoch (A9) the node stopped warp-syncing, stopped
/// asking for state, and the four markers stopped being written at all: four
/// hard failures that were really the absence of a probe.
pub fn ce129_serve(probes: Vec<Ce129Probe>) -> Check {
    check("ce129_serve", Severity::Hard, move |_obs| {
        if probes.is_empty() {
            return vec![log::check_detail(
                "ce129_served",
                false,
                Severity::Hard,
                || "no CE 129 request to the node under test was made".to_string(),
            )];
        }
        probes
            .iter()
            .flat_map(|probe| {
                // A refused request is one fact, not four. Reporting
                // "keys not sorted" about a response that never arrived
                // invents a claim, which is the failure mode this whole lane
                // was built on.
                let mut results = vec![log::check_detail(
                    "ce129_served",
                    probe.error.is_none(),
                    Severity::Hard,
                    || {
                        probe
                            .error
                            .clone()
                            .unwrap_or_else(|| "CE 129 was not served".to_string())
                    },
                )];
                if probe.error.is_some() {
                    return results;
                }
                let sorted = probe.keys.windows(2).all(|w| w[0] < w[1]);
                let in_range = probe
                    .keys
                    .iter()
                    .all(|k| *k >= probe.start && *k <= probe.end);
                results.extend([
                    log::check_detail(
                        "ce129_keys_sorted",
                        sorted && in_range,
                        Severity::Hard,
                        || {
                            if !sorted {
                                "CE 129 keys are not in ascending order".to_string()
                            } else {
                                format!(
                                    "CE 129 returned {} key(s) outside the requested range",
                                    probe
                                        .keys
                                        .iter()
                                        .filter(|k| **k < probe.start || **k > probe.end)
                                        .count()
                                )
                            }
                        },
                    ),
                    log::check_detail(
                        "ce129_boundary_parent_before_child",
                        boundary_fault(&probe.boundary_nodes).is_none(),
                        Severity::Hard,
                        || {
                            let n = probe.boundary_nodes.len();
                            match boundary_fault(&probe.boundary_nodes) {
                                Some(BoundaryFault::Duplicate { at }) => {
                                    format!("CE 129 repeated a boundary node at index {at} of {n}")
                                }
                                Some(BoundaryFault::ChildBeforeParent { parent, child }) => {
                                    format!(
                                        "CE 129 put a boundary node at index {child} before its \
                                         parent at index {parent}, of {n}"
                                    )
                                }
                                None => String::new(),
                            }
                        },
                    ),
                    log::check_detail(
                        "ce129_size_cap",
                        budgeted_bytes(&probe.entry_bytes) <= probe.max_size as usize,
                        Severity::Hard,
                        || {
                            format!(
                                "asked for at most {} byte(s) of key/value data; got {} \
                                 across {} pair(s) ({} on the wire in all)",
                                probe.max_size,
                                budgeted_bytes(&probe.entry_bytes),
                                probe.entry_bytes.len(),
                                probe.response_bytes
                            )
                        },
                    ),
                    log::check_detail(
                        "ce129_len_prefixed_values",
                        probe.decoded,
                        Severity::Hard,
                        || {
                            "the CE 129 response did not decode as `Key ++ len++[u8]` pairs"
                                .to_string()
                        },
                    ),
                ]);
                results
            })
            .collect()
    })
}

/// Key/value bytes the size cap governs: every returned pair but the first.
///
/// A responder has to be allowed to exceed the cap on a single pair, or a
/// value larger than any cap a requester might name could never be served and
/// the state holding it could never be synced. The exemption is for the first
/// pair only; everything after it is inside the budget.
fn budgeted_bytes(entry_bytes: &[usize]) -> usize {
    entry_bytes.iter().skip(1).sum()
}

/// Why a boundary-node sequence is not acceptable (`simple.md:275-281`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundaryFault {
    Duplicate { at: usize },
    ChildBeforeParent { parent: usize, child: usize },
}

/// Boundary nodes hold no duplicates, and no node appears before the node that
/// references it (`simple.md:275-281`).
///
/// A branch node carries its children's hashes, so "parent before child" is
/// testable without decoding the node layout: if some 32-byte half of node *i*
/// is the reference to node *j*, then *j* is that node's child and must come
/// after it. A leaf's halves are a key fragment and a value hash, neither of
/// which references a sibling boundary node except by collision.
fn boundary_fault(nodes: &[[u8; 64]]) -> Option<BoundaryFault> {
    let mut seen = std::collections::HashSet::new();
    for (at, node) in nodes.iter().enumerate() {
        if !seen.insert(*node) {
            return Some(BoundaryFault::Duplicate { at });
        }
    }
    let index: std::collections::HashMap<[u8; 32], usize> = nodes
        .iter()
        .enumerate()
        .map(|(i, node)| (node_hash(node), i))
        .collect();
    for (i, node) in nodes.iter().enumerate() {
        for half in [&node[..32], &node[32..]] {
            let mut h = [0u8; 32];
            h.copy_from_slice(half);
            h[0] &= 0b0111_1111;
            if let Some(&child) = index.get(&h) {
                if child <= i {
                    return Some(BoundaryFault::ChildBeforeParent { parent: i, child });
                }
            }
        }
    }
    None
}

/// How a parent refers to a child node: blake2b-256 with the top bit of the
/// first byte cleared, that bit being the branch/leaf discriminator rather
/// than part of the hash.
///
/// Without the mask this matches only the half of all children whose hash
/// happens to have that bit clear, so an out-of-order child goes unnoticed
/// about half the time.
fn node_hash(node: &[u8; 64]) -> [u8; 32] {
    let digest = blake2b_simd::Params::new().hash_length(32).hash(node);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_bytes());
    out[0] &= 0b0111_1111;
    out
}

/// Per-run facts the N0 lane needs, which depend on the validator set rather
/// than on the protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct N0Ctx {
    /// Blocks the reference chain authored, for the CE 128 coverage check.
    pub reference_block_count: usize,
    /// Reference chain after genesis, in slot order: what an ascending
    /// CE 128 walk from genesis should return.
    pub reference_chain: Vec<[u8; 32]>,
    /// CE 128 replies the node under test gave the emulator.
    pub ce128_probes: Vec<Ce128Probe>,
    /// CE 129 replies the node under test gave the emulator.
    pub ce129_probes: Vec<Ce129Probe>,
    /// Lowest emulated validator index: 1 only when the NUT is at index 0.
    pub first_emu_peer: u16,
    /// A mutual TLS 1.3 handshake with the node completed.
    pub handshake_completed: bool,
    /// A dial offering an ALPN for a different chain was refused.
    pub wrong_alpn_rejected: bool,
    /// What the builder-role probe saw, when it ran.
    pub builder: Option<BuilderProbeFacts>,
    /// Emulated peers the NUT is the preferred initiator for: it should dial
    /// these, and the emulator should not.
    pub nut_preferred_peers: Vec<u16>,
    /// Emulated peers the emulator is the preferred initiator for: it dials
    /// these, and the NUT should wait.
    pub emu_preferred_peers: Vec<u16>,
}

/// All nine N0 checks in dependency order (N0 first; later lanes build on it).
pub fn all(ctx: &N0Ctx) -> Vec<Check> {
    vec![
        tls_cert(ctx.handshake_completed),
        alpn(ctx.wrong_alpn_rejected),
        preferred_initiator(
            ctx.nut_preferred_peers.clone(),
            ctx.emu_preferred_peers.clone(),
        ),
        endpoint_decoding(),
        builder_slots(ctx.builder.clone()),
        up0_handshake(),
        up0_announce(),
        ce128_serve(ctx.reference_chain.clone(), ctx.ce128_probes.clone()),
        ce129_serve(ctx.ce129_probes.clone()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsl::{CheckResult, Obs, ObsLog, Outcome};

    fn ev(peer: u16, kind: ObsKind, at_ms: u64) -> Obs {
        Obs { peer, kind, at_ms }
    }
    fn run(c: &Check, obs: &ObsLog) -> Vec<CheckResult> {
        (c.run)(obs)
    }

    fn all_pass(results: &[CheckResult]) -> bool {
        results.iter().all(|r| r.outcome == Outcome::Pass)
    }

    /// `tls_cert_connection_established` is the handshake, nothing else.
    ///
    /// It used to demand that the node open UP 0 to the run's lowest-numbered
    /// emulated peer within 8 s, and a test here guarded that it watched the
    /// *configured* first peer rather than a fixed index 1. The index was the
    /// smaller of the two problems: UP 0 goes to grid neighbours, so a node
    /// that connects to a peer and opens UP 0 only to its neighbours is
    /// conforming and failed this check anyway. The handshake itself is what
    /// the connectivity probe establishes, and what this row now reports.
    #[test]
    fn tls_cert_reports_the_handshake_not_up0() {
        let mut obs = ObsLog::new();
        obs.push(10, ev(1, ObsKind::Other(CERT_ED25519), 10));
        obs.push(20, ev(1, ObsKind::Other(CERT_KEY_MATCH), 20));
        obs.push(30, ev(1, ObsKind::Other(CERT_SAN_OK), 30));

        // No UP 0 anywhere in the log, and the lane is still satisfied.
        assert!(
            all_pass(&run(&tls_cert(true), &obs)),
            "a completed handshake passes without any UP 0 observation"
        );
        assert_eq!(
            outcome_of(
                &run(&tls_cert(false), &obs),
                "tls_cert_connection_established"
            ),
            &Outcome::Fail(Severity::Hard),
            "no handshake fails hard"
        );
    }

    #[test]
    fn tls_cert_pass_and_fail() {
        let mut obs = ObsLog::new();
        obs.push(10, ev(1, ObsKind::Other(CERT_ED25519), 10));
        obs.push(20, ev(1, ObsKind::Other(CERT_KEY_MATCH), 20));
        obs.push(30, ev(1, ObsKind::Other(CERT_SAN_OK), 30));
        assert!(
            all_pass(&run(&tls_cert(true), &obs)),
            "conforming log passes"
        );

        let mut bad = ObsLog::new();
        bad.push(10, ev(1, ObsKind::Other(CERT_ED25519), 10));
        bad.push(20, ev(1, ObsKind::Other(CERT_KEY_MATCH), 20)); // no CERT_SAN_OK
        let results = run(&tls_cert(true), &bad);
        assert!(
            results
                .iter()
                .any(|r| r.name == "tls_cert_single_san_e_base32"
                    && r.outcome == Outcome::Fail(Severity::Hard)),
            "missing SAN observation fails hard"
        );
    }

    #[test]
    fn alpn_pass_and_fail() {
        let mut obs = ObsLog::new();
        obs.push(0, ev(1, ObsKind::Other(ALPN_ACCEPTED), 0));
        obs.push(10, ev(1, ObsKind::Other(ALPN_OFFERED), 10));
        assert!(all_pass(&run(&alpn(true), &obs)), "conforming log passes");

        let bad = ObsLog::new(); // nothing observed
        let results = run(&alpn(true), &bad);
        assert!(
            results.iter().any(|r| r.name == "alpn_version1_accepted"
                && r.outcome == Outcome::Fail(Severity::Hard)),
            "missing ALPN acceptance fails hard"
        );

        // A node that completes a handshake for another chain's ALPN fails,
        // which the marker-based version could not express: nothing ever
        // recorded a mismatch, so its `!mismatched` term was always true.
        assert_eq!(
            outcome_of(&run(&alpn(false), &obs), "alpn_wrong_version_rejected"),
            &Outcome::Fail(Severity::Hard),
            "accepting a mismatched ALPN fails hard"
        );
    }

    /// The run under test: the NUT should dial peers 0, 1 and 2; the emulator
    /// dials 3 and 4. This is the split the default six-validator set with the
    /// NUT at index 5 actually produces.
    fn split() -> (Vec<u16>, Vec<u16>) {
        (vec![0, 1, 2], vec![3, 4])
    }

    fn initiator_check() -> Check {
        let (nut, emu) = split();
        preferred_initiator(nut, emu)
    }

    fn outcome_of<'a>(results: &'a [CheckResult], name: &str) -> &'a Outcome {
        &results
            .iter()
            .find(|r| r.name == name)
            .expect("check is reported")
            .outcome
    }

    #[test]
    fn preferred_initiator_passes_on_the_exact_split() {
        let mut obs = ObsLog::new();
        for peer in [0u16, 1, 2] {
            obs.push(1000, ev(peer, ObsKind::Other(NUT_INITIATED), 1000));
        }
        assert!(all_pass(&run(&initiator_check(), &obs)));
    }

    /// A node that dials nothing: the old flat check could only call this soft,
    /// because it asked whether *any* peer saw an initiation.
    #[test]
    fn preferred_initiator_fails_hard_when_the_nut_never_dials() {
        let results = run(&initiator_check(), &ObsLog::new());
        assert_eq!(
            outcome_of(&results, "nut_initiates_where_preferred"),
            &Outcome::Fail(Severity::Hard)
        );
    }

    /// A node that dials one of the three it owes is not conformant, and a
    /// count-based check that compared totals could still be satisfied by it
    /// dialling somewhere else instead.
    #[test]
    fn preferred_initiator_fails_hard_on_a_partial_split() {
        let mut obs = ObsLog::new();
        obs.push(1000, ev(0, ObsKind::Other(NUT_INITIATED), 1000));
        let results = run(&initiator_check(), &obs);
        assert_eq!(
            outcome_of(&results, "nut_initiates_where_preferred"),
            &Outcome::Fail(Severity::Hard)
        );
    }

    /// Dialling a peer the emulator is preferred for breaks the rule from the
    /// other side, even with all three owed connections made.
    #[test]
    fn preferred_initiator_fails_hard_when_the_nut_dials_where_it_should_wait() {
        let mut obs = ObsLog::new();
        for peer in [0u16, 1, 2, 3] {
            obs.push(1000, ev(peer, ObsKind::Other(NUT_INITIATED), 1000));
        }
        let results = run(&initiator_check(), &obs);
        assert_eq!(
            outcome_of(&results, "nut_waits_where_not_preferred"),
            &Outcome::Fail(Severity::Hard)
        );
        assert_eq!(
            outcome_of(&results, "nut_initiates_where_preferred"),
            &Outcome::Pass
        );
    }

    /// The node connected everywhere it owed, but only after the grace had
    /// expired and the emulator had already dialled: soft, not hard.
    #[test]
    fn preferred_initiator_is_soft_when_the_nut_misses_the_grace() {
        let mut obs = ObsLog::new();
        obs.push(5000, ev(2, ObsKind::Other(FALLBACK_DIAL), 5000));
        for peer in [0u16, 1, 2] {
            obs.push(7000, ev(peer, ObsKind::Other(NUT_INITIATED), 7000));
        }
        let results = run(&initiator_check(), &obs);
        assert_eq!(
            outcome_of(&results, "nut_initiates_where_preferred"),
            &Outcome::Pass
        );
        assert_eq!(
            outcome_of(&results, "nut_initiates_within_grace"),
            &Outcome::Fail(Severity::Soft)
        );
    }

    #[test]
    fn endpoint_decoding_pass_and_fail() {
        let mut obs = ObsLog::new();
        obs.push(0, ev(1, ObsKind::Other(ENDPOINT_DIALED), 0));
        assert!(all_pass(&run(&endpoint_decoding(), &obs)));
        assert_eq!(
            run(&endpoint_decoding(), &ObsLog::new())[0].outcome,
            Outcome::Fail(Severity::Hard)
        );
    }

    fn builder(accepted: usize, ce133: bool) -> BuilderProbeFacts {
        BuilderProbeFacts {
            attempted: 21,
            accepted,
            ce133_accepted: ce133,
            ce133_detail: None,
        }
    }

    #[test]
    fn builder_slots_grades_the_probe() {
        let obs = ObsLog::new();
        assert!(all_pass(&run(
            &builder_slots(Some(builder(21, true))),
            &obs
        )));

        // Nineteen of twenty-one is a soft shortfall, not a hard failure.
        let results = run(&builder_slots(Some(builder(19, true))), &obs);
        assert_eq!(
            outcome_of(&results, "builder_slots_ge_20"),
            &Outcome::Fail(Severity::Soft)
        );
        assert_eq!(
            outcome_of(&results, "alpn_builder_suffix_accepted"),
            &Outcome::Pass,
            "the suffix was accepted even though capacity fell short"
        );

        // None accepted: the suffix itself was refused.
        let results = run(&builder_slots(Some(builder(0, false))), &obs);
        assert_eq!(
            outcome_of(&results, "alpn_builder_suffix_accepted"),
            &Outcome::Fail(Severity::Hard)
        );
        assert_eq!(
            outcome_of(&results, "ce133_accepted_on_builder"),
            &Outcome::Fail(Severity::Hard)
        );

        // No probe at all cannot pass: the three checks this replaced read
        // markers that only the fabricated dry run ever wrote, so in a live
        // run they failed for want of a probe rather than for anything the
        // node did.
        let results = run(&builder_slots(None), &obs);
        assert!(results.iter().all(|r| r.outcome != Outcome::Pass));
    }

    #[test]
    fn up0_handshake_pass_and_fail() {
        let mut obs = ObsLog::new();
        obs.push(0, ev(1, ObsKind::Other(UP0_KIND0), 0));
        obs.push(10, ev(1, ObsKind::Other(UP0_FINAL_GENESIS), 10));
        assert!(all_pass(&run(&up0_handshake(), &obs)));

        let bad = ObsLog::new(); // non-genesis Final
        assert_eq!(
            run(&up0_handshake(), &bad)[1].outcome,
            Outcome::Fail(Severity::Hard)
        );
    }

    #[test]
    fn up0_announce_pass_and_fail() {
        let mut obs = ObsLog::new();
        obs.push(0, ev(1, ObsKind::Up0Announce, 0));
        obs.push(300, ev(1, ObsKind::Other(REANNOUNCED), 300)); // within 2 s
        assert!(all_pass(&run(&up0_announce(), &obs)));

        let no_reannounce = ObsLog::new(); // nothing announced
        let results = run(&up0_announce(), &no_reannounce);
        assert!(
            results.iter().any(|r| r.outcome != Outcome::Pass),
            "missing re-announce fails"
        );
    }

    /// Three blocks chaining from genesis, for the CE 128 probe tests.
    fn probed_chain() -> ([u8; 32], Vec<[u8; 32]>, Vec<ProbedBlock>) {
        let genesis = [0u8; 32];
        let hashes: Vec<[u8; 32]> = (1u8..=3).map(|i| [i; 32]).collect();
        let mut parent = genesis;
        let mut blocks = Vec::new();
        for (i, hash) in hashes.iter().enumerate() {
            blocks.push(ProbedBlock {
                slot: i as u32 + 1,
                hash: *hash,
                parent,
            });
            parent = *hash;
        }
        (genesis, hashes, blocks)
    }

    fn ce128_probe(genesis: [u8; 32], returned: Vec<ProbedBlock>) -> Ce128Probe {
        Ce128Probe {
            peer: PEER_1,
            max_blocks: 64,
            from: genesis,
            returned,
            finished: true,
            error: None,
        }
    }

    #[test]
    fn ce128_serve_grades_the_nut_reply() {
        let (genesis, reference, blocks) = probed_chain();
        let obs = ObsLog::new();

        let results = run(
            &ce128_serve(
                reference.clone(),
                vec![ce128_probe(genesis, blocks.clone())],
            ),
            &obs,
        );
        assert!(
            all_pass(&results),
            "a reply that is the reference chain passes (results: {results:?})"
        );

        // A block that does not chain from its predecessor is not an
        // ascending-exclusive walk, whatever its slots say.
        let mut broken = blocks.clone();
        broken[2].parent = [0x99; 32];
        let results = run(
            &ce128_serve(reference.clone(), vec![ce128_probe(genesis, broken)]),
            &obs,
        );
        assert!(
            results
                .iter()
                .any(|r| r.name == "ce128_ascending_covers_reference"
                    && r.outcome == Outcome::Fail(Severity::Hard)),
            "a reply that is not a chain fails hard"
        );

        // Disagreeing with the reference at a position inside the overlap.
        let mut diverged = reference.clone();
        diverged[1] = [0x42; 32];
        let results = run(
            &ce128_serve(diverged, vec![ce128_probe(genesis, blocks.clone())]),
            &obs,
        );
        assert!(
            results
                .iter()
                .any(|r| r.name == "ce128_ascending_covers_reference"
                    && r.outcome == Outcome::Fail(Severity::Hard)),
            "a reply that differs from the reference fails hard"
        );

        // More blocks than asked for.
        let mut over = ce128_probe(genesis, blocks.clone());
        over.max_blocks = 2;
        let results = run(&ce128_serve(reference.clone(), vec![over]), &obs);
        assert!(
            results
                .iter()
                .any(|r| r.name == "ce128_respects_max" && r.outcome != Outcome::Pass),
            "exceeding Maximum Blocks fails"
        );

        // No reply at all is a failure, not a silent pass: the previous
        // version of this lane could not tell the two apart.
        let results = run(&ce128_serve(reference, Vec::new()), &obs);
        assert!(
            results.iter().all(|r| r.outcome != Outcome::Pass),
            "an unanswered CE 128 request cannot pass"
        );
    }

    fn ce129_probe(keys: Vec<[u8; 31]>) -> Ce129Probe {
        Ce129Probe {
            peer: PEER_1,
            start: [0u8; 31],
            end: [0xff; 31],
            max_size: 1024,
            entry_bytes: keys.iter().map(|k| k.len() + 1).collect(),
            keys,
            boundary_nodes: Vec::new(),
            response_bytes: 64,
            decoded: true,
            error: None,
        }
    }

    #[test]
    fn ce129_serve_grades_the_nut_reply() {
        let obs = ObsLog::new();
        let sorted = vec![[1u8; 31], [2u8; 31], [3u8; 31]];

        assert!(all_pass(&run(
            &ce129_serve(vec![ce129_probe(sorted.clone())]),
            &obs
        )));

        let unsorted = vec![[3u8; 31], [1u8; 31]];
        let results = run(&ce129_serve(vec![ce129_probe(unsorted)]), &obs);
        assert!(
            results.iter().any(
                |r| r.name == "ce129_keys_sorted" && r.outcome == Outcome::Fail(Severity::Hard)
            ),
            "unsorted keys fail hard"
        );

        // A key outside the requested range.
        let mut narrow = ce129_probe(sorted.clone());
        narrow.end = [2u8; 31];
        let results = run(&ce129_serve(vec![narrow]), &obs);
        assert!(
            results.iter().any(
                |r| r.name == "ce129_keys_sorted" && r.outcome == Outcome::Fail(Severity::Hard)
            ),
            "a key past the end of the range fails hard"
        );

        // The cap governs key/value bytes, and exempts the first pair: a value
        // larger than any cap a requester might name still has to be servable.
        let mut huge_first = ce129_probe(sorted.clone());
        huge_first.max_size = 100;
        huge_first.entry_bytes = vec![4096, 10, 10];
        assert_eq!(
            outcome_of(&run(&ce129_serve(vec![huge_first]), &obs), "ce129_size_cap"),
            &Outcome::Pass,
            "one oversized pair is allowed; the rest are inside the budget"
        );

        let mut over = ce129_probe(sorted.clone());
        over.max_size = 100;
        over.entry_bytes = vec![10, 4096, 10];
        assert_eq!(
            outcome_of(&run(&ce129_serve(vec![over]), &obs), "ce129_size_cap"),
            &Outcome::Fail(Severity::Hard),
            "pairs after the first must fit the budget"
        );

        let mut undecodable = ce129_probe(sorted);
        undecodable.decoded = false;
        let results = run(&ce129_serve(vec![undecodable]), &obs);
        assert!(
            results
                .iter()
                .any(|r| r.name == "ce129_len_prefixed_values" && r.outcome != Outcome::Pass),
            "a response that does not decode as len-prefixed pairs fails"
        );

        let results = run(&ce129_serve(Vec::new()), &obs);
        assert!(
            results.iter().all(|r| r.outcome != Outcome::Pass),
            "an unanswered CE 129 request cannot pass"
        );
    }

    #[test]
    fn boundary_nodes_must_not_repeat_or_precede_their_parent() {
        let child = [7u8; 64];
        let hash = node_hash(&child);
        let mut parent = [0u8; 64];
        parent[..32].copy_from_slice(&hash);

        assert_eq!(
            boundary_fault(&[parent, child]),
            None,
            "parent before child is accepted"
        );
        assert_eq!(
            boundary_fault(&[child, parent]),
            Some(BoundaryFault::ChildBeforeParent {
                parent: 1,
                child: 0
            }),
            "a child before its parent is rejected, and named"
        );
        assert_eq!(
            boundary_fault(&[child, child]),
            Some(BoundaryFault::Duplicate { at: 1 }),
            "duplicate boundary nodes are rejected, and named"
        );
    }

    #[test]
    fn all_n0_checks_distinct() {
        let checks = all(&N0Ctx {
            reference_block_count: 2,
            reference_chain: Vec::new(),
            ce128_probes: Vec::new(),
            ce129_probes: Vec::new(),
            first_emu_peer: PEER_1,
            handshake_completed: true,
            wrong_alpn_rejected: true,
            builder: None,
            nut_preferred_peers: vec![PEER_1],
            emu_preferred_peers: Vec::new(),
        });
        assert_eq!(checks.len(), 9);
        let mut ids: Vec<&str> = checks.iter().map(|c| c.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), 9, "all check ids are distinct");
    }
}
