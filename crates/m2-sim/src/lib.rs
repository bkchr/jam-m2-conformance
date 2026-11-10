//! A node-shaped stand-in the harness can grade, honest or broken one named
//! way at a time.
//!
//! A check is an assertion about a node, and until a node makes the mistake it
//! describes nobody knows whether it can fail. Every run this harness had done
//! was against polkajam, which does not make those mistakes -- which is how
//! two harness defects survived for weeks. [`SimFault`] is the answer: a check
//! that fails against the broken node and passes against the honest one has
//! been shown to work.
//!
//! [`SimNode`] speaks UP 0, CE 128/129 and CE 131/132 over whatever
//! [`jamnp_s::transport`] it is handed, authors its own slots and runs the
//! Safrole lottery.
//!
//! **A stand-in, not a node**: it keeps no state machine and serves from the
//! reference chain. The honest variant passing a check means the check is
//! satisfiable, not that polkajam would satisfy it; the evidence runs the
//! other way, from the faults.

#![deny(unsafe_code)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_consensus::SigningKey;
use jam_std_common::{bandersnatch::ring_vrf, Block, TicketEnvelope};
use jam_types::{Decode, Encode, HeaderHash};
use jamnp_s::clock;
use jamnp_s::codec::ce128_129::{BlockRequest, BlockResponse, Direction, StateRequest};
use jamnp_s::codec::ce131_136::{Ticket, TicketDistribution};
use jamnp_s::codec::up0::{Announcement, Final, Handshake};
use jamnp_s::endpoint::{EndpointConfig, EndpointError};
use jamnp_s::framing::{frame, frame_message, FrameReader, CE128, CE129, CE131, CE132, UP};
use jamnp_s::transport::{Conn, RecvHalf, SendHalf, Transport};
use m2_reference::chain::RefChain;
use m2_reference::tickets::{proxy_index, ticket_id, verify_ticket};
use tokio::sync::broadcast;

/// What this node gets wrong: one at a time, each the smallest deviation that
/// should cost one named row. A fault breaking two things leaves it unclear
/// which check caught which.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SimFault {
    /// Behave.
    #[default]
    None,
    /// Never answer UP 0. The stream stays open and nothing is said on it.
    SilentOnUp0,
    /// Answer UP 0 naming a finalized head that is not genesis.
    FinalIsNotGenesis,
    /// Never re-announce a block the peer announced.
    NeverReannounces,
    /// Answer an ascending CE 128 walk newest-first.
    Ce128Descending,
    /// Never answer CE 128.
    Ce128Silent,
    /// Announce an authored block two slots late. The block is untouched:
    /// forging the header would break the seal and fail several rows at once.
    AnnouncesLate,
    /// Name the epoch after the one the ticket was proved for.
    TicketWrongEpoch,
    /// Claim an attempt index at the per-validator cap, which is one past the
    /// last legal one.
    TicketAttemptOverCap,
    /// Send a ticket to a validator that is not its designated proxy.
    TicketWrongProxy,
    /// Distribute at phase 0, the epoch boundary itself, where the entropy a
    /// ticket is sealed against has only just rotated.
    TicketAtEpochStart,
    /// Broadcast a self-proxied ticket to every validator but one.
    SelfProxyMissesAPeer,
    /// Distribute no tickets at all.
    SendsNoTickets,
    /// Send a CE 131 ticket whose ring proof does not verify.
    TicketBadProof,
    /// Broadcast a CE 132 ticket whose ring proof does not verify.
    SelfProxyBadProof,
    /// Send one ticket to its designated proxy *and* to the next validator
    /// along, so two validators hold a ticket only one of them proxies.
    TicketToTwoProxies,
    /// Accept a ticket proxied to it and never pass it on.
    NeverForwards,
    /// Accept a ticket whose ring proof does not verify, instead of refusing
    /// it by resetting the stream it arrived on.
    AcceptsBadProof,
    /// Accept a ticket for an epoch past its horizon, instead of resetting
    /// the stream (`simple.md:335-337`).
    AcceptsUnknownEpoch,
    /// Forward every proxied ticket twice, a slot apart, both while the
    /// lottery is still open.
    ///
    /// Not itself a defect -- the stopping rule bounds forwarding *after*
    /// finality, not repetition before it -- but it is what gives that rule
    /// something to bound. Against a node that forwards each ticket once the
    /// rule holds however it is written, and the row reports itself
    /// unexercised.
    RepeatsForwards,
    /// Forward a ticket again after a block of this node's own carried it and
    /// was announced as final.
    ReForwardsAfterFinality,
    /// Hold a proxied ticket until the lottery has shut, then forward it.
    ///
    /// The forward itself is well formed and goes to every validator; only
    /// its slot is wrong. Nothing can act on a ticket distributed past
    /// `epoch_tail_start`, so passing it on then is the proxy doing its duty
    /// too late to be a duty.
    ForwardsInTail,
    /// Take delivery of a ticket and never offer it to its own pool, so the
    /// block it authors leaves it out. Seals just as validly.
    OmitsDeliveredTickets,
}

/// Application error code the node resets a refused ticket stream with.
const TICKET_REFUSED_CODE: u32 = 1;

/// Byte to flip to break a proof without moving the ticket.
///
/// Past the first 32: those are the VRF output, which *is* the id, and the id
/// picks the proxy. Corrupting them would fail the routing rows too.
const PROOF_TAIL_BYTE: usize = 100;

/// Errors starting the simulated node.
#[derive(Debug, thiserror::Error)]
pub enum SimError {
    /// The transport refused to bind.
    #[error("endpoint error: {0}")]
    Endpoint(#[from] EndpointError),
}

/// How many slots late [`SimFault::AnnouncesLate`] is.
const LATE_BY_SLOTS: u64 = 2;

/// A node-shaped peer the harness can grade.
pub struct SimNode {
    chain: Arc<RefChain>,
    genesis_hash: [u8; 32],
    fault: SimFault,
    /// Announcements for every live UP 0 stream. Fan-out rather than a held
    /// send half, which is not clonable.
    announce: broadcast::Sender<Vec<u8>>,
    /// This node's validator index.
    index: usize,
    /// Emulated validators this node dialled, keyed by index: a ticket goes to
    /// the proxy its id names, not to whoever happens to be connected.
    peers: Mutex<Vec<(u16, Conn)>>,
    /// Blocks this node authored. Not in the harness's reference chain, so
    /// only this node can serve them when it fetches by hash over CE 128.
    own_blocks: Mutex<Vec<Block>>,
    /// Tickets this node forwarded as proxy, by id, so it can forward one
    /// again once a block of its own carries it.
    forwarded: Mutex<Vec<([u8; 32], TicketDistribution)>>,
}

impl SimNode {
    /// A node that serves `chain` and gets `fault` wrong.
    pub fn new(chain: Arc<RefChain>, fault: SimFault) -> Self {
        Self::at_index(chain, fault, 0)
    }

    /// A node that is validator `index` of the set.
    pub fn at_index(chain: Arc<RefChain>, fault: SimFault, index: usize) -> Self {
        let genesis_hash = chain.genesis_hash();
        Self {
            chain,
            genesis_hash,
            fault,
            index,
            peers: Mutex::new(Vec::new()),
            announce: broadcast::Sender::new(16),
            own_blocks: Mutex::new(Vec::new()),
            forwarded: Mutex::new(Vec::new()),
        }
    }

    /// Announce a block this node authored, and keep it to serve.
    ///
    /// Stored before announced: the harness fetches by hash the moment it
    /// hears the announcement.
    pub fn publish(self: &Arc<Self>, block: Block) {
        let wire = m2_emu::emu::announcement_wire(&block, &self.chain);
        if self.fault == SimFault::ReForwardsAfterFinality {
            // Announcing this block names it final, so anything it carries is
            // finalized-included from here. Forwarding one again a slot later
            // is what the stopping rule forbids.
            let carried: Vec<[u8; 32]> = block.extrinsic.tickets.iter().map(|t| t.id().0).collect();
            let again: Vec<TicketDistribution> = self
                .forwarded
                .lock()
                .expect("sim forwards")
                .iter()
                .filter(|(id, _)| carried.contains(id))
                .map(|(_, d)| *d)
                .collect();
            if !again.is_empty() {
                let node = Arc::clone(self);
                tokio::spawn(async move {
                    clock::current()
                        .sleep(Duration::from_millis(jam_types::slot_period_sec() * 1000))
                        .await;
                    for distribution in again {
                        node.broadcast_ticket(&distribution).await;
                    }
                });
            }
        }
        self.own_blocks.lock().expect("sim blocks").push(block);
        if self.fault == SimFault::AnnouncesLate {
            let node = Arc::clone(self);
            tokio::spawn(async move {
                let slot_ms = jam_types::slot_period_sec() * 1000;
                clock::current()
                    .sleep(Duration::from_millis(LATE_BY_SLOTS * slot_ms))
                    .await;
                let _ = node.announce.send(wire);
            });
            return;
        }
        let _ = self.announce.send(wire);
    }

    /// Dial the emulated validators, keyed by index. A peer that cannot be
    /// reached is skipped: the duty to the others stands.
    pub async fn connect_to(
        self: &Arc<Self>,
        transport: &Arc<dyn Transport>,
        secret: SigningKey,
        peers: &[(u16, SocketAddr, String)],
    ) {
        for (index, addr, san) in peers {
            let config = EndpointConfig {
                genesis_hash: self.genesis_hash,
                builder: false,
            };
            if let Ok(conn) = transport
                .connect(config, secret.clone(), san.clone(), *addr)
                .await
            {
                self.peers
                    .lock()
                    .expect("sim peers")
                    .push((*index, Arc::clone(&conn)));
                // Serve it too: the peer sends tickets on whichever
                // connection it has, so a node that served only inbound ones
                // silently ignores every ticket proxied over an outbound.
                tokio::spawn(Arc::clone(self).serve_connection(conn));
            }
        }
    }

    /// Run the Safrole lottery for `target_epoch` and distribute it: CE 132
    /// to every validator for a ticket it proxies itself, CE 131 to the
    /// designated proxy alone otherwise (`simple.md:305-349`).
    pub async fn run_lottery(self: &Arc<Self>, target_epoch: u32) {
        if self.fault == SimFault::SendsNoTickets {
            return;
        }
        if self.fault != SimFault::TicketAtEpochStart {
            // Phase 0 is the boundary itself, where the entropy a ticket is
            // sealed against has only just rotated.
            let period = u64::from(jam_types::epoch_period());
            let slot = u64::from(m2_reference::chain::wall_clock_slot());
            if slot % period == 0 {
                let ms = jam_types::slot_period_sec() * 1000;
                clock::current().sleep(Duration::from_millis(ms)).await;
            }
        }
        let Ok(ctx) = self.chain.ticket_ctx() else {
            return;
        };
        // Its own only: proving the other five would cost five times the
        // ring-VRF work for nothing.
        let Ok(mut tickets) = self.chain.generate_tickets_for(&ctx, self.index) else {
            return;
        };
        if self.fault == SimFault::TicketAttemptOverCap {
            // Its last honest attempt swapped for one at the cap, signed over
            // that attempt: the count stays within the cap and the proof
            // verifies, so the attempt row is the only one broken.
            let cap = jam_types::tickets_per_validator(jam_types::max_val_count());
            let Ok(Some(over)) = self.chain.generate_ticket_at(&ctx, self.index, cap) else {
                return;
            };
            tickets.pop();
            tickets.push(over);
        }
        let val_count = usize::from(jam_types::max_val_count());
        for ticket in tickets.iter() {
            let attempt = ticket.attempt;
            let epoch = if self.fault == SimFault::TicketWrongEpoch {
                target_epoch.saturating_add(1)
            } else {
                target_epoch
            };
            let self_proxied = ticket.proxy == self.index;
            let mut proof = ticket.proof;
            let break_proof = match self.fault {
                SimFault::TicketBadProof => !self_proxied,
                SimFault::SelfProxyBadProof => self_proxied,
                _ => false,
            };
            if break_proof {
                proof[PROOF_TAIL_BYTE] ^= 0xff;
            }
            let wire = TicketDistribution {
                epoch_index: epoch,
                ticket: Ticket { attempt, proof },
            };
            if self_proxied {
                self.broadcast_ticket(&wire).await;
            } else {
                let proxy = if self.fault == SimFault::TicketWrongProxy {
                    // The next validator along that is not us, which is a
                    // peer the rule did not name. Landing on ourselves would
                    // send nothing at all.
                    let next = (ticket.proxy + 1) % val_count;
                    if next == self.index {
                        (next + 1) % val_count
                    } else {
                        next
                    }
                } else {
                    ticket.proxy
                };
                self.send_ticket(CE131, proxy as u16, &wire).await;
                if self.fault == SimFault::TicketToTwoProxies {
                    let second = (proxy + 1) % val_count;
                    if second != self.index {
                        self.send_ticket(CE131, second as u16, &wire).await;
                    }
                }
            }
        }
    }

    /// Wait until the lottery has shut for this epoch, or the next one if it
    /// already has.
    async fn sleep_until_tail(&self) {
        let period = jam_types::epoch_period();
        let now = m2_reference::chain::wall_clock_slot();
        let tail = now - now % period + jam_types::epoch_tail_start();
        let tail = if tail <= now { tail + period } else { tail };
        let target = m2_reference::chain::slot_start_ms(tail);
        if let Some(wait) = target.checked_sub(clock::current().wall_ms()) {
            clock::current().sleep(Duration::from_millis(wait)).await;
        }
    }

    /// CE 132: a self-proxied ticket goes to every current validator.
    async fn broadcast_ticket(self: &Arc<Self>, wire: &TicketDistribution) {
        let targets: Vec<u16> = {
            let peers = self.peers.lock().expect("sim peers");
            peers.iter().map(|(index, _)| *index).collect()
        };
        let skip = (self.fault == SimFault::SelfProxyMissesAPeer)
            .then(|| targets.last().copied())
            .flatten();
        for index in targets {
            if Some(index) == skip {
                continue;
            }
            self.send_ticket(CE132, index, wire).await;
        }
    }

    /// One ticket, one stream, as a node distributes them.
    async fn send_ticket(self: &Arc<Self>, kind: u8, peer: u16, wire: &TicketDistribution) {
        let conn = {
            let peers = self.peers.lock().expect("sim peers");
            peers
                .iter()
                .find(|(index, _)| *index == peer)
                .map(|(_, conn)| Arc::clone(conn))
        };
        let Some(conn) = conn else { return };
        let Ok((mut send, _recv)) = conn.open_bi().await else {
            return;
        };
        if send.write_all(&frame(kind, &wire.encode())).await.is_ok() {
            send.finish();
        }
    }

    /// Bind on `transport` at `addr` and serve until the returned task is
    /// dropped or aborted.
    ///
    /// The bound address is returned alongside, since a transport is free to
    /// assign the port.
    /// `Arc<Self>` because the node outlives the call: the serving task holds
    /// it, as does anything that goes on to [`SimNode::publish`].
    pub async fn listen(
        self: Arc<Self>,
        transport: Arc<dyn Transport>,
        secret: SigningKey,
        addr: SocketAddr,
    ) -> Result<(SocketAddr, tokio::task::JoinHandle<()>), SimError> {
        let listener = transport
            .listen(
                EndpointConfig {
                    genesis_hash: self.genesis_hash,
                    builder: false,
                },
                secret,
                addr,
            )
            .await?;
        let bound = listener.local_addr();
        let node = self;
        let task = tokio::spawn(async move {
            while let Some(incoming) = listener.accept().await {
                let Ok(connection) = incoming.established().await else {
                    continue;
                };
                let node = Arc::clone(&node);
                tokio::spawn(node.serve_connection(connection));
            }
        });
        Ok((bound, task))
    }

    /// One task per stream, for as long as the peer keeps the connection.
    async fn serve_connection(self: Arc<Self>, connection: Conn) {
        while let Ok((send, recv)) = connection.accept_bi().await {
            let node = Arc::clone(&self);
            tokio::spawn(node.serve_stream(send, recv));
        }
    }

    /// Dispatch one accepted stream on the kind byte its opening frame
    /// carries (`simple.md:122-124`).
    async fn serve_stream(self: Arc<Self>, mut send: SendHalf, recv: RecvHalf) {
        let mut reader = StreamReader::new(recv);
        let Some((kind, content)) = reader.next().await else {
            return;
        };
        match kind {
            UP => self.serve_up0(&mut send, &mut reader, &content).await,
            CE128 => self.serve_ce128(&mut send, &content).await,
            CE129 => self.serve_ce129(&mut send, &content).await,
            CE131 | CE132 => self.receive_ticket(&mut send, kind, &content).await,
            // A real node resets an unserved kind; this one is not graded on
            // that, so it drops the stream.
            _ => {}
        }
    }

    /// UP 0 is persistent: answer the handshake, then re-announce whatever
    /// the peer announces, for as long as it keeps the stream open.
    async fn serve_up0(&self, send: &mut SendHalf, reader: &mut StreamReader, first: &[u8]) {
        if self.fault == SimFault::SilentOnUp0 {
            // Hold the stream open: the peer grades the silence, not a
            // closed connection.
            while reader.next().await.is_some() {}
            return;
        }
        if Handshake::decode(&mut &first[..]).is_ok()
            && send.write_all(&self.handshake()).await.is_err()
        {
            return;
        }
        // Both halves at once: serving them in turn would stall whichever
        // came second.
        let mut announcements = self.announce.subscribe();
        loop {
            tokio::select! {
                incoming = reader.next() => {
                    let Some((_, content)) = incoming else { return };
                    let Ok(announcement) = Announcement::decode(&mut &content[..]) else {
                        continue;
                    };
                    if self.fault == SimFault::NeverReannounces {
                        continue;
                    }
                    if send
                        .write_all(&frame_message(&announcement.encode()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                own = announcements.recv() => match own {
                    Ok(wire) => {
                        if send.write_all(&wire).await.is_err() {
                            return;
                        }
                    }
                    // Falling behind skips what was missed; the peer can
                    // still fetch a block it hears about later.
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return,
                },
            }
        }
    }

    /// This node's handshake: its finalized head and no leaves.
    fn handshake(&self) -> Vec<u8> {
        let header_hash = if self.fault == SimFault::FinalIsNotGenesis {
            // A hash that is not genesis and not any block in the chain.
            HeaderHash::from([0x5a; 32])
        } else {
            HeaderHash::from(self.genesis_hash)
        };
        frame_message(
            &Handshake {
                final_block: Final {
                    header_hash,
                    slot: 0,
                },
                leaves: vec![],
            }
            .encode(),
        )
    }

    /// Take delivery of a ticket, refusing what it cannot act on by resetting
    /// the stream (`simple.md:335-337`) and forwarding what it proxies.
    async fn receive_ticket(self: &Arc<Self>, send: &mut SendHalf, kind: u8, content: &[u8]) {
        let Ok(distribution) = TicketDistribution::decode(&mut &content[..]) else {
            send.reset(TICKET_REFUSED_CODE);
            return;
        };
        // Exactly the next epoch: a later one has entropy nobody holds yet, an
        // earlier one is stale. polkajam refuses both ("bad ticket epoch
        // value"), and pooling a stale ticket puts it in a block uninvited.
        let period = jam_types::epoch_period();
        let next_epoch = m2_reference::chain::wall_clock_slot() / period + 1;
        if distribution.epoch_index != next_epoch && self.fault != SimFault::AcceptsUnknownEpoch {
            send.reset(TICKET_REFUSED_CODE);
            return;
        }
        // At or above the per-validator cap there is no lawful attempt index,
        // so the proof cannot belong to this epoch's lottery however well it
        // verifies. polkajam refuses these too ("bad ticket attempt value").
        if distribution.ticket.attempt
            >= jam_types::tickets_per_validator(jam_types::max_val_count())
        {
            send.reset(TICKET_REFUSED_CODE);
            return;
        }
        let verifies = self
            .chain
            .ticket_ctx()
            .map(|ctx| {
                verify_ticket(
                    &ctx,
                    distribution.ticket.attempt,
                    &distribution.ticket.proof,
                )
            })
            .unwrap_or(false);
        if !verifies && self.fault != SimFault::AcceptsBadProof {
            send.reset(TICKET_REFUSED_CODE);
            return;
        }
        // A CE 131 arrival is a ticket sent to this node *as proxy*, so one
        // the proxy rule names another validator for was misrouted: refuse it
        // rather than pass it on or carry it. A CE 132 arrival is a broadcast
        // and belongs to no proxy, so it is kept whoever it names.
        let id = ticket_id(&distribution.ticket.proof);
        let proxies_here = proxy_index(&id, usize::from(jam_types::max_val_count())) == self.index;
        if kind == CE131 && !proxies_here {
            send.reset(TICKET_REFUSED_CODE);
            return;
        }
        send.finish();
        // Into its own pool, so a block it authors this epoch carries it.
        // Whichever stream it arrived on -- hence before the CE 131-only
        // forwarding rule below.
        if self.fault != SimFault::OmitsDeliveredTickets {
            self.chain.submit_tickets(&[TicketEnvelope {
                attempt: distribution.ticket.attempt,
                signature: ring_vrf::Signature(distribution.ticket.proof),
            }]);
        }
        // Only a CE 131 arrival is this node's to pass on: a CE 132 one is
        // already a broadcast.
        if kind != CE131 || self.fault == SimFault::NeverForwards {
            return;
        }
        self.forwarded
            .lock()
            .expect("sim forwards")
            .push((id, distribution));
        if self.fault == SimFault::ForwardsInTail {
            self.sleep_until_tail().await;
        }
        self.broadcast_ticket(&distribution).await;
        if self.fault == SimFault::RepeatsForwards {
            let node = Arc::clone(self);
            tokio::spawn(async move {
                clock::current()
                    .sleep(Duration::from_millis(jam_types::slot_period_sec() * 1000))
                    .await;
                node.broadcast_ticket(&distribution).await;
            });
        }
    }

    /// Serve a block request from the reference chain.
    async fn serve_ce128(&self, send: &mut SendHalf, content: &[u8]) {
        if self.fault == SimFault::Ce128Silent {
            send.finish();
            return;
        }
        let Ok(request) = BlockRequest::decode(&mut &content[..]) else {
            return;
        };
        // The fetch that follows an announcement -- by hash, descending, one
        // block -- which only this node can answer.
        if request.direction == Direction::DescendingInclusive && request.max_blocks == 1 {
            let own = self
                .own_blocks
                .lock()
                .expect("sim blocks")
                .iter()
                .find(|b| b.header.hash() == request.header_hash)
                .cloned();
            if let Some(block) = own {
                let response = BlockResponse {
                    blocks: vec![block],
                };
                let _ = send.write_all(&frame_message(&response.encode())).await;
                send.finish();
                return;
            }
        }
        let chain = self.chain.chain_blocks();
        let Ok(mut response) = m2_emu::emu::serve_ce128(&request, &chain) else {
            return;
        };
        if self.fault == SimFault::Ce128Descending {
            // The walk the peer asked for, in the opposite order. Every block
            // it asked for is there, so only the ordering rule can catch it.
            response.blocks.reverse();
        }
        let _ = send.write_all(&frame_message(&response.encode())).await;
        send.finish();
    }

    /// Serve a state request: the same empty response the emulator serves.
    ///
    /// Two messages, not one -- boundary nodes then key/value pairs, each read
    /// as items-until-end-of-message.
    async fn serve_ce129(&self, send: &mut SendHalf, content: &[u8]) {
        let Ok(request) = StateRequest::decode(&mut &content[..]) else {
            return;
        };
        let (boundary, entries) = m2_emu::emu::serve_ce129(&request).messages();
        for message in [boundary, entries] {
            if send.write_all(&frame_message(&message)).await.is_err() {
                return;
            }
        }
        send.finish();
    }
}

/// Incremental frame reader. One read routinely delivers several frames, so a
/// reader rebuilt per message drops everything behind the first.
struct StreamReader {
    recv: RecvHalf,
    reader: FrameReader,
    buf: [u8; 4096],
}

impl StreamReader {
    fn new(recv: RecvHalf) -> Self {
        Self {
            recv,
            reader: FrameReader::new(),
            buf: [0u8; 4096],
        }
    }

    /// The next complete message, or `None` once the stream ends or breaks.
    async fn next(&mut self) -> Option<(u8, Vec<u8>)> {
        loop {
            match self.reader.next_frame() {
                Ok(Some(item)) => return Some(item),
                Ok(None) => {}
                Err(_) => return None,
            }
            match self.recv.read(&mut self.buf).await {
                Ok(Some(n)) => {
                    let (buf, reader) = (&self.buf, &mut self.reader);
                    reader.push(&buf[..n]);
                }
                _ => return None,
            }
        }
    }
}
