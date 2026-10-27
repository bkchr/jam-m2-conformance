//! The §4 run lifecycle, orchestrated by [`crate::cli::run`].

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

use jamnp_s::cert::san_for_key;
use m2_emu::emu::Emulator;
use m2_reference::chain::RefChain;
use m2_reference::tickets::{ScheduledTicket, TicketCtx};
use m2_scenario::dsl::ObsKind;
use m2_scenario::scenarios::l0;

use crate::cli::{Cli, Preset};
use crate::connectivity::{self, ConnectivityPlan, ProbeOutcome};
use crate::keygen;
use crate::launch::{self, LaunchConfig, NutProcess};
use crate::real::{
    build_real_run_ctx, generate_tickets, plans_by_peer, schedule_tickets, EpochContexts,
    RealRunData,
};
use crate::report::{self, Finding};
use crate::scenario::{evaluate, fabricated_obs_log, fabricated_run_ctx, Evaluation, ObsSource};
use crate::spec;

/// How many emulated slots the dry-run baseline pretends were authored.
const DRY_RUN_BLOCK_COUNT: usize = 3;

/// Errors from a run, mapped to exit codes (startup = 1, internal = 2).
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// The NUT failed to start or never came up (§4 step 2).
    #[error("NUT startup failure: {0}")]
    Startup(String),
    /// Any other internal failure (keygen/spec/emulator/report).
    #[error("internal error: {0}")]
    Internal(String),
}

/// Run a full §4 lifecycle, returning the scenario evaluation or an error.
pub(crate) async fn run_once(cli: Cli) -> Result<Evaluation, RunError> {
    let session_dir = &cli.session_dir;
    report::ensure_layout(session_dir).map_err(internal)?;

    // Before anything reads a protocol parameter. `current_epoch_start_slot`
    // divides by `epoch_period`, and under the process-wide default that is
    // 600 rather than the tiny set's 12 -- which anchored genesis 336 slots in
    // the past instead of at most 11. The node then had to import and finalize
    // a month of chain before it would accept a ticket, and the whole ticket
    // plan was delivered into that window and rejected with "finality
    // lagging". Everything downstream applies these too; this call is the one
    // that happens first.
    jam_types::ProtocolParameters::tiny()
        .apply()
        .map_err(|e| internal(format!("failed to apply tiny protocol parameters: {e}")))?;

    // §4.1 keys + spec.
    let nut_index = cli.validator_index;
    let keys = keygen::generate(cli.seed, nut_index, VALIDATOR_COUNT);
    keygen::write_seed_files(session_dir, &keys).map_err(internal)?;

    let ips = loopback_ips();
    let ports: Vec<u16> = (0..VALIDATOR_COUNT)
        .map(|i| cli.base_port + i as u16)
        .collect();
    // Genesis is anchored to the start of the current epoch (A9). polkajam
    // gates its ticket lottery on the finalized block being in the current
    // epoch, which a genesis at slot 0 can never satisfy, so the node would
    // never submit a ticket and never author. `ChainSpec` holds a boxed
    // closure and is not `Clone`, so the reference engine gets its own build
    // from the same inputs -- `tiny_spec` is deterministic, so the two agree
    // byte for byte.
    let anchor_slot = m2_reference::chain::current_epoch_start_slot();
    let chain_spec = spec::tiny_spec(&ips, &ports, anchor_slot).map_err(internal)?;
    let genesis_hash = chain_spec.genesis_header.hash().0;
    let spec_id = format!("m2-{}", cli.seed);
    let m2_spec = spec::m2_spec(&spec_id, &chain_spec).map_err(internal)?;
    spec::write_m2_spec(session_dir, &spec_id, &m2_spec).map_err(internal)?;
    let spec_path = spec::write_polkajam_spec(session_dir, &chain_spec).map_err(internal)?;

    let nut_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, cli.base_port + nut_index as u16));
    let nut_san = san_for_key(&keys.keysets[nut_index].ed25519.0.verification_key());

    // §4.2 launch + startup probe, §4.3 connectivity (both skipped in dry-run).
    let emu_indices = emulated_indices(nut_index);
    let emu_keys: Vec<[u8; 32]> = emu_indices
        .iter()
        .map(|&i| keys.keysets[i].ed25519.0.verification_key().to_bytes())
        .collect();
    let nut_key = keys.keysets[nut_index]
        .ed25519
        .0
        .verification_key()
        .to_bytes();
    let plan = connectivity::plan_connectivity(&emu_keys, &nut_key);

    // The reference chain is built here so the connectivity phase can serve
    // from it, but ticket generation deliberately is *not* started alongside
    // it. A ring-VRF ticket is sealed against the tickets entropy read from
    // the chain head, and at this point the chain is still at its anchored
    // genesis: tickets proved now carry genesis entropy, while the node
    // validates them against the entropy of the epoch the run is actually in.
    // They never match, and the node rejects every one with "invalid ticket
    // signature" -- which is what it did, silently, for as long as the ticket
    // plan existed. Generation happens after seeding instead; with the
    // dependencies optimized it costs about three seconds, so there is nothing
    // left to overlap with the node's startup.
    let reference = if cli.dry_run {
        None
    } else {
        let ref_spec = spec::tiny_spec(&ips, &ports, anchor_slot).map_err(internal)?;
        Some(Arc::new(
            RefChain::with_spec(nut_index, ref_spec).map_err(internal)?,
        ))
    };

    let mut nut: Option<NutProcess> = None;
    let mut conn_findings: Vec<Finding> = Vec::new();
    // L0 facts the connectivity phase establishes. A dry run leaves them at
    // the conforming values, since it fabricates a conforming node.
    let mut handshake_completed = true;
    let mut wrong_alpn_rejected = true;
    let mut builder: Option<l0::BuilderProbeFacts> = Some(l0::BuilderProbeFacts {
        attempted: connectivity::BUILDER_CONNECTIONS,
        accepted: connectivity::BUILDER_CONNECTIONS,
        ce133_accepted: true,
        ce133_detail: None,
    });
    if !cli.dry_run {
        let cfg = launch_config(&keys, &cli, spec_path);
        // The peer-id is the 53-char text form ("e" + base32 of the Ed25519
        // key) — the same string as the certificate SAN.
        let peer_id = nut_san.clone();
        let image = std::env::var("JAM_M2_IMAGE").unwrap_or_else(|_| "polkajam".to_string());
        let cmd = match cli.preset {
            Preset::Polkajam => launch::preset_polkajam(&cfg).replace("{peer-id}", &peer_id),
            Preset::Docker => launch::preset_docker(&cfg).replace("{image}", &image),
            Preset::Mock => "sleep 30".to_string(),
        };
        nut = Some(launch::spawn(&cmd, session_dir).await.map_err(startup)?);
        if !wait_for_nut(nut_addr, &nut_san, genesis_hash, cli.startup_timeout).await {
            if let Some(nut) = nut.take() {
                let _ = launch::kill(nut).await;
            }
            return Err(RunError::Startup(format!(
                "NUT did not come up on {nut_addr} within {}s",
                cli.startup_timeout
            )));
        }

        let emu_addrs: Vec<SocketAddr> = emu_indices
            .iter()
            .map(|&i| SocketAddr::from((Ipv4Addr::LOCALHOST, cli.base_port + i as u16)))
            .collect();
        let outcomes =
            connectivity::run_connectivity(&plan, nut_addr, &emu_addrs, genesis_hash, &nut_san)
                .await;
        conn_findings = connectivity_findings(&plan, &outcomes);
        handshake_completed = outcomes.iter().any(|o| o.connected);
        // Both before the emulator starts: the builder probe opens twenty-one
        // connections and the mismatch probe deliberately fails one, and
        // neither should be in flight while the preferred-initiator split is
        // being observed.
        wrong_alpn_rejected = connectivity::probe_wrong_alpn(
            nut_addr,
            &nut_san,
            genesis_hash,
            connectivity::INITIATOR_GRACE,
        )
        .await;
        let probe = connectivity::probe_builder_slots(
            nut_addr,
            &nut_san,
            genesis_hash,
            connectivity::INITIATOR_GRACE,
        )
        .await;
        builder = Some(l0::BuilderProbeFacts {
            attempted: probe.attempted,
            accepted: probe.accepted,
            ce133_accepted: probe.ce133_accepted,
            ce133_detail: probe.ce133_detail,
        });
    }

    // §4.4 scenario: reference chain + emulator, or the fabricated dry-run log.
    let (source, reference_block_count, dial_tasks, real_run) = if cli.dry_run {
        (
            ObsSource::Fabricated {
                log: fabricated_obs_log(DRY_RUN_BLOCK_COUNT),
                trace: jamnp_s::trace::Trace::default(),
            },
            DRY_RUN_BLOCK_COUNT,
            Vec::new(),
            None,
        )
    } else {
        let ref_chain = reference.expect("a live run builds the reference chain");
        // Seeded before the tickets are proved, not after: every slot between
        // genesis and now has to be filled for the chain to be current, and
        // the entropy the tickets are sealed against is read from its head.
        seed_past_slots(&ref_chain).map_err(internal)?;
        let epoch_contexts: EpochContexts = Arc::new(Mutex::new(Vec::new()));
        let (ticket_ctx, ticket_plan, target_epoch) =
            plan_tickets_for_this_run(&ref_chain, nut_index)
                .await
                .map_err(internal)?;
        // Counted from the chain rather than from the seeding, which may have
        // run twice: the L0 lane compares this against the reference chain the
        // contexts are built from, and the two have to be the same chain.
        let count = ref_chain.chain_blocks().len().saturating_sub(1);
        if ticket_plan.is_empty() {
            conn_findings.push(empty_ticket_plan_finding(&ref_chain, target_epoch));
        }
        let emu = Emulator::l0(emu_indices.clone(), genesis_hash, cli.base_port)
            .await
            .map_err(internal)?;
        // Each emulated validator's tickets go out on the first connection to
        // it, whichever side opened it.
        emu.set_ticket_plans(plans_by_peer(&ticket_plan));
        let obs = emu.obs();
        let trace = emu.trace();
        let nut_blocks = emu.nut_blocks();
        let deliveries = emu.deliveries();
        let shared = emu.shared(Arc::clone(&ref_chain));
        let _accept = emu.accept_loop(ref_chain.clone());
        // Drive the preferred-initiator connectivity: emulated validators that
        // are the preferred initiator dial the NUT now; the rest wait the 5 s
        // grace then dial anyway (a soft finding).
        //
        // Keep authoring for the whole observation window, announcing each
        // block as its slot arrives (A10). Aborted with the dial tasks when the
        // window closes.
        let mut dial_tasks = vec![tokio::spawn(drive_slots(
            Arc::clone(&ref_chain),
            emu.announce_tx(),
            Arc::clone(&epoch_contexts),
        ))];
        for &i in &plan.initiate_now {
            let shared = shared.clone();
            let nut_san = nut_san.clone();
            let index = emu_indices[i];
            dial_tasks.push(tokio::spawn(async move {
                let _ = m2_emu::emu::dial_nut(index, genesis_hash, nut_addr, nut_san, shared).await;
            }));
        }
        for &i in &plan.wait_then_connect {
            let shared = shared.clone();
            let nut_san = nut_san.clone();
            let index = emu_indices[i];
            dial_tasks.push(tokio::spawn(async move {
                tokio::time::sleep(connectivity::INITIATOR_GRACE).await;
                // The NUT is the preferred initiator for this peer. The grace
                // is there so the pair still connects if it never dials, not
                // so we open a second connection alongside its first.
                let peer = index as u16;
                if !connectivity::should_fallback_dial(&lock(&shared.obs), peer) {
                    return;
                }
                m2_emu::emu::record(&shared.obs, peer, ObsKind::Other(l0::FALLBACK_DIAL));
                let _ = m2_emu::emu::dial_nut(index, genesis_hash, nut_addr, nut_san, shared).await;
            }));
        }
        let ce128_probes = emu.ce128_probes();
        let ce129_probes = emu.ce129_probes();
        let real_run = RealRunData {
            ref_chain,
            nut_blocks,
            deliveries,
            ticket_ctx,
            plan: ticket_plan,
            target_epoch,
            nut_index,
            emu_indices: emu_indices.clone(),
            epoch_contexts,
        };
        (
            ObsSource::Emulator {
                obs,
                trace,
                ce128_probes,
                ce129_probes,
                _emu: emu,
            },
            count,
            dial_tasks,
            Some(real_run),
        )
    };

    if !dial_tasks.is_empty() {
        tokio::time::sleep(Duration::from_secs(cli.observe_secs)).await;
    }
    // Abort rather than drop: dropping a `JoinHandle` detaches the task, so the
    // slot driver would keep authoring into the reference chain while the
    // checks read it, and two runs of the same log could disagree.
    for task in &dial_tasks {
        task.abort();
    }
    drop(dial_tasks);

    let run_ctx = match &source {
        ObsSource::Emulator {
            trace,
            ce128_probes,
            ce129_probes,
            ..
        } => {
            let data = real_run.as_ref().ok_or_else(|| {
                RunError::Internal("emulator run missing reference run data".into())
            })?;
            // Everything after genesis, in slot order: what an ascending
            // CE 128 walk from genesis is supposed to return.
            let reference_chain: Vec<[u8; 32]> = data
                .ref_chain
                .chain_blocks()
                .iter()
                .skip(1)
                .map(|block| block.header.hash().0)
                .collect();
            build_real_run_ctx(
                data,
                &lock(trace),
                l0::L0Ctx {
                    reference_block_count,
                    reference_chain,
                    ce128_probes: lock(ce128_probes).clone(),
                    ce129_probes: lock(ce129_probes).clone(),
                    first_emu_peer: emu_indices[0] as u16,
                    handshake_completed,
                    wrong_alpn_rejected,
                    builder,
                    nut_preferred_peers: peers_of(&plan.wait_then_connect, &emu_indices),
                    emu_preferred_peers: peers_of(&plan.initiate_now, &emu_indices),
                },
            )
        }
        ObsSource::Fabricated { .. } => {
            fabricated_run_ctx(reference_block_count).map_err(internal)?
        }
    };

    let evaluation = match &source {
        ObsSource::Emulator { obs, .. } => evaluate(&lock(obs), &run_ctx),
        ObsSource::Fabricated { log, .. } => evaluate(log, &run_ctx),
    };

    // §4.6 teardown: kill the NUT (stdout/stderr already collected by `spawn`).
    if let Some(nut) = nut.take() {
        launch::kill(nut).await.map_err(internal)?;
    }

    // §4.6 report + trace.
    let Evaluation {
        outcomes,
        findings: scenario_findings,
        all_hard_passed,
    } = evaluation;
    let mut findings = conn_findings;
    findings.extend(scenario_findings);
    report::write_report(session_dir, &outcomes, &findings).map_err(internal)?;
    let trace_result = match &source {
        ObsSource::Emulator { trace, .. } => report::write_trace(session_dir, &lock(trace)),
        ObsSource::Fabricated { trace, .. } => report::write_trace(session_dir, trace),
    };
    trace_result.map_err(internal)?;

    Ok(Evaluation {
        outcomes,
        findings,
        all_hard_passed,
    })
}

/// The tiny validator set: six validators, one of which is the NUT.
const VALIDATOR_COUNT: usize = 6;

/// Validator indices the harness emulates: every index except the NUT's.
///
/// The result is positional — position `i` of the returned list is the
/// validator that position `i` of the [`ConnectivityPlan`], `emu_keys` and
/// `emu_addrs` refers to. It is deliberately not a range: a NUT anywhere but
/// the ends of the keyset splits the emulated set in two, and treating it as
/// the range `0..nut_index` both dropped the validators above the NUT and left
/// the NUT's own keyset loaded in the reference chain (defect 2).
fn emulated_indices(nut_index: usize) -> Vec<usize> {
    (0..VALIDATOR_COUNT).filter(|&i| i != nut_index).collect()
}

/// Seed the reference chain over the slots between its head and now.
///
/// Every slot authored here is in the past, which is the point. The old
/// pre-window burst started at the *current* slot and ran forward, so all but
/// the first block carried a slot the wall clock had not reached yet, and a
/// node is entitled to refuse a header from the future. Genesis is anchored to
/// the start of the current epoch (A9), so there are real past slots to fill
/// instead.
///
/// Seeding resumes from the head rather than from genesis, so calling it
/// again after the clock has moved tops the chain up instead of failing:
/// authoring a slot the chain already holds is an error, which made a second
/// call abort the whole run.
///
/// Returns how many blocks were produced; the harness skips the NUT's own
/// slots by itself.
fn seed_past_slots(chain: &RefChain) -> Result<usize, m2_reference::chain::ChainError> {
    let now = chain.next_slot();
    let mut count = 0;
    for slot in (chain.best_slot() + 1)..=now {
        if chain.author_block(slot)?.is_some() {
            count += 1;
        }
    }
    Ok(count)
}

/// Prove the emulated validators' tickets and schedule them, regenerating once
/// if proving was overtaken by an epoch boundary.
///
/// The caller seeds the chain first. That ordering is not an optimization: a
/// ticket is sealed against the tickets entropy of the chain head, so proving
/// against an unseeded head produces tickets the node rejects outright.
///
/// Even seeded, proving can still straddle a boundary — it reads the entropy,
/// proves, and by the time the plan is laid the submission window for the
/// epoch it generated for may have closed, which leaves *both* ticket lanes
/// measuring nothing. The second attempt re-seeds, so it reads the entropy of
/// the epoch the run is now in and has that epoch's whole window ahead of it.
async fn plan_tickets_for_this_run(
    ref_chain: &RefChain,
    nut_index: usize,
) -> Result<(TicketCtx, Vec<ScheduledTicket>, u32), m2_reference::chain::ChainError> {
    let (ticket_ctx, tickets, target_epoch) = generate_tickets(ref_chain)?;
    let plan = schedule_tickets(ref_chain, &tickets, nut_index, target_epoch);
    if !plan.is_empty() {
        return Ok((ticket_ctx, plan, target_epoch));
    }
    // The window for this epoch's lottery has closed, and nothing within this
    // epoch can reopen it: tickets are submitted before the tail, and the tail
    // is where the run started. Waiting it out costs a slot or three and buys
    // the whole of the next epoch's window; not waiting costs both ticket
    // lanes, which then measure nothing at all.
    wait_for_next_epoch(ref_chain).await;
    seed_past_slots(ref_chain)?;
    let (ticket_ctx, tickets, target_epoch) = generate_tickets(ref_chain)?;
    let plan = schedule_tickets(ref_chain, &tickets, nut_index, target_epoch);
    Ok((ticket_ctx, plan, target_epoch))
}

/// Sleep until the start of the next epoch.
async fn wait_for_next_epoch(ref_chain: &RefChain) {
    let period = jam_types::epoch_period();
    let now = ref_chain.next_slot();
    let slots = period - now % period;
    tokio::time::sleep(Duration::from_millis(
        u64::from(slots) * m2_scenario::ctx::SLOT_PERIOD_MS,
    ))
    .await;
}

/// Author each slot as the wall clock reaches it and announce every block, for
/// as long as the task lives.
///
/// This is what keeps the chain moving: before, it was authored once up front
/// and then stood still for the rest of the observation window.
async fn drive_slots(
    chain: Arc<RefChain>,
    announce: broadcast::Sender<Vec<u8>>,
    contexts: EpochContexts,
) {
    let mut next = chain.next_slot() + 1;
    let mut captured_epoch = None;
    loop {
        // Wait for the slot to actually begin. Sleeping to the boundary rather
        // than for one slot period keeps the pacing from drifting over a run.
        let start = m2_reference::chain::slot_start(next);
        if let Ok(delay) = start.duration_since(std::time::SystemTime::now()) {
            tokio::time::sleep(delay).await;
        }
        // The head no longer moves only when this task authors: a NUT block
        // adopted into the chain can already occupy this slot or a later one,
        // and authoring at or behind the head is an error that would end the
        // driver for the rest of the run.
        if next <= chain.best_slot() {
            next += 1;
            continue;
        }
        match chain.author_block(next) {
            Ok(Some(block)) => {
                // Fails only when nothing is subscribed, which is not an error:
                // the announcement simply has nowhere to go yet.
                let _ = announce.send(m2_emu::emu::announcement_wire(&block, &chain));
            }
            // The NUT's own slot, or nothing to author.
            Ok(None) => {}
            Err(_) => break,
        }
        // A ticket proof is bound to the tickets-entropy of the epoch it
        // targets, so the only moment the harness can read the context for
        // epoch `e + 1` is while the chain is *in* epoch `e`. Capturing it on
        // each boundary is the difference between judging the node's tickets
        // and reporting them unjudged: a run spans several epochs, and the
        // node generates afresh in each one.
        //
        // Read after authoring, not before: the entropy rotates with the first
        // block of the new epoch, so a read taken before it still holds the
        // previous epoch's and the context would be filed one epoch late.
        let epoch = next / jam_types::epoch_period();
        if captured_epoch != Some(epoch) {
            if let Ok(ctx) = chain.ticket_ctx() {
                lock(&contexts).push((epoch + 1, ctx));
            }
            captured_epoch = Some(epoch);
        }
        next += 1;
    }
}

/// A soft finding for a run whose ticket plan came out empty: the epoch's
/// submission window closed before the harness was ready to use it.
///
/// Reported rather than swallowed, because the L1 and L2 ticket checks are
/// then measuring nothing — the honest reading is "not exercised", not "no
/// defect found".
fn empty_ticket_plan_finding(ref_chain: &RefChain, target_epoch: u32) -> Finding {
    let now = ref_chain.next_slot();
    Finding {
        severity: "soft".into(),
        spec_citation: "simple.md :305-349".into(),
        slot: Some(now),
        evidence: "ticket plan".into(),
        message: format!(
            "no tickets scheduled: at slot {now} (epoch offset {}) the submission window for \
             epoch {target_epoch} has closed, so the ticket lanes are not exercised",
            now % jam_types::epoch_period()
        ),
    }
}

/// Probe the NUT port until a handshake succeeds or `timeout_secs` elapses.
async fn wait_for_nut(
    addr: SocketAddr,
    san: &str,
    genesis_hash: [u8; 32],
    timeout_secs: u64,
) -> bool {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let attempt = connectivity::probe_nut(
            addr,
            san,
            genesis_hash,
            remaining.min(Duration::from_secs(1)),
        )
        .await;
        if attempt.connected {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    false
}

/// Map `run_connectivity`'s outcomes back onto emulator indices (outcomes are
/// ordered `initiate_now` then `wait_then_connect`) and report soft findings
/// for probes that never established a connection.
fn connectivity_findings(plan: &ConnectivityPlan, outcomes: &[ProbeOutcome]) -> Vec<Finding> {
    let n_now = plan.initiate_now.len();
    let mut findings = Vec::new();
    for (k, &i) in plan.initiate_now.iter().enumerate() {
        push_connectivity_finding(&mut findings, i, &outcomes[k]);
    }
    for (k, &i) in plan.wait_then_connect.iter().enumerate() {
        push_connectivity_finding(&mut findings, i, &outcomes[n_now + k]);
    }
    findings
}

fn push_connectivity_finding(findings: &mut Vec<Finding>, emu_index: usize, o: &ProbeOutcome) {
    if o.connected {
        return;
    }
    findings.push(Finding {
        severity: "soft".into(),
        spec_citation: "simple.md :5-99".into(),
        slot: None,
        evidence: "connectivity probe".into(),
        message: format!("emulated validator {emu_index} could not handshake with the NUT"),
    });
}

/// §7 `LaunchConfig` for a run: NUT on `base_port + validator_index`, IPv4-mapped loopback
/// public address, session dir as data path.
fn launch_config(
    keys: &keygen::GeneratedKeys,
    cli: &Cli,
    spec_path: std::path::PathBuf,
) -> LaunchConfig {
    LaunchConfig {
        spec_path,
        ed25519_secret_hex: keys.nut_ed25519_secret_hex.clone(),
        bandersnatch_secret_hex: keys.nut_bandersnatch_secret_hex.clone(),
        listen: format!("[::]:{}", cli.base_port + cli.validator_index as u16),
        public_addr: format!(
            "::ffff:127.0.0.1:{}",
            cli.base_port + cli.validator_index as u16
        ),
        data_path: cli.session_dir.clone(),
        log_level: "info".to_string(),
    }
}

/// The six validators' IPv4-mapped loopback addresses (`::ffff:127.0.0.1`).
fn loopback_ips() -> [[u8; 16]; 6] {
    let mut ips = [[0u8; 16]; 6];
    for ip in ips.iter_mut() {
        ip[10] = 0xff;
        ip[11] = 0xff;
        ip[12] = 127;
        ip[15] = 1;
    }
    ips
}

/// Map plan positions onto validator indices.
///
/// `ConnectivityPlan` holds positions into `emu_indices`, not validator
/// indices; the observation log is keyed by validator index.
fn peers_of(positions: &[usize], emu_indices: &[usize]) -> Vec<u16> {
    let mut peers: Vec<u16> = positions.iter().map(|&i| emu_indices[i] as u16).collect();
    peers.sort_unstable();
    peers
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn internal(e: impl std::fmt::Display) -> RunError {
    RunError::Internal(e.to_string())
}

fn startup(e: impl std::fmt::Display) -> RunError {
    RunError::Startup(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `current_epoch_start_slot` divides the wall-clock slot by
    /// `epoch_period`, which is process-wide state. Read before the tiny
    /// parameters are applied it uses 600 instead of 12, and genesis lands up
    /// to 599 slots back rather than 11 -- a chain the node must import and
    /// finalize before it will accept a single ticket.
    #[test]
    fn the_genesis_anchor_uses_the_tiny_epoch_period() {
        jam_types::ProtocolParameters::tiny()
            .apply()
            .expect("tiny parameters apply");
        let period = jam_types::epoch_period();
        let anchor = m2_reference::chain::current_epoch_start_slot();
        let now = m2_reference::chain::wall_clock_slot();
        assert_eq!(anchor % period, 0, "the anchor is an epoch boundary");
        assert!(
            now - anchor < period,
            "genesis is anchored inside the current epoch: {now} - {anchor} >= {period}"
        );
    }

    /// Seeding has to be callable again once the clock has moved: ticket
    /// generation that overran its epoch tops the chain up before proving
    /// afresh. Seeding from genesis each time re-authors a slot the chain
    /// already holds, which is an error — and that error aborted the whole
    /// run before any report was written.
    ///
    /// Anchored to the current epoch, exactly as a live run anchors it: on the
    /// slot-0 dev spec the gap between genesis and now is nine million slots,
    /// and seeding it would author every one of them.
    #[test]
    fn seed_past_slots_can_be_called_again() -> Result<(), m2_reference::chain::ChainError> {
        // Before the anchor is read, exactly as `run` does it. The parameters
        // are process-wide, so a test that reads the anchor first gets
        // whichever set some other test happened to install: with the default
        // 600-slot epoch genesis lands up to 599 slots back, `tiny_spec` then
        // installs the tiny set anyway, and seeding authors every one of those
        // slots until the test is killed. That is a flake in the suite, not in
        // the harness -- `run` applies these first -- but it has aborted a
        // whole test run twice.
        jam_types::ProtocolParameters::tiny()
            .apply()
            .expect("tiny parameters apply");
        let ports: Vec<u16> = (0..VALIDATOR_COUNT).map(|i| 40000 + i as u16).collect();
        let anchor = m2_reference::chain::current_epoch_start_slot();
        let spec = spec::tiny_spec(&loopback_ips(), &ports, anchor)
            .map_err(|e| m2_reference::chain::ChainError::Chain(e.to_string()))?;
        let chain = RefChain::with_spec(5, spec)?;

        seed_past_slots(&chain)?;
        let head = chain.best_slot();

        // The second call is the regression: seeding from genesis would try to
        // re-author a slot the chain already holds, which `author_block`
        // rejects. It may legitimately fill a slot or two -- seeding takes
        // seconds and a slot is six of them -- but never one at or behind the
        // head, and it must not fail.
        let second = seed_past_slots(&chain).expect("seeding resumes instead of re-authoring");
        assert!(
            chain.best_slot() >= head,
            "the head only ever moves forward"
        );
        assert_eq!(
            chain.best_slot() - head,
            second as u32,
            "the second call authored exactly the slots the clock had moved on by"
        );
        Ok(())
    }

    /// Defect 2: at every NUT position the harness emulates the other five
    /// validators and never the NUT itself. The old contiguous range gave
    /// `0..nut_index`, which both lost the validators above the NUT and
    /// included the NUT at index 0.
    #[test]
    fn emulated_indices_cover_every_validator_but_the_nut() {
        for nut_index in 0..VALIDATOR_COUNT {
            let emu = emulated_indices(nut_index);
            assert_eq!(
                emu.len(),
                VALIDATOR_COUNT - 1,
                "NUT index {nut_index}: every other validator must be emulated"
            );
            assert!(
                !emu.contains(&nut_index),
                "NUT index {nut_index}: the harness must not emulate the NUT"
            );
            let expected: Vec<usize> = (0..VALIDATOR_COUNT).filter(|&i| i != nut_index).collect();
            assert_eq!(emu, expected, "NUT index {nut_index}: indices stay ordered");
        }
    }
}
