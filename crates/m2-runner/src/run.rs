//! The §4 run lifecycle, orchestrated by [`crate::cli::run`].

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

use jamnp_s::cert::san_for_key;
use m2_emu::emu::Emulator;
use m2_reference::chain::RefChain;
use m2_reference::tickets::{
    first_delivery_slot, window_can_exercise_forwarding, ScheduledTicket, TicketCtx, TicketDelivery,
};
use m2_scenario::dsl::ObsKind;
use m2_scenario::scenarios::n0;

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

/// How often the runner re-reads the node's advertised finalized slot while
/// waiting for it to be able to accept tickets.
const NODE_READINESS_POLL_MS: u64 = 250;

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
    let m2_spec_path = spec::write_m2_spec(session_dir, &spec_id, &m2_spec).map_err(internal)?;
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
    // N0 facts the connectivity phase establishes. A dry run leaves them at
    // the conforming values, since it fabricates a conforming node.
    let mut handshake_completed = true;
    let mut wrong_alpn_rejected = true;
    let mut builder: Option<n0::BuilderProbeFacts> = Some(n0::BuilderProbeFacts {
        attempted: connectivity::BUILDER_CONNECTIONS,
        accepted: connectivity::BUILDER_CONNECTIONS,
        ce133_accepted: true,
        ce133_detail: None,
    });
    if !cli.dry_run {
        let cfg = launch_config(&keys, &cli, spec_path, m2_spec_path);
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
        builder = Some(n0::BuilderProbeFacts {
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
        // Seeded before the node is given anything to sync from: every slot
        // between genesis and now has to be filled for the chain to be
        // current, and the entropy the tickets are later proved against is
        // read from its head.
        seed_past_slots(&ref_chain).map_err(internal)?;
        let epoch_contexts: EpochContexts = Arc::new(Mutex::new(Vec::new()));
        let emu = Emulator::n0(emu_indices.clone(), genesis_hash, cli.base_port)
            .await
            .map_err(internal)?;
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
                jamnp_s::clock::current()
                    .sleep(connectivity::INITIATOR_GRACE)
                    .await;
                // The NUT is the preferred initiator for this peer. The grace
                // is there so the pair still connects if it never dials, not
                // so we open a second connection alongside its first.
                let peer = index as u16;
                if !connectivity::should_fallback_dial(&lock(&shared.obs), peer) {
                    return;
                }
                m2_emu::emu::record(&shared.obs, peer, ObsKind::Other(n0::FALLBACK_DIAL));
                let _ = m2_emu::emu::dial_nut(index, genesis_hash, nut_addr, nut_san, shared).await;
            }));
        }
        // Only now is the plan laid out. Until the node has imported and
        // finalized the chain it was just handed it refuses every ticket, so
        // the sender holds them back (`ticket_io::node_can_accept_tickets`)
        // -- and a schedule written before that hold is a schedule of
        // intentions. `sessions/fwd-1` planned its one proxied ticket for
        // phase 2 and the gate released it in phase 7, past any forwarding
        // window, with the plan none the wiser. Planning against a node that
        // can already accept makes the slots the schedule names the slots the
        // tickets arrive in.
        let (ticket_ctx, ticket_plan, target_epoch) = if cli.lanes.needs_tickets() {
            wait_until_the_node_can_accept_tickets(&shared, cli.observe_secs).await;
            plan_tickets_for_this_run(&ref_chain, nut_index)
                .await
                .map_err(internal)?
        } else {
            // Neither ticket lane was asked for. Proving a plan nothing will
            // grade costs the most expensive seconds in the run, and waiting
            // for the node to be able to accept tickets costs more still.
            (ref_chain.ticket_ctx().map_err(internal)?, Vec::new(), 0)
        };
        // Counted from the chain rather than from the seeding: by now
        // `drive_slots` has added blocks of its own, and the N0 lane compares
        // this against the reference chain the contexts are built from, which
        // has to be the same chain.
        let count = ref_chain.chain_blocks().len().saturating_sub(1);
        if cli.lanes.needs_tickets() && ticket_plan.is_empty() {
            conn_findings.push(empty_ticket_plan_finding(&ref_chain, target_epoch));
        }
        // Each emulated validator's tickets go out on the connection to it,
        // whichever side opened it; the senders pick the plan up from here.
        emu.set_ticket_plans(plans_by_peer(&ticket_plan));
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
        jamnp_s::clock::current()
            .sleep(Duration::from_secs(cli.observe_secs))
            .await;
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
                n0::N0Ctx {
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
        ObsSource::Emulator { obs, .. } => evaluate(&lock(obs), &run_ctx, cli.lanes),
        ObsSource::Fabricated { log, .. } => evaluate(log, &run_ctx, cli.lanes),
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
/// measuring nothing. The second attempt reads the entropy of the epoch the
/// run is now in and has that epoch's whole window ahead of it.
///
/// Neither attempt seeds the chain itself. By the time this runs `drive_slots`
/// owns authoring, and a second writer racing it for the same slot fails the
/// whole run with "cannot author slot N: reference chain head is at slot N".
async fn plan_tickets_for_this_run(
    ref_chain: &RefChain,
    nut_index: usize,
) -> Result<(TicketCtx, Vec<ScheduledTicket>, u32), m2_reference::chain::ChainError> {
    let (ticket_ctx, tickets, target_epoch) = generate_tickets(ref_chain)?;
    let plan = schedule_tickets(ref_chain, &tickets, nut_index, target_epoch);
    if !this_epoch_is_a_waste(ref_chain.next_slot(), &plan, target_epoch) {
        return Ok((ticket_ctx, plan, target_epoch));
    }
    // The window for this epoch's lottery cannot carry the run, and nothing
    // within this epoch can change that: tickets are submitted before the
    // tail, and forwards are owed only early in the lottery. Waiting it out
    // costs slots before the observation window opens and buys the whole of
    // the next epoch's window; not waiting costs the lanes that would have
    // measured something.
    wait_for_next_epoch(ref_chain).await;
    let (ticket_ctx, tickets, target_epoch) = generate_tickets(ref_chain)?;
    let plan = schedule_tickets(ref_chain, &tickets, nut_index, target_epoch);
    Ok((ticket_ctx, plan, target_epoch))
}

/// Whether this epoch's remaining window is poor enough to be worth trading
/// for the next one's.
///
/// Two cases. An empty plan is the obvious one: the window has closed
/// outright, so both ticket lanes measure nothing. The second is a window
/// that is open but opens late — a CE 131 delivery goes out at its first
/// slot, and once that slot is past the forwardable phases the node owes no
/// forward for it, so `n2_proxy_duty` reports "not exercised" however well
/// the node behaves (`sessions/gate-7`, which planned every CE 131 at phase
/// 8). Deferring is only worth it when the plan actually proxies something to
/// the NUT; with no CE 131 entry there is no duty to exercise and the wait
/// buys nothing.
fn this_epoch_is_a_waste(now_slot: u32, plan: &[ScheduledTicket], target_epoch: u32) -> bool {
    if plan.is_empty() {
        return true;
    }
    let proxies_to_the_nut = plan.iter().any(|s| s.delivery == TicketDelivery::Ce131);
    proxies_to_the_nut
        && !window_can_exercise_forwarding(first_delivery_slot(now_slot), target_epoch)
}

/// Block until the NUT is in a state to accept tickets, or until waiting
/// stops being worth it.
///
/// The node refuses every ticket offered to it while its finalized head is
/// behind the current epoch, which it is for as long as it takes to import
/// and finalize the chain the harness seeded. The emulator's sender already
/// holds tickets back for exactly this (`node_can_accept_tickets`), but a
/// plan written while the node is still catching up names slots the tickets
/// will not arrive in, and the proxy-forwarding duty is owed only on arrival.
///
/// Giving up is deliberate rather than an error: a node that never finalizes
/// has a defect of its own, and the run should go on to report it from the
/// lanes rather than hang here. The sender's own gate still withholds, so
/// nothing is graded against a ticket the node could not have taken.
async fn wait_until_the_node_can_accept_tickets(shared: &m2_emu::emu::EmuShared, budget_secs: u64) {
    // Half the observation window, capped at an epoch: past an epoch the
    // lottery has moved on and the wait has bought nothing.
    let cap = u64::from(jam_types::epoch_period()) * m2_scenario::ctx::SLOT_PERIOD_MS / 1000;
    // Protocol time, not orchestration time: the budget is counted in slots
    // and the loop reads the slot clock, so the deadline has to be on the same
    // clock as the thing it is waiting for. Measured against a machine clock
    // while the slots came from a virtual one, this would never expire.
    let clock = jamnp_s::clock::current();
    let deadline = clock
        .mono_ms()
        .saturating_add((budget_secs / 2).min(cap).saturating_mul(1000));
    while clock.mono_ms() < deadline {
        let now_slot = m2_reference::chain::wall_clock_slot();
        if m2_emu::ticket_io::node_can_accept_tickets(shared.nut_final_slot(), now_slot) {
            return;
        }
        clock
            .sleep(Duration::from_millis(NODE_READINESS_POLL_MS))
            .await;
    }
}

/// Sleep until the start of the next epoch.
async fn wait_for_next_epoch(ref_chain: &RefChain) {
    let period = jam_types::epoch_period();
    let now = ref_chain.next_slot();
    let slots = period - now % period;
    jamnp_s::clock::current()
        .sleep(Duration::from_millis(
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
        let start = m2_reference::chain::slot_start_ms(next);
        let clock = jamnp_s::clock::current();
        if let Some(delay) = start.checked_sub(clock.wall_ms()) {
            clock.sleep(Duration::from_millis(delay)).await;
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
/// Reported rather than swallowed, because the N1 and N2 ticket checks are
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
    m2_spec_path: std::path::PathBuf,
) -> LaunchConfig {
    LaunchConfig {
        spec_path,
        m2_spec_path,
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

    /// The planner and the lane have to mean the same thing by "early enough
    /// to forward". They are in different crates and neither can see the
    /// other's constant, so the phases they admit are compared directly here:
    /// a planner that ran ahead of the rule would schedule deliveries the
    /// lane then declines to judge, and one that lagged would wait out epochs
    /// it had no need to.
    #[test]
    fn forwardable_phases_match_the_judged_rule() {
        jam_types::ProtocolParameters::tiny()
            .apply()
            .expect("tiny parameters apply");
        let period = jam_types::epoch_period();
        let tail = jam_types::epoch_tail_start();
        let last =
            m2_reference::tickets::last_forwardable_phase().expect("tiny leaves room to forward");
        for phase in 0..period {
            assert_eq!(
                phase <= last,
                m2_scenario::ctx::leaves_room_to_forward(41 * period + phase, period, tail),
                "phase {phase} is judged one way and planned the other"
            );
        }
    }

    /// The lane grades which validator the node proxied a ticket to, and the
    /// reference assigns which validator the emulator proxies to. They are in
    /// different crates -- `m2-scenario` holds `m2-reference` only as a
    /// dev-dependency, so the lane carries its own copy of the rule -- and a
    /// drift between them would have the harness send a ticket to one
    /// validator while faulting the node for not choosing another.
    #[test]
    fn proxy_rule_matches_the_reference() {
        jam_types::ProtocolParameters::tiny()
            .apply()
            .expect("tiny parameters apply");
        let val_count = usize::from(jam_types::max_val_count());
        // Ids that exercise the whole modulus, the boundaries of the four
        // bytes the rule reads, and bytes outside them that it must ignore.
        let mut ids: Vec<[u8; 32]> = (0u8..=32).map(|b| [b; 32]).collect();
        for tail in [
            [0u8, 0, 0, 0],
            [0xff, 0xff, 0xff, 0xff],
            [1, 0, 0, 7],
            [0, 0, 0, 5],
        ] {
            let mut id = [0xa5u8; 32];
            id[28..32].copy_from_slice(&tail);
            ids.push(id);
        }
        for id in ids {
            assert_eq!(
                usize::from(m2_scenario::ctx::proxy_index(&id, val_count)),
                m2_reference::tickets::proxy_index(&id, val_count),
                "the lane and the reference disagree about the proxy for {:02x?}",
                &id[28..32],
            );
        }
    }

    /// A plan that proxies nothing to the NUT has no forwarding duty to
    /// exercise, so a late window is as good as an early one and waiting an
    /// epoch for it buys nothing. A plan that does proxy to the NUT is worth
    /// the wait, because every CE 131 in it goes out at the window's first
    /// slot and a late first slot owes no forward at all.
    #[test]
    fn a_late_window_is_traded_only_when_a_ticket_is_proxied_to_the_nut() {
        jam_types::ProtocolParameters::tiny()
            .apply()
            .expect("tiny parameters apply");
        let period = jam_types::epoch_period();
        let target_epoch = 42;
        let scheduled = |delivery| ScheduledTicket {
            ticket: m2_reference::tickets::EmulatedTicket {
                id: [0u8; 32],
                author: 0,
                attempt: 0,
                proof: [0u8; 784],
                proxy: 0,
            },
            delivery,
            fault: None,
            plan_index: 0,
            slot: 0,
            target_epoch,
        };
        let proxied = [scheduled(TicketDelivery::Ce131)];
        let broadcast_only = [scheduled(TicketDelivery::Ce132)];

        assert!(
            this_epoch_is_a_waste(41 * period, &[], target_epoch),
            "an empty plan measures nothing whatever the phase"
        );
        // Phase 0: the whole lottery is ahead, so nothing is traded.
        assert!(!this_epoch_is_a_waste(41 * period, &proxied, target_epoch));
        // Phase 8: still inside the submission window, but a CE 131 landing
        // there is one no proxy owes a forward for.
        assert!(this_epoch_is_a_waste(
            41 * period + 8,
            &proxied,
            target_epoch
        ));
        assert!(
            !this_epoch_is_a_waste(41 * period + 8, &broadcast_only, target_epoch),
            "no CE 131 in the plan means no duty to wait for"
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

    /// The whole guaranteeing path on one trivial work item: a package, the
    /// report it refines to, the bundle, and a guarantee signed by the
    /// validators holding the core.
    ///
    /// Here rather than in `m2-reference` because it needs a chain whose
    /// genesis is anchored to the current epoch. An unanchored one refuses
    /// twice over -- the guarantee's slot names an epoch the state has never
    /// heard of, and once past that, genesis is far too old to be a lookup
    /// anchor -- and anchoring is `spec::tiny_spec`'s job, which lives here.
    ///
    /// It also measures what refining costs on the interpreter backend, which
    /// `RefChain` forces because the compiler backend needs a userfaultfd
    /// sandbox. N3 schedules work packages into slots, so the figure decides
    /// whether that calendar is realistic.
    /// A reference chain anchored to the current epoch, seeded to the present.
    ///
    /// Everything about guaranteeing needs one: assignments come from the
    /// storage for a slot, and an unanchored chain's state is at epoch 0 while
    /// its clock is eight hundred thousand epochs later, so it has no
    /// assignment for any slot the harness would ask about.
    fn anchored_chain(base_port: u16) -> Result<RefChain, m2_reference::chain::ChainError> {
        jam_types::ProtocolParameters::tiny()
            .apply()
            .expect("tiny parameters apply");
        let ports: Vec<u16> = (0..VALIDATOR_COUNT).map(|i| base_port + i as u16).collect();
        let anchor = m2_reference::chain::current_epoch_start_slot();
        let spec = spec::tiny_spec(&loopback_ips(), &ports, anchor)
            .map_err(|e| m2_reference::chain::ChainError::Chain(e.to_string()))?;
        let chain = RefChain::with_spec(5, spec)?;
        seed_past_slots(&chain)?;
        Ok(chain)
    }

    /// Every validator holds exactly one core, and the two directions of the
    /// assignment agree. A harness that read them apart would grade a node
    /// against a split the engine never made.
    #[test]
    fn the_assignment_is_a_partition_and_both_directions_agree()
    -> Result<(), m2_reference::chain::ChainError> {
        let chain = anchored_chain(42000)?;
        let slot = chain.best_slot();
        let mut seen = Vec::new();
        for core in 0..jam_types::core_count() {
            let holders = chain
                .guarantors_for(core, slot)
                .expect("an active core has holders");
            for val in &holders {
                assert_eq!(
                    chain.core_for(*val, slot),
                    Some(core),
                    "validator {val} is listed under core {core} but does not name it"
                );
            }
            seen.extend(holders);
        }
        seen.sort_unstable();
        assert_eq!(
            seen,
            (0..jam_types::max_val_count()).collect::<Vec<_>>(),
            "every validator holds exactly one core"
        );
        assert!(
            chain.guarantors_for(jam_types::core_count(), slot).is_none(),
            "a core outside the active set has no holders"
        );
        Ok(())
    }

    /// The assignment rotates within an epoch, which is the half of the rule a
    /// harness caching one lookup would silently lose.
    #[test]
    fn the_assignment_rotates_within_an_epoch() -> Result<(), m2_reference::chain::ChainError> {
        let chain = anchored_chain(43000)?;
        let slot = chain.best_slot();
        assert_ne!(
            chain.core_for(0, slot),
            chain.core_for(0, slot + jam_types::rotation_period()),
            "the core a validator holds must change across a rotation boundary"
        );
        Ok(())
    }

    #[test]
    fn a_work_item_refines_into_a_signed_guarantee() -> Result<(), m2_reference::chain::ChainError>
    {
        jam_types::ProtocolParameters::tiny()
            .apply()
            .expect("tiny parameters apply");
        let ports: Vec<u16> = (0..VALIDATOR_COUNT).map(|i| 41000 + i as u16).collect();
        let anchor = m2_reference::chain::current_epoch_start_slot();
        let spec = spec::tiny_spec(&loopback_ips(), &ports, anchor)
            .map_err(|e| m2_reference::chain::ChainError::Chain(e.to_string()))?;
        let chain = RefChain::with_spec(5, spec)?;
        seed_past_slots(&chain)?;

        let item = jam_node::hazmat::BuildItem::new(
            jam_node::DEV_BOOTSTRAP_SERVICE_ID,
            jam_types::WorkPayload(Vec::new()),
            jam_types::max_refine_gas(),
            jam_types::max_accumulate_gas(),
            Vec::new(),
            Vec::new(),
            0,
        );
        let core = 0;
        let started = std::time::Instant::now();
        let work = chain.guarantee_work(vec![item], core)?;
        eprintln!("refine took {:?}", started.elapsed());

        assert!(!work.bundle.is_empty(), "the bundle carries the package");
        assert!(
            !work.guarantee.signatures.is_empty(),
            "the guarantee is signed"
        );
        // Every signer must hold the core -- at the guarantee's *own* slot, not
        // the chain head's. The assignment rotates every `rotation_period`, so
        // the two disagree whenever a run straddles a boundary, and asserting
        // against the head made this test fail about half the time.
        let holders = chain
            .guarantors_for(core, work.guarantee.slot)
            .expect("an active core has holders");
        for signature in work.guarantee.signatures.iter() {
            assert!(
                holders.contains(&signature.val_index),
                "validator {} signed for a core it does not hold ({holders:?})",
                signature.val_index
            );
        }
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
