//! The §4 run lifecycle, orchestrated by [`crate::cli::run`].

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use jamnp_s::cert::san_for_key;
use m2_emu::emu::Emulator;
use m2_emu::ticket_io::plan_for_peer;
use m2_reference::chain::RefChain;
use m2_scenario::dsl::ObsKind;
use m2_scenario::scenarios::l0;

use crate::cli::{Cli, Preset};
use crate::connectivity::{self, ConnectivityPlan, ProbeOutcome};
use crate::keygen;
use crate::launch::{self, LaunchConfig, NutProcess};
use crate::real::{build_real_run_ctx, compute_ticket_plan, RealRunData};
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
    let mut nut: Option<NutProcess> = None;
    let mut conn_findings: Vec<Finding> = Vec::new();
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
        let ref_spec = spec::tiny_spec(&ips, &ports, anchor_slot).map_err(internal)?;
        let mut ref_chain = RefChain::with_spec(nut_index, ref_spec).map_err(internal)?;
        let count = author_emulated_slots(&mut ref_chain).map_err(internal)?;
        let ref_chain = Arc::new(ref_chain);
        let emu = Emulator::l0(emu_indices.clone(), genesis_hash, cli.base_port)
            .await
            .map_err(internal)?;
        let obs = emu.obs();
        let trace = emu.trace();
        let nut_blocks = emu.nut_blocks();
        let _accept = emu.accept_loop(ref_chain.clone());
        // L2: compute the emulated ticket plan for the target epoch so each
        // dialed connection can deliver its own tickets to the NUT.
        let (ticket_ctx, ticket_plan, target_epoch) =
            compute_ticket_plan(&ref_chain, nut_index).map_err(internal)?;
        // Drive the preferred-initiator connectivity: emulated validators that
        // are the preferred initiator dial the NUT now; the rest wait the 5 s
        // grace then dial anyway (a soft finding).
        let mut dial_tasks = Vec::new();
        for &i in &plan.initiate_now {
            let trace = trace.clone();
            let obs = obs.clone();
            let nut_blocks = nut_blocks.clone();
            let ref_chain = ref_chain.clone();
            let nut_san = nut_san.clone();
            let index = emu_indices[i];
            let peer_plan = plan_for_peer(&ticket_plan, index);
            dial_tasks.push(tokio::spawn(async move {
                let _ = m2_emu::emu::dial_nut(
                    index,
                    genesis_hash,
                    nut_addr,
                    nut_san,
                    ref_chain,
                    trace,
                    obs,
                    nut_blocks,
                    peer_plan,
                )
                .await;
            }));
        }
        for &i in &plan.wait_then_connect {
            let trace = trace.clone();
            let obs = obs.clone();
            let nut_blocks = nut_blocks.clone();
            let ref_chain = ref_chain.clone();
            let nut_san = nut_san.clone();
            let index = emu_indices[i];
            let peer_plan = plan_for_peer(&ticket_plan, index);
            dial_tasks.push(tokio::spawn(async move {
                tokio::time::sleep(connectivity::INITIATOR_GRACE).await;
                // The NUT is the preferred initiator for this peer. The grace
                // is there so the pair still connects if it never dials, not
                // so we open a second connection alongside its first.
                let peer = index as u16;
                if !connectivity::should_fallback_dial(&lock(&obs), peer) {
                    return;
                }
                m2_emu::emu::record(&obs, peer, ObsKind::Other(l0::FALLBACK_DIAL));
                let _ = m2_emu::emu::dial_nut(
                    index,
                    genesis_hash,
                    nut_addr,
                    nut_san,
                    ref_chain,
                    trace,
                    obs,
                    nut_blocks,
                    peer_plan,
                )
                .await;
            }));
        }
        let real_run = RealRunData {
            ref_chain,
            nut_blocks,
            ticket_ctx,
            plan: ticket_plan,
            target_epoch,
        };
        (
            ObsSource::Emulator {
                obs,
                trace,
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
    drop(dial_tasks);

    let run_ctx = match &source {
        ObsSource::Emulator { obs, trace, .. } => {
            let data = real_run.as_ref().ok_or_else(|| {
                RunError::Internal("emulator run missing reference run data".into())
            })?;
            build_real_run_ctx(
                data,
                &lock(obs),
                &lock(trace),
                l0::L0Ctx {
                    reference_block_count,
                    first_emu_peer: emu_indices[0] as u16,
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

/// Author up to three emulated (non-NUT) slots into `chain`; returns how many
/// blocks were actually produced.
fn author_emulated_slots(chain: &mut RefChain) -> Result<usize, m2_reference::chain::ChainError> {
    let start = chain.next_slot();
    let mut count = 0;
    for slot in start..start + 12 {
        if chain.author_block(slot)?.is_some() {
            count += 1;
            if count >= 3 {
                break;
            }
        }
    }
    Ok(count)
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
