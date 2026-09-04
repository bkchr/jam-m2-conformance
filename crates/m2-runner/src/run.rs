//! The §4 run lifecycle, orchestrated by [`crate::cli::run`].

use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Range;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use jamnp_s::cert::san_for_key;
use m2_emu::emu::Emulator;
use m2_reference::chain::RefChain;

use crate::cli::{Cli, Preset};
use crate::connectivity::{self, ConnectivityPlan, ProbeOutcome};
use crate::keygen;
use crate::launch::{self, LaunchConfig, NutProcess};
use crate::report::{self, Finding};
use crate::scenario::{evaluate, fabricated_obs_log, Evaluation, ObsSource};
use crate::spec;

/// How many emulated slots the dry-run baseline pretends were authored.
/// Seconds to let JAMNP traffic accumulate before evaluating the scenario.
const OBSERVATION_WINDOW: u64 = 30;
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
    let keys = keygen::generate(cli.seed, nut_index, 6);
    keygen::write_seed_files(session_dir, &keys).map_err(internal)?;

    let ips = loopback_ips();
    let ports: Vec<u16> = (0..6).map(|i| cli.base_port + i as u16).collect();
    let chain_spec = spec::tiny_spec(&ips, &ports).map_err(internal)?;
    let genesis_hash = chain_spec.genesis_header.hash().0;
    let spec_id = format!("m2-{}", cli.seed);
    let m2_spec = spec::m2_spec(&spec_id, &chain_spec).map_err(internal)?;
    spec::write_m2_spec(session_dir, &spec_id, &m2_spec).map_err(internal)?;
    let spec_path = spec::write_polkajam_spec(session_dir, &chain_spec).map_err(internal)?;

    let nut_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, cli.base_port + nut_index as u16));
    let nut_san = san_for_key(&keys.keysets[nut_index].ed25519.0.verification_key());

    // §4.2 launch + startup probe, §4.3 connectivity (both skipped in dry-run).
    // Emulated validators are the other five indices; with the default NUT index 5 that is the
    // contiguous range 0..5 (with index 0 it is 1..6), so the emulator and reference use a Range.
    let emu_range: Range<usize> = if nut_index == 0 { 1..6 } else { 0..nut_index };
    let emu_keys: Vec<[u8; 32]> = emu_range
        .clone()
        .map(|i| keys.keysets[i].ed25519.0.verification_key().to_bytes())
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

        let emu_addrs: Vec<SocketAddr> = emu_range
            .clone()
            .map(|i| SocketAddr::from((Ipv4Addr::LOCALHOST, cli.base_port + i as u16)))
            .collect();
        let outcomes =
            connectivity::run_connectivity(&plan, nut_addr, &emu_addrs, genesis_hash).await;
        conn_findings = connectivity_findings(&plan, &outcomes);
    }

    // §4.4 scenario: reference chain + emulator, or the fabricated dry-run log.
    let (source, reference_block_count, dial_tasks) = if cli.dry_run {
        (
            ObsSource::Fabricated {
                log: fabricated_obs_log(DRY_RUN_BLOCK_COUNT),
                trace: jamnp_s::trace::Trace::default(),
            },
            DRY_RUN_BLOCK_COUNT,
            Vec::new(),
        )
    } else {
        let mut ref_chain = RefChain::tiny(emu_range.clone()).map_err(internal)?;
        let count = author_emulated_slots(&mut ref_chain).map_err(internal)?;
        let ref_chain = Arc::new(ref_chain);
        let emu = Emulator::l0(emu_range.clone(), genesis_hash, cli.base_port)
            .await
            .map_err(internal)?;
        let obs = emu.obs();
        let trace = emu.trace();
        let _accept = emu.accept_loop(ref_chain.clone());
        // Drive the preferred-initiator connectivity: emulated validators that
        // are the preferred initiator dial the NUT now; the rest wait the 5 s
        // grace then dial anyway (a soft finding).
        let mut dial_tasks = Vec::new();
        for i in plan.initiate_now {
            let trace = trace.clone();
            let obs = obs.clone();
            let ref_chain = ref_chain.clone();
            let nut_san = nut_san.clone();
            dial_tasks.push(tokio::spawn(async move {
                let _ = m2_emu::emu::dial_nut(
                    emu_range.start,
                    i,
                    genesis_hash,
                    nut_addr,
                    nut_san,
                    ref_chain,
                    trace,
                    obs,
                )
                .await;
            }));
        }
        for i in plan.wait_then_connect {
            let trace = trace.clone();
            let obs = obs.clone();
            let ref_chain = ref_chain.clone();
            let nut_san = nut_san.clone();
            dial_tasks.push(tokio::spawn(async move {
                tokio::time::sleep(connectivity::INITIATOR_GRACE).await;
                let _ = m2_emu::emu::dial_nut(
                    emu_range.start,
                    i,
                    genesis_hash,
                    nut_addr,
                    nut_san,
                    ref_chain,
                    trace,
                    obs,
                )
                .await;
            }));
        }
        (
            ObsSource::Emulator {
                obs,
                trace,
                _emu: emu,
            },
            count,
            dial_tasks,
        )
    };

    if !dial_tasks.is_empty() {
        tokio::time::sleep(Duration::from_secs(OBSERVATION_WINDOW)).await;
    }
    drop(dial_tasks);

    let evaluation = match &source {
        ObsSource::Emulator { obs, .. } => evaluate(&lock(obs), reference_block_count),
        ObsSource::Fabricated { log, .. } => evaluate(log, reference_block_count),
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

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn internal(e: impl std::fmt::Display) -> RunError {
    RunError::Internal(e.to_string())
}

fn startup(e: impl std::fmt::Display) -> RunError {
    RunError::Startup(e.to_string())
}
