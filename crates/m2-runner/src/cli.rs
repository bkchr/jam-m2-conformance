//! CLI entry point: clap parsing plus the T20 run lifecycle (§4).

use std::path::PathBuf;

use clap::{Parser, ValueEnum};

use crate::run;

/// The m2-runner command line (§4).
#[derive(Debug, Clone, Parser)]
pub struct Cli {
    /// Run seed: deterministic key/spec derivation (§4 step 1).
    #[arg(long, default_value_t = 1)]
    pub seed: u64,
    /// NUT validator index. Defaults to 5, not 0: the preferred-initiator rule
    /// is degenerate for trivial keys at index 0 (the NUT is never preferred,
    /// so NUT-initiated L0 checks can never fire). L7 rotates this.
    #[arg(long, default_value_t = 5)]
    pub validator_index: usize,
    /// Base port: the NUT listens on this port, the five emulated validators
    /// on `base+1 ..= base+5`.
    #[arg(long, default_value_t = 40000)]
    pub base_port: u16,
    /// NUT launch preset.
    #[arg(long, value_enum, default_value = "polkajam")]
    pub preset: Preset,
    /// Session directory (the `sessions/<id>` root; layout `{logs,traces,report}`).
    #[arg(long)]
    pub session_dir: PathBuf,
    /// Seconds to wait for the NUT's QUIC port to come up (§4 step 2).
    #[arg(long, default_value_t = 30)]
    pub startup_timeout: u64,
    /// Seconds of JAMNP observation before evaluation (§4 step 4).
    #[arg(long, default_value_t = 60)]
    pub observe_secs: u64,
    /// Comma-separated lane set to run (parsed for this pass; selection wiring
    /// is iterative).
    #[arg(long, default_value = "l0,l1,l2")]
    pub lanes: String,
    /// Skip NUT launch and connectivity; fabricate a conforming observation
    /// log so the scenario checks pass and the report renders. The
    /// deterministic S4 baseline (no network, no processes).
    #[arg(long)]
    pub dry_run: bool,
}

/// NUT launch preset (§7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Preset {
    /// Polkajam NUT: `polkajam --chain <spec> run ...` (§7).
    Polkajam,
    /// Docker host-network NUT via the `JAM_M2_*` env contract (§7).
    Docker,
    /// Fake NUT that never opens its QUIC port, so the startup probe times
    /// out: the deterministic no-NUT failure path. `--dry-run` skips spawning
    /// entirely and fabricates the observation log instead.
    Mock,
}

/// Map a run outcome onto a process exit code (§4 step 6): 0 iff every hard
/// check passed and there was no startup failure; 1 on a hard failure or NUT
/// startup failure/timeout; 2 on internal errors.
fn exit_code(all_hard_passed: bool, startup_failed: bool) -> i32 {
    if startup_failed || !all_hard_passed {
        1
    } else {
        0
    }
}

/// Orchestrate a full §4 run and map its outcome to a process exit code.
pub async fn run(cli: Cli) -> i32 {
    match run::run_once(cli).await {
        Ok(eval) => exit_code(eval.all_hard_passed, false),
        Err(run::RunError::Startup(_)) => 1,
        Err(run::RunError::Internal(_)) => 2,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    use clap::Parser;
    use m2_scenario::dsl::{Obs, ObsKind, ObsLog};
    use m2_scenario::scenarios::l0;

    use super::{exit_code, run, Cli, Preset};

    /// Unique temp dir under `std::env::temp_dir()`, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "m2_run_{name}_{}_{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&path);
            Self(path)
        }

        fn path(&self) -> &PathBuf {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn cli_parses() {
        let cli = Cli::parse_from([
            "m2-runner",
            "--seed",
            "7",
            "--base-port",
            "41000",
            "--session-dir",
            "/tmp/x",
        ]);
        assert_eq!(cli.seed, 7);
        assert_eq!(cli.base_port, 41000);
        assert_eq!(cli.session_dir, PathBuf::from("/tmp/x"));
        assert_eq!(cli.validator_index, 5);
        assert_eq!(cli.startup_timeout, 30);
        assert_eq!(cli.observe_secs, 60);
        assert_eq!(cli.lanes, "l0,l1,l2");
        assert!(!cli.dry_run);
        assert_eq!(cli.preset, Preset::Polkajam);

        let mock = Cli::parse_from(["m2-runner", "--preset", "mock", "--session-dir", "/tmp/x"]);
        assert_eq!(mock.preset, Preset::Mock);
    }

    #[test]
    fn cli_lanes_and_observe_parse() {
        let cli = Cli::parse_from([
            "m2-runner",
            "--observe-secs",
            "45",
            "--lanes",
            "l1,l2",
            "--session-dir",
            "/tmp/x",
        ]);
        assert_eq!(cli.observe_secs, 45);
        assert_eq!(cli.lanes, "l1,l2");

        let defaults = Cli::parse_from(["m2-runner", "--session-dir", "/tmp/x"]);
        assert_eq!(defaults.observe_secs, 60);
        assert_eq!(defaults.lanes, "l0,l1,l2");
    }

    #[tokio::test]
    async fn dry_run_renders_report_and_exits_0() {
        let dir = TempDir::new("dry-run");
        let cli = Cli {
            seed: 7,
            validator_index: 0,
            base_port: 41000,
            preset: Preset::Mock,
            session_dir: dir.path().clone(),
            startup_timeout: 30,
            observe_secs: 60,
            lanes: "l0,l1,l2".to_string(),
            dry_run: true,
        };
        let code = run(cli).await;
        assert_eq!(code, 0);

        let report = dir.path().join("report/report.md");
        let findings = dir.path().join("report/findings.json");
        let bin = dir.path().join("traces/jamnp.bin");
        let json = dir.path().join("traces/jamnp.json");
        assert!(report.exists(), "report.md missing");
        assert!(findings.exists(), "findings.json missing");
        assert!(bin.exists(), "traces/jamnp.bin missing");
        assert!(json.exists(), "traces/jamnp.json missing");

        let md = std::fs::read_to_string(&report).expect("report readable");
        assert!(
            md.contains("HARD PASS"),
            "report must show passing hard checks"
        );
        assert!(
            !md.contains("| FAIL |"),
            "dry-run report must have no failures"
        );
        for check in [
            "tls_cert",
            "alpn",
            "preferred_initiator",
            "endpoint_decoding",
            "builder_slots",
            "up0_handshake",
            "up0_announce",
            "ce128_serve",
            "ce129_serve",
        ] {
            assert!(md.contains(check), "report must cover L0 check {check}");
        }
    }

    #[tokio::test]
    async fn dry_run_deterministic_same_seed() {
        let dir = TempDir::new("det");
        let mk = |dir: &PathBuf| Cli {
            seed: 9,
            validator_index: 0,
            base_port: 41000,
            preset: Preset::Mock,
            session_dir: dir.clone(),
            startup_timeout: 30,
            observe_secs: 60,
            lanes: "l0,l1,l2".to_string(),
            dry_run: true,
        };
        let cli = mk(dir.path());
        assert_eq!(run(cli).await, 0);

        // Snapshot the first run, rerun into the same session dir, compare.
        let strip_ts = |s: String| -> String {
            s.lines()
                .filter(|l| !l.starts_with("- Timestamp:"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        let report = |dir: &PathBuf| {
            strip_ts(std::fs::read_to_string(dir.join("report/report.md")).expect("report"))
        };
        let fa = std::fs::read(dir.path().join("report/findings.json")).expect("findings a");
        let ba = std::fs::read(dir.path().join("traces/jamnp.bin")).expect("trace a");
        let ra = report(dir.path());

        assert_eq!(run(mk(dir.path())).await, 0);

        let fb = std::fs::read(dir.path().join("report/findings.json")).expect("findings b");
        let bb = std::fs::read(dir.path().join("traces/jamnp.bin")).expect("trace b");
        let rb = report(dir.path());
        assert_eq!(
            fa, fb,
            "findings.json must be byte-identical for the same seed"
        );
        assert_eq!(ba, bb, "jamnp.bin must be byte-identical for the same seed");
        // Only the wall-clock timestamp line (report.rs behaviour) may differ.
        assert_eq!(
            ra, rb,
            "report.md must match for the same seed (modulo timestamp)"
        );
    }

    #[tokio::test]
    async fn mock_nut_startup_timeout_exits_1() {
        let dir = TempDir::new("mock-timeout");
        let cli = Cli {
            seed: 1,
            validator_index: 0,
            base_port: 40100,
            preset: Preset::Mock,
            session_dir: dir.path().clone(),
            startup_timeout: 1,
            observe_secs: 60,
            lanes: "l0,l1,l2".to_string(),
            dry_run: false,
        };
        let code = run(cli).await;
        assert_eq!(
            code, 1,
            "mock NUT never comes up: startup failure must exit 1"
        );
        // The spawned stand-in must be reaped (no orphan process).
    }

    #[tokio::test]
    async fn exit_code_reflects_hard_failure() {
        let dir = TempDir::new("hard-fail");
        // A fabricated observation log missing the `CERT_SAN_OK` observation
        // (L0 contract code 22): `tls_cert_single_san_e_base32` hard-fails.
        let mut log = ObsLog::new();
        let mut t = 0u64;
        let mut push = |kind: ObsKind| {
            log.push(
                t,
                Obs {
                    peer: l0::PEER_1,
                    kind,
                    at_ms: t,
                },
            );
            t += 10;
        };
        push(ObsKind::Accept);
        push(ObsKind::Other(l0::CERT_ED25519));
        push(ObsKind::Other(l0::CERT_KEY_MATCH));
        push(ObsKind::OpenUp0);
        // CERT_SAN_OK deliberately omitted.
        drop(push); // end the closure's borrows so `log` can be read

        let eval = crate::scenario::evaluate(
            &log,
            &crate::scenario::fabricated_run_ctx(3).expect("fabricated run ctx builds"),
        );
        assert!(
            !eval.all_hard_passed,
            "missing HARD observation must fail the run"
        );
        assert!(
            eval.outcomes
                .iter()
                .any(|o| o.id.ends_with("tls_cert_single_san_e_base32") && !o.passed && !o.soft),
            "the missing CERT_SAN_OK must surface as a hard FAIL row"
        );

        crate::report::write_report(dir.path(), &eval.outcomes, &eval.findings)
            .expect("report writes");
        let md = std::fs::read_to_string(dir.path().join("report/report.md")).expect("report");
        assert!(md.contains("FAIL"), "report must contain a FAIL row");

        assert_eq!(exit_code(eval.all_hard_passed, false), 1);
    }
}
