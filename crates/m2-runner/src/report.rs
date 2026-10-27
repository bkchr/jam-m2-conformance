//! Session report rendering: `report.md`, `findings.json`, trace output and
//! session directory layout (DESIGN.md §9).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// One conformance finding (DESIGN.md §9 `findings.json` shape).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Finding {
    pub severity: String,
    pub spec_citation: String,
    pub slot: Option<u32>,
    pub evidence: String,
    pub message: String,
}

/// The outcome of one check, as aggregated for the coverage table (§11).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CheckOutcome {
    pub id: String,
    pub lane: String,
    pub severity: String,
    pub passed: bool,
    pub soft: bool,
    pub details: String,
}

/// Session directory for a run: `root/<id>` (DESIGN.md §9).
pub fn session_dir(root: &Path, id: &str) -> PathBuf {
    root.join(id)
}

/// Create the session subdirectories `{logs,traces,report}` (DESIGN.md §9).
pub fn ensure_layout(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    for sub in crate::SESSION_LAYOUT {
        std::fs::create_dir_all(dir.join(sub))?;
    }
    Ok(())
}

/// Coverage-table result marker (§11): `HARD PASS` / `SOFT PASS` / `SOFT` /
/// `FAIL`.
///
/// A soft check that passed and a soft check that failed are different
/// outcomes and must not share a marker: printing `SOFT` for both made every
/// passing soft row read like a finding, when only the failures appear in
/// `findings.json`.
fn result_marker(o: &CheckOutcome) -> &'static str {
    match (o.soft, o.passed) {
        (true, true) => "SOFT PASS",
        (true, false) => "SOFT",
        (false, true) => "HARD PASS",
        (false, false) => "FAIL",
    }
}

/// Write `report/report.md` (coverage table + findings) and
/// `report/findings.json` under `session_dir` (DESIGN.md §9).
pub fn write_report(
    session_dir: &Path,
    results: &[CheckOutcome],
    findings: &[Finding],
) -> std::io::Result<()> {
    let report_dir = session_dir.join("report");
    std::fs::create_dir_all(&report_dir)?;

    let run_id = session_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "unknown".to_string());
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let mut md = String::new();
    md.push_str("# M2 Conformance Report\n\n");
    md.push_str(&format!("- Run: {run_id}\n"));
    md.push_str(&format!("- Timestamp: {secs} (unix seconds)\n"));
    md.push_str(&format!(
        "- Checks: {}, Findings: {}\n\n",
        results.len(),
        findings.len()
    ));

    md.push_str("## Coverage\n\n");
    md.push_str("| Lane | Check | Severity | Result |\n");
    md.push_str("|---|---|---|---|\n");
    for r in results {
        md.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            r.lane,
            r.id,
            r.severity,
            result_marker(r)
        ));
    }

    md.push_str("\n## Findings\n\n");
    if findings.is_empty() {
        md.push_str("_None._\n");
    } else {
        for f in findings {
            md.push_str(&format!("### [{}] {}\n\n", f.severity, f.spec_citation));
            if let Some(slot) = f.slot {
                md.push_str(&format!("- Slot: {slot}\n"));
            }
            md.push_str(&format!("- Evidence: {}\n\n", f.evidence));
            md.push_str(&format!("{}\n\n", f.message));
        }
    }
    std::fs::write(report_dir.join("report.md"), md)?;

    let json = serde_json::to_string_pretty(findings)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(report_dir.join("findings.json"), json)
}

/// Write the JAMNP message trace under `session_dir/traces` (DESIGN.md §9).
///
/// `Trace::write_dir` produces `jamnp.bin`, `jamnp.json`, `tx/` and `rx/`
/// directly in the given directory, so it is pointed at `traces/`.
pub fn write_trace(session_dir: &Path, trace: &jamnp_s::trace::Trace) -> std::io::Result<()> {
    trace.write_dir(&session_dir.join("traces"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jamnp_s::trace::{Direction, Trace, TraceRecord};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Unique temp dir under `std::env::temp_dir()`, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "m2_report_{name}_{}_{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&path);
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn record(direction: Direction, peer: u16, kind: u8, id: u64, bytes: &[u8]) -> TraceRecord {
        TraceRecord {
            direction,
            peer_index: peer,
            stream_kind: kind,
            stream_id: id,
            mono_ts: 0,
            wall_ts: 0,
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn report_md_renders_table() {
        let tmp = TempDir::new("table");
        let results = vec![
            CheckOutcome {
                id: "up0_handshake".into(),
                lane: "L0".into(),
                severity: "hard".into(),
                passed: true,
                soft: false,
                details: "ok".into(),
            },
            CheckOutcome {
                id: "preferred_initiator".into(),
                lane: "L0".into(),
                severity: "soft".into(),
                passed: true,
                soft: true,
                details: "late but ok".into(),
            },
            CheckOutcome {
                id: "ce128_fetch".into(),
                lane: "L0".into(),
                severity: "hard".into(),
                passed: false,
                soft: false,
                details: "reset".into(),
            },
        ];
        write_report(tmp.path(), &results, &[]).unwrap();
        let md = std::fs::read_to_string(tmp.path().join("report/report.md")).unwrap();
        assert!(md.contains("| L0 | up0_handshake | hard | HARD PASS |"));
        assert!(md.contains("| L0 | preferred_initiator | soft | SOFT PASS |"));
        assert!(md.contains("| L0 | ce128_fetch | hard | FAIL |"));
    }

    #[test]
    fn findings_json_roundtrip() {
        let tmp = TempDir::new("json");
        let findings = vec![
            Finding {
                severity: "hard".into(),
                spec_citation: "simple.md :48-59".into(),
                slot: Some(42),
                evidence: "traces/jamnp.bin#3".into(),
                message: "ALPN version mismatch".into(),
            },
            Finding {
                severity: "soft".into(),
                spec_citation: "simple.md :70-80".into(),
                slot: None,
                evidence: "traces/jamnp.bin#1".into(),
                message: "preferred peer never connected".into(),
            },
        ];
        write_report(tmp.path(), &[], &findings).unwrap();
        let raw = std::fs::read_to_string(tmp.path().join("report/findings.json")).unwrap();
        let parsed: Vec<Finding> = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed, findings);
    }

    #[test]
    fn session_layout_created() {
        let tmp = TempDir::new("layout");
        ensure_layout(tmp.path()).unwrap();
        for sub in ["logs", "traces", "report"] {
            assert!(tmp.path().join(sub).is_dir(), "{sub} missing");
        }
    }

    #[test]
    fn trace_files_written() {
        let tmp = TempDir::new("trace");
        let mut trace = Trace::default();
        trace.push(record(Direction::Tx, 0, 1, 7, &[1, 2, 3]));
        trace.push(record(Direction::Rx, 1, 2, 8, &[4, 5]));
        write_trace(tmp.path(), &trace).unwrap();
        let bin = std::fs::read(tmp.path().join("traces/jamnp.bin")).unwrap();
        assert!(!bin.is_empty(), "jamnp.bin must be non-empty");
        let raw = std::fs::read_to_string(tmp.path().join("traces/jamnp.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(value.as_array().expect("array").len(), 2);
    }

    #[test]
    fn findings_section_in_report() {
        let tmp = TempDir::new("findings");
        let findings = vec![Finding {
            severity: "soft".into(),
            spec_citation: "simple.md :70-80".into(),
            slot: None,
            evidence: "traces/jamnp.bin#1".into(),
            message: "preferred peer never connected".into(),
        }];
        write_report(tmp.path(), &[], &findings).unwrap();
        let md = std::fs::read_to_string(tmp.path().join("report/report.md")).unwrap();
        assert!(md.contains("## Findings"), "findings section missing");
        assert!(md.contains("soft"), "severity missing");
        assert!(md.contains("simple.md :70-80"), "citation missing");
    }
}
