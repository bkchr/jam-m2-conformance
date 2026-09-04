//! NUT launch: command templates, presets and process lifecycle (DESIGN.md §7).

use std::path::{Path, PathBuf};

use thiserror::Error;
use tokio::process::Child;

/// Configuration for a NUT launch: everything the command templates reference.
pub struct LaunchConfig {
    /// Path to the generated spec file.
    pub spec_path: PathBuf,
    /// Hex of the NUT's 32-byte Ed25519 secret.
    pub ed25519_secret_hex: String,
    /// Hex of the NUT's 32-byte Bandersnatch secret.
    pub bandersnatch_secret_hex: String,
    /// `[::]:<port>` listen address.
    pub listen: String,
    /// `<ipv6>:<port>` public address carried in genesis metadata.
    pub public_addr: String,
    /// Directory holding seed files and node data.
    pub data_path: PathBuf,
    /// NUT log level.
    pub log_level: String,
}

/// Replaces the DESIGN.md §7 placeholders `{spec} {ed25519_secret}
/// {bandersnatch_secret} {listen} {public_addr} {data} {log_level}` with `cfg`
/// values. Unknown placeholders are rejected.
///
/// # Errors
/// Returns [`LaunchError::MalformedTemplate`] for an unknown placeholder or a
/// non-UTF-8 path value.
pub fn substitute(template: &str, cfg: &LaunchConfig) -> Result<String, LaunchError> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        rest = &rest[open..];
        let Some(close) = rest.find('}') else {
            return Err(LaunchError::MalformedTemplate(rest.to_string()));
        };
        out.push_str(value_of(&rest[1..close], cfg)?);
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Resolves a single placeholder name to its config value.
fn value_of<'a>(name: &str, cfg: &'a LaunchConfig) -> Result<&'a str, LaunchError> {
    match name {
        "spec" => path_str(&cfg.spec_path),
        "ed25519_secret" => Ok(&cfg.ed25519_secret_hex),
        "bandersnatch_secret" => Ok(&cfg.bandersnatch_secret_hex),
        "listen" => Ok(&cfg.listen),
        "public_addr" => Ok(&cfg.public_addr),
        "data" => path_str(&cfg.data_path),
        "log_level" => Ok(&cfg.log_level),
        other => Err(LaunchError::MalformedTemplate(format!(
            "unknown placeholder {{{other}}}"
        ))),
    }
}

/// Renders a path placeholder; a command line cannot carry a non-UTF-8 path.
fn path_str(path: &Path) -> Result<&str, LaunchError> {
    path.to_str().ok_or_else(|| {
        LaunchError::MalformedTemplate(format!(
            "placeholder value is not valid UTF-8: {}",
            path.display()
        ))
    })
}

/// Polkajam preset (DESIGN.md §7): `polkajam --chain <spec> run
/// --key-seed-file <data>/seed.seed --listen-ip <ip> --port <port>
/// --peer-id {peer-id} --external-ip <ip> --mode validator`. `{peer-id}` derives
/// from the NUT public key (not in [`LaunchConfig`]) and is left for the caller.
pub fn preset_polkajam(cfg: &LaunchConfig) -> String {
    let (listen_ip, port) = split_host_port(&cfg.listen);
    let (external_ip, _) = split_host_port(&cfg.public_addr);
    let spec = cfg.spec_path.display();
    let data = cfg.data_path.display();
    format!(
        "polkajam --chain {spec} run --temp --key-seed-file {data}/seed.seed \
         --listen-ip {listen_ip} --port {port} --peer-id {{peer-id}} \
         --external-ip {external_ip} --mode validator"
    )
}

/// Docker preset (DESIGN.md §7): host network (QUIC is UDP; the NUT must
/// initiate connections under the preferred-initiator rule). Config values are
/// substituted; `{image}` is left for the caller to fill in.
pub fn preset_docker(cfg: &LaunchConfig) -> String {
    let spec = cfg.spec_path.display();
    let ed25519_secret = &cfg.ed25519_secret_hex;
    let bandersnatch_secret = &cfg.bandersnatch_secret_hex;
    let listen = &cfg.listen;
    let public_addr = &cfg.public_addr;
    let data = cfg.data_path.display();
    let log_level = &cfg.log_level;
    format!(
        "docker run --network host \
         -e JAM_M2=1 \
         -e JAM_M2_SPEC={spec} \
         -e JAM_M2_ED25519_SECRET={ed25519_secret} \
         -e JAM_M2_BANDERSNATCH_SECRET={bandersnatch_secret} \
         -e JAM_M2_LISTEN={listen} \
         -e JAM_M2_PUBLIC_ADDR={public_addr} \
         -e JAM_M2_DATA_PATH={data} \
         -e JAM_M2_LOG_LEVEL={log_level} \
         {{image}}"
    )
}

/// Splits `<host>:<port>` (raw IPv6, port after the last colon) or
/// `[<v6>]:<port>` into `(host, port)`. On a malformed address the missing part
/// is `""`.
fn split_host_port(addr: &str) -> (&str, &str) {
    if let Some(rest) = addr.strip_prefix('[') {
        match rest.find(']') {
            Some(close) => {
                let host = &addr[1..close + 1];
                let port = rest[close + 1..].trim_start_matches(':');
                (host, port)
            }
            None => (addr, ""),
        }
    } else {
        match addr.rsplit_once(':') {
            Some((host, port)) => (host, port),
            None => (addr, ""),
        }
    }
}

/// A running NUT process with its redirected log paths.
pub struct NutProcess {
    pub child: Child,
    pub stdout: PathBuf,
    pub stderr: PathBuf,
}

/// Tokenizes `cmd` by whitespace — deliberately no shell, so no quoting,
/// globbing or environment expansion (paths with spaces must be pre-escaped by
/// the caller) — and spawns it with stdout/stderr redirected to
/// `session_dir/logs/nut.{stdout,stderr}.log`.
///
/// # Errors
/// Returns an I/O error if the program cannot be spawned or the log files
/// cannot be created.
pub async fn spawn(cmd: &str, session_dir: &Path) -> std::io::Result<NutProcess> {
    let mut tokens = cmd.split_whitespace();
    let program = tokens.next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "empty launch command")
    })?;
    let args: Vec<&str> = tokens.collect();

    let logs = session_dir.join("logs");
    tokio::fs::create_dir_all(&logs).await?;
    let stdout = logs.join("nut.stdout.log");
    let stderr = logs.join("nut.stderr.log");
    let stdout_file = std::fs::File::create(&stdout)?;
    let stderr_file = std::fs::File::create(&stderr)?;

    let child = tokio::process::Command::new(program)
        .args(args)
        .stdout(stdout_file)
        .stderr(stderr_file)
        .spawn()?;

    Ok(NutProcess {
        child,
        stdout,
        stderr,
    })
}

/// Kills and reaps the NUT process. Safe on an already-exited child: a failed
/// `kill()` is ignored and `wait()` returns the cached exit status.
///
/// # Errors
/// Returns an I/O error if the child cannot be reaped.
pub async fn kill(mut nut: NutProcess) -> std::io::Result<()> {
    let _ = nut.child.kill().await;
    nut.child.wait().await.map(drop)
}

/// Errors from composing or launching a NUT command.
#[derive(Debug, Error)]
pub enum LaunchError {
    /// I/O failure while launching the NUT.
    #[error("launch I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Unknown or malformed placeholder in a command template.
    #[error("malformed launch template: {0}")]
    MalformedTemplate(String),
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{
        preset_docker, preset_polkajam, spawn, split_host_port, substitute, LaunchConfig,
        LaunchError,
    };

    fn test_config() -> LaunchConfig {
        LaunchConfig {
            spec_path: PathBuf::from("/tmp/m2-test/spec.json"),
            ed25519_secret_hex: "ab".repeat(32),
            bandersnatch_secret_hex: "cd".repeat(32),
            listen: "[::]:3000".to_string(),
            public_addr: "2001:db8::1:40000".to_string(),
            data_path: PathBuf::from("/tmp/m2-test/data"),
            log_level: "info".to_string(),
        }
    }

    /// Unique-per-call temp dir (parallel-test safe), removed by the caller.
    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("m2-launch-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn substitute_all_placeholders() {
        let cfg = test_config();
        let template = "{spec} {ed25519_secret} {bandersnatch_secret} {listen} {public_addr} {data} {log_level}";
        let out = substitute(template, &cfg).unwrap();
        assert!(!out.contains('{'));
        assert!(out.contains(&cfg.spec_path.display().to_string()));
        assert!(out.contains(&cfg.ed25519_secret_hex));
        assert!(out.contains(&cfg.bandersnatch_secret_hex));
        assert!(out.contains(&cfg.listen));
        assert!(out.contains(&cfg.public_addr));
        assert!(out.contains(&cfg.data_path.display().to_string()));
        assert!(out.contains(&cfg.log_level));
    }

    #[test]
    fn substitute_unknown_placeholder_error() {
        let cfg = test_config();
        let err = substitute("run --flag {bogus}", &cfg).unwrap_err();
        assert!(matches!(err, LaunchError::MalformedTemplate(_)));
    }

    /// polkajam defaults its data dir to `~/.local/share/polkajam/<chain-id>`
    /// and RESUMES that chain on the next run. A conformance run must start
    /// from the spec's genesis, so the preset has to isolate node state.
    #[test]
    fn preset_polkajam_isolates_node_state() {
        let cfg = test_config();
        let cmd = preset_polkajam(&cfg);
        assert!(
            cmd.contains(" --temp") || cmd.contains(" --data-path"),
            "polkajam must not reuse its default persistent data dir across \
             runs (stale chain state blocks sync/authoring); got: {cmd}"
        );
    }

    #[test]
    fn preset_polkajam_shape() {
        let cfg = test_config();
        let cmd = preset_polkajam(&cfg);
        assert!(cmd.contains("--chain"));
        assert!(cmd.contains("--mode validator"));
        assert!(cmd.contains("--key-seed-file"));
        assert!(cmd.contains(&cfg.spec_path.display().to_string()));
        assert!(
            cmd.contains("--listen-ip ::"),
            "bracketed IPv6 is split into a bare --listen-ip"
        );
        assert!(
            cmd.contains("--port 3000"),
            "the port is split out of the listen address"
        );
    }

    #[test]
    fn split_host_port_bracketed_ipv6() {
        assert_eq!(split_host_port("[::]:40000"), ("::", "40000"));
        assert_eq!(
            split_host_port("[::ffff:127.0.0.1]:40000"),
            ("::ffff:127.0.0.1", "40000")
        );
        assert_eq!(split_host_port("127.0.0.1:40000"), ("127.0.0.1", "40000"));
    }

    #[test]
    fn preset_docker_shape() {
        let cfg = test_config();
        let cmd = preset_docker(&cfg);
        assert!(cmd.contains("docker run"));
        assert!(cmd.contains("--network host"));
        assert!(cmd.contains("JAM_M2=1"));
        assert!(cmd.contains("JAM_M2_SPEC"));
        assert!(cmd.contains("JAM_M2_ED25519_SECRET"));
    }

    #[tokio::test]
    async fn spawn_and_kill() {
        let dir = temp_dir("spawn-kill");
        let mut nut = spawn("true", &dir).await.unwrap();
        let status = nut.child.wait().await.unwrap();
        assert!(status.success());
        // `true` already exited: kill must still be safe (ignored kill + reaped wait).
        super::kill(nut).await.unwrap();

        let err = spawn("/nonexistent/m2-launch-test-bin", &dir).await;
        assert!(err.is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn kill_running_process() {
        let dir = temp_dir("kill-running");
        let mut nut = spawn("sleep 30", &dir).await.unwrap();
        let pid = nut.child.id().unwrap();
        super::kill(nut).await.unwrap();
        // Killed and reaped: the child's /proc entry is gone.
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn stdout_redirected() {
        let dir = temp_dir("stdout");
        let mut nut = spawn("echo hello", &dir).await.unwrap();
        let status = nut.child.wait().await.unwrap();
        assert!(status.success());
        let stdout = std::fs::read_to_string(&nut.stdout).unwrap();
        assert!(stdout.contains("hello"));
        super::kill(nut).await.unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
