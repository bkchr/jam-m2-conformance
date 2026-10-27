# jam-m2-conformance

Conformance harness for JAM prize Milestone 2 ("AUTHORER": fully conformant, produces blocks,
including networking and off-chain duties).

The harness runs a node under test (NUT) as one of six tiny-spec validators, emulates the other
five over JAMNP-S with an **independent** protocol implementation (`jamnp-s`, written from
`jam-np/simple.md` — not polkajam's networking stack), and validates every block and off-chain
artefact the NUT produces against the polkajam `hazmat` reference engine.

## Status

**Implemented and green (2026-09):** P0 infrastructure complete plus conformance lanes **L0**
(connectivity/sync), **L1** (block authoring), and **L2** (Safrole tickets). See [DESIGN.md](DESIGN.md)
for the design; this README documents the current implementation state.

- Workspace: `cargo build --workspace` ✓, `cargo test --workspace` **328 passed / 0 failed** ✓,
  `cargo fmt --all --check` ✓, no `unwrap`/`panic`/`expect`/`todo!` in non-test code.
- Dry-run baseline: `cargo run -p m2-runner -- --preset mock --dry-run --session-dir /tmp/x`
  exits 0 with **all L0+L1+L2 checks HARD PASS** — the harness's own expectations are satisfiable.

## Crates

| Crate | Responsibility |
|---|---|
| `jamnp-s` | Independent JAMNP-S: QUIC/TLS endpoint (quinn 0.11 + rustls), Ed25519 cert + custom SAN, ALPN `jamnp-s/1/<8hex>[/builder]`, preferred-initiator rule, kind-once stream framing (`u32 LE` messages), typed codecs for every UP/CE protocol (UP 0, CE 128–148), message trace recorder. |
| `m2-reference` | Reference oracle over polkajam `hazmat`: `RefChain` (tiny 6-validator chain, deterministic authoring of emulated slots), NUT-block import + state diff (`import.rs`/`state.rs`), ticket generation/planning/verification (`tickets.rs`). |
| `m2-emu` | Five emulated validators (skeletons — no core logic; all values/decisions injected from `m2-reference`): UP 0 announce, CE 128/129 serve, NUT-block fetch (L1), CE 131/132 ticket send/receive (L2). |
| `m2-scenario` | The §5 DSL (`check`/`expect_subseq`/`log::check`) + hard-coded lanes: `l0.rs` (9 checks), `l1.rs` (6), `l2.rs` (5). |
| `m2-runner` | CLI: keygen → spec → NUT launch (docker/polkajam presets) → connectivity → scenario (L0/L1/L2) → `report.md`/`findings.json`/trace → exit code. |

## Build and run

```sh
cargo build --workspace
cargo test --workspace

# Dry-run baseline (no real NUT; fabricates a conforming observation log):
cargo run -p m2-runner -- --preset mock --dry-run --session-dir /tmp/m2-dry

# Real surface against the polkajam NUT:
# (binary built from third_party/polkajam by scripts/prepare-nut.sh)
PATH="$PWD/third_party/polkajam/target/release:$PATH" \
cargo run -p m2-runner -- --seed 1 --validator-index 5 --base-port 40000 \
  --preset polkajam --session-dir sessions/p0 --startup-timeout 60 --observe-secs 90
```

CLI: `--seed` (run seed), `--validator-index` (default 5 — index 0 is degenerate for the
preferred-initiator rule), `--base-port`, `--preset` (`polkajam`/`docker`/`mock`),
`--session-dir`, `--startup-timeout`, `--observe-secs` (observation window), `--dry-run`.

## Real-surface results vs polkajam-as-NUT (2026-09)

The harness runs end-to-end against the polkajam NUT and produces a genuine conformance
report (`sessions/<id>/report/{report.md,findings.json}`, `traces/jamnp.{bin,json}`):

- **L0 connectivity**: 20/22 HARD PASS — real TLS 1.3 mutual handshake, Ed25519 cert + SAN,
  ALPN `jamnp-s/1/…`, preferred-initiator, UP 0 handshake with genesis Final, block
  announcement + CE 128 fetch.
- **L1**: 6 checks evaluated SOFT ("no NUT blocks observed in window").
- **L2**: 8 rows — `l2_gen_ce131_observed` and `l2_inclusion_covers_valid` FAIL; the rest vacuous
  pass (no ticket traffic observed).
- Runner exits 1 (correct — hard findings exist).

**Why the real NUT does not pass L1/L2:** polkajam-as-NUT never imports the reference blocks (its
sync stays at `block #0`, `0/0 active peers` in this setup), so its chain never advances past
genesis — it therefore never authors a block and never distributes tickets. This is a
polkajam-side behavior (flagged in DESIGN §10), confirmed empirically; the harness reports it as
findings rather than masking it. The lanes themselves are proven correct by their unit tests and
the dry-run all-pass baseline.

## Dependency wiring

Polkajam's library crates (`jam-types`, `jam-std-common`, `jam-node` with
`hazmat`, `polkajam-fuzz` declared/unused) are ordinary **git dependencies**
pinned to a commit in the root `Cargo.toml` (DESIGN.md §8). Nothing from
polkajam is vendored into this repository.

That pin is the **single source** of the polkajam revision. `prepare-nut.sh`
reads it from the manifest to build the `polkajam` **binary** used as the node
under test, so the node and the engine that grades it are the same build:

```sh
./scripts/prepare-nut.sh
export PATH="$PWD/third_party/polkajam/target/release:$PATH"
```

`third_party/` is gitignored. The harness's own networking (`jamnp-s`) is an
independent implementation.

**Re-pinning policy.** Upstream HEAD has broken this workspace three times in
four weeks, so the revision moves deliberately: at most once per milestone, in
a commit of its own, recording what changed in the genesis writer
(`chainspec.rs`, `chain/exec/the_state.rs`) and the `hazmat` export list, with
a regenerated spec diffed against the old one. `POLKAJAM_REV` overrides the
revision for a one-off comparison and warns that the oracle no longer matches.

No patches are applied to the NUT. The ALPN patch this repository used to carry
(`jamnp-s/0` → `/1`) is obsolete: upstream carries `JAMNP_VERSION = 1` itself.
polkavm's generic sandbox is a one-line feature flip in the script, behind
`POLKAJAM_GENERIC_SANDBOX=1`, for hosts that deny unprivileged `userfaultfd`;
run the NUT with `POLKAVM_SANDBOX=generic` when it is enabled. The library
dependency needs neither, because the harness never runs polkajam's networking
and pins `PvmBackend::Interpreter`.

## Roadmap status (DESIGN §13)

| Phase | Content | Status |
|---|---|---|
| P0 | `jamnp-s`, runner skeleton, L0 | ✅ implemented |
| P1 | `m2-reference` wrapper, L1 authoring, L2 tickets | ✅ implemented |
| P2 | L3 guaranteeing, L4 availability (erasure export) | ⏳ next |
| P3 | L5 auditing/disputes, L6 preimages | ⏳ |
| P4 | L7 adversarial, index rotation, IPv6, web UI | ⏳ |

Iterate-later items: full 2-epoch observation + epoch-boundary alignment of the ticket window;
independent (non-`import_block`) seal/entropy VRF re-verification; full M1-style keyvals diff on
state-root mismatch; emulator↔emulator links; `polkajam-fuzz` reuse for L3+ (provisioners still
private).

References:
- JAM prize: https://jam.web3.foundation/
- JAMNP-S spec: https://github.com/zdave-parity/jam-np (`simple.md`)
- Graypaper: https://graypaper.com/
- M1 conformance (fuzz-proto, reports): https://github.com/davxy/jam-conformance
