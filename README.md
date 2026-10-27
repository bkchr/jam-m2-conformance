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

- Workspace: `cargo build --workspace` ✓, `cargo test --workspace` **348 passed / 0 failed** ✓,
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

## Real-surface results vs polkajam-as-NUT (2026-10)

The harness runs end-to-end against the polkajam NUT and produces a genuine conformance
report (`sessions/<id>/report/{report.md,findings.json}`, `traces/jamnp.{bin,json}`):

- **N0 connectivity and sync**: 26/27 HARD PASS — real TLS 1.3 mutual handshake, Ed25519 cert +
  SAN, ALPN `jamnp-s/1/…` with a mismatched ALPN refused, preferred-initiator split, 21 `/builder`
  connections accepted, UP 0 handshake with genesis Final, and the node's own CE 128 and CE 129
  replies graded. One hard finding: `ce129_boundary_parent_before_child`.
- **N1 authoring**: the node authors, the harness imports and grades each block — parent,
  seal, prior and posterior state roots. One hard finding: a block that left an owed ticket
  out with room to carry it (`l1_extrinsic_includes_delivered`).
- **N2 Safrole tickets**: the node accepts the emulator's tickets, runs its own lottery and
  distributes to proxies; proofs, target epochs, attempt ranges, per-epoch caps, proxy
  routing and inclusion are all graded. One hard finding: a ticket for an epoch past the
  node's horizon is rejected but the stream is not reset (`l2_unknown_epoch_reset_observed`).
- Runner exits 1 (correct — hard findings exist).

**On reading the lanes.** Every check asserts what the *node* does. Several used to be recorded by
the emulator's own serve path — the harness answering the node, then entering a pass for itself —
so they could not fail; the CE 128 and CE 129 rows are now driven by requests the emulator makes
and graded on the replies (`m2-emu/src/sync_probe.rs`). A check that could only ever pass is worse
than a missing one, so findings carry the values that disagreed.

The same audit over N1 and N2 found the defect in five more shapes, every one of which made a
conforming node look wrong or a wrong one look conforming. Tickets were sealed against entropy
buffer entry 1 where a node checks entry 2, so **every ticket the emulator ever offered was
rejected** — invisible because the two entries agree whenever an epoch boundary happens to fall
between proving and delivery, which a genesis anchored 28 epochs in the past made likely. That
anchor was itself a defect: it was computed before the tiny protocol parameters were applied, so
it divided by an epoch period of 600 instead of 12. Tickets were also proved against the chain
*before* it was seeded, carrying genesis entropy; the node's own tickets were charged as tickets
nobody delivered, though a validator's own tickets belong in its own block; one block was asked to
carry every valid ticket of the epoch against a cap of three; and inclusion was judged on the
newest block even when it fell outside the epoch those tickets could be submitted in.

Where a rule genuinely was not exercised the harness now says so rather than passing: a ticket
that arrived too late in the lottery to demand a forward, an epoch with no NUT block to judge, and
a proof for an epoch the harness holds no context for are reported as soft "not exercised" rows.

The N2 lane had the same fault in a different form. It told a proxied ticket from a self-proxied
one by the peer index a frame arrived at, in a space where the node's own index never appears —
making two checks unfailable — while requiring frames from a peer the run never emulates, making
two others unpassable. The lane now reads CE 131 from CE 132 off the stream kind, takes the
emulated set from the run, counts tickets rather than frames, and derives the epoch a ticket must
name from the moment it was sent rather than pinning one for the whole run. Three further rules
are reported as **not exercised** rather than passed when a run cannot reach them: a proof for an
epoch the harness holds no ring for, a proxied ticket delivered too late in the lottery for any
forwarding window, and an unknown-epoch probe that was never scheduled.

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
