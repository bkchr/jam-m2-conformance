# JAM M2 Conformance Harness — Design

Status: draft for review, 2026-09-03. Implementation now exists for P0 + N0/N1/N2 (see README.md); this document remains the design contract.

**Lane naming.** The M2 lanes are **N0–N7** (`N` for network). They were called L0–L7 in the first draft of this document and in the code, which collides with M1's L0–L3 — a different axis that already appears in the published conformance matrix. The reports this harness emits go to the same teams that read that matrix, so the names had to differ. The one L0–L3 left in this document, under §1, is M1's and stays as it is.

## 1. Goals and non-goals

The JAM prize defines Milestone 2 ("AUTHORER") as *"Fully conformant and can produce blocks (incl
networking, off-chain)"*. M1 conformance is covered by `polkajam-fuzz` and
[davxy/jam-conformance](https://github.com/davxy/jam-conformance) (fuzz-proto v1 over a unix socket:
`Initialize` / `ImportBlock` / `GetState`, state-root comparison, lanes L0–L3). Nothing covers M2:
no networking conformance, no authoring conformance, no off-chain duties (ticket generation,
guaranteeing, assuring, auditing, preimage handling).

**Goal.** A black-box harness that runs a node under test (NUT) as **one of six tiny-spec
validators**, **emulates the other five validators over JAMNP-S**, and uses the **fuzzer's reference
STF/authoring engine** to validate every block the NUT authors and every off-chain artefact it emits.

**Principles.**
- The harness has its **own JAMNP-S implementation**. It is a spec oracle and must not inherit the
  quirks of any node's networking stack (polkajam included, see §10).
- Emulated validators are **scenario-driven, not full nodes**. The scenario decides which messages are
  exchanged and when; emulated peers still *react* to NUT-initiated streams (serve blocks/state/shards,
  accept reports/assurances/judgments, take work-package submissions).
- Emulated validators are **skeletons, not nodes**: `m2-reference` computes ground truth exactly once
  and emits decisions; `m2-emu` never executes core logic (no PVM refinement, no erasure coding, no
  verification). Honest signals are derived from reference truth so emulation is indistinguishable from
  real validators; fault lanes override those signals deliberately.
- The NUT is launched from a **command template**; a **Docker preset** provides the M1-style
  `JAM_*` environment contract for submissions.
- Everything the harness does is **seed-deterministic**; everything the NUT does is **recorded** so a
  failure can be replayed at the message level.

**Non-goals (v1).** Full-spec (V=1023) emulation; GRANDPA/BEEFY (not part of JAMNP-S); performance
measurement (M3/M4); testing more than one NUT per run.

## 2. Inputs and normative references

| Input | Location | Notes |
|---|---|---|
| JAMNP-S spec | `jam-np/simple.md` (HEAD 2026-09-02, untagged) | Only file in the repo. ALPN protocol version `1`. Line numbers below refer to it. |
| Graypaper | `graypaper/` v0.8.0 | Off-chain duties: `text/work_packages_and_reports.tex:15` (Honest Behavior), `guaranteeing.tex`, `assurance.tex`, `auditing.tex`, `best_chain.tex`, `safrole.tex`. |
| Reference engine | `polkajam/crates/polkajam-fuzz` (lib + bin), `polkajam/crates/node` (`hazmat` feature) | Authoring engine, STF import, state diff, mutation engine. |
| Tiny parameters | `w3f/jamtestvectors` README | V=6, C=2, E=12, Y=10, N=3, rotation R=4, EC recovery 2 shards. |

Tiny derived numbers used throughout: grid width W=⌊√6⌋=2 (rows {0,1},{2,3},{4,5}; columns
{0,2,4},{1,3,5}); three guarantor rotations per epoch (slots 0–3, 4–7, 8–11); `max(⌊E/30⌋,1)` =
`max(⌊E/60⌋,1)` = `max(⌊E/20⌋,1)` = 1 slot; epoch = 72 s.

Key wire facts: QUIC + TLS 1.3, Ed25519 self-signed X.509 with a single SAN `e` + base32(pubkey, 52
chars) (`:30-43`); ALPN `jamnp-s/1/<first 8 hex nibbles of genesis header hash>[/builder]` (`:48-59`);
endpoints in validator metadata bytes 0..18 = IPv6 + LE u16 port (`:66-68`); preferred-initiator
tie-break `P(a,b)` with ~5 s grace (`:70-80`); one stream-kind byte then `u32 LE len ++ GP-codec
content` messages (`:122-130`). Stream kinds: UP 0; CE 128, 129, 131, 132, 133, 134, 135, 136, 137,
138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148. There is no CE 130.

## 3. Architecture

```
 ┌──────────────────────────────── jam-m2-conformance (Rust workspace) ────────────────────────────────┐
 │                                                                                                      │
 │  m2-runner (bin)      scenario check functions ──► Scheduler (event-driven) ──► Report         │
 │        │                                             │                                               │
 │        │ spawns NUT (cmd template / docker preset)   │ drives                                        │
 │        ▼                                             ▼                                               │
 │  ┌───────────┐    QUIC/JAMNP-S     ┌──────────────────────────────┐    ┌────────────────────────┐    │
 │  │    NUT    │◄───────────────────►│ jamnp-s (lib)                │    │ m2-reference (lib)      │    │
 │  │ validator │  5 endpoints, one   │ - endpoint/cert/ALPN         │◄──►│ polkajam-fuzz + jam-node│    │
 │  │  index k  │  Ed25519 id each    │ - UP/CE stream codecs        │    │  (hazmat): STF import,  │    │
 │  └───────────┘                     │ - per-peer reactive handlers │    │  authoring tables,      │    │
 │                                    │ - message trace recorder     │    │  signing for emulated   │    │
 │                                    └──────────────────────────────┘    │  keys, refine, EC       │    │
 │                                                                        └────────────────────────┘    │
 └──────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

| crate | responsibility |
|---|---|
| `jamnp-s` | Independent JAMNP-S: QUIC endpoint (quinn 0.11 + rustls), Ed25519 self-signed cert and SAN derivation, ALPN, preferred-initiator rule, stream-kind byte, `u32 LE` framing, typed codecs for every UP/CE message (GP codec via `jam-types`/`codec`), request/response helpers, full message trace recording, and the transport and clock boundaries below. No policy. |
| `m2-reference` | Wrapper over `polkajam-fuzz` (lib) + `jam-node` (`hazmat`): reference chain state for the 6-validator net; authors blocks for emulated slots; signs tickets/guarantees/assurances/judgments/audit announcements with the five emulated keysets; refines work packages; erasure-codes bundles and builds justifications; imports NUT blocks and diffs state. |
| `m2-emu` | The five emulated validators plus an optional builder / non-validator peer. One `jamnp-s` endpoint each; reactive handlers (serve CE 128/129/137/138/139/140/147/148/136/143; accept UP 0, CE 131/132/134/135/141/142/144/145/133/146); every inbound and outbound message goes to the observation log. Behaviour is data-driven by the scenario: `m2-emu` executes **no core protocol logic** — every value (report results, segments, shards, proofs) and every decision (audit verdicts, assurance bits) is computed once by `m2-reference` and injected; `m2-emu` only keeps per-peer state, frames, and signs. |
| `m2-scenario` | Scenario model and scheduler: steps keyed by `(slot_rel, offset_ms)`; actions (emulated side) and expectations (NUT side) with severity; lanes are scenario collections. |
| `m2-runner` | CLI: generates spec and keys, launches the NUT (command template / preset), runs the scenario, writes report and traces, sets the exit code. |
| `m2-sim` | A simulated node under test: an in-process stand-in the harness can grade, honest or deliberately broken. Not a node — it keeps no state machine and validates nothing — but node-shaped enough for a lane to grade, which is what makes a check's ability to fail testable. |

Dependencies on polkajam are git dependencies pinned to a commit (see §8 for the small changes
polkajam needs first).

**The transport boundary.** `jamnp_s::transport` is what everything above `jamnp-s` sees of a
connection: open a bidirectional stream, accept one, write, finish, reset, read, stop. Two
carriers implement it — `transport::quic` over QUIC, which is what grades a real node, and
`transport::mock`, which carries the same streams between tasks in one process. No crate above
`jamnp-s` depends on `quinn` at all, so the boundary is enforced by the build and not by
convention.

Two properties of that boundary are load-bearing, because a lane reads them rather than the
bytes. **A reset is not an error**: `ReadError::Reset` carries the peer's application error
code, which is how the harness sees a node refuse a ticket (`simple.md:335-337`) and what two
N2 checks are built on. **A stream has a number**, unique for the life of its connection, which
is how a trace groups frames. Both are asserted against both carriers by the same tests, so a
carrier that lost one would fail rather than quietly make a check unobservable.

The mock authenticates nothing: no TLS, no certificate, no ALPN. The N0 rules about those are
properties of the QUIC carrier and are graded there; a run on the mock cannot exercise them.

**The clock boundary.** `jamnp_s::clock` is the other injectable the milestone asks for. A run
is a calendar — which slot a frame belongs to, when a ticket is due, how long to watch before
grading — and all of it is arithmetic on a timestamp. `SystemClock` is the machine's clock and
is what grades a real node, whose slots really do take six seconds. `VirtualClock` is time that
moves only when the runtime moves it, so a run against a *simulated* node costs the time the
computation takes rather than the time the protocol describes. One clock is installed per
process, before anything reads it, and `trace::mono_ts`/`trace::wall_ts` read it — a trace has
to carry the same calendar the waits that produced it were keeping, or the lanes would grade
frames against a clock nothing else is on.

Only the protocol's own waits moved onto it: the slot boundary, the epoch wait, the ticket
sender's delivery target and readiness poll, the initiator grace, the CE 129 probe delay and
the observation window. Waiting for a node *process* to start, or for a port to answer, is not
protocol time — it is about another program on this machine — and stays on the real clock
however the harness is run.

**What the two seams are for.** A check is an assertion about a node, and until a node makes
the mistake it describes, nobody knows whether it can fail. Every live run this harness has
done was against polkajam, which does not make those mistakes — which is why two harness
defects survived for weeks, passing a check that was grading the harness's own intentions.
`m2-sim` closes that: on the in-process carrier and the virtual clock, a deliberately broken
node can be graded in milliseconds, and a check that fails against it and passes against the
honest one has been *shown* to work. The test asserts the broken row is present **and**
failing: a row the grading never produced caught nothing, and accepting its absence would be
the same vacuous pass the lanes' own controls exist to prevent.

## 4. Run lifecycle

1. **Spec and key generation.** The runner picks the NUT's validator index `k` (default 0) and a base
   port. Emulated validators `v ≠ k` use deterministic keysets derived from the run seed
   (`SecretKeyset::trivial(i)`-style, `jam-std-common/src/keyset.rs:151-161`). NUT secrets are
   generated and handed over (§7). Validator metadata carries each validator's IPv6 endpoint and port.
   Genesis header has slot 0. The spec file (§7) is written to the run directory.
2. **NUT launch.** Command template substitution; the Docker preset runs
   `docker run --network host -e JAM_M2_* <image>`. The runner probes the NUT's QUIC port until a
   handshake succeeds or the startup timeout expires.
3. **Connectivity phase.** Each emulated validator that is the preferred initiator towards the NUT
   connects immediately; the others wait for the NUT to connect (5 s grace, then connect anyway and
   record a soft finding). Certificate, SAN and ALPN checks are recorded as assertions.
4. **Scenario execution.** The scheduler is event-driven: it fires each check's stimulus when its
   dependencies are satisfied, then matches the expected answer sequence against the observation log
   (§5). Blocks for emulated authors' slots are produced by `m2-reference` and announced (UP 0) and
   served (CE 128) like a real author.
5. **NUT block handling.** On a UP 0 announcement from the NUT: fetch via CE 128 from the NUT, import
   with the reference STF, compare state roots, check the header (seal, entropy VRF, markers, slot ≤
   wall clock), and check the extrinsic against the delivery ledger (inclusion of every valid item the
   scenario fed the NUT in time, exclusion of every injected-invalid item). Optionally
   (`--fuzz-sock`), if the NUT also exposes its M1 fuzz-proto socket, `GetState` after each NUT block
   yields a full state diff. Not required.
6. **Teardown and report.** Kill the NUT, collect its stdout/stderr, write `report.md`,
   `findings.json`, JAMNP trace and reference chain dump (§9). Exit code 0 iff all hard assertions
   passed and the scenario reached its final slot.

## 5. Scenario model

A scenario is a **conversation script**: for every stimulus the harness sends, the NUT's expected
**answer** is a sequence of messages that must appear in the observation log in response. Sequences
are **hard-coded in Rust** — authoring them in an external format (TOML/JSON) buys nothing and adds
a parser, a validation layer, and indirection for no benefit; the checks are code and need the full
expression power of code. Rust is also the language a conformance reviewer already needs to read
(the reference engine and harness both are it), so it doubles as the "spec as code" deliverable.

```rust
// src/scenarios/l3.rs — one function per scenario
use crate::{check, log, stimulus::{self, *}, expect::Seq as *};

/// N3: a work-package is submitted to the NUT; it must refine, share (CE 134 ×2)
/// with its co-guarantors and report (CE 135) to all validators.
pub fn wp_refine_and_report(net: &mut Net, sched: &mut Scheduler) -> CheckId {
    check("wp_refine_and_report", sched, |obs| {
        net.submit_wp(builder, nut, /*core*/ 1, /*profile*/ Full(Rng::seed(&seed, 7)));

        // The answer: sharing before the report leaves the NUT. Anything else in between
        // is allowed and recorded, just not counted towards the check.
        obs.expect_subseq(vec![
            // window relative to the previous matched event, not a slot offset,
            // checked with a soft-finding fallback for tolerance clauses.
            Obs::from(nut).ce134_msg1(to coguarantors).within(3s)  // Core ++ ShardCount ++ len++[…]
                .verify(|m| m.core == 1),
            Obs::from(nut).ce134_msg2(to coguarantors).within(1s)  // bundle bytes, byte-identical
                .verify(|m| m.bytes == reference_bundle()),
            Obs::from(nut).ce135_report(to all).within(2s)         // Report ++ Slot ++ len++[(Idx,Sig)]
                .verify(|m| m.report == reference_refine()),
        ]);

        // Standalone extra check on top of the sequence (runs regardless of the above :within):
        log::check("ce134_msg1_shard_count_is_6",
            obs.first::<Ce134Msg1>().map(|m| m.shard_count == 6),
            Severity::Hard);
    })
}
```

```rust
// src/scenarios/l7.rs — a fault as a delta: reuse an existing sequence, inject the failure
pub fn equivocating_emulated_author(net: &mut Net, sched: &mut Scheduler) -> CheckId {
    check("equivocating_emulated_author", sched, |obs| {
        // reuse the authoring base, then override the emulated slot with a second block
        let base = l1::authoring_basic(net, sched);
        net.fault(Fault::EquivocateAuthor /* bad sig, wrong slot, duplicate, … */);
        // same expectation, one-step window
        obs.expect_subseq(vec![Obs::from(nut).authors_block().within(0s, 4s)]);
    })
}
```

**Semantics.** Each check reads as "we did X; the NUT must answer with A, B, C":

- Expectations are matched as a **subsequence** of the observation log: messages in between are
  allowed and recorded, they just don't count towards the check. Order between listed events is
  enforced (CE 134 msg 1 before msg 2 before CE 135); anything not listed is ignored unless it is
  *invalid* for the protocol, which fails the check.
- Timing windows are **relative to the previous matched event** (`within(3s)`), not to a slot offset —
  "reach the expected point within a reasonable time". If a window expires the check fails (or is a
  soft finding for timing-tolerance clauses).
- A check fires after its dependencies are satisfied; a `trigger` variant fires when a prior
  expectation is observed (e.g. "once the CE 135 report is seen, we request shards"). `at_slot` is
  only used where the protocol itself is slot-relative (authoring, ticket epochs, assurance timing).
- `depends_on` gives ordering and fail-fast: if the NUT never opens CE 134, we never request shards,
  and the scenario stops at the first hard failure.
- **Extra checks live in the same check body**: `log::check(...)`-style assertions on the
  observation log (shard count is 6, WPHash equals reference, size caps, sorted keys, exclusive
  ranges) are embedded Rust checks that run alongside the sequence — they are how the §11 check
  catalogue's "asserts" column is expressed.**

```rust
// the plain assertions from §11 that need no stimulus fall out of the same DSL:
pub fn upgrade_asserts(net: &mut Net, sched: &mut Scheduler) -> CheckId {
    check("ce129_key_shape", sched, |obs| {
        net.send(emu0, Ce129Request{ range: KeyRange::AscExclusive(known_root) });
        obs.expect_subseq(vec![Obs::from(nut).serves_ce129()
            .verify(|m| { m.keys_sorted() && m.boundaries_parent_before_child() && m.len_prefixed_values() })]);
        log::check("ce129_size_cap", obs.last::<Ce129Served>().map(|m| m.size() <= max_size), Severity::Hard);
    })
}
```

**Hard-coded sequences + on-top tests, in one bucket.** Each scenario file is a module of `check`
functions; a scenario "runs" by executing its checks in dependency order. A standalone
JavaScript/TypeScript port of the sequence DSL is planned as a v1.1 companion so the conformance
group can hand-verify scenarios without the Rust toolchain — the Rust version is the source of truth.
(§7 keeps the machine-readable *spec file* that a NUT consumes; it is not a scenario format.)

**Stimuli (emulated side).** `connect` / `accept`, `announce_block`, `send_tickets`,
`submit_work_package`, `submit_bundle`, `share_work_package`, `distribute_report`,
`request_shards` (CE 137/138/139/140/148), `request_ce129`, `send_assurances`, `announce_preimage`,
`announce_audit`, `publish_judgment`, `skip_slot`, `kill_nut` / `restart_nut`, and `inject_fault`
(a mutation applied to any of the above: bad signature, wrong slot, duplicate, oversize, wrong
stream kind, truncated frame, stream reset mid-message; the mutation vocabulary follows
`polkajam-fuzz/src/mutator.rs`).

**Expected-answer events (NUT side).** `accept`, `open_up0`, `up0_announce`, `serves_ce128`
`serves_ce129`, `sends_tickets`, `ce134_msg1 { wphash, segroot }`, `ce134_msg2 { bytes }`,
`ce135_report { matches, sigs }`, `serves_ce137/138/139/140/147/148/136/143`,
`ce141_assurance`, `ce142_announce`, `ce143_request`, `ce144_announce`,
`ce145_judgment { validity }`, `authors_block { valid, on_time, includes, excludes }`,
`resets_stream`, `ignores` (no message, or no inclusion), `state_root_matches`.

**Severity.** `hard` fails the scenario; `soft` is reported only (timing outside tolerance,
"should" clauses, e.g. serving CE 148 when 139/140 would do).

**Role control.** Because the harness holds five of six keysets and sees every ticket, it knows in
advance who authors, guarantees, assures and audits what:

| Role | How the scenario forces it |
|---|---|
| Block author at slot s | Fallback mode: author sequence derived from η'₂. Ticket mode: harness owns the five emulated tickets and receives NUT tickets via CE 131/132, so the per-slot author is known before the epoch starts. Expectations are phrased as "the next slot the NUT authors". |
| Guarantor of core c | `rotate(shuffle([0,0,0,1,1,1], η'₂), ⌊(s mod 12)/4⌋)` (GP `reporting_assurance.tex:230-236`). Work packages are submitted in a rotation where the NUT guarantees the target core; the two other validators on that core are the co-guarantors. |
| Assurer | Every validator. NUT's shard index is `i = (2c + k) mod 6` (`:506-521`). |
| Auditor | Tranche 0 selects min(10, #reports) cores, so in tiny every validator audits every report at tranche 0. Audit tests are deterministic. |
| Ticket proxy | `BE_u32(vrf_out[28..32]) mod 6` over the *next* epoch's validator list (`:318-325`); about one in six emulated tickets has the NUT as proxy. |
| Grid neighbour | With W=2 and k=0: neighbours 1, 2, 4; non-neighbours 3, 5 (`:182-190`). |

**Scenario catalogue.** Scenarios are hard-coded modules under `src/scenarios/<lane>/`; the runner
executes their checks and renders a coverage table (§11 row ↔ scenario module) into every
`report.md`. A module whose expectations are unsatisfiable (checked by simulating it against
`m2-reference` in virtual time before any NUT is spent) is rejected up front.

- Slot `s` starts at `JAM_COMMON_ERA + 6·s` (`jam-types/src/simple.rs:13`, 1735732800). Genesis
  has slot 0 (`jam-std-common/src/header.rs:70`); the first authored block carries the current
  wall-clock slot. The harness sets its reference `next_slot = (now − JCE) / 6` at start. Scenario
  timings are event-relative (`within_ms` windows, §5); a check pins to a slot only where the
  protocol is slot-relative. Lanes that need "start of epoch" wait for `slot % 12 == 0` (at most 72 s).
- The reference authoring engine is virtual-time (`node/src/chain/authoring/harness.rs:49,208-216`)
  and only claims a slot if its keystore holds the author's Bandersnatch key
  (`node/src/chain/authoring/mod.rs:431-458`). With only the five emulated keysets loaded it skips the
  NUT's slots by itself.
- Slot duration is a runtime parameter in polkajam (`slot_period_sec`, `jam-types/src/simple.rs:285`)
  but both tiny and full keep 6 s and other implementations hard-code it. The design uses P = 6 s and
  does not try to shrink it. A full lane set takes on the order of 30 minutes per target; parallel
  runs use disjoint port ranges.
- Intra-slot phases come from jam-np, not the graypaper: assurances ~2 s before the slot (`:679-680`);
  assurer keyset switch +4 s and author keyset switch −2 s around epoch start (`:680-684`); ticket
  proxy step after `E/60` and direct step after `E/20` slots (`:329-332`); third-guarantor grace 2 s
  (`:465-467`); audit tranche 8 s (GP `auditing.tex:30`). Polkajam's constants match
  (`node/src/util/periodic_event.rs:11-30,159`, `MAX_CLOCK_DRIFT` 250 ms).
- Default tolerances (soft in v1): NUT block announced within `[slot_start, slot_start + 4 s]`;
  assurance received within `[slot_start − 4 s, slot_start]`; CE 135 within 2 slots of the CE 133
  submission; tickets delivered before slot 10 of the epoch. Ordering and validity are hard.
- Lane sizing: N0 one epoch; most lanes two to three epochs so that epoch transitions and the
  rotation period (4 slots) are exercised.

## 7. Node-under-test contract

**Spec file** (JSON, one per run; proposed as the M2 standard):

```json
{
  "id": "m2-<seed>",
  "parameters": { "validators": 6, "cores": 2, "epoch_length": 12, "ticket_submission_end": 10,
                  "tickets_per_validator": 3, "rotation_period": 4, "max_lookup_anchor_age": 24,
                  "min_turnaround_period": 32, "slot_period_sec": 6, "...": "remaining GP constants" },
  "genesis_header": "0x…",
  "genesis_state": { "0x<31-byte key>": "0x<value>" },
  "bootnodes": []
}
```

Header plus key/values is what every M1 target already parses from fuzz-proto `Initialize`; named
parameters make tiny-specific values explicit (polkajam's tiny sets `max_lookup_anchor_age = 24` and
`min_turnaround_period = 32`, `jam-types/src/simple.rs:381-386`). Bootnodes are unnecessary because
validators locate each other via on-chain metadata (`:61-68`); the field stays optional. Polkajam
needs a small adapter from this format to its own spec JSON (`node/src/chainspec.rs:190-310`).

**Validator metadata** (`jam-std-common/src/keyset.rs:17-24`): `PeerAddr { ip: [u8;16], port: u16 LE }`
first (18 bytes, as in jam-np), then P-256 id, then filler. IPv4 loopback is written IPv4-mapped
(`::ffff:127.0.0.1`); a lane variant uses `::1` to exercise real IPv6 handling.

**Keys.** The NUT's public keys are in genesis, so its secrets are handed over explicitly rather than
as a single seed (a seed would force every team onto one derivation scheme): raw 32-byte Ed25519 and
Bandersnatch secrets, BLS optional (zero placeholder as in polkajam `keyset.rs:78-95`).

**Environment contract** (mirrors M1's `JAM_FUZZ_*`):

| variable | meaning |
|---|---|
| `JAM_M2=1` | enable M2 conformance mode |
| `JAM_M2_SPEC` | path to the spec file above, in the M2 standard format (`spec-m2.json`) |
| `JAM_M2_ED25519_SECRET`, `JAM_M2_BANDERSNATCH_SECRET` | hex, 32 bytes each |
| `JAM_M2_LISTEN` | `[::]:<port>` |
| `JAM_M2_PUBLIC_ADDR` | `<ipv6>:<port>` as carried in genesis metadata |
| `JAM_M2_DATA_PATH`, `JAM_M2_LOG_LEVEL` | as in M1 |

**Launch.** Command template with placeholders `{spec} {m2_spec} {ed25519_secret}
{bandersnatch_secret} {listen} {public_addr} {data} {log_level}`. `{spec}` is polkajam's native
format and `{m2_spec}` the M2 standard one; a preset passes whichever its node reads, and only
the `polkajam` preset reads the former. Presets: `docker` (host network, because QUIC is UDP and
the NUT must be able to *initiate* connections under the preferred-initiator rule) and `polkajam`
(`polkajam --chain {spec} run --key-seed-file … --listen-ip … --port … --mode validator`, once the
spec adapter exists).

## 8. Reference engine: reuse and required polkajam changes

`polkajam-fuzz` is a library (`crates/polkajam-fuzz/src/lib.rs:14-50`) re-exporting
`jam_node::hazmat::{AuthoringHarness, ImportBlockParams, ImportBlockResult, …}`, `Report` and
`StateDiff`. Importing a foreign block is `Chain::import_block(.., ImportParams::new_exec(hash))`
(`node/src/chain/mod.rs:765`), already used by the fuzzer's local target path. The following small
changes in polkajam are prerequisites:

1. Make the provisioners `tickets`, `guarantees`, `assurances`, `preimages`, `disputes`, `builder`
   public (`lib.rs:21-31`) and parameterise them on an explicit RNG instead of the global
   `rng_context!`, so a step can say "validator 3 produces its tickets now" deterministically.
2. `create_harness` (`fuzzer.rs:718`) loads all six `dev_validators_secrets()` (`fuzzer.rs:754`); add
   a constructor taking a keyset subset (`Keystore::from_secret_keysets` / `insert_keyset`,
   `node/src/keystore/mod.rs:146,207`).
3. Return signed artefacts instead of submitting them to the pool: `compose_guarantee`,
   `try_compose_assurances`, `table_tickets` (`harness.rs:352,574,621`) for a chosen validator index.
   The harness sends them over JAMNP and optionally feeds the reference pool.
4. Hazmat export for "bundle → erasure shards + justifications + segment proofs" (today inside
   `jam-node` `availability` / `util::erasure`), needed to serve CE 137/138/139/140/147/148 byte-exactly.
   The exact surface still needs inspection.
5. Keep the `ark-vrf` `test-vectors` feature (`polkajam-fuzz/Cargo.toml:35-37`) for deterministic
   RingVRF proofs on the harness side.

Reference computations the lanes need (union): STF import and state diff; deterministic authoring for
emulated slots; best-chain tracking; signing with five emulated keysets (seals, entropy VRF, RingVRF
tickets, guarantees, assurances, judgments, audit s₀/sₙ); refine (PVM) of scenario work packages
into report, exported segments and bundle bytes; authorizer evaluation; erasure coding (6 shards,
recovery 2), `M_B`, co-paths `T`, segment proofs; guarantor-assignment, author-per-slot, grid and
proxy calculators; a delivery ledger (item, peer, timestamp) to derive inclusion/exclusion. These
run exactly once in `m2-reference`; `m2-emu` consumes the outputs and never recomputes them.

**Relationship to `polkajam-fuzz` (what is and is not reused).** The M1 fuzzer is a seed-driven
generator and white-box mutator, not a repository of named test cases: its "cases" are produced on
the fly by its built-in authoring engine, and its conformance mode speaks fuzz-proto over a unix
socket (synchronous `Initialize`/`ImportBlock`/`GetState` requests). Neither maps onto M2's JAMNP-S
surface, so the harness does **not** replay fuzzer sessions and does **not** adopt fuzzer-generated
scenarios. Reuse is limited to:

- the `hazmat` reference engine as the **oracle** (§3 above);
- the mutation vocabulary (`mutator.rs`) as the primitives behind `inject_fault` (§5);
- the `FUZZ_PROTOCOL_TRACE_DIR` framing for `trace/jamnp.bin` and the
  `TraceStep { pre_state, block, post_state }` shape for per-block records (§9);
- the M1 `JAM_*` environment contract and spec-file parsing as the model for the M2 contract (§7).

The one *content* reuse is the fuzzer's **work-package generator**: scenarios wrap new, curated
JAMNP-S choreography around fuzzer-generated package content (`profile = "full"`, §5). The fuzzer
may additionally be run as a bug-finding pass on top of the conformance suite — complementary, not a
substitute for the catalogue.

## 9. Traces and reports

- The harness side is seed-deterministic; the NUT side is not (randomised RingVRF proofs, connection
  timing). Replay is therefore at the **message level**, not the state level.
- `trace/jamnp.bin` (+ JSON mirror): every JAMNP message with direction, peer index, stream kind,
  stream id, monotonic and wall timestamps, raw bytes; framing as the `FUZZ_PROTOCOL_TRACE_DIR` dumps
  (`polkajam-fuzz/src/remote.rs:53-59`).
- Every NUT block also recorded as a fuzz-style `TraceStep { pre_state, block, post_state }`
  (`polkajam-fuzz/src/trace.rs:64-68`), so an authoring divergence can be re-checked offline with the
  M1 minifuzz tooling by any team.
- `findings.json` (severity, spec citation, slot, evidence pointer into the trace) and `report.md`
  rendered like `fuzz-reports/<gp>/<target>/`. Session directory layout
  `sessions/<id>/{logs,traces,report}` as in `scripts/fuzz-workflow.py`, so the existing fuzz web UI
  can list M2 sessions.

## 10. Known discrepancies to flag (polkajam vs spec)

- ALPN: polkajam emits `jamnp-s/0/…` (`node/src/net/mod.rs:99-105`); the spec says version `1`
  (`:51-53`). Polkajam's prefix `u32::from_be_bytes(first 4 bytes)` formatted `{:08x}` equals "first
  8 nibbles". Polkajam as NUT fails N0 until it bumps the version.
- Polkajam defines CE 149–152 (GRANDPA vote/commit/state/catch-up), absent from the spec. The harness
  refuses unknown kinds; a NUT opening an unknown kind is a soft finding.
- Finality is unspecified in jam-np (polkajam default `FinalityMode::Dummy`, `node/src/node/config.rs:404`).
  The harness defines "finalized" for the CE 128 exclusion rule and the epoch-transition rule
  (default: depth ≥ 2) and advances `Final` in its UP 0 messages accordingly.
- Polkajam also offers `h3` ALPN and a P-256 certificate for WebTransport (`net/endpoint.rs:157,216`);
  the harness offers only `jamnp-s/1/…`.
- CE 134's explicit `Shard Count` is the newest spec change (jam-np commit `06a2fe9`); verify
  polkajam's `WorkPackageSharing` sends it before using it as reference.
- Ticket attempts per validator: §2 records tiny `N = 3` from the `w3f/jamtestvectors` README, and
  that figure predates GP 0.8.0. Polkajam carried an explicit `tickets_attempts_number` (tiny = 3)
  until `7b7993c8 GP 0.8.0 (#1024)` replaced it with a quantity derived from two parameters that
  remain, `tickets_per_validator(val_count) = ⌈2·E / V⌉ = ⌈24/6⌉ = `**`4`**, applied as the cap at
  all three points it matters — generation, the CE 131 attempt check, and the Safrole STF. This
  harness targets GP 0.8.0 (§2) and pins a revision after that change, so **4 is the live figure**:
  it generates and judges against 4, and `spec-m2.json` declares 4. §2's `N = 3` is the stale one
  and is kept only as the provenance of the number. Confirm with the conformance group that the
  tiny vector set has followed GP 0.8.0 here; if it has not, a node built to the vectors will make
  three attempts where the harness expects four, and `m2-runner`'s
  `m2_spec_parameters_match_the_engine` is where that surfaces.

## 11. Lanes and check catalogue

Line numbers refer to `jam-np/simple.md`. Severity is hard unless marked *(soft)*.

### N0 — connectivity and sync (1 epoch)

| Check | Emulated side | Assertions on NUT | Faults → expected |
|---|---|---|---|
| TLS cert `:7-23` | spec-conformant Ed25519 self-signed certs | Ed25519 signature algorithm; key = on-chain Ed25519 key; exactly one SAN `e`+base32(key,52) `:30-43`; TLS 1.3 mutual | wrong SAN / RSA / two SANs / no cert → NUT closes connection |
| ALPN `:48-59` | `jamnp-s/1/<8 hex nibbles>` | NUT accepts it and offers the same when initiating; `/builder` accepted on NUT's accept side | `jamnp-s/0/…`, wrong nibbles → handshake fails |
| Preferred initiator `:70-80` | preferred emulated peers connect at once, others wait | NUT initiates where preferred within 5 s; accepts the others; no duplicate connection *(soft)* | preferred emulated peer never connects → NUT connects after ~5 s *(soft)* |
| Endpoint decoding `:66-68` | IPv6 + LE port in metadata[0..18] | NUT dials the exact address and port | one peer with port 0 → NUT tolerates it |
| Builder slots `:82-84` | 21 connections with `/builder` | ≥20 accepted *(soft)*; CE 133 accepted on any connection `:56-57` | — |
| UP 0 handshake `:192-236` | open UP 0 on initiated connections, send `Final ++ len++[Leaf]` | NUT opens UP 0 on connections it initiated, to grid neighbours *(soft if to all)*; kind byte 0; handshake Final = genesis; `u32 LE` framing | duplicate UP 0 → keep greatest stream id, reset other `:111-114`; malformed → reset |
| UP 0 announce | emulated author announces within 500 ms | NUT re-announces every valid block it learns or authors unless a descendant is announced `:207-212`; `Header ++ Final`, Final is an ancestor | invalid seal → no re-announce, at most one CE 128 fetch; non-descendant of finalized → may ignore |
| CE 128 serve `:238-265` | ascending-exclusive and descending-inclusive requests | ordered, ≤ Max, both halves FIN; ascending from genesis equals the reference chain; unknown hash → reset | Max=0, Max=2³²−1 (must cap), Dir=2 → reset |
| CE 128 fetch | reply to NUT requests | after an announcement of an unknown block the NUT fetches missing parents; never re-fetches known blocks *(soft)* | wrong-parent block → not announced; reset → retry another peer *(soft)* |
| CE 129 `:267-303` | ranges with various Max Size | 31-byte sorted keys in range; boundary nodes parent-before-child, no duplicates `:275-281`; size cap `:283-285`; `len++` values | unknown hash → reset |

### N1 — block authoring, fuzzer-validated (2 epochs)

| Check | Assertions | Faults |
|---|---|---|
| Timing | NUT block for its slot announced within `[slot_start, slot_start + tolerance]`; header slot ≤ wall-clock slot | — |
| Parent | equals the reference best block (descends from finalized, no equivocation, audited; GP `best_chain.tex`) | equivocating emulated author → NUT builds on neither |
| Header and seal | seal and entropy VRF verify against the NUT's Bandersnatch key; markers as reference; extrinsic hash matches body | — |
| State root | reference STF import succeeds and root equals header root; otherwise an M1-style diff report (optionally via NUT fuzz socket `GetState`) | — |
| Extrinsic completeness | includes every valid ticket/guarantee/assurance/preimage/judgment delivered ≥2 s before the slot; excludes every injected-invalid item; assurance anchor = parent | item delivered 200 ms before the slot → inclusion optional *(soft)* |
| Skipped slots | emulated author skips → NUT's next block has the gap and the correct parent | — |

### N2 — Safrole tickets, CE 131/132 `:305-349` (2 epochs)

| Check | Assertions | Faults |
|---|---|---|
| Generation, step 1 (NUT → proxy, CE 131) | ≤ `A` tickets per epoch; proxy drawn from the next-epoch validator set, by the selection rule below *(soft)*; from slot ≥ epoch_start+1; `Epoch(next) ++ Attempt(<A) ++ [u8;784]` `:340-346`; proof verifies against ring root and η'₂ | — |
| Self-proxy (CE 132) | tickets the NUT generated **and** is itself the proxy for go directly to all current validators `:322-325`. A ticket it forwards as another validator's proxy is the row below, not this one | — |
| Proxy duty (accept 131, send 132) | verify, then forward to all five emulated; the forward is not before the arrival and lands inside the lottery (phase < `Y`); window per the formula below *(soft)*; stop after finalized inclusion *(soft)* | bad proof / wrong proxy / wrong epoch → no forward, no inclusion; slot ≥ `Y` → not included |
| Inclusion | NUT blocks have all valid received tickets, sorted, deduplicated; empty extrinsic when slot ≥ 10 | duplicate → once |
| Unknown epoch | ticket for epoch+2 → reset `:335-337` | — |

`A` is the per-validator attempt cap, `tickets_per_validator(V) = ⌈2·E / V⌉` — **4** under
tiny, not the `N = 3` of §2, which predates GP 0.8.0 (§10). `Y` is `epoch_tail_start`, 10
under tiny.

**Proxy selection.** `proxy_index(ticket_id, V) = u32::from_be(ticket_id[28..32]) mod V`,
over the *next-epoch* validator set. Whether this is normative or implementation-defined is
§12 question 9; the harness grades it soft until that is settled. Note that set membership
on its own is not gradable with this topology — the harness holds endpoints only for
validators, so a CE 131 sent to a non-validator cannot be observed.

**Forward window.** The proxy delays before forwarding, to avoid exposing when the
generator sent:

| phase | formula | full (E=600) | tiny (E=12) |
|---|---|---|---|
| forward start | `conn + max(E/20, 1)` | 50 | 2 |
| forward end | `min(Y, max(Y/2, start + m))` | 250 | 7 |
| lottery end | `Y` | 500 | 10 |

with `conn = max(E/30, 1)` and `m = 5` (polkajam's `MIN_FORWARD_WINDOW`). Earlier revisions
of this table said "spread until slot 5", which is the nominal `Y/2` and correct at full
spec; under tiny the minimum-window clamp legitimately carries the end to 7, so a hard
bound at 5 would fail a conforming node. Only `phase < Y` is asserted hard.

**The stopping rule.** "Stop after finalized inclusion" is judged against the node's *own*
account of finality, not the harness's: §10 defines depth ≥ 2 for the rules the harness
applies, but this one is a decision the node makes, and it publishes what it considers
final in the `Final` of every UP 0 message. A forwarded ticket is finalized-included from
the first moment the node advertised a `Final` at or past the slot of its own block
carrying it. Two silences would otherwise read as obedience, so two controls gate the row:
the run must have watched on past that moment — a node still advertising a slot later
could have forwarded again — and the node must repeat a forward *somewhere* in the run.
polkajam sends exactly one CE 132 frame per ticket per peer, so against it the rule holds
however it is written and the row reports itself unexercised, which is the expected
verdict and not a defect in either the node or the rule. A node that re-gossips is the one
it bites.

**Which blocks.** The subject is every block the NUT authored in the epoch its tickets were
submittable in, not that epoch's newest. The tail rule, sortedness and "carried nothing the
harness never sent" are properties of a block on its own and are reported once per block;
"no faulted ticket" is a property of the epoch, since a node could otherwise bury one in
any block but the last. Coverage is judged once, against what the node held by its last
chance to include — the arrival lead of the N1 Extrinsic-completeness row — because a block
sealed before a ticket arrived is owed nothing, and a ticket carried early is on chain and
owed by no later block. Strict per-block completeness is the N1 row's; this lane does not
repeat it.

**Faults.** The prohibitions above are negatives, and are reported only alongside the
control that makes them mean something: a node that forwards nothing and authors nothing
satisfies every "must not" without deciding anything. "No forward" is further assertable
only for the faults delivered over CE 131 — a node forwards what it is *proxy* for and
does not rebroadcast a CE 132 arrival, so against a broadcast fault the rule holds in
every run and tests nothing. The wrong-epoch and late faults reach the node over CE 132
(sending them over CE 131 from a ticket the NUT does not proxy would make each of them a
wrong-proxy case too, and no verdict could say which defect the node answered), so for
those the assertion is "not included" alone.

### N3 — guaranteeing, CE 133/146/134/135/148 (2–3 epochs)

| Check | Assertions | Faults |
|---|---|---|
| CE 133 `:351-376` (builder → NUT in NUT's rotation) | NUT FINs, opens CE 134 to both co-guarantors within ~3 s | first message > 2+200·1024 bytes → reset `:362-364`; NUT not guarantor of the core → ignore; unauthorized package → no sharing; extrinsic size mismatch → reset |
| CE 146 `:378-404` | as 133; no CE 139/140/148 for supplied segments | bad import proof → refuse; package > 200·1024 → reset |
| CE 134 send `:406-458` | message 1 `Core ++ ShardCount(6) ++ len++[WPHash ++ SegRoot]`; message 2 bundle byte-identical to reference `:421-425`; shard count valid `:433-437` | co-guarantor replies wrong hash → its signature excluded; reset → proceed with the other |
| CE 134 receive | NUT replies `WRHash ++ sig($jam_guarantee ++ blake(E(report)))`; hash equals reference (NUT refines) | shard count 5 or 7 → reject; bad mappings → refuse or trust `:443-445`; invalid authorization → reset |
| CE 135 send `:460-485` | `Report ++ Slot ++ len++[(Idx,Sig)]`, 2–3 signatures sorted and valid; report equals reference; to all current validators, in the last rotation also to the next set `:469-471`; ~2 s wait for the third `:465-467` | — |
| CE 135 receive → inclusion | NUT includes reference-signed reports in its next block | one signature; unassigned signer; stale slot; duplicate core → excluded |
| CE 148 `:650-673` | serves `[Segment] ++ [Import-Proof]` for own bundles; prefers 148 over 139/140 *(soft)*; ≤3072 per stream | corrupt segment → fallback to 139/140 `:660` |

### N4 — availability, CE 137/138/139/140/141 (2 epochs)

| Check | Assertions | Faults |
|---|---|---|
| CE 137 serve `:523-556` | `BundleShard ++ [SegShard] ++ Justification` equals reference erasure coding; co-path `T(s,i,H)` `:530-543` | unknown root or index ≥6 → reset |
| CE 137 fetch | NUT requests only its own index from a guarantor after seeing the report | wrong shard / bad justification → no assurance for that core; tries another guarantor *(soft)* |
| CE 141 send `:675-695` | `Anchor ++ Bitfield[1] ++ Sig`; bit set iff shard verified; ~2 s before the slot to all possible authors `:679-680`; epoch edge +4 s / −2 s `:680-684` | — |
| CE 141 receive → inclusion | all valid assurances included; report available at ≥5 of 6 | wrong anchor, bad signature, bit set for an empty core → excluded |
| CE 138 serve `:558-580` | bundle shard + justification with segment-shard root `:566-568` | unknown → reset |
| CE 139/140 serve `:597-648` | 139 `[SegShard]`; 140 adds justification discriminator 0/1/2 `:637`; ≤2·3072 | over limit → reset |
| CE 139/140 fetch | NUT reconstructs imports from 2 shards; 139 first, 140 on inconsistency `:625-630` | one corrupt shard → retries via 140 and completes |

### N5 — auditing and disputes, CE 136/144/145/147 (2–3 epochs)

| Check | Assertions | Faults |
|---|---|---|
| CE 144 tranche 0 `:743-793` | per block with newly available reports: `HeaderHash ++ 0 ++ len++[(Core,WRHash)] ++ sig`, then `Evidence` s₀ (96 bytes); at tranche start; covers all reports; none announced twice `:757-758`; nothing when nothing to audit `:749-750` | — |
| CE 147 `:582-595` | requests the bundle from a guarantor first, falls back to 138 `:587`; serves own bundles | corrupt bundle → reconstruct via 138, still judges |
| CE 145 `:795-833` | `Epoch ++ ValIdx ++ Validity ++ WRHash ++ Sig`; positive within 8 s *(soft)*; Validity=0 followed by the `Guarantee` message `:819-830`; also to the succeeding set | — |
| Negative judgment | emulated guarantors include an invalid report (two emulated signatures) and serve the real bundle → NUT publishes Validity=0 plus guarantees; forwards received negative judgments to grid neighbours `:813-815`; disputes extrinsic in its next block | emulated negative judgment on a valid report → NUT publishes Validity=1; fault recorded |
| CE 136 `:487-504` | serves held reports; on an unknown negatively-judged report requests it from the judging peer `:494-495` | — |
| Later tranches | two or more emulated auditors no-show → NUT sends a tranche-n announcement 8 s later with `[sₙ(w) ++ len++[No-Show]]` `:769-775` | — |

### N6 — preimages, CE 142/143 (1–2 epochs)

| Check | Assertions | Faults |
|---|---|---|
| Announce → request `:697-741` | a non-validator peer announces `ServiceID ++ Hash ++ Len` and keeps the connection 10 s `:702-707`; NUT opens CE 143 iff the preimage is requested on chain and not held; verifies hash and length | un-requested hash → no CE 143; wrong preimage → no inclusion, no gossip |
| Gossip | NUT announces an obtained preimage to grid neighbours `:709-710` | — |
| Serve | returns the bytes, FIN | unknown → reset |
| Inclusion | in the next NUT block, sorted; lookups updated | no longer requested → excluded |

### N7 — adversarial and robustness (cross-cutting)

| Fault | Expected |
|---|---|
| Unknown stream byte (130, 200) | reset stream, connection stays up |
| Length prefix mismatch / truncated / trailing bytes | reset, no crash, connection reusable |
| Slow-loris CE stream (kind byte then 30 s silence) | timeout and reset *(soft)* |
| Flood: 500 CE 141 streams per second from one peer | stays responsive; authors on time |
| Equivocating emulated author | builds on neither; no re-announce *(soft)* |
| Reorg: emulated majority extends a sibling | NUT follows the reference best chain; CE 128 ascending reflects it |
| Epoch-transition connectivity `:86-98` | with a scheduled validator-set change: connect to the next set, keep the old set until the first block of the epoch is finalized **and** one slot elapsed; UP 0 topology re-evaluated `:200-202` |
| Kill and restart NUT mid-epoch | re-syncs via CE 128/129; authors again in its next slot |
| NUT index rotation | every lane re-run with `k ∈ {1..5}` to catch index-dependent bugs (grid neighbours, shard index) |

Out of scope: GRANDPA/BEEFY (no JAMNP-S spec). Finality is emulated by the harness (§10).

## 12. Open questions for the conformance group (with proposed defaults)

1. M2 spec-file format → header + key/values + named parameters (§7).
2. Secret hand-over → raw Ed25519 and Bandersnatch secrets via environment; BLS omitted.
3. Is finality/GRANDPA in scope for M2? → no; harness-defined finality, documented.
4. Which jam-np timings are normative? → soft in v1; ordering and validity hard.
5. Required protocols → CE 129 required; CE 147/148 optional (fallback to 138/139 verified);
   CE 136 required only in N5.
6. jam-np has no tags → pin the commit hash in every report; ask for tagging.
7. NUT index → 0 in all lanes; N7 rotates it.
8. Clock → shared host clock, NTP-synced, 250 ms drift budget.
9. Is the ticket proxy *selection* rule normative, or only the requirement that the proxy
   come from the next-epoch set? → membership normative, selection implementation-defined;
   the harness reports a mismatch against `proxy_index` as soft (§11 N2). Polkajam enforces
   its own rule with `Error::NotCorrectProxy`, so a client that selects differently is
   refused by it today.

## 13. Roadmap

| phase | content |
|---|---|
| P0 | polkajam prerequisite PRs (§8); `jamnp-s` crate (endpoint, cert, ALPN, framing, all codecs); runner skeleton; N0 |
| P1 | `m2-reference` wrapper; N1 authoring validation; N2 tickets |
| P2 | N3 guaranteeing; N4 availability (erasure coding export) |
| P3 | N5 auditing/disputes; N6 preimages |
| P4 | N7 adversarial, index rotation, IPv6 variant; fuzz web UI integration; public trace format |
