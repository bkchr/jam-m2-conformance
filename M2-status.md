# M2 Conformance — Status

Progress tracker for the M2 conformance harness. Three documents govern this project and
nothing else does:

| Document | Governs |
|---|---|
| `DESIGN.md` | the implementation — lanes, checks, wire formats, the NUT contract |
| `M2 Conformance - Delivery Plan.md` | the delivery plan — milestone ladder, effort, rollout |
| `M2-status.md` (this file) | progress against that ladder, and the evidence for it |

Last verified 2026-10-30 against polkajam @ `940ef56c7`, branch `m2/connectivity-fixes`
@ `60f5c46` plus the uncommitted fixes of §3.1 and §3.2.

## Milestone ladder

| Milestone | Lanes | Coverage | Status |
|---|---|---|---|
| **M2-A** — Foundations live | N0, N1 | 6 / 41 | ✅ **complete** — §1 |
| **M2-B** — Self-tested | N2 | 8 / 41 | ⚠️ **partial** — the N2 lane exists; the bar does not. See below |
| **M2-C** — Guaranteeing | N3 | 21 / 41 | ⏳ not started |
| **M2-D** — Availability | N4 | 30 / 41 | ⏳ not started |
| **M2-E** — Audit & preimages | N5, N6 | 41 / 41 | ⏳ not started |
| **M2-F** — Adversarial | N7 | + fault matrix | ⏳ not started |
| **M2-G** — Rollout | — | ecosystem-gated | ⏳ not started |

**On M2-B.** Its bar is *"Safrole tickets covered, **and** the harness's own checks are proven
by deliberately faulty simulated clients"* — the delivery plan calls it the structural
milestone: *before it, the harness reports; after it, the harness can be trusted to judge.* The
N2 lane is implemented and graded live, so the first half holds. The second does not: there are
no simulated clients, no transport abstraction and no virtual clock to build them on (§4). Two
of the four hard failures in the last run were harness defects that simulated faulty clients
exist to catch (§3), which is the cost of that gap measured rather than argued.

This document records what each milestone required, the evidence that it holds, what is not
covered, and how to point the suite at a third-party node.

---

## 1. M2-A — complete

| Criterion | Status | Evidence |
|---|---|---|
| Five peers register with the NUT | ✅ | 45 consecutive `Net status: 5 peers (5 vals)` samples in the NUT log |
| The chain advances | ✅ | reference chain authors every emulated slot; NUT imports and re-announces |
| The NUT's slots are left unclaimed | ✅ | harness keystore holds no key for the NUT index; NUT authors its own slots |
| A non-vacuous run exists | ✅ | 82–122 graded checks per run, with real findings, exit code 1 |

The three blockers that defined P0 are closed. The harness now produces a conformance verdict
that depends on what the node actually does, which is the property M2-A exists to establish.

---

## 2. What M2-A required

Three confirmed blockers stood between the harness and a verdict that meant anything. They were
recorded in the September planning drafts, since superseded by this file. Before they were fixed
the only all-green evidence was a `--dry-run` that fabricated its own input.

| # | Blocker (as recorded) | Status |
|---|---|---|
| 1 | NUT registers zero peers — `0/0 active peers`, no UP 0 handshake ever completed | closed |
| 2 | The harness steals the NUT's slots — measured 96/96 slots claimed, 18 as the NUT | closed |
| 3 | Genesis sits ~8.8M slots behind the wall clock, so ticket distribution is refused | closed |

### Blocker 1 — peer registration

Five emulated validators complete the UP 0 handshake and stay registered for the whole
observation window:

```
INFO jam_node::node  Net status: 5 peers (5 vals)
INFO jam_node::node  Sync status: Idle, 3 peers
```

(`sessions/m0-verify/logs/nut.stderr.log`, repeated every 2 s until teardown.)

### Blocker 2 — NUT slots left unclaimed

The fix is structural rather than conditional: the harness keystore is built with a keyset that
belongs to no genesis validator in the NUT's position, so the authoring harness has no key to
claim that slot with and skips it.

`crates/m2-reference/src/chain.rs`:

```rust
/// The keyset handed to the NUT's slot in the harness keystore.
///
/// The keystore is a fixed-length vector with one slot per validator, so the
/// NUT's slot cannot simply be left out. `trivial(u32::MAX)` is a well-formed
/// keyset that belongs to no genesis validator, so the harness never matches it
/// against an author index and never claims a slot with it.
const NON_VALIDATOR_KEYSET: u32 = u32::MAX;
```

Confirmed live: the NUT authors, and the N1 lane imports and grades those blocks — parent,
seal, prior and posterior state roots.

### Blocker 3 — genesis anchoring

Genesis is anchored to the start of the current epoch rather than slot 0. Two defects had to be
fixed together for this to hold:

- `current_epoch_start_slot()` divides the wall-clock slot by `epoch_period`, which is
  **process-wide state**. Read before the tiny parameters are applied it uses 600 rather than 12,
  which anchors genesis up to 599 slots back instead of at most 11. `run` now applies
  `ProtocolParameters::tiny()` before anything reads a parameter.
- A ticket is sealed against entropy buffer **entry 2**, which is what a node validates against.
  The harness used entry 1. Entry 1 is what entry 2 *becomes* after the next epoch change, so the
  two agree whenever an epoch boundary happens to fall between proving and delivery — which the
  mis-anchored genesis made likely. Each bug masked the other.

Result: the node accepts every ticket the emulator offers. `invalid ticket signature` went from
20 occurrences per run to 0.

---

## 3. Harness state

| | |
|---|---|
| Crates | 5 (`jamnp-s`, `m2-reference`, `m2-emu`, `m2-scenario`, `m2-runner`) |
| Rust | ~17.6k lines, 359 test functions |
| `cargo test --workspace` | **363 passed / 0 failed** |
| `cargo fmt --all --check` | clean |
| `cargo clippy --workspace --all-targets` | 3 warnings, all pre-existing |
| Dry-run baseline | exits 0 — the harness's own expectations are satisfiable |
| Live run | exits 1 — correct; hard findings exist |

### Live results vs polkajam-as-NUT

Verification run (`sessions/m0-verify`, 2026-10-28): **82 checks, 5 findings, 4 distinct hard
failures**, exit code 1. Five peers registered and stayed registered for the whole window
(45 consecutive `Net status: 5 peers (5 vals)` samples).

Run-to-run check counts vary between roughly 82 and 130, because which slots the node wins and
when a proxied ticket arrives decide which rules get exercised. A single run is not a stable
baseline, and the set of findings is not stable either — see the caution below.

| Lane | Coverage | Result |
|---|---|---|
| N0 connectivity and sync | UP 0, CE 128, CE 129 | 26/27 hard pass |
| N1 authoring | asserted over UP 0 and CE 128 | parent, seal, prior/posterior state roots graded per block |
| N2 Safrole tickets | CE 131, CE 132 | proofs, target epochs, attempt ranges, per-epoch caps, proxy routing, inclusion |

Four distinct hard failures have been observed. Reading the node's own log alongside them shows
that **only two are node defects**; the other two are the harness blaming the node for a refusal
it was right to make.

| Check | Verdict | Seen |
|---|---|---|
| `ce129_boundary_parent_before_child` | node defect | every run |
| `n2_unknown_epoch_reset_observed` | node defect | every run |
| `n2_proxy_duty_forwarded` | **harness-induced — fixed 2026-10-29 and 2026-10-30** | was intermittent |
| `n1_extrinsic_includes_delivered` | **harness-induced — fixed 2026-10-29** | was every run |

**Update, 2026-10-30.** Every hard failure but the two node defects is closed. §3.1 records four
delivery fixes and §3.2 three more, with the evidence for each. `n2_proxy_duty_forwarded` took
both rounds: the gate of §3.1 got tickets accepted at all, and the decoder fix of §3.2 got the
node's forwards seen. The latest runs (`sessions/fwd-3`, `sessions/fwd-4`) report **two hard
findings, both node defects**.

#### 3.1 The delivery fixes, 2026-10-29

Three of the four hard failures above were the harness grading the node against its own
intentions rather than against what happened on the wire. Four changes closed them.

**1. A readiness gate on ticket delivery.** A node validates an incoming ticket against finalized
state, so one whose finalized head is still behind the current epoch refuses every ticket it is
offered — polkajam's `ticket_preflight` returns `FinalityLagging` when `final_slot /
epoch_period < curr_slot / epoch_period`. That is the normal state for a second or two after the
harness seeds a chain the node must import, which is exactly when the first tickets went out.
Every UP 0 message the node sends carries its finalized block, so the emulator now keeps a
watermark of the highest finalized slot the node has advertised and holds each ticket until that
head is in the current epoch. A ticket the node cannot accept inside its submission window is
**withheld** rather than sent into a refusal.

The gate is on the epoch, not on "the finalized head reaches the seeded head" as §5.7 used to
put it: finality trails the chain head by a slot or two indefinitely, so the literal version
waits for something that may never happen while the node has long been able to accept tickets.

**2. The lanes grade deliveries, not plans.** The gate alone would have produced the same false
failures from the other side, because `n2_proxy_duty`, `n2_inclusion` and `n2_unknown_epoch_reset`
read the *plan*. `EmuTicket` now carries `delivered_at_ms: Option<u64>`, and a ticket that never
went out is reported as **not exercised** rather than failed. `n2_inclusion` also emits a soft row
naming how many were withheld, so a run that withheld most of its tickets cannot pass on a
near-empty expectation and look like coverage it never had.

**3. The unknown-epoch probe is never owed.** The probe names an epoch past the node's horizon on
purpose and the node is *required* to refuse it. It is the epoch after the plan's, which is
exactly the submittable epoch of a block one epoch further into the run — so `N1` demanded that
the node include the one ticket it was obliged to reject. It only fired in runs long enough to
author such a block, which is why it read as intermittent and unexplained. `DeliveredTicket` now
carries `probe`, and nothing is ever owed on it.

**4. Each peer's plan is delivered in slot order.** A peer's sender walks its plan one entry at a
time, sleeping until each ticket's slot, and the plan was built in ticket order. A peer's CE 132
slot is spread by author index while its CE 131 slot is the window's first, so for every author
but the first the ticket proxied to the NUT sat behind a broadcast scheduled several slots later
and arrived that late — past the window any proxy could still forward in. Predicted and observed
send phases agreed exactly (authors 0, 3, 4 → phases 3, 6, 7 against a plan that said 3 for all).

| Evidence | Before | After |
|---|---|---|
| `finality lagging` in the node log | every run | **0** across 7 runs (`sessions/gate-1`…`gate-7`) |
| `n1_extrinsic_includes_delivered` | every run | gone |
| `n2_proxy_duty_forwarded` | failed, never passed | **3 hard passes** in `sessions/gate-6` |

`sessions/gate-6` is the first run in which the proxy-forwarding rule was ever *exercised*: five
tickets reached the node at epoch phase 4 and it forwarded at phase 5.

**Resolved since.** Two of those five forwards were not observed, and the batch split
`ceil(pending / remaining_win_slots)` fitted the three-then-two shape exactly. It was the wrong
explanation: the node had forwarded all five. See §3.2.

#### 3.2 The decoder defect and the scheduling fixes, 2026-10-30

Three more changes, and one of them explains every remaining `n2_proxy_duty_forwarded` failure
the project has ever recorded.

**1. The CE 131/132 decoder rejected any ticket attempt above 1.**

```rust
let attempt = input.read_byte()?;
if attempt > 1 {
    return Err(codec::Error::from("ticket attempt must be 0 or 1"));
}
```

`tickets_per_validator` is a protocol parameter — four under tiny — not a wire constant, so
every ticket numbered 2 or 3 failed to decode. `collect_nut_tickets` skips a frame that will not
decode, silently, because an undecodable frame is not evidence of anything. So the node sent the
ticket, the harness never saw it, and the lane recorded that the node had not sent it.

The evidence is in the traces that were already on disk:

| run | tickets proxied to the NUT | attempts | forwarded by the node | graded as forwarded |
|---|---|---|---|---|
| `sessions/gate-6` | 5, all arriving at phase 4 | 1, 1, 1, 2, 3 | all 5, to all 5 validators — 3 at phase 5, 2 at phase 6 | 3 |
| `sessions/fwd-2` | 1, arriving at phase 1 | 2 | 1, to all 5 validators, at phase 2 | 0 |

The three-then-two split in `gate-6` really is polkajam's batching, and it is also exactly where
the attempt numbers happen to divide — which is how a correct mechanism came to look like the
cause. `fwd-2` has no batching to hide behind: one ticket, forwarded to everyone one slot after
it arrived, graded as reaching nobody.

The range check is gone from the decoder. A decoder decodes the wire; a parameter range is the
lane's business, and the N2 lane already judges it as `n2_gen_attempt_in_range`, where an
out-of-range attempt is a **reportable failure instead of an invisible one**. The blast radius
was wider than the one check: the same drop shortened `own_ticket_ids` for N1, `nut_tickets` for
all of N2, and on the inbound path classified a conforming ticket as a malformed frame.

**2. The plan is laid out after the node can accept tickets.** The readiness gate of §3.1 holds
tickets back while the node finalizes the seeded chain, so a schedule written before that hold
names slots the tickets will not arrive in — and the proxy-forwarding duty is owed on arrival,
not on intent. `sessions/fwd-1` planned its one proxied ticket for phase 2 and the gate released
it at phase 7, past any forwarding window, with the plan none the wiser. The runner now waits for
the node's advertised finalized head to reach the current epoch before proving and planning;
ticket senders wait for a plan to exist rather than reading an empty map at connect time. The
wait is bounded at half the observation window, capped at an epoch: a node that never finalizes
has a defect of its own, and the run should go on to report it.

**3. A lottery that cannot exercise the proxy duty is traded for the next one.** A CE 131
delivery goes out at the submission window's first slot. If that slot is already past the
forwardable phases, nothing in the epoch can be, and the duty is reported as not exercised
however well the node behaves (`sessions/gate-7`, every CE 131 planned at phase 8). The runner
already waited out an epoch whose window had closed outright; it now also waits out one that is
open but too late to forward in — and only when the plan actually proxies something to the NUT,
since otherwise the wait buys nothing. `m2-reference` plans against the rule and `m2-scenario`
judges by it from different crates, so `forwardable_phases_match_the_judged_rule` compares the
phases they admit directly.

**Evidence.**

| | `gate-6` (2026-10-29) | `fwd-3` / `fwd-4` (2026-10-30) |
|---|---|---|
| Checks | 125 | 130 / 107 |
| Hard findings | 4 | **2 / 2**, both node defects |
| `n2_proxy_duty_forwarded` | 3 pass, 2 fail | **1 pass / 5 pass, none failing** |
| `n2_inclusion_covers_valid` | pass | pass |
| `finality lagging` in the node log | 0 | 0 |

The two that remain are `ce129_boundary_parent_before_child` and
`n2_unknown_epoch_reset_observed` — the two node defects of §3.

#### `ce129_boundary_parent_before_child` — node defect

> CE 129 put a boundary node at index 1 before its parent at index 3, of 11

`simple.md:275-281` requires a CE 129 response's boundary nodes to hold no duplicates and never
place a node before the node that references it. The check needs no knowledge of node layout: a
branch node carries its children's hashes, so if some 32-byte half of node *i* is the reference
to node *j*, then *j* is that node's child and must come after it.

One caveat on confidence: the check assumes a reference is blake2b-256 with the top bit of the
first byte cleared, that bit being the branch/leaf discriminator. If polkajam uses a different
convention the match is a coincidence. Cross-check against the node's trie code before raising
this upstream.

#### `n2_unknown_epoch_reset_observed` — node defect

> 1 ticket(s) for an epoch past the NUT's horizon were delivered, and none made it reset the stream

`simple.md:335-337` requires a ticket for an epoch the node cannot know yet to make it reset the
stream. The node detects the ticket correctly —

```
WARN authoring  Error processing incoming ticket: bad ticket epoch value 797852
```

— rejects it, and then lets the stream finish cleanly. The emulator records a reset only on a
genuine `ReadError::Reset`, deliberately: a connection that died for its own reasons must not be
credited as a refusal. So the node is right semantically and wrong at the transport layer.

#### `n2_proxy_duty_forwarded` — harness-induced (closed, §3.1)

> a ticket proxied to the NUT in slot 9574202 must be forwarded via CE 132 to every validator;
> it reached peer(s) [] and not [0, 1, 2, 3, 4]

The node never forwarded the ticket because it never accepted it — one of two causes, the
other being §3.2:

```
10:00:09.504  WARN authoring  Error processing incoming ticket: finality lagging (final: 9574199, curr: 9574201)
10:00:09.505  WARN authoring  Error processing incoming ticket: finality lagging ...
10:00:09.506  WARN authoring  Error processing incoming ticket: finality lagging ...
10:00:09.508  WARN authoring  Error processing incoming ticket: finality lagging ...
```

Slot 9574202 begins at 10:00:12. The harness delivered four tickets 2.5 s earlier — correct by
its own arrival-lead rule — but that was seconds after launch, while the node was still
finalizing the chain it had just been seeded. It refused all four on a finality-lag guard, and
the harness graded it for not forwarding one of them. See §5.7.

This check is also intermittent for an unrelated and legitimate reason: the rule can only be
demanded when a proxied ticket reaches the node early enough in the lottery for a forward to be
meaningful. Arriving late, it is reported as a soft "not exercised" row instead — which is how
`sessions/n2-9` recorded it, at phase 8 of the lottery.

#### `n1_extrinsic_includes_delivered` — harness-induced (closed, §3.1)

> block at slot 9574202 owed 4 ticket(s), could carry 3, carried 0
> block at slot 9574214 owed 1 ticket(s), could carry 1, carried 0

The first is the same four tickets refused for finality lag — same slot, same cause, not a node
defect.

The second was not explained by anything in the log at the time of writing. It is now: the
ticket the node "owed" was the unknown-epoch probe, which it is required to refuse — see §3.1,
fix 3. The original reasoning, kept because it shows how the wrong conclusion was reached: By 10:01:24 finality was tracking one block
per slot and no rejection was recorded, so the node appears to have accepted a ticket, held it
with the full 2 s lead, authored a block in a slot that accepts tickets, and left it out. The
check's guards are sound: it demands only tickets delivered at least `TICKET_ARRIVAL_LEAD_MS`
before the slot began, targeting the epoch that slot submits into, outside the tail, and not
already on chain. What it did not guard was the probe: a ticket the harness sends precisely so
the node will reject it. **Closed.**

Note that `n2_inclusion_covers_valid` passed in the same run. The two lanes judge different
blocks — L2 takes the newest block in the submission epoch, L1 grades every block — so L1's
per-block rule is the stricter of the two.

#### Reading these over several runs

**A single run can miss a real defect, and can invent one.** Grade a client over several runs,
read the soft "not exercised" rows as coverage gaps rather than passes, and check a hard failure
against the node's own log before reporting it: two of the four above look like protocol
violations and are not.

### A caution about "green"

Every check in these lanes once passed while measuring nothing. The ticket lanes in particular
had never tested a node: every emulated ticket was rejected, and the checks that should have
caught it were written so they could not fail. Two unit tests asserted the defective behaviour
and so pinned it in place. The current lanes were audited for that defect class and six distinct
instances were fixed. Treat any future all-green run as a claim to be checked rather than a
result — confirm the checks were *exercised*, not merely *not failed*.

---

## 4. What is not covered yet

M2-A is the first milestone on the ladder. Clearing it is not a statement about protocol
coverage beyond its own 6 / 41.

- **Messages asserted: 8 of 41.** UP 0, CE 128, CE 129, CE 131, CE 132. Lanes N3–N7
  (guaranteeing, availability, auditing/disputes, preimages, adversarial) are designed in
  DESIGN §11 and not implemented.
- **The transport abstraction has not been started**, and M2-B depends on it. The criterion is
  *transport and clock injectable, QUIC behaviour unchanged* — a trait boundary with a real
  QUIC implementation and an in-process mock behind it, plus a virtual clock, which is what
  makes simulated faulty clients and sub-second deterministic runs possible. Today the workspace defines **zero traits**, `quinn`
  appears at **33 sites above `jamnp-s`** (all in `m2-emu`), and there are **18 direct
  `sleep`/`SystemTime::now`/`Instant::now` sites** above `jamnp-s`. The plan's estimate of
  earlier estimate of "only 10 call sites" understates the work by roughly 3×; re-estimate
  before scheduling it.
- **No negative testing.** Roughly half the DESIGN §11 catalogue is fault injection; none of it
  exists. A node that accepts a bad signature can still pass today.
- **One real node has been graded.** The suite has only ever run against polkajam.

---

## 5. Running the suite against a third-party node

### 5.1 Topology

Every run uses the same fixed topology: six tiny-spec validators (`V=6`, `C=2`, `E=12`,
`ticket_submission_end=10`, 6 s slots). Five are emulated by the harness; one is the node under
test. The harness speaks its own independent JAMNP-S implementation — not any node's networking
stack — and grades what the NUT emits against polkajam's `hazmat` engine as reference oracle.

By default the NUT takes **validator index 5** and listens on `base_port + 5` (`40005`); the five
emulated validators occupy `40000`–`40004`. Index 5 rather than 0 is deliberate: at index 0 with
trivial keys the preferred-initiator rule is degenerate — the NUT is never the preferred
initiator, so the NUT-initiated N0 checks can never fire.

### 5.2 What the harness hands the node

Written into `<session-dir>` before launch:

| File | Contents |
|---|---|
| `spec-m2.json` | the M2-standard spec: `parameters`, `genesis_header`, `genesis_state` (21 key/values), `bootnodes` |
| `spec.json` | the same chain in polkajam's native spec format |
| `nut_ed25519.hex`, `nut_bandersnatch.hex` | the NUT's 32-byte secrets, hex |

`genesis_header` plus `genesis_state` key/values is the same shape every M1 target already parses
from fuzz-proto `Initialize`. Validator metadata is `PeerAddr { ip: [u8;16], port: u16 LE }` first
(18 bytes, as in jam-np), then the P-256 id, then filler. IPv4 loopback is written IPv4-mapped
(`::ffff:127.0.0.1`).

Secrets are handed over explicitly rather than as a single seed, so no team is forced onto one
derivation scheme.

### 5.3 The environment contract

The `docker` preset launches the node with host networking — QUIC is UDP, and the node must be
able to *initiate* connections under the preferred-initiator rule — and passes:

| Variable | Meaning |
|---|---|
| `JAM_M2=1` | enable M2 conformance mode |
| `JAM_M2_SPEC` | path to the spec file |
| `JAM_M2_ED25519_SECRET` | hex, 32 bytes |
| `JAM_M2_BANDERSNATCH_SECRET` | hex, 32 bytes |
| `JAM_M2_LISTEN` | `[::]:<port>` |
| `JAM_M2_PUBLIC_ADDR` | `<ipv6>:<port>` as carried in genesis metadata |
| `JAM_M2_DATA_PATH` | writable state directory |
| `JAM_M2_LOG_LEVEL` | log level |

The image is taken from the `JAM_M2_IMAGE` environment variable of the *runner* process
(default `polkajam`).

### 5.4 Running it

```sh
# 1. Build the harness.
cargo build --workspace

# 2. Sanity-check the harness against its own expectations (no node, no network).
cargo run -p m2-runner -- --preset mock --dry-run --session-dir /tmp/m2-dry
#    Expect exit 0 and every check HARD PASS.

# 3. Grade a third-party node image.
JAM_M2_IMAGE=ghcr.io/<team>/<client>:<tag> \
cargo run -p m2-runner -- \
  --preset docker \
  --seed 1 \
  --validator-index 5 \
  --base-port 40000 \
  --session-dir sessions/<team>-01 \
  --startup-timeout 60 \
  --observe-secs 90
```

For a node that runs as a local binary rather than an image, the `polkajam` preset is a worked
example of a command-template launch; the template placeholders are `{spec}`,
`{ed25519_secret}`, `{bandersnatch_secret}`, `{listen}`, `{public_addr}`, `{data}`,
`{log_level}`.

Use `--observe-secs 90` or more. The window must span enough slots for the node to win some and
for a ticket submission window to open; shorter runs leave rules unexercised and report soft
"not exercised" rows rather than verdicts.

### 5.5 Exit codes and output

| Code | Meaning |
|---|---|
| 0 | every hard check passed, no startup failure |
| 1 | a hard check failed, or the NUT did not come up in time |
| 2 | internal harness error |

Output lands in `<session-dir>`:

```
report/report.md        human-readable coverage table and findings
report/findings.json    machine-readable findings
traces/jamnp.bin        full wire trace
traces/jamnp.json       decoded trace
traces/{tx,rx}/         per-message frames
logs/nut.{stdout,stderr}.log
```

Every finding cites `traces/jamnp.bin` as evidence, so a disputed verdict can be re-derived from
the wire.

### 5.6 What the node must implement, in the order the run exercises it

A node that fails an early stage produces a run that cannot reach the later ones, so read the
report top-down.

1. **QUIC + TLS 1.3, mutual auth.** Ed25519 self-signed certificate, exactly one SAN carrying
   the 53-character peer id (`e` + base32 of the Ed25519 public key), key matching the one in
   genesis.
2. **ALPN.** Offer and accept `jamnp-s/1/<first 8 hex of genesis header hash>`, accept the
   `/builder` suffix, and **refuse** a mismatched version.
3. **Preferred-initiator rule.** Initiate where preferred, wait where not, and initiate within
   the grace period.
4. **Builder slots.** Accept at least 20 `/builder` connections and serve CE 133 on them.
5. **UP 0.** Kind byte 0; handshake announcing genesis as Final; announce blocks it authors;
   re-announce blocks it learns.
6. **CE 128 / CE 129.** Serve block requests ascending and ordered, respect the maximum, FIN
   both halves; serve state requests with sorted keys, a size cap, and length-prefixed values.
7. **Authoring (N1).** Author in its own slots with the correct parent, a valid seal, and
   correct prior and posterior state roots; carry the tickets it has been delivered.
8. **Safrole tickets (N2).** Run the lottery, send over CE 131 to its proxy and CE 132 to every
   validator, respect target epoch, attempt range and the per-epoch cap, and reset the stream on
   a ticket for an unknown epoch.

A node that implements only part of this still gets a useful report: checks that could not be
exercised are reported as soft "not exercised" rows, distinct from failures.

### 5.7 Known gaps that affect third-party runs

These are limitations of the harness as it stands, not of any node. They should be closed before
the suite is offered to other teams. The struck-through rows are closed; they are kept because
each one produced false failures against polkajam, and a client that behaves the same way would
have been failed for it.

| Gap | Impact | Fix |
|---|---|---|
| ~~**Ticket delivery begins before the node has finalized the seeded chain**~~ | **closed 2026-10-29** — the sender now holds each ticket until the node's advertised finalized head is in the current epoch, and withholds one it cannot accept in time. See §3.1 | — |
| ~~**CE 131 deliveries are scheduled into the submission window, not the forwarding one**~~ | **closed 2026-10-30** — the plan is laid out only once the node can accept tickets, and a lottery with no forwardable slot left is traded for the next one. See §3.2 | — |
| ~~**The proxy-forward rule does not model batching or pruning**~~ | **closed 2026-10-30, as not-a-defect** — the node had forwarded every ticket; the harness's decoder was dropping the frames. The batch split fitted the symptom by coincidence. See §3.2 | — |
| ~~`JAM_M2_SPEC` receives `spec.json` (polkajam's native format), not `spec-m2.json`~~ | **closed 2026-10-30** — `LaunchConfig` carries both paths behind a `{spec}` and a `{m2_spec}` placeholder, and the docker preset passes the M2 one | — |
| ~~`--lanes` is parsed but never consumed~~ | **closed 2026-10-30** — parsed into a `LaneSet` (an unknown lane name is refused rather than ignored) and consumed by `evaluate`. A lane left out is neither graded nor exercised: `--lanes n0` skips ticket proving entirely | — |
| No capability handshake | the report cannot distinguish *not attempted* from *not exercised* | declared-lane negotiation, per the delivery plan's rollout section |
| The `docker` preset has never been exercised live | only its command string is under test; the polkajam preset is the only path with live evidence | run it against a real image before onboarding anyone |
| The oracle is polkajam | a genuine state-transition disagreement between a third-party node and polkajam surfaces as an N1 state-root failure | expected; M1 state-transition conformance is `davxy/jam-conformance`'s job, and a client should be M1-green before attempting M2 |

---

## 6. Reproducing these results

```sh
# Build the node under test from the pinned revision.
./scripts/prepare-nut.sh

# Harness checks.
cargo test --workspace            # 363 passed / 0 failed
cargo fmt --all -- --check
cargo clippy --workspace --all-targets

# Dry-run baseline: exit 0.
cargo run -p m2-runner -- --preset mock --dry-run --session-dir /tmp/m2-dry

# Live surface: exit 1. Two node defects remain (§3); every harness-induced
# failure was closed on 2026-10-29 (§3.1) and 2026-10-30 (§3.2).
PATH="$PWD/third_party/polkajam/target/release:$PATH" \
cargo run -p m2-runner -- --seed 1 --validator-index 5 --base-port 40000 \
  --preset polkajam --session-dir sessions/m0-verify \
  --startup-timeout 60 --observe-secs 90
```

The polkajam revision is pinned in the root `Cargo.toml` and read from there by
`scripts/prepare-nut.sh`, so the node under test and the engine that grades it are the same
build.

---

## References

- `DESIGN.md` — design contract; §7 environment contract, §11 check catalogue, §13 roadmap
- `M2 Conformance - Delivery Plan.md` — milestone ladder keyed to JAMNP-S coverage
- `README.md` — build, run, and current implementation state
- JAMNP-S: https://github.com/zdave-parity/jam-np (`simple.md`)
- M1 conformance: https://github.com/davxy/jam-conformance
