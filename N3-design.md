# N3 — design for the guaranteeing lane

Status: inspection done, nothing implemented. Written 2026-11-10 against `main` at `e444700`,
with polkajam pinned at `940ef56`.

This document exists because N2's did its job: before any code, it found an attempt cap read off
the wrong checkout, two checks that could not fail, and a deferral whose premise was false. N3 is
the largest lane in DESIGN §11 — five protocols, seven check rows — and the one DESIGN claims is
blocked on upstream polkajam work. The first job is to find out whether that is still true.

---

## 1. DESIGN §8, re-read against the pin

§8 lists four prerequisites "in polkajam" before the reference engine can serve N3 and N4. Three
of them are already satisfied at the pinned revision. The list has simply aged: it was written
against an older polkajam, as §2.1 of `N2-design.md` was.

| §8 item | state at `940ef56` |
|---|---|
| 1. public, RNG-parameterised provisioners | `tickets` and `disputes` are still private (`fn`, not `pub fn`) — but see below: the artefact methods make them unnecessary |
| 2. a constructor taking a keyset subset | **already there.** `AuthoringHarness::new(spec, SecretKeysets, config)` takes arbitrary keysets; `RefChain::tiny_for` already uses it to build a chain holding one validator's keys |
| 3. compose methods returning signed artefacts | **already there.** `compose_guarantee(report) -> ReportGuarantee`, `try_compose_assurances(..) -> Vec<AvailabilityAssurance>` and `table_tickets() -> Vec<TicketEnvelope>` are all public and all return rather than submit |
| 4. bundle → shards + justifications + segment proofs | **genuinely blocked.** `mod util;` and `mod availability;` are private in `crates/node/src/lib.rs`, so `util::erasure` (`erasure_shards`, `segments_shards`, `reconstruct`) and every justification/segment-proof path are unreachable from outside the crate |

**On item 1.** The reason §8 gave was "so a step can say *validator 3 produces its tickets now*
deterministically". That control now exists by another route: the harness generates its own
tickets (`RefChain::generate_tickets_for`), offers them to the pool (`submit_tickets`), and
composes guarantees on demand. Making the provisioners public would be tidier but is not on the
critical path. **Recommendation: drop item 1 from the prerequisite list and say why.**

**On item 4.** This is the only real upstream dependency, and it is narrower than §8 implies:
two `mod` declarations need `pub`, or a `hazmat` re-export needs to name the handful of
functions. It is still an upstream PR with review and re-pin lead time, so it should be opened
early whatever else happens.

---

## 2. What the reference engine can already do

The whole path from work items to a signed guarantee is public on the authoring harness:

```
build_package(items)            -> (WorkPackage, Vec<Vec<u8>>)
compose_report(package, xts, core) -> (WorkReport, bundle: Bytes, _)
compose_guarantee(report)       -> ReportGuarantee          // signed
submit_work_items(items, core)  -> (ReportGuarantee, Bytes) // all three, and submits
```

So the harness can build a real work package, refine it, and hold both the bundle bytes and a
signed guarantee — which is what CE 133, CE 134 and CE 135 carry. `jamnp-s`'s
`WorkPackageSubmission` still has `// TODO(P1): typed GP WorkPackage once m2-reference exposes
it`; this is what unblocks that.

Codecs for CE 133, 134, 135, 146 and 148 already exist in `jamnp-s`.

---

## 3. What this means for the lane's scope

DESIGN §11 N3 has seven check rows. Splitting them by what item 4 blocks:

**Reachable now**

- CE 133 `:351-376` — submit a package to the NUT as a builder; it must FIN and open CE 134 to
  both co-guarantors. Needs a real `WorkPackage`, which §2 provides.
- CE 135 send/receive `:460-485` — the NUT distributes `Report ++ Slot ++ signatures` and
  includes reference-signed reports in its next block. Needs a signed guarantee, which §2
  provides, and block inclusion, which N2's work already exercises.
- The faults on both: oversized first message, not-a-guarantor, unauthorized package, extrinsic
  size mismatch, one signature, unassigned signer, stale slot, duplicate core.

**Blocked on item 4**

- CE 134 message 2 "bundle byte-identical to reference" — the bundle itself is reachable, but the
  *segment-shard root* in message 1 is not.
- CE 148 `:650-673` — serving `[Segment] ++ [Import-Proof]` requires segment proofs outright.
- CE 146 `:378-404` — "no CE 139/140/148 for supplied segments" needs the segment path to exist
  before the absence means anything.

**Also reachable now: guarantor assignment** — see §3.1. It was the one unknown when this
document was first written, and the answer removed it from the blocked list.

### 3.1 Guarantor assignment, resolved 2026-11-10

Reachable today with no upstream change, though not where §8 would lead you to look.
`engaged_cores()` says which cores are busy, not who guarantees them. The calculator is
`chain::core_assignments::CoreAssignments`, and the route to it is:

```rust
let jam = harness.chain();                       // Arc<JamChain>
let (_index, epoch, _next) = jam.current_and_next_epochs();
let assignments = epoch.core_assignments(slot);  // CoreAssignments
assignments.val_to_core(val)   -> Option<CoreIndex>
assignments.core_to_vals(core) -> Option<[ValIndex; VALS_PER_CORE]>
```

`mod chain` is private in polkajam's `lib.rs` and `hazmat` does not re-export `CoreAssignments`,
so the *type* cannot be named from here -- but its methods are public and the value comes back
from a public API, which is enough to call them. Verified by probe against the pin: under tiny,
core 0 holds validators 1, 2 and 3 and core 1 holds 0, 4 and 5.

The rule, for the harness to assert against rather than mirror blindly:

- `val_to_core[v] = v / VALS_PER_CORE` initially (3 per core under tiny, 2 cores for 6
  validators), then `gp_shuffle` by entropy;
- `rotation = ((slot % epoch_period) / rotation_period) % core_count`, added to the initial core
  modulo the core count;
- the entropy is the accumulator's final value for epoch `(slot / epoch_period) - 2` --
  **entry 2** of `TheState::entropy` when grading the current epoch.

That last line is the one to be careful with. The same off-by-one between entropy entries 1 and
2 cost N2 a session: every emulated ticket was rejected as "invalid ticket signature" because
the context was built from entry 1, and it went unnoticed because the two agree whenever an
epoch boundary falls between proving and delivery.

---

## 4. Open questions, to settle before coding

1. ~~**Guarantor assignment.**~~ **Resolved: §3.1.** Reachable with no upstream change.
2. **Does N3 wait for item 4, or land in two halves?** Recommendation: two halves. CE 133 and
   CE 135 are a coherent lane on their own, and they are the rows a third-party node is most
   likely to get wrong first. Holding them back for the availability export delays the whole
   lane behind an upstream PR.
3. **Is the reference pool fed as well as the wire?** `submit_work_items` both returns the
   guarantee and submits it. For N3's inclusion rows the reference chain *should* hold the
   report, so submitting is right — but it means the harness cannot send a guarantee it has not
   also adopted. If a fault needs "sent but never adopted", `compose_report` + `compose_guarantee`
   without `submit_guarantee` is the path.
4. ~~**PVM backend.**~~ **Resolved 2026-11-11: it is not a constraint.** Refining one trivial
   work item on the interpreter takes **5.7 ms** against a six-second slot -- three orders of
   magnitude of headroom. A realistic package will cost more, but nothing about the slot
   calendar needs designing around the interpreter. Measured by
   `a_work_item_refines_into_a_signed_guarantee` in `m2-runner`, which prints the figure.

---

## 5. Order of work

0. **Open the upstream PR for item 4** — two `mod` declarations, or a `hazmat` re-export naming
   the erasure and justification functions. It is the long pole and it is small; it should not
   wait for the rest of this plan.
1. ~~Settle open question 1.~~ Done; §3.1 has the route and the rule.
2. ~~**`m2-reference`: work packages and reports.**~~ **Done 2026-11-11.** `reports.rs` has
   `guarantee_work(items, core) -> GuaranteedWork` (package, report, bundle, signed guarantee)
   plus `guarantors_for(core, slot)` and `core_for(validator, slot)`. Nothing is submitted to the
   reference pool: `submit_work_items` would do both, and a harness that could not send a report
   without also adopting it would have no way to pose "guaranteed but never included".

   Two things the work turned up:

   - **A guarantee needs a chain anchored to the current epoch.** An unanchored `RefChain::tiny`
     refuses twice over -- the guarantee's slot names an epoch the state has never heard of, and
     once past that, genesis is far too old to serve as a lookup anchor. Anchoring is
     `spec::tiny_spec`'s job and lives in `m2-runner`, so the integration test lives there too,
     beside the other anchored-chain tests. The artefact stays in `m2-reference`.
   - **`CoreAssignments` cannot be factored into a helper.** Its type lives behind a private
     module upstream, so the value can be used but not named, and a helper returning one has
     nothing to return it as. Both accessors therefore repeat the two-line lookup.
3. **`jamnp-s`: type `WorkPackageSubmission`** against the real `WorkPackage`, closing its TODO.
4. **N3 first half** — CE 133 and CE 135, with their faults, and the inclusion rows.
5. **N3 second half** — CE 134's byte-exactness, CE 146 and CE 148, once item 4 lands.

---

## 6. What is deliberately not in this design

- **Availability (N4).** CE 137/138/139/140/141 are N4's, and item 4 unblocks both lanes at once;
  this document does not plan them.
- **Simulated-node coverage for N3.** M2-B's self-test proves rows by making a node get them
  wrong. N3's rows will want the same treatment, but a stand-in that guarantees work packages is
  a larger build than one that runs a lottery, and it should follow the lane rather than lead it.
