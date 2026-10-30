# M2 Conformance \- Delivery Plan

## Project Plan

Authors: [Javier Viola Villanueva](mailto:javier@parity.io)
State: Draft
Approvers:
Last updated: 8 Oct 2026

# TL;DR

**What.** Build the conformance harness for JAM Milestone 2 — *“fully conformant, produces blocks, including networking and off-chain duties”* — and publish the contract that makes M2 testable across the ecosystem, as `fuzz-proto` did for M1.

**Why now.** M1 conformance is covered by [jam-conformance](https://github.com/davxy/jam-conformance). Nothing covers M2: no networking, no authoring, no off-chain duties. This project is the next iteration of that same tooling and process, and the foundation for M3.

**How.** Run the third-party client as **one of six tiny-spec validators**, emulate the other five over an **independent JAMNP-S implementation**, and grade every block and off-chain artefact against polkajam's reference engine as oracle. One client per run.

**Where we are.** The harness now runs end to end against a live reference node and produces a real report — **38 checks, 25 pass, 6 fail**. The blocker that stopped every prior run (the node connecting to zero peers) was **found, fixed and verified** this week, along with a second defect; a third turned out not to be a defect at all. But only **8 of 41 protocol messages are asserted**, no client has yet authored a block under test, and seven known defects remain — **all harness-side**; the reference client is not implicated in any of them.

**Shape of the work.** Seven milestones keyed to JAMNP-S protocol coverage, so progress is measurable rather than asserted. **M2-B is the structural one**: before it the harness reports, after it the harness can be trusted to judge, because its own checks are under test for the first time.

**Cost.** \~29 person-weeks of effort — \~18–20 weeks elapsed at planned staffing, or \~28–31 weeks at 1 FTE.

**Done when** two ecosystem teams have been graded end to end and their reports published — not when the harness is feature-complete.

**Top risk.** Upstream drift: the reference client's HEAD moved twice in four weeks and broke our build both times.


# Background

This project is framed within the framework of [jam implementor's prize](https://jam.web3.foundation/), and specifically seeks to be an iteration of the tool used as harness for M1 ([https\://github.com/davxy/jam-conformance](https://github.com/davxy/jam-conformance)), ensuring conformance of *M2*  and building the foundation for the next phase M3

## Previous / current work in this space to date

After a few initial explorations, the agreed path was to run the 3rd party client (NUT)  as **one of six tiny-spec validators**, emulate the other five over an **independent JAMNP-S implementation**, and grade every block and off-chain artefact against polkajam's reference engine as oracle.  There is an initial work effort made by Basti ([https\://github.com/bkchr/jam-m2-conformance](https://github.com/bkchr/jam-m2-conformance)), that laid the design and we should keep building on top.

That foundation is substantial: the conformance definition covers all eight lanes, and the independent JAMNP-S implementation already has typed codecs for the whole message surface. What it has never had is a verdict produced against a live client — which is where this plan starts.

# What success looks like

A harness that grades any JAM client against M2 ("*fully conformant, produces blocks, including networking and off-chain duties*"), plus the published contract that makes M2 testable across the ecosystem, as \`fuzz-proto\` did for M1.

# Definition of done

This project should not be considered *done by* the completion of the harness tool and should follow the grading and reporting of the ecosystem teams. We can establish a minimal number of 2 teams graded to mark as **done**.

# Current state

Measured 8 Oct 2026 against the reference node built from upstream `main`, not asserted from design intent.

> **Superseded.** This is a snapshot, kept for the record. Current status, evidence and open defects live in `M2-status.md`, which is the progress tracker for this ladder. Several defects listed below as open are closed; the lanes are now named N0–N7 in the code and in every emitted report.

| Signal | Value |
| :---- | :---- |
| Checks evaluated | **38** — 25 pass, 7 soft, 6 fail |
| JAMNP-S messages asserted | **8 of 41** |
| Lanes implemented | 3 of 8 (N0–N2) |
| Node network peers | 2 of 5 emulated validators connect |
| Blocks authored by a client under test | **0** |

**Caveat on the pass count.** “25 pass” is not 25 properties of the client. Several rows — notably the CE 128 and CE 129 serving checks — are recorded unconditionally when the *harness* answers a request, so they cannot fail. Correcting this is scheduled in M2-B. Until then the honest headline is **8 of 41 messages asserted**.

**Defects.** Seven known, all harness-side; **two fixed, one closed as not-a-defect, four open**. Fixed: the zero-peers blocker (our generated genesis carried validator addresses in only three of the four places the validator keyset appears, so the node dialled the wrong ports), and a connectivity probe that demanded the wrong certificate, which had been producing five spurious findings in every report. Closed: "only two of five validators connect" is correct behaviour — the client dials only the three peers where it wins the preferred-initiator tie-break, and the other two dial in. Still open: the harness claims the client's own authoring slots; genesis sits far behind the wall clock; and two message-level defects that between them keep block-announcement peers at zero — the emulator closing the client's stream after one frame, and a decode failure that drops the inbound connections.

# The plan

Seven milestones keyed to JAMNP-S coverage so progress is measurable rather than asserted:

|  |  |  |
| :---- | :---- | :---- |
| **M2-A** First live verdict | N0–N1 | 6 / 41 messages |
| **M2-B** Harness proven trustworthy | N2 | 8 / 41 |
| **M2-C–E** Full protocol surface | N3–N6 | 41 / 41 |
| **M2-F** Adversarial behaviour | N7 | \+ fault matrix |
| **M2-G** Two third-party clients graded | — | ecosystem-gated |

# Execution approach

## Milestone ladder, keyed to JAMNP-S coverage

M2 is defined over **21 JAMNP-S stream kinds** ( UP 0 plus CE 128, 129, 131–148) carrying **41 wire messages**. Milestones are expressed as protocol coverage, so progress is measurable rather than asserted.

**Lane naming.** The M2 lanes are **N0–N7** (`N` for network). They were renamed from `L0–L7` to avoid collision with M1's existing `L0–L3`, which denote a different axis and already appear in the published conformance matrix.

| Lane | Scope | JAMNP-S stream kinds |
| :---- | :---- | :---- |
| **N0** | Connectivity and sync | UP 0, CE 128, CE 129 |
| **N1** | Block authoring | *(asserted over UP 0 and CE 128\)* |
| **N2** | Safrole tickets | CE 131, CE 132 |
| **N3** | Guaranteeing | CE 133, 134, 135, 146, 148 |
| **N4** | Availability | CE 137, 138, 139, 140, 141 |
| **N5** | Auditing and disputes | CE 136, 144, 145, 147 |
| **N6** | Preimages | CE 142, CE 143 |
| **N7** | Adversarial | all 21 kinds, negative cases |

| Milestone | Lanes | JAMNP-S coverage added | Cumulative | Meaning |
| :---- | :---- | :---- | :---- | :---- |
| **M2-A — Foundations live** | N0, N1 | UP 0, CE 128, CE 129 | 6 / 41 | A live client is graded end to end on connectivity, sync and authoring. First real verdict. |
| **M2-B — Self-tested** | N2 | CE 131, CE 132 | 8 / 41 | Safrole tickets covered, and the harness's own checks are proven by deliberately faulty simulated clients. |
| **M2-C — Guaranteeing** | N3 | CE 133, 134, 135, 146, 148 | 21 / 41 | Work-package submission, sharing, report distribution, bundle and segment requests. |
| **M2-D — Availability** | N4 | CE 137, 138, 139, 140, 141 | 30 / 41 | Erasure shards, audit shards, segment shards, assurances. |
| **M2-E — Audit & preimages** | N5, N6 | CE 136, 144, 145, 147, 142, 143 | **41 / 41** | Full protocol surface asserted. |
| **M2-F — Adversarial** | N7 | negative matrix across all 21 kinds | 41 / 41 \+ faults | Invalid input is proven to be *rejected*, not absorbed. |
| **M2-G — Rollout** | — | — | — | Two independent third-party clients graded end to end, reports published. |

M2-B is the structural milestone: before it, the harness reports; after it, the harness can be trusted to judge. M2-E is the completeness milestone. M2-G is the one the ecosystem sees.

## Rollout to third-party clients

Inherit M1's Docker-image submission format, environment contract and reporting habit, so M2 feels like the next lane set rather than a new regime. The one genuine addition is a **capability handshake**: the client declares which protocol lanes it implements, the harness runs only those, and the report distinguishes *not attempted* from *not exercised* from *failed*. This makes partial clients first-class instead of drowning them in irrelevant failures, and gives the conformance matrix an honest progress axis.

Onboarding runs as a ladder — T0 self-check (handshake only), T1 foundations (N0–N2), T2 full surface (N0–N6), T3 adversarial (N7, the bar for sign-off). T0 matters more than its position suggests: the first thing a non-Rust client will struggle with is QUIC and the certificate rules, and that failure must be legible as *a handshake failure* rather than “everything failed”.

# Roadmap (& timeline)

Estimates are planning figures, not commitments.

| Milestone | Effort | Elapsed (planned) | Elapsed (1 FTE) | Notes |
| :---- | :---- | :---- | :---- | :---- |
| **M2-A — First live verdict** | 1.8 pw | 2 w | wk 2 | Nine tasks remaining of eleven. Two blockers, one on each half of the connection set: the emulator closing the client's UP 0 stream, and a decode failure on inbound connections |
| **M2-B — Self-tested** | 7.7 pw | 6 w | wk 10 | Transport abstraction, in-process network and virtual clock, simulated clients, real scheduler, check test suite |
| **M2-C — N3 guaranteeing** | 5 pw | 3 w | wk 15 | Largest lane: 13 messages; needs refine and bundle handling from the oracle |
| **M2-D — N4 availability** | 4 pw | 2.5 w | wk 19 | Erasure coding and justifications; **depends on upstream oracle exports** |
| **M2-E — N5/N6 audit & preimages** | 3 pw | 2 w | wk 22 | Two lanes, 11 messages; cheapest per message |
| **M2-F — N7 adversarial** | 3.5 pw | 2.5 w | wk 25 | Fault injection across the full surface |
| **M2-G — Rollout** | 4 pw | 3 w (overlapping) | wk 29 | Contract, image, onboarding, reports; runs alongside M2-E/F |
| **Total** | **\~29 pw** | **\~18–20 w** | **\~28–31 w** | Critical path M2-A → M2-F; M2-G overlaps from M2-E |

**Critical path:** M2-A → M2-B → M2-C → M2-D → M2-E → M2-F. M2-G runs alongside from M2-E.

Elapsed duration assumes the independent lanes are worked in parallel where the critical path allows; staffing is out of scope for this document (see the linked RASCI). The lanes from M2-C onward are largely independent once the harness self-tests, so they parallelise well. At a single engineer, elapsed weeks equal person-weeks and the milestones land as shown in the last column. Two items do not compress with headcount in either direction: **M2-D** waits on an upstream export, and **M2-G** is gated on ecosystem teams responding.

# Key risks

| Risk | Likelihood | Impact | Mitigation / when |
| :---- | :---- | :---- | :---- |
| **Upstream drift breaks the build** | High | Days lost per occurrence | Observed twice in four weeks. Pin the reference client to a fixed revision instead of a path dependency; re-pin deliberately at most once per milestone. **Do at M2-A.** |
| Upstream exports for erasure coding and justifications never land | Medium | M2-D slips or is descoped | N4 is the only lane with a hard external dependency. **Confirm before M2-C ends.** |
| Ecosystem teams not ready for T1 | Medium | M2-G slips regardless of our progress | Publish the contract for comment **before** the harness is finished; M2-G is ecosystem-gated, not engineering-gated |
| The remaining undiagnosed defect proves deeper than estimated | Medium | M2-A grows; the inbound half stays blocked | 1–1.5 d budgeted; try the stream-lifetime fix first, which may resolve it. Re-estimate after diagnosis |
| Scope creep into full-spec or performance work | Low | Large | Out of scope by definition — that is M3 |

**Known unknown.** One defect remains observed but not root-caused: a `Malformed [u8; 64]` decode failure that drops the inbound connections. It has been narrowed — not an exotic protocol, and the block-announcement schemas match — but not resolved. Budgeted at 1–1.5 days, and it may share a root cause with the stream-lifetime defect, in which case fixing that one resolves both.


# Associated documents

- Initial repo (with design): [https\://github.com/bkchr/jam-m2-conformance](https://github.com/bkchr/jam-m2-conformance)
- [Full analysis](https://claude.ai/artifact/9aCxLcSLAt6xAsrWsRQ1R1?sk=iiHeXk29GTGIet1-Bso2-g)
