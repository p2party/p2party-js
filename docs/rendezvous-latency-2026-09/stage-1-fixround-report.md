# Stage 1, fix round — closing the review's findings

2026-09-08, from `1fb12a5`. Scope: the findings in `stage-1-review.md`. The
review found **no defect in the shipped code**, so nothing here changes what the
prototype does: every change is to a claim, a disclosure, a test or the harness's
own assertions. The delivery profile is untouched and steps 4-8 of
`optimization-plan.md` are still unstarted.

**Machine.** macOS 26.6.2, Apple silicon, 12 cores, load average 2.9-3.7
throughout, shared with other agents. `node` v24.11.1, `bun` 1.3.14. Every
number below is one loaded laptop and is an upper bound.

**Ports.** Stores `6700`-`6701` (`--store-port-base=6700`), page server `6720`,
and for the four-scenario runs `6730`-`6741` with page servers `6750`-`6752`.
Deliberately disjoint from the implementer's 6300-6320 and the reviewer's
6500-6520. Nothing below 5000 was bound; 5432 was never touched. `npm run
predist` was never run. One `--scenario=all` attempt on 6700 failed to start its
`healthy` store b because a **sibling agent's** process had taken 6701 in the
meantime; the harness said so plainly (`store b never answered /health on 6701`)
and the attempt was moved to 6730 rather than anything being killed. Every run
in §1 and §3 predates that and passed.

**Method.** Every number is from a run whose command is given. Numbers marked
_derived_ are computed from the profile literal rather than observed, and say so.
Scratch directory `…/scratchpad/fixround-opus5`, used by this task alone.

---

## 1. Sequential runs phase-lock; unlocking them changes what the numbers mean

The review's §1.1 is right and it matters more than it looks. A `--scenario=healthy`
run takes almost exactly an integer number of delivery windows, so a loop of
runs resamples nearly the same start phase `p` and every "mean" over such a
batch is a mean over one point of the phase space.

`docs/rendezvous-latency-2026-09/bench/phasesweep.sh` (committed with this
round) runs the harness `n` times with a **uniform random sleep in
`[0, deliveryWindowMs)` between runs**, which breaks the lock:

```
docs/rendezvous-latency-2026-09/bench/phasesweep.sh 16 4000 6700 6720 <out-dir>
```

| `p` (ms) | 234 | 547 | 636 | 961 | 1339 | 1687 | 1753 | 1808 | 2028 | 2291 | 2641 | 2672 | 3170 | 3586 | 3654 | 3954 |
| --- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| connect (s) | 24.5 | 24.2 | 24.1 | 23.8 | 23.4 | 23.1 | 23.0 | 22.9 | 22.7 | 22.4 | 22.1 | 22.1 | 21.5 | 21.1 | 21.1 | 20.8 |
| `w+0` requests | 15 | 7\* | 7 | 7 | 6 | 5 | 4 | 4 | 3 | 2 | 2 | 2 | 2 | 2 | 2 | 2 |

\* `p = 547` is below the 600 ms read offset and would be 15 but for §2.5: that
run's store began its chain in the same window, so the read had no predecessor
window and issued no request. It is the only run of the sixteen whose count is
not the rule's.

**16 of 16 PASS**, exit 0, `0 of 148 needles` on every run, zero `append
window-finalized` on every run. `p` now covers the window instead of clustering:
the implementer's sixteen observations all fell in `[755, 3339]` and the
reviewer's twelve of fourteen in `[1457, 1540]`.

**The connect spread is the start phase and almost nothing else.**
`p + connect` over these 16 runs is **24.74 s, min 24.67, max 24.79 — a total
range of 0.12 s**, against a `connect` range of 20.8-24.5 s. The rendezvous
finishes at a fixed point on the window grid; where it starts is the only thing
that moves. That replaces `stage-1-report.md`'s "the spread is about 2 s wider
than the 4 s uniform start phase would explain", which had no method and read
backwards (review Minor 1).

Mean connect over the unlocked sample is **22.7 s** (range 20.8-24.5), against
the report's phase-locked 22.6 s and the review's phase-locked 22.92 s. The
three agree, which is the useful result; the mean is only meaningful with the
phase distribution stated beside it.

**The milestone ladder still steps in fours.** Every one of the 16 runs prints
it; e.g. run 8 (`p` = 234 ms): `peer-observed` 8.4 s, `hello-opened` 12.4 s,
`accepted` 16.4 s, `offer-opened` 20.4 s, `handoff` 20.4/24.4 s. One window per
flight, which is what step 1 had to produce.

---

## 2. Review **Important 1** — item 15 described the wrong variable

### 2.1 What the code actually does

Read together, `#nextEvent` (`carrierRuntime.ts`) and `start()` say:

- `#nextEvent` returns the first queued event whose `timeMs >= nowMs`, so an
  event at offset `o` goes out in the start window **exactly when `o >= p`**.
- `start()` takes the cold-start branch when `nowMs >= allocationInstantMs`; it
  emits `missed`, **filters the queued allocation out of this window's queue**,
  and issues one allocation for `window + 1` immediately. So the allocation is
  present exactly once at every `p` — scheduled below the offset, cold-start at
  or above it. It is not a conditional extra.
- The once-per-session descriptor GET lands in the same window.
- One read event expands to `Σ publicChunksPerWindow` chunk GETs **plus** one
  checkpoint GET, and is followed by the witness pair under §3a item 14's
  ordinary condition.

So the rule is
**`1 (descriptor) + 1 (allocation) + every scheduled request at an offset ≥ p`**,
plus the conditional witness pair — not `2 + (append offsets after p)`. The
review's own reconstruction had the allocation right but omitted the witness
pair, which is why its table reads 14/13 where the harness measures 16/15.

### 2.2 Pinned by a test, not by a sample

A sample cannot establish a rule over a phase space it did not enter. The rule
is now asserted at every boundary the schedule has, from an injected clock:

```
bun test tests/blindRendezvous/prototype/carrierRuntime.test.ts \
  -t "still ahead of its start phase"        # 1 pass, 28 expect() calls
```

`issues exactly the scheduled events still ahead of its start phase`
(`carrierRuntime.test.ts`) arms a runtime at **fourteen** start phases —
`0, 100, 101, 350, 600, 601, 700, 701, 1300, 1301, 1700, 2100, 2101, 3999` — in
window `W2` rather than the chain-start window, so the read has a predecessor in
range, and compares `windowShape()` against the rule at each. Two transports per
phase, 28 assertions, all pass.

### 2.3 The corrected table

Per store, at the pinned profile (token 100, read 600, allocation 700, appends
1300/1500/1700/1900/2100, 5 chunk GETs). The five scheduled-route columns are
**asserted** by the test above; the descriptor and witness columns are the E2E
harness's, and the totals are _derived_ by adding them:

| `p` (ms) | token | chunk+ckpt | alloc | append | descriptor | witness | total |
| --- | --: | --: | --: | --: | --: | --: | --: |
| `≤ 100` | 1 | 5+1 | 1 | 5 | 1 | 2 | **16** |
| `100 < p ≤ 600` | 0 | 5+1 | 1 | 5 | 1 | 2 | **15** |
| `600 < p ≤ 1300` | 0 | 0 | 1 | 5 | 1 | 0 | **7** |
| `1300 < p ≤ 1500` | 0 | 0 | 1 | 4 | 1 | 0 | **6** |
| `1500 < p ≤ 1700` | 0 | 0 | 1 | 3 | 1 | 0 | **5** |
| `1700 < p ≤ 1900` | 0 | 0 | 1 | 2 | 1 | 0 | **4** |
| `1900 < p ≤ 2100` | 0 | 0 | 1 | 1 | 1 | 0 | **3** |
| `2100 < p` | 0 | 0 | 1 | 0 | 1 | 0 | **2** |

against **15** in every later window. **Fifteen of the sixteen** unlocked E2E
runs in §1 match their row exactly; the sixteenth is `p = 547`, which shows 7
where the table says 15 for the reason in §2.5 — its store's chain began in the
same window, so the read had no predecessor to fetch. **9 is not a reachable
total at any `p`**, which is review Important 3.

### 2.4 What the corrected disclosure says, and why it is smaller

- **That the session began in this window: always** — but from the descriptor
  GET, which is unconditional and on its own route (`/.well-known/…`). Not from
  the count.
- **The start phase to within one offset gap: only above the read offset.**
  `600 < p < 4000` is 85 % of the phase space and the missing offsets separate
  six bins there.
- **Below the read offset the leak very nearly closes.** Every scheduled event
  of the window still goes out, so the schedule contributes a complete
  steady-state trace; at `100 < p ≤ 600` the **total is exactly the 15 of a
  steady-state window**, the descriptor GET taking the token POST's place in the
  count. A store learns one bit there — whether `p ≤ 100` — and nothing finer.

Measured directly at the pinned profile, run 8, `p = 234 ms`:

```
start phase [A] presence-published at +234ms into its 4000ms delivery window;
  requests per window  w+0 a=15 b=15 (30)  w+1 a=15 b=15 (30)  w+2 a=15 b=15 (30)
    item 15 [A→a] start window w+0: token=0 read=5+1 alloc=1 append=5 witness=2 descriptor=1
```

The original disclosure's closed form was not merely unlucky in its sample: the
sample **could not** reach the region that falsifies it, because the loop that
produced it was phase-locked. That is the finding worth carrying forward.

### 2.5 One caveat the rule needs, and it is not about `p`

`scanWindow` returns `out-of-range` **without issuing a request** when the
window it would read is below the store's published chain start
(`storeClient.ts`). The read of the start window targets `w-1`, so a client that
starts in the *same* window the store's chain begins in issues no read at all,
whatever `p` is. In this harness the stores are spawned under a second before
the pages, so at the pinned 4,000 ms window that is the usual case: run 2
(`p = 547`, below the read offset) shows `read=0+0` for exactly this reason, and
run 8 shows `read=5+1` because its store's chain had begun in the previous
window. Any store older than one window has a predecessor to read, so this is a
fact about a store's age and not about the client — but a reader comparing the
table above against a harness log needs it, and it is now in the test's docblock.

---

## 3. Review **Important 6** — the shortest-window rows

Several runs per row, randomised inter-run sleep, `--scenario=healthy`, pinned
cohort 8, HEAD:

```
node docs/e2e/blind-two-store/run.mjs --scenario=healthy \
  --window-ms=<W> --store-port-base=6700 --page-port=6720 [--deadline-ms=60000]
```

| `--window-ms` | runs | result | `append window-finalized` |
| ---: | ---: | --- | --- |
| 4000 | 16 | 16 PASS, 20.8-24.5 s | 0 on every run |
| 2000 | 3 | 3 PASS, 10.7 / 11.3 / 12.2 s | 0 on every run |
| 1000 | 3 | 3 PASS, 5.3 / 5.7 / 6.1 s | 0 on every run |
| 500 | 4 | 4 PASS, 3.3 / 3.4 / 3.5 / 3.6 s | 0 on every run |
| 250 | 3 | **1 PASS (1.8 s), 2 FAIL** | 5 and 475 misses; one also timed out |
| 240 | 2 | **1 PASS (1.7 s), 1 FAIL** | 0 misses; both pages degraded to `single-carrier-dependent` |
| 200 | 2 | 2 FAIL | 641 and 841 misses, then timeout |

**2,000 / 1,000 / 500 ms reproduced; 250 and 240 did not, and neither does the
idea of a floor.** The report recorded "250 ms passes in 1.8 s, the first append
failures appear at 240 ms"; the review measured 250 ms failing with 450 misses.
Both are true, of different runs. Below 500 ms this profile is in a **flaky
band**, not on one side or the other of a step, and a single run per row cannot
see that. The shipped rows in
`docs/blind-rendezvous-two-store-prototype.md` and
`docs/e2e/blind-two-store/README.md` are now the multi-run table with the flaky
band named, and `stage-1-report.md` §1.5 carries a correction.

This is a measurement of a flag, not a proposal. The pinned profile is still
4,000 ms at cohort 8.

---

## 4. Review **Important 4** — the harness's three assertions

**(c) was not an assertion.** It computed the start phase and the first three
windows' counts and passed them to `say()`; it never called `note()`, so nothing
in it could fail. It is now an assertion of design §3a item 15's rule, per
route, against the observed `p`:

- The five scheduled routes are compared against the rule evaluated at
  `p ± START_PHASE_TOLERANCE_MS` (60 ms at a 4,000 ms window, scaled with the
  window). `p` is read on the driver side and the schedule compares its own
  clock, so within a band of an offset either outcome is accepted rather than
  guessed at. The count is monotone in `p`, so evaluating the rule at both ends
  of the band brackets every outcome the schedule could legitimately produce.
- The **allocation** is compared with no tolerance at all, because the rule is
  `exactly 1` at every `p`. That is the invariant `start()`'s own comment
  states — two allocations for one target window would be "one more than the
  profile's fixed shape" — and nothing checked it outside the unit test's single
  boundary case.
- Two more invariants design §5 asserts and nothing checked: **exactly one
  descriptor GET per store per session**, and **no requests on a route §5 does
  not enumerate**.
- If a page reported no start phase, or no page-store pair produced a start
  window, the assertion **fails** rather than skipping.

Requests are now tallied per route, which is what makes the per-route rule
checkable at all; `profileTool.ts info` gained the three schedule offsets and
the per-class append offsets so the assertion compares against the profile
rather than against rescaled constants copied into the harness.

**(b) was silently vacuous.** `detailsOf(page, kind)` returns `[]` when no
transport flight was published, and the loop body then never ran, so a run that
never reached the transport stage passed the payload-class check by having
nothing to check. It now counts the flights that carried a class and requires
**exactly one `offer-sent` and one `answered` across the two pages** — zero is
the vacuous pass, and more than one is a repeated transport flight, which is a
delivery-geometry change of its own.

**Non-vacuity, proven.** Each mutation was applied with `perl -0pi`, its landing
proven by SHA-256 before and after, the harness run, and the file restored from
a pristine copy taken beforehand and proven byte-identical with `diff`:

| mutation | failure |
| --- | --- |
| `classesSeen[kind] += 1` → `+= 0` (`run.mjs`) | `SCENARIO healthy FAIL — the run reported 0 offer-sent transport flights carrying a payload class across both pages, expected exactly 1 — the payload-class assertion had nothing to check; …0 answered…` |
| `allocation: 1` → `2` in the predictor (`run.mjs`) | `FAIL healthy: page A start window (index 0) sent 1 allocation requests to store a at p=1393ms; design §3a item 15's rule predicts 2 (tolerance ±60ms)` — the `1` is read from the live request log |

`run.mjs` sha `535dcb60…` before, `c9786816…` / `497b0541…` mutated, `535dcb60…`
restored, `diff` clean both times.

**One reporting defect found by these runs and fixed.** The
`of which "append window-finalized"  A=0 B=0` line is a snapshot printed while
events are still arriving: at `--window-ms=250` a run printed `A=0 B=0` there and
then failed on exactly that assertion, because the misses arrived during
teardown. A final count is now printed after teardown, on every path including a
timeout — which is also the only place it appears on a run that times out.

---

## 5. Review §6 — keeping the precomputed rows, for the right reason

The report justified step 2 as "headroom", which is the weakest available
defence of a change that costs 40 % more disk per window. Isolated: **only** the
precomputed read path disabled — `cached !== undefined` forced false in both
`readChunkEncoded` and `readCheckpointEncoded`, leaving the schema, the writes
and the codec untouched; landing proven by hash, restored byte-identically.

| `--window-ms` | read path ON (HEAD) | read path OFF |
| ---: | --- | --- |
| 1000 | 3/3 PASS, 5.3-6.1 s, 0 misses | 3 PASS (5.4-7.1 s), **2 FAIL in 5** (one with 3 misses, one a bare timeout) |
| 500 | 4/4 PASS, 3.3-3.6 s, 0 misses | 3 PASS (4.6-5.1 s), **2 FAIL in 5**, both with real `append window-finalized` misses |

**KEEP.** Step 2 is what makes a 500 ms window reachable at all — with the read
path off, a 500 ms window is *slower than a 1,000 ms window with it on* — and
"how short can the window go" is the next stage's question. Two further facts
belong on the record beside the +40 %: the `chunk_response` and
`checkpoint_response` rows are by construction the reconstructible part
(`loadWindow` stays the source of truth and every read falls back to it, which a
test holds), so they are the first thing a retention sweep should drop; and the
correctness of the lookup rests on an unstated precondition — **nothing prunes
finalized windows** — which is now named in `storeCore.ts`'s docblock along with
the ordering a future sweep must respect.

The review's own isolation (`500 ms` PASS → FAIL, `1000 ms` unchanged) agrees in
direction; my larger sample shows the effect at 1,000 ms as well, as flakiness
rather than as a clean failure.

---

## 6. The Critical — every restatement of the fixed-request-count claim

`git grep -iE "thirteen|only part of this trace"` over `docs/`, `src/` and
`tests/` at `1fb12a5` returns **44 lines in 14 files**; one
(`blind-rendezvous-implementation-status.md`, "thirteen findings") is unrelated,
leaving **43 restatements**. Each was read.

**Five were unqualified universal assertions that this branch's own commits
disprove. All five are fixed:**

| where | was | now |
| --- | --- | --- |
| `…-design.md:619` | "**Thirteen fixed requests**, issued whether or not anything real was sent" | "…**in every window after the client's first**" |
| `…-design.md:648-649` | the witness conditioning "is the only part of this trace that is not fixed" | "**It is not the only part…**", with the mechanism and a pointer to item 15 |
| `carrierRuntime.ts:13-18` | "…one read — **thirteen requests, always.** The witness pair is the one exception" | both exceptions named, items 14 **and** 15 cited, the cold-start allocation spelled out |
| `attack-privacy.md:264` | "**Fixed count.** Thirteen requests per store per window … idle or busy" | "…**in every window after the client's first**, which is §3a item 15" |
| `attack-privacy.md:1087` | "a client that sends nothing still emits the same thirteen requests" | "…in every window after its first (§3a item 15)" |

**Three lines in the two shipped documents were already correctly qualified** by
`17bba7d` (`prototype.md:191,195`; `README.md:305`) and were re-read and
verified.

**The remaining 35 are conditional statements about what a *candidate change*
would do to the trace** — "becomes fourteen", "→ ten", "unchanged by every
candidate in this report" — or quotations inside a dated record. None asserts
that the count is fixed in the session's first window; each was read and left as
it stands.

Separately, **three places carried the stale "9 requests" first-window number**
and now carry a correction: `observed.md` §8 (the source record the others point
at), `attack-honesty.md` §2.3, and `optimization-plan.md` §6.1's item-15 draft,
which is now marked superseded by what shipped.

---

## 7. Review **Important 2** — three present-tense sentences the branch retracts

| where | fixed how |
| --- | --- |
| `README.md` "It is not a dead end — it is a _cost_ problem, and the cost has a second knob" | Past tense, and it now says the cost was the store's, not the cohort's, and points at the retraction 60 lines below |
| `prototype.md` / `README.md` "**The knob that buys the latency is the one that sizes the shared bucket.**" | "**The knob that _appeared_ to buy the latency … what it bought was a way around a store defect**", body in the past tense |
| `prototype.md` / `README.md` "the shorter window that **the smaller cohort makes possible**" | "**The shorter window was never made possible by the smaller cohort**" — 2,000 / 1,000 / 500 ms all complete at the pinned cohort of 8, which §3 measures |

---

## 8. Review **Important 5** — reproducibility

- `stage-1-report.md`'s "**Nine** new tests" is corrected to **ten, from eight
  `test(...)` call sites** (one is parameterised over three labels).
- `benchstore.ts`, `benchscan.ts` and `mutate.sh` are **committed**, under
  `docs/rendezvous-latency-2026-09/bench/`, with their absolute imports made
  repo-relative, and re-run at HEAD to confirm they still measure what the
  report says:

  | | report | re-run here |
  | --- | ---: | ---: |
  | `saveWindow` p50 | 2.22 ms | 2.08 ms |
  | `loadWindow` p50 | 7.34 ms | 7.33 ms |
  | `loadChunkResponse` p50 | 0.07 ms | 0.10 ms |
  | `loadCheckpointResponse` p50 | 0.01 ms | 0.00 ms |
  | window row / response rows | 3,450,684 / 1,377,756 B | 3,450,684 / 1,377,756 B (+39.9 %) |
  | scan of one store's window, p50 n=20 | 4.36 ms | 4.68 ms |

  `mutate.sh` was exercised through its committed copy to re-derive mutation
  M-B below, including its `RESTORED byte-identical` check. `phasesweep.sh`,
  the driver for §1 and §3, is committed beside them.
- **The one section that remains author-reproducible is §1.4**, the milestone
  ladder, whose `s1-1.txt` was never committed. It is stated as such in the
  report, and the ladder itself was re-measured here (§1). The "before
  (`8be5c14`)" column of §1.1 also cannot be re-derived without reverse-applying
  the two perf commits; the command for that is in the review's §1.1.

---

## 9. New test, and its individual mutation

`issues exactly the scheduled events still ahead of its start phase`
(`tests/blindRendezvous/prototype/carrierRuntime.test.ts`). Suite before: 591
pass. After: **592 pass, 0 fail, 3,465 expect() calls, 40 files.**

| mutation | tests killed | failure was |
| --- | ---: | --- |
| **M-A**: drop the cold-start allocation, `carrierRuntime.ts` `start()` | 2 — the new test **and** "issues one allocation when it starts exactly on the allocation offset" | `expect(received).toEqual(expected)`, `"allocation": 1` → `0` |
| **M-B**: `#nextEvent`'s `event.timeMs >= nowMs` → `> nowMs` | **1, only the new test** | `expect(received).toEqual(expected)`, `"token": 1` → `0` at `p = 100` |

Both failures are the test's **own** assertion reporting a wrong value on a code
path that completed successfully — not a stub, not a throw, not a timeout. M-B
kills nothing else in the file, which is the isolation the brief asks for; M-A
overlaps with the pre-existing cold-start test, which is honest and expected,
since the two assert the same invariant at different phases.

`carrierRuntime.ts` sha `6eb8d8e3…` before, `840fe22e…` under M-A, `3813d671…`
under M-B, `6eb8d8e3…` after each restore, `diff` clean each time.

---

## 10. Verification

```
bun test tests/blindRendezvous        592 pass, 0 fail, 3465 expect(), 40 files
npx tsc -p tsconfig.json --noEmit     clean
npx tsc -p tsconfig.test.json --noEmit clean
npx prettier --check <every .ts/.mjs touched>   clean
node --check docs/e2e/blind-two-store/run.mjs   clean
```

All four scenarios were run at HEAD with the new assertions in place:
`healthy` 23.3 s, `kill-a` 23.4 s, `withhold-a` 23.5 s (`--store-port-base=6730`)
and `unreachable-b-for-one` 21.1 s (`--store-port-base=6740`), identical audit
verdicts (`0 of 148 needles`) and the expected topologies. The
`unreachable-b-for-one` run inside the `--scenario=all` batch timed out at 180 s
and passed on its own re-run; see §11.

The Markdown in this corpus is **not** prettier-clean at `1fb12a5` and was left
alone: running `--write` on it would bury this change under an unrelated
reformat. Checked by extracting the HEAD versions to a scratch directory and
running `prettier --check` on them.

`git status --short` shows only this task's files. Nothing was staged except by
explicit path; no `git add -A`, no bare commit, no amend, no stash, no reset, no
checkout, no clean, no switch. `npm run predist` was never run.

---

## 11. Not done, and why

- **Review Minor 2** (item 17 lacks a "What would fix it" clause), **Minor 4**
  (`blind-rendezvous-handoff.md`'s pre-fix scenario times presented as current)
  and **Minor 5** ("item 15" denoting three different leaks across the research
  corpus, and two files still saying "§3a's fourteen") are unaddressed. Minor 5
  is the one with teeth: stage 2 will cite "item 15" and a renumbering pass over
  `docs/rendezvous-latency-2026-09/` should happen before it does.
- **Minor 7** — `#saveFinalizedResponses` (3.41 ms p50) is the one place
  server-side timing moved. It is post-commit and inside the drain headroom, so
  it is not a delivery-timing change; recorded here rather than argued.
- **The intermittent hang** was not investigated. It appeared **once** in this
  round, at HEAD: **36 runs** in configurations expected to complete — 16 at
  `--window-ms=4000`, 3 at 2000, 3 at 1000, 4 at 500, 3 pilots at 1000, 3 plain
  `healthy` runs, and the four scenarios of a `--scenario=all` batch plus one
  re-run — completed **35 of 36**, the exception being an
  `unreachable-b-for-one` run that timed out at 180 s and passed on re-run. That
  is 1 in 36, against the implementer's 3 in 13 and the review's 0 in 21; the
  three samples are consistent with a low single-digit rate and not with 23 %.
  A second bare timeout, with zero append misses, occurred in the deliberately
  degraded step-2-off set of §5. The review's advice stands — scope it as a
  measurement task with a randomised inter-run sleep, which `bench/phasesweep.sh`
  now provides, on an idle machine, and dump the data-channel and protocol-v4
  handshake state on a timeout.
