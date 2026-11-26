# Stage 1 review — store codec, precomputed rows, harness assertions, disclosures

Reviewer: independent agent, 2026-09-08. Range `8be5c14..HEAD` (6 commits).
Worktree `/Users/deliberative/Desktop/@p2party/p2party-js-latency`, branch
`feat/rendezvous-latency-2026-09`. Nothing was committed; every mutation below
was restored byte-identically and `git status --short` is empty at the end of
this review. Ports used for every harness run: **stores 6500-6507, page 6520**
(the implementer used 6300-6307/6320; no overlap, and nothing below 5000 was
bound).

**Verdict: NEEDS FIXES.** 1 Critical, 6 Important, 7 Minor. Every finding is in
documentation or in the framing of the work. **No defect was found in the
shipped code.** The codec is exactly equivalent, the precomputed rows cannot
diverge from the window row, the measurements reproduce, and the tests are
non-vacuous. What fails the project's own standard is the disclosure sweep: the
commit that corrected four false sentences left a directly contradictory one
standing in the authoritative design document, and the new item 15 states a
closed form that my own runs falsify outside the region it was sampled in.

---

## 0. Baseline

| Check | Result |
| --- | --- |
| `bun test tests/blindRendezvous` | **591 pass / 0 fail**, 3437 expect() calls, 40 files, 12.2 s |
| `npx tsc -p tsconfig.json --noEmit` | clean |
| `npx tsc -p tsconfig.test.json --noEmit` | clean |
| `git status --short` at start and end | empty |

Machine: macOS 26.6.2, 12 cores, load average 2.4-3.3 throughout (other agents
active). Every number below is therefore an upper bound, and the run-to-run
spread should be read with that in mind.

---

## 1. Are the measurements real, and reproducible?

### 1.1 End to end — reproduced, with a caveat about how the sample is drawn

`node docs/e2e/blind-two-store/run.mjs --scenario=healthy --store-port-base=6500
--page-port=6520`, `--window-ms` left at the pinned 4,000, cohort 8, **n = 14**,
run sequentially and deliberately (never in parallel):

```
20.8  21.6  23.2  23.2  23.2  23.2  23.3  23.2  23.2  23.2  23.2  23.2  23.2  23.2
n=14  mean 22.92 s  median 23.2 s  min 20.8 s  max 23.3 s
```

All 14 PASS, exit 0, `0 of 148 needles` on every run, zero `append
window-finalized`.

I also reproduced the **before** figure rather than taking it on trust. I
reverse-applied the two perf commits to the working tree, restricted to
`src/blindRendezvous/prototype/store/` so that `196c52e`'s driver
instrumentation stayed in place (`git diff HEAD 8be5c14 -- .../store/ | git
apply`), and re-ran the same command:

```
before (store dir at 8be5c14):  41.0 s,  38.5 s   (n=2)
after  (HEAD):                  22.92 s mean      (n=14)
```

**The claim holds.** The report's 32.8/37.1/39.0 → 21.4-24.0 and mean 22.6
reproduce as 38.5-41.0 → 20.8-23.3 and mean 22.92 on a busier machine. The ratio
I measure is ≈1.7×, marginally better than the reported 1.6×. The plan's
prediction of ≈22.6 s is met by both samples.

**The caveat, which is mine and not in the report.** The reported and observed
means are *not* means over a uniform start phase. 9 of my 14 runs started at
`p ≈ 1,457-1,540 ms`, and the connect time tracks it almost deterministically:

| start phase `p` | runs | connect |
| ---: | ---: | ---: |
| 3,938 ms | 1 | 20.8 s |
| 3,149 ms | 1 | 21.6 s |
| 1,457-1,540 ms | 12 | 23.2-23.3 s |

A scenario takes ≈28 s wall clock including teardown, which is 7 × 4,000 ms — so
a **loop of sequential runs phase-locks to the delivery-window grid** and
resamples nearly the same `p` every time. This explains both the tightness of my
distribution and the fact that the implementer's sixteen start-phase
observations all landed in `p ∈ [755, 3,339]`. It matters twice: the "mean" is a
mean over a biased phase distribution, and §5 below shows the unsampled region
is exactly where item 15's formula breaks.

**Minor 1.** `stage-1-report.md:90-93` — "The spread within each group is about
2 s wider than the 4 s uniform start phase would explain on its own." The
after-group spread is 21.4-24.0 = 2.6 s, which is *narrower* than 4 s, not 2 s
wider; and the phase distribution is not uniform. The sentence has no stated
method and, read literally, is backwards. Delete it or replace it with the
phase/connect correlation, which is a real and stronger result.

### 1.2 Store-port and scan microbenchmarks — plausible, arithmetic checks, not reproducible

`stage-1-report.md:31-72` cites `bun run <scratchpad>/benchstore.ts 12` and
`benchscan.ts 20`. **Neither script is in the repo**, nor is `mutate.sh` or
`s1-1.txt`. §1.1, §1.2, §1.4 and the whole of §2 therefore cannot be
re-derived by anyone but the author from this worktree. See Important 5.

What I could check independently:

- The **disk arithmetic** is internally consistent. 1,377,756 / 3,450,684 =
  39.9 %, so "+40 %" is right. The window row's 3,450,684 B is consistent with
  1,376,256 B of finalized objects at 2× for hex (2,752,512 B) plus ~10 occupied
  slots of mixed size class in hex (~698,000 B). The claim in
  `storeSqlite.ts:262-276` describing this is accurate.
- The **scan cost** is corroborated end-to-end: my Step 2 isolation (§6) shows
  the store's per-request cost, not the browser's, sets the achievable window
  floor — which is the substantive claim the 4.36 ms figure exists to support.
- The **codec speedup** is corroborated by the reproduced before/after
  end-to-end delta, which is the only place it matters.

I did not attempt to reconstruct the two benchmark harnesses.

---

## 2. Is the codec change equivalent?

**Yes — proven, not argued.** I extracted the old (`8be5c14`) and new (`HEAD`)
`hexOf` and `bytesFrom` verbatim into a differential fuzzer and ran
**1,711,085 cases under both `node` and `bun` (the store's actual runtime),
with 0 mismatches in either.** Coverage:

- **Encode**: all 256 single-byte values; every length 0-512; 5,000 random
  `subarray` views with a **non-zero `byteOffset`** — the one real hazard in
  `Buffer.from(value.buffer, value.byteOffset, value.byteLength)`, since
  `Buffer.from(value.buffer)` alone would have silently encoded the whole
  backing store; a Node `Buffer`-backed view; a `SharedArrayBuffer`-backed view.
- **Round trip**: new→new, old-encode→new-decode and new-encode→old-decode, for
  every length 0-400.
- **Decode**: 500,000 random strings over an alphabet mixing hex digits,
  uppercase, `g`, whitespace, `\n`, `%+/=`, Latin-1, `Ā`, `߿`, `￿` and an
  astral emoji; **exhaustive over all 2-character strings with code units
  0..0x2FF** (589,824 cases, covering all ASCII, all Latin-1 and the `< 256`
  guard boundary); exhaustive over all 4-character strings from a 28-character
  near-hex alphabet (614,656 cases); and a hand-built adversarial list including
  `""`, `"0"`, `"FF"`, `"0x00"`, `"0\n"`, lone surrogates and full-width digits.

Accept/reject and decoded bytes agree on every case. The empty string
round-trips. Odd lengths reject on both. `$`-anchoring in the old regex is
end-of-input in JavaScript (unlike Perl), so `"00\n"` rejected on both sides —
confirmed empirically, not assumed.

The `< 256` guard and the `-1`-filled `Int8Array` are both load-bearing and
correctly reasoned in the docblock at `storeSqlite.ts:69-82`: without the guard,
an out-of-range typed-array read yields `undefined`, `undefined < 0` is `false`,
and `(undefined << 4) | low` silently produces `low`. Mutation M1 below
demonstrates exactly that, and a test catches it.

One behavioural difference, harmless and worth one line if anyone touches this
again: the old codec validated the whole string *before* allocating, the new one
allocates `value.length >>> 1` bytes first and validates per pair. For a
pathologically long invalid row that is a transient allocation the old code
avoided. It cannot corrupt anything.

**No stored byte changes meaning.** Verdict: equivalent.

---

## 3. Can the three harness assertions genuinely fail?

### (a) `append window-finalized` — YES, and it does the thing it was moved for

Verified **without any code mutation**, which is stronger than the
implementer's proof: `--window-ms=200 --deadline-ms=45000` on unmodified HEAD.

```
SCENARIO healthy FAIL — page B appended after its window closed —
  …w8944320494: append window-finalized; TIMEOUT healthy: rendezvous and
  message exchange (45000ms)
TWO-STORE E2E FAILURE (1 of 1 scenarios)     exit 1
```

This is the decisive case for the design choice. The run **also timed out**, and
because the assertion is evaluated inside `push()` as the event arrives
(`run.mjs:466-478`) rather than with the other verdicts (`run.mjs:~840`), it
named the cause *first* in the failure string. Evaluated with the other
verdicts it would have contributed nothing — the verdict block is inside the
`try` and is never reached on a timeout. The implementer's reasoning at
`stage-1-report.md:495-500` is correct and the placement is right.

I hit the same behaviour a second time by accident at `--window-ms=250` (§4),
where it again named the cause on an otherwise opaque timeout. This assertion
earns its place twice over.

### (b) transport payload class — YES

Mutated `run.mjs:101` `EXPECTED_TRANSPORT_PAYLOAD_CLASS = 0` → `1`
(sha `e1d4adae…` → `de4645c9…`, landing proven by hash), ran `--scenario=healthy`:

```
SCENARIO healthy FAIL — page A published its answered transport flight in
  operationPayloadClass 0, expected 1: …; page B published its offer-sent
  transport flight in operationPayloadClass 0, expected 1: …     exit 1
```

Restored byte-identically (`diff` clean, sha back to `e1d4adae…`). Note that in
this run **page B offered and page A answered** — the reverse of my earlier
runs — which independently justifies the comment in
`pairDriver.test.ts:280-282` that the offering side is chosen by the protocol
and must not be assumed.

**Important 4a.** Assertion (b) is *silently vacuous on any run that does not
reach the transport flight*. `detailsOf(page, kind)` returns `[]` and the loop
body never executes, so a run in which no offer is ever sent passes this
assertion. The healthy path has a separate required-phase check, so this is not
a live hole today, but the assertion is written as "the class is 0" when what it
enforces is "if a class was reported, it is 0". One extra line — assert that
exactly one `offer-sent` and one `answered` carry a class across the two pages —
would close it and would also pin the flight count the plan's Step 6 intends to
change.

### (c) the start phase — NO. It is not an assertion.

`run.mjs:899-913` computes the start phase and the first three windows' request
counts and passes them to `say()`. It **never calls `note()`**, so it can never
add to `problems`, and `const ok = problems.length === 0` (`run.mjs:1143`) can
never see it. Nothing in it can fail. The comment block that introduces all
three is headed "**Three assertions** that exist because these failures are
otherwise silent" (`run.mjs:859`).

**Important 4b.** Calling (c) an assertion is the one place in this branch where
the work is described as stronger than it is, in a project whose whole discipline
is not doing that. It is *good and necessary instrumentation* — without it item
15 could not have been measured, and it is the reason I could falsify item 15's
formula in §5. But it is instrumentation.

Two ways to fix, either acceptable:

1. **Relabel.** Change the header to "Two assertions and one measurement", and
   move (c) out of the block. Cheapest, and honest.
2. **Make it an assertion.** The natural predicate is already implied by item
   15: `note()` if the observed start-window count differs from the count item
   15's rule predicts for the observed `p`. That would have caught the formula
   error in §5 automatically, and it would guard every future profile change the
   way (a) guards the window length. This is the version I would recommend, but
   it must not be written until the rule in §5 is corrected — asserting a wrong
   rule is worse than printing a number.

As shipped, (c) does not earn the label. It does earn its place in the harness.

---

## 4. The claim that changes everything downstream: does the shorter window hold?

**Yes, decisively, for 2,000 ms and 1,000 ms.** All at HEAD, pinned cohort 8,
`--scenario=healthy`, ports 6500/6520:

| `--window-ms` | my runs | my result | report |
| ---: | ---: | --- | --- |
| 2000 | n=2 | **12.0 s, 11.2 s**, PASS, 0 finalized misses | 12.4 s |
| 1000 | n=2 | **6.1 s, 6.2 s**, PASS, 0 finalized misses | 5.3 s |
| 500 | n=1 | 3.3 s, PASS, 0 finalized misses | 3.4 s |
| 250 | n=1 | **FAIL** — 450 `append window-finalized`, then timeout | 1.8 s PASS |
| 200 | n=1 | FAIL — same shape | FAIL (from 240 down) |

**The headline result is confirmed.** A 2,000 ms delivery window at the pinned
cohort of 8 does not stall, does not miss a single append, and completes in
roughly half the time of the pinned 4,000 ms profile. The two shipped findings
that rested on the stall being real were genuinely wrong, and correcting them
without shipping a profile change was the right call. Most of the remaining
latency is indeed available by shortening the window, and the rest of the plan
should be re-derived on that basis.

My 1,000 ms figure is ~15 % slower than the report's (6.1-6.2 s vs 5.3 s), which
is one machine under more load and well inside what a single run at a 1 s window
can vary by. It does not change the conclusion.

**Important 6.** The 250 ms row does **not** reproduce here — it failed with 450
`append window-finalized` misses and a timeout, and the report's stated failure
floor ("append failures first appear at 240 ms") is at least one step
optimistic on this machine. The report is careful to label the sweep as single
runs of a measurement flag, but the 250 ms and 240 ms numbers have been copied
into **two shipped documents** —
`docs/blind-rendezvous-two-store-prototype.md:503-507` and
`docs/e2e/blind-two-store/README.md:643-648` — as "**250 ms** in **1.8 s**" and
"The first append failures appear at `--window-ms=240`". Those are the two rows
that did not survive a second machine. Either drop the 500/250/240 rows from the
shipped documents and keep only 2,000 and 1,000 (which reproduce robustly), or
mark the floor as machine-dependent and unreplicated. As written they are the
most quotable and least reliable numbers on the branch.

---

## 5. The disclosure work

### 5.1 Style and numbering — good

§3a now carries **17 items, contiguously numbered 1..17**, no gaps, no
duplicates (`design.md:104,145,148,149,151,154,158,163,166,169,171,173,175,177,205,229,243`).
The list's intro (`design.md:101`) states no total, so nothing there goes stale.
Items 15 and 16 match the heavyweight style of items 1 and 14 exactly: bold lead
sentence, an explicit "**What would fix it**" clause with its price, and a
statement of which test does *not* cover them. The outward summary was updated
correctly — "seventeen residual leaks. All seventeen are disclosed there"
(`prototype.md:543`) and the heading "### 2–17, in brief" (`prototype.md:600`).

**Minor 2.** Item 17 (`design.md:243-250`) is the odd one out: no "What would
fix it" clause and no coverage statement, although it names the unused
mitigation (`roomSlotsPerClient`, pinned to 1). Items 15 and 16 both have both.
One sentence — pinning `roomSlotsPerClient` above 1 folds `K` rooms behind one
fixed object count, at the price of `K`× the fixed traffic for every client
regardless of how many rooms they hold — would bring it into line.

### 5.2 The "nine requests" correction — the disclosure now describes a variable, but the variable it describes is wrong outside the sampled region

**The good part.** The plan's `optimization-plan.md:607-608` asserted "**9
requests** and no append bodies in the start window against 15 in every later
one". Item 15 as shipped states a **closed form in `p`** —
`design.md:209-216`, "the start window carries **2 + (append offsets after `p`)**
requests per store … **2** at `p` = 3,339 ms, **5** at `p` = 1,581-1,601 ms,
**7** at `p` = 755-1,227 ms — against **15** in every later window". That is a
variable, not a sample, and the report is candid at `stage-1-report.md:152-155`
that 9 is not among the observed values. **The request in the review brief is
satisfied: the disclosure describes the variable.**

**Important 1 — the closed form is false below the allocation offset, and my own
runs show it.** Reading `carrierRuntime.ts:660-674` (`#nextEvent` skips any
event whose instant has passed) together with `carrierRuntime.ts:424-448` (the
cold-start branch, which fires **only when `nowMs >= allocationInstantMs`**,
emits the `missed` event, issues one allocation for `window+1`, and *filters the
queued allocation out of the schedule*), the start-window count is:

| `p` (fraction of window) | descriptor | token | read | alloc | cold-start alloc | appends ahead | total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| < 100 ms | 1 | 1 | 6 | 1 | 0 | 5 | **14** |
| 100-600 | 1 | 0 | 6 | 1 | 0 | 5 | **13** |
| 700-1300 | 1 | 0 | 0 | 0 | 1 | 5 | **7** |
| 1300-1500 | 1 | 0 | 0 | 0 | 1 | 4 | **6** |
| 1500-1700 | 1 | 0 | 0 | 0 | 1 | 3 | **5** |
| 2100-4000 | 1 | 0 | 0 | 0 | 1 | 0 | **2** |

Three consequences, all confirmed against my own harness output:

1. **The "2" is not two schedule events.** It is the once-per-session descriptor
   GET plus the cold-start allocation POST — and the second of those *exists
   only because `p >= 700`*. Item 15 frames the count as "only the events still
   ahead of `p`" (`design.md:208-209`), which reads as if both came from the
   schedule. `design.md:220-221` then presents the descriptor GET as an
   *additional* signal ("states the first bit again") when it is already one of
   the two.
2. **The formula is false for `p < 700 ms`**, roughly 17.5 % of start phases.
   At `p = 500` it predicts 7 and the true value is 13.
3. **Below the read offset the leak very nearly disappears**, which the
   disclosure does not say. I observed this directly: a 1,000 ms run at
   `p = 89 ms` (the scaled equivalent of `p = 356 ms` at the pinned profile)
   printed `w+0 a=15 b=15` — **a start window indistinguishable from a
   steady-state window**. Item 15's central claim, that "a store therefore reads
   off its own log … both that this client's session began in this window and …
   the start phase to within one offset gap", is simply not true in that region.

I also observed **6** at `p = 1,457-1,499` on the pinned profile, twice — a
value not in item 15's list, and one the formula predicts correctly. So the rule
is right where it was sampled and wrong where it was not, and the sampling was
biased by the phase-locking described in §1.1.

The fix is small and the honest version is *weaker*, not stronger: state the
rule as `1 (descriptor) + (scheduled requests still ahead of p)`, note that the
allocation event is replaced by a cold-start allocation for the next window once
`p >= allocationRequestOffsetMs`, give the full range 2…14, and say plainly that
for `p` below `publicReadOffsetMs` the start window is **not** distinguishable
from a later one. That is a smaller leak than currently disclosed, correctly
described.

**Important 3 — the source record was not corrected.**
`docs/rendezvous-latency-2026-09/observed.md:591-593` still reads "`w0+0` = 9
requests and **0 append POST bodies**", in §8, as the primary measurement the
plan and three analysis documents cite. Commit `17bba7d` added two "Correction,
2026-09-08 (stage 1)" blockquotes to **this same file** (§3 and §4e) and left §8
untouched. 9 is not merely an unlucky sample: it is not a reachable value of the
count at the pinned profile at all. The same stale number survives at
`optimization-plan.md:607-608`, `attack-privacy.md:199,297-298`,
`attack-honesty.md:150,288` and `angle-presence-discovery.md:236` (**Minor 3** —
these are research notes rather than shipped documents, but `observed.md` §8 is
the record they all point at, and it is one blockquote away from being right).

### 5.3 The corrected sentences — all four are now true

| Correction | Where it now stands | True? |
| --- | --- | --- |
| (a) "the browser cannot finish 1.38 MB × 2 stores" | `prototype.md:483-497`, `README.md:619-634` | **Yes** — blames the store, carries 4.4 ms / 4.0 ms, past tense correct |
| (b) cohort table's causal reading | `prototype.md:460-469`, `README.md:599-606` blockquotes | **Yes**, but see Important 2 |
| (c) "thirteen fixed requests … whether idle" | `prototype.md:195-200`, `README.md:308-311` | **Yes** in those two files, **no** in two others — see Critical 1 |
| (d) "a 2,000 ms window cannot append at all" | `prototype.md:499-510`, `README.md:641-652` | **Yes**, and correctly restates that the pinned profile is unchanged |

### 5.4 Sentences the branch made false and did not fix

**CRITICAL 1 — the design document contradicts its own new disclosure, in the
same file, uncorrected.**

- `docs/blind-rendezvous-two-store-prototype-design.md:648-649`: the witness
  conditioning "**is the only part of this trace that is not fixed**." Item 15,
  at `design.md:205` in the same document, is a second part of the trace that is
  not fixed. This sentence is now flatly false.
- `docs/blind-rendezvous-two-store-prototype-design.md:619`: "**Thirteen fixed
  requests**, issued whether or not anything real was sent" — the exact sentence
  §6.2(c) exists to qualify, unqualified, with no pointer to item 15.
- `src/blindRendezvous/prototype/carrierRuntime.ts:13-18`: "The same number of
  same-sized requests leave for every store in every window whether the outbox
  is empty or full … **thirteen requests, always.** The witness pair is the one
  exception". This is the header of the file whose `#nextEvent` *is* item 15's
  mechanism, and it cites item 14 for the witness exception while asserting that
  the witness pair is the only one.

This is graded Critical because it is a **privacy claim about traffic shape** —
the single property this prototype most must not overstate — asserted as
absolute ("always", "the only part") in the authoritative design document and in
the implementing source file, and disproved by a measurement in the same commit
range. The §6.2(c) correction was applied to 2 of 4 places. The remaining two
are the two that matter most.

Fix: qualify both design-doc sentences with "in every window after the client's
first" and cross-reference item 15; change the `carrierRuntime.ts` header to
name both exceptions and cite items 14 **and** 15.

**IMPORTANT 2 — three present-tense sentences in the two shipped documents still
assert what the branch retracts.**

1. `docs/e2e/blind-two-store/README.md:574-576`: "at 2,000 ms every append
   arrives after `window-finalized`. Task 8b recorded that as a dead end. **It
   is not a dead end — it is a _cost_ problem, and the cost has a second
   knob.**" Present tense, section heading "`--cohort=<n>`: window length and
   cohort size are exchangeable". The retraction sits 64 lines below at
   `:641-652`. The parallel passage in the outward document **was** moved to past
   tense (`prototype.md:437-443`), so this is a missed mirror edit rather than a
   deliberate asymmetry.
2. `prototype.md:512` and `README.md:653`: "**The knob that buys the latency is
   the one that sizes the shared bucket.**" Bolded finding header, present
   tense, ~45 lines after the same file's own blockquote saying
   `cohortAllocationsPerWindow` "can be chosen for what it is actually for — how
   much unrelated traffic a client's objects sit among — rather than for speed".
   The document now asserts and denies the same thing, with the assertion in the
   bolder position.
3. `prototype.md:516-517` and `README.md:658-660`: "the shorter window that **the
   smaller cohort makes possible**". Refuted by the same commit's own
   measurement — 2,000 / 1,000 / 500 ms all complete at **cohort 8**, which I
   reproduced independently in §4.

Item 3 is the clearest: it is false, it is in two shipped documents, and the
evidence refuting it is 8 lines above it in both.

**Minor 4.** `docs/blind-rendezvous-handoff.md:295-303` still presents the
pre-fix 41.9 / 35.2 / 35.6 / 35.4 s scenario numbers as the branch's current
result, with no "pre-fix" note, in the branch's own summary document. The
outward document's equivalent table was correctly relabelled "Re-measured later
the same day".

**Minor 5.** "Item 15" now denotes three different leaks across the research
corpus: the shipped first-window shape; a speculative-offer/harvest disclosure
(`angle-collapse-flights.md:502,515,522,538,709,711,717,773,792`,
`attack-honesty.md:591`); and a presence-liveness disclosure
(`angle-presence-discovery.md:425-426,609`). `optimization-plan.md:602` and
`attack-privacy.md:291` still say "continues from §3a's **fourteen**", and
`angle-product-shape.md:768-769` proposes "a **fifteenth** item … the
fourteen". Stage 2 will cite "item 15" and will mean something. One renumbering
pass over `docs/rendezvous-latency-2026-09/` would prevent a real collision.

---

## 6. Step 2: keep or revert?

**KEEP.** The report justifies Step 2 only as microbenchmark headroom
("step 2's value is headroom, and §1.1 is where it is visible",
`stage-1-report.md:98-99`), which is why the question is open at all. It is
worth more than that, and I measured it end to end.

**Isolation experiment** (mine; not in the report). I disabled *only* the
precomputed read path — `cached !== undefined &&` → `false &&` in both
`readChunkEncoded` and `readCheckpointEncoded`, `storeCore.ts:1201` and
`:1226`, landing proven by hash, restored byte-identically — leaving the
schema, the writes and the codec untouched:

| `--window-ms` | Step 2 read path ON (HEAD) | Step 2 read path OFF |
| ---: | --- | --- |
| 1000 | 6.2 s PASS | 6.2 s PASS (unchanged) |
| 500 | **3.3 s PASS** | **FAIL** — appends miss, then stalls |

**Step 2 buys roughly one octave of window floor**, from ~1,000 ms to ~500 ms on
this machine, and buys nothing at all at the pinned 4,000 ms — exactly as the
plan predicted, and exactly where a plan whose next question is "how short can
the window go" needs it. It is a prerequisite for the finding in §4 that
reshapes the rest of the work, not a speculative optimisation.

Against that, the +40 % disk per window is real, it is on a store that already
writes ~60 GB/day with **no pruning anywhere** (no `DELETE`, no retention sweep
in `storeSqlite.ts` or `storeCore.ts`), and the plan omits it. But the response
rows are, by construction, exactly the reconstructible part: `loadWindow`
remains the source of truth and every read falls back to it, which is tested
("serves a database written before the rows existed"). So they are the *first*
thing a retention sweep should drop, and dropping them is already a supported
state.

**Recommendation:** keep, and record two lines — that Step 2 is what makes
`--window-ms=500` reachable (with the table above), and that the
`chunk_response` / `checkpoint_response` rows are safe to prune independently of
the `window` row, which makes the +40 % the cheapest 40 % on the disk. The
report's own honest note that the plan omits the disk cost
(`stage-1-report.md:51-54`) should stay.

---

## 7. Non-vacuity

**Re-derived four of the mutations myself** (the brief asked for three), chosen
as the ones re-derivable purely from committed material. Each was applied with
`perl -0pi`, its landing proven by comparing SHA-256 before and after, the
target test file run, the file restored from a pristine copy taken before any
edit, and the restore proven with `diff` and a matching SHA-256. Scratch
directory `…/scratchpad/reviewer-opus5`, used by me alone.

| Mutation | What it removes | Tests killed | Failure — and *why* |
| --- | --- | ---: | --- |
| **M1** | the `< 256` guard on the character code, `storeSqlite.ts:104-105` | **1** | `refuses a stored row holding a character above U+00FF` — `Expected promise that rejects / Received promise that resolved`. The row decodes silently, exactly as the docblock warns. |
| **M4** | the odd-length check, `storeSqlite.ts:99` | **1** | `refuses a stored row whose hex has an odd number of characters` — same form; `length >>> 1` silently truncates the trailing nibble. |
| **M10** | the descriptor comparison, `storeSqlite.ts:437-443` | **1** | `ignores a checkpoint row written under a different descriptor` — `expect(received).toBeNull()`, received the 482-byte body. |
| **M11** | the payload-class detail on `offer-sent`, `pairDriver.ts:1590-1593` | **1** | `reports the payload class its transport flights were published in` — `expect(received).toBe(expected)`, expected `"operationPayloadClass 0"`, received `undefined`. |

**All four are non-vacuous in the strict sense the brief asks about.** Every
failure message is the test's **own assertion** reporting a wrong value —
`rejects`/`resolved`, `toBeNull`, `toBe` — not a stub throwing, not a
constructor blowing up, not a timeout. In each case the mutated code path
*completed successfully and returned the wrong answer*, which is the seam the
test exists to cross. M11 in particular kills the test through the `offer-sent`
branch only, proving the test is not merely reading the `answered` branch.

Each mutation killed **exactly one** test and left the other 12 / 25 in its file
passing, so none of the four is a blunt instrument. All four files restored
byte-identically; the full suite is back to 591 pass / 0 fail.

**Important 5 — the report's own non-vacuity evidence is not reproducible, and
the headline count is wrong.**

- `stage-1-report.md:161` says "**Nine** new tests". Its own subsection headers
  say six (`:171`) + three (`:194`) + one (`:213`) = **ten**, and the diff
  contains 8 `test(...)` call sites producing **10 runtime cases** (one call
  site is parameterised over three labels, `storeSqlite.test.ts:140-145`).
  Neither count is nine. Fix the headline to ten and say "8 call sites, 10
  cases".
- Of the ten, **six** are claimed killed by a mutation that kills nothing else.
  M5 kills two; M7 kills its target plus four pre-existing round-trip tests;
  M8 and M9 each kill two. The report defends the overlaps honestly at
  `:185-192` and `:202-203`, but "each claimed killed by a targeted mutation"
  overstates it, and the review brief was given that stronger claim.
- `<scratchpad>/mutate.sh`, `benchstore.ts`, `benchscan.ts` and `s1-1.txt` are
  **not in the repo**. The "hash-checked as landed and restored byte-identically"
  discipline is exactly right and I used it myself — but as shipped, nobody can
  re-run it. Either commit the three scripts under
  `docs/rendezvous-latency-2026-09/` (they are tiny, and this branch's whole
  argument is evidentiary) or state in the report that §1.1, §1.2, §1.4 and §2
  are author-reproducible only.

**Minor 6.** `storeCore.ts:1196-1218` — `readChunkEncoded` reaches the
precomputed row *before* `readChunk`'s `requireProfileHash` / `requireWindow` /
`requireSizeClassId` / `requireChunkIndex` validators and before the
`ingressWindow < chainStart` refusal. I chased this and it **cannot** diverge
today: rows exist only for triples this store finalized; there is no pruning
anywhere; and `chainStart` is verified against the persisted value at
construction (`storeCore.ts:536-538`), so a process cannot come up with a
different chain start against the same database. The docblock's reasoning is
sound. But the invariant it rests on — *no pruning* — is nowhere asserted, and a
retention sweep is exactly what §6 above recommends thinking about. One line in
the docblock naming "and nothing prunes finalized windows" as the precondition
would keep the next change honest.

**Minor 7.** `storeCore.ts:1039` adds an awaited `#saveFinalizedResponses`
(3.41 ms p50) inside `#finalizeWindow`. It is post-commit, server-side and
inside the drain headroom, so it is not a delivery-timing change and not scope
creep — but "no change to delivery timing" was the exclusion criterion for Steps
4-8, and this is the one place server-side timing moved. Worth one line in the
report's scope section.

---

## 8. Scope

**No part of Steps 4-8 crept in.** Verified positively rather than by absence
from the diff:

- The pinned profile is **byte-identical**: `git rev-parse
  8be5c14:src/blindRendezvous/prototype/profile.ts` and
  `HEAD:src/blindRendezvous/prototype/profile.ts` are both
  `bee30649b58ac3ca0f83679587581835824ad845`. `deliveryWindowMs: 4_000n`,
  `cohortAllocationsPerWindow: 8`, `fixedCarrierObjectBytes: 73_728`,
  `publicChunksPerWindow: 3` / `2`, and the append-slot roles are all in their
  pre-Step-4 form. The profile hash is derived at runtime from that literal, so
  pinning the literal pins the hash.
- Step 5's fixpoint (`pairDriver.ts:751-766`) is still a single pass.
- Step 6's role swap, `LazyTransportProvider` rebinding and ICE pool are absent;
  `index.ts`, `webrtcProvider.ts` and `transportCandidates.ts` are not in the
  diff at all. `F` is still 5.
- Step 8's `run.mjs` default is untouched — the three `WINDOW_MS` references the
  diff adds are read-only consumers in the new instrumentation.
- No new `publish` call site, no new page-side injection, no new wait. The two
  `pairDriver.ts` hunks pass a diagnostic string to an existing optional
  parameter of `setPhase`; no wire byte changes.

The two lines in `src/` needed for assertion (b) exceed the plan's "**Files.**
`run.mjs`" for Step 3. The implementer discloses this at
`stage-1-report.md:487-493`. I concur it is not creep.

Steps 1, 2, 3, §6.1 and §6.2 are all fully implemented. Step 2 ships one guard
the plan did not ask for — `loadCheckpointResponse` verifies the
`descriptorHash` the row was written under — which is a correct addition, and
M10 proves a test holds it.

---

## 9. The intermittent hang — a separate opinion, as requested

**I could not reproduce it, and I agree it is independent of these commits.**

| configuration | runs | completed | timed out |
| --- | ---: | ---: | ---: |
| HEAD, `--scenario=healthy`, W=4000 | **14** | 14 | **0** |
| HEAD, W=2000 / W=1000 / W=500 | 5 | 5 | 0 |
| store dir reverse-patched to `8be5c14`, W=4000 | 2 | 2 | 0 |
| **total, in configurations expected to complete** | **21** | **21** | **0** |

(Separately, 3 runs at W=250 / W=200 and one deliberate assertion mutation
failed *by design* and are excluded.)

**Statistics.** At the reported 3-in-13 ≈ 23 % rate, the probability of seeing
0 timeouts in 14 same-configuration runs is `0.77^14 = 2.7 %`; over all 21
completing-configuration runs it is `0.77^21 = 0.5 %`. So either the rate is
substantially lower than 23 %, or it is conditional on something my runs did not
have.

**Do I agree it is independent of this work?** Yes, on three grounds, and the
first is the strongest:

1. **One of the three timeouts was on unmodified `8be5c14`**, before any change
   in this range. That alone settles independence, and it is the implementer's
   own observation reported against their own interest.
2. **The failure is downstream of everything this branch touches.** In all three
   the pages reach `webrtc-connected` and `dtls-verified` and then never reach
   `session-authenticated` — the protocol-v4 session handshake over an
   already-established data channel. Nothing in these six commits is on that
   path: the store commits end at the HTTP response bytes, and the `pairDriver`
   change is a diagnostic string on `setPhase`.
3. My 2 reverse-patched runs and 14 HEAD runs behave identically apart from
   speed, which is what "independent" predicts.

**My advice on opening a separate investigation: yes, but scope it as a
measurement task first, not a bug hunt.** Three things make the 23 % figure
untrustworthy as stated, and all three are cheap to remove:

- **n = 13, unblinded, on a loaded shared laptop.** The report says so
  (`stage-1-report.md:508-510`) and declines to draw a conclusion, which is
  correct. Three agents on this machine mistook contention for a hanging test
  today; I saw load averages of 2.4-3.3 throughout my own runs.
- **The runs are phase-locked** (§1.1). A sequential batch resamples nearly the
  same start phase, so 13 runs are not 13 independent draws from whatever
  condition triggers this. If the trigger correlates with `p` — and the start
  phase is now printed, so this is directly testable — a batch could easily
  produce 3 hits or 0 depending on where the batch happened to lock.
- **`--deadline-ms=180000` on a hang gives you nothing to read.** The current
  failure produces one `TIMEOUT` line.

What I would ask that investigation to do, in order: run ≥40 `--scenario=healthy`
runs at HEAD with a randomised inter-run sleep to break the phase lock, on an
otherwise idle machine, recording the printed start phase per run; and on any
timeout, dump the WebRTC data-channel state and the protocol-v4 handshake's
last-sent/last-received frame rather than only the phase list. If the rate
survives at anything like 23 % under those conditions, then yes — a ~23 %
failure rate in a shipped session handshake matters a great deal beyond this
prototype, and it should be the branch's next priority ahead of any further
latency work. If it collapses under an idle machine, it is a harness artefact
and this stage's numbers are unaffected either way.

I would open the task. I would not yet believe the 23 %.

---

## 10. Summary of findings

**Critical (1)**

1. `docs/blind-rendezvous-two-store-prototype-design.md:648-649` (with `:619`)
   and `src/blindRendezvous/prototype/carrierRuntime.ts:13-18` — the design
   document and the implementing source file still assert that the witness pair
   is "the only part of this trace that is not fixed" and that there are
   "thirteen requests, always", both disproved by item 15 added in the same
   commit range. The §6.2(c) correction reached 2 of 4 places and missed the
   two authoritative ones.

**Important (6)**

1. `docs/blind-rendezvous-two-store-prototype-design.md:209-216` — item 15's
   closed form `2 + (append offsets after p)` is false for `p` below
   `allocationRequestOffsetMs`; the "2" is the descriptor GET plus a
   conditional cold-start allocation POST, not two schedule events; and below
   `publicReadOffsetMs` the start window is indistinguishable from a
   steady-state window, which I observed directly (`w+0 a=15 b=15` at `p=89 ms`).
2. `docs/e2e/blind-two-store/README.md:574-576`, `…prototype.md:512` /
   `README.md:653`, `…prototype.md:516-517` / `README.md:658-660` — three
   present-tense shipped sentences the branch retracts elsewhere in the same
   files, including "the shorter window that the smaller cohort makes possible",
   which this commit's own measurement (and mine) refutes.
3. `docs/rendezvous-latency-2026-09/observed.md:591-593` — the source
   measurement record still asserts "`w0+0` = 9 requests", a value not reachable
   at the pinned profile, in a file the same commit corrected in two other
   sections.
4. `docs/e2e/blind-two-store/run.mjs:859` and `:899-913` — the third "assertion"
   only calls `say()` and can never fail; and assertion (b) at `:883-896` is
   silently vacuous on any run that never reaches a transport flight.
5. `docs/rendezvous-latency-2026-09/stage-1-report.md:161` — "nine new tests" is
   ten (8 call sites, 10 cases); "each killed by a targeted mutation" is six of
   ten uniquely; and `benchstore.ts`, `benchscan.ts`, `mutate.sh` and `s1-1.txt`
   were never committed, so §1.1, §1.2, §1.4 and §2 are author-reproducible only.
6. `docs/blind-rendezvous-two-store-prototype.md:503-507` and
   `docs/e2e/blind-two-store/README.md:643-648` — the shipped 250 ms / 240 ms
   sweep rows did not reproduce on a second machine (250 ms failed here with 450
   `append window-finalized` misses). The 2,000 ms and 1,000 ms rows reproduced
   robustly and should be the only ones that ship.

**Minor (7)**

1. `stage-1-report.md:90-93` — the "2 s wider than the 4 s uniform start phase"
   spread claim has no method and reads backwards; the phase/connect correlation
   is a better and real result.
2. `design.md:243-250` — item 17 lacks the "What would fix it" clause and the
   coverage statement items 15 and 16 both carry.
3. `optimization-plan.md:607-608`, `attack-privacy.md:199,297-298`,
   `attack-honesty.md:150,288`, `angle-presence-discovery.md:236` — the stale
   "9 requests" propagated through the research corpus.
4. `docs/blind-rendezvous-handoff.md:295-303` — pre-fix scenario times presented
   as current in the branch's summary document.
5. `optimization-plan.md:602`, `attack-privacy.md:291`,
   `angle-product-shape.md:768-769`, `angle-presence-discovery.md:425-426,609`,
   `angle-collapse-flights.md` (×9), `attack-honesty.md:591` — "§3a's fourteen"
   and three colliding meanings of "item 15".
6. `storeCore.ts:1196-1218` — the precomputed lookup's correctness rests on an
   unstated "nothing prunes finalized windows" precondition; name it in the
   docblock.
7. `storeCore.ts:1039` — the one place server-side timing moved (3.41 ms p50 in
   `#finalizeWindow`); worth a line in the report's scope section.

**What is right, and should be said plainly.** The diagnosis was correct and
important: the prototype's slowness was blamed on its privacy design and that
was wrong. The codec is exactly equivalent under 1.7 M differential cases. The
precomputed rows keep `loadWindow` as the source of truth and cannot diverge
from it. Assertion (a) is well designed, correctly placed, and caught a real
failure twice during this review without any mutation. The pinned profile is
byte-identical and no part of Steps 4-8 crept in. The end-to-end result, the
before/after ratio and the 2,000 ms and 1,000 ms window figures all reproduce
independently. Every finding above is a documentation or framing fix; none of
them requires a line of shipped logic to change.
