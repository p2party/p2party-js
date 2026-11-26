# Recovering the slack inside the delivery schedule

Angle: **same flight count, same object sizes, same cohort, same window.** Only
the placement of the events inside the window, and the one rule that decides
which window a client's first append lands in.

Written 2026-09-08 against `feat/blind-two-store-prototype` (tree clean at
`profile.ts` md5 `07386f4c…`, `carrierRuntime.ts` md5 `89cfdcbc…`,
`run.mjs` md5 `398e9a61…`). Paths relative to
the repository root.

**This is not an arithmetic paper. Every headline number below was measured by
running the real harness with a patched profile and then reverting the tree.**
Eleven new end-to-end runs (§1), plus the eight runs already recorded in
`floor.md` / `observed.md` / the README, all fit one four-term equation (§2).

---

## 0. The result in one table

`--scenario=healthy`, cohort 8, `--window-ms=4000`, `presence-published` →
`message-verified`. Baseline rows are the recorded runs; the rest are runs I
performed for this report.

| Profile | healthy | all four scenarios | Δ |
| --- | ---: | --- | ---: |
| pinned (`chunkFinalizationOffsetMs` 2800, appends 1300/1700/2100 + 1500/1900) | 35.5 / 38.7 / 40.4 s | 41.9 / 35.2 / 35.6 / 35.4 s | — |
| **E7 — recommended: appends 2400/2600/2800 + 2450/2650, cf 3500, roles reversed** | **23.4 / 22.5 s** | **24.2 / 22.9 / 24.1 / 23.5 s** | **−42% / −35% / −32% / −34%** |
| E7 + cold-start current-window allocation (code change) | 22.3 / 22.7 s when it fires | — | −44% expected |

Same cohort. Same 1,380,336 B scan per store per window. Same 172,542 B of
appends per store per window. **Same thirteen fixed requests per window, same
routes, same sizes, same offsets-are-fixed property.** `profileTool info`
confirms `scannedBytesPerWindow` and `appendedBytesPerWindow` are byte-identical
to the pinned profile; only `deliveryProfileHash` changes, as it must.

At the pinned cohort of **8**, the recommended profile now beats the recorded
cohort-4 (22.3 s) and cohort-2 (23.8 s) rows of the outward doc's table. That is
a strict privacy win as well as a latency one: the same speed at four times the
anonymity set.

And the same profile at `--window-ms=2000 --cohort=4` measured **12.2 s**,
against the **20.8 s** the outward doc records for that exact configuration.

---

## 1. What I ran

All runs are `PLAYWRIGHT_BROWSERS_PATH=… node docs/e2e/blind-two-store/run.mjs`,
full stdout kept beside this file.

| File | Profile under test | Verdict |
| --- | --- | --- |
| `E2-run1.txt` (+ one earlier) | cf 3200, class0 `[2400 ib, 2600 sc, 2800 sr]`, class1 `[2450 sc, 2650 sr]` | PASS 24.9 s, 24.6 s |
| `E3-run{1,2,3}.txt` | E2 + `start()` also allocates for the current window | PASS 22.3 / 23.9 / 22.7 s |
| `E5-c1c3.txt` | cf 3200, role order reversed (`sr, sc, ib`) | PASS 23.5 s |
| `E7-final-run{1,2}.txt` | **cf 3500**, role order reversed — the recommendation | PASS 23.4 / 22.5 s |
| `E7-all.txt` | the recommendation, `--scenario=all` | PASS 24.2 / 22.9 / 24.1 / 23.5 s |
| `E6-w2000.txt` | E2+E3 at `--window-ms=2000` cohort 8 | **FAIL (timeout)** |
| `E8-w2000-c4.txt` | recommendation at W=2000 cohort 4 | **PASS 12.2 s** |
| `E8-w1000-c2.txt` | recommendation at W=1000 cohort 2 | **FAIL — 17 × `append window-finalized`** |

The last row is the one that keeps me honest and it is discussed in §6.

Tree restored afterwards: `git checkout --` on the two touched files, md5s match,
`bun test tests/blindRendezvous/prototype` → **134 pass, 0 fail**, profile hash
back to `83a2261ee4c0f345…`, bundle rebuilt at the pinned geometry.

---

## 2. The equation the whole angle turns on

Let

- `W` = `deliveryWindowMs`
- `r` = `publicReadOffsetMs`
- `a(role, class)` = that slot's `appendSchedule.offsetMs`
- `cf` = `chunkFinalizationOffsetMs`
- `S` = the wall time from the read event firing to the operations being handed
  to the driver (two stores, joined) — **measured 1.48–1.54 s at cohort 8**
  (`observed.md` §3: scan wall p50 1,453 ms + 27 ms open/drive)
- `F` = 5 dependent flights
- `C` = 1 if the client burns a cold-start window, 0 if it does not
- `p` = the client's start phase inside its start window, uniform on `[0, W)`
- `M` = the number of answering flights that miss their own window's slot

then

```
T  =  (C + F)·W  +  r  +  S  −  p  +  M·W

M  =  #{ answering flights : r + S  >  a(their role, their class) }
```

**Validation across every run I have numbers for** (M read off the run's own
`store-missed` lines and flight table; S ≈ 1.5 s; p corroborated independently
by `observed.md`'s recorded window offsets where available):

| Run | C | M | predicted | measured |
| --- | :-: | :-: | ---: | ---: |
| baseline run1 (p = 2,710 recorded) | 1 | 3 | 35.4 s | 35.4 s |
| baseline run2 (p = 3,438 recorded) | 1 | 4 | 38.7 s | 38.7 s |
| baseline run3 (p = 1,720 recorded) | 1 | 4 | 40.4 s | 40.4 s |
| E2 ×2 | 1 | 0 | 24.6 s + (S−p) | 24.9 / 24.6 s |
| E5 / E7 ×3 | 1 | 0 | 24.6 s + (S−p) | 23.5 / 23.4 / 22.5 s |
| E3 ×2 (fired) | 0 | 0 | 20.6 s + (S−p) | 22.3 / 22.7 s |
| E3 ×1 (did not fire) | 1 | 0 | 24.6 s + (S−p) | 23.9 s |

Every row closes, and in each case the implied `p` is inside the band the run's
own `store-missed` count independently requires. (E3 run2 implies
`p ≈ 2.2 s`; the guard needs `p < 1.9 s` to fire and the 12 misses need
`p < 2.4 s` — so `p ∈ [1.9, 2.4)`, and it did not fire. Consistent.)

### Five corollaries, and they are the whole answer to the brief

1. **`a` does not appear in `T` except inside `M`.** The slot offset changes
   *nothing* about when the peer sees the object — every slot in window `w`
   lands in the same finalized chunk set, read at one instant of `w+1`. Moving
   slots later is free latency right up to the point where `M` reaches 0, and
   worth exactly nothing after that. *This is the whole 16 s.*
2. **`r` is worth `r` milliseconds once, not per flight.** Driving
   `publicReadOffsetMs` to 0 saves 600 ms of a 24 s run. It is not a lever.
3. **`publicReadLagWindows` does not appear in the equation at all.** Inside one
   window, `append → finalize → read` is a total order forced by the validator
   (`profile.ts:348-353` then `profile.ts:245-251`). So an answer to a lag-0
   read *still* cannot append before the next window, and the cadence is exactly
   `W` under lag 0 and lag 1 alike. Lag 0 buys `W − r₀ + r` **once**. See §5(d).
4. **`S` is worth `S` once, and it sets the floor on `W`.** Because `M = 0`
   requires `r + S ≤ a < cf − skew < W`, we get **`W > S`**. At `S ≈ 1.5 s` no
   schedule shape makes `W = 1,000 ms` work — which is exactly what
   `E8-w1000-c2.txt` measured.
5. **Therefore the ceiling of this angle at the pinned profile is
   `5·W + S − E[p] ≈ 19.5 s`** (C = 0, r = 0, M = 0). Everything below that
   needs `F` down (protocol change) or `W` down (which needs `S` down, which is
   the store's `loadWindow`, `observed.md` §7.1). I cannot reach "blazing fast"
   from here alone, and I say so in §7.

---

## 3. Why the pinned profile has `M = 4`, stated as a mechanism

The read fires at `r = 600` and completes at `600 + S ≈ 2,050–2,130 ms`
(`observed.md` §2: *every* read-derived phase event lands at offset 2,050–2,160).
The answering slots are at 1,300 (identity) and 1,700 (transport). They are
already 400–800 ms in the past. Four of the five flights therefore wait a whole
window. `PRESENCE` is the exception only because it is enqueued at `start()`,
not from a read.

**The role ordering is exactly backwards.** In the pinned profile:

| role | class-0 slot | budget from the read | who uses it |
| --- | ---: | ---: | --- |
| identity-bootstrap | 1,300 | **700 ms** | `IDENTITY_HELLO`, `IDENTITY_ACCEPT` — both answering flights |
| safety-control | 1,700 | 1,100 ms | `TRANSPORT_OFFER/ANSWER` — both answering flights |
| state-replication | 2,100 | 1,500 ms | `PRESENCE` — **never** on the critical path |

The two roles that must beat the read get the *tightest* deadlines; the one role
that never has to beat anything gets the loosest. The role labels in
`appendSchedule` are free-form (the validator requires only `>= 1` of each and
strictly increasing offsets, `profile.ts:286-309`), and `#pendingEntry` matches
by role, not by index — so reversing them costs nothing and is not a deviation.

There is a second, load-bearing measurement behind the fix. I re-analysed the
recorded Playwright traces per append offset:

```
append@1300  n=40  start p50=1303  duration p50= 770 ms  →  ends at 2,075 ms
append@1500  n=38  start p50=1506  duration p50= 591 ms  →  ends at 2,096 ms
append@1700  n=36  start p50=1703  duration p50= 409 ms  →  ends at 2,112 ms
append@1900  n=41  start p50=1906  duration p50= 251 ms  →  ends at 2,159 ms
append@2100  n=40  start p50=2103  duration p50= 139 ms  →  ends at 2,241 ms
alloc @700   n=38  start p50= 703  duration p50=1394 ms  →  ends at 2,098 ms
```

Every request, whenever it starts, **ends at the same place**. The store is a
serial drain that clears at ~2,100–2,330 ms into the window; almost all of every
append's "duration" is queueing behind the scan storm, not service. Consequence:
**moving the appends later adds no work to the store — it moves them off the
storm and onto an idle store.** That is why the fix costs nothing and why it
worked on the first try.

---

## 4. The candidates

Ranked by saving-per-risk. Every "saving" is in delivery windows first because
that is the unit the system actually pays in.

---

### C1 — *Late slots, reversed roles* — **4 windows (16.0 s), profile-only, measured**

**Name.** Place every append slot after the read completes, and give the
critical-path roles the latest slots.

**Mechanism.** In `PROTOTYPE_DELIVERY_PROFILE_V0` (`profile.ts:98-123`):

```diff
-  chunkFinalizationOffsetMs: 2_800n,
+  chunkFinalizationOffsetMs: 3_500n,
   ...
   sizeClasses: [
     { id: 0, ...
       appendSchedule: [
-        { offsetMs: 1_300n, role: "identity-bootstrap" },
-        { offsetMs: 1_700n, role: "safety-control" },
-        { offsetMs: 2_100n, role: "state-replication" },
+        { offsetMs: 2_400n, role: "state-replication" },
+        { offsetMs: 2_600n, role: "safety-control" },
+        { offsetMs: 2_800n, role: "identity-bootstrap" },
       ], publicChunksPerWindow: 3 },
     { id: 1, ...
       appendSchedule: [
-        { offsetMs: 1_500n, role: "safety-control" },
-        { offsetMs: 1_900n, role: "state-replication" },
+        { offsetMs: 2_450n, role: "state-replication" },
+        { offsetMs: 2_650n, role: "safety-control" },
       ], publicChunksPerWindow: 2 },
   ],
```

New budgets from the read: identity flights **2,200 ms** (was 700, ×3.1),
transport class-0 **2,000 ms** (was 1,100), transport class-1 **2,050 ms** (was
900). Measured `S` p50 1,480 ms, max 1,531 ms → `M = 0` with ~670 ms of margin
on the tightest flight.

`cf = 3,500` rather than 3,200 is deliberate; see the privacy note below.

**Saving.** `M: 4 → 0` = **4 windows = 16.0 s**. Measured 41.9 → 24.2 s healthy;
35.2/35.6/35.4 → 22.9/24.1/23.5 s on the fault scenarios.

**Privacy cost, in the design doc's vocabulary.** *None on §3a items 1–14, with
one narrowing and one improvement to disclose:*

- §5's "thirteen fixed requests": unchanged in count, route, size and
  fixed-ness. Only the offsets column changes, uniformly for every client on the
  grid. `scannedBytesPerWindow` and `appendedBytesPerWindow` are byte-identical
  (verified with `profileTool info`).
- §3a item 4 ("polling shape must stay schedule-shaped"): still schedule-shaped;
  nothing became event-shaped.
- §3a item 1, **narrowed and then repaired**. The doc quotes a per-store phase
  band of 100 ms earlier + 499 ms later = 599 ms, and
  `carrierRuntime.test.ts:1444-1446` pins those literals. `PHASE_LATER_MS` is
  `cf − skew − lastAppend − 1`. At `cf = 3,200` with the last append at 2,800
  the band collapses to **199 ms (span 299)** — the test caught it, which is
  exactly what that test exists for. Setting `cf = 3,500` restores it to
  **499 ms (span 599), byte-identical to the quoted numbers**, and the test
  passes. This is why the recommendation is 3,500 and not 3,200, and it is the
  single most important detail in this report for anyone implementing it.
- **An unlisted leak gets *smaller*.** `observed.md` §8 records that the first
  window of a session has a different request count than every later one,
  because `#nextEvent` skips appends whose offsets are already past. That count
  reveals the session start phase `p`. Today the slots span 1,300–2,100, so a
  store reads `p` to one of six bands over `[0, 2100]`. Under C1 they span
  2,400–2,800, so 60% of clients (`p < 2,400`) emit the *full* five-append shape
  in their first window instead of 32.5% today, and the resolvable bands are
  wider at the front. C1 does not fix that leak — it makes it coarser and rarer.
  It still belongs in §3a as a new item, C1 or no C1.

**Spec deviation.** **None.** Every §4.3 inequality (spec 5793-5825) holds:
`700+300+200 = 1,200 < 2,400`; `2,800+200 = 3,000 < 3,500`;
`0 < 3,500 < 4,000`; `3,500+200 = 3,700 < 4,000+600 = 4,600`; roles present;
offsets strictly increasing. `validateDeliveryProfileGeometry` passes unchanged.
Spec 3392's prototyping licence is **not needed** for this one.

**Implementation cost.** 6 literal lines in `src/blindRendezvous/prototype/profile.ts`;
1 line in `tests/blindRendezvous/prototype/profile.test.ts:92`
(`expect(fast.chunkFinalizationOffsetMs).toBe(1400n)` → `1750n`, the ×0.5
rescale). Nothing else in `src/` or `tests/` pins the literals — I verified by
running the suite: with `cf = 3,500` it is **133 pass / 1 fail**, the one failure
being that single rescale literal. Docs to update: design §4.2 profile block,
design §5 offsets table, design §3a item 1's two quoted offsets, the outward
doc's cohort/latency table, `docs/e2e/blind-two-store/README.md` header. ≈ 25
lines of code + docs.

**How to measure it worked.** (i) `bun run docs/e2e/blind-two-store/profileTool.ts info
--window-ms=4000` must still print `scannedBytesPerWindow 1380336` and
`appendedBytesPerWindow 172542` — if either moves, the geometry changed and the
privacy claim above is void. (ii) `run.mjs --scenario=all` must show every leg at
**one** window: the per-page phase table's `peer-observed → hello-opened →
accepted → offer-opened → handoff` deltas ≈ `W`, not `2W`. (iii) `counters`
`appendsReal + appendsDummy` unchanged per window, and **zero**
`append window-finalized` in the `store-missed` lines — that string is the
failure mode this change flirts with. (iv) `bun test tests/blindRendezvous/prototype`
green, in particular the phase-band test at `carrierRuntime.test.ts:1444`.

---

### C2 — *Reclaim the cold-start window* — **1 window (4.0 s) with p ≈ 48% probability, code + one disclosed leak, measured**

**Name.** Let a client that starts early enough in its window allocate for that
window instead of only for the next one.

**Mechanism.** `carrierRuntime.start()` (`carrierRuntime.ts:418-451`). The store
already accepts it: `#allocate` refuses only `target < current` or
`target > current + maxFutureIngressWindows` (`storeCore.ts:661-665`). Add, per
store, before `#arm(state)`:

```ts
const earliestAppendOffsetMs = this.#classes.reduce(
  (least, c) => (c.appendSchedule[0].offsetMs < least ? c.appendSchedule[0].offsetMs : least),
  this.#profile.deliveryWindowMs,
);
const earliestAppendInstantMs =
  ingressWindowStartMs(window, this.#profile.deliveryWindowMs) + earliestAppendOffsetMs;
if (nowMs + this.#profile.allocationResponseBudgetMs + this.#profile.maxScheduleSkewMs
    < earliestAppendInstantMs)
  this.#spawn(this.#allocate(state, window));
```

With C1's earliest slot at 2,400 the guard fires for `p < 1,900` — **47.5% of
start phases**. Under the pinned profile (earliest slot 1,300) it would fire for
`p < 800` — 20%. C1 therefore roughly doubles C2's hit rate; they compose.

**Saving.** `C: 1 → 0` = exactly **1 window = 4.0 s**, when it fires.
Expectation ≈ 0.475 × 4.0 = **1.9 s**. Measured: fired in 2 of 3 runs (22.3 s
and 22.7 s against 23.9 s for the run where it did not, all with the same
profile); the equation closes on all three.

**Privacy cost.** **A new §3a item — and a smaller one than it first looks.**
The session's first window carries **two** allocation POSTs where every later
window carries one. A store learns from its own log that this client's session
began in this window: one bit, once. *But:* the current code **already** emits
that bit. At `p ≥ 700` today, `start()` fires one allocation POST at wall time
`p` — off the profile's 700 ms grid (`carrierRuntime.ts:447`). An off-grid POST
at an arbitrary offset is itself "this client just started", and §3a does not
list it. C2 adds a second request to a window that already announces itself.
Both belong in §3a; neither is currently there.

- **A shape-preserving variant exists** and should be considered before shipping
  the simple one: send **two** allocation POSTs every window forever — the fresh
  one for `w+1`, and a **byte-identical replay** of the request that won the `w`
  lease. `#allocate` returns the same lease for an exact duplicate and consumes
  no second ordinal (`storeCore.ts:670-674`), so the steady-state cost is one
  extra round trip and zero cohort capacity. At cold start there is nothing to
  replay, so the client sends a fresh request for `w` — same route, same size,
  same offset, indistinguishable on the wire. This moves the leak out of the
  traffic shape (which is what §4.5 protects) and into the store's allocation
  table, where §3a already assumes the store sees ordinals. Cost: 14 → 15 fixed
  requests per window, and one extra `loadWindow` per client per window on a
  store that is already the bottleneck.

**Spec deviation.** **Yes, and it is precise.** Spec **5832-5835**: "At
`IngressWindowStart(w) + allocationRequestOffsetMs`, it makes **exactly one**
allocation request **for `w+1`** per active public carrier context", and spec
**5873**: "allocation events in scheduler window `w` target ingress window
`w+1`". Licensed by spec **3392** as a flagged prototype, and must be named.

**Implementation cost.** ~14 LOC in `carrierRuntime.ts` (exactly the patch above,
which is what I ran), plus a new §3a item, a §5 note, and one test asserting the
first window's request shape. The shape-preserving variant additionally needs the
runtime to retain the winning allocation request bytes per window: ~40 LOC.

**How to measure it worked.** The `store-missed` counter is the direct probe.
When C2 fires there are **no** `append unallocated-cover` lines in the first
window (page counter drops from 12 to 2); when it does not fire, 12. Cross-check
against the harness's `PASS in` time: a firing run must be 4.0 s faster than a
non-firing run at the same `p`, and `p` is recoverable from the first
`presence-published` timestamp mod `W`. Add one line to the harness printing
`Date.now() % deliveryWindowMs` at `presence-published` and the whole thing
becomes a measurement rather than an inference — `floor.md` §11 asks for the same
line for the same reason.

**One measured caveat that could sink it.** `allocationResponseBudgetMs` is
300 ms; the measured allocation POST takes **p50 1,394–1,459 ms, max 1,629 ms**
at cohort 8. The guard uses the profile's fiction, so it will sometimes fire and
still miss the slot — a wasted request, not a regression, but it means the 47.5%
is an upper bound on this store. An honest `allocationResponseBudgetMs` of
~1,600 ms would force `min(appendOffset) > 700 + 1,600 + 200 = 2,500`, i.e. it
would push C1's earliest slot from 2,400 to 2,500. Worth doing; it is one more
literal.

---

### C3 — *`publicReadOffsetMs` → 0* — **0 windows, 0.6 s once, profile-only**

**Name.** Start the read at the window boundary instead of 600 ms into it.

**Mechanism.** `publicReadOffsetMs: 600n → 0n`, and pull the slots and `cf` back
by the same 600 ms so the finalize→read margin does not shrink: `cf 3,500 →
2,900`, class 0 `[1,800 sr, 2,000 sc, 2,200 ib]`, class 1 `[1,850 sr, 2,050 sc]`.
Budgets are then identical to C1's (2,200 ms for identity). Validator:
`2,900 + 200 = 3,100 < 4,000 + 0` ✓; `2,200 + 200 < 2,900` ✓;
`1,200 < 1,800` ✓.

**Saving.** Exactly `r` = **600 ms, once** (corollary 2). Not a window. A 2.5%
improvement on a 24 s run.

**Privacy cost.** None. Same count, same sizes, same fixed-ness. It does move the
whole client's read storm 600 ms earlier, which is a *store throughput*
improvement — the scan and the appends stop overlapping — but that is not a
privacy statement.

**Spec deviation.** None (`0 <= publicReadOffsetMs < deliveryWindowMs`,
spec 5815). But note it burns the read's only tolerance for a client clock that
runs *fast*: at `r = 0` a client 200 ms ahead reads a window the store has not
finalized. Keep `r` at a small positive value (150–300 ms) rather than 0 unless
there is a clock-sync story.

**Implementation cost.** 6 literals in `profile.ts`, same doc set as C1.
Not measured — I judged it not worth a run against a 0.6 s prize, and the
equation says it cannot be more than that.

**How to measure it worked.** Total time drops by 600 ms ± the phase noise, and
`scan` events in the harness log move from offset ~600 to ~0. If any run shows
`not-final` scan statuses, revert immediately.

---

### C4 — *A second append slot per critical role* — **0 windows normally, 1 window of insurance, +5% traffic**

**Name.** Give the roles on the critical path two chances per window instead of
one.

**Mechanism.** Class 0 `appendSchedule` grows to
`[2,400 sr, 2,600 sc, 2,800 ib, 3,000 ib]` (length 3 → 4). The validator
recomputes `publicChunksPerWindow = ceil(8 × 1 × 4 / 8) = 4`
(`profile.ts:313-331`), so class-0 scan bytes go 199,056 → 265,408 and the total
scan 1,380,336 → **1,446,688 B (+4.8%)**, with **6 chunk GETs per store per
window instead of 5**. A full doubling (3 → 6) would be +14.4% and 8 GETs.

**Saving.** **Zero** while `M = 0` — corollary 1 again. Its entire value is that
it removes the *cliff*: with one slot, a client whose `S` exceeds the budget by
1 ms pays a whole window. With two, it pays nothing. Worth 4.0 s per flight, on
the days it is worth anything.

**Privacy cost.** No new §3a item, but a **measurable traffic increase that must
be reported**: §5's "thirteen fixed requests" becomes fourteen, and the scan
grows 4.8%. §3a item 3 ("size and count are visible; the fixed schedule pads
both") still holds — the count is still fixed, just larger. It is partly
self-defeating: a bigger scan means a bigger `S`, which is what you are insuring
against. Measured coupling from `observed.md` §4d: per-request store cost is
close to linear in window-document bytes (2.10× bytes → 2.06× cost), and scan
wall time also scales with the *number* of chunks (5 → 2 chunks took 519 → 92 ms,
5.6×, of which only 2.1× was bytes).

**Spec deviation.** None. Spec 5822-5824 says `count(role) >= 1`, not `== 1`.

**Implementation cost.** 1 line in `profile.ts` plus regenerating every quoted
byte count in three docs. ≈ 10 lines + doc regeneration.

**Verdict.** **Do not ship this with C1. Ship C1, then measure `S`'s tail on real
devices, and add C4 only if the tail crosses the budget.** It is the right
answer to "C1 moved the cliff but did not remove it" and the wrong answer to
"make it faster".

---

### C5 — *`publicReadLagWindows` → 0* — **0 windows, ≤1.7 s once, spec deviation, high risk. Drop it.**

The brief asks what lag 0 costs in correctness and what it buys. The answer is
that it **buys much less than it looks like it buys**, and I want to be explicit
because the intuition is very strong the other way.

Inside one window the validator forces `every append + skew < cf`
(`profile.ts:348-353`) and the read must follow finalization. So the order is
`append → finalize → read`, **always**. A lag-0 read at offset `r₀ > cf`
therefore discovers an operation *after* every append slot of its own window has
passed, and the answer still goes in the next window. **The cadence is exactly
`W` under lag 0 and under lag 1.** Lag 0 does not save a window per flight. It
saves a one-off phase shift of `W − r₀ + r`: with `cf = 1,900`, `r₀ = 2,900`,
`r = 600`, that is **1.7 s once**, on a 24 s run.

Against that:

- It deletes the margin the spec pins it for. Spec **5844**: "The one-window read
  lag removes a same-window store/client clock race." Under lag 1 the margin
  between finalization and the read is `W + r − cf` = **1,400 ms** at C1. Under
  lag 0 it is `r₀ − cf` and it must also absorb the finalizer's own latency —
  `finalizeDue` polls on a 250 ms interval (`storeServer.ts:58`) and is
  serialized behind that window's appends (`storeCore.ts:914`), then does a
  Merkle recomputation and a multi-megabyte `saveWindow`.
- The failure mode is not graceful: a `not-final` read loses the **whole
  window**, 4.0 s, to save 1.7 s. One clock-skew event per rendezvous and it is
  net negative.

**Spec deviation.** Line **5816** (`publicReadLagWindows == 1`), the type at
`profile.ts:55` / spec 3183, the validator at `profile.ts:255-257`, and the read
target at `carrierRuntime.ts:709-711`. ≈ 60 LOC plus a fresh margin analysis.

**Verdict: drop.** Worst saving-per-risk of the five, by a wide margin.

---

## 5. Ranking

| # | Candidate | Windows saved | Seconds (measured or derived) | Privacy | Spec deviation | LOC |
| ---: | --- | :-: | ---: | --- | --- | ---: |
| 1 | **C1 late slots + reversed roles** | **4** | **16.0 s, measured 41.9 → 24.2 s** | none; narrows one unlisted leak; §3a item 1 band preserved by `cf = 3,500` | **no** | ~25 |
| 2 | **C2 cold-start reclaim** | 1 (p ≈ 48%) | 4.0 s when it fires, E[1.9 s] | **new §3a item** (or shape-preserving variant) | **yes** — 5832-5835, 5873 | 14–40 |
| 3 | C3 `publicReadOffsetMs` → 0 | 0 | 0.6 s once | none | no | ~6 |
| 4 | C4 second slot per role | 0 (insurance: 1/flight) | 0 s now; 4.0 s/flight when `S` spikes | +4.8% scan, disclosed | no | ~10 |
| 5 | C5 read lag 0 | **0** | ≤1.7 s once | none | **yes** — 5816 | ~60 |

Stacked expectation at `W = 4,000`, cohort 8, `S = 1.5 s`, `E[p] = 2.0 s`:

| Stack | E[T] | vs pinned |
| --- | ---: | ---: |
| pinned | 40.1 s | — |
| + C1 | **24.1 s** | **−40%** |
| + C1 + C3 | 23.5 s | −41% |
| + C1 + C3 + C2 | **21.6 s** | **−46%** |
| angle ceiling (`C = 0` always, `r = 0`, `M = 0`) | 19.5 s | −51% |

---

## 6. Being skeptical of my own best idea

C1 is measured, cheap and deviation-free. Here is what would make me drop it.

**1. It moved the cliff; it did not remove it.** `M` is a step function of `S`.
C1 buys 670 ms of margin over the measured `S` p50 on *this* machine, in
*headless Chromium on loopback*, at cohort 8. A real phone on a real network
with a cold WASM module and a slower store will have a larger `S`. The moment
`S > 2,200 ms` all four flights fall back to two windows and the run returns to
~40 s with no warning and no degraded label. **Mitigation:** C4, and a harness
assertion on `S` rather than on the total.

**2. It costs store drain headroom, and I measured that costing a whole run.**
This is the finding that nearly changed my recommendation. `E8-w1000-c2.txt`:
the recommended profile at `--window-ms=1000 --cohort=2` **FAILS** — 17
`append window-finalized` misses — where the *pinned* profile is recorded at
10.5 s. `withDeliveryWindowMs` scales offsets proportionally, but the store's
per-request cost is **absolute** (97 ms at cohort 8, 47 ms at cohort 2,
`observed.md` §4d). At `W = 4,000` the gap `cf − a_min` is 1,100 ms, more than
enough to drain ten appends. At `W = 1,000` it scales to 275 ms and is not.
So C1 is **not** a profile-independent improvement:

> **The rule C1 must ship with:** `cf − min(appendOffset)` must exceed the
> store's absolute drain time for one window's appends, and
> `min(appendOffset) − publicReadOffsetMs` must exceed `S`. Both are absolute
> milliseconds, neither scales with `W`. Any rescale must re-check both, and
> `withDeliveryWindowMs` cannot do it for you.

`E8-w2000-c4.txt` is the counter-example that keeps C1 alive at short windows:
**12.2 s**, against the 20.8 s the outward doc records for that same
window/cohort — a 41% cut — because at cohort 4 the drain is small enough that
550 ms of gap suffices.

**3. It narrows a mitigation the design doc has already argued about.** At
`cf = 3,200` the §3a item-1 per-store phase band collapses from 599 ms to
299 ms. I only found this because `carrierRuntime.test.ts:1444` pins the
literals — the argument in §3a is that the band was useless anyway (15% of a
window, crossing zero window boundaries), and 7.5% is no more useless than 15%,
but the doc quotes numbers and a future maintainer revisiting per-store phase
offsets deserves the room. `cf = 3,500` gives it back for free. **If a future
change needs `cf` below 3,500, that trade must be made deliberately, not by
arithmetic drift.**

**4. It is measured on one machine with two stores in one process tree.** Three
healthy runs and one four-scenario run is not a distribution. The claim is "on
these runs, at this profile, every flight cost one window" — the same standard
the outward doc holds itself to.

**What would make me drop C2 instead:** if the maintainer is unwilling to add a
§3a item, drop the simple form immediately and implement the byte-identical
replay variant, or drop it entirely — 1.9 s expected is not worth an undisclosed
bit. And note the honest asymmetry: C2 helps exactly the users who start early
in a window, who are already the users with the largest `−p` credit. Per user it
is all-or-nothing, never 1.9 s.

---

## 7. The ceiling of this angle, stated plainly

`T = (C + F)·W + r + S − p`. With `C = 0`, `F = 5`, `r = 0` and `S = 1.5 s`, the
best this angle can reach at `W = 4,000` is **19.5 s expected**. That is not
"blazing fast" and no rearrangement of the schedule gets there, because:

- `F` is the pair protocol, not the schedule.
- `W` is floored by `S` (corollary 4, confirmed by two measured failures:
  `E6-w2000.txt` at cohort 8 and `E8-w1000-c2.txt` at cohort 2).
- `S` is 99.5% the store's `loadWindow` `JSON.parse`, not the client
  (`observed.md` §4b/§4e: the browser's entire per-window AEAD is **8 ms**).

So the honest sequencing is: **C1 now** (16 s, free, measured, no deviation) →
fix `loadWindow` (which collapses `S`, and only then does `W` become a free
variable) → re-tune C1's two absolute constraints at the new `S` → then and only
then shrink `W`. `E8-w2000-c4.txt`'s **12.2 s** is what one step down that path
already looks like. With `S` in the tens of milliseconds, `W = 1,000` satisfies
both constraints and the same equation gives `5 × 1,000 + 150 + 0.05 − 500 ≈
4.7 s` — which is the number the maintainer is asking for, and it is two
independent changes away, not one.

---

## Appendix — files

All in this directory.

| File | What |
| --- | --- |
| `E2-run1.txt` | late slots, original role order, `cf` 3200 — PASS 24.6 s |
| `E3-run{1,2,3}.txt` | + cold-start current-window allocation — 22.3 / 23.9 / 22.7 s |
| `E5-c1c3.txt` | late slots, reversed roles, `cf` 3200 — PASS 23.5 s |
| `E7-final-run{1,2}.txt` | **the recommendation** (`cf` 3500) — PASS 23.4 / 22.5 s |
| `E7-all.txt` | the recommendation, all four scenarios — 24.2 / 22.9 / 24.1 / 23.5 s |
| `E6-w2000.txt` | `W=2000` cohort 8 — FAIL (timeout) |
| `E8-w2000-c4.txt` | recommendation at `W=2000` cohort 4 — **PASS 12.2 s** (baseline 20.8 s) |
| `E8-w1000-c2.txt` | recommendation at `W=1000` cohort 2 — **FAIL**, 17 × `append window-finalized` |
| `profile.ts.orig`, `carrierRuntime.ts.orig` | pre-patch copies; tree restored via `git checkout --` and md5-verified |

Tree state on exit: **clean** for every tracked file this report touched;
`bun test tests/blindRendezvous/prototype` → 134 pass, 0 fail; delivery profile
hash `83a2261ee4c0f345977e94416591372007578db22619b80afa583d2082c68a38`;
`docs/e2e/blind-two-store/bundle.js` rebuilt at the pinned geometry. (The
untracked `docs/e2e/desync/` and `docs/e2e/runs/` artefacts that appeared
mid-session are another agent's; I did not touch them.)
