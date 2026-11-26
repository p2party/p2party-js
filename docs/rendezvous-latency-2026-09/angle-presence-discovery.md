# The discovery half: from "A starts" to "A and B have seen each other"

Angle report, 2026-09-08, branch `feat/blind-two-store-prototype` @ `127ca95`.
Every code citation is `file:line` against
`/Users/deliberative/Desktop/@p2party/p2party-js`, verified by reading the file
at that revision. Every latency number is anchored to
`scratchpad/latency/floor.md` (structural derivation) and
`scratchpad/latency/observed.md` (three instrumented runs + two isolating
probes), or to the recorded run in `docs/e2e/blind-two-store/README.md:378-397`
and the cohort table in `docs/blind-rendezvous-two-store-prototype.md:427-433`.

Scope: **only** `presence-published → peer-observed`. The four flights after it
(HELLO, ACCEPT, OFFER, ANSWER) are another angle's problem; where a candidate
also helps them I say so and do not count it twice.

---

## 0. The one-paragraph answer

Discovery today costs **6.7–9.7 s, mean 8.0 s** — a fifth of the whole
rendezvous — and it decomposes exactly, with no residue, into
`4,000 ms cold-start window + 4,000 ms read lag + 600 ms read offset + 1,450 ms
scan − p`. Three of those four terms can be removed or shrunk **without giving
up one privacy property and without adding one byte to the wire**, taking the
mean to **~3.0 s at the pinned 4,000 ms window** and **~0.8 s at a 1,000 ms
window**. But the more important finding is not a latency one: **the prototype
publishes presence exactly once, reads exactly one window ever, and requires
both sides to hold each other's presence before either can open a HELLO — so
two peers who start more than roughly one delivery window apart never rendezvous
at all.** The recovery time from a single missed presence window is not slow; it
is infinite. The fix is the cheapest change in this report — presence already
owns a `state-replication` slot in every window that currently carries a dummy,
so republishing it costs **zero extra requests and zero extra bytes**.

---

## 1. What discovery costs today, and the model that predicts it

### 1.1 The chain, with citations

| Step | Where | Cost |
| --- | --- | ---: |
| `driver.start()` enqueues PRESENCE; nothing is sent (`publish` only enqueues, `carrierRuntime.ts:496-511`) | `pairDriver.ts:717` | 0 |
| The scheduled allocation event **always** targets `w+1` (`carrierRuntime.ts:727`), and so does the cold-start branch (`carrierRuntime.ts:454`). So window `w0` never holds a lease and its five appends go out as `unallocated-cover` that the store discards (`storeCore.ts:793`); the outbox entry stays queued (`carrierRuntime.ts:872`). | `carrierRuntime.ts:454,727` | **4,000 ms** |
| PRESENCE rides `w0+1`'s class-0 `state-replication` slot at **2,100 ms** (`workKinds.ts:47-49` → role; `profile.ts:110` → offset; payload class 0 at `pairDriver.ts:705`) | `profile.ts:110` | — |
| The store finalizes `w0+1` at 2,800 ms; the peer reads `w−1` at `publicReadOffsetMs` of the next window, `publicReadLagWindows` pinned to 1 (`carrierRuntime.ts:734`, `profile.ts:99-100`) | `profile.ts:99` | **4,000 + 600 ms** |
| The two-store scan resolves | measured | **~1,450 ms** |
| `observePeer` fixes the role and emits `peer-observed` in the same turn | `pairDriver.ts:1046-1076` | ~4 ms |

### 1.2 The model, and its fit

```
T_discovery = W_coldstart + W_readlag + publicReadOffsetMs + S − p
            = 4,000 + 4,000 + 600 + 1,453 − p
            = 10,053 ms − p                     p ∈ [0, 4,000) uniform
            ∈ (6.05 s, 10.05 s],   mean 8.05 s
```

`S` = 1,453 ms is the measured p50 two-store scan wall (`observed.md` §3,
n = 58, min 715 / p50 1,453 / max 1,531). `p` is the start phase
`Date.now() mod 4000`, uncontrolled and uniform, because window boundaries are
absolute against the Unix epoch (`publicWindow.ts:175-181`).

Every recorded `presence-published → peer-observed` sample:

| Source | A | B |
| --- | ---: | ---: |
| `observed.md` run 1 | 7.373 s | 7.372 s |
| `observed.md` run 2 | 6.689 s | 6.689 s |
| `observed.md` run 3 | 7.881 s | 8.370 s |
| `README.md:392-394` recorded run | 9.7 s | 9.7 s |

Range 6.69–9.7 s, mean 8.0 s, against a predicted range (6.05, 10.05] and a
predicted mean of 8.05 s. **The model is not an estimate; it is the profile
arithmetic, and seven samples sit inside it.** Every saving below is computed
against this model, so it is falsifiable by one run.

### 1.3 Where discovery is *not* slow

- **Role selection is free.** `observePeer` and `sendHello()` run in the same
  `ingest` turn (`pairDriver.ts:743-748`); `peer-observed → hello-sent` is
  **4 ms** in every run (`observed.md` §6). There is nothing to optimise between
  seeing a peer and answering it.
- **The client's crypto is free.** Decode + trial-open of all 40 objects of one
  window, 1,380,336 bytes, is **4.0 ms per store, 8 ms for both**
  (`observed.md` §4b). The prior belief that "the browser could not finish the
  per-window AEAD" is refuted by that benchmark; what cannot be finished is the
  **store's** service of the scan.
- **The presence object is already in the smallest legal class.** See D8: the
  spec pins `PRESENCE` to payload class 0 (spec:6435) and pins the profile to
  exactly one size class per payload class (spec:5770-5774), so "ride a smaller
  size class" is not available. Only class 0's `fixedCarrierObjectBytes` is a
  lever, and it is worth ~6.7 % of the scan.

---

## 2. The finding neither measurement report contains: discovery is fragile, not just slow

Three facts, each read directly out of the code:

1. **Presence is published exactly once, for the life of the room.**
   `start()` refuses a second call (`pairDriver.ts:626-627`) and `publish` is
   called once (`pairDriver.ts:717`). Nothing re-emits it.
2. **A client reads exactly one window, ever, and never revisits one.**
   `#runEvent` dispatches `EVENT_READ` to `#read(event.window - 1n)`
   (`carrierRuntime.ts:734`) and `#read` is the sole caller of
   `scanWindow` (`carrierRuntime.ts:1033`), guarded by a per-window
   idempotence set (`carrierRuntime.ts:1028-1030`). There is no catch-up scan,
   no re-read, no retention walk — even though the store retains 160,000
   windows (`profile.ts`, `carrierRetentionWindows`) and answers a chunk GET for
   any of them.
3. **A HELLO cannot be opened by a peer that has not observed the sender's
   presence.** `handlePairOperation` returns `false` when
   `remotePresence === null` (`pairDriver.ts:1163-1164`), before any of the
   HELLO machinery runs.

Compose them. A publishes presence into window `wA = w0_A + 1` (always +1,
because the allocation always targets `w+1`). B sees it only if B's scheduler is
already reading by window `wA + 1`. `#nextEvent` skips events whose instant has
passed (`carrierRuntime.ts:668-673`), so a client starting at phase
`p_B > publicReadOffsetMs` does not read at all in its first window. Therefore:

> **B must start within about one delivery window of A — at most ~8 s later —
> or B never sees A's presence, and by fact 3 the pair deadlocks
> permanently, whichever of the two is the initiator.**

The harness never tests this: `run.mjs` loads both pages together and both
report `presence-published` at 0.5 s (`README.md:378-381`). There is no
`--stagger` flag. So the recorded "4 of 4 scenarios" says nothing about it.

The same argument covers three failure modes a chat product will hit constantly:

- **The late joiner.** One person opens the link two minutes after the other.
  Recovery time today: **never**. The run ends at the harness deadline.
- **A missed read.** If a client's read of the one window carrying the peer's
  presence fails at *both* stores, or is skipped, that presence is gone for
  good. `withhold-a` and `kill-a` survive only because the union covers a
  single store; nothing covers a missed window.
- **A throttled tab.** Browsers clamp and coalesce `setTimeout` in background
  tabs. A backgrounded page silently skips whole windows of read and append
  events — `#nextEvent` is explicit that "an event whose instant has gone is
  missed for good" — and there is no mechanism that ever recovers what it
  missed. **Hypothesis, not measured here** (see §6).

This is the discovery half's real problem, and it is not the 8 seconds.

---

## 3. Candidates

Each carries: mechanism, saving in seconds and in delivery windows anchored to
the reports, privacy cost in the design doc's vocabulary mapped to §3a, spec
deviation with the line, implementation cost, and the measurement that would
prove it.

---

### D1 — Serve a chunk without parsing the whole window document

**Mechanism.** `storeCore.ts:1121` calls `this.#persistence.loadWindow(w)` on
every chunk GET; `storeSqlite.loadWindow` (`storeSqlite.ts:277`) `JSON.parse`s
the entire window document and hex-decodes every slot *and* every finalized
chunk — ≈ 5.5 MB of JSON — to return one of them, on bun's single-threaded
event loop. Store finalized chunks as their own rows of raw `BLOB` keyed
`(profileHash, window, sizeClass, chunkIndex)` and serve a chunk GET with one
`SELECT`. Keep `loadWindow` for `finalize()` only.

**Saving.** `S` 1,453 ms → tens of ms. Measured directly: `storeprobe.txt` shows
**97 ms per chunk GET, flat, and perfectly serial** (96/192/289/386/482 ms for
five chunks); the cohort-2 probe confirms linearity in window bytes (2.10× fewer
bytes → 2.06× cheaper per request, `observed.md` §4d). Discovery saving:
**1.40 s, 0.35 windows.** Not a window; a slice.

**Privacy.** **None.** No wire byte, no request shape, no offset, no geometry,
no disclosure changes. §3a: touches nothing.

**Spec deviation.** None. The spec says nothing about a store's persistence.

**Implementation.** `store/storeSqlite.ts` (~80 LOC: a `chunk` table, a
`getChunk`, and `toDocument` stops double-encoding), `store/storeCore.ts`
(~15 LOC), `store/storePersistence.ts` port (~10 LOC). Existing
`storeCore.test.ts` restart-replay tests cover the migration.

**Measure.** Re-run `storeprobe.sh` — per-request TTFB and the 5-chunk wall.
Then a `healthy` run: the `offset(ms)` column of `analyze.mjs` for
`peer-observed` must move from ~2,080 to ~650.

**Caveat, stated up front.** This is `observed.md`'s finding, not mine, and it
is a *prototype-store artifact*: a competently built store would never have had
it. Counting its 1.4 s as a protocol optimisation is double-counting. It earns
its rank-1 place for a different reason: **D2, D3, D4 and D7 are all blocked on
it** — each of them shortens a budget the 1,450 ms scan currently blows.

---

### D2 — Allocate for the window you are in, not the next one

**Mechanism.** `#runEvent` targets `event.window + 1n` for both the token
(`carrierRuntime.ts:725`) and the allocation (`carrierRuntime.ts:727`), and the
cold-start branch does the same (`carrierRuntime.ts:454`). Change all three to
`event.window` / `window`. `storeCore.#allocate` already accepts it: it refuses
only `target < current` or `target > current + maxFutureIngressWindows`
(`storeCore.ts:660-665`). The profile's own inequality is sized for exactly
this: `allocationRequestOffsetMs + allocationResponseBudgetMs +
maxScheduleSkewMs < min(appendSchedule.offsetMs)` → `700 + 300 + 200 = 1,200 <
1,300` (`profile.ts:336-345`, spec:5805-5808). A steady-state client is
unaffected — it holds a lease for the window it is appending into either way.
A **cold-started** client, which already issues exactly one immediate allocation
and deletes the queued one (`carrierRuntime.ts:449-454`), now gets a lease for
the window it is standing in, and its PRESENCE rides that window's 2,100 ms slot
instead of the next window's.

**Saving.** The whole cold-start window, when the immediate allocation can beat
presence's own slot:

```
p + allocationResponseBudgetMs + maxScheduleSkewMs < presence slot
p + 300 + 200 < 2,100   ⇒   p < 1,600   ⇒  40 % of start phases
```

**4.00 s = 1.00 delivery window** when it fires, 0 when it does not; **expected
1.60 s**. (Note: `floor.md` §8 quotes 20 % for this, using
`min(appendSchedule.offsetMs) = 1,300`. For *discovery* the binding slot is
presence's own at 2,100, so the hit rate is 40 %, not 20 %. Correction, with the
arithmetic.)

**Privacy.** One new bit, and it is smaller than it looks. Uniformly changing
every client's allocation target means a store still sees **exactly one
allocation POST per client per window**, same route, same size, same offset —
the fixed-shape claim of design §5 is untouched, and no new request appears.
What changes is the target-window integer in the body, and it changes for
everyone at once, so it is not a per-client tell. The residual tell is the
cold-start client's allocation firing at an off-grid instant `p` rather than at
700 ms — **which is already true today** (`carrierRuntime.ts:454`) and which
`observed.md` §8 already observed as an undisclosed first-window shape
difference (9 requests in `w0+0` vs 15 afterwards). §3a mapping: **widens
nothing; it inherits an existing, currently undisclosed first-window
distinguishability that should get its own §3a item regardless of this
candidate.**

**Spec deviation.** **Yes, and a clear one.** Spec:5832 ("one scheme-1 blind
token issuance request for `w+1`"), spec:5835 ("exactly one allocation request
for `w+1`"), and spec:5875-5877 ("Issuance and allocation events in scheduler
window `w` target ingress window `w+1`"). Permitted for a prototype under
spec:3392; must be named in the doc as a deviation.

**It also gives up a real robustness property.** The spec's `w+1` target buys
a full window of slack: "Allocation completion after the pinned response budget
is a failed allocation; it cannot race the first append of the next window"
(spec:5836-5838). Under D2 the allocation must answer within
`1,300 − 700 = 600 ms` or this window's appends go out as cover.
**Today's measured allocation POST takes 1,270 ms** (`observed.md` §4c) — so
**D2 shipped before D1 would make things worse, not better.** D2 is strictly
downstream of D1.

**Implementation.** `carrierRuntime.ts`: 3 lines. Plus one
`carrierRuntime.test.ts` case asserting a cold-started runtime's first append is
`stored`, not `unallocated-cover` (~40 LOC).

**Measure.** The harness already prints `cold start past the allocation offset`.
Instrument `run.mjs` to print `Date.now() % deliveryWindowMs` at
`presence-published` (one line — `floor.md` §11 asks for the same thing), run 20
`healthy` runs, and check that every run with `p < 1,600` shows
`presence-published → peer-observed` ≈ 4.0 s shorter than every run with
`p ≥ 1,600`. That bimodality is the proof; a mean is not.

---

### D3 — Read at the top of the window

**Mechanism.** `publicReadOffsetMs` 600 → 0 (or 200). The validator requires
`chunkFinalizationOffsetMs + maxScheduleSkewMs < deliveryWindowMs +
publicReadOffsetMs` (`profile.ts:245-251`, spec:5813-5814): at 2,800 + 200 =
3,000 < 4,000 + 0 ✓. The read of `w−1` then fires 1,200 ms after that window
finalized, which is 6× `maxScheduleSkewMs` of margin.

**Saving.** **0.60 s, 0.15 windows**, deterministic, on discovery — and again on
each of the four later flights, which is another angle's credit.

**Privacy.** **None.** It moves one fixed offset for every client on the grid.
Same route, same count, same size. §3a: touches nothing. It does narrow the
finalize-to-read margin, which is a liveness risk, not a privacy one; 200 ms is
the conservative pick and still saves 0.40 s.

**Spec deviation.** None — spec:5815 permits `0 <= publicReadOffsetMs <
deliveryWindowMs`, and `profile.ts:252-254` enforces exactly that.

**Implementation.** One integer in `profile.ts:100`. The profile hash changes,
so both stores and both pages must be rebuilt together — `--cohort` already does
that atomically (`README.md`).

**Measure.** `analyze.mjs`'s `offset(ms)` column for `peer-observed` drops by
600; total run time drops by ~3.0 s (five flights × 0.6).

---

### D4 — Move presence's append slot to the end of the window

**Mechanism.** Class 0's `state-replication` offset is 2,100
(`profile.ts:110`) — the last of three, but still only 53 % of the way through
the window. Per `floor.md` §8's Gate 3, **the slot offset has no effect on when
the peer sees the object**: every slot lands in the same finalized chunk set,
read at the same instant. It governs exactly two things: how much compute budget
an *answering* flight has (another angle's concern), and — the discovery-half
concern — **how late a cold-started client may start and still catch its own
window**. Adopt `floor.md`'s conforming re-profiling (a):
`chunkFinalizationOffsetMs` 2,800 → 3,400, class 0 schedule
`[1300, 1700, 2100] → [2500 ib, 2800 sc, 3100 sr]`, class 1
`[1500, 1900] → [2650 sc, 2950 sr]`. All four §4.3 inequalities still hold
(`profile.ts:239-353`). With D3 at 0 the more aggressive
`[3100, 3300, 3499]` / finalize 3,700 is also legal.

**Saving.** Nothing on its own. It **raises D2's hit rate**: presence's slot at
3,100 means D2 fires for `p < 2,600` (65 %) instead of 40 %; at 3,499 it fires
for `p < 2,999` (75 %). Marginal expected saving over D2 alone: **+1.00 s**
(slot 3,100) or **+1.40 s** (slot 3,499).

**Privacy.** **None.** Design §5's fixed-request table changes only in the
"Offset in the window" column, identically for every client on the grid. §3a
item 3 (size and count) unchanged; item 4 (polling shape) unchanged — the shape
is still schedule-shaped, just a different schedule. One honest note for §3a
item 1: the admissible append band widens from 800 ms to 600 ms→... it stays
~600 ms wide, so the "599 ms against a 4,000 ms window" argument in §3a item 1
is unchanged and a per-store phase offset remains as useless as it was.

**Spec deviation.** None. Every inequality at `profile.ts:205-353`
(spec:5777-5825) is satisfied; `validateDeliveryProfileGeometry` passes.

**Implementation.** Five integers in `profile.ts:98,108-110,119-120`.
`profile.test.ts` recomputes `publicChunksPerWindow` independently and must
still pass unchanged (it will: `appendSchedule.length` does not change).

**Measure.** `store-missed` lines must contain zero `window-finalized`, and
`appendsDummy + appendsReal` per window must be unchanged (13 fixed + witness
pair). That is the check `floor.md` §8 demands and it is the only thing that
distinguishes this from arithmetic.

---

### D5 — Presence heartbeat: keep PRESENCE in the state-replication slot

**This is the answer to "what is the recovery time if that single presence lands
in a window the peer misses" and to "should presence be republished every
window".**

**Mechanism.** PRESENCE maps to `state-replication`
(`workKinds.ts:47-49`), and the profile *requires* at least one
`state-replication` slot in every size class (`profile.ts:295-309`,
spec:5824). Today that slot carries a dummy in every window after the first
(`carrierRuntime.ts:810-812`). Re-enqueue the same operation bytes after a
successful append so it rides that slot again:

```ts
// carrierRuntime.ts #append, after entry.targets.delete(storeIdHex)
if (entry.repeat && this.#repeatWindows(entry) > 0)
  this.#enqueue(entry.operationBytes, payloadClassOf(entry),
                "REPLICATION_OR_BACKFILL", [storeIdHex]);
```

`REPLICATION_OR_BACKFILL` already maps to `state-replication`
(`workKinds.ts:41-42`) and `#enqueue` already exists and appends to the tail
(`carrierRuntime.ts:1298-1322`), so a re-queued presence never starves a genuine
backfill (`#pendingEntry` returns the oldest match, `carrierRuntime.ts:1325`).
This is the *existing* replication path, invoked unconditionally instead of only
when one store missed an object.

Three things make it correct without any protocol change:

- **The same bytes stay valid for 24 hours.** `logicalWindowMs` is 60,000 and
  `operationRetentionWindows` is 1,440 (`roomPolicyV4.ts:191,193`), so a
  presence minted at logical window `L` carries
  `expiresAfterWindow = L + 1440` and passes validation at any reference window
  up to `L + 1440 + skew` (`operation.ts:465-470`). One logical window is
  **fifteen** delivery windows, so republication is entirely inside the room's
  own clock.
- **Republishing identical bytes creates no fork and no duplicate.** Same
  `OperationId` → the peer's `#seen` filter drops it (`carrierRuntime.ts:1070`),
  so `#onOperations` is not even called; the driver's `knownOperations` map is
  keyed by id (`pairDriver.ts:733-736`). Same `PresenceSemanticSlot`
  (spec:6703-6708) → no slot conflict. The carrier envelope carries a fresh
  nonce and this window's `ingressWindow`, so the two stores still never see
  byte-identical ciphertext (design §4.5).
- **It self-heals the asymmetric deadlock in one window.** A responder that
  holds an unopenable HELLO (`handlePairOperation` returned `false`, so the id
  was *not* added to `handledPairOperationIds`, `pairDriver.ts:1163`) retries it
  on the very next `ingest` — which happens as soon as any fresh operation
  arrives. The republished presence *is* that fresh operation. So the recovery
  path already exists in the driver; it is only starved of the presence.

Bound it: republish while the driver has not reached `hello-opened` /
`accepted`, capped at `presenceRepublishWindows` (15 windows = one logical
window = 60 s is the natural cap), then stop. Not forever.

**Saving.** **0 s in the measured healthy simultaneous-start run** — say that
first and loudly. Its value is entirely in the cases the harness does not test:

| Case | Today | With D5 |
| --- | ---: | ---: |
| both start together (all recorded runs) | 8.0 s | 8.0 s |
| B starts one window late | deadlock | **+1 window (4.0 s)** |
| B starts minutes late | deadlock, harness deadline | **≤ 4.0 s after B's first read** |
| the window carrying A's presence is missed at both stores | never recovers | **4.0 s** |
| B's tab was backgrounded through A's presence window | never recovers | **4.0 s after B is foregrounded** |

**Privacy.** **Nothing new at any store.** The slot, the instant, the route, the
byte count and the request count are identical — a dummy becomes a real object,
and design §4.5's whole point is that a store cannot tell them apart. §3a
item 1 (replicated-write timing linkability): the join a cross-store observer
runs takes the same input either way, because it works over indistinguishable
objects at fixed instants; **not widened.** Item 3 (size and count):
**unchanged**. Item 4 (polling shape): unchanged — this is not a burst after a
hit, it is a scheduled slot that was always going to fire. Item 5 (retry
oracle): the republication is unconditional-per-window and is not triggered by an
observed omission, so it is not the cross-store tagging channel item 5 forbids.
Items 6/14 (witness): untouched.

**But there is a real new disclosure, and it is not to a store.** Today a
capability holder — which under the prototype's OPEN policy is anyone who has
the room secret, including someone who obtains it later and has archived carrier
objects — learns "this endpoint was present at window `w`". With a heartbeat
they learn "this endpoint was online across windows `w … w+n`". That converts
presence from a point event into a **liveness interval visible to co-members and
to any future capability compromise**. It is bounded by
`presenceRepublishWindows` and it is arguably what a chat product wants, but it
is a widening and it needs **a new §3a item 15**, written in the same voice as
the other fourteen. It must not be shipped silently.

**Spec deviation.** None found. Nothing in §4.3 or §4.11 forbids re-publishing a
live operation; §4.3 defines `REPLICATION_OR_BACKFILL` as the role "for every
imported copy, replica, and backfill" (`workKinds.ts:20-22`), and REQ-018
(spec:988) already names "durable republish-on-contact behavior" as the intended
substitute for direct-channel retry timers. The nearest thing to a constraint is
the spec's own bound on replication loops, which `#queueBackfills`'s docblock
(`carrierRuntime.ts:1218-1228`) already reasons about; a self-republication is
bounded by construction because it has one publisher.

**Implementation.** `carrierRuntime.ts`: a `repeat` flag on `OutboxEntry`, an
optional third argument on `publish`, the re-enqueue above, and a
`stopRepeating(operationId)` — ~35 LOC. `pairDriver.ts`: pass
`{ repeat: true }` at line 717 and call `stopRepeating` when the phase reaches
`hello-opened` / `accepted` — ~10 LOC. Tests: one `carrierRuntime.test.ts` case
(the state-replication slot carries a real object in three consecutive windows
and the window shape is unchanged), one `pairDriver.test.ts` case (a driver that
misses the presence window still pairs) — ~120 LOC. **A new `--stagger-ms`
scenario in `run.mjs`** is the real test — ~60 LOC.

**Measure.** Two things, and the first matters more than the second:
1. **Add `--stagger-ms=<n>` to `run.mjs`** and run `healthy` at
   n ∈ {0, 4000, 12000, 60000}. Before D5 the last three must fail at the
   deadline; after D5 all four must pass, with
   `B.presence-published → B.peer-observed` ≤ 2 windows + S in every case.
   **Run this before implementing anything** — it is the falsification test for
   §2 and for this whole candidate.
2. Count republications. In `--scenario=healthy --stagger-ms=0` the count must be
   **0 or 1**; anything higher means a store or read fault the heartbeat is now
   masking, and the E2E should fail on it rather than absorb it.

---

### D6 — Warm start: co-publish PRESENCE and HELLO from a cached peer presence

**Mechanism.** A returning client that still holds the peer's presence operation
can compute the role at `start()` — the role is just
`compareBytes(localPresenceId, remotePresenceId)` (`pairDriver.ts:1072`) — and,
if it is the initiator, publish PRESENCE **and** HELLO in the same delivery
window. They use different role slots in the same window (identity-bootstrap
1,300 and state-replication 2,100, `profile.ts:108,110`), and per Gate 3 both
land in the same finalized chunk set. The peer reads both in `w+1`, observes the
sender, and opens the HELLO in the same `ingest` turn — `ingest` calls
`observePeer` before the pair loop (`pairDriver.ts:743-748`). With D5 in place
the cached presence is guaranteed live, because the peer is republishing the
same bytes.

**Saving.** **4.00 s = 1.00 window**, but only on a *return* visit and only when
the returning side sorts as initiator — expected **2.00 s** on return visits,
**0 s on first contact**. It collapses PRESENCE and HELLO into one flight, so
it is really a discovery/connection boundary saving.

**Privacy.** Two costs. (i) **§3a item 12 (local forensics) is widened**: today
persisted state is "keyed by per-store opaque ids, never by room-derived tags";
caching a peer's presence operation stores a room-derived object at rest, which
is exactly what item 12 says the prototype does not do. (ii) Nothing changes at
a store — the same five appends, the same instants; a real HELLO replaces a
dummy in a slot that was going to fire anyway.

**Spec deviation.** None on the wire. The caching policy is a client-local
choice §4.11 does not constrain.

**Implementation.** `pairDriver.ts`: accept an optional cached remote presence,
run the `observePeer` role computation against it at `start()`, and gate
`sendHello()` on being the initiator — ~70 LOC. Persistence layer: a
room-scoped store for one operation — ~50 LOC and a design decision about
encryption at rest.

**Measure.** A two-phase `run.mjs` scenario: run to `message-verified`, reload
both pages, and assert the second rendezvous is one window shorter than the
first for the pair where the reloading side is initiator.

**Why it is ranked low.** It buys 2 s expected on a repeat visit, costs a
persistence design and a widened §3a item, and needs a failure path for a stale
cache (the peer regenerated its receiver key → the HELLO is undeliverable and
must degrade to the normal path; §4.6 step 4 says an AEAD mismatch is
"not-this-candidate", so it degrades safely, but it costs a wasted window). Do
D1–D5 first.

---

### D7 — Shorten the delivery window (only after D1)

**Mechanism.** `withDeliveryWindowMs` (`profile.ts:415+`) already scales every
offset and re-validates. The cohort table records `W=2000, cohort 8` as
**stalling** — "every append answers `window-finalized`"
(`docs/blind-rendezvous-two-store-prototype.md:431`). `observed.md` §5 explains
why, and it is not what the doc assumed: at `W=2000` the finalization offset
scales to 1,400 ms while the store still needs ~1,450 ms to answer one scan, and
the appends queue behind that scan on the store's single event loop. **It is a
store-throughput failure, and D1 removes it.**

**Saving.** Discovery scales with `W`. At `W=1,000` with D1–D4:
**mean ~0.8 s** (see §4), i.e. **−90 %** against today.

**Privacy.** Direct and honest: a shorter window is a **smaller mixing epoch**.
Every §3a item that is argued against "599 ms against a 4,000 ms window"
(item 1) has to be re-argued at 1,000 ms — the band scales too, so the *ratio* is
preserved, but the absolute number of unrelated writes any one window can hide
shrinks with the cohort held fixed, and `requestDeadlineMs` shrinks in lockstep
(`storeClient.ts:276-283`). This is the one candidate here that **must be
measured and disclosed as a privacy trade**, not asserted as free.

**Spec deviation.** None — `deliveryWindowMs` is a profile value. But the
recorded `W=1000, cohort=2` row of the cohort table reaches 10.5 s at a cohort
**below** `minMeasuredSharedCohort`-adjacent comfort, and the doc already treats
the cohort as the anonymity knob. Do not conflate the two.

**Implementation.** Zero — `--window-ms` exists. The work is the re-measurement.

**Measure.** Re-run the whole cohort table after D1. The claim to test is that
`W=2000, cohort 8` and `W=1000, cohort 8` now complete with zero
`window-finalized` in the `store-missed` lines. If they do not, D1 is
incomplete.

---

### D8 — Shrink class 0's carrier object (refuting "presence could ride a smaller class")

**Mechanism and refutation.** Presence is **already** in the smallest class
available: `pairDriver.ts:705` sets `operationPayloadClass: 0`, spec:6435 pins
`PRESENCE` to class 0 only, and spec:5770-5774 (enforced at `profile.ts:196-203`)
pins the profile to exactly two size classes, one per payload class. So there is
no smaller class to ride. The only lever is class 0's
`fixedCarrierObjectBytes = 8,192` (`profile.ts:105`) against payload class 0's
frozen 4,096 bytes (`schemas.ts:47`). Summing the outer operation codec
(`schemas.ts:238-266`: 32 + 8 + 8 + 32 + 8 + 32 + 32 + signature 64 + tags and
length prefixes ≈ 200 B) over the 4,096-byte payload gives an encoded operation
of ≈ 4,300 B, so with the AEAD tag the body could be ~4,352 rather than 8,192 —
about **47 % of class 0 is unused padding**.

**Saving.** Class 0 is 24 objects of the 40-object scan but only
199,056 B of 1,380,336 B — **14 %** (`observed.md` §4a; class 1 is 85.6 %).
Halving it saves ~92 KB = **6.7 % of the scan**, worth ~0.10 s of `S` today and
**~0 s after D1**. Effectively dead once D1 lands.

**Privacy.** A smaller fixed object is a smaller cover object. §3a item 3 (size
and count) is where this lives, and it is a mild negative: less padding is less
padding. Not a reason to avoid it, but it is not free either.

**Spec deviation.** None for `fixedCarrierObjectBytes` (a profile value).
Shrinking class **1** — the 86 % — would require changing
`OPERATION_PAYLOAD_CLASS_BYTES[1] = 69,632` (`schemas.ts:48`, spec:6432), which
is a frozen release constant in shared, non-prototype code. That is a real
deviation and it is out of this angle's scope.

**Implementation.** One integer, `profile.ts:105`.

**Measure.** `profileTool info` prints the new scan bytes; `storeprobe.sh` prints
the new per-request cost.

---

### D9 — Considered and rejected: read the current window

The obvious "why wait a whole window" answer is to drop `publicReadLagWindows`
to 0 and read window `w` during window `w`. **It is not available and it should
not be made available.** It is pinned to exactly 1 by the profile validator
(`profile.ts:255-257`) *and* by the spec (spec:5816, an equality not an
inequality), and the reason is structural, not conservative: a chunk does not
exist before `finalize()` runs at `chunkFinalizationOffsetMs`
(`storeCore.ts:1213-1218`), and an unfinalized chunk has no signed root, no
Merkle commitment and no checkpoint chain link — so serving one would hand the
store a per-client omission channel with **no detection**, which is the one
property design §3a item 7 says the prototype does have. The spec's own note
(spec:5844) is blunter: "The one-window read lag removes a same-window
store/client clock race."

The legal sub-window levers are D3 (read earlier in the window) and D7 (make the
window shorter). There is no third.

---

## 4. Ranking, and what discovery becomes

Ranked by saving-per-risk — expected seconds bought, divided by how much
disclosure, deviation and review each costs.

| # | Candidate | Expected saving | Windows | New §3a leak | Spec deviation | LOC | Risk |
| ---: | --- | ---: | ---: | --- | --- | ---: | --- |
| 1 | **D1** store `loadWindow` | **1.40 s** | 0.35 | none | none | ~105 | none — and it unblocks 2, 3, 4, 7 |
| 2 | **D3** `publicReadOffsetMs` → 0 | **0.60 s** | 0.15 | none | none | 1 | liveness margin only |
| 3 | **D5** presence heartbeat | 0 s here; **∞ → 4 s** in three untested cases | 0 / ∞ | **new item 15** (liveness interval to capability holders) | none | ~225 | masks faults if unmetered |
| 4 | **D4** presence slot later | **+1.00–1.40 s** (via D2) | 0.25–0.35 | none | none | 5 | must confirm no `window-finalized` |
| 5 | **D2** same-window allocation | **1.60 s** (4.0 s for 40 % of starts) | 1.00 when it fires | inherits an existing undisclosed one | **yes** — spec:5832, 5835, 5875-5877 | ~55 | **strictly after D1**; gives up a window of allocation slack |
| 6 | **D7** shorter window | **×4 on everything** | — | none new, but a **smaller mixing epoch** | none | 0 | the real privacy trade; measure and disclose |
| 7 | **D6** warm-start co-publication | 2.00 s on return visits only | 1.00 | **widens item 12** (local forensics) | none | ~120 | stale-cache path; persistence design |
| 8 | **D8** class 0 shrink | 0.10 s, → 0 after D1 | 0.03 | mild negative on item 3 | none | 1 | not worth the profile churn |

### The composite

Mean over the uniform start phase `p`, using the §1.2 model:

| Configuration | Mean | Worst case | vs today |
| --- | ---: | ---: | ---: |
| today (measured 6.69–9.7 s, mean 8.0 s) | **8.05 s** | 10.05 s | — |
| + D1 | 6.65 s | 8.65 s | −17 % |
| + D1 + D3 | 6.05 s | 8.05 s | −25 % |
| + D1 + D3 + D2 | 4.45 s | 8.05 s | −45 % |
| **+ D1 + D3 + D2 + D4** (slot 3,499) | **3.05 s** | **5.05 s** | **−62 %** |
| all of the above at `W = 2,000` | 1.53 s | 2.53 s | −81 % |
| all of the above at `W = 1,000` | **0.80 s** | 1.30 s | **−90 %** |
| any of the above, peers minutes apart, **without D5** | never | never | — |
| any of the above, peers minutes apart, **with D5** | +1 window | +1 window | — |

The `W = 4,000` row is reached with **one store-side rewrite and six integers**.
No new leak, no spec deviation except D2's, no change to what any store sees per
window beyond the offsets in design §5's table. The `W = 1,000` row is the one
that reaches "blazing fast" and it is the one that costs a privacy argument.

**The hard floor.** With `publicReadLagWindows == 1` frozen (spec:5816),
discovery can never be less than one delivery window plus the read offset plus
the scan, minus the start phase:

```
T_discovery ≥ deliveryWindowMs + publicReadOffsetMs + S − p
```

At `W = 4,000, publicReadOffsetMs = 0` that is `4,050 − p ∈ (50, 4050]`, mean
**2.05 s**. Everything above `2.05 s` at this window is recoverable; nothing
below it is, without shrinking the window. That is the honest ceiling on this
angle.

---

## 5. Being skeptical of my own best idea

My best idea is **D5, the presence heartbeat** — cheapest mechanism, no store
disclosure, reuses an already-reviewed code path, and it fixes something that
looks like a product-killing bug. Here is what is wrong with it.

- **It buys zero seconds in every run anyone has recorded.** Its entire value
  rests on §2's claim that a staggered start deadlocks — and that claim is a
  code reading, not a measurement. If the maintainer's product only ever starts
  both sides within a few seconds of each other (both people click a link in one
  conversation), D5 is dead weight with a disclosure cost.
- **It is the only candidate here that adds a §3a item.** Everything in the
  top 4 except D5 changes nothing a store or a capability holder can see. D5
  turns presence into a liveness interval for capability holders. That is a real
  trade, made for robustness rather than speed, and it should be argued on
  robustness grounds, not smuggled in with a latency patch.
- **It hides faults.** A lost presence today is a hard failure that shows up as
  a harness timeout. With D5 it becomes a silent 4-second retry. The mitigation
  (fail `healthy` when the republication count exceeds 1) is easy, but if it is
  not shipped in the same commit, D5 makes the system less observable.
- **It does not fix the analogous hole in the four flights that follow it.**
  HELLO, ACCEPT, OFFER and ANSWER are each published once, into one window, and
  a peer that misses that window deadlocks exactly as it does for presence. D5
  makes discovery robust and leaves the connection half as brittle as it was —
  which is arguably worse, because the failure now happens later and looks
  different. The same mechanism extends to pair steps (the ledger already
  returns `replay` for a re-delivered id, `pairDriver.ts:1208-1211`, so it is
  safe), but that is a second change and a second review.

**What would make me drop it:** one `--stagger-ms=12000` run that *passes* on
the current code. That would falsify §2 outright, and D5 would collapse from
"fixes a permanent deadlock" to "shaves a rare retry" — at which point its §3a
item 15 is not worth paying. **Run that test first.** It costs ~60 LOC in
`run.mjs` and three minutes.

And a symmetric skepticism about the rank-1 candidate: **D1's 1.4 s is not a
protocol saving.** It is the removal of a prototype-store defect that a real
store would never have shipped. Any plan that lists "−1.4 s from D1" alongside
"−4.0 s from D2" as two protocol optimisations is double-counting, because in a
world with a competent store D1's saving was never there to take. D1 belongs at
rank 1 for its dependency structure, not its number.

---

## 6. What I could not measure, and what would settle it

- **The staggered-start deadlock is derived, not observed.** §2 rests on
  `carrierRuntime.ts:734` + `carrierRuntime.ts:1028` + `pairDriver.ts:1163`.
  `run.mjs` has no `--stagger-ms`. This is the single highest-value experiment
  in this report and it is ~60 LOC.
- **The start phase `p` is not recorded**, so every per-run prediction here is
  bimodal-but-unassigned. One line in `run.mjs` printing
  `Date.now() % deliveryWindowMs` at `presence-published` — the same line
  `floor.md` §11 asks for — turns D2's expected 1.60 s into a measured
  bimodality.
- **Background-tab throttling is a hypothesis.** I asserted that a throttled tab
  silently skips windows because `#nextEvent` skips past events
  (`carrierRuntime.ts:668-673`); I did not test it. A Playwright run that
  backgrounds page B for 30 s mid-rendezvous would settle it, and it is the most
  likely real-world trigger for the D5 recovery path.
- **D8's 47 % headroom in class 0 is arithmetic on the codec descriptor**
  (`schemas.ts:238-266`), not a measured encoding. It changes nothing about the
  ranking (D8 is last either way) but the number should be measured before it is
  quoted.
- **D2's 600 ms allocation budget after D1 is unverified.** `observed.md` §4c
  measures 1,270 ms today and attributes ~1,060 ms of it to the store; whether
  the residue lands under 600 ms is exactly what the post-D1 `storeprobe.sh`
  run answers, and D2 must not ship before that number exists.
