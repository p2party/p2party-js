# The claims adversary's pass over the latency candidates

2026-09-08. Lens: **would shipping this force a sentence in the shipped docs to
become false, make a recorded measurement unreproducible, or quietly convert
"we do not claim X" into "we now depend on X"?**

Inputs read in full: `floor.md`, `observed.md`, and all six angle reports;
`docs/blind-rendezvous-two-store-prototype.md` (outward),
`docs/blind-rendezvous-two-store-prototype-design.md` (design),
`src/blindRendezvous/prototype/profile.ts`,
`src/blindRendezvous/prototype/store/storeSqlite.ts`,
`src/blindRendezvous/schemas.ts`,
`tests/blindRendezvous/prototype/carrierRuntime.test.ts`,
`tests/blindRendezvous/projections.test.ts`. Five code facts below I checked
myself rather than taking from a report; they are marked **[verified]**.

Paths are relative to `~/Desktop/@p2party/p2party-js`.

---

## 0. Verdict table

Names are prefixed by their source report because `C1` means five different
things across the six.

| Candidate | Verdict |
|---|---|
| **SCAN-C2** replace `hexOf`/`bytesFrom` in `storeSqlite.ts` | **SURVIVES** — but it invalidates the outward doc's flagship measurement (§2) |
| **SCAN-C1** precomputed chunk/checkpoint rows | **SURVIVES** — same doc consequence as SCAN-C2 |
| **SCAN-C3** split the window document | **SURVIVES** (subsumed by SCAN-C2) |
| **SCAN-C4** drop `slots` after finalization | **SURVIVES** — settle the receipt-provenance question first |
| **SCAN-C5** in-process immutable response cache | **SURVIVES WITH A DISCLOSURE** (§4.5) |
| **SCAN-C7** stop the slow store gating the fast one | **SURVIVES WITH A DISCLOSURE** (§4.6) — it widens §3a item 14 |
| **SCAN-C8** memoize the checkpoint-chain verdict | **SURVIVES** — measure the problem first, as the author says |
| **SCHED-C1** late slots + reversed roles, `cf` 3,500 | **SURVIVES WITH A DISCLOSURE** (§4.1) — the best candidate in the set |
| **SCHED-C3** `publicReadOffsetMs` → 150–300 | **SURVIVES** — worth 0.6 s **once**, not per flight (§3.1) |
| **SCHED-C4** second append slot per critical role | **SURVIVES WITH A DISCLOSURE** (§4.7) |
| **SCHED-C2 / DISC-D2** allocate for the current window | **SURVIVES WITH A DISCLOSURE** (§4.2) — forces a §3a item that is owed anyway |
| **COL-C5** fixpoint the ingest batch | **SURVIVES** — zero disclosure, and it gates COL-C1 |
| **COL-C1** responder sends the first transport offer | **SURVIVES WITH A DISCLOSURE** (§4.3) |
| **PROD-C7** pre-gather ICE at start-up | **SURVIVES WITH A DISCLOSURE** (§4.4) — fingerprint reuse |
| **DISC-D5 / PROD-C2** standing presence in the cover slot | **SURVIVES WITH A DISCLOSURE** (§4.8) — and it must not ship without the fault-masking guard |
| **DISC-D7** shorter delivery window | **SURVIVES WITH A DISCLOSURE** (§4.9) |
| **SHRINK-C1** class-1 carrier 73,728 → 8,448 | **NEEDS A GATE** (§4.10) — a KILL without SHRINK-C5 and two assertions |
| **SHRINK-C4** `publicChunkObjectCount` 8 → 24 | **SURVIVES WITH A DISCLOSURE** (§4.11) |
| **SHRINK-C5** §4.12 operation-carrier fallback | **SURVIVES** — it is the gate SHRINK-C1 needs, not an optimisation |
| **PROD-C1 / DISC-D6** warm start from a retained peer presence | **SURVIVES WITH A DISCLOSURE** (§4.12) — it amends a disclosed leak |
| **COL-C6 / PROD-C5** symmetric transport parameters | **SURVIVES WITH A DISCLOSURE** (§4.13) — but COL-C1 dominates it |
| **SHRINK-C2** payload class 1 → 8,192 | **KILL** (§5.1) |
| **SHRINK-C3** payload class 1 → 36,864 | **KILL** (§5.1, same reason, less than half the prize) |
| **COL-C2** speculative offer under a HELLO-derived root | **NEEDS A GATE the prototype cannot build → KILL for now** (§5.2) |
| **COL-C3** SDP inside HELLO/ACCEPT | **KILL** (§5.3) |
| **COL-C4** room-keyed identity beacon | **KILL** (§5.4) |
| **PROD-C3** transport parameters inside PRESENCE | **KILL** (§5.5) — the ugliest disclosure in the set |
| **PROD-C6** store as a fast SDP drop | **KILL** (§5.6) |
| **PROD-C8** legacy signaling as a fast path | **KILL** (§5.7) |
| **PROD-C9** long-lived push read | **KILL** (§5.8) |
| **SCAN-C6** CDN in front of the immutable routes | **KILL for the prototype / NEEDS A GATE in production** (§5.9) |
| **SCAN-C11** one request for the whole window | **KILL** (§5.10) |
| **SCHED-C5 / DISC-D9** `publicReadLagWindows` → 0 | **KILL** (§5.11) |
| **DISC-D8** shrink class 0's carrier object | **KILL** (§5.12) |
| **SCAN-C9** pre-AEAD recipient hint | **KILL** — the authors already reject it; I concur, and the k-bit sieve argument is the right one |
| **SCAN-C10** WebCrypto for the AEAD | **KILL** — WebCrypto has no XChaCha20; not a candidate |
| **SHRINK-C6** class 1 → 4,097 | **KILL** — the author's own experiment, kept as evidence not as a candidate |
| **SCAN-C12** negative `publicReadOffsetMs` | park, as the author says |

---

## 1. What I verified myself

1. **[verified] The pinned profile is exactly as the reports quote it.**
   `profile.ts:86-125`: window 4,000; `chunkFinalizationOffsetMs` 2,800;
   `publicReadOffsetMs` 600; `publicReadLagWindows` 1; class 0 8,192 at
   1,300/1,700/2,100; class 1 73,728 at 1,500/1,900; cohort 8; `pcoc` 8.

2. **[verified] The four §4.3 inequalities are enforced exactly as `floor.md`
   §8 quotes them** (`profile.ts:238-251`, `:336-345`, `:347-353`), and
   `publicReadLagWindows !== 1` is a hard fail (`profile.ts:255-257`). So
   `SCHED-C1` really is deviation-free and `SCHED-C5` really is a deviation.

3. **[verified] `observed.md` §4c/§4e blames the wrong line, and the angle that
   corrected it is right.** `storeSqlite.ts:68-78`: `hexOf` is
   `[...value].map(b => b.toString(16).padStart(2,"0")).join("")` and
   `bytesFrom` is a regex plus `Number.parseInt(value.slice(i*2, i*2+2), 16)`
   per byte. `JSON.parse` is not the cost; the hand-rolled hex codec is. Any
   doc sentence written from `observed.md` §4e would be false.

4. **[verified] The per-store phase band is pinned by a test, on purpose.**
   `tests/blindRendezvous/prototype/carrierRuntime.test.ts:1438-1446` asserts
   `PHASE_EARLIER_MS === 100n`, `PHASE_LATER_MS === 499n`,
   `PHASE_SPAN_MS === 599n`, with the comment *"Design doc §3a item 1 quotes
   these three numbers; they are measured against the real validator here
   rather than written down, so a profile edit that changes the band fails this
   test instead of quietly making the document wrong."* **This is the single
   best honesty guard in the repository and every profile candidate must be
   judged against it.** `SCHED-C1`'s choice of `cf = 3,500` is what keeps it
   green; `cf = 3,200` would have made design §3a item 1 false, and the test
   would have caught it.

5. **[verified] `OPERATION_PAYLOAD_CLASS_BYTES` is not prototype-scoped, and a
   release-candidate test pins class 1 above the v4 control frame.** It is
   consumed by `src/blindRendezvous/pairStepEnvelope.ts:119,166`,
   `src/blindRendezvous/operation.ts:175,419,735` and
   `src/blindRendezvous/pairOpenBudget.ts:148-177` — five call sites, none of
   them under `prototype/`. And `tests/blindRendezvous/projections.test.ts:246-252`:

   ```ts
   expect(OPERATION_PAYLOAD_CLASS_BYTES[1]).toBe(69_632);
   // Class 1 must hold the existing 65,490-byte protocol-v4 control frame
   // plus pair and operation framing overhead.
   expect(OPERATION_PAYLOAD_CLASS_BYTES[1]).toBeGreaterThan(65_490);
   ```

   That comment is the answer to `angle-shrink-class-1` §6.1's open question
   ("this is the one question I would put to the maintainer"): the intent is
   already written down, in a test, in the release-candidate surface. It
   settles SHRINK-C2 and SHRINK-C3 (§5.1).

---

## 2. Three sentences that are already false, before any candidate ships

The adversary's first duty is to check the baseline. All three are in the
outward doc, which is the one an outside reader quotes.

**2.1 — `docs/blind-rendezvous-two-store-prototype.md:446-449` blames the
browser for something the browser does in 8 ms.**

> "At cohort 8 the browser cannot finish 1.38 MB × 2 stores of scanning and
> sealing between the read offset (600 ms) and the last append offset
> (2,100 ms), so every flight slips to the window after"

`observed.md` §4b measures the entire per-window decode + trial-open of all 40
objects at **4.0 ms per store, 8 ms for both**. The browser finishes it 180×
inside the budget. What cannot be finished is the *store's* service of the
scan. This sentence is wrong today and must be corrected whether or not any
candidate ships.

**2.2 — the same paragraph's causal claim about the cohort is wrong.**

> "The knob that buys the latency is the one that sizes the shared bucket."

The cohort bought latency only because the store's per-request cost is
`O(whole window document)` and the cohort sizes that document. It is a
measurement of a store implementation defect seen through a proxy. The
consequence is stated in full in §3.1 below, and it is the most important
honesty finding in this report.

**2.3 — "thirteen fixed requests… whether the client is idle or mid-rendezvous"
is true only after the first window.** `observed.md` §8 measured `w0+0` at **9
requests and 0 append bodies** per page per store, against 15 afterwards,
because `#nextEvent` skips append events whose offsets are already past. A
store therefore reads the client's start phase off the *set of appends missing
from its first window*. This is an undisclosed leak; it is not in §3a; it is
not caused by any candidate; and three candidates (SCHED-C1, SCHED-C2,
DISC-D2) touch it. **It must become §3a item 15 regardless of what ships.**

> **Correction, 2026-09-08 (stage 1, fix round).** It is now §3a item 15, and
> the finding stands — but "9 requests" was never a reachable count and the
> inference is weaker than stated here. A store reads the start phase off the
> missing offsets **only above `publicReadOffsetMs`**; below it the start window
> carries the whole fixed thirteen, and at `100 < p ≤ 600` its total is exactly
> the steady-state 15. See design §3a item 15 and `observed.md` §8.

---

## 3. Two things the maintainer must not compound

### 3.1 The store fix invalidates the outward doc's flagship measurement — and that is the right outcome, stated wrongly if stated carelessly

`SCAN-C1`/`SCAN-C2`/`DISC-D1`/`PROD-C0` are the same fix under four names, and
every angle correctly says it has **zero** privacy cost: no wire byte, no
route, no request count, no offset, no geometry. I agree, and I add what none
of them says plainly:

> **The whole of §6 of the outward doc — the cohort table, its 39.9 s / 22.3 s
> / 23.8 s / 20.8 s / 17.9 s / 10.5 s rows, its "stalls" row, and its causal
> paragraph — becomes unreproducible the moment the store's hex codec is
> fixed, and the trade it appears to demonstrate (a larger anonymity set costs
> latency) largely stops existing.**

That is not a reason to refuse the fix. It is a reason to refuse to ship the
fix and leave §6 standing. The exact sentence §6 needs afterwards:

> The cohort table below was measured against a store whose chunk GET
> rebuilt the entire window document with a hand-rolled hex codec on every
> request, at a flat ~97 ms per request regardless of the chunk requested. The
> cohort appeared to buy latency because it sizes that document. With the
> codec replaced, the per-request cost is not linear in the cohort in the same
> way, the "per flight" column collapses to one window at every row measured,
> and `cohortAllocationsPerWindow` can be chosen for what it is actually for —
> how much unrelated traffic a client's objects sit among — rather than for
> speed. The rows are retained as a record of what was measured at
> profile hash `83a2261e…` on the pre-fix store, not as a current cost model.

**Do not delete the table.** A recorded measurement that a later change made
obsolete is exactly the thing this project's discipline says you keep, with the
conditions under which it held.

### 3.2 Two angles double-count `publicReadOffsetMs`, and one double-counts the scan

`floor.md` §4 and `angle-schedule-shape` §2 both give the correct equation:

```
T = (C + F)·W + r + S − p + M·W
```

`r` and `S` each appear **once**. But:

- `angle-presence-discovery` D3 claims `publicReadOffsetMs` → 0 saves "0.60 s
  … and again on each of the four later flights", and its composite table
  spends 0.6 s five times.
- `angle-product-shape` C9 prices the push read at "roughly 0.6 s per flight =
  3.0 s at F=5", spending both `r` and `S` per flight.

Both are wrong. Shifting every read earlier by `r` shifts the whole ladder
earlier by `r` once; the flights are still one window apart. `S` likewise
enters the total once, at the end, plus once more as a *condition* on whether
each slot is caught (the `M` term). **A stacked plan that adds `SCHED-C3`'s
0.6 s to `DISC-D3`'s 3.0 s is adding the same 600 ms six times.** If a slide
ever shows that arithmetic, a member of the audience with `floor.md` open will
catch it.

Two smaller cross-report corrections worth carrying, both already found by one
angle against another and neither yet propagated:

- `observed.md` §3's per-flight table attributes `TRANSPORT_OFFER`/`ANSWER` to
  the class-1 slot at 1,500 ms. `floor.md` §3 and `angle-shrink-class-1` §1.2
  show every recorded transport flight is class 0 at 1,700 ms (the measured
  harness SDP is 692 B against a class-0 ceiling of 3,613 B). Conclusions
  unchanged; the quoted budgets differ by 200 ms.
- `observed.md` §4e's `JSON.parse` attribution is wrong by ~340× (§1 item 3).
  Four other reports cite it. Fix it at the source before anyone writes it into
  a doc.

---

## 4. Survivors, with the exact sentence each one owes

### 4.1 SCHED-C1 — late slots, reversed roles, `cf = 3,500` — **SURVIVES WITH A DISCLOSURE**

The strongest candidate in the set: measured (11 runs), no spec deviation, byte-identical
geometry, and it deliberately preserves the §3a item 1 band that a test pins
(§1 item 4). Nothing about it converts a non-claim into a dependency *in kind*
— the system already depends on `S` beating a deadline, and today it loses.

Doc edits it forces (all edits, none of them a falsehood introduced): design
§4.2's profile block; design §5's "Offset in the window" column; design §3a
item 1's parenthetical derivation (`2800`→`3500`, `2100`→`2800`, result
unchanged at 499/599); outward doc §3's offsets row; outward doc §7 leak 1's
table. Exact sentence to add to design §4.2:

> The append offsets and `chunkFinalizationOffsetMs` sit late in the window so
> that an answering flight's read of the previous window completes before its
> own window's append slot, and the append roles are ordered so that the two
> roles on the critical path (`identity-bootstrap`, `safety-control`) get the
> latest slots and `state-replication`, which is never on it, gets the
> earliest. The geometry is otherwise unchanged — `scannedBytesPerWindow`
> 1,380,336 and `appendedBytesPerWindow` 172,542 are byte-identical to the
> previous profile, every §4.3 inequality holds, and the per-store phase band
> of §3a item 1 is preserved at exactly 100 ms earlier / 499 ms later / 599 ms
> wide. **This profile is not safely rescalable.** `chunkFinalizationOffsetMs −
> min(appendSchedule.offsetMs)` must exceed the store's absolute time to drain
> one window's appends, and `min(appendSchedule.offsetMs) − publicReadOffsetMs`
> must exceed the store's absolute time to serve two clients' scans. Both are
> absolute milliseconds and neither scales with `deliveryWindowMs`, so
> `withDeliveryWindowMs` cannot re-derive them and every `--window-ms` other
> than 4,000 must be re-measured with `--scenario=all` before it is quoted.

That last clause is not decoration. `angle-schedule-shape` §6.2 measured
`E8-w1000-c2.txt` **FAILING** with 17 × `append window-finalized` at a
configuration the outward doc records at 10.5 s. Shipping SCHED-C1 turns a
recorded passing row into a failing one. Outward doc §8's line
"`P2PARTY_STORE_WINDOW_MS` — rescales the pinned delivery profile" becomes a
foot-gun and needs the same caveat.

**Residual risk to state, not hide:** SCHED-C1 moves `M` from 4 to 0 with
~670 ms of margin over the measured `S` p50 *on one laptop, on loopback,
headless*. A device with a larger `S` falls back to two windows per flight
with no degraded label and no warning — a silent 24 s → 40 s. That cliff is
removed by SCAN-C2, not by SCHED-C1, which is why the ordering in §6 puts the
store fix first.

### 4.2 SCHED-C2 / DISC-D2 — allocate for the current window — **SURVIVES WITH A DISCLOSURE**

It is a named spec deviation (spec:5832, 5835, 5875-5877) and it adds a second
allocation POST to the session's first window. The honest disclosure is larger
than the candidate, because it must carry the pre-existing leak of §2.3. Exact
§3a item:

> 15. **First-window shape.** A client's first delivery window is
>     distinguishable from every later one, and always has been. `#nextEvent`
>     skips append events whose offsets are already past, so a store sees
>     fewer requests in that window and can read the client's start phase from
>     *which* appends are missing (measured: 9 requests in the first window
>     against 15 afterwards). A client that starts after
>     `allocationRequestOffsetMs` additionally issues its allocation POST at an
>     off-grid instant rather than at the profile's offset. The current-window
>     allocation adds one more allocation POST to that same window. The total
>     disclosure is one bit — "this client's session began in this window" —
>     readable by each store from its own log, in the first window of a session
>     only. `windowShape()` in `carrierRuntime.test.ts` does not cover it,
>     because it asserts steady-state windows.

**Two conditions.** (i) It must not ship before the store fix: the measured
allocation POST takes p50 1,394–1,459 ms against a profile budget of 300 ms, so
today the guard fires, the round trip misses the slot anyway, and the only
effect is a wider first-window tell for nothing. (ii) The byte-identical replay
variant (`angle-schedule-shape` C2) is strictly better and moves the leak out
of the traffic shape entirely; prefer it if the maintainer will pay one extra
request per window forever.

Also correct the hit rate before quoting it: `floor.md` says 20 %,
`angle-presence-discovery` says 40 %, `angle-schedule-shape` says 47.5 %. They
are measuring against different slots (`min(appendOffset)` vs presence's own
slot) under different profiles. Pick one and say which.

### 4.3 COL-C1 — the responder sends the first transport offer — **SURVIVES WITH A DISCLOSURE**

I checked the claim that a store sees nothing: `#eventsForWindow` schedules the
same five append POSTs whether the outbox holds nothing, one operation or two,
and an unmatched slot sends a same-size dummy at the same instant. The
responder's ACCEPT window changes from *one real + four cover* to *two real +
three cover*, which is by construction indistinguishable. **Design §5's
thirteen fixed requests are byte-for-byte unchanged. No §3a item is added or
widened.** That holds.

What it costs is an ordering rule, and it must be named as a deviation:

> Named deviation, permitted for a flagged prototype by spec line 3392, from
> spec REQ-012 line 927, spec:10184-10188 and spec:10220: the responder emits
> its transport offer in the same delivery window as its `IDENTITY_ACCEPT`,
> after its own identity gate and before the initiator's. The offer is sealed
> under `EstablishedPairRoot`, which only the endpoint whose HELLO the
> responder has just opened, verified and admitted can derive, so the recipient
> set is identical to today's and a party the responder denied still obtains no
> SDP. What is given up is the property that the first transport offer proves
> the initiator received and admitted the ACCEPT — key confirmation moves from
> the offer to the answer.

Design §4.6 steps 8 and 9 must swap, and §4.6's note that "the prototype
detects a fork at the identity slot, not at the transport slots" is unchanged
but its surrounding prose is not.

**COL-C5 (the ingest fixpoint) must land first or COL-C1 delivers its window
about half the time** — `coreReduce` sorts the active set by operation id, i.e.
randomly with respect to causality, and `ingest` makes one pass. That is a
10-line fix with zero disclosure and it is the cheapest thing in this entire
exercise.

### 4.4 PROD-C7 / COL-C1's companion — pre-gather ICE — **SURVIVES WITH A DISCLOSURE**

Free in the harness (`iceServers: []`), worth up to a whole window per
transport flight in production. But a session-long `RTCPeerConnection` reuses
one DTLS certificate fingerprint and one ICE ufrag/pwd across every pair
attempt in that session. Nothing reaches a store — the SDP is inside the pair
envelope — but a *peer* that completes two attempts with this endpoint sees the
same fingerprint twice. Today each attempt gets fresh credentials. Exact line:

> Pre-gathering creates one `RTCPeerConnection`, and therefore one DTLS
> certificate fingerprint and one ICE ufrag/pwd, at session start rather than
> per pair attempt. No store sees any of it. A peer that completes two attempts
> with the same endpoint in one session can link them by fingerprint; before
> this change each attempt carried fresh credentials.

The alternative — regenerate per attempt and pay the gathering cost on the
second attempt only — is cheap and removes the disclosure. Prefer it.

### 4.5 SCAN-C5 — in-process immutable response cache — **SURVIVES WITH A DISCLOSURE**

Only if populated **eagerly at finalization**. A lazily-populated cache makes a
hit and a miss distinguishable by timing, so a client can tell whether someone
else recently read the same public chunk. It reveals nothing about rooms or
membership (every client reads every chunk of every window), but it is a
new observable and the prototype's discipline is to state those. Eager
population removes it; say in the code comment that it is why.

### 4.6 SCAN-C7 — stop the slow store gating the fast one — **SURVIVES WITH A DISCLOSURE**

This one has a cost the angle did not find. Design §4.5 already says the
witness pair fires "once that scan's union resolves — no fixed offset". Under
per-store settlement it fires when *that store's own* scan settles rather than
when the slower of the two does. So §3a item 14's oracle gains resolution:

> §3a item 14, amended: a store learns not only *whether* the other store
> served this client a finalized window, but *when* the other store's scan
> completed, to within the difference between the two stores' service times —
> because the witness pair now fires on per-store settlement rather than on the
> union.

**The better fix is to pin the witness pair to a fixed offset in the window**,
which would close part of item 14 rather than widen it, and which the design
doc already names as the fix ("post a witness record to every other store every
window regardless, carrying cover when there is nothing to witness"). Do that
in the same commit or accept the amendment.

### 4.7 SCHED-C4 — a second append slot per critical role — **SURVIVES WITH A DISCLOSURE**

No spec deviation (spec:5822-5824 says `count(role) >= 1`). It is a measurable
traffic increase and must be reported as one: design §5's "thirteen fixed
requests" becomes fourteen, the scan grows 1,380,336 → 1,446,688 B (+4.8 %),
and chunk GETs go 5 → 6 per store per window. It is insurance against the
`S`-tail cliff SCHED-C1 leaves, worth zero on the healthy path, and partly
self-defeating (a bigger scan is a bigger `S`). Ship it only if a real-device
`S` measurement shows the tail crossing the budget.

### 4.8 DISC-D5 / PROD-C2 — standing presence — **SURVIVES WITH A DISCLOSURE**, with a guard

Mechanically the cleanest idea in the set: the `state-replication` slot already
fires with cover in every window, and filling it with a real presence changes
no byte, no instant, no count, no route. **No store sees anything.** But it
changes what presence *means* to a capability holder, and that needs its own
item:

> 16. **Presence is a liveness interval, not a point event.** While a room has
>     no established edge, the same `PRESENCE` operation bytes are re-published
>     into the `state-replication` append slot that already fires with cover in
>     every window, bounded to N windows. No store sees a change — the slot,
>     the instant, the route and the byte count are identical, and a real
>     object and cover are the same bytes at the same instant. Any capability
>     holder, however — including one who obtains the capability later and
>     holds archived carrier objects — learns that this endpoint was online
>     *across* that interval rather than at a single instant.

Two hard conditions.

- **Republish the same bytes, not a fresh presence.** `angle-presence-discovery`
  D5 says same-bytes; `angle-product-shape` C2 says mint a fresh presence with
  a fresh author epoch. They disagree and only one is safe. Same bytes keep the
  `OperationId` stable, so the peer's `#seen` filter drops duplicates and no
  `PairEdgeId` churn occurs; a fresh presence every window mints a new
  `PairEdgeId` every window and risks the fork/slot semantics of spec:9894-9897.
  Republish the same bytes.
- **It must not silently mask faults.** Today a lost presence is a hard failure
  that surfaces as a harness timeout; with a heartbeat it becomes a silent
  4-second retry. The harness must fail `--scenario=healthy` when the
  republication count exceeds 1, **in the same commit**. Without that guard the
  change makes the system less observable, which is a direct cost to the one
  property this artifact actually has.

**And the claim that motivates it is unmeasured.** Both angles assert that two
peers who start more than about one delivery window apart *never* rendezvous.
The reasoning reads correctly against `carrierRuntime.ts:734`, `:1028` and
`pairDriver.ts:1163` — and the failure is asymmetric, which is why it is easy
to get wrong: the late starter B *is* seen by A, A sends a HELLO, and B defers
it forever because B never observed A's presence. But **nobody ran it.**
`run.mjs` has no `--stagger-ms`. Until a staggered run fails on the current
code, that sentence must not appear in any document, and the framing "the
41.8 s is the latency of a case the product will never be in" must not appear
on a slide. The test is ~60 LOC and it is the highest-value experiment named
anywhere in these six reports.

### 4.9 DISC-D7 — a shorter delivery window — **SURVIVES WITH A DISCLOSURE**

The only candidate whose privacy cost is intrinsic rather than incidental: a
shorter window is a smaller mixing epoch, and `requestDeadlineMs` shrinks in
lockstep (`storeClient.ts:276-283`). Every §3a argument that leans on "599 ms
against a 4,000 ms window" must be re-stated at the new window — the *ratio* is
preserved by `withDeliveryWindowMs`, the absolute count of unrelated writes any
one window can hide is not, at a fixed cohort. Do not conflate it with the
cohort, which the outward doc already treats as the anonymity knob. And per
§4.1 it must be re-measured with `--scenario=all`, not extrapolated.

### 4.10 SHRINK-C1 — class-1 carrier 73,728 → 8,448 — **NEEDS A GATE**

The prize is real and is the largest of any single line in the set: the scan
falls 4.11×, and with it the store's per-request cost, the client's sustained
downlink (5.5 → 1.3 Mbit/s per idle client), the uplink (690 → 168 kbit/s) and
the store's disk (4.1×). `fixedCarrierObjectBytes` is a profile field and is
properly prototype-scoped. Class 1 is provably pure cover in this prototype.

But as written it ships a profile in which operation payload class 1 has **no
size class that fits it**, which the validator does not check, and a pair step
the codec routes to class 1 then throws inside `buildCarrierPlaintext` and
fails the edge — with no typed outcome and no fallback. That makes design §4.6
step 8's *"SDP must be 1..32,768 UTF-8 bytes with exactly one SHA-256
fingerprint"* a sentence the same build contradicts at runtime, and it
converts "the rendezvous degrades honestly" into "the rendezvous dies with a
canonical-encoding error on a user with too many network interfaces".

**Three things gate it, and without all three it is a KILL:**

1. **SHRINK-C5** — the spec's own §4.12 fallback (spec:10396-10398): compute
   the padded class before committing, and if the offer would not fit, emit an
   offer holding only `operation-carrier` and surface a typed
   "no WebRTC path on this network" outcome instead of `failEdge`.
2. **Three lines in `validateDeliveryProfileGeometry`** asserting
   `fixedCarrierObjectBytes >= OPERATION_PAYLOAD_CLASS_BYTES[c] + 255`, with
   the prototype's violation as an explicit, named allow — so the
   incompatibility is *stated by the validator* rather than silent.
3. **A harness assertion on the published `operationPayloadClass`** of each
   transport flight, which `floor.md` §11 and `angle-shrink-class-1` §6.3 both
   ask for independently. Today the class flip is invisible; under SHRINK-C1 it
   is fatal, and no run has ever observed a class-1 real object.

Disclosure sentence:

> Named deviation, permitted for a flagged prototype by spec line 3392, from
> `RoomProfileCompatible` at spec:4605-4607: the class-1 carrier object is
> sized at 8,448 bytes, which does not fit operation payload class 1's 69,632
> bytes, so payload class 1 has no usable size class in this profile. Class 1
> carries only cover in this prototype — every recorded run's transport flights
> are class 0, whose 3,613-byte SDP ceiling is 3.6× the largest SDP measured
> here (1,002 B with one STUN server, four ICE candidates). An offer that would
> exceed the class-0 ceiling is refused before it is committed and reported as
> "no WebRTC path", not carried and not silently dropped.

Note also that the SDP measurements the whole argument rests on are **Chromium
only**, and spec:10394-10396 asks for a browser × ICE × TURN × IPv4/IPv6
matrix. Say so.

### 4.11 SHRINK-C4 — `publicChunkObjectCount` 8 → 24 — **SURVIVES WITH A DISCLOSURE**

No spec deviation; the minimum-chunks inequality is recomputed by the
validator. It changes a number the outward doc puts in its title position:

> §5's fixed trace becomes **ten** requests per client per store per window
> rather than thirteen — two chunk GETs instead of five — and the per-window
> scan grows from 335,856 to 404,256 bytes per store, because eight of each
> class-1 chunk's twenty-four slots are unscheduled cover. Both numbers remain
> fixed and identical for every client on the grid.

Drop `angle-shrink-class-1`'s claim that it "slightly reduces the surface for
§3a item 2 (source addresses)": item 2 is about the client's IP, which the
store sees on every request regardless of how many there are. That is an
overclaim and it should not survive into a doc.

And it is a byte-for-request trade that only pays while the store's per-request
cost is `O(whole window document)`. After SCAN-C2 it is a pure +20 % byte loss
and should be reverted. Say that in the commit message so it is not left in by
inertia.

### 4.12 PROD-C1 / DISC-D6 — warm start from a retained peer presence — **SURVIVES WITH A DISCLOSURE**

It amends a disclosed leak rather than adding one, which is the honest kind:

> 12. **Local forensics.** Persisted seen-sets and checkpoints are keyed by
>     per-store opaque ids, never by room-derived tags — **except** the
>     retained peer presence used by the warm-start path, which is a
>     room-derived operation held at rest and is therefore a durable
>     co-membership record on the device. It is encrypted under the identity
>     vault key and expires with `receiverKeyValidThroughLogicalWindow`
>     (24 hours at the default policy).

If the retained store cannot be encrypted under the identity vault, drop the
candidate: 4 seconds is not worth writing the one thing the wire protocol works
hardest to avoid onto the disk in the clear. Note also that outward doc §9
lists "persistent scheduler cursors and restart-safe outboxes" as *not
implemented* and says "a reloaded page starts a fresh session" — so this is a
persistence project with a latency benefit, not a latency patch, and pricing it
at 530 LOC is optimistic.

### 4.13 COL-C6 / PROD-C5 — symmetric transport parameters — **SURVIVES WITH A DISCLOSURE**, but COL-C1 dominates

Same one-window saving as COL-C1, no role flip, no pre-gathering caveat — but
it hand-rolls SDP synthesis or munging. Required sentence:

> The prototype has only ever run on headless Chromium. A path that synthesises
> or rewrites a peer's session description from transport parameters is exactly
> the kind of code that works on one engine and fails on another, and no run
> here tests a second engine.

Take COL-C1 first; keep this as the fallback if the pre-gathering fingerprint
disclosure is refused.

---

## 5. Kills

### 5.1 SHRINK-C2 (class 1 → 8,192) and SHRINK-C3 (→ 36,864) — **KILL**

**One sentence for the implementer:** they edit
`OPERATION_PAYLOAD_CLASS_BYTES` in `src/blindRendezvous/schemas.ts` — a frozen
constant consumed by five non-prototype call sites and pinned by
`tests/blindRendezvous/projections.test.ts:246-252` with the comment *"Class 1
must hold the existing 65,490-byte protocol-v4 control frame plus pair and
operation framing overhead"* — so they are not prototype-scoped changes, they
delete an existing release-candidate guard, and they falsify the outward doc's
"the prototype lives entirely under `src/blindRendezvous/prototype/`".

Two further consequences, in case the first is argued: the change would
require regenerating a **cross-language SHA-256 conformance vector**
(`tests/blindRendezvous/reference/pair_plaintext_vectors.py`), which is a
conformance artifact and not a fixture; and it lowers the §4.12 SDP ceiling
from 32,768 to 7,709 bytes, which spec:10399 says "changes the pair/class codec
and profile" — symmetrically, in both directions.

`angle-shrink-class-1` §6.1 correctly identified the maintainer question ("does
the roadmap intend `PQ_CONTROL` over the operation carrier?") and correctly
said nothing it measured settles it. It is settled, in the repository, by that
test's comment. **Revivable only** as a prototype-local class table threaded
through the prototype modules, leaving `schemas.ts` and `projections.test.ts`
untouched — which is materially more than the two lines it is costed at.

### 5.2 COL-C2 — speculative offer under a HELLO-derived root — **NEEDS A GATE the prototype cannot build → KILL for now**

The angle is right about what it costs and right that the cost is paid to a
peer, never to a store, and its proposed §3a item 15 and `--scenario=harvest`
measurement are exactly the right discipline. The problem is the gate. It must
be refused unless `eligibility === "open"` and the frontend is not in
`onlyConnectWithKnownPeers` / address-book / authority mode — and **the
prototype has no admission kernel at all** (design §2: "The admission kernel …
is *not* consulted"; outward doc §9 lists it as unimplemented). So the gate
would be a constant, its refusal test would be vacuous, and the artifact would
carry a fast path whose only safety argument is a policy engine that does not
exist and a comment that a later product decision will not read.

**One sentence:** it makes the prototype *depend* on the open policy it
currently only *declares*, and the mechanism that would enforce that dependency
is the admission kernel, which is not implemented.

Revisit when `Admit()` exists, with the harvest scenario landing in the same
commit — the number that scenario prints is the disclosure, and it is worth
building even now as a measurement of the current protocol's zero.

### 5.3 COL-C3 — SDP inside HELLO/ACCEPT — **KILL**

Same saving and same privacy price as COL-C2, plus a silent data-dependent
failure at roughly five ICE candidates (1,136 B of headroom in a bootstrap
class-0 plaintext, with no class-1 bootstrap form to grow into —
`pairStepEnvelope.ts:112-114` fails closed), plus edits to two frozen §4.11
body types and their pinned vectors, plus it writes SDP into the two flights
spec:10182 singles out by name. The author already recommends rejecting it and
is right.

### 5.4 COL-C4 — room-keyed identity beacon — **KILL**

It widens design §1.6's open-mode concession from "*the selected* capability
holder may learn that first sender identity" to *every* capability holder, and
it collapses the pair root from two hybrid KEM encapsulations to one. One
window is not worth a cryptographic weakening plus a new byte in a closed
`PairStepKindV1` registry.

### 5.5 PROD-C3 — transport parameters inside PRESENCE — **KILL**

**The ugliest disclosure in the set, and the reason is not the leak — it is
what the leak does to an existing measurement.** Under C3 the ICE parameters
and DTLS fingerprint ride inside the room-AEAD'd presence payload, so they
never appear in a store's request body — and the privacy audit would continue
to print, truthfully, **"0 of 148 needles found in the N request bodies the
audit searched"** for a run in which every member's IP and DTLS fingerprint
were broadcast to every capability holder before any identity flight. A
literally true verdict line that a reader would take for the opposite of what
happened is worse than a false one, because nothing in the harness would catch
it.

It also forfeits AC-005 (spec:11697-11699) — a *named, numbered, testable*
acceptance criterion — by construction, and its safety rests on a
`maxRoomMembers === 2` gate that would have to survive a "join by link" feature
three quarters later. The author's own §9 makes four of these arguments; I add
the fifth and consider it decisive on its own.

### 5.6 PROD-C6 — store as a fast SDP drop — **KILL**

A location derived from `EstablishedPairRoot` is a deterministic peer-equality
handle at the store, which spec:480-482 forbids in as many words, and the
aggressive polling it needs is the event-shaped traffic §3a item 4 exists to
forbid. It trades the artifact's single most important property for 8 seconds.

### 5.7 PROD-C8 — legacy signaling as a fast path — **KILL**

It would make outward doc §2 item 3 ("**No signaling server is running anywhere
in the test.** The legacy WebSocket path is not started, not imported by the
page bundle, and not reachable") and design §6 ("no fallback to legacy
signaling exists or is added") false in the same commit, and it hands a third
party every item on spec:494-505 plus the one connection-side item. There is no
honest sentence a client can say about a session that was sometimes blind.

### 5.8 PROD-C9 — long-lived push read — **KILL for the prototype**

It dissolves the artifact's central disclosure. Design §5's fixed trace is
thirteen enumerated requests at named offsets; a streamed read replaces six of
them with one connection whose *lifetime* is a per-client observable, which is
the session-clustering signal Cwtch's own handbook concedes. And its claimed
saving is double-counted (§3.2): it is worth `r` once, not `r` per flight, and
after the store fix `S` is tens of milliseconds. A new observable, a spec
deviation on the read event, and ~570 LOC, for about 0.6 s.

### 5.9 SCAN-C6 — CDN in front of the immutable routes — **KILL for the prototype, NEEDS A GATE in production**

In the harness it buys nothing (two clients, one machine). In production a
shared CDN in front of both stores makes them one observation domain and one
fault domain, which collapses the entire architecture and hands §3a items 1 and
2 to a single party. If it is ever deployed: different CDNs per store, named
explicitly in §3a item 8's independence statement ("operator, ASN, hosting,
jurisdiction and funding must be stated and auditable" gains "and CDN"), with
the two ASNs asserted.

### 5.10 SCAN-C11 — one request for the whole window — **KILL**

A spec deviation against REQ-007 (spec:876-879), spec:5837-5841 and AC-049
(spec:12560-12562), which shrinks design §5's fixed trace from thirteen
requests to nine, in exchange for 0.36 ms after SCAN-C1/C2 have landed.

### 5.11 SCHED-C5 / DISC-D9 — `publicReadLagWindows` → 0 — **KILL**

It buys a one-off phase shift of ≤1.7 s, not a window per flight — inside one
window the validator forces `append → finalize → read` as a total order, so the
cadence is exactly `W` under lag 0 and lag 1 alike — and it spends the margin
spec:5844 pins it for, against a failure mode (`not-final`) that costs a whole
window each time it fires.

### 5.12 DISC-D8 — shrink class 0's carrier object — **KILL**

Worth 0.10 s today and ~0 after the store fix, in exchange for less padding in
the class that carries every real operation in every recorded run. §3a item 3
("size and count are visible; the fixed schedule pads both") is the only thing
standing between a real object and its length; do not spend it for zero.

---

## 6. The reproducibility ledger

What each surviving change costs in re-measurement. Anything in this list that
is not re-run before the docs are edited is a doc that has stopped matching the
build.

| Change | Recorded artifact that dies |
|---|---|
| SCAN-C1/C2 (store codec) | outward §6's entire cohort table and its causal paragraph; outward §4's four scenario times; `observed.md` §3/§4c/§4d wholesale; the "per flight 8.0 s = 2 windows" column |
| SCHED-C1 (late slots) | profile hash `83a2261e…` everywhere it is quoted; outward §3 and design §5 offset columns; design §3a item 1's derivation; **outward §6's `1000 / cohort 2 → 10.5 s` row, which measured a FAIL under this profile**; outward §8's `P2PARTY_STORE_WINDOW_MS` "rescales" line |
| SHRINK-C1 (carrier 8,448) | design §5 "Each append carries 8,192 or 73,728 ciphertext bytes"; outward §6's scan-byte column; outward §8 and §9 and design §9's 2,763,134 B/window and 59.7 GB/day retention numbers (they fall ~4.1×) |
| SHRINK-C4 (`pcoc` 24) | outward §3 and design §5's "thirteen fixed requests" → ten; both chunk-read rows |
| SCHED-C4 (second slot) | the same tables → fourteen; scan bytes +4.8 % |
| Any of them | **outward §5's audit corpus counts.** A 22 s run has roughly half the request bodies of a 41.9 s run, so "0 of 148 needles in 345 bodies" becomes "0 of 148 in ~180". The audit's strength is partly its corpus size; the new numbers must be recorded, not carried over. |

And one that is not a doc: the **`--cohort=8` rebuild check**. Outward §6 says
"At the pinned cohort of 8 the rebuilt profile hashes byte-identical to the
pinned literal, which is the check that the rebuild is faithful." That check
survives any profile edit — but only if the literal and the rebuild are changed
together in one commit. Splitting them across two commits leaves a window in
which the harness's own faithfulness check is comparing a new literal against an
old rebuild.

---

## 7. The order this implies

Not a plan — the ordering that the honesty constraints force, which happens to
agree with four of the six angles:

1. **SCAN-C2** (25 lines, one file, zero disclosure) — because until it lands
   every other measurement is measuring a hand-rolled hex decoder, and because
   it is the only change that *removes* a dependency rather than adding one.
2. **Rewrite outward §6** with the sentence in §3.1 and re-measure the cohort
   table. Do this before anything else touches the profile, so there is one
   clean post-fix baseline that every later change is measured against.
3. **COL-C5** (ingest fixpoint, 10 lines, zero disclosure).
4. **SCHED-C1**, with the rescale rule of §4.1 and the doc edits it forces.
   Verify `carrierRuntime.test.ts:1438-1446` stays green untouched — that test
   is the honesty guard and a green run is the evidence the §3a item 1 numbers
   still hold.
5. **§3a item 15 (first-window shape)** — owed today, independent of any
   candidate, and a precondition for SCHED-C2.
6. Then the ones with real disclosures, one per commit with its disclosure in
   the same commit: DISC-D5 (+ the fault-masking guard and the `--stagger-ms`
   run that justifies it), COL-C1 (+ PROD-C7), SCHED-C2, SHRINK-C1 (+ the three
   gates of §4.10).

---

## 8. What I could not check, and what would settle it

- **The staggered-start deadlock.** Two angles assert it, both from code
  reading, neither ran it. It is load-bearing for DISC-D5 and for the framing
  of the whole exercise. `--stagger-ms` is ~60 LOC. Until it fails on the
  current code, do not write the claim down.
- **`S` on anything but this laptop.** Every candidate that turns on `M = 0`
  turns on a step function of `S` measured once, headless, on loopback, with
  both stores in the same process tree. There is no distribution and no tail.
- **A second browser engine.** Every SDP number, every class-selection
  argument, and every synthesis/munging candidate is Chromium-only.
  spec:10394-10396 asks for the full matrix and it has never been run.
- **A real class-1 object.** Nobody has ever observed one. `angle-shrink-class-1`
  §1.4 proves class 1 is unused by making it unreachable and watching the run
  pass, which is good evidence and not a measurement of the published class.
  One harness assertion turns it into one.
- **Whether the store fix changes the fault scenarios' detection latency.**
  `withhold-a`'s custody-breach detection is quoted as "one delivery window"
  and should still be one; nothing I read checks that a much faster store does
  not shorten or lengthen it. Re-run `--scenario=all` and re-read the 7.7–7.8 s
  drop to `single-carrier-dependent`.
