# Angle: shrink size class 1 so the delivery window can shrink

Measured 2026-09-08 against `feat/blind-two-store-prototype` @ `127ca95`.
macOS 25.6.0 / arm64, headless Chromium, `bun 1.3.14`, `node v24.11.1`.
Anchored throughout to `floor.md` and `observed.md` beside this file.

**The real repository was never modified.** A sibling agent was editing
`src/blindRendezvous/prototype/profile.ts` in the working tree while I ran, so
every experiment below ran in an isolated `rsync` copy at
`scratchpad/wt`, seeded from `git show HEAD:` for the three files I touch and
with `node_modules` symlinked. `git status` and the `md5` of
`src/blindRendezvous/schemas.ts` (`8f75190f…`) and
`docs/e2e/blind-two-store/run.mjs` (`398e9a61…`) are unchanged from session
start. Ports 6100/6101 and 6120, above 5000, and away from the harness
defaults so a concurrent sibling run could not collide.

---

## 0. The result, first

**One line of `PROTOTYPE_DELIVERY_PROFILE_V0` takes the rendezvous from
35–42 s to 22 s at the pinned 4,000 ms window, and makes the 2,000 ms window —
which today stalls outright — complete in 11.1 s. Three lines more take
1,000 ms to 7.5 s with all four fault scenarios passing.** The cohort stays at
the pinned 8. Nothing about the anonymity set, the request shape, the schedule,
or cover/real indistinguishability changes.

Every row below is a real `run.mjs` run in the isolated copy, cohort 8 pinned:

| class-1 carrier object | scan B/store/window | W=4000 | W=2000 | W=1000 | W=750 | W=500 |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **73,728 (pinned)** | 1,380,336 | 34.6 s *(README 39.9/41.9; observed.md 35.5/38.7/40.4)* | **stalls** *(README)* | — | — | — |
| 37,120 | 794,608 | 30.9 / 27.6 | 20.5 / 17.2 | — | — | — |
| 16,640 | 466,928 | 24.8 | 16.8 | 9.2 | — | — |
| **8,448** | 335,856 | **24.3 / 22.0 / 23.3 / 22.1** | **11.6 / 11.1 / 11.1** | 7.2 / 9.1 | 7.2 / 6.7 | FAIL |
| 8,448 + `publicChunkObjectCount` 24 | 404,256 | — | — | **6.4** | — | FAIL |
| 4,352 *(pure-cover floor)* | 270,320 | 23.9 | — | — | — | — |

Four-scenario suites (`--scenario=all`) at carrier 8,448:

| geometry | healthy | kill-a | withhold-a | unreachable-b-for-one | verdict |
| --- | ---: | ---: | ---: | ---: | --- |
| W=4000 | 23.7 s | 23.6 s | 23.4 s | 23.5 s | **4/4 PASS** |
| W=2000 | 11.4 s | 11.6 s | 11.5 s | 11.5 s | **4/4 PASS** |
| W=1000 | 9.0 s | 10.4 s | 5.5 s | 7.6 s | 3/4 — see §6.3 |
| W=1000 + `publicChunkObjectCount` 24 | 9.4 s | 7.5 s | 7.5 s | 7.5 s | **4/4 PASS** |

Compare the recorded prototype: `healthy` 41.9 s, `kill-a` 35.2 s
(`docs/e2e/blind-two-store/README.md:357-430`). **4.7× at 4/4 scenarios.**

---

## 1. What I measured, and where the brief's premise is wrong

The brief says class 1 "sizes the class to the spec's largest pair payload,
which is driven by the 32,768-byte SDP ceiling (spec §4.12)". **That is not
what sizes it, and the correction is most of the argument.**

### 1.1 Real complete-ICE SDP — measured, not guessed

Headless Chromium, one `m=application` line, data channel created before
`createOffer`, waited to `iceGatheringState === "complete"`, `localDescription.sdp`
read verbatim — exactly `webrtcProvider.ts`'s contract
(`scratchpad/latency/sdpprobe.mjs`):

| launch args | `rtcConfig` | offer | answer | candidates |
| --- | --- | ---: | ---: | ---: |
| `--disable-features=WebRtcHideLocalIpsWithMdns` **(the harness)** | `{iceServers: []}` | **692 B** | 691 B | 2 |
| the harness | 1 STUN | **1,002 B** | 691 B | 4 / 2 |
| the harness | 2 STUN + 3 TURN URLs (unresolvable) | 1,001 B | 691 B | 4 / 2 |
| Chromium default (mDNS on) | `{iceServers: []}` | 715 B | 714 B | 2 |
| Chromium default (mDNS on) | 1 STUN | 986 B | 986 B | 4 |

**≈155 bytes per additional ICE candidate.** This is precisely the measurement
spec §4.12 demands and has never been done: *"Phase 0 must measure complete
offer/answer sizes across the supported browser, ICE, TURN, IPv4/IPv6, and
network matrix and freeze successful boundary vectors"* (spec:10394-10396).

### 1.2 The plaintext arithmetic (measured from the canonical schemas)

`scratchpad/latency/classprobe.ts` encodes real `PairPlaintextV1` values:

```
offer  plaintext bytes = 404 + len(SDP)
answer plaintext bytes = 431 + len(SDP)

established envelope overhead 63 B   AEAD tag 16 B   (pairStepEnvelope.ts)
class-0 established plaintext target 4,017 B     ciphertext+tag 4,033 B
class-1 established plaintext target = CLASS1 − 79
```

⇒ **class 0 alone already holds an SDP up to 3,613 B (offer) / 3,586 B
(answer)** — about **21 ICE candidates**. The measured harness SDP is 692 B and
the measured STUN SDP is 1,002 B, so **every transport flight in every recorded
run is class 0 and rides the 1,700 ms slot.** `floor.md` §3 says this and is
right; `observed.md`'s `budget.mjs` attributes the transport flights to the
1,500 ms class-1 slot and is **wrong** — that reconstruction mapped
`safety-control` to the class-1 schedule without checking the class. It does not
change any of `observed.md`'s conclusions (the budgets it quotes for 1,500 ms
and 1,700 ms differ by 200 ms), but it should be corrected before anyone quotes
it.

### 1.3 What actually sizes class 1: `PQ_CONTROL`, not SDP

`scratchpad/latency/sizeprobe.ts` encodes every `PairStepBodyV1` variant at its
schema maximum:

| body at maximum | plaintext | minimum `OPERATION_PAYLOAD_CLASS_BYTES[1]` |
| --- | ---: | ---: |
| `V4_HANDSHAKE` (3,329 B) | 3,515 | 3,594 — *fits class 0* |
| `TRANSPORT_ANSWER` @ SDP 32,768 | 33,199 | 33,278 |
| `TRANSPORT_OFFER` @ SDP 32,768 + local-link 2,048 | 35,229 | 35,308 |
| **`PQ_CONTROL` — `fixedBytes(WIRE_CHUNK_FRAME_LEN=65,490)`** | **65,672** | **65,751** |

The pinned 69,632 has 3,881 B of slack over `PQ_CONTROL`. **The 32,768-byte SDP
ceiling needs only 36 KiB; the other 33 KiB is one complete protocol-v4 chunk
frame carried as a pair step.** That is the PQ re-key control path over the
mandatory `operation-carrier` (spec:10693-10706) — a *post-promotion, established
session* path that the prototype does not implement at all: `PQ_CONTROL` and
`V4_HANDSHAKE` appear nowhere under `src/blindRendezvous/prototype/`.

### 1.4 Class 1 carries no real object — proved by running it

Analytically it follows from §1.2. Empirically I set
`OPERATION_PAYLOAD_CLASS_BYTES[1] = 4,097` — one byte above class 0, so class 1
is unreachable by any plaintext the pair codec can build — rebuilt, and ran:

```
SCENARIO healthy PASS in 23.9s   scan 270320 B/store/window
counters A={"appendsReal":8,"appendsDummy":52,"scans":12,"operationsSeen":6}
```

**Class 1 is 100 % cover in this prototype, at 85.6 % of the scan and 85.6 % of
the appended bytes.**

### 1.5 The carrier-sizing chain, measured

`scratchpad/latency/opsize.ts`:

```
encoded AuthenticatedRoomOperationV1 = OPERATION_PAYLOAD_CLASS_BYTES[c] + 231
carrierPlaintext framing (empty)     = 8     carrier AEAD tag = 16
⇒ fixedCarrierObjectBytes  >=  OPERATION_PAYLOAD_CLASS_BYTES[c] + 255
   carrierObjectWireBytes   =  fixedCarrierObjectBytes + 102
pinned:  class 0  8,192 >= 4,351 (slack 3,841)   class 1  73,728 >= 69,887 (slack 3,841)
```

`varBytes` always writes a `u32be` length prefix regardless of its declared
bound (`canonicalSchema.ts:392-398`), so **shrinking `MAX_OPERATION_PAYLOAD_BYTES`
does not move the 231 B or the 63 B overheads.** The arithmetic is stable under
the change; nothing re-derives.

### 1.6 The scan cost mechanism — the brief's second premise is also wrong

The brief asks me to "derive it from the measured per-byte AEAD cost". I did,
and the answer is that **AEAD is never the constraint, by a factor of ~40.**
`observed.md` §4b measured the *entire* per-window decode + trial-open of all 40
objects at **4.0 ms per store, 8 ms for both** — 2.9 ns/B, 345 MB/s. At the
shrunken geometry that is **1.95 ms for both stores**, against a reply budget of
`0.175 × W`, i.e. a window floor from AEAD alone of **11 ms**.

The real cost is the store's `storeSqlite.loadWindow`, which `JSON.parse`s the
entire hex-encoded window document on every single chunk GET
(`observed.md` §4e). It is linear in the window's byte count, which is exactly
what class 1 dominates. Three measured points:

| window document | per chunk GET | source |
| ---: | ---: | --- |
| 1,380,336 B (pinned) | **97 ms** | `observed.md` §4d |
| 656,992 B (cohort 2) | **47 ms** | `observed.md` §4d |
| **335,856 B (carrier 8,448)** | **15.5–16.8 ms** | **measured here** |

My store probe at carrier 8,448 (one store, no browser, `curl`):

```
sequential, cold:  class0 chunks 16.8 / 15.5 / 16.0 ms   class1 chunks 15.7 / 15.6 ms
one client's whole 5-chunk scan of one store:   118 ms   (pinned: 519 ms)
ten requests, i.e. two clients scanning at once: 198 ms   (pinned: ~970 ms)
sqlite window state blob:                   674,174 B   (pinned: 2,763,134 B)
```

The last row is the mechanism in one number: **the window document shrank
4.10× and the per-request cost shrank 6.1×** (better than linear — a smaller
document parses faster per byte, so linear extrapolation is conservative).

---

## 2. How small can class 1 be?

### 2.1 The smallest that still fits a real WebRTC offer and answer

```
SDP fits class 1  ⟺  431 + len(SDP)  ≤  CLASS1 − 79
                  ⟺  len(SDP)        ≤  CLASS1 − 510
```

| `CLASS1` | carrier | wire | max SDP (offer / answer) | ICE candidates that fits | vs. measured 1,002 B |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 69,632 (pinned) | 73,728 | 73,830 | 69,149 / 69,122 | ≫ 400 | 69× |
| 36,864 | 37,120 | 37,222 | 36,381 / 36,354 | ≈ 233 | 36× |
| 16,384 | 16,640 | 16,742 | 15,901 / 15,874 | ≈ 100 | 16× |
| **8,192** | **8,448** | **8,550** | **7,709 / 7,682** | **≈ 47** | **7.7×** |
| 4,097 | 4,352 | 4,454 | 3,614 / 3,587 | ≈ 21 (= class 0) | 3.6× |

**8,192 is the answer to "smallest with headroom."** Class 0 already covers
21 candidates; 8,192 covers 47. To reach 47 candidates on one
`m=application` line you need roughly twelve network interfaces with both
address families plus a full relay set — a machine, not a browser tab. The
measured worst case here (STUN, 4 candidates, 1,002 B) has **7.7× headroom**,
and the class-0/class-1 boundary is untouched, so nothing about *which* class a
flight picks changes.

### 2.2 The window floor, derived and then verified

Three independent limits, each with a measured crossover.

**(a) One window per flight.** A reply must be enqueued between the read
(`publicReadOffsetMs` = 0.15 W) and the earliest append slot (1,300 ms = 0.325 W),
so the budget is **0.175 W**, and what must fit in it is the store serving *two*
clients' scans:

```
storeService(2 clients) = 2 × chunksPerStore × perChunkMs  <  0.175 W
pinned            10 × 97 ms = 970 ms   ⇒  W > 5,543 ms   (so even 4,000 misses — as observed)
carrier 8,448     10 × 16 ms = 160 ms   ⇒  W > 1,131 ms   (measured 198 ms concurrent ⇒ W > 1,131)
+ pcoc 24          4 × 19 ms =  76 ms   ⇒  W >   434 ms
```

Verified: at 8,448, W=2,000 lands exactly on the structural floor (11.1–11.6 s
against `floor.md`'s `12.3 − p`), W=1,000 is marginal (7.2 s and 9.1 s — some
flights still take two windows), and with `pcoc` 24, W=1,000 hits the floor
(6.4 s against `6.15 − p`).

**(b) The stall limit.** Everything — 2 scans, 10 appends, 2 allocations — must
be served before `chunkFinalizationOffsetMs` = 0.7 W, or appends answer
`window-finalized` and the run dies. Pinned: fails at W=2,000, works at 4,000
(README). At 8,448: **fails at W=500** (`append window-finalized`, measured),
**works at W=750** (6.7–7.2 s). With `pcoc` 24 it still fails at 500 and 400 —
below ~750 ms the *append* write, not the chunk read, dominates, and no amount
of further shrinking helps. **That is the boundary of this angle.**

**(c) `requestDeadlineMs = deliveryWindowMs`** (`storeClient.ts:276-283`). At
W=1,000 under `kill-a` the *surviving* store misses the 1,000 ms deadline on
appends; see §6.3.

### 2.3 The measured refutation of the brief's window-shrink premise

The brief says a previous `--window-ms=2000` attempt "failed because the browser
could not finish the per-window AEAD in the remaining slack." **It failed
because the store could not finish `JSON.parse` in the remaining slack.**
With the same cohort, the same window, the same browser and the same AEAD —
only the class-1 object smaller — `--window-ms=2000` now completes all four
scenarios in 11.4–11.6 s.

---

## 3. The candidates

### C1 — Shrink the class-1 **carrier object** only (one line, no codec change)

**Mechanism.** In `PROTOTYPE_DELIVERY_PROFILE_V0`
(`src/blindRendezvous/prototype/profile.ts:116`):
`fixedCarrierObjectBytes: 73_728` → `8_448`. Leave
`OPERATION_PAYLOAD_CLASS_BYTES = { 0: 4096, 1: 69632 }` completely alone. The
class-1 chunk stream keeps its two append slots, its two chunks per window and
its role coverage; only the object is smaller. Class-1 objects are cover in
every run (§1.4), so nothing real ever needs to fit.

**Saving.** Measured, cohort 8, `healthy`: 34.6 s → **22.1 s** at W=4,000
(−36 %), and W=2,000 goes from *stalling* to **11.1 s**. In windows: every
flight goes from 2 windows to 1, i.e. **5 windows saved** out of 11
(`floor.md` §5 charged 16.0 s to exactly this). Scan 1,380,336 → 335,856 B
(4.11×); appended bytes 172,542 → 41,982 B/store/window (4.11×) — that second
number is the sustained *uplink* of an idle client and drops from 690 kbit/s to
168 kbit/s per store.

**Privacy cost, in the design doc's vocabulary.** §3a item **3** ("Size and
count are visible; the fixed schedule pads both") — the size changes and stays
fixed and identical for every client on the grid. §5's table changes one
sentence: "Each append carries 8,192 or 73,728 ciphertext bytes" → "8,192 or
8,448". §3a item **4** (polling shape) untouched: same 13 fixed requests, same
routes, same offsets, same conditional witness pair. The anonymity set is
`cohortAllocationsPerWindow` = 8 and does not move — **this is the whole point
of the candidate: it buys the latency the cohort knob buys, without paying the
cohort knob's price.** Cover/real indistinguishability is untouched: a real and
a dummy class-1 object are still the same bytes at the same instant.
**No new leak, no widened leak.** One thing genuinely *narrows*: spec:9836
discloses that "class 1 identifies the large-body pair family"; under C1 that
family is provably empty, so the store learns strictly less from it than the
spec permits.

**Spec deviation — yes, and it is the sharp one.**
`validateDeliveryProfileGeometry` does **not** check it (spec:3234 only requires
`fixedCarrierObjectBytes > 0`), so this passes silently. But
`RoomProfileCompatible` at **spec:4605-4607** requires "each operation payload
class permitted by `roomPolicy.operationCodec` maps to exactly one profile size
class whose `fixedCarrierObjectBytes` fit the exact canonical operation, carrier
framing, padding, and tag". 8,448 < 69,887, so **payload class 1 has no usable
size class**. Named deviation under **spec:3392** ("Implementations may
prototype behind internal flags"). Consequence to disclose: a pair step that the
codec routes to class 1 — SDP > 3,613 B — throws in `buildCarrierPlaintext`
(`carrierEnvelope.ts:156`) and fails the edge. That fires for an offer with
more than ~21 ICE candidates; measured SDP is 692–1,002 B (2–4 candidates).

**Implementation cost.** **1 line** of source. Plus: 3 numbers in
`docs/blind-rendezvous-two-store-prototype-design.md` (`:270`, `:585`), the
recorded runs and cohort table in `docs/e2e/blind-two-store/README.md` and
`docs/blind-rendezvous-two-store-prototype.md`, and a new §3a/§2 line naming the
deviation. **~1 + ~25 doc lines.** No test changes (no test pins 73,830).
I also recommend **+3 lines in `validateDeliveryProfileGeometry`** asserting
`fixedCarrierObjectBytes >= OPERATION_PAYLOAD_CLASS_BYTES[c] + 255`, so the
incompatibility is *stated* rather than silent — with the prototype's deviation
as an explicit allow.

**How to measure it worked.** `run.mjs --scenario=all --window-ms=4000` must
report 4/4 with per-flight legs of ~4.0 s (not ~8.0 s) in the per-phase table;
`profileTool info` must print `scannedBytesPerWindow: 335856`; the `counters`
line must still show `appendsReal` unchanged (8) and `store-missed` limited to
the two cold-start `unallocated-cover` lines; the privacy audit must still find
0 of 148 needles. Then repeat at `--window-ms=2000`, which must go from stall to
pass.

---

### C2 — Also shrink the class-1 **payload class** to 8,192 (restores conformance)

**Mechanism.** C1, plus `src/blindRendezvous/schemas.ts:48`:
`OPERATION_PAYLOAD_CLASS_BYTES = Object.freeze({ 0: 4096, 1: 8192 })`.
Now 8,448 ≥ 8,192 + 255 and **spec:4605-4607 holds again**. The class-1
plaintext target becomes 8,113, so an offer with SDP up to 7,709 B (≈47 ICE
candidates) rides class 1 normally instead of failing.

**Saving.** Identical to C1 — measured 24.3 / 22.0 / 23.3 s at W=4,000 and
11.6 / 11.1 s at W=2,000, statistically indistinguishable from C1's 22.1 /
11.1 s. **The latency is entirely bought by the carrier size; the codec change
buys only headroom.** That separation is the most useful thing in this report.

**Privacy cost.** Same as C1, and strictly better on one axis: the class-1
family is now *reachable* again, so the design keeps the property spec:9836
already discloses rather than emptying it. No new leak, no widened leak.

**Spec deviation.** Changes the frozen class table at **spec:6424** and its
projection at **spec:6433**; consequentially invalidates the derived numbers at
**spec:9731** (`MAX_PAIR_PADDING_BYTES_V1` = 69,553 − 4,018 = 65,535 — the bound
stays valid as an upper bound, the *derivation* does not), **spec:9783**
(class-1 established targets 69,569 / 69,553), and the Phase-0 vector list at
**spec:12289**. It also lowers the §4.12 SDP ceiling from 32,768 to 7,709 —
**spec:10389-10390**, and spec:10399 says plainly "Raising the limit changes the
pair/class codec and profile", which is symmetric. Permitted for a prototype by
**spec:3392**; it is a real codec deviation and must be named as one.

**Implementation cost.** 2 source lines (schemas + profile), plus the doc
comment at `schemas.ts:66-73`. Tests: `projections.test.ts:248` (1),
`pairOpenBudget.test.ts` (8 sites), `pairPlaintextVectors.test.ts:315-320`
(3 fields including **one recomputed SHA-256 conformance vector**), and
`tests/blindRendezvous/reference/pair_plaintext_vectors.py:283,344,363`
(4 constants — the independent cross-language check must move in lockstep).
**~2 + ~20 lines + 1 regenerated vector**, plus the same doc set as C1. The
vector is the real cost: it is a conformance artifact, not a test fixture.

**How to measure.** Everything in C1, plus `bun test tests/blindRendezvous` green
and the Python reference reproducing the new `sha256` byte-for-byte, plus an
added harness assertion that the transport flight's `operationPayloadClass` is
what the SDP size predicts (today the class flip is silent — `floor.md` §11
asks for this too).

---

### C3 — Conservative sizing: class 1 = 36,864, carrier 37,120

**Mechanism.** As C2 with different literals. Chosen so the *complete* offer at
the spec's own 32,768-byte SDP ceiling with all three candidates (35,229 B
plaintext, §1.3) still fits: 36,864 − 79 = 36,785 ≥ 35,229. **The §4.12 SDP
ceiling at spec:10389-10390 is preserved exactly.** Only `PQ_CONTROL` is
evicted.

**Saving.** Measured: W=4,000 → 30.9 / 27.6 s (−20 %); W=2,000 → 20.5 / 17.2 s
(from *stalling*). It does **not** reach the one-window-per-flight floor at
W=4,000: 794,608 B still costs ~56 ms/chunk, i.e. ~560 ms of store service
against a 700 ms budget, so flights are mixed 1- and 2-window. Roughly **2 of
the 5 slipped windows recovered**, versus 5 of 5 for C1/C2.

**Privacy cost.** Identical to C2. No new leak.

**Spec deviation.** spec:6424 / 6433 / 9731 / 9783 / 12289 as C2, but **not**
spec:10389 — the SDP ceiling is intact, and the only lost capability is
`PQ_CONTROL` over the operation carrier (spec:9716, 10693-10706).

**Implementation cost.** Identical to C2.

**How to measure.** Same as C2, plus an explicit negative test that a
65,490-byte `PQ_CONTROL` body is refused with a clear error rather than a
canonical-encoding failure.

---

### C4 — Fewer, fatter chunks: `publicChunkObjectCount` 8 → 24

**Mechanism.** A pure profile change, no codec involvement.
`publicChunkObjectCount: 8` → `24`, and the two `publicChunksPerWindow` literals
`3` and `2` → `1` and `1` (the validator recomputes
`ceil(cohort × slots × appendSchedule.length / publicChunkObjectCount)` and
rejects a literal that disagrees, so both must move together). Class 0 packs
exactly (24 scheduled objects = 24 capacity); class 1 wastes 8 slots of the
24 (16 scheduled). **The store's cost is `requests × O(document)`, and this
attacks the first factor**: 5 chunk GETs per store per window become 2.

**Saving.** Only worth it *after* C1/C2. Measured with carrier 8,448:
W=1,000 goes from **7.2 / 9.1 s** to **6.4 s** (the structural floor), and the
four-scenario suite at W=1,000 goes from **3/4** to **4/4 PASS** at
7.5–9.4 s — including `kill-a`, which C1 alone fails (§6.3). Store service per
window drops from 10 × 16 ms to 4 × 19 ms.

**Cost, stated honestly.** Scan bytes go **up**: 335,856 → 404,256
(+20.3 %), because 8 of the 24 class-1 slots per chunk are unscheduled cover.
Appended bytes are unchanged (41,982). It is a byte-for-request trade and only
pays while the store's per-request cost is `O(whole window document)`; after
`observed.md`'s candidate 1 (fix `loadWindow`) it becomes a pure 20 % byte loss
and should be reverted.

**Privacy cost.** §5's fixed-request table changes from **thirteen fixed
requests to ten** (5 chunk GETs → 2). Both numbers are fixed, uniform, and
disclosed; §3a items 3 and 4 hold unchanged. If anything it slightly *reduces*
the surface for §3a item 2 (source addresses; fewer request/response pairs per
window for a store to correlate against its own log). **No new leak.**

**Spec deviation.** None. `publicChunkObjectCount` is a profile field; the
minimum-chunks inequality at **spec:5781-5791** is satisfied and is recomputed
by `validateDeliveryProfileGeometry` (`profile.ts:322-331`). It **is** a
measurable traffic increase and must be reported as one, exactly as
`floor.md` §10 item 3 reports the second-slot option.

**Implementation cost.** **3 lines** in `profile.ts` (`:92`, `:112`, `:122`),
plus the §5 request table and the two README tables. ~3 + ~15 doc lines.

**How to measure.** `profileTool info` must print `publicChunksPerWindow: 1`
for both classes and `scannedBytesPerWindow: 404256`; the harness's
`requests issued by page` line must drop by 3 per store per window; the
four-scenario suite at W=1,000 must be 4/4.

---

### C5 — Implement the §4.12 operation-carrier fallback so the SDP cliff fails soft

**Mechanism.** Spec:10396-10398 already prescribes it: *"A client whose complete
local SDP exceeds it omits WebRTC and offers the mandatory operation carrier; a
responder gathers before selection and does likewise."* Today
`buildOfferCandidates` (`transportCandidates.ts:135-146`) always includes
`webrtc-complete` and `selectWebRtcCandidate` (`:183-187`) fails when there is
none, so an oversized SDP throws in `sendOffer`
(`pairDriver.ts:1549-1556`) and calls `failEdge`. Minimum version: compute the
padded plaintext class *before* committing, and if the offer would not fit the
profile's class-1 carrier, emit an offer holding only `operation-carrier` and
surface a typed "no WebRTC path on this network" outcome instead of a dead edge.

**Saving.** Zero latency. It is the *insurance* on C1/C2/C3 — it converts the
cliff those candidates create from "the rendezvous silently dies" into "the
rendezvous completes control-plane-only and says so".

**How often would it fire?** With C2 (7,709 B ceiling): an offer needs ≈47 ICE
candidates. Measured: 2 candidates on loopback, 4 with one STUN server. Even a
laptop with Wi-Fi + Ethernet + two VPN interfaces on both address families plus
a full UDP/TCP/TLS relay set reaches ~16 candidates ≈ 2.9 KB, which is still
**class 0**. I would expect it to fire approximately never for a
data-channel-only connection, and I would not ship C2 without it anyway, because
"approximately never" is not a number I measured — it is an extrapolation from
155 B/candidate.

**Privacy cost.** None to a store: the offer is inside the pair-encrypted,
class-padded payload, so the store cannot see which candidates it holds. There
*is* a peer-visible signal — "this endpoint could not offer WebRTC" is one bit
about the other endpoint's network — but that bit exists in the spec by design
and is not a store-facing leak. Worth one sentence in §2 ("what this is not"),
not a §3a item.

**Implementation cost.** Cheap version (offer carrier-only, fail with a typed
result instead of `failEdge`): ~40 LOC across `transportCandidates.ts` and
`pairDriver.ts`, plus a test. Full version (actually running the v4 handshake
over pair steps) is a different project — and note it needs class 1 back at
65,751 B for `PQ_CONTROL`, which is exactly the tension C2/C3 create.

---

### C6 — *(measured and rejected)* shrink to the pure-cover floor, class 1 = 4,097

Ran it (§1.4): 23.9 s at W=4,000, scan 270,320 B. **It is not faster than
8,448** — at W=4,000 both sit on the structural floor, so the extra 20 % of scan
reduction buys nothing. It also deletes the large-body class outright, which
would make spec:9836 vacuous and leave no room at all above SDP 3,613. Recorded
here only as the experiment that *proves* class 1 is pure cover.

---

## 4. Ranking by saving-per-risk

| rank | candidate | saving | risk | why |
| ---: | --- | --- | --- | --- |
| **1** | **C1** carrier → 8,448 | 34.6 → 22.1 s; 2,000 ms window from stall → 11.1 s; 4.11× scan and uplink | **low** | one line; no codec, no vectors, no tests; the only loss is a class that is provably empty. The deviation (spec:4605) is sharp and easy to state. |
| **2** | **C4** `pcoc` 8 → 24 | 3/4 → **4/4** at W=1,000; 7.2/9.1 → 6.4 s | **low** | three lines, no deviation at all; costs +20 % scan bytes, which must be reported |
| **3** | **C2** class → 8,192 | same latency as C1, plus 7.7× SDP headroom and spec:4605 conformance restored | **medium** | touches the frozen class table and a cross-language conformance vector |
| **4** | **C5** §4.12 fallback | none | **medium** | no privacy cost, but it is protocol work, and it is the honest prerequisite for shipping C2/C3 |
| **5** | **C3** class → 36,864 | 34.6 → ~29 s only; does not reach the floor | **medium** | same deviation cost as C2 for less than half the saving; its one virtue is preserving spec:10389 |

Ship **C1 + C4** first: four lines, no codec deviation, no vector change,
4/4 scenarios, **35–42 s → 7.5 s at W=1,000** or a conservative **11.5 s at
W=2,000**. Then decide C2 vs C3 vs C5 as a design question about how much pair
payload the product actually wants.

---

## 5. Where this sits against the other levers

`observed.md` §7 item 1 — fix `storeSqlite.loadWindow` so a chunk GET reads one
row instead of `JSON.parse`ing the whole window — is **strictly better than
everything above**, costs nothing in privacy, changes no byte on the wire, and
should be done first. My candidates and that one are not additive in the way
they look: once the store is O(1) per chunk, C1's latency win largely evaporates
at W=4,000, because both land on the same structural floor.

**What survives the store fix, and is the reason to do C1 anyway:**

- **Bandwidth.** The scan is a real download: 2 × 1,380,336 B every 4,000 ms is
  **5.5 Mbit/s sustained, per idle client, forever**. C1 makes it 1.3 Mbit/s.
  On mobile that is the difference between shippable and not, and no store fix
  touches it.
- **Uplink.** 172,542 B × 2 stores per window is **690 kbit/s of sustained
  upload from a client that is doing nothing.** C1 makes it 168 kbit/s.
- **Short windows on a real network.** `requestDeadlineMs = deliveryWindowMs`;
  at W=1,000 a 591 KB class-1 chunk needs ~5 Mbit/s just to arrive in time. At
  8,550 B/object the chunks are 68 KB.
- **Disk.** 2,763,134 → 674,174 B per window per store (measured), i.e. the
  store's retention cost drops 4.1× at the same `carrierRetentionWindows`.

So the honest framing is: **the store fix buys the latency; C1 buys the
latency *and* the bandwidth, and C1 is one line.**

---

## 6. Being skeptical of my own best idea

### 6.1 What would make me drop C1/C2 outright

**If the maintainer intends the `operation-carrier` data path to be real.**
Class 1 exists for `PQ_CONTROL` (§1.3) — one complete 65,490-byte protocol-v4
chunk frame carried as a pair step. That is the PQ re-key path for an
established pair that has *lost* its WebRTC channel. If the roadmap says a pair
must survive a NAT change without re-rendezvousing, class 1 must stay ≥ 65,751
and this entire angle collapses to C4 plus the store fix. **This is the one
question I would put to the maintainer before writing any code.** Nothing I
measured settles it, because the prototype implements none of it.

### 6.2 What would make me drop C1 in favour of C2

C1 leaves `RoomProfileCompatible` (spec:4605-4607) false. It is one line and it
is fast, but it ships a profile whose validator cannot express what is wrong
with it. If the answer to §6.1 is "no, `PQ_CONTROL` over the carrier is out of
scope", then C2 is the honest version and the extra cost is one conformance
vector.

### 6.3 The failure C1 does not fix, measured

At W=1,000 with C1 alone, `--scenario=all` is **3/4**. `kill-a` completes the
rendezvous in 10.4 s but the harness fails it on a sharp assertion
(`run.mjs:846-859`, "the honest store b must produce nothing at all"): the
*surviving* store filed three `unreachable` faults reading
`"/append: no answer within the 1000 ms request deadline"`. That is
`requestDeadlineMs = deliveryWindowMs` (`storeClient.ts:276-283`) biting when
one store carries the whole load. C4 fixes it in this measurement (4/4 at
W=1,000), but the coupling is structural and is a third, independent floor on
how short the window may go. **Do not quote a 1,000 ms window without the
`--scenario=all` run.**

### 6.4 Three things that would change my numbers

- **These are loopback numbers on one laptop running two Chromium contexts and
  two `bun` stores at once.** The README says so about its own table and it is
  equally true here. On a real network the store's parse is joined by real RTTs
  and real bandwidth, and the bandwidth argument in §5 gets *stronger* while the
  latency argument gets weaker.
- **The 155 B/ICE-candidate figure is Chromium-only.** Firefox and Safari emit
  different SDP shapes; spec:10394 asks for the full browser × ICE × TURN ×
  IPv4/IPv6 matrix and I measured one browser. If some browser's data-channel
  SDP is 4 KB rather than 700 B, class 0 stops covering it and the class-1
  ceiling starts mattering for real.
- **I never observed a real class-1 object.** Every claim that class 1 is cover
  rests on the class-selection arithmetic plus five harness runs. A harness
  assertion on the published `operationPayloadClass` would turn that inference
  into a measurement; it is one line and both `floor.md` §11 and I want it.

---

## 7. Reproduction

```bash
WT=<scratchpad>/wt          # rsync copy, node_modules symlinked, sources from git HEAD

# C1 (one line):   profile.ts class-1  fixedCarrierObjectBytes: 73_728 -> 8_448
# C2 (one more):   schemas.ts:48       OPERATION_PAYLOAD_CLASS_BYTES { 0: 4096, 1: 8192 }
# C4 (three):      profile.ts          publicChunkObjectCount 8 -> 24, both publicChunksPerWindow -> 1
bash $WT/docs/e2e/blind-two-store/build.sh
cd $WT && bun run docs/e2e/blind-two-store/profileTool.ts info --window-ms=4000
PLAYWRIGHT_BROWSERS_PATH=~/Library/Caches/ms-playwright \
  node docs/e2e/blind-two-store/run.mjs --scenario=all --window-ms=2000 \
    --store-port-base=6100 --page-port=6120
```

| file | what it is |
| --- | --- |
| `sdpprobe.mjs` | the §1.1 SDP matrix in headless Chromium |
| `classprobe.ts` | offer/answer plaintext vs. SDP length; the exact class-0 flip points |
| `sizeprobe.ts` | every `PairStepBodyV1` variant at its maximum; what really sizes class 1 |
| `opsize.ts` | the operation/carrier framing chain (231 / 8 / 16 / 102) |
| `setclass1.sh` | the two-file patch + rebuild, used for every row of §0 |
| `storeprobe-wt.sh` | one store, no browser, `curl` — the per-chunk cost at the new geometry |
| `c1-*.txt`, `variantP.*.txt` | full stdout of every run quoted above |
