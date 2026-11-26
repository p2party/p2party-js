# The structural latency floor of the two-store blind rendezvous

Derived from the pinned profile and the code, 2026-09-08, branch
`feat/blind-two-store-prototype`. Every constant is cited `file:line`. All paths
are relative to `~/Desktop/@p2party/p2party-js`.

Two claims in the brief turn out to be **half right**, and the correction is the
whole result:

- "The floor is structural: five dependent flights each gated by
  `publicReadLagWindows = 1`, plus a cold-start window." — **Confirmed, exactly.
  Six windows.** The arithmetic is §4 below: 24,600 ms − p, where p is the
  client's phase inside the delivery window it starts in.
- "Size class 1 is 86% of the scan and that is what stops the window from
  shrinking." — **Confirmed as an arithmetic fact** (85.6%, §7.1), **but it is
  not what costs the 35–42 s.** At the pinned 4,000 ms window the scan cost buys
  its 16 s of delay through a *different* mechanism: it makes each answering
  flight miss its own window's append slot by a few hundred milliseconds. That
  miss is worth 16.0 s of the recorded 41.8 s, and **it can be removed without
  touching the cohort, the scan, the window, or any privacy property** — by
  moving five integers in the profile. §8 is that finding, stated loudly.

---

## 1. The constants, with citations

`src/blindRendezvous/prototype/profile.ts`, all inside
`PROTOTYPE_DELIVERY_PROFILE_V0` (lines 81–127):

| Constant | Value | Line |
| --- | ---: | ---: |
| `deliveryWindowMs` | 4,000 | `profile.ts:87` |
| `maxFutureIngressWindows` | 2 | `profile.ts:89` |
| `roomSlotsPerClient` | 1 | `profile.ts:90` |
| `cohortAllocationsPerWindow` | 8 | `profile.ts:91` |
| `publicChunkObjectCount` | 8 | `profile.ts:92` |
| `maxScheduleSkewMs` | 200 | `profile.ts:93` |
| `tokenIssueOffsetMs` | 100 | `profile.ts:94` |
| `tokenIssueResponseBudgetMs` | 300 | `profile.ts:95` |
| `allocationRequestOffsetMs` | 700 | `profile.ts:96` |
| `allocationResponseBudgetMs` | 300 | `profile.ts:97` |
| `chunkFinalizationOffsetMs` | 2,800 | `profile.ts:98` |
| `publicReadLagWindows` | 1 | `profile.ts:99` |
| `publicReadOffsetMs` | 600 | `profile.ts:100` |
| class 0 `fixedCarrierObjectBytes` | 8,192 | `profile.ts:105` |
| class 0 append `identity-bootstrap` | 1,300 | `profile.ts:108` |
| class 0 append `safety-control` | 1,700 | `profile.ts:109` |
| class 0 append `state-replication` | 2,100 | `profile.ts:110` |
| class 0 `publicChunksPerWindow` | 3 | `profile.ts:112` |
| class 1 `fixedCarrierObjectBytes` | 73,728 | `profile.ts:116` |
| class 1 append `safety-control` | 1,500 | `profile.ts:119` |
| class 1 append `state-replication` | 1,900 | `profile.ts:120` |
| class 1 `publicChunksPerWindow` | 2 | `profile.ts:122` |

Window origin: `IngressWindowStart(w) = w × deliveryWindowMs` against the Unix
epoch (`publicWindow.ts:175-181`, `publicWindow.ts:149-156`). So window
boundaries are absolute, not session-relative, and a client's *phase* p inside
its start window is `Date.now() mod 4000` — uniform, uncontrolled, and worth up
to a whole window of the measured spread.

Payload-class sizes: `OPERATION_PAYLOAD_CLASS_BYTES = {0: 4096, 1: 69632}`
(`schemas.ts:47-48`).

---

## 2. The three gates that set the cadence

Everything below follows from exactly three facts in the code.

**Gate 1 — an allocation always names the *next* window.** The scheduled
allocation event fires at `allocationRequestOffsetMs` in window `w` and requests
a lease for `w + 1` (`carrierRuntime.ts:704`; the token event at
`tokenIssueOffsetMs` likewise, `carrierRuntime.ts:702`). The cold-start branch
does the same: a runtime that starts after the allocation instant fires one
immediate `#allocate(state, window + 1n)` (`carrierRuntime.ts:447`). An append
in window `w` is admitted only by the lease keyed `w` (`carrierRuntime.ts:818`);
with no lease the object still goes out at full size and on time, the store
answers `unallocated-cover` and discards it (`storeCore.ts:793`), and the outbox
entry stays queued because the result is neither `stored` nor `already-present`
(`carrierRuntime.ts:845-857`).

⇒ **The first window in which a client can land anything is its start window
+ 1.** That is the cold-start window, and it is unconditional: it costs 4,000 ms
whatever the phase p.

**Gate 2 — exactly one append opportunity per (role, size class) per window.**
`#eventsForWindow` schedules one event per `appendSchedule` entry
(`carrierRuntime.ts:632`), and `#append` selects the oldest outbox entry whose
`role` and `sizeClassId` match *that* slot (`carrierRuntime.ts:788-796`,
`#pendingEntry` at `carrierRuntime.ts:1325-1337`). The profile gives class 0 one
slot per role and class 1 one slot for each of two roles
(`profile.ts:107-111`, `profile.ts:118-121`). A missed slot is missed for good —
`#nextEvent` skips anything already past (`carrierRuntime.ts:668-673`) and there
is no same-window retry.

⇒ **A dependent flight can advance at most once per window.** This holds even
with zero compute time, and it is the reason `publicReadLagWindows` is not the
only thing to blame: even if the read lag were 0, the answer to a message read
at 3,000 ms would still have to wait for the next window's slot, because every
slot in this window is behind it.

**Gate 3 — the read is one whole window behind, at a fixed offset.** The read
event fires at `publicReadOffsetMs` in window `w` and scans `w − 1`
(`carrierRuntime.ts:621`, `carrierRuntime.ts:709-711`); `publicReadLagWindows`
is pinned to exactly 1 by the profile validator (`profile.ts:255-257`), which is
spec line 5816. The store finalizes `w − 1` at `chunkFinalizationOffsetMs` into
`w − 1` (`storeCore.ts:1213-1218`), i.e. 1,200 ms *before* `w` begins, so the
600 ms read offset is 1,200 ms of pure slack past the moment the data exists.

⇒ **What a peer publishes in window `w` is legible to the other side at
`(w+1)×4000 + 600`, no earlier, regardless of which slot inside `w` it used.**

The last clause matters and is easy to miss: **the slot offset inside a window
does not affect when the peer sees the object.** All five slots (1,300 … 2,100)
land in the same finalized chunk set and are read at the same instant. The slot
offset governs one thing only: *how much compute budget the answering side has
between its read and its own next slot.* That is what §8 exploits.

---

## 3. Which flight uses which slot

`operationServiceRole` (`workKinds.ts:38-52`) is total, and the driver labels
each publication:

| Flight | `publish(...)` | Role | Line | Payload class | Slot used |
| --- | --- | --- | ---: | :---: | ---: |
| `PRESENCE` | `pairDriver.ts:717` | `state-replication` (`workKinds.ts:47-49`) | | 0 (`pairDriver.ts:705`) | class 0 @ **2,100** |
| `IDENTITY_HELLO` | `pairDriver.ts:911` | `identity-bootstrap` (`workKinds.ts:44-46`) | | 0 (`pairDriver.ts:854`) | class 0 @ **1,300** |
| `IDENTITY_ACCEPT` | `pairDriver.ts:1321` | `identity-bootstrap` | | 0 (`pairDriver.ts:1263`) | class 0 @ **1,300** |
| `TRANSPORT_OFFER` | `pairDriver.ts:1585` | `safety-control` (`workKinds.ts:50-51`, default) | | 0 or 1, data-dependent | class 0 @ **1,700** / class 1 @ 1,500 |
| `TRANSPORT_ANSWER` | `pairDriver.ts:1697` | `safety-control` | | 0 or 1, data-dependent | class 0 @ **1,700** / class 1 @ 1,500 |

The transport flights' class is not fixed by the protocol — it is chosen by
`padPairPlaintextV1` from the encoded plaintext length
(`pairPlaintext.ts:664-697`, class selection at `pairPlaintext.ts:580-598`),
against the class-0 established-flight plaintext target of **4,017 bytes**
(`pairStepEnvelope.ts:126-131`; derived overheads: established envelope 63 B
`pairStepEnvelope.ts:94-95`, AEAD tag 16 B `pairStepEnvelope.ts:36-37`).

I encoded a canonical `TRANSPORT_OFFER` plaintext at a range of SDP lengths
against `pairPlaintextV1Schema` to find the flip point:

```
plaintext bytes = 404 + len(SDP)        (measured, canonical encoding)
largest SDP that still selects class 0  = 3,613 bytes
```

Chromium's loopback, `iceServers: []` offer (`docs/e2e/blind-two-store/entry.ts:116`)
is ~1–2 KB, so **in every recorded run the transport flights are class 0 and use
the 1,700 ms slot.** On a real network with STUN/TURN and several interfaces an
SDP can exceed 3,613 bytes, at which point the same flight silently moves to the
class-1 slot at 1,500 ms — *earlier*, so 200 ms *less* budget — and its carrier
object grows from 8,192 to 73,728 bytes. `MAX_PAIR_WEBRTC_SDP_BYTES_V1` is
32,768 (`schemas.ts:78`), so this is reachable, and it is a silent, data-dependent
change of both slot and object size. Name it as a hazard, not a bug.

---

## 4. The floor timeline, instant by instant

Assumptions, all of them the best case: both endpoints start in the same window
`w0`; zero compute time; zero network time; both stores honest; no missed slot.
Time t = 0 is `IngressWindowStart(w0)`. Client A starts at t = p, 0 ≤ p < 4,000.

| t (ms) | Window | What happens | Constant |
| ---: | :---: | --- | --- |
| p | w0 | `runtime.start()` (`index.ts:888`) then `driver.start()` (`index.ts:890`) queues `PRESENCE` into the outbox. Nothing is sent: `publish` only enqueues (`carrierRuntime.ts:496-511`). | — |
| 100 | w0 | allocation-token POST for **w1** | `tokenIssueOffsetMs` |
| 700 | w0 | allocation POST for **w1** → lease(w1). (If p > 700 the cold-start branch issues the identical request at t = p, `carrierRuntime.ts:432-448`.) | `allocationRequestOffsetMs` |
| 600 | w0 | read of w−1: nothing there | `publicReadOffsetMs` |
| 1,300–2,100 | w0 | five appends go out at full size. The 2,100 slot selects the queued `PRESENCE`, but there is no lease for w0 → `unallocated-cover`, discarded, entry stays queued. | Gate 1 |
| **6,100** | w1 | **`PRESENCE` stored** (class 0, `state-replication`, 2,100 into w1) | `profile.ts:110` |
| 6,800 | w1 | store finalizes w1 | `chunkFinalizationOffsetMs` |
| **8,600** | w2 | **both sides read w1** → each sees the other's presence; initiator = lower presence id; `ingest` calls `sendHello()` in the same turn (`pairDriver.ts:743-748`) | `publicReadOffsetMs`, lag 1 |
| **9,300** | w2 | **`IDENTITY_HELLO` stored** (1,300 into w2). Budget from the read: **700 ms**. | `profile.ts:108` |
| **12,600** | w3 | responder reads w2, opens HELLO, seals ACCEPT | lag 1 |
| **13,300** | w3 | **`IDENTITY_ACCEPT` stored** (1,300 into w3). Budget: **700 ms**. | `profile.ts:108` |
| **16,600** | w4 | initiator reads w3, opens ACCEPT, derives `EstablishedPairRoot`, calls `createOffer()` + complete ICE gathering | lag 1 |
| **17,700** | w4 | **`TRANSPORT_OFFER` stored** (1,700 into w4). Budget incl. ICE gathering: **1,100 ms**. | `profile.ts:109` |
| **20,600** | w5 | responder reads w4 → **responder now holds the initiator's SDP**; `acceptOffer()` + gathering | lag 1 |
| **21,700** | w5 | **`TRANSPORT_ANSWER` stored** (1,700 into w5). Budget: **1,100 ms**. | `profile.ts:109` |
| **24,600** | w6 | initiator reads w5 → **initiator now holds the responder's SDP.** Both sides have SDP. | `publicReadOffsetMs` |

### The floor

```
T_floor  =  deliveryWindowMs × (1 + F)  +  publicReadOffsetMs  −  p
         =  4000 × (1 + 5) + 600 − p
         =  24,600 ms − p                     p ∈ [0, 4000)

         ∈ (20.6 s, 24.6 s],  mean 22.6 s
```

`F = 5` is the number of dependent flights; the `1 +` is the cold-start window.
If the two endpoints start k windows apart, add `k × 4000`.

**Answer to (1): six delivery windows, plus `publicReadOffsetMs`, minus the
start phase.** Windows: one for the cold-start allocation, one per dependent
flight.

### Independent corroboration

The recorded cohort table (`docs/blind-rendezvous-two-store-prototype.md:427-433`)
contains two runs in which the doc itself certifies "per flight 4.0 s = 1
window", i.e. no missed slot:

| Window | Cohort | Measured `presence-published` → `message-verified` | Predicted floor band |
| ---: | ---: | ---: | --- |
| 4000 | 4 | **22.3 s** | (20.6, 24.6] |
| 4000 | 2 | **23.8 s** | (20.6, 24.6] |

Both land inside the predicted band, and their 1.5 s spread is exactly the
phase term p, which is why that pair of rows is non-monotone in the cohort. The
design doc's own prediction, written before any of this was measured, was
"roughly 20–25 s" (`…-design.md:279-282`). The floor is not an estimate; it is
what the profile arithmetic says, and two runs sit on it.

---

## 5. Accounting for the recorded 41.8 s (healthy, page A)

From `docs/e2e/blind-two-store/README.md:378-397`, wall clock re-based on page
A's `presence-published` at 0.5 s (both pages published within 0.1 s of each
other, so B's events are on the same axis to within the log's resolution). The
events alternate between the two pages because each one is the *next* peer's
read completing:

```
 9.7 s  [A] peer-observed  + hello-sent    (A's read of w1 completes)
17.7 s  [B] hello-opened   + accepted      +8.0
25.6 s  [A] accepted       + offer-sent    +7.9
33.5 s  [B] offer-opened   + answered      +7.9
41.8 s  [A] handoff                        +8.3   ← both sides have SDP
41.8 s  [A] session-authenticated          +0.0
41.8 s  [A] message-verified               +0.0
```

Four legs of **8.0 s = two delivery windows each**, where the floor says one.
Writing S for the read-to-delivery latency of one scan (HTTP fetch + signature
verification + Merkle recomputation + 80 AEAD opens + `coreReduce` + seal), the
first leg gives the only equation available:

```
9.7  =  2W + publicReadOffsetMs − p + S  =  8.6 − p + S      ⇒   S − p = 1.1 s
```

and the whole run decomposes with no residue:

| Term | ms | Share of 41.8 s | Controlled by |
| --- | ---: | ---: | --- |
| cold-start allocation window | 4,000 | 9.6% | `carrierRuntime.ts:704` / `:447` targeting `w+1`; `allocationRequestOffsetMs` `profile.ts:96` |
| five dependent flights × 1 window | 20,000 | 47.8% | `publicReadLagWindows` `profile.ts:99` + one slot per role per window `profile.ts:107-111` |
| **four answering flights missing their own window's slot** | **16,000** | **38.3%** | `publicReadOffsetMs` 600 vs. slots at 1,300/1,700 (`profile.ts:100`, `:108`, `:109`) against the scan cost from `cohortAllocationsPerWindow` `profile.ts:91` |
| final read offset | 600 | 1.4% | `publicReadOffsetMs` `profile.ts:100` |
| final ingest, net of start phase (S − p) | 1,100 | 2.6% | scan geometry (§7.1) |
| WebRTC connect + DTLS verify + v4 handshake + 140,005 B + 9,005 B | ≤ 100 | ≤ 0.2% | not the profile |
| **total** | **41,700** | | measured 41,800 (log prints to 0.1 s) |

`4,000 + 20,000 + 16,000 + 600 = 40,600`, plus `S − p = 1,100` → 41.7 s against
a printed 41.8 s. The arithmetic closes.

**Answer to (2): the structural floor accounts for 24.6 s − p of the 41.8 s
(59%, or 62% if the final ingest is charged to it). The remaining 16.0 s is one
single cause: four flights each missing their own window's append slot by a few
hundred milliseconds and waiting a whole extra window.** And of the floor
itself, 4.0 s is the cold-start allocation and 20.0 s is the five flights.

The same decomposition on `kill-a` (page A, 35.2 s, legs 8.1 / 8.1 / 7.3 /
**4.6**): three missed slots instead of four, and the last leg made its slot
because with store A dead the scan is half the work. Floor 24.6 − p + 3 × 4.0 +
S = 36.6 − p + S = 35.2 ⇒ S − p = −1.4, consistent with a single-store S below
the 1,100 ms budget the 4.6 s leg proves it met. Two scenarios, two independent
fits, same model. (The outward doc is right that scenario-to-scenario ordering
is not a measurement — but the *mechanism* is visible inside a single run: the
one leg that halved was the one whose read only had to scan one store.)

### Where the rest does *not* go

- **WebRTC and the v4 handshake are free here.** `handoff`, `webrtc-connected`,
  `dtls-verified`, `session-authenticated`, `message-sent` and both
  `message-verified` all print in the same 0.1 s bucket (README:386-393). Real
  ICE, DTLS and a hybrid 3DH + ML-KEM handshake plus 149 KB of application data
  cost under 100 ms on loopback. On a real network add ICE + DTLS RTTs — still
  a fraction of one 4,000 ms window. **Do not go looking for savings here.**
- **The witness pair costs no critical-path latency.** It runs after
  `onOperations` has already handed the fresh operations to the driver
  (`carrierRuntime.ts:1079` then `:1090`), so it cannot delay a publication. It
  is a disclosure problem (design §3a item 14), not a latency one.
- **The union join costs latency twice over**, and this is real: both stores'
  scans are joined under one `Promise.all` (`carrierRuntime.ts:1032`) so the
  slower store gates the read, and then both stores' objects are opened
  **sequentially, on the main thread** (`carrierRuntime.ts:1049-1063`), so 80
  AEAD opens run where 40 would do. The second store roughly doubles S — which
  is precisely what pushes S past the 700 ms budget.

---

## 6. Every source of slack, and the constant that controls it

Ranked by what it is worth at the pinned profile.

| # | Source | Worth | Controlled by |
| ---: | --- | ---: | --- |
| 1 | **Answering flight misses its own window's append slot** | 4,000 ms × 4 = **16.0 s** | gap between `publicReadOffsetMs` (`profile.ts:100`) and the answering slot (`profile.ts:108`, `:109`), versus S; S is set by `cohortAllocationsPerWindow` (`profile.ts:91`), `fixedCarrierObjectBytes` (`profile.ts:105`, `:116`), `publicChunkObjectCount` (`profile.ts:92`) and the two-store union (`carrierRuntime.ts:1032`, `:1052`) |
| 2 | **Five dependent flights, one window each** | **20.0 s** | `publicReadLagWindows` (`profile.ts:99`, validator `profile.ts:255-257`) × one slot per role per window (`profile.ts:107-111`) × `deliveryWindowMs` (`profile.ts:87`); flight count is `pairDriver.ts` (§3) |
| 3 | **Cold-start allocation window** | **4.0 s** | allocation targets `w+1` (`carrierRuntime.ts:704`, cold start `:447`); the store would accept `w` (`storeCore.ts:660-665` refuses only `target < current`) |
| 4 | **Start phase p** | 0–4.0 s, mean 2.0 s (a *credit*, not a cost) | absolute epoch-aligned windows (`publicWindow.ts:175-181`) |
| 5 | **Final read offset** | **0.6 s** | `publicReadOffsetMs` (`profile.ts:100`); 1,200 ms of it is pure slack past finalization (`chunkFinalizationOffsetMs` `profile.ts:98`) |
| 6 | **Final ingest S** | 1.1–2.6 s | as #1 |
| 7 | Peers starting in different windows | k × 4.0 s | nothing in the profile; a product-level "join now" concern |
| 8 | ICE gathering inside the transport budget | 0 s here, **4.0 s each in production** | `DEFAULT_GATHERING_TIMEOUT_MS` 15,000 (`webrtcProvider.ts:55`); the harness uses `iceServers: []` (`entry.ts:116`) so gathering is ~ms. With STUN/TURN, `createOffer` + complete gathering routinely exceeds the 1,100 ms budget and costs a whole window per transport flight |
| 9 | Main-thread contention | bounded, small | the AEAD/hash work is synchronous WASM on the main thread; the next event is armed *before* the handler runs (`carrierRuntime.ts:681-687`) so the grid does not drift, but an append can be delayed by one in-flight WASM call |
| 10 | Request deadline coupling | — | `requestDeadlineMs = deliveryWindowMs` (`storeClient.ts:276-283`): shortening the window shortens every request's deadline in lockstep, which is a second reason a short window + big cohort stalls |
| 11 | WebRTC + DTLS + v4 + payload | ≤ 0.1 s | not the profile |

---

## 7. Why S is what it is (the number behind #1)

### 7.1 The per-window scan, recomputed

One carrier object on the wire is `fixedCarrierObjectBytes + 102`
(`carrierObjectWireBytes`, `profile.ts:393-414`: 4-byte length prefix + version
1 + profile hash 32 + ingress window 8 + size class 1 + carrier context id 32 +
nonce 24 = 102).

```
class 0:  publicChunksPerWindow 3 × publicChunkObjectCount 8 = 24 objects × 8,294 =   199,056 B
class 1:  publicChunksPerWindow 2 × publicChunkObjectCount 8 = 16 objects × 73,830 = 1,181,280 B
                                                                        total       1,380,336 B  ✓ (README:363)
appends:  3 × 8,294 + 2 × 73,830                                                    =   172,542 B  ✓ (README:363)
```

Class 1 is **85.58%** of the scan — the brief's "86%" is right. Both stores:
**2,760,672 B and 80 AEAD opens per client per window**, plus per store one
SHA-256 pass over 1.38 MB, one RFC 9162 Merkle root recomputation, chain
verification and custody verification (`storeClient.ts:955-995`) — all on the
main thread, in the *development* WASM build.

### 7.2 What S must beat, and what it is

| Flight | Read completes at | Slot | Budget |
| --- | ---: | ---: | ---: |
| `IDENTITY_HELLO` | 600 + S | 1,300 | **700 ms** |
| `IDENTITY_ACCEPT` | 600 + S | 1,300 | **700 ms** |
| `TRANSPORT_OFFER` | 600 + S | 1,700 | **1,100 ms** (must also fit `createOffer` + complete ICE gathering) |
| `TRANSPORT_ANSWER` | 600 + S | 1,700 | **1,100 ms** (must also fit `acceptOffer` + gathering) |
| `PRESENCE` | queued at start | 2,100 | not on the critical path |

Bracketing S from the recorded runs. Lower bound: with two stores the 700 ms and
1,100 ms budgets were missed on all four flights ⇒ S₂ > 1.1 s (the transport
flight also carries `createOffer`, so strictly S₂ + gathering > 1.1 s). Upper
bound: `kill-a`'s 4.6 s leg made the 1,100 ms budget with one store ⇒ S₁ <
1.1 s, and the scan work is very close to linear in the number of stores
(`carrierRuntime.ts:1032` fetches in parallel, `:1049-1063` opens sequentially),
so S₂ ≲ 2.2 s. Cross-check: `S − p = 1.1 s` with `p ∈ [0, 4)` gives S₂ ∈ [1.1,
5.1) and hence `p ∈ (0, 1.1]` for this run. **S₂ ≈ 1.1–2.2 s against a 700 ms
budget** — it misses by roughly 0.4–1.5 s, and pays a full 4,000 ms window for
it.

---

## 8. THE CHEAPEST WIN IN THE SYSTEM — say it loudly

**Four of the five flights regularly miss their own window's append slot and
wait a whole extra delivery window. That is 16.0 s of the recorded 41.8 s — 38%
of the run — and it is bought back by editing five integers in
`PROTOTYPE_DELIVERY_PROFILE_V0`. No cohort change, no window change, no scan
change, no traffic change, no shape change, no spec deviation.**

The reason it is free is Gate 3's last clause: **the slot offset inside a window
has no effect on when the peer sees the object** — every slot lands in the same
finalized chunk set, read at the same instant of the next window. The slot
offset governs *only* the answering side's compute budget. The profile currently
places the answering slots as early as the geometry permits (1,300 / 1,700),
which minimises that budget for no benefit whatsoever.

The frozen §4.3 inequalities (spec lines 5793-5825, enforced at
`profile.ts:205-353`) that bound how late a slot may sit are:

```
every appendSchedule.offsetMs + maxScheduleSkewMs  <  chunkFinalizationOffsetMs      (profile.ts:348-353)
chunkFinalizationOffsetMs + maxScheduleSkewMs      <  deliveryWindowMs + publicReadOffsetMs   (profile.ts:245-251)
0 < chunkFinalizationOffsetMs < deliveryWindowMs                                     (profile.ts:239-243)
allocationRequestOffsetMs + allocationResponseBudgetMs + maxScheduleSkewMs
                                                   <  min(appendSchedule.offsetMs)   (profile.ts:336-345)
```

With `deliveryWindowMs` 4,000, `maxScheduleSkewMs` 200, `publicReadOffsetMs` 600
and `allocation…` 700 + 300, the admissible band for append offsets is
`(1,200, chunkFinalizationOffsetMs − 200)`, and `chunkFinalizationOffsetMs` may
go as high as 3,999 while satisfying the second inequality (3,999 + 200 = 4,199 <
4,600). Two conforming re-profilings:

**(a) Conservative — keep `publicReadOffsetMs` at 600, finalize at 3,400.**

```
chunkFinalizationOffsetMs 2,800 → 3,400          (3,400 + 200 = 3,600 < 4,600 ✓)
class 0 appendSchedule  [1300, 1700, 2100] → [2,500 ib, 2,800 sc, 3,100 sr]   (3,100 + 200 = 3,300 < 3,400 ✓)
class 1 appendSchedule  [1500, 1900]       → [2,650 sc, 2,950 sr]
                                                 (1,200 < 2,500 ✓ allocation inequality)
```
Budget: identity flights **1,900 ms** (was 700, ×2.7), transport flights
**2,200 ms** (was 1,100, ×2.0). That clears the bracketed S₂ ≈ 1.1–2.5 s for
most of its range at the pinned cohort of 8, and clears it outright at cohort 4.

**(b) Aggressive — also take `publicReadOffsetMs` to 0, finalize at 3,700.**

```
publicReadOffsetMs 600 → 0                       (read is still 1,200 ms after the
                                                  previous window finalized at 3,700
                                                  of a window that ended 300 ms ago ✓
                                                  3,700 + 200 = 3,900 < 4,000 + 0 ✓)
class 0 appendSchedule → [3,100 ib, 3,300 sc, 3,499 sr]   (3,499 + 200 = 3,699 < 3,700 ✓)
```
Budget: **3,100 ms** for the identity flights (×4.4), and it shaves a further
600 ms off the final leg. The margin between finalization and the read narrows
to 300 ms, which is inside `maxScheduleSkewMs` but leaves the store no room for
a slow `finalize()` — (a) is the safe one to ship first.

**One caveat that applies to both, and that a run must confirm rather than an
argument.** Moving the appends later moves them *into* the interval the client
spends scanning. The AEAD, SHA-256 and Ed25519 work is synchronous WASM on the
main thread, so the append handler's own seal and POST queue behind whatever
scan call is in flight. The schedule itself will not drift — the next event is
armed before the handler runs (`carrierRuntime.ts:681-687`) — but an append can
be delayed by roughly one WASM call, and if the last append lands past
`chunkFinalizationOffsetMs` the store answers `window-finalized`
(`storeCore.ts:789-790`) and the flight is lost for a window, which is the very
failure the cohort table records at `--window-ms=2000`. That is why (a) keeps
300 ms between the last append (3,100) and finalization (3,400) rather than
spending it: the fix must be verified by a `--scenario=healthy` run showing
`appendsDummy + appendsReal` unchanged and no `window-finalized` in the
`store-missed` lines, not by this arithmetic alone.

**Second-cheapest, if (a) is not enough at cohort 8: give each role a second
slot in the same window.** Spec §4.3 requires `count(role) >= 1`, not exactly 1
(spec line 5822-5824, enforced at `profile.ts:295-309`), so a class-0 schedule
of `[1300 ib, 1700 sc, 2100 sr, 2900 ib, 3100 sc, 3300 sr]` is conforming. A
flight that misses the early slot lands in the late one, in the *same* window,
instead of losing 4,000 ms. The cost is honest and small in this profile,
because it is class 0 that grows: `appendSchedule.length` 3 → 6 raises
`publicChunksPerWindow` 3 → 6 (the minimum-integer rule, `profile.ts:325-331`),
so the scan grows 1,380,336 → 1,579,392 B (**+14.4%**) and the per-window append
volume 172,542 → 197,424 B (**+14.4%**). It is strictly worse than (a) as a
first move — it enlarges the very scan that causes the miss — but it is the
right *second* move, because it makes the schedule robust to a client that is
merely slow rather than requiring every client to beat a single deadline.

**Third: reclaim the cold-start window (4.0 s, 9.6% — but only sometimes).**
`storeCore.#allocate` already accepts a lease request for the *current* window:
it refuses only `target < current` or `target > current +
maxFutureIngressWindows` (`storeCore.ts:660-665`). A runtime that, at start,
also allocated for its own window would land `PRESENCE` 4,000 ms earlier —
**provided it starts early enough for the round trip to beat the first append
slot**:

```
p + allocationResponseBudgetMs + maxScheduleSkewMs  <  min(appendSchedule.offsetMs)
p + 300 + 200 < 1,300   ⇒   p < 800      (today: fires for 20% of start phases)
p + 300 + 200 < 2,500   ⇒   p < 2,000    (under re-profiling (a): 50%)
```

So the honest value is **expected** 0.8 s today and 2.0 s under (a), not a flat
4 s — though for any given user it is either the whole 4 s or nothing.
**And it is a disclosed deviation, not free:** the session's first window would
carry two allocation POSTs (one for `w`, the scheduled one for `w+1`) instead of
one, so the first window of a session becomes distinguishable from a
steady-state window — exactly one bit ("this client just started"), in the first
window only. That needs a new item in design §3a. The maintainer's call.

**Fourth, and the only one that changes the protocol: collapse a flight.**
`IDENTITY_ACCEPT` (identity-bootstrap, slot 1,300) and `TRANSPORT_OFFER`
(safety-control, slot 1,700) use **different role slots in the same window**, and
the responder can compute `EstablishedPairRoot` immediately after sealing its
ACCEPT (`pairDriver.ts:1512-1533`) and `createOffer()` needs nothing from the
peer. So a responder that emits ACCEPT *and* OFFER in one window, with the
initiator answering, turns five flights into four: floor `(1 + 4) × 4000 + 600 =
20.6 s`. This is a pair-protocol change with its own security review (who offers,
the tie-break for two concurrent offers, §3a item "no uniqueness"), so it is
named here as an option with its number attached, not recommended.

---

## 9. What the floor becomes, per change

`T_floor = deliveryWindowMs × (1 + F) + publicReadOffsetMs − p`, averaged over
the uniform start phase p, plus S for "SDP actually in hand" (S ≈ 2.0 s at
cohort 8 with two stores, ≈ 1.0 s at cohort 4, ≈ 0.9 s at cohort 2 — the
bracket from §7.2, scaled by the scan-byte column of the recorded cohort table).
The cold-start reclaim is folded in as an expectation, because it fires only for
a start phase below the threshold in §8 and those are exactly the runs with the
smallest `−p` credit.

| Change | W | F | readOffset | E[floor] | + S | vs. today's 41.8 s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| today (pinned, 4 slots missed) | 4,000 | 5 | 600 | 22.6 s + 16.0 s slip | ≈ 40.6 s | (measured 41.8 s) |
| **(a) move the slots later** — profile only | 4,000 | 5 | 600 | **22.6 s** | **≈ 25 s** | **−41%** |
| (a) + reclaim the cold start | 4,000 | 5 | 600 | **20.6 s** | ≈ 23 s | −46% |
| (a) + cold start + ACCEPT‖OFFER | 4,000 | 4 | 600 | **16.6 s** | ≈ 19 s | −56% |
| all of the above at cohort 4 | 4,000 | 4 | 600 | 16.6 s | ≈ 18 s | −58% |
| all of the above at W = 1,000, cohort 2 | 1,000 | 4 | 150 | **4.2 s** | **≈ 5 s** | **−88%** |

The last row is the one that reaches "blazing fast", and it is reachable only
because rows 2–4 remove the reasons the shorter window currently fails: at the
pinned profile a 1,000 ms window has a 1,000 ms request deadline
(`storeClient.ts:276-283`) and a 1.38 MB scan, and every append lands after
`window-finalized` (measured, README cohort table). The measured
`W=1000, cohort=2` run already reached **10.5 s** with none of these changes.

---

## 10. Deviations this analysis proposes, named

Per the brief's rule that every deviation is stated as one:

1. **Moving the append offsets and `chunkFinalizationOffsetMs` later** — *not a
   deviation.* Those are profile values; every §4.3 inequality still holds and
   `validateDeliveryProfileGeometry` passes unchanged. Both stores and both
   pages already agree on one profile hash by construction (`--cohort` rebuilds
   it), so the change is atomic across the deployment.
2. **`publicReadOffsetMs` → 0** — *not a deviation*, but it narrows the
   finalize-to-read margin to `deliveryWindowMs − chunkFinalizationOffsetMs`;
   keep that ≥ `maxScheduleSkewMs` with room to spare.
3. **A second append slot per role** — *not a deviation* (spec says `>= 1`), but
   it is a **measurable traffic increase** (+14.4% scan and append bytes) and
   must be reported as one.
4. **Allocating for the current window at cold start** — **a deviation**, and a
   *new* residual leak: one extra allocation POST in the first window of a
   session makes that window distinguishable. Requires a new §3a item, or a
   variant that hides it (e.g. always issue two allocation POSTs per window, at
   double the token/allocation cost).
5. **Collapsing ACCEPT and OFFER into one window** — a **protocol** change, not
   a profile change. Out of scope for a latency derivation.

None of 1–3 touches what a store learns: same number of requests, same sizes,
same routes, same fixed schedule, same cover/real indistinguishability. They
move *when in the window* the same requests happen, uniformly for every client
on the grid.

---

## 11. What I could not measure, and what would settle it

- **S is bracketed, not measured.** I derived `S − p = 1.1 s` from the healthy
  run and `S₁ < 1.1 s` from `kill-a`'s 4.6 s leg, but neither p nor S is
  recorded. One line in the harness — print `Date.now() % deliveryWindowMs` at
  `presence-published`, and the wall time at read-start and at
  `onOperations` — turns every one of these inferences into a measurement, and
  would immediately show how much of S is HTTP, how much is
  hash/signature verification, and how much is the 80 AEAD opens. The
  `withhold-a` log hints the post-fetch half is ~0.3 s (`topology` at 7.7 s →
  `peer-observed` at 8.0 s), which would put the fetch-plus-verify half at ~2 s
  and make the *verification*, not the AEAD, the thing to optimise — but that is
  one pair of printed timestamps in one run, not a measurement.
- **The transport flights' payload class in production is untested.** Class 0
  holds an SDP up to 3,613 bytes; a real network can exceed it. Assert the class
  in the harness so the flip is visible rather than silent.
- **ICE gathering in production is untested and is worth a whole window per
  transport flight.** With `iceServers: []` it is ~ms; with STUN it routinely
  exceeds the 1,100 ms budget. Pre-gathering the offer at start-up costs nothing
  — `createOffer()` depends on no peer state — and would immunise the transport
  flights against it.
