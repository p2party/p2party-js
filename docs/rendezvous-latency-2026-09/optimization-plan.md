# Making the two-store blind rendezvous fast — the plan

2026-09-08. Inputs: `floor.md`, `observed.md`, six angle reports, three
adversarial verdicts, all read in full; every code fact re-verified against
the repository root at the pinned profile
(`profile.ts:86-125`, tree clean for `src/blindRendezvous/`).

**The honest headline, before the detail.**

| Milestone | Time to first message | Evidence |
| --- | ---: | --- |
| today, pinned, cohort 8, W=4,000 | 35.5 – 41.9 s | measured, 8 runs |
| after the store fix + the free profile move | **≈ 22.6 s** | measured 22.0–24.3 s, 13 runs, three independent routes |
| + shrink the class-1 carrier, W=2,000 | **≈ 11.5 s** | measured 11.1–11.6 s, 4/4 scenarios |
| + `publicChunkObjectCount` 24, W=1,000 | **≈ 7.5 – 9.4 s** | measured, 4/4 scenarios |
| + collapse one flight (F: 5 → 4) | **≈ 6.5 – 8.4 s** | **projected**, never run |

**That is 4.4× confidently and ~5.5× optimistically — not 10×.** The floor is
`W × (1 + F) + r − p`, and after the store is fixed only `W` and `F` are levers.
Every second below `W × (1+F)` costs either a spec deviation, a disclosure, or
both, and §4 lists the eleven ideas that were killed trying.

**Three things you should know before reading further.**

1. **The 16 s that four reports independently chase is one bug, and three
   different changes each remove all of it.** They are *not additive*. Any plan
   that adds the store fix's 16 s to the schedule move's 16 s to the class-1
   shrink's 16 s is claiming 48 s of saving on a 41.8 s run.
2. **The prior belief that "the browser could not finish the per-window AEAD" is
   refuted by measurement.** The browser does the entire 2.76 MB two-store scan
   in **8 ms**. The 1,450 ms is the store rebuilding its whole window document
   from a hand-rolled hex codec on every chunk GET. `observed.md` §4e blames
   `JSON.parse`; that was measured at **0.30 ms** and is wrong by 340×. The cost
   is `bytesFrom`/`hexOf` at `storeSqlite.ts:68-78`.
3. **Three sentences in the shipped docs are already false**, before any change
   ships, and three residual leaks are already owed. §6 has them.

---

## 1. Where the time goes today

One measured run (`README.md:378-397`, healthy, page A, 41.8 s), decomposed with
no residue. Every row is measured; the two derived rows say so.

| # | Term | ms | % of 41.8 s | Controlled by | How known |
| ---: | --- | ---: | ---: | --- | --- |
| 1 | Five dependent flights × 1 delivery window | 20,000 | 47.8 % | `publicReadLagWindows = 1` (`profile.ts:99`, pinned by validator `:255-257`) × exactly one append slot per `(role, sizeClass)` per window (`profile.ts:107-121`, `#pendingEntry` `carrierRuntime.ts:1325-1337`) | **measured** — the `w0+2 / w0+4 / w0+6 / w0+8 / w0+10` ladder in all three instrumented runs |
| 2 | **Four answering flights missing their own window's append slot** | **16,000** | **38.3 %** | the gap between `publicReadOffsetMs = 600` and the answering slots at 1,300 / 1,700, versus the scan wall `S` | **measured** — every read-derived phase event lands at offset 2,050–2,160 ms; 14 of 15 flights cost two windows; the one flight that made its slot is the one whose scan took 732 ms against a 900 ms budget |
| 3 | Cold-start allocation window | 4,000 | 9.6 % | the allocation always targets `w+1` (`carrierRuntime.ts:704`, cold start `:447`); the store would accept `w` (`storeCore.ts:660-665`) | **measured** — the harness prints `cold start past the allocation offset`; fires for 82 % of start phases |
| 4 | Final read offset | 600 | 1.4 % | `publicReadOffsetMs` (`profile.ts:100`) | constant |
| 5 | Final ingest, net of start phase (`S − p`) | 1,100 | 2.6 % | as row 2 | **measured** (fit) |
| 6 | WebRTC + DTLS + protocol-v4 + 149 KB of payload | ≤ 100 | ≤ 0.2 % | not the profile | **measured** — `4 + 1 + 7 + 5 + 8 ms` |
| — | start phase `p` (a credit, uniform on `[0, 4000)`) | −0 … −4,000 | — | epoch-aligned windows (`publicWindow.ts:175-181`) | derived; **never recorded** |
| | **total** | **41,700** | | | printed 41.8 s |

### 1.1 Row 2 is one bug, and it is inside the store

The scan wall `S` (read event fires → operations reach the driver) decomposes:

| Component | Measured | Source |
| --- | ---: | --- |
| client decode + trial-open of all 40 objects, **per store** | **4.0 ms** | `scanbench.ts` in headless Chromium |
| both stores | **8 ms** | same |
| post-fetch: Merkle recomputation + custody + union + Ed25519 + HPKE open + reseal | **13.9 – 39.1 ms**, p50 27.2 | in-run, n=15 |
| **the store answering 10 serial chunk GETs** | **~1,450 ms** (p50 1,453, n=58) | in-run + `storeprobe.sh` |
| **⇒ per chunk GET, flat, whatever the chunk holds** | **97 – 103 ms** | one store, no browser, `curl` |

And inside that 97 ms, on a *populated* window (`benchload.ts`, `benchload2.ts`,
`benchload3.ts`):

| Step | ms | Line |
| --- | ---: | --- |
| `SELECT state FROM "window"` | 0.69 | `storeSqlite.ts:278` |
| `TextDecoder.decode` | 0.28 | `storeSqlite.ts:285` |
| `JSON.parse` | **0.30** | `storeSqlite.ts:285` |
| **`bytesFrom` — hex-decode the whole window document** | **100.7** | `storeSqlite.ts:71-78` |
| `encodePublicChunkReadV1` (the actual response) | 0.08 | `storeHttp.ts:320` |
| **`loadWindow` total, populated window** | **137.0** | |
| write side: `saveWindow` (`hexOf`, `storeSqlite.ts:68-69`) | **184.0** | `benchsave.ts` |

`bytesFrom` is `Number.parseInt(value.slice(i*2, i*2+2), 16)` per byte over a
1.18 MB string; `hexOf` spreads a 73,728-byte array into 73,728 two-character
strings and joins them. Both run in full on **every** chunk GET, checkpoint GET,
append POST, allocation POST and finalization, behind one global mutex
(`storeCore.ts:1190`) on one event loop. Derived load factor at cohort 8 with two
clients: **0.9 – 1.5 CPU-seconds per 4,000 ms window** — the store is at or past
saturation, which is why the allocation POST takes 1,270 ms and why
`--window-ms=2000` stalls outright.

**So row 2 is not a protocol cost and never was.** It is a store defect that a
competent implementation would not have had.

---

## 2. The recommended sequence

Ordered by saving-per-risk. Only candidates that survived all three adversarial
passes. Steps 1–4 have **no disclosure and no deviation at all**; the price
starts at step 6.

---

### Step 1 — Replace the hex codec in `storeSqlite.ts`

*(SCAN-C2 / D-C2. Unanimous rank 1 in all three adversarial verdicts.)*

**Change.** `bytesFrom` (`storeSqlite.ts:71-78`): `charCodeAt` nibble table
instead of `slice` + `parseInt`, **keeping the strict validation** (reject any
non-`[0-9a-f]` nibble, keep the odd-length check — a table that maps an
unexpected character to 0 turns a corrupt row into a silently wrong object, and
the store signs what it serves). `hexOf` (`:68-69`):
`Buffer.from(value).toString("hex")`.

**Saving.** Per chunk GET **137 → ~5 ms** (measured 37× on the decode, 409× on
the encode). Two-store scan wall **p50 1,453 ms → tens of ms**. Store load factor
**≈1.2 → ≈0.05**. In windows: it removes the cause of row 2 — **4 windows,
16.0 s** — and it is the reason the answering budget stops being tight.

**Privacy cost.** None. No wire byte, no route, no request count, no size, no
offset, no geometry, no signature (the chunk is signed once at finalization,
`storeCore.ts:982-988`). **Maps to no §3a item; adds none, widens none.**

**Spec deviation.** None. The spec does not constrain a store's persistence.

**Files.** `src/blindRendezvous/prototype/store/storeSqlite.ts`. **~25 LOC, one
file.**

**Measurement that proves it.** `probe-attribute.sh`: chunk-GET TTFB must drop
from ~103 ms to <5 ms, and the 6-request cold ladder (102/204/304/406/508/610)
must go flat. Then `run.mjs --scenario=healthy`: the milestone ladder must be
`w0+1, w0+2, w0+3, …` not `w0+2, w0+4, …`, and `store-missed` must contain zero
`window-finalized`.

---

### Step 2 — Serve finalized chunks and checkpoints from precomputed rows

*(SCAN-C1 / D-C1.)*

**Change.** At finalization, write one `BLOB` row per finalized chunk holding the
exact `encodePublicChunkReadV1` response bytes, plus one for the checkpoint. Add
`loadChunkResponse` / `loadCheckpointResponse` to `StorePersistencePort`;
`readChunk` (`storeCore.ts:1090-1124`) and `readCheckpoint` (`:1043-1075`) call
those instead of `loadWindow`. **Keep the `loadWindow` fallback** for rows
written by an older build — without it an existing database serves nothing, the
client's chain verification fails, and the store goes inert, which looks exactly
like `withhold-a` on a store that did nothing wrong.

**Saving.** Per chunk GET **137 → 0.072 ms**; over real HTTP **0.54–0.81 ms
TTFB** for a 590 KB body (measured, `scanprobe.sh` pass 3). **Zero further
windows at W=4,000** once step 1 has landed — its value is that the answering
budget becomes **60× the need instead of 1.2×**, which is what makes a shorter
window discussable at all.

**Privacy cost.** None. Same as step 1.

**Spec deviation.** None. `storePersistence.ts:11-16` names this task explicitly.

**Files.** `storeSqlite.ts`, `storePersistence.ts`, `storeCore.ts`,
`storeHttp.ts`. **~140 LOC, four files.**

**Measurement.** `scanprobe.sh` cold pass flat and sub-2 ms; `--scenario=all`
4/4 with identical audit verdicts (0 needles).

---

### Step 3 — Three harness assertions, before any profile is touched

*(Tests 3 and 5 of `attack-correctness.md` §4; asked for independently by
`floor.md` §11 and three angle reports.)*

**Change.** In `docs/e2e/blind-two-store/run.mjs`:
(a) **fail the run** on any `append window-finalized` line in `store-missed`;
(b) assert the transport flight's published `operationPayloadClass` — today the
class flip at SDP > 3,613 bytes is completely silent and moves the flight to an
*earlier* slot with *less* budget (class-1 safety-control 1,500 vs class-0
1,700);
(c) print `Date.now() % deliveryWindowMs` at `presence-published`.

**Saving.** Zero seconds. It converts every step below from an argument into a
measurement, and (a) is the single assertion that guards steps 4, 6, 7 and every
window shrink at once.

**Privacy / deviation.** None.

**Files.** `run.mjs`. **~30 LOC.**

---

### Step 4 — Reverse the append roles at the pinned offsets

November 27 follow-up on SDK v0.15.1. The harness now runs the candidate
against the release profile at matched launch phases, with both native
and delayed local reads. The study records the conditions under which the
extra scheduling margin changed time to verified messages.
[Paired experiment and release decision](slot-order-study.md)

*(A narrowing of SCHED-C1. See the note below: I am recommending **less** than
`angle-schedule-shape` proposes, and saying why.)*

**Change.** In `PROTOTYPE_DELIVERY_PROFILE_V0`, permute the roles only — no
offset moves, no `chunkFinalizationOffsetMs` change:

```
class 0  [1300 identity-bootstrap, 1700 safety-control, 2100 state-replication]
      →  [1300 state-replication,  1700 identity-bootstrap, 2100 safety-control]
class 1  [1500 safety-control, 1900 state-replication]
      →  [1500 state-replication, 1900 safety-control]
```

The two roles that must beat the read (`identity-bootstrap`, `safety-control`)
currently get the *tightest* deadlines and the one that never has to beat
anything (`state-replication`, which carries only PRESENCE) gets the loosest.
Verified legal against the real validator: strictly increasing offsets ✓; class 0
keeps ≥1 `identity-bootstrap` ✓ (`profile.ts:295-299`); every class keeps ≥1
`safety-control` and ≥1 `state-replication` ✓ (`:302-309`).

**Saving.** Identity flights **700 → 1,100 ms** of budget, transport flights
**1,100 → 1,500 ms**, for free. After steps 1–2 this buys **0 s on this laptop**
— it is insurance against a real-device `S` tail, and it is the cheapest
insurance available.

**Why not the full SCHED-C1 (late slots at 2,400/2,600/2,800, `cf` 3,500)?**
Because it is measured, deviation-free, and *worth 16.0 s only on the slow
store*. Once the store is fixed the read completes at ~650 ms against a 1,300 ms
slot, so the late-slot move buys nothing on the healthy path — and it costs
something real: it cuts `chunkFinalizationOffsetMs − min(appendOffset)` from
1,500 ms to 1,100 ms, which is the store's drain headroom, and
**`E8-w1000-c2.txt` measured it FAILING at W=1,000 with 17 ×
`append window-finalized`** at a configuration the outward doc records at 10.5 s.
Role reversal has none of that: last append stays at 2,100, `cf` stays at 2,800,
the drain headroom is unchanged, and the §3a item-1 phase band stays at exactly
100 / 499 / 599 (`PHASE_LATER = cf − skew − lastAppend − 1 = 2800 − 200 − 2100 −
1 = 499`), which `carrierRuntime.test.ts:1438-1446` pins.
**Keep the late-slot move in your pocket**: ship it only if step 3(c)'s data
shows a real-device `S` tail crossing 1,100 ms, and never rescale it below
W=2,000 without a full `--scenario=all` run.

**Privacy cost.** None. Same count, same routes, same sizes, same offsets,
byte-identical `scannedBytesPerWindow` (1,380,336) and `appendedBytesPerWindow`
(172,542). Offsets move uniformly for every client on a public profile.

**Spec deviation.** None — `appendSchedule` roles are free-form and every §4.3
inequality is untouched.

**Files.** `profile.ts` (6 role literals). The profile hash changes, so both
stores and both pages rebuild together — `--cohort` already does that atomically.

**Measurement.** `profileTool info` must still print `scannedBytesPerWindow
1380336` and `appendedBytesPerWindow 172542` — if either moves, the geometry
changed and the privacy claim is void. `carrierRuntime.test.ts:1438-1446` green
**untouched**.

> **Stop here and measure.** Steps 1–4 are ~200 LOC across five files, carry
> **zero disclosure and zero deviation**, and land at **≈ 22.6 s** — measured
> 22.0–24.3 s across 13 runs by three independent routes. That is −45 %, and it
> is the number you can defend without an asterisk.

---

### Step 5 — Fixpoint the ingest batch

*(COL-C5 / B-C5. Enabler; buys nothing alone, halves everything below it.)*

**Change.** `pairDriver.ts:751-767` makes exactly one pass over
`state.activePairOuterOperationIds`, which `coreReduce` sorts by operation id
(`coreReduce.ts:1589`) — i.e. randomly with respect to causality. Loop until a
whole pass makes no progress. **Two constraints:** do not re-run `coreReduce`
inside the loop (it would re-derive room state mid-drive and could re-observe a
peer, `pairDriver.ts:743`), and bound the passes at
`activePairOuterOperationIds.length`.

**Saving.** Zero alone. Without it, step 6 delivers its window **with
probability 1/2**.

**Privacy / deviation.** None. §4.11 constrains what may be *created*, not the
order a receiver drains one batch.

**Files.** `pairDriver.ts` ~10 LOC; `pairDriver.test.ts` ~40 LOC (one `ingest`
carrying an ACCEPT and an OFFER, in both orders, both handled in that call).

---

### Step 6 — The responder sends the first transport offer, with a pre-gathered ICE pool

*(COL-C1 / B-C1 + PROD-C7 in the pool form. First step with a price.)*

**Change.** `sendAccept` already calls `promoteEstablishedRoot` at
`pairDriver.ts:1313` *before* it publishes at `:1321`, so the responder can seal
a `TRANSPORT_OFFER` under `EstablishedPairRoot` in the same turn. ACCEPT rides
`identity-bootstrap`, the OFFER rides `safety-control` — two different role slots
in one window, no profile change. `handleIncomingOffer` / `handleIncomingAnswer`
swap role branches; `LazyTransportProvider` (`index.ts:293-333`) rebinds the
WebRTC offerer to the rendezvous responder.

**Mandatory companion — pre-gather an ICE *pool*, not one connection.**
`createOffer()` depends on no peer state. Gather `k` **independently generated**
`RTCPeerConnection`s at session start (fresh certificate, fresh ufrag/pwd each)
and consume one per attempt. Neither report proposed this form and both got the
sign wrong in opposite directions: gathering at start **fixes** the undisclosed
event-shaped leak (new §3a item 16 — with STUN/TURN configured, gathering
happens *if and only if* a rendezvous in this room reached the transport stage);
one session-long connection would reuse a DTLS fingerprint and an ICE ufrag
across attempts, linkable by any peer **and by any on-path observer watching the
STUN binding requests**. A pool gets both.

**Mandatory ordering constraint (visible only across two reports).** If you ever
also take the late-slot move, `identity-bootstrap` must sit at the **earlier** of
the two critical slots — the recommended step-4 permutation already does this
(ib 1,700 before sc 2,100). Reversed, a partially-late enqueue delivers an OFFER
the peer cannot open a window before its ACCEPT.

**Saving.** `F: 5 → 4`. **−1 delivery window = −4.0 s at W=4,000**, −1.0 s at
W=1,000. `E[floor]` 22.6 → 18.6 s.

**Privacy cost.** **None to a store** — `#eventsForWindow` schedules the same
five append POSTs whether the outbox holds nothing, one operation or two; the
responder's window goes from *one real + four cover* to *two real + three cover*,
which `#coverObject` (`carrierRuntime.ts:964-1000`) makes indistinguishable by
construction. Design §5's thirteen fixed requests are byte-for-byte unchanged.
**No §3a item is added or widened.** The recipient set is identical: the OFFER is
sealed under `EstablishedPairRoot`, derivable only with the HELLO response KEM
secret, held only by the endpoint whose identity the responder verified. Which
party discloses its address first flips from initiator to responder — a coin flip
per attempt either way, since the initiator is the lexicographically lower
presence id.

**Spec deviation — yes, named.** REQ-012 line 927 ("only after **both** identity
gates succeed"), spec:10184-10188 (the first offer as initiator key
confirmation), spec:10220 (`RendezvousRole=initiator` sends the first offer).
Permitted for a flagged prototype by spec:3392.

**Disclosure sentence (design §2 / §4.6, not §3a):**

> Named deviation, permitted for a flagged prototype by spec line 3392, from spec
> REQ-012 line 927, spec:10184-10188 and spec:10220: the responder emits its
> transport offer in the same delivery window as its `IDENTITY_ACCEPT`, after its
> own identity gate and before the initiator's. The offer is sealed under
> `EstablishedPairRoot`, which only the endpoint whose HELLO the responder has
> just opened, verified and admitted can derive, so the recipient set is
> identical to today's and a party the responder denied still obtains no SDP.
> What is given up is the property that the first transport offer proves the
> initiator received and admitted the ACCEPT — key confirmation moves from the
> offer to the answer.

**Files.** `pairDriver.ts` (~180), `index.ts` (~40), `webrtcProvider.ts` pool
(~60), `pairDriver.test.ts` (~120), docs (~70). **≈ 470 LOC, five files.**

**Measurement.** The milestone ladder must shorten from five rungs to four; the
responder's ACCEPT window must show **two** real appends (`appendsReal` in that
window); `windowShape()` in `carrierRuntime.test.ts` must stay green
**unchanged**; `--scenario=all` 4/4 including `kill-a`'s sharp assertion; the
wire audit must still find 0 of N needles with SDP needles for both pages.

---

### Step 7 — Shrink the class-1 carrier object to 8,448, behind three gates

*(SHRINK-C1 / A-C1. The largest single-line prize in the set, and the one the
correctness adversary KILLs if shipped bare.)*

**Change.** `profile.ts:116` `fixedCarrierObjectBytes: 73_728 → 8_448`. Leave
`OPERATION_PAYLOAD_CLASS_BYTES` completely alone (see §4 — changing it is a
kill). Measured: class 1 is **100 % cover in this prototype** — proved by running
with the class-1 payload pinned at 4,097 bytes, one byte above class 0, and
passing. The transport flights are class 0 in every recorded run: complete-ICE
SDP measured at **692 B** with no ICE servers and **1,002 B** with one STUN
server, against a class-0 ceiling of **3,613 B**.

**The three gates. Without all three this is a KILL, not a risk.** As written it
ships a profile in which payload class 1 has no size class that fits it, which
`validateDeliveryProfileGeometry` does not check — and the resulting throw in
`buildCarrierPlaintext` is **caught deliberately** by `#buildObject`
(`carrierRuntime.ts:900-923`, verified), which drops the outbox entry, emits a
`missed` event and sends cover. The failure mode is therefore **not** a failed
edge, as `angle-shrink-class-1` claims: the client's traffic is unchanged, the
operation silently vanishes, no error reaches the user, and the rendezvous hangs
to the harness deadline. `maxConsecutiveMissedAppendOpportunities` is validated
at `profile.ts:101` and **enforced nowhere in `src/`** — nothing will notice.

1. **SHRINK-C5 — the spec's own §4.12 fallback** (spec:10396-10398): compute the
   padded class before committing; if the offer would not fit, emit an offer
   holding only `operation-carrier` and surface a typed "no WebRTC path on this
   network" outcome. **Two call sites, not one** — `buildOfferCandidates`
   (`transportCandidates.ts:135-146`) always emits `webrtc-complete`, and
   `selectWebRtcCandidate` (`:184-188`) hard-fails on a carrier-only offer, so
   the *responder* converts the soft failure back into a `failEdge`.
2. **Three lines in `validateDeliveryProfileGeometry`** asserting
   `fixedCarrierObjectBytes >= OPERATION_PAYLOAD_CLASS_BYTES[c] + 255`, with the
   prototype's violation as an explicit named allow — so the incompatibility is
   *stated by the validator* rather than silent.
3. **Step 3(b)'s class assertion**, already shipped.

**Saving.** **Zero seconds at W=4,000 after steps 1–2** — same floor. What it
buys is everything a store fix cannot: sustained downlink **5.5 → 1.3 Mbit/s per
idle client**, uplink **690 → 168 kbit/s**, store disk **4.1×** — and it is what
makes the short window work: measured **11.1–11.6 s at W=2,000, 4/4 scenarios**,
where the pinned geometry stalls outright.

**Privacy cost.** New §3a item 19 (§6). No new store leak, no widened one, **and
no anonymity set shrinks** — the cohort was never an anonymity set against a
store, which issues the lease, signs the admission over
`(lease, sizeClass, objectOrdinal, object)` and places the object at coordinates
it computes. The crowd a client hides in comes from the *fixed full scan*, which
is untouched. One honest cost in the same sentence: it cuts by 4× the price of
archiving a room's entire traffic, and carrier objects are sealed under a
non-rotating `RoomRoot` and retained ~7.4 days.

**Spec deviation — yes.** `RoomProfileCompatible` at spec:4605-4607. Permitted by
spec:3392.

**Files.** `profile.ts` (1 line), `transportCandidates.ts` + `pairDriver.ts`
(~40 for the fallback), `profile.ts` validator (~3), docs (~25).

**Measurement.** `profileTool info` prints `scannedBytesPerWindow: 335856`;
`appendsReal` unchanged at 8; `--scenario=all` 4/4 at W=4,000 **and** at
W=2,000; the wire audit still 0 needles; a negative test that an oversized SDP
produces the typed "no WebRTC path" outcome, not a `missed` line.

---

### Step 8 — Shorten the delivery window

*(DISC-D7. The only remaining lever, and the only one whose privacy cost is
intrinsic rather than incidental.)*

**Change.** `--window-ms=2000`, then `--window-ms=1000` with
`publicChunkObjectCount: 8 → 24` and both `publicChunksPerWindow → 1` (SHRINK-C4;
the validator recomputes them and rejects a literal that disagrees).

**Saving.** Measured, with step 7 in place, cohort 8:
**W=2,000 → 11.4–11.6 s, 4/4 scenarios**; **W=1,000 + `pcoc` 24 → 7.5–9.4 s,
4/4 scenarios** (W=1,000 without `pcoc` 24 is 3/4 — `kill-a` fails because the
surviving store misses the 1,000 ms append deadline).

**Privacy cost — the framing everyone uses is wrong, and the true version is
worse in one way and better in another.** *Better:* the per-window crowd does not
shrink — same cohort, same 40 objects, same fixed full scan, same real/cover
indistinguishability, and `minMeasuredSharedCohort` is unaffected by `W`.
*Worse:* §3a item 1's cross-store join is per-window and already has 0 ms
separation, so shortening `W` multiplies the joinable write-pairs per session —
a rendezvous spans ~11 windows at W=4,000 and ~44 at W=1,000. **The confidence of
the worst disclosed leak scales as 1/W, and so does sustained bandwidth.**
`pcoc` 24 additionally raises scan bytes 335,856 → 404,256 (+20.3 %) and changes
§5's fixed trace from **thirteen requests to ten**, and eight of each class-1
chunk's twenty-four slots are **store-authored** padding — indistinguishable to a
third party, but not cover against the adversary this design is built for.

**Spec deviation.** None (`deliveryWindowMs` is a profile value).

**Three absolute constants come under it, none of which scales with the store's
speed** — this is why every `--window-ms` must be re-measured, never
extrapolated:
`requestDeadlineMs = deliveryWindowMs` (`storeClient.ts:276-283`);
`maxScheduleSkewMs` is scaled by `withDeliveryWindowMs` (`profile.ts:425-459`),
so at W=1,000 the conforming drift band is **50 ms** and browser timer coalescing
alone exceeds it; `MAX_OBSERVED_CHECKPOINTS = 256` is reached after ~17 min at
W=4,000 and **4 min at W=1,000**, after which `#verifyChain` re-verifies a
256-entry chain twice per window forever (unmeasured — measure before optimising,
SCAN-C8).

**Measurement.** `--scenario=all` 4/4 at every window you intend to quote, with
step 3(a)'s `window-finalized` assertion armed. Re-run the whole cohort table.

---

### Optional, after the sequence — three that are worth their price only in context

| Candidate | Buys | Price | When |
| --- | --- | --- | --- |
| **Cold-start current-window allocation** (SCHED-C2 / DISC-D2) | 1 window (4.0 s) for ~48 % of start phases, E[1.9 s] | **new §3a item 18** + named deviation from spec:5832, 5835, 5875-5877 | only after step 1 — today the allocation POST takes p50 1,394 ms against a 300 ms budget, so the guard fires, misses the slot anyway, and widens the first-window tell for nothing |
| **Don't let the slow store gate the fast one** (SCAN-C7) | 0 on the healthy path; up to 1 window *per flight* when a store is slow | `carriedBy` and `#queueBackfills` must be computed from the **joined** set, and `#witness` must stay on the joint path — otherwise every healthy read spawns backfills and item 14 gains latency resolution | when the degraded scenarios matter |
| **Standing presence, identical bytes** (DISC-D5 / PROD-C2) | **0 s.** Fixes a claimed *permanent* deadlock for peers who start more than ~1 window apart | **new §3a item 20** (a retroactive liveness trace), plus a mandatory republication cap and a fault-masking guard | **only after `run.mjs --stagger-ms=12000` fails on current code.** Nobody has run it; the deadlock is a code reading. It is robustness, not speed, and must be argued as such |

**Two constraints on the standing presence that are not optional:** republish the
**identical bytes**, never a rotated presence (a fresh presence per heartbeat puts
two live presences per author in the room, `observePeer` picks the first by
operation-id order, the two endpoints bind different `pairEdgeId`s and the HELLO
fails the edge permanently); and keep **at most one outstanding heartbeat entry**
at a time (the class-0 `state-replication` slot is shared with every backfill, and
`#pendingEntry` is strict FIFO). Note also that its self-heal claim is false:
`#onOperations` fires only when `fresh.length > 0` and `#seen` already holds the
republished id, so a peer that already saw the presence gets nothing — step 5 is
the fix for a deferred handler, not the heartbeat.

---

## 3. Projected end state

```
T = (C + F)·W + r + S − p + M·W
```

`C` = cold-start window (1), `F` = dependent flights, `W` = delivery window,
`r` = `publicReadOffsetMs`, `S` = scan wall, `p` ~ Uniform[0, W), `M` = answering
flights that miss their own slot.

| Stack | W | F | M | E[T] | Confidence |
| --- | ---: | ---: | ---: | ---: | --- |
| today | 4,000 | 5 | 4 | 40.6 s | **measured** 35.5–41.9 s, 8 runs |
| steps 1–4 | 4,000 | 5 | 0 | **22.6 s** | **measured** 22.0–24.3 s, 13 runs, three routes |
| + steps 5–6 | 4,000 | 4 | 0 | 18.6 s | **projected** (the F=4 collapse has never been run) |
| + step 7, W=2,000 | 2,000 | 5 | 0 | **11.3 s** | **measured** 11.1–11.6 s, 4/4 |
| + steps 5–6 at W=2,000 | 2,000 | 4 | 0 | 9.3 s | **projected** |
| + step 8 (`pcoc` 24), W=1,000 | 1,000 | 5 | 0 | **5.7 s floor; 7.5–9.4 s** | **measured**, 4/4 |
| **+ steps 5–6 at W=1,000** | 1,000 | **4** | 0 | **4.7 s floor; ≈ 6.5–8.4 s** | **projected** |
| + cold-start reclaim | 1,000 | 4 | 0 | ≈ 6.0–7.9 s | projected, ~50 % hit rate |

**The number to quote: ≈ 7 s to first message at W=1,000, cohort 8** — call it
**41.8 → 7 s, a 6× improvement**, of which the profile-and-store part
(41.8 → 7.5–9.4 s) is **measured across 4/4 fault scenarios** and the
flight-collapse part (−1.0 s) is **projected**. If you want a number with no
projection in it at all, it is **7.5–9.4 s, measured, −78 %**.

**The new structural floor** is `W × (1 + F) + r − W/2`. At W=1,000, F=4 that is
**4.65 s**, and it is made of: one cold-start window, four dependent flights, and
the read offset. To go below it you must remove a flight, and §4 shows every
remaining way to do that is a kill or needs a gate the prototype cannot build.

**What could make this wrong, in order of likelihood.**

1. **`S` on a real device.** Every `M = 0` claim is a step function of `S`,
   measured once, headless, on loopback, with both stores in one process tree.
   There is no distribution and no tail. A device whose `S` crosses the budget
   falls silently back to two windows per flight — 22.6 s becomes 40 s with no
   warning and no degraded label. Step 4 buys 400 ms of margin against that; step
   2 buys 60×.
2. **The steps 4 + 7 + 8 stack has never been run together.** Step 4's
   role-reversal is chosen *precisely* to avoid the composition hazard (it does
   not touch drain headroom), but that reasoning is arithmetic, not a run. Do not
   quote a stacked number without a stacked `--scenario=all`.
3. **ICE gathering in production is unpriced and worth a whole window per
   transport flight.** `DEFAULT_GATHERING_TIMEOUT_MS = 15,000`; the harness uses
   `iceServers: []`. Step 6's pool removes it from the critical path; without
   step 6, budget for it.
4. **Everything is Chromium-only.** Every SDP number, every class-selection
   argument. spec:10394-10396 asks for the full browser × ICE × TURN ×
   IPv4/IPv6 matrix; it has never been run.

---

## 4. What was rejected, and why

So nobody re-proposes it.

| Candidate | Why it is dead |
| --- | --- |
| **Shrink payload class 1 to 8,192 or 36,864** (SHRINK-C2/C3) | `OPERATION_PAYLOAD_CLASS_BYTES` is not prototype-scoped — five non-prototype call sites — and `tests/blindRendezvous/projections.test.ts:246-252` pins class 1 above 65,490 with the comment "Class 1 must hold the existing 65,490-byte protocol-v4 control frame", which settles the maintainer question the report raised. |
| **Class 1 → 4,097** (SHRINK-C6) | Not measurably faster than 8,448 at any window where both work, and it deletes the large-body class outright. |
| **Speculative offer under a HELLO-derived root** (COL-C2) | Its gate must refuse every non-open policy, and **the prototype has no admission kernel** — the gate would be a constant and its refusal test vacuous. Revisit when `Admit()` exists. Also: `promoteEstablishedRoot` wipes `HelloRoot` (`pairDriver.ts:1528-1533`), so the child must be derived before that or the fast path works only when the offer arrives first. |
| **SDP inside HELLO/ACCEPT** (COL-C3) | 1,136 bytes of SDP headroom with **no class-1 bootstrap form to grow into** (`pairStepEnvelope.ts:112-115` fails closed), so it dies at ~5 ICE candidates — one STUN server already produces four — and the throw is swallowed into a silent hang. |
| **Room-keyed identity beacon** (COL-C4) | A new byte in the closed `PairStepKindV1` registry, a stable identity broadcast to *every* capability holder rather than the selected one, and a pair root resting on one hybrid KEM encapsulation instead of two — three deviations for one window. |
| **Transport parameters inside PRESENCE** (PROD-C3) | It converts a live-only disclosure into a **seven-day archive of every member's public IPv4, IPv6 and DTLS fingerprint**, readable by anyone who later obtains the capability, in a project whose headline promise is forward secrecy; forfeits AC-005's final clause (spec:11697-11699); and its `maxRoomMembers === 2` gate will not survive a "join by link" feature. Worst of all, the privacy audit would keep printing "0 of 148 needles found" truthfully for a run in which every member's IP was broadcast. |
| **Warm start from a retained peer presence** (PROD-C1 / DISC-D6) | The peer's HPKE receiver secret is generated at `start()` and wiped at `destroy()` and nothing persists it, so a warm HELLO opens for nobody if the peer restarted — and if it did not restart, its `remotePresence` is already bound and the HELLO's `expectedPairEdgeId` check **kills the peer's live edge**. |
| **Store as a fast SDP drop** (PROD-C6) | A location derived from `EstablishedPairRoot` is a deterministic peer-equality handle at the store, which spec:480-482 forbids in as many words. |
| **Legacy signaling as a fast path** (PROD-C8) | It hands one server every item on spec:494-505 plus the connection-side one; makes the blind path event-shaped (its *stopping* becomes the signal); and a client that is sometimes blind has no honest statement to make about any session. |
| **Long-lived push read** (PROD-C9) | Replaces thirteen fixed requests with one connection whose *lifetime* is a per-client observable joinable across both stores at sub-millisecond precision — §3a item 1 made stronger — for 0.6 s per flight that step 1 already delivers. |
| **`publicReadLagWindows` → 0** (SCHED-C5 / DISC-D9) | Inside a window the validator forces `append → finalize → read` as a total order, so the cadence is exactly `W` under lag 0 and lag 1 alike: it buys a one-off ≤1.7 s phase shift and spends the margin spec:5844 pins it for. |
| **`publicReadOffsetMs` → 0** (SCHED-C3 / DISC-D3) | At `r = 0` a fast clock reads an unfinalized window, and a `not-final` scan **suppresses the witness pair** (`carrierRuntime.ts:1263-1268`), so the fixed request count silently drops 13 → 11 for exactly the clients with fast clocks. Survives only at `r ≥ maxScheduleSkewMs`, where it is worth 0.4 s **once** — not per flight. |
| **Read early / negative read offset** (SCAN-C12) | Same reason: `finalizeDue` polls on a 250 ms interval behind that window's appends, so "the data exists at `cf`" is a statement about the clock, not the finalizer. |
| **Pre-AEAD recipient hint** (SCAN-C9) | The trial AEAD **is** the unlinkability mechanism — every plaintext-visible header field is a bucket coordinate identical for all 40 objects — and a `RoomRoot`-derived hint gives a future capability holder an O(1) sieve over seven days of archive, to save 2.9 ms of a 1,450 ms scan. |
| **WebCrypto for the AEAD** (SCAN-C10) | WebCrypto has no XChaCha20; substituting an AEAD is forbidden by SEC-002/SEC-019; the prize is part of 4.0 ms. |
| **One request for the whole window** (SCAN-C11) | Deviates from REQ-007, spec:5837-5841 and AC-049, shrinks §5's fixed trace 13 → 9, and saves 0.36 ms after step 1. |
| **CDN in front of the immutable routes** (SCAN-C6) | Buys nothing in the harness; in production a shared CDN makes the two stores **one observation domain** and hands §3a items 1 and 2 to one party pre-computed. Deployable only with verified distinct operators and ASNs per store, named in §3a item 8. |
| **Shrink class 0's carrier object** (DISC-D8) | Worth 0.10 s today and ~0 after step 1. (The privacy objection to it is wrong — the padding that hides payload length is the codec's, not the carrier's — but it is still not worth the profile churn.) |
| **A second append slot per critical role** (SCHED-C4) | Worth zero while `M = 0`, costs +4.8 % scan and turns §5's thirteen requests into fourteen, and is partly self-defeating (a bigger scan is a bigger `S`). It is the right answer to a measured real-device `S` tail, and the wrong answer to "make it faster". |
| **Rotating standing presence** (PROD-C2's fresh-presence form) | Multiple live presences per author → `observePeer` picks the first by operation-id order → the two endpoints bind different `pairEdgeId`s → permanent `failEdge`. Take the identical-bytes form. |
| **Fold identity into `PresenceCoreV1`; both sides offer, lower id wins; ICE-lite; trickle ICE over the carrier** | Respectively: a strictly worse room-keyed beacon; WebRTC will not accept a peer's independent offer as an answer; the DTLS fingerprint cannot be derived from a shared secret; trickling costs *more* flights. |

---

## 5. The fast path's policy gate

The prototype runs one policy — open, `Admit()` is a no-op, and the admission
kernel is **not implemented**. So these gates protect a future, which is exactly
why `angle-product-shape` §9.3 is right that they must be enforced at the **type**
level (a distinct room type) and not by a runtime `if` that a product decision
three quarters later will relax with no memory of this document.

| Step | Refused under | What the code must check |
| --- | --- | --- |
| **1, 2, 3** store fix + harness | never | nothing — no wire byte changes |
| **4** role reversal | never | nothing — a public profile field, uniform for every client |
| **5** ingest fixpoint | never | nothing — receiver-side batch drain order |
| **6** responder offers | **never required.** Each side still releases SDP only after its **own** `Admit()`, so §1.6's "a client that is denied by the receiving frontend obtains no SDP/ICE from that endpoint" holds verbatim in both directions | Optional defence-in-depth flag: prefer the strict spec ordering when `admissionFloor.mode !== "capability"` or the frontend is in `onlyConnectWithKnownPeers`. Default fast in open mode |
| **7** class-1 carrier shrink | never on policy grounds — it is a *capability* limit (SDP ≤ 3,613 B), not a disclosure | the §4.12 fallback must fire on class, not on policy |
| **8** shorter window | never on policy grounds | but the 1/W scaling of §3a item 1 must be re-disclosed at each window |
| **cold-start reclaim** | never on policy grounds | — |
| **standing presence** | not refused, but **coarsen `k` in any room with more than two capability holders**: every republication carries the same `stableIdentityCommitment(roomContextId, stableKey)`, so a room-wide liveness trace grows with the holder count. In `local-address-book-proved` / `authority-permit-proved` rooms the presence also carries eligibility proof, which republication multiplies | `roomPolicy.maxRoomMembers` (default **64**, `roomPolicyV4.ts:200`) and `admissionFloor.mode` |
| **speculative offer** (rejected; if ever revived) | **`eligibility !== "open"`; `local-address-book-proved`; `authority-permit-proved`; any denylist-with-teeth or `onlyConnectWithKnownPeers` frontend; `maxRoomMembers > 2`; a reusable capability** | all four, at the type level, with a refusal unit test |
| **params in PRESENCE** (rejected) | everything except a two-party single-use room *type* | — |

**PIN is not a gate and must not be sold as one.** The PACE/PIN step runs inside
protocol-v4 *after* the data channel exists (`mode: "nopin"` is passed to
`createSession`, `index.ts:699`), so it cannot gate SDP release. An IP address
disclosed before the session exists is disclosed whether or not the session is
later MITM-proof. A PIN room needs the **same** gates as an address-book room for
anything that moves SDP earlier — and gets none of them from the PIN.

---

## 6. The disclosure delta

### 6.1 Owed today, before any of this ships

Three residual leaks describe the prototype **as merged** and are not caused by
any candidate. The outward doc's discipline — "claim no labels, disclose
everything" — is what makes them owed. Numbering continues from §3a's fourteen.

> **15. The first window of a session is a different shape.** `#nextEvent`
> skips any scheduled event whose instant has already passed
> (`carrierRuntime.ts:660-673`), so a client that starts at phase `p` into a
> delivery window issues only the events after `p`: measured at **9 requests and
> no append bodies in the start window against 15 requests and 174,470 bytes in
> every later one**. A store therefore reads off its own log, with no cooperation
> from anyone, both that this client's session began in this window and — from
> which of the scheduled offsets are present — the start phase to within one
> offset gap. The descriptor GET, issued once per store per session rather than
> per window, states the same bit again. This is the alignment anchor a
> cross-store observer would use before anything else, so it sits directly
> against item 1. `windowShape()` in `carrierRuntime.test.ts` does not cover it,
> because it asserts steady-state windows.

**Superseded by what shipped.** The mechanism above is right and is now design
§3a item 15, but its number is not: the start window carries a descriptor GET,
exactly one allocation POST and every scheduled request at an offset `≥ p`, so
the reachable totals at the pinned profile are 16, 15, 7, 6, 5, 4, 3 and 2 —
**9 is not one of them**, and below `publicReadOffsetMs` the start window is
indistinguishable from a steady-state one by count. Read design §3a item 15,
not this draft. (`observed.md` §8, corrected; `stage-1-fixround-report.md` §2.)

> **16. ICE gathering is event-shaped, on a route the fixed schedule does not
> cover.** Item 4 requires the polling shape to stay schedule-shaped and never
> event-shaped, and it is stated about the store routes. `createOffer()` and
> complete ICE gathering run only when a pair has been found, both identity gates
> have passed, and the transport flight is being built (`pairDriver.ts`,
> `sendOffer`, measured at 126–137 ms after `accepted`). With any STUN or TURN
> server configured — the recorded runs use `iceServers: []` and therefore cannot
> see this — a client emits gathering traffic **if and only if a rendezvous in
> this room reached the transport stage**, at a predictable offset inside one
> delivery window. An on-path observer or the STUN/TURN operator learns that a
> rendezvous is in progress and at what stage without reading a carrier byte.
> Gathering once at session start, before any peer is known, removes the
> correlation; gathering again per pair attempt restores it.

> **17. The per-window request count is a room counter.** One carrier runtime
> holds one `RoomRoot` and runs one scheduler per store, so a client with `K`
> open rooms issues `13K` fixed requests per store per window from one source
> address at the same six offsets, and a store divides its own log by thirteen to
> read `K` and to join all `K` rooms' traffic to one address. Item 2 discloses the
> address; it does not disclose the multiplier. The profile field that exists to
> fold several rooms behind one fixed per-client object count,
> `roomSlotsPerClient`, is pinned to 1 and unused.

### 6.2 Three sentences already false, to correct with step 1

**(a) Outward doc `:446-449` blames the browser for something it does in 8 ms.**
Replace:

> ~~"At cohort 8 the browser cannot finish 1.38 MB × 2 stores of scanning and
> sealing between the read offset (600 ms) and the last append offset (2,100 ms)"~~
>
> At cohort 8 the **store** cannot serve two clients' scans between the read
> offset (600 ms) and the answering append offsets. The browser's entire
> per-window work — decode and trial-open of all 40 carrier objects, 1,380,336
> bytes — is **4.0 ms per store, 8 ms for both**, measured in the same headless
> Chromium the harness uses.

**(b) The cohort table's causal paragraph, and the table itself.** Do **not**
delete the table — a recorded measurement that a later change made obsolete is
exactly what this project keeps. Add above it:

> The cohort table below was measured against a store whose chunk GET rebuilt the
> entire window document with a hand-rolled hex codec on every request, at a flat
> ~97 ms per request regardless of the chunk requested. The cohort appeared to
> buy latency because it sizes that document. With the codec replaced, the
> per-request cost is not linear in the cohort in the same way, the "per flight"
> column collapses to one window at every row measured, and
> `cohortAllocationsPerWindow` can be chosen for what it is actually for — how
> much unrelated traffic a client's objects sit among — rather than for speed.
> The rows are retained as a record of what was measured at profile hash
> `83a2261e…` on the pre-fix store, not as a current cost model.

**(c) "Thirteen fixed requests … whether the client is idle or mid-rendezvous"
is true only after the first window.** Add the qualifier and point at item 15.

**(d) Correct `observed.md` §4e at the source** before anyone quotes it: the cost
is `bytesFrom`/`hexOf` at `storeSqlite.ts:68-78`, not `JSON.parse` (0.30 ms).
Four reports cite the wrong line. And `observed.md` §3's flight table attributes
the transport flights to the class-1 slot at 1,500 ms; every recorded transport
flight is class 0 at 1,700 ms.

### 6.3 New, per step

**Step 4** — design §4.2, one sentence:

> The append roles are ordered so that the two roles on the critical path
> (`identity-bootstrap`, `safety-control`) get the later slots and
> `state-replication`, which carries only PRESENCE and is never on it, gets the
> earliest. The offsets, `chunkFinalizationOffsetMs`, `scannedBytesPerWindow`
> (1,380,336) and `appendedBytesPerWindow` (172,542) are unchanged, every §4.3
> inequality holds unchanged, and the per-store phase band of §3a item 1 is
> preserved at exactly 100 ms earlier / 499 ms later / 599 ms wide.

**Step 6** — design §2 and §4.6 (steps 8 and 9 swap): the named-deviation
paragraph quoted in §2 above, plus:

> Pre-gathering creates a small pool of independently generated
> `RTCPeerConnection`s at session start, one consumed per pair attempt, so ICE
> gathering no longer happens if and only if a rendezvous reached the transport
> stage (item 16) and every attempt still carries a fresh DTLS certificate
> fingerprint and fresh ICE credentials.

**Step 7** — new §3a item 19, plus the §4.12 note:

> **19. Size class 1 carries no real object, and it is 86 % of every client's
> traffic.** The pair codec routes a step to class 1 only above 3,613 bytes of
> SDP, and complete-gathering SDP measured in the supported browser is 692 bytes
> with no ICE servers and 1,002 with one STUN server, so class 1 is cover in
> every recorded run — confirmed by a run with the class-1 payload pinned to
> 4,097 bytes, one byte above class 0, which passed. Shrinking the class-1
> carrier object to 8,448 bytes changes the size table in §5 and nothing else a
> store sees, and it shrinks no anonymity set, because a store binds every object
> to a lease it issued and to the address that requested it. It does cut by the
> same factor the cost of archiving a room's entire traffic: carrier objects are
> sealed under a non-rotating `RoomRoot` and retained for
> `carrierRetentionWindows`, so a capability obtained later opens the whole
> archive, and cheaper archival is a real cost to set against the bandwidth win.
> This is a named deviation, permitted for a flagged prototype by spec line 3392,
> from `RoomProfileCompatible` at spec:4605-4607: payload class 1 has no usable
> size class in this profile. An offer that would exceed the class-0 ceiling is
> refused before it is committed and reported as "no WebRTC path", not carried
> and not silently dropped. The SDP measurements are Chromium-only;
> spec:10394-10396 asks for the full browser × ICE × TURN × IPv4/IPv6 matrix and
> it has not been run.

**Step 8** — outward §6 and design §4.2:

> At delivery windows shorter than 4,000 ms the per-window anonymity properties
> are unchanged — same cohort, same forty objects, same fixed full scan, same
> real/cover indistinguishability — but the number of cross-store joinable events
> per session, and the sustained bandwidth per idle client, both scale as 1/W. A
> rendezvous spans about eleven delivery windows at 4,000 ms and about
> forty-four at 1,000 ms, so an observer of both stores' logs obtains four times
> as many independent confirmations of the join that item 1 discloses. With
> `publicChunkObjectCount` at 24 the fixed trace of §5 becomes **ten** requests
> per client per store per window rather than thirteen, and eight of each
> class-1 chunk's twenty-four slots are store-authored padding: indistinguishable
> to a third party, but not cover against a store.

**Cold-start reclaim (if taken)** — new §3a item 18:

> **18. Cold start allocates twice.** A client that starts early enough in its
> window requests a lease for that window in addition to the scheduled request
> for `w+1`, so the first window of a session carries two allocation POSTs where
> every later window carries one; with item 15 the first window becomes fully
> self-identifying. The byte-identical-replay variant does not remove the bit — a
> store must recognise those exact bytes to return the same lease, so the count is
> levelled while the content still separates cold start from steady state. The
> only genuinely shape-preserving form is two *fresh* allocation requests every
> window, one for `w` and one for `w+1`, which halves the distinct clients one
> window's cohort admits unless `cohortAllocationsPerWindow` is doubled.

**Standing presence (if taken)** — new §3a item 20:

> **20. A standing presence is a retroactive liveness trace.** Republishing the
> identical PRESENCE bytes into the `state-replication` slot changes nothing a
> store sees — that slot fires with cover otherwise, and cover and real are the
> same bytes sealed with the same work at the same instant — but every
> republication carries the same `stableIdentityCommitment(roomContextId,
> stableKey)`, so any capability holder joins them into one endpoint's online
> interval at the delivery window's resolution. Because carrier objects are
> sealed under a non-rotating `RoomRoot` and stores retain them for
> `carrierRetentionWindows` (~7.4 days at the pinned window), a capability
> obtained after the fact turns that interval into an activity trace over the
> whole retention horizon, for every member who republished. Republication is
> therefore bounded by `presenceRepublishWindows`, stops the moment an edge is
> established, and its interval is a privacy parameter rather than a tuning
> constant.

### 6.4 The reproducibility ledger

Every recorded artifact that stops being true, and must be re-run rather than
carried over:

| Change | What dies |
| --- | --- |
| Steps 1–2 | outward §6's entire cohort table and its causal paragraph; outward §4's four scenario times; `observed.md` §3/§4c/§4d wholesale; the "per flight 8.0 s = 2 windows" column |
| Step 4 | profile hash `83a2261e…` everywhere it is quoted; design §5's offsets column; outward §3's offsets row |
| Step 7 | design §5's "each append carries 8,192 or 73,728 ciphertext bytes"; outward §6's scan-byte column; the 2,763,134 B/window and 59.7 GB/store/day retention numbers (they fall 4.1×) |
| Step 8 | design §5 and outward §3's "thirteen fixed requests" → ten |
| **Any of them** | **outward §5's audit corpus counts.** A 22 s run has roughly half the request bodies of a 41.9 s run, so "0 of 148 needles in 345 bodies" becomes "0 of 148 in ~180". The audit's strength is partly its corpus size; record the new numbers, do not carry the old ones. |

And one that is not a doc: outward §6's `--cohort=8` faithfulness check compares
the rebuilt profile hash against the pinned literal. **Change the literal and the
rebuild in one commit** — split across two, the harness's own faithfulness check
is comparing a new literal against an old rebuild.

---

## 7. If you only do one thing

Step 1. Twenty-five lines in one file, no disclosure, no deviation, no wire byte,
and it removes the cause of 38 % of the run — plus a 0.9–1.5 CPU-second-per-window
load factor that is silently distorting every other measurement anyone has taken
on this system.

## 8. If the honest answer is "blind rendezvous cannot be fast"

It can be fast *enough* — ~7 s, measured — but not free. The floor is
`W × (1 + F)`, and each of the three ways below it costs something specific:

- **Shorter `W`**: the confidence of §3a item 1's cross-store join, and the
  sustained bandwidth, both scale as 1/W. **Measured, disclosable, recommended.**
- **Fewer flights**: one flight is available for an ordering deviation and no
  disclosure (step 6). The second one always costs the initiator's admission
  gate — SDP released to a presence author whose stable identity it has never
  verified — and in any room that is not two-party-with-a-single-use-capability
  that is an IP-address harvest with no signed artifact. **Not recommended, and
  not buildable today: the prototype has no admission kernel to gate it.**
- **Event-shaped traffic**: every deployed identifier-free messenger that is fast
  (Nostr, Signal, Cwtch, Session) is fast because it is event-shaped, and every
  research system that is fast *and* server-blind buys it with ≥4 servers (Arke,
  <0.5 s) or a TEE. p2party's prototype is the only design in that set that is
  fixed-schedule, two-server, TEE-free and browser-native. **You are not slow
  because you did something wrong; you are slow because you chose the one
  property none of them has** — and that sentence is worth more at FOSDEM than
  the last two seconds.
