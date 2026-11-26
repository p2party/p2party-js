# The blind rendezvous two-store prototype

Date: 2026-09-08. Status: **flagged internal prototype**, outside the package
surface, on the branch `feat/blind-two-store-prototype`.

This document describes a working demonstration: two headless browsers that
share nothing but a 32-byte room capability find each other through two
independently-run store processes, negotiate a real WebRTC connection with no
signaling server anywhere in the test, and exchange encrypted application
messages over the SDK's existing protocol-v4 session.

It is a demonstration of a **shape** — that the pieces compose, that the client
survives one store failing or lying, and that the store's request bodies did not
contain the secrets the harness looked for. It is not evidence of a **property**.
Where the two could be confused below, the text says which one it means.

The design that this implements is
[`blind-rendezvous-two-store-prototype-design.md`](blind-rendezvous-two-store-prototype-design.md).
Every number quoted here comes from the harness's own recorded runs in
[`e2e/blind-two-store/README.md`](e2e/blind-two-store/README.md), from the unit
suite, or from a command named in the text. Nothing here is measured a second
time in prose.

---

## 1. What this does not claim

Read this section before the rest. It is first because the prototype is the
kind of artifact that gets quoted out of a summary, and because most of what
makes it interesting is also what makes it easy to overstate.

**It has no label.** The specification
([`spec/spec-architecture-l2-blind-rendezvous.md`](../spec/spec-architecture-l2-blind-rendezvous.md))
defines a vocabulary of privacy tiers, threat models and release gates. None of
its names are claimed here. They are named below only so that nobody has to
guess whether an omission is an oversight, and only as the things this work does
**not** earn: not `S1`, which the spec defines as its *single-carrier safety
baseline* and which explicitly excludes availability, global completeness,
traffic-source anonymity and omission tolerance; not `R2-BEC`; not `SP1`, the
spec's *bounded measured public-store source unlinkability* package; not its
`L2` or `L3` control-compatibility statements; not "anonymous"; not
"censorship-resistant"; not Byzantine fault tolerance; and not
`conformant`. It is likewise not the `v0.4` release surface: the specification
says implementations "shall not independently invent release bytes and call
them v0.4", so every route path and every media type in this prototype says
`prototype-v0` instead. Those bytes are not interoperable with the frozen §4.6
route family and are not a proposal for it.

**Admission is open, and allocation is open.** The specification's admission
kernel — `Admit()`, reservations, trials, topology custody, the CAS captures —
is not consulted at any point. Any capability holder is admitted, which the code
says out loud: the function that opens an incoming identity flight is named
`openIdentityHelloOpenPolicyPrototype` and its docblock states the bypass.
Allocation is equally open: the Privacy Pass issuance path is stubbed by a store
mode that ignores the token bytes and answers `issued` with 32 zero bytes.
There is therefore no abuse control of any kind, and no Sybil or fairness claim
follows from anything in the prototype.

**Two stores buy availability, not privacy.** Either store may fail or withhold
and the rendezvous still completes; that is what the scenarios show — and they
show exactly two fault modes, both of which fail fast. A third, a store that
accepts the connection and then answers nothing, is defended in code (every
request carries a deadline; §3) and covered by a unit test, and by **no
end-to-end scenario**. Adding one is follow-up work. Adding the
second store moves no privacy statement in the other direction either — but which
observer is meant matters, and the rest of this document is careful about it.
*For the two stores themselves*, collusion gains nothing: both already see the
same source address at the same instants, so the join they could perform on
timing is redundant with the join they can already perform on the address. *For a
network observer who holds both stores' request logs but not their clients'
addresses*, it is not redundant at all — replicating one operation to two stores
milliseconds apart is exactly what lets such an observer link the two logs, and
§7 calls that the worst residual leak and reports it as unmitigated and measured.
The two sentences are about different observers and neither dismisses the other.

**Two store processes on one laptop are one fault domain.** They share a kernel,
a disk, a clock, a power supply and an operator. Nothing in any recorded run is
evidence that two stores would fail independently. What the runs show is that
the *client* keeps working when one store stops or lies, which is a different
statement. Independence, in this design, is a business fact — operator, ASN,
hosting, jurisdiction, funding — that has to be stated and audited, not a
cryptographic one that a test can establish.

**Detection, not prevention.** A client here can detect forged or altered
entries, replays, and disagreement between what a store promised and what it
published. It cannot prevent any of them. Omission evidence needs signed
checkpoints; a targeted split view needs a second observer. Both stores
colluding on omission is undetectable, as is an omission that happens before any
checkpoint exists to compare against.

**The `withhold` fault mode is not adversary-grade.** The store answers `stored`
to *every* append, including a repeat of bytes an honest store would have
answered `already-present` for. A real adversary would not be caught this way —
a client that re-appended the same object could tell the two apart. What the
scenario exercises is the *detection path*: the client holds a signed receipt
naming a slot, reads that slot out of the finalized chunk, hashes it, and finds
bytes the store never received. Receipt-versus-slot comparison is under test.
Indistinguishability is not.

**The privacy audit covers request bodies on one run.** Its exact scope, and the
three things it does not cover, are in §5. The one-sentence version: it says
that on a particular run, a particular set of byte needles did not appear in a
particular corpus of POST bodies. It says nothing about what a store could
infer, nothing about request URLs, and nothing about source addresses, timing or
sizes — all of which both stores see.

**Nothing in it is reachable from the SDK.** The prototype lives entirely under
`src/blindRendezvous/prototype/`, is not exported from `src/index.ts`, and the
store process refuses to start without two environment flags. The public
`connect()` path still rejects every rendezvous mode other than
`legacy-signaling`. The frontend cannot reach any of this, and that is unchanged.

---

## 2. What one run demonstrates

One `--scenario=healthy` run, end to end:

1. **Two headless Chromium contexts** are handed the same 32-byte room
   capability and nothing else — no shared origin, no shared storage, no channel
   between them but the stores.
2. **Two store processes** start on separate ports with fresh SQLite databases
   and fresh identity keys, and answer `/health` with different store ids.
3. **No signaling server is running anywhere in the test.** The legacy
   WebSocket path is not started, not imported by the page bundle, and not
   reachable.
4. **Presence and the four pair flights are carried blind.** Each page publishes
   a `PRESENCE` operation to both stores; each discovers the other through
   either store; and the pair then completes `IDENTITY_HELLO` →
   `IDENTITY_ACCEPT` → `TRANSPORT_OFFER` → `TRANSPORT_ANSWER` as pair-sealed
   operations the stores carry blind — the harness's own wording, and an
   observation about the run rather than a claim about the AEAD.
5. **A real WebRTC edge opens** from the exchanged SDP — complete ICE gathering,
   both connections reaching `connected`, over loopback host candidates.
6. **DTLS is verified on both sides — on these runs.** `verifyCertificates`
   compares the SHA-256 fingerprint parsed out of each side's exact SDP bytes
   against the live certificate that `getStats()` reports, and both pages
   report `dtls-verified`. Read that as an observation and not as a property of
   the composition, because **the tripwire is fail-closed in the harness and
   fail-open in the library**: a genuine mismatch throws and ends the session
   (the peer connection closes; the carrier schedule runs on until the run is
   stopped), but an engine that reports no certificate statistics yields
   `unsupported`, and `#establishSession` in `index.ts` then emits
   `dtls-unsupported` and proceeds to `createSession` regardless. It is
   `run.mjs`, not the SDK, that treats a run without `dtls-verified` on both
   pages as failed.
7. **The existing protocol-v4 session runs over the data channel.** A real
   `createSession` on both sides — hybrid 3DH + ML-KEM, Double Ratchet — with
   the session role taken from the handoff facts rather than from who dialled.
8. **Messages round-trip byte-exact.** 140,005 bytes A→B (3 uniform chunk
   frames) and 9,005 bytes B→A (1 frame), so one run covers both shapes of the
   app-lane framing. The comparison is `Buffer.equals` on the UTF-8 re-encoding
   of what arrived against the UTF-8 of what was sent.

Nothing in that list is stubbed. The stores are real processes, the browsers are
real browsers, the crypto is the development build of the shipped WASM module
(§8 says why it must be that build and not the production one), and the session
is the same one the released SDK uses.

---

## 3. How it is assembled

Fifteen modules under `src/blindRendezvous/prototype/` (10,508 lines), with nine
test files behind them, built on top of the thirty-two release-candidate modules
that already existed in `src/blindRendezvous/`.

| Module | Owns |
| --- | --- |
| `profile.ts` | `PROTOTYPE_DELIVERY_PROFILE_V0`, the wire constants, `validateDeliveryProfileGeometry` (every inequality of the spec's §4.3 arithmetic), and `withDeliveryWindowMs`. |
| `storeWire.ts` | Typed encode/decode wrappers over the `schemas.ts` descriptors — a projection, never a second authority for a wire field. Every decoder is strict-canonical. |
| `storeRoutes.ts` | The `prototype-v0` route table and media types, shared by the browser client and the server. |
| `store/storeCore.ts` | The pure per-window machine: allocation, append slot binding, finalization with CSPRNG dummies, the signed chunk chain and the checkpoint chain. |
| `store/storePersistence.ts`, `store/storeSqlite.ts` | The persistence port and its `bun:sqlite` implementation; a restarted store re-serves byte-identical signed objects. |
| `store/storeHttp.ts` | The `Bun.serve` handler, the constant-shaped refusals, CORS for a cross-origin page, and the optional body log. |
| `store/storeServer.ts` | The entrypoint and its two mandatory gate flags; the chain start is chosen once and then persisted. |
| `storeClient.ts` | The browser-side adapter: descriptor validation, signature verification on every answer, checkpoint-root recomputation, chain verdicts, custody-breach detection, and the fault taxonomy. |
| `carrierRuntime.ts` | The fixed schedule, one per store: token, allocation, appends at the profile's offsets, and the union read — real work and cover byte-shaped and latency-matched by construction. |
| `pairDriver.ts` | Presence, HELLO/ACCEPT, OFFER/ANSWER, the pair ledger, the established root, and the handoff facts. |
| `workKinds.ts`, `transportCandidates.ts` | The service-role classifier, and the strict SDP validator and candidate ordering. |
| `webrtcProvider.ts` | The browser transport: complete-gathering offer/answer, the bootstrap data channel created before the offer, and `verifyCertificates` over `getStats()`. |
| `index.ts` | The composition — `runBlindRendezvousPrototype(options)` — and the run's event vocabulary. |

Three properties of the runtime are worth naming, because they are the ones an
edit could quietly remove.

**A real object and cover are the same size at the same instant.** Every
scheduled append happens whether or not the outbox has anything to send. Cover
is sealed through the same HKDF and AEAD path as a real object, over a fresh
throwaway root that is wiped afterwards, so it is byte-shaped like a real object
and latency-matched to one, and it opens for nobody.

**What a store actually sees, per client, per window: thirteen fixed requests,
plus a conditional pair that is either both or neither.** Counted from
`carrierRuntime.ts` —
`#eventsForWindow` for the schedule, `storeClient.scanWindow` for what one read
expands into. The thirteen go out whether the client is idle or mid-rendezvous:

| Count | Request | Offset in the window |
| ---: | --- | --- |
| 1 | allocation-token issue (POST) | `tokenIssueOffsetMs` = 100 |
| 1 | allocation (POST) | `allocationRequestOffsetMs` = 700 |
| 5 | append (POST) | class 0 at 1300/1700/2100, class 1 at 1500/1900 |
| 1 | checkpoint read (GET) | `publicReadOffsetMs` = 600 |
| 5 | chunk read (GET) | `publicReadOffsetMs` = 600 |

Five appends is the sum over the two size classes of `appendSchedule.length` at
one room slot (3 + 2); five chunk reads is the sum of `publicChunksPerWindow`
(3 + 2). The token-issue POST is part of the shape even though open mode issues
no authority — skipping it would make this client distinguishable from one that
did not. The descriptor GET is once per store per session, not per window.

The **conditional** pair is a witness POST and a witness GET, and it is the only
part of this trace that is not fixed. A store receives both or neither — never
one — and it receives them exactly when the *other* store's scan of that window
came back `finalized` and neither store is inert. Both stores healthy: each gets
the pair. One store's scan degrades: the pair to the **healthy** store
disappears, so its absence is a direct readout of the other store's behaviour
towards this client, sitting in the healthy store's own request log. Either
store inert: the traffic stops both ways. It is disclosed as design §3a item 14,
and the runtime's own invariance test does not cover it — `windowShape()` counts
five hardcoded routes and not the witness route, so that test would pass
unchanged if witness traffic varied arbitrarily.

**The schedule is fixed, and a late event is sent late.** One `setTimeout`
holds the runtime's next due instant for every store, and the next one is
armed inside the timer callback *before* any handler runs, so a slow store
cannot shift its own following request off the grid. A timer the engine
delivers late (a busy main thread, a background tab's one-second clamp)
releases every event it held back at the late instant, so the count per window
does not change; the store may refuse an append that arrives after
finalization. Uploads more than one delivery window late are not sent, reads
are made however late within a 64-window reach, and both bounds are reported as
`missed` (`#takeDue`). There is no same-window retry, because retrying at the
surviving store after an omission would be an active cross-store tagging
channel. The application callback is called one batch at a time and never
from inside a scheduled event, so a slow, throwing or hung callback moves no
request. Every request also carries a deadline of one delivery window
(`storeClient.ts`, `requestDeadlineMs`) — the same value on every route,
because the profile sets no per-route budget for appends, chunks, or
checkpoints to derive one from, and it exists because the witness event waits
for the other store's scan, which an unbounded request would hold open.

**A store's topology verdict is local and unlabelled.** The runtime reports
`multi-store-union`, `single-carrier-dependent` or `no-usable-carrier`, computed
only from reads this client itself completed in the last window. It is a
statement about what this page saw, not an umbrella label about the deployment.

---

## 4. The four scenarios

```
node docs/e2e/blind-two-store/run.mjs --scenario=<name>
```

| Scenario | What is done to the stores | What the run must still do |
| --- | --- | --- |
| `healthy` | nothing | both pages `multi-store-union`, no faults, no `store-unreachable` |
| `kill-a` | store A is `SIGKILL`ed once both pages have published presence and A has logged ≥ 1 request body; the kill is confirmed (child exit awaited, `/health` polled until it refuses) | both pages `message-verified` byte-exact each way, both end `single-carrier-dependent`, and every recorded fault is kind `unreachable` against A — nothing naming B, nothing of any other kind |
| `withhold-a` | store A runs `P2PARTY_STORE_FAULT=withhold`: it answers `stored` to every append and finalizes dummies | both pages `message-verified` via B, ≥ 1 `custody-breach` against A, **no other fault of any kind**, and both pages drop to `single-carrier-dependent` |
| `unreachable-b-for-one` | nothing; page B is *given* only store A's origin | page A ends `multi-store-union`, page B `single-carrier-dependent`, page A's `counters.backfills ≥ 1`, and page B issues **zero** requests to store B |

Every scenario additionally asserts — not prints — the full pair exchange, both
pages' `dtls-verified`, both pages' `session-authenticated`, the byte-exact
messages both ways, the absence of any `failed` or `session-failed` phase, the
`store-connected` count per page, and the privacy audit on both stores.

### Recorded results

`--scenario=all`, 2026-09-08, headless Chromium on macOS, `--window-ms=4000`
with the pinned cohort of 8, exit 0, 4 of 4 scenarios. Times are wall clock from
that page's own `presence-published` to `message-verified`.

| Scenario | Verdict | Connect | A: peer→verified | B: peer→verified | Topology A / B |
| --- | --- | ---: | ---: | ---: | --- |
| `healthy` | PASS | 41.9 s | 9.7 s → 41.8 s | 9.7 s → 41.9 s | `multi-store-union` / `multi-store-union` |
| `kill-a` | PASS | 35.2 s | 7.1 s → 35.2 s | 7.2 s → 35.2 s | `single-carrier-dependent` / `single-carrier-dependent` |
| `withhold-a` | PASS | 35.6 s | 7.6 s → 35.6 s | 7.6 s → 35.6 s | `single-carrier-dependent` / `single-carrier-dependent` |
| `unreachable-b-for-one` | PASS | 35.4 s | 7.4 s → 35.4 s | 7.2 s → 35.4 s | `multi-store-union` / `single-carrier-dependent` |

Three things are worth reading off that run.

**`kill-a` produced 264 fault records, all of kind `unreachable`, and zero of
kind `signature-invalid`** (131 on page A, 133 on page B, all naming store A).
That distinction is load-bearing, and it was a defect until `f1f5aa4`: before
that commit the client filed a killed store's `ERR_CONNECTION_REFUSED` under the
same kind as a store caught signing a lie, and a pre-`f1f5aa4` run of this same
scenario produced 269 records that a report built from the fault list would have
read as accusations against a store that was simply switched off. The 264 above
are from a run after the fix and are a different run, not the same number
recounted. A store that did not answer now files as `unreachable`;
`signature-invalid` is reserved for an answer that arrived, decoded, carried a
signature and failed to verify. Neither kind marks a store inert.

**`withhold-a` shows the detection latency of the custody check: one delivery
window.** Both pages reported `multi-store-union` at 3.8 s and dropped to
`single-carrier-dependent` at 7.7–7.8 s, when the first receipt-versus-slot
comparison failed and store A was marked inert. A client can only compare a
receipt against a window after that window is finalized, so a withholding store
looks usable for exactly one window. Each page recorded 8 `custody-breach`
records against A and nothing else.

**`unreachable-b-for-one` shows the union working in one direction only.** Page
B issued **0** requests to store B — asserted, not merely printed — and still
reached `message-verified` byte-exact both ways. Page A **queued 3 backfills for
store B**: `CarrierCounters.backfills` counts `(operation, store)` pairs enqueued
for replication, so it is evidence that page A decided store B was missing those
operations, not evidence that any of them was appended or acknowledged. Nothing
in store B's log distinguishes a backfilled object from cover.

### On the wall-clock times

The four scenarios' times differ by a few seconds in every direction and the
ordering is **not** stable across runs; the recorded run has `healthy` slowest by
6.5 s, and in other runs of the same four scenarios that ordering reverses.
Read the differences as run-to-run variance — chiefly where in a delivery window
each run happens to start, and whether the very first flight costs one window or
two — and not as a measurement of what reading one store instead of two costs.
Nothing in the harness asserts on wall-clock time. The deliberate latency
measurement is §6, which changes the geometry rather than comparing scenarios.

---

## 5. The privacy audit

Both stores run with `P2PARTY_STORE_LOG_BODIES`, which appends the hex of every
accepted request body **before parsing**, so the audit sees the bytes that
arrived rather than a re-encoding of what the store made of them.

### What it searches

For each run the harness looks, in every logged body, for fourteen secrets:

- each page's room **capability**, its `RoomContextId`, and its stable Ed25519
  key, read back from `window.__blind.audit()`;
- each page's local and remote **SDP**, in full;
- the SDP markers `a=fingerprint`, `a=candidate`, `a=ice-ufrag` and `v=0\r\n`.

Each of those is searched in every encoding a client could plausibly have
produced: the raw bytes, the ASCII of the lower-case hex, the ASCII of the
upper-case hex, the ASCII of base64 and base64url, and — because a marker
embedded inside a larger base64 blob starts wherever its byte offset mod 3 puts
it — base64 and base64url at all three alignments. That is **148 distinct byte
needles per run**: 14 secrets at 11 encodings each, less the 6 alignment
variants of the 5-byte `v=0\r\n` marker whose stable cores fall below the
8-character floor.

Five things keep the result from being theatre:

- **A missing or empty log fails the scenario**, and so does a log with zero
  parsed bodies. A clean audit over nothing is not a clean audit.
- **A positive control runs over the same bytes with the same matcher.** The
  delivery-profile hash is a field of every allocation-token request body, so it
  *must* be found. If it is not, the audit is not reading what it thinks it is,
  and the scenario fails.
- **The capability is cross-checked.** `audit().capabilityHex` must equal the 32
  bytes `run.mjs` itself generated, so the needle is known to be the real secret
  rather than whatever the page felt like returning. A secret shorter than 32
  bytes, or an SDP under 64 bytes, is refused rather than quietly dropped.
- **Short needles are refused, not searched.** `v=0` alone is three bytes and
  turns up by chance roughly once per 16 MB of ciphertext, against logs of
  6-8 MB. It is searched as `v=0\r\n`, which is what Chromium emits, and
  anything under four bytes is dropped from the needle set rather than counted
  as "not found". The same discipline is what subtracts six needles from the
  count above: an 8-character floor on a base64 alignment core removes the six
  alignment variants of that same 5-byte marker.
- **The needle count is asserted, not printed.** A run that builds anything other
  than 148 needles fails, so an edit that drops a secret or an encoding cannot
  shrink the search and still report a clean audit.

### What it found

| Scenario | Store A: bodies searched | Store B: bodies searched | Total | Needles found |
| --- | ---: | ---: | ---: | ---: |
| `healthy` | 171 | 174 | 345 | 0 of 148 |
| `kill-a` | 2 | 116 | 118 | 0 of 148 |
| `withhold-a` | 128 | 128 | 256 | 0 of 148 |
| `unreachable-b-for-one` | 135 | 72 | 207 | 0 of 148 |

Every per-store count is the corpus the audit actually searched — carried out of
the search loop rather than re-read afterwards — and each verdict line's total is
their sum.

In `kill-a`, store A's clean audit is about **two request bodies**. The kill
lands in the first delivery window, so that is all it had received. The run
prints the count for exactly this reason; the honest statement about store A in
that scenario is a statement about those two bodies.

### What the audit does not cover

Three things, and the verdict line is worded so as not to imply any of them.

1. **GET routes are not examined at all.** The store's body log sits inside the
   POST branch of the request handler, so it records request *bodies* only. The
   chunk and checkpoint reads carry their coordinates in the URL path
   (`/chunk/<deliveryProfileHash>/<window>/<class>/<chunk>`). Those paths are
   public geometry by construction and hold no room-derived value, but **this run
   does not check that**; it checks the bodies.
2. **Traffic logged after the audit ran is outside the corpus.** Each log is read
   exactly once, immediately after both pages report `message-verified` and
   *before* `stop()`. The scheduled traffic of every window that follows is not
   searched.
3. **Source addresses, request timing and sizes** — all of which both stores see
   on every request — are not covered by any needle.

### What a run may therefore claim

Exactly this, and no more: *on this run, none of the 148 needles for the room
capability, the `RoomContextId`, either stable Ed25519 key, either SDP blob, or
those SDP markers appeared in any of the N request bodies the audit searched*,
where N is the number printed per store. Nothing about what a store could infer.
Nothing about independence.

---

## 6. What latency costs: the cohort measurement

The design asked for a latency table over `deliveryWindowMs ∈ {4000, 2000,
1000}`. Rescaling the window alone does not reach it — `withDeliveryWindowMs`
scales the append offsets and the finalization offset by the same ratio, so the
slack between the last append and the window's close shrinks with the window,
and at 2,000 ms every append arrives after `window-finalized`. That is not a
dead end; it is a *cost* problem, and the cost has a second knob.

Per client, per store, per window the schedule costs a fixed **append** of
172,542 bytes (5 objects, set by the append schedule and independent of the
cohort) and a fixed **full scan** of every object in the bucket — each of which
the client AEAD-attempts, because a fixed scan that skipped anything would be
event-shaped. That scan is what `cohortAllocationsPerWindow` sizes.
`--cohort=<n>` rebuilds the profile at that cohort, derives the chunk counts from
the geometry rather than guessing them, re-runs the validator, and applies the
result to both store processes and both pages so all four agree on one delivery
profile hash. At the pinned cohort of 8 the rebuilt profile hashes byte-identical
to the pinned literal, which is the check that the rebuild is faithful.

Measured on one machine — macOS, headless Chromium, both pages and both stores in
one process tree — `--scenario=healthy`, time from `presence-published` to
`message-verified`:

| Window | Cohort | Chunks/window | Full scan, B/store/window | Per flight | To `message-verified` |
| ---: | ---: | :---: | ---: | ---: | ---: |
| 4000 | **8** (pinned) | 3+2 | 1,380,336 | 8.0 s = 2 windows | **39.9 s** |
| 4000 | 4 | 2+1 | 723,344 | 4.0 s = 1 window | **22.3 s** |
| 4000 | 2 | 1+1 | 656,992 | 4.0 s = 1 window | **23.8 s** |
| 2000 | **8** (pinned) | 3+2 | 1,380,336 | — | **stalls**: every append answers `window-finalized` |
| 2000 | 4 | 2+1 | 723,344 | 4.0 s = 2 windows | **20.8 s** |
| 2000 | 2 | 1+1 | 656,992 | 4.0 s = 2 windows | **17.9 s** |
| 1000 | 2 | 1+1 | 656,992 | 2.0 s = 2 windows | **10.5 s** |

**The pinned cohort already costs a whole extra delivery window per flight.** The
protocol's designed cadence is one window per flight: append in window `w`, the
peer reads `w` at the read offset into `w+1` and appends its answer inside `w+1`.
At cohort 8 the browser cannot finish 1.38 MB × 2 stores of scanning and sealing
between the read offset (600 ms) and the last append offset (2,100 ms), so every
flight slips to the window after — 8 s instead of 4 s, and 39.9 s instead of
about 22 s for the whole rendezvous. Halving the cohort halves the scan and
recovers the designed cadence at the *same* window length. A smaller cohort is
also exactly what makes a shorter window work: at the pinned cohort a 2,000 ms
window cannot append at all, while a 1,000 ms window at cohort 2 completes in
10.5 s with zero misses.

**The knob that buys the latency is the one that sizes the shared bucket.**
`cohortAllocationsPerWindow` is, by definition, how many allocations a store may
hand out per window in one bucket, and the fixed scan is large precisely because
it is that whole bucket. Moving it from 8 to 2 measured a 2.1× smaller scan and,
at the same 4,000 ms window, a 1.7× faster rendezvous — 3.8× only if the shorter
window that the smaller cohort makes possible is taken as well, which is a
two-knob change and not a cohort effect. And by definition it also divides by
four the number of allocations that share the bucket. **Those ratios are
different quantities, not one.** What the change means for what a store can tell
apart is **not** measured by any run here and is not claimed. The table is a cost
measurement, not a recommendation: the pinned profile is 8, and moving it is a
change to how much unrelated traffic a client's objects sit among.

Each row is a single `--scenario=healthy` run with both stores honest, and the
table is **not monotone**: at the same 4,000 ms window, cohort 4 (22.3 s) is
*faster* than cohort 2 (23.8 s) — the smaller cover set is the slower row, by
1.07×. That step is a single measurement in each direction and sits inside
the run-to-run variance of §4; on its own it shows nothing. What survives is
the separation between the extreme rows — 1.7× at a fixed 4,000 ms window
(39.9 → 23.8 s) and 3.8× once the shorter window is taken too (39.9 → 10.5 s)
— both far outside that variance. The mechanism behind them (a smaller cover
set means fewer objects to scan) is carried by the scan-byte column, which
*is* monotone (1,380,336 → 723,344 → 656,992 as the cohort halves from 8 to
2), not by the timings alone. And the timings are wall clock on one laptop
running two Chromium contexts and two `bun` stores at once — an upper bound on
what two real clients on two machines would see, not a protocol constant.

---

## 7. The residual leaks

The design enumerates fourteen residual leaks. All fourteen are disclosed
there; this is the summary an outside reader needs, with the worst one in full.

### 1. Replicated-write timing linkability — unmitigated, and measured

Writing the same operation to both stores milliseconds apart lets anyone who sees
both request logs join them into one client, with no identifiers involved at all.
The observer that matters here is one holding both logs but not the source
addresses — for the stores themselves this join is redundant with the addresses
they already have, which is the sense in which §1 says colluding stores gain
nothing.

**The runtime schedules both stores at the profile's offsets, and the measured
separation between the two stores' writes of one operation is 0 ms — minimum,
median and maximum** over three operations in three consecutive windows
(`tests/blindRendezvous/prototype/carrierRuntime.test.ts`, "writes one operation
to both stores in the same millisecond, measured"). The clock is injected, so
0 ms is the schedule's own contribution with network jitter removed.

A per-store phase offset was measured against this profile and **rejected rather
than shipped**, because the profile has no room for one that would help:

| | ms |
| --- | ---: |
| earliest a store's schedule may be shifted | −100 (the token offset reaches zero) |
| latest | +499 (finalization at 2800, less 200 ms permitted skew, less the last append at 2100, less one — that inequality is strict, so 500 itself fails validation) |
| widest separation of two stores | 599 |
| delivery window | 4000 |
| window boundaries a maximally delayed write crosses | 0 |

A join partitions both logs by window before it does anything else. A 599 ms band
against a 4000 ms window is 15% of one epoch and crosses no window boundary, so
the candidate set an observer works over is *identical* with the offset and
without it. It reduces the join by nothing measurable, rather than reducing it a
little; a delay wide against the epoch — which is what the literature's
mitigation actually is — would need a profile whose append band is wide against
its window rather than 15% of it.

Two further facts settle it. Derived from the public carrier context id, the
phase is `H(StoreId || DeliveryProfileHash)` — shared by every client of that
store and recomputable by anyone holding the store's descriptor — so it is the
same grid under a different name, and an observer subtracts one known constant
(129 ms, for the store pair and derivation the test measures). Derived per client
instead, it would be a stable cross-window timing fingerprint at each store, and
would put that client outside the 200 ms band the profile itself defines as
conforming drift — which is the very set a fixed schedule exists to create.

**What would actually work needs no new geometry.** Hold the second store's copy
of an operation for a whole number of windows drawn from a wide distribution, and
let that store's slot carry cover meanwhile. Nothing changes on the wire, because
a real object and cover are already the same size at the same instant, and the
schedule stays exactly fixed. The price is k windows (k × 4000 ms) of replication
latency and a correspondingly longer stretch in which one store is the only
carrier of that operation. That is a latency and fault-tolerance decision for the
maintainer, so it is recorded as follow-up work with its numbers, not presented
as a solved problem.

### 2–14, in brief

- **Source addresses.** Both stores see the client's IP on every write and poll;
  a single store can recover a write-then-read pairing in a few rounds. The
  co-membership edge is hidden at the identifier level only.
- **Size and count** are visible; the fixed schedule pads both.
- **Polling shape** must stay schedule-shaped and never event-shaped: no burst
  after a hit, no coordinated dial phase between stores.
- **Retry oracle.** Retrying at the surviving store after an omission would be an
  active cross-store tagging channel, so retries happen only at the next
  scheduled slot.
- **The witness channel is itself a beacon.** Cross-store checkpoint writes are
  replicated writes, and are scheduled independently of user traffic for that
  reason. That is their *timing*; their *presence* is the next item.
- **Detection, not prevention** — see §1.
- **Independence is a business fact**, not a cryptographic one. Two processes on
  one laptop are one fault domain.
- **Key split-view.** Each store can serve a per-client descriptor to partition
  the set of clients it serves; witnessing the descriptor digest mitigates but
  does not solve it.
- **No uniqueness.** Two concurrent offers for one room in one window cannot be
  prevented; the tie-break is part of the protocol.
- **Token and quota shape.** If two stores ever shared a double-spend database,
  redemptions would become a cross-store membership edge.
- **Local forensics.** Persisted seen-sets and checkpoints are keyed by per-store
  opaque ids, never by room-derived tags.
- **No labels.** Two stores give crash and omission tolerance with detection.
- **The witness channel is a cross-store status oracle** — the one part of the
  per-window trace that is conditional rather than fixed. A witness POST and a
  witness GET reach a store only when the *other* store's scan of that window
  came back `finalized` and neither is inert, so each store reads off its own
  request log whether the other served this client a finalized window: the pair
  while both are healthy, nothing for the healthy store once the other one
  degrades, nothing either way once either goes inert.
  §3 counts it; design §3a item 14 discloses it in full, including that
  the runtime's fixed-shape test does not cover the witness route. Making the
  traffic unconditional — a witness post every window regardless, carrying
  cover when there is nothing to witness — is what would fix it, and is a
  design change rather than a correction, so it is not attempted here.

What no literature sweep found published together — and therefore the only thing
this work may present as novel — is the *composition*: a capability-authenticated,
self-authenticating grow-only set, fixed-scan reads, mutual
transparency-log-style witnessing treated as evidence rather than validity,
replicated writes, and browser-side cost measurements. That is a systems
contribution for a flagged prototype, not a cryptographic result. The design's
§3a carries the reasoning and the comparison against the two rejected
architectures.

---

## 8. Running it

### The unit suite

```sh
bun test tests/blindRendezvous
```

581 pass, 0 fail, 3,396 assertions across 40 files, as of this commit. Nine of
those files are the prototype's own: the profile geometry, the store wire codecs,
the store core, its SQLite persistence, its HTTP handler, its server entrypoint,
the store client, the carrier runtime and the pair driver.

### A store process

```sh
P2PARTY_STORE_PROTOTYPE=1 P2PARTY_STORE_OPEN_ALLOCATION=1 \
  P2PARTY_STORE_PORT=5910 \
  P2PARTY_STORE_DB=/tmp/store-a.sqlite \
  P2PARTY_STORE_KEY_FILE=/tmp/store-a.key \
  bun run store:prototype
```

Both gate flags are required and the process refuses to start without both,
naming them. The refusal is deliberate: nobody should be able to point at a
running instance as evidence of the specified store.

**Before running one anywhere but a scratch disk, read the storage number.**
Every window is padded to the profile's full geometry whether or not anything
real was appended, and nothing ever deletes one. A store left running with no
traffic at all was measured at **2,763,134 bytes of state per finalized
window** — seven consecutive all-dummy windows, every row byte-identical in
size, 19,390,464 bytes of SQLite file for the seven. At the pinned 4,000 ms
window that is 21,600 windows a day, so **about 59.7 GB per store per day, with
no retention sweep to stop it**. §9 says what a next stage owes here.

| Variable | Meaning |
| --- | --- |
| `P2PARTY_STORE_PROTOTYPE` | must be `1`. Gate flag. |
| `P2PARTY_STORE_OPEN_ALLOCATION` | must be `1`. Gate flag, and the only allocation mode implemented — there is no issuer. |
| `P2PARTY_STORE_PORT` | default 5910; must be 5001–65535. Nothing binds below 5000 locally. |
| `P2PARTY_STORE_WINDOW_MS` | rescales the pinned delivery profile. Pinned to the chain on first start; a restart under a different value refuses rather than equivocate. |
| `P2PARTY_STORE_DB` | SQLite path. A restart replays state; a finalized window is never re-signed. |
| `P2PARTY_STORE_KEY_FILE` | 32-byte Ed25519 seed, created `0600` on first start or not at all. |
| `P2PARTY_STORE_CHAIN_START` | the chain's first ingress window. Chosen once, then persisted; it cannot be moved afterwards. |
| `P2PARTY_STORE_LOG_BODIES` | test-only: a path that receives the hex of every accepted POST body, before parsing. |
| `P2PARTY_STORE_FAULT` | test-only: `withhold` — accept every append, finalize dummies. |

### The browser harness

```sh
bash docs/e2e/blind-two-store/build.sh
PLAYWRIGHT_BROWSERS_PATH=~/Library/Caches/ms-playwright \
  node docs/e2e/blind-two-store/run.mjs \
    [--scenario=healthy|kill-a|withhold-a|unreachable-b-for-one|all] \
    [--window-ms=4000] [--cohort=8] [--deadline-ms=180000] \
    [--store-port-base=5910] [--page-port=5920]
```

`--scenario=all` is the default; each scenario gets its own port pair, its own
temp database and key files, and tears everything down on every path including a
thrown assertion. The driver exits non-zero if any scenario fails.

Do **not** run `npm run predist` first. The harness runs against the development
WASM (`src/cryptography/libcrypto.wasm`, SRI-pinned in `wasmLoader.ts`), and
`predist` overwrites that artifact with the web-only production build. The
generated `bundle*.js`, `provider-smoke-bundle.js` and the copied
`libcrypto.wasm` are all covered by `.gitignore`.

There is also a component-level harness, `provider-smoke.*`, which proves the
WebRTC transport provider on its own — two providers in one page handing each
other offer and answer by direct call, with everything downstream of that real:
complete ICE gathering, DTLS verified both sides, real protocol-v4 sessions, and
multi-chunk messages byte-exact each way. Five consecutive runs passed at about
0.2 s each.

### Environment facts the harness discovered

The first two were found the hard way, and both are load-bearing: without either,
the demonstration does not run at all.

- **Headless Chromium needs `--disable-features=WebRtcHideLocalIpsWithMdns`.**
  Chromium otherwise replaces host candidates with `<uuid>.local` mDNS names, and
  the headless sandbox has no mDNS responder. Because the blind profile is
  complete-gathering — the candidates ride inside the single SDP blob, and there
  is no trickle channel — an unresolvable remote candidate is simply dropped, and
  both connections sit at `iceConnectionState: "new"` forever with zero candidate
  pairs. With the flag, ICE connects in under 500 ms; without it, never.
- **The page must load the bundle as `<script type="module">`.** A browser-target
  `bun build` emits ESM, and the bundled `wasmLoader.ts` contains
  `import.meta.url` inside a Node-only branch the page never takes — a classic
  script cannot even parse it. The `process` shim stays a classic inline script so
  it still runs before the deferred module.

- **Cross-origin headers.** A page is never served from a store's origin, so the
  store answers with `access-control-allow-origin: *`,
  `access-control-expose-headers: x-p2party-store` (the client refuses any answer
  without that header, and it is not CORS-safelisted), and a 204 preflight for
  the `application/p2party-*-prototype-v0` request media types. Without those, no
  browser reaches a store at all.

### One caveat about the harness itself

`docs/e2e/**` is outside `tsconfig.json`. Neither the page entry nor the harness
tooling is type-checked by `bunx tsc --noEmit`, and `bun build` only transpiles.
A green build there is not a type check.

---

## 9. What a next stage would need

None of the following is implemented, and none of it is stubbed in a way that
could be mistaken for implemented.

- **The Privacy Pass allocation path.** Blind-RSA issuance (RFC 9474/9578) and
  redemption. Today's store answers `issued` with 32 zero bytes and ignores the
  token, so there is no abuse control at all. This needs the frozen allocation
  registry, including the token bytes and issuance vectors.
- **The admission kernel.** `VerifyAdmissionContext`, the trusted snapshot,
  authority custody and view construction, private provenance brands, `Admit()`,
  atomic persistence, and the action-recheck wrappers. Until those exist, no
  SDP/ICE promotion is gated by policy, and the prototype's open-admission
  bypass is the whole of its policy.
- **Persistent scheduler cursors and restart-safe outboxes.** The runtime's
  schedule and outbox are in memory; a reloaded page starts a fresh session.
- **`STORE_HINT` discovery.** Descriptor-only hints validate and reduce today,
  but any non-empty route sequence fails closed because the content-addressed
  route-family registry and its parsers do not exist. Store origins reach the
  prototype as run options.
- **The spec's server-privacy profile**, which its own vocabulary calls `SP1`
  and defines as *bounded measured public-store source unlinkability* — bounded,
  measured, and scoped to one exact interval, profile, route set, corruption
  model and cohort floor. The spec's own list of misreadings names "treating
  `SP1` as protection against a global observer", so even where it exists it is
  not the blanket the name suggests. Both stores see every client IP on every
  request today, and nothing here changes that.
- **Retention and garbage collection.** Windows accumulate; nothing expires,
  and the bill is measurable rather than theoretical. An idle store — no
  client, no real append — was measured at **2,763,134 bytes of state per
  finalized window** (seven consecutive all-dummy windows, 19,390,464 bytes of
  SQLite file between them), because every window is padded to the profile's
  full geometry regardless. At the pinned 4,000 ms geometry that is 21,600
  windows a day and **about 59.7 GB per store per day**. The profile's own
  `carrierRetentionWindows` is 160,000 — roughly 7.4 days — which is about
  442 GB even once something exists to enforce it. Reproduce it by starting one
  store with the §8 command, stopping it after ~25 s, and reading
  `select window, length(state) from window;` out of its SQLite file. Anyone
  who runs a store for real needs the sweep first, and a size class or a window
  length chosen with this number in front of them.
- **An end-to-end scenario for a stalled store.** The library now bounds every
  request (§3), and a unit test covers a store that accepts connections and
  answers nothing. `run.mjs` does not: its two fault modes, `kill-a` and
  `withhold-a`, both fail fast. A `stall-a` scenario is cheap and is not done
  here.
- **The frontend.** `p2party.com` vendors the SDK as a hash-verified tarball, and
  the blind modules are deliberately absent from the barrel. Reaching this from a
  real application needs a reviewed public API, a new vendored artifact and hash,
  and coordinated frontend and server work.
- **Every release-registry freeze.** The binary schema, the executable kernel,
  the claim and formal registries, the HTTP protocol, the default profile,
  planner and resource values, the allocation scheme, and the compatibility hash.
  Until those are frozen and vector-tested, nothing here is wire-interoperable
  with anything, and the `prototype-v0` bytes exist precisely so that they cannot
  be mistaken for the frozen family.

Two smaller items are worth recording because they are cheap and were left
deliberately. The cohort override used for §6 is a build-time source rewrite,
applied by a Bun loader plugin and by the harness's bundle builder, because the
composition module was off limits to the measuring agent; if a cohort override is
ever wanted outside a measurement, it belongs in the run options and in a
`P2PARTY_STORE_COHORT` variable. And the store's body log sits inside the POST
branch of the handler; if the privacy audit is ever to cover request URLs, that
call has to move.
