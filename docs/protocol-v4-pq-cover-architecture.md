# Protocol v4: sparse PQ healing and scheduled cover

**Status:** accepted for implementation, 2026-07-24  
**Scope:** p2party-js pairwise edges inside the existing n-peer WebRTC mesh  
**Compatibility:** clean wire/session break; protocol v3 peers and persisted v3
crypto rows are not resumed as v4

## Context

Protocol v3 already authenticates a room-wide policy, bootstraps every edge with
interactive 3DH plus the selected ML-KEM-512/768/1024 suite, and advances a
classical Double Ratchet once per logical message. It also reserves a one-byte
PQ epoch, but that byte is fixed to zero and is not part of the message AEAD
AAD. The sparse PQ state machine exists only as a store-free core.

Scheduled cover is already an authenticated room policy, but the live runtime
rejects it. The immediate transport opens one DataChannel per message, bursts
all chunks, emits receipts as soon as work completes, and closes immediately.
Those behaviours are activity oracles and cannot be reused unchanged.

The two features are independent:

- sparse healing must work in an immediate room;
- scheduled cover must work without a healing exchange in progress;
- in a scheduled room, a PQ control cell or cancellation replaces a dummy cell
  and never adds an observer-visible scheduled cell.

## Decision

### 1. Protocol-v4 uniform cells

All large application/control cells remain exactly 65,490 bytes:

```text
type(1) | dh-or-control-id(32) | N(8) | PN(8) | pqEpoch(8) | nonce(12)
| padded plaintext(65,405) | tag(16)
```

The seven extra epoch bytes consume padding; they do not increase the outer
cell. The complete clear header excluding the nonce, including the type and
u64 epoch, is authenticated. Message-key cache identities include the epoch.
Unknown, stale, or future epochs fail before mutating the Double Ratchet.

Classical per-message keys and the current PQ epoch root enter a
domain-separated HKDF bound to the suite, edge binding, epoch and ratchet
header. Classical skipped keys stay classical. Already-combined active receive
keys live in a separate epoch-bound collection so a restored key cannot be
combined twice.

### 2. One atomic edge-crypto state

One stable `(roomId, peerPublicKey)` row contains the Double Ratchet, PQ
checkpoint, combined active receive keys, exact sealed control outbox, and
duplicate-ADVANCE ACK cache. A single non-extractable AES-GCM key wraps one
bounded canonical snapshot. Public AAD binds the row format, stable edge,
authenticated suite/binding, generation and timestamp.

Every crypto mutation follows:

```text
clone complete edge state
→ mutate/authenticate clone
→ CAS-persist one wrapped row
→ adopt live clone
→ expose plaintext or send exact bytes
```

The same edge mutation lock covers message send, message receive and PQ
transitions. A storage failure leaves both live ratchets unchanged. V4 database
migration discards v3 crypto/send-ciphertext state, preserves room/message
history and received chunks, and forces a new v4 handshake.

### 3. Crash-safe sparse healing

The handshake derives independent Double-Ratchet and PQ-healing roots plus a
non-secret transcript binding. Stable Ed25519 identity ordering chooses the
first OFFER turn.

Canonical encrypted control records are OFFER, ADVANCE and ACK. The 64-byte ACK
binds suite, edge, epoch and ADVANCE counter. OFFER and ADVANCE carry exact
suite-selected FIPS 203 material; the largest ML-KEM-1024 ADVANCE is 3,264
bytes and fits in one padded cell.

Durable ordering is:

- OFFER: prepare and seal under the current root; persist the pending KEM secret
  and exact sealed frame; then send.
- ADVANCE: authenticate OFFER; prepare and seal under the old root; commit the
  candidate PQ root on the clone; persist the new root and exact old-root frame;
  then send.
- ACK: authenticate/decapsulate ADVANCE under the old root; commit the new root;
  seal ACK under the new root; persist the new root, exact ACK and replay cache;
  then send.
- ACK receipt: authenticate under the new root; persist idle; only then reopen
  application traffic.

Exact duplicate records retransmit the persisted exact frame. Different bytes
reusing a counter/epoch slot are a fork and close the edge. Retry exhaustion
forces a fresh hybrid handshake; it never falls back to epoch zero or another
suite.

Healing starts only at a quiescent transfer boundary. Receiving an OFFER closes
the local application gate before waiting for old-epoch channels to drain.

### 4. Scheduled room cover

The authenticated policy defines a cycle of `coverDurationEpochs` epochs. At
each cycle boundary each endpoint opens exactly `coverLanes` outbound channels
per peer edge. Every channel sends exactly `coverFramesPerCell` full cells per
epoch and closes only at the cycle boundary. A lane is assigned a queued
message or remains dummy for the whole cycle.

Deadlines are absolute and room-phase shifted. Cells are staggered within an
epoch. The scheduler never accelerates for typing/queued data, never sends a
late catch-up burst, and never falls back to WebSocket payload relay. A missed
deadline or backpressure marks cover degraded and fails/requeues real work.

Cancellation is explicit:

- before admission, remove the job; the lane remains dummy;
- after admission, local UI cancellation is immediate, the next slot carries an
  encrypted CANCEL, all remaining slots are dummy, and close stays at the fixed
  boundary.

Completion substitutes a terminal receipt into a scheduled reverse slot and
keeps the dummy tail. It never emits an extra receipt or closes early. Large
files use declared `F × D` capacity classes; a message that does not fit the
room class fails rather than silently switching to immediate delivery.

Browser `freeze`, `pagehide`, offline state, or excessive timer drift marks
cover suspended/degraded. Missed epochs are skipped. Resume begins only at a
future cycle boundary. The API exposes this status so the UI cannot claim cover
during a browser-imposed gap.

A hidden page is not suspended: its schedule stays armed. Because a hidden
page's own timers are throttled, the schedule's wake-ups come from a dedicated
timer worker, one shared by every scheduled-cover edge on the page. The page
sends each cell when the worker's message arrives. Lateness is judged on the
page's clock when it runs the slot, and a cycle with a slot past its drift
tolerance is marked degraded.

A late wake-up on the page's clock does not prove the worker is dead: a freeze,
a system sleep or a long task delays every wake-up too. So a wake-up 5 s
overdue only makes the page ping the worker, and a worker that answers is kept.
The ping's 10 s timeout is a page timer too: one that runs more than 1 s past
its own deadline ran after another pause, possibly ahead of the worker's
queued answer, so it waits another 10 s, once. A worker that raises its error
event, cannot be reached, or does not answer in that time is replaced:

- the pending wake-ups move to page timers at once;
- a new worker starts at a later cycle boundary, after a backoff of 1, 2 and
  then 4 s. Each edge moves to it at a cycle boundary of its own, so an edge's
  cycle runs on one source from open to close, except in the cycle where a
  worker is lost;
- replacements are counted in a row, at most 3. The count starts again once a
  replacement has delivered 100 wake-ups, and when the page's last
  scheduled-cover edge closes. Only when 3 replacements in a row are lost
  before that does the page stay on page timers for good, and each
  scheduled-cover edge then reports this once with `console.warn`.

`p2party.getCoverTimerSource()` returns `"worker"`, `"page"` or `"none"`.

The figures below come from one measurement in Chrome for Testing 159.0.8154.6
on macOS 27.2 (arm64). Setup:

- the harness and results are in `docs/e2e/cover-timers/`;
- the browser was launched without the flags browser drivers add to disable
  background throttling;
- the page was hidden behind another tab;
- the 1-minute load average on the host was 6 to 9;
- the harness ran the scheduler alone, with recorder lanes and a constant
  cell, so cell sealing and WebRTC were not part of it, and with one worker
  per scheduler (the worker is shared now; the path from worker timer through
  `postMessage` to the page's handler is the same);
- one cycle a second over 2 lanes × 5 frames, so a slot every 100 ms with a
  99 ms tolerance, 390 s hidden.

Results:

- On page timers, the clock used before the worker, no cell was sent while
  hidden and all 389 cycles degraded. Past 300 s hidden, wake-ups arrived once
  a minute.
- On the timer worker, 3,456 of 3,890 cells were sent and 75 of 389 cycles
  (19.3 %) degraded. The wake-ups ran late on the hidden page: median 50 ms,
  90th percentile 94 ms, 99th percentile 100 ms, maximum 143 ms. 1.8 % of them
  were past the 99 ms tolerance.
- The phase past 300 s hidden looked like the earlier ones. While visible, no
  wake-up was more than 6 ms late.
- With 500 ms slots (499 ms tolerance) and 120 s hidden, the worker sent all
  230 cells and no cycle degraded, but its wake-ups still ran late: median
  60 ms, maximum 105 ms. Page timers sent none.

The harness timestamps only the page side. It therefore cannot tell a late
worker timer from a late page task. That the worker's own timers are not
throttled is an inference from Chromium's documented behaviour, not a
measurement.

Later the same day the harness ran again, on the code with the shared worker
and the ping, and on the code above (one worker per scheduler) for
comparison. The host's screen was locked for all of these runs, so every
window was occluded; the browser kept the page visible
(`--disable-backgrounding-occluded-windows`) until a tab was opened in front
of it, as before. Each run was 20 s visible, 120 s hidden. The 1-minute load
average was 4 to 23, from other work on the host.

| Slots  | Worker                      | Cells sent while hidden | Cycles degraded | Wake-up lateness hidden (median / p99 / max) |
| ------ | --------------------------- | ----------------------- | --------------- | -------------------------------------------- |
| 100 ms | shared, with ping           | 24 of 1,190             | 119 of 119      | 151 ms / 205 ms / 249 ms                     |
| 100 ms | one per scheduler (earlier) | 47 of 1,190             | 119 of 119      | 123 ms / 200 ms / 201 ms                     |
| 500 ms | shared, with ping           | 230 of 230              | 0 of 23         | 152 ms / 227 ms / 316 ms                     |
| 500 ms | one per scheduler (earlier) | 230 of 230              | 0 of 23         | 149 ms / 200 ms / 204 ms                     |

While visible, wake-ups were at most 11 ms late on both. So with the screen
locked a hidden page ran the worker's wake-ups about three times later than
in the first measurement, and at 100 ms slots almost no cell was sent; the
shared worker and the ping made no difference of that size. In the same
conditions the page handled its database worker's replies within a few
milliseconds (below), which suggests, without proving it, that the lateness
is in when the timer worker's own timers fire.

So tab visibility can still be read off the wire:

- from cell timing, even when no cycle degrades. A cell is sent when its
  wake-up runs on the page. On a hidden page that was tens of milliseconds
  after the slot (median 50–60 ms with the screen unlocked, about 150 ms with
  it locked), and on a visible one at most 6 ms (11 ms locked). An observer
  timing cells against the slot grid sees the difference. Closing this needs
  the cells to be sent off the page's event loop, from the worker, which is
  not built. The shift is the same for every cell, whatever it carries (next
  section).
- in the cycles that still degrade at short slot spacings, as measured above;
- in cases that were not measured:
  - a frozen or discarded page (mobile browsers, Safari), where `freeze`
    suspends cover;
  - a browser that throttles worker timers;
  - a suspended process;
  - page timers, used while a lost worker is being replaced and for good
    where no worker can be created or the replacements are spent.

While the page is hidden, a scheduled send's delivery idle budget is held
exactly as it is while cover is suspended, so a send that genuinely stalls
while the page is hidden is detected when the page is visible again.

#### When a cell leaves, and what it carries

A slot's cell is produced during the slot before it, and the slot's wake-up
only sends it. Before that, the wake-up produced the cell and sent it when it
was ready, so a cell left at its wake-up plus however long it took to produce:

- a dummy: one AEAD seal of the 65,490-byte cell in WASM;
- a control cell (a receipt batch, a CANCEL): the same seal of its content;
- a real chunk: a read of its staged row from the outbox store (a round trip
  to the database worker); the first time it is sent, also its receipt token
  (SHA-512 by WebCrypto) and a write of the row back with token and proof (a
  second round trip); then the seal under the message key.

This was measured in the sealed mode of `docs/e2e/cover-timers/`:

- three real `CoverRuntime`s on one page, the edges of one room: one slot
  grid, one shared timer worker;
- real PQ runtimes and sealers, and the real database worker over IndexedDB;
- recorder lanes in place of WebRTC;
- two edges carry a job each cycle in rotation (first send, control, re-send),
  and the third carries none;
- Chrome for Testing 159, macOS 27.2 arm64, screen locked, page kept visible
  as above;
- 100 ms slots, 90 s visible, 1-minute load average 1.9 to 2.3.

| Cell (100 ms slots, page visible) | Wake-up to `send` (median / p99 / max) | Slot to `send` (median / p99) | Later than 99 % of dummies |
| --------------------------------- | -------------------------------------- | ----------------------------- | -------------------------- |
| dummy (1,763)                     | 0.5 / 1.4 / 2.6 ms                     | 9.3 / 12.4 ms                 | 1 % by definition          |
| control (294)                     | 0.5 / 1.4 / 1.4 ms                     | 9.1 / 12.1 ms                 | 0 %                        |
| real, re-send (293)               | 1.5 / 4.0 / 7.7 ms                     | 9.9 / 14.6 ms                 | 13 %                       |
| real, first send (293)            | 3.0 / 6.1 / 29.5 ms                    | 11.3 / 17.1 ms                | 38 %                       |

The Kolmogorov–Smirnov distance from the dummies' distribution was 0.41 for
first sends and 0.22 for re-sends. With 500 ms slots it was 0.55, with 54 % of
first sends later than 99 % of dummies.

The observer this has to defeat is one on the sender's LAN or at the TURN
relay. It timestamps packets to well under a millisecond, and the path from
the sender to it adds well under a millisecond of jitter. A millisecond is
assumed as its resolution. Network jitter on a long path would blur a 2 ms
shift, but not for that observer. And a job's lane carries every one of its
cells in one cycle, so it does not need to classify single cells.

Two designs were considered:

- (a) produce the cell for slot k during slot k − 1, and only send at slot k;
- (b) produce at the wake-up and send at a fixed offset after it, the offset
  a constant above the worst production time.

(a) was chosen:

- a fixed offset must stay under the smallest slot spacing (25 ms), and a
  single first-send production was measured at 29.5 ms (46 ms later). (a)
  gives a cell about one slot spacing: 100 ms here, 312 ms in the 10 s preset;
- (b) needs a second wake-up per slot, which on a hidden page would run late
  as the first does (above), and it delays every cell by the offset.

The costs of (a):

- no added latency on the wire;
- each edge holds one produced cell (65,490 bytes, sealed) between slots;
- a receipt or chunk that becomes ready after its lane's next cell was
  produced waits for that lane's following slot;
- the first slot of a cycle has half a slot spacing to be produced in, since
  its cell can only be produced once the cycle's lanes and jobs exist;
- a cancel, a completion or a rekey after the next cell was produced makes the
  scheduler produce that slot's cell again (a CANCEL, or a dummy), so a
  cancelled, completed or retired job never sends a cell it produced earlier.

A cell that is produced but not sent stays with its job and goes in the job's
next slot (the job sends it once, and no second production of the job runs
while one is still running). A dummy that is not sent is zeroed. A job that
settles, including at teardown, zeroes its unsent cells. The scheduler holds
only sealed cells; the plaintext exists while the producer seals it.

The page's timer host runs every wake-up already due on the page's clock in
one task, and the scheduler starts each production in a microtask. So when
edges of one room fall due together, every edge sends (or opens its lanes)
before any edge produces its next cell. Without this, the measurement showed
one lane's cells leaving 0.5 ms later than the other's on every edge, real or
dummy, from the work that ran between the sends
(`results-2026-11-26-sealed-100ms-slots-produced-ahead-unbatched.json`).

Measured after the change, same setup:

| Cell (100 ms slots, page visible) | Wake-up to `send` (max) | Slot to `send` (median / p99) | Later than 99 % of dummies |
| --------------------------------- | ----------------------- | ----------------------------- | -------------------------- |
| dummy (1,759)                     | 0.2 ms                  | 8.6 / 11.1 ms                 | 1 % by definition          |
| control (296)                     | 0.2 ms                  | 8.6 / 11.1 ms                 | 0.3 %                      |
| real, re-send (291)               | 0.2 ms                  | 8.6 / 11.1 ms                 | 0.3 %                      |
| real, first send (290)            | 0.1 ms                  | 8.6 / 11.1 ms                 | 0.3 %                      |

The Kolmogorov–Smirnov distances were 0.04 to 0.06, under the 0.09 that a
difference would need at these sample sizes to show at the 5 % level; before
the change they were 0.22 to 0.41. The idle edge's dummies left at the same
time beside another edge's real cells as beside its dummies (distance 0.04).
With 500 ms slots (60 s visible) every kind left at a median of 7.8 to 7.9 ms
after its slot, with distances of 0.10 to 0.13 on 32 to 45 cells, under the
0.24 needed there.

On the hidden page, before and after, cells left 140 to 180 ms after their
slots at the median, and that spread hid a 2 ms production difference from
this test (distances 0.06 to 0.08). In the 500 ms run after the change, from
about 200 s into the hidden phase, the host's load average rose from 12 to
over 300 (other work on the host), and every degraded cycle of that run (39 of
177, counted over the three edges) fell in that period. Before the change
none degraded, at a load average of 2 to 6 during its hidden phase.

What remains observable:

- a production that is not ready at its slot is a late slot: the cycle
  degrades, as it does for a late wake-up (what a late slot does is an open
  owner decision). Only a real cell is slow enough for that, so a degraded
  cycle can follow a slow store. In the 100 ms run, 1 of 261 visible cycles
  degraded this way: a first send's write back took 44.7 ms, for the first
  slot of a cycle, which has 50 ms. Before the change that cell would have
  gone 46 ms late, inside the tolerance;
- the hidden page's lateness, the same for every cell (above);
- a control cell (a receipt) produced under a PQ epoch that a rekey retires
  before its slot is sent as produced, and the peer drops it, as for a
  receipt held back by backpressure before. A dummy or a CANCEL is produced
  again under the new epoch;
- the page's own main-thread work (rendering, the application, garbage
  collection) delays wake-ups whatever the cells carry. These runs had none.

## Alternatives rejected

- **Keep the one-byte epoch:** creates an unspecified wrap/replay window and
  leaves the epoch unauthenticated.
- **Separate DR and PQ database rows:** permits crash-visible split brain and
  message-key reuse.
- **Store combined keys in `RatchetState.skipped`:** restoration would combine
  an already-combined key again.
- **Treat `RTCDataChannel.send()` or open state as ACK:** neither is a
  peer-authenticated application acknowledgement.
- **Open/close cover channels around real activity:** directly leaks activity.
- **Catch up missed browser timers:** converts suspension into a distinctive
  burst.
- **Immediate fallback on cover failure:** silently removes the room-wide
  guarantee.

## Consequences and claim boundary

Immediate/no-cover remains the product default. Scheduled mode spends fixed
bandwidth and channel churn whether or not users speak. It hides application
cell count, timing, completion and cancellation relative to its declared
schedule; it does not hide IP addresses, peer association, browser suspension,
congestion, or global correlation. WebRTC/SCTP/DTLS fragmentation means equal
application cells are a hypothesis to validate with direct and TURN packet
traces, not a proof of packet-trace indistinguishability.

The paper claim remains an architecture-specific systems result: authenticated
room policy, sparse standard ML-KEM healing, a classical Double Ratchet,
fixed-size WebRTC cells, scheduled dummy substitution, per-message channel UX,
and n-peer mesh evaluation. The key combiner is an engineered construction
until the formal model covers this exact composition.
