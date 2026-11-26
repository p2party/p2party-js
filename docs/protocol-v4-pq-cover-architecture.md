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
  not built. The shift was measured the same for every kind of cell, for the
  spacings, grids and message sizes the next section lists.
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

A slot's cells are produced during the slot before it, and the slot's wake-up
only sends one of them. Before that, the wake-up produced the cell and sent it
when it was ready, so a cell left at its wake-up plus however long it took to
produce:

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
  single first-send production was measured at 29.5 ms (46 ms, 124 ms and
  148 ms in later runs, from IndexedDB writes). (a) gives a cell about one slot
  spacing: 100 ms here, 312 ms in the 10 s preset;
- (b) needs a second wake-up per slot, which on a hidden page would run late
  as the first does (above), and it delays every cell by the offset.

How (a) works:

- every slot first gets its dummy, sealed for every slot whatever the slot
  carries; then, if the lane has a job, the job's cell is produced. So the work
  done for a slot before the job's production does not depend on what the
  slot will carry;
- the wake-up sends the job's cell if it is ready, otherwise the slot's dummy,
  on time. A job's cell that was not ready (or whose production failed) keeps
  its chunk for a later slot of its lane, and at the cycle's end a job that
  lost a slot this way is requeued rather than failed. Before this, a cell not
  ready at its slot degraded the cycle, and the edge went silent for the rest
  of it; only a slow real production could cause that, so the silence showed
  that one was there;
- what a late wake-up does (the timer itself past the tolerance) is
  unchanged: the cycle degrades. That remains an open owner decision;
- the page's timer host runs every wake-up already due on the page's clock in
  one task, and a production starts after that task, so the edges of one grid
  all send (or open their lanes) before any of them produces;
- a production also does not start while a wake-up of another grid on the
  page falls due within `COVER_PRODUCTION_CLEARANCE_MS` (6 ms). That covers
  the first synchronous work of a production: the slot's dummy seal and, on a
  control lane, the control cell's seal (at most 2.6 ms and 3.1 ms measured).
  It does not cover the synchronous work that follows a store read inside the
  producer (below).

What (a) costs:

- no added latency on the wire;
- one dummy seal more for every slot whose lane has a job;
- a chunk whose production overruns its slot goes one lane period later
  (counted as `fallbackDummies` in the summaries: 5 of 877 job slots at
  100 ms, 10 to 20 of about 1,750 at 25 ms with gaps between jobs, and 130 to
  173 of about 3,400 at 25 ms with 1,600-cell messages);
- each edge holds up to two produced cells (65,490 bytes each) between slots;
- a receipt or chunk that becomes ready after its lane's next cell was
  produced waits for that lane's following slot;
- the first slot of a cycle has half a slot spacing to be produced in, since
  its cell can only be produced once the cycle's lanes and jobs exist;
- a cancel, a completion or a rekey after the next cell was produced makes the
  scheduler produce that slot's cell again (a CANCEL, or a dummy), so a
  cancelled, completed or retired job never sends a cell it produced earlier.
  A receipt cell produced before a rekey is sealed again under the new epoch:
  the drain job puts its receipt back at the head of the queue.

A cell that is produced but not sent stays with its job and goes in the job's
next slot (the job sends it once, and no second production of the job runs
while one is still running). A dummy that is not sent is zeroed. A job that
settles, including at teardown, zeroes its unsent cells. The scheduler holds
only sealed cells. The plaintext of a real chunk (metadata, proof and data) is
built by the producer in `handleSendMessage.ts`, which at this commit does not
zero it after sealing.

#### What was measured after the change

All in the sealed mode of `docs/e2e/cover-timers/`, Chrome for Testing 159,
macOS 27.2 arm64, the screen locked and the page kept visible as above, the
host's 1-minute load average 2.6 to 5.1 unless stated. The times are those of
`send()` on the data channel (recorder channels, no WebRTC), not of packets
leaving the machine. Offsets subtract the scheduler's slot deadline (page
`Date.now()`) from `performance.timeOrigin + performance.now()`, so their
absolute value includes the offset between those two clocks, 0 to 0.9 ms in
these runs (recorded in each summary); comparisons on one page do not. The
Kolmogorov–Smirnov critical values quoted assume independent cells; cells of
one instant share its lateness, so they overstate significance.

One grid of three edges (two carrying a job each cycle, one idle), 5-cell
messages:

| Slots, phase       | Cells          | Degraded cycles | Kinds against dummies (KS, 5 % critical)    |
| ------------------ | -------------- | --------------- | ------------------------------------------- |
| 100 ms, 90 s shown | 2,610 of 2,610 | 0               | 0.03 to 0.08 (0.086); medians within 0.2 ms |
| 500 ms, 60 s shown | 300 of 300     | 0               | 0.13 to 0.18 (0.22 to 0.25)                 |
| 500 ms, 300 s hid  | 1,770 of 1,770 | 0               | 0.06 to 0.07 (0.10)                         |

In the 500 ms run no cycle degraded on the hidden page, at a load average of
2.6 to 5.1. The earlier 500 ms run after the first change had 39 degraded
cycles (13 on each of its three edges), all while the host's load average
rose from 12 to over 300. Its summary now lists every edge's degraded cycles
by the scheduler's reason: all were missed deadlines, and the idle edge, which
produces no real cell, degraded in the same cycles as the busy ones, so the
cause was late wake-ups, not cells that were not ready. A cell not ready can
no longer degrade a cycle; a dummy not ready could (reason `dummy-not-ready`),
and no run had one.

Two grids on one page: a busy grid (two edges with jobs, one idle edge) and
idle grids of one edge each, 1, 2, 3, 5, 7 and 10 ms off it, with a cycle
between one job and the next on each busy edge, so the same slots carry a job
in some cycles and dummies in others. Offsets are compared at the same slot
position (each against the median of the dummies at that position), because
the first slot of a cycle, armed half a slot ahead, ran earlier than the
others: 0.8 ms after its slot against 7.3 to 7.6 ms at 25 ms slots.

| Slots, message size | Busy grid kinds vs dummies (median shift, KS) | Idle grids 1–5 ms off, busy producing real vs dummy (shift, KS) | 5 % critical |
| ------------------- | --------------------------------------------- | --------------------------------------------------------------- | ------------ |
| 25 ms, 5 cells      | 0 ms; 0.05 to 0.08                            | +0.1 to +0.2 ms; 0.09 to 0.11                                   | 0.047–0.058  |
| 25 ms, 1,600 cells  | 0 to −0.1 ms; 0.06 to 0.07                    | 0 to −0.1 ms; 0.05 to 0.07                                      | 0.049–0.058  |
| 100 ms, 5 cells     | −0.4 to +0.2 ms; 0.08 to 0.09                 | −0.7 to −1.2 ms; 0.08 to 0.12                                   | 0.106–0.117  |
| 100 ms, 1,600 cells | −0.5 to −2.2 ms; 0.10 to 0.17                 | −0.6 to −0.9 ms; 0.08 to 0.09                                   | 0.106–0.117  |

With a job in every cycle (no gaps), the 100 ms runs showed no difference (KS
under the critical value, medians within 0.2 ms). At 25 ms the pooled
comparison did differ (KS 0.12 to 0.15), which the slot position explains:
real cells ride their lane's slots, the first slot of every cycle among them.

With the gaps, the cycles that carried jobs differed from those that did not
on every edge of the page, the idle grids included: up to 1.2 ms earlier at
100 ms slots, up to 0.2 ms later at 25 ms slots. Cells of one cycle still left
alike whatever they carried. It is not synchronous work running over a
wake-up: an idle grid's cell counted under "busy producing real" was sent in
the same batch as the busy grid's previous slot, before that production
started. The cause was not found. The production clearance did not change
these figures (the same runs without it are recorded too).

The proof levels of a message are built once, synchronously, when its first
cell is produced: 4.0 ms at the median for 1,600 cells (6.2 to 7.0 ms the
first time in a run), growing with the number of cells. That work runs inside
the producer (`handleSendMessage.ts`), after its first store read, so the
clearance does not cover it; a wake-up of any grid that falls due during it
waits. The two-grid runs above did not show it separately.

What remains observable:

- the first slot of each cycle leaves earlier than the cycle's other slots, at
  25 ms slots by about 6.5 ms. That is the same whatever the slots carry, and
  shows where cycles start, which the lanes' opening at each boundary shows
  already;
- whether a cycle carried jobs: on this host, such cycles ran up to 1.2 ms
  earlier (100 ms slots) or up to 0.2 ms later (25 ms slots) than cycles
  without, on every grid of the page (above). Real and dummy cells of the same
  cycle still leave alike;
- a job's chunk delayed by a lane period when its production overran its slot.
  The slot itself still went out on time;
- the proof-level build of a large message, synchronous inside the producer
  (above), measured up to 1,600 cells;
- the hidden page's lateness, the same for every cell (above);
- the page's own main-thread work (rendering, the application, garbage
  collection) delays wake-ups whatever the cells carry. These runs had none.

Not measured: a page with the screen unlocked, other browsers, messages
larger than 1,600 cells, idle grids at other offsets than 1 to 10 ms, packets
on the wire.

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
