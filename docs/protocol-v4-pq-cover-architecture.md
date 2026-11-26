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
  not built. On the hidden page, kinds of cell were compared only at 500 ms
  slots on one grid, where they left alike (all 1,770 cells sent; KS 0.06 to
  0.07 against 0.10). At 25 and 100 ms slots almost every hidden cycle
  degraded (at most 51 of up to 1,770 cells were sent), so nothing could be
  compared there.
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

- after a slot's send, the next slot's dummy is sealed first, for every slot
  whatever it carries; then, if that slot's lane has a job, the job's cell is
  produced. What runs between two wake-ups is therefore the same up to the
  dummy's seal and differs after it: a job slot also runs its job's
  production (a control cell's seal; for a real chunk a store read, on a
  first send a receipt token and a write back, then the seal);
- the wake-up sends the job's cell if it is ready, otherwise the slot's dummy,
  on time. Nothing that depends on which of them goes runs before the send:
  zeroing the dummy that was not used, and marking a job that lost its slot,
  run after it. A job's cell that was not ready (or whose production failed)
  keeps its chunk for a later slot of its lane, and at the cycle's end a job
  that lost a slot this way is requeued rather than failed. Before this, a
  cell not ready at its slot degraded the cycle, and the edge went silent for
  the rest of it; only a slow real production could cause that, so the
  silence showed that one was there;
- what a late wake-up does (the timer itself past the tolerance) is
  unchanged: the cycle degrades. That remains an open owner decision;
- the page's timer host runs every wake-up already due on the page's clock in
  one task, and a production starts in a microtask after that task's
  callbacks, so the edges of one grid all send (or open their lanes) before
  any of them produces;
- a CANCEL does not wait for a chunk's production: a cancelled job whose store
  read never returns still sends its CANCEL in its lane's next slot and
  settles, and whatever the read returns later is zeroed and not sent.

What (a) costs:

- no added latency on the wire;
- one dummy seal more for every slot whose lane has a job;
- a chunk whose production overruns its slot costs about five dummies on its
  lane (the one in its place, and the lane's dummy tail when the job, requeued,
  finishes a cycle later). The summaries count those dummies
  (`fallbackDummies`): 5 of 877 job slots at 100 ms, 10 to 20 of about 1,750 at
  25 ms with gaps between jobs, and 130 to 173 of about 3,400 at 25 ms with
  1,600-cell messages, so about 1, 2 to 4 and 26 to 35 overruns;
- each edge holds up to two produced cells (65,490 bytes each) between slots;
- a receipt or chunk that becomes ready after its lane's next cell was
  produced waits for that lane's following slot;
- the first slot of a cycle has half a slot spacing to be produced in, since
  its cell can only be produced once the cycle's lanes and jobs exist;
- a production's synchronous parts run on the page's thread between
  wake-ups, so one that is running when another grid's wake-up on the same
  page falls due delays that wake-up by up to its own length. Measured sizes:
  a dummy's seal 0.5 ms at the median, at most 2.6 ms on a visible page (once
  9.7 ms on a hidden one); a control cell's seal
  at most 3.1 ms; a chunk's seal at most about 1.8 ms; a message's proof-level
  build, once on its first cell, 4.0 ms at 1,600 cells (6.2 to 7.0 ms the
  first time in a run) and more for larger files. Taking the proof-level build
  off the page's thread is a separate task (A4b);
- a cancel, a completion or a rekey after the next cell was produced makes the
  scheduler produce that slot's cell again (a CANCEL, or a dummy), so a
  cancelled, completed or retired job never sends a cell it produced earlier.
  A receipt cell produced before a rekey, or still being produced when the
  rekey lands, is sealed again under the new epoch: the drain job puts its
  receipt back at the head of the queue. So a receipt's tokens stay in memory,
  unwiped, from its seal until its cell is sent (about one slot), or until the
  drain job settles, which wipes them.

A cell that is produced but not sent stays with its job and goes in the job's
next slot (the job sends it once, and no second production of the job runs
while one is still running). A dummy that is not sent is zeroed. A job that
settles, including at teardown, zeroes its unsent cells. The scheduler holds
only sealed cells; the producer in `handleSendMessage.ts` zeroes a real
chunk's plaintext and its staged copy once it has sealed it.

#### What was measured after the change

All in the sealed mode of `docs/e2e/cover-timers/`, Chrome for Testing 159,
macOS 27.2 arm64, the screen locked and the page kept visible as above, the
host's 1-minute load average 2.6 to 5.1 unless stated. The times are those of
`send()` on the data channel (recorder channels, no WebRTC), not of packets
leaving the machine. Offsets subtract the scheduler's slot deadline (page
`Date.now()`) from `performance.timeOrigin + performance.now()`, so their
absolute value includes the offset between those two clocks: medians of −0.3
to +0.9 ms (at most 1.0 ms) in these runs, and one run drifted 1.1 ms from its
start to its end (each summary records it). Comparisons on one page do not
depend on it. The Kolmogorov–Smirnov critical values quoted assume
independent cells; cells of one instant share its lateness, so they overstate
significance.

The runs in this section were made on a working tree, before the changes of
the second review round (their summaries name the code as a working tree and
give the hashes of its bundle and entry file), some of them with the
production clearance that round removed.

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
rose from 12 to over 300. Its summary lists every edge's degraded cycles by
the scheduler's reason: 9 of each edge's 13 had a missed-deadline degrade in
that cycle or the one before, and for the other 4 the summary finds no degrade
event in that cycle or the one before. The idle edge, which produces no real
cell, degraded in the same cycles as the busy ones, so the cause was not
cells that were not ready. A cell not ready can no longer degrade a cycle. A
dummy not ready could (reason `dummy-not-ready`), but only with an
asynchronous `makeDummy`; `CoverRuntime`'s is synchronous, and no run had one.

Two grids on one page, with a job in every cycle: a busy grid (two edges with
jobs, one idle edge) and idle grids of one edge each, 1, 2, 3, 5 and 10 ms off
it. At 100 ms slots the kinds' medians were within 0.4 ms of the dummies' and
their KS distances under the critical value but one (first sends in the
1,600-cell run, 0.096 against 0.086). At 25 ms the pooled comparison
differed (KS 0.12 to 0.15), which the slot position explains: real cells ride
their lane's slots, the first slot of every cycle among them, and the first
slot of a cycle, armed half a slot ahead, ran earlier than the others (0.8 ms
after its slot against 7.3 to 7.6 ms at 25 ms slots).

Then with a cycle between one job and the next on each busy edge, so that the
same slots carry a job in some cycles and dummies in others, at 25 and 100 ms
slots with 5- and 1,600-cell messages, comparing cycles that carried a job
with cycles that did not. A review of these runs took cycles as the unit:
each cycle's mean offset over every cell of every edge (each against its
edge's median), job cycles against the others, with a permutation test over
the cycles:

| Slots, message size | Job minus no-job cycles | Permutation p |
| ------------------- | ----------------------- | ------------- |
| 100 ms, 5 cells     | −0.11 ms                | 0.54          |
| 100 ms, 1,600 cells | −0.18 ms                | 0.36          |
| 25 ms, 5 cells      | +0.05 ms                | 0.35          |
| 25 ms, 1,600 cells  | −0.12 ms                | 0.036         |

No cycle-level shift is established at these sample sizes; the one p under
0.05 is not corrected for four tests. The "up to 1.2 ms" stated before was a
median over cells at a few slot positions of a two-mode lateness; position by
position the job-minus-no-job difference ran from −1.6 to +1.3 ms, with both
signs. If the largest of these values were real, an observer of one edge
(whose cycle means spread by 1.2 to 1.3 ms at 100 ms slots and 0.2 to 0.85 ms
at 25 ms) would need about 150 to 600 cycles of each kind to tell them apart
(one-sided 5 %, power 80 %), and would classify a single cycle right about
55 % of the time. The harness may bias this comparison: in those runs the
timer that enqueued the next job fired in the cycle without a job, at about
its eighth slot. Open questions, not tested: the browser's or the system's
timer leeway with the screen locked; the database worker's activity; garbage
collection; a production overlapping a wake-up.

#### Confirmatory runs, from commit 8002f47

These four runs were made from an archive of commit `8002f47`: the bundle was
built from it (SHA-256 `04cd594d…`, the same on a rebuild), the entry file's
SHA-256 (`adc331f6…`) is the committed file's, and each summary's `code` is
the commit. Two grids on one page as above (a busy grid of two edges with jobs
and its idle edge; idle grids 1, 2, 3, 5, 7 and 10 ms off it), jobs in every
other cycle on both busy edges alike (enqueued by a page timer that fires in
the middle of every cycle, job cycle or not), page visible, 120 s at 25 ms
slots and 180 s at 100 ms slots. The host's screen was locked when the first
run started and unlocked about two minutes into it, and stayed unlocked for
the other three (recorded with each run); the 1-minute load average was 7 to
9, from other work on the host. Clock offsets: medians of −0.7 to +1.1 ms.

| Slots, message size | Cells sent (degraded cycles) | Kinds vs the idle edge's dummies at the same position: shift; KS (5 % critical) | Job minus no-job cycles, page: difference; permutation p | Per edge: p (smallest) |
| ------------------- | ---------------------------- | ------------------------------------------------------------------------------- | -------------------------------------------------------- | ---------------------- |
| 25 ms, 5 cells      | 42,480 (0)                   | −0.1 to 0 ms; 0.029 to 0.056 (0.052)                                            | −0.04 ms; 0.49 (240 and 232 cycles)                      | 0.34                   |
| 25 ms, 1,600 cells  | 42,390 (0)                   | 0 to +0.1 ms; 0.043 to 0.063 (0.052)                                            | +0.05 ms; 0.079 (242 and 229 cycles)                     | 0.018                  |
| 100 ms, 5 cells     | 16,020 (0)                   | −0.2 to −0.1 ms; 0.031 to 0.056 (0.085)                                         | −0.002 ms; 0.98 (89 and 89 cycles)                       | 0.068                  |
| 100 ms, 1,600 cells | 15,930 (0)                   | 0 to +0.1 ms; 0.023 to 0.036 (0.085)                                            | +0.007 ms; 0.94 (89 and 89 cycles)                       | 0.52                   |

The per-cycle figures come from the committed summariser (cycles as the unit,
10,000 permutations, fixed seed). No cycle-level shift shows: the page-wide
differences are under 0.05 ms with p from 0.079 to 0.98. Of the 36 per-edge
tests, two have p under 0.05 (0.018 and 0.021, both in the 25 ms 1,600-cell
run, for the grids 5 and 7 ms off, with opposite signs), as about two in 36
would by chance. A cycle's mean offset on one edge spread by 0.19 to 0.85 ms;
the largest per-edge |d′| was 0.28, for which an observer would need about
160 cycles of each kind, and would classify one cycle right 56 % of the time.
At the same slot position, kinds of cell left within 0.2 ms of the idle edge's
dummies; three of the six KS distances at 25 ms are a little over the
critical value, which overstates significance here (above). The first slot of
a cycle again ran earlier than the others, by about 3 ms at 25 ms slots
(0.9 ms after its slot against 3.8 to 4.3 ms), less than with the screen
locked. Every slot of every cycle was sent; 20 and 35 of the 25 ms runs' slots
were a job lane's dummies in place of a cell not ready or in a dummy tail.

What remains observable:

- the first slot of each cycle leaves earlier than the cycle's other slots, at
  25 ms slots by about 6.5 ms with the screen locked and 3 ms with it
  unlocked. That is the same whatever the slots carry, and
  shows where cycles start, which the lanes' opening at each boundary shows
  already;
- a job's chunk delayed by a lane period when its production overran its slot.
  The slot itself still went out on time;
- a production's synchronous parts, which delay another grid's wake-up that
  falls due while they run (sizes above), the proof-level build of a large
  message the longest of them;
- the hidden page's lateness, the same for every cell where it was compared
  (above);
- the page's own main-thread work (rendering, the application, garbage
  collection) delays wake-ups whatever the cells carry. These runs had none.

Not measured: a quiet host (the confirmatory runs had the screen unlocked but
other work running), a hidden page at 25 or 100 ms slots, other browsers,
messages larger than 1,600 cells, idle grids at other offsets than 1 to
10 ms, packets on the wire.

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
