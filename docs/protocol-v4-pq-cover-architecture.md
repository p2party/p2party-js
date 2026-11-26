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
A worker that raises its error event, cannot be reached, or does not answer
within 10 s is replaced:

- the pending wake-ups move to page timers at once;
- a new worker starts at a later cycle boundary, after a backoff of 1, 2 and
  then 4 s, at most 3 times;
- after that the page stays on page timers for good, and each scheduled-cover
  edge reports this once with `console.warn`.

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

So tab visibility can still be read off the wire:

- from cell timing, even when no cycle degrades. A cell is sent when its
  wake-up runs on the page. On a hidden page that was tens of milliseconds
  after the slot (median 50–60 ms), and on a visible one at most 6 ms. An
  observer timing cells against the slot grid sees the difference. Closing
  this needs the cells to be sent off the page's event loop, from the worker;
  this change does not do that.
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

