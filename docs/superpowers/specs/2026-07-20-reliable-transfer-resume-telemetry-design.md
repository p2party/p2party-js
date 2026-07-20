# Reliable transfer + resume + telemetry — design spec

Date: 2026-07-20
Repo: `p2party-js`
Status: design (pre-implementation). Part of the 0.9.0 protocol-v2 line (wire changes allowed).

## Motivation

The chunk-transfer layer must satisfy four user objectives, be a stepping stone
to **resume-on-renegotiation**, and surface **telemetry** so a human can see the
obfuscation and reliability working. Two incremental prototypes (a fixed-cadence
receipt scheduler; a resend-all retransmit) each hit subtle races and were
reverted — so this is designed as ONE coherent subsystem, spec-first.

### Objectives
1. **No double-store** — a chunk stored twice would overshoot `savedSize` and corrupt the message.
2. **Sender sends all needed chunks** — never stop until every load-bearing chunk is delivered.
3. **No close before verified** — completion/close must not fire until receipt is verified, and must not wipe un-flushed data.
4. **Receipts leak nothing about content or size** — an observer of the receipts cannot recover the real message content or the real chunk count.

Plus: **resume-on-renegotiation** (continue an in-flight message after an ICE
restart/reconnect) and **telemetry** (total chunks received incl. decoys, how
many were real, retransmit count; progress % over the REAL message).

## Current state (baseline on master)

- **Obj 1 — SAFE.** `fnSetDBChunk` uses `db.add("chunks", …)` keyed by `[merkleRoot, chunkIndex]` → throws on duplicate → `handleReceiveMessage` catch → `chunkAlreadyExists:true` → `savedSize` advance gated on `!chunkAlreadyExists` (handleMessageQueueing.ts) and clamped to `totalSize`. Resends are idempotent — the precondition for retransmission.
- **Obj 3 — partially done.** Completion rides the receiver's final message-hash receipt (`savedSize === totalSize`); `drainAndClose` (merged) closes only at `bufferedAmount === 0`. Remaining: gate the close on *all frames receipted* so trailing decoy receipts aren't cut off (see §Close sequencing).
- **Obj 4 — count done, timing/relay open.** Receipt-count uniformity merged (one receipt per real+decoy frame). Open: (i) real chunks are delayed by verify+IndexedDB before their receipt while decoys aren't → inter-receipt **timing** separates them; (ii) real receipts relayed via the signaling server on the WS-relay path leak leaf hashes + the split.
- **Obj 2 — GAP.** Send loop is one-pass; no retransmit.

## Principles (KISS / DRY / SSOT)

- **DRY — retransmit *is* resume.** Both are one operation: "resend the real
  chunks the receiver hasn't acked." The only difference is the trigger — a
  live timeout, or a reconnect (where the receiver re-emits its receipts first).
  ONE `reconcile()` path, two triggers. No separate resume machinery.
- **DRY — one send path.** Selective resend reuses `sendChunks` with an optional
  `onlyIndices?: Set<number>` filter, not a second function.
- **KISS — no new wire, no new store, no bitfield.** Receipts are the have-set;
  the sender extrapolates. The sender's ack-set is disposable in-memory state
  (rebuilt from receipts). The durable sources already exist: sender `newChunks`,
  receiver `chunks`.
- **SSOT — one place per fact.** Real-vs-decoy is read from a chunk's metadata
  (`chunkEndIndex − chunkStartIndex ≤ totalSize`), never tracked separately. The
  leaf hash is stored once, as a field on the receiver's chunk record (not a
  parallel set). All tunables live in `src/utils/constants.ts`.
- **KISS — layer the subtle stuff.** The core (reconcile + telemetry + real %)
  ships first and is simple. The obj-4 *timing* hardening (normalized receipt
  emission + close-gated-on-all-receipted) is an optional later layer — it does
  not block the reliability/resume value.

## Design overview

A per-message-per-peer transfer is a small in-memory state machine over the
already-persistent chunk stores, driven by one `reconcile()` (selective resend
of un-acked reals).

```
sender edge state  (IN-MEMORY per (peerId, hashHex); durable source is newChunks):
  ackedReal : Set<chunkIndex>     // EXTRAPOLATED from received leaf-hash receipts
  totalFrames : number            // real + decoy (the sender created them)
  receiptsSeen : number           // any 64-byte receipt (close gating)
  retransmits : number            // telemetry
  complete : boolean
  // Rebuilt on reconnect from the receiver's re-sent receipts — no persistent
  // sender ack store. `newChunks` (IndexedDB, already persisted) is the durable
  // resend source.

receiver edge state (mostly already in IndexedDB):
  chunks store                    // received real chunks, keyed [merkleRoot, idx]
  messageData.savedSize/totalSize // real progress
  receivedHashes                  // NEW (small): the leaf hashes it has receipted,
                                  //      stored alongside each chunk, so it can
                                  //      re-emit them as receipts on reconnect
```

## Wire changes

**None.** The reconcile reuses the existing 64-byte leaf-hash receipt — the
receipts ARE the have-set. There is no `totalChunks` metadata field, no bitfield,
and no new control-frame type or routing marker.

Key insight: the receiver's per-chunk receipt is the chunk's leaf hash, and the
sender already resolves a received receipt to a chunk index via
`getDBNewChunk(hash) → chunkIndex` (handleReadReceipt.ts:61). So the set of
receipts the sender has seen IS the acked set — the sender **extrapolates** which
real chunks the receiver holds, and therefore which are missing, without the
receiver ever transmitting sizes, indices, or a bitfield. On reconnect the
receiver simply re-emits the leaf-hash receipts for the chunks it holds, and the
sender rebuilds the acked set from them.

## Sender behavior — one `reconcile()`, two triggers

`reconcile()` = "resend the real chunks not in `ackedReal`, read from `newChunks`,
via `sendChunks(channel, …, onlyIndices)`." Reused for both cases:
- **Live** (obj 2): after the initial send, while `!complete` — wait
  `RETRANSMIT_TIMEOUT_MS` (linear backoff) polling `complete`, then `reconcile()`;
  stop on `complete` or `MAX_RETRANSMITS`.
- **Resume** (reconnect): the receiver re-emits its receipts, the sender rebuilds
  `ackedReal`, then `reconcile()` — the same call.

`ackedReal` is built in `handleReadReceipt`: a real receipt resolves via
`getDBNewChunk(hash) → chunkIndex` (already the code today) → add to the set.
Real indices are `[0, realCount)` (splitToChunks creates reals first); read
real-vs-decoy from a chunk's metadata (`chunkEnd − chunkStart ≤ totalSize`) — do
NOT track it separately (SSOT). Selective only (never resend-all): resend-all
buffered dups that broke uniformity and left buffers un-drained. Tunables
(`MAX_RETRANSMITS`, `RETRANSMIT_TIMEOUT_MS`, `DRAIN_CLOSE_*`) in `constants.ts`.

## Receiver behavior

Core (ships with the reliability layer):
- **Store the leaf hash on the chunk record** (SSOT). The receiver already stores
  received chunks; add the 64-byte leaf hash as a field so it can re-emit receipts
  on reconnect without recomputing (it kept only the real slice, not the full
  padded chunk). No parallel set.
- **Emit receipts as today** (one 64-byte receipt per frame — real leaf hash /
  decoy random / final message-hash), and **re-emit them all on reconnect** from
  the stored leaf hashes.
- **Stop relaying receipt content via the signaling server** (obj 4 relay): the
  real-receipt hash currently goes through the WS relay when the channel isn't
  open; drop it (the raised `MAX_BUFFERED_AMOUNT` + retransmit make it moot).

Optional obj-4 *timing* layer (later — see Sequencing): normalize per-receipt
emission timing (fixed-cadence flush) so real-vs-decoy processing latency doesn't
show through. Only safe together with close-gating-on-all-receipted, which is why
it's layered, not in the core.

## Close sequencing

Core close (obj 3): close the per-message channel when `complete` (receiver's
final message-hash receipt) AND `bufferedAmount === 0` (`drainAndClose`, merged).
Selective retransmit means no dup frames pile up, so drain is cheap.

Optional (with the timing layer): additionally gate on
`receiptsSeen >= totalFrames` (the sender knows `totalFrames`) so the receiver's
timing-delayed trailing receipts aren't cut off. Bounded by a grace timeout.

## Relay-open fix

`handleSendMessage` currently relays a per-message channel's first frames when
the channel is still `connecting`. Wait for `readyState === "open"` (bounded
timeout) before the initial send; anything that still slips is recovered by
retransmit. Removes the intermittent uniformity-defeating relay.

## Resume-on-renegotiation

The reconnect path (`handleConnectToPeer` `restartIce`/reconnect, and the
per-peer negotiation mutex already added) triggers, for each in-flight message:
1. Re-open the same Merkle-root-labeled per-message channel.
2. Receiver **re-emits the ordinary 64-byte leaf-hash receipts** for the chunks
   it already holds (from `receivedHashes`) — no special frame.
3. Sender resolves each via `getDBNewChunk`, rebuilds `ackedReal`, and resends
   the missing REAL chunks from `newChunks` (already persisted).
4. Idempotent apply (obj 1) absorbs overlap; completion/close as above.

Durable state that must survive the drop: the sender's `newChunks` (already
persisted) and the receiver's `chunks` + `receivedHashes`. The sender's ack-set
is disposable — rebuilt from the receiver's re-sent receipts. (The Double Ratchet
session keys will still want a durable per-edge record — [[p2party-double-ratchet-plan]] —
but the transfer reconcile itself needs no new sender store.)

## Telemetry + real progress

Expose in the Redux message model (roomSlice `Message`) and via `readMessage`:
- `chunksReceivedTotal` (incl. decoys) — receiver counts every processed frame.
- `chunksReceivedReal` — real chunks stored (`savedSize`/real chunk size, or a counter).
- `retransmits` — from the sender edge state, dispatched to message state.
Progress % must be over the REAL message: receiver `savedSize/totalSize` is
already decoy-free; fix the sender's split-phase % (uses `totalChunks`) to use
real chunks. The frontend (p2party.com) renders these live so a human validates
the obfuscation (total ≫ real) and reliability (retransmits) — spec'd here,
implemented in the consumer.

## How each objective is met

- **Obj 1** — unchanged `db.add` unique index; selective resends stay idempotent.
- **Obj 2** — selective retransmit until `complete`, bounded, backed off.
- **Obj 3** — close gated on complete + all-receipted + drained.
- **Obj 4** — count uniformity (done) + timing-normalized emission + no relay of
  receipt content + close-gated so no trailing receipts are dropped.

## Testing (real-WebRTC E2E, `p2party.com/e2e/run.mjs`)

- Uniformity: `count64 > count65536` on non-retransmit messages (robust to relay).
- Retransmit: loss-inject (drop one 65536 frame once) an ALL-real file → assert
  `__dropped` and byte-exact receipt; assert count64 still ≥ count65536 (selective
  resend adds no un-receipted dups).
- Drain: instrument `close()`; assert `bufferedAmount === 0` for per-message
  closes (exclude teardown closes, or drain those too).
- Resume: kill/restart one peer's connection mid-transfer; assert the message
  completes byte-exact after reconnect with only the missing chunks resent.
- Telemetry: assert message state exposes total/real/retransmit and % is real.

## Risks & open questions

RESOLVED by receipts-as-have-set: no control-frame framing/routing question
(reconcile reuses the 64-byte receipt) and no `totalChunks` metadata change (the
sender already knows totalFrames; the receiver never needs it). **No wire change
at all for the core.**

Remaining:
- **Reconnect trigger & single re-emit.** On reconnect the receiver re-emits its
  stored leaf-hash receipts once and the sender re-runs `reconcile()`. Keying
  "same in-flight message on the new channel" off the Merkle-root channel label —
  confirm the label survives the ICE restart.
- **Cleanup — reuse, don't parallel.** Clear the sender's in-memory edge state
  and cancel the reconcile loop on complete/cancel/purge; `newChunks`/`chunks`
  are already cleaned on those paths — hook the same lifecycle.
- **Caps.** `MAX_RETRANSMITS` + linear backoff bound the live loop (start 5 × 2s);
  the optional `receiptsSeen >= totalFrames` gate needs a grace fallback.
- **Decoys are never resent** (cover, never acked) — intended; `reconcile()`
  resends only reals.

## Implementation sequencing

Core — ships the reliability + resume + telemetry value, **no wire change, no new
WASM build**:
1. **`reconcile()` + selective resend** — `sendChunks(…, onlyIndices)` (DRY) +
   in-memory `ackedReal` built in `handleReadReceipt` + the live timeout loop.
   Store the receiver's leaf hash on the chunk record. E2E: loss injection.
2. **Relay-open wait** — send a per-message channel's frames only once it's
   `open` (bounded); anything that slips is recovered by `reconcile()`.
3. **Reconcile-on-reconnect** — receiver re-emits receipts; sender re-runs
   `reconcile()`. Same code as (1). E2E: kill/restart mid-transfer → byte-exact.
4. **Telemetry + real %** — message-state fields (total/real/retransmit) + fix
   the sender split-% to reals; p2party.com renders them.

Optional obj-4 *timing* layer (later, independent — touches C, needs a rebuild):
5. **Timing-normalized receipts** + **stop relaying receipt content** +
   **close-gate on `receiptsSeen >= totalFrames`** — together, or not at all.

Each step is independently E2E-verifiable; ship as 0.9.0 protocol-v2 increments.
`npm run uploadcdn` only if step 5 touches the WASM.

## Post-implementation notes — step 3 resume (2026-07-20)

**Built (no wire change, no WASM rebuild).** Resume is realized by keeping
`sendWithReconcile` ALIVE across the reconnect instead of the spec's original
"registry + re-derive destroyed WASM state" plan. When the per-message channel
goes `closed`/`closing`, the loop calls `resumeChannel()` (poll `peerConnections`
— the module-scoped array is mutated in place, so it gets the fresh `epc` — for a
`connected` peer, re-open the SAME Merkle-root label, wait the remaining budget),
sets `currentChannel` and continues. `senderSecretKey`/modules/`ackedReal` stay
in scope, so nothing is re-derived. Receiver persists `Chunk.leafHash` (optional
value field — NO dbVersion bump) and re-emits stored leaf-hash receipts on the
new channel's `onopen`, gated `merkleRootHex !== "" && typeof channel !== "string"`
(the receiver RECEIVES the per-message channel as an object; the sender OPENS it
as a string). New `getDBAllChunkLeafHashes` cursor getter. Verified end-to-end in
headless Chromium over real WebRTC: forced FULL reconnect mid-transfer with the WS
relay blocked → byte-exact completion, new `RTCPeerConnection`, P2P resend,
sender-retransmit telemetry, AND a send-buffer-leak assertion.

**Root-cause bug (the whole debug).** The per-message channel's `onclose`
deleted the sender's `newChunks` on ANY close — including a mid-transfer
disconnect — destroying the resend source (receiver stalled ~98%). Fixed by
gating `deleteDBNewChunk` on transfer completion. The WS-relay fallback masks
resume by silently completing broken transfers; block relay in the harness to
force pure-P2P and make resume deterministic.

**Adversarial-review fixes folded in (2026-07-20).**
- Completion `newChunks` leak (HIGH, deterministic on real links): the first gate
  re-read volatile reconcile state (`isTransferComplete`) AFTER `await
  drainAndClose`, which `clearTransfer` races → the whole message body leaked into
  IndexedDB on EVERY completed transfer. Fixed with an EXPLICIT `transferComplete`
  param from `handleReadReceipt` (race-free), regression-tested by the E2E
  send-buffer assertion via the new `getSendChunksCount` export.
- `resumeChannel` duplicate channels (HIGH): a slow-opening (>3.5s) resumed
  channel got re-created (dedup only matches OPEN channels), leaking WASM buffers
  and blocking `newChunks` cleanup. Fixed: create once, wait the REMAINING budget,
  neutralize an abandoned channel; also tightened the death test to `closed`/
  `closing` only.
- Permanent-disconnect `newChunks` leak (MEDIUM): gating removed the only
  auto-cleanup for abandoned sends. Fixed with a terminal `deleteDBNewChunk` after
  `Promise.allSettled` (idempotent, multi-peer-safe).
- Completion close now `drainAndClose` (obj 3) instead of bare `close()`.
- Re-emit loop got `bufferedAmount` backpressure (latent, pre-big-files).

**Documented residual limitations (deferred, NOT shipped-as-preserved):**
- **Obj-4 reconnect count leak.** The reconnect re-emit sends one receipt per REAL
  chunk held (not decoy-padded like live 1:1 operation), so the burst length
  reveals the real-chunk count to a passive DTLS traffic-analysis observer. Same
  category as the already-deferred obj-4 timing/relay gaps → belongs in the obj-4
  hardening layer (pace 1:1 with forward frames, or pad with decoy receipts). Live
  transfers (the common case) keep the 1:1 count-hiding. Content stays DTLS-
  confidential; only a size hint leaks, only on reconnect.
- **Send-mutex hold on drop (~timeout).** `handleSendMessage` runs under the
  process-global `sendMutex`; the resume poll holds it while waiting for the peer,
  so a peer that drops and never returns stalls other sends up to
  `RECONNECT_RESUME_TIMEOUT_MS`. Bounded (pre-diff all sends were already
  serialized). Proper fix: narrow the mutex to the WASM-touching sections.
- **`getDBAllChunkLeafHashes` is O(held bytes).** A value cursor deserializes each
  ~62KB chunk record to read a 128-char hex; fine today, but the GB-file streaming
  workstream should move leaf hashes to a key-only index / dedicated store.
- Pre-existing (NOT this diff): `handleOpenChannel` `onclose` frees ptr1..ptr5
  under `if (peerRoomIndex && ...)` which is falsy for index 0, and the completion
  path nulls `onclose` before close — receive buffers can leak per message-channel
  over a long-lived pc. Separate follow-up.
- Legacy chunks stored before `leafHash` existed are skipped by the re-emit (they
  fall back to normal reconcile resend) — transient to the upgrade window, self-
  healing thereafter.
