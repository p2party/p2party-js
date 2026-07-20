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

## Design overview

A per-message-per-peer transfer becomes a small state machine backed by durable
state, with **selective** retransmit (resend only what's missing) and a close
gated on full receipting.

```
sender edge state  (persistent, per (peerId, hashHex)):
  ackedReal : Set<chunkIndex>     // real chunks the receiver has acked
  totalFrames : number            // real + decoy (sender knows this)
  receiptsSeen : number           // any 64-byte receipt (for close gating)
  retransmits : number            // telemetry
  complete : boolean

receiver edge state (persistent — mostly already in IndexedDB):
  chunks store                    // received real chunks, keyed [merkleRoot, idx]
  messageData.savedSize/totalSize // real progress
  receivedIdx : Set<chunkIndex>   // NEW: indices received (real+decoy) — for the
                                  //      reconnect have-set; persisted per message
```

## Wire changes

1. **Add `totalChunks` (u64) to the encrypted metadata** (`utils.h` Metadata +
   `serialize_metadata`/`deserialize_metadata` in C, `metadata.ts` twin,
   `METADATA_LEN` in `utils.h`/`constants.ts`). It rides inside the AEAD, so no
   leak. Lets the receiver size its `receivedIdx` set / bitfield and lets both
   sides reason about "all frames". Rebuild WASM.
2. **Have-set reconcile message** (control frame): on reconnect the receiver
   sends its `receivedIdx` as a compact bitfield (`ceil(totalChunks/8)` bytes)
   over the (re-opened) per-message channel, padded to the uniform 64-byte
   receipt size class or larger, framed with an in-band type marker so it routes
   distinctly from data (65536) and receipts (64). Sender replies by resending
   the missing REAL chunks. (Encoding + routing marker: see Open questions.)

## Sender behavior

- **Selective retransmit** (obj 2). After the initial `sendChunks` pass, loop:
  wait `RETRANSMIT_TIMEOUT_MS` (linear backoff) polling `complete`; if not
  complete and channel open, **resend only `realIndices \ ackedReal`** via a new
  `sendChunks(…, onlyIndices)` variant (re-encrypts fresh frames for just those
  indices). Stop on `complete` or `MAX_RETRANSMITS`. `ackedReal` is updated in
  `handleReadReceipt` (real receipt → `getDBNewChunk` → index → add). Selective
  (not resend-all) is REQUIRED: resend-all buffered dups that (a) broke receipt
  uniformity and (b) left ~235 KB un-drained at teardown.
- **`realIndices`**: real chunks are created first in `splitToChunks`, so they
  are indices `[0, realCount)`. Persist `realCount` (or derive from `totalSize`
  and the chunk-fill) in the sender edge state at send time.
- **Constants** live in `src/utils/constants.ts` (SSOT): `MAX_RETRANSMITS`,
  `RETRANSMIT_TIMEOUT_MS`, `DRAIN_CLOSE_TIMEOUT_MS`, `DRAIN_CLOSE_POLL_MS`.

## Receiver behavior

- **Timing-normalized receipt emission** (obj 4 timing). Reintroduce the
  per-channel receipt scheduler (queue + fixed-cadence batch flush) so emission
  time reflects the timer, not per-chunk verify/DB latency. Safe now because the
  sender's close is gated on all-frames-receipted (below), so trailing decoy
  receipts are never cut off — the exact race that killed the standalone
  scheduler.
- **`receivedIdx` tracking**: on each stored/decoy frame, record its index;
  persist per `(merkleRoot)` so a reconnecting receiver can produce the have-set.
- **No WS-relay of receipt content** (obj 4 relay): stop relaying real-receipt
  leaf hashes through the signaling server; rely on the data channel + retransmit
  (and the raised `MAX_BUFFERED_AMOUNT` already keeps traffic on the DC).

## Close sequencing (obj 3 + obj 4 timing)

Sender closes the per-message channel only when ALL hold:
1. `complete` — all real chunks acked (receiver's final message-hash receipt).
2. `receiptsSeen >= totalFrames` — every frame (real + decoy) has drawn a
   receipt, so the receiver's trailing decoy receipts are not cut off (preserves
   count + timing uniformity). Bounded by a grace timeout as a safety net.
3. `bufferedAmount === 0` via `drainAndClose` (already merged).

This replaces "close immediately on the final receipt" and is what makes the
timing-normalized scheduler safe.

## Relay-open fix

`handleSendMessage` currently relays a per-message channel's first frames when
the channel is still `connecting`. Wait for `readyState === "open"` (bounded
timeout) before the initial send; anything that still slips is recovered by
retransmit. Removes the intermittent uniformity-defeating relay.

## Resume-on-renegotiation

The reconnect path (`handleConnectToPeer` `restartIce`/reconnect, and the
per-peer negotiation mutex already added) triggers, for each in-flight message:
1. Re-open the same Merkle-root-labeled per-message channel.
2. Receiver sends its `receivedIdx` have-set (bitfield).
3. Sender resends missing real chunks from `newChunks` (persistent).
4. Idempotent apply (obj 1) absorbs any overlap; completion/close as above.

Because sender `ackedReal` and receiver `receivedIdx`/`chunks` are persisted,
state survives the drop. This is the same durable per-edge record that will hold
the Double Ratchet session keys ([[p2party-double-ratchet-plan]]) — build ONE
per-edge store, not two.

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

- **Have-set/control-frame framing & routing.** Data routes by size (65536),
  receipts by size (64). A have-set/reconcile frame needs an in-band type marker
  and a routing branch in `handleOpenChannel.onmessage` without shifting the
  fixed WASM offsets for data frames. Decide the marker scheme (reserved control
  size vs a tagged 64-byte frame) — must not be a NEW distinguishable size class
  that leaks (per obj 4).
- **`receiptsSeen >= totalFrames` under loss.** Reliable SCTP delivers all
  frames, but the grace-timeout fallback must be tuned so close isn't delayed
  unduly; and retransmit interacts with the counter (count receipts for resent
  frames? — yes, each received frame is receipted once by index-dedup).
- **State growth / cleanup.** Persistent sender/receiver edge state must be
  cleaned on completion/cancel/purge; cap per-edge memory (MAX_SKIP-style).
- **`totalChunks` metadata add** breaks the wire again (rebuild + CDN redeploy) —
  batch it with the metadata change, keep within 0.9.0 (unreleased).
- **Selective resend of decoys.** Decoys are cover; do NOT resend them (they are
  never acked) — resend only reals. Confirm the receiver still gets uniform
  receipts for the resent reals.

## Implementation sequencing

1. **Metadata `totalChunks`** (C + TS + WASM rebuild) — enables everything below.
2. **Persistent edge state** (IndexedDB store keyed by `(peerId, hashHex)`): sender
   `ackedReal`/`realCount`/`retransmits`; receiver `receivedIdx`. Shared with the
   ratchet later.
3. **Selective retransmit** (`sendChunks` `onlyIndices` variant + the loop) +
   `handleReadReceipt` ack tracking. E2E loss injection.
4. **Close gating** (complete + all-receipted + drained) + **relay-open wait**.
5. **Timing-normalized receipt scheduler** (now safe under close gating) + stop
   relaying receipt content. E2E.
6. **Reconcile-on-reconnect** (have-set control frame + resend missing). E2E resume.
7. **Telemetry + real progress** in message state and p2party.com UI.

Each step is independently E2E-verifiable; ship as further 0.9.0 protocol-v2
increments. Deploy still needs `npm run uploadcdn`.
