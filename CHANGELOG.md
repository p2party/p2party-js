# Changelog

All notable changes to the **p2party** SDK are documented here. This project
adheres to [Semantic Versioning](https://semver.org/) and the spirit of
[Keep a Changelog](https://keepachangelog.com/).

## [0.14.3] — 2026-07-27

### Added

- `getTransferAcks(roomId, transferId)`. Live outbound progress for one logical
  send: for every peer edge, how many chunks that peer has receipted so far and
  whether the transfer completed. Pair it with the message row's `totalChunks`
  for a percentage.

  The sender already knew this -- every receipt lands in the have-set that
  drives selective retransmit -- but nothing outside the module could read it,
  so a UI could say "sending" and then show nothing at all until the transfer
  settled. On a large file that is a progress bar's worth of silence.

  The counts are real chunks, not frames: a decoy receipt does not resolve to a
  staged chunk on the sender, so cover traffic never inflates the number. Wire
  totals including cover remain derivable as `totalChunks * WIRE_CHUNK_FRAME_LEN`.

  Derived from the same state selective retransmit uses, so it cannot drift
  from what the sender believes was delivered. Read-only and defensively
  copied; polling it never affects the transfer.

## [0.14.2] — 2026-07-26

### Added

- `getRoomStats(roomId)`. Aggregate history for one saved room: message counts
  split into sent and received, byte totals for each direction, and the
  distinct peers this device has received from. The arithmetic runs inside the
  database worker rather than shipping every `MessageData` row to the main
  thread so a UI can sum a few numbers, which for a busy room means serialising
  thousands of objects across the worker boundary on every render.

  Sizes are logical message bytes, not wire bytes. p2party pads everything to
  uniform 65,490-byte cells, so what crossed the network is always larger and
  is a property of the padding policy rather than of the conversation.
  A partially received message counts what arrived, not what was promised, so
  an abandoned transfer cannot inflate the total.

## [0.14.1] — 2026-07-26

Cross-browser and release-integrity fixes. No wire change: 0.14.0 and 0.14.1
peers interoperate.

### Fixed

- **p2party could not connect at all in Firefox.** The post-connect DTLS check
  reads the live certificate from `getStats()` and fails closed when it cannot
  confirm it. Firefox implements neither the `transport` stat nor `certificate`
  rows, so every peer edge aborted with a fingerprint mismatch that was really
  a browser unable to answer the question. A browser reporting no certificate
  statistics now proceeds with a warning; where the browser can answer, a
  disagreement is still fatal.
- A peer edge that entered `disconnected` was torn down after eight seconds
  with no attempt to repair it, so a room quiet for a few minutes failed the
  next send with `not-connected` while the roster still listed the peer. The
  edge now attempts an ICE restart first.
- Redux logged a non-serializable-state warning on every send and every ICE
  candidate. RTK Query echoes a mutation's arguments — live `RTCDataChannel`
  and `RTCIceCandidate` handles — back on each action; both API slices are now
  exempt from that check while application reducers stay checked.
- The CDN immutability guard compared gzip bytes, which embed an MTIME, so
  re-running a published tag reported a violation that had not happened. It now
  compares decoded content.
- Crypto provenance recorded the raw `emcc --version` banner, which differs by
  install method (`6.0.3-git` from Homebrew, `6.0.3 (<commit>)` from emsdk) for
  the same compiler and byte-identical WASM. It records the semantic version,
  so any Emscripten 6.0.3 reproduces the artifact and the provenance.
- The failure log said "protocol-v3 handshake failed" on protocol v4.

## [0.14.0] — 2026-07-26

Developer experience, plus an Emscripten toolchain bump. No wire change: v4
peers on 0.13.0 and 0.14.0 interoperate.

### Added

- `joinRoom()` and `waitForRoom()`. Learning a room's id previously required
  hand-rolling a store subscription with a mutable `unsubscribe` binding, a
  synchronous re-check for the already-joined case, and no timeout — thirteen
  lines for one string. `waitForRoom()` owns that wait, with a timeout and an
  `AbortSignal`; `joinRoom()` is `connect()` plus the wait.
- `waitForPeers()`. Resolves once the room has authenticated peer edges — not
  merely present ones. Waiting for a peer to _appear_ is the bug callers
  actually wrote: a peer is in the room a beat before its protocol-v4
  handshake completes, and a send in that window is skipped as
  unauthenticated, so the message silently goes nowhere. Takes a peer `count`,
  a timeout, and an `AbortSignal`; on timeout it reports how many peers did
  authenticate.
- `onMessage()`. Fires once per fully-arrived message with the payload already
  decoded, replacing a manual `store.subscribe` diff against
  `room.messages` plus a `readMessage()` call. A throwing handler is isolated.
- `setDebugLogging(boolean)`, and the `p2party:debug` localStorage key.
- `examples/browser-mesh/` — a runnable two-tab page, and `docs/wire-format.md`,
  moved out of the README.

### Changed

- Diagnostic logging is off by default. 34 `console.log` calls across the
  signaling, WebRTC and middleware paths filled an embedding application's
  console — `[roomListenerMiddleware] setRoom: {...}` on every room change —
  with no way to silence them. They are retained but gated; errors and
  warnings are unaffected.
- The Emscripten pin moves 6.0.2 → 6.0.3, so `libcrypto.wasm` and its SRI
  change. CI and the release workflow move with it.
- `MessageDeliveryError` is exported, and `handle.done`'s rejection is
  documented where callers meet it.
- Install is `npm install p2party`, with `npm audit signatures` for checking
  release provenance.

### Fixed

- `error instanceof MessageDeliveryError` on a rejected `handle.done` could
  never be true, which is the check the docs told callers to write. RTK Query
  serializes an error thrown from a `queryFn` into a plain object, discarding
  the prototype and the `result` field carrying the per-peer outcomes;
  `sendMessageQuery` now returns `{ error }` so the instance survives.
- The release build no longer ships documentation naming a version other than
  the one being released. The check derives its flag set from the CHANGELOG's
  own release headings and scans every tracked Markdown file, exempting only
  the files whose purpose is recording history. The previous allowlist omitted
  `ROADMAP.md`, which had drifted to `0.13.0`.
- `getDBPeerIsBlacklisted()` fails closed. A worker error resolved it to
  `false` — "not blacklisted" — so a database fault silently readmitted a
  blocked peer. Worker `error`/`messageerror` events now reject every pending
  call instead of leaving them hanging forever.
- The room listener effect no longer leaks an unhandled promise rejection into
  the host application when IndexedDB is unavailable.
- `scripts/buildRelease.mjs` still packaged `docs/protocol-v3-security.md`,
  renamed in 0.13.0 — the release build failed at the copy step.

## [0.13.0] — 2026-07-25

Protocol **v4**: a clean, incompatible wire/session break (v3 peers and
persisted v3 crypto rows are not resumed). Adds sparse post-quantum healing
and room-wide scheduled timing cover.

### Added

- **Sparse PQ healing (immediate mode).** An authenticated 64-bit PQ epoch is
  carried in every uniform 65,490-byte cell and mixed into the message AEAD
  AAD. A store-free sparse-PQ state machine performs standard ML-KEM
  OFFER/ADVANCE/ACK exchanges; a live WebRTC orchestrator drives due-time
  initiation (64 messages / 24 h, stable-role turn, quiescent boundary),
  exact-frame retransmission (5 s × 8), and fail-closed fork/exhaustion
  handling. Combined message keys live in an epoch-bound active receive-key
  collection persisted in one atomic encrypted edge checkpoint alongside the
  Double Ratchet.
- **Scheduled timing cover.** An authenticated room policy opens exactly
  `coverLanes` fixed-schedule lanes per edge, each emitting `coverFramesPerCell`
  authenticated 65,490-byte cells per epoch for `coverDurationEpochs`, closing
  only at cycle boundaries. Real message chunks, PQ control, receipts, and an
  encrypted CANCEL substitute into scheduled slots; dummy cover cells fill the
  rest. Absolute room-phased cycles derived from the policy hash; browser
  visibility/freeze/pagehide/offline suspend cover and resume only at a future
  boundary. Surfaced status (`starting|active|degraded|suspended|stopped`) so a
  browser-imposed gap is never claimed as cover.
- **Public session API v4.** `pqEpoch` / `healingInProgress`, PQ-combined
  `encrypt`/`decrypt`, snapshot format 4 (rejects v3) carrying the PQ machine +
  active receive keys, and a store-free `prepareHealing`/`acceptControlFrame`/
  `pendingControl` control surface with an explicit persist-before-send
  contract.

### Changed

- `PROTOCOL_VERSION` is now `4`; the public epoch is an authenticated u64 (was
  a fixed reserved zero byte). `CHUNK_PLAINTEXT_LEN` drops from 65,412 to
  65,405 bytes (the seven epoch bytes consume padding); the outer cell stays
  exactly 65,490 bytes. Room-policy encoding/hash KATs updated for the v4
  wire-version byte.

### Verified

- Full source gate green (lint, format, typecheck, tests, standalone example).
- Real headless-Chromium E2E: immediate sparse-PQ mesh at n=2/3/4; scheduled
  cover lanes over real WebRTC; and a full app-stack run (Redux + IndexedDB +
  WebRTC) delivering byte-exact messages in immediate, PIN, and scheduled
  rooms.

## [0.12.0] — 2026-07-24

### Added

- Authenticated room-wide ML-KEM-512, ML-KEM-768 (default), and ML-KEM-1024
  bootstrap profiles. The selected suite is fixed before the handshake and
  bound into framing, channel input, root KDF domains, confirmation proofs,
  ratchet persistence, and standalone snapshots; there is no negotiation,
  inference from length, downgrade, or classical fallback.
- A third chained handshake confirmation. The initiator proof commits to the
  responder proof, the responder FINISH commits to both, and the initiator
  cannot establish until FINISH verifies.
- Compact 256-bit room capabilities (43-character unpadded base64url),
  versioned fragment invites, strict legacy-hex normalization, and an optional
  checksum-protected 24-word encoding of the same capability bytes.
- An internal sparse PQ-healing state-machine core. Production nonzero epochs
  remain gated on crash-safe persistence, authenticated control routing,
  message-key integration, and scheduler wiring.

### Fixed

- Concurrent room joins now allocate every signaled WebRTC edge, restoring the
  intended n-party full mesh rather than leaving identity-initiator edges idle.
- WebCrypto randomness is staged through fixed `ArrayBuffer`s before entering
  resizable WebAssembly memory, restoring compatibility with newer Chromium.

### Security

- Tampering either of the first two key-confirmation proofs now prevents both
  endpoints from completing. A tampered final FINISH is rejected by the
  initiator. As with every finite handshake over a lossy transport, dropping a
  valid last packet can still leave the sender complete while the receiver
  waits; this is an availability/common-knowledge boundary, not key disclosure.

### Release engineering

- npm and `package-lock.json` are now the release dependency authority. Package
  exports and files are allowlisted, direct source-tree publishing is refused,
  and tagged npm releases carry provenance.
- Pull requests build the pinned cryptographic source before running checks.
  Tagged releases publish immutable versioned CDN objects, fetch the public
  WASM back, and verify its exact bytes, SHA-256, and SRI before npm publication.
- Release validation now pins and hashes the vendored mlkem-native source tree
  and p2party wrappers, packages the provenance manifest and third-party
  notices, and rejects unexpected tarball entries.
- Added security, contribution, conduct, and attribution metadata for public
  development.

## [0.10.0] — 2026-07-23

Protocol v3 is an intentional wire break. Versionless, legacy, and downgraded
peers fail closed.

### Added

- Mandatory X25519 interactive 3DH plus ML-KEM-768 bootstrap for every peer
  edge; PIN rooms additionally authenticate with CPace.
- Per-peer Double Ratchet message encryption, wrapped persistent ratchet state,
  DTLS fingerprint binding, exact tagged receipts, and room/peer-scoped
  transport ownership.
- Store-free `p2party/session` exports: `createSession`, `restoreSession`, and
  `generateSessionIdentity`, usable outside browsers.
- Per-message transfer handles with cancellation and per-peer mesh delivery
  outcomes.

### Changed

- Outbound transfers now have independent random identities, including
  concurrent sends of identical content.
- The WASM release uses an exact stable libsodium source commit through its
  configured build, public APIs, checked initialization, no LTO, and a packaged
  provenance manifest.
- The SDK is now licensed under Apache-2.0.

### Not included in 0.10.0

Scheduled timing cover, sparse post-quantum ratchet healing, server-blind
rendezvous, and the private BitTorrent extension are next-version work, not
0.10.0 shipped properties.

## [0.9.2] — 2026-07-21

Receive-side storage for files is re-architected so a received file's bytes live
in exactly one place — its disk-backed OPFS file — instead of being buffered in
IndexedDB and reassembled on read. This halves peak storage for large transfers
and makes reload-resume fill only the still-missing gaps. **No wire-protocol
change** and **no public-API change** — `readMessage` still returns a disk-backed
`File`; a 0.9.2 peer interoperates with 0.9.1/0.9.0.

### Changed

- **Receive-time OPFS writes (no double storage).** Each received real FILE chunk
  is now written straight into a per-message OPFS file at its byte offset
  (`chunkIndex × uniformSize`) as it arrives — out of order — into a file
  pre-sized to the total size (zero-filled). IndexedDB keeps only the per-chunk
  leaf-hash "have-set" (bytesless records), not the bytes. Previously every
  received chunk's bytes were stored in IndexedDB **and** the whole file was
  reassembled into OPFS on read, doubling peak disk for the duration; that
  reassembly pass is gone. `uniformSize` (real bytes per full chunk) is a
  per-send tunable not carried on the wire, so it is learned empirically
  (`max(realLen)`, exact after two chunks or from chunk 0); the ≤1 chunk that
  arrives before it is known is kept in IndexedDB and migrated into OPFS when the
  file is opened.
- **Reload-resume fills only the gaps.** Because the OPFS file (with zeros in the
  not-yet-received gaps) and the leaf-hash have-set both persist across a page
  reload, a resumed transfer overwrites only the remaining gaps rather than
  restarting. The have-set is a strict subset of the bytes actually on disk
  (bytes are written before the record is recorded), so a resumed sender never
  skips a chunk whose bytes are missing.

### Notes

- Text messages and the sender's own copy of a sent file are unchanged (still
  stored in IndexedDB); only the receive path for files changed.
- Where worker OPFS is unavailable (very old browsers), received file bytes fall
  back to IndexedDB and the in-memory `Blob` read path, exactly as before.

## [0.9.1] — 2026-07-21

Reliability and scale for the peer-to-peer file transfer layer: an in-flight
transfer now survives a dropped connection, and arbitrarily large files stream
through disk instead of ever sitting in memory. **No wire-protocol change** — a
0.9.1 peer interoperates with a 0.9.0 peer.

### Added

- **Resume-on-reconnect.** An in-flight message no longer fails when the WebRTC
  connection is fully torn down and re-established mid-transfer (network drop,
  ICE failure, peer refresh). The sender re-opens its per-message channel on the
  peer's fresh connection and continues; the receiver re-emits the leaf-hash
  receipts for the chunks it already holds, so only the still-missing chunks are
  resent — no full re-send, no wire change. Reconnect recoveries surface in the
  existing `retransmits` telemetry.
- **Arbitrary large files (GB+), never held whole in RAM.**
  - _Send:_ the whole-message SHA-512 is now computed incrementally, streaming
    the file from disk one window at a time through a new WebAssembly streaming
    hash — the file is never fully loaded to hash it.
  - _Receive:_ a completed file is reassembled by streaming its stored chunks
    straight to a disk-backed file in the **Origin Private File System (OPFS)**
    inside the storage worker, and `readMessage` returns a disk-backed `File` —
    the whole file is never built as an in-memory `Blob`. Reassembly is
    idempotent and content-addressed (repeat reads are O(1)); concurrent reads
    of the same file are coalesced; assembled files are reclaimed when the
    message or database is deleted.
- **`getSendChunksCount(hashHex)`** — a read-only diagnostic returning how many
  outbound chunks are still buffered for a message (0 once a send completes or is
  abandoned). Useful for surfacing send-buffer usage.
- **`readMessage(merkleRootHex, hashHex?, materialize?)`** — a `materialize`
  flag (default `true`, backward-compatible). Pass `false` to read a completed
  file's metadata (name/size/category) **without** reassembling the file — so a
  UI can render list previews and file bubbles cheaply and only materialize the
  `File` on open/download/save. Consumers can then offer a "Save as…" that
  streams the disk-backed `File` straight to a user-chosen location
  (`showSaveFilePicker`) without ever holding it in RAM.

### Changed

- The per-message channel's completion close now drains its send buffer before
  closing (mirrors the graceful-close path), so a completing transfer never
  wipes an un-flushed frame.

### Fixed

- The sender's per-message send buffer (`newChunks`) is now reliably reclaimed
  from IndexedDB after a transfer completes **or** is permanently abandoned —
  previously an edge case could leave a completed/aborted transfer's data behind.

### Browser support

- The **never-in-RAM** guarantee for large-file receive applies to browsers with
  worker OPFS: Chrome/Edge, Firefox 111+, and Safari 16.4+. Older browsers fall
  back to an in-memory reassembly (correct, but memory-bound).

### Deploying 0.9.1

This release adds new exports to `libcrypto.wasm` and pins the WASM URL to
`@0.9.1` (`cdn.p2party.com/@0.9.1/libcrypto.wasm`), leaving `@0.9.0` untouched
for existing clients. To publish:

```sh
npm run predist      # rebuild the production WASM + re-pin its SRI
npm run uploadcdn    # upload the WASM to the CDN (needs AWS credentials)
```

The JavaScript that calls the new streaming-hash export cannot run until the
`@0.9.1` WASM is live on the CDN. The signaling server is unchanged and does not
need redeployment.

## [0.9.0] — 2026-07-20

Protocol-v2 security hardening and the reliable-transfer foundation.

### Security

- Bind per-chunk sender authentication to a domain-separated transcript
  (`DOMAIN || merkle_root || ephemeral_pk`) so a signature harvested from the
  server-challenge oracle cannot be replayed as chunk authentication.
- Merkle tree: domain-separated node hashing and odd-node promotion
  (CVE-2012-2459 class), and reuse of the verified leaf hash.
- Tier-1 hardening: BigInt rejection sampling for range RNG, WASM heap-leak and
  zeroization fixes, and stricter bounds validation.
- Updated libsodium and rebuilt the WASM.

### Reliability

- Selective retransmit / reconcile: receipts are the have-set; the sender resends
  only the chunks a receiver hasn't acknowledged, until completion.
- Wait-for-channel-open before the first send; drain-before-close; read-receipt
  count uniformity; and per-message transfer telemetry (total/real chunk counts,
  retransmits).

[0.12.0]: https://github.com/p2party/p2party-js/releases/tag/v0.12.0
[0.10.0]: https://github.com/p2party/p2party-js/releases/tag/v0.10.0
[0.9.2]: https://github.com/p2party/p2party-js/releases/tag/v0.9.2
[0.9.1]: https://github.com/p2party/p2party-js/releases/tag/v0.9.1
[0.9.0]: https://github.com/p2party/p2party-js/releases/tag/v0.9.0
