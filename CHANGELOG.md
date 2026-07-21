# Changelog

All notable changes to the **p2party** SDK are documented here. This project
adheres to [Semantic Versioning](https://semver.org/) and the spirit of
[Keep a Changelog](https://keepachangelog.com/).

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

[0.9.1]: https://github.com/deliberative/p2party/releases/tag/v0.9.1
[0.9.0]: https://github.com/deliberative/p2party/releases/tag/v0.9.0
