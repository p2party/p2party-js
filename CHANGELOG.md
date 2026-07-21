# Changelog

All notable changes to the **p2party** SDK are documented here. This project
adheres to [Semantic Versioning](https://semver.org/) and the spirit of
[Keep a Changelog](https://keepachangelog.com/).

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
