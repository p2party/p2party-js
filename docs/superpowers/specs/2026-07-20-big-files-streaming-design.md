# Arbitrary-Big-File Streaming — Design

**Date:** 2026-07-20
**Status:** proposed (awaiting review)
**Related:** [[p2party-arbitrary-big-files]], [[p2party-transfer-reliability]]

## Goal

Send and receive **arbitrarily large files (GB+)** without ever holding the whole
file in RAM. IndexedDB is already the backing store for chunks (`newChunks` on
send, `chunks` on receive) so chunks are never all resident at once — the
architecture is right. Two spots still load the whole file into memory and must
be fixed; nothing on the wire changes.

## Verified browser-support constraints (checked 2026-07)

- **`showSaveFilePicker` / the File System Access local-disk pickers are still
  Chromium-only.** Firefox (flagged "harmful") and Safari (no commitment) do
  not ship them. We therefore do **not** rely on the save picker for the
  cross-browser path.
- **OPFS (Origin Private File System) is universal:** Chrome/Edge 86+,
  Firefox 111+, Safari 15.2+. It is origin-sandboxed (not the user's Downloads).
- **Writing OPFS cross-browser requires `createSyncAccessHandle()` inside a
  *dedicated Web Worker*** — Safari does not expose `createWritable()` on the
  main thread. p2party already runs `src/db/db.worker.ts`; the sync access
  handle lives there. This is also the fastest path (no structured-clone tax).

Consequence: we **assemble** the received file in OPFS (universal, in-worker),
then hand the user a **disk-backed** `File`/`Blob` for a normal `<a download>`.
The download itself never loads the file into RAM (`getFile()` on an OPFS handle
returns a disk-backed `File`). On Chromium we *may* additionally offer
`showSaveFilePicker` to stream straight to a chosen location, but that is an
enhancement, not the baseline.

## Current state (grounded in the code)

### Send — `src/utils/splitToChunks.ts`
- The chunk loop (lines 143–215) is **already slice-based**: it reads
  `file.slice(offset, offset + bytesToCopy)` (line 156) and copies that slice
  into a padded 64KiB chunk. It never holds the whole file. ✅
- The **only** whole-file-in-RAM spot is the message hash: line 115 does
  `await (file as File).arrayBuffer()` and passes the entire buffer to
  `crypto.subtle.digest` (line 116). The comment on line 113 claims this
  streams; it does not. ❌
- The whole-file SHA-512 (`m.hash`) must be known **before** the chunk loop,
  because every chunk's serialized metadata embeds it (line 124 → line 176).
  So the hash cannot be folded into the loop — it needs its own ordered pass.

### Receive — `readMessage` (`src/index.ts`) via `fnGetDBAllChunks` (`db.worker.ts:580`)
- `readMessage` calls `getDBAllChunks` (reads **every** chunk for the message
  into an array) and builds `new Blob([...all chunk ArrayBuffers])` in RAM. ❌
- `db.worker.ts` is a dedicated Web Worker — the correct, Safari-safe home for
  the OPFS sync access handle. ✅

## Design

Two independent components; ship send first (smaller, isolated), receive second.

### Component A — streaming send-side hash (WASM + `splitToChunks`)

**A1. New WASM export: incremental SHA-512.**
libsodium's `crypto_hash_sha512_init/update/final` are already linked (used
internally at `utils.c:131`). Expose a JS-callable streaming API. KISS option:
three thin exports operating on a heap-allocated `crypto_hash_sha512_state`:

- `sha512_init(state_ptr) -> int`
- `sha512_update(state_ptr, in_ptr, in_len) -> int`
- `sha512_final(state_ptr, out_ptr) -> int`  (out = 64 bytes)

Add to the emscripten `EXPORTED_FUNCTIONS` list and a small JS binding in the
crypto module mirroring the existing ones. Rebuild `libcrypto.wasm`; update the
pinned SRI in `wasmLoader.ts`. (Local E2E serves the freshly built wasm, so this
is fully verifiable locally; `npm run uploadcdn` — user's AWS creds — is only
for production deploy.)

**A2. `splitToChunks` uses it for files.**
Replace lines 105–118's file branch with an ordered pass that reads the file in
fixed windows (e.g. `HASH_WINDOW_BYTES`, a new SSOT constant, ~4 MiB) via
`file.slice(w, w+HASH_WINDOW_BYTES).arrayBuffer()`, feeding each window to
`sha512_update`, then `sha512_final`. O(1) memory, O(file) sequential I/O. The
string branch (small, already in memory) keeps `crypto.subtle.digest`.

**Correctness invariant (TDD):** for the same bytes, the incremental digest ===
`crypto.subtle.digest("SHA-512", wholeBuffer)`. Red test first: a multi-window
buffer whose streamed hash must equal the one-shot hash. The existing file E2E
also covers it end-to-end (a wrong hash → Merkle mismatch → transfer fails).

### Component B — streaming receive-side reassembly (OPFS in the worker)

**B1. New worker method `assembleToOPFS(hashHex | merkleRootHex) -> {opfsPath|Blob}`.**
In `db.worker.ts`:
1. `root = await navigator.storage.getDirectory()`.
2. Open/create an OPFS file named by `merkleRoot` (unique per message).
3. `const access = await fileHandle.createSyncAccessHandle()`.
4. Iterate the `chunks` store **in `chunkIndex` order via a cursor** (never
   `getAll` — that is the RAM blowup we are removing). For each real chunk,
   `access.write(data, { at: offset })` where `offset` is derived from the
   chunk's stored `chunkStartIndex`/order. Decoys are skipped (already
   distinguishable; real payload region is known from metadata).
5. `access.flush(); access.close()`. Return the OPFS path (and, where the caller
   is on the main thread, a disk-backed `File` via `fileHandle.getFile()`).

Reassembly reads one chunk at a time from IndexedDB and writes it straight to
disk: peak memory ≈ one chunk, not the whole file.

**B2. `readMessage` streams instead of buffering.**
When `messageType !== Text` and OPFS is available, call `assembleToOPFS` and
return the disk-backed `File` (or an object URL from it) rather than
`new Blob([...])`. **Fallback:** if OPFS is unavailable (ancient browser), keep
the current in-memory Blob path — correct, just memory-bound. Feature-detect
`navigator.storage?.getDirectory` and `createSyncAccessHandle`.

**B3. Offset bookkeeping.** The real bytes of each chunk sit at
`[chunkStartIndex, chunkEndIndex)` within the 64KiB frame, and chunks map to
file offsets by index. Reassembly must write each chunk's real slice to the
correct file offset. The receiver already reconstructs this today to advance
`savedSize`; B1 reuses the same metadata, just writing to OPFS instead of
concatenating in RAM. No new wire data.

**Note (future optimization, out of scope):** B writes real bytes to OPFS at
receive-*read* time from the IndexedDB `chunks` store (transiently ~2× on disk).
A later step could write real bytes to OPFS at receive-*time* and keep only the
have-set/metadata in IndexedDB (no double storage), but that touches the
dedup/reconcile path and is deferred. Per the user's framing ("that is why we
have indexeddb, to not use the memory"), keeping IndexedDB as the chunk store
and fixing only the RAM-at-read is the KISS first step.

## SSOT constants (add to `src/utils/constants.ts`)
- `HASH_WINDOW_BYTES` — send-side incremental-hash read window (~4 MiB).
- `OPFS_REASSEMBLE_DIR` — OPFS subdirectory name for assembled files.

## Testing / definition of done
- **TDD unit (bun):** streamed SHA-512 === one-shot SHA-512 over the same bytes
  (Component A correctness). Red first.
- **E2E (Playwright + headless Chromium, real WebRTC, local wasm):**
  - **Big-file byte-exact:** send a file larger than a comfortable RAM budget
    (start ~64–128 MiB in CI; the mechanism is size-independent), assert the
    received file is byte-exact and the transfer completes. This exercises the
    streaming hash (send) and OPFS reassembly (receive) together.
  - Existing text + small-file + reliability assertions still pass (no
    regression to uniformity, drain-before-close, selective retransmit,
    telemetry).
- Per project DoD: verified on the local stack in headless Chromium like a
  normal user, then committed and merged to master. `uploadcdn` (deploy of the
  rebuilt wasm to the CDN) is the user's step.

## Sequencing
1. **A** (send-side streaming hash) — isolated, small, TDD + existing file E2E.
2. **B** (OPFS receive reassembly) — new worker method + `readMessage` + big-file
   E2E, with the in-memory Blob fallback.

Each merges independently; neither changes the wire format, and both are fully
compatible with the per-chunk reliability subsystem (which already scales).
