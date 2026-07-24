# p2party — Design Decisions & Security Findings

> Consolidated project record synthesized from four mined datasets (git history, spec docs, crypto code, curated memory). Commit hashes (`abc1234`) and source files are preserved where the inputs recorded them. Nothing here is asserted beyond what those inputs support; a few points where the inputs disagree or leave a gap are flagged inline.
>
> **Companion:** the chronological *decision log* — every protocol-evolution dilemma (resolved, decided, and future), including the two hard handshake calls **D1 (initiator-random CPace `sid`)** and **D2 (dedicated X25519 identity key + key separation)** decided 2026-07-22 — lives in [`protocol-evolution-decision-log.md`](./protocol-evolution-decision-log.md).

---

## 1. Overview

p2party is a browser-based, peer-to-peer WebRTC mesh for end-to-end-encrypted message and file transfer. Signaling runs over WebSockets; payloads run over WebRTC data channels (each logical message over its own ephemeral channel). Its distinguishing thesis is **offensive cryptography**: rather than only protecting *content*, the transport actively shapes traffic to reduce metadata leakage — message size, chunk count, real-vs-decoy split, and chunk boundaries. Historical protocol-v2 frames were exactly 64 KiB; the current protocol-v3 chunk frame is 65,490 bytes (`62`-byte header + `65,412`-byte authenticated plaintext + `16`-byte tag), with active-transfer random fill/decoys and 65-byte tagged receipt frames carrying a 64-byte true-or-random token. Timing cover is a researched room policy, not a shipped property. The SDK (`p2party-js`) and signaling server (`p2party-server`) use Apache-2.0; the website (`p2party.com`) uses AGPL-3.0-only.

### Current protocol-v3 implementation checkpoint (2026-07-23)

This checkpoint supersedes “current” wording in the historical ADRs below without deleting the decisions that led here:

- **One mandatory suite:** Ed25519 anchors identity and cross-signs a dedicated X25519 identity key. An interactive 3DH possession proof runs in every room; PIN policy adds draft-21 CPace ISK. ML-KEM-768 is mandatory in both policies, so the root input is `3DH ‖ ML-KEM` or `CPace-ISK ‖ 3DH ‖ ML-KEM`, never CPace instead of 3DH and never a classical fallback. This online handshake is neither Signal X3DH (no prekey bundle) nor X-Wing (a specific hybrid-KEM combiner).
- **Assurance boundary:** the fixed-order/domain-separated HKDF and explicit transcript confirmation are an engineered PQ/T hybrid composition, not a formal X-Wing/PQXDH instantiation. RFC 9794 cautions that hybrid confidentiality and authentication are separate properties. Signal PQXDH is the closest formally analyzed bootstrap baseline and has higher assurance today; its asynchronous prekey/offline objective differs from p2party's live WebRTC edge + optional CPace policy. X-Wing draft-10 is not an RFC and is a non-interactive, unauthenticated KEM.
- **Suite provenance:** persisted sessions accept only `rootSuite = "hybrid-3dh-mlkem768-cpace21-v3"`. Standalone snapshots use format version `3`, wire protocol `3`, and root-suite byte `3`; the handshake channel-input separately carries `PQ_TAG = 0x01`. Those two numeric tags have different scopes.
- **Transport ownership:** ratchet gates and handshake inboxes are separate `(roomId, peerId)` registries with opaque per-attempt leases. A stale reconnect callback cannot open, reject, deliver to, or clear the replacement attempt. Stable-identity alias exclusion and ratchet persistence are separately serialized by `(roomId, peerPublicKey)`.
- **PIN throttling:** durable exponential backoff is keyed by `(roomId, stable Ed25519 identity)`—three free failures, 500 ms base, five-minute cap—with an additional soft in-memory room aggregate of 30 failures per five minutes to bound identity rotation without making one peer a permanent room-wide lock.
- **WASM memory:** the build enables growth from 2 MiB toward a 1-GiB compile ceiling, but imported memories enforce caller-selected operation maxima. Current small protocol/session modules cap themselves at 32 pages; Merkle and Argon2 helpers size larger memories for their operation. “Every WASM operation is fixed to 2 MiB” and “growth is compile-disabled” are both false.
- **Transfer/receipt scope:** IndexedDB v18 gives each outbound logical send a random 32-byte `transferId` and keys transient `newChunks` by `[transferId, chunkIndex]`. A chunk receipt token itself is exactly `SHA-512(domain ‖ merkleRoot ‖ u64(index) ‖ leafHash)`—it contains no transfer ID—then lookup is root-scoped and the handler requires the resolved row's `transferId` to match the active send. Terminal completion remains the 64-byte content hash. A true token is emitted only after the receive worker crosses its durability boundary; storage failure follows decoy/drop semantics.
- **Cancellation:** immediate mode treats closure of one message DataChannel on the same current authenticated RTCPeerConnection as peer cancellation; a failed/replaced connection remains a resume case. There is no encrypted `CANCEL` frame today.
- **Unimplemented claim boundary:** nonzero/sparse PQ ratchet epochs, scheduled traffic cover (including its future encrypted `CANCEL`), L2 server-blind rendezvous, and P2BT are research/design work. Policy descriptors exist, but runtime accepts only PQ epoch zero, immediate cover mode, and legacy rendezvous.

---

## 2. Offensive-cryptography transport mechanisms

Each mechanism below is paired with the traffic-analysis property it defends. This table began as the protocol-v2 transport record; rows now distinguish that history from the current v3 wire where the construction changed. File/line refs are historical unless a current source path is stated.

| Mechanism | What it is | Traffic-analysis property defended |
|---|---|---|
| **Uniform framing** — historical `MESSAGE_LEN=65,536`; current `WIRE_CHUNK_FRAME_LEN=65,490` | v2 used a 64-KiB box frame. V3 uses a 62-byte ratchet header, 65,412-byte authenticated plaintext cell, and 16-byte tag. | A v3 chunk frame's length does not disclose real-vs-decoy or useful bytes within that cell; it does not by itself hide whether/when a transfer exists. |
| **Fixed header budget** | V2 used ephemeral pk + identity signature. V3 replaces that with `type ‖ dhPub ‖ N ‖ PN ‖ PQ_EPOCH ‖ random nonce`; metadata and Merkle proof remain inside the fixed encrypted plaintext. | Keeps current chunk cells byte-length identical while authenticating ratchet counters and the message root. |
| **Full-noise chunk fill** — `src/utils/splitToChunks.ts:149` | Each chunk buffer is filled entirely with `crypto.getRandomValues`, then only `percentageFilledChunk` of real data is overlaid; unused space is cryptographic noise, not zeros. | Removes a zero-padding fingerprint inside the encrypted application cell. It does not establish SCTP/DTLS packet-trace indistinguishability. |
| **Random real-data offset** (`chunkStartIndex`) — `src/utils/splitToChunks.ts:150` | Real bytes are placed at a random offset in `[0, chunkSize*(1−percentageFilledChunk)]` via `randomNumberInRange`. | Position of useful data inside the noise is unpredictable — not fixed at byte 0. |
| **Decoy chunks** (out-of-range `chunkEndIndex`) — `src/utils/splitToChunks.ts:166` | Once all real bytes are placed, remaining chunks carry no real data: `chunkEndIndex` is bumped so `end − start > totalSize`. On the v3 wire a decoy is a normal ratchet-authenticated, encrypted, Merkle-committed frame. | Only a recipient holding decrypted metadata can detect a decoy; the real chunk count is hidden under active-transfer padding. |
| **Random decoy end-index** (up to `MAX_SAFE_INTEGER`) — `src/utils/splitToChunks.ts:167` | Decoy `chunkEndIndex` is drawn from a wide range above `totalSize`. | Decoy markers are not a constant sentinel that could be pattern-matched. |
| **Fisher-Yates chunk shuffle + decoy interleave** | Chunks of a message are shuffled and interleaved with decoys before send. V3 uses one message key/header per logical message and a fresh random 12-byte nonce for every seal/reseal; the rejected `nonce=chunkIndex` design is historical. | Order carries no positional information without introducing nonce reuse. |
| **Merkle-root-bound AEAD per chunk** | V3 authenticates `merkleRoot ‖ N ‖ PN` as AAD and rejects nonzero `PQ_EPOCH`. | Chunks are tied to one message and one ratchet step; sparse PQ advancement is not implied by the reserved epoch byte. |
| **Per-chunk domain-separated Ed25519 signature (protocol-v2 history)** | V2 signed `DOMAIN ‖ merkle_root ‖ ephemeral_pk`. V3 retired this field atomically when the mandatory identity-possessing hybrid ratchet became the sender authenticator. | Preserves the historical challenge-oracle fix without falsely describing the current v3 frame. |
| **Uniform reverse read-receipt token** — `src/utils/receiptToken.ts`, `src/handlers/receiptFrame.ts` | Every forward frame draws one exact 65-byte reverse frame: `FRAME_TYPE_RECEIPT(1) ‖ token(64)`. A valid real token hashes `domain ‖ root ‖ u64(index) ‖ leaf`; invalid/decoy/duplicate cases send fresh random bytes. Raw untagged 64-byte inputs are rejected. Sender lookup is `(root,token)` plus an active-`transferId` equality check, and a true token is emitted only after durable storage. | Reverse count tracks forward count; explicit framing prevents receipt/chunk ambiguity; duplicate equal leaves and overlapping equal sends cannot acknowledge the wrong staged chunk. Timing and reconnect-burst leakage remain outside this count property. |
| **1 MiB send-buffer high watermark** (16 historical 64-KiB frames) | The watermark keeps normal transfer flow on the DataChannel. Protocol-v3 does not fall back to WebSocket payload relay. | Avoids handing payload records and transfer timing to the signaling path; availability now relies on reconnect/reconcile rather than relay. |

### The "uniform chunks make a PQ ratchet ciphertext free" insight

The current v3 bootstrap already carries mandatory ML-KEM-768, and a whole 1,088-byte ciphertext fits easily inside one fixed application cell. The narrower future hypothesis is that a **sparse periodic** PQ advance could replace padding in a room cell that a scheduled-cover policy was already going to send. Neither that sparse epoch state machine nor scheduled cover is implemented, so “free” may mean only zero marginal scheduled application frames/bytes after those systems exist—not zero bandwidth and not a shipped metadata claim.

The academic positioning was re-adjudicated rather than erased. Signal SPQR uses 32-byte micro-chunks and generic erasure codes; PQ3, Post Quantum Sphinx, Outfox, OKE/Kemeleon, Hybrid OKE, and especially Zerion's dense fixed-frame ML-KEM design preempt broad primitive/“first fixed PQ frame” novelty. The surviving claim is a novel-adjacent systems comparison—sparse PQ healing in an n-party browser/WebRTC mesh with message-scoped channels—only if implemented and measured. See D4 and D7 in `protocol-evolution-decision-log.md`.

### Chosen cover policy: room-wide opt-in, message-scoped channels

The product default and only currently wired runtime is immediate delivery with no timing cover. The accepted future cover architecture keeps one ephemeral WebRTC DataChannel per logical message for isolated cancellation, progress, backpressure, retry, and cleanup. Each direction would open the configured number of neutrally-labelled lanes on the room's fixed cadence whether idle or active, and a real message or PQ control step would substitute for a dummy lane. Fixed 65,490-byte chunk frames and fixed 65-byte tagged true-or-random receipt frames would be sent at scheduled offsets.

This is **accepted but not implemented or packet-trace-validated**. Immediate mode today signals remote cancellation by closing the one message DataChannel on the still-current authenticated peer connection; transport replacement remains a resume case. The future cover mode instead needs an encrypted `CANCEL` in a scheduled slot and must keep the lane's observable lifetime unchanged. Its claim would be zero *marginal observer-visible application frames/bytes relative to an already-running cover schedule*, not zero bandwidth. Ten-second cover gives a five-second mean chat delay but schedules 565.8 MB/day outbound per endpoint for just one lane, or 1.132 GB/day across a pair before WebRTC overhead. Sixty-second cover reduces that pair cost to 188.6 MB/day but imposes a 30-second mean delay. It would protect activity, bounded size, and cancel/complete timing only on an already-established WebRTC/DTLS association. It would not hide IP addresses, connection or room existence, endpoint compromise, global correlation, browser suspension, congestion/loss artifacts, or the chosen duration class for a large transfer. See decision D3 in `protocol-evolution-decision-log.md`.

---

## 3. Design decisions (ADR-style)

Format: **Decision / Context / Rationale / Status**. Grouped by area.

### 3.1 Transport-obfuscation

**ADR-T1 — WebSocket signaling + WebRTC data channels with E2E encryption (baseline)**
- *Decision:* Transport payloads peer-to-peer over WebRTC, signal over WebSockets, encrypt end-to-end.
- *Context:* Project baseline; terse commit, no recorded body.
- *Status:* Shipped — `1df7411`.

**ADR-T2 — Signaling overhaul: peer blacklist + address book**
- *Decision:* Add a peer blacklist and an address book to the signaling layer.
- *Context:* Major signaling-layer update; subject-only commit. `onlyConnectWithKnownAddresses` remains **off by default** (see §6).
- *Status:* Shipped — `0b218c7`.

**ADR-T3 — One ephemeral data channel per message**
- *Decision:* Each logical message is sent over its own dedicated ephemeral WebRTC data channel rather than a shared channel.
- *Rationale:* This per-message-channel model underpins later wait-for-open, drain-before-close, and resume work.
- *Status:* Shipped — `d59517b`.

**ADR-T4 — Channel label trimmed to name + Merkle root; hash in chunk metadata**
- *Decision:* Reduce the data-channel label to channel name + Merkle root; move the message hash into per-chunk metadata.
- *Context:* The plaintext Merkle-root label was later flagged as a relay metadata leak (finding `c584ed0`); opaque channel IDs were specified but deferred (they conflict with the 0.9.0 chunk-auth transcript, which signs the root read pre-decryption from the label, and overlap the Double Ratchet redesign).
- *Status:* Shipped — `b8efb47`; opaque-ID follow-up deferred (see §6).

### 3.2 Message-crypto

**ADR-M1 — Per-chunk E2E encryption via signed ephemeral keys**
- *Decision:* Encrypt end-to-end per chunk using signed ephemeral keys.
- *Context:* This per-chunk signed-ephemeral scheme is exactly what the 0.9.0 chunk-auth transcript fix later hardens.
- *Status:* Shipped — `ad494b5`.

**ADR-M2 — Split crypto fixes into Tier 1 (pure-TS) vs Tier 2 (C/WASM)**
- *Decision:* Tier 1 = pure-TypeScript, no wire-format change, no WASM rebuild, verifiable E2E against the existing CDN-hosted `libcrypto.wasm`. Tier 2 = C/WASM, wire-breaking, versioned protocol-v2.
- *Rationale:* `wasmLoader.ts` fetches `libcrypto.wasm` from `cdn.p2party.com` under a hardcoded sha384 SRI, so any WASM/wire change cannot reach the running app without a CDN redeploy + SRI bump. Separating pure-TS fixes makes them independently shippable and testable with no interop break.
- *Status:* Design `91d5955` / spec `2026-07-20-crypto-hardening-tier1-design.md`; Tier 2 spec `2026-07-20-crypto-hardening-tier2-protocol-v2-design.md`.

**ADR-M3 — Domain-separated chunk-auth transcript (protocol-v2)**
- *Decision:* Sign a domain-separated 117-byte transcript `DOMAIN(21)='p2party-chunk-auth-v1' ‖ merkle_root(64) ‖ ephemeral_pk(32)` instead of the bare 32-byte ephemeral pk; the receiver verifies over the reconstructed transcript **before decrypting**. `DOMAIN` defined once in `utils.h`, mirrored in TS. `metadataSchemaVersion` bumped 1→2 for documentation only.
- *Rationale:* Eliminates the challenge-oracle forgery (finding `0174333`); a signature harvested from the raw-nonce server-login challenge can never satisfy chunk verification once the domains are distinct. No server change needed.
- *Context:* Frame layout stays byte-identical (64-byte sig). Because verification runs **before** decryption, the break cannot be gated by the in-metadata `schemaVersion` — it is enforced structurally, so both peers must run the new build.
- *Status:* Design `0174333` / merge `393aa20`, shipped **0.9.0**.

**ADR-M4 — Verify transcript signature and bind AEAD AAD to the Merkle root**
- *Decision:* On receive, reconstruct the transcript and require `verify()==0` or abort (`-1`) before decrypt (`utils.c:122`); call `decrypt_chachapoly_asymmetric` with the Merkle root as AAD (`utils.c:141`).
- *Rationale:* Sender authentication precedes decryption; AAD binding prevents cross-message chunk splicing.
- *Status:* Shipped (protocol-v2).

**ADR-M5 — `sodium_malloc`/`sodium_free` for secrets; zeroize before free**
- *Decision:* Place X25519 secret keys and kx session keys in guarded `sodium_malloc` regions freed on every error path (`chacha20poly1305.c:21`); route TS-side secret frees through `zeroFree` (`src/utils/zeroFree.ts:11`).
- *Rationale:* `_malloc`/`_free` do not clear memory and the heaps are long-lived and reused; guard pages/canaries/wipe-on-free protect derived secrets.
- *Status:* Shipped (Tier 1 + Tier 2).

### 3.3 Merkle

**ADR-K1 — Leaf/node domain separation + odd-node promotion**
- *Decision:* Leaves hashed `SHA-512(0x00 ‖ chunk)`, internal nodes `SHA-512(0x01 ‖ l ‖ r)` via a `hash_node` helper; a lone odd node is **promoted unchanged** rather than hashed with itself. Applied consistently across `merkle.c` (root/proof/verify/root-from-proof), the sender leaf (`hashMerkleLeaf`), the receiver proof leaf (`receive_message`), and the TS verify helpers (`src/utils/leafHash.ts`).
- *Rationale:* Closes the CVE-2012-2459 malleability class (finding `c39c4d6`). Bundled efficiency win: the receiver computes the leaf once on the stack (drops a `malloc`) and reuses it as the read-receipt token instead of re-hashing the 62 KB chunk in JS.
- *Context:* Specified in the Tier 2 spec as a lower-severity change touching four files in lockstep, so it got its own pass.
- *Status:* Design `c39c4d6` / merge `2c1df22`, shipped protocol-v2.

**ADR-K2 — Proof-parsing hardening**
- *Decision:* Reject a proof length unless it is an exact multiple of (hash + position byte) and `≤ PROOF_LEN` (`utils.c:151`); treat a 1-artifact proof where `root == element` as a single-leaf tree (`merkle.c:206`); fold verification into a copy so the real leaf survives as the receipt token (`utils.c:169`).
- *Rationale:* Proof length is read from attacker-influenced decrypted bytes; guards prevent malformed/oversized parsing and ambiguous single-leaf proofs.
- *Status:* Shipped.

### 3.4 Reliability

**ADR-R1 — Design the transfer layer as ONE subsystem (four objectives), spec-first**
- *Decision:* One coherent subsystem satisfying: (1) no double-store, (2) sender sends all needed chunks, (3) no close before verified, (4) receipts leak nothing about content or size — plus resume-on-renegotiation and telemetry.
- *Rationale:* Two incremental prototypes (a fixed-cadence receipt scheduler and a resend-all retransmit) each hit subtle races and were reverted, so the pieces had to be designed together.
- *Status:* Spec `2026-07-20-reliable-transfer-resume-telemetry-design.md` / `927c4ac`.

**ADR-R2 — Receipts ARE the have-set (KISS/DRY/SSOT; v2 decision evolved in v3)**
- *Historical decision:* No new wire, no new store, no bitfield, no `totalChunks` field. Protocol-v2 used the 64-byte leaf hashes as the have-set and resolved them back to staged chunks. The sender ack-set remained disposable in-memory state; durable sources stayed sender `newChunks` + receiver `chunks`.
- *Current v3 correction:* A real chunk's 64-byte token is now `SHA-512(domain ‖ merkleRoot ‖ u64-BE(chunkIndex) ‖ leafHash)`, so equal leaf bytes at different roots or indices do not alias. Resolution is by `(merkleRoot, receiptToken)`, after which the handler also requires the staged row's random v18 `transferId` to equal the active send. The `transferId` is **not** an input to the token itself. Terminal completion remains the raw 64-byte content hash.
- *Status:* Original decision `7187836`; token scoping and v18 transfer ownership are the current implementation.

**ADR-R3 — Retransmit IS resume: one `reconcile()`, two triggers**
- *Decision:* A single reconcile path ("resend the real chunks the receiver hasn't acked") with two triggers — a live timeout, or a reconnect where the receiver re-emits its receipts first. Selective resend reuses `sendChunks` with an optional `onlyIndices?:Set<number>` filter. Decoys are never resent (cover, never acked). Bounded by `MAX_RETRANSMITS` with linear backoff (start 5 × 2 s).
- *Rationale:* DRY — both are the same operation differing only in trigger. Selective (never resend-all) keeps frames idempotent (the `db.add` unique index absorbs overlap) and adds no un-receipted duplicates, preserving count-uniformity and drain.
- *Status:* `9d29fe9` (obj 2).

**ADR-R4 — Wait for channel open before the initial send**
- *Decision:* `sendWithReconcile` waits (bounded by `CHANNEL_OPEN_TIMEOUT_MS`) for `readyState === 'open'` before the first send; anything that still slips is recovered by `reconcile()`.
- *Rationale:* A `connecting` per-message channel previously relayed first frames through the signaling server, leaking sender/receiver/size/timing and defeating uniformity on the relay path.
- *Status:* `5511831`.

**ADR-R5 — Close sequencing: complete AND drained**
- *Decision:* Close the per-message channel only when complete (receiver's final message-hash receipt) **and** `bufferedAmount === 0` (`drainAndClose`, bounded by a timeout). Optionally additionally gate on `receiptsSeen ≥ totalFrames` as part of the later timing layer.
- *Status:* Shipped (`b5ebe2f` drain fix); all-receipted gate is part of the deferred obj-4 layer.

**ADR-R6 — Telemetry over the REAL message**
- *Decision:* Add optional `Message` fields `chunksReceivedTotal` (incl. decoys), `chunksReceivedReal`, `retransmits`, plus an `incrementMessageStats` action; surface them via `readMessage`. Progress % stays over the real message (`savedSize/totalSize`) so decoys never advance it; the sender split-phase % was fixed to use real chunks, not `totalChunks`.
- *Rationale:* A human validates obfuscation (total ≫ real) and reliability (retransmit rounds) by seeing the numbers; rendered live by the `p2party.com` frontend.
- *Status:* `e71ad7b`.

**ADR-R7 — Resume across a full peer reconnect (historical mechanism, superseded identity)**
- *Historical decision:* The first resume implementation kept `sendWithReconcile` alive while `resumeChannel` reopened the same Merkle-root-labelled channel on a replacement connection, retaining the then-current sender key/module and `ackedReal` state in scope. The receiver persisted `Chunk.leafHash` and re-emitted stored receipts on `onopen`.
- *Current v3 correction:* IndexedDB v18 gives every logical send a random 32-byte `transferId`; transient outbound rows are keyed `[transferId, chunkIndex]`, and reconcile/ack state is transfer-scoped. A replacement peer connection must establish its own leased hybrid handshake/gate and ratchet state before application traffic resumes, rather than inheriting authority from a stale transport callback. Hash/root-only public selectors fail when ambiguous.
- *Status:* Original reconnect work `69568e0`; transfer ownership and transport-attempt isolation were subsequently replaced by the v18/leased-gate model.

### 3.5 Storage

**ADR-S1 — Early large-file memory-model rework (superseded)**
- *Decision:* Rework the in-memory model to handle large files.
- *Status:* `c360cd6` — superseded by the streaming/OPFS work in 0.9.1/0.9.2.

**ADR-S2 — Support GB+ files without ever holding the whole file in RAM**
- *Decision:* Fix the only two whole-file-in-RAM spots (send-side message hash, receive-side reassembly Blob); keep IndexedDB as the chunk backing store; nothing on the wire changes.
- *Rationale:* The chunk architecture is already slice-based/IndexedDB-backed; only the hash pass and the read-time reassembly buffer the whole file.
- *Status:* Spec `2026-07-20-big-files-streaming-design.md` / `772635f`.

**ADR-S3 — Stream the send-side SHA-512 via a new WASM export (big-files A)**
- *Decision:* Add JS-callable incremental SHA-512 (`sha512_init/update/final`) over libsodium's already-linked multipart API on a heap-allocated 208-byte `crypto_hash_sha512_state`; `splitToChunks` feeds `File` inputs one ~1 MiB / `HASH_WINDOW_BYTES` window at a time (in 64 KiB sub-chunks via `hashFileStreaming`). The whole-file hash gets its own ordered pass before the chunk loop (every chunk's metadata embeds it). Strings keep `crypto.subtle.digest`. The hash is deliberately **plain** SHA-512 (no domain prefix) so it is byte-identical to `crypto.subtle.digest('SHA-512', …)` (`utils.c:5`).
- *Historical context:* The 208-byte state was heap-allocated from JS and freed before `getMerkleRoot` to fit that caller's then-fixed 2-MiB memory. Current helpers instead assign an explicit maximum sized to each operation; small protocol modules may still choose 2 MiB, while Merkle/Argon2 operations can choose more. Changes to `libcrypto.wasm` still require an SRI repin + CDN redeploy.
- *Status:* `44867ca`.

**ADR-S4 — Stream receive-side reassembly to OPFS (big-files B)**
- *Decision:* `assembleToOPFS` iterates the chunks store in `chunkIndex` order via a cursor (never `getAll`), writes each real chunk's `[chunkStartIndex, chunkEndIndex)` slice to the correct file offset via a **worker-only** `createSyncAccessHandle` (Safari-safe), skips decoys, then flush/close; `readMessage` returns a disk-backed `File`. In-memory Blob fallback where worker OPFS is absent; text and in-progress reads keep the small in-memory path.
- *Rationale:* Do **not** rely on `showSaveFilePicker` (Chromium-only); OPFS is universal (Chrome/Edge 86+, Firefox 111+, Safari 15.2/16.4+) and a Worker sync access handle is the only cross-browser (and fastest — no structured-clone tax) path because Safari has no main-thread `createWritable()`. OPFS is origin-sandboxed; an explicit `<a download>` hands the user the file.
- *Status:* `0357713`.

**ADR-S5 — `readMessage(materialize=false)` metadata-only read**
- *Decision:* Add a third `readMessage` arg `materialize` (default `true`); with `false` a completed FILE returns metadata only (`message: ''`) and does **not** reassemble to OPFS.
- *Rationale:* A frontend audit found `readMessage` was called on the render path after the 0.9.1 OPFS change, so list previews / file bubbles were materializing huge files on every render. Backward-compatible; materialize only on open/download/save.
- *Status:* `8e57593`.

**ADR-S6 — Write received file chunks straight to OPFS at their offsets (0.9.2)**
- *Decision:* Received real FILE chunks are written directly into a per-message OPFS file at `chunkIndex*uniformSize` as they arrive (out of order), into a file pre-sized to `totalSize` and zero-filled. IndexedDB keeps only the leaf-hash have-set (bytesless records; `Chunk.data` made optional); the read-time reassembly pass is gone. Bytes are written+flushed **before** the have-set record commits, so a bytesless record always implies durable OPFS bytes. `uniformSize` is a per-send tunable (not on the wire), learned empirically (exact after two chunks or from chunk 0); the `≤1` early chunk stays in IndexedDB and is migrated by `getReceiveFile`.
- *Rationale:* Halves peak disk for large transfers (no double-buffer) and makes reload-resume fill only the still-missing zero-gaps. No wire or public-API change; OPFS-unavailable browsers fall back to IndexedDB + in-memory Blob.
- *Status:* `562fbcc`.

### 3.6 Auth / PFS

**ADR-A1 — Mnemonic-to-keypair seeding via argon2**
- *Decision:* Derive the identity keypair seed from a mnemonic using argon2.
- *Context:* Establishes the identity-key derivation path the later PACE/Double-Ratchet spec builds on.
- *Status:* Shipped — `2b68c5b`.

**ADR-A2 — CPace + interactive 3DH + mandatory ML-KEM + Double Ratchet = protocol-v3** *(historical spec, implemented and evolved in the current working tree)*
- *Spec/history:* `2026-07-22-pace-ratchet-protocol-v3-design.md` / `91fd123` began as a clean v3 wire-break design with no v2 interop. The bullets preserve that design arc while recording where the implemented suite superseded it:

  - **One handshake root, one ratchet, one suite (SSOT).** The authenticated handshake output seeds the ratchet and messaging runs over it from the first logical message. The implementation does not negotiate CPace versus 3DH versus PQ suites: interactive 3DH and ML-KEM-768 are mandatory, while the authenticated room policy decides only whether CPace is additionally required.
  - **FS and identity possession in every room; PIN adds PAKE authentication.** Interactive 3DH runs in both policies and proves possession of the dedicated cross-signed X25519 identity key; PIN policy additionally runs draft-21 CPace. It is not Signal X3DH because both online parties exchange ephemeral keys directly rather than using asynchronous prekeys.
  - **Exactly two fail-closed authentication policies inside one suite.** `authMode` is `nopin` or `pin`; it is not a capability negotiation. Wrong/absent PIN, key-confirmation failure, DTLS-fingerprint mismatch, version/suite mismatch, or missing ML-KEM support aborts without downgrade.
  - **CPace over Ristretto255 for the PAKE** — explicitly *not* literal ICAO-9303 PACE (drags ASN.1/APDU/Brainpool/EAC baggage libsodium doesn't expose); *not* SPAKE2+/OPAQUE (asymmetric client-server aPAKEs, mismatched to p2party's symmetric peer shape). The ASIACRYPT 2021 analysis supplies CPace's proof pedigree; draft-21 is still an active work in progress, and the application owns suite agreement, channel/identity binding, and fresh `sid` handling. Do not call the draft an RFC or call p2party's larger root composition proven by the CPace paper.
  - **Root-combiner inputs.** No-PIN uses `3DH ‖ ML-KEM`; PIN uses `CPace-ISK ‖ 3DH ‖ ML-KEM`. CPace now follows draft-21's length-prefixing, zero padding, transcript ordering, and ISK derivation; the raw shared point never leaves WASM. `PRS=NFC(PIN)`, the initiator-random `sid`, and channel input bind ordered identities/fingerprints/policy/PQ tag before explicit key confirmation. CPace never replaces 3DH possession proof, and ML-KEM has no classical fallback.
  - **DTLS-fingerprint binding.** Fingerprints from SDP fold into the channel input and are re-verified post-connect against the established transport; disagreement tears the channel down. This binds the handshake to that WebRTC connection. In a no-PIN room it does **not** by itself defeat a malicious signaling server that substitutes both the identity anchor and SDP; the PIN/CPace secret is the additional server-unknown authenticator.
  - **Drop the 0.9.0 per-chunk Ed25519 signature — atomically.** Frame shrinks (−64 B, −1 sign+verify/chunk; the old `handleReceiveMessage` "signature wrong" path is gone) only with the authenticated ratchet: mandatory 3DH proves possession of each dedicated Ed25519-cross-signed X25519 identity, PIN policy adds CPace, and key confirmation covers the hybrid root. Under that root the Poly1305 tag is the chunk authenticator. Dropping the signature before those pieces landed would have been a net downgrade (Risk R1).
  - **Frame layout.** The current 62-byte clear header is `type(1) ‖ DH_ratchet_pub(32) ‖ N(8) ‖ PN(8) ‖ PQ_EPOCH(1) ‖ random nonce(12)`. `N`/`PN` join the Merkle root in AEAD authentication. `PQ_EPOCH` is currently fixed to zero; the receiver rejects nonzero values.
  - **Ratchet granularity.** State is durable per `(roomId, peerPublicKey)` and advances **per logical message**, never per chunk. All chunks of a message share one message key but each seal/reseal uses a fresh random 12-byte nonce; the earlier `nonce = chunkIndex`/identical-ciphertext retransmit design was rejected. Skipping is bounded by `MAX_SKIP=512` per advance and `MAX_SKIP_SESSION=2000` retained keys.
  - **Handshake wiring and gates.** The main channel owns the handshake transport. Handshake frames carry an explicit leading type; application frames are rejected until the current `(roomId, peerId)` leased gate opens after handshake and durable persistence. The handshake inbox has an independent lease so a stale connection cannot deliver to or clear its replacement.
  - **At-rest persistence and provenance.** `ratchetSessions` remains keyed by stable `['roomId','peerPublicKey']`. Every secret field now uses a versioned AES-GCM envelope whose canonical AAD binds suite, room/peer identities, DH publics, counters, nullable fields, skipped-key metadata, field identity, a per-write record ID, and `updatedAt`; the wrap key remains non-extractable. The database is version 18 for transfer identity, and persisted ratchet rows accept only `rootSuite = "hybrid-3dh-mlkem768-cpace21-v3"`. Snapshot format version `3`, wire protocol `3`, and root-suite byte `3` are fail-closed provenance fields. An in-process high-water guard detects rollback/equivocation while the page/worker lives; full IndexedDB rollback after restart still needs an independent monotonic or remote anchor. PIN material remains transient.
  - **Anti-guessing.** Durable exponential backoff is keyed by `(roomId, stable Ed25519 identity)`: the third failure starts at 500 ms, doubling to a five-minute cap. A separate soft room-wide in-memory aggregate allows 30 failures per five minutes to bound identity rotation without making one identity's durable bucket a room-wide denial of service. Successful key confirmation clears that peer bucket; PIN replacement clears the room.
  - **WASM additions and memory.** Ristretto255, interactive 3DH/ratchet, and ML-KEM-768 compile into the WASM build. The build enables memory growth from a 2-MiB initial declaration up to 1 GiB, while callers supply explicit operation maxima. Small protocol/session callers currently cap at 32 pages; Merkle and Argon2 callers allocate larger operation-sized memories. There is no universal fixed-2-MiB invariant.
  - **SSOT/DRY discipline.** All frame-layout constants (`RATCHET_DHPUB_LEN=32`, `RATCHET_N_LEN=8`, `RATCHET_PN_LEN=8`, `PQ_EPOCH_LEN`, `PQ_TAG_LEN`, MESSAGE_START remap), KDF labels, and CPace domain strings live once, byte-matched C↔TS with cross-referencing comments and a unit test asserting C and TS agree.
  - **Active-transfer decoys under the ratchet.** Real and decoy chunks share the same fixed v3 frame construction, but this is transfer padding—not scheduled idle-time cover. A scheduled room cadence and its encrypted `CANCEL` control remain future work.
  - **Mandatory bootstrap PQ; sparse PQ still reserved.** ML-KEM-768 is already mandatory in the bootstrap root, represented by handshake `PQ_TAG=0x01`. The `PQ_EPOCH` byte reserves future periodic/sparse healing, but sender state remains at epoch zero and receivers reject nonzero epochs.
- *Status:* The original design has been implemented and materially evolved in the current working tree. Release/full-stack verification status belongs to the root controller; this documentation pass records no new passing test result.

### 3.7 Tooling / build / project

**ADR-B1 — libsodium bump + WASM rebuild** — Submodule `3d9d8f5..7014b20` (1.0.17-RELEASE-1218; NEON/AVX-512 chacha20/salsa20, interleaved ChaCha20-Poly1305); rebuild `libcrypto`. Dropped legacy `-s NODEJS_CATCH_EXIT/NODEJS_CATCH_REJECTION` emcc flags (emcc 6.0.2 rejects them under STRICT; node-only, target is web/worker); updated `wasmLoader` SRI. Suggests a version bump so new WASM lands at a fresh `@version` path. — `8f4f656`.

**ADR-B2 — Version bump 0.8.4 → 0.9.0 for protocol-v2** — Per 0.x semver so the rebuilt `libcrypto.wasm` uploads to `cdn.p2party.com/@0.9.0/` instead of overwriting `@0.8.4` and breaking deployed clients (rollup injects `P2PARTY_VERSION`, driving loader URL + `uploadToCDN` key). Untracked the stale 0.8.4 tarball. — `6297e33`.

**ADR-B3 — Release 0.9.1** — Resume-on-reconnect + big-file streaming; pin WASM URL to `@0.9.1` (leaving `@0.9.0` for existing clients, since big-files A added a new WASM export); add `CHANGELOG.md`. Deploy: `npm run predist && npm run uploadcdn` for the WASM, then build/deploy the app. — `e867a4b`.

**ADR-B4 — Dependency bump within-range (no majors)** — `@reduxjs/toolkit 2.11→2.12`, `rollup 4.59→4.62`, `eslint 10.0→10.7`, `prettier 3.8→3.9`, `typescript-eslint 8.56→8.65`, `@types/node 25.3→25.9`, `@rollup/plugin-commonjs 29.0.0→29.0.3`. Deliberately held the breaking majors (TypeScript 7, `@rollup/plugin-terser` 1, `class-validator` 0.15) to match `p2party.com`'s pins; full headless-Chromium E2E green. — `bf4d341`. *(Shipped alongside the 0.9.2 OPFS-receive rewrite `562fbcc` as a no-wire/no-API change.)*

**ADR-B5 — Take the clean major bumps; hold TypeScript at 5.9** — Took `@rollup/plugin-terser 0.4→1.0`, `@types/node 25→26`, `class-validator 0.14→0.15` but **held TypeScript at 5.9** because `typescript-eslint` does not yet support TS 7.0 (errors out; tracking TS ≥7.1 in typescript-eslint #10940) and `p2party.com` also pins 5.9. Also modernized `tsconfig` `moduleResolution 'node'→'bundler'` (correct for this rollup-bundled `verbatimModuleSyntax` library), which surfaced and fixed two bad deep `@reduxjs/toolkit/dist/query` imports; declared the only-transitively-hoisted `globals` as a devDependency. — `ecb2560`. *(Note: the curated-memory dataset flagged this TS-7-hold rationale as not captured in memory; it is captured here from commit `ecb2560`.)*

**ADR-B6 — Reformat under prettier 3.9.6** — Line-wrap reflow only, no logic change; `prettier --check` clean across `src`. — `70a39e0`.

**ADR-B7 — SSOT for constants** — Define wire values/tunables once in `src/utils/constants.ts`, import everywhere. Only accepted exception: cross-language C↔TS mirrors (e.g. `CHUNK_AUTH_DOMAIN`, Merkle leaf/node domain bytes), which MUST carry a "must byte-match the C side" comment. — engineering discipline.

**ADR-B8 — Remove the CHAIN 41 Single Member P.C. (I.K.E.) legal entity from the website** — Footer + privacy + terms neutralized to "the operator of p2party"; address / G.E.MI. / VAT dropped; contact email replaced with a placeholder. Part of preparing the stack to go open source. — `1cf715e`. *(Leaves GDPR docs temporarily without a named controller — see §6.)*

**ADR-B9 — Open-source the whole stack; TURN is off-the-shelf coturn** — SDK `p2party-js` and signaling server `p2party-server` are Apache-2.0; website `p2party.com` is AGPL-3.0-only. STUN + signaling + TURN(coturn) run on EU/Hetzner.

---

## 4. Security findings & fixes (ledger)

Severity as recorded in the inputs. Commit = the fixing/design commit.

| # | Finding | Sev | Root cause | Fix | Commit |
|---|---|---|---|---|---|
| 1 | **`randomNumberInRange` 32-bit overflow corrupts decoy generation** | HIGH | Integer accumulated with a **signed 32-bit** `<<= 8`, so any range needing >4 bytes overflowed / went negative. Corrupted the ~2⁵³ decoy `chunkEndIndex` range: `r` could land in `[0,totalSize]` (decoy silently accepted as REAL, corrupting reassembly) or go negative and throw, failing ~75% of sends. Also a missing `return` on the `min===max` fast path (→ `RANGE=0`, `Math.log2(0)=-Infinity`) and a double-resolve. | BigInt-based unbiased rejection sampling correct for 53-bit ranges; added the missing early return; removed the double-resolve. Corrected decoy lower bound (`chunkEnd+totalSize+1`) then structurally guarantees `end−start > totalSize`. Introduced `bun:test` with an isolated `tsconfig.test.json`. | `8340686` |
| 2 | **Two WASM buffers leaked per send exhaust the encryption heap** | MED | In the v2 implementation, `allocateSendMessage` `malloc`'d `ptr4` (Ed25519 secret key) and `ptr8` (SHA-512 buffer) and returned them, but `sendChunks` never freed them — 128 B orphaned per send into that caller's then-fixed heap until `_malloc` failed and sends halted until reload (self-DoS). | Removed the two dead allocations at their source in `allocateSendMessage` (single teardown freeing exactly what it returned, avoiding double-free with the per-iteration locals). | `656d6dd` |
| 3 | **Received chunk offsets stored unvalidated** | MED | `handleReceiveMessage` sliced `chunk[chunkStartIndex, chunkEndIndex]` from attacker-controllable metadata, sanity-checked only against `totalSize/MESSAGE_LEN`. Out-of-range/inverted offsets that still pass the decoy check silently store wrong bytes and corrupt reassembly. | Pure `isStorableChunkRange` guard requiring `0 ≤ start ≤ end ≤ chunk.length` before slicing (`src/utils/chunkBounds.ts:9`); failing chunks dropped like decoys. | `8fc2e9e` |
| 4 | **Secret WASM buffers left in heap after free** | MED | `_malloc`/`_free` don't clear memory; encryption/receive heaps are long-lived and reused, so freed secret key material lingered in the `ArrayBuffer`. | Route secret frees through a `zeroFree(module, view)` helper (mirrors `sodium_free`): ephemeral secret key + seed on send, sender identity-secret copy, receiver secret key on channel close, seed/secret in ed25519 keygen. | `ffef0e1` |
| 5 | **Swapped nonce/tag sizes in AEAD box-layout comments** | LOW | The AEAD box is `nonce(12) ‖ ciphertext ‖ tag(16)`, but source comments had nonce/tag sizes backwards (misleading for implementers). | Corrected the comments. The dead `random_bytes.c` path in `scripts/paths.js` was intentionally left as-is (feeds the WASM build, out of scope for the pure-TS pass). | `e3acb5c` |
| 6 | **Chunk-auth challenge-oracle message forgery** | HIGH | Chunk auth signed the bare 32-byte ephemeral pubkey, and the same identity key signs the raw 32-byte server login challenge with **no domain separation** — a malicious signaling server sends a "challenge" equal to an ephemeral pubkey, harvests the signature, and injects a forged frame the receiver accepts as authentic. Plus a copy-paste NULL-check in `decrypt_chachapoly_asymmetric`/`chacha20poly1305.c` tested the wrong pointer after `malloc`. | Sender signs a domain-separated transcript `'p2party-chunk-auth-v1' ‖ merkle_root(64) ‖ ephemeral_pk(32)`; receiver verifies over the reconstructed transcript, so the two signature domains are incompatible (no server change). Frame byte-identical (64-byte sig); breaking pre-decryption verify. NULL-check corrected to test the pointer actually allocated (`sender_x25519_pk`). | `0174333` |
| 7 | **SDP/ICE glare race put `setRemoteDescription` in wrong state** | LOW | Concurrent SDP/ICE signaling for the same peer interleaved at `await` points; `epc.signalingState` went stale → `setRemoteDescription` in the wrong state ("Called in wrong state: stable"), breaking establishment. | Module-level `Map<peerId, AsyncMutex>` (`negotiationLock.ts`); wrapped `webrtcSetDescriptionQuery`/`webrtcSetIceCandidateQuery` bodies in `getPeerMutex(peerId).runExclusive` (per-peer serialized; different peers still parallel). Removed the now-redundant `NEGOTIATION_DEBOUNCE_MS`, kept the perfect-negotiation guard. | `c5386611` |
| 8 | **Merkle-tree malleability (CVE-2012-2459 class)** | HIGH | No leaf/node domain separation (an internal-node hash could be reinterpreted as a leaf), and lone odd nodes hashed with themselves (`H(x‖x)`), letting distinct leaf multisets collide to one root. | Leaves `SHA-512(0x00‖chunk)`, internal nodes `SHA-512(0x01‖l‖r)` via `hash_node`; lone odd node promoted unchanged. Applied across `merkle.c`, `hashMerkleLeaf`, `receive_message`, TS helpers. Bundled win: receiver computes the leaf once on the stack (drops a `malloc`) and reuses it as the receipt token. | `c39c4d6` / merge `2c1df22` |
| 9 | **Low data-channel buffer watermark spills metadata to the relay** | MED | `MAX_BUFFERED_AMOUNT` was 2 frames (131072), so ordinary congestion immediately spilled full 64 KiB frames through the signaling server — handing it sender/receiver, size, timing, and the plaintext root label. | Raised to 16 frames (1 MiB; browsers buffer ~16 MiB) so normal transfers stay P2P; relay reserved for a genuinely dead channel. Opaque channel IDs (to replace the plaintext root label) specified but deferred (conflict with chunk-auth transcript, overlap ratchet redesign). | `c584ed0` |
| 10 | **Read-receipt count leaks real-vs-decoy split** | MED | Receipts were emitted only for accepted REAL chunks, so a DTLS-record observer could count the tiny reverse records to recover the real chunk count, defeating the decoy padding. | At the v2 checkpoint, every forward frame elicited one 64-byte true-or-random token, so reverse count equalled forward count. Current v3 preserves that property in an exact **65-byte typed frame**, `FRAME_TYPE_RECEIPT(1) ‖ token(64)`, and rejects raw 64-byte frames. A true token now binds domain, root, index, and leaf; invalid/decoy/duplicate cases send fresh random bytes. It remains deliberately much smaller than a forward chunk to avoid reverse amplification, so packet direction and receipt timing are not hidden. | `6016862`; current v3 framing/receipt-token follow-up |
| 11 | **`close()` before drain wipes still-buffered send data** | MED | `RTCDataChannel.close()` discards anything queued in the SCTP send buffer; the `send(messageHash)` immediately followed by `close()` in `disconnectFromChannelLabelQuery` could wipe the just-queued finished-message receipt (and buffered chunks) before it reached the wire. | `drainAndClose()`: poll `bufferedAmount` to 0, bounded by a timeout so a stalled channel can't hang teardown, then close. Verified with both per-message channels closing at `bufferedAmount === 0`. | `b5ebe2f` |
| 12 | **Channel `onclose` destroyed the resend source on any disconnect** | MED | The per-message channel's `onclose` deleted the sender's `newChunks` on ANY close — including a mid-transfer disconnect — destroying the resend source (receiver stalled ~98%); an abandoned send could also leak its body into IndexedDB. | Deletion gated on an explicit race-free `transferComplete` flag from the completion path (passed from `handleReadReceipt`, not re-read after an `await`), with terminal cleanup after all peers settle. Adversarial fixes folded in: `resumeChannel` no longer spawns duplicate same-label channels on a slow open; death test tightened to closed/closing; receipt re-emit loop got `bufferedAmount` backpressure. | `69568e0` |
| 13 | **Concurrent `readMessage` assembles collide → whole-file-in-RAM** | MED | With streaming OPFS reassembly, an overlapping/poll-style `readMessage` opened a second exclusive OPFS sync access handle, collided, and silently fell back to building the whole file in an in-memory Blob (the exact OOM being removed). A non-idempotent re-truncate could invalidate a `File` handed out earlier (`NotReadableError`); assembled OPFS files orphaned as full-size copies on delete/wipe. | Coalesce concurrent assembles per `merkleRoot` via an in-flight-promise `Map`; idempotency guard returns a correctly-sized existing content-addressed file as-is; remove assembled OPFS files on delete (`fnDeleteOPFSFile`) and the whole subtree on full DB wipe; drop partial files from a failed write; always close `getDB()`/handle/connection even on mid-stream error, with short writes looped to completion. | `0357713` |
| 14 | **Receive-time OPFS write path: dedup TOCTOU + `uniformSize` double-count** | MED | Writing received chunks straight to OPFS introduced a `count()→add()` dedup TOCTOU and a shared-entry double-count that could lock the learned `uniformSize` to the short final chunk when the same file arrived from two peers; durability wasn't guaranteed before committing the have-set record; open receive handles could leak on stalled transfers; delete/close paths raced. | Serialize all receive-file ops per `merkleRoot` in the worker (closes TOCTOU + double-count); `flush()` each chunk before committing its have-set record (a bytesless record always implies durable bytes, so a resumed sender never skips a chunk whose bytes are missing); cap open handles by evicting the oldest; run delete's close+`removeEntry` under the per-`merkleRoot` lock; `closeAllReceiveFiles` awaits in-flight opens before a full DB wipe. | `562fbcc` |

**Deferred (specified, not built):** Merkle change #8's *Tier-2 spec* framing and forward-secrecy belong to later increments; server-side challenge-signature domain separation is defense-in-depth needing a coordinated server change (deferred, per the Tier-2 spec).

**Adversarial-review note:** the OPFS receive work surfaced findings #13 (5 issues) and #14 (3 issues incl. HIGH) *only* under adversarial review, not the happy-path E2E — see §7.

---

## 5. Threat model — historical 0.9.x baseline vs current protocol-v3 working tree

| Attacker class | Historical 0.9.x / protocol-v2 baseline | Current protocol-v3 construction |
|---|---|---|
| **Passive / off-path network or relay observer** | Uniform 64-KiB framing, full-noise fill, decoys, and AEAD hid useful bytes inside active transfers. Receipt timing, the reconnect replay burst, and transfer activity remained observable. | Forward secrecy plus the fixed v3 AEAD cells protects content and active-transfer cell structure. Immediate mode still exposes when a transfer/channel exists and its timing; scheduled idle-time cover is unimplemented, so no broader metadata claim is made. |
| **Active malicious/compromised signaling server (MITM)** | **HIGH exposure.** Peers learn each other's Ed25519 pubkeys + DTLS fingerprints only from server-relayed messages, and `onlyConnectWithKnownAddresses` is off by default. The server can substitute pubkey + SDP fingerprint and transparently MITM DTLS + app-layer crypto. The per-chunk signature binds a frame to a sender but the sender's key came from the server. | **Defeated in PIN rooms** — CPace binds a PIN the server doesn't hold plus the observed identity keys and both DTLS fingerprints, with a key-confirmation MAC that fails if the legs' `CI` disagree (a swapped key/cert makes them disagree). **Explicitly NOT defeated in no-PIN rooms** — a server substituting both identities still MITMs; this is the honest, stated limit of a no-PIN room. |
| **Harvest-now-decrypt-later (recorded ciphertext + later device/key theft)** | **Not defended.** No forward secrecy: the receiver's DH half was its static identity key, so later key theft could expose recorded messages. | Interactive 3DH establishes fresh input, mandatory ML-KEM-768 contributes to the bootstrap root, and the Double Ratchet provides FS/PCS in both auth policies. Persisted ratchet state is wrapped under a non-extractable WebCrypto AES-GCM key. Sparse periodic PQ healing is not yet implemented. |
| **Message-forgery via challenge oracle** | **Fixed (0.9.0).** Domain-separated chunk-auth transcript made a signature harvested from the raw-nonce server challenge unusable as chunk auth (`0174333`). | The v2 per-chunk signature is retired; the cross-signed X25519 possession proof authenticates the root and the ratchet's Poly1305 tag authenticates each current chunk frame. |
| **Online PIN guessing (MITM, one guess per CPace exchange)** | N/A (no PIN mode yet). | CPace removes offline dictionary attack. Durable backoff is per `(roomId, stable Ed25519 identity)` after three failures (500-ms base, five-minute cap), plus a soft in-memory room aggregate of 30 failures/five minutes to constrain identity rotation. |
| **DTLS-fingerprint substitution that manifests post-connect** | Not detected (fingerprints come from the server-relayed SDP). | Fingerprints bound into `CI` from the SDP and **re-verified post-connect** via `getStats()`; any disagreement tears the channel down (abort, not log). |
| **At-rest attacker with device + origin access** | Could read localStorage secrets (the then-current static-key weakness). | Non-extractable wrap stops raw-key export / cross-device copy, but does **NOT** stop local decryption by an attacker with device+origin access — a documented, accepted limit. The PIN itself is never persisted. |

**v3 implementation risks tracked in the spec:** R1 (atomicity — retiring the per-chunk signature is safe only with the identity-possessing authenticated ratchet), R2 (async reconnect ownership and cross-channel ordering — addressed with type-tagged frames plus separate leased gate/inbox registries), and R3 (nonce/key reuse and memory exhaustion — current frames use fresh random nonces, skipped keys are bounded at 512/2,000, and callers assign operation-specific WASM maxima rather than relying on a universal 2-MiB heap).

---

## 6. Still-open weaknesses & roadmap

1. **No-PIN signaling-server substitution remains an accepted limit.** Current v3 always proves possession of the in-band cross-signed X25519 identity and binds DTLS fingerprints, but a malicious signaling service that substitutes both identity anchors and both SDP views can still mediate a no-PIN room. PIN policy adds the server-unknown CPace secret and fails closed on key-confirmation mismatch. L2 private rendezvous would address a different metadata problem and is unimplemented.
2. **Release verification remains outstanding in this record.** The current tree contains the one-suite interactive-3DH + optional-CPace + mandatory-ML-KEM bootstrap and the Double Ratchet. This documentation pass does not assert a fresh full-suite, typecheck, packed-frontend, or local-stack WebRTC result; the root controller owns that final gate.
3. **Opaque channel IDs not yet done — the Merkle root still travels PLAINTEXT in the DataChannel label**, linking a message's chunks + fan-out to peers and any observer of channel setup. The original deferral cited the v2 chunk-auth transcript and the coming ratchet redesign; v3 retired that signature but did not deliver opaque labels, so this remains separate future work.
4. **Transfer obj-4 residual side channels.** Count-uniformity was closed by `6016862`; current v3 sends exact 65-byte tagged true-or-random receipt frames over the authenticated DataChannel and does not use WebSocket payload fallback. Receipt work is bounded/serialized and reconnect replay is batched with SCTP backpressure, but immediate emission can still differ around verification/storage work. A scheduled, padded receipt cadence is still future cover work; it must not be inferred from active-transfer decoys.
5. **GDPR/legal docs have no named data controller and a placeholder contact email** after the CHAIN 41 removal (`1cf715e`); ToS §6 "Open-Source Software" lists only `p2party-js` + a generic `github.com/p2party` link. → **Planned:** supply a named controller + real email before publishing; update ToS §6 to add the `p2party.com` + `p2party-server` repos and note TURN = coturn once public.
6. **Deploy debt:** every WASM change—including the current Ristretto/ratchet/ML-KEM build—must ship as a PROD build with an SRI repin + versioned CDN path, because changing bytes under a live `@version` breaks existing clients. → **Process:** `npm run predist` (rebuild + auto-repin via `updateWasmIntegrity.mjs`) → bump the CDN version → user-owned `npm run uploadcdn` (AWS credentials). Never overwrite a live version with changed WASM.
7. **Explicitly unimplemented research layers:** nonzero/sparse PQ ratchet epochs, scheduled room cover and its encrypted `CANCEL`, L2 server-blind rendezvous, and the proposed P2BT transport. Descriptors and research decisions are not runtime support. Capstone READMEs/blog/paper should retain this claim boundary and the re-adjudicated prior art in §8.

---

## 7. Verification methodology

- **Definition of done.** A coding task is NOT done until (1) the change is verified end-to-end against the **locally running stack** (signaling server + app) in **headless Chromium**, exercised the way a normal user would (not just unit tests or type checks), AND (2) the work is committed and merged to master. Rationale: p2party is a WebRTC mesh, so most regressions (signaling, ICE, data channels, IndexedDB, WASM crypto) only surface in a real browser against a real server.
- **How to apply.** Start the local stack (server + `p2party.com` app), drive a real user flow via Playwright — create/join a room from **two** browser contexts, exchange a message/file, verify receipt — fix what breaks, then commit and merge.
- **Canonical E2E harness:** `p2party.com/e2e/run.mjs` (Playwright). It **intercepts the CDN WASM request and serves the locally-built WASM** so the committed SRI matches. Standard assertion: two contexts, text + byte-exact file, 64 KiB frames confirmed on the data channel, no relay fallback. (Tier-1 spec cites Chromium 131 / `bun test` as the new test infra; the memory methodology states headless Chromium — both as recorded.)
- **Robust invariant:** assert `count64 > count65536` (receipts > forward frames) rather than exact counts, so the test tolerates intermittent WS-relay fallback.
- **Determinism for P2P/resume tests:** **block the WS-relay fallback** in the harness (drop `WebSocket.send` frames of type `'message'`) to force pure-P2P, because the relay silently completes transfers that a disconnect should break and thus masks resume bugs. Read **sender-only** telemetry (e.g. `retransmits`) from the sender page.
- **TDD, red-first.** Write failing tests first for the RNG and decoy invariants and the streaming-hash correctness invariant (streamed incremental SHA-512 must equal `crypto.subtle.digest('SHA-512', wholeBuffer)` over the same bytes — a wrong hash → Merkle mismatch → observable E2E failure). The send-reliability fix is the core assertion (pre-fix it fails intermittently).
- **Spec-first for security-critical redesigns.** Use the brainstorming skill and write a committed design spec (`docs/superpowers/specs/*`) **before** implementing large changes (Double Ratchet, PACE) — incremental patching failed twice on the reliability layer (the receipt scheduler and resend-all were both built then reverted).
- **Adversarial self-review before merge.** A single happy-path E2E hides concurrency/idempotency bugs — the OPFS work found 5 + 3 (incl. HIGH) bugs *only* under adversarial review (shared-entry TOCTOU, exclusive-lock read collisions, handle invalidation, unbounded disk). Add a matching E2E assertion for each class (reload-persistence, drop-a-frame recovery, `bufferedAmount===0` at close, send-buffer/`getSendChunksCount` regression for the at-rest leak).
- **Build/deploy discipline.** Commit and deploy the **prod** WASM (`npm run predist`), never the dev build — the dev build (`-O0 -g3 -fsanitize -SAFE_HEAP`) is ~10× slower and blew the resume E2E timeout. Any WASM change requires an SRI repin (auto via `updateWasmIntegrity.mjs`) + version bump + `uploadcdn`.

---

## 8. Prior-art to position against (for the paper)

A prior-art pass is a prerequisite before drafting the paper. Position p2party's contribution against:

- **Chaffing-and-winnowing** (Rivest) — authenticated chaff vs valid packets. Contrast: p2party's decoys are full-noise, size-uniform, Merkle-committed frames, distinguishable only by a recipient holding decrypted metadata (`end−start > totalSize`).
- **Cover traffic** (general anonymity-system padding). Contrast active-transfer decoys with the proposed demand-independent room schedule. Only after that schedule exists could a sparse rekey replace an already-paid slot with zero marginal scheduled application bytes.
- **PURBs / padded uniform random blobs** (padding to hide length and format). Contrast: v2 fixed frames at 64 KiB and v3 fixes chunk frames at 65,490 bytes, while randomizing real-data offset inside the authenticated plaintext rather than only padding whole-message length.
- **Tor traffic analysis** (fixed-size cells; timing/volume correlation attacks). Relevant to the residual timing/receipt side channels and the uniform-cell analogy; p2party's current fixed chunk frame does not itself provide Tor-like timing or path anonymity.
- **Signal SPQR** (Sparse Post-Quantum Ratchet) — 32-byte micro-chunking plus generic erasure coding to spread a larger PQ KEM ciphertext. Direct contrast: p2party's fixed v3 application cell can hold a whole ML-KEM-768 ciphertext at under 2% of one cell. That removes SPQR's fragmentation pressure here; hiding a future sparse rekey in an already-scheduled cover slot remains an unimplemented hypothesis, not “free PQ.”
- **Apple PQ3** (hybrid PQ messaging ratchet). Compare p2party's mandatory hybrid bootstrap and still-reserved sparse `PQ_EPOCH` healing against PQ3's ongoing post-quantum ratchet; do not describe current v3 as classical-only.
- **PQXDH** (Signal specification; USENIX Security 2024 formal analysis) — the closest higher-assurance hybrid bootstrap baseline. It targets asynchronous/offline delivery through server-hosted prekeys; p2party targets live interactive WebRTC edges and can add CPace. Both still authenticate classically in their current forms.
- **X-Wing** (IACR CiC 2024; active individual Internet-Draft 10) — a concrete X25519+ML-KEM-768 KEM combiner, not an RFC, not interactive, and not authenticated. It is combiner/size prior art, not the name or proof of the p2party handshake.
- **CPace** (CFRG `draft-irtf-cfrg-cpace-21`) — an active draft with an ASIACRYPT 2021 security analysis and an explicitly supported Ristretto255/SHA-512 profile. It is the PIN-policy primitive; contrast with ICAO-9303 PACE (ASN.1/APDU/Brainpool/EAC baggage) and asymmetric SPAKE2+/OPAQUE, and keep the application-composition proof boundary explicit.
- **Double Ratchet** (Signal) — the FS/PCS engine. P2party advances it per **logical message**, not per chunk; all chunks share the message key but every seal/reseal uses a fresh random 12-byte nonce. The publishable question is the measured systems composition with fixed cells, active-transfer decoys, optional scheduled cover, and sparse PQ—not primitive novelty.
- **Myco** (IEEE S&P 2025) and **Peer2PIR** (IEEE S&P 2025) — mandatory corrections to the L2/P2BT baseline. Myco is the polylogarithmic two-server metadata-private messaging efficiency frontier; Peer2PIR already privatizes peer routing, provider advertisements, and content retrieval in IPFS. Neither supplies p2party's dynamic WebRTC-room handoff, but both preempt broad novelty language.
