# p2party — Design Decisions & Security Findings

> Consolidated project record synthesized from four mined datasets (git history, spec docs, crypto code, curated memory). Commit hashes (`abc1234`) and source files are preserved where the inputs recorded them. Nothing here is asserted beyond what those inputs support; a few points where the inputs disagree or leave a gap are flagged inline.
>
> **Companion:** the chronological *decision log* — every protocol-evolution dilemma (resolved, decided, and future), including the two hard handshake calls **D1 (initiator-random CPace `sid`)** and **D2 (dedicated X25519 identity key + key separation)** decided 2026-07-22 — lives in [`protocol-evolution-decision-log.md`](./protocol-evolution-decision-log.md).

---

## 1. Overview

p2party is a browser-based, peer-to-peer WebRTC mesh for end-to-end-encrypted message and file transfer. Signaling runs over WebSockets; payloads run over WebRTC data channels (each logical message over its own ephemeral channel). Its distinguishing thesis is **offensive cryptography**: rather than only protecting *content*, the transport actively shapes traffic to deny a network or relay observer the *metadata* — message size, chunk count, real-vs-decoy split, chunk boundaries, and timing. Every wire frame is a byte-length-identical 64 KiB unit of cryptographic noise carrying randomly-offset real data or a pure decoy, committed under a per-message Merkle root and acknowledged by a uniform fixed-size receipt. The client is AGPL-3.0 (`p2party-js`); the website (`p2party.com`) and signaling server (`p2party-server`) are being opened alongside it.

---

## 2. Offensive-cryptography transport mechanisms

Each mechanism below is paired with the traffic-analysis property it defends. File/line refs are from the crypto-code dataset.

| Mechanism | What it is | Traffic-analysis property defended |
|---|---|---|
| **Uniform 64 KiB framing** (`MESSAGE_LEN = 64*1024`) — `src/utils/constants.ts:10`, `src/cryptography/utils.h:8` | Every data-channel frame is exactly `MESSAGE_LEN`; `CHUNK_LEN = MESSAGE_LEN − IMPORTANT_DATA_LEN` flexes payload capacity while the on-wire frame stays constant. | Frame length never reveals message size, chunk size, chunk boundaries, or real-vs-decoy for any observer, including the relay. |
| **Fixed `IMPORTANT_DATA_LEN` header budget** — `src/cryptography/utils.h:31` | Ephemeral pk + identity signature + metadata + Merkle proof + AEAD nonce/tag occupy a fixed header, so real-data capacity per frame is deterministic. | Guarantees every frame is byte-length identical regardless of payload. |
| **Full-noise chunk fill** — `src/utils/splitToChunks.ts:149` | Each chunk buffer is filled entirely with `crypto.getRandomValues`, then only `percentageFilledChunk` of real data is overlaid; unused space is cryptographic noise, not zeros. | Whole frame is indistinguishable from random ciphertext; no zero-padding fingerprint. |
| **Random real-data offset** (`chunkStartIndex`) — `src/utils/splitToChunks.ts:150` | Real bytes are placed at a random offset in `[0, chunkSize*(1−percentageFilledChunk)]` via `randomNumberInRange`. | Position of useful data inside the noise is unpredictable — not fixed at byte 0. |
| **Decoy chunks** (out-of-range `chunkEndIndex`) — `src/utils/splitToChunks.ts:166` | Once all real bytes are placed, remaining chunks carry no real data: `chunkEndIndex` is bumped so `end − start > totalSize`. On the wire a decoy is a normal signed, encrypted, Merkle-committed frame. | Only a recipient holding decrypted metadata can detect a decoy; the real chunk count is hidden under cover frames. |
| **Random decoy end-index** (up to `MAX_SAFE_INTEGER`) — `src/utils/splitToChunks.ts:167` | Decoy `chunkEndIndex` is drawn from a wide range above `totalSize`. | Decoy markers are not a constant sentinel that could be pattern-matched. |
| **Fisher-Yates chunk shuffle + decoy interleave** (design premise, per the v3 spec) | Chunks of a message are shuffled and interleaved with decoys before send; the relay can further reorder. | Order carries no positional information; per-chunk nonce = `chunkIndex` makes random-order delivery safe under one message key. |
| **Merkle-root-bound AEAD per chunk** — `src/cryptography/utils.c:141` | Each chunk is encrypted with the message Merkle root as AEAD additional data. | Chunks are cryptographically tied to one message; cannot be replayed or spliced across transfers/roots. |
| **Per-chunk domain-separated Ed25519 signature** — `src/utils/constants.ts:55` | Signature over `DOMAIN ‖ merkle_root ‖ ephemeral_pk` authenticates the sender per frame. | Authenticates each frame while making the signature unusable outside this domain (defeats the challenge-oracle replay — see §4). |
| **Uniform reverse read-receipt token** — `src/cryptography/utils.c:176` | After proof verification the receiver re-emits the 64-byte domain-separated leaf hash as the ack; every frame (real, decoy, dup, crypto-fail) emits exactly one 64-byte receipt (reals send the true leaf hash, others a fresh random 64-byte token — see finding `6016862`). | Fixed-size opaque receipts reveal nothing about chunk content or index, and the reverse receipt count equals the forward frame count, hiding the real/decoy split. |
| **1 MiB send-buffer high watermark** (16 frames) — `src/utils/constants.ts:18` | `MAX_BUFFERED_AMOUNT = 16*MESSAGE_LEN` keeps transfers on the P2P data channel; the WS relay is reserved for a genuinely dead channel. | Denies the signaling server sender/receiver identity, size, timing, and the plaintext root label that the chunking scheme exists to hide. |

### The "uniform chunks make a PQ ratchet ciphertext free" insight

Because every chunk is a uniform 64 KiB frame, a whole post-quantum KEM ciphertext (ML-KEM-768 ≈ 1088 B, X-Wing ≈ 1120 B) fits inside **one** chunk at under 2% occupancy. This eliminates the entire reason schemes like Signal's SPQR exist — 42-byte micro-chunking with Reed-Solomon erasure coding to spread a too-large ciphertext. In p2party a hybrid rekey can even ride a **decoy** slot, giving free cover-traffic rekey-hiding. v3 therefore reserves structural markers (`PQ_TAG` in the CPace channel-input, a `PQ_EPOCH` header marker) so a future hybrid ML-KEM / X-Wing KEM folds into the ratchet root **without another wire break**.

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

**ADR-R2 — Receipts ARE the have-set (KISS/DRY/SSOT)**
- *Decision:* No new wire, no new store, no bitfield, no `totalChunks` field. The 64-byte leaf-hash receipts are the have-set; the sender resolves each receipt to a `chunkIndex` via `getDBNewChunk(hash)` and extrapolates which reals are missing. The sender ack-set is disposable in-memory state rebuilt from receipts; durable sources stay sender `newChunks` + receiver `chunks`. Real-vs-decoy is read from chunk metadata (`chunkEnd − chunkStart ≤ totalSize`), never tracked separately.
- *Status:* `7187836`. Core ships with no WASM rebuild.

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

**ADR-R7 — Resume across a full peer reconnect by keeping `sendWithReconcile` alive**
- *Decision:* Instead of the spec's original "registry + re-derive destroyed WASM state" plan, keep `sendWithReconcile` alive across the reconnect: on channel death, `resumeChannel` re-opens the **same** Merkle-root-labeled channel on the peer's fresh connection and continues with `senderSecretKey`/modules/`ackedReal` still in scope. The receiver persists `Chunk.leafHash` (optional field, **no** `dbVersion` bump) and re-emits stored receipts on the new channel's `onopen`.
- *Rationale:* Keeping state in scope avoids re-deriving destroyed WASM state; the module-scoped `peerConnections` array is mutated in place so polling yields the fresh `epc`. No wire change, no WASM build; completion close now `drainAndClose`s.
- *Status:* `69568e0` (step 3).

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
- *Context:* The 208-byte state is heap-allocated from JS and freed before `getMerkleRoot` to fit the merkle module's fixed 2 MiB heap. Changes `libcrypto.wasm` → SRI repin + CDN redeploy required.
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

**ADR-A2 — PACE (CPace) + Double Ratchet = protocol-v3** *(design spec, awaiting implementation)*
- *Spec:* `2026-07-22-pace-ratchet-protocol-v3-design.md` / `91fd123`. A clean v3 wire break (e.g. 0.10.0), no v2 interop, ships atomically with an SRI repin + CDN upload. Sub-decisions:

  - **Merge PACE with the Double Ratchet (SSOT).** The handshake output seeds the ratchet root and messaging runs over the ratchet from the first message; the seed is the only branch (one ratchet, seeded by one of exactly two functions). *Phase 1 (a server-blind, no-PAKE high-entropy link path) is deferred* — go straight to merged v3.
  - **FS in every room; PIN adds authentication only.** The ratchet runs in every room; the seed differs by mode (X3DH-DH vs CPace) but the ratchet is byte-identical afterward.
  - **Exactly two room modes, no fallback.** The presence of a PIN *is* the mode; wrong/absent PIN, key-confirmation failure, DTLS-fingerprint mismatch, or version mismatch all **fail closed** (abort, clear error state) — no silent downgrade, no capability negotiation. A minimal `protocolVersion` tag on the signaling connection exists only to cleanly reject a mismatched (or pre-v3) peer.
  - **CPace over Ristretto255 for the PAKE** — explicitly *not* literal ICAO-9303 PACE (drags ASN.1/APDU/Brainpool/EAC baggage libsodium doesn't expose); *not* SPAKE2+/OPAQUE (asymmetric client-server aPAKEs, mismatched to p2party's symmetric peer shape). CPace is UC-proven, offline-dictionary-resistant, FS, quantum-annoying, prime-order-clean, setup-free, symmetric.
  - **No-PIN mode = X3DH-style identity-mixed ephemeral DH:** fresh X25519 EK each side, `secret = HKDF(DH(IK_a,EK_b) ‖ DH(EK_a,IK_b) ‖ DH(EK_a,EK_b))`. **PIN mode = CPace/Ristretto255:** `PRS=NFC(PIN)`, fresh session nonce `sid`, `G = ristretto255_from_hash(H(PRS,sid,CI))` with channel-input `CI = channel-id ‖ IK_a ‖ IK_b ‖ fp_a ‖ fp_b ‖ PQ_TAG`; each side sends `Y=y·G`, `K=y·Y_peer`, `secret=HKDF(K,CI)`; explicit key-confirmation MAC over the transcript before any message flows. Both modes yield a single 32-byte secret binding both parties' identity keys.
  - **DTLS-fingerprint binding.** Fingerprints (from received/local SDP `a=fingerprint`) fold into `CI` and are **re-verified post-connect** via `RTCPeerConnection.getStats()` transport→certificate reports; disagreement tears the channel down. Identity-key binding is the always-on floor; fingerprint binding is the primary MITM check with no identity-only fallback.
  - **Drop the 0.9.0 per-chunk Ed25519 signature — atomically.** Frame shrinks (−64 B, −1 sign+verify/chunk; the `handleReceiveMessage` case `-1` "signature wrong" path removed) but ONLY with the mutual-identity-authenticated ratchet, and only because both seed paths mix both parties' static Ed25519→X25519 keys — under an authenticated root the Poly1305 tag is a genuine sender authenticator. Dropping it earlier would be a net downgrade (Risk R1).
  - **Frame layout.** Remap the 96-byte cleartext prefix (`ephemeral_pk 32 + signature 64`) → **48 bytes** (`DH_ratchet_pub 32 + N 8 + PN 8`). The DH pub stays cleartext (needed to derive the key before decrypt); `N`/`PN` fold into the AEAD AAD (previously merkle_root only) so they're authenticated without a separate MAC. A `PQ_EPOCH` header marker is reserved; `METADATA_LEN` is untouched (inside the encrypted payload).
  - **Ratchet granularity.** Pairwise per `(roomId, peerPublicKey)`; the DH/chain ratchet advances **per logical message**, never per chunk. All chunks of a message share ONE message key with nonce = `chunkIndex`; a retransmit of a `chunkIndex` MUST reuse the identical deterministic ciphertext; a message key is never reused across two logical messages; out-of-order/lost messages use a bounded skipped-keys map (`MAX_SKIP ≈ 500`, measured against the 2 MB heap).
  - **Handshake wiring.** Run at the top of `extChannel.onopen` (now async), gated to the persistent per-peer main channel (`merkleRootHex==='' && channelLabel==='main'`); handshake frames carry an explicit 1-byte type tag routed ahead of the length-only classifier; non-handshake frames arriving before `ratchetEstablished` buffer on the existing queue/seen/drain machinery; the reconnect leaf-hash receipt-replay burst is gated on `epc.ratchetEstablished`.
  - **At-rest persistence.** New IndexedDB store `ratchetSessions` keyed `['roomId','peerPublicKey']` (stable identity edge, not the per-session `peerId`), `dbVersion 16→17` purely additive. All secret fields (rootKey, chain keys, `dhSelfSec`, skipped keys) stored **wrapped** under a single non-extractable (`extractable:false`) WebCrypto AES-GCM key held in IndexedDB, so raw key bytes never enter JS. The live session handle lives on `epc` (not Redux); only serializable `pakeVerified`/`ratchetEstablished` booleans go in Redux. The PIN is a secret and is **never** persisted (transient roomId-keyed module `Map`).
  - **Anti-guessing.** `MAX_PIN_ATTEMPTS = 3` then **exponential backoff** (not a hard lock), enforced at the honest peer, **per room** (not per claimed identity — identities are attacker-chosen), persisted so reconnect doesn't refill it; counter clears on successful key-confirmation or PIN rotation. PIN = 6-digit numeric (10⁶) default, NFC-normalized.
  - **WASM additions.** Compile Ristretto255 sources; new `cpace.c` / `ratchet.c` wrappers; hand-roll HKDF-SHA512 `kdf_rk`/`kdf_ck` on the already-compiled `crypto_auth_hmacsha512` (zero new source, SSOT'd labels); symmetric AEAD path (`encrypt_chachapoly_symmetric`, `receive_message_with_key`). Keep `INITIAL_MEMORY=2mb`, `ALLOW_MEMORY_GROWTH=0`, `STACK_SIZE=512kb`; cap `MAX_SKIP` conservatively so Ristretto ops + skipped-key map + per-message DH/KDF scratch fit the fixed heap (Risk R3).
  - **SSOT/DRY discipline.** All frame-layout constants (`RATCHET_DHPUB_LEN=32`, `RATCHET_N_LEN=8`, `RATCHET_PN_LEN=8`, `PQ_EPOCH_LEN`, `PQ_TAG_LEN`, MESSAGE_START remap), KDF labels, and CPace domain strings live once, byte-matched C↔TS with cross-referencing comments and a unit test asserting C and TS agree.
  - **Decoy indistinguishability under the ratchet.** Decoy frames carry ratchet headers indistinguishable from reals (random-looking DH pub, plausible `N`), verified by a decoy-header E2E test; the chunking/padding/decoy and reliability/resume semantics are otherwise unchanged except first send is gated behind the handshake.
  - **PQ-reserved (v3 is classical only).** Reserve named SSOT transcript space (`PQ_TAG` in `CI`) and a `PQ_EPOCH` marker so a future hybrid ML-KEM / X-Wing KEM folds into the root without a v4 wire break; the future ~1 KB KEM ciphertext rides handshake + periodic per-epoch rekey frames, each fitting whole in one 64 KiB chunk. No KEM is implemented in v3.
- *Status:* Design spec written, **awaiting user review before implementation**.

### 3.7 Tooling / build / project

**ADR-B1 — libsodium bump + WASM rebuild** — Submodule `3d9d8f5..7014b20` (1.0.17-RELEASE-1218; NEON/AVX-512 chacha20/salsa20, interleaved ChaCha20-Poly1305); rebuild `libcrypto`. Dropped legacy `-s NODEJS_CATCH_EXIT/NODEJS_CATCH_REJECTION` emcc flags (emcc 6.0.2 rejects them under STRICT; node-only, target is web/worker); updated `wasmLoader` SRI. Suggests a version bump so new WASM lands at a fresh `@version` path. — `8f4f656`.

**ADR-B2 — Version bump 0.8.4 → 0.9.0 for protocol-v2** — Per 0.x semver so the rebuilt `libcrypto.wasm` uploads to `cdn.p2party.com/@0.9.0/` instead of overwriting `@0.8.4` and breaking deployed clients (rollup injects `P2PARTY_VERSION`, driving loader URL + `uploadToCDN` key). Untracked the stale 0.8.4 tarball. — `6297e33`.

**ADR-B3 — Release 0.9.1** — Resume-on-reconnect + big-file streaming; pin WASM URL to `@0.9.1` (leaving `@0.9.0` for existing clients, since big-files A added a new WASM export); add `CHANGELOG.md`. Deploy: `npm run predist && npm run uploadcdn` for the WASM, then build/deploy the app. — `e867a4b`.

**ADR-B4 — Dependency bump within-range (no majors)** — `@reduxjs/toolkit 2.11→2.12`, `rollup 4.59→4.62`, `eslint 10.0→10.7`, `prettier 3.8→3.9`, `typescript-eslint 8.56→8.65`, `@types/node 25.3→25.9`, `@rollup/plugin-commonjs 29.0.0→29.0.3`. Deliberately held the breaking majors (TypeScript 7, `@rollup/plugin-terser` 1, `class-validator` 0.15) to match `p2party.com`'s pins; full headless-Chromium E2E green. — `bf4d341`. *(Shipped alongside the 0.9.2 OPFS-receive rewrite `562fbcc` as a no-wire/no-API change.)*

**ADR-B5 — Take the clean major bumps; hold TypeScript at 5.9** — Took `@rollup/plugin-terser 0.4→1.0`, `@types/node 25→26`, `class-validator 0.14→0.15` but **held TypeScript at 5.9** because `typescript-eslint` does not yet support TS 7.0 (errors out; tracking TS ≥7.1 in typescript-eslint #10940) and `p2party.com` also pins 5.9. Also modernized `tsconfig` `moduleResolution 'node'→'bundler'` (correct for this rollup-bundled `verbatimModuleSyntax` library), which surfaced and fixed two bad deep `@reduxjs/toolkit/dist/query` imports; declared the only-transitively-hoisted `globals` as a devDependency. — `ecb2560`. *(Note: the curated-memory dataset flagged this TS-7-hold rationale as not captured in memory; it is captured here from commit `ecb2560`.)*

**ADR-B6 — Reformat under prettier 3.9.6** — Line-wrap reflow only, no logic change; `prettier --check` clean across `src`. — `70a39e0`.

**ADR-B7 — SSOT for constants** — Define wire values/tunables once in `src/utils/constants.ts`, import everywhere. Only accepted exception: cross-language C↔TS mirrors (e.g. `CHUNK_AUTH_DOMAIN`, Merkle leaf/node domain bytes), which MUST carry a "must byte-match the C side" comment. — engineering discipline.

**ADR-B8 — Remove the CHAIN 41 Single Member P.C. (I.K.E.) legal entity from the website** — Footer + privacy + terms neutralized to "the operator of p2party"; address / G.E.MI. / VAT dropped; contact email replaced with a placeholder. Part of preparing the stack to go open source. — `1cf715e`. *(Leaves GDPR docs temporarily without a named controller — see §6.)*

**ADR-B9 — Open-source the whole stack; TURN is off-the-shelf coturn** — Client `p2party-js` (public, AGPL-3.0), website `github.com/p2party/p2party.com`, signaling server `github.com/p2party/p2party-server`. STUN + signaling + TURN(coturn) on EU/Hetzner. AGPL-vs-other licensing for website/server repos + LICENSE files not yet decided.

---

## 4. Security findings & fixes (ledger)

Severity as recorded in the inputs. Commit = the fixing/design commit.

| # | Finding | Sev | Root cause | Fix | Commit |
|---|---|---|---|---|---|
| 1 | **`randomNumberInRange` 32-bit overflow corrupts decoy generation** | HIGH | Integer accumulated with a **signed 32-bit** `<<= 8`, so any range needing >4 bytes overflowed / went negative. Corrupted the ~2⁵³ decoy `chunkEndIndex` range: `r` could land in `[0,totalSize]` (decoy silently accepted as REAL, corrupting reassembly) or go negative and throw, failing ~75% of sends. Also a missing `return` on the `min===max` fast path (→ `RANGE=0`, `Math.log2(0)=-Infinity`) and a double-resolve. | BigInt-based unbiased rejection sampling correct for 53-bit ranges; added the missing early return; removed the double-resolve. Corrected decoy lower bound (`chunkEnd+totalSize+1`) then structurally guarantees `end−start > totalSize`. Introduced `bun:test` with an isolated `tsconfig.test.json`. | `8340686` |
| 2 | **Two WASM buffers leaked per send exhaust the encryption heap** | MED | `allocateSendMessage` `malloc`'d `ptr4` (ed25519 secret key) and `ptr8` (sha512 buffer) and returned them, but `sendChunks` never freed them — 128 B orphaned per send into the fixed, non-growable encryption heap until `_malloc` fails and all sends halt until reload (self-DoS). | Removed the two dead allocations at their source in `allocateSendMessage` (single teardown freeing exactly what it returned, avoiding double-free with the per-iteration locals). | `656d6dd` |
| 3 | **Received chunk offsets stored unvalidated** | MED | `handleReceiveMessage` sliced `chunk[chunkStartIndex, chunkEndIndex]` from attacker-controllable metadata, sanity-checked only against `totalSize/MESSAGE_LEN`. Out-of-range/inverted offsets that still pass the decoy check silently store wrong bytes and corrupt reassembly. | Pure `isStorableChunkRange` guard requiring `0 ≤ start ≤ end ≤ chunk.length` before slicing (`src/utils/chunkBounds.ts:9`); failing chunks dropped like decoys. | `8fc2e9e` |
| 4 | **Secret WASM buffers left in heap after free** | MED | `_malloc`/`_free` don't clear memory; encryption/receive heaps are long-lived and reused, so freed secret key material lingered in the `ArrayBuffer`. | Route secret frees through a `zeroFree(module, view)` helper (mirrors `sodium_free`): ephemeral secret key + seed on send, sender identity-secret copy, receiver secret key on channel close, seed/secret in ed25519 keygen. | `ffef0e1` |
| 5 | **Swapped nonce/tag sizes in AEAD box-layout comments** | LOW | The AEAD box is `nonce(12) ‖ ciphertext ‖ tag(16)`, but source comments had nonce/tag sizes backwards (misleading for implementers). | Corrected the comments. The dead `random_bytes.c` path in `scripts/paths.js` was intentionally left as-is (feeds the WASM build, out of scope for the pure-TS pass). | `e3acb5c` |
| 6 | **Chunk-auth challenge-oracle message forgery** | HIGH | Chunk auth signed the bare 32-byte ephemeral pubkey, and the same identity key signs the raw 32-byte server login challenge with **no domain separation** — a malicious signaling server sends a "challenge" equal to an ephemeral pubkey, harvests the signature, and injects a forged frame the receiver accepts as authentic. Plus a copy-paste NULL-check in `decrypt_chachapoly_asymmetric`/`chacha20poly1305.c` tested the wrong pointer after `malloc`. | Sender signs a domain-separated transcript `'p2party-chunk-auth-v1' ‖ merkle_root(64) ‖ ephemeral_pk(32)`; receiver verifies over the reconstructed transcript, so the two signature domains are incompatible (no server change). Frame byte-identical (64-byte sig); breaking pre-decryption verify. NULL-check corrected to test the pointer actually allocated (`sender_x25519_pk`). | `0174333` |
| 7 | **SDP/ICE glare race put `setRemoteDescription` in wrong state** | LOW | Concurrent SDP/ICE signaling for the same peer interleaved at `await` points; `epc.signalingState` went stale → `setRemoteDescription` in the wrong state ("Called in wrong state: stable"), breaking establishment. | Module-level `Map<peerId, AsyncMutex>` (`negotiationLock.ts`); wrapped `webrtcSetDescriptionQuery`/`webrtcSetIceCandidateQuery` bodies in `getPeerMutex(peerId).runExclusive` (per-peer serialized; different peers still parallel). Removed the now-redundant `NEGOTIATION_DEBOUNCE_MS`, kept the perfect-negotiation guard. | `c5386611` |
| 8 | **Merkle-tree malleability (CVE-2012-2459 class)** | HIGH | No leaf/node domain separation (an internal-node hash could be reinterpreted as a leaf), and lone odd nodes hashed with themselves (`H(x‖x)`), letting distinct leaf multisets collide to one root. | Leaves `SHA-512(0x00‖chunk)`, internal nodes `SHA-512(0x01‖l‖r)` via `hash_node`; lone odd node promoted unchanged. Applied across `merkle.c`, `hashMerkleLeaf`, `receive_message`, TS helpers. Bundled win: receiver computes the leaf once on the stack (drops a `malloc`) and reuses it as the receipt token. | `c39c4d6` / merge `2c1df22` |
| 9 | **Low data-channel buffer watermark spills metadata to the relay** | MED | `MAX_BUFFERED_AMOUNT` was 2 frames (131072), so ordinary congestion immediately spilled full 64 KiB frames through the signaling server — handing it sender/receiver, size, timing, and the plaintext root label. | Raised to 16 frames (1 MiB; browsers buffer ~16 MiB) so normal transfers stay P2P; relay reserved for a genuinely dead channel. Opaque channel IDs (to replace the plaintext root label) specified but deferred (conflict with chunk-auth transcript, overlap ratchet redesign). | `c584ed0` |
| 10 | **Read-receipt count leaks real-vs-decoy split** | MED | Receipts were emitted only for accepted REAL chunks, so a DTLS-record observer could count the tiny 64-byte reverse records to recover the real chunk count, defeating the decoy padding. | Every frame reaching `processMessage` emits exactly one 64-byte receipt — real-new chunks send their true leaf hash, every other frame (decoy/already-stored/crypto-failed) sends a fresh **random** 64-byte token — so reverse count = forward count. Safe by construction (a random token can't equal the 512-bit message hash, ~2⁻⁵¹², so never triggers completion; `getDBNewChunk` resolves nothing so `savedSize` is untouched). Kept at 64 B (not padded to 65536) to avoid a WASM-offset marker byte and 1024× reverse amplification; decoy receipts are data-channel only. | `6016862` |
| 11 | **`close()` before drain wipes still-buffered send data** | MED | `RTCDataChannel.close()` discards anything queued in the SCTP send buffer; the `send(messageHash)` immediately followed by `close()` in `disconnectFromChannelLabelQuery` could wipe the just-queued finished-message receipt (and buffered chunks) before it reached the wire. | `drainAndClose()`: poll `bufferedAmount` to 0, bounded by a timeout so a stalled channel can't hang teardown, then close. Verified with both per-message channels closing at `bufferedAmount === 0`. | `b5ebe2f` |
| 12 | **Channel `onclose` destroyed the resend source on any disconnect** | MED | The per-message channel's `onclose` deleted the sender's `newChunks` on ANY close — including a mid-transfer disconnect — destroying the resend source (receiver stalled ~98%); an abandoned send could also leak its body into IndexedDB. | Deletion gated on an explicit race-free `transferComplete` flag from the completion path (passed from `handleReadReceipt`, not re-read after an `await`), with terminal cleanup after all peers settle. Adversarial fixes folded in: `resumeChannel` no longer spawns duplicate same-label channels on a slow open; death test tightened to closed/closing; receipt re-emit loop got `bufferedAmount` backpressure. | `69568e0` |
| 13 | **Concurrent `readMessage` assembles collide → whole-file-in-RAM** | MED | With streaming OPFS reassembly, an overlapping/poll-style `readMessage` opened a second exclusive OPFS sync access handle, collided, and silently fell back to building the whole file in an in-memory Blob (the exact OOM being removed). A non-idempotent re-truncate could invalidate a `File` handed out earlier (`NotReadableError`); assembled OPFS files orphaned as full-size copies on delete/wipe. | Coalesce concurrent assembles per `merkleRoot` via an in-flight-promise `Map`; idempotency guard returns a correctly-sized existing content-addressed file as-is; remove assembled OPFS files on delete (`fnDeleteOPFSFile`) and the whole subtree on full DB wipe; drop partial files from a failed write; always close `getDB()`/handle/connection even on mid-stream error, with short writes looped to completion. | `0357713` |
| 14 | **Receive-time OPFS write path: dedup TOCTOU + `uniformSize` double-count** | MED | Writing received chunks straight to OPFS introduced a `count()→add()` dedup TOCTOU and a shared-entry double-count that could lock the learned `uniformSize` to the short final chunk when the same file arrived from two peers; durability wasn't guaranteed before committing the have-set record; open receive handles could leak on stalled transfers; delete/close paths raced. | Serialize all receive-file ops per `merkleRoot` in the worker (closes TOCTOU + double-count); `flush()` each chunk before committing its have-set record (a bytesless record always implies durable bytes, so a resumed sender never skips a chunk whose bytes are missing); cap open handles by evicting the oldest; run delete's close+`removeEntry` under the per-`merkleRoot` lock; `closeAllReceiveFiles` awaits in-flight opens before a full DB wipe. | `562fbcc` |

**Deferred (specified, not built):** Merkle change #8's *Tier-2 spec* framing and forward-secrecy belong to later increments; server-side challenge-signature domain separation is defense-in-depth needing a coordinated server change (deferred, per the Tier-2 spec).

**Adversarial-review note:** the OPFS receive work surfaced findings #13 (5 issues) and #14 (3 issues incl. HIGH) *only* under adversarial review, not the happy-path E2E — see §7.

---

## 5. Threat model — now (0.9.x) vs after protocol-v3

| Attacker class | Now (0.9.x) | After protocol-v3 (PACE + Double Ratchet) |
|---|---|---|
| **Passive / off-path network or relay observer** | Cannot infer message size, chunk size/count, real-vs-decoy split, or chunk boundaries — uniform 64 KiB framing + full-noise fill + decoys + AEAD. Residual: receipt **timing** side channel (a real chunk's receipt is delayed by verify+DB vs an immediate decoy receipt) and the reconnect receipt-replay **burst** length can hint at the real chunk count (both deferred to the obj-4 hardening layer). Count-uniformity itself was closed by `6016862`. | **Defeated in all rooms** by forward secrecy + AEAD (as before). |
| **Active malicious/compromised signaling server (MITM)** | **HIGH exposure.** Peers learn each other's Ed25519 pubkeys + DTLS fingerprints only from server-relayed messages, and `onlyConnectWithKnownAddresses` is off by default. The server can substitute pubkey + SDP fingerprint and transparently MITM DTLS + app-layer crypto. The per-chunk signature binds a frame to a sender but the sender's key came from the server. | **Defeated in PIN rooms** — CPace binds a PIN the server doesn't hold plus the observed identity keys and both DTLS fingerprints, with a key-confirmation MAC that fails if the legs' `CI` disagree (a swapped key/cert makes them disagree). **Explicitly NOT defeated in no-PIN rooms** — a server substituting both identities still MITMs; this is the honest, stated limit of a no-PIN room. |
| **Harvest-now-decrypt-later (recorded ciphertext + later device/key theft)** | **Not defended.** No forward secrecy: the receiver's DH half is its STATIC identity key (Ed25519→X25519), so recorded ciphertext + one later localStorage key theft decrypts ALL past messages; no post-compromise security. | **Defeated in all rooms** by the ratchet's FS/PCS. Persisted at-rest ratchet state is wrapped under a non-extractable WebCrypto AES-GCM key. |
| **Message-forgery via challenge oracle** | **Fixed (0.9.0).** Domain-separated chunk-auth transcript makes a signature harvested from the raw-nonce server challenge unusable as chunk auth (`0174333`). | Per-chunk signature is dropped atomically; under the mutual-identity-authenticated ratchet the Poly1305 tag is the sender authenticator. |
| **Online PIN guessing (MITM, one guess per CPace exchange)** | N/A (no PIN mode yet). | CPace removes offline dictionary attack; `MAX_PIN_ATTEMPTS=3` then per-**room**, persisted, exponential backoff (not a hard lock) throttles a guesser to a crawl over the 10⁶ space while a legitimate mistyper simply retries; keying per-room (not per attacker-chosen identity) prevents both counter reset and room-DoS. |
| **DTLS-fingerprint substitution that manifests post-connect** | Not detected (fingerprints come from the server-relayed SDP). | Fingerprints bound into `CI` from the SDP and **re-verified post-connect** via `getStats()`; any disagreement tears the channel down (abort, not log). |
| **At-rest attacker with device + origin access** | Can read localStorage secrets (the current static-key weakness). | Non-extractable wrap stops raw-key export / cross-device copy, but does **NOT** stop local decryption by an attacker with device+origin access — a documented, accepted limit. The PIN itself is never persisted. |

**v3 implementation risks tracked in the spec:** R1 (atomicity — dropping the per-chunk signature is a net downgrade unless it lands with a mutual-identity-authenticated ratchet where both seed modes bind both identity keys), R2 (async-onopen retrofit + cross-datachannel ordering/deadlock + length-only classifier collision — mitigated by type-tagged handshake frames, the `ratchetEstablished` gate, and buffer-then-drain), R3 (nonce/key reuse + 2 MB heap pressure — mitigated by deterministic-ciphertext retransmit, never reusing a message key across messages, a measured `MAX_SKIP≈500`, and `cryptography/memory.ts` profiling).

---

## 6. Still-open weaknesses & roadmap

1. **Unauthenticated trusted-PKI signaling server (HIGH to active server, LOW to passive).** Peers learn keys + fingerprints only from server-relayed messages; `onlyConnectWithKnownAddresses` off by default. → **Planned:** PACE/PAKE "secure rooms" in protocol-v3 (CPace/Ristretto255 PIN rooms or authenticated ephemeral X25519 DH, binding both Ed25519 identity keys + both DTLS fingerprints). Design spec `91fd123` written, **awaiting user review**.
2. **No forward secrecy / no PCS.** Receiver's DH half is the static identity key; one later key theft decrypts all past. → **Planned:** full Signal-style Double Ratchet per `(roomId, peerPublicKey)` edge, seeded by the PACE key; subsumes and replaces the per-chunk Ed25519 signature. Design-only, folded into the protocol-v3 spec.
3. **Opaque channel IDs not yet done — the Merkle root still travels PLAINTEXT in the DataChannel label**, linking a message's chunks + fan-out to the server/peers. → **Deferred** (conflicts with the 0.9.0 chunk-auth transcript, which signs the root read pre-decryption from the label; overlaps the ratchet session/key-id redesign — do it inside that redesign).
4. **Transfer obj-4 residual side channels.** Count-uniformity was closed by `6016862`, but **timing** (real receipt delayed by verify+DB vs immediate decoy receipt) and the **WS-relay** path (real receipts hex through the signaling server, exposing leaf hashes + the split) remain, as does the **reconnect receipt-replay burst** which re-emits one receipt per REAL chunk held (not decoy-padded like live 1:1 operation), leaking a real-chunk-count size hint on reconnect. → **Deferred** to an optional obj-4 timing-hardening layer: normalized/fixed-cadence emission, stop relaying receipt content, close-gate on all-frames-receipted, and pad/pace the reconnect burst 1:1. Touches the C side, so it needs its own verified pass. *(Note: the curated-memory dataset still describes receipts as "per REAL chunk only"; that predates `6016862`, which already emits one receipt per frame — the remaining gap is timing/relay/reconnect, not the live count.)*
5. **GDPR/legal docs have no named data controller and a placeholder contact email** after the CHAIN 41 removal (`1cf715e`); ToS §6 "Open-Source Software" lists only `p2party-js` + a generic `github.com/p2party` link. → **Planned:** supply a named controller + real email before publishing; update ToS §6 to add the `p2party.com` + `p2party-server` repos and note TURN = coturn once public.
6. **Deploy debt:** any WASM change (streaming SHA-512 export, future PACE/Ristretto rebuild) must ship as a PROD build with an SRI repin + a version bump, because a WASM change under a live `@version` breaks existing clients via SRI mismatch (loader still fetches from `cdn.p2party.com`). → **Process:** `npm run predist` (rebuild prod WASM + auto-repin SRI via `updateWasmIntegrity.mjs`) → bump to a new `@version` CDN path → `npm run uploadcdn` (AWS creds). Never overwrite a live version with changed WASM.
7. **Deferred capstone deliverables (after PACE+ratchet):** (a) READMEs for the three repos (`p2party-js` SDK, `p2party.com` website, `p2party-server` signaling server) covering what it is, the offensive-crypto transport, quickstart, architecture, security model, licensing; (b) a possible applied/systems LaTeX paper on the traffic-analysis-resistant chunked transport and the "uniform chunks make a PQ-ratchet ciphertext free and hideable in decoys" insight — **with a prior-art pass first** (see §8). AGPL-vs-other licensing + LICENSE files for the website/server repos are undecided.

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
- **Cover traffic** (general anonymity-system padding). Contrast: p2party folds cover into the transfer itself (decoy chunks) and can ride a rekey on a decoy slot for free.
- **PURBs / padded uniform random blobs** (padding to hide length and format). Contrast: p2party fixes the *frame* at 64 KiB and randomizes real-data *offset within* each frame rather than only padding message length.
- **Tor traffic analysis** (fixed-size cells; timing/volume correlation attacks). Relevant to the residual obj-4 timing/receipt side channels and the uniform-cell analogy (Tor 512-byte cells vs p2party 64 KiB frames).
- **Signal SPQR** (Sparse Post-Quantum Ratchet) — 42-byte micro-chunking + Reed-Solomon erasure coding to spread a too-large PQ KEM ciphertext. Direct contrast: p2party's 64 KiB uniform chunk swallows a whole ML-KEM-768 (~1088 B) / X-Wing (~1120 B) ciphertext at <2%, so SPQR's reason for existing vanishes and a rekey can even hide in a decoy.
- **Apple PQ3** (hybrid PQ messaging ratchet). Position the classical-now / PQ-reserved (`PQ_TAG`, `PQ_EPOCH`) folding-in-without-a-wire-break design against it.
- **CPace** (CFRG `draft-irtf-cfrg-cpace`) — UC-proven, offline-dictionary-resistant, FS, quantum-annoying, prime-order-clean, setup-free, symmetric PAKE — the chosen primitive; contrast with ICAO-9303 PACE (ASN.1/APDU/Brainpool/EAC baggage) and asymmetric SPAKE2+/OPAQUE.
- **Double Ratchet** (Signal) — the FS/PCS engine; p2party's novelty is per-**logical-message** (not per-chunk) ratcheting over shuffled, decoy-interleaved, uniform 64 KiB chunks with `nonce = chunkIndex` and deterministic-ciphertext retransmit.
