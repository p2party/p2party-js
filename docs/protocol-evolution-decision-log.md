# p2party Protocol-Evolution Decision Log

*A structured record of the design dilemmas the p2party wire protocol has faced on the road to protocol-v3. Dual-register: each entry carries a precise one-liner for the paper's "Design Rationale" section and, where the difficulty earns it, a sentence of narrative color for the blog's "road of hard choices." Depth is proportional to difficulty — the obvious calls are one-liners; the genuinely hard ones (the unrealizable nonce, the atomic signature drop, the ratchet commit-before-auth desync, the DTLS fail-open, D1, D2, and the future Kemeleon obstacle) get the full tension/options/reasoning treatment. Every claim is anchored to a commit or a section of `docs/design-decisions-and-security-findings.md`, `docs/protocol-v3-implementation-log.md`, the protocol-v3 design spec / plan under `docs/superpowers/`, the Stage-4 SDD task reports under `.superpowers/sdd/`, or `docs/paper-prior-art-and-related-work.md`. Where the artifacts record no debate, none is asserted.*

---

## 0. Framing: the protocol as an evolution, decisions as the through-line

p2party did not begin with a handshake. It began with a naive per-chunk scheme: a message split into uniform 64 KiB chunks, each carrying a per-chunk Ed25519 signature, sent from the initiator to every peer in the mesh in parallel, with the WebRTC data-channel label literally spelling out the message's Merkle root. Every subsequent version is a decision made under pressure — a malleability class closed here, a metadata leak plugged there, a whole reliability subsystem rewritten spec-first after two incremental prototypes died of races — until the accumulated pressure forced the current rewrite: **protocol-v3**, which retires the per-chunk signature and folds a PACE-style PAKE handshake (CPace over Ristretto255 for PIN rooms, X3DH-style identity-mixed DH for no-PIN rooms) into a per-edge Double Ratchet seeded by exactly one of those two handshakes. The decisions below *are* that evolution; the last two — **D1** (session binding) and **D2** (the no-PIN identity key) — were where the road ran out of paved surface, and both are now decided (maintainer, 2026-07-22; see §2).

---

## 1. RESOLVED DILEMMAS

Grouped by concern, roughly chronological within each group. "Deferred" entries have a chosen interim answer but an explicitly parked structural follow-up; they are marked as such rather than presented as fully closed.

### 1a. Crypto-primitive

**C-1 — Merkle-tree malleability (CVE-2012-2459 class).**
*Paper:* Undifferentiated leaf/internal-node hashing plus self-hashing of lone odd nodes (`H(x‖x)`) let distinct leaf multisets collide to one root; fixed by domain-separating leaves (`SHA-512(0x00‖chunk)`) from internal nodes (`SHA-512(0x01‖l‖r)`) via a `hash_node` helper and promoting lone odd nodes unchanged (with a free efficiency win: the receiver computes the leaf once and reuses it as its receipt token).
*Source:* finding #8 / ADR-K1; commits `c39c4d6`, merge `2c1df22`; shipped protocol-v2.

**C-2 — Chunk-auth challenge-oracle message forgery.**
*Paper:* The sender signed the bare 32-byte ephemeral pubkey with the same identity key that (undomain-separated) signs the 32-byte server login challenge, so a malicious signaling server could harvest a signature over a "challenge" equal to an ephemeral key and inject a forged frame; fixed by signing a domain-separated 117-byte transcript `DOMAIN(21)='p2party-chunk-auth-v1' ‖ merkle_root(64) ‖ ephemeral_pk(32)`, verified pre-decrypt, at zero wire cost.
*Source:* finding #6 / ADR-M3 / ADR-M4; design commit `0174333`, merge `393aa20`; shipped 0.9.0. (Server-side domain separation of the login challenge itself noted as complementary defense-in-depth, deferred pending a coordinated server change.)

**C-3 — `randomNumberInRange` 32-bit overflow corrupting decoy generation.**
*Paper:* Range sampling accumulated with a signed 32-bit `<<= 8`, overflowing the ~2⁵³ decoy range so a decoy could land in `[0,totalSize]` and be accepted as REAL (corrupting reassembly) or go negative and throw (~75% of sends failing); replaced with BigInt unbiased rejection sampling correct for 53-bit ranges, plus a missing early return and a removed double-resolve.
*Source:* finding #1; commit `8340686` (introduced `bun:test` + `tsconfig.test.json`).

**C-4 — WASM send-buffer leak and unzeroed secret buffers.**
*Paper:* `allocateSendMessage` malloc'd an ephemeral Ed25519 secret and a SHA-512 scratch buffer that `sendChunks` never freed (128 bytes orphaned per send into the fixed non-growable heap → eventual self-DoS), and freed secret buffers were never cleared before free; fixed by removing the dead allocations and routing all secret frees through a `zeroFree` helper mirroring `sodium_free`.
*Source:* findings #2 and #4; commits `656d6dd`, `ffef0e1`.

**C-5 — Received chunk offsets stored unvalidated.**
*Paper:* `handleReceiveMessage` sliced `[chunkStartIndex, chunkEndIndex]` from attacker-controllable decrypted metadata checked only against `totalSize`; added a pure `isStorableChunkRange` guard (`0 ≤ start ≤ end ≤ chunk.length`), dropping failing chunks like decoys.
*Source:* finding #3; commit `8fc2e9e`.

**C-6 — Fixed 2 MB WASM heap: link-time claim vs runtime-verified budget gate.**
*Paper:* `INITIAL_MEMORY=2mb / ALLOW_MEMORY_GROWTH=0` was only a build flag once Ristretto255/X25519/HKDF/AEAD shared the heap; added a runtime test that runs the heaviest Stage-1 op (`receive_message_with_key` over a full 64 KiB frame) on a fresh 32-page memory and asserts `byteLength` is still exactly 2,097,152, trapping any future `maximum` change that reintroduces headroom.
*Source:* Stage 1; commit `a848694`.

**C-7 — Unrealizable per-chunk nonce (`nonce = chunkIndex`) → fresh random 12-byte cleartext nonce.** *(hard)*
*Paper:* The v3 plan's `nonce = chunkIndex` is unrealizable (chunkIndex lives inside the encrypted metadata, so the receiver can't know it before decrypting), and both obvious repairs are broken (one message-counter `N` across all chunks = catastrophic ChaCha20-Poly1305 nonce reuse; a cleartext raw index leaks chunk count/order); resolved as a fresh random 12-byte nonce per chunk carried in the cleartext frame header — receiver-derivable, metadata-safe, birthday-safe within one message key — with a retransmit required to reuse the identical cached `(nonce, ciphertext)`.
*Blog:* Adversarial review caught this before a single send↔receive round-trip existed — the "obvious" nonce was one that the receiver literally cannot read until after it has already decrypted.
*Source:* Stage 1 narrative + Methodology item 1; commit `92b07e8`. **NB:** the C-level `#define`s and the placeholder nonce in `receive_message_with_key` were deliberately left at the old values with an in-code note, scheduled for reconciliation in Stage 5 — see **F-4** (this is the source of the still-live 62-vs-50 frame-layout fork).

**C-8 — CPace transcript ambiguity → IRTF-CPace `lv_cat` length-prefixing.**
*Paper:* Bare-concatenation `SHA512(DOMAIN‖PRS‖sid‖CI)` becomes ambiguous once CI binds variable-length data, letting distinct `(PRS, CI)` pairs collide to one generator `G`; mandated IRTF-CPace `lv_cat` length-prefixing of every transcript field (and wiped leftover PRS/PIN bytes from the heap).
*Source:* Stage 2 `cpace` + Methodology item 2; commits `b3b69b7`, `e5f6348`, `58c02a4`.

**C-9 — Hand-rolled RFC 5869 HKDF → libsodium's native HKDF-SHA512.**
*Paper:* Swapped a hand-rolled HKDF-SHA512 in a security-critical path for libsodium's `crypto_kdf_hkdf_sha512_extract/_expand` behind identical export names/signatures (downstream cpace/x3dh/ratchet untouched), verified byte-identical against the same KAT and `node:crypto.hkdfSync` — pure downside-removal, prefer the vetted native primitive.
*Source:* Stage 2 "Stage-1 revision"; commit `d8ae95b`.

**C-10 — Unwiped X25519 DH secret in the Stage-2 wrapper.**
*Paper:* The X25519 shared secret and the keypair failure path were freed without `zeroFree`, leaving key material in the reused WASM heap; fixed to zero-before-free, noting that a passing agreement test proves the DH is correct but says nothing about erasure.
*Source:* Stage 2 `x25519` + Methodology item 3; commit `26d353f`.

**C-11 — X3DH test suite blind to the initiator's own identity-key binding.**
*Paper:* The X3DH tests bound the peer's IK but had no negative control for the initiator's own `IK_a` — silently dropping `IK_a` from the DH mix would have kept every test green; added the missing negative test corrupting `IK_a` and asserting agreement breaks.
*Source:* Stage 2 `x3dh` + Methodology item 4; commit `b4b713d`.

**C-12 — Unbounded skipped-message-key retention (no global cap).**
*Paper:* Only a per-decrypt `MAX_SKIP=512` bound existed on the ratchet's out-of-order skipped-key map, with no global cap (unbounded RAM and later persisted-row growth), and the plan's "capped at MAX_SKIP" comment was false; fixed with `MAX_SKIP_SESSION=2000` (evict-oldest), header integer validation (`Number.isInteger, >=0`), and an honest doc-comment.
*Source:* Stage 2 `ratchet` + Methodology item 5(#2); commits `8bba4e9`, `d65ce73`.

**C-13 — Ratchet decrypt mutates state before AEAD authentication (replay-desync).** *(Deferred; hard)*
*Paper:* `ratchetDecrypt` mutates ratchet state (possibly firing a backward DH step) *before* the AEAD tag verifies, so a duplicate/replayed old-chain message — reachable via p2party's own retransmit layer — can desync a session that should have been rejected; **deferred** to Stage 4/5 as a documented caller contract (decrypt on a serialize/deserialize clone, commit only after auth, dedup `(dhPub,N)`), not yet structurally fixed as of Stage 3.
*Blog:* The right fix is to restructure decrypt so it authenticates before it mutates; for now the danger is fenced off by a caller discipline written into the plan's Global Constraints, with the structural rewrite named and parked — an authenticated-encryption invariant (never mutate on unverified input) that today lives in a contract instead of the code.
*Source:* Stage 2 Methodology item 5(#1).

**C-14 — Ratchet granularity: per-chunk vs per-logical-message.**
*Paper:* Chunks of one message are shuffled, interleaved with decoys, and may retransmit, so per-chunk ratchet advance complicates deterministic-ciphertext retransmit; resolved as pairwise per `(roomId, peerPublicKey)` with the DH/chain ratchet advancing **per logical message** (one message key for all its chunks, nonce disambiguates chunks), a message key never reused across two messages, out-of-order/lost messages handled by the bounded skipped-keys map.
*Source:* ADR-A2 "Ratchet granularity."

**C-15 — Drop the 0.9.0 per-chunk Ed25519 signature — but only *atomically* with the ratchet.** *(hard)*
*Paper:* The per-chunk signature (added in 0.9.0 to close C-2) costs 64 bytes plus a sign+verify per chunk; once both PACE seed paths mix both parties' static identity keys — making the Poly1305 tag itself a genuine sender authenticator under an authenticated root — it becomes redundant, but dropping it *before* the authenticated ratchet lands would be a net downgrade; resolved to drop it atomically in the same release as the ratchet, tracked as Risk R1, never phased (phased = two wire breaks).
*Blog:* The one piece of hard-won 0.9.0 armor is scheduled for removal — but only at the exact moment its replacement (a mutually-authenticated ratchet) is load-bearing, not one commit sooner.
*Source:* ADR-A2 "Drop the 0.9.0 per-chunk Ed25519 signature — atomically"; §5 threat-model + Risk R1; design §12.

### 1b. Handshake

**H-1 — PAKE primitive choice for PIN mode.**
*Paper:* Rejected literal ICAO-9303 PACE (drags ASN.1/APDU/Brainpool/EAC baggage libsodium doesn't expose) and SPAKE2+/OPAQUE (asymmetric client-server aPAKEs, mismatched to p2party's symmetric peer shape); chose **CPace over Ristretto255** (UC-proven, offline-dictionary-resistant, forward-secret, quantum-annoying, prime-order-clean, setup-free, symmetric).
*Source:* ADR-A2; §8 prior-art positioning.

**H-2 — PACE + Double Ratchet: separate deferred-PAKE phase vs merged handshake/ratchet as SSOT.**
*Paper:* Considered shipping a server-blind, no-PAKE high-entropy link path (Phase 1) first as a stepping stone; chose instead to **merge** PACE with the ratchet immediately as the single source of truth — the handshake output seeds the ratchet root and messaging runs over the ratchet from the first message; Phase 1 explicitly deferred (see **F-3**).
*Source:* ADR-A2 spec `91fd123`; plan `9f8acc3`.

**H-3 — Capability negotiation rejected in favor of a binary version tag with fail-closed reject.**
*Paper:* Rejected per-peer capability negotiation with best-effort downgrade to an "unverified" mode; chose a minimal `protocolVersion` tag with strict equality against `PROTOCOL_VERSION = 3` (`isProtocolVersionCompatible`), no fallback (missing field = pre-v3 = rejected), "presence of a PIN is the mode," no "unverified" degradation UX.
*Source:* design §2 pt 3, §7; plan Stage 6 Task 1 (`protocolVersion.ts`), Task 2 (`selectHandshakeMode`).

**H-4 — Atomic v3 wire break — no v2↔v3 interoperability.**
*Paper:* Considered a capability-detect/downgrade interop path to the old per-chunk-signature scheme; chose a clean, non-interoperable break (`0.9.2 → 0.10.0`), old v2 rooms/data kept separate — the same reason R1's signature-drop must ship atomically.
*Source:* design §2 pt 4, §3, §15, §12 R1; plan Global Constraints; Stage 7 CHANGELOG draft.

**H-5 — Throttling online PIN-guessing: `MAX_PIN_ATTEMPTS` + exponential backoff, keyed to the room not the identity.**
*Paper:* CPace defeats offline dictionary attacks but a MITM signaling server still gets one online guess per session; resolved with `MAX_PIN_ATTEMPTS = 3` free key-confirmation failures per room, then `PIN_BACKOFF_BASE_MS·2^(n-1)` (base 500 ms, capped ~5 min) — **backoff, not a hard lock** (a permanent lock would let one malicious peer DoS the room) — counter persisted **per room only** (identities are attacker-chosen, so a per-identity counter resets on reconnect), cleared on success or PIN rotation, all failure states fail closed via a serializable secret-free `Peer.pakeVerified` boolean.
*Source:* design §7; plan Stage 6 Tasks 1/3/7 (`pinBackoff.ts`, `pakeVerified`).

**H-6 — DTLS remote-certificate verify failed OPEN when the live cert stat was unverifiable.** *(review-driven fix; hard)*
*Paper:* `verifyDtlsFingerprints` guarded with `if (liveRemoteFp !== null && liveRemoteFp !== remoteSdpFp) throw` — but `certificateFingerprint` legitimately returns `null` (missing transport stat / absent `remoteCertificateId` / no matching cert stat), and `null` short-circuited the `&&` so an *unverifiable* MITM tripwire silently passed; rewritten to fail closed on both branches (`if (liveLocalFp === null || liveLocalFp !== localSdpFp) throw`, and symmetric for remote), with a regression test asserting rejection.
*Blog:* The tripwire that was supposed to catch a man-in-the-middle would wave one through whenever it couldn't read the certificate at all — caught as CRITICAL in Stage-4 review and made to treat "can't verify" identically to "mismatch," the canonical fail-open→fail-closed correction.
*Source:* introduced `445aaea`, fixed `2af322b` (re-reviewed APPROVED); `.superpowers/sdd/task-s4t3-report.md`; `src/handlers/handleHandshake.ts`.

**H-7 — Key-confirmation R2 ordering: verify-then-send deadlocks on a wrong PIN.** *(review-driven fix)*
*Paper:* The brief's flow had the initiator verify the responder's `mac_R` before sending its own `mac_I`, so a wrong PIN aborted the initiator before `mac_I` was ever sent and the responder's `recv()` blocked forever; fixed by sending `CONFIRM{0, mac_I}` (needs only transcript `T`, not ratchet state) *before* verifying `mac_R`, so both legs reject independently, while `initRatchet` still runs only after `mac_R` verifies (a failed handshake yields no usable initiator ratchet).
*Source:* commit `c835244`; `.superpowers/sdd/task-s4t4-report.md` deviation #6.

**H-8 — `getStats()` certificate lookup: the brief's `stats.get(id)` fallback doesn't typecheck.** *(review-driven fix)*
*Paper:* The project's TS DOM lib declares `RTCStatsReport` with only `forEach` (no `.get()`), so the brief's `stats.get(id) as any` fallback fails to typecheck; re-derived the same matching using `forEach`'s own key argument (each report's id per webrtc-stats), keeping `report.id` as a secondary check, typed with a local `RTCStatEntry`.
*Source:* commit `445aaea`; `.superpowers/sdd/task-s4t3-report.md` deviation #2.

**H-9 — `buildChannelInput`: reusing the async `concatUint8Arrays` under a synchronous interface.** *(review-driven fix)*
*Paper:* The brief implemented `buildChannelInput` via the codebase's async `concatUint8Arrays` (`Promise<Uint8Array>`), but the interface + test require a synchronous `Uint8Array`; kept the synchronous signature as source of truth and wrote a small local synchronous byte-concat.
*Source:* commit `445aaea`; `.superpowers/sdd/task-s4t3-report.md` deviation #1.

**H-10 — HELLO/CONFIRM frame validation: tag-byte check without an exact-length check.** *(review-driven fix)*
*Paper:* The brief validated only the leading type-tag byte before parsing HELLO/CONFIRM, so a short/truncated frame with a valid tag would parse via out-of-range slices; added exact `HELLO_LEN`/`CONFIRM_LEN` checks so any malformed inbound handshake frame throws (which `runHandshake`'s single catch turns into a gate rejection).
*Source:* commit `c835244`; `.superpowers/sdd/task-s4t4-report.md` deviation #7.

### 1c. Transport / framing

**T-1 — Low data-channel buffer watermark spilling metadata to the relay.**
*Paper:* `MAX_BUFFERED_AMOUNT` was 2 frames (131072 B), so ordinary send congestion immediately spilled full 64 KiB frames through the signaling-relay path (handing it sender/receiver identity, size, timing, and the plaintext root label); raised to 16 frames (1 MiB; browsers buffer ~16 MiB), keeping normal transfers P2P and reserving relay for a genuinely dead channel.
*Source:* finding #9; commit `c584ed0`.

**T-2 — Read-receipt count leaking the real-vs-decoy split.**
*Paper:* Receipts were emitted only for accepted REAL chunks, so a DTLS-record observer could count the 64-byte reverse records to recover the real chunk count and defeat decoy padding; rejected padding every receipt to full frame size (needs a WASM-offset marker + 1024× reverse amplification); resolved by emitting exactly one fixed 64-byte receipt per **every** forward frame (real/decoy/dup/crypto-fail), reals carrying the true leaf hash and everything else a fresh random 64-byte token — so reverse count == forward count, safe by construction.
*Source:* finding #10; commit `6016862`.

**T-3 — `close()` before drain wipes still-buffered send data.**
*Paper:* `RTCDataChannel.close()` discards the SCTP send buffer, so `send(messageHash)` immediately followed by `close()` could wipe the just-queued finished-message receipt; resolved with `drainAndClose()` — poll `bufferedAmount` to 0, bounded by a timeout so a stalled channel can't hang teardown, then close.
*Source:* finding #11 / ADR-R5; commit `b5ebe2f`.

**T-4 — Channel `onclose` destroying the resend source on any disconnect.**
*Paper:* The per-message channel's `onclose` deleted the sender's `newChunks` on *any* close (including a mid-transfer disconnect), destroying the resend source and stalling the receiver near completion (and leaking an abandoned send's body into IndexedDB); gated deletion on an explicit race-free `transferComplete` flag set only by the completion path, with terminal cleanup after all peers settle.
*Source:* finding #12; commit `69568e0`.

**T-5 — Reliability layer: incremental patches vs one spec-first subsystem.** *(process)*
*Paper:* Two incremental prototypes (a fixed-cadence receipt scheduler and a resend-all retransmit) each hit subtle races and were reverted, proving the pieces couldn't be built independently; resolved by designing the whole transfer layer spec-first as **one** subsystem against four explicit objectives (no double-store; sender sends all needed chunks; no close before verified; receipts leak nothing about content/size) plus resume-on-reconnect and telemetry.
*Blog:* Two honest attempts to patch reliability one race at a time both had to be rolled back — the lesson the log records is that this was a subsystem, not a set of independent patches.
*Source:* ADR-R1; spec `2026-07-20-reliable-transfer-resume-telemetry-design.md`, commit `927c4ac`.

**T-6 — Have-set representation: new wire/bitfield vs reusing receipts.**
*Paper:* Considered a new bitfield/`totalChunks` wire field + store to track which chunks the receiver has; chose to treat the existing 64-byte leaf-hash receipts as the have-set itself (KISS/DRY/SSOT) — the sender resolves each receipt to a `chunkIndex` via `getDBNewChunk(hash)` and extrapolates missing reals, ack-set is disposable in-memory state rebuilt from receipts.
*Source:* ADR-R2; commit `7187836`.

**T-7 — Retransmit vs resume: separate mechanisms or one reconcile path.**
*Paper:* Considered building retransmit-on-timeout and resume-on-reconnect as two code paths; chose a single `reconcile()` with two triggers (live timeout, or reconnect + receipt replay), selective resend only via `sendChunks(onlyIndices)`, decoys never resent (cover, never acked), bounded by `MAX_RETRANSMITS` with linear backoff.
*Source:* ADR-R3; commit `9d29fe9`.

**T-8 — Opaque channel IDs vs plaintext Merkle-root label in the data-channel name.** *(Deferred)*
*Paper:* The WebRTC data-channel label carries the Merkle root in plaintext, letting a relay/signaling observer link a message's chunks and fan-out to peers; **deferred** into the ratchet's session/key-id redesign rather than solved standalone, because opaque IDs now would conflict with the 0.9.0 chunk-auth transcript (which signs the root as read pre-decryption from the label).
*Source:* ADR-T4, finding #9, §6 weakness item 3.

**T-9 — `serializeRatchet` returns `ArrayBuffer` fields, not `Uint8Array`.** *(review-driven fix; persistence-adjacent)*
*Paper:* The brief accessed `s.rootKey.buffer` and spread `[...(sA.dhRemotePub as Uint8Array)]`, but `RatchetSessionSecrets` fields are plain `ArrayBuffer` (no `.buffer`, doesn't iterate bytes on spread); passed the `ArrayBuffer` values directly to `wrapSecret` and fixed the test's spread to `[...new Uint8Array(sA.dhRemotePub as ArrayBuffer)]`.
*Source:* commit `c835244`; `.superpowers/sdd/task-s4t4-report.md` consumed-signature deviation #2.

### 1d. Persistence

**P-1 — Persist ratchet state across page refresh without leaking secrets at rest.**
*Paper:* A refresh discards the live ratchet (collapsing forward-secrecy continuity), but plaintext IndexedDB persistence would hand a DB dump every root/chain key the ratchet rotates away; resolved with an additive `ratchetSessions` store (dbVersion 16→17) keyed by `(roomId, peerPublicKey)`, secret fields wrapped under a single non-extractable WebCrypto AES-GCM key (fresh 12-byte IV per wrap), public/counter fields left cleartext so the non-unique indexes stay queryable without decrypting.
*Source:* Stage 3; commits `5bedc9b`, `7ec1776`, `fe4f159`, `1da2c27`, `4da1719`.

**P-2 — Cross-tab race creating the wrap key on first run.**
*Paper:* Two tabs racing to create the AES-GCM wrap key could each persist a different key; `getWrapKey()` uses double-checked locking (cheap read → speculative `generateKey` outside any txn → authoritative re-check inside a `readwrite` txn on `meta` before `put`), and IndexedDB serializing `readwrite` txns across connections makes the re-check a real mutex — the race was already structurally closed, with only a rare-re-handshake liveness note and a doc-wording polish remaining.
*Source:* Stage 3 "a race found already closed."

**P-3 — Non-extractable WebCrypto wrap key: how much protection it actually buys.**
*Paper:* `extractable:false` defeats raw-key exfiltration and cross-device copy (`exportKey('raw', …)` refuses) but **not** an attacker who already holds device+origin (in-origin XSS can still invoke `decrypt` via the handle) — documented honestly rather than overclaimed; real-browser structured-clone survival deferred to the Stage-7 E2E pass.
*Source:* Stage 3 "The at-rest wrap."

**P-4 — At-rest ratchet-secret wrapping: non-extractable WebCrypto key now vs passphrase-derived KEK later.** *(Deferred alternative)*
*Paper:* Chose the non-extractable WebCrypto key for v3 because it survives refresh silently; the stronger **passphrase-KEK** at-rest is explicitly named and **deferred** (not rejected) precisely because it trades away the "survives refresh without re-entry" property.
*Source:* design §8, §15, §12 R3(a); plan Stage 3 (`ratchetWrap.ts`).

**P-5 — Resume across a full peer reconnect: registry + re-derive vs keep-state-alive.**
*Paper:* The original spec plan re-derived destroyed WASM state via a registry; chose instead to keep `sendWithReconcile` alive across the reconnect, reopening the same Merkle-root-labeled channel on the peer's fresh connection with `senderSecretKey/modules/ackedReal` still in scope; the receiver persists `Chunk.leafHash` (additive, no dbVersion bump) and re-emits stored receipts on reopen.
*Source:* ADR-R7; commit `69568e0` (step 3).

**P-6 — Large-file handling: whole-file-in-RAM vs streaming to OPFS.**
*Paper:* The two whole-file-in-RAM spots (send-side message hash, receive-side reassembly Blob) blocked GB+ files; resolved by streaming both — a JS-callable incremental SHA-512 WASM export fed ~1 MiB at a time on send, and `assembleToOPFS` writing each chunk's slice to its file offset via a worker-only `createSyncAccessHandle` on receive; eventually (0.9.2) received chunks are written straight to OPFS at their offsets as they arrive, dropping the reassembly pass entirely.
*Source:* ADR-S1/S2/S3/S4/S6; commits `c360cd6` (superseded), `772635f`, `44867ca`, `0357713`, `562fbcc`.

**P-7 — OPFS reassembly API: `showSaveFilePicker` vs worker sync-access-handle.**
*Paper:* Safari has no main-thread `createWritable()`, so `showSaveFilePicker` is Chromium-only; chose OPFS via a worker-only `createSyncAccessHandle` for cross-browser coverage (Chrome/Edge 86+, Firefox 111+, Safari 15.2/16.4+) and the fastest path (no structured-clone tax).
*Source:* ADR-S4; commit `0357713`.

**P-8 — `readMessage` materializing large files on every render.**
*Paper:* A frontend audit found `readMessage` on the render path, so previews/file bubbles materialized huge files every render; added a `materialize` arg (default `true`) whose `false` mode returns metadata only for a completed FILE without reassembling — backward-compatible.
*Source:* ADR-S5; commit `8e57593`.

**P-9 — Concurrent `readMessage` assembles collide → silent whole-file-in-RAM fallback.**
*Paper:* An overlapping/poll-style `readMessage` opened a second exclusive OPFS sync handle, collided, and silently fell back to an in-memory Blob — reintroducing the exact OOM the streaming rewrite removed; coalesced concurrent assembles per `merkleRoot` via an in-flight-promise Map, with an idempotency guard, removal on delete/wipe, partial-file cleanup, and always-close handles even on mid-stream error.
*Source:* finding #13; commit `0357713`.

**P-10 — Receive-time OPFS write: dedup TOCTOU + `uniformSize` double-count.**
*Paper:* Writing received chunks straight to OPFS introduced a `count()→add()` dedup TOCTOU and a shared-entry double-count that could lock the learned `uniformSize` to the short final chunk when the same file arrived from two peers, plus durability-before-have-set-commit and open-handle leaks; resolved by serializing all receive-file ops per `merkleRoot` in the worker, `flush()`-ing each chunk before committing its have-set record (so a bytesless record always implies durable bytes), capping open handles (evict-oldest), running delete's close+removeEntry under the per-`merkleRoot` lock, and awaiting in-flight opens before a full DB wipe.
*Source:* finding #14; commit `562fbcc`.

### 1e. Process / methodology

**M-1 — Adversarial two-stage review adopted as a required gate, not a courtesy pass.**
*Paper:* Considered gating security-critical crypto/ratchet code solely on a green KAT/unit suite; adopted instead a mandatory two-stage (spec-compliance then code-quality) adversarial subagent review per task — which across Stages 1–3 caught 5 genuine issues a green suite would not surface (C-7 unrealizable nonce, C-8 CPace transcript ambiguity, C-10 unwiped DH secret, C-11 X3DH blind spot, C-12/C-13 ratchet skipped-key/replay) and separately confirmed P-2 was already safely closed.
*Blog:* The through-line of this whole rewrite is a methodology: tests prove the code does what it asserts, and a dedicated adversary is what proves the assertions were the right ones.
*Source:* Methodology sections across Stages 1–3.

**M-2 — `ratchetGate` brief test asserted a tautology that fails strict typecheck (TS2801).** *(review-driven fix)*
*Paper:* The brief's memoization test `expect(getRatchetGate('B')).not.toBe(getRatchetGate('B') && null)` triggers TS2801 (the `Promise<void>` is provably never falsy) and at runtime reduces to `not.toBe(null)`, testing nothing; replaced with an equivalent typechecking assertion verifying both halves of the title (memoized while unreset; distinct after `resetRatchetGate`), gate implementation untouched.
*Source:* commit `b21fe78`; `.superpowers/sdd/task-s4t2-report.md` §4.

**M-3 — `rejectRatchetGate` on a never-awaited peer fires an unhandled-rejection event.** *(review-driven fix)*
*Paper:* Rejecting a lazily-minted promise with zero listeners fires the runtime's unhandled-rejection event even though a later consumer still receives the error; added a synchronous no-op `promise.catch(() => {})` at construction inside `ensure()`, with a regression test crossing two macrotask boundaries.
*Source:* commit `4b98c62` (re-reviewed APPROVED); `.superpowers/sdd/task-s4t2-report.md`.

### 1f. Signaling

**S-1 — SDP/ICE glare race breaking peer establishment.**
*Paper:* Concurrent SDP/ICE signaling for the same peer interleaved at `await` points, leaving `epc.signalingState` stale and `setRemoteDescription` in the wrong state ("Called in wrong state: stable"); resolved with a module-level `Map<peerId, AsyncMutex>` wrapping the set-description/ICE bodies in `getPeerMutex(peerId).runExclusive` (per-peer serialized, different peers still parallel), removing the ad-hoc `NEGOTIATION_DEBOUNCE_MS` and keeping the perfect-negotiation guard.
*Source:* finding #7; commit `c5386611`.

### 1g. Scope / capability

**Sc-1 — Tier 1 (pure-TS) vs Tier 2 (C/WASM) split for crypto hardening.**
*Paper:* Because `wasmLoader.ts` fetches `libcrypto.wasm` from a CDN under a hardcoded sha384 SRI, any WASM/wire change needs a CDN redeploy + SRI bump before it can reach the running app; split the hardening batch into Tier 1 (pure-TS, no wire change, testable against the existing CDN wasm, independently shippable) and Tier 2 (C/WASM, wire-breaking, versioned protocol-v2).
*Source:* ADR-M2; design commit `91d5955`; specs `2026-07-20-crypto-hardening-tier1-design.md`, `…-tier2-protocol-v2-design.md`.

---

## 2. DECIDED — the two hard handshake calls (maintainer, 2026-07-22)

> These were the two genuinely-open decisions of the v3 handshake, escalated to the design owner in `.superpowers/sdd/progress.md` ("ESCALATIONS to design owner") and analyzed in the companion rigor memo (`scratchpad/handshake-rigor-memo.md`, workflow `wf_a20541e8-a93`). Both are now **DECIDED** (2026-07-22). The shipped Stage-4 code (`src/handlers/handleHandshake.ts`, commit `c835244`) had converged on *none* of the options for either — for D1 it exchanges a real 32-byte `sidSelf` in HELLO but feeds an empty `CPACE_GEN_SID` to the generator; for D2 it reads the Ed25519 `keyPair` straight out of Redux and passes raw bytes into `x25519Dh` with no conversion or dedicated-key step — so both decisions are also implementation work, not just doc updates. Recording these is what unblocks the ADR-A2 update that was the pending DOCS TODO gating Stage-4 Task 5.

### D1 — DECIDED: initiator-random `sid` (fill the existing single-round HELLO field)

*Paper:* Protocol-v3's single-flight CPace/Ristretto255 PIN handshake binds each session with a **fresh initiator-chosen `sid`** — 16–32 bytes from `crypto.getRandomValues` placed in the HELLO `sid` field the frame already carries — fed into the generator `G` and the key-confirmation transcript `T`. This is on-spec (the CFRG CPace draft's guidance for exactly this initiator/responder single-flight topology) and adds **zero round trips**. The channel-input `CI = channelId‖IK_a‖IK_b‖fp_a‖fp_b‖PQ_TAG` (the DTLS fingerprints) is retained as an **independent second binding layer**, with a runtime assertion that no `RTCCertificate` is cached or reused across sessions; the **human PIN inside CPace remains the real MITM anchor**, CI documented as defense-in-depth against signaling bugs, not as the primary MITM defense.

**Chosen: Option 2 (initiator-random `sid`).** Options weighed (from the rigor memo):

| Option | Verdict | Why |
|---|---|---|
| **1. Empty `sid` + CI(DTLS-fp) + fresh-cert guard** *(shipped `c835244` behavior)* | Rejected | Adequate under a fresh-cert invariant but **not provably ideal** — it forfeits the UC-composability guarantee the cited proof [AHH21] ties to `sid` uniqueness (CPace draft §10.9), and rests on p2party's own unblessed inference that "CI does `sid`'s freshness job." Freshness becomes a silent operational invariant (never reuse `RTCCertificate`), not a cryptographic one. |
| **2. Initiator-random `sid` in the existing HELLO** ⭐ | **DECIDED** | Literally the draft's prescribed fix for this exact single-flight topology, at **zero extra RTT** — the HELLO field already exists and the code already fills a random `sidSelf` (it just wasn't feeding the generator). Restores the `sid`-uniqueness assumption the UC proof needs. The "mutual contribution needs 2 messages" belief was a conflation of *mutual contribution* with mere *freshness*. |
| **2b. Full 2-message mutual `sid`** | Rejected (cost) | Strictly stronger against a *biased-but-not-colluding initiator RNG*, but costs a structural extra round trip (G must be fixed before either Y), and Option 2 already closes the standards gap for free. Escalation path only if the initiator's own RNG is distrusted. |
| **3. DTLS/TLS-exporter binding (RFC 9266)** | Deferred → FUTURE | Theoretically the **strongest** value — derived from the live handshake's fresh secrets, immune to the cert-reuse / triple-handshake failure class — but **no browser JS surfaces a general-purpose DTLS exporter** (`RTCDtlsTransport`/webrtc-stats expose none). A pure API-surface gap, tracked as **F-8**, to adopt the day a browser exposes it. |

*Rationale:* Fill the `sid` because it is the on-spec, free move that takes the design from "sanctioned degenerate mode" to inside the letter of the cited proof; keep CI as belt-and-suspenders against signaling-layer bugs; name the PIN as the MITM defense (matching RFC 8827's SAS/IdP requirement and MLS's don't-trust-the-transport posture). The cert-fingerprint reuse concern is the **same class** as the historical `tls-unique` / triple-handshake failures — a static/reusable artifact standing in for a fresh-secret binding — **not literally that failure**; the fresh-`sid` + fresh-cert invariant plus the PIN is what neutralizes it in-browser today.
*Standards:* CPace draft §3.1 (initiator chooses a fresh random `sid`, ≥8 bytes; use 16+) and §10.9 (`sid` SHOULD NOT be reused — UC composability depends on it); RFC 9266 (channel binding to fresh handshake secrets; the corrected successor to fingerprint/`Finished`-based binding, parked as F-8); RFC 8827 (WebRTC Security Architecture: assume signaling is adversarial, require SAS/IdP).
*Blog:* The handshake's own author shipped empty-`sid` and, to his credit, flagged it as a Concern rather than a silent choice; a rigor pass then showed the "fix" rested on conflating *mutual contribution* with mere *freshness* — and that a fresh unilateral `sid`, on-spec and free, was already sitting in a HELLO field the code fills but doesn't yet read. The decision took the free fix, kept the belt-and-suspenders, and held a slot (F-8) for the binding that browsers won't yet expose.
*Source:* design spec `…v3-design.md` lines 117–123; `.superpowers/sdd/task-s4t4-report.md` deviation #5 / Concern #2; `.superpowers/sdd/progress.md` (escalation, now resolved); `scratchpad/handshake-rigor-memo.md` §D1; `src/handlers/handleHandshake.ts` lines 186–194 (`CPACE_GEN_SID` empty — to be fed the real `sid`), 307 (`sidSelf` random); `docs/paper-prior-art-and-related-work.md` line 342 (RFC 9266 nearest prior art). Implementation follow-up: audit the generator-string byte layout against draft §8.1 (`CI`-before-`sid` ordering, PRS/DSI zero-padding) and confirm the `K == G.I` identity-element abort is present.

### D2 — DECIDED: Option B, dedicated X25519 identity key + codebase-wide key separation

*Paper:* The no-PIN identity-mixed X3DH DH `secret = HKDF(DH(IK_a,EK_b)‖DH(EK_a,IK_b)‖DH(EK_a,EK_b))` runs over a **dedicated, separately-generated X25519 identity key**, never the Ed25519 signing key. The Ed25519 identity key stays the sole signing/identity anchor and **cross-signs** the X25519 key so it inherits identity authentication; the X25519 key is **seed-derived from the existing mnemonic via a domain-separated KDF** (single-seed backup/upgrade UX, never one scalar for two group operations). This is the textbook key-separation choice and is PQ-forward — the planned hybrid KEM key is unavoidably separate too, so committing to separation now is the forward-compatible move.

**Chosen: Option B (dedicated X25519 key + key separation).** Options weighed (from the rigor memo):

| Option | Verdict | Why |
|---|---|---|
| **A. Convert Ed25519 IK → X25519** (`crypto_sign_ed25519_sk/pk_to_curve25519`) *(the spec's original passing-clause plan)* | Rejected | Smallest delta and settled birational math, but reuses a signing key for DH with **no joint-security proof** for bare Ed25519-sign ∥ X25519-DH; the only precedent (XEdDSA §8) explicitly declines to certify it — and p2party's plan is a *weaker* variant than XEdDSA (no sign-bit discipline, no randomized-nonce construction). Plus a documented silent-truncation footgun (`sk_to_curve25519` reads only the first 32 of the packed 64-byte secret), a signing/DH lifecycle conflict, and a PQ dead-end. |
| **B. Dedicated separate X25519 identity key** ⭐ | **DECIDED** | Removes the entire unanalyzed cross-protocol-reuse class; matches NIST SP 800-57 §5.2, libsodium's FAQ ("always safer"), Noise §14, and MLS/RFC 9420's separate `signature_key`/`encryption_key`. Independent lifecycle, PQ-forward, tiny cost (one 32-byte pubkey in a CI that already carries an IK, two fingerprints, and a PQ tag). Cross-sign or same-seed-derive for UX. |
| **C. Defer no-PIN; ship PIN-only** | Acceptable interim only | Zero D2 crypto risk now (CPace never touches the identity keys); a legitimate product-scope call — *provided* the eventual no-PIN path lands on B, **never** A as a "temporary" measure. |

*Precedent it migrates off:* p2party's **shipped** `chacha20poly1305` box scheme already converts the one Ed25519 identity to X25519 (`crypto_sign_ed25519_sk_to_curve25519` / `pk_to_curve25519` + `crypto_kx`), thereby reusing a single key for **both** signing and DH — exactly the XEdDSA-uncertified pattern. D2=B deliberately migrates the codebase *off* that reuse: the box scheme is **deprecated-in-place** (decrypt kept for legacy interop, v3 never uses it), and v3's no-PIN path consumes the dedicated X25519 key instead. The WASM already exports `_x25519_keypair` + `_sign`/`_verify`, so **no new Ed25519→X25519 conversion export is added** (the truncation footgun is removed by never taking that path).
*Rationale + honest caveat:* This is risk-aversion + PQ-forwardness, **not a demonstrated break** — there is **no published attack** on Ed25519/X25519 reuse specifically (unlike the RSA/EMV case in Degabriele et al.). The reasoning is "no one has proven the exact scheme-pair jointly secure, the field default is separation, and the PQ KEM key forces separation anyway," not "a forgery is imminent."
*Standards:* XEdDSA §8 (reuse for sign + certain DH is "a complicated topic requiring careful analysis… outside the scope"); NIST SP 800-57 Pt.1 Rev.5 §5.2 ("a single key shall be used for only one purpose"); libsodium FAQ (prefer distinct keypairs; PQ sig/KEM keys are incompatible types); Noise §14 (reusing a static key outside its protocol "would require extremely careful analysis"); MLS/RFC 9420 (structurally separate `signature_key` / `encryption_key`; Signal's PQXDH likewise added a *separate* KEM key).
*Implementation shape (current plan):* X25519 key seed-derived from the mnemonic (domain-separated, upgrade/backup-friendly); Ed25519 cross-signs the X25519 pub; box scheme deprecated-in-place; CI optionally carries the X25519 IK (or its cross-signature) so both peers bind it; `performHandshakeCore`'s no-PIN branch reads a real X25519 key rather than converting, PIN branch untouched. This supersedes the shipped `c835244` flow that fed a 64-byte Ed25519 secret into a function expecting a 32-byte X25519 scalar.
*Blog:* The spec committed, in a single passing clause, to converting the one identity key p2party already has — and implementation then discovered the conversion primitive was never even exported, and the wired data flow was feeding a 64-byte Ed25519 secret into a 32-byte X25519 slot. The gap between "what one line of the design decided" and "what a safe implementation requires" *was* the dilemma; the decision resolves it by separating the keys — and, in doing so, migrating p2party off the very same one-key-for-both reuse its shipped `chacha20poly1305` box scheme has quietly relied on all along.
*Source:* design spec `…v3-design.md` line 108, §9 (no conversion primitive listed); `.superpowers/sdd/task-s4t4-report.md` Concern #1; `.superpowers/sdd/progress.md` (escalation, now resolved); `scratchpad/handshake-rigor-memo.md` §D2; `src/handlers/handleHandshake.ts` line 509 (`idSelfSec = hexToUint8Array(secretKey)` — to be replaced by the dedicated X25519 key); `src/cryptography/x3dh.ts`, `src/cryptography/x25519.ts`; shipped box scheme `src/cryptography/chacha20poly1305.*` (the reuse being migrated off).

---

## 3. FUTURE DILEMMAS

Named destinations and known-open technical dependencies past the current work. Some carry genuine recorded option-sets (full treatment); the roadmap items carry only a stated direction — no fabricated debate is attached where none is on record.

### F-1 — The PQ epoch: whole-ciphertext-per-epoch vs SPQR-style micro-chunking *(recorded options; hard)*
*Paper:* Once v3's classical ratchet ships, how should a future hybrid PQ KEM (ML-KEM-768 / X-Wing) fold into the ratchet? p2party's stated insight is to exploit its uniform 64 KiB transport to carry a whole ~1 KB KEM ciphertext in a single chunk at <2% occupancy per epoch — skipping the erasure-coding that Signal's SPQR needs only because its per-message PCS budget caps at ~40 bytes — and even ride a decoy slot for free cover-traffic rekey-hiding. v3 reserves the seam (`PQ_TAG` in CI, a `PQ_EPOCH` header marker, both value 0 in v3) so a future hybrid KEM folds into the root without another wire break; **no KEM is implemented in v3.** Sub-decision (open): KEM sourcing — upgrade vendored libsodium 1.0.22 (may expose `crypto_kem_*` X-Wing — VERIFY) vs `mlkem-native`/`libcrux-ml-kem` vs `@noble/post-quantum`.
*Blog:* This is the grant's headline promise, and the log culminates here: the uniform chunk that hides real data behind decoys turns out to make a post-quantum rekey nearly free to carry and free to hide — a structural gift SPQR and Apple's PQ3 don't have. The design is sketched; nothing is scheduled.
*Source:* §2 "uniform chunks make a PQ ratchet ciphertext free"; ADR-A2 "PQ-reserved"; design §2 pt 7, §5–6, §15; plan Global Constraints, Stage 1/5 (`PQ_TAG_LEN=1`, `PQ_EPOCH_LEN=1`); `p2party-double-ratchet-plan` (phasing, sourcing caveat); `paper-prior-art-and-related-work.md` §D/§3.

### F-2 — Kemeleon byte-uniformity obstacle to C3 *(recorded options; hard)*
*Paper:* C3 (the paper's strongest, only-novel claim) includes hiding a PQ rekey inside a pure-noise decoy chunk — but Kemeleon (Günther–Rosenberg–Stebila–Veitch, RWC 2025) shows raw ML-KEM public keys/ciphertexts are **not** computationally uniform (unlike Elligator-encoded X25519), so a raw KEM ciphertext dropped into a "pure-noise" slot is byte-level fingerprintable, undermining the decoy-hiding half of C3 as stated. Options: **(a)** apply a Kemeleon/Elligator-style obfuscation encoding to the ciphertext before hiding it (technically complete, currently unimplemented), or **(b)** scope the C3 claim to size/timing/ordering uniformity only and openly concede byte-content uniformity requires Kemeleon.
*Blog:* The prettiest line in the paper — "we can hide the post-quantum rekey inside noise" — runs straight into the one result that says raw ML-KEM bytes don't look like noise. The prior-art doc calls this "the sharpest unresolved objection… must be answered head-on," and leaves (a)-vs-(b) as an explicit to-do, not a decision.
*Source:* `paper-prior-art-and-related-work.md` §D (Kemeleon), §3 C3 verdict, §4 threats table, §5, ref #80.

### F-3 — Deferred Phase-1 server-blind high-entropy link *(direction only)*
*Paper:* The double-ratchet plan's "Phase 0/1" structure includes a server-blind, no-PAKE high-entropy link path that H-2 explicitly deferred in favor of going straight to the merged v3. The v3 design/plan files do **not** restate that phase content — they only cross-reference "the ratchet plan's Phase 0 (classical)" — so no Phase-1-vs-Phase-2 debate is asserted from these artifacts; the substance lives in the separate `p2party-double-ratchet-plan` document.
*Source:* H-2 (ADR-A2); design §2 pt 1 cross-reference; `p2party-double-ratchet-plan`.

### F-4 — Stage-5 frame-layout reconciliation: `MESSAGE_START` 62 vs 50 *(open, internally inconsistent; hard)*
*Paper:* The per-chunk nonce discipline is decided in principle (C-7: fresh random 12-byte cleartext nonce → `MESSAGE_START`/`CHUNK_HEADER_LEN` = 62/61) and the plan's Global Constraints preamble restates it, explicitly flagging the old `nonce = chunkIndex` as "WRONG." **But the plan's executed Stage-5 task bodies still implement the deterministic layout** (`nonce = chunkNonce(chunkIndex)`, 50/49), carried through the sender/receiver swap, Stage 6/7 consumer contracts, and the draft CHANGELOG. This is a live, unpropagated fork; the C-level `#define`s and the placeholder nonce in `receive_message_with_key` were also left at old values pending Stage 5. The maintainer must pick one layout and actually edit the plan, landing it against the first real send↔receive round-trip KAT.
*Blog:* The design won the argument — random nonce, 62-byte header — but the win never propagated into the task bodies that ship the code, which still carry the rejected `nonce = chunkIndex` and its 50-byte header. Stage 5 is where that contradiction, deferred since Stage 1, finally has to be reconciled against the first end-to-end round-trip test.
*Source:* design §6 (random-nonce rationale, `MESSAGE_START`=62); plan Global Constraints line 17 vs Stage 5 Task 1/3 (`chunkNonce`, 50/49), Task 11 CHANGELOG; C-7 in-code note (Stage-1 log).

### F-5 — Optimized chunk-flooding: peer-to-peer relay instead of sender-fans-out-to-all *(roadmap; direction only)*
*Paper:* Today "data is transferred naively from the initiator to every node in the mesh in parallel"; roadmap beat ② is to have peers relay chunks to each other so flood throughput scales with peer count. The sources record only the destination, not a weighed set of relay-topology alternatives — no such debate is on record, so none is asserted.
*Source:* `p2party-writing-style` ROADMAP ②; `p2party-project-overview`.

### F-6 — Signaling decentralization via gossip *(roadmap; direction only)*
*Paper:* Today every peer holds its own WebSocket to the single trusted-PKI signaling server; roadmap beat ③ is to have only a small percentage of peers keep a live WS socket, the rest learning peer/room info via gossip — reducing the server's centrality and metadata exposure. Only the destination is recorded, not a set of considered gossip-protocol alternatives.
*Source:* `p2party-writing-style` ROADMAP ③; `p2party-project-overview` "Still open" item 1 (today's signaling server is an unauthenticated trusted PKI → transparent MITM of confidentiality).

### F-7 — Swift + Kotlin SDK ports (iOS/Android) *(roadmap; direction only)*
*Paper:* Roadmap beat ④ is native SDK ports to Swift and Kotlin, broadening the SDK beyond the browser/TypeScript surface (TRL 7→9 framing). No design or implementation activity found; the Swift/Xcode satellite repo is listed among the dormant repos — a deferred, unscoped future beat, not an active decision with options on record.
*Source:* `p2party-writing-style` ROADMAP ④; `p2party-project-overview` "dormant/abandoned satellites."

### F-8 — DTLS/TLS-exporter channel binding (RFC 9266) when browsers expose it *(direction only; from D1)*
*Paper:* The theoretically-strongest session binding value — derived from the live DTLS handshake's fresh secrets, immune to the cert-reuse / triple-handshake failure class — is blocked only by an API-surface gap: no browser JS surfaces a general-purpose DTLS exporter (unlike Node's `tls.exportKeyingMaterial()`). Tracked from D1 as the binding to adopt the moment a browser exposes it, at which point CI's fingerprint layer becomes fully redundant.
*Source:* D1 (§2); `scratchpad/handshake-rigor-memo.md` §D1 Option 3; RFC 9266; `docs/paper-prior-art-and-related-work.md` line 342.

---

*End of log. Resolved and deferred entries are anchored to specific fixing commits or ADR/finding sections. D1 and D2 are now DECIDED (2026-07-22) with the chosen option, a tight pros/cons summary, rationale, and standards citations; their deep pros/cons derive from the companion rigor memo. Future entries state only what the artifacts record, with roadmap items marked direction-only where no debate exists. Depth is proportional to difficulty: the hard decisions (C-7, C-13, C-15, H-6, D1, D2, F-1, F-2, F-4) carry both registers; the obvious calls are one-liners.*
