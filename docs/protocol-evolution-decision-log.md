# p2party Protocol-Evolution Decision Log

_A structured record of the design dilemmas the p2party wire protocol has faced on the road to protocol-v3. Dual-register: each entry carries a precise one-liner for the paper's "Design Rationale" section and, where the difficulty earns it, a sentence of narrative color for the blog's "road of hard choices." Depth is proportional to difficulty — the obvious calls are one-liners; the genuinely hard ones (the unrealizable nonce, the atomic signature drop, the ratchet commit-before-auth desync, the DTLS fail-open, D1, D2, and the future Kemeleon obstacle) get the full tension/options/reasoning treatment. Every claim is anchored to a commit or a section of `docs/design-decisions-and-security-findings.md`, `docs/protocol-v3-implementation-log.md`, the protocol-v3 design spec / plan under `docs/superpowers/`, the Stage-4 SDD task reports under `.superpowers/sdd/`, or `docs/paper-prior-art-and-related-work.md`. Where the artifacts record no debate, none is asserted._

---

## 0. Framing: the protocol as an evolution, decisions as the through-line

p2party did not begin with a handshake. It began with a naive per-chunk scheme: a message split into uniform 64 KiB chunks, each carrying a per-chunk Ed25519 signature, sent from the initiator to every peer in the mesh in parallel, with the WebRTC data-channel label literally spelling out the message's Merkle root. Every subsequent version is a decision made under pressure — a malleability class closed here, a metadata leak plugged there, a whole reliability subsystem rewritten spec-first after two incremental prototypes died of races — until the accumulated pressure forced the current rewrite: **protocol-v3**, which retires the per-chunk signature and requires one exact room-selected hybrid profile. Every room proves possession of the cross-signed X25519 identity through online interactive 3DH and mixes its authenticated ML-KEM-512/768/1024 choice into the bootstrap root; a PIN room additionally mixes CPace, rather than substituting CPace for 3DH. Three chained confirmation proofs protect completion. This is not Signal X3DH because there are no asynchronous prekeys. That root seeds one Double Ratchet per room/peer edge. The decisions below _are_ that evolution; **D1** and **D2** settle the handshake, **D7** records the exact-profile composition, and **D3** preserves message-scoped WebRTC channels inside a future scheduled-cover mode (maintainer decisions, 2026-07-22–24; see §2).

---

## 1. RESOLVED DILEMMAS

Grouped by concern, roughly chronological within each group. "Deferred" entries have a chosen interim answer but an explicitly parked structural follow-up; they are marked as such rather than presented as fully closed.

### 1a. Crypto-primitive

**C-1 — Merkle-tree malleability (CVE-2012-2459 class).**
_Paper:_ Undifferentiated leaf/internal-node hashing plus self-hashing of lone odd nodes (`H(x‖x)`) let distinct leaf multisets collide to one root; fixed by domain-separating leaves (`SHA-512(0x00‖chunk)`) from internal nodes (`SHA-512(0x01‖l‖r)`) via a `hash_node` helper and promoting lone odd nodes unchanged. Protocol-v2 reused that leaf directly as its receipt; current v3 keeps the one-pass leaf computation but derives a separate root/index/leaf-bound receipt token (T-6).
_Source:_ finding #8 / ADR-K1; commits `c39c4d6`, merge `2c1df22`; shipped protocol-v2.

**C-2 — Chunk-auth challenge-oracle message forgery.**
_Paper:_ The sender signed the bare 32-byte ephemeral pubkey with the same identity key that (undomain-separated) signs the 32-byte server login challenge, so a malicious signaling server could harvest a signature over a "challenge" equal to an ephemeral key and inject a forged frame; fixed by signing a domain-separated 117-byte transcript `DOMAIN(21)='p2party-chunk-auth-v1' ‖ merkle_root(64) ‖ ephemeral_pk(32)`, verified pre-decrypt, at zero wire cost.
_Source:_ finding #6 / ADR-M3 / ADR-M4; design commit `0174333`, merge `393aa20`; shipped 0.9.0. (Server-side domain separation of the login challenge itself noted as complementary defense-in-depth, deferred pending a coordinated server change.)

**C-3 — `randomNumberInRange` 32-bit overflow corrupting decoy generation.**
_Paper:_ Range sampling accumulated with a signed 32-bit `<<= 8`, overflowing the ~2⁵³ decoy range so a decoy could land in `[0,totalSize]` and be accepted as REAL (corrupting reassembly) or go negative and throw (~75% of sends failing); replaced with BigInt unbiased rejection sampling correct for 53-bit ranges, plus a missing early return and a removed double-resolve.
_Source:_ finding #1; commit `8340686` (introduced `bun:test` + `tsconfig.test.json`).

**C-4 — WASM send-buffer leak and unzeroed secret buffers.**
_Paper:_ `allocateSendMessage` malloc'd an ephemeral Ed25519 secret and a SHA-512 scratch buffer that `sendChunks` never freed (128 bytes orphaned per send into the then-fixed, non-growable heap → eventual self-DoS), and freed secret buffers were never cleared before free; fixed by removing the dead allocations and routing all secret frees through a `zeroFree` helper mirroring `sodium_free`.
_Source:_ findings #2 and #4; commits `656d6dd`, `ffef0e1`.

**C-5 — Received chunk offsets stored unvalidated.**
_Paper:_ `handleReceiveMessage` sliced `[chunkStartIndex, chunkEndIndex]` from attacker-controllable decrypted metadata checked only against `totalSize`; added a pure `isStorableChunkRange` guard (`0 ≤ start ≤ end ≤ chunk.length`), dropping failing chunks like decoys.
_Source:_ finding #3; commit `8fc2e9e`.

**C-6 — Historical fixed-2-MiB gate → growable module with operation-scoped maxima.**
_Paper:_ Stage 1 originally made `INITIAL_MEMORY=2mb / ALLOW_MEMORY_GROWTH=0` a tested budget by running `receive_message_with_key` in exactly 32 pages. That remains useful provenance, but it is no longer the current global memory contract. The generated module now permits growth (`ALLOW_MEMORY_GROWTH=1`, build ceiling 1 GiB), while callers supply an explicit maximum sized for the operation: small protocol-v3 operations may retain a 32-page cap, while Merkle and Argon2 helpers allocate larger bounded memories. The security invariant is therefore “no operation may exceed its declared maximum,” not “all crypto always fits in 2 MiB.”
_Source:_ Stage 1; commit `a848694`.

**C-7 — Unrealizable per-chunk nonce (`nonce = chunkIndex`) → fresh random 12-byte cleartext nonce.** _(hard)_
_Paper:_ The v3 plan's `nonce = chunkIndex` is unrealizable (chunkIndex lives inside the encrypted metadata, so the receiver can't know it before decrypting), and both obvious repairs are broken (one message-counter `N` across all chunks = catastrophic ChaCha20-Poly1305 nonce reuse; a cleartext raw index leaks chunk count/order); resolved as a fresh random 12-byte nonce carried in each cleartext frame header — receiver-derivable, metadata-safe, and birthday-safe within one message key. Current streaming reconciliation reseals a retransmitted chunk with another fresh nonce rather than retaining whole cached ciphertext; the invariant is never to reuse a `(message key, nonce)` pair.
_Blog:_ Adversarial review caught this before a single send↔receive round-trip existed — the "obvious" nonce was one that the receiver literally cannot read until after it has already decrypted.
_Source:_ Stage 1 narrative + Methodology item 1; commit `92b07e8`. **Historical follow-up:** the C `#define`s and placeholder nonce were deliberately left at the old values for Stage 5; that fork is now resolved at 62/61 with a fresh 12-byte cleartext nonce (see resolved F-4).

**C-8 — CPace transcript ambiguity → IRTF-CPace `lv_cat` length-prefixing.**
_Paper:_ Bare-concatenation `SHA512(DOMAIN‖PRS‖sid‖CI)` becomes ambiguous once CI binds variable-length data, letting distinct `(PRS, CI)` pairs collide to one generator `G`; mandated IRTF-CPace `lv_cat` length-prefixing of every transcript field (and wiped leftover PRS/PIN bytes from the heap).
_Source:_ Stage 2 `cpace` + Methodology item 2; commits `b3b69b7`, `e5f6348`, `58c02a4`.

**C-9 — Hand-rolled RFC 5869 HKDF → libsodium's native HKDF-SHA512.**
_Paper:_ Swapped a hand-rolled HKDF-SHA512 in a security-critical path for libsodium's `crypto_kdf_hkdf_sha512_extract/_expand` behind identical export names/signatures (downstream cpace/x3dh/ratchet untouched), verified byte-identical against the same KAT and `node:crypto.hkdfSync` — pure downside-removal, prefer the vetted native primitive.
_Source:_ Stage 2 "Stage-1 revision"; commit `d8ae95b`.

**C-10 — Unwiped X25519 DH secret in the Stage-2 wrapper.**
_Paper:_ The X25519 shared secret and the keypair failure path were freed without `zeroFree`, leaving key material in the reused WASM heap; fixed to zero-before-free, noting that a passing agreement test proves the DH is correct but says nothing about erasure.
_Source:_ Stage 2 `x25519` + Methodology item 3; commit `26d353f`.

**C-11 — Interactive-3DH test suite blind to the initiator's own identity-key binding.**
_Paper:_ The historically named `x3dh` tests bound the peer's IK but had no negative control for the initiator's own `IK_a` — silently dropping `IK_a` from the DH mix would have kept every test green; added the missing negative test corrupting `IK_a` and asserting agreement breaks. The live protocol is an online three-DH exchange, not Signal X3DH: it has no prekey bundle.
_Source:_ Stage 2 `x3dh` + Methodology item 4; commit `b4b713d`.

**C-12 — Unbounded skipped-message-key retention (no global cap).**
_Paper:_ Only a per-decrypt `MAX_SKIP=512` bound existed on the ratchet's out-of-order skipped-key map, with no global cap (unbounded RAM and later persisted-row growth), and the plan's "capped at MAX_SKIP" comment was false; fixed with `MAX_SKIP_SESSION=2000` (evict-oldest), header integer validation (`Number.isInteger, >=0`), and an honest doc-comment.
_Source:_ Stage 2 `ratchet` + Methodology item 5(#2); commits `8bba4e9`, `d65ce73`.

**C-13 — Ratchet decrypt mutates state before AEAD authentication (replay-desync).** _(resolved at the durable caller boundary; hard)_
_Paper:_ Stage 2 found that `ratchetDecrypt` mutates its input state before the AEAD tag verifies, so a duplicate/replayed old-chain message could desynchronize a live session. The primitive retains that mutation model, but current message receive runs it on a clone, authenticates and validates the frame, persists the successor, and only then adopts it and publishes the message-key cache; a failed authentication discards and wipes the candidate. The once-deferred caller contract is now enforced by the durable receive boundary.
_Blog:_ The primitive still moves first, so production gives it a disposable copy. Only an authenticated, durably stored successor is allowed to become the live ratchet.
_Source:_ Stage 2 Methodology item 5(#1); `src/handlers/messageChunkCrypto.ts`; `src/handlers/ratchetPersist.ts`.

**C-14 — Ratchet granularity: per-chunk vs per-logical-message.**
_Paper:_ Chunks of one message are shuffled, interleaved with decoys, and may retransmit, so advancing the ratchet per chunk would make out-of-order recovery and reconciliation needlessly stateful; resolved as durable pairwise state per `(roomId, peerPublicKey)` with the DH/chain ratchet advancing **per logical message**. One message key serves all of that message's chunks, fresh random nonces disambiguate every seal/reseal, a message key is never shared across logical messages, and the bounded skipped-key map handles out-of-order/lost messages.
_Source:_ ADR-A2 "Ratchet granularity."

**C-15 — Drop the 0.9.0 per-chunk Ed25519 signature — but only _atomically_ with the ratchet.** _(hard)_
_Paper:_ The per-chunk signature (added in 0.9.0 to close C-2) costs 64 bytes plus a sign+verify per chunk; once the mandatory interactive-3DH leg proves possession of both cross-signed identity keys (with CPace additionally authenticating PIN rooms) — making the Poly1305 tag a genuine sender authenticator under the confirmed hybrid root — it becomes redundant, but dropping it _before_ the authenticated ratchet lands would be a net downgrade; resolved to drop it atomically in the same release as the ratchet, tracked as Risk R1, never phased (phased = two wire breaks).
_Blog:_ The one piece of hard-won 0.9.0 armor is scheduled for removal — but only at the exact moment its replacement (a mutually-authenticated ratchet) is load-bearing, not one commit sooner.
_Source:_ ADR-A2 "Drop the 0.9.0 per-chunk Ed25519 signature — atomically"; §5 threat-model + Risk R1; design §12.

### 1b. Handshake

**H-1 — PAKE primitive choice for PIN mode.**
_Paper:_ Rejected literal ICAO-9303 PACE (drags ASN.1/APDU/Brainpool/EAC baggage libsodium doesn't expose) and SPAKE2+/OPAQUE (asymmetric client-server aPAKEs, mismatched to p2party's symmetric peer shape); chose **CPace over Ristretto255** (UC-proven, offline-dictionary-resistant, forward-secret, quantum-annoying, prime-order-clean, setup-free, symmetric).
_Source:_ ADR-A2; §8 prior-art positioning.

**H-2 — PACE + Double Ratchet: separate deferred-PAKE phase vs merged handshake/ratchet as SSOT.**
_Paper:_ The original decision rejected a separate PAKE-less stepping-stone ratchet and merged CPace with the v3 handshake/ratchet source of truth. The implemented exact-profile family refined that branch model: interactive 3DH and the room-selected ML-KEM-512/768/1024 profile feed every bootstrap root, PIN policy additionally feeds CPace, and all application messaging uses the same ratchet construction from the first logical message. Each room authenticates one profile with no negotiation or fallback. The old opaque-token “Phase 1” is superseded by D5's separately scoped L1/L2 rendezvous research.
_Source:_ ADR-A2 spec `91fd123`; plan `9f8acc3`.

**H-3 — Capability negotiation rejected in favor of a binary version tag with fail-closed reject.**
_Paper:_ Rejected per-peer capability negotiation with best-effort downgrade to an "unverified" mode; chose a minimal `protocolVersion` tag with strict equality against `PROTOCOL_VERSION = 3` (`isProtocolVersionCompatible`), no fallback (missing field = pre-v3 = rejected). The canonical room policy selects `authMode=pin|nopin`; it does not negotiate a second cipher suite.
_Source:_ design §2 pt 3, §7; plan Stage 6 Task 1 (`protocolVersion.ts`), Task 2 (`selectHandshakeMode`).

**H-4 — Atomic v3 wire break — no v2↔v3 interoperability.**
_Paper:_ Considered a capability-detect/downgrade interop path to the old per-chunk-signature scheme; chose a clean, non-interoperable break (`0.9.2 → 0.10.0`), old v2 rooms/data kept separate — the same reason R1's signature-drop must ship atomically.
_Source:_ design §2 pt 4, §3, §15, §12 R1; plan Global Constraints; Stage 7 CHANGELOG draft.

**H-5 — Throttling online PIN-guessing: durable stable-identity backoff plus a soft room aggregate.**
_Paper:_ CPace defeats offline dictionary attacks but an active signaling adversary still gets online guesses. Current v3 gives each stable Ed25519 peer identity three free failures for a room, then applies 500-ms exponential backoff capped at five minutes, persisted by `(roomId, peerIdentityEd25519)`. Success clears that identity's state. To make cheap identity rotation non-free without letting one peer hard-lock every honest member, an additional in-tab room aggregate softly throttles after 30 failures in a five-minute window. Both controls are backoff/window throttles, not permanent locks.
_Source:_ `src/roomPinAttempts.ts`; `src/db/types.ts`; `src/db/db.worker.ts`; `src/handlers/handleOpenChannel.ts`.

**H-6 — DTLS remote-certificate verify failed OPEN when the live cert stat was unverifiable.** _(review-driven fix; hard)_
_Paper:_ `verifyDtlsFingerprints` guarded with `if (liveRemoteFp !== null && liveRemoteFp !== remoteSdpFp) throw` — but `certificateFingerprint` legitimately returns `null` (missing transport stat / absent `remoteCertificateId` / no matching cert stat), and `null` short-circuited the `&&` so an _unverifiable_ MITM tripwire silently passed; rewritten to fail closed on both branches (`if (liveLocalFp === null || liveLocalFp !== localSdpFp) throw`, and symmetric for remote), with a regression test asserting rejection.
_Blog:_ The tripwire that was supposed to catch a man-in-the-middle would wave one through whenever it couldn't read the certificate at all — caught as CRITICAL in Stage-4 review and made to treat "can't verify" identically to "mismatch," the canonical fail-open→fail-closed correction.
_Source:_ introduced `445aaea`, fixed `2af322b` (re-reviewed APPROVED); `.superpowers/sdd/task-s4t3-report.md`; `src/handlers/handleHandshake.ts`.

**H-7 — Key-confirmation R2 ordering: verify-then-send deadlocks on a wrong PIN.** _(review-driven fix)_
_Paper:_ The brief's flow had the initiator verify the responder's `mac_R` before sending its own `mac_I`, so a wrong PIN aborted the initiator before `mac_I` was ever sent and the responder's `recv()` blocked forever; fixed by sending `CONFIRM{0, mac_I}` (needs only transcript `T`, not ratchet state) _before_ verifying `mac_R`, so both legs reject independently, while `initRatchet` still runs only after `mac_R` verifies (a failed handshake yields no usable initiator ratchet).
_Source:_ commit `c835244`; `.superpowers/sdd/task-s4t4-report.md` deviation #6.

**H-8 — `getStats()` certificate lookup: the brief's `stats.get(id)` fallback doesn't typecheck.** _(review-driven fix)_
_Paper:_ The project's TS DOM lib declares `RTCStatsReport` with only `forEach` (no `.get()`), so the brief's `stats.get(id) as any` fallback fails to typecheck; re-derived the same matching using `forEach`'s own key argument (each report's id per webrtc-stats), keeping `report.id` as a secondary check, typed with a local `RTCStatEntry`.
_Source:_ commit `445aaea`; `.superpowers/sdd/task-s4t3-report.md` deviation #2.

**H-9 — `buildChannelInput`: reusing the async `concatUint8Arrays` under a synchronous interface.** _(review-driven fix)_
_Paper:_ The brief implemented `buildChannelInput` via the codebase's async `concatUint8Arrays` (`Promise<Uint8Array>`), but the interface + test require a synchronous `Uint8Array`; kept the synchronous signature as source of truth and wrote a small local synchronous byte-concat.
_Source:_ commit `445aaea`; `.superpowers/sdd/task-s4t3-report.md` deviation #1.

**H-10 — HELLO/CONFIRM frame validation: tag-byte check without an exact-length check.** _(review-driven fix)_
_Paper:_ The brief validated only the leading type-tag byte before parsing HELLO/CONFIRM, so a short/truncated frame with a valid tag would parse via out-of-range slices; added exact `HELLO_LEN`/`CONFIRM_LEN` checks so any malformed inbound handshake frame throws (which `runHandshake`'s single catch turns into a gate rejection).
_Source:_ commit `c835244`; `.superpowers/sdd/task-s4t4-report.md` deviation #7.

### 1c. Transport / framing

**T-1 — Low data-channel buffer watermark spilling metadata to the relay.**
_Paper:_ In v2, `MAX_BUFFERED_AMOUNT` was 2 frames (131072 B), so ordinary send congestion immediately spilled full 64-KiB frames through the signaling-relay path (handing it sender/receiver identity, size, timing, and the plaintext root label); raising it to 16 frames kept ordinary traffic P2P. Current protocol-v3 removes WebSocket payload fallback entirely and relies on authenticated reconnect/reconcile for availability.
_Source:_ finding #9; commit `c584ed0`.

**T-2 — Read-receipt count leaking the real-vs-decoy split.**
_Paper:_ Protocol-v2 receipts were emitted only for accepted REAL chunks, so a DTLS-record observer could count the 64-byte reverse records to recover the real chunk count and defeat decoy padding. V2 resolved this by emitting one 64-byte true-or-random token for every forward frame. Current v3 retains that count property but wraps the token in an exact 65-byte typed frame, `FRAME_TYPE_RECEIPT(1) ‖ token(64)`, and rejects raw 64-byte frames. A valid token is `SHA-512(receipt_domain ‖ merkleRoot ‖ u64(chunkIndex) ‖ leafHash)`; the v18 sender resolves by root and additionally requires the stored chunk's random `transferId` to match the active send.
_Source:_ finding #10; commit `6016862`.

**T-3 — `close()` before drain wipes still-buffered send data.**
_Paper:_ `RTCDataChannel.close()` discards the SCTP send buffer, so `send(messageHash)` immediately followed by `close()` could wipe the just-queued finished-message receipt; resolved with `drainAndClose()` — poll `bufferedAmount` to 0, bounded by a timeout so a stalled channel can't hang teardown, then close.
_Source:_ finding #11 / ADR-R5; commit `b5ebe2f`.

**T-4 — Channel `onclose` destroying the resend source on any disconnect.**
_Paper:_ The per-message channel's `onclose` deleted the sender's `newChunks` on _any_ close (including a mid-transfer disconnect), destroying the resend source and stalling the receiver near completion (and leaking an abandoned send's body into IndexedDB); gated deletion on an explicit race-free `transferComplete` flag set only by the completion path, with terminal cleanup after all peers settle.
_Source:_ finding #12; commit `69568e0`.

**T-5 — Reliability layer: incremental patches vs one spec-first subsystem.** _(process)_
_Paper:_ Two incremental prototypes (a fixed-cadence receipt scheduler and a resend-all retransmit) each hit subtle races and were reverted, proving the pieces couldn't be built independently; resolved by designing the whole transfer layer spec-first as **one** subsystem against four explicit objectives (no double-store; sender sends all needed chunks; no close before verified; receipts leak nothing about content/size) plus resume-on-reconnect and telemetry.
_Blog:_ Two honest attempts to patch reliability one race at a time both had to be rolled back — the lesson the log records is that this was a subsystem, not a set of independent patches.
_Source:_ ADR-R1; spec `2026-07-20-reliable-transfer-resume-telemetry-design.md`, commit `927c4ac`.

**T-6 — Have-set representation: new wire/bitfield vs reusing receipts.**
_Paper:_ Considered a new bitfield/`totalChunks` wire field + store to track which chunks the receiver has; chose to keep receipts as the have-set (KISS/DRY/SSOT). In current v3 the 64-byte token is not a raw leaf hash: it binds root, index, and leaf; lookup is by `(merkleRoot, receiptToken)`; and the returned staging row must match the active v18 `transferId` before its `chunkIndex` enters the disposable in-memory ack set. Worker storage is the durability boundary: only a successful durable insert/dedup result can emit the true token. A storage exception wipes the token/plaintext copy and produces the same decoy/drop result as a cryptographic failure.
_Source:_ ADR-R2; commit `7187836`.

**T-7 — Retransmit vs resume: separate mechanisms or one reconcile path.**
_Paper:_ Considered building retransmit-on-timeout and resume-on-reconnect as two code paths; chose a single `reconcile()` with two triggers (live timeout, or reconnect + receipt replay), selective resend only via `sendChunks(onlyIndices)`, decoys never resent (cover, never acked), bounded by `MAX_RETRANSMITS` with linear backoff.
_Source:_ ADR-R3; commit `9d29fe9`.

**T-8 — Opaque channel IDs vs plaintext Merkle-root label in the data-channel name.** _(Deferred)_
_Paper:_ The WebRTC data-channel label carries the Merkle root in plaintext, letting a relay/signaling observer link a message's chunks and fan-out to peers; **deferred** into the ratchet's session/key-id redesign rather than solved standalone, because opaque IDs now would conflict with the 0.9.0 chunk-auth transcript (which signs the root as read pre-decryption from the label).
_Source:_ ADR-T4, finding #9, §6 weakness item 3.

**T-9 — `serializeRatchet` returns `ArrayBuffer` fields, not `Uint8Array`.** _(review-driven fix; persistence-adjacent)_
_Paper:_ The brief accessed `s.rootKey.buffer` and spread `[...(sA.dhRemotePub as Uint8Array)]`, but `RatchetSessionSecrets` fields are plain `ArrayBuffer` (no `.buffer`, doesn't iterate bytes on spread); passed the `ArrayBuffer` values directly to `wrapSecret` and fixed the test's spread to `[...new Uint8Array(sA.dhRemotePub as ArrayBuffer)]`.
_Source:_ commit `c835244`; `.superpowers/sdd/task-s4t4-report.md` consumed-signature deviation #2.

**T-10 — Transfer identity and immediate cancellation: content hash → random v18 `transferId`.**
_Paper:_ Identical concurrent sends cannot safely share cancellation, staging, progress, or reconciliation state. Database v18 therefore recreates only the transient `newChunks` store with key `['transferId','chunkIndex']`, where `transferId` is a fresh random 32-byte value returned synchronously with the send handle. Hash/root cancellation remains compatibility syntax but fails when ambiguous. In immediate mode, closing only the per-message DataChannel while the same authenticated room/peer RTCPeerConnection remains connected is the peer-cancel signal; a dead/replaced transport remains eligible for resume and receives a fresh ratchet step. Scheduled cover is not implemented, so its explicit encrypted `CANCEL` control record remains future D3 work.
_Source:_ `src/index.ts`; `src/handlers/transferAbort.ts`; `src/handlers/handleSendMessage.ts`; `src/db/src/getDB.ts`.

### 1d. Persistence

**P-1 — Persist ratchet state across page refresh without leaking secrets at rest.**
_Paper:_ A refresh discards the live ratchet (collapsing forward-secrecy continuity), but plaintext IndexedDB persistence would hand a DB dump every root/chain key the ratchet rotates away; resolved with an additive `ratchetSessions` store (dbVersion 16→17) keyed by `(roomId, peerPublicKey)`, secret fields wrapped under a single non-extractable WebCrypto AES-GCM key (fresh 12-byte IV per wrap), public/counter fields left cleartext so the non-unique indexes stay queryable without decrypting.
_Source:_ Stage 3; commits `5bedc9b`, `7ec1776`, `fe4f159`, `1da2c27`, `4da1719`.

**P-2 — Cross-tab race creating the wrap key on first run.**
_Paper:_ Two tabs racing to create the AES-GCM wrap key could each persist a different key; `getWrapKey()` uses double-checked locking (cheap read → speculative `generateKey` outside any txn → authoritative re-check inside a `readwrite` txn on `meta` before `put`), and IndexedDB serializing `readwrite` txns across connections makes the re-check a real mutex — the race was already structurally closed, with only a rare-re-handshake liveness note and a doc-wording polish remaining.
_Source:_ Stage 3 "a race found already closed."

**P-3 — Non-extractable WebCrypto wrap key: how much protection it actually buys.**
_Paper:_ `extractable:false` defeats raw-key exfiltration and cross-device copy (`exportKey('raw', …)` refuses) but **not** an attacker who already holds device+origin (in-origin XSS can still invoke `decrypt` via the handle) — documented honestly rather than overclaimed; real-browser structured-clone survival deferred to the Stage-7 E2E pass.
_Source:_ Stage 3 "The at-rest wrap."

**P-4 — At-rest ratchet-secret wrapping: non-extractable WebCrypto key now vs passphrase-derived KEK later.** _(Deferred alternative)_
_Paper:_ Chose the non-extractable WebCrypto key for v3 because it survives refresh silently; the stronger **passphrase-KEK** at-rest is explicitly named and **deferred** (not rejected) precisely because it trades away the "survives refresh without re-entry" property.
_Source:_ design §8, §15, §12 R3(a); plan Stage 3 (`ratchetWrap.ts`).

**P-5 — Resume across a full peer reconnect: registry + re-derive vs keep-state-alive.**
_Paper:_ The original reliability slice kept `sendWithReconcile` alive and re-opened the same Merkle-root-labelled channel, with the receiver persisting each leaf for receipt replay. Protocol-v3 tightens the transport boundary: reopening on the same authenticated RTCPeerConnection may retain the message key/header, but a replacement connection has a fresh hybrid root and must wait for its leased gate, advance its own ratchet, wipe the old message key, and reseal missing plaintext chunks. Receipt replay derives the current root/index/leaf token; v18 transfer identity keeps concurrent equal sends separate.
_Source:_ ADR-R7; commit `69568e0` (historical step 3); `src/handlers/handleSendMessage.ts`; `src/handlers/handleOpenChannel.ts`.

**P-6 — Large-file handling: whole-file-in-RAM vs streaming to OPFS.**
_Paper:_ The two whole-file-in-RAM spots (send-side message hash, receive-side reassembly Blob) blocked GB+ files; resolved by streaming both — a JS-callable incremental SHA-512 WASM export fed ~1 MiB at a time on send, and `assembleToOPFS` writing each chunk's slice to its file offset via a worker-only `createSyncAccessHandle` on receive; eventually (0.9.2) received chunks are written straight to OPFS at their offsets as they arrive, dropping the reassembly pass entirely.
_Source:_ ADR-S1/S2/S3/S4/S6; commits `c360cd6` (superseded), `772635f`, `44867ca`, `0357713`, `562fbcc`.

**P-7 — OPFS reassembly API: `showSaveFilePicker` vs worker sync-access-handle.**
_Paper:_ Safari has no main-thread `createWritable()`, so `showSaveFilePicker` is Chromium-only; chose OPFS via a worker-only `createSyncAccessHandle` for cross-browser coverage (Chrome/Edge 86+, Firefox 111+, Safari 15.2/16.4+) and the fastest path (no structured-clone tax).
_Source:_ ADR-S4; commit `0357713`.

**P-8 — `readMessage` materializing large files on every render.**
_Paper:_ A frontend audit found `readMessage` on the render path, so previews/file bubbles materialized huge files every render; added a `materialize` arg (default `true`) whose `false` mode returns metadata only for a completed FILE without reassembling — backward-compatible.
_Source:_ ADR-S5; commit `8e57593`.

**P-9 — Concurrent `readMessage` assembles collide → silent whole-file-in-RAM fallback.**
_Paper:_ An overlapping/poll-style `readMessage` opened a second exclusive OPFS sync handle, collided, and silently fell back to an in-memory Blob — reintroducing the exact OOM the streaming rewrite removed; coalesced concurrent assembles per `merkleRoot` via an in-flight-promise Map, with an idempotency guard, removal on delete/wipe, partial-file cleanup, and always-close handles even on mid-stream error.
_Source:_ finding #13; commit `0357713`.

**P-10 — Receive-time OPFS write: dedup TOCTOU + `uniformSize` double-count.**
_Paper:_ Writing received chunks straight to OPFS introduced a `count()→add()` dedup TOCTOU and a shared-entry double-count that could lock the learned `uniformSize` to the short final chunk when the same file arrived from two peers, plus durability-before-have-set-commit and open-handle leaks; resolved by serializing all receive-file ops per `merkleRoot` in the worker, `flush()`-ing each chunk before committing its have-set record (so a bytesless record always implies durable bytes), capping open handles (evict-oldest), running delete's close+removeEntry under the per-`merkleRoot` lock, and awaiting in-flight opens before a full DB wipe.
_Source:_ finding #14; commit `562fbcc`.

### 1e. Process / methodology

**M-1 — Adversarial two-stage review adopted as a required gate, not a courtesy pass.**
_Paper:_ Considered gating security-critical crypto/ratchet code solely on a green KAT/unit suite; adopted instead a mandatory two-stage (spec-compliance then code-quality) adversarial subagent review per task — which across Stages 1–3 caught 5 genuine issues a green suite would not surface (C-7 unrealizable nonce, C-8 CPace transcript ambiguity, C-10 unwiped DH secret, C-11 X3DH blind spot, C-12/C-13 ratchet skipped-key/replay) and separately confirmed P-2 was already safely closed.
_Blog:_ The through-line of this whole rewrite is a methodology: tests prove the code does what it asserts, and a dedicated adversary is what proves the assertions were the right ones.
_Source:_ Methodology sections across Stages 1–3.

**M-2 — `ratchetGate` brief test asserted a tautology that fails strict typecheck (TS2801).** _(review-driven fix)_
_Paper:_ The historical peer-only brief's memoization assertion reduced to `not.toBe(null)` and tested nothing; it was replaced with a real identity/reset assertion. The current registry is keyed by `(roomId, peerId)` and `resetRatchetGate` returns an opaque ownership lease, so equivalent peer IDs in different rooms and a replaced transport's stale completion cannot share or settle one another's gate.
_Source:_ commit `b21fe78`; `.superpowers/sdd/task-s4t2-report.md` §4.

**M-3 — `rejectRatchetGate` on a never-awaited peer fires an unhandled-rejection event.** _(review-driven fix)_
_Paper:_ Rejecting a lazily-minted promise with zero listeners fires the runtime's unhandled-rejection event even though a later consumer still receives the error; added a synchronous no-op `promise.catch(() => {})` at construction inside `ensure()`, with a regression test crossing two macrotask boundaries.
_Source:_ commit `4b98c62` (re-reviewed APPROVED); `.superpowers/sdd/task-s4t2-report.md`.

**M-4 — Reconnect ownership: registries need leases, not just composite keys.**
_Paper:_ Room/peer keys stop cross-room collision but do not stop late async completion from an old transport overwriting its replacement at the same key. Current v3 gives each ratchet gate a `RatchetGateLease` and each main-channel handshake inbox a `HandshakeLease`; open/reject/deliver/clear paths validate the captured lease. Persistence separately serializes the stable `(roomId, peerPublicKey)` edge and invalidates an old connection's owner token before the replacement seed lands.
_Source:_ `src/handlers/ratchetGate.ts`; `src/handlers/handleHandshake.ts`; `src/handlers/ratchetPersist.ts`.

### 1f. Signaling

**S-1 — SDP/ICE glare race breaking peer establishment.**
_Paper:_ Concurrent SDP/ICE signaling for the same transport interleaved at `await` points, leaving `epc.signalingState` stale and `setRemoteDescription` in the wrong state ("Called in wrong state: stable"). The original peer-only mutex fixed the immediate race; the current registry is room-scoped (`(roomId, peerId)`), with a second `(roomId, stable Ed25519 identity)` lock preventing aliases from concurrently claiming one durable edge. Terminal release waits for the active critical section to drain before deleting the mutex.
_Source:_ finding #7; commit `c5386611`.

### 1g. Scope / capability

**Sc-1 — Tier 1 (pure-TS) vs Tier 2 (C/WASM) split for crypto hardening.**
_Paper:_ Because `wasmLoader.ts` fetches `libcrypto.wasm` from a CDN under a hardcoded sha384 SRI, any WASM/wire change needs a CDN redeploy + SRI bump before it can reach the running app; split the hardening batch into Tier 1 (pure-TS, no wire change, testable against the existing CDN wasm, independently shippable) and Tier 2 (C/WASM, wire-breaking, versioned protocol-v2).
_Source:_ ADR-M2; design commit `91d5955`; specs `2026-07-20-crypto-hardening-tier1-design.md`, `…-tier2-protocol-v2-design.md`.

---

## 2. DECIDED — the two hard handshake calls (maintainer, 2026-07-22)

> These were the two genuinely-open decisions of the v3 handshake, escalated to the design owner in `.superpowers/sdd/progress.md` ("ESCALATIONS to design owner") and analyzed in the companion rigor memo (`scratchpad/handshake-rigor-memo.md`, workflow `wf_a20541e8-a93`). Both were **DECIDED** on 2026-07-22. At the historical `c835244` Stage-4 checkpoint, the code had implemented neither final choice: it fed an empty CPace generator `sid` and passed Ed25519 bytes toward X25519. The current implementation instead feeds the initiator-random `sid` and uses a separately generated, wrapped, cross-signed X25519 identity. The paragraph is retained to explain why D1/D2 required implementation rather than a documentation-only ruling.

### D1 — DECIDED: initiator-random `sid` (fill the existing single-round HELLO field)

_Paper:_ Protocol-v3's single-flight CPace/Ristretto255 PIN handshake binds each session with a **fresh initiator-chosen `sid`** — 16–32 bytes from `crypto.getRandomValues` placed in the HELLO `sid` field the frame already carries — fed into the generator `G` and the key-confirmation transcript `T`. This is on-spec (the CFRG CPace draft's guidance for exactly this initiator/responder single-flight topology) and adds **zero round trips**. The channel-input `CI = channelId‖IK_a‖IK_b‖fp_a‖fp_b‖PQ_TAG` (the DTLS fingerprints) is retained as an **independent second binding layer**, with a runtime assertion that no `RTCCertificate` is cached or reused across sessions; the **human PIN inside CPace remains the real MITM anchor**, CI documented as defense-in-depth against signaling bugs, not as the primary MITM defense.

**Chosen: Option 2 (initiator-random `sid`).** Options weighed (from the rigor memo):

| Option                                                                             | Verdict           | Why                                                                                                                                                                                                                                                                                                                                                                                                      |
| ---------------------------------------------------------------------------------- | ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **1. Empty `sid` + CI(DTLS-fp) + fresh-cert guard** _(shipped `c835244` behavior)_ | Rejected          | Adequate under a fresh-cert invariant but **not provably ideal** — it forfeits the UC-composability guarantee the cited proof [AHH21] ties to `sid` uniqueness (CPace draft §10.9), and rests on p2party's own unblessed inference that "CI does `sid`'s freshness job." Freshness becomes a silent operational invariant (never reuse `RTCCertificate`), not a cryptographic one.                       |
| **2. Initiator-random `sid` in the existing HELLO** ⭐                             | **DECIDED**       | Literally the draft's prescribed fix for this exact single-flight topology, at **zero extra RTT** — the HELLO field already exists and the code already fills a random `sidSelf` (it just wasn't feeding the generator). Restores the `sid`-uniqueness assumption the UC proof needs. The "mutual contribution needs 2 messages" belief was a conflation of _mutual contribution_ with mere _freshness_. |
| **2b. Full 2-message mutual `sid`**                                                | Rejected (cost)   | Strictly stronger against a _biased-but-not-colluding initiator RNG_, but costs a structural extra round trip (G must be fixed before either Y), and Option 2 already closes the standards gap for free. Escalation path only if the initiator's own RNG is distrusted.                                                                                                                                  |
| **3. DTLS/TLS-exporter binding (RFC 9266)**                                        | Deferred → FUTURE | Theoretically the **strongest** value — derived from the live handshake's fresh secrets, immune to the cert-reuse / triple-handshake failure class — but **no browser JS surfaces a general-purpose DTLS exporter** (`RTCDtlsTransport`/webrtc-stats expose none). A pure API-surface gap, tracked as **F-8**, to adopt the day a browser exposes it.                                                    |

_Rationale:_ Fill the `sid` because it is the on-spec, free move that takes the design from "sanctioned degenerate mode" to inside the letter of the cited proof; keep CI as belt-and-suspenders against signaling-layer bugs; name the PIN as the MITM defense (matching RFC 8827's SAS/IdP requirement and MLS's don't-trust-the-transport posture). The cert-fingerprint reuse concern is the **same class** as the historical `tls-unique` / triple-handshake failures — a static/reusable artifact standing in for a fresh-secret binding — **not literally that failure**; the fresh-`sid` + fresh-cert invariant plus the PIN is what neutralizes it in-browser today.
_Standards:_ CPace draft §3.1 (initiator chooses a fresh random `sid`, ≥8 bytes; use 16+) and §10.9 (`sid` SHOULD NOT be reused — UC composability depends on it); RFC 9266 (channel binding to fresh handshake secrets; the corrected successor to fingerprint/`Finished`-based binding, parked as F-8); RFC 8827 (WebRTC Security Architecture: assume signaling is adversarial, require SAS/IdP).
_Blog:_ The handshake's own author shipped empty-`sid` and, to his credit, flagged it as a Concern rather than a silent choice; a rigor pass then showed the "fix" rested on conflating _mutual contribution_ with mere _freshness_ — and that a fresh unilateral `sid`, on-spec and free, was already sitting in a HELLO field the code fills but doesn't yet read. The decision took the free fix, kept the belt-and-suspenders, and held a slot (F-8) for the binding that browsers won't yet expose.
_Source:_ design spec `…v3-design.md` lines 117–123; `.superpowers/sdd/task-s4t4-report.md` deviation #5 / Concern #2; `.superpowers/sdd/progress.md` (escalation, now resolved); `scratchpad/handshake-rigor-memo.md` §D1; historical `c835244` flow; current `src/handlers/handshakeCore.ts`; `docs/paper-prior-art-and-related-work.md` line 342 (RFC 9266 nearest prior art).

### D2 — DECIDED: Option B, dedicated X25519 identity key + codebase-wide key separation

_Paper:_ The identity-mixed interactive-3DH calculation `secret = HKDF(DH(IK_a,EK_b)‖DH(EK_a,IK_b)‖DH(EK_a,EK_b))` runs over a **dedicated, separately-generated X25519 identity key**, never the Ed25519 signing key. Its helper/file was historically named `x3dh`, but current v3 runs an online three-DH exchange in every room and lets PIN policy add CPace; it is not Signal X3DH because there are no asynchronous prekeys. The Ed25519 identity key stays the sole signing/identity anchor and **cross-signs** the X25519 key so it inherits identity authentication. This is the textbook key-separation choice and is PQ-forward — the mandatory ML-KEM key is separately generated too.

**Chosen: Option B (dedicated X25519 key + key separation).** Options weighed (from the rigor memo):

| Option                                                                                                                     | Verdict                 | Why                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| -------------------------------------------------------------------------------------------------------------------------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **A. Convert Ed25519 IK → X25519** (`crypto_sign_ed25519_sk/pk_to_curve25519`) _(the spec's original passing-clause plan)_ | Rejected                | Smallest delta and settled birational math, but reuses a signing key for DH with **no joint-security proof** for bare Ed25519-sign ∥ X25519-DH; the only precedent (XEdDSA §8) explicitly declines to certify it — and p2party's plan is a _weaker_ variant than XEdDSA (no sign-bit discipline, no randomized-nonce construction). Plus a documented silent-truncation footgun (`sk_to_curve25519` reads only the first 32 of the packed 64-byte secret), a signing/DH lifecycle conflict, and a PQ dead-end. |
| **B. Dedicated separate X25519 identity key** ⭐                                                                           | **DECIDED**             | Removes the entire unanalyzed cross-protocol-reuse class; matches NIST SP 800-57 §5.2, libsodium's FAQ ("always safer"), Noise §14, and MLS/RFC 9420's separate `signature_key`/`encryption_key`. Independent lifecycle, PQ-forward, tiny cost (one 32-byte pubkey in a CI that already carries an IK, two fingerprints, and a PQ tag). Cross-sign or same-seed-derive for UX.                                                                                                                                 |
| **C. Defer no-PIN; ship PIN-only**                                                                                         | Acceptable interim only | Zero D2 crypto risk now (CPace never touches the identity keys); a legitimate product-scope call — _provided_ the eventual no-PIN path lands on B, **never** A as a "temporary" measure.                                                                                                                                                                                                                                                                                                                       |

_Historical precedent and migration plan:_ protocol-v2's `chacha20poly1305` box scheme converted the Ed25519 identity to X25519, reusing one key for signing and DH. The first D2 plan proposed deprecating that box in place while retaining legacy decrypt. Current v3 completed the migration instead: the box/conversion surface is removed from `src`/WASM exports, and both auth policies consume the dedicated X25519 identity; no Ed25519→X25519 conversion export was added.
_Rationale + honest caveat:_ This is risk-aversion + PQ-forwardness, **not a demonstrated break** — there is **no published attack** on Ed25519/X25519 reuse specifically (unlike the RSA/EMV case in Degabriele et al.). The reasoning is "no one has proven the exact scheme-pair jointly secure, the field default is separation, and the PQ KEM key forces separation anyway," not "a forgery is imminent."
_Standards:_ XEdDSA §8 (reuse for sign + certain DH is "a complicated topic requiring careful analysis… outside the scope"); NIST SP 800-57 Pt.1 Rev.5 §5.2 ("a single key shall be used for only one purpose"); libsodium FAQ (prefer distinct keypairs; PQ sig/KEM keys are incompatible types); Noise §14 (reusing a static key outside its protocol "would require extremely careful analysis"); MLS/RFC 9420 (structurally separate `signature_key` / `encryption_key`; Signal's PQXDH likewise added a _separate_ KEM key).
_Implementation shape (current correction):_ the dedicated X25519 identity is generated independently, wrapped in IndexedDB, and cross-signed by Ed25519; its public key and cross-signature travel in-band and are verified before interactive 3DH. `performHandshakeCore` always runs that three-DH leg, while the PIN branch additionally runs CPace. This supersedes both the old `c835244` flow that fed a 64-byte Ed25519 secret into a 32-byte X25519 slot and the intermediate plan that left the PIN branch untouched.
_Blog:_ The spec committed, in a single passing clause, to converting the one identity key p2party already has — and implementation then discovered the conversion primitive was never even exported, and the wired data flow was feeding a 64-byte Ed25519 secret into a 32-byte X25519 slot. The gap between "what one line of the design decided" and "what a safe implementation requires" _was_ the dilemma; the decision resolves it by separating the keys — and, in doing so, migrating p2party off the very same one-key-for-both reuse its shipped `chacha20poly1305` box scheme has quietly relied on all along.
_Source:_ design spec `…v3-design.md` line 108, §9 (no conversion primitive listed); `.superpowers/sdd/task-s4t4-report.md` Concern #1; `.superpowers/sdd/progress.md` (escalation, now resolved); `scratchpad/handshake-rigor-memo.md` §D2; historical `handleHandshake.ts`/box implementation; current `src/handlers/handshakeCore.ts`, `src/cryptography/x3dh.ts`, and `src/cryptography/x25519.ts`.

### D3 — DECIDED: message-scoped DataChannels with a room-wide immediate/cover policy

**Status:** Architecture accepted 2026-07-23. Immediate-mode authenticated channel-close cancellation is implemented; the scheduler, encrypted cover-mode `CANCEL`, and packet-trace validation are not implemented.

**Context and decision drivers:** One WebRTC DataChannel per logical message is useful product machinery, not accidental plumbing: each transfer gets an isolated lifecycle, backpressure budget, progress state, retry boundary, and cancel handle. Replacing it with one permanent multiplexed channel would throw those boundaries away. Opening a channel only when a person sends, however, exposes message timing; closing it immediately on cancel or completion exposes those events too.

**Decision:** Keep one ephemeral DataChannel per real message. The transport-privacy setting is a **room-wide policy**, with **immediate / no cover as the default**. A cover-enabled room fixes its cadence, lane count `C`, frames per cell `F`, and file-duration classes independently of activity. Every peer-to-peer edge derives the same epoch origin from its authenticated handshake and provisions the configured direction-specific, neutrally-labelled message lanes whether users are idle or active. A queued real message replaces one dummy lane; otherwise the lane carries cover. Each lane sends exactly `F` fixed 65,490-byte application frames at fixed offsets and one exact 65-byte tagged true-or-random receipt frame (`type(1) ‖ token(64)`) per forward frame, then follows its declared close boundary. Excess messages wait for a later epoch. The initiator/responder role supplies a stable tie-break so both sides agree who opens each lane. WebSocket payload fallback is forbidden in cover mode because it would reveal the event to the signaling server.

The signaling service may distribute the room policy but is not trusted to select it. A canonical policy descriptor and version are bound into the authenticated handshake transcript and key confirmation. A mismatch fails closed for a cover room; it must never silently fall back to immediate mode. A room-policy change is a versioned, all-peer transition at an agreed future epoch boundary, with the old schedule continuing until the transition commits. It is never triggered by typing, a queued message, or a file attachment.

Cancellation is immediate in the local UI. In the implemented immediate mode, closing only the message-scoped DataChannel while the same authenticated room/peer transport remains connected is interpreted as peer cancellation; a failed/replaced peer connection instead enters resume. The future privacy mode must **not** close early: before admission cancellation removes the intent and leaves the lane dummy; after admission an encrypted `CANCEL` replaces the next scheduled payload, remaining slots become cover, and the lane closes only at its scheduled boundary.

Large messages require a room-declared duration/capacity class (for example 1, 4, or 16 epochs) or another fixed schedule. Otherwise a longer-lived channel reveals a size bucket. The exact cadence, `C`, `F`, offsets, lifetime classes, congestion behavior, and suspension policy remain evaluation parameters, not paper constants.

_Paper:_ We preserve message-scoped RTCDataChannels as per-transfer isolation boundaries and make scheduled cover an authenticated room policy rather than an always-on product default. In a cover room, a real transfer or authenticated ML-KEM control step substitutes for bytes that the schedule would have sent as cover; therefore its **marginal observer-visible application-frame and byte cost is zero relative to that configured schedule**, not zero bandwidth in absolute terms. The protected observation is real-versus-cover activity, bounded size, and cancel/complete timing on an already-established WebRTC/DTLS association. Immediate rooms make no traffic-analysis claim. Cover excludes peer IPs, association existence, room membership, endpoint compromise, global correlation, browser suspension, congestion/loss artifacts, and leakage from duration classes. Because WebRTC fragments application frames, the result is a hypothesis until TURN/on-path packet captures show that the scheduled application calls yield the intended observable trace.

_Blog:_ Immediate delivery stays the default. When a room turns cover on, picture a tiny encrypted train that leaves on the room's timetable even when nobody is travelling. An idle train carries convincing junk. A real message takes the seat the junk was going to occupy, so the watcher still sees one train. Canceling kicks the message off inside the tunnel, but the train keeps its timetable and arrives full of junk. We keep a separate train for each transfer because cancellation, progress, retries, and cleanup stay wonderfully local. Privacy here is bought with a room-wide timetable, not a per-message incognito button or a magic compression trick.

**Cadence trade-off (`C=1, F=1`):**

| Cadence                        | Mean / maximum admission wait | Scheduled payload per endpoint outbound / across pair per day | Approx. channel opens across pair per day | Pros                                                                                                                                          | Cons / intended use                                                                             |
| ------------------------------ | ----------------------------: | ------------------------------------------------------------: | ----------------------------------------: | --------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| **No cover (product default)** |     **immediate / immediate** |                                                    **0 idle** |                        activity-dependent | Native chat UX; no idle battery, bandwidth, or TURN bill.                                                                                     | Send, completion, and cancellation timing are visible; no real-versus-cover claim.              |
| 10 s                           |                    5 s / 10 s |                                           565.8 MB / 1.132 GB |                                    17,280 | Best listed cover UX for a foreground chat room; remote cancel and PQ control are bounded to ten seconds.                                     | High battery/TURN cost and extreme DataChannel churn; 1.132 GB/day is for only one pair.        |
| 15 s                           |                  7.5 s / 15 s |                                           377.2 MB / 754.4 MB |                                    11,520 | Feels close to live chat; fastest scheduled cancel delivery and PQ healing opportunity.                                                       | Severe mobile/TURN cost and DataChannel churn; foreground high-assurance mode only.             |
| 30 s                           |                   15 s / 30 s |                                           188.6 MB / 377.2 MB |                                     5,760 | Conversational delay remains tolerable; halves the 15-second cost.                                                                            | Still expensive for an idle pair and demanding on browser stream-reset behavior.                |
| 60 s                           |                   30 s / 60 s |                                            94.3 MB / 188.6 MB |                                     2,880 | Balanced lower-data cover; cancellation remains locally instant and remotely bounded to one minute; five times faster than five-minute cells. | A minute feels broken for ordinary chat; still too expensive for casual always-on mobile cover. |
| 2 min                          |                 1 min / 2 min |                                             47.2 MB / 94.3 MB |                                     1,440 | Half the chosen bandwidth and channel churn; plausible for asynchronous rooms.                                                                | Noticeable conversational stalls; cancel/PQ control can wait two minutes.                       |
| 5 min                          |               2.5 min / 5 min |                                             18.9 MB / 37.7 MB |                                       576 | Cheap enough for background file-drop or slow rekey cover.                                                                                    | Poor chat UX; a remote cancellation can appear stuck for minutes.                               |
| 10 min                         |                5 min / 10 min |                                              9.4 MB / 18.9 MB |                                       288 | Lowest listed continuous-cover cost.                                                                                                          | Store-and-forward UX, not conversation; slow recovery/control propagation.                      |

The byte figures count only one 65,490-byte application frame per direction per epoch and use decimal MB. Receipts, DCEP, SCTP, DTLS, TURN, and IP overhead are excluded. Costs scale linearly with `C×F` and with the number of WebRTC edges. **Rooms are shipped n-party (`n>2`) full peer meshes:** the signaling/discovery service is centralized and star-shaped, but every room member receives the peer list and opens a WebRTC edge to every other member. The data plane therefore has `n(n−1)/2` covered edges. At 10 seconds, five peers create ten covered edges and roughly **11.32 GB/day** of scheduled application payload across the room. Each endpoint participates in `n−1` edges. A faster cadence may be a room privacy profile, but **must not activate in response to typing or queued data**: an activity-triggered cadence change recreates the timing signal the cover schedule is meant to remove.

**Large-file consequence:** The fixed cell has a 61,919-byte data region, but the current chat sender deliberately admits only `ceil(0.9 × 61,919) = 55,728` useful bytes per ordinary live chunk so every real cell retains random fill. At a 10-second `F=1` chat cadence that is only 5.57 kB/s: about 5.2 hours for 100 MiB or 53.5 hours for 1 GiB. A cover room therefore needs an explicit room-wide bulk policy:

1. **Base-lane only:** the file uses ordinary chat cells. This best hides file existence but is intentionally slow.
2. **Bucketed bulk lanes:** the room declares fixed `F` and duration buckets. A file starts only at a bulk boundary, stays on one message-scoped channel, and sends cover until its bucket ends even after completion or cancellation. For a 10-second cadence, `F=16` yields about 89 kB/s (100 MiB in 19.6 minutes; 1 GiB in 3.35 hours), while `F=64` yields about 357 kB/s (100 MiB in 4.9 minutes; 1 GiB in 50 minutes). The observer learns the bulk class and duration bucket, but not exact size, progress, completion, or cancellation.
3. **Immediate bulk:** send at available WebRTC speed. This preserves content encryption and per-message cancel/progress isolation but reveals that a bulk transfer is active and exposes its approximate traffic volume.

Hiding even the **existence** of a fast large-file transfer requires dummy bulk lanes to run independently of demand, which is expensive: symmetric 10-second cover at `F=16` schedules about 754 MB per pair per hour while active; `F=64` schedules about 3.02 GB per pair per hour. There is no protocol trick that simultaneously gives arbitrary-file speed, negligible cover bandwidth, and hides whether a large transfer exists.

**Threat-model boundary:** This is link-local application-layer cover against a passive observer of an already-established direct or TURN-carried WebRTC association. It is not an anonymity network and does not hide who connected to whom. Dummy payloads must be cryptographically and syntactically valid at the encrypted-frame layer. ML-KEM control must remain inside the authenticated application encryption and DTLS envelope; at this declared observer layer, Kemeleon's raw-encoding distinguisher has no raw ML-KEM bytes to inspect. F-2 records the boundary and the condition under which an OKEM would become necessary.

_Source:_ maintainer decisions and cover-scheduler analysis, 2026-07-23 (immediate default; cover is room-wide); `src/api/webrtc/handleSendMessage.ts` / `handleOpenChannel.ts` (current per-message-channel lifecycle); `src/handlers/chunkFrame.ts` and `src/utils/constants.ts` (65,490-byte v3 application frame); `src/handlers/handleSendMessage.ts` (0.9 useful fill); finding #10 / `6016862` (historical true-or-random token decision) plus `src/handlers/receiptFrame.ts` (current 65-byte tagged frame); F-1/F-2 below (PQ substitution and byte-uniformity); `docs/paper-prior-art-and-related-work.md` (claim boundary).

### D4 — DECIDED: paper claim re-scoped after independent SOTA adjudication

**Status:** Claim boundary accepted 2026-07-23; it supersedes the earlier “C3 is the only NOVEL / no preemption found” language.

_Paper:_ The broader crypto-and-networking pass found that the original search overfocused on Signal-like secure messaging. Post Quantum Sphinx and Outfox already put PQ KEMs into metadata-hiding packet formats; CCS 2024 OKE/Kemeleon and CRYPTO 2025 Hybrid OKE already solve the stronger primitive problem of random-looking exposed PQ/hybrid KEM transcripts; and Zerion's public 2026-07-23 v3 source combines exact 4096-byte real-or-cover frames at roughly 750 ms with in-frame ML-KEM. Therefore p2party does **not** claim a new cryptographic construction, the first fixed frame to carry PQ material, or an unpreempted “free ciphertext” insight.

The research question is narrower and comparative: can a **shipped n-party (`n>2`) browser/WebRTC full peer mesh** place sparse, authenticated Triple-Ratchet PQ advances into cells an optional room-wide schedule would already send, thereby avoiding Zerion's permanent per-frame KEM tax, while message-scoped RTCDataChannels retain cancellation/progress/backpressure/retry/teardown isolation? The server remains only the star-shaped signaling/bootstrap point; it is not the room data hub. “Free” means only zero marginal observer-visible application frames/bytes relative to sufficient scheduled capacity. Immediate/no-cover rooms make no metadata claim. This is **NOVEL-ADJACENT / open until evaluated**, with WPES or PoPETs as the honest first venue.

The signaling star is nevertheless a room-membership observer. Today the client gives it `roomUrl` + stable `peerId`, then asks for the `roomId` roster, receives peer IDs/public keys, and brokers each pair's SDP/ICE through it. High-entropy/PIN rooms protect discovery/authentication and keep E2E secrets in-band, but do not hide which clients share a room. Never merge the cover claim with the active-but-unshipped L2 target in D5: L1 opaque/OPRF tokens still reveal same-token co-presence, and even private writes + PIR do not erase source-IP/timing/TURN residuals.

Claude's prior-art pass remains useful: it correctly rejected primitive novelty; identified SPQR/Triple Ratchet/PQ3; fixed SPQR 42→32 bytes and “Reed–Solomon”→“erasure codes”; and demanded a measured threat model. Its errors were the broad negative-result claim and treating Kemeleon as a current blocker. Kemeleon matters only if an observer receives raw KEM encodings. With PQ control inside old-epoch application AEAD and then DTLS, the declared direct/TURN observer sees ciphertext; packet captures must verify that premise. If a future layer exposes the KEM before DTLS, use the published OKE/Hybrid-OKE construction rather than inventing an encoding.

The dated p2party commits (`6ba8558b...`, `68fd058f...`) precede Zerion v3 commit `1f9d00f...` by roughly 28 and 19 hours respectively. Record this only as independent near-concurrent provenance, never as academic priority or a “won by hours” argument.

_Blog:_ The first survey gave us a beautiful headline and then the wider field took a hammer to it. Good. Signal proved the bandwidth problem; the mixnet people proved PQ packets were already a thing; the obfuscation people had already taught ML-KEM to wear random-looking clothes; and Zerion put dense ML-KEM into a constant-rate messenger. What is left is more specific and more interesting to build: **sparse rather than dense PQ healing, smuggled into a room timetable a browser mesh was already paying for, without sacrificing the per-message channel UX.** The paper earns that sentence with traces and measurements, not typography.

_Required evidence:_ multi-browser direct+TURN packet traces; n>2 full-mesh regression tests as a release gate; classifier tests across idle/text/PQ/cancel/complete/file classes; bandwidth/latency/CPU/battery/TURN/channel-churn measurements across cadences and mesh size; dense-Zerion vs sparse-p2party vs SPQR/PQ3 comparison; downgrade/policy/epoch/retry/fork/crash tests; and a precise leakage function restricted to cover-enabled rooms. The production milestone is the v3 package actually running on `p2party.com`; the current live site proves the n-party browser mesh exists, not that the new PQ-cover result has shipped.

_Source:_ `docs/paper-prior-art-and-related-work.md` §1.1, §D, §3 C3, §4–5, refs 99–104; Zerion commit `1f9d00fce039fd99c2cd90e14da3a213f6ffa80a`; p2party provenance commits `6ba8558b57c2b08509385030ac520e692f4a5c22`, `68fd058fd834dde0c72f969fc67c4f6c07aa5678`.

### D5 — DECIDED: fold strong L2 server-blind rooms into the combined target

**Status:** Scope and working construction accepted 2026-07-23; it is not yet implemented. This promotes and supersedes the old deferred L1/OPRF note in F-3.

**Current-state correction:** Shipped p2party has a centralized signaling star and a full WebRTC data mesh. It is server-blind for E2E payloads and in-band secret key material, but not for membership: the client exposes a stable Ed25519 key in the WebSocket URL, sends raw `roomUrl` + stable `peerId`, receives the room's peer-ID/public-key roster, and brokers every pair's SDP/ICE through the service. A high-entropy room is unguessable to outsiders and a PIN/CPace room authenticates peers; neither prevents the service from enumerating the room graph.

**Target:** The combined system must protect three different surfaces:

1. **Control plane / L2 rendezvous:** the signaling service must not learn a room's stable identifier, stable peer identities, roster, or which fixed-size signaling records form one room graph.
2. **Data-plane association:** the full mesh remains pairwise WebRTC, with one independently authenticated/serialized hybrid ratchet per `(room, stable-peer)` edge and one ephemeral DataChannel per logical message. The server never becomes a content relay merely to gain blindness.
3. **On-edge activity:** optional room-wide scheduled cells hide bounded real-vs-cover/PQ/cancel/file events after associations exist.

An OPRF over one common room token is **not** sufficient L2: it can hide the token's input while still letting the server group every client that uses the same output/mailbox. Likewise, encrypting a roster under the room key hides its contents but not which clients read/write the same object. OPRF/Privacy Pass remains useful for unlinkable quota credentials; it is not the rendezvous address. PSI can find an intersection, but does not supply asynchronous n-party presence and private signaling.

**Working construction:** prototype a short-lived anytrust private rendezvous service over two or three independently operated replicas. The dynamic multi-writer presence board uses DPF/Riposte-style private point writes plus batched information-theoretic PIR reads; after two peers discover one another, pairwise directional single-writer logs may use a Talek-like construction. Measure both against Myco's asymmetric two-server/oblivious-data-structure efficiency frontier. A new invite carries a 256-bit room capability in the URL **fragment**, plus a canonical authenticated room policy; the human PIN remains a separate peer-authentication input and never derives a public-board AEAD key, which would expose an offline PIN verifier. Epoch-derived hidden presence rows contain only rotating presence IDs, short-lived inbox handles, expiry, capabilities, and ephemeral X25519 + ML-KEM rendezvous keys. Stable identities appear only inside the encrypted authenticated pairwise exchange. Fixed-size fragmented SDP/ICE records move through one hidden inbox per peer, and rotating presence IDs deterministically select the WebRTC offerer. L2 then leaves the path: it bootstraps or repairs `n−1` pairwise WebRTC edges while application data stays in-band.

Talek is a plausible pairwise-log substrate and comparator, not the presence-board primitive, a drop-in rendezvous service, or the current SOTA efficiency claim. **Myco (IEEE S&P 2025)** changes that frontier with `O(N log² N)` work in an asymmetric two-server distributed-trust model and reports large throughput gains over PIR systems. **Peer2PIR (IEEE S&P 2025)** separately demonstrates private peer routing, provider advertisements, and content retrieval in IPFS. Neither supplies p2party's dynamic room semantics: a capability room still needs a fixed-capacity multi-writer presence design, private subslot allocation, collision handling, expiry, active-server equivocation/partition auditing, and a browser WebRTC handoff. A cheap global trial-decryption board is an acceptable experimental baseline, but it hides membership only when every online client performs indistinguishable real-or-dummy accesses at a service-wide cadence. Otherwise join timing reclusters the room.

**Two levels must remain explicit.** L2a is protocol-level graph blindness: the application server sees fixed-size random records but cannot partition them into rooms or stable identities. L2b adds network unlinkability: source IP, connection timing, and a co-operated TURN service otherwise remain correlators, so the strong claim needs independently operated ingress/board/TURN services, OHTTP-style trust splitting, or an anonymity/mix/onion layer plus an explicit residual-leakage statement. OHTTP alone hides IP from the request processor but neither hides a shared mailbox nor survives ingress/processor collusion. Direct WebRTC necessarily reveals endpoints to peers; a compromised room member knows the roster by design. “L2 shipped” means the chosen target level and leakage are tested, not that the room token is merely opaque.

**n-party invariant:** `createSession()` remains the correct two-party cryptographic primitive. A room endpoint owns `n−1` independent sessions; it never shares ML-KEM keys, PQ epochs, counters, skipped keys, retry/fork state, or serialized secrets across edges. A logical room message is encrypted separately for every peer edge. Join readiness requires every expected edge to be authenticated and bidirectionally send-ready.

_Paper:_ The combined question is whether a server-blind n-party control plane, sparse PQ-healing full-mesh data plane, and scheduled activity cover can be composed without turning the self-hosted service into a private-access supercomputer or the browser into an unusable bandwidth furnace. DP5 and Private Signaling already establish private presence/signaling; Signal Private Groups hides the roster but not accesses; Talek and 2PPS establish anytrust hidden-access logs/pub-sub; Myco is the polylogarithmic two-server efficiency baseline; Peer2PIR is the direct private-P2P-query baseline. Pung, DPIR, Riposte, Express, Vuvuzela, Stadium, Karaoke, and Alpenhorn complete the mandatory comparison. The contribution must be sold as an evaluated dynamic-room/WebRTC architecture, not a newly invented privacy primitive.

_Blog:_ The server used to know the guest list even when it could not read the party. L2 puts the guest list inside the attack surface: no stable name at the door, no common clipboard everyone signs, no public roster endpoint. The room members do the expensive pattern-matching; the dumb server moves equal-looking envelopes. Then the WebRTC mesh takes over and the scheduled trains hide when those peers actually speak.

**Release/OSS blockers discovered while scoping (historical checkpoint):** the client then hardcoded `nopin`, left responder-first sending unprimed, and keyed runtime gates by peer only. Those client blockers are now addressed: room policy selects PIN/no-PIN, interactive 3DH and ML-KEM remain mandatory in both, the responder ratchet is primed before return, and gate/inbox ownership is `(room, peer)` plus per-attempt leases. The separately recorded server-side roster/membership-authorization findings are not made true by those client fixes and still require verification in the server repository before any L2 claim.

_Source:_ maintainer decision 2026-07-23; `src/api/signalingServerApi.ts`, `src/middleware/keyPairListenerMiddleware.ts`, `src/handlers/handleWebSocketMessage.ts`, `src/handlers/handleConnectToPeer.ts`, `src/handlers/handleSendMessage.ts`, `src/handlers/handleOpenChannel.ts`; server `src/ws/handleRoom.ts`, `src/ws/handlePeers.ts`, `src/wss.ts`, `src/routes.ts`; `docs/paper-prior-art-and-related-work.md`; DP5 (PoPETs 2015), Talek (ACSAC 2020), 2PPS (2021), Private Signaling (USENIX Security 2022), Myco (IEEE S&P 2025, https://eprint.iacr.org/2025/687), Peer2PIR (IEEE S&P 2025, https://doi.org/10.1109/SP61157.2025.00231), and the metadata-protection SoK (PoPETs 2024).

### D6 — DECIDED: explore p2party crypto as a fail-closed BitTorrent private-swarm extension

**Status:** Architecture/research direction accepted 2026-07-23; **P2BT is not implemented**. It follows the protocol-v3 core and does not replace the room-mesh implementation. “BitTorrent” here means extending discovery and the peer wire protocol, not merely borrowing the Mainline DHT or tunnelling an unchanged client.

**Protocol direction:** define a capability-gated private-swarm mode with no silent compatibility downgrade:

1. A high-entropy swarm capability is distributed out of band or held only in a local URI fragment. Strong mode discovers peers through D5's private rendezvous; hashing or blinding the `info_hash` and using an ordinary tracker/DHT is only L1 because the common lookup key and source endpoints still cluster the swarm.
2. Before any standard BitTorrent handshake bytes are exposed, peers establish an authenticated X25519 + exact swarm-policy-selected ML-KEM-512/768/1024 p2party session bound to the swarm capability, protocol version, content identity, and canonical swarm policy. The conventional handshake and peer messages then travel only inside authenticated encryption.
3. HAVE/bitfield/request/piece/cancel/choke state is encoded into a fixed-size cell profile. Preserve piece/Merkle verification, pipelining, choking, rarest-first, resume, and cancellation. Dummy cells never advertise false verified content and never count toward tit-for-tat or upload credit; only verified useful piece bytes do.
4. Cover is a swarm-wide **rate profile**, not just a cadence: `payload_per_cell / cadence` bounds goodput. A fixed duration/rate class can hide exact size/progress/cancellation inside that class; immediate bulk mode leaks that bulk activity exists. Never accelerate the cover profile in response to demand.
5. Disable legacy trackers, Mainline DHT, PEX, LSD, plaintext handshakes, and hole-punch rendezvous in strong mode. Content and piece semantics may remain compatible, but legacy wire/discovery interoperability is incompatible with the privacy claim. A gateway is explicitly a graph observer.
6. Keep BitTorrent's sparse bounded-neighbor graph. Importing p2party rooms' all-to-all edges and per-edge cover into a large swarm would make bandwidth quadratic and destroy the protocol's scaling and incentive model.
7. The strong carrier is WebRTC/DTLS or TLS 1.3/QUIC with the p2party channel input bound to a TLS exporter. Do **not** put the current 2,465-byte hybrid HELLO directly on raw TCP and then claim camouflage: its length and raw ML-KEM encoding are fingerprintable. Raw TCP requires a published obfuscated-key-exchange construction such as OKE/Kemeleon, or an explicitly weaker confidentiality-only claim.
8. Chat keeps one physical DataChannel per logical message because cancel/close lifecycle is useful UX. P2BT does not copy that mapping: torrents multiplex bounded logical transfer IDs and standard peer-wire records over one long-lived covered neighbor connection. Opening a stream/channel for every request or block would itself reveal demand and create pathological churn on large files.
9. The first prototype profile is `P2BT/1`: an encrypted `OPEN` cell repeats the exact version, content identity, policy hash, cell profile, mandatory-feature bitmap, and ordinary BitTorrent handshake; later fixed cells fragment/reassemble ordinary peer-wire bytes. Security-critical features are descriptor-selected and cannot be disabled through BEP 10. Unknown mandatory features abort without plaintext fallback.

**Capacity consequence:** the fixed cell's theoretical data region is 61,919 bytes; this P2BT calculation deliberately uses that full region rather than chat's 90%-fill profile. At one cell per 10 seconds that is only about 49.5 kbit/s per neighbor direction and roughly 48 hours/GiB from one source; at 60 seconds it is about 8.26 kbit/s and roughly 289 hours/GiB. Ten seconds is a plausible control/small-transfer profile, not a bulk-file profile. Covered bulk needs a predeclared higher cell count/rate or a preannounced bulk window whose transitions occur at swarm epochs rather than on demand. PQ bytes are “free” only in the narrow observer-visible sense when they replace padding in an already-paid cell; in a saturated torrent they displace useful piece bytes.

**Prior-art correction:** a broad “first BitTorrent with ML-KEM and a Double Ratchet” claim is false. I2P ships BitTorrent through I2PSnark; its ECIES-X25519-AEAD protocol incorporates Signal's Double Ratchet, and proposal 169 reports the hybrid ratchet complete in Java I2P and i2pd. The separate hybrid specification still labels implementation, testing, and rollout in progress, so “ratchet implementation complete” must not become “universally deployed.” Peer2PIR already implements private peer routing, provider advertisement, and content retrieval for IPFS. OneSwarm, Tribler, Aqua, anonymous DHT lookup work, BEP 37 anonymous mode, and BitTorrent's MSE/PE also occupy pieces of the anonymity/obfuscation design space. The narrower opening is application-layer **private logical swarm discovery + uniform authenticated peer-wire cells + demand-independent cover**, evaluated as a privacy/throughput/incentive/interoperability trade-off.

_Paper:_ For the main p2party paper this is initially a secondary implementation that demonstrates `createSession()` is transport-neutral and tests the large-file case on a sparse graph. It becomes a separate publishable result only if a BEP-shaped prototype implements private discovery and the fixed-cell wire mode, states a precise leakage function, and beats or meaningfully shifts the design frontier against Peer2PIR, I2P, OneSwarm, Tribler, and Aqua. Required measurements include discovery leakage, throughput/time-to-first-piece, cover amplification, CPU/energy, tracker/DHT/PEX downgrade resistance, churn/NAT traversal, free-riding under dummy traffic, and classifier accuracy over idle/control/piece/cancel traces. OneSwarm already has capabilities, disposable addresses, private lookup, tunneled BitTorrent semantics, and incentive work; Peer2PIR already puts PIR into a large real P2P stack; Aqua targets high-bandwidth traffic against a stronger mix-network adversary. The differentiator therefore cannot be “encrypted capability BitTorrent,” only the measured anytrust-rendezvous + fixed-cell + hybrid-PQ + fail-closed operating point.

_Blog:_ We are not “putting torrents in a chat room.” We are making a torrent that refuses to announce its swarm in public, refuses to speak its handshake in clear structure, and refuses to tell a watcher whether the next equal-looking cell was a HAVE, a CANCEL, a piece, or deliberate noise. The hard part is keeping BitTorrent's economics honest: chaff buys privacy, never upload credit.

_Source:_ maintainer clarification 2026-07-23; BEP 3/5/10/11/27/42/44/55; I2P ECIES-X25519-AEAD, hybrid ML-KEM ratchet, proposal 169, and BitTorrent-over-I2P documentation; Peer2PIR (IEEE S&P 2025, https://doi.org/10.1109/SP61157.2025.00231); OneSwarm; Tribler; Aqua; `docs/paper-prior-art-and-related-work.md`.

### D7 — DECIDED: one exact room-selected ML-KEM suite; no negotiation or fallback

**Status:** 0.10.0 shipped the ML-KEM-768 profile. The 0.11.0 working tree adds
FIPS 203 ML-KEM-512 and ML-KEM-1024 as authenticated room-wide alternatives,
while keeping ML-KEM-768 as the product default. The later sparse PQ
ratchet-epoch mechanism in F-1 is separate state-machine/integration work.

Every room deliberately exposes one exact cryptographic profile:

- Ed25519 is the pinned identity/signature anchor and cross-signs a dedicated
  X25519 identity key.
- The identity-bound interactive X25519 3DH leg runs in **every** room and proves possession
  of the cross-signed identity key. PIN policy **adds** CPace; it never replaces
  3DH. This is not Signal X3DH: there are no asynchronous prekey bundles; both
  peers are online and contribute fresh ephemeral keys. PIN/no-PIN are
  authentication policies inside the selected profile, not a peer-negotiated
  cipher-suite list.
- The room policy selects exactly one of `hybrid-mlkem512`,
  `hybrid-mlkem768`, or `hybrid-mlkem1024`. No-PIN combines
  `3DH ‖ ML-KEM`; PIN combines `CPace-ISK ‖ 3DH ‖ ML-KEM`, each under a distinct
  mode- and parameter-set-specific HKDF-SHA-512 domain. All KEM fields and the
  exact suite identifier are key-confirmation/transcript bound.
- PIN rooms implement draft-21's `CPACE-RISTR255-SHA512` construction and feed
  only the transcript-derived ISK to the root combiner; the raw CPace point
  never leaves WASM. Ristretto255/SHA-512 is explicitly supported by the draft,
  though the draft's primary recommended low-cost profile is
  `CPACE-X25519-SHA512`.
- The live Double Ratchet uses X25519 and message chunks use
  ChaCha20-Poly1305-IETF. Ratchet state and IndexedDB carry exact root-suite
  provenance (`hybrid-3dh-mlkem{512,768,1024}-cpace21-v3`). Standalone snapshot
  version/protocol remain `3/3`, with root-suite bytes `4/3/5` for
  512/768/1024. The channel-input suite tags are `0x02/0x01/0x03`; 768 keeps
  the 0.10 byte assignment. Pre-hybrid, untagged, unknown, or cross-suite
  snapshots fail closed.

This is **selection, not negotiation**. The creator fixes the room policy
before any edge handshakes. The HELLO parser receives that policy context and
accepts the one exact shape—1,761 bytes for ML-KEM-512, 2,465 for ML-KEM-768,
or 3,329 for ML-KEM-1024. It never infers a suite from attacker-controlled
length, advertises a preference list, chooses a “best common” value, retries a
smaller profile, or falls back to classical DH. A mismatch changes both the
expected frame shape and the authenticated transcript and aborts.

The reason for the hybrid is robustness across assumptions, not
backward-compatibility. The classical 3DH leg avoids making the bootstrap depend
only on a newer lattice assumption; ML-KEM protects the bootstrap against
store-now/decrypt-later attacks if scalable quantum computers later defeat the
classical DH leg. This does **not** make authentication post-quantum: Ed25519 is
still the identity anchor, and the current ongoing ratchet has not yet landed
the sparse PQ healing epochs in F-1. Nor do we claim a formal X-Wing-style
robust-combiner proof for the whole interactive handshake: the component
secrets are fixed-order/domain-separated through HKDF and the transcript is
key-confirmed, but the paper must either prove that exact composition or state
it as an engineered hybrid assumption.

FIPS 203 defines ML-KEM-512, -768, and -1024 at NIST security categories 1, 3,
and 5. Their public-key/ciphertext sizes are 800/768, 1,184/1,088, and
1,568/1,568 bytes; all yield a 32-byte shared secret. ML-KEM-768 remains the
balanced default. ML-KEM-512 reduces computation and bootstrap bytes but saves
little observer-visible bandwidth inside a fixed 65,490-byte cell.
ML-KEM-1024 is the category-5 option and costs a larger HELLO, but choosing it
does not upgrade Ed25519/X25519 authentication beyond their classical security
level. The profile selector expresses assumption/performance preference, not an
“overall 256-bit secure room” claim.

Adding AES-GCM merely for choice would expand downgrade, transcript, test, and
implementation surface without adding a meaningful threat-model benefit. A
future genuinely post-quantum-authenticated identity profile or an
algorithm-diversity profile such as HQC requires a separate design and review,
its own authenticated identifier, and exhaustive cross-profile rejection
tests. CPace draft-21 separately defines or supports
X25519/SHA-512, P-256/SHA-256, X448/SHAKE-256, P-384/SHA-384,
P-521/SHA-512, Ristretto255/SHA-512, and Decaf448/SHAKE-256 profiles. Those
are future ingredients, not values peers negotiate inside a room.

This composition is p2party's transcript-bound hybrid protocol; it must not be
mislabelled X-Wing merely because both use X25519 and ML-KEM. X-Wing remains
relevant prior art and a possible standardized KEM component for a future
redesign. As of draft-10 it is an active individual Internet-Draft, not a final
RFC, and it specifies a non-interactive, unauthenticated KEM rather than an
interactive identity/PAKE handshake.

The closest formal handshake baseline is Signal **PQXDH**, whose specification
and USENIX Security 2024 artifacts collectively support authentication,
secrecy, forward secrecy, HNDL resistance, KCI resistance, and session
independence under stated models. The audit corrects an over-broad shorthand:
ProVerif proves the maximal-compromise symbolic queries from which those
properties are derived; CryptoVerif proves a narrower set of computational
classical/PQ games. Neither proves Signal's Double Ratchet, deniability,
implementation, or whole ecosystem. PQXDH targets asynchronous messaging
through a server-hosted prekey directory and offline responder; p2party targets
two live peers on a WebRTC edge and optionally adds CPace room-PIN
authentication. That is an architecture-fit difference, not proof of superior
cryptography. PQXDH has higher formal assurance today.

The formal audit found a concrete 0.10 confirmation boundary and the 0.11
working tree hardens it. The old two-flight order let either confirmation MAC be
changed so one endpoint could complete while the other rejected. The new
sequence is chained: responder `mac_R`; initiator
`mac_I = MAC(transcript ‖ mac_R)`; responder
`mac_F = MAC(transcript ‖ mac_R ‖ mac_I)`. The initiator establishes only after
validating `mac_F`. A changed `mac_R` therefore poisons `mac_I`; a changed
`mac_I` prevents a finish; and a changed finish is rejected.

The honest remaining correspondence is directional:
`AcceptI ⇒ VerifyI_R ∧ FinishSentR`, while responder completion proves it
verified the initiator but cannot prove the FINISH was delivered. A final packet
drop can still leave the responder complete and the initiator waiting/rejecting;
no finite acknowledgement chain produces common knowledge over a lossy
transport. This is a DoS/state-synchronization edge, not key disclosure. An
already-open DataChannel cannot stand in for the finish: it proves only the
earlier DTLS/SCTP transport, and browser JavaScript receives no peer-verified
application-MAC receipt.

ProVerif can cover the no-PIN pairwise handshake, compromise cases,
downgrade/UKS and channel binding; Tamarin should cover the chained
confirmation order, erasure/ratchet state and n-peer consistency. CryptoVerif
must not idealize away the open robust-combiner question in
`HKDF-Extract(0, [CPace-ISK ‖] 3DH ‖ ML-KEMss)`.

_Paper:_ Treat the suite as standard-component systems engineering, not a new
hybrid combiner. The research claim lives in how the authenticated hybrid state,
room policy, WebRTC edge, uniform cells, and private rendezvous compose and are
measured.

_Blog:_ One room profile, one transcript, one way to fail. The hybrid's design goal is
two locks made from different mathematics, so the initial session should not
depend on only one assumption. Until the exact composition has a proof, that is
an engineered assumption rather than a theorem. The price is larger bootstrap
material; p2party's fixed cells make that price cheap to carry, not
cryptographically “free.”

_Source:_ maintainer questions/decisions 2026-07-23; Signal PQXDH specification
(https://signal.org/docs/specifications/pqxdh/); RFC 9794
(https://www.rfc-editor.org/rfc/rfc9794.html); X-Wing draft-10
(https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/10/);
`src/handlers/handshakeCore.ts`,
`src/cryptography/ratchet.ts`, `src/handlers/messageChunkCrypto.ts`,
`src/session.ts`, `src/db/ratchetWrap.ts`, and
`docs/paper-prior-art-and-related-work.md`.

### D8 — DECIDED: compact links plus a checksum-protected word encoding

**Status:** The store-free compact/word codec and strict legacy normalization
land in p2party-js commit `8e8b823`; the `p2party.com` fragment router, QR/share
path, transient policy/PIN bridge, and tests land in frontend commit `0455d2b`.
Production deployment remains a separate gate. This replaces “human-readable
room name” with human-readable **random capability encoding**.

The room capability remains 256 uniformly random bits. The normal copy/QR form
uses unpadded base64url (43 characters instead of today's 64 hex characters).
The L2 form is fragment-only—`https://p2party.com/r#<invite>`—so HTTP,
reverse-proxy, analytics, and rendezvous request logs do not receive the
capability. The current `/rooms/<64-hex>?v=3&auth=...` route is a migration
format, not the L2 target.

The same 32 capability bytes may also be rendered as a canonical,
checksum-protected mnemonic over the project's existing 2,048-entry English
list, pinned for this purpose as `p2party-invite-en-v1`. Its checksum is the
first byte of domain-separated SHA-256 over the capability; this is not wallet
seed derivation or BIP39 checksum semantics.
Eleven bits per word means 24 words preserve the full 256-bit capability while
leaving checksum capacity. Twelve words encode only about 128 bits; four to six
words are suitable only as a compare-aloud fingerprint, never as the room
secret. User-chosen words and “memorable room names” are rejected because they
turn an unguessable capability into an offline dictionary target.

The compact and word forms decode to the same bytes and room identifier; they
do not create aliases. QR/copy defaults to base64url, read-aloud/import accepts
the words, and the UI shows a short independent fingerprint for comparing
peers. Decoding is strict and local: normalize only the specified
case/whitespace rules, verify version/checksum before networking, reject unknown
or ambiguous words, and never autocomplete a near match. The final list needs a
phonetic/confusability, accessibility, localization, and license review; do not
silently call it BIP39 or reuse wallet-seed UX.

The PIN stays separate. It authenticates room membership through CPace and is
never appended to, derived from, or used as the checksum of the invite. The
canonical room policy and rendezvous descriptor remain authenticated under the
capability-derived context, so converting hex/base64url/words cannot alter the
room-wide ML-KEM, cover, PIN-required, or L2 configuration.

_Paper:_ The mnemonic is usability engineering, not a cryptographic
contribution. Evaluate transcription error rate, correction-free recovery, and
whether users can distinguish the capability from the optional PIN. The
fragment-only compact form is the security-relevant part because it reduces
accidental server/log disclosure; it does not by itself hide IP, timing, or
room co-presence.

_Blog:_ The invite can look like machine code or be spoken like a spell. Either
way it is the same random key. We are changing the alphabet, not sanding entropy
off the lock.

_Source:_ maintainer decision 2026-07-24; `src/roomInvite.ts`,
`src/roomInvite.test.ts`, current room normalization in `src/index.ts`, and the
L2 construction in D5.

---

## 3. FUTURE DILEMMAS

Named destinations and known-open technical dependencies past the current work. Some carry genuine recorded option-sets (full treatment); the roadmap items carry only a stated direction — no fabricated debate is attached where none is on record.

### F-1 — The PQ epoch: sparse whole-ciphertext CKA vs SPQR-style micro-chunking _(core landed; production integration pending; hard)_

_Paper:_ The bootstrap uses one exact room-selected ML-KEM-512/768/1024 suite. Commit `a426490` now implements an internal per-edge sparse-healing core with canonical full-width OFFER/ADVANCE records, exact suite and edge binding, u64 epochs/counters, alternating turns, full-record KDF transcripts, replay/fork/gap rejection, prepared/committed/acknowledged phases, traffic gating, and secret wiping. It carries one complete suite-selected ML-KEM public key/ciphertext rather than inventing a bespoke fold into the classical root or erasure-coding it into 32-byte SPQR pieces. This is not yet runtime PQ healing: canonical authenticated ACK encoding, crash-safe encrypted checkpoint/restore, exact sealed-record retransmission, separate classical/PQ message-key combination, WebRTC control routing, and scheduler integration remain required. Until those land and are adversarially tested, production still rejects nonzero `PQ_EPOCH`. This remains a systems comparison with SPQR/PQ3/Zerion, not a new ratchet construction.
_Blog:_ This is still the grant's headline promise, but the honest antagonist changed. Signal amortizes the KEM, Apple throttles it, and Zerion pays for one in every fast cover frame. We are testing the sparse point: do the full standard ratchet advance only when healing needs it, and let an already-running room cell carry it.
_Source:_ §2 "uniform chunks make a PQ ratchet ciphertext free"; ADR-A2 "PQ-reserved"; design §2 pt 7, §5–6, §15; plan Global Constraints, Stage 1/5 (`PQ_TAG_LEN=1`, `PQ_EPOCH_LEN=1`); `p2party-double-ratchet-plan` (phasing, sourcing caveat); `paper-prior-art-and-related-work.md` §D/§3.

### F-2 — Kemeleon boundary: encrypted inner record now; OKEM if the boundary moves _(decided boundary; hard)_

_Paper:_ OKE/Kemeleon (CCS 2024) proves raw ML-KEM public keys/ciphertexts are not uniform and Hybrid OKE (CRYPTO 2025) gives the relevant hybrid obfuscating combiner. The earlier memo incorrectly made this the current transport blocker without checking who sees the raw bytes. Decision: PQ control remains inside an authenticated application cell protected under the preceding epoch and then DTLS. The declared passive direct/TURN observer sees fixed-length ciphertext, so raw ML-KEM byte uniformity is not required at that layer. If a future bootstrap/control path exposes the KEM outside that encrypted envelope—or claims the key exchange itself resembles random traffic—adopt the published OKEM construction; do not improvise an Elligator-like wrapper.
_Blog:_ Kemeleon was a real paper pointed at the wrong layer. The watcher outside DTLS never gets the ML-KEM polynomial to fingerprint. Keep it that way. If we ever drag the rekey into daylight, then we use the cryptographers' proper disguise.
_Source:_ `paper-prior-art-and-related-work.md` §1.1, §D, §3 C3, refs 99–100; D3/D4 above.

### F-3 — SUPERSEDED: deferred L1 server-blind high-entropy link

_Paper:_ The old double-ratchet plan deferred an opaque-token/no-PAKE “Phase 1.” D5 supersedes that sequencing: L1 remains a migration/baseline mode, while the active combined research target is strong L2 graph-blind rendezvous. An opaque or common OPRF-derived token must never be relabelled L2.
_Source:_ H-2 (ADR-A2); D5; `p2party-double-ratchet-plan`.

### F-4 — RESOLVED: Stage-5 frame-layout reconciliation chose 62/61

_Paper:_ The historical plan fork is closed. Current v3 serializes `FRAME_TYPE_CHUNK(1) ‖ dhPub(32) ‖ N(8) ‖ PN(8) ‖ PQ_EPOCH(1) ‖ nonce(12)`, so `CHUNK_HEADER_LEN=61`, `MESSAGE_START=62`, and each seal/reseal uses a fresh random nonce. The receiver reads that cleartext nonce; `PQ_EPOCH` is currently required to be zero because sparse epoch advancement remains unimplemented.
_Blog:_ The random-nonce design finally reached both sides of the wire. The rejected 50-byte, index-derived layout survives only as history.
_Source:_ `src/utils/constants.ts`; `src/handlers/chunkFrame.ts`; `src/cryptography/pake_ratchet.h`; `src/cryptography/pake_ratchet.c`.

### F-5 — Optimized chunk-flooding: peer-to-peer relay instead of sender-fans-out-to-all _(roadmap; direction only)_

_Paper:_ Today "data is transferred naively from the initiator to every node in the mesh in parallel"; roadmap beat ② is to have peers relay chunks to each other so flood throughput scales with peer count. The sources record only the destination, not a weighed set of relay-topology alternatives — no such debate is on record, so none is asserted.
_Source:_ `p2party-writing-style` ROADMAP ②; `p2party-project-overview`.

### F-6 — Signaling decentralization via gossip _(roadmap; direction only)_

_Paper:_ Today every peer holds its own WebSocket to the single trusted-PKI signaling server; roadmap beat ③ is to have only a small percentage of peers keep a live WS socket, the rest learning peer/room info via gossip — reducing the server's centrality and metadata exposure. Only the destination is recorded, not a set of considered gossip-protocol alternatives.
_Source:_ `p2party-writing-style` ROADMAP ③; `p2party-project-overview` "Still open" item 1 (today's signaling server is an unauthenticated trusted PKI → transparent MITM of confidentiality).

### F-7 — Swift + Kotlin SDK ports (iOS/Android) _(roadmap; direction only)_

_Paper:_ Roadmap beat ④ is native SDK ports to Swift and Kotlin, broadening the SDK beyond the browser/TypeScript surface (TRL 7→9 framing). No design or implementation activity found; the Swift/Xcode satellite repo is listed among the dormant repos — a deferred, unscoped future beat, not an active decision with options on record.
_Source:_ `p2party-writing-style` ROADMAP ④; `p2party-project-overview` "dormant/abandoned satellites."

### F-8 — DTLS/TLS-exporter channel binding (RFC 9266) when browsers expose it _(direction only; from D1)_

_Paper:_ The theoretically-strongest session binding value — derived from the live DTLS handshake's fresh secrets, immune to the cert-reuse / triple-handshake failure class — is blocked only by an API-surface gap: no browser JS surfaces a general-purpose DTLS exporter (unlike Node's `tls.exportKeyingMaterial()`). Tracked from D1 as the binding to adopt the moment a browser exposes it, at which point CI's fingerprint layer becomes fully redundant.
_Source:_ D1 (§2); `scratchpad/handshake-rigor-memo.md` §D1 Option 3; RFC 9266; `docs/paper-prior-art-and-related-work.md` line 342.

---

_End of log. Resolved and deferred entries are anchored to specific fixing commits or ADR/finding sections. D1–D7 record the active 2026-07-22–23 decisions, rationale, consequences, and explicit claim boundaries; D5/D6 are research architectures until implemented and evaluated. Future entries state only what the artifacts record, with roadmap items marked direction-only where no debate exists. Depth is proportional to difficulty: the hard decisions (C-7, C-13, C-15, H-6, D1–D7, F-1, F-2, F-4) carry both registers; the obvious calls are one-liners._
