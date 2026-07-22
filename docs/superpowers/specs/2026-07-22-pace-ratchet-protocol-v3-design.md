# PACE + Double Ratchet (protocol-v3) — Design

**Date:** 2026-07-22
**Status:** Design — awaiting review before implementation planning
**Breaking:** Yes (wire protocol-v3). Clean cutover, no v2 interop (self-deployed, pre-1.0).
**Supersedes on the wire:** the 0.9.0 per-chunk Ed25519 transcript signature (dropped).

Related: [[p2party-pace-handshake-plan]], [[p2party-double-ratchet-plan]],
[[p2party-project-overview]]. Verify like a real user against the local stack +
headless Chromium E2E (`p2party.com/e2e/run.mjs`) per the definition of done.

---

## 1. Goal & threat model

Give p2party **forward secrecy + post-compromise security** for every room, and
**authentication against a malicious signaling server** for rooms that opt into a
PIN — by seeding a per-peer-edge **Double Ratchet** from a handshake run over the
already-established DTLS data channel.

Today (0.9.x): peer↔peer trust is TOFU — each side learns the other's identity
Ed25519 key only from the server-relayed roster/SDP, and the receiver decrypts
with its **static** identity X25519 key (no FS). The per-chunk Ed25519 signature
is the *only* thing binding a frame to a sender. A malicious signaling server can
substitute identity keys + SDP fingerprints and transparently MITM.

Threat model after v3:
- **Passive/off-path attacker:** defeated in all rooms (FS + AEAD, as before).
- **Recorded-ciphertext + later device/key theft:** defeated in all rooms (FS/PCS
  from the ratchet). At-rest ratchet state is wrapped (§8).
- **Active malicious signaling server (MITM):** defeated in **PIN rooms** (CPace
  binds a secret the server doesn't hold + the observed identity keys + DTLS
  fingerprints). **Not** defeated in no-PIN rooms — that is the honest, stated
  limit of a no-PIN room, not a bug.

## 2. Locked decisions (from brainstorming)

1. **Merge PACE with the Double Ratchet.** CPace's output seeds the ratchet root;
   messaging runs over the ratchet from the first message. This is the ratchet
   plan's **Phase 0 (classical)**.
2. **FS everywhere; PIN adds authentication.** The ratchet runs in *every* room.
   The seed differs by mode (§5); the ratchet is byte-identical afterward.
3. **Two clean room modes, no fallback between them.** The *presence of a PIN* is
   the mode. Mismatch / wrong PIN → **fail closed** (abort the channel). No
   best-effort downgrade, no per-peer capability negotiation, no "unverified"
   degradation UX.
4. **Clean v3 break, no v2 interop.** A minimal on-wire version tag rejects a
   mismatched peer cleanly; there is no v2↔v3 fallback path. Old v2 rooms/data
   remain separate.
5. **Drop the 0.9.0 per-chunk Ed25519 signature** — ships **atomically** with the
   authenticated ratchet (never before; see Risk R1).
6. **Pairwise per peer-edge**, advancing **per logical message** (all chunks of a
   message share one message key). Matches p2party's existing per-recipient
   encryption; no group/sender-key machinery.
7. **PQ-reserved.** Classical ratchet now; the handshake transcript and frame
   header reserve named SSOT space so a future hybrid ML-KEM/X-Wing KEM folds into
   the root without another wire break (v4). No KEM is implemented in v3.
8. **At-rest:** wrap persisted ratchet secrets with a **non-extractable WebCrypto
   AES-GCM key** stored in IndexedDB (survives refresh; §8).

## 3. Non-goals (explicitly not in v3)

- No v2↔v3 wire interoperability / fallback.
- No group sender-keys (pairwise edges cover the broadcast fan-out).
- No PQ KEM *implementation* (only reserved structure).
- No change to the offensive chunking/padding/decoy scheme — it layers on top
  unchanged, except decoy frames must carry indistinguishable ratchet headers.
- No change to the reliability/resume layer semantics (leaf-hash receipts,
  reconcile) beyond gating first send behind the handshake.

## 4. Architecture overview

```
main channel onopen (per peer edge, over DTLS)
        │
        ▼
   HANDSHAKE  ──►  32-byte shared secret ──► kdf_rk ──► Double-Ratchet ROOT
   (no-PIN: X3DH-DH   |   PIN: CPace/Ristretto255; both bind identities [+DTLS fp])
        │
        ▼
   epc.ratchetEstablished = true;  session persisted (wrapped) in IndexedDB
        │
        ▼
   every logical message → advance ratchet (per edge) → ONE message key
        → all 64KiB chunks AEAD'd under it (fresh random 12-byte nonce per chunk in the cleartext header)
```

One ratchet implementation (SSOT), seeded by one of exactly two functions. The
seed is the only branch; everything downstream is identical.

## 5. Handshake

**Where:** the top of `extChannel.onopen` in `src/handlers/handleOpenChannel.ts`
(~:252), gated to the persistent per-peer channel (`merkleRootHex === '' &&
channelLabel === 'main'`), before the receive-scratch allocation and any
chunk/receipt flow. `onopen` becomes `async`.

**Frame routing (Risk R2):** the current `onmessage` classifies inbound frames by
length only (64B receipt, `MESSAGE_LEN` chunk). Handshake frames get an explicit
1-byte **type tag** that cannot be confused with either, and are routed ahead of
those branches. Non-handshake frames that arrive before `ratchetEstablished` are
buffered on the existing `queue`/`seen`/`drainingRef` and drained after. The
reconnect leaf-hash receipt-replay burst (per-message channels) must not fire
until the peer's `main` ratchet is established — an explicit cross-channel gate
keyed by `epc.ratchetEstablished`.

**Both modes** produce a single 32-byte secret and **both mix both parties'
static Ed25519→X25519 identity keys** — that mutual authentication is the
precondition that makes the signature-drop safe (§6, R1). Both carry each side's
first DH-ratchet public key to initialize the ratchet.

**No-PIN mode (X3DH-style):** fresh ephemeral X25519 `EK` each side, mixed:
`DH(IK_a, EK_b) ‖ DH(EK_a, IK_b) ‖ DH(EK_a, EK_b)` → HKDF → secret. FS + binds the
identities each side observed. A server that substituted *both* identities still
MITMs — this is the acknowledged no-PIN limit.

**PIN mode (CPace over Ristretto255):**
- `PRS = NFC(PIN)` (6-digit numeric default; §7 room-shared).
- `sid` = a fresh random session nonce exchanged at the start of the handshake
  (standard CPace; prevents cross-session replay). `channel-id` = the connection's
  `main`-channel identifier.
- `G = crypto_core_ristretto255_from_hash( H( lv(DOMAIN), lv(PRS), lv(sid), lv(CI) ) )`
  where the **channel-input** `CI = channel-id ‖ IK_a ‖ IK_b ‖ fp_a ‖ fp_b ‖ PQ_TAG`,
  binding both identity keys and both DTLS fingerprints. **`lv(·)` = length-prefixed
  encoding** (each field is preceded by its byte-length as a fixed-width integer),
  per IRTF `draft-irtf-cfrg-cpace`'s `lv_cat` — MANDATORY because `PRS` (the PIN)
  and `CI` (which will bind variable-length DTLS-fingerprint/identity data in a
  secure room) are variable-length: bare concatenation would let distinct
  `(PRS, CI)` pairs hash to the same generator, amplifying online guessing and
  breaking the CPace security argument. `PQ_TAG` is a fixed-size **algorithm/epoch
  marker** (a few bytes, `0` in v3), reserving transcript structure so a future
  hybrid KEM binds cleanly without a v4 wire break — it is NOT the KEM ciphertext.
- Each side: `y ← scalar_random`, sends `Y = y·G`; shared `K = y·Y_peer`;
  `secret = HKDF(K, CI)`.
- Explicit **key-confirmation** exchange (MAC over the transcript) before any
  message flows — a swapped key/cert makes the two legs' `CI` disagree → the MAC
  fails → **abort**.
- A server MITM gets **one online PIN guess per session**; CPace gives no offline
  dictionary attack. Online guessing is bounded by a lockout (§7).

**DTLS fingerprint (feasible, verified):** read the remote `a=fingerprint:` from
the received SDP (`handleWebSocketMessage` `case 'description'`) / local from
`localDescription.sdp`; **re-verify post-connect** via `RTCPeerConnection.getStats()`
(`transport` → `certificate` reports). A `getStats` fingerprint that disagrees
with the value bound into `CI` ⇒ **tear the channel down** (abort, not log).
Identity-key binding is the always-on floor; fingerprint binding is the primary
MITM check. No fallback to identity-only unless a browser removes cert access
(none do today).

## 6. Double Ratchet (protocol-v3 message crypto)

**Granularity:** one ratchet per `(roomId, peerPublicKey)`. The DH/chain ratchet
advances **per logical message per edge** — never per chunk (chunks are
Fisher-Yates-shuffled, decoy-interleaved, relay-reorderable, and reconcile resends
only gaps, so a per-chunk step would desync). All chunks of a message share the
one message key; each chunk carries a **fresh random 12-byte nonce in its cleartext
frame header** (`chunkIndex` CANNOT be the nonce — it lives inside the encrypted
metadata, so the receiver can't know it before decrypting, and a message-level value
reused across a message's chunks would break the AEAD; a cleartext raw index would
also leak chunk count/order, so the nonce is random — birthday-safe within one
per-message key). A **retransmit MUST reuse the identical (nonce, ciphertext)** —
achieved by **resending the cached pair** from the existing retransmit store (R3),
never by re-encrypting with a fresh nonce on the same key+different plaintext, and
never a message key reused across two logical messages. Out-of-order/lost messages use a bounded
**skipped-message-keys** map (`MAX_SKIP`, measured against the 2 MB heap, ~500).

**Frame layout change (frame SHRINKS):** the current 96-byte cleartext prefix is
`ephemeral_pk(32) + signature(64)` (`MESSAGE_START`, `constants.ts:33`). Remap the
cleartext header to **62 bytes**:
`FRAME_TYPE(1) + DH_ratchet_pub(32) + N(8) + PN(8) + PQ_EPOCH(1) + nonce(12)`
(`MESSAGE_START = 62`, still well under 96). The DH pub must be cleartext (the
receiver needs it to derive the key before decrypting); the 12-byte **random nonce**
must be cleartext (the receiver needs it to decrypt). `N`
(message number) and `PN` (previous-chain length) fold into the **AEAD AAD**
(today AAD = merkle_root only) so they're authenticated without a separate MAC.
The header also carries a small **`PQ_EPOCH`** marker (decision 7) — a per-message
epoch/flag only; the actual future KEM ciphertext (~1 KB) rides the **handshake +
periodic per-epoch rekey frames**, each of which fits whole in one 64 KiB chunk
(p2party's uniform-chunk advantage — no erasure coding). Even with `PQ_EPOCH` the
header stays well under the old 96 bytes, so the frame still SHRINKS.
`METADATA_LEN` is **untouched** (it is inside the encrypted payload).

**Decoys:** decoy frames carry ratchet headers indistinguishable from reals
(random-looking DH pub, plausible `N`) or they re-leak the real/decoy split.

**Drop the per-chunk Ed25519 signature:** −64 B and −1 sign+verify per chunk.
Under a mutual-identity-authenticated root, the ability to derive the message key
proves identity and the Poly1305 tag is a genuine authenticator. The
raw-nonce-oracle domain-separation defense (`utils.h`) becomes moot on the wire;
the `handleReceiveMessage` `case -1` "signature wrong" path is removed.

**Injection points (grounded):**
- **Sender** `src/handlers/handleSendMessage.ts:~256` — replace
  `_encrypt_chachapoly_asymmetric` with symmetric AEAD
  (`crypto_aead_chacha20poly1305_ietf_encrypt`) under the message key. Derive the
  message key **once per (message, peer edge)** before the chunk loop; delete the
  per-chunk ephemeral keypair + the `_sign` transcript; generate a fresh random
  12-byte nonce per chunk and place it in the cleartext header;
  rewrite frame assembly to `[type ‖ DH_pub ‖ N ‖ PN ‖ ciphertext]`. Drop
  `senderSecretKey` plumbing; `allocateSendMessage` shrinks.
- **Receiver** new C `receive_message_with_key(decrypted, message, merkle_root,
  message_key)` (in `utils.c`) — skips the signature-verify block, symmetric
  decrypt under the supplied key + chunkIndex nonce + `AAD(merkle_root ‖ N ‖ PN)`,
  and keeps the post-decrypt merkle-proof/leaf-hash/receipt logic **verbatim**
  (the leaf-hash is still the reliability read-receipt token). Derive+advance the
  ratchet in `processMessage` (`handleMessageQueueing.ts`, which has `peerId` + the
  raw frame) and pass the message-key pointer in.

## 7. Room-mode separation, PIN, negotiation, failure

- **Version tag:** a minimal `protocolVersion` on the signaling `connection`/
  `description` message (`utils/interfaces.ts:142` / `signalingServerApi.ts:272` /
  `handleWebSocketMessage.ts:480`). Used only for a **clean reject** of a
  version-mismatched peer — not for fallback. A missing field = pre-v3 = rejected.
- **PIN plumbing:** `connect()` (`src/index.ts:~84`) gains a `secureRoomPin?`
  param (the surface a UI PIN field calls). `Room` gains an `isSecureRoom` flag
  (`roomSlice.ts`, precedent `onlyConnectWithKnownAddresses`) — but the **PIN is a
  secret and MUST NOT be persisted** to localStorage; hold it transiently in a
  `roomId`-keyed module Map (precedent `lastReconnectAttempt`,
  `handleOpenChannel.ts:42`). Thread the mode into `OpenChannelHelperParams` so
  `main` onopen picks CPace(pin) vs X3DH-DH.
- **PIN format:** 6-digit numeric default (10⁶ space), room-shared,
  `NFC`-normalized before use as `PRS`.
- **Online-guessing defense (`MAX_PIN_ATTEMPTS = 3`, then exponential backoff).**
  CPace already makes offline dictionary attack impossible; only *online* guessing
  remains, one guess per CPace exchange. The attempt budget is enforced **at the
  honest peer, per room, persisted** (so reconnecting does not refill it) and keyed
  to the **room — NOT the claimed peer identity** (identities are attacker-chosen
  and would reset a per-identity counter). After 3 failed key-confirmations in a
  room, each further CPace attempt in that room backs off exponentially (e.g.
  2ⁿ·base, capped). **Backoff, not a hard lock** — a permanent lock would let one
  malicious peer DoS the room; backoff throttles a guesser to a crawl (~3 fast
  guesses, then rate-limited against 10⁶) while a legitimate user who mistypes
  simply retries. The counter lives with the room's transient PIN state and a
  small persisted `pinAttempts` record (per `roomId`); it clears on a successful
  confirmation or PIN rotation.
- **Failure behavior (no fallback):** wrong/absent PIN, key-confirmation failure,
  DTLS-fingerprint mismatch, or version mismatch → **abort the channel** and
  surface a clear error state. No silent downgrade.

## 8. Persistence & at-rest

New IndexedDB store **`ratchetSessions`**, keyPath `['roomId','peerPublicKey']` —
keyed by the **stable identity edge** (not the per-session `peerId`, which changes
on reconnect) so the ratchet **survives reconnect** (couples to the resume goal).
`dbVersion` **16 → 17** (upgrade is purely additive — the new store's create
branch is the only thing that fires; no migration).

```ts
interface RatchetSession {
  roomId: string; peerPublicKey: string; peerId: string;
  rootKey: ArrayBuffer;
  sendingChainKey: ArrayBuffer | null; receivingChainKey: ArrayBuffer | null;
  dhSelfPub: ArrayBuffer; dhSelfSec: ArrayBuffer; dhRemotePub: ArrayBuffer | null;
  Ns: number; Nr: number; PN: number;
  skippedMessageKeys: Array<{ dhPub: ArrayBuffer; n: number; messageKey: ArrayBuffer }>; // capped MAX_SKIP
  updatedAt: number;
}
```

All secret fields (`rootKey`, chain keys, `dhSelfSec`, skipped keys) are stored
**wrapped**: a single non-extractable AES-GCM `CryptoKey` (generated once,
`extractable:false`) is stored as a `CryptoKey` object in IndexedDB and read back
after refresh to unwrap. Raw key bytes never enter JS. This stops raw-key
export / cross-device copy; it does **not** stop local decryption by an attacker
with device+origin access (documented limit). Live session handle lives on `epc`
(`api/webrtc/interfaces.ts:8`), not Redux. A serializable `pakeVerified` /
`ratchetEstablished` boolean may go on `roomSlice` `Peer` for UI, but **no secret
material in Redux**.

**Reconnect coupling:** on full reconnect `epc` is spliced and rebuilt; continuity
comes from this store — look up by `peerPublicKey`, rebind the new `peerId`; a peer
returning with a new DH pub triggers a normal DH-ratchet step (skipped-key
handling), not stale-chain reuse.

Worker wiring mirrors `fnSetDBChunk`: `getRatchetSession` / `setRatchetSession` /
`deleteRatchetSession` in `db.worker.ts` + `db/api.ts` + `db/types.ts`
(`WorkerMessages`/`WorkerMethodReturnTypes`), each `getDB()`/tx/put|get/`db.close()`.

## 9. WASM additions

Confirmed: Ristretto255 is **not** compiled; X25519/`crypto_kx` are compiled but
**not exported**; blake2b + `crypto_auth_hmacsha512` are compiled.

- **New libsodium sources** → `scripts/paths.js` + emcc set:
  `crypto_core/ed25519/core_ristretto255.c` (from_hash + scalar ops; may pull
  `core_h2c.c`/`core_ed25519.c` — add if the `-O0` dev build reports undefined
  symbols, or rely on `--gc-sections`), and
  `crypto_scalarmult/ristretto255/ref10/scalarmult_ristretto255_ref10.c`.
- **New C wrappers** (`cpace.c`, `ratchet.c`, added to the `libcrypto.c` shim):
  - CPace: `cpace_ristretto255_from_hash`, `cpace_ristretto255_scalarmult`
    (point×scalar, not base), `cpace_ristretto255_scalar_random`.
  - Ratchet DH (export the already-compiled X25519): `x25519_keypair`, `x25519_dh`.
  - KDF: `kdf_rk` / `kdf_ck` — **hand-rolled HKDF-SHA512 on the already-compiled
    `crypto_auth_hmacsha512`** (zero new source; SSOT the KDF labels).
  - AEAD path: `encrypt_chachapoly_symmetric`, `receive_message_with_key`.
- **Exports** added to `scripts/emscripten.js` EXPORTED_FUNCTIONS + `scripts/
  libcrypto.d.ts` (+ the `src/` copies) — forgetting yields silent "function not
  found" at runtime. Regenerate `.tgz`/`lib`; **SRI repin + CDN upload** (wire +
  wasm change → version bump; `npm run predist && npm run uploadcdn`).
- **Heap budget (Risk R3):** `INITIAL_MEMORY=2mb`, `ALLOW_MEMORY_GROWTH=0`,
  `STACK_SIZE=512kb`. The WASM holds **no ratchet state** — the skipped-message-key
  map + all session state live in **JS/IndexedDB**, and WASM only runs a single
  operation at a time (Ristretto/CPace, one KDF, or the AEAD of one 64 KiB chunk),
  so the heap need only fit the **largest single op** (measure via
  `cryptography/memory.ts`; raise `INITIAL_MEMORY` if needed — growth stays off).
  `MAX_SKIP` bounds the **JS-side** skipped-key derivations to stop a malicious
  huge-`N` DoS, not the WASM heap. Confirm the prod `-O3 -flto` build size stays
  in budget.

## 10. SSOT / DRY

- **One ratchet implementation**, seeded by one of two functions.
- **Frame-layout constants live once** in `src/utils/constants.ts`
  (`MESSAGE_START=62` remap, `RATCHET_DHPUB_LEN=32`, `RATCHET_N_LEN=8`,
  `RATCHET_PN_LEN=8`, `RATCHET_NONCE_LEN=12` cleartext random AEAD nonce,
  `PQ_EPOCH_LEN` header marker, `PQ_TAG_LEN` transcript marker)
  and are **byte-matched in `utils.h`** with
  cross-referencing comments both ways (the known C↔TS duplication hazard — a
  mismatch mis-slices chunks silently). A unit test asserts C and TS agree.
- **KDF labels + CPace domain strings** are SSOT constants, byte-matched C↔TS.
- Casual/secure share the identity-mixing + transcript-binding helper (one impl).

## 11. Component breakdown (isolation)

1. **`crypto/cpace.ts` + `cpace.c`** — CPace exchange over Ristretto255. In: PIN,
   `CI`. Out: 32-byte secret. Testable against CPace test vectors.
2. **`crypto/x3dh.ts`** — no-PIN identity-mixed ephemeral DH. In: identity keys,
   ephemerals. Out: 32-byte secret.
3. **`crypto/ratchet.ts` + `ratchet.c`** — the Double Ratchet state machine
   (kdf_rk/kdf_ck, DH step, skipped keys). In: root seed, per-message header. Out:
   message key. Pure, unit-testable in isolation with known vectors.
4. **`handlers/handleHandshake.ts`** — orchestration at `main` onopen: pick mode,
   run exchange, bind DTLS fp, key-confirm, seed ratchet, set `ratchetEstablished`,
   gate/buffer frames.
5. **`db` ratchetSessions store + WebCrypto wrap** — persistence.
6. **message-crypto swap** — sender/receiver injection (§6).
7. **negotiation/version tag + PIN plumbing** (§7).

Each has one purpose, a narrow interface, and is testable without the others.

## 12. Risks (tracked) + decided mitigations

- **R1 — Authentication continuity.** Dropping the signature is a net downgrade
  unless it lands in the *same* release as a mutual-identity-authenticated ratchet,
  and unless *both* seed paths mix *both* identity keys.
  **DECIDED — Atomic drop (option A):** signature removal + authenticated ratchet
  ship together in v3; both modes bind both identity keys; correctness is gated by
  the E2E forgery + MITM-abort tests (§13), not by a redundant signature — which
  preserves deniability. (Rejected: keep-signature = loses deniability + per-chunk
  cost; phased = two wire breaks.)
- **R2 — Async-onopen retrofit + cross-datachannel ordering.** `onopen` is
  synchronous fire-and-forget today; per-message transfers use *separate* data
  channels the sender can blast independently; the inbound classifier is
  length-only (64 B receipt / `MESSAGE_LEN` chunk). Biggest restructuring unknown.
  **DECIDED:** (a) a **1-byte type tag on every data-channel frame** (handshake /
  chunk / receipt) — unambiguous, future-proof, ~free after the 48 B frame
  shrink; (b) the handshake runs **only on the persistent `main` channel**; (c)
  per-message channels **and** the reconnect receipt-replay burst **await a
  per-peer `ratchetEstablished` gate** (a promise `main` resolves — no deadlock,
  since nothing `main` needs depends on the per-message channels); inbound frames
  before the gate opens are buffered on the existing `queue`/`seen`/`drainingRef`
  and drained after.
- **R3 — Persistence + at-rest + reorder.** Persisted secrets are a new at-rest
  surface; retransmit risks nonce reuse; heap budget under a fixed 2 MB WASM.
  **DECIDED:** (a) **at-rest wrap** with a non-extractable WebCrypto key (§8); (b)
  the **skipped-key map + all ratchet state live in JS/IndexedDB, not the WASM
  heap** (WASM runs one op at a time — §9), so `MAX_SKIP` only bounds JS-side
  derivations as an anti-DoS cap; (c) **retransmit resends the CACHED ciphertext**
  (reusing p2party's existing retransmit-from-store model), making nonce reuse
  structurally impossible — never re-encrypt with a fresh nonce, never reuse a
  message key across two logical messages.

## 13. Testing

TDD throughout (`bun test`), plus the real-WebRTC E2E (`p2party.com/e2e/run.mjs`,
headless Chromium, two contexts, local WASM served with matching SRI):
- CPace against published test vectors; ratchet against Signal-style vectors.
- C↔TS constant-agreement unit test.
- E2E: PIN room byte-exact transfer + FS (a captured frame + later state can't
  decrypt); no-PIN room byte-exact + FS; **MITM abort** (inject a swapped
  fingerprint → channel tears down, no data); wrong-PIN → fail closed; reconnect
  mid-transfer resumes the ratchet byte-exact; reload persistence (wrapped state
  unwraps and continues); retransmit determinism; decoy-header indistinguishability.

## 14. Staged implementation (ships atomically as v3)

Design/PR staging for reviewability — but v3 releases **as one wire break** (R1):
1. WASM: Ristretto + X25519 + KDF exports; vectors green.
2. `ratchet.ts`/`cpace.ts`/`x3dh.ts` pure units + vectors.
3. IndexedDB `ratchetSessions` + WebCrypto wrap.
4. Handshake orchestration at `main` onopen (frame tagging, gating).
5. Message-crypto swap + signature drop + frame remap (C+TS lockstep).
6. Version tag + PIN plumbing + failure states.
7. Full E2E; SRI repin + CDN upload; version bump (protocol-v3, e.g. 0.10.0).

## 15. Deferred

- Hybrid PQ KEM *implementation* (v4; structure reserved here).
- Passphrase-KEK at-rest (stronger, but can't survive refresh without re-entry).
- Any v2↔v3 interop.
