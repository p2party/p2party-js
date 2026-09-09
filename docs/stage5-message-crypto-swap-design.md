# Stage 5 — message-crypto swap onto the ratchet (design)

The atomic change that moves the message hot path off the box scheme onto the
handshake-seeded Double Ratchet. **Only fully verifiable under the Stage-7 headless-
Chromium E2E** — but the crypto round-trip + frame codec are unit-testable and should
land green first. Companion: box-removal surface is in
`docs/superpowers/specs/2026-07-22-d2b-x25519-key-separation-design.md` §6.

## THE key subtlety — the ratchet is per-MESSAGE, not per-chunk
`ratchetEncrypt(state, module) → { messageKey, header:{dhPub(32), N, PN} }` and
`ratchetDecrypt(state, header, module) → messageKey` BOTH **mutate** state and advance
the ratchet **once per call** (`ratchet.ts:183,314`). A logical message is chunked into
many `MESSAGE_LEN`(64 KiB) frames. Therefore:
- **SEND:** call `ratchetEncrypt` **ONCE per message** → one `messageKey` + one `header`;
  every chunk of that message reuses the same `messageKey` and the same `header`, with a
  **fresh random 12-byte nonce per chunk**.
- **RECEIVE:** call `ratchetDecrypt` **ONCE per message** (the first-ARRIVING chunk of a
  given `(dhPub, N)`), then **CACHE the `messageKey`** and reuse it for that message's
  remaining chunks. **Calling `ratchetDecrypt` per chunk throws** `"message key already
  consumed"` on the 2nd chunk (`ratchet.ts:337-338`) — this is the #1 bug to avoid.

## Frame layout (replaces the box `MESSAGE_START`=96)
Per the plan Global Constraints (the "50" in the Stage-1 C comment is the stale pre-nonce
fork — use **62**):
```
CHUNK frame = FRAME_TYPE_CHUNK(1) ‖ dhPub(32) ‖ N(8) ‖ PN(8) ‖ PQ_EPOCH(1) ‖ nonce(12) ‖ ciphertext
                                    └──────────── ratchet header ──────────┘   random
MESSAGE_START = 62   (= FRAME_TYPE_LEN 1 + CHUNK_HEADER_LEN 61)
CHUNK_HEADER_LEN = 61 (= DHPUB 32 + N 8 + PN 8 + PQ_EPOCH 1 + NONCE 12)
```
`N`/`PN` are the ratchet counters serialized as 8-byte **big-endian** (they are `number`
in TS but must be a fixed wire width; guard `N,PN < 2^53`). `PQ_EPOCH` = 0 in v3
(reserved). The nonce is `crypto.getRandomValues(12)` per chunk. A retransmit MUST resend
the **identical** cached `(nonce, ciphertext)` pair (never re-encrypt with a new nonce).

## Constants (SSOT: `src/utils/constants.ts`, byte-matched in `src/cryptography/utils.h`)
Add `RATCHET_DHPUB_LEN=32`, `RATCHET_N_LEN=8`, `RATCHET_PN_LEN=8`, `PQ_EPOCH_LEN=1`,
`RATCHET_NONCE_LEN=12`, `CHUNK_HEADER_LEN=61`; change `MESSAGE_START` 96→62. The C-side
`utils.h`/`utils.c` `receive_message_with_key` must read the **cleartext 12-byte nonce**
from the frame (currently an N-derived PLACEHOLDER — see `pake_ratchet.c` ~:148-152) and
`message + MESSAGE_START` for the ciphertext. Rebuild wasm via `npm run prebuild`
(dev)/`predist` (prod) so the SRI in `wasmLoader.ts` re-pins.

## SEND — `handleSendMessage.ts` (currently `:256` `_encrypt_chachapoly_asymmetric`)
1. `await getRatchetGate(peerId)` — do not send until the ratchet is established.
2. Load the peer's `RatchetSession` (`getRatchetSession`), `deserializeRatchet` → state.
3. `const { messageKey, header } = ratchetEncrypt(state, module)` — ONCE for the message.
4. Persist the advanced state immediately (`setRatchetSession(serializeRatchet(state))`) —
   the sending chain advanced; don't lose it on crash.
5. Chunk the message as today (Merkle, metadata, proof). For EACH chunk: fresh random
   nonce; `_encrypt_chachapoly_symmetric(ciphertext_out, chunk_plaintext, messageKey, nonce)`;
   assemble the frame `FRAME_TYPE_CHUNK ‖ header(dhPub,N,PN) ‖ PQ_EPOCH ‖ nonce ‖ ciphertext`.
   Drop the per-chunk ephemeral `_keypair_from_seed` (~:106-136) + the per-chunk `_sign`
   (~:147) — the ratchet + AEAD replace both.
6. `messageKey.fill(0)` after the last chunk.

## RECEIVE — `handleReceiveMessage.ts` (currently `:31` `_receive_message`)
1. Parse the cleartext frame header → `FRAME_TYPE_CHUNK`, `header={dhPub,N,PN}`, `nonce`.
2. **Per-message messageKey cache** keyed by `(dhPub||N)` (a `Map` on the peer/room state,
   or module-level keyed by `peerId+dhPubHex+N`): if MISS, derive it via the
   **clone-rollback-dedup contract** (below) and cache it; if HIT, reuse.
3. `_receive_message_with_key(decrypted_out, frame_ciphertext, /*merkleRoot*/, messageKey)`
   with the chunk's `nonce`; then the existing verify-merkle-proof + receive-time-OPFS-write
   path is UNCHANGED (it operates on the decrypted chunk).
4. **Cache lifecycle:** evict a message's `messageKey` when the message completes (all
   leaf-hashes present) or on a TTL, so the cache can't grow unbounded (a peer could
   otherwise pin keys with never-completing messages — bound it).

### The clone-rollback-dedup contract (Stage-2 Global Constraint — MANDATORY)
`ratchetDecrypt` mutates state BEFORE the AEAD authenticates, so a replayed/old-chain
frame (reachable via our own retransmit layer) would fire a spurious DH-step and desync.
So, to derive a message key for a new `(dhPub,N)`:
1. `clone = deserializeRatchet(serializeRatchet(state))`.
2. Dedup: if `(dhPub,N)` was already seen/consumed for this session, DROP (no re-derive).
3. `messageKey = ratchetDecrypt(clone, header, module)`.
4. Decrypt the chunk with `messageKey` — **only if the AEAD authenticates** do you COMMIT:
   `state = clone`, `setRatchetSession(serializeRatchet(state))`, mark `(dhPub,N)` seen.
   On auth failure, discard `clone` (rollback) — `state` is untouched.

## Then: box FULL REMOVAL (spec §6) + Ed25519-secret at-rest wrap
Once send+receive are on the ratchet (box code now dead), do spec §6's full removal
(`chacha20poly1305.{c,h,ts}`, the wasm `_encrypt/_decrypt_chachapoly_asymmetric` +
`_receive_message` cascade, the `encryptAsymmetric`/`decryptAsymmetric` public API,
`memory.ts` helpers, the `crypto_sign_ed25519_sk/pk_to_curve25519` usage = the LAST
Ed25519→X25519 reuse). **Now** also migrate the **Ed25519 identity secret** into the
WebCrypto wrap (deferred from D2=B because the box scheme read it plaintext; its readers
are gone after removal) — reuse `getWrapKey`/`wrapSecret` + a `meta` record like the
X25519 identity, and make `handleChallenge`/`runHandshake` unwrap it async.

## GOTCHA (Q4) — amend the stale plan first
`docs/superpowers/plans/2026-07-22-pace-ratchet-protocol-v3.md` Stage 5 Task 2 step 7
(~L4708) + exit criteria (~L5367) say to KEEP `_receive_message`/`_decrypt_chachapoly_
asymmetric` compiled "per the contract" — this CONTRADICTS D2=B full removal. Amend it (and
the decision-log D2 "deprecated-in-place" wording) before executing, or an agent following
the plan verbatim will preserve exactly the code this removes.

## Task decomposition (each landable green except the E2E)
1. **Frame codec + constants** (pure, unit-test the pack↔parse round-trip byte-exact):
   the v3 constants + `packChunkFrameHeader`/`parseChunkFrameHeader` helpers. Additive.
2. **C-side nonce read** in `receive_message_with_key` (read the cleartext 12-byte nonce);
   rebuild wasm + KAT.
3. **Send swap** (`handleSendMessage`) + **receive swap** (`handleReceiveMessage`) +
   the messageKey cache + the clone-rollback contract. **Atomic** (both must agree). Unit
   test: message → ratchetEncrypt → chunk-encrypt → parse → ratchetDecrypt → chunk-decrypt
   → byte-exact, incl. a 2+-chunk message proving the per-message cache (not per-chunk).
4. **Box full removal** (spec §6) + Ed25519-secret wrap migration. Atomic with #3's landing.
5. **Stage-7 E2E**: two headless-Chromium contexts, local stack, byte-exact transfer over
   the ratchet, a no-PIN room, resume/reload. THIS is the definition of done → merge.

Keep the adversarial-review gate on #3/#4 (security-critical crypto) — it has caught real
bugs every stage.
