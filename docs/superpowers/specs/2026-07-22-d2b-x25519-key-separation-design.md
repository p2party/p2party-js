# D2=B — dedicated X25519 identity key + codebase-wide key separation — Design

**Date:** 2026-07-22
**Status:** Design — **reviewed** (DRY/SSOT/KISS + security, 2026-07-22; 13 findings
triaged — the cross-sig oracle-collision is fixed in §3.2). Q1 resolved **in-band**
(§5.2). Implementation-ready: D1 `sid` fix → T1–T7 (§12).
**Breaking:** Yes — rides the protocol-v3 wire break (clean cutover, no v2 interop,
self-deployed pre-1.0). Also a **public-API break** (`p2party.encrypt`/`.decrypt`
removed).
**Locked decision:** D2=B (user, 2026-07-22) — dedicated X25519 identity keypair +
Ed25519 cross-signature, full removal of the pre-v3 box scheme.

Related: [[p2party-pace-handshake-plan]], [[p2party-double-ratchet-plan]],
[[p2party-project-overview]], and the protocol-v3 design
(`docs/superpowers/specs/2026-07-22-pace-ratchet-protocol-v3-design.md`). Verify
like a real user against the local stack + headless Chromium E2E per the definition
of done.

---

## 1. Goal & threat-model motivation

Today the codebase reuses **one Ed25519 identity keypair for two incompatible
cryptographic roles**:

1. **Signing** — the login challenge (`handleChallenge.ts`) and (pre-v3) the
   per-chunk transcript signature.
2. **Diffie-Hellman** — the box scheme (`chacha20poly1305.c`) runs
   `crypto_sign_ed25519_sk/pk_to_curve25519` on the Ed25519 identity keys to derive
   an X25519 DH secret, and the no-PIN X3DH path
   (`handleHandshake.ts` runHandshake, ~:507-510) feeds the raw 64-byte Ed25519
   secret **directly** into `x25519Dh` with no conversion at all.

Reusing one key across a signature scheme and a DH scheme is a textbook
cross-protocol footgun: it removes the domain separation that lets each scheme be
analyzed independently, and it entangles the identity key's compromise surface
across both. The no-PIN X3DH instance of it is not merely unsound — it is a **hard
runtime crash**: `x25519Dh` does `new Uint8Array(wasmMemory, skPtr, 32).set(secretKey)`
and `TypedArray.set()` throws a `RangeError` when the 64-byte Ed25519 secret is the
source (confirmed live bug; risk R6 below).

**Goal.** Give the codebase a clean **key separation**: a dedicated random X25519
identity keypair used *only* for DH (X3DH + future ratchet identity mixing), the
Ed25519 identity used *only* for signing, and an Ed25519 **cross-signature** binding
the two so relying parties can trust the X25519 key transitively from the identity
they already anchor on. Deleting the box scheme in the same motion **removes the
last `Ed25519→X25519` conversion call site in the codebase** (grep-confirmed: the
two `crypto_sign_ed25519_*_to_curve25519` calls live only in `chacha20poly1305.c`),
completing the migration off single-key reuse.

**PQ-forward.** Clean key separation is a prerequisite for a hybrid ML-KEM/X-Wing
identity later: the X25519 identity becomes one half of a hybrid identity KEM
without disturbing the Ed25519 signing anchor or forcing a second wire break beyond
v3.

### Threat model after D2=B

- **Single-key reuse across sign+DH:** eliminated. Ed25519 signs; X25519 DHs; never
  the same bytes in both roles.
- **No-PIN X3DH runtime crash + undefined shared secret:** fixed — the DH now runs
  on genuine 32-byte X25519 scalars.
- **Server/peer substituting a peer's X25519 identity:** defeated *up to the same
  bound as the Ed25519 identity trust* — the receiver verifies the Ed25519
  cross-signature over the peer's X25519 pub before any DH, so an attacker who
  cannot forge Ed25519 cannot swap the X25519 key. **This holds only because the
  cross-signature is domain-separated (§3.2):** a *bare* signature would be
  forgeable via the login-challenge signing oracle with no Ed25519 forgery at all.
  (A server that substitutes *both* the Ed25519 pub and a matching cross-sig still
  MITMs a no-PIN room — the acknowledged no-PIN limit, unchanged by D2=B; PIN rooms
  close it via CPace.)

This change does **not** by itself add forward secrecy or PIN authentication — those
are the protocol-v3 ratchet/CPace work. D2=B is the identity-key foundation that
the no-PIN X3DH seed (and later the ratchet identity mixing) stands on.

## 2. Locked decisions (D2=B)

1. **Dedicated X25519 identity keypair, RANDOM** — generated like the current
   Ed25519 identity (`_x25519_keypair`, mirroring `newKeyPair()`'s malloc/copy/zeroFree
   pattern), **not** mnemonic/seed-derived. Rationale: `keyPairFromMnemonic` exists
   but is **not wired to any UI**, so seed-derivation buys nothing today. Revisit
   only if a mnemonic-recovery UI is ever built (logged as a future dilemma, §11).
2. **Ed25519 cross-signs the X25519 pub.** `sign(X25519_pub, Ed25519_secret)` via the
   existing `sign()`; peers verify via the existing `verify()` against the Ed25519
   identity they already carry. This transitively binds the X25519 key to the
   Ed25519 identity that CI already anchors.
3. **No-PIN X3DH uses the dedicated X25519 keys.** `idSelfSec` = own X25519 secret;
   `idPeerPub` = peer's **cross-sig-verified** X25519 pub — replacing the broken
   raw-Ed25519-secret path.
4. **Persist in localStorage** alongside the Ed25519 identity (its own keys), reset
   together with it.
5. **Box scheme REMOVED ENTIRELY in Stage 5** (not deprecated): `encrypt/decrypt_chachapoly_asymmetric`
   (C + wasm exports), `encryptAsymmetric/decryptAsymmetric` (public API + TS
   wrapper), the memory helpers, `handleSendMessage.ts`'s direct call, and — the
   headline — the `crypto_sign_ed25519_sk/pk_to_curve25519` usage vanishes with it.
   Gated on Stage 5 having replaced the send/receive path with ratchet AEAD.
6. **CI stays Ed25519-based** (unchanged). The Ed25519 IK cross-signs the X25519 IK,
   so any session binding the Ed25519 IKs into CI/transcript transitively
   authenticates the cross-signed X25519 IK. A second binding of X25519 into CI
   would be redundant — explicitly NOT done (§5).
7. **v3 clean break.** All peers regenerate identities; existing Ed25519-only users
   generate the X25519 half + cross-sign on upgrade (§8). No box-scheme back-compat
   beyond what the v3 break already assumes.

## 3. New identity model

### 3.1 Generation

- **Primitive:** reuse `x25519Keypair(module)` (`src/cryptography/x25519.ts`) — it
  already calls the compiled `_x25519_keypair` export (32B/32B random keypair,
  identical malloc/free/zeroFree pattern to `ed25519.newKeyPair`). **No new C/WASM
  export is needed** (§6).
- **Friction to resolve (risk R6):** `x25519Keypair` requires a *pre-loaded*
  `LibCrypto` module — unlike `newKeyPair()`, it has no optional-module overload
  that self-loads. Add a thin async wrapper mirroring `newKeyPair()`'s
  optional-`module` + own-memory pattern (loads a module + sizes its own memory when
  none is passed), so the identity-generation call site can call it the same way it
  calls `newKeyPair()` today.
- **Companion memory helper** (`src/cryptography/memory.ts`): if the new wrapper
  self-loads a module rather than sharing the Ed25519 call's, add a small
  `identityX25519KeypairMemory` sizer (à la `newKeyPairMemory` + `memoryLenToPages`)
  for `crypto_scalarmult_curve25519_BYTES + SCALARBYTES` (32+32 B).

### 3.2 Cross-signature

At generation time (whether first-run or upgrade), sign the freshly generated
X25519 **public** key — under a mandatory **domain-separation prefix** — with the
**existing Ed25519 secret** key:

```
identityCrossSignature = sign( IDENTITY_CROSS_SIGN_DOMAIN ‖ X25519_identity_pub, Ed25519_identity_secret )   // 64B sig
```

where `IDENTITY_CROSS_SIGN_DOMAIN = "p2party-x25519-idsig-v1"` is a new SSOT constant
(§9), in the same `p2party-*-v1` family as `CHUNK_AUTH_DOMAIN_BYTES`.

**Why the domain prefix is MANDATORY (SECURITY-1 — must-fix, caught in review).**
A *bare* `sign(X25519_pub, Ed25519_secret)` collides with an existing signing
**oracle**. `handleChallenge.ts` signs a server-supplied login challenge with this
same Ed25519 identity secret, and `handleWebSocketMessage.ts` gates that flow on
`challenge.length === 64` hex = **exactly 32 bytes** — the exact size of an X25519
pub. So a malicious/compromised signaling server sends a **chosen** X25519 pubkey
(whose secret it holds) *as the login challenge* and gets back
`sign(chosen_X25519_pub, victim_Ed25519_secret)` — bit-for-bit a valid
`identityCrossSignature` binding the *attacker's* X25519 key to the *victim's
genuine* Ed25519 identity, defeating the §1 anchoring goal with **no Ed25519
forgery**. This is the exact class of bug the codebase already fixed once
(`CHUNK_AUTH_DOMAIN_BYTES` exists precisely so "a signature harvested from the
raw-nonce server-challenge oracle cannot be replayed as chunk auth"). The domain
prefix makes the cross-sig transcript disjoint from the challenge transcript, so no
oracle output is ever a valid cross-sig. **Defense-in-depth (recommended):** also
give `handleChallenge`'s signed message a fixed distinguishing prefix so the two
`sign()` call sites can never collide even if a third caller appears.

`sign`/`verify` (`src/cryptography/ed25519.ts`) stay generic over message bytes and
need **no change** — the caller prepends the domain label, and both the producer and
every verifier build the same `IDENTITY_CROSS_SIGN_DOMAIN ‖ pub` transcript.
**Ordering dependency (risk R4):** cross-signing requires the Ed25519 secret to
already exist; the generation logic must never regenerate the Ed25519 identity in
the upgrade case (§8).

### 3.3 Persistence (`keyPairSlice.ts` + `keyPairListenerMiddleware.ts`)

State + localStorage hold only Ed25519 identity + challenge material today
(`peerId/challengeId/publicKey/secretKey/challenge/signature`). Extend:

- **`KeyPair` + `SetKeyPair` interfaces** (`keyPairSlice.ts:7-19`): add
  `publicKeyX25519`, `secretKeyX25519`, `identityCrossSignature` (all hex strings).
- **`initialState`** (`:42-43` pattern): read the three new fields from localStorage
  (`localStorage.getItem("publicKeyX25519") ?? ""`, etc.).
- **`setKeyPair` reducer** (`:97-101`): persist the three new fields under
  X25519-**correct** length validation. **Do NOT reuse the existing
  `publicKey.length===64 && secretKey.length===128` check** (Ed25519-specific):
  - X25519 pub = 32 B = **64 hex chars** (same length as an Ed25519 pub — risk R2).
  - X25519 sec = 32 B = **64 hex chars** (NOT 128 like Ed25519 — risk R3; reusing
    `===128` silently rejects every valid X25519 secret).
  - cross-sig = 64 B = **128 hex chars**.
  Because X25519 pub and sec are the *same* hex length, validation must key off
  **field identity**, never length alone (risk R4). Consider validating each of the
  three fields by its own expected length as an internally consistent triple.
- **`resetIdentity` reducer** (`:147-155`): add the three new fields (empty string)
  to the returned all-empty object.
- **Persist branch** (`keyPairListenerMiddleware.ts` `setKeyPair.match`, ~:32-38):
  `localStorage.setItem` the three new keys when the extended action fires.
- **Reset branch** (`resetIdentity.match`, ~:211-219): `localStorage.setItem(...,'')`
  the three new keys alongside the existing six. **Correctness-critical (risk R5):**
  a reset that rotates the Ed25519 identity but leaves the old X25519 pub + its now
  orphaned cross-sig in localStorage produces a **permanently broken cross-sig**
  (signed by an Ed25519 key that no longer matches) — every future no-PIN handshake's
  cross-sig verify fails silently. Both identities must reset atomically. The
  existing sequential non-transactional `setItem('')` writes already have a
  partial-reset crash window; adding three keys widens it (pre-existing in kind, not
  new — flagged, not blocking).
- **At-rest posture (SECURITY-4) + deprecation path:** the X25519 identity **secret**
  is stored in `localStorage` as plaintext hex — the **same** posture as the existing
  Ed25519 identity secret, and weaker than the ratchet session secrets (non-extractable
  WebCrypto wrap, Stage 3). Consistent with the current model, not a regression.
  **Deprecation (planned, NOT in D2=B):** the insecure plaintext-`localStorage` wiring
  is slated to be replaced by wrapping *both* identity secrets under the same Stage-3
  non-extractable WebCrypto key (`getWrapKey`), relocating them from `localStorage`
  into wrapped IndexedDB — a storage dump then yields ciphertext + a non-exportable
  handle, not the key bytes. Best sequenced **after Stage 5** removes the box scheme's
  raw-Ed25519-secret readers (`handleOpenChannel`/`handleMessageQueueing`), which is
  what forces the keys to be plaintext-usable today. Honest limit (as with the ratchet
  keys): non-extractable bars *export*, not *use* — a live same-origin XSS could still
  use the handle mid-session; removing the bytes from JS entirely means moving identity
  sign/DH onto native WebCrypto `CryptoKey`s (off libsodium-WASM), a larger optional
  Level-B step. Logged as a future item (protocol-evolution decision log / roadmap).

### 3.4 Generation / upgrade point (`signalingServerApi.ts` websocketBaseQuery)

`websocketBaseQuery` (~:98-119) is the **sole** lazy identity-generation point: if
no Ed25519 secret is in store/localStorage it calls `newKeyPair()` and dispatches
`setKeyPair`; otherwise it rehydrates. Today it handles three states (present in
store / present in localStorage / absent-or-corrupt). Add a **4th state**:

| State | Ed25519 | X25519 | Action |
|---|---|---|---|
| First run | absent | absent | generate **both**, cross-sign, dispatch extended `setKeyPair` |
| **Upgrade** | present | absent | generate **X25519 only**, cross-sign with the **existing** Ed25519 secret, dispatch extended `setKeyPair` — **never** regenerate Ed25519 |
| Steady state | present | present | rehydrate all fields (no generation) |
| Corrupt | invalid | — | repair as today, regenerating whatever is invalid |

The generation site must obtain/load a `LibCrypto` module (via `wasmLoader`) before
calling the X25519 wrapper, or the wrapper must self-load (§3.1).

### 3.5 Distribution to peers — IN-BAND (superseding the signaling-wire design)

**Per §5.2 (decided in-band), the X25519 pub + cross-sig do NOT travel via
signaling.** The earlier design here — adding `publicKeyX25519`/`identitySignature`
to `RoomPeer`, the `WebSocketMessage*` shapes, `WSPeerConnection`, and the
`api/webrtc/interfaces.ts` companions, and threading a verified value through
discovery → channel open — is **struck**. Net effect on the signaling server:
**unchanged** (risk R1 eliminated).

- The `?publickey=<hex>` param + `handleChallenge.ts` stay **Ed25519-only** (§4),
  exactly as today — the server still learns only the Ed25519 identity, only for
  peerId/challenge.
- The peer's X25519 pub + cross-sig arrive **in the HELLO frame** and are verified
  **inside `performHandshakeCore`** before any DH (§5.2). No `interfaces.ts` /
  `roomSlice` / `handleConnectToPeer` / `api/webrtc` field additions are needed for
  distribution.
- **Post-handshake availability (UNRESOLVED, no consumer today):**
  `performHandshakeCore` returns only `{state, secret}` and `RatchetSession` stores
  only the Ed25519 `peerPublicKey`. If a later consumer needs the verified X25519 pub
  after the handshake, extend the return type or set `epc.withPeerPublicKeyX25519`
  from the **in-band-verified** value at that point — never from signaling.

### 3.6 Reset / identity-change handling

`purgeIdentity`/`purge` (`src/index.ts:747-784`) dispatch `resetIdentity()` and need
**no index.ts code change** — once `keyPairSlice.resetIdentity` (§3.3) and the
middleware reset branch clear the three new fields, purge transitively clears them.
There is currently **no exported way to read/generate the X25519 identity pub or
cross-sig**; if a downstream consumer needs to display/share it (QR / "share my
identity" UX), add a new `index.ts` export then. **Open sub-question Q2 (§11).**

## 4. CI stays Ed25519 — stated explicitly

**No change to `buildChannelInput`/`ChannelInputParams` (`handleHandshake.ts:26-68`)
byte layout or signature.** CI remains:

```
CI = channelId ‖ IK_a ‖ IK_b ‖ fp_a ‖ fp_b ‖ PQ_TAG      // IK_a/IK_b are Ed25519 identity pubs
```

Rationale (locked decision 6): the Ed25519 IK cross-signs the X25519 IK, so any
session that passes CPace channel-binding (PIN) or key-confirmation (both modes)
over a CI/transcript containing the Ed25519 IKs has **transitively authenticated**
the cross-signed X25519 IK. A second, redundant binding of the X25519 pub into CI
buys nothing. `buildChannelInput`'s `ikInitiator`/`ikResponder` stay the **Ed25519**
identity pubs — do **not** also thread X25519 pubs into CI (risk #7 from the map).

`handleChallenge.ts` is likewise **unchanged**: Ed25519 remains the sole identity
proven to and trusted by the signaling server; the X25519 identity is never asserted
to the server, only to peers.

**Conditioned on the cross-sig check landing in the same change (risk R5-CI):** the
"X25519 is transitively bound via cross-sign" argument only holds if the cross-sig
verification (§3.5) actually runs before any secret derived from CI-adjacent
material is trusted. If a future implementer wires CI/runHandshake without the
cross-sig check, CI's Ed25519-only design silently becomes a gap. Keep them in one
change.

**Defense-in-depth option (not required):** the key-confirmation transcript `T`
(`buildTranscript`, `handleHandshake.ts:359-370`) explicitly includes `ekI`/`ekR`
but not the two X25519 IK pubs. Binding the X25519 IK pubs into `T` alongside the
ephemerals would be a cheap belt-and-suspenders improvement. **Open sub-question
Q3 (§11).**

## 5. No-PIN X3DH rewire

### 5.1 The call-site fix (`handleHandshake.ts` runHandshake, ~:507-517)

Replace the broken reads:

```ts
// BEFORE (broken — Ed25519 secret fed into x25519Dh; RangeError + wrong curve):
const { publicKey, secretKey } = store.getState().keyPair;
const amInitiator = publicKey < epc.withPeerPublicKey;      // KEEP (see below)
const idSelfSec = hexToUint8Array(secretKey);               // 64B Ed25519 secret  ✗
const idPeerPub = hexToUint8Array(epc.withPeerPublicKey);   // 32B Ed25519 pub      ✗
```

```ts
// AFTER (D2=B, in-band per §5.2):
const { publicKey, secretKeyX25519, publicKeyX25519, identityCrossSignature } =
  store.getState().keyPair;
const amInitiator = publicKey < epc.withPeerPublicKey;      // UNCHANGED — Ed25519-hex tie-break
const idSelfSec = hexToUint8Array(secretKeyX25519);         // 32B X25519 identity secret  ✓
// idPeerPub is NO LONGER read here — the peer's X25519 pub arrives in the HELLO and
// is cross-sig-verified INSIDE performHandshakeCore (§5.2). runHandshake instead passes:
//   selfIdentityX25519Pub      = hexToUint8Array(publicKeyX25519)
//   selfIdentityCrossSignature = hexToUint8Array(identityCrossSignature)
//   peerIdentityEd25519Pub     = hexToUint8Array(epc.withPeerPublicKey)  // pinned Ed25519 IK
```

- `idSelfSec` = own dedicated X25519 identity secret (new `keyPairSlice` field, §3.3).
- The peer's X25519 pub (`idPeerPub`) is **parsed from the peer's HELLO and
  cross-sig-verified inside `performHandshakeCore`** (§5.2) — never sourced from
  signaling. `runHandshake` supplies only its own key material + the pinned peer
  Ed25519 IK to verify against.
- **`amInitiator` tie-break stays Ed25519-hex** (`publicKey < epc.withPeerPublicKey`)
  — a symmetric deterministic role assignment, not a DH input. **Confirm both peers
  compare the SAME (Ed25519) field.**

`x3dhDeriveSecret` (`src/cryptography/x3dh.ts`) and
`performHandshakeCore`/`HandshakeCoreParams` (`handleHandshake.ts:210-217`, 298-434)
are **already provenance-agnostic** — typed `idSelfSec: Uint8Array` / `idPeerPub:
Uint8Array`, requiring only 32-byte X25519 scalars/points, and their existing tests
(`x3dh.test.ts`, `handleHandshake.test.ts:218-334`) already exercise them
**exclusively with `x25519Keypair(module)`-generated keys**. The target design was
already assumed there; **the bug lives entirely in the `runHandshake` caller.**

### 5.2 In-band exchange + verify the peer cross-sig BEFORE the DH — DECIDED (in-band)

**Decision (user, 2026-07-22): the X25519 pub + cross-sig are exchanged IN-BAND over
the DTLS data channel, never via the signaling server.** The server is a dumb WebRTC
bootstrap and must not carry keys or secrets. This **supersedes** the earlier
"Option A (signaling-relay) recommended" framing — that was a workload judgment, not
a correctness one, and it is rejected on the *don't-trust-the-server* principle.

**Carrier — the HELLO frame.** The peer's X25519 identity pub (32 B) + Ed25519
cross-signature (64 B) are appended to the HELLO frame:

```
HELLO = HS_STEP_HELLO(1) ‖ sid(32) ‖ EK(32) ‖ Y(32) ‖ X25519_id_pub(32) ‖ crossSig(64)
HELLO_LEN: 97 → 193      // +96 B
```

Add **local, non-exported, TS-only** length consts in `handleHandshake.ts`
(`X25519_IDENTITY_PUB_LEN = crypto_scalarmult_curve25519_BYTES` = 32,
`IDENTITY_SIG_LEN = crypto_sign_ed25519_BYTES` = 64) — these are frame offsets, not
the cross-sig *domain* label (the one SSOT constant, §9). Keep `IDENTITY_SIG_LEN`
distinct from `MAC_LEN` even though both are 64 (risk R2). No C-header change.

**Control flow (`performHandshakeCore`).** `idPeerPub` is **removed** as a
`HandshakeCoreParams` input; the core instead gains three params supplied by
`runHandshake`: `selfIdentityX25519Pub` + `selfIdentityCrossSignature` (to send in
its own HELLO) and `peerIdentityEd25519Pub` (already known via
`epc.withPeerPublicKey`, to verify against). After `transport.recv()` parses the
peer's HELLO, the core extracts the two new tail fields and runs

```
verify( IDENTITY_CROSS_SIGN_DOMAIN ‖ peerX25519Pub, peerCrossSig, peerIdentityEd25519Pub )
```

**before** the PIN/no-PIN branch. Only in no-PIN mode does the verified
`peerX25519Pub` become the `idPeerPub` fed to `x3dhDeriveSecret`. On verify failure
it **throws through the existing `try/catch/finally`** — which already does
`secret?.fill(0)` + the `ek.secretKey`/`cpaceScalar` wipe — so it is **fail-closed
for free**, with no new cleanup path. (PIN mode: recommend verifying unconditionally
in both modes; the source does not *mandate* PIN-mode rejection on a bad cross-sig —
see Q3/§4.)

**Fail-closed invariant — single enforcement point (SECURITY-3).** The *only* place
`peerX25519Pub` becomes trusted is immediately after that in-core `verify(...)`;
there is no other path that populates it. A missing/short tail field, a malformed
frame, or a `verify` returning false all throw before any DH — never derive or
persist a secret from an unverified X25519 key.

**Verification anchor (SECURITY-2).** `peerIdentityEd25519Pub` — the key the cross-sig
is checked against — MUST be the independently-pinned Ed25519 IK that also flows into
CI (`epc.withPeerPublicKey`), **not** an Ed25519 value read from the same HELLO that
carries the X25519 key; otherwise an attacker who controls the HELLO supplies both
halves and the check is circular. (Ed25519 IK trust still roots in the existing
`?publickey=`/address-book TOFU path — its own limit, unchanged.)

**Consequence:** the cross-repo signaling dependency (**risk R1) is eliminated** and
**all of §3.5's signaling-wire additions are struck** — zero new `interfaces.ts`
fields, no `api/webrtc` companions, no server change. Because
`runHandshake`/`performHandshakeCore` have **no live callers yet**, this is
reversal-free.

### 5.3 Note on `handleOpenChannel.ts` (still-live box consumer, pre-Stage-5)

`handleOpenChannel.ts` (~:58-59) still feeds the raw Ed25519 pub/secret into the
legacy box scheme via `handleMessageQueueing.ts`. **No change for the
identity-separation work itself** — this whole path is *removed* in Stage 5 (§6),
not modified. Flagged as a coupling constraint: any reshaping of
`keyPair.secretKey`'s semantics/length before Stage 5 lands must not break this
still-live reader of the raw 64-byte Ed25519 secret. D2=B **adds** X25519 fields and
does **not** touch `keyPair.secretKey`, so this constraint is satisfied by
construction.

## 6. Box-scheme full-removal surface (Stage-5-gated)

**Gate:** every deletion here is gated on Stage 5 having migrated the send path
(`handleSendMessage.ts`) onto `_encrypt_chachapoly_symmetric` and the receive path
(`handleReceiveMessage.ts`) onto the already-built, already-tested
`_receive_message_with_key` (`pake_ratchet.c:100`; unit-tested at
`pake_ratchet.test.ts:226,256`). The removal and the rewire must land **atomically**
(same commit/PR) — a partial land breaks `npm run typecheck` and the WASM build, not
just a runtime edge (risk R-atomic).

### 6.1 C sources & headers

| File | Symbol | Action |
|---|---|---|
| `src/cryptography/chacha20poly1305.c` | `encrypt/decrypt_chachapoly_asymmetric` (whole 216-line file) | **Delete file.** Only these two functions live in it; they hold the **only** `crypto_sign_ed25519_sk/pk_to_curve25519` calls in `src/`. |
| `src/cryptography/chacha20poly1305.h` | the two prototypes (whole 35-line file) | **Delete file.** |
| `src/cryptography/libcrypto.c` | `#include "./chacha20poly1305.c"` | **Remove the include line** (the emcc amalgamation unit). |
| `src/cryptography/utils.h` | `#include "chacha20poly1305.h"` (line 4); `receive_message(...)` prototype (~:113-117) | **Remove both.** `utils.h`'s AEAD/sign macros survive via its own `#include "ed25519.h"` (which pulls the libsodium AEAD + sign headers), so the include drop is not a hard break — but don't rely on that coincidence silently (see pake_ratchet note). |
| `src/cryptography/utils.c` | `receive_message()` (~:115-182) | **Delete function.** Its body calls `decrypt_chachapoly_asymmetric(...)` directly (~:138); it cannot compile once that symbol is gone and has no meaningful rewrite (its whole purpose was the box decrypt). Gated on `handleReceiveMessage.ts` being cut over to `_receive_message_with_key` first. |

**Fragile-include note (risk R-include):** `pake_ratchet.h` gets
`crypto_aead_chacha20poly1305_ietf_*` only via a 3-hop chain
(`utils.h → chacha20poly1305.h → libsodium AEAD header`). After the deletion the
chain still resolves (`utils.h → ed25519.h → libsodium AEAD header`, confirmed), so
the build survives — but recommend adding an **explicit** `#include` of the
libsodium AEAD header directly to `pake_ratchet.h` so its symbol needs are
self-declared rather than riding two unrelated files' includes.

### 6.2 WASM export wiring

| File | Symbol | Action |
|---|---|---|
| `scripts/emscripten.js` | `_encrypt_chachapoly_asymmetric` (line 148), `_decrypt_chachapoly_asymmetric` (line 149) | **Remove both** from `EXPORTED_FUNCTIONS`. |
| `scripts/emscripten.js` | `_receive_message` (line 160) | **Remove** — mandatory cascade once `utils.c::receive_message` is deleted, else it's a dangling export referencing a deleted function. **This contradicts the current plan text** (which says keep it) — see §6.7 / risk R-plan. |
| `scripts/libcrypto.d.ts` (**source of truth**) | `_encrypt_chachapoly_asymmetric` (~:34-43), `_decrypt_chachapoly_asymmetric` (~:44-52), `_receive_message` (~:101-107) | **Remove** the signatures. `scripts/emscripten.js:54-56` reads this file and **generates** `src/cryptography/libcrypto.d.ts` verbatim at build time. |
| `src/cryptography/libcrypto.d.ts` (generated) | same three | **No hand-edit.** Re-run `npm run prebuild` to regenerate; do not edit only the generated copy (it gets silently overwritten). |

Keep `_encrypt_chachapoly_symmetric` and `_receive_message_with_key` (the new paths)
and every unrelated export (merkle, argon2, sha512 streaming, CPace/HKDF/ratchet
AEAD, `_x25519_keypair`, `_x25519_dh`, `_sign`, `_verify`, malloc/free) untouched.

### 6.3 TS wrappers, public API, memory sizers, allocators

| File | Symbol | Action |
|---|---|---|
| `src/cryptography/chacha20poly1305.ts` | `encryptAsymmetric` (~:70-238), `decryptAsymmetric` (~:298-455) — whole 456-line file | **Delete file.** Fails typecheck the instant the WASM methods leave `LibCrypto`; must land in the same commit as the export removal. |
| `src/index.ts` | `import { encryptAsymmetric, decryptAsymmetric }` (lines 8-9); export entries `encrypt: encryptAsymmetric` (line 843), `decrypt: decryptAsymmetric` (line 844) | **Remove** import + both export-object entries. **Public-API break** (`p2party.encrypt`/`.decrypt`) — call out in CHANGELOG/release notes (acceptable under the v3 clean break). |
| `src/cryptography/memory.ts` | `encryptAsymmetricMemory` (~:93-112), `decryptAsymmetricMemory` (~:114-131) + their export-object entries (~:231-232) | **Delete both.** |
| `src/cryptography/memory.ts` | `getReceiveMessageMemory` (~:180-223) | **Delete** once `_receive_message` goes (it sizes the old box-receive Ed25519→X25519 scratch; `_receive_message_with_key` needs only a 32B key). Its **6 callers** must repoint at the Stage-5 ratchet-receive memory helper: `api/webrtc/baseQuery.ts:87`, `handleConnectToPeer.ts:54` & `:87`, `handleOpenChannel.ts:63`, `handleWebSocketMessage.ts:522` & `:596`. |
| `src/api/webrtc/index.ts` | `encryptionWasmMemory = cryptoMemory.encryptAsymmetricMemory(CHUNK_LEN, crypto_hash_sha512_BYTES)` (line 41) | **Repoint** at the new (smaller) symmetric-AEAD send-path memory sizer. Variable name/plumbing survives even though its namesake function is deleted — a `_encrypt_chachapoly_asymmetric`-only grep will NOT surface this line (easy to miss). |
| `src/utils/allocators.ts` | `allocateSendMessage()` | **Shrink.** Once the per-chunk ephemeral-Ed25519 pattern is dropped, `ptr1/ptr2/ptr3/ptr5` (ephemeral pub/sec/seed/sig) and `ptr7` (receiver Ed25519 pub) become dead; keep only what the symmetric-AEAD send path needs (chunk/nonce/encrypted/AAD buffers). |

### 6.4 The two direct-wasm call sites (the ones a camelCase grep misses)

| File | Symbol | Action |
|---|---|---|
| `src/handlers/handleSendMessage.ts` | `encryptionModule._encrypt_chachapoly_asymmetric(...)` (line 256, inside `sendChunks()`) | **Replace with `_encrypt_chachapoly_symmetric`** keyed by the per-edge ratchet message key; drop the per-chunk ephemeral `_keypair_from_seed` (~:106-136) + the per-chunk `_sign` transcript (~:147). **Direct wasm call, not the TS wrapper** — grepping `encryptAsymmetric` in this file finds nothing (risk #4). This is the live send path for every chunk of every transfer. Frame-layout remap is Stage-5-owned, adjacent to this. |
| `src/handlers/handleReceiveMessage.ts` | `module._receive_message(decrypted, messageArray, merkleRootArray, senderPublicKeyArray, receiverSecretKeyArray)` (line 31) | **Rewire to `module._receive_message_with_key(decrypted, messageArray, merkleRootArray, messageKeyArray)`** (`pake_ratchet.test.ts` signature); source `messageKeyArray` from the ratchet session. `senderPublicKeyArray`/`receiverSecretKeyArray` params drop. |
| `src/handlers/handleMessageQueueing.ts` | `processMessage()` — threads `senderPublicKeyArray`/`receiverSecretKeyArray`/`receiveMessageModule` to `handleReceiveMessage` (~:83-85 params, :109 call) | **Update signature** to take/thread a `messageKeyArray` (ratchet-derived) instead; drop the `crypto_sign_ed25519_PUBLICKEYBYTES/SECRETKEYBYTES` imports if unused after. |

Two more scratch-allocation sites feed the old `_receive_message` and must rewire to
`messageKeyArray`: `handleOpenChannel.ts` `ptr4/senderPublicKeyArray` (~:291-299) +
`ptr5/receiverSecretKeyArray` (~:301-309), and `handleWebSocketMessage.ts`'s two
near-identical blocks (~:522-566 and ~:596+). These are Stage-5 send/receive-path
work; enumerated here because they are the load-bearing consumers of the doomed
export.

### 6.5 Secondary constant/interface cleanup (careful re-grep, not blind delete)

- `src/cryptography/interfaces.ts`: `crypto_box_x25519_PUBLICKEYBYTES/SECRETKEYBYTES/NONCEBYTES`,
  `crypto_box_poly1305_AUTHTAGBYTES`, `getEncryptedLen()`, `getDecryptedLen()`
  (~:17-23, 51-65) — used **today only** by `chacha20poly1305.ts` + the memory
  helpers. **But** `constants.ts` also imports `getEncryptedLen` /
  `crypto_box_poly1305_AUTHTAGBYTES` for its own `ENCRYPTED_LEN` — so this needs a
  careful re-grep at implementation time, not a blind delete.
- `utils.h`/`utils.c` frame constants (`ENCRYPTED_LEN`, `DECRYPTED_LEN`,
  `MESSAGE_LEN`, `IMPORTANT_DATA_LEN`, `CHUNK_LEN`) are remapped by the Stage-5 v3
  frame work (owned elsewhere). Confirm that remap lands so removing
  `IMPORTANT_DATA_LEN`'s ephemeral-pk/signature terms is safe.

### 6.6 Do NOT touch

Vendored `libsodium/` (keypair.c / crypto_sign_ed25519.h / tests / dist-build defs):
`crypto_sign_ed25519_sk/pk_to_curve25519` are **never separately exported** as wasm
symbols — the only reachable path was via `chacha20poly1305.c`. Once that file is
deleted these primitives become harmlessly unreferenced inside the dependency. **No
libsodium edit.** (Optional, non-required: `crypto_kx.c` / `libsodiumKx1` in
`scripts/paths.js` + emcc set become unreferenced too — `wasm-ld --gc-sections`
dead-strips them regardless, so dropping them is cleanup only, not correctness.)

### 6.7 Plan/decision conflict to resolve (documentation, not code)

The written plan (`docs/superpowers/plans/2026-07-22-pace-ratchet-protocol-v3.md`,
Stage 5 Task 2 step 7 ~line 4708-4709; Stage-5 exit criteria ~line 5367)
**explicitly says to KEEP** `_receive_message` / `_decrypt_chachapoly_asymmetric`
compiled-but-unused "per the contract," and Stage 7 (final release) never revisits
them. As written, v3 would ship with the box scheme, its public API, and the two
`Ed25519→X25519` conversion sites fully intact **forever** — the exact opposite of
D2=B. Supporting docs conflict too:
`docs/protocol-evolution-decision-log.md` D2 section says "deprecated-in-place,
decrypt kept for legacy interop" and "X25519 key seed-derived from the mnemonic" —
**both superseded** by D2=B (full removal; random keypair).
`docs/design-decisions-and-security-findings.md` (lines 84, 233) references
now-to-be-deleted code (historical entries; documentation-currency only).

**Required before Stage 5 execution:** amend Stage 5 Task 2 step 7 + the exit
criteria to **drop** `_encrypt/_decrypt_chachapoly_asymmetric` **and**
`_receive_message` from `EXPORTED_FUNCTIONS` and add the file deletions +
`utils.c::receive_message` removal + `index.ts`/`chacha20poly1305.ts`/`memory.ts`
cleanup as explicit Stage-5 tasks; and add a superseding note to the decision-log D2
section. **Open sub-question Q4 (§11)** — who owns the plan edit.

## 7. WASM / build impact

- **No new export.** `_x25519_keypair`, `_x25519_dh`, `_sign`, `_verify` are already
  declared + exported (both `LibCrypto` interface and `EXPORTED_FUNCTIONS`). D2=B
  needs **zero** new C/WASM symbols — the headline confirmation for the build area.
  `_x25519_keypair` mints the random X25519 identity exactly as
  `_keypair`/`_keypair_from_seed` mints Ed25519.
- **Exports removed:** `_encrypt/_decrypt_chachapoly_asymmetric` (+ `_receive_message`
  cascade) leave `EXPORTED_FUNCTIONS` and `scripts/libcrypto.d.ts` (§6.2). Any
  export-list change changes the wasm bytes → the SHA-384 SRI changes
  unconditionally.
- **SRI/CDN discipline (risk R-SRI):** rebuild **only** via `npm run prebuild` (dev)
  / `npm run predist` (prod) — both run `node scripts/emscripten.js && node
  scripts/updateWasmIntegrity.mjs`, the second re-hashing `libcrypto.wasm` and
  rewriting the literal `integrity: "sha384-…"` in `src/cryptography/wasmLoader.ts`.
  Calling `node scripts/emscripten.js` bare leaves a **stale SRI** and breaks every
  integrity-checked CDN `fetch()` at runtime after deploy.
- **Version + stale fallback:** `wasmLoader.ts:7`'s hardcoded
  `wasmVersion = process.env.P2PARTY_VERSION ?? "0.9.1"` is **already** one release
  behind `package.json` (0.9.2). Bump it together with the version step. The plan
  fixes the v3 release target at **0.10.0**; bump `package.json` 0.9.2 → 0.10.0
  (the CDN object key `@<version>/…` and the `npm pack` tarball name both derive from
  it), then run **predist → dist → uploadcdn** in that order so SRI, CDN key, and the
  shipped tarball's embedded fallback all agree.
- **Typecheck is the safety net:** no existing test references the removed symbols by
  name, so `bun test` won't catch a missed call site — `npm run typecheck` + a full
  `npm run prebuild` (wasm rebuild) are the gates that surface any dangling
  reference, per the project's definition of done.

## 8. Migration

v3 is a **clean wire break** — all peers regenerate identities; there is no
box-scheme back-compat to preserve beyond that.

- **New users:** first-run `websocketBaseQuery` generates **both** identities +
  cross-sign (§3.4 row 1).
- **Existing users (Ed25519-only in localStorage):** on first upgrade run, the **4th
  branch** (§3.4 row 2) generates the **X25519 half only** and cross-signs it with
  the **existing** Ed25519 secret — the Ed25519 identity, peerId, and any address
  book are preserved. No user-visible re-onboarding for the identity itself; the v3
  wire break forces fresh *sessions/ratchets*, not fresh *identities*.
- **Reset/rotation:** `purgeIdentity`/`purge` clear all six existing + three new
  localStorage keys atomically (§3.3, §3.6); a subsequent reconnect regenerates the
  full pair. Never leave a stale X25519 pub + orphaned cross-sig behind (risk R5).

## 9. SSOT / DRY

- **One identity-generation path** — the `websocketBaseQuery` lazy-init point
  (§3.4); no second place mints identities.
- **Cross-sig produced + verified via the single `sign`/`verify`** in
  `ed25519.ts` — no bespoke signing helper.
- **X25519 field names are distinct and never reused** across every state/frame shape
  (risk R2) — one canonical name for the X25519 pub, one for the cross-sig. A generic
  `.length===64` pubkey check can never disambiguate Ed25519 vs X25519 pub — enforce
  by field identity.
- **One new SSOT constant:** `IDENTITY_CROSS_SIGN_DOMAIN_BYTES =
  new TextEncoder().encode("p2party-x25519-idsig-v1")` in `src/utils/constants.ts`,
  in the existing `p2party-*-v1` domain family (alongside `CHUNK_AUTH_DOMAIN_BYTES`,
  `CPACE_DOMAIN`). It is a **TS-only** transcript-domain label — the cross-sig is
  produced/verified entirely in TS via `sign`/`verify`, so **no C-header byte-match
  is required** (unlike `FRAME_TYPE_*`/`PQ_TAG`). Both the producer (§3.2) and every
  verifier (§5.2) prefix it; defined once, referenced everywhere.
- **Byte-lengths reference the existing named constants (SSOT-2)** — use
  `crypto_scalarmult_curve25519_BYTES`/`_SCALARBYTES` (32, `interfaces.ts`) and
  `crypto_sign_ed25519_BYTES` (64) in the new validation + HELLO-layout code, not
  bare `32`/`64`/`128`-hex literals.
- **DRY (fold in during implementation):** factor the "generate X25519 + cross-sign +
  dispatch" sub-sequence shared by the first-run and upgrade branches into one helper
  (DRY-2); one shared X25519-triple length/hex validator used by both the reducer and
  the middleware (DRY-3, DRY-5); centralize the identity `localStorage` key list
  rather than repeating it in four places (DRY-4). Choosing in-band already collapses
  the would-be triplicated signaling-verify (DRY-1/KISS-2) to the single
  in-`performHandshakeCore` check (§5.2).
- **CI/transcript labels otherwise unchanged** — the rest is key-provenance, not
  wire-format.

## 10. Testing

TDD throughout (`bun test`) + the real-WebRTC E2E (headless Chromium, two contexts,
local WASM with matching SRI) per the definition of done.

- **Identity generation/persistence (units):** first-run generates a valid 32B/32B
  X25519 pair + a 64B cross-sig; localStorage round-trips all three; the extended
  `setKeyPair` validator **accepts** a valid X25519 triple and **rejects** a 128-hex
  "secret" (proves the Ed25519 `===128` check was not copied — risk R3).
- **Upgrade branch (unit):** Ed25519-present/X25519-absent state generates X25519
  only, cross-signs with the existing Ed25519 secret, and does **not** regenerate
  Ed25519 (risk R4).
- **Reset atomicity (unit):** `resetIdentity` + middleware clear all nine keys; no
  orphaned cross-sig survives (risk R5).
- **Cross-sig verify (unit):** `verify(IDENTITY_CROSS_SIGN_DOMAIN ‖ peerX25519Pub,
  peerCrossSig, peerEd25519Pub)` passes for a genuine binding; **negative cases
  abort** — forged/mismatched cross-sig, cross-sig checked against the wrong Ed25519
  IK, a substituted X25519 pub with no valid cross-sig, and — **the SECURITY-1
  regression** — a signature **harvested from the login-challenge oracle** (i.e.
  `sign(chosen_pub, victim_secret)` with *no* domain prefix) must **fail** because the
  verifier requires the `IDENTITY_CROSS_SIGN_DOMAIN` prefix. All reject before any DH.
- **runHandshake sourcing (unit/integration):** `idSelfSec`/`idPeerPub` are genuine
  32-byte X25519 scalars from the new identity fields, **not** repurposed Ed25519
  material; `amInitiator` still compares the Ed25519 field on both peers (risk R6).
  Existing `x3dh.test.ts` / `handleHandshake.test.ts` stay green unmodified (they
  already use `x25519Keypair`-generated keys).
- **Box-removal gates:** `npm run typecheck` green (catches every dangling reference)
  + `npm run prebuild` wasm rebuild succeeds (catches C compile breaks from the
  `receive_message`/header cascade). No existing test names the removed symbols, so
  the typecheck + build are the real net.
- **E2E:** a no-PIN room completes a byte-exact transfer end-to-end (proving the
  X3DH seed is now a valid shared secret, not the old crash), and a peer offering an
  X25519 key with a bad cross-sig is rejected (channel does not establish).

## 11. Open sub-questions (for the user)

- **Q1 — RESOLVED (user, 2026-07-22): in-band (HELLO frame).** The X25519 pub +
  cross-sig ride the HELLO frame over the DTLS data channel; the signaling server is
  never trusted with keys/secrets. Risk R1 (cross-repo server relay) is thereby
  **eliminated**; §3.5's signaling-wire additions are struck; §5.2 is the
  implementation.
- **Q2 — export the X25519 identity?** No `index.ts` export currently reads/generates
  the X25519 pub or cross-sig. Is any UX (QR / "share my identity") planned that
  needs it, or is the peer-to-peer signaling exchange the only consumer? (If the
  latter, no new export.)
- **Q3 — bind X25519 IK pubs into the key-confirmation transcript `T`?** Optional
  defense-in-depth (§4). Cheap; not required for correctness given the cross-sig
  check. Include now or leave for later?
- **Q4 — who edits the stale plan/decision docs?** §6.7 — the protocol-v3 plan +
  decision-log D2 section currently instruct the *opposite* of D2=B (keep-compiled,
  seed-derived). They must be amended before Stage 5 executes or an implementer
  following the plan verbatim will preserve exactly the code D2=B deletes.
- **Q5 — mnemonic-derivation revisit trigger.** Locked decision: random X25519
  identity because `keyPairFromMnemonic` is UI-unwired. If a mnemonic-recovery UI is
  ever built, a random X25519 identity is **not** recoverable from the seed — logged
  as a future dilemma. Confirm this is acceptable to defer.

## 12. Task breakdown (bite-sized, TDD-friendly)

Each task is independently testable. Tasks **T1-T7 are D2=B proper** and can land
**before** Stage 5. **T8-T9 are the box removal**, strictly **gated on Stage 5**'s
send/receive rewire and land atomically with it. D2=B sequences **after the D1 `sid`
fix** (independent handshake correctness, no overlap) and provides the identity
substrate that **Task 5** (the first real `runHandshake` caller) and **Stage 5**
consume.

1. **T1 — X25519 identity generator wrapper.** Add the optional-module async wrapper
   over `x25519Keypair` (+ `identityX25519KeypairMemory` if self-loading), mirroring
   `newKeyPair()`. *Test:* returns a valid 32B/32B pair; callable with and without a
   passed module. (§3.1)
2. **T2 — keyPairSlice fields + validation.** Add `publicKeyX25519`/`secretKeyX25519`/
   `identityCrossSignature` to `KeyPair`/`SetKeyPair`/`initialState`/`setKeyPair`
   (X25519-correct lengths) / `resetIdentity`. *Test:* accepts a valid triple,
   rejects a 128-hex secret, round-trips localStorage, reset zeroes all three.
   (§3.3)
3. **T3 — middleware persist + reset.** Persist the three keys on `setKeyPair`; clear
   them on `resetIdentity`. *Test:* localStorage has/loses the three keys; no
   orphaned cross-sig after reset. (§3.3, R5)
4. **T4 — generation/upgrade branch in `websocketBaseQuery`.** Generate both
   (first-run) or X25519-only + cross-sign (upgrade), never regenerate Ed25519;
   dispatch extended `setKeyPair`. *Test:* the 4-state table (§3.4), esp. the upgrade
   row preserving the Ed25519 secret. (§3.4, R4)
5. **T5 — HELLO-frame carrier + cross-sig verify in `performHandshakeCore` (in-band).**
   Append `X25519_id_pub`(32) + `crossSig`(64) to the HELLO layout (HELLO_LEN 97→193,
   local consts); add `selfIdentityX25519Pub`/`selfIdentityCrossSignature`/
   `peerIdentityEd25519Pub` to `HandshakeCoreParams` and **remove `idPeerPub`**; parse
   the peer's two tail fields after `transport.recv()` and
   `verify(IDENTITY_CROSS_SIGN_DOMAIN ‖ pub, sig, peerEd25519Pub)` **before** the
   PIN/no-PIN branch, fail-closed via the existing try/finally. **No signaling /
   `interfaces.ts` change.** *Test:* good binding accepted; forged/mismatched/wrong-IK/
   **oracle-harvested** cross-sig all rejected before any DH. (§5.2, SECURITY-1/2/3)
6. **T6 — runHandshake rewire.** Read `secretKeyX25519`/`publicKeyX25519`/
   `identityCrossSignature` and pass them + the pinned `epc.withPeerPublicKey`
   (Ed25519) into `performHandshakeCore`; **no `idPeerPub` from signaling** (it comes
   from the peer's HELLO — T5). Keep the Ed25519 `amInitiator` tie-break. *Test:* the
   DH inputs are genuine 32B X25519 scalars; existing x3dh/handleHandshake tests stay
   green; a bad-cross-sig peer never reaches the DH. (§5.1, R6)
7. **T7 — CI/transcript confirmation.** Assert `buildChannelInput` stays Ed25519-only
   (no X25519 threaded in); optionally (Q3) bind X25519 IK pubs into `T`. *Test:*
   CI byte layout unchanged. (§4)
8. **T8 — box send/receive rewire (Stage-5-gated, atomic).** `handleSendMessage.ts` →
   `_encrypt_chachapoly_symmetric`; `handleReceiveMessage.ts` →
   `_receive_message_with_key`; `handleMessageQueueing.ts` + the `handleOpenChannel`/
   `handleWebSocketMessage` scratch sites → `messageKeyArray`; `allocateSendMessage`
   shrinks. *Test:* Stage-5 E2E byte-exact transfer. (§6.4)
9. **T9 — box full removal (Stage-5-gated, atomic with T8).** Delete
   `chacha20poly1305.{c,h,ts}`; remove the `libcrypto.c` include, `utils.h` include +
   `receive_message` proto, `utils.c::receive_message`; drop
   `_encrypt/_decrypt_chachapoly_asymmetric` + `_receive_message` from
   `scripts/libcrypto.d.ts` + `EXPORTED_FUNCTIONS`; delete `encryptAsymmetricMemory`/
   `decryptAsymmetricMemory`/`getReceiveMessageMemory` + repoint their callers; remove
   the `index.ts` public exports; add the explicit `pake_ratchet.h` AEAD include;
   re-grep `interfaces.ts` box constants; edit the stale plan/decision docs (Q4).
   *Test:* `npm run typecheck` + `npm run prebuild` green; SRI repin via
   predist; version 0.9.2 → 0.10.0. (§6, §7)

**Sequencing summary:** D1 sid fix → **T1-T7 (D2=B identity separation, no wire
break beyond the additive signaling fields)** → Task 5 wires the first real
`runHandshake` caller (consumes T6) → Stage 5 message-crypto swap **T8** → box full
removal **T9** (atomic with T8) → v3 release (SRI repin, CDN, 0.10.0).
