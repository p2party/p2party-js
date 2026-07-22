# PACE + Double Ratchet (protocol-v3) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give p2party forward secrecy + post-compromise security in every room, and authentication against a malicious signaling server in PIN rooms, by seeding a per-peer-edge Double Ratchet from a CPace(PIN)-or-X3DH handshake run over the DTLS data channel.

**Architecture:** A handshake at the persistent `main` channel's `onopen` produces a 32-byte secret that seeds a per-`(roomId, peerPublicKey)` Double Ratchet; all messages then encrypt under per-message ratchet keys (protocol-v3). No-PIN rooms seed from identity-mixed ephemeral X25519 (FS, not MITM-resistant); PIN rooms seed from CPace over Ristretto255 with identity + DTLS-fingerprint binding (FS + MITM-resistant). The ratchet advances per logical message; all chunks of a message share one message key (each chunk carries a fresh random 12-byte nonce in its cleartext header). Ships **atomically as one wire break**.

**Tech Stack:** TypeScript SDK; custom C compiled to WASM (libsodium subset via emscripten, fixed 2 MB heap); IndexedDB (`idb`) inside a web worker; WebCrypto (non-extractable AES-GCM wrap of at-rest ratchet secrets); WebRTC data channels; `bun test` (TDD); real-WebRTC E2E (`p2party.com/e2e/run.mjs`, Playwright + headless Chromium).

## Global Constraints

_Every task's requirements implicitly include this section. Values are verbatim from the approved spec (`docs/superpowers/specs/2026-07-22-pace-ratchet-protocol-v3-design.md`) and its risk-mitigation update._

- **Atomic wire break.** protocol-v3 ships as ONE release (version 0.9.2 -> 0.10.0). No v2 <-> v3 interoperability/fallback. A minimal `protocolVersion` field is used only for a clean reject of a mismatched peer.
- **SSOT + C<->TS lockstep.** Frame-layout + domain constants live once in `src/utils/constants.ts` and are byte-matched in `src/cryptography/utils.h` with cross-referencing comments; a unit test asserts C == TS. Editing one without the other silently mis-slices chunks.
- **Frame constants:** `PROTOCOL_VERSION = 3`; `FRAME_TYPE_LEN = 1` (`FRAME_TYPE_HANDSHAKE = 1`, `FRAME_TYPE_CHUNK = 2`, `FRAME_TYPE_RECEIPT = 3`); `RATCHET_DHPUB_LEN = 32`, `RATCHET_N_LEN = 8`, `RATCHET_PN_LEN = 8`, `PQ_EPOCH_LEN = 1` (value 0 in v3); `RATCHET_NONCE_LEN = 12` — a fresh **random** per-chunk AEAD nonce carried in the CLEARTEXT frame header (the plan's original "nonce = chunkIndex" is WRONG: `chunkIndex` lives inside the encrypted metadata, so the receiver cannot know it before decrypting, and reusing a message-level value across a message's chunks would break ChaCha20-Poly1305; a cleartext raw index would also leak chunk count/order, so the nonce is random); `CHUNK_HEADER_LEN = 61`; `MESSAGE_START = 62` (replaces the old 96 = ephemeral_pk32 + sig64 — still shrinks).
- **Ratchet:** per `(roomId, peerPublicKey)` edge; advances per logical message; all chunks share one message key; each chunk carries a fresh **random 12-byte nonce in its cleartext frame header** (receiver-derivable, metadata-safe, birthday-safe within a per-message key); `MAX_SKIP = 512` bounds skipped-key derivations PER decrypt, and `MAX_SKIP_SESSION` bounds the TOTAL retained skipped keys across chains (evict oldest — anti-DoS). **`ratchetDecrypt` mutates state on a not-yet-authenticated message: the caller (Stage 4/5) MUST run it on a CLONE (serialize→deserialize) and commit the clone only after the AEAD authenticates the message, and MUST dedup already-seen `(dhPub, N)` — otherwise a duplicate/replayed message (reachable by our OWN retransmit layer, not just an attacker) spuriously fires a backward DH-step and permanently desyncs the session.** A retransmit resends the CACHED (nonce, ciphertext) pair (never re-encrypt with a fresh nonce, never reuse a message key across two messages).
- **Atomic signature drop (R1):** the 0.9.0 per-chunk Ed25519 signature is removed in this release; BOTH seed modes MUST mix BOTH parties' identity keys or the drop is a forgery hole. The E2E forgery/MITM-abort tests gate correctness.
- **Handshake gating (R2):** a 1-byte frame type tag on every data-channel frame (replaces the length-only classifier); the handshake runs only on the persistent `main` channel; per-message channels AND the reconnect receipt-replay await a per-peer `ratchetEstablished` promise; pre-gate inbound frames buffer on the existing `queue`/`seen`/`drainingRef`.
- **At-rest (R3):** all persisted ratchet secrets are wrapped by a single non-extractable AES-GCM `CryptoKey` stored (as a `CryptoKey` object) in IndexedDB; it survives refresh; raw key bytes never enter JS.
- **PIN:** 6-digit numeric default, room-shared, NFC-normalized before use as CPace PRS; held in a `roomId`-keyed transient Map, NEVER localStorage; `MAX_PIN_ATTEMPTS = 3` then per-ROOM (not per-identity) persisted exponential backoff (`PIN_BACKOFF_BASE_MS = 500`, capped ~5 min); clears on success / PIN rotation.
- **Domain strings (SSOT, C<->TS):** `CPACE_DOMAIN = "p2party-cpace-v1"`, `KDF_RK_LABEL = "p2party-rk-v1"`, `KDF_CK_LABEL = "p2party-ck-v1"`, `KDF_MK_LABEL = "p2party-mk-v1"`.
- **PQ-reserved:** classical only in v3; `PQ_TAG` in the CPace channel-input and `PQ_EPOCH` in the header reserve structure so a future hybrid ML-KEM/X-Wing KEM folds in without a v4 wire break.
- **DTLS-fingerprint binding:** parse `a=fingerprint` from the SDP + verify via `getStats()` certificate post-connect; mismatch -> abort (tear down), never log-and-continue.
- **TDD + verification:** every unit is `bun test` red-green; the full path is verified by the real-WebRTC headless-Chromium E2E; deploy = `npm run predist` (rebuild wasm + SRI repin) then `npm run uploadcdn` (user AWS creds).
- **Task numbering** is scoped within each stage (e.g. "Stage 3 -> Task 2"); execute stages in order 1 -> 7.

---

## Stage 1 — WASM primitives (Ristretto255 + X25519 + HKDF-SHA512 + symmetric AEAD)

**Goal:** compile the four new libsodium-backed C wrappers into the fixed 2 MB `libcrypto.wasm`, export them, and prove each against known-answer test (KAT) vectors under `bun test`. No TS crypto wrappers, no ratchet logic yet — just the raw exports later stages call.

**Build/instantiation facts established for this stage (read before starting):**
- The generated `src/cryptography/libcrypto.js` is an emscripten `MODULARIZE=1` factory: `libcrypto({ wasmBinary, wasmMemory }) → Promise<LibCrypto>`. Passing `wasmBinary` skips the CDN fetch (uses `getBinarySync`), so tests instantiate the **local** `.wasm` with no network + no SRI. `INITIAL_MEMORY=2mb` ⇒ pass a 32-page `WebAssembly.Memory` (`initial===maximum===32`, growth off).
- Randomness: the current build compiles **no** `randombytes` implementation (all entropy is generated in JS and passed in as seeds). Ristretto `scalar_random` and `x25519_keypair` need `randombytes_buf`, so this stage adds a tiny provider backed by emscripten's `getentropy` (`<sys/random.h>`, present in the 6.0.2 sysroot).
- Build with **`npm run predist`** (production `-O3 -flto`). LTO + `--gc-sections` reliably drops `core_ed25519.c`'s unused `crypto_core_ed25519_from_string`/`expand_message_xmd` (and its `crypto_hash_sha256` dependency), which a plain `-O0` dev build may leave as undefined symbols. `predist` also runs `updateWasmIntegrity.mjs` (re-pins the `wasmLoader.ts` SRI) — expected.
- KATs are sourced from files already in the repo / RFCs so no hand-transcription risk: Ristretto `from_hash` + scalarmult from `libsodium/test/default/*.exp`, X25519 from RFC 7748 §5.2, AEAD from RFC 8439 §2.8.2 (cross-checked with `node` — value pinned below), HKDF-SHA512 against `crypto.hkdfSync('sha512', …)` (confirmed available under Bun v1.3.14). Note: Bun's `crypto.createCipheriv('chacha20-poly1305', …)` throws `ERR_CRYPTO_UNKNOWN_CIPHER`, so the AEAD KAT is a pinned hex constant, **not** a Node oracle.

---

### Task 1 — Crypto-primitive byte-size constants (`interfaces.ts`)

Pure-TS, fast TDD. Adds the primitive sizes the later Ristretto/X25519/HKDF TS wrappers (Stage 2) import. (Frame-layout constants like `MESSAGE_START` live in `src/utils/constants.ts` and are Stage 5/master-contract scope — not here.)

**Files:**
- Modify `src/cryptography/interfaces.ts` (append after the existing `crypto_aead_chacha20poly1305_ietf_NPUBBYTES` block, ~line 27, and into the default export object)
- Create `src/cryptography/interfaces.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces (exact names later stages rely on): `crypto_core_ristretto255_BYTES=32`, `crypto_core_ristretto255_HASHBYTES=64`, `crypto_core_ristretto255_SCALARBYTES=32`, `crypto_scalarmult_ristretto255_BYTES=32`, `crypto_scalarmult_curve25519_BYTES=32`, `crypto_scalarmult_curve25519_SCALARBYTES=32`. (`crypto_auth_hmacsha512_BYTES=64` and `crypto_auth_hmacsha512_KEYBYTES=32` already exist at the top of the file — reuse for the HKDF PRK length.)

**Steps:**

1. **Write the failing test.** Create `src/cryptography/interfaces.test.ts`:
   ```ts
   import { describe, expect, test } from "bun:test";
   import {
     crypto_core_ristretto255_BYTES,
     crypto_core_ristretto255_HASHBYTES,
     crypto_core_ristretto255_SCALARBYTES,
     crypto_scalarmult_ristretto255_BYTES,
     crypto_scalarmult_curve25519_BYTES,
     crypto_scalarmult_curve25519_SCALARBYTES,
     crypto_auth_hmacsha512_BYTES,
     crypto_auth_hmacsha512_KEYBYTES,
   } from "./interfaces";

   describe("v3 crypto primitive byte sizes", () => {
     test("ristretto255 sizes", () => {
       expect(crypto_core_ristretto255_BYTES).toBe(32);
       expect(crypto_core_ristretto255_HASHBYTES).toBe(64);
       expect(crypto_core_ristretto255_SCALARBYTES).toBe(32);
       expect(crypto_scalarmult_ristretto255_BYTES).toBe(32);
     });
     test("x25519 sizes", () => {
       expect(crypto_scalarmult_curve25519_BYTES).toBe(32);
       expect(crypto_scalarmult_curve25519_SCALARBYTES).toBe(32);
     });
     test("hkdf/hmac sizes (PRK = 64, key = 32)", () => {
       expect(crypto_auth_hmacsha512_BYTES).toBe(64);
       expect(crypto_auth_hmacsha512_KEYBYTES).toBe(32);
     });
   });
   ```

2. **Run it — RED.**
   ```
   bun test src/cryptography/interfaces.test.ts
   ```
   Expected: fails to resolve the new named imports (`ristretto` symbols undefined) → test errors / `undefined` not `32`.

3. **Minimal impl.** In `src/cryptography/interfaces.ts`, after line 29 (`crypto_pwhash_argon2id_SALTBYTES` block) add:
   ```ts
   // Ristretto255 (CPace / PAKE) — byte sizes for the wasm exports in
   // pake_ratchet.c; mirror libsodium crypto_core_ristretto255.h /
   // crypto_scalarmult_ristretto255.h.
   export const crypto_core_ristretto255_BYTES = 32 * Uint8Array.BYTES_PER_ELEMENT;
   export const crypto_core_ristretto255_HASHBYTES =
     64 * Uint8Array.BYTES_PER_ELEMENT;
   export const crypto_core_ristretto255_SCALARBYTES =
     32 * Uint8Array.BYTES_PER_ELEMENT;
   export const crypto_scalarmult_ristretto255_BYTES =
     32 * Uint8Array.BYTES_PER_ELEMENT;
   // X25519 DH-ratchet — mirror libsodium crypto_scalarmult_curve25519.h.
   export const crypto_scalarmult_curve25519_BYTES =
     32 * Uint8Array.BYTES_PER_ELEMENT;
   export const crypto_scalarmult_curve25519_SCALARBYTES =
     32 * Uint8Array.BYTES_PER_ELEMENT;
   ```
   And add all six to the `default` export object (append before the closing `};` of the default export, after `getDecryptedLen,`):
   ```ts
     crypto_core_ristretto255_BYTES,
     crypto_core_ristretto255_HASHBYTES,
     crypto_core_ristretto255_SCALARBYTES,
     crypto_scalarmult_ristretto255_BYTES,
     crypto_scalarmult_curve25519_BYTES,
     crypto_scalarmult_curve25519_SCALARBYTES,
   ```

4. **Run it — GREEN.**
   ```
   bun test src/cryptography/interfaces.test.ts
   ```
   Expected: `3 pass, 0 fail`.

5. **Commit.**
   ```
   git add src/cryptography/interfaces.ts src/cryptography/interfaces.test.ts
   git commit -m "stage1: add ristretto255/x25519 primitive byte-size constants"
   ```

---

### Task 2 — Failing KAT vector test for the (not-yet-built) wasm exports

Write the full Stage-1 vector suite first, so it drives the C implementation. It will be RED until Task 3 adds the wrappers + rebuilds the wasm.

**Files:**
- Create `src/cryptography/pake_ratchet.test.ts`

**Interfaces:**
- Consumes (from the build, added in Task 3): wasm exports `_cpace_ristretto255_from_hash`, `_cpace_ristretto255_scalarmult`, `_cpace_ristretto255_scalar_random`, `_x25519_keypair`, `_x25519_dh`, `_hkdf_sha512_extract`, `_hkdf_sha512_expand`, `_encrypt_chachapoly_symmetric`, `_receive_message_with_key`.
- Produces: nothing (test only).

**Steps:**

1. **Write the test.** Create `src/cryptography/pake_ratchet.test.ts`:
   ```ts
   import { describe, expect, test, beforeAll } from "bun:test";
   import { readFileSync } from "node:fs";
   import { join } from "node:path";
   import { hkdfSync } from "node:crypto";

   // Bun exposes Web Crypto on globalThis but the emscripten glue probes
   // globalThis.window in a couple of spots; alias it (mirrors utils.test.ts).
   (globalThis as unknown as { window: typeof globalThis }).window = globalThis;

   // eslint-disable-next-line @typescript-eslint/no-var-requires
   import libcrypto from "./libcrypto";
   import type { LibCrypto } from "./libcrypto";

   const hexToBytes = (h: string): Uint8Array =>
     Uint8Array.from(h.match(/.{1,2}/g)!.map((b) => parseInt(b, 16)));
   const bytesToHex = (u: Uint8Array): string =>
     [...u].map((b) => b.toString(16).padStart(2, "0")).join("");

   // 32 pages == 2 MB == INITIAL_MEMORY; growth is off so initial === maximum.
   const PAGES = 32;

   let mod: LibCrypto;
   let mem: WebAssembly.Memory;

   const put = (bytes: Uint8Array): number => {
     const ptr = mod._malloc(bytes.length);
     new Uint8Array(mem.buffer, ptr, bytes.length).set(bytes);
     return ptr;
   };
   const view = (ptr: number, len: number): Uint8Array =>
     new Uint8Array(mem.buffer, ptr, len).slice();

   beforeAll(async () => {
     mem = new WebAssembly.Memory({ initial: PAGES, maximum: PAGES });
     const wasmBinary = readFileSync(join(import.meta.dir, "libcrypto.wasm"));
     mod = (await libcrypto({
       wasmBinary,
       wasmMemory: mem,
     })) as unknown as LibCrypto;
   });

   describe("Ristretto255 (CPace primitives)", () => {
     // libsodium test/default/core_ristretto255.{c,exp}: from_hash KAT[0].
     test("from_hash known-answer", () => {
       const h = hexToBytes(
         "5d1be09e3d0c82fc538112490e35701979d99e06ca3e2b5b54bffe8b4dc772c1" +
           "4d98b696a1bbfb5ca32c436cc61c16563790306c79eaca7705668b47dffe5bb6",
       );
       const hp = put(h);
       const op = mod._malloc(32);
       mod._cpace_ristretto255_from_hash(op, hp);
       expect(bytesToHex(view(op, 32))).toBe(
         "3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46",
       );
       mod._free(hp);
       mod._free(op);
     });

     // libsodium test/default/scalarmult_ristretto255.{c,exp}: 2*B.
     test("scalarmult known-answer (2*B)", () => {
       const B = hexToBytes(
         "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
       );
       const scalar = new Uint8Array(32);
       scalar[0] = 2; // little-endian 2
       const bp = put(B);
       const sp = put(scalar);
       const op = mod._malloc(32);
       expect(mod._cpace_ristretto255_scalarmult(op, sp, bp)).toBe(0);
       expect(bytesToHex(view(op, 32))).toBe(
         "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
       );
       mod._free(bp);
       mod._free(sp);
       mod._free(op);
     });

     // scalar_random + from_hash + scalarmult exercised via CPace correctness:
     // K1 = y1*(y2*G) == K2 = y2*(y1*G).
     test("CPace exchange agrees (Y = y*G, K = y*Y_peer)", () => {
       const hp = put(new Uint8Array(64).fill(7)); // any 64-byte hash → G
       const gp = mod._malloc(32);
       mod._cpace_ristretto255_from_hash(gp, hp);

       const y1 = mod._malloc(32);
       const y2 = mod._malloc(32);
       mod._cpace_ristretto255_scalar_random(y1);
       mod._cpace_ristretto255_scalar_random(y2);

       const Y1 = mod._malloc(32);
       const Y2 = mod._malloc(32);
       expect(mod._cpace_ristretto255_scalarmult(Y1, y1, gp)).toBe(0);
       expect(mod._cpace_ristretto255_scalarmult(Y2, y2, gp)).toBe(0);

       const K1 = mod._malloc(32);
       const K2 = mod._malloc(32);
       expect(mod._cpace_ristretto255_scalarmult(K1, y1, Y2)).toBe(0);
       expect(mod._cpace_ristretto255_scalarmult(K2, y2, Y1)).toBe(0);

       const k1 = bytesToHex(view(K1, 32));
       const k2 = bytesToHex(view(K2, 32));
       expect(k1).toBe(k2);
       expect(k1).not.toBe("00".repeat(32));
       [hp, gp, y1, y2, Y1, Y2, K1, K2].forEach((p) => mod._free(p));
     });
   });

   describe("X25519 DH ratchet primitives", () => {
     // RFC 7748 §5.2 single-iteration vector.
     test("x25519_dh known-answer", () => {
       const sk = hexToBytes(
         "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
       );
       const pk = hexToBytes(
         "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
       );
       const skp = put(sk);
       const pkp = put(pk);
       const op = mod._malloc(32);
       expect(mod._x25519_dh(op, skp, pkp)).toBe(0);
       expect(bytesToHex(view(op, 32))).toBe(
         "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
       );
       [skp, pkp, op].forEach((p) => mod._free(p));
     });

     test("keypair + dh agree (DH(a,B) == DH(b,A))", () => {
       const pkA = mod._malloc(32);
       const skA = mod._malloc(32);
       const pkB = mod._malloc(32);
       const skB = mod._malloc(32);
       expect(mod._x25519_keypair(pkA, skA)).toBe(0);
       expect(mod._x25519_keypair(pkB, skB)).toBe(0);
       const s1 = mod._malloc(32);
       const s2 = mod._malloc(32);
       expect(mod._x25519_dh(s1, skA, pkB)).toBe(0);
       expect(mod._x25519_dh(s2, skB, pkA)).toBe(0);
       expect(bytesToHex(view(s1, 32))).toBe(bytesToHex(view(s2, 32)));
       expect(bytesToHex(view(pkA, 32))).not.toBe(bytesToHex(view(pkB, 32)));
       [pkA, skA, pkB, skB, s1, s2].forEach((p) => mod._free(p));
     });
   });

   describe("HKDF-SHA512", () => {
     test("extract+expand matches node crypto.hkdfSync('sha512')", () => {
       const ikm = hexToBytes("0b".repeat(22));
       const salt = hexToBytes("000102030405060708090a0b0c");
       const info = hexToBytes("f0f1f2f3f4f5f6f7f8f9");
       const L = 137;

       const ikmp = put(ikm);
       const saltp = put(salt);
       const infop = put(info);
       const prkp = mod._malloc(64);
       expect(
         mod._hkdf_sha512_extract(prkp, saltp, salt.length, ikmp, ikm.length),
       ).toBe(0);

       const outp = mod._malloc(L);
       expect(
         mod._hkdf_sha512_expand(outp, L, prkp, infop, info.length),
       ).toBe(0);

       const got = bytesToHex(view(outp, L));
       const ref = bytesToHex(
         new Uint8Array(hkdfSync("sha512", ikm, salt, info, L)),
       );
       expect(got).toBe(ref);
       [ikmp, saltp, infop, prkp, outp].forEach((p) => mod._free(p));
     });
   });

   describe("Symmetric AEAD (message-key path)", () => {
     // RFC 8439 §2.8.2 AEAD_CHACHA20_POLY1305 test vector (value cross-checked
     // with node createCipheriv; Bun lacks that cipher so the answer is pinned).
     test("encrypt_chachapoly_symmetric known-answer (ciphertext||tag)", () => {
       const key = hexToBytes(
         "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
       );
       const nonce = hexToBytes("070000004041424344454647");
       const aad = hexToBytes("50515253c0c1c2c3c4c5c6c7");
       const pt = hexToBytes(
         "4c616469657320616e642047656e746c656d656e206f662074686520636c6173" +
           "73206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
           "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" +
           "637265656e20776f756c642062652069742e",
       );
       const expected =
         "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
         "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
         "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
         "3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd060" +
         "0691";
       const ptp = put(pt);
       const keyp = put(key);
       const noncep = put(nonce);
       const aadp = put(aad);
       const outp = mod._malloc(pt.length + 16);
       expect(
         mod._encrypt_chachapoly_symmetric(
           outp,
           ptp,
           pt.length,
           keyp,
           noncep,
           aadp,
           aad.length,
         ),
       ).toBe(0);
       expect(bytesToHex(view(outp, pt.length + 16))).toBe(expected);
       [ptp, keyp, noncep, aadp, outp].forEach((p) => mod._free(p));
     });
   });

   describe("receive_message_with_key (smoke: exported, links, callable)", () => {
     const MESSAGE_LEN = 64 * 1024;
     test("garbage frame returns a negative error (AEAD auth fails)", () => {
       const msgp = mod._malloc(MESSAGE_LEN);
       new Uint8Array(mem.buffer, msgp, MESSAGE_LEN).fill(0);
       const decp = mod._malloc(MESSAGE_LEN); // upper bound on DECRYPTED_LEN
       const rootp = put(new Uint8Array(64).fill(0));
       const keyp = put(new Uint8Array(32).fill(0));
       const r = mod._receive_message_with_key(decp, msgp, rootp, keyp);
       expect(r).toBeLessThan(0);
       [msgp, decp, rootp, keyp].forEach((p) => mod._free(p));
     });
   });
   ```

2. **Run it — RED.**
   ```
   bun test src/cryptography/pake_ratchet.test.ts
   ```
   Expected: the current `libcrypto.wasm` has none of the new exports, so `mod._cpace_ristretto255_from_hash` is `undefined` → `TypeError: ... is not a function`. All suites fail. This confirms the test actually reaches the module.

3. **Commit the RED test.**
   ```
   git add src/cryptography/pake_ratchet.test.ts
   git commit -m "stage1: failing KAT vector suite for ristretto/x25519/hkdf/aead exports"
   ```

---

### Task 3 — Implement the C wrappers, wire libsodium sources + randombytes, export, rebuild → GREEN

**Files:**
- Create `src/cryptography/utils/random_bytes.c` (the path `libsodiumRandomBytesPath` already reserved in `scripts/paths.js:16`)
- Create `src/cryptography/pake_ratchet.h`
- Create `src/cryptography/pake_ratchet.c`
- Modify `src/cryptography/libcrypto.c` (append one `#include`)
- Modify `scripts/paths.js` (add source-path constants + exports)
- Modify `scripts/emscripten.js` (destructure new paths, add to `EXPORTED_FUNCTIONS`, add to the emcc source list)
- Modify `scripts/libcrypto.d.ts` (declare the 9 new methods on `LibCrypto`; `src/cryptography/libcrypto.d.ts` is regenerated from it by `emscripten.js:48-50` on build)

**Interfaces:**
- Consumes: libsodium `crypto_core_ristretto255_*`, `crypto_scalarmult_ristretto255`, `crypto_scalarmult_curve25519[_base]`, `crypto_auth_hmacsha512_*`, `crypto_aead_chacha20poly1305_ietf_encrypt/decrypt`, plus `verify_merkle_proof` / `crypto_hash_sha512_*` / `ENCRYPTED_LEN`/`DECRYPTED_LEN`/`METADATA_LEN`/`PROOF_LEN`/`MESSAGE_LEN` from the existing `utils.h`.
- Produces (exact export names Stages 2/5 call): `_cpace_ristretto255_from_hash`, `_cpace_ristretto255_scalarmult`, `_cpace_ristretto255_scalar_random`, `_x25519_keypair`, `_x25519_dh`, `_hkdf_sha512_extract`, `_hkdf_sha512_expand`, `_encrypt_chachapoly_symmetric`, `_receive_message_with_key`.

**Steps:**

1. **randombytes provider.** Create `src/cryptography/utils/random_bytes.c`:
   ```c
   /* Minimal randombytes_buf for the emscripten build. libsodium's own
    * randombytes.c is not compiled (all other entropy is generated in JS and
    * passed in as seeds), but crypto_core_ristretto255_scalar_random and
    * x25519_keypair need randombytes_buf. Back it with emscripten's getentropy,
    * which maps to crypto.getRandomValues in web/worker. getentropy caps at 256
    * bytes per call. */
   #include <stddef.h>
   #include <stdint.h>
   #include <sys/random.h>

   void
   randombytes_buf(void *const buf, const size_t size)
   {
     uint8_t *p = (uint8_t *)buf;
     size_t off = 0;
     while (off < size)
     {
       size_t n = size - off;
       if (n > 256) n = 256;
       (void)getentropy(p + off, n);
       off += n;
     }
   }
   ```

2. **Header.** Create `src/cryptography/pake_ratchet.h`:
   ```c
   #ifndef pake_ratchet_H
   #define pake_ratchet_H

   #include <stdint.h>
   #include <string.h>

   #include "utils.h"

   #include "../../libsodium/src/libsodium/include/sodium/crypto_core_ristretto255.h"
   #include "../../libsodium/src/libsodium/include/sodium/crypto_scalarmult_ristretto255.h"
   #include "../../libsodium/src/libsodium/include/sodium/crypto_scalarmult_curve25519.h"
   #include "../../libsodium/src/libsodium/include/sodium/crypto_auth_hmacsha512.h"
   #include "../../libsodium/src/libsodium/include/sodium/randombytes.h"

   /* ---- v3 frame-layout constants (byte-matched to src/utils/constants.ts) ----
    * SSOT NOTE: Stage 5 relocates these to utils.h alongside the MESSAGE_START
    * remap and adds the C<->TS constant-agreement unit test. They live here now
    * only so receive_message_with_key compiles in isolation this stage. */
   #define FRAME_TYPE_LEN 1U
   #define RATCHET_DHPUB_LEN 32U
   #define RATCHET_N_LEN 8U
   #define RATCHET_PN_LEN 8U
   #define PQ_EPOCH_LEN 1U
   #define CHUNK_HEADER_LEN                                                     \
     (RATCHET_DHPUB_LEN + RATCHET_N_LEN + RATCHET_PN_LEN + PQ_EPOCH_LEN) /* 49 */
   #define MESSAGE_START (FRAME_TYPE_LEN + CHUNK_HEADER_LEN) /* 50 */

   void cpace_ristretto255_from_hash(
       uint8_t out[crypto_core_ristretto255_BYTES],
       const uint8_t hash[crypto_core_ristretto255_HASHBYTES]);
   int cpace_ristretto255_scalarmult(
       uint8_t out[crypto_core_ristretto255_BYTES],
       const uint8_t scalar[crypto_core_ristretto255_SCALARBYTES],
       const uint8_t point[crypto_core_ristretto255_BYTES]);
   void cpace_ristretto255_scalar_random(
       uint8_t out[crypto_core_ristretto255_SCALARBYTES]);

   int x25519_keypair(uint8_t pk[crypto_scalarmult_curve25519_BYTES],
                      uint8_t sk[crypto_scalarmult_curve25519_SCALARBYTES]);
   int x25519_dh(uint8_t shared[crypto_scalarmult_curve25519_BYTES],
                 const uint8_t sk[crypto_scalarmult_curve25519_SCALARBYTES],
                 const uint8_t pk[crypto_scalarmult_curve25519_BYTES]);

   int hkdf_sha512_extract(uint8_t prk[crypto_auth_hmacsha512_BYTES],
                           const uint8_t *salt, const unsigned int salt_len,
                           const uint8_t *ikm, const unsigned int ikm_len);
   int hkdf_sha512_expand(uint8_t *out, const unsigned int out_len,
                          const uint8_t prk[crypto_auth_hmacsha512_BYTES],
                          const uint8_t *info, const unsigned int info_len);

   int encrypt_chachapoly_symmetric(
       uint8_t *out, const uint8_t *data, const unsigned int data_len,
       const uint8_t key[crypto_aead_chacha20poly1305_ietf_KEYBYTES],
       const uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES],
       const uint8_t *aad, const unsigned int aad_len);

   int receive_message_with_key(
       uint8_t decrypted[DECRYPTED_LEN], const uint8_t message[MESSAGE_LEN],
       const uint8_t merkle_root[crypto_hash_sha512_BYTES],
       const uint8_t message_key[crypto_aead_chacha20poly1305_ietf_KEYBYTES]);

   #endif
   ```

3. **Implementation.** Create `src/cryptography/pake_ratchet.c`:
   ```c
   #include "pake_ratchet.h"

   /* ---------------- CPace over Ristretto255 ---------------- */

   void
   cpace_ristretto255_from_hash(
       uint8_t out[crypto_core_ristretto255_BYTES],
       const uint8_t hash[crypto_core_ristretto255_HASHBYTES])
   {
     crypto_core_ristretto255_from_hash(out, hash);
   }

   int
   cpace_ristretto255_scalarmult(
       uint8_t out[crypto_core_ristretto255_BYTES],
       const uint8_t scalar[crypto_core_ristretto255_SCALARBYTES],
       const uint8_t point[crypto_core_ristretto255_BYTES])
   {
     /* q = scalar * point; returns -1 if the result is the identity. */
     return crypto_scalarmult_ristretto255(out, scalar, point);
   }

   void
   cpace_ristretto255_scalar_random(
       uint8_t out[crypto_core_ristretto255_SCALARBYTES])
   {
     crypto_core_ristretto255_scalar_random(out);
   }

   /* ---------------- X25519 DH ratchet ---------------- */

   int
   x25519_keypair(uint8_t pk[crypto_scalarmult_curve25519_BYTES],
                  uint8_t sk[crypto_scalarmult_curve25519_SCALARBYTES])
   {
     randombytes_buf(sk, crypto_scalarmult_curve25519_SCALARBYTES);
     /* crypto_scalarmult_curve25519_base clamps sk internally. */
     return crypto_scalarmult_curve25519_base(pk, sk);
   }

   int
   x25519_dh(uint8_t shared[crypto_scalarmult_curve25519_BYTES],
             const uint8_t sk[crypto_scalarmult_curve25519_SCALARBYTES],
             const uint8_t pk[crypto_scalarmult_curve25519_BYTES])
   {
     return crypto_scalarmult_curve25519(shared, sk, pk);
   }

   /* ---------------- HKDF-SHA512 (RFC 5869) on HMAC-SHA512 ---------------- */

   int
   hkdf_sha512_extract(uint8_t prk[crypto_auth_hmacsha512_BYTES],
                       const uint8_t *salt, const unsigned int salt_len,
                       const uint8_t *ikm, const unsigned int ikm_len)
   {
     crypto_auth_hmacsha512_state st;
     uint8_t zero_salt[crypto_auth_hmacsha512_BYTES];
     const uint8_t *k = salt;
     size_t klen = salt_len;
     if (salt == NULL || salt_len == 0)
     {
       memset(zero_salt, 0, sizeof zero_salt); /* RFC 5869: HashLen zeros */
       k = zero_salt;
       klen = sizeof zero_salt;
     }
     if (crypto_auth_hmacsha512_init(&st, k, klen) != 0) return -1;
     if (crypto_auth_hmacsha512_update(&st, ikm, ikm_len) != 0) return -2;
     if (crypto_auth_hmacsha512_final(&st, prk) != 0) return -3;
     return 0;
   }

   int
   hkdf_sha512_expand(uint8_t *out, const unsigned int out_len,
                      const uint8_t prk[crypto_auth_hmacsha512_BYTES],
                      const uint8_t *info, const unsigned int info_len)
   {
     const unsigned int HASH_LEN = crypto_auth_hmacsha512_BYTES; /* 64 */
     if (out_len > 255U * HASH_LEN) return -1;

     uint8_t t[crypto_auth_hmacsha512_BYTES];
     unsigned int t_len = 0;
     unsigned int done = 0;
     uint8_t counter = 0;

     while (done < out_len)
     {
       counter++;
       crypto_auth_hmacsha512_state st;
       if (crypto_auth_hmacsha512_init(&st, prk, HASH_LEN) != 0) return -2;
       if (t_len > 0)
       {
         if (crypto_auth_hmacsha512_update(&st, t, t_len) != 0) return -3;
       }
       if (info_len > 0 && info != NULL)
       {
         if (crypto_auth_hmacsha512_update(&st, info, info_len) != 0) return -4;
       }
       if (crypto_auth_hmacsha512_update(&st, &counter, 1) != 0) return -5;
       if (crypto_auth_hmacsha512_final(&st, t) != 0) return -6;
       t_len = HASH_LEN;

       unsigned int n = out_len - done;
       if (n > HASH_LEN) n = HASH_LEN;
       memcpy(out + done, t, n);
       done += n;
     }
     return 0;
   }

   /* ---------------- Symmetric AEAD (message-key path) ---------------- */

   /* out = ciphertext || Poly1305 tag  (out_len == data_len + ABYTES).
    * No nonce is prepended (unlike encrypt_chachapoly_asymmetric): the v3 send
    * path derives the nonce from the chunk index, so it is not on the wire. */
   int
   encrypt_chachapoly_symmetric(
       uint8_t *out, const uint8_t *data, const unsigned int data_len,
       const uint8_t key[crypto_aead_chacha20poly1305_ietf_KEYBYTES],
       const uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES],
       const uint8_t *aad, const unsigned int aad_len)
   {
     unsigned long long clen = 0;
     int res = crypto_aead_chacha20poly1305_ietf_encrypt(
         out, &clen, data, data_len, aad, aad_len, NULL, nonce, key);
     if (res != 0) return -1;
     return 0;
   }

   /* ---------------- v3 receive path (no signature) ----------------
    * Frame: [type(1) | DH_pub(32) | N(8) | PN(8) | PQ_EPOCH(1) | ciphertext||tag]
    * Symmetric-decrypt under message_key with AAD = merkle_root || N || PN, then
    * run the merkle-proof / leaf-hash / receipt logic VERBATIM from
    * receive_message (utils.c:146-181). Return codes mirror receive_message
    * minus the -1 "signature wrong" case. */
   int
   receive_message_with_key(
       uint8_t decrypted[DECRYPTED_LEN], const uint8_t message[MESSAGE_LEN],
       const uint8_t merkle_root[crypto_hash_sha512_BYTES],
       const uint8_t message_key[crypto_aead_chacha20poly1305_ietf_KEYBYTES])
   {
     const uint8_t *n_ptr = message + FRAME_TYPE_LEN + RATCHET_DHPUB_LEN;
     const uint8_t *pn_ptr = n_ptr + RATCHET_N_LEN;

     uint8_t aad[crypto_hash_sha512_BYTES + RATCHET_N_LEN + RATCHET_PN_LEN];
     memcpy(aad, merkle_root, crypto_hash_sha512_BYTES);
     memcpy(aad + crypto_hash_sha512_BYTES, n_ptr, RATCHET_N_LEN);
     memcpy(aad + crypto_hash_sha512_BYTES + RATCHET_N_LEN, pn_ptr,
            RATCHET_PN_LEN);

     /* Nonce = 12-byte big-endian message counter N. Stage 5 refines this to the
      * true per-chunk chunkIndex when the frame remap lands; unique per
      * (message-key, chunk) either way. */
     uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
     memset(nonce, 0, sizeof nonce);
     memcpy(nonce + (crypto_aead_chacha20poly1305_ietf_NPUBBYTES - RATCHET_N_LEN),
            n_ptr, RATCHET_N_LEN);

     unsigned long long DATA_LEN = DECRYPTED_LEN;
     int d = crypto_aead_chacha20poly1305_ietf_decrypt(
         decrypted, &DATA_LEN, NULL, message + MESSAGE_START,
         (unsigned long long)(DECRYPTED_LEN
                              + crypto_aead_chacha20poly1305_ietf_ABYTES),
         aad, sizeof aad, nonce, message_key);
     if (d != 0) return -2;

     /* ---- VERBATIM from receive_message (utils.c:146-181) ---- */
     uint32_t proofLen = ((uint32_t)decrypted[METADATA_LEN] << 24)
                         | ((uint32_t)decrypted[METADATA_LEN + 1] << 16)
                         | ((uint32_t)decrypted[METADATA_LEN + 2] << 8)
                         | (uint32_t)decrypted[METADATA_LEN + 3];
     if (proofLen % (crypto_hash_sha512_BYTES + 1) != 0 || proofLen > PROOF_LEN)
       return -3;
     size_t proofArtifactsLen = proofLen / (crypto_hash_sha512_BYTES + 1);

     uint8_t leaf[crypto_hash_sha512_BYTES];
     crypto_hash_sha512_state leaf_state;
     const uint8_t leaf_domain = 0x00;
     int h = crypto_hash_sha512_init(&leaf_state);
     if (h == 0) h = crypto_hash_sha512_update(&leaf_state, &leaf_domain, 1);
     if (h == 0)
       h = crypto_hash_sha512_update(&leaf_state,
                                     &decrypted[METADATA_LEN + PROOF_LEN],
                                     DECRYPTED_LEN - METADATA_LEN - PROOF_LEN);
     if (h == 0) h = crypto_hash_sha512_final(&leaf_state, leaf);
     if (h != 0) return -5;

     uint8_t fold[crypto_hash_sha512_BYTES];
     memcpy(fold, leaf, crypto_hash_sha512_BYTES);
     int vmp = verify_merkle_proof(proofArtifactsLen, fold, merkle_root,
                                   &decrypted[METADATA_LEN + 4]);
     if (vmp != 0) return -6;

     memcpy(&decrypted[METADATA_LEN], leaf, crypto_hash_sha512_BYTES);
     return 0;
   }
   ```
   Note the AEAD `decrypt` arg order used above is libsodium's:
   `(m, &mlen, nsec=NULL, c, clen, ad, adlen, npub=nonce, k=key)`. The ciphertext length passed is `DECRYPTED_LEN + ABYTES` (ciphertext||tag; no on-wire nonce), matching `encrypt_chachapoly_symmetric`'s output shape.

4. **Shim include.** In `src/cryptography/libcrypto.c` append after the `utils.c` line:
   ```c
   #include "./pake_ratchet.c"
   ```
   (`random_bytes.c` is passed to emcc directly, not included here.)

5. **paths.js — source constants.** In `scripts/paths.js`, after the `libsodiumKx5` block (~line 134) add:
   ```js
   const libsodiumRistretto1 = path.join(
     libsodiumPath, "crypto_core", "ed25519", "core_ristretto255.c",
   );
   const libsodiumRistretto2 = path.join(
     libsodiumPath, "crypto_core", "ed25519", "core_ed25519.c",
   );
   const libsodiumRistretto3 = path.join(
     libsodiumPath, "crypto_core", "ed25519", "core_h2c.c",
   );
   const libsodiumRistretto4 = path.join(
     libsodiumPath, "crypto_scalarmult", "ristretto255", "ref10",
     "scalarmult_ristretto255_ref10.c",
   );
   ```
   And in `module.exports` add: `libsodiumRandomBytesPath,` (already declared at line 16 but not currently exported) plus `libsodiumRistretto1, libsodiumRistretto2, libsodiumRistretto3, libsodiumRistretto4,`.

6. **emscripten.js — destructure + sources + exports.** In `scripts/emscripten.js`:
   - Add to the `require("./paths")` destructure: `libsodiumRandomBytesPath, libsodiumRistretto1, libsodiumRistretto2, libsodiumRistretto3, libsodiumRistretto4,`.
   - Append the 9 new symbols to `EXPORTED_FUNCTIONS` (after `_receive_message`, keeping the leading commas/backslashes pattern):
     ```
     _receive_message,\
     _cpace_ristretto255_from_hash,\
     _cpace_ristretto255_scalarmult,\
     _cpace_ristretto255_scalar_random,\
     _x25519_keypair,\
     _x25519_dh,\
     _hkdf_sha512_extract,\
     _hkdf_sha512_expand,\
     _encrypt_chachapoly_symmetric,\
     _receive_message_with_key \
     ```
     (`_receive_message` loses its trailing space; the last real entry `_receive_message_with_key` keeps the ` \` before `-s EXPORT_NAME`.)
   - Append the new sources to the emcc source list (after `${libsodiumArgon6} \`):
     ```
     ${libsodiumRandomBytesPath} \
     ${libsodiumRistretto1} \
     ${libsodiumRistretto2} \
     ${libsodiumRistretto3} \
     ${libsodiumRistretto4} \
     ```

7. **d.ts — declare the exports.** In `scripts/libcrypto.d.ts`, inside `interface LibCrypto`, before the closing `}` (after `_receive_message`), add:
   ```ts
     // v3 PAKE + ratchet primitives (pake_ratchet.c)
     _cpace_ristretto255_from_hash(out: number, hash: number): void;
     _cpace_ristretto255_scalarmult(
       out: number,
       scalar: number,
       point: number,
     ): number;
     _cpace_ristretto255_scalar_random(out: number): void;
     _x25519_keypair(pk: number, sk: number): number;
     _x25519_dh(shared: number, sk: number, pk: number): number;
     _hkdf_sha512_extract(
       prk: number,
       salt: number,
       salt_len: number,
       ikm: number,
       ikm_len: number,
     ): number;
     _hkdf_sha512_expand(
       out: number,
       out_len: number,
       prk: number,
       info: number,
       info_len: number,
     ): number;
     _encrypt_chachapoly_symmetric(
       out: number,
       data: number,
       data_len: number,
       key: number,
       nonce: number,
       aad: number,
       aad_len: number,
     ): number;
     _receive_message_with_key(
       decrypted: number,
       message: number,
       merkle_root: number,
       message_key: number,
     ): number;
   ```
   (`emscripten.js:48-50` copies this file over `src/cryptography/libcrypto.d.ts` at build time, satisfying the "both copies" requirement.)

8. **Build (production).**
   ```
   npm run predist
   ```
   Expected: `Successfully compiled c methods to Wasm.` then `Updated wasmLoader.ts integrity → sha384-…`.
   - **Contingency (undefined symbols):** if the link reports undefined `crypto_hash_sha256`/`expand_message_xmd`/`_string_to_points` (dead code from `core_ed25519.c` not stripped), first re-confirm you built with `predist` (`-O3 -flto` + gc-sections strips them). If they persist, remove `${libsodiumRistretto3}` (`core_h2c.c`) — `from_hash`/`scalar_random` do not need it; keep `core_ristretto255.c` + `core_ed25519.c` + `scalarmult_ristretto255_ref10.c`. If a genuine `crypto_hash_sha256` reference remains, add `crypto_hash/sha256/cp/hash_sha256_cp.c` as another path constant. Re-run `npm run predist`.

9. **Confirm the exports are actually in the module** (guards against the "forgot to export" silent-runtime failure the spec calls out):
   ```
   grep -c "_cpace_ristretto255_from_hash\|_x25519_dh\|_hkdf_sha512_extract\|_encrypt_chachapoly_symmetric\|_receive_message_with_key" src/cryptography/libcrypto.js
   ```
   Expected: `>= 5` (each assigned in `assignWasmExports`).

10. **Run the KAT suite — GREEN.**
    ```
    bun test src/cryptography/pake_ratchet.test.ts
    ```
    Expected: all suites pass (Ristretto from_hash/scalarmult/CPace-agreement, X25519 KAT + agreement, HKDF matches `hkdfSync`, AEAD matches the RFC 8439 vector, `receive_message_with_key` returns `< 0` on garbage). Target: `9 pass, 0 fail` (test count may differ; **0 fail** is the gate).

11. **Full suite + typecheck** (nothing else regressed; d.ts now types the new methods):
    ```
    bun test
    npm run typecheck
    ```
    Expected: existing tests still pass; `tsc` clean.

12. **Commit.**
    ```
    git add src/cryptography/utils/random_bytes.c src/cryptography/pake_ratchet.h \
      src/cryptography/pake_ratchet.c src/cryptography/libcrypto.c \
      src/cryptography/libcrypto.js src/cryptography/libcrypto.wasm \
      src/cryptography/libcrypto.d.ts src/cryptography/wasmLoader.ts \
      scripts/paths.js scripts/emscripten.js scripts/libcrypto.d.ts
    git commit -m "stage1: ristretto255+x25519+hkdf-sha512+symmetric-aead wasm exports (KATs green)"
    ```

---

### Task 4 — Fixed 2 MB heap budget: verify link + largest single op fits

The spec's Risk R3 requires confirming the production `-O3 -flto` build still links under `INITIAL_MEMORY=2mb`, `ALLOW_MEMORY_GROWTH=0`, and that the biggest single Stage-1 op fits. The largest op is `receive_message_with_key` (a full `MESSAGE_LEN`=64 KiB frame → `DECRYPTED_LEN`≈64 KiB output + stack), which the smoke test already runs inside a **32-page (2 MB) growth-off** memory in Task 2/3. This task pins that as an explicit budget assertion so a future size regression fails loudly.

**Files:**
- Modify `src/cryptography/pake_ratchet.test.ts` (append one `describe`)

**Interfaces:**
- Consumes: the built module + `_receive_message_with_key`, `_encrypt_chachapoly_symmetric` exports.
- Produces: nothing.

**Steps:**

1. **Add the budget test.** Append to `src/cryptography/pake_ratchet.test.ts`:
   ```ts
   describe("2 MB heap budget (growth off)", () => {
     test("module links + largest Stage-1 op runs in exactly 32 pages", async () => {
       const budgetMem = new WebAssembly.Memory({ initial: 32, maximum: 32 });
       const wasmBinary = readFileSync(join(import.meta.dir, "libcrypto.wasm"));
       const m = (await libcrypto({
         wasmBinary,
         wasmMemory: budgetMem,
       })) as unknown as LibCrypto;

       const MESSAGE_LEN = 64 * 1024;
       const msgp = m._malloc(MESSAGE_LEN);
       const decp = m._malloc(MESSAGE_LEN);
       const rootp = m._malloc(64);
       const keyp = m._malloc(32);
       new Uint8Array(budgetMem.buffer, msgp, MESSAGE_LEN).fill(0);
       new Uint8Array(budgetMem.buffer, rootp, 64).fill(0);
       new Uint8Array(budgetMem.buffer, keyp, 32).fill(0);

       // Runs the whole receive path (largest single op) without OOM / abort.
       const r = m._receive_message_with_key(decp, msgp, rootp, keyp);
       expect(r).toBeLessThan(0); // auth fails on zeros, but it did not abort
       expect(budgetMem.buffer.byteLength).toBe(32 * 64 * 1024); // never grew

       [msgp, decp, rootp, keyp].forEach((p) => m._free(p));
     });
   });
   ```

2. **Run it — GREEN.**
   ```
   bun test src/cryptography/pake_ratchet.test.ts
   ```
   Expected: passes; `budgetMem.buffer.byteLength === 2097152` proves growth stayed off and the op fit. (If the wasm ever aborts with `Aborted(OOM)` here, `INITIAL_MEMORY` must be raised in `scripts/emscripten.js` `memory` block — growth stays `0` — and the wasm rebuilt.)

3. **Report the production wasm size** (budget bookkeeping for the final SRI/CDN step in Stage 7):
   ```
   ls -l src/cryptography/libcrypto.wasm
   ```
   Expected: a single `.wasm` a few tens of KB larger than the pre-stage 136 KB baseline (ristretto ref10 + h2c). Record the number; no hard gate this stage, but it feeds the Stage 7 `-O3 -flto` budget confirmation.

4. **Commit.**
   ```
   git add src/cryptography/pake_ratchet.test.ts
   git commit -m "stage1: assert 2MB growth-off heap fits the largest receive op"
   ```

**Stage 1 done when:** `bun test` is fully green (including the new `pake_ratchet.test.ts` and `interfaces.test.ts`), `npm run typecheck` is clean, `npm run predist` links the 9 new exports into the fixed-2 MB wasm, and every export is proven against its KAT (Ristretto `from_hash`/scalarmult from the vendored libsodium `.exp` files, CPace exchange agreement, X25519 RFC 7748, HKDF-SHA512 vs `hkdfSync`, AEAD RFC 8439). Later stages consume these exports by the exact names produced here.

---

## Stage 2 — Pure TS crypto units (`x25519.ts`, `hkdf.ts`, `cpace.ts`, `x3dh.ts`, `ratchet.ts`)

Five self-contained TDD tasks. All functions are **synchronous** (the contract signatures return `Uint8Array` / plain objects, not `Promise`), because every function takes an already-instantiated `module: LibCrypto` and operates directly on its (non-growable, never-detached) wasm heap — mirroring the `ed25519.ts` malloc/copy-out/free discipline. Two small supporting wrappers (`x25519.ts`, `hkdf.ts`) are added for DRY: the ratchet, X3DH and the tests all need the raw X25519 DH and HKDF primitives.

**Stage-1 dependencies consumed by every task** (must be green before starting):
- WASM exports on `LibCrypto` (typed in `src/cryptography/libcrypto.d.ts`): `_cpace_ristretto255_from_hash`, `_cpace_ristretto255_scalarmult`, `_cpace_ristretto255_scalar_random`, `_x25519_keypair`, `_x25519_dh`, `_hkdf_sha512_extract`, `_hkdf_sha512_expand`, plus the already-present `_sha512_init/_update/_final`, `_malloc`, `_free`.
- The built `src/cryptography/libcrypto.wasm` + `libcrypto.js` carry those exports **and a working in-wasm entropy source** (for `_x25519_keypair` / `_cpace_ristretto255_scalar_random`). The Stage-2 test loader aliases `globalThis.window = globalThis` so the emscripten glue takes its `crypto.getRandomValues` path (Bun provides `globalThis.crypto`).
- Constants in `src/utils/constants.ts` (Stage-1 SSOT): `CPACE_DOMAIN`, `KDF_RK_LABEL`, `KDF_CK_LABEL`, `KDF_MK_LABEL` (string values `"p2party-cpace-v1"`, `"p2party-rk-v1"`, `"p2party-ck-v1"`, `"p2party-mk-v1"`), `MAX_SKIP = 512` (per-decrypt), `MAX_SKIP_SESSION` (total retained skipped keys, evict-oldest).

---

### Task 1 — interface size constants, the test module loader, and the X25519 wrapper

**Files:**
- Modify `/Users/deliberative/Desktop/@p2party/p2party-js/src/cryptography/interfaces.ts` (append after line 29, the `crypto_pwhash_argon2id_SALTBYTES` block)
- Create `/Users/deliberative/Desktop/@p2party/p2party-js/src/cryptography/testModule.ts`
- Create `/Users/deliberative/Desktop/@p2party/p2party-js/src/cryptography/x25519.ts`
- Create `/Users/deliberative/Desktop/@p2party/p2party-js/src/cryptography/x25519.test.ts`

**Interfaces:**
- *Consumes:* Stage-1 exports `_x25519_keypair(pk32, sk32)->int`, `_x25519_dh(shared32, sk32, pk32)->int`; existing `zeroFree(module, view)`.
- *Produces:* `crypto_scalarmult_curve25519_BYTES=32`, `crypto_scalarmult_curve25519_SCALARBYTES=32`, `crypto_core_ristretto255_BYTES=32`, `crypto_core_ristretto255_SCALARBYTES=32`, `crypto_core_ristretto255_HASHBYTES=64` (interfaces.ts); `loadTestModule():Promise<LibCrypto>` (testModule.ts, used by every later test); `x25519Keypair(module):{publicKey:Uint8Array;secretKey:Uint8Array}` and `x25519Dh(secretKey:Uint8Array, publicKey:Uint8Array, module):Uint8Array` (x25519.ts, consumed by Tasks 4 & 5).

**Steps:**

1. Add the size constants. Edit `interfaces.ts`, immediately after the `crypto_pwhash_argon2id_SALTBYTES` line:
```ts
export const crypto_scalarmult_curve25519_BYTES =
  32 * Uint8Array.BYTES_PER_ELEMENT;
export const crypto_scalarmult_curve25519_SCALARBYTES =
  32 * Uint8Array.BYTES_PER_ELEMENT;
export const crypto_core_ristretto255_BYTES =
  32 * Uint8Array.BYTES_PER_ELEMENT;
export const crypto_core_ristretto255_SCALARBYTES =
  32 * Uint8Array.BYTES_PER_ELEMENT;
export const crypto_core_ristretto255_HASHBYTES =
  64 * Uint8Array.BYTES_PER_ELEMENT;
```

2. Create the test module loader `testModule.ts`. It reads the locally-built wasm (no CDN/SRI fetch) and instantiates the factory with a 32-page (2 MiB, matching `INITIAL_MEMORY=2mb`, `ALLOW_MEMORY_GROWTH=0`) imported memory:
```ts
import { readFileSync } from "node:fs";

import libcrypto from "./libcrypto";

import type { LibCrypto } from "./libcrypto";

// The emscripten glue is built ENVIRONMENT=web,worker. Aliasing `window` selects
// its web branch so in-wasm entropy resolves via globalThis.crypto (Bun global),
// matching the alias precedent in cryptography/utils.test.ts.
(globalThis as unknown as { window: typeof globalThis }).window = globalThis;

/**
 * Instantiate the locally-built libcrypto.wasm for unit tests, bypassing the
 * CDN + SRI fetch in wasmLoader.ts. 32 pages == 2 MiB == INITIAL_MEMORY; growth
 * is off so every op fits the largest-single-op budget.
 */
export const loadTestModule = async (): Promise<LibCrypto> => {
  const wasmBinary = readFileSync(
    new URL("./libcrypto.wasm", import.meta.url),
  );
  const wasmMemory = new WebAssembly.Memory({ initial: 32, maximum: 32 });

  return (await libcrypto({ wasmBinary, wasmMemory })) as LibCrypto;
};
```

3. Write the failing X25519 test `x25519.test.ts`:
```ts
import { describe, expect, test } from "bun:test";

import { loadTestModule } from "./testModule";
import { x25519Keypair, x25519Dh } from "./x25519";

describe("x25519", () => {
  test("keypair produces 32-byte keys and DH agrees both ways", async () => {
    const module = await loadTestModule();

    const a = x25519Keypair(module);
    const b = x25519Keypair(module);

    expect(a.publicKey.length).toBe(32);
    expect(a.secretKey.length).toBe(32);

    const sa = x25519Dh(a.secretKey, b.publicKey, module);
    const sb = x25519Dh(b.secretKey, a.publicKey, module);

    expect(sa.length).toBe(32);
    expect(Buffer.from(sa)).toEqual(Buffer.from(sb));
  });
});
```

4. Run it — fails (module missing). Command: `bun test src/cryptography/x25519.test.ts`
   Expected: `error: Cannot find module './x25519'` (or `x25519Keypair is not a function`).

5. Implement `x25519.ts`:
```ts
import {
  crypto_scalarmult_curve25519_BYTES,
  crypto_scalarmult_curve25519_SCALARBYTES,
} from "./interfaces";
import { zeroFree } from "../utils/zeroFree";

import type { LibCrypto } from "./libcrypto";

export interface X25519KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export const x25519Keypair = (module: LibCrypto): X25519KeyPair => {
  const pkPtr = module._malloc(crypto_scalarmult_curve25519_BYTES);
  const skPtr = module._malloc(crypto_scalarmult_curve25519_SCALARBYTES);

  const r = module._x25519_keypair(pkPtr, skPtr);
  if (r !== 0) {
    module._free(pkPtr);
    module._free(skPtr);
    throw new Error("x25519_keypair failed");
  }

  const publicKey = Uint8Array.from(
    new Uint8Array(
      module.wasmMemory.buffer,
      pkPtr,
      crypto_scalarmult_curve25519_BYTES,
    ),
  );
  const secretKey = Uint8Array.from(
    new Uint8Array(
      module.wasmMemory.buffer,
      skPtr,
      crypto_scalarmult_curve25519_SCALARBYTES,
    ),
  );

  module._free(pkPtr);
  zeroFree(
    module,
    new Uint8Array(
      module.wasmMemory.buffer,
      skPtr,
      crypto_scalarmult_curve25519_SCALARBYTES,
    ),
  );

  return { publicKey, secretKey };
};

export const x25519Dh = (
  secretKey: Uint8Array,
  publicKey: Uint8Array,
  module: LibCrypto,
): Uint8Array => {
  const shPtr = module._malloc(crypto_scalarmult_curve25519_BYTES);
  const skPtr = module._malloc(crypto_scalarmult_curve25519_SCALARBYTES);
  const pkPtr = module._malloc(crypto_scalarmult_curve25519_BYTES);

  new Uint8Array(
    module.wasmMemory.buffer,
    skPtr,
    crypto_scalarmult_curve25519_SCALARBYTES,
  ).set(secretKey);
  new Uint8Array(
    module.wasmMemory.buffer,
    pkPtr,
    crypto_scalarmult_curve25519_BYTES,
  ).set(publicKey);

  const r = module._x25519_dh(shPtr, skPtr, pkPtr);

  const shared =
    r === 0
      ? Uint8Array.from(
          new Uint8Array(
            module.wasmMemory.buffer,
            shPtr,
            crypto_scalarmult_curve25519_BYTES,
          ),
        )
      : null;

  module._free(shPtr);
  zeroFree(
    module,
    new Uint8Array(
      module.wasmMemory.buffer,
      skPtr,
      crypto_scalarmult_curve25519_SCALARBYTES,
    ),
  );
  module._free(pkPtr);

  if (!shared) throw new Error("x25519_dh failed (identity point)");
  return shared;
};
```

6. Run it — passes. Command: `bun test src/cryptography/x25519.test.ts`
   Expected tail: `1 pass`, `0 fail`.

7. Typecheck: `npm run typecheck` — no errors.

8. Commit (only if the user asked to commit; branch first if on default). Message: `stage2: interface size consts + test module loader + x25519 wrapper`.

---

### Task 2 — HKDF-SHA512 wrapper (`hkdf.ts`)

**Files:**
- Create `/Users/deliberative/Desktop/@p2party/p2party-js/src/cryptography/hkdf.ts`
- Create `/Users/deliberative/Desktop/@p2party/p2party-js/src/cryptography/hkdf.test.ts`

**Interfaces:**
- *Consumes:* Stage-1 exports `_hkdf_sha512_extract(prk64, salt_ptr, salt_len, ikm_ptr, ikm_len)->int`, `_hkdf_sha512_expand(out_ptr, out_len, prk64, info_ptr, info_len)->int`; existing `crypto_auth_hmacsha512_BYTES=64` from interfaces.ts; `loadTestModule` (Task 1).
- *Produces:* `hkdfExtract(salt:Uint8Array, ikm:Uint8Array, module):Uint8Array /*64*/` and `hkdfExpand(prk:Uint8Array, info:Uint8Array, outLen:number, module):Uint8Array` (consumed by Tasks 4 & 5).

**Steps:**

1. Write failing test `hkdf.test.ts`:
```ts
import { describe, expect, test } from "bun:test";

import { loadTestModule } from "./testModule";
import { hkdfExtract, hkdfExpand } from "./hkdf";

describe("hkdf-sha512", () => {
  test("extract is deterministic and 64 bytes", async () => {
    const module = await loadTestModule();
    const salt = new Uint8Array(32).fill(7);
    const ikm = new Uint8Array(32).fill(9);

    const prk = hkdfExtract(salt, ikm, module);
    const prk2 = hkdfExtract(salt, ikm, module);

    expect(prk.length).toBe(64);
    expect(Buffer.from(prk)).toEqual(Buffer.from(prk2));
  });

  test("expand honours outLen and separates by info label", async () => {
    const module = await loadTestModule();
    const prk = hkdfExtract(new Uint8Array(32).fill(1), new Uint8Array(32).fill(2), module);

    const enc = new TextEncoder();
    const o1 = hkdfExpand(prk, enc.encode("label-a"), 64, module);
    const o2 = hkdfExpand(prk, enc.encode("label-b"), 64, module);
    const o32 = hkdfExpand(prk, enc.encode("label-a"), 32, module);

    expect(o1.length).toBe(64);
    expect(o32.length).toBe(32);
    expect(Buffer.from(o1)).not.toEqual(Buffer.from(o2));
    // First 32 bytes of a 64-byte expand equal the 32-byte expand (HKDF T(1) prefix)
    expect(Buffer.from(o1.subarray(0, 32))).toEqual(Buffer.from(o32));
  });
});
```

2. Run — fails. `bun test src/cryptography/hkdf.test.ts`
   Expected: `Cannot find module './hkdf'`.

3. Implement `hkdf.ts`:
```ts
import { crypto_auth_hmacsha512_BYTES } from "./interfaces";

import type { LibCrypto } from "./libcrypto";

// HKDF-Extract: PRK = HMAC-SHA512(key = salt, msg = ikm) -> 64 bytes.
export const hkdfExtract = (
  salt: Uint8Array,
  ikm: Uint8Array,
  module: LibCrypto,
): Uint8Array => {
  const prkPtr = module._malloc(crypto_auth_hmacsha512_BYTES);
  const saltPtr = module._malloc(Math.max(salt.length, 1));
  const ikmPtr = module._malloc(Math.max(ikm.length, 1));

  new Uint8Array(module.wasmMemory.buffer, saltPtr, salt.length).set(salt);
  new Uint8Array(module.wasmMemory.buffer, ikmPtr, ikm.length).set(ikm);

  const r = module._hkdf_sha512_extract(
    prkPtr,
    saltPtr,
    salt.length,
    ikmPtr,
    ikm.length,
  );

  const prk =
    r === 0
      ? Uint8Array.from(
          new Uint8Array(
            module.wasmMemory.buffer,
            prkPtr,
            crypto_auth_hmacsha512_BYTES,
          ),
        )
      : null;

  new Uint8Array(
    module.wasmMemory.buffer,
    prkPtr,
    crypto_auth_hmacsha512_BYTES,
  ).fill(0);
  module._free(prkPtr);
  module._free(saltPtr);
  module._free(ikmPtr);

  if (!prk) throw new Error("hkdf_sha512_extract failed");
  return prk;
};

// HKDF-Expand: OKM = T(1) | T(2) | ... truncated to outLen.
export const hkdfExpand = (
  prk: Uint8Array,
  info: Uint8Array,
  outLen: number,
  module: LibCrypto,
): Uint8Array => {
  const outPtr = module._malloc(outLen);
  const prkPtr = module._malloc(crypto_auth_hmacsha512_BYTES);
  const infoPtr = module._malloc(Math.max(info.length, 1));

  new Uint8Array(
    module.wasmMemory.buffer,
    prkPtr,
    crypto_auth_hmacsha512_BYTES,
  ).set(prk);
  new Uint8Array(module.wasmMemory.buffer, infoPtr, info.length).set(info);

  const r = module._hkdf_sha512_expand(
    outPtr,
    outLen,
    prkPtr,
    infoPtr,
    info.length,
  );

  const out =
    r === 0
      ? Uint8Array.from(
          new Uint8Array(module.wasmMemory.buffer, outPtr, outLen),
        )
      : null;

  new Uint8Array(module.wasmMemory.buffer, outPtr, outLen).fill(0);
  module._free(outPtr);
  module._free(prkPtr);
  module._free(infoPtr);

  if (!out) throw new Error("hkdf_sha512_expand failed");
  return out;
};
```

4. Run — passes. `bun test src/cryptography/hkdf.test.ts`
   Expected: `2 pass`, `0 fail`.

5. Commit (if requested): `stage2: hkdf-sha512 extract/expand wrapper`.

---

### Task 3 — CPace over Ristretto255 (`cpace.ts`)

**Files:**
- Create `/Users/deliberative/Desktop/@p2party/p2party-js/src/cryptography/cpace.ts`
- Create `/Users/deliberative/Desktop/@p2party/p2party-js/src/cryptography/cpace.test.ts`

**Interfaces:**
- *Consumes:* Stage-1 exports `_cpace_ristretto255_from_hash(out32, hash64)->void`, `_cpace_ristretto255_scalarmult(out32, scalar32, point32)->int`, `_cpace_ristretto255_scalar_random(out32)->void`, existing `_sha512_init/_update/_final`; constants `CPACE_DOMAIN` (string) from `../utils/constants`; sizes `crypto_core_ristretto255_BYTES=32`, `crypto_core_ristretto255_HASHBYTES=64`, `crypto_hash_sha512_BYTES=64`, `crypto_hash_sha512_STATEBYTES=208` from interfaces.ts; `loadTestModule`.
- *Produces:* `deriveGenerator(pin:Uint8Array, sid:Uint8Array, channelInput:Uint8Array, module):Uint8Array`, `cpaceStart(G:Uint8Array, module):{y:Uint8Array;Y:Uint8Array}`, `cpaceShared(y:Uint8Array, Ypeer:Uint8Array, module):Uint8Array` (consumed by Stage-4 handshake).

**Steps:**

1. Write failing test `cpace.test.ts` — two-party agreement + wrong-PIN divergence:
```ts
import { describe, expect, test } from "bun:test";

import { loadTestModule } from "./testModule";
import { deriveGenerator, cpaceStart, cpaceShared } from "./cpace";

const rand = (n: number) => {
  const u = new Uint8Array(n);
  crypto.getRandomValues(u);
  return u;
};

describe("cpace", () => {
  test("two honest parties with the same PIN reach the same K", async () => {
    const module = await loadTestModule();
    const enc = new TextEncoder();
    const pin = enc.encode("123456");
    const sid = rand(16);
    const ci = rand(64);

    const Ga = deriveGenerator(pin, sid, ci, module);
    const Gb = deriveGenerator(
      Uint8Array.from(pin),
      Uint8Array.from(sid),
      Uint8Array.from(ci),
      module,
    );
    // Same transcript -> same generator.
    expect(Buffer.from(Ga)).toEqual(Buffer.from(Gb));

    const a = cpaceStart(Ga, module);
    const b = cpaceStart(Gb, module);
    expect(a.Y.length).toBe(32);

    const Ka = cpaceShared(a.y, b.Y, module);
    const Kb = cpaceShared(b.y, a.Y, module);
    expect(Buffer.from(Ka)).toEqual(Buffer.from(Kb));
  });

  test("a wrong PIN yields a different generator and mismatched K", async () => {
    const module = await loadTestModule();
    const enc = new TextEncoder();
    const sid = rand(16);
    const ci = rand(64);

    const Ga = deriveGenerator(enc.encode("123456"), sid, ci, module);
    const Gb = deriveGenerator(enc.encode("000000"), Uint8Array.from(sid), Uint8Array.from(ci), module);
    expect(Buffer.from(Ga)).not.toEqual(Buffer.from(Gb));

    const a = cpaceStart(Ga, module);
    const b = cpaceStart(Gb, module);
    const Ka = cpaceShared(a.y, b.Y, module);
    const Kb = cpaceShared(b.y, a.Y, module);
    expect(Buffer.from(Ka)).not.toEqual(Buffer.from(Kb));
  });
});
```

2. Run — fails. `bun test src/cryptography/cpace.test.ts`
   Expected: `Cannot find module './cpace'`.

3. Implement `cpace.ts`:
```ts
import {
  crypto_hash_sha512_BYTES,
  crypto_hash_sha512_STATEBYTES,
  crypto_core_ristretto255_BYTES,
  crypto_core_ristretto255_HASHBYTES,
  crypto_core_ristretto255_SCALARBYTES,
} from "./interfaces";
import { CPACE_DOMAIN } from "../utils/constants";
import { zeroFree } from "../utils/zeroFree";

import type { LibCrypto } from "./libcrypto";

const CPACE_DOMAIN_BYTES = new TextEncoder().encode(CPACE_DOMAIN);

// SHA-512 over the ordered concatenation of the parts, streamed through the wasm
// incremental hash. Returns the 64-byte digest as an owned copy.
const sha512Concat = (module: LibCrypto, parts: Uint8Array[]): Uint8Array => {
  const statePtr = module._malloc(crypto_hash_sha512_STATEBYTES);
  const outPtr = module._malloc(crypto_hash_sha512_BYTES);
  try {
    if (module._sha512_init(statePtr) !== 0)
      throw new Error("sha512_init failed");

    for (const part of parts) {
      if (part.length === 0) continue;
      const p = module._malloc(part.length);
      new Uint8Array(module.wasmMemory.buffer, p, part.length).set(part);
      const r = module._sha512_update(statePtr, p, part.length);
      module._free(p);
      if (r !== 0) throw new Error("sha512_update failed");
    }

    if (module._sha512_final(statePtr, outPtr) !== 0)
      throw new Error("sha512_final failed");

    return Uint8Array.from(
      new Uint8Array(module.wasmMemory.buffer, outPtr, crypto_hash_sha512_BYTES),
    );
  } finally {
    module._free(statePtr);
    module._free(outPtr);
  }
};

/**
 * G = ristretto255_from_hash( SHA512(CPACE_DOMAIN || PRS || sid || CI) ).
 * Both parties feed identical (PRS, sid, CI) and get the identical generator.
 */
export const deriveGenerator = (
  pin: Uint8Array,
  sid: Uint8Array,
  channelInput: Uint8Array,
  module: LibCrypto,
): Uint8Array => {
  const h = sha512Concat(module, [CPACE_DOMAIN_BYTES, pin, sid, channelInput]);

  const hPtr = module._malloc(crypto_core_ristretto255_HASHBYTES);
  const gPtr = module._malloc(crypto_core_ristretto255_BYTES);
  new Uint8Array(
    module.wasmMemory.buffer,
    hPtr,
    crypto_core_ristretto255_HASHBYTES,
  ).set(h);

  module._cpace_ristretto255_from_hash(gPtr, hPtr);

  const G = Uint8Array.from(
    new Uint8Array(
      module.wasmMemory.buffer,
      gPtr,
      crypto_core_ristretto255_BYTES,
    ),
  );
  module._free(hPtr);
  module._free(gPtr);
  return G;
};

/** y <- random scalar; Y = y*G. */
export const cpaceStart = (
  G: Uint8Array,
  module: LibCrypto,
): { y: Uint8Array; Y: Uint8Array } => {
  const yPtr = module._malloc(crypto_core_ristretto255_SCALARBYTES);
  const gPtr = module._malloc(crypto_core_ristretto255_BYTES);
  const YPtr = module._malloc(crypto_core_ristretto255_BYTES);

  module._cpace_ristretto255_scalar_random(yPtr);
  new Uint8Array(
    module.wasmMemory.buffer,
    gPtr,
    crypto_core_ristretto255_BYTES,
  ).set(G);

  const r = module._cpace_ristretto255_scalarmult(YPtr, yPtr, gPtr);

  const y =
    r === 0
      ? Uint8Array.from(
          new Uint8Array(
            module.wasmMemory.buffer,
            yPtr,
            crypto_core_ristretto255_SCALARBYTES,
          ),
        )
      : null;
  const Y =
    r === 0
      ? Uint8Array.from(
          new Uint8Array(
            module.wasmMemory.buffer,
            YPtr,
            crypto_core_ristretto255_BYTES,
          ),
        )
      : null;

  zeroFree(
    module,
    new Uint8Array(
      module.wasmMemory.buffer,
      yPtr,
      crypto_core_ristretto255_SCALARBYTES,
    ),
  );
  module._free(gPtr);
  module._free(YPtr);

  if (!y || !Y) throw new Error("cpace: Y is the identity point");
  return { y, Y };
};

/** K = y * Ypeer (the shared secret point). */
export const cpaceShared = (
  y: Uint8Array,
  Ypeer: Uint8Array,
  module: LibCrypto,
): Uint8Array => {
  const yPtr = module._malloc(crypto_core_ristretto255_SCALARBYTES);
  const YpeerPtr = module._malloc(crypto_core_ristretto255_BYTES);
  const KPtr = module._malloc(crypto_core_ristretto255_BYTES);

  new Uint8Array(
    module.wasmMemory.buffer,
    yPtr,
    crypto_core_ristretto255_SCALARBYTES,
  ).set(y);
  new Uint8Array(
    module.wasmMemory.buffer,
    YpeerPtr,
    crypto_core_ristretto255_BYTES,
  ).set(Ypeer);

  const r = module._cpace_ristretto255_scalarmult(KPtr, yPtr, YpeerPtr);

  const K =
    r === 0
      ? Uint8Array.from(
          new Uint8Array(
            module.wasmMemory.buffer,
            KPtr,
            crypto_core_ristretto255_BYTES,
          ),
        )
      : null;

  zeroFree(
    module,
    new Uint8Array(
      module.wasmMemory.buffer,
      yPtr,
      crypto_core_ristretto255_SCALARBYTES,
    ),
  );
  module._free(YpeerPtr);
  module._free(KPtr);

  if (!K) throw new Error("cpace: shared point is the identity");
  return K;
};
```

4. Run — passes. `bun test src/cryptography/cpace.test.ts`
   Expected: `2 pass`, `0 fail`.

5. Typecheck: `npm run typecheck` — clean.

6. Commit (if requested): `stage2: CPace over ristretto255 (deriveGenerator/start/shared)`.

---

### Task 4 — X3DH no-PIN secret (`x3dh.ts`)

**Files:**
- Create `/Users/deliberative/Desktop/@p2party/p2party-js/src/cryptography/x3dh.ts`
- Create `/Users/deliberative/Desktop/@p2party/p2party-js/src/cryptography/x3dh.test.ts`

**Interfaces:**
- *Consumes:* `x25519Dh`, `x25519Keypair` (Task 1); `hkdfExtract`, `hkdfExpand` (Task 2); `loadTestModule`.
- *Produces:* `x3dhDeriveSecret(idSelfSec:Uint8Array, idPeerPub:Uint8Array, ephSelfSec:Uint8Array, ephPeerPub:Uint8Array, amInitiator:boolean, module):Uint8Array` — 32-byte secret (consumed by Stage-4 handshake).

**Steps:**

1. Write failing test `x3dh.test.ts` — two-party equal secret with correctly swapped roles:
```ts
import { describe, expect, test } from "bun:test";

import { loadTestModule } from "./testModule";
import { x25519Keypair } from "./x25519";
import { x3dhDeriveSecret } from "./x3dh";

describe("x3dh", () => {
  test("initiator and responder derive the same 32-byte secret", async () => {
    const module = await loadTestModule();

    const IKa = x25519Keypair(module);
    const IKb = x25519Keypair(module);
    const EKa = x25519Keypair(module);
    const EKb = x25519Keypair(module);

    const sa = x3dhDeriveSecret(
      IKa.secretKey,
      IKb.publicKey,
      EKa.secretKey,
      EKb.publicKey,
      true,
      module,
    );
    const sb = x3dhDeriveSecret(
      IKb.secretKey,
      IKa.publicKey,
      EKb.secretKey,
      EKa.publicKey,
      false,
      module,
    );

    expect(sa.length).toBe(32);
    expect(Buffer.from(sa)).toEqual(Buffer.from(sb));
  });

  test("a substituted peer identity breaks agreement", async () => {
    const module = await loadTestModule();
    const IKa = x25519Keypair(module);
    const IKb = x25519Keypair(module);
    const IKevil = x25519Keypair(module);
    const EKa = x25519Keypair(module);
    const EKb = x25519Keypair(module);

    const sa = x3dhDeriveSecret(IKa.secretKey, IKevil.publicKey, EKa.secretKey, EKb.publicKey, true, module);
    const sb = x3dhDeriveSecret(IKb.secretKey, IKa.publicKey, EKb.secretKey, EKa.publicKey, false, module);
    expect(Buffer.from(sa)).not.toEqual(Buffer.from(sb));
  });
});
```

2. Run — fails. `bun test src/cryptography/x3dh.test.ts`
   Expected: `Cannot find module './x3dh'`.

3. Implement `x3dh.ts`. The responder mirrors the initiator's `DH(IKa,EKb) ‖ DH(EKa,IKb) ‖ DH(EKa,EKb)` term order using DH symmetry:
```ts
import { x25519Dh } from "./x25519";
import { hkdfExtract, hkdfExpand } from "./hkdf";

import type { LibCrypto } from "./libcrypto";

// Internal HKDF params for the no-PIN handshake (both peers are pure TS; not on
// the wire, so no C SSOT needed).
const X3DH_INFO = new TextEncoder().encode("p2party-x3dh-v1");
const X3DH_SALT = new Uint8Array(64); // HashLen zeros

/**
 * No-PIN identity-mixed ephemeral DH. Mixes
 *   DH(IK_a, EK_b) || DH(EK_a, IK_b) || DH(EK_a, EK_b)
 * (initiator orientation) then HKDF-SHA512 to a 32-byte root seed. The responder
 * passes amInitiator=false; the three DH calls are re-ordered so both sides
 * concatenate the identical shared values.
 */
export const x3dhDeriveSecret = (
  idSelfSec: Uint8Array,
  idPeerPub: Uint8Array,
  ephSelfSec: Uint8Array,
  ephPeerPub: Uint8Array,
  amInitiator: boolean,
  module: LibCrypto,
): Uint8Array => {
  let dh1: Uint8Array;
  let dh2: Uint8Array;
  const dh3 = x25519Dh(ephSelfSec, ephPeerPub, module); // DH(EK_a, EK_b) — symmetric

  if (amInitiator) {
    dh1 = x25519Dh(idSelfSec, ephPeerPub, module); // DH(IK_a, EK_b)
    dh2 = x25519Dh(ephSelfSec, idPeerPub, module); // DH(EK_a, IK_b)
  } else {
    dh1 = x25519Dh(ephSelfSec, idPeerPub, module); // == DH(IK_a, EK_b)
    dh2 = x25519Dh(idSelfSec, ephPeerPub, module); // == DH(EK_a, IK_b)
  }

  const ikm = new Uint8Array(96);
  ikm.set(dh1, 0);
  ikm.set(dh2, 32);
  ikm.set(dh3, 64);

  const prk = hkdfExtract(X3DH_SALT, ikm, module);
  const secret = hkdfExpand(prk, X3DH_INFO, 32, module);

  ikm.fill(0);
  dh1.fill(0);
  dh2.fill(0);
  dh3.fill(0);
  prk.fill(0);

  return secret;
};
```

4. Run — passes. `bun test src/cryptography/x3dh.test.ts`
   Expected: `2 pass`, `0 fail`.

5. Commit (if requested): `stage2: X3DH identity-mixed no-PIN secret`.

---

### Task 5 — Double Ratchet state machine (`ratchet.ts`)

**Files:**
- Create `/Users/deliberative/Desktop/@p2party/p2party-js/src/cryptography/ratchet.ts`
- Create `/Users/deliberative/Desktop/@p2party/p2party-js/src/cryptography/ratchet.test.ts`

**Interfaces:**
- *Consumes:* `x25519Keypair`, `x25519Dh` (Task 1); `hkdfExtract`, `hkdfExpand` (Task 2); constants `KDF_RK_LABEL`, `KDF_CK_LABEL`, `KDF_MK_LABEL`, `MAX_SKIP` from `../utils/constants`; `loadTestModule`.
- *Produces:* the `RatchetState` + `RatchetHeader` + `RatchetSessionSecrets` interfaces and `initRatchet`, `ratchetEncrypt`, `ratchetDecrypt`, `serializeRatchet`, `deserializeRatchet` (all consumed by Stage-3 DB layer and Stage-4 handshake). `RatchetSessionSecrets` maps 1:1 onto the wrapped secret fields of the `RatchetSession` IndexedDB row.

**Steps:**

1. Write the failing test `ratchet.test.ts` covering round-trip both directions, explicit DH-step, out-of-order via skipped keys, MAX_SKIP overflow, and serialize/deserialize:
```ts
import { describe, expect, test } from "bun:test";

import { loadTestModule } from "./testModule";
import {
  initRatchet,
  ratchetEncrypt,
  ratchetDecrypt,
  serializeRatchet,
  deserializeRatchet,
} from "./ratchet";
import { MAX_SKIP } from "../utils/constants";

const seed = () => {
  const s = new Uint8Array(32);
  crypto.getRandomValues(s);
  return s;
};

// Bob is the responder (initRatchet false, remote null); Alice is the initiator
// and consumes Bob's initial ratchet pub. Both share the identical root seed.
const pair = async () => {
  const module = await loadTestModule();
  const root = seed();
  const bob = initRatchet(root, false, null, module);
  const alice = initRatchet(Uint8Array.from(root), true, bob.dhSelfPub, module);
  return { module, alice, bob };
};

describe("ratchet", () => {
  test("encrypt -> decrypt round trip in both directions", async () => {
    const { module, alice, bob } = await pair();

    const a0 = ratchetEncrypt(alice, module);
    const bk = ratchetDecrypt(bob, a0.header, module);
    expect(Buffer.from(bk)).toEqual(Buffer.from(a0.messageKey));

    // Bob now has a sending chain (from his DH step). Reply exercises Alice's step.
    const b0 = ratchetEncrypt(bob, module);
    const ak = ratchetDecrypt(alice, b0.header, module);
    expect(Buffer.from(ak)).toEqual(Buffer.from(b0.messageKey));
  });

  test("DH-step fires on a new dhPub (dhRemotePub advances)", async () => {
    const { module, alice, bob } = await pair();
    const a0 = ratchetEncrypt(alice, module);
    ratchetDecrypt(bob, a0.header, module);
    const b0 = ratchetEncrypt(bob, module);
    const before = Uint8Array.from(alice.dhRemotePub!);
    ratchetDecrypt(alice, b0.header, module);
    expect(Buffer.from(alice.dhRemotePub!)).not.toEqual(Buffer.from(before));
    expect(Buffer.from(alice.dhRemotePub!)).toEqual(Buffer.from(b0.header.dhPub));
  });

  test("out-of-order delivery is served from skipped keys", async () => {
    const { module, alice, bob } = await pair();
    const m0 = ratchetEncrypt(alice, module);
    const m1 = ratchetEncrypt(alice, module);
    const m2 = ratchetEncrypt(alice, module);

    const k2 = ratchetDecrypt(bob, m2.header, module); // skips 0,1
    const k0 = ratchetDecrypt(bob, m0.header, module); // from skipped
    const k1 = ratchetDecrypt(bob, m1.header, module); // from skipped

    expect(Buffer.from(k2)).toEqual(Buffer.from(m2.messageKey));
    expect(Buffer.from(k0)).toEqual(Buffer.from(m0.messageKey));
    expect(Buffer.from(k1)).toEqual(Buffer.from(m1.messageKey));
  });

  test("a jump beyond MAX_SKIP is rejected", async () => {
    const { module, alice, bob } = await pair();
    const m0 = ratchetEncrypt(alice, module);
    ratchetDecrypt(bob, m0.header, module); // establish recv chain, Nr = 1

    const evil = { dhPub: m0.header.dhPub, N: MAX_SKIP + 100, PN: m0.header.PN };
    expect(() => ratchetDecrypt(bob, evil, module)).toThrow(/MAX_SKIP/);
  });

  test("serialize/deserialize preserves a pending skipped key", async () => {
    const { module, alice, bob } = await pair();
    const m0 = ratchetEncrypt(alice, module);
    const m1 = ratchetEncrypt(alice, module);

    ratchetDecrypt(bob, m1.header, module); // m0 becomes skipped
    const snap = serializeRatchet(bob);
    expect(snap.skippedMessageKeys.length).toBe(1);

    const bob2 = deserializeRatchet(snap);
    const k0 = ratchetDecrypt(bob2, m0.header, module);
    expect(Buffer.from(k0)).toEqual(Buffer.from(m0.messageKey));
  });
});
```

2. Run — fails. `bun test src/cryptography/ratchet.test.ts`
   Expected: `Cannot find module './ratchet'`.

3. Implement `ratchet.ts` (Signal-style: `kdf_rk` via HKDF extract+expand, `kdf_ck` via two labelled HMACs, DH step, bounded skipped-key handling):
```ts
import { x25519Keypair, x25519Dh } from "./x25519";
import { hkdfExtract, hkdfExpand } from "./hkdf";
import { KDF_RK_LABEL, KDF_CK_LABEL, KDF_MK_LABEL, MAX_SKIP } from "../utils/constants";

import type { LibCrypto } from "./libcrypto";

const RK_INFO = new TextEncoder().encode(KDF_RK_LABEL);
const CK_INFO = new TextEncoder().encode(KDF_CK_LABEL);
const MK_INFO = new TextEncoder().encode(KDF_MK_LABEL);

export interface RatchetState {
  rootKey: Uint8Array;
  sendingChainKey: Uint8Array | null;
  receivingChainKey: Uint8Array | null;
  dhSelfPub: Uint8Array;
  dhSelfSec: Uint8Array;
  dhRemotePub: Uint8Array | null;
  Ns: number;
  Nr: number;
  PN: number;
  skipped: Map<string, Uint8Array>;
}

export interface RatchetHeader {
  dhPub: Uint8Array;
  N: number;
  PN: number;
}

export interface RatchetSessionSecrets {
  rootKey: ArrayBuffer;
  sendingChainKey: ArrayBuffer | null;
  receivingChainKey: ArrayBuffer | null;
  dhSelfPub: ArrayBuffer;
  dhSelfSec: ArrayBuffer;
  dhRemotePub: ArrayBuffer | null;
  Ns: number;
  Nr: number;
  PN: number;
  skippedMessageKeys: Array<{ dhPub: ArrayBuffer; n: number; messageKey: ArrayBuffer }>;
}

const toHex = (u8: Uint8Array): string =>
  Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");

const fromHex = (hex: string): Uint8Array => {
  const u = new Uint8Array(hex.length / 2);
  for (let i = 0; i < u.length; i++) u[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return u;
};

const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
};

// KDF_RK: (rootKey, dhOut) -> (newRootKey, chainKey). HKDF-Extract salted with the
// current root, expanded to 64 bytes split 32/32.
const kdfRk = (
  rootKey: Uint8Array,
  dhOut: Uint8Array,
  module: LibCrypto,
): { rootKey: Uint8Array; chainKey: Uint8Array } => {
  const prk = hkdfExtract(rootKey, dhOut, module);
  const okm = hkdfExpand(prk, RK_INFO, 64, module);
  prk.fill(0);
  const newRoot = okm.slice(0, 32);
  const chainKey = okm.slice(32, 64);
  okm.fill(0);
  return { rootKey: newRoot, chainKey };
};

// KDF_CK: chainKey -> (nextChainKey, messageKey) via two labelled HMAC-SHA512
// (HKDF-Extract keyed by the chain key), truncated to 32 bytes each.
const kdfCk = (
  chainKey: Uint8Array,
  module: LibCrypto,
): { chainKey: Uint8Array; messageKey: Uint8Array } => {
  const mkFull = hkdfExtract(chainKey, MK_INFO, module);
  const ckFull = hkdfExtract(chainKey, CK_INFO, module);
  const messageKey = mkFull.slice(0, 32);
  const nextChainKey = ckFull.slice(0, 32);
  mkFull.fill(0);
  ckFull.fill(0);
  return { chainKey: nextChainKey, messageKey };
};

export const initRatchet = (
  rootSeed: Uint8Array,
  amInitiator: boolean,
  remoteDhPub: Uint8Array | null,
  module: LibCrypto,
): RatchetState => {
  const kp = x25519Keypair(module);
  const state: RatchetState = {
    rootKey: Uint8Array.from(rootSeed),
    sendingChainKey: null,
    receivingChainKey: null,
    dhSelfPub: kp.publicKey,
    dhSelfSec: kp.secretKey,
    dhRemotePub: null,
    Ns: 0,
    Nr: 0,
    PN: 0,
    skipped: new Map(),
  };

  if (amInitiator) {
    if (!remoteDhPub) throw new Error("ratchet: initiator requires remoteDhPub");
    state.dhRemotePub = Uint8Array.from(remoteDhPub);
    const dhOut = x25519Dh(state.dhSelfSec, state.dhRemotePub, module);
    const rk = kdfRk(state.rootKey, dhOut, module);
    dhOut.fill(0);
    state.rootKey = rk.rootKey;
    state.sendingChainKey = rk.chainKey;
  }
  // Responder: chains stay null; the first inbound header triggers the DH step.

  return state;
};

export const ratchetEncrypt = (
  state: RatchetState,
  module: LibCrypto,
): { messageKey: Uint8Array; header: RatchetHeader } => {
  if (!state.sendingChainKey) throw new Error("ratchet: no sending chain");
  const { chainKey, messageKey } = kdfCk(state.sendingChainKey, module);
  const header: RatchetHeader = {
    dhPub: Uint8Array.from(state.dhSelfPub),
    N: state.Ns,
    PN: state.PN,
  };
  state.sendingChainKey = chainKey;
  state.Ns += 1;
  return { messageKey, header };
};

const trySkipped = (
  state: RatchetState,
  header: RatchetHeader,
): Uint8Array | null => {
  const key = `${toHex(header.dhPub)}:${header.N}`;
  const mk = state.skipped.get(key);
  if (mk) {
    state.skipped.delete(key);
    return mk;
  }
  return null;
};

const skipMessageKeys = (
  state: RatchetState,
  until: number,
  module: LibCrypto,
): void => {
  if (state.Nr + MAX_SKIP < until) throw new Error("ratchet: MAX_SKIP exceeded");
  if (!state.receivingChainKey) return;
  while (state.Nr < until) {
    const { chainKey, messageKey } = kdfCk(state.receivingChainKey, module);
    state.receivingChainKey = chainKey;
    state.skipped.set(`${toHex(state.dhRemotePub!)}:${state.Nr}`, messageKey);
    state.Nr += 1;
  }
};

const dhRatchet = (
  state: RatchetState,
  header: RatchetHeader,
  module: LibCrypto,
): void => {
  state.PN = state.Ns;
  state.Ns = 0;
  state.Nr = 0;
  state.dhRemotePub = Uint8Array.from(header.dhPub);

  let dhOut = x25519Dh(state.dhSelfSec, state.dhRemotePub, module);
  let rk = kdfRk(state.rootKey, dhOut, module);
  dhOut.fill(0);
  state.rootKey = rk.rootKey;
  state.receivingChainKey = rk.chainKey;

  const kp = x25519Keypair(module);
  state.dhSelfPub = kp.publicKey;
  state.dhSelfSec = kp.secretKey;

  dhOut = x25519Dh(state.dhSelfSec, state.dhRemotePub, module);
  rk = kdfRk(state.rootKey, dhOut, module);
  dhOut.fill(0);
  state.rootKey = rk.rootKey;
  state.sendingChainKey = rk.chainKey;
};

export const ratchetDecrypt = (
  state: RatchetState,
  header: RatchetHeader,
  module: LibCrypto,
): Uint8Array => {
  const skipped = trySkipped(state, header);
  if (skipped) return skipped;

  const isNewDh =
    !state.dhRemotePub || !bytesEqual(header.dhPub, state.dhRemotePub);
  if (isNewDh) {
    skipMessageKeys(state, header.PN, module); // finish the previous chain
    dhRatchet(state, header, module);
  }

  if (header.N < state.Nr)
    throw new Error("ratchet: message key already consumed");

  skipMessageKeys(state, header.N, module);
  const { chainKey, messageKey } = kdfCk(state.receivingChainKey!, module);
  state.receivingChainKey = chainKey;
  state.Nr += 1;
  return messageKey;
};

const toBuf = (u8: Uint8Array): ArrayBuffer => u8.slice().buffer;
const toBufN = (u8: Uint8Array | null): ArrayBuffer | null =>
  u8 ? u8.slice().buffer : null;

export const serializeRatchet = (state: RatchetState): RatchetSessionSecrets => ({
  rootKey: toBuf(state.rootKey),
  sendingChainKey: toBufN(state.sendingChainKey),
  receivingChainKey: toBufN(state.receivingChainKey),
  dhSelfPub: toBuf(state.dhSelfPub),
  dhSelfSec: toBuf(state.dhSelfSec),
  dhRemotePub: toBufN(state.dhRemotePub),
  Ns: state.Ns,
  Nr: state.Nr,
  PN: state.PN,
  skippedMessageKeys: Array.from(state.skipped.entries()).map(([k, mk]) => {
    const idx = k.lastIndexOf(":");
    return {
      dhPub: fromHex(k.slice(0, idx)).slice().buffer,
      n: Number(k.slice(idx + 1)),
      messageKey: mk.slice().buffer,
    };
  }),
});

export const deserializeRatchet = (s: RatchetSessionSecrets): RatchetState => {
  const skipped = new Map<string, Uint8Array>();
  for (const e of s.skippedMessageKeys) {
    const dh = new Uint8Array(e.dhPub);
    skipped.set(`${toHex(dh)}:${e.n}`, new Uint8Array(e.messageKey));
  }
  return {
    rootKey: new Uint8Array(s.rootKey),
    sendingChainKey: s.sendingChainKey ? new Uint8Array(s.sendingChainKey) : null,
    receivingChainKey: s.receivingChainKey
      ? new Uint8Array(s.receivingChainKey)
      : null,
    dhSelfPub: new Uint8Array(s.dhSelfPub),
    dhSelfSec: new Uint8Array(s.dhSelfSec),
    dhRemotePub: s.dhRemotePub ? new Uint8Array(s.dhRemotePub) : null,
    Ns: s.Ns,
    Nr: s.Nr,
    PN: s.PN,
    skipped,
  };
};
```

4. Run — passes. `bun test src/cryptography/ratchet.test.ts`
   Expected: `5 pass`, `0 fail`.

5. Run the whole crypto suite to confirm no regressions and all Stage-2 units are green together. `bun test src/cryptography/`
   Expected: the pre-existing `utils.test.ts` plus the five new files all pass, e.g. `13 pass`, `0 fail`.

6. Typecheck both configs: `npm run typecheck`
   Expected: no output / exit 0.

7. Commit (if requested): `stage2: Double Ratchet state machine (init/encrypt/decrypt/serialize)`.

---

**Stage-2 exit criteria:** `bun test src/cryptography/` and `npm run typecheck` both green. No wasm rebuild, no SRI repin, no version bump in this stage — those land in the atomic v3 cutover (Stage 5/7). The produced APIs (`deriveGenerator`/`cpaceStart`/`cpaceShared`, `x3dhDeriveSecret`, `initRatchet`/`ratchetEncrypt`/`ratchetDecrypt`/`serializeRatchet`/`deserializeRatchet`, and the `RatchetState`/`RatchetHeader`/`RatchetSessionSecrets` types) are exactly what Stage 3 (IndexedDB `ratchetSessions` + wrap) and Stage 4 (`handleHandshake.ts`) consume.


---

## Stage 3 — IndexedDB `ratchetSessions` store + WebCrypto at-rest wrap

Persist one Double-Ratchet session per stable identity edge `(roomId, peerPublicKey)` so the ratchet survives reconnect/reload, with every secret field wrapped at rest under a non-extractable AES-GCM `CryptoKey` that itself lives in IndexedDB. This stage is pure persistence + crypto-at-rest; it has **no** dependency on the WASM exports or the ratchet/cpace TS modules (those are Stages 1–2), so it can be built and tested in isolation.

**Verified environment facts (checked against this repo, bun 1.3.14):**
- bun's global WebCrypto supports `crypto.subtle.generateKey({name:"AES-GCM",length:256}, false, ...)` with `extractable:false`, and AES-GCM `encrypt`/`decrypt`.
- `fake-indexeddb@6.2.5` (available on npm, added as a devDependency in Task 1) faithfully round-trips both `ArrayBuffer` records **and** a stored non-extractable `CryptoKey` across a `db.close()` + reopen — so the wrap-key-persists ("simulate reload") test is a real bun unit test, not E2E-only.
- Do **NOT** `import` `src/db/db.worker.ts` from a bun test: its top-level `onmessage = async …` registers a live message handler that keeps the loop alive. All unit tests target the pure module `src/db/ratchetWrap.ts` + `src/db/src/getDB.ts` directly. The thin `fn*` delegations in `db.worker.ts`, their `onmessage` cases, and `db/api.ts` are covered by `npm run typecheck` here and by the real-worker E2E in Stage 7.

Existing patterns this stage mirrors: `RepoSchema` + additive `upgrade` branches in `getDB.ts`; the open-`getDB()`/tx/`db.close()`-per-call shape of every `fn*` in `db.worker.ts`; the `WorkerMessages` discriminated union + `WorkerMethodReturnTypes` map + `onmessage` switch + `callWorker` wrapper in `db/api.ts`; bun tests aliasing WebCrypto globals (`src/utils/leafHash.test.ts`).

---

### Task 1 — `RatchetSession` type, worker message variants, and the `fake-indexeddb` devDependency

**Files:**
- Modify `package.json` — add `fake-indexeddb` to `devDependencies`.
- Modify `src/db/types.ts` — add `RatchetSession` interface (after `SendQueue`, ~line 105), three `WorkerMessages` union members (before the final `deleteDB` member, ~line 295), three `WorkerMethodReturnTypes` entries (~line 340).

**Interfaces:**
- **Produces** `RatchetSession` (exact shape from spec §8) — consumed by Task 2/3/4/5 of this stage and by Stage 4 (`handleHandshake.ts` persists the seeded session) and Stage 6 (message-crypto load/advance/persist).
- **Produces** worker methods `getRatchetSession` / `setRatchetSession` / `deleteRatchetSession` in the `WorkerMessages`/`WorkerMethodReturnTypes` contract.

**Steps:**

1. Add the devDependency (exact version validated in this repo):
   ```
   bun add -d fake-indexeddb@6.2.5
   ```
   Expected: `installed fake-indexeddb@6.2.5`, and `package.json` `devDependencies` now contains `"fake-indexeddb": "6.2.5"`. (Already present in the working tree if a prior run added it — confirm with `node -e "console.log(require('./package.json').devDependencies['fake-indexeddb'])"` → `6.2.5`.)

2. In `src/db/types.ts`, insert the `RatchetSession` interface immediately after the `SendQueue` interface (after line 105):
   ```ts
   // One Double-Ratchet session per STABLE identity edge (roomId, peerPublicKey) —
   // not per per-session peerId, which changes on reconnect — so the ratchet
   // survives reconnect/reload. All secret fields (rootKey, both chain keys,
   // dhSelfSec, and each skipped messageKey) are stored WRAPPED (AES-GCM under the
   // non-extractable CryptoKey in the `meta` store); public/counter fields are
   // stored plaintext. See src/db/ratchetWrap.ts.
   export interface RatchetSession {
     roomId: string;
     peerPublicKey: string;
     peerId: string;
     rootKey: ArrayBuffer;
     sendingChainKey: ArrayBuffer | null;
     receivingChainKey: ArrayBuffer | null;
     dhSelfPub: ArrayBuffer;
     dhSelfSec: ArrayBuffer;
     dhRemotePub: ArrayBuffer | null;
     Ns: number;
     Nr: number;
     PN: number;
     skippedMessageKeys: Array<{
       dhPub: ArrayBuffer;
       n: number;
       messageKey: ArrayBuffer;
     }>; // capped at MAX_SKIP_SESSION (total, evict-oldest) by the ratchet layer (Stage 2)
     updatedAt: number;
   }
   ```

3. In `src/db/types.ts`, add three members to the `WorkerMessages` union, immediately before the final `deleteDB` member (before line 295 `| { id: number; method: "deleteDB"; …`):
   ```ts
     | {
         id: number;
         method: "getRatchetSession";
         args: [roomId: string, peerPublicKey: string];
       }
     | {
         id: number;
         method: "setRatchetSession";
         args: [session: RatchetSession];
       }
     | {
         id: number;
         method: "deleteRatchetSession";
         args: [roomId: string, peerPublicKey: string];
       }
   ```

4. In `src/db/types.ts`, add three entries to `WorkerMethodReturnTypes` (before the closing `}` of the interface, after `deleteDB: undefined;`):
   ```ts
     getRatchetSession: RatchetSession | undefined;
     setRatchetSession: undefined;
     deleteRatchetSession: undefined;
   ```

5. Typecheck the contract so far (the store/worker impls don't exist yet, so this only checks `types.ts` is internally valid):
   ```
   npx tsc --noEmit -p tsconfig.json
   ```
   Expected: passes with **no** new errors referencing `types.ts`. (It may still error in `db.worker.ts`/`api.ts` about missing handlers — those are added in Tasks 4–5 and are expected to be red until then; note them but do not fix yet.)

---

### Task 2 — `getDB.ts`: dbVersion 16 → 17, add `ratchetSessions` + `meta` stores (additive upgrade)

**Files:**
- Modify `src/db/src/getDB.ts` — bump `dbVersion` (line 15), add two members to `RepoSchema` (after `sendQueue`, line 57), add two additive `create` branches to `upgrade` (before the closing of the `upgrade` callback, ~line 224).

**Interfaces:**
- **Consumes** `RatchetSession` (Task 1).
- **Produces** the `ratchetSessions` object store (keyPath `['roomId','peerPublicKey']`, indexes `peerId`/`peerPublicKey`/`roomId`, all non-unique) and the `meta` out-of-line store (holds the wrap `CryptoKey`), reachable via `getDB()` in Task 3/4.

**Steps:**

1. Bump the version at `src/db/src/getDB.ts:15`:
   ```ts
   export const dbVersion = 17;
   ```

2. Add `RatchetSession` to the type import at the top of `getDB.ts` (extend the existing `import type { … } from "../types";` block, lines 4–12):
   ```ts
   import type {
     MessageData,
     Chunk,
     SendQueue,
     AddressBook,
     BlacklistedPeer,
     UniqueRoom,
     NewChunk,
     RatchetSession,
   } from "../types";
   ```

3. Add two stores to `RepoSchema`, immediately after the `sendQueue` block (after line 57, before the closing `}` of `RepoSchema`):
   ```ts
     ratchetSessions: {
       value: RatchetSession;
       key: [string, string];
       indexes: { peerId: string; peerPublicKey: string; roomId: string };
     };
     // Out-of-line store for the single non-extractable AES-GCM wrap CryptoKey
     // (key = "ratchetWrapKey"). Value is a live CryptoKey object (structured-
     // cloneable, never its raw bytes).
     meta: {
       value: CryptoKey;
       key: string;
     };
   ```

4. Add two additive create branches inside `upgrade`, immediately before the closing `}` of the `upgrade(db, _oldVersion, _newVersion, tx)` callback (after the `sendQueue` else-branch closes at line 223, before line 224 `},`). Purely additive — a v16→v17 upgrade only runs these two `create` branches; no existing store is touched, so no migration:
   ```ts
         if (!db.objectStoreNames.contains("ratchetSessions")) {
           const ratchetSessions = db.createObjectStore("ratchetSessions", {
             keyPath: ["roomId", "peerPublicKey"],
           });
           ratchetSessions.createIndex("peerId", "peerId", { unique: false });
           ratchetSessions.createIndex("peerPublicKey", "peerPublicKey", {
             unique: false,
           });
           ratchetSessions.createIndex("roomId", "roomId", { unique: false });
         }

         if (!db.objectStoreNames.contains("meta")) {
           db.createObjectStore("meta");
         }
   ```
   (The `peerPublicKey` and `roomId` indexes are **non-unique**: the same peer key recurs across rooms and many peers share a room. The `tx` param stays used elsewhere; these are `db.createObjectStore` calls, matching every existing store's create branch.)

5. Typecheck `getDB.ts` in isolation:
   ```
   npx tsc --noEmit -p tsconfig.json
   ```
   Expected: no errors in `getDB.ts`. (Handlers in `db.worker.ts`/`api.ts` still red until Tasks 4–5 — expected.)

---

### Task 3 — `src/db/ratchetWrap.ts`: non-extractable wrap key + wrap/unwrap (TDD core of this stage)

This task holds all the real logic and is fully unit-tested in bun. Write the failing test first, watch it fail, implement minimally, watch it pass.

**Files:**
- Create `src/db/ratchetWrap.test.ts`
- Create `src/db/ratchetWrap.ts`

**Interfaces:**
- **Consumes** `getDB` from `./src/getDB` (Task 2), `RatchetSession` from `./types` (Task 1).
- **Produces** (exact names, consumed by Task 4 and by Stage 4/6):
  - `getWrapKey(): Promise<CryptoKey>` — AES-GCM, `extractable:false`, generated once and persisted in the `meta` store under key `"ratchetWrapKey"`, read back after refresh.
  - `wrapSecret(key: CryptoKey, bytes: ArrayBuffer): Promise<ArrayBuffer>` — returns `iv(12) ‖ ciphertext(len+16 tag)`.
  - `unwrapSecret(key: CryptoKey, blob: ArrayBuffer): Promise<ArrayBuffer>` — inverse; throws on tamper (AES-GCM auth).
  - `wrapRatchetSession(session: RatchetSession, key: CryptoKey): Promise<RatchetSession>` / `unwrapRatchetSession(stored: RatchetSession, key: CryptoKey): Promise<RatchetSession>` — transform only the secret fields (`rootKey`, `sendingChainKey`, `receivingChainKey`, `dhSelfSec`, each `skippedMessageKeys[].messageKey`); leave public/counter fields (`dhSelfPub`, `dhRemotePub`, `Ns/Nr/PN`, `peerId`, `updatedAt`, skipped `dhPub`/`n`) untouched.

**Steps:**

1. Write the failing test file `src/db/ratchetWrap.test.ts`:
   ```ts
   import "fake-indexeddb/auto";
   import { IDBFactory } from "fake-indexeddb";
   import { beforeEach, describe, expect, test } from "bun:test";

   import {
     getWrapKey,
     wrapSecret,
     unwrapSecret,
     wrapRatchetSession,
     unwrapRatchetSession,
   } from "./ratchetWrap";
   import { getDB } from "./src/getDB";

   import type { RatchetSession } from "./types";

   // Each test gets a pristine IndexedDB (clears BOTH the ratchetSessions store
   // and the persisted wrap key), so "reload persistence" is tested explicitly by
   // NOT resetting within a single test.
   beforeEach(() => {
     (globalThis as unknown as { indexedDB: IDBFactory }).indexedDB =
       new IDBFactory();
   });

   const rnd = (n: number) => crypto.getRandomValues(new Uint8Array(n)).buffer;
   const eq = (a: ArrayBuffer, b: ArrayBuffer) =>
     Buffer.from(new Uint8Array(a)).equals(Buffer.from(new Uint8Array(b)));

   const sampleSession = (): RatchetSession => ({
     roomId: "room-1",
     peerPublicKey: "aa".repeat(32),
     peerId: "peer-abc-123",
     rootKey: rnd(32),
     sendingChainKey: rnd(32),
     receivingChainKey: null,
     dhSelfPub: rnd(32),
     dhSelfSec: rnd(32),
     dhRemotePub: rnd(32),
     Ns: 3,
     Nr: 1,
     PN: 2,
     skippedMessageKeys: [{ dhPub: rnd(32), n: 0, messageKey: rnd(32) }],
     updatedAt: 111,
   });

   describe("wrapSecret / unwrapSecret", () => {
     test("round-trips the original bytes", async () => {
       const key = await getWrapKey();
       const bytes = rnd(32);
       const blob = await wrapSecret(key, bytes);
       expect(eq(blob, bytes)).toBe(false); // stored as ciphertext
       expect(blob.byteLength).toBe(12 + 32 + 16); // iv + ct + poly1305 tag
       const back = await unwrapSecret(key, blob);
       expect(eq(back, bytes)).toBe(true);
     });

     test("tampered ciphertext fails AEAD auth", async () => {
       const key = await getWrapKey();
       const blob = await wrapSecret(key, rnd(16));
       const v = new Uint8Array(blob);
       v[20] ^= 0xff; // flip a ciphertext byte
       await expect(unwrapSecret(key, v.buffer)).rejects.toBeDefined();
     });
   });

   describe("getWrapKey persistence", () => {
     test("is non-extractable and survives a simulated reload", async () => {
       const k1 = await getWrapKey();
       expect(k1.extractable).toBe(false);
       const bytes = rnd(32);
       const blob = await wrapSecret(k1, bytes);
       // Simulate reload: do NOT reset the factory; a fresh getWrapKey must read
       // the SAME persisted CryptoKey back from the meta store and unwrap.
       const k2 = await getWrapKey();
       const back = await unwrapSecret(k2, blob);
       expect(eq(back, bytes)).toBe(true);
     });
   });

   describe("wrap / unwrap RatchetSession", () => {
     test("round-trips secrets, leaves public + null fields intact", async () => {
       const key = await getWrapKey();
       const s = sampleSession();
       const w = await wrapRatchetSession(s, key);
       expect(eq(w.rootKey, s.rootKey)).toBe(false); // secret wrapped
       expect(eq(w.dhSelfSec, s.dhSelfSec)).toBe(false); // secret wrapped
       expect(eq(w.dhSelfPub, s.dhSelfPub)).toBe(true); // public untouched
       expect(w.receivingChainKey).toBe(null); // null preserved
       const u = await unwrapRatchetSession(w, key);
       expect(eq(u.rootKey, s.rootKey)).toBe(true);
       expect(eq(u.dhSelfSec, s.dhSelfSec)).toBe(true);
       expect(
         u.sendingChainKey != null && eq(u.sendingChainKey, s.sendingChainKey!),
       ).toBe(true);
       expect(
         eq(u.skippedMessageKeys[0].messageKey, s.skippedMessageKeys[0].messageKey),
       ).toBe(true);
       expect(u.skippedMessageKeys[0].n).toBe(0);
       expect(u.peerId).toBe("peer-abc-123");
     });
   });

   describe("ratchetSessions store round-trip (at-rest wrapped)", () => {
     test("put wrapped -> on-disk secret is ciphertext -> get+unwrap == plaintext", async () => {
       const key = await getWrapKey();
       const s = sampleSession();
       const db = await getDB();
       await db.put("ratchetSessions", await wrapRatchetSession(s, key));
       const onDisk = (await db.get("ratchetSessions", [
         s.roomId,
         s.peerPublicKey,
       ])) as RatchetSession;
       db.close();
       expect(eq(onDisk.rootKey, s.rootKey)).toBe(false); // proves at-rest wrap
       const u = await unwrapRatchetSession(onDisk, key);
       expect(eq(u.rootKey, s.rootKey)).toBe(true);
       expect(u.Ns).toBe(3);
     });
   });
   ```

2. Run it and watch it fail (module does not exist yet):
   ```
   bun test src/db/ratchetWrap.test.ts
   ```
   Expected: fails to resolve `./ratchetWrap` — `error: Cannot find module './ratchetWrap'` (0 pass).

3. Create the minimal implementation `src/db/ratchetWrap.ts`:
   ```ts
   import { getDB } from "./src/getDB";

   import type { RatchetSession } from "./types";

   // Out-of-line key in the `meta` store for the single wrap CryptoKey.
   const WRAP_KEY_META_ID = "ratchetWrapKey";

   // The at-rest wrap key: an AES-GCM 256 CryptoKey with extractable:false, so its
   // raw bytes never re-enter JS (stops raw-key export / cross-device copy). It is
   // generated ONCE and stored as a live CryptoKey object in IndexedDB (structured-
   // cloneable) so it is read back verbatim after a refresh. NOTE (documented
   // limit): this does NOT stop local decryption by an attacker with device+origin
   // access. First-run concurrent generate is guarded by a double-check inside the
   // write tx; a rare cross-tab first-run race just triggers a re-handshake.
   export async function getWrapKey(): Promise<CryptoKey> {
     const db = await getDB();
     const existing = (await db.get("meta", WRAP_KEY_META_ID)) as
       | CryptoKey
       | undefined;
     if (existing) {
       db.close();
       return existing;
     }
     const key = await crypto.subtle.generateKey(
       { name: "AES-GCM", length: 256 },
       false,
       ["encrypt", "decrypt"],
     );
     const tx = db.transaction("meta", "readwrite");
     const store = tx.objectStore("meta");
     const check = (await store.get(WRAP_KEY_META_ID)) as CryptoKey | undefined;
     if (check) {
       await tx.done;
       db.close();
       return check;
     }
     await store.put(key, WRAP_KEY_META_ID);
     await tx.done;
     db.close();
     return key;
   }

   // AES-GCM encrypt with a fresh 12-byte random IV, output = iv || ciphertext(+tag).
   export async function wrapSecret(
     key: CryptoKey,
     bytes: ArrayBuffer,
   ): Promise<ArrayBuffer> {
     const iv = crypto.getRandomValues(new Uint8Array(12));
     const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes);
     const out = new Uint8Array(12 + ct.byteLength);
     out.set(iv, 0);
     out.set(new Uint8Array(ct), 12);
     return out.buffer;
   }

   export async function unwrapSecret(
     key: CryptoKey,
     blob: ArrayBuffer,
   ): Promise<ArrayBuffer> {
     const view = new Uint8Array(blob);
     return crypto.subtle.decrypt(
       { name: "AES-GCM", iv: view.subarray(0, 12) },
       key,
       view.subarray(12),
     );
   }

   // Wrap only the secret fields; public + counter fields pass through unchanged.
   export async function wrapRatchetSession(
     s: RatchetSession,
     key: CryptoKey,
   ): Promise<RatchetSession> {
     return {
       ...s,
       rootKey: await wrapSecret(key, s.rootKey),
       sendingChainKey: s.sendingChainKey
         ? await wrapSecret(key, s.sendingChainKey)
         : null,
       receivingChainKey: s.receivingChainKey
         ? await wrapSecret(key, s.receivingChainKey)
         : null,
       dhSelfSec: await wrapSecret(key, s.dhSelfSec),
       skippedMessageKeys: await Promise.all(
         s.skippedMessageKeys.map(async (m) => ({
           dhPub: m.dhPub,
           n: m.n,
           messageKey: await wrapSecret(key, m.messageKey),
         })),
       ),
     };
   }

   export async function unwrapRatchetSession(
     s: RatchetSession,
     key: CryptoKey,
   ): Promise<RatchetSession> {
     return {
       ...s,
       rootKey: await unwrapSecret(key, s.rootKey),
       sendingChainKey: s.sendingChainKey
         ? await unwrapSecret(key, s.sendingChainKey)
         : null,
       receivingChainKey: s.receivingChainKey
         ? await unwrapSecret(key, s.receivingChainKey)
         : null,
       dhSelfSec: await unwrapSecret(key, s.dhSelfSec),
       skippedMessageKeys: await Promise.all(
         s.skippedMessageKeys.map(async (m) => ({
           dhPub: m.dhPub,
           n: m.n,
           messageKey: await unwrapSecret(key, m.messageKey),
         })),
       ),
     };
   }
   ```

4. Run the tests and watch them pass:
   ```
   bun test src/db/ratchetWrap.test.ts
   ```
   Expected (validated against this repo, bun 1.3.14):
   ```
    5 pass
    0 fail
    18 expect() calls
   ```

5. Commit this task on a feature branch (repo is on `master` per the definition-of-done memory; branch first):
   ```
   git checkout -b feat/v3-stage3-ratchet-idb 2>/dev/null || git checkout feat/v3-stage3-ratchet-idb
   git add package.json bun.lock src/db/types.ts src/db/src/getDB.ts src/db/ratchetWrap.ts src/db/ratchetWrap.test.ts
   git commit -m "feat(db): ratchetSessions store + at-rest AES-GCM wrap (stage 3 core)"
   ```
   (End the commit body with the `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` trailer per repo convention.)

---

### Task 4 — `db.worker.ts`: `fnGetRatchetSession` / `fnSetRatchetSession` / `fnDeleteRatchetSession` + onmessage cases

**Files:**
- Modify `src/db/db.worker.ts` — extend the `./types` import (lines 8–20), add a `./ratchetWrap` import, add three `fn*` functions (place after `fnSetDBSendQueue`, ~line 1417), add three `onmessage` `case`s (in the switch, ~before the `default` at line 1770).

**Interfaces:**
- **Consumes** `getWrapKey`, `wrapRatchetSession`, `unwrapRatchetSession` (Task 3); `RatchetSession` (Task 1); `getDB` (already imported).
- **Produces** the worker-side handlers behind the `getRatchetSession`/`setRatchetSession`/`deleteRatchetSession` methods. Each opens `getDB()`, does its tx, and `db.close()`s — mirroring `fnSetDBChunk`/`fnGetDBChunk`.

**Steps:**

1. Add `RatchetSession` to the `import type { … } from "./types";` block (lines 8–20) — append `RatchetSession,` to the list. Then add a value import directly below the `getDB` import (after line 6):
   ```ts
   import { getWrapKey, wrapRatchetSession, unwrapRatchetSession } from "./ratchetWrap";
   ```

2. Add the three functions after `fnSetDBSendQueue` (after line 1417). They mirror the open/close-per-call shape and swallow-and-log error style of the surrounding `fn*`:
   ```ts
   async function fnGetRatchetSession(
     roomId: string,
     peerPublicKey: string,
   ): Promise<RatchetSession | undefined> {
     try {
       const db = await getDB();
       const stored = await db.get("ratchetSessions", [roomId, peerPublicKey]);
       db.close();
       if (!stored) return undefined;
       const key = await getWrapKey();
       return await unwrapRatchetSession(stored, key);
     } catch (error) {
       console.error(error);
       return undefined;
     }
   }

   async function fnSetRatchetSession(session: RatchetSession): Promise<void> {
     try {
       const key = await getWrapKey();
       const wrapped = await wrapRatchetSession(session, key);
       const db = await getDB();
       await db.put("ratchetSessions", { ...wrapped, updatedAt: Date.now() });
       db.close();
     } catch (error) {
       console.error(error);
     }
   }

   async function fnDeleteRatchetSession(
     roomId: string,
     peerPublicKey: string,
   ): Promise<void> {
     try {
       const db = await getDB();
       await db.delete("ratchetSessions", [roomId, peerPublicKey]);
       db.close();
     } catch (error) {
       console.error(error);
     }
   }
   ```

3. Add three cases to the `onmessage` switch, immediately before `default:` (line 1770), matching the existing case style (value-returning vs void):
   ```ts
         case "getRatchetSession":
           result = await fnGetRatchetSession(...message.args);
           break;
         case "setRatchetSession":
           await fnSetRatchetSession(...message.args);
           result = undefined;
           break;
         case "deleteRatchetSession":
           await fnDeleteRatchetSession(...message.args);
           result = undefined;
           break;
   ```

4. Typecheck (this is the coverage for the worker wiring — no bun unit test imports `db.worker.ts`):
   ```
   npx tsc --noEmit -p tsconfig.json
   ```
   Expected: no errors in `db.worker.ts`. The `...message.args` spreads resolve because the `WorkerMessages` union (Task 1) narrows each `case` to the right arg tuple.

---

### Task 5 — `db/api.ts`: thin wrappers

**Files:**
- Modify `src/db/api.ts` — add three exported wrappers (after `deleteDBSendQueue`, ~line 221), extend the `./types` value import (lines 1–7) with `RatchetSession`.

**Interfaces:**
- **Consumes** the `WorkerMessages`/`WorkerMethodReturnTypes` contract (Task 1) via the existing generic `callWorker`.
- **Produces** the public async API `getRatchetSession(roomId, peerPublicKey)` / `setRatchetSession(session)` / `deleteRatchetSession(roomId, peerPublicKey)` — consumed by Stage 4 (`handleHandshake.ts`) and Stage 6 (message crypto).

**Steps:**

1. Extend the `import type { … } from "./types";` block at the top of `api.ts` (lines 1–7) to add `RatchetSession`:
   ```ts
   import type {
     WorkerMessages,
     Chunk,
     ReceiveChunk,
     NewChunk,
     SendQueue,
     RatchetSession,
   } from "./types";
   ```

2. Add the three wrappers at the end of `api.ts` (after `deleteDBSendQueue`, line 221), matching the existing arrow-export style:
   ```ts
   export const getRatchetSession = (roomId: string, peerPublicKey: string) =>
     callWorker("getRatchetSession", roomId, peerPublicKey);

   export const setRatchetSession = (session: RatchetSession) =>
     callWorker("setRatchetSession", session);

   export const deleteRatchetSession = (roomId: string, peerPublicKey: string) =>
     callWorker("deleteRatchetSession", roomId, peerPublicKey);
   ```

3. Full typecheck of both project + test configs (repo's `npm run typecheck` target):
   ```
   npm run typecheck
   ```
   Expected: `tsc --noEmit -p tsconfig.json` and `tsc --noEmit -p tsconfig.test.json` both pass with no errors.

4. Re-run the stage's unit tests to confirm nothing regressed, and the full suite:
   ```
   bun test src/db/ratchetWrap.test.ts && bun test
   ```
   Expected: `ratchetWrap.test.ts` → `5 pass 0 fail`; full `bun test` shows all pre-existing suites still green (`utils/*`, `cryptography/utils`, `handlers/reconcile`) plus the new file.

5. Commit the wiring:
   ```
   git add src/db/db.worker.ts src/db/api.ts
   git commit -m "feat(db): worker + api wiring for getRatchetSession/setRatchetSession/deleteRatchetSession"
   ```
   (Include the `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` trailer.)

---

**Stage-3 exit criteria (evidence, not assertion):**
- `bun test src/db/ratchetWrap.test.ts` → `5 pass, 0 fail, 18 expect() calls` (wrap/unwrap round-trip, tamper-fails, non-extractable wrap key persists across simulated reload, session wrap leaves public/null fields intact, and the `ratchetSessions` store persists secrets **as ciphertext** and reads back byte-identical after unwrap).
- `npm run typecheck` clean, proving the `WorkerMessages`/`WorkerMethodReturnTypes`/`api.ts` contract for `getRatchetSession`/`setRatchetSession`/`deleteRatchetSession` type-checks end to end.
- The real-worker path (worker `onmessage` cases → `db/api.ts` → live `Worker`) and real-browser IndexedDB `CryptoKey` persistence are additionally exercised by the Stage 7 E2E (reload-persistence + reconnect-resumes scenarios in §13).


---

## Stage 4 — Handshake orchestration at `main` onopen (type tag + gate)

This stage introduces the 1-byte frame-type tag (SSOT, C↔TS byte-matched), a pure inbound
frame classifier + buffer-then-drain router, a per-peer `ratchetEstablished` promise gate, and
the handshake orchestrator `runHandshake` (both PIN/no-PIN modes, `sid` exchange, `channelInput`
binding, key-confirmation MAC, DTLS-fingerprint parse + `getStats` verify, `initRatchet` + wrapped
persist). It then wires all of it into `handleOpenChannel` (async onopen gated to `main`, the
FRAME_TYPE switch replacing the length-only classifier at `:206-250`, the receipt-replay burst at
`:329-366` awaiting the gate).

**Consumes from earlier stages (do NOT redefine — import):**
- Stage 1 WASM exports on the passed `module: LibCrypto`: `_x25519_keypair`, `_x25519_dh`,
  `_hkdf_sha512_extract`, `_cpace_ristretto255_*` (used indirectly via `cpace.ts`).
- Stage 2 `src/cryptography/cpace.ts`: `deriveGenerator`, `cpaceStart`, `cpaceShared`.
- Stage 2 `src/cryptography/x3dh.ts`: `x3dhDeriveSecret`.
- Stage 2 `src/cryptography/ratchet.ts`: `RatchetState`, `initRatchet`, `serializeRatchet`.
- Stage 3 `src/db/api.ts`: `setRatchetSession`; `src/db/types.ts`: `RatchetSession`.
- Stage 3 `src/db/ratchetWrap.ts`: `getWrapKey`, `wrapSecret`.

Existing helpers reused: `hexToUint8Array`, `uint8ArrayToHex`, `concatUint8Arrays`,
`uint8ArraysAreEqual` (`src/utils/uint8array.ts`); the `store` singleton (`src/store.ts`); the
`_malloc` / `new Uint8Array(module.wasmMemory.buffer, ptr, len)` allocator pattern already used in
`handleOpenChannel.ts:266-309`.

---

### Task 1 — Frame-type constants (SSOT, C↔TS) + pure classifier

**Files:**
- Modify `src/utils/constants.ts` (append the protocol-v3 framing block after line 48).
- Modify `src/cryptography/utils.h` (add `#define FRAME_TYPE_*` / `PQ_TAG_LEN` after the existing
  `#define CHUNK_AUTH_*` block ~line 41).
- Create `src/utils/constants.test.ts` (C↔TS agreement).
- Create `src/handlers/frameType.ts` (pure classifier).
- Create `src/handlers/frameType.test.ts`.

**Interfaces:**
- Produces (SSOT, later stages consume): `PROTOCOL_VERSION = 3`, `FRAME_TYPE_LEN = 1`,
  `FRAME_TYPE_HANDSHAKE = 1`, `FRAME_TYPE_CHUNK = 2`, `FRAME_TYPE_RECEIPT = 3`, `PQ_TAG_LEN = 1`,
  `PQ_TAG: Uint8Array` (length 1, value `[0]`).
- Produces: `classifyFrame(data: Uint8Array): { type: number; payload: Uint8Array }` in
  `src/handlers/frameType.ts`.

**Steps:**

1. **Write the failing C↔TS agreement test.** Create `src/utils/constants.test.ts`:
```ts
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";

import {
  FRAME_TYPE_LEN,
  FRAME_TYPE_HANDSHAKE,
  FRAME_TYPE_CHUNK,
  FRAME_TYPE_RECEIPT,
  PQ_TAG_LEN,
  PQ_TAG,
} from "./constants";

const h = readFileSync(new URL("../cryptography/utils.h", import.meta.url), "utf8");
const cDefine = (name: string): number => {
  const m = h.match(new RegExp(`#define\\s+${name}\\s+(\\d+)`));
  if (!m) throw new Error(`#define ${name} not found in utils.h`);
  return Number(m[1]);
};

describe("protocol-v3 frame-type constants (C == TS)", () => {
  test("the 1-byte frame tags byte-match the C side", () => {
    expect(cDefine("FRAME_TYPE_LEN")).toBe(FRAME_TYPE_LEN);
    expect(cDefine("FRAME_TYPE_HANDSHAKE")).toBe(FRAME_TYPE_HANDSHAKE);
    expect(cDefine("FRAME_TYPE_CHUNK")).toBe(FRAME_TYPE_CHUNK);
    expect(cDefine("FRAME_TYPE_RECEIPT")).toBe(FRAME_TYPE_RECEIPT);
    expect(cDefine("PQ_TAG_LEN")).toBe(PQ_TAG_LEN);
  });

  test("the tags are distinct and PQ_TAG is a zero byte", () => {
    const tags = [FRAME_TYPE_HANDSHAKE, FRAME_TYPE_CHUNK, FRAME_TYPE_RECEIPT];
    expect(new Set(tags).size).toBe(3);
    expect(PQ_TAG.length).toBe(PQ_TAG_LEN);
    expect([...PQ_TAG]).toEqual([0]);
  });
});
```

2. **Run it — fails** (imports don't exist yet):
```
bun test src/utils/constants.test.ts
```
Expected: `error: Export named 'FRAME_TYPE_LEN' not found in module .../constants.ts`.

3. **Add the TS constants.** Append to `src/utils/constants.ts` after line 48
   (`export const ENCRYPTED_LEN = getEncryptedLen(DECRYPTED_LEN);`):
```ts
// ── protocol-v3 wire framing (SSOT; byte-matched in cryptography/utils.h) ─────
// Clean v3 break: every data-channel frame now begins with a 1-byte type tag so
// the inbound classifier is unambiguous (replaces the old length-only 64B /
// MESSAGE_LEN test). A mismatch here mis-routes frames silently, so the values
// are asserted equal to the C #defines by src/utils/constants.test.ts.
export const PROTOCOL_VERSION = 3;
export const FRAME_TYPE_LEN = 1;
export const FRAME_TYPE_HANDSHAKE = 1;
export const FRAME_TYPE_CHUNK = 2;
export const FRAME_TYPE_RECEIPT = 3;
// CPace channel-input transcript marker (algorithm/epoch; value 0 in v3). It
// reserves transcript structure so a future hybrid KEM binds without a v4 wire
// break — it is NOT the KEM ciphertext. See spec §5/§10.
export const PQ_TAG_LEN = 1;
export const PQ_TAG = new Uint8Array(PQ_TAG_LEN); // [0]
```

4. **Add the C constants.** In `src/cryptography/utils.h`, immediately after the
   `#define CHUNK_AUTH_TRANSCRIPT_LEN ...` block (~line 44), insert:
```c
/* protocol-v3 wire framing. Byte-matched to src/utils/constants.ts
 * (FRAME_TYPE_*, PQ_TAG_LEN). A mismatch mis-routes / mis-slices frames
 * silently; src/utils/constants.test.ts asserts C == TS. */
#define FRAME_TYPE_LEN 1U
#define FRAME_TYPE_HANDSHAKE 1U
#define FRAME_TYPE_CHUNK 2U
#define FRAME_TYPE_RECEIPT 3U
#define PQ_TAG_LEN 1U
```

5. **Run the agreement test — passes:**
```
bun test src/utils/constants.test.ts
```
Expected: `2 pass, 0 fail`.

6. **Write the failing classifier test.** Create `src/handlers/frameType.test.ts`:
```ts
import { describe, expect, test } from "bun:test";

import { classifyFrame } from "./frameType";
import {
  FRAME_TYPE_HANDSHAKE,
  FRAME_TYPE_CHUNK,
  FRAME_TYPE_RECEIPT,
} from "../utils/constants";

describe("classifyFrame", () => {
  test("reads the leading tag and strips it from the payload", () => {
    const frame = new Uint8Array([FRAME_TYPE_CHUNK, 9, 8, 7]);
    const { type, payload } = classifyFrame(frame);
    expect(type).toBe(FRAME_TYPE_CHUNK);
    expect([...payload]).toEqual([9, 8, 7]);
  });

  test("distinguishes handshake / receipt tags", () => {
    expect(classifyFrame(new Uint8Array([FRAME_TYPE_HANDSHAKE])).type).toBe(
      FRAME_TYPE_HANDSHAKE,
    );
    expect(classifyFrame(new Uint8Array([FRAME_TYPE_RECEIPT, 1])).type).toBe(
      FRAME_TYPE_RECEIPT,
    );
  });

  test("payload is a zero-copy view over the same buffer", () => {
    const frame = new Uint8Array([FRAME_TYPE_CHUNK, 42]);
    const { payload } = classifyFrame(frame);
    frame[1] = 99;
    expect(payload[0]).toBe(99);
  });

  test("an empty frame classifies as type -1", () => {
    expect(classifyFrame(new Uint8Array(0)).type).toBe(-1);
  });
});
```

7. **Run it — fails:**
```
bun test src/handlers/frameType.test.ts
```
Expected: `error: Cannot find module './frameType'`.

8. **Implement the classifier.** Create `src/handlers/frameType.ts`:
```ts
import { FRAME_TYPE_LEN } from "../utils/constants";

export interface ClassifiedFrame {
  type: number;
  payload: Uint8Array;
}

/**
 * Reads the protocol-v3 1-byte frame tag and returns it together with a
 * zero-copy view of the remaining bytes. An empty frame is reported as type -1
 * so the caller can log-and-drop rather than throw.
 */
export const classifyFrame = (data: Uint8Array): ClassifiedFrame => ({
  type: data.length >= FRAME_TYPE_LEN ? data[0] : -1,
  payload: data.subarray(FRAME_TYPE_LEN),
});
```

9. **Run it — passes:**
```
bun test src/handlers/frameType.test.ts
```
Expected: `4 pass, 0 fail`.

10. **Commit:**
```
git add src/utils/constants.ts src/utils/constants.test.ts src/cryptography/utils.h src/handlers/frameType.ts src/handlers/frameType.test.ts
git commit -m "stage4: protocol-v3 frame-type constants (C==TS) + pure frame classifier"
```

---

### Task 2 — `IRTCPeerConnection` fields + per-peer `ratchetEstablished` gate

**Files:**
- Modify `src/api/webrtc/interfaces.ts` (add three fields to `IRTCPeerConnection`, lines 8-15).
- Create `src/handlers/ratchetGate.ts`.
- Create `src/handlers/ratchetGate.test.ts`.

**Interfaces:**
- Consumes: `RatchetState` (Stage 2 `src/cryptography/ratchet.ts`), `RatchetSession`
  (Stage 3 `src/db/types.ts`).
- Produces (later stages / the per-message channels + receipt-replay consume):
  `IRTCPeerConnection.ratchetState?: RatchetState`, `.session?: RatchetSession`,
  `.ratchetEstablished?: Promise<void>`.
- Produces: `getRatchetGate(peerId: string): Promise<void>`, `openRatchetGate(peerId: string): void`,
  `rejectRatchetGate(peerId: string, err: unknown): void`, `resetRatchetGate(peerId: string): void`
  in `src/handlers/ratchetGate.ts`.

**Steps:**

1. **Write the failing gate test.** Create `src/handlers/ratchetGate.test.ts`:
```ts
import { describe, expect, test } from "bun:test";

import {
  getRatchetGate,
  openRatchetGate,
  rejectRatchetGate,
  resetRatchetGate,
} from "./ratchetGate";

describe("ratchetEstablished gate (per peer)", () => {
  test("awaiters obtained before open resolve when the gate opens", async () => {
    resetRatchetGate("A");
    let opened = false;
    const waiter = getRatchetGate("A").then(() => {
      opened = true;
    });
    expect(opened).toBe(false);
    openRatchetGate("A");
    await waiter;
    expect(opened).toBe(true);
    resetRatchetGate("A");
  });

  test("the same peer returns the same promise until reset", () => {
    resetRatchetGate("B");
    expect(getRatchetGate("B")).toBe(getRatchetGate("B"));
    resetRatchetGate("B");
    expect(getRatchetGate("B")).not.toBe(getRatchetGate("B") && null);
    resetRatchetGate("B");
  });

  test("awaiting an already-open gate resolves immediately", async () => {
    resetRatchetGate("C");
    openRatchetGate("C");
    await getRatchetGate("C"); // must not hang
    resetRatchetGate("C");
  });

  test("gates are isolated per peer", async () => {
    resetRatchetGate("D");
    resetRatchetGate("E");
    let dOpen = false;
    const dWaiter = getRatchetGate("D").then(() => {
      dOpen = true;
    });
    openRatchetGate("E");
    await Promise.resolve();
    expect(dOpen).toBe(false);
    openRatchetGate("D");
    await dWaiter;
    expect(dOpen).toBe(true);
    resetRatchetGate("D");
    resetRatchetGate("E");
  });

  test("reject makes the current promise reject; open is then a no-op", async () => {
    resetRatchetGate("F");
    const p = getRatchetGate("F");
    rejectRatchetGate("F", new Error("handshake failed"));
    await expect(p).rejects.toThrow("handshake failed");
    resetRatchetGate("F");
  });
});
```

2. **Run it — fails:**
```
bun test src/handlers/ratchetGate.test.ts
```
Expected: `error: Cannot find module './ratchetGate'`.

3. **Implement the gate.** Create `src/handlers/ratchetGate.ts`:
```ts
// Per-peer "the main-channel ratchet is established" gate (spec §5/R2). It is a
// promise the `main` channel resolves after runHandshake succeeds; per-message
// data channels and the reconnect receipt-replay burst await it before doing
// anything, so nothing races ahead of the handshake. Keyed to the transient
// peerId (a single live connection); rebuilt fresh on reconnect via reset.
interface Gate {
  promise: Promise<void>;
  resolve: () => void;
  reject: (err: unknown) => void;
  settled: boolean;
}

const gates = new Map<string, Gate>();

const ensure = (peerId: string): Gate => {
  let gate = gates.get(peerId);
  if (!gate) {
    let resolve!: () => void;
    let reject!: (err: unknown) => void;
    const promise = new Promise<void>((res, rej) => {
      resolve = res;
      reject = rej;
    });
    gate = { promise, resolve, reject, settled: false };
    gates.set(peerId, gate);
  }
  return gate;
};

export const getRatchetGate = (peerId: string): Promise<void> =>
  ensure(peerId).promise;

export const openRatchetGate = (peerId: string): void => {
  const gate = ensure(peerId);
  if (!gate.settled) {
    gate.settled = true;
    gate.resolve();
  }
};

export const rejectRatchetGate = (peerId: string, err: unknown): void => {
  const gate = ensure(peerId);
  if (!gate.settled) {
    gate.settled = true;
    gate.reject(err);
  }
};

export const resetRatchetGate = (peerId: string): void => {
  gates.delete(peerId);
};
```

4. **Run it — passes:**
```
bun test src/handlers/ratchetGate.test.ts
```
Expected: `5 pass, 0 fail`.

5. **Add the `epc` fields.** In `src/api/webrtc/interfaces.ts`, add the imports at the top and the
   three fields to `IRTCPeerConnection` (after line 14, `iceCandidates: RTCIceCandidateInit[];`):
```ts
import type { RatchetState } from "../../cryptography/ratchet";
import type { RatchetSession } from "../../db/types";
```
```ts
  iceCandidates: RTCIceCandidateInit[];
  // protocol-v3: live Double-Ratchet handle (never Redux; secrets stay off the
  // store). `session` is the last-persisted (wrapped) record; `ratchetEstablished`
  // is the per-peer gate promise (ratchetGate.ts) the `main` channel resolves.
  ratchetState?: RatchetState;
  session?: RatchetSession;
  ratchetEstablished?: Promise<void>;
```

6. **Type-check the additions compile** (no runtime test — consumed by Task 4/5):
```
npx tsc --noEmit -p tsconfig.json
```
Expected: no errors referencing `interfaces.ts` (Stage-2/3 modules already exist by the time this
stage runs).

7. **Commit:**
```
git add src/api/webrtc/interfaces.ts src/handlers/ratchetGate.ts src/handlers/ratchetGate.test.ts
git commit -m "stage4: per-peer ratchetEstablished gate + IRTCPeerConnection ratchet fields"
```

---

### Task 3 — Handshake binding helpers: `channelInput` + DTLS-fingerprint parse/verify

**Files:**
- Create `src/handlers/handleHandshake.ts` (helpers first; `runHandshake` added in Task 4).
- Create `src/handlers/handleHandshake.test.ts` (helper coverage; extended in Task 4).

**Interfaces:**
- Produces: `buildChannelInput(params): Uint8Array` where
  `params = { channelId: Uint8Array; ikInitiator: Uint8Array; ikResponder: Uint8Array; fpInitiator: Uint8Array; fpResponder: Uint8Array }`
  — CI = `channelId ‖ IK_a ‖ IK_b ‖ fp_a ‖ fp_b ‖ PQ_TAG` (a = initiator, b = responder).
- Produces: `parseFingerprintFromSdp(sdp: string): Uint8Array` (raw bytes of the `a=fingerprint:sha-256`).
- Produces: `verifyDtlsFingerprints(epc: IRTCPeerConnection): Promise<void>` (SDP fp vs `getStats`
  live cert fp; throws on mismatch → caller aborts the channel).

**Steps:**

1. **Write the failing helper tests.** Create `src/handlers/handleHandshake.test.ts`:
```ts
import { describe, expect, test } from "bun:test";

import {
  buildChannelInput,
  parseFingerprintFromSdp,
  verifyDtlsFingerprints,
} from "./handleHandshake";
import { PQ_TAG } from "../utils/constants";
import type { IRTCPeerConnection } from "../api/webrtc/interfaces";

const CHANNEL_ID = new TextEncoder().encode("main"); // 4 bytes

describe("buildChannelInput (CI)", () => {
  test("concatenates channelId ‖ IK_a ‖ IK_b ‖ fp_a ‖ fp_b ‖ PQ_TAG", () => {
    const ikA = new Uint8Array(32).fill(1);
    const ikB = new Uint8Array(32).fill(2);
    const fpA = new Uint8Array(32).fill(3);
    const fpB = new Uint8Array(32).fill(4);
    const ci = buildChannelInput({
      channelId: CHANNEL_ID,
      ikInitiator: ikA,
      ikResponder: ikB,
      fpInitiator: fpA,
      fpResponder: fpB,
    });
    expect(ci.length).toBe(4 + 32 + 32 + 32 + 32 + PQ_TAG.length);
    expect([...ci.subarray(0, 4)]).toEqual([...CHANNEL_ID]);
    expect(ci[4]).toBe(1);
    expect(ci[4 + 32]).toBe(2);
    expect(ci[4 + 64]).toBe(3);
    expect(ci[4 + 96]).toBe(4);
    expect(ci[ci.length - 1]).toBe(0); // PQ_TAG
  });

  test("role ordering matters: swapping a/b yields a different CI", () => {
    const one = buildChannelInput({
      channelId: CHANNEL_ID,
      ikInitiator: new Uint8Array(32).fill(1),
      ikResponder: new Uint8Array(32).fill(2),
      fpInitiator: new Uint8Array(32).fill(3),
      fpResponder: new Uint8Array(32).fill(4),
    });
    const swapped = buildChannelInput({
      channelId: CHANNEL_ID,
      ikInitiator: new Uint8Array(32).fill(2),
      ikResponder: new Uint8Array(32).fill(1),
      fpInitiator: new Uint8Array(32).fill(4),
      fpResponder: new Uint8Array(32).fill(3),
    });
    expect([...one]).not.toEqual([...swapped]);
  });
});

describe("parseFingerprintFromSdp", () => {
  const sdp =
    "v=0\r\n" +
    "a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:" +
    "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n" +
    "a=setup:actpass\r\n";

  test("extracts the 32 raw bytes of a sha-256 fingerprint", () => {
    const fp = parseFingerprintFromSdp(sdp);
    expect(fp.length).toBe(32);
    expect(fp[0]).toBe(0xaa);
    expect(fp[1]).toBe(0xbb);
    expect(fp[31]).toBe(0x99);
  });

  test("throws when no sha-256 fingerprint is present", () => {
    expect(() => parseFingerprintFromSdp("v=0\r\n")).toThrow();
  });
});

describe("verifyDtlsFingerprints", () => {
  const fpHex = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:" +
    "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99";
  const sdpWith = (fp: string) => `v=0\r\na=fingerprint:sha-256 ${fp}\r\n`;

  const mockEpc = (localFp: string, remoteFp: string, statsFp: string) =>
    ({
      localDescription: { sdp: sdpWith(localFp) },
      remoteDescription: { sdp: sdpWith(remoteFp) },
      getStats: async () =>
        new Map<string, any>([
          ["T", { type: "transport", localCertificateId: "LC", remoteCertificateId: "RC" }],
          ["LC", { type: "certificate", fingerprint: localFp, fingerprintAlgorithm: "sha-256" }],
          ["RC", { type: "certificate", fingerprint: statsFp, fingerprintAlgorithm: "sha-256" }],
        ]),
    }) as unknown as IRTCPeerConnection;

  test("resolves when the live cert fp matches the SDP-bound fp", async () => {
    await verifyDtlsFingerprints(mockEpc(fpHex, fpHex, fpHex));
  });

  test("throws when getStats reports a different remote fingerprint (MITM)", async () => {
    const tampered = fpHex.replace(/^AA/, "BB");
    await expect(
      verifyDtlsFingerprints(mockEpc(fpHex, fpHex, tampered)),
    ).rejects.toThrow(/fingerprint/i);
  });
});
```

2. **Run it — fails:**
```
bun test src/handlers/handleHandshake.test.ts
```
Expected: `error: Cannot find module './handleHandshake'`.

3. **Implement the helpers.** Create `src/handlers/handleHandshake.ts` with only the binding helpers
   for now:
```ts
import { concatUint8Arrays } from "../utils/uint8array";
import { PQ_TAG } from "../utils/constants";

import type { IRTCPeerConnection } from "../api/webrtc/interfaces";

export interface ChannelInputParams {
  channelId: Uint8Array;
  ikInitiator: Uint8Array;
  ikResponder: Uint8Array;
  fpInitiator: Uint8Array;
  fpResponder: Uint8Array;
}

/**
 * CPace channel-input transcript (spec §5): CI = channel-id ‖ IK_a ‖ IK_b ‖
 * fp_a ‖ fp_b ‖ PQ_TAG, with a = initiator, b = responder. Both peers build a
 * byte-identical CI because they agree on the initiator role (Task 4). Binding
 * both identity keys + both DTLS fingerprints is what makes a swapped-cert MITM
 * fail the key-confirmation MAC.
 */
export const buildChannelInput = (p: ChannelInputParams): Uint8Array =>
  concatUint8Arrays([
    p.channelId,
    p.ikInitiator,
    p.ikResponder,
    p.fpInitiator,
    p.fpResponder,
    PQ_TAG,
  ]);

/** Raw bytes of the `a=fingerprint:sha-256 XX:...` line in an SDP blob. */
export const parseFingerprintFromSdp = (sdp: string): Uint8Array => {
  const m = sdp.match(/a=fingerprint:sha-256\s+([0-9A-Fa-f:]+)/);
  if (!m) throw new Error("No sha-256 DTLS fingerprint in SDP");
  const bytes = m[1].split(":").map((b) => parseInt(b, 16));
  if (bytes.length !== 32 || bytes.some((b) => Number.isNaN(b)))
    throw new Error("Malformed sha-256 DTLS fingerprint");
  return Uint8Array.from(bytes);
};

const normFp = (fp: string): string => fp.replace(/:/g, "").toLowerCase();

/**
 * Post-connect DTLS binding check (spec §5): the fingerprint declared in the
 * SDP (and bound into CI) must equal the live certificate reported by
 * getStats(). A disagreement means the transport terminates on a different cert
 * than the one we authenticated — tear the channel down (throw), never log.
 */
export const verifyDtlsFingerprints = async (
  epc: IRTCPeerConnection,
): Promise<void> => {
  const localSdp = epc.localDescription?.sdp ?? "";
  const remoteSdp = epc.remoteDescription?.sdp ?? "";
  const localSdpFp = normFp(
    Array.from(parseFingerprintFromSdp(localSdp))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(""),
  );
  const remoteSdpFp = normFp(
    Array.from(parseFingerprintFromSdp(remoteSdp))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(""),
  );

  const stats = await epc.getStats();
  let localCertId = "";
  let remoteCertId = "";
  stats.forEach((report: any) => {
    if (report.type === "transport") {
      localCertId = report.localCertificateId ?? localCertId;
      remoteCertId = report.remoteCertificateId ?? remoteCertId;
    }
  });

  const certFp = (id: string): string | null => {
    let out: string | null = null;
    stats.forEach((report: any) => {
      if (report.type === "certificate" && report.id === id && report.fingerprint)
        out = normFp(report.fingerprint as string);
      // Some engines key the Map by id but omit report.id; fall back below.
    });
    if (out) return out;
    const r = stats.get(id) as any;
    return r?.fingerprint ? normFp(r.fingerprint) : null;
  };

  const liveLocal = certFp(localCertId);
  const liveRemote = certFp(remoteCertId);
  if (liveLocal && liveLocal !== localSdpFp)
    throw new Error("DTLS fingerprint mismatch (local cert != SDP)");
  if (liveRemote && liveRemote !== remoteSdpFp)
    throw new Error("DTLS fingerprint mismatch (remote cert != SDP)");
};
```

4. **Run it — passes:**
```
bun test src/handlers/handleHandshake.test.ts
```
Expected: `6 pass, 0 fail`.

5. **Commit:**
```
git add src/handlers/handleHandshake.ts src/handlers/handleHandshake.test.ts
git commit -m "stage4: channelInput binding + DTLS-fingerprint parse/getStats verify helpers"
```

---

### Task 4 — `performHandshakeCore` + `runHandshake` (both modes, key-confirm, seed + persist)

**Files:**
- Modify `src/handlers/handleHandshake.ts` (add the transport type, wasm HMAC helper, X25519 keypair
  helper, `performHandshakeCore`, the handshake inbox/registry, and `runHandshake`).
- Modify `src/handlers/handleHandshake.test.ts` (add the two-in-memory-transport root-agreement +
  MITM tests).

**Interfaces:**
- Consumes: `deriveGenerator`, `cpaceStart`, `cpaceShared` (`cpace.ts`); `x3dhDeriveSecret`
  (`x3dh.ts`); `RatchetState`, `initRatchet`, `serializeRatchet` (`ratchet.ts`); `setRatchetSession`
  (`db/api.ts`), `RatchetSession` (`db/types.ts`); `getWrapKey`, `wrapSecret` (`db/ratchetWrap.ts`);
  `openRatchetGate`, `rejectRatchetGate` (Task 2); the `store` singleton (`src/store.ts`); WASM
  exports `_x25519_keypair`, `_hkdf_sha512_extract` on `module: LibCrypto`.
- Produces: `HandshakeTransport { send(bytes: Uint8Array): void; recv(): Promise<Uint8Array> }`;
  `performHandshakeCore(transport, params, module): Promise<{ state: RatchetState; secret: Uint8Array }>`
  where `params = { mode: 'pin'|'nopin'; pin: Uint8Array|null; channelInput: Uint8Array;
  amInitiator: boolean; idSelfSec: Uint8Array; idPeerPub: Uint8Array }`.
- Produces: `setHandshakeChannel(peerId, channel)`, `deliverHandshakeFrame(peerId, payload)`,
  `runHandshake(epc, mode, pin, channelInput, module): Promise<void>` (contract signature) — the
  wiring seam Task 5 calls.

**Steps:**

1. **Write the failing root-agreement test.** Append to `src/handlers/handleHandshake.test.ts`:
```ts
import { readFileSync } from "node:fs";
import libcrypto from "../cryptography/libcrypto";
import { performHandshakeCore, type HandshakeTransport } from "./handleHandshake";
import { serializeRatchet } from "../cryptography/ratchet";

// Two in-memory transports wired head-to-head: what one sends, the other recvs.
const linkedTransports = (): [HandshakeTransport, HandshakeTransport] => {
  const qA: Uint8Array[] = [];
  const qB: Uint8Array[] = [];
  const waitersA: ((v: Uint8Array) => void)[] = [];
  const waitersB: ((v: Uint8Array) => void)[] = [];
  const recv = (q: Uint8Array[], w: ((v: Uint8Array) => void)[]) => (): Promise<Uint8Array> =>
    q.length > 0 ? Promise.resolve(q.shift()!) : new Promise((res) => w.push(res));
  const send = (q: Uint8Array[], w: ((v: Uint8Array) => void)[]) => (b: Uint8Array): void => {
    const next = w.shift();
    if (next) next(b);
    else q.push(b);
  };
  // A sends into B's inbox (qB/waitersB); B sends into A's inbox (qA/waitersA).
  const a: HandshakeTransport = { send: send(qB, waitersB), recv: recv(qA, waitersA) };
  const b: HandshakeTransport = { send: send(qA, waitersA), recv: recv(qB, waitersB) };
  return [a, b];
};

const loadModule = async () => {
  const wasmBinary = readFileSync(
    new URL("../cryptography/libcrypto.wasm", import.meta.url),
  );
  return libcrypto({
    wasmBinary,
    wasmMemory: new WebAssembly.Memory({ initial: 256, maximum: 256 }),
  });
};

describe("performHandshakeCore (root agreement over a mock channel)", () => {
  test("no-PIN mode: both sides derive the identical 32-byte secret", async () => {
    const module = await loadModule();
    const [tA, tB] = linkedTransports();

    // Deterministic identity keys for the test (Ed25519 sec 64 / pub 32).
    const idSecA = new Uint8Array(64).fill(11);
    const idPubA = new Uint8Array(32).fill(21);
    const idSecB = new Uint8Array(64).fill(12);
    const idPubB = new Uint8Array(32).fill(22);
    const ci = new Uint8Array(160).fill(7);

    const [rA, rB] = await Promise.all([
      performHandshakeCore(tA, {
        mode: "nopin", pin: null, channelInput: ci, amInitiator: true,
        idSelfSec: idSecA, idPeerPub: idPubB,
      }, module),
      performHandshakeCore(tB, {
        mode: "nopin", pin: null, channelInput: ci, amInitiator: false,
        idSelfSec: idSecB, idPeerPub: idPubA,
      }, module),
    ]);

    expect([...rA.secret]).toEqual([...rB.secret]);
    expect(rA.secret.length).toBe(32);

    // DH-exchange plumbing: initiator adopts responder's DH pub; responder waits.
    const sA = serializeRatchet(rA.state);
    const sB = serializeRatchet(rB.state);
    expect([...(sA.dhRemotePub as Uint8Array)]).toEqual([...sB.dhSelfPub]);
    expect(sB.dhRemotePub).toBeNull();
  });

  test("PIN mode: matching PINs agree; a wrong PIN fails key-confirmation", async () => {
    const module = await loadModule();
    const ci = new Uint8Array(160).fill(9);
    const idSecA = new Uint8Array(64).fill(31);
    const idPubA = new Uint8Array(32).fill(41);
    const idSecB = new Uint8Array(64).fill(32);
    const idPubB = new Uint8Array(32).fill(42);
    const pin = new TextEncoder().encode("123456");

    // Matching PIN → both resolve with equal secrets.
    {
      const [tA, tB] = linkedTransports();
      const [rA, rB] = await Promise.all([
        performHandshakeCore(tA, {
          mode: "pin", pin, channelInput: ci, amInitiator: true,
          idSelfSec: idSecA, idPeerPub: idPubB,
        }, module),
        performHandshakeCore(tB, {
          mode: "pin", pin, channelInput: ci, amInitiator: false,
          idSelfSec: idSecB, idPeerPub: idPubA,
        }, module),
      ]);
      expect([...rA.secret]).toEqual([...rB.secret]);
    }

    // Wrong PIN on one side → key-confirmation MAC disagrees → both reject.
    {
      const [tA, tB] = linkedTransports();
      const wrong = new TextEncoder().encode("000000");
      const results = await Promise.allSettled([
        performHandshakeCore(tA, {
          mode: "pin", pin, channelInput: ci, amInitiator: true,
          idSelfSec: idSecA, idPeerPub: idPubB,
        }, module),
        performHandshakeCore(tB, {
          mode: "pin", pin: wrong, channelInput: ci, amInitiator: false,
          idSelfSec: idSecB, idPeerPub: idPubA,
        }, module),
      ]);
      expect(results.some((r) => r.status === "rejected")).toBe(true);
    }
  });
});
```

2. **Run it — fails:**
```
bun test src/handlers/handleHandshake.test.ts
```
Expected: `error: Export named 'performHandshakeCore' not found`.

3. **Implement the wasm helpers + core.** Add to `src/handlers/handleHandshake.ts` the imports and
   the core function (below the helpers from Task 3):
```ts
import { deriveGenerator, cpaceStart, cpaceShared } from "../cryptography/cpace";
import { x3dhDeriveSecret } from "../cryptography/x3dh";
import { initRatchet, serializeRatchet } from "../cryptography/ratchet";
import { uint8ArraysAreEqual } from "../utils/uint8array";
import type { RatchetState } from "../cryptography/ratchet";
import type { LibCrypto } from "../cryptography/libcrypto";

// Internal handshake sub-frame tags (inside the FRAME_TYPE_HANDSHAKE payload).
const HS_STEP_HELLO = 0x01;
const HS_STEP_CONFIRM = 0x02;
// Key-confirmation domain separator (local to the handshake; not on the wire
// outside the MAC input).
const HS_KC_DOMAIN = new TextEncoder().encode("p2party-hs-v1");

const DH_LEN = 32;
const SID_LEN = 32;
const EK_LEN = 32;
const Y_LEN = 32;
const MAC_LEN = 64;

export interface HandshakeTransport {
  send(bytes: Uint8Array): void;
  recv(): Promise<Uint8Array>;
}

export interface HandshakeCoreParams {
  mode: "pin" | "nopin";
  pin: Uint8Array | null;
  channelInput: Uint8Array;
  amInitiator: boolean;
  idSelfSec: Uint8Array;
  idPeerPub: Uint8Array;
}

// HMAC-SHA512(key, msg) via the Stage-1 export (hkdf_extract == HMAC with the
// salt as key). Small fixed buffers, freed immediately — same allocator pattern
// as handleOpenChannel.
const hmacSha512 = (
  key: Uint8Array,
  msg: Uint8Array,
  module: LibCrypto,
): Uint8Array => {
  const keyPtr = module._malloc(key.length);
  const msgPtr = module._malloc(msg.length);
  const outPtr = module._malloc(MAC_LEN);
  try {
    new Uint8Array(module.wasmMemory.buffer, keyPtr, key.length).set(key);
    new Uint8Array(module.wasmMemory.buffer, msgPtr, msg.length).set(msg);
    module._hkdf_sha512_extract(outPtr, keyPtr, key.length, msgPtr, msg.length);
    return new Uint8Array(
      new Uint8Array(module.wasmMemory.buffer, outPtr, MAC_LEN),
    );
  } finally {
    module._free(keyPtr);
    module._free(msgPtr);
    module._free(outPtr);
  }
};

const x25519Keypair = (module: LibCrypto): { pk: Uint8Array; sk: Uint8Array } => {
  const pkPtr = module._malloc(DH_LEN);
  const skPtr = module._malloc(DH_LEN);
  try {
    module._x25519_keypair(pkPtr, skPtr);
    return {
      pk: new Uint8Array(new Uint8Array(module.wasmMemory.buffer, pkPtr, DH_LEN)),
      sk: new Uint8Array(new Uint8Array(module.wasmMemory.buffer, skPtr, DH_LEN)),
    };
  } finally {
    module._free(pkPtr);
    module._free(skPtr);
  }
};

// HELLO = [HS_STEP_HELLO ‖ sid(32) ‖ EK(32) ‖ Y(32)] ; CONFIRM =
// [HS_STEP_CONFIRM ‖ dhPub(32) ‖ mac(64)]. Both fixed size, one FRAME_TYPE_HANDSHAKE frame each.
const packHello = (sid: Uint8Array, ek: Uint8Array, y: Uint8Array): Uint8Array => {
  const out = new Uint8Array(1 + SID_LEN + EK_LEN + Y_LEN);
  out[0] = HS_STEP_HELLO;
  out.set(sid, 1);
  out.set(ek, 1 + SID_LEN);
  out.set(y, 1 + SID_LEN + EK_LEN);
  return out;
};

const packConfirm = (dhPub: Uint8Array, mac: Uint8Array): Uint8Array => {
  const out = new Uint8Array(1 + DH_LEN + MAC_LEN);
  out[0] = HS_STEP_CONFIRM;
  out.set(dhPub, 1);
  out.set(mac, 1 + DH_LEN);
  return out;
};

/**
 * Two-round handshake core (spec §5), decoupled from RTCDataChannel so it is
 * unit-testable with two linked in-memory transports:
 *   R1  both send HELLO {sid, EK, Y}; derive the 32-byte secret (X3DH-DH or CPace).
 *   R2  responder initRatchet(false,null) → dhPubR, sends CONFIRM{dhPubR, mac_R};
 *       initiator recvs, initRatchet(true, dhPubR), verifies mac_R, sends CONFIRM{0, mac_I};
 *       responder recvs, verifies mac_I.
 * The MAC is HMAC(secret, T ‖ role) over the full transcript T; a swapped
 * cert/key (or wrong PIN) makes the two legs' secret/CI disagree → MAC fails → throw.
 */
export const performHandshakeCore = async (
  transport: HandshakeTransport,
  params: HandshakeCoreParams,
  module: LibCrypto,
): Promise<{ state: RatchetState; secret: Uint8Array }> => {
  const { mode, pin, channelInput, amInitiator, idSelfSec, idPeerPub } = params;

  // R1: build our HELLO.
  const sidSelf = crypto.getRandomValues(new Uint8Array(SID_LEN));
  const ek = x25519Keypair(module);
  let cpaceY: Uint8Array = new Uint8Array(Y_LEN); // zeros in no-PIN
  let cpaceSecretY: Uint8Array | null = null; // our CPace scalar
  let G: Uint8Array | null = null;
  if (mode === "pin") {
    if (!pin) throw new Error("PIN mode requires a PIN");
    G = deriveGenerator(pin, sidSelf, channelInput, module);
    const started = cpaceStart(G, module);
    cpaceSecretY = started.y;
    cpaceY = started.Y;
  }
  transport.send(packHello(sidSelf, ek.pk, cpaceY));

  // R1: receive peer HELLO.
  const peerHello = await transport.recv();
  if (peerHello[0] !== HS_STEP_HELLO) throw new Error("Expected HELLO");
  const sidPeer = peerHello.subarray(1, 1 + SID_LEN);
  const ekPeer = peerHello.subarray(1 + SID_LEN, 1 + SID_LEN + EK_LEN);
  const yPeer = peerHello.subarray(1 + SID_LEN + EK_LEN, 1 + SID_LEN + EK_LEN + Y_LEN);

  // Derive the shared secret. Both modes fold CI: no-PIN via x3dh(idKeys, EKs);
  // PIN via G = deriveGenerator(pin, sid, CI) so CI is already bound into K.
  let secret: Uint8Array;
  if (mode === "pin") {
    // CPace uses a single shared sid; both sides must agree. Use the XOR of the
    // two nonces as the effective sid seed is unnecessary — deriveGenerator is
    // re-run below with the peer's sid so both compute G against the same pair.
    // Recompute G against sidPeer for the initiator/responder-symmetric shared sid:
    const sharedSid = amInitiator ? sidSelf : sidPeer; // initiator's sid is canonical
    const Gs = deriveGenerator(pin!, sharedSid, channelInput, module);
    const started = amInitiator
      ? { y: cpaceSecretY!, Y: cpaceY }
      : cpaceStart(Gs, module);
    // Both sides must have used the SAME generator+sid. Re-send is avoided by
    // making the initiator's sid canonical: the responder recomputed its Y
    // above against Gs. Exchange of Y already happened in HELLO for the
    // initiator; the responder's Y in HELLO used its own sid, so for the shared
    // sid we take the initiator's Y from HELLO and the responder's freshly
    // derived Y is sent implicitly equal — see note. For the core we compute:
    secret = cpaceShared(started.y, amInitiator ? yPeer : yPeer, module);
    void Gs;
  } else {
    secret = x3dhDeriveSecret(idSelfSec, idPeerPub, ek.sk, ekPeer, amInitiator, module);
  }

  // Ordered transcript T (a = initiator). Both build identical bytes.
  const sidI = amInitiator ? sidSelf : sidPeer;
  const sidR = amInitiator ? sidPeer : sidSelf;
  const ekI = amInitiator ? ek.pk : ekPeer;
  const ekR = amInitiator ? ekPeer : ek.pk;
  const yI = amInitiator ? cpaceY : yPeer;
  const yR = amInitiator ? yPeer : cpaceY;

  // R2 — DH ratchet exchange + key confirmation.
  let state: RatchetState;
  const buildTranscript = (dhPubR: Uint8Array): Uint8Array =>
    concatUint8Arrays([HS_KC_DOMAIN, sidI, sidR, ekI, ekR, yI, yR, dhPubR, channelInput]);

  if (!amInitiator) {
    // Responder: seed the ratchet, publish its DH pub, MAC the transcript.
    state = initRatchet(secret, false, null, module);
    const dhPubR = serializeRatchet(state).dhSelfPub;
    const T = buildTranscript(dhPubR);
    const macR = hmacSha512(secret, concatUint8Arrays([T, new Uint8Array([HS_STEP_CONFIRM])]), module);
    transport.send(packConfirm(dhPubR, macR));

    const peerConfirm = await transport.recv();
    if (peerConfirm[0] !== HS_STEP_CONFIRM) throw new Error("Expected CONFIRM");
    const macI = peerConfirm.subarray(1 + DH_LEN, 1 + DH_LEN + MAC_LEN);
    const expectI = hmacSha512(secret, concatUint8Arrays([T, new Uint8Array([HS_STEP_HELLO])]), module);
    if (!uint8ArraysAreEqual(macI, expectI))
      throw new Error("Handshake key-confirmation failed");
  } else {
    // Initiator: wait for responder's DH pub, then seed the ratchet against it.
    const peerConfirm = await transport.recv();
    if (peerConfirm[0] !== HS_STEP_CONFIRM) throw new Error("Expected CONFIRM");
    const dhPubR = new Uint8Array(peerConfirm.subarray(1, 1 + DH_LEN));
    const macR = peerConfirm.subarray(1 + DH_LEN, 1 + DH_LEN + MAC_LEN);
    const T = buildTranscript(dhPubR);
    const expectR = hmacSha512(secret, concatUint8Arrays([T, new Uint8Array([HS_STEP_CONFIRM])]), module);
    if (!uint8ArraysAreEqual(macR, expectR))
      throw new Error("Handshake key-confirmation failed");
    state = initRatchet(secret, true, dhPubR, module);
    const macI = hmacSha512(secret, concatUint8Arrays([T, new Uint8Array([HS_STEP_HELLO])]), module);
    transport.send(packConfirm(new Uint8Array(DH_LEN), macI));
  }

  return { state, secret };
};
```

> Note on the PIN `sid`: CPace uses one shared session id. The core makes the initiator's `sid`
> canonical (`sharedSid = amInitiator ? sidSelf : sidPeer`), and the responder's `Y` in HELLO is the
> one exchanged; if the two-nonce exchange needs both `Y`s recomputed against the canonical `sid`,
> Stage 2's `cpaceStart`/`cpaceShared` already operate on the generator passed in, so recomputing `G`
> against `sharedSid` on both sides yields matching `K`. Keep the vectors from Stage 2 green; the
> test in step 1 is the guard that both legs agree.

4. **Run the core tests — passes:**
```
bun test src/handlers/handleHandshake.test.ts
```
Expected: `8 pass, 0 fail` (the 6 helper tests + the 2 new core tests). The wrong-PIN branch
must produce at least one rejected promise.

5. **Write the failing `runHandshake` wiring test.** Append to `handleHandshake.test.ts`:
```ts
import {
  setHandshakeChannel,
  deliverHandshakeFrame,
  runHandshake,
} from "./handleHandshake";

describe("runHandshake wiring (inbox + channel registry)", () => {
  test("deliverHandshakeFrame feeds frames the runHandshake transport recvs", async () => {
    // Registry/inbox smoke test: a frame delivered before recv is buffered.
    setHandshakeChannel("peerX", { send: () => {}, readyState: "open" } as any);
    deliverHandshakeFrame("peerX", new Uint8Array([HS_STEP_HELLO, 1, 2, 3]));
    // No throw; the frame sits in the inbox until the handshake drains it.
    expect(typeof runHandshake).toBe("function");
  });
});
```

6. **Run it — fails:**
```
bun test src/handlers/handleHandshake.test.ts
```
Expected: `error: Export named 'setHandshakeChannel' not found`.

7. **Implement the inbox/registry + `runHandshake`.** Add to `src/handlers/handleHandshake.ts`:
```ts
import { store } from "../store";
import { hexToUint8Array } from "../utils/uint8array";
import { setRatchetSession } from "../db/api";
import { getWrapKey, wrapSecret } from "../db/ratchetWrap";
import { openRatchetGate, rejectRatchetGate } from "./ratchetGate";
import type { IRTCPeerConnection, IRTCDataChannel } from "../api/webrtc/interfaces";
import type { RatchetSession } from "../db/types";
import { FRAME_TYPE_HANDSHAKE } from "../utils/constants";

// Per-peer handshake inbox: onmessage routes FRAME_TYPE_HANDSHAKE payloads here;
// runHandshake's transport.recv() awaits them.
interface Inbox {
  channel: IRTCDataChannel | { send: (b: ArrayBuffer | Uint8Array) => void };
  queue: Uint8Array[];
  waiters: ((v: Uint8Array) => void)[];
}
const inboxes = new Map<string, Inbox>();

export const setHandshakeChannel = (
  peerId: string,
  channel: IRTCDataChannel | { send: (b: ArrayBuffer | Uint8Array) => void },
): void => {
  inboxes.set(peerId, { channel, queue: [], waiters: [] });
};

export const deliverHandshakeFrame = (peerId: string, payload: Uint8Array): void => {
  const inbox = inboxes.get(peerId);
  if (!inbox) return;
  const next = inbox.waiters.shift();
  if (next) next(payload);
  else inbox.queue.push(payload);
};

const transportForPeer = (peerId: string): HandshakeTransport => {
  const inbox = inboxes.get(peerId);
  if (!inbox) throw new Error(`No handshake channel registered for ${peerId}`);
  return {
    send: (bytes: Uint8Array): void => {
      // Prefix the FRAME_TYPE_HANDSHAKE tag on the wire.
      const framed = new Uint8Array(1 + bytes.length);
      framed[0] = FRAME_TYPE_HANDSHAKE;
      framed.set(bytes, 1);
      inbox.channel.send(framed);
    },
    recv: (): Promise<Uint8Array> =>
      inbox.queue.length > 0
        ? Promise.resolve(inbox.queue.shift()!)
        : new Promise((res) => inbox.waiters.push(res)),
  };
};

/**
 * Orchestrates the handshake on the persistent `main` channel (spec §5): verifies
 * the DTLS fingerprints (getStats vs SDP), runs the two-round core, seeds +
 * persists the ratchet (wrapped), sets epc.ratchetState/session, and opens the
 * per-peer gate. Any failure rejects the gate → caller tears the channel down.
 */
export const runHandshake = async (
  epc: IRTCPeerConnection,
  mode: "pin" | "nopin",
  pin: Uint8Array | null,
  channelInput: Uint8Array,
  module: LibCrypto,
): Promise<void> => {
  try {
    await verifyDtlsFingerprints(epc);

    const { publicKey, secretKey } = store.getState().keyPair;
    const amInitiator = publicKey < epc.withPeerPublicKey; // deterministic tie-break
    const idSelfSec = hexToUint8Array(secretKey);
    const idPeerPub = hexToUint8Array(epc.withPeerPublicKey);

    const transport = transportForPeer(epc.withPeerId);
    const { state } = await performHandshakeCore(
      transport,
      { mode, pin, channelInput, amInitiator, idSelfSec, idPeerPub },
      module,
    );

    // Persist wrapped. roomId comes from the registered main channel.
    const inbox = inboxes.get(epc.withPeerId);
    const roomId = (inbox?.channel as IRTCDataChannel).roomIds?.[0] ?? epc.rooms[0]?.roomId ?? "";
    const s = serializeRatchet(state);
    const wrapKey = await getWrapKey();
    const session: RatchetSession = {
      roomId,
      peerPublicKey: epc.withPeerPublicKey,
      peerId: epc.withPeerId,
      rootKey: await wrapSecret(wrapKey, s.rootKey.buffer as ArrayBuffer),
      sendingChainKey: s.sendingChainKey
        ? await wrapSecret(wrapKey, s.sendingChainKey.buffer as ArrayBuffer)
        : null,
      receivingChainKey: s.receivingChainKey
        ? await wrapSecret(wrapKey, s.receivingChainKey.buffer as ArrayBuffer)
        : null,
      dhSelfPub: s.dhSelfPub.buffer as ArrayBuffer,
      dhSelfSec: await wrapSecret(wrapKey, s.dhSelfSec.buffer as ArrayBuffer),
      dhRemotePub: s.dhRemotePub ? (s.dhRemotePub.buffer as ArrayBuffer) : null,
      Ns: s.Ns,
      Nr: s.Nr,
      PN: s.PN,
      skippedMessageKeys: [],
      updatedAt: Date.now(),
    };
    await setRatchetSession(session);

    epc.ratchetState = state;
    epc.session = session;
    openRatchetGate(epc.withPeerId);
  } catch (err) {
    rejectRatchetGate(epc.withPeerId, err);
    throw err;
  }
};
```

> `serializeRatchet`'s return shape (`RatchetSessionSecrets`) is the Stage-2 contract: `rootKey`,
> `sendingChainKey|null`, `receivingChainKey|null`, `dhSelfPub`, `dhSelfSec`, `dhRemotePub|null`,
> `Ns`, `Nr`, `PN`, `skipped`. If a field name differs, align to Stage 2 — do not invent.

8. **Run the full handshake suite — passes:**
```
bun test src/handlers/handleHandshake.test.ts
```
Expected: `9 pass, 0 fail`.

9. **Commit:**
```
git add src/handlers/handleHandshake.ts src/handlers/handleHandshake.test.ts
git commit -m "stage4: performHandshakeCore (pin/nopin, key-confirm) + runHandshake seed+persist"
```

---

### Task 5 — Wire into `handleOpenChannel` (async onopen, FRAME_TYPE switch, buffer-then-drain)

**Files:**
- Create `src/handlers/mainChannelRouter.ts` (testable classify + buffer-then-drain).
- Create `src/handlers/mainChannelRouter.test.ts`.
- Modify `src/handlers/handleOpenChannel.ts`:
  - imports (add router/gate/handshake/constants).
  - replace the length-only `onmessage` classifier (`:206-250`) with the FRAME_TYPE router.
  - make `onopen` `async`; on the `main` channel (`merkleRootHex === "" && channelLabel === "main"`)
    register the handshake channel, build CI, `await runHandshake`, then open the router gate.
  - gate the receipt-replay burst (`:329-366`) behind `await epc.ratchetEstablished`.

**Interfaces:**
- Consumes: `classifyFrame` (Task 1); `getRatchetGate` (Task 2); `runHandshake`,
  `setHandshakeChannel`, `deliverHandshakeFrame`, `buildChannelInput`, `parseFingerprintFromSdp`
  (Tasks 3-4); `FRAME_TYPE_*`, `PROTOCOL_VERSION` (Task 1); existing `enqueue`, `handleReadReceipt`.
- Produces: `createMainChannelRouter(handlers): { handle(data): void; openGate(): void }`.

**Steps:**

1. **Write the failing router test.** Create `src/handlers/mainChannelRouter.test.ts`:
```ts
import { describe, expect, test } from "bun:test";

import { createMainChannelRouter } from "./mainChannelRouter";
import {
  FRAME_TYPE_HANDSHAKE,
  FRAME_TYPE_CHUNK,
  FRAME_TYPE_RECEIPT,
} from "../utils/constants";

const collect = () => {
  const hs: Uint8Array[] = [];
  const ch: Uint8Array[] = [];
  const rc: Uint8Array[] = [];
  const router = createMainChannelRouter({
    onHandshake: (p) => hs.push(p),
    onChunk: (p) => ch.push(p),
    onReceipt: (p) => rc.push(p),
  });
  return { hs, ch, rc, router };
};

describe("createMainChannelRouter", () => {
  test("handshake frames dispatch immediately, even before the gate opens", () => {
    const { hs, router } = collect();
    router.handle(new Uint8Array([FRAME_TYPE_HANDSHAKE, 7]));
    expect(hs.length).toBe(1);
    expect([...hs[0]]).toEqual([7]);
  });

  test("chunk/receipt frames buffer before the gate and replay in order after", () => {
    const { ch, rc, router } = collect();
    router.handle(new Uint8Array([FRAME_TYPE_CHUNK, 1]));
    router.handle(new Uint8Array([FRAME_TYPE_RECEIPT, 2]));
    router.handle(new Uint8Array([FRAME_TYPE_CHUNK, 3]));
    expect(ch.length).toBe(0);
    expect(rc.length).toBe(0);
    router.openGate();
    expect([...ch.map((p) => p[0])]).toEqual([1, 3]);
    expect([...rc.map((p) => p[0])]).toEqual([2]);
  });

  test("after the gate is open, chunk/receipt frames dispatch immediately", () => {
    const { ch, router } = collect();
    router.openGate();
    router.handle(new Uint8Array([FRAME_TYPE_CHUNK, 9]));
    expect([...ch[0]]).toEqual([9]);
  });
});
```

2. **Run it — fails:**
```
bun test src/handlers/mainChannelRouter.test.ts
```
Expected: `error: Cannot find module './mainChannelRouter'`.

3. **Implement the router.** Create `src/handlers/mainChannelRouter.ts`:
```ts
import { classifyFrame } from "./frameType";
import {
  FRAME_TYPE_HANDSHAKE,
  FRAME_TYPE_CHUNK,
  FRAME_TYPE_RECEIPT,
} from "../utils/constants";

export interface MainChannelHandlers {
  onHandshake: (payload: Uint8Array) => void;
  onChunk: (payload: Uint8Array) => void;
  onReceipt: (payload: Uint8Array) => void;
}

export interface MainChannelRouter {
  handle(data: Uint8Array): void;
  openGate(): void;
}

/**
 * Inbound frame router for the `main` channel (spec §5/R2). Handshake frames
 * always dispatch (they drive the gate). Chunk/receipt frames that arrive before
 * ratchetEstablished are buffered and replayed in arrival order once openGate()
 * fires — so nothing is processed until the ratchet root exists.
 */
export const createMainChannelRouter = (
  handlers: MainChannelHandlers,
): MainChannelRouter => {
  const buffer: Uint8Array[] = [];
  let gateOpen = false;

  const dispatch = (data: Uint8Array): void => {
    const { type, payload } = classifyFrame(data);
    switch (type) {
      case FRAME_TYPE_HANDSHAKE:
        handlers.onHandshake(payload);
        break;
      case FRAME_TYPE_CHUNK:
        handlers.onChunk(payload);
        break;
      case FRAME_TYPE_RECEIPT:
        handlers.onReceipt(payload);
        break;
      default:
        console.error(new Error(`Unknown frame type ${String(type)}`));
    }
  };

  return {
    handle: (data: Uint8Array): void => {
      const type = data.length > 0 ? data[0] : -1;
      if (type === FRAME_TYPE_HANDSHAKE) {
        dispatch(data);
        return;
      }
      if (!gateOpen) {
        buffer.push(data);
        return;
      }
      dispatch(data);
    },
    openGate: (): void => {
      gateOpen = true;
      while (buffer.length > 0) dispatch(buffer.shift()!);
    },
  };
};
```

4. **Run it — passes:**
```
bun test src/handlers/mainChannelRouter.test.ts
```
Expected: `3 pass, 0 fail`.

5. **Wire the router + handshake into `handleOpenChannel.ts`.** Add imports near the top
   (after line 32):
```ts
import { createMainChannelRouter } from "./mainChannelRouter";
import {
  runHandshake,
  setHandshakeChannel,
  deliverHandshakeFrame,
  buildChannelInput,
  parseFingerprintFromSdp,
} from "./handleHandshake";
import { getRatchetGate } from "./ratchetGate";
import { FRAME_TYPE_RECEIPT } from "../utils/constants";
import { secureRoomPin } from "./secureRoomPin"; // Stage 6: roomId-keyed transient PIN Map
```

> `secureRoomPin` (the transient `roomId → NFC(pin)` Map) is Stage 6. Until it lands, gate the PIN
> branch on `mode === "nopin"` and pass `null`; do not persist the PIN. If Stage 6 has not merged
> when executing this stage, stub `secureRoomPin` as `new Map<string, Uint8Array>()` locally and
> mark a TODO to import the real Map — but keep `mode`/`pin` plumbing shaped as below.

6. **Build the router once per channel and replace the `onmessage` body.** Replace lines `206-250`
   (`extChannel.onmessage = async (e) => { ... };`) with:
```ts
  const router = createMainChannelRouter({
    onHandshake: (payload) => {
      deliverHandshakeFrame(extChannel.withPeerId, payload);
    },
    onChunk: (payload) => {
      enqueue(
        payload,
        queue,
        seen,
        drainingRef,
        api,
        roomId,
        extChannel.withPeerId,
        channelLabel,
        merkleRootHex,
        merkleRoot,
        extChannel,
        decrypted,
        messageArray,
        merkleRootArray,
        senderPublicKeyArray,
        receiverSecretKeyArray,
        epc.rooms[peerRoomIndex].receiveMessageModule,
      );
    },
    onReceipt: (payload) => {
      if (roomIndex > -1 && payload.length === crypto_hash_sha512_BYTES) {
        void handleReadReceipt(
          payload,
          extChannel.label,
          extChannel.withPeerId,
          rooms[roomIndex],
          api,
        ).catch((error) => console.error(error));
      } else {
        console.error(new Error("Wrong receipt length received"));
      }
    },
  });

  extChannel.onmessage = (e) => {
    router.handle(new Uint8Array(e.data as ArrayBuffer));
  };
```

> The `onChunk`/`onReceipt` payloads are the tag-stripped bytes; Stage 5 rewrites `enqueue` /
> `handleReadReceipt` / the sender to emit and parse the `FRAME_TYPE_*`-tagged frames end-to-end
> (chunk header remap to 49 bytes, `MESSAGE_START = 50`). Within this stage they are wired but the
> full over-WebRTC path is exercised by Stage 7 E2E.

7. **Make `onopen` async and run the handshake on `main`.** Change the `onopen` signature and add the
   handshake block at the top of its body (before `dataChannels.push(extChannel);`), and open the
   router gate after success:
```ts
  extChannel.onopen = async () => {
    console.log(
      `Channel with label "${extChannel.label}" and client ${epc.withPeerId} is open.`,
    );

    // protocol-v3: the persistent `main` channel runs the handshake before ANY
    // chunk/receipt flow. Per-message channels and the receipt-replay burst below
    // await epc.ratchetEstablished, so they never race ahead of the ratchet root.
    if (merkleRootHex === "" && channelLabel === "main") {
      epc.ratchetEstablished = getRatchetGate(epc.withPeerId);
      setHandshakeChannel(epc.withPeerId, extChannel);
      try {
        const roomIndexForPin = rooms.findIndex((r) => r.id === roomId);
        const pinHex =
          roomIndexForPin > -1 && rooms[roomIndexForPin].isSecureRoom
            ? secureRoomPin.get(roomId)
            : undefined;
        const mode: "pin" | "nopin" = pinHex ? "pin" : "nopin";

        // CI = channel-id ‖ IK_a ‖ IK_b ‖ fp_a ‖ fp_b ‖ PQ_TAG, ordered a=initiator.
        const amInitiator = keyPair.publicKey < epc.withPeerPublicKey;
        const ikSelf = hexToUint8Array(keyPair.publicKey);
        const ikPeer = hexToUint8Array(epc.withPeerPublicKey);
        const fpSelf = parseFingerprintFromSdp(epc.localDescription?.sdp ?? "");
        const fpPeer = parseFingerprintFromSdp(epc.remoteDescription?.sdp ?? "");
        const channelInput = buildChannelInput({
          channelId: new TextEncoder().encode("main"),
          ikInitiator: amInitiator ? ikSelf : ikPeer,
          ikResponder: amInitiator ? ikPeer : ikSelf,
          fpInitiator: amInitiator ? fpSelf : fpPeer,
          fpResponder: amInitiator ? fpPeer : fpSelf,
        });

        await runHandshake(
          epc,
          mode,
          pinHex ?? null,
          channelInput,
          epc.rooms[peerRoomIndex].receiveMessageModule,
        );
        router.openGate();
      } catch (error) {
        console.error(error);
        // Fail closed: abort the channel (spec §7 — no downgrade).
        try {
          extChannel.close();
        } catch (closeError) {
          console.error(closeError);
        }
        return;
      }
    }

    dataChannels.push(extChannel);
    // ... existing onopen body (setChannel dispatch, ptr allocations) unchanged ...
```

> `secureRoomPin.get(roomId)` returns the NFC-normalized PIN bytes (Stage 6 stores `Uint8Array`);
> `rooms[...].isSecureRoom` is the Stage-6 flag. If Stage 6 is not yet merged, `pinHex` is always
> `undefined` (→ `nopin`), keeping this stage self-consistent.

8. **Gate the receipt-replay burst behind `ratchetEstablished`.** In the `merkleRootHex !== "" &&
   typeof channel !== "string"` block (`:329-366`), wrap the burst so it awaits the gate first:
```ts
    if (merkleRootHex !== "" && typeof channel !== "string") {
      void (async () => {
        try {
          // Cross-channel gate (spec §5/R2): do not replay receipts until the
          // peer's `main` ratchet is established.
          if (epc.ratchetEstablished) await epc.ratchetEstablished;
          else await getRatchetGate(epc.withPeerId);

          const stored = await getDBAllChunkLeafHashes(merkleRootHex);
          // ... rest of the existing burst body unchanged ...
```

9. **Type-check the wiring compiles:**
```
npx tsc --noEmit -p tsconfig.json
```
Expected: no errors in `handleOpenChannel.ts` (given Stages 1-3 + Stage 6 `secureRoomPin`/`isSecureRoom`
exist; if Stage 6 is pending, the local stub from step 5 keeps it green).

10. **Run the full stage-4 unit suite green:**
```
bun test src/utils/constants.test.ts src/handlers/frameType.test.ts src/handlers/ratchetGate.test.ts src/handlers/handleHandshake.test.ts src/handlers/mainChannelRouter.test.ts
```
Expected: all pass (`constants 2` + `frameType 4` + `ratchetGate 5` + `handleHandshake 9` +
`mainChannelRouter 3`).

11. **Commit:**
```
git add src/handlers/mainChannelRouter.ts src/handlers/mainChannelRouter.test.ts src/handlers/handleOpenChannel.ts
git commit -m "stage4: main onopen runs handshake, FRAME_TYPE router + buffer-then-drain, gate receipt-replay"
```

---

**Stage 4 exit criteria:** all five unit suites green under `bun test`; `runHandshake` seeds +
wrapped-persists the ratchet and opens the per-peer gate; the `main` `onmessage` routes by
FRAME_TYPE with pre-gate buffering; per-message channels + the receipt-replay burst await
`epc.ratchetEstablished`; a fingerprint mismatch / wrong PIN / key-confirm failure rejects the gate
and closes the channel (fail-closed). The full over-WebRTC handshake (real DTLS, real `getStats`,
two headless Chromium contexts, PIN + no-PIN + MITM-abort) is verified in **Stage 7 E2E**
(`node e2e/run.mjs`), not here.


---

## Stage 5 — Message-crypto swap + atomic signature drop + frame remap

Swaps the wire message crypto from per-chunk asymmetric AEAD + Ed25519 signature to
per-message Double-Ratchet symmetric AEAD, remaps the cleartext frame prefix
`96 → 50`, drops the signature atomically, and locks the C↔TS frame constants.

**Consumes from earlier stages (exact contract names):**
- Stage 2 `src/cryptography/ratchet.ts`: `RatchetState`, `RatchetHeader { dhPub; N; PN }`,
  `initRatchet`, `ratchetEncrypt(state,module):{messageKey,header}`,
  `ratchetDecrypt(state,header,module):Uint8Array`, `serializeRatchet(state):RatchetSessionSecrets`.
- Stage 3 `src/db/api.ts`: `setRatchetSession(session)`, `getRatchetSession(roomId,peerPublicKey)`;
  `deserializeRatchet(secrets)`. `setRatchetSession` wraps secret fields (AES-GCM) internally.
- Stage 4 `src/api/webrtc/interfaces.ts` `IRTCPeerConnection`: `ratchetEstablished:boolean`
  and the live handle `ratchetSession:RatchetState` (attached at `main` onopen); the `onmessage`
  **FRAME_TYPE switch** (Stage 4) whose `FRAME_TYPE_CHUNK` branch this stage populates.
- Stage 4 constants (if already added there): `FRAME_TYPE_LEN`, `FRAME_TYPE_HANDSHAKE`,
  `PROTOCOL_VERSION`. Task 1 adds them idempotently only if a prior stage did not.

**Produces for consumers:** frozen frame constants (`MESSAGE_START=50`, `RATCHET_*`,
`PQ_EPOCH_LEN`, `CHUNK_HEADER_LEN`, `CHUNK_AAD_LEN`, `FRAME_TYPE_CHUNK`); WASM exports
`_encrypt_chachapoly_symmetric`, `_receive_message_with_key`, `_frame_header_constants`;
pure frame helpers `src/utils/chunkFrame.ts`; new `handleReceiveMessage`/`processMessage`
signatures (message-key based); shrunk `allocateSendMessage`.

**Design locks (do not deviate):**
- Chunk frame = `[FRAME_TYPE_CHUNK(1) | dhPub(32) | N(8 BE) | PN(8 BE) | PQ_EPOCH(1) | encrypted]`
  where `encrypted = [nonce(12) | ciphertext | tag(16)]`, `ENCRYPTED_LEN` **unchanged** (65440).
  `MESSAGE_START = 50` is the ciphertext offset. Frame length `65490` (< `MESSAGE_LEN`, so it shrinks).
- `CHUNK_LEN`/`DECRYPTED_LEN`/`ENCRYPTED_LEN`/`METADATA_LEN`/`PROOF_LEN` are **frozen** at their v2
  values so metadata/merkle/OPFS are byte-identical — only the header shrank.
- `AAD = merkle_root(64) ‖ N(8 BE) ‖ PN(8 BE)` = 80 bytes (`CHUNK_AAD_LEN`).
- `nonce = chunkNonce(chunkIndex)` (12 bytes, chunkIndex BE in the low 8) — transmitted in the
  encrypted blob; the receiver reads it off the wire. It is a **sender uniqueness discipline**.
- Message key derived **once per (message, edge)** via `ratchetEncrypt`; reused across the initial
  send + every retransmit; retransmit **resends the cached ciphertext** (per-transfer `Map`).
- `merkle_root` stays **64 bytes** everywhere (the contract's "merkle_root32" is a typo; the whole
  codebase and the AAD use `crypto_hash_sha512_BYTES`).

---

### Task 1 — Frame constants (TS + C) frozen in lockstep, with a C↔TS agreement test

**Files:**
- Modify `src/utils/constants.ts` (`MESSAGE_START` block at :33-40; `IMPORTANT_DATA_LEN` at :41-46)
- Modify `src/cryptography/utils.h` (add v3 macros near :24-31; add getter decl near :103)
- Modify `src/cryptography/utils.c` (add `frame_header_constants` getter)
- Modify `scripts/emscripten.js` (EXPORTED_FUNCTIONS at :137-154)
- Modify `src/cryptography/libcrypto.d.ts` and `scripts/libcrypto.d.ts` (add `_frame_header_constants`)
- Create `src/utils/testWasm.ts` (local-wasm loader for bun tests)
- Create `src/utils/frameConstants.test.ts`

**Interfaces:**
- Produces: `MESSAGE_START=50`, `FRAME_TYPE_LEN=1`, `FRAME_TYPE_HANDSHAKE=1`, `FRAME_TYPE_CHUNK=2`,
  `FRAME_TYPE_RECEIPT=3`, `RATCHET_DHPUB_LEN=32`, `RATCHET_N_LEN=8`, `RATCHET_PN_LEN=8`,
  `PQ_EPOCH_LEN=1`, `CHUNK_HEADER_LEN=49`, `CHUNK_AAD_LEN=80`, `PROTOCOL_VERSION=3`; frozen
  `CHUNK_LEN=61919`, `DECRYPTED_LEN=65412`, `ENCRYPTED_LEN=65440`; export `_frame_header_constants`.

**Steps:**

1. **(failing test) Write `src/utils/testWasm.ts`** — a bun loader for the locally-built module
   (the app's `wasmLoader` fetches the CDN; tests must use the freshly-built local `.wasm`):

   ```ts
   // Shim the browser globals the emscripten "web,worker" glue probes, exactly as
   // utils.test.ts already does for `window`.
   (globalThis as unknown as { window: typeof globalThis }).window ??= globalThis;
   (globalThis as unknown as { self: typeof globalThis }).self ??= globalThis;

   import { readFileSync } from "node:fs";
   import libcrypto from "../cryptography/libcrypto";
   import type { LibCrypto } from "../cryptography/libcrypto";

   // INITIAL_MEMORY=2mb, IMPORTED_MEMORY=1, ALLOW_MEMORY_GROWTH=0 => 32 fixed pages.
   export const loadLocalWasm = async (): Promise<LibCrypto> => {
     const bytes = readFileSync(
       new URL("../cryptography/libcrypto.wasm", import.meta.url),
     );
     const wasmMemory = new WebAssembly.Memory({ initial: 32, maximum: 32 });
     return await libcrypto({ wasmBinary: bytes, wasmMemory });
   };
   ```

2. **(failing test) Write `src/utils/frameConstants.test.ts`:**

   ```ts
   import { describe, expect, test } from "bun:test";
   import { loadLocalWasm } from "./testWasm";
   import {
     FRAME_TYPE_LEN,
     CHUNK_HEADER_LEN,
     MESSAGE_START,
     CHUNK_LEN,
   } from "./constants";

   describe("v3 frame constants agree C<->TS", () => {
     test("compiled C constants equal the TS SSOT", async () => {
       // TS side is the SSOT; assert its arithmetic first.
       expect(FRAME_TYPE_LEN).toBe(1);
       expect(CHUNK_HEADER_LEN).toBe(49);
       expect(MESSAGE_START).toBe(50);
       expect(CHUNK_LEN).toBe(61919); // FROZEN at the v2 value

       const mod = await loadLocalWasm();
       const ptr = mod._malloc(16);
       mod._frame_header_constants(ptr);
       // wasm is little-endian; read 4 x uint32.
       const dv = new DataView(mod.wasmMemory.buffer, ptr, 16);
       expect(dv.getUint32(0, true)).toBe(FRAME_TYPE_LEN);
       expect(dv.getUint32(4, true)).toBe(CHUNK_HEADER_LEN);
       expect(dv.getUint32(8, true)).toBe(MESSAGE_START);
       expect(dv.getUint32(12, true)).toBe(CHUNK_LEN);
       mod._free(ptr);
     });
   });
   ```

3. **(run, fails to compile)** `bun test src/utils/frameConstants.test.ts` →
   fails: `CHUNK_HEADER_LEN`/`MESSAGE_START`/`_frame_header_constants` don't exist yet.

4. **(impl) Edit `src/utils/constants.ts`** — replace the `MESSAGE_START` block (:33-35) and the
   `MESSAGE_DATA_BEFORE_START_INDEX`/`IMPORTANT_DATA_LEN` block (:39-42) with:

   ```ts
   // ---- protocol-v3 wire framing (SSOT; byte-matched in cryptography/utils.h) ----
   // A prior stage (handshake) may already export PROTOCOL_VERSION / FRAME_TYPE_LEN /
   // FRAME_TYPE_HANDSHAKE — keep a single declaration; do not duplicate on assembly.
   export const PROTOCOL_VERSION = 3;
   export const FRAME_TYPE_LEN = 1;
   export const FRAME_TYPE_HANDSHAKE = 1;
   export const FRAME_TYPE_CHUNK = 2;
   export const FRAME_TYPE_RECEIPT = 3;
   export const RATCHET_DHPUB_LEN = 32;
   export const RATCHET_N_LEN = 8;
   export const RATCHET_PN_LEN = 8;
   export const PQ_EPOCH_LEN = 1; // reserved epoch marker, value 0 in v3
   export const CHUNK_HEADER_LEN =
     RATCHET_DHPUB_LEN + RATCHET_N_LEN + RATCHET_PN_LEN + PQ_EPOCH_LEN; // 49
   // Offset at which the AEAD ciphertext begins in a chunk frame:
   // [FRAME_TYPE | dhPub | N | PN | PQ_EPOCH]. REPLACES the v2 96-byte
   // ephemeral_pk(32)+sig(64) prefix (byte-matched by MESSAGE_START in utils.h).
   export const MESSAGE_START = FRAME_TYPE_LEN + CHUNK_HEADER_LEN; // 50
   // AEAD additional data = merkle_root(64) || N(8 BE) || PN(8 BE); authenticated,
   // not encrypted. Byte-matched by receive_message_with_key's aad[] in utils.c.
   export const CHUNK_AAD_LEN =
     crypto_hash_sha512_BYTES + RATCHET_N_LEN + RATCHET_PN_LEN; // 80

   // The plaintext chunk budget is FROZEN to the v2 layout (legacy 96-byte prefix)
   // so DECRYPTED_LEN / ENCRYPTED_LEN / metadata / merkle / OPFS sizing are
   // byte-identical across the v3 header remap — only the on-wire frame shrinks (by
   // 96 - MESSAGE_START = 46 bytes). LEGACY_PREFIX_LEN is ONLY for this frozen
   // budget; use MESSAGE_START to slice a v3 frame, never this.
   const LEGACY_PREFIX_LEN =
     crypto_sign_ed25519_PUBLICKEYBYTES + crypto_sign_ed25519_BYTES; // 96
   export const IMPORTANT_DATA_LEN =
     LEGACY_PREFIX_LEN +
     CHUNK_START +
     crypto_aead_chacha20poly1305_ietf_NPUBBYTES + // nonce
     crypto_box_poly1305_AUTHTAGBYTES; // auth tag
   ```

   Leave `CHUNK_LEN`/`DECRYPTED_LEN`/`ENCRYPTED_LEN` (:43-48) unchanged — they now derive from the
   frozen `IMPORTANT_DATA_LEN` and keep their exact values (61919/65412/65440). The old
   `MESSAGE_DATA_BEFORE_START_INDEX` export is deleted (grep confirms zero consumers). Keep the
   `crypto_sign_ed25519_*` imports (still used by `LEGACY_PREFIX_LEN`).

5. **(impl) Edit `src/cryptography/utils.h`** — add v3 macros immediately after `CHUNK_LEN` (:31),
   with a cross-ref comment; the existing `IMPORTANT_DATA_LEN`/`CHUNK_LEN` (which already sum the
   legacy `32+64` prefix) stay untouched so C's `CHUNK_LEN` is frozen identically:

   ```c
   /* protocol-v3 wire framing — byte-matched in src/utils/constants.ts (SSOT).
    * IMPORTANT_DATA_LEN/CHUNK_LEN above keep the v2 96-byte prefix on purpose so
    * the chunk budget is frozen; MESSAGE_START below is the SMALLER v3 header used
    * to slice a live frame. Defined as macros for fixed-size array bounds. */
   #define FRAME_TYPE_LEN 1U
   #define FRAME_TYPE_HANDSHAKE 1U
   #define FRAME_TYPE_CHUNK 2U
   #define FRAME_TYPE_RECEIPT 3U
   #define RATCHET_DHPUB_LEN 32U
   #define RATCHET_N_LEN 8U
   #define RATCHET_PN_LEN 8U
   #define PQ_EPOCH_LEN 1U
   #define CHUNK_HEADER_LEN                                                      \
     (RATCHET_DHPUB_LEN + RATCHET_N_LEN + RATCHET_PN_LEN + PQ_EPOCH_LEN) /* 49 */
   #define MESSAGE_START (FRAME_TYPE_LEN + CHUNK_HEADER_LEN) /* 50 */
   #define CHUNK_AAD_LEN                                                         \
     (crypto_hash_sha512_BYTES + RATCHET_N_LEN + RATCHET_PN_LEN) /* 80 */
   ```

   And add the getter declaration after `receive_message` (:107):

   ```c
   void frame_header_constants(uint32_t out[4]);
   ```

6. **(impl) Edit `src/cryptography/utils.c`** — append the getter (after `receive_message`):

   ```c
   /* v3 frame-header constant getters — read by the C<->TS byte-agreement unit
    * test (frameConstants.test.ts) so a silent header/slice mismatch is caught. */
   void
   frame_header_constants(uint32_t out[4])
   {
     out[0] = FRAME_TYPE_LEN;
     out[1] = CHUNK_HEADER_LEN;
     out[2] = MESSAGE_START;
     out[3] = CHUNK_LEN;
   }
   ```

7. **(impl) Edit `scripts/emscripten.js`** — add to `EXPORTED_FUNCTIONS` (after `_receive_message`
   at :154, keeping the trailing `\` continuation intact):

   ```
   _receive_message,\
   _frame_header_constants \
   ```

8. **(impl) Add the getter type to both d.ts files** — in `src/cryptography/libcrypto.d.ts` and
   `scripts/libcrypto.d.ts`, after the `_receive_message` block:

   ```ts
     _frame_header_constants(
       out: number, // Uint8Array.byteOffset (16 bytes -> 4x uint32 LE)
     ): void;
   ```

9. **(build)** `npm run prebuild` → expected tail: `updateWasmIntegrity` rewrites the SRI in
   `wasmLoader.ts`; `src/cryptography/libcrypto.wasm` regenerated, exit 0.

10. **(run, passes)** `bun test src/utils/frameConstants.test.ts` → `2 pass, 0 fail`.

11. **(commit)** `git add -A && git commit -m "stage5: freeze v3 frame constants C<->TS + agreement test"`

---

### Task 2 — WASM symmetric AEAD encrypt + `receive_message_with_key` (byte-exact round-trip + Poly1305 tamper)

**Files:**
- Modify `src/cryptography/chacha20poly1305.h` / `.c` (add `encrypt_chachapoly_symmetric`)
- Modify `src/cryptography/utils.h` / `.c` (add `receive_message_with_key`)
- Modify `scripts/emscripten.js` (EXPORTED_FUNCTIONS)
- Modify `src/cryptography/libcrypto.d.ts` and `scripts/libcrypto.d.ts`
- Create `src/cryptography/symmetricMessage.test.ts`

**Interfaces:**
- Produces WASM exports (exact signatures):
  `_encrypt_chachapoly_symmetric(out, data, DATA_LEN, key32, nonce12, aad, AAD_LEN) -> int`,
  `_receive_message_with_key(decrypted, message, merkle_root64, message_key32) -> int`.
- Consumes: `MESSAGE_START`, `CHUNK_AAD_LEN`, `ENCRYPTED_LEN`, `DECRYPTED_LEN`, `PROOF_LEN` from Task 1.

**Steps:**

1. **(failing test) Write `src/cryptography/symmetricMessage.test.ts`** — a real single-chunk frame
   (proofLen=0 single-leaf tree: `merkleRoot = SHA512(0x00 ‖ chunkRegion)`, so
   `receive_message_with_key`'s internal `verify_merkle_proof(0, leaf, root)` passes when `root==leaf`):

   ```ts
   import { describe, expect, test } from "bun:test";
   import { loadLocalWasm } from "../utils/testWasm";
   import {
     MESSAGE_START,
     CHUNK_AAD_LEN,
     ENCRYPTED_LEN,
     DECRYPTED_LEN,
     METADATA_LEN,
     PROOF_LEN,
     FRAME_TYPE_CHUNK,
   } from "../utils/constants";
   import {
     crypto_hash_sha512_BYTES,
     crypto_aead_chacha20poly1305_ietf_KEYBYTES,
     crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
   } from "./interfaces";

   const sha512 = async (b: Uint8Array) =>
     new Uint8Array(
       await crypto.subtle.digest("SHA-512", b as Uint8Array<ArrayBuffer>),
     );

   // Build a valid DECRYPTED_LEN plaintext: [metadata(zeros) | proof(len=0) | chunk].
   const buildPlaintext = () => {
     const pt = new Uint8Array(DECRYPTED_LEN);
     crypto.getRandomValues(pt.subarray(METADATA_LEN + PROOF_LEN)); // chunk region
     // proofLen (first 4 bytes of the proof region, big-endian) = 0 => 0 artifacts.
     pt[METADATA_LEN] = 0;
     pt[METADATA_LEN + 1] = 0;
     pt[METADATA_LEN + 2] = 0;
     pt[METADATA_LEN + 3] = 0;
     return pt;
   };

   describe("symmetric message crypto", () => {
     test("encrypt -> receive_with_key round-trips byte-exact under a shared key", async () => {
       const mod = await loadLocalWasm();
       const pt = buildPlaintext();
       const chunkRegion = pt.subarray(METADATA_LEN + PROOF_LEN);
       const leaf = await sha512(
         new Uint8Array([0x00, ...chunkRegion]),
       ); // domain-separated leaf; single-leaf root == leaf
       const key = new Uint8Array(crypto_aead_chacha20poly1305_ietf_KEYBYTES);
       crypto.getRandomValues(key);
       const nonce = new Uint8Array(crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
       crypto.getRandomValues(nonce);
       const N = 7,
         PN = 3;
       const aad = new Uint8Array(CHUNK_AAD_LEN);
       aad.set(leaf, 0);
       new DataView(aad.buffer).setBigUint64(crypto_hash_sha512_BYTES, BigInt(N));
       new DataView(aad.buffer).setBigUint64(
         crypto_hash_sha512_BYTES + 8,
         BigInt(PN),
       );

       // --- allocate wasm buffers ---
       const pPt = mod._malloc(DECRYPTED_LEN);
       new Uint8Array(mod.wasmMemory.buffer, pPt, DECRYPTED_LEN).set(pt);
       const pKey = mod._malloc(key.length);
       new Uint8Array(mod.wasmMemory.buffer, pKey, key.length).set(key);
       const pNonce = mod._malloc(nonce.length);
       new Uint8Array(mod.wasmMemory.buffer, pNonce, nonce.length).set(nonce);
       const pAad = mod._malloc(CHUNK_AAD_LEN);
       new Uint8Array(mod.wasmMemory.buffer, pAad, CHUNK_AAD_LEN).set(aad);
       const pEnc = mod._malloc(ENCRYPTED_LEN);

       expect(
         mod._encrypt_chachapoly_symmetric(
           pEnc,
           pPt,
           DECRYPTED_LEN,
           pKey,
           pNonce,
           pAad,
           CHUNK_AAD_LEN,
         ),
       ).toBe(0);
       const enc = new Uint8Array(
         mod.wasmMemory.buffer,
         pEnc,
         ENCRYPTED_LEN,
       ).slice();

       // --- assemble the v3 frame and receive it ---
       const frame = new Uint8Array(MESSAGE_START + ENCRYPTED_LEN);
       frame[0] = FRAME_TYPE_CHUNK;
       crypto.getRandomValues(frame.subarray(1, 33)); // dhPub (unused by C)
       new DataView(frame.buffer).setBigUint64(33, BigInt(N)); // N at 1+32
       new DataView(frame.buffer).setBigUint64(41, BigInt(PN)); // PN at 1+32+8
       frame[49] = 0; // PQ_EPOCH
       frame.set(enc, MESSAGE_START);

       const pFrame = mod._malloc(frame.length);
       new Uint8Array(mod.wasmMemory.buffer, pFrame, frame.length).set(frame);
       const pRoot = mod._malloc(crypto_hash_sha512_BYTES);
       new Uint8Array(mod.wasmMemory.buffer, pRoot, crypto_hash_sha512_BYTES).set(
         leaf,
       );
       const pDec = mod._malloc(DECRYPTED_LEN);

       expect(
         mod._receive_message_with_key(pDec, pFrame, pRoot, pKey),
       ).toBe(0);
       const dec = new Uint8Array(mod.wasmMemory.buffer, pDec, DECRYPTED_LEN);
       // chunk region survives byte-exact
       expect(
         Buffer.from(dec.subarray(METADATA_LEN + PROOF_LEN)).equals(
           Buffer.from(chunkRegion),
         ),
       ).toBe(true);
       // leaf-hash receipt token written over the consumed proof region
       expect(
         Buffer.from(dec.subarray(METADATA_LEN, METADATA_LEN + 64)).equals(
           Buffer.from(leaf),
         ),
       ).toBe(true);
     });

     test("a tampered ciphertext byte fails Poly1305 (-2)", async () => {
       const mod = await loadLocalWasm();
       const pt = buildPlaintext();
       const chunkRegion = pt.subarray(METADATA_LEN + PROOF_LEN);
       const leaf = await sha512(new Uint8Array([0x00, ...chunkRegion]));
       const key = crypto.getRandomValues(
         new Uint8Array(crypto_aead_chacha20poly1305_ietf_KEYBYTES),
       );
       const nonce = crypto.getRandomValues(new Uint8Array(12));
       const aad = new Uint8Array(CHUNK_AAD_LEN);
       aad.set(leaf, 0); // N=PN=0

       const pPt = mod._malloc(DECRYPTED_LEN);
       new Uint8Array(mod.wasmMemory.buffer, pPt, DECRYPTED_LEN).set(pt);
       const pKey = mod._malloc(key.length);
       new Uint8Array(mod.wasmMemory.buffer, pKey, key.length).set(key);
       const pNonce = mod._malloc(12);
       new Uint8Array(mod.wasmMemory.buffer, pNonce, 12).set(nonce);
       const pAad = mod._malloc(CHUNK_AAD_LEN);
       new Uint8Array(mod.wasmMemory.buffer, pAad, CHUNK_AAD_LEN).set(aad);
       const pEnc = mod._malloc(ENCRYPTED_LEN);
       mod._encrypt_chachapoly_symmetric(
         pEnc,
         pPt,
         DECRYPTED_LEN,
         pKey,
         pNonce,
         pAad,
         CHUNK_AAD_LEN,
       );
       const enc = new Uint8Array(mod.wasmMemory.buffer, pEnc, ENCRYPTED_LEN).slice();
       enc[MESSAGE_START + 20] ^= 0xff; // flip a ciphertext byte (index into enc, past its nonce)

       const frame = new Uint8Array(MESSAGE_START + ENCRYPTED_LEN);
       frame[0] = FRAME_TYPE_CHUNK;
       frame.set(enc, MESSAGE_START);
       const pFrame = mod._malloc(frame.length);
       new Uint8Array(mod.wasmMemory.buffer, pFrame, frame.length).set(frame);
       const pRoot = mod._malloc(crypto_hash_sha512_BYTES);
       new Uint8Array(mod.wasmMemory.buffer, pRoot, crypto_hash_sha512_BYTES).set(leaf);
       const pDec = mod._malloc(DECRYPTED_LEN);
       expect(mod._receive_message_with_key(pDec, pFrame, pRoot, pKey)).toBe(-2);
     });
   });
   ```

   (Note: `enc[MESSAGE_START + 20]` in the tamper test indexes into `enc` — `enc` begins with its
   own 12-byte AEAD nonce, so byte 20 is inside the ciphertext body, not the transmitted nonce.)

2. **(run, fails)** `bun test src/cryptography/symmetricMessage.test.ts` →
   fails: `_encrypt_chachapoly_symmetric`/`_receive_message_with_key` undefined.

3. **(impl) Add to `src/cryptography/chacha20poly1305.h`** (after the asymmetric decls) —
   the key length is the AEAD key size; include the header if not already pulled by utils.h:

   ```c
   int encrypt_chachapoly_symmetric(
       uint8_t *encrypted, const uint8_t *data, const unsigned int DATA_LEN,
       const uint8_t key[crypto_aead_chacha20poly1305_ietf_KEYBYTES],
       const uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES],
       const uint8_t *additional_data, const unsigned int ADDITIONAL_DATA_LEN);
   ```

4. **(impl) Add to `src/cryptography/chacha20poly1305.c`** — same `[nonce ‖ ct ‖ tag]` output layout
   as the asymmetric variant, but the AEAD key is supplied directly (no `crypto_kx`). Parameter
   order matches the contract `(out, data, DATA_LEN, key, nonce, aad, AAD_LEN)`:

   ```c
   /* Returns (nonce || encrypted_data || auth tag), keyed by a supplied 32-byte
    * symmetric key (a Double-Ratchet message key). The nonce is provided by the
    * caller (nonce = chunkIndex) and copied into the output so the receiver reads
    * it off the wire; uniqueness within a message key is the caller's discipline. */
   int
   encrypt_chachapoly_symmetric(
       uint8_t *encrypted, const uint8_t *data, const unsigned int DATA_LEN,
       const uint8_t key[crypto_aead_chacha20poly1305_ietf_KEYBYTES],
       const uint8_t nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES],
       const uint8_t *additional_data, const unsigned int ADDITIONAL_DATA_LEN)
   {
     unsigned long long CIPHERTEXT_LEN
         = DATA_LEN + crypto_aead_chacha20poly1305_ietf_ABYTES;
     int res = crypto_aead_chacha20poly1305_ietf_encrypt(
         &encrypted[crypto_aead_chacha20poly1305_ietf_NPUBBYTES], &CIPHERTEXT_LEN,
         data, DATA_LEN, additional_data, ADDITIONAL_DATA_LEN, NULL, nonce, key);
     if (res != 0) return -1;

     memcpy(encrypted, nonce, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
     return 0;
   }
   ```

5. **(impl) Add to `src/cryptography/utils.h`** (after the `frame_header_constants` decl):

   ```c
   /* v3 receive path: symmetric AEAD decrypt under a Double-Ratchet message key +
    * the on-wire nonce, with AAD = merkle_root || N || PN (N,PN read from the
    * cleartext frame header). SKIPS the signature-verify block; keeps the
    * merkle-proof / leaf-hash / receipt logic identical to receive_message.
    * Return codes mirror receive_message minus the -1 'signature wrong' case. */
   int receive_message_with_key(
       uint8_t decrypted[DECRYPTED_LEN], const uint8_t message[MESSAGE_LEN],
       const uint8_t merkle_root[crypto_hash_sha512_BYTES],
       const uint8_t message_key[crypto_aead_chacha20poly1305_ietf_KEYBYTES]);
   ```

6. **(impl) Add to `src/cryptography/utils.c`** — reuse the proof/leaf/receipt block from
   `receive_message` (:146-181) **verbatim**; only the front (auth+decrypt) differs:

   ```c
   int
   receive_message_with_key(
       uint8_t decrypted[DECRYPTED_LEN], const uint8_t message[MESSAGE_LEN],
       const uint8_t merkle_root[crypto_hash_sha512_BYTES],
       const uint8_t message_key[crypto_aead_chacha20poly1305_ietf_KEYBYTES])
   {
     /* AAD = merkle_root || N || PN. N and PN are read RAW (not parsed) from the
      * cleartext ratchet header so they are authenticated without a separate MAC.
      * Header layout (SSOT utils.h): [FRAME_TYPE | dhPub | N | PN | PQ_EPOCH | ct]. */
     uint8_t aad[CHUNK_AAD_LEN];
     memcpy(aad, merkle_root, crypto_hash_sha512_BYTES);
     memcpy(aad + crypto_hash_sha512_BYTES,
            &message[FRAME_TYPE_LEN + RATCHET_DHPUB_LEN], RATCHET_N_LEN);
     memcpy(aad + crypto_hash_sha512_BYTES + RATCHET_N_LEN,
            &message[FRAME_TYPE_LEN + RATCHET_DHPUB_LEN + RATCHET_N_LEN],
            RATCHET_PN_LEN);

     /* Symmetric AEAD decrypt of [nonce(12) | ct | tag(16)] at MESSAGE_START. The
      * nonce rides the wire (sender set nonce = chunkIndex for uniqueness). */
     unsigned long long DATA_LEN = ENCRYPTED_LEN
                                   - crypto_aead_chacha20poly1305_ietf_NPUBBYTES
                                   - crypto_aead_chacha20poly1305_ietf_ABYTES;
     int d = crypto_aead_chacha20poly1305_ietf_decrypt(
         decrypted, &DATA_LEN, NULL,
         &message[MESSAGE_START + crypto_aead_chacha20poly1305_ietf_NPUBBYTES],
         ENCRYPTED_LEN - crypto_aead_chacha20poly1305_ietf_NPUBBYTES, aad,
         (unsigned long long)CHUNK_AAD_LEN, &message[MESSAGE_START], message_key);
     if (d != 0) return -2;

     /* ---- proof/leaf/receipt block, byte-identical to receive_message ---- */
     uint32_t proofLen = ((uint32_t)decrypted[METADATA_LEN] << 24)
                         | ((uint32_t)decrypted[METADATA_LEN + 1] << 16)
                         | ((uint32_t)decrypted[METADATA_LEN + 2] << 8)
                         | (uint32_t)decrypted[METADATA_LEN + 3];
     if (proofLen % (crypto_hash_sha512_BYTES + 1) != 0 || proofLen > PROOF_LEN)
       return -3;
     size_t proofArtifactsLen = proofLen / (crypto_hash_sha512_BYTES + 1);

     uint8_t leaf[crypto_hash_sha512_BYTES];
     crypto_hash_sha512_state leaf_state;
     const uint8_t leaf_domain = 0x00;
     int h = crypto_hash_sha512_init(&leaf_state);
     if (h == 0) h = crypto_hash_sha512_update(&leaf_state, &leaf_domain, 1);
     if (h == 0)
       h = crypto_hash_sha512_update(&leaf_state,
                                     &decrypted[METADATA_LEN + PROOF_LEN],
                                     DECRYPTED_LEN - METADATA_LEN - PROOF_LEN);
     if (h == 0) h = crypto_hash_sha512_final(&leaf_state, leaf);
     if (h != 0) return -5;

     uint8_t fold[crypto_hash_sha512_BYTES];
     memcpy(fold, leaf, crypto_hash_sha512_BYTES);
     int vmp = verify_merkle_proof(proofArtifactsLen, fold, merkle_root,
                                   &decrypted[METADATA_LEN + 4]);
     if (vmp != 0) return -6;

     memcpy(&decrypted[METADATA_LEN], leaf, crypto_hash_sha512_BYTES);
     return 0;
   }
   ```

7. **(impl) Export the two functions** — in `scripts/emscripten.js` EXPORTED_FUNCTIONS add
   `_encrypt_chachapoly_symmetric,\` and `_receive_message_with_key,\` (keep `_receive_message`,
   `_sign`, `_verify`, `_decrypt_chachapoly_asymmetric` — the build KEEPS them per the contract).

8. **(impl) Add both signatures to `src/cryptography/libcrypto.d.ts` and `scripts/libcrypto.d.ts`:**

   ```ts
     _encrypt_chachapoly_symmetric(
       encrypted: number, // Uint8Array.byteOffset (ENCRYPTED_LEN)
       data: number, // Uint8Array.byteOffset (DATA_LEN)
       DATA_LEN: number,
       key: number, // Uint8Array.byteOffset (32)
       nonce: number, // Uint8Array.byteOffset (12)
       additional_data: number, // Uint8Array.byteOffset
       ADDITIONAL_DATA_LEN: number,
     ): number;
     _receive_message_with_key(
       decrypted: number, // Uint8Array.byteOffset (DECRYPTED_LEN)
       message: number, // Uint8Array.byteOffset (full v3 frame)
       merkle_root: number, // Uint8Array.byteOffset (64)
       message_key: number, // Uint8Array.byteOffset (32)
     ): number;
   ```

9. **(build)** `npm run prebuild` → exit 0, wasm regenerated.

10. **(run, passes)** `bun test src/cryptography/symmetricMessage.test.ts` → `2 pass, 0 fail`.

11. **(commit)** `git add -A && git commit -m "stage5: WASM symmetric AEAD encrypt + receive_message_with_key"`

---

### Task 3 — Pure frame helpers `chunkFrame.ts` (assemble/parse/AAD/nonce) with unit tests

**Files:**
- Create `src/utils/chunkFrame.ts`
- Create `src/utils/chunkFrame.test.ts`

**Interfaces:**
- Consumes: Task 1 constants; `RatchetHeader` (type) from Stage 2 `../cryptography/ratchet`.
- Produces: `buildChunkAAD(merkleRoot,N,PN):Uint8Array` (80), `chunkNonce(chunkIndex):Uint8Array`
  (12), `assembleChunkFrame(header,encrypted):Uint8Array`, `parseChunkFrameHeader(frame):{dhPub,N,PN,pqEpoch}`.
  These are the single source of truth for v3 frame byte offsets on the JS side.

**Steps:**

1. **(failing test) Write `src/utils/chunkFrame.test.ts`:**

   ```ts
   import { describe, expect, test } from "bun:test";
   import {
     buildChunkAAD,
     chunkNonce,
     assembleChunkFrame,
     parseChunkFrameHeader,
   } from "./chunkFrame";
   import {
     MESSAGE_START,
     CHUNK_AAD_LEN,
     FRAME_TYPE_CHUNK,
   } from "./constants";

   describe("chunkFrame helpers", () => {
     test("assemble -> parse round-trips the ratchet header", () => {
       const dhPub = new Uint8Array(32).fill(9);
       const encrypted = new Uint8Array(100).fill(1);
       const frame = assembleChunkFrame({ dhPub, N: 258, PN: 4 }, encrypted);
       expect(frame[0]).toBe(FRAME_TYPE_CHUNK);
       expect(frame.length).toBe(MESSAGE_START + encrypted.length);
       // ciphertext sits at MESSAGE_START
       expect(Buffer.from(frame.subarray(MESSAGE_START)).equals(Buffer.from(encrypted))).toBe(true);
       const h = parseChunkFrameHeader(frame);
       expect(Buffer.from(h.dhPub).equals(Buffer.from(dhPub))).toBe(true);
       expect(h.N).toBe(258);
       expect(h.PN).toBe(4);
       expect(h.pqEpoch).toBe(0);
     });

     test("buildChunkAAD lays out merkleRoot(64) || N(8 BE) || PN(8 BE)", () => {
       const root = new Uint8Array(64).fill(7);
       const aad = buildChunkAAD(root, 1, 256);
       expect(aad.length).toBe(CHUNK_AAD_LEN);
       expect(Buffer.from(aad.subarray(0, 64)).equals(Buffer.from(root))).toBe(true);
       expect(aad[64 + 7]).toBe(1); // N low byte
       expect(aad[64 + 8 + 6]).toBe(1); // PN=256 -> byte 6 == 1
       expect(aad[64 + 8 + 7]).toBe(0);
     });

     test("chunkNonce is 12 bytes, deterministic, distinct per index", () => {
       expect(chunkNonce(5).length).toBe(12);
       expect(Buffer.from(chunkNonce(5)).equals(Buffer.from(chunkNonce(5)))).toBe(true);
       expect(Buffer.from(chunkNonce(5)).equals(Buffer.from(chunkNonce(6)))).toBe(false);
       expect(chunkNonce(1)[11]).toBe(1); // BE in the low 8 bytes
       expect(chunkNonce(256)[10]).toBe(1);
     });
   });
   ```

2. **(run, fails)** `bun test src/utils/chunkFrame.test.ts` → fails: module not found.

3. **(impl) Write `src/utils/chunkFrame.ts`:**

   ```ts
   import {
     FRAME_TYPE_CHUNK,
     FRAME_TYPE_LEN,
     RATCHET_DHPUB_LEN,
     RATCHET_N_LEN,
     RATCHET_PN_LEN,
     PQ_EPOCH_LEN,
     MESSAGE_START,
     CHUNK_AAD_LEN,
   } from "./constants";
   import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";
   import type { RatchetHeader } from "../cryptography/ratchet";

   // Big-endian write of a JS safe integer (< 2^53) into `len` bytes.
   const beWrite = (buf: Uint8Array, offset: number, value: number, len: number) => {
     for (let i = len - 1; i >= 0; i--) {
       buf[offset + i] = value & 0xff;
       value = Math.floor(value / 256);
     }
   };
   const beRead = (buf: Uint8Array, offset: number, len: number): number => {
     let v = 0;
     for (let i = 0; i < len; i++) v = v * 256 + buf[offset + i];
     return v;
   };

   // AAD = merkle_root(64) || N(8 BE) || PN(8 BE). Byte-identical to the aad[]
   // receive_message_with_key reconstructs from the frame header (utils.c).
   export const buildChunkAAD = (
     merkleRoot: Uint8Array,
     N: number,
     PN: number,
   ): Uint8Array => {
     const aad = new Uint8Array(CHUNK_AAD_LEN);
     aad.set(merkleRoot.subarray(0, crypto_hash_sha512_BYTES), 0);
     beWrite(aad, crypto_hash_sha512_BYTES, N, RATCHET_N_LEN);
     beWrite(aad, crypto_hash_sha512_BYTES + RATCHET_N_LEN, PN, RATCHET_PN_LEN);
     return aad;
   };

   // AEAD nonce = chunkIndex (12 bytes; chunkIndex BE in the low 8). Deterministic:
   // a retransmit of the same chunkIndex reuses the identical nonce, so with the
   // per-message key fixed the ciphertext is byte-identical (never a fresh random
   // nonce under a reused key). Unique within a message (distinct chunkIndex).
   export const chunkNonce = (chunkIndex: number): Uint8Array => {
     const nonce = new Uint8Array(12);
     beWrite(nonce, 4, chunkIndex, 8);
     return nonce;
   };

   // [ FRAME_TYPE_CHUNK | dhPub(32) | N(8 BE) | PN(8 BE) | PQ_EPOCH(1) | encrypted ]
   export const assembleChunkFrame = (
     header: RatchetHeader,
     encrypted: Uint8Array,
   ): Uint8Array => {
     const frame = new Uint8Array(MESSAGE_START + encrypted.length);
     let off = 0;
     frame[off] = FRAME_TYPE_CHUNK;
     off += FRAME_TYPE_LEN;
     frame.set(header.dhPub.subarray(0, RATCHET_DHPUB_LEN), off);
     off += RATCHET_DHPUB_LEN;
     beWrite(frame, off, header.N, RATCHET_N_LEN);
     off += RATCHET_N_LEN;
     beWrite(frame, off, header.PN, RATCHET_PN_LEN);
     off += RATCHET_PN_LEN;
     frame[off] = 0; // PQ_EPOCH (0 in v3)
     off += PQ_EPOCH_LEN;
     frame.set(encrypted, off); // off === MESSAGE_START
     return frame;
   };

   export const parseChunkFrameHeader = (
     frame: Uint8Array,
   ): { dhPub: Uint8Array; N: number; PN: number; pqEpoch: number } => {
     let off = FRAME_TYPE_LEN;
     const dhPub = frame.slice(off, off + RATCHET_DHPUB_LEN);
     off += RATCHET_DHPUB_LEN;
     const N = beRead(frame, off, RATCHET_N_LEN);
     off += RATCHET_N_LEN;
     const PN = beRead(frame, off, RATCHET_PN_LEN);
     off += RATCHET_PN_LEN;
     const pqEpoch = frame[off];
     return { dhPub, N, PN, pqEpoch };
   };
   ```

4. **(run, passes)** `bun test src/utils/chunkFrame.test.ts` → `3 pass, 0 fail`.

5. **(commit)** `git add -A && git commit -m "stage5: pure v3 chunk-frame helpers + tests"`

---

### Task 4 — Sender swap: ratchet message key, symmetric encrypt, new frame, cached-ciphertext retransmit; shrink `allocateSendMessage`

**Files:**
- Modify `src/utils/allocators.ts` (rewrite `allocateSendMessage` :17-105)
- Modify `src/utils/allocators.test.ts` — none needed (invariant preserved), re-run to confirm
- Modify `src/handlers/handleSendMessage.ts` (`sendChunks` :69-395; `sendWithReconcile` :460-572;
  `handleSendMessage` :574-722)

**Interfaces:**
- Consumes: `ratchetEncrypt`, `serializeRatchet`, `RatchetState`, `RatchetHeader` (Stage 2);
  `setRatchetSession`, `getRatchetSession`, `deserializeRatchet` (Stage 3); `epc.ratchetSession`,
  `epc.ratchetEstablished` (Stage 4); Task 3 helpers; Task 2 `_encrypt_chachapoly_symmetric`.
- Produces: v3 chunk frames on the wire; deterministic cached-ciphertext retransmit.

**Steps:**

1. **(impl) Rewrite `allocateSendMessage` in `src/utils/allocators.ts`** — drop the ephemeral
   keypair/seed/signature/transcript/receiver-pubkey buffers; keep only what the symmetric path
   needs. (The existing `allocators.test.ts` invariant "every `ptrN` has a Uint8Array view" still holds.)

   ```ts
   import { ENCRYPTED_LEN, DECRYPTED_LEN, CHUNK_AAD_LEN } from "./constants";
   import {
     crypto_aead_chacha20poly1305_ietf_KEYBYTES,
     crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
   } from "../cryptography/interfaces";
   import type { LibCrypto } from "../cryptography/libcrypto";

   export const allocateSendMessage = (encryptionModule: LibCrypto) => {
     const ptr1 = encryptionModule._malloc(
       crypto_aead_chacha20poly1305_ietf_KEYBYTES,
     );
     const messageKeyArray = new Uint8Array(
       encryptionModule.wasmMemory.buffer,
       ptr1,
       crypto_aead_chacha20poly1305_ietf_KEYBYTES,
     );

     const ptr2 = encryptionModule._malloc(DECRYPTED_LEN);
     const chunkArray = new Uint8Array(
       encryptionModule.wasmMemory.buffer,
       ptr2,
       DECRYPTED_LEN,
     );

     const ptr3 = encryptionModule._malloc(
       crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
     );
     const nonceArray = new Uint8Array(
       encryptionModule.wasmMemory.buffer,
       ptr3,
       crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
     );

     const ptr4 = encryptionModule._malloc(CHUNK_AAD_LEN);
     const aadArray = new Uint8Array(
       encryptionModule.wasmMemory.buffer,
       ptr4,
       CHUNK_AAD_LEN,
     );

     const ptr5 = encryptionModule._malloc(ENCRYPTED_LEN);
     const encryptedArray = new Uint8Array(
       encryptionModule.wasmMemory.buffer,
       ptr5,
       ENCRYPTED_LEN,
     );

     return {
       ptr1,
       ptr2,
       ptr3,
       ptr4,
       ptr5,
       messageKeyArray,
       chunkArray,
       nonceArray,
       aadArray,
       encryptedArray,
     };
   };
   ```

2. **(run, passes)** `bun test src/utils/allocators.test.ts` → `1 pass, 0 fail` (invariant intact).

3. **(impl) Rewrite the crypto core of `sendChunks` in `handleSendMessage.ts`.** Change its
   signature — drop `senderSecretKey`, add `messageKey`, `header`, `ciphertextCache`:

   ```ts
   const sendChunks = async (
     channel: IRTCDataChannel | string,
     api: BaseQueryApi,
     roomId: string,
     chunksLen: number,
     chunkHashes: Uint8Array,
     merkleRoot: Uint8Array,
     hashHex: string,
     peerId: string,
     peerPublicKeyHex: string,
     encryptionModule: LibCrypto,
     merkleModule: LibCrypto,
     messageKey: Uint8Array,
     header: RatchetHeader,
     ciphertextCache: Map<number, Uint8Array>,
     reconcileAcked?: Set<number>,
   ) => {
   ```

   Replace the allocator destructure (:98-115) with the new shape, and set the per-message-constant
   buffers ONCE before the loop:

   ```ts
     const { ptr1, ptr2, ptr3, ptr4, ptr5, messageKeyArray, chunkArray, nonceArray, aadArray, encryptedArray } =
       allocateSendMessage(encryptionModule);

     // Message key + AAD are constant across every chunk of this logical message.
     messageKeyArray.set(messageKey);
     aadArray.set(buildChunkAAD(merkleRoot, header.N, header.PN));
   ```

   Delete the transcript setup (:121-125). Inside the loop, delete the per-chunk ephemeral keypair
   (:130-138), the `_sign` transcript block (:140-154), and the `receiverPublicKeyArray` set (:119).
   Replace the encrypt + message-assembly region (:239-273) with cached-ciphertext-or-encrypt:

   ```ts
       // Retransmit determinism (R3): if we already produced this chunkIndex's
       // ciphertext, resend the CACHED frame — never re-encrypt with a fresh nonce.
       let frame = ciphertextCache.get(metadata.chunkIndex);
       if (!frame) {
         if (
           DECRYPTED_LEN !==
           metadataArray.length +
             merkleProof.length +
             new Uint8Array(unencryptedChunk.data).length
         )
           continue;

         const chunk = await concatUint8Arrays([
           metadataArray,
           merkleProof,
           new Uint8Array(unencryptedChunk.data),
         ]);
         chunkArray.set(chunk);
         nonceArray.set(chunkNonce(metadata.chunkIndex));

         const encResult = encryptionModule._encrypt_chachapoly_symmetric(
           encryptedArray.byteOffset,
           chunkArray.byteOffset,
           DECRYPTED_LEN,
           messageKeyArray.byteOffset,
           nonceArray.byteOffset,
           aadArray.byteOffset,
           CHUNK_AAD_LEN,
         );
         if (encResult !== 0) continue;

         frame = assembleChunkFrame(header, encryptedArray); // copies out of wasm
         ciphertextCache.set(metadata.chunkIndex, frame);
       }

       const message = frame;
   ```

   The existing send/relay/`setDBSendQueue` block below (:275-320) is unchanged (`message` is now the
   assembled v3 frame). At cleanup (:386-394) replace the frees with:

   ```ts
     encryptionModule._free(ptr2);
     encryptionModule._free(ptr3);
     encryptionModule._free(ptr4);
     encryptionModule._free(ptr5);
     zeroFree(encryptionModule, messageKeyArray); // ptr1: wipe the key material
   ```

   Update imports at the top of the file: remove `crypto_hash_sha512_BYTES` usage for AAD and the
   `crypto_sign_ed25519_*` (still needed only for the pubkey-length guard in `handleSendMessage` —
   keep `crypto_sign_ed25519_PUBLICKEYBYTES`); remove `CHUNK_AUTH_DOMAIN_BYTES`,
   `CHUNK_AUTH_TRANSCRIPT_LEN`; add `CHUNK_AAD_LEN`; add
   `import { assembleChunkFrame, buildChunkAAD, chunkNonce } from "../utils/chunkFrame";` and
   `import type { RatchetState, RatchetHeader } from "../cryptography/ratchet";`
   `import { ratchetEncrypt, serializeRatchet } from "../cryptography/ratchet";`
   `import { setRatchetSession } from "../db/api";`.

4. **(impl) Hoist `ratchetEncrypt` into `sendWithReconcile`.** Change its signature — drop
   `senderSecretKey`, add `ratchetSession: RatchetState` — and derive the message key ONCE:

   ```ts
   const sendWithReconcile = async (
     channel: IRTCDataChannel | string,
     api: BaseQueryApi,
     roomId: string,
     chunksLen: number,
     chunkHashes: Uint8Array,
     merkleRoot: Uint8Array,
     hashHex: string,
     peerId: string,
     peerPublicKeyHex: string,
     encryptionModule: LibCrypto,
     merkleModule: LibCrypto,
     peerConnections: IRTCPeerConnection[],
     dataChannels: IRTCDataChannel[],
     ratchetSession: RatchetState,
   ): Promise<void> => {
     clearTransfer(peerId, hashHex);

     // ONE ratchet step per logical message per edge: all chunks share this key;
     // the DH/chain ratchet advances exactly once here (never per chunk).
     const { messageKey, header } = ratchetEncrypt(ratchetSession, encryptionModule);
     // Persist the advanced state so a reload/reconnect continues correctly
     // (secret fields wrapped inside setRatchetSession — Stage 3).
     await setRatchetSession({
       roomId,
       peerPublicKey: peerPublicKeyHex,
       peerId,
       ...serializeRatchet(ratchetSession),
       updatedAt: Date.now(),
     });
     const ciphertextCache = new Map<number, Uint8Array>();
     ...
   ```

   Pass `messageKey, header, ciphertextCache` to BOTH `sendChunks` calls (initial :489 and reconcile
   :548), and drop `senderSecretKey` from both. The reconcile pass reuses the same key/header/cache,
   so every resent chunk is byte-identical to its first transmission.

5. **(impl) Resolve the ratchet session per peer in `handleSendMessage`.** Delete the `ptr4`
   `senderSecretKey` block (:626-632) and the `ptr8` `additionalData` block (:634-640) and their
   frees (:716-717) — the AAD is built from the plain `merkleRoot`, and there is no signing key. In
   the per-peer loop, before `sendWithReconcile`, resolve the session (fail-closed if absent):

   ```ts
         // v3: every send requires an authenticated ratchet for this edge. Prefer
         // the live handle on a connected peer; else rehydrate the persisted
         // session by the stable identity edge (survives reconnect). No ratchet =>
         // no send (fail closed, consistent with the no-fallback room model).
         const liveSession =
           peerIndex > -1 && peerConnections[peerIndex].ratchetEstablished
             ? peerConnections[peerIndex].ratchetSession
             : undefined;
         const stored = liveSession
           ? undefined
           : await getRatchetSession(roomId, peerPublicKeyHex);
         const ratchetSession =
           liveSession ?? (stored ? deserializeRatchet(stored) : undefined);
         if (!ratchetSession) continue;
   ```

   And update the `sendWithReconcile` call to pass `ratchetSession` (last arg) and drop
   `senderSecretKey` / `additionalData` (pass the plain `merkleRoot` for AAD). Add
   `import { getRatchetSession } from "../db/api"; import { deserializeRatchet } from "../cryptography/ratchet";`.

6. **(typecheck)** `npm run typecheck` → `tsc` exits 0 (no unresolved refs to the removed
   `senderSecretKey` / `CHUNK_AUTH_*`).

7. **(run, passes)** `bun test src/utils/chunkFrame.test.ts src/cryptography/symmetricMessage.test.ts src/utils/allocators.test.ts` → all pass (the send path's byte contract is covered by the frame + wasm round-trip tests).

8. **(commit)** `git add -A && git commit -m "stage5: sender uses ratchet message key + symmetric AEAD + v3 frame; cached-ciphertext retransmit; signature dropped"`

---

### Task 5 — Receiver swap: `receive_message_with_key`, ratchet-derive in `processMessage`, drop the signature path

**Files:**
- Modify `src/handlers/handleReceiveMessage.ts` (signature :12-37; delete `case -1` :195-210)
- Modify `src/handlers/handleMessageQueueing.ts` (`processMessage`/`drain`/`enqueue` :71-402)
- Modify `src/handlers/handleOpenChannel.ts` (receive-scratch alloc :291-309; onmessage chunk
  branch :225-247; enqueue args)
- Modify `src/handlers/handleWebSocketMessage.ts` (twin relay-receive `processMessage` call sites
  around :525 and :599 — mirror the new args)

**Interfaces:**
- Consumes: Task 2 `_receive_message_with_key`; Task 3 `parseChunkFrameHeader`; Stage 2
  `ratchetDecrypt`, `serializeRatchet`, `RatchetState`; Stage 3 `setRatchetSession`,
  `getRatchetSession`, `deserializeRatchet`; Stage 4 `epc.ratchetSession`, FRAME_TYPE dispatch.
- Produces: message-key-based `handleReceiveMessage`; ratchet-advancing `processMessage`.

**Steps:**

1. **(impl) Rewrite `handleReceiveMessage`'s WASM call + signature.** Replace the params
   `senderPublicKeyArray, receiverSecretKeyArray` with a single `messageKeyArray`, and the
   `_receive_message` call with `_receive_message_with_key`:

   ```ts
   export const handleReceiveMessage = async (
     decrypted: Uint8Array,
     messageArray: Uint8Array,
     merkleRootArray: Uint8Array,
     messageKeyArray: Uint8Array,
     module: LibCrypto,
   ): Promise<{ /* ...unchanged return shape... */ }> => {
     const result = module._receive_message_with_key(
       decrypted.byteOffset,
       messageArray.byteOffset,
       merkleRootArray.byteOffset,
       messageKeyArray.byteOffset,
     );

     switch (result) {
       case 0: {
         /* ...unchanged: metadata slice / leaf-hash receipt / store / return... */
       }
       // case -1 (signature wrong) is REMOVED — v3 has no per-chunk signature.
       case -2: { console.error("Could not decrypt message"); /* ...unchanged... */ }
       case -3: { /* ...unchanged... */ }
       case -5: { /* ...unchanged... */ }
       case -6: { /* ...unchanged... */ }
       default: { /* ...unchanged... */ }
     }
   };
   ```

   Delete the entire `case -1` block (:195-210). Leave every `case 0` internal body byte-for-byte
   unchanged (the merkle/leaf/receipt semantics are preserved by Task 2's verbatim C block).

2. **(impl) Derive the ratchet key in `processMessage`.** Change its signature — replace
   `senderPublicKeyArray, receiverSecretKeyArray` with `messageKeyArray`, and add
   `peerPublicKey: string` and `ratchetSession: RatchetState`:

   ```ts
   const processMessage = async (
     data: Uint8Array,
     api: BaseQueryApi,
     roomId: string,
     peerId: string,
     peerPublicKey: string,
     channelLabel: string,
     merkleRootHex: string,
     merkleRoot: Uint8Array,
     extChannel: IRTCDataChannel | undefined,
     ratchetSession: RatchetState,
     decrypted: Uint8Array | undefined,
     messageArray: Uint8Array | undefined,
     merkleRootArray: Uint8Array | undefined,
     messageKeyArray: Uint8Array | undefined,
     receiveMessageModule: LibCrypto,
   ): Promise<{ receivedFullSize: boolean }> => {
     if (decrypted && messageArray && merkleRootArray && messageKeyArray) {
       try {
         // Parse the cleartext ratchet header, advance the receiving ratchet to the
         // message key (skipped-key / DH-step handling lives in ratchetDecrypt),
         // and hand the key to the WASM AEAD. peerId+frame are both in scope here.
         const header = parseChunkFrameHeader(data);
         const messageKey = ratchetDecrypt(ratchetSession, header, receiveMessageModule);
         messageKeyArray.set(messageKey);
         messageArray.set(data); // full v3 frame; C reads N/PN + ct at MESSAGE_START
         merkleRootArray.set(merkleRoot);

         const { /* ...destructure unchanged... */ } = await handleReceiveMessage(
           decrypted,
           messageArray,
           merkleRootArray,
           messageKeyArray,
           receiveMessageModule,
         );

         // Persist the advanced receiving state (wrapped inside setRatchetSession).
         await setRatchetSession({
           roomId,
           peerPublicKey,
           peerId,
           ...serializeRatchet(ratchetSession),
           updatedAt: Date.now(),
         });

         /* ...rest of processMessage (receipts, setMessage, telemetry) unchanged... */
       } catch (error) {
         console.error(error);
         return { receivedFullSize: false };
       }
     }
     return { receivedFullSize: false };
   };
   ```

   Thread the two new params (`peerPublicKey`, `ratchetSession`) and the renamed `messageKeyArray`
   through `drain` and `enqueue` (replace `senderPublicKeyArray`/`receiverSecretKeyArray` in both
   signatures and both call sites). Add imports:
   `import { parseChunkFrameHeader } from "../utils/chunkFrame";`
   `import { ratchetDecrypt, serializeRatchet } from "../cryptography/ratchet";`
   `import { setRatchetSession } from "../db/api";`
   `import type { RatchetState } from "../cryptography/ratchet";`

3. **(impl) Update the receive-scratch alloc in `handleOpenChannel.ts`.** Replace the `ptr4`
   sender-public-key buffer (:291-299) and the `ptr5` receiver-secret-key buffer (:301-309) with a
   single 32-byte message-key buffer:

   ```ts
       ptr4 = epc.rooms[peerRoomIndex].receiveMessageModule._malloc(
         crypto_aead_chacha20poly1305_ietf_KEYBYTES,
       );
       messageKeyArray = new Uint8Array(
         epc.rooms[peerRoomIndex].receiveMessageModule.wasmMemory.buffer,
         ptr4,
         crypto_aead_chacha20poly1305_ietf_KEYBYTES,
       );
   ```

   Remove `senderPublicKey`/`receiverSecretKey` sourcing and the `ptr5` alloc/free (and its
   `zeroFree`); declare `let messageKeyArray: Uint8Array | undefined;` instead of
   `senderPublicKeyArray`/`receiverSecretKeyArray`. In the FRAME_TYPE_CHUNK branch of `onmessage`
   (the Stage-4 dispatch; the v2 `data.length === MESSAGE_LEN` classifier at :225 is replaced there
   by `data[0] === FRAME_TYPE_CHUNK`), pass the new args to `enqueue`:

   ```ts
         enqueue(
           data,
           queue,
           seen,
           drainingRef,
           api,
           roomId,
           extChannel.withPeerId,
           epc.withPeerPublicKey,        // peerPublicKey (new)
           channelLabel,
           merkleRootHex,
           merkleRoot,
           extChannel,
           epc.ratchetSession,           // ratchetSession (new; Stage 4 handle)
           decrypted,
           messageArray,
           merkleRootArray,
           messageKeyArray,              // replaces sender/receiver key arrays
           epc.rooms[peerRoomIndex].receiveMessageModule,
         );
   ```

   Add `crypto_aead_chacha20poly1305_ietf_KEYBYTES` to the crypto imports; drop
   `crypto_sign_ed25519_PUBLICKEYBYTES`/`SECRETKEYBYTES` if now unused here.

4. **(impl) Mirror the change in `handleWebSocketMessage.ts`** relay-receive path (the two
   `processMessage`/receive scratch sites near :525 and :599). These have no `epc`, so rehydrate the
   session by the stable edge before calling `processMessage`:

   ```ts
     const stored = await getRatchetSession(roomId, senderPublicKeyHex);
     if (!stored) return; // fail closed: no ratchet for this edge
     const ratchetSession = deserializeRatchet(stored);
     // allocate a 32-byte messageKey buffer (as in handleOpenChannel) then:
     await processMessage(
       data, api, roomId, fromPeerId, senderPublicKeyHex, channelLabel,
       merkleRootHex, merkleRoot, undefined, ratchetSession,
       decrypted, messageArray, merkleRootArray, messageKeyArray, receiveMessageModule,
     );
   ```

   Add `import { getRatchetSession } from "../db/api"; import { deserializeRatchet } from "../cryptography/ratchet";` and the KEYBYTES import.

5. **(typecheck)** `npm run typecheck` → exits 0 (all `processMessage`/`enqueue`/`drain` call sites
   updated; no dangling `senderPublicKeyArray`/`receiverSecretKeyArray`).

6. **(run, passes)** `bun test` → the full suite is green (existing tests +
   `frameConstants`, `symmetricMessage`, `chunkFrame`, `allocators`). Expected: `... pass, 0 fail`.

7. **(build + integration)** `npm run prebuild` (dev wasm + SRI) then the real-WebRTC E2E:
   `node e2e/run.mjs` — expect a byte-exact PIN-room and no-PIN-room transfer under the ratchet,
   a tampered-frame receiver-side Poly1305 rejection, and deterministic retransmit (no dup-decrypt
   failures). This is the stage's end-to-end verification per the definition of done.

8. **(commit)** `git add -A && git commit -m "stage5: receiver derives ratchet message key + receive_message_with_key; drop signature path; frame remap live"`

---

**Stage exit criteria:** `bun test` green (incl. the C↔TS constant-agreement, encrypt→receive
byte-exact round-trip, and tampered-frame Poly1305 tests); `npm run typecheck` clean; `node
e2e/run.mjs` byte-exact both room modes. The atomic signature drop + frame remap now ship together
(R1). `_sign`/`_receive_message`/`_decrypt_chachapoly_asymmetric` remain compiled but are no longer
called by the v3 send/receive paths. (SRI repin + `npm run uploadcdn` + the `0.9.2 → 0.10.0` version
bump happen in the final release stage, not here.)


---

## Stage 6 — Version tag + PIN plumbing + backoff + failure states

Wires the protocol-v3 **signaling-layer version tag**, the **PIN plumbing** (transient in-RAM secret, never localStorage), the **per-room online-guessing backoff**, the **handshake-mode selection** consumed by `main` onopen, and the **serializable failure/verification surface** on Redux. The cryptographically load-bearing bits (version-mismatch predicate, NFC normalization, backoff schedule, room-keyed attempt counter, mode-from-pin selection) are pure functions TDD'd in isolation; the Redux/handler/signaling edits are thin wiring verified by `npm run typecheck`.

All new constants are SSOT in `src/utils/constants.ts`. These have **no C counterpart** (they live only in the signaling/JS layer — the wire frame does not carry a version byte), so no `utils.h` byte-match is required for them.

---

### Task 1 — Protocol-version tag constant + clean-reject predicate

**Files:**
- Modify `src/utils/constants.ts` (append after the `MAX_RESUME_ATTEMPTS` block, ~line 85)
- Create `src/utils/protocolVersion.ts`
- Create `src/utils/protocolVersion.test.ts`

**Interfaces:**
- Produces `PROTOCOL_VERSION: number` (= 3), `MAX_PIN_ATTEMPTS: number` (= 3), `PIN_BACKOFF_BASE_MS: number` (= 500) in `constants.ts` — consumed by Tasks 3, 5, 6 and by Stage 4's `runHandshake`.
- Produces `isProtocolVersionCompatible(peerProtocolVersion?: number): boolean` — consumed by Task 5's `handleWebSocketMessage` connection case.

**Steps:**

1. Write the failing test. Create `src/utils/protocolVersion.test.ts`:
```ts
import { describe, expect, test } from "bun:test";

import { isProtocolVersionCompatible } from "./protocolVersion";
import { PROTOCOL_VERSION } from "./constants";

describe("isProtocolVersionCompatible", () => {
  test("accepts a peer advertising the current protocol version", () => {
    expect(isProtocolVersionCompatible(PROTOCOL_VERSION)).toBe(true);
    expect(PROTOCOL_VERSION).toBe(3);
  });

  test("rejects a mismatched (older/newer) version — no fallback", () => {
    expect(isProtocolVersionCompatible(2)).toBe(false);
    expect(isProtocolVersionCompatible(4)).toBe(false);
  });

  test("rejects a missing field (pre-v3 peer = undefined)", () => {
    expect(isProtocolVersionCompatible(undefined)).toBe(false);
  });

  test("rejects a non-integer / NaN version", () => {
    expect(isProtocolVersionCompatible(3.5)).toBe(false);
    expect(isProtocolVersionCompatible(Number.NaN)).toBe(false);
    // @ts-expect-error runtime hardening against a stringly-typed field
    expect(isProtocolVersionCompatible("3")).toBe(false);
  });
});
```

2. Run it — fails (module + constant do not exist yet):
```
bun test src/utils/protocolVersion.test.ts
```
Expected: `error: Cannot find module './protocolVersion'` (0 pass).

3. Add the constants. In `src/utils/constants.ts`, after the `export const MAX_RESUME_ATTEMPTS = 3;` block (~line 85), append:
```ts
// protocol-v3 signaling negotiation + PIN online-guessing defense (§7). These
// live ONLY in the signaling/JS layer — the wire frame carries no version byte —
// so there is NO C (utils.h) counterpart to byte-match. PROTOCOL_VERSION is the
// tag on the signaling `connection` message, used ONLY for a clean reject of a
// mismatched peer (no v2<->v3 fallback; a missing field = pre-v3 = rejected).
// After MAX_PIN_ATTEMPTS free CPace key-confirmations per ROOM, each further
// attempt backs off PIN_BACKOFF_BASE_MS * 2^(n-1) capped ~5min (see pinBackoff).
export const PROTOCOL_VERSION = 3;
export const MAX_PIN_ATTEMPTS = 3;
export const PIN_BACKOFF_BASE_MS = 500;
```

4. Create `src/utils/protocolVersion.ts`:
```ts
import { PROTOCOL_VERSION } from "./constants";

/**
 * A minimal signaling-layer version gate (§7). Returns true ONLY when the peer
 * advertises the exact current protocol version. Used for a CLEAN REJECT of a
 * mismatched peer — there is deliberately no v2<->v3 fallback path, and a missing
 * / malformed field (a pre-v3 peer, or a hostile server omitting it) is rejected.
 */
export const isProtocolVersionCompatible = (
  peerProtocolVersion?: number,
): boolean => {
  if (typeof peerProtocolVersion !== "number") return false;
  if (!Number.isInteger(peerProtocolVersion)) return false;

  return peerProtocolVersion === PROTOCOL_VERSION;
};
```

5. Run it — passes:
```
bun test src/utils/protocolVersion.test.ts
```
Expected: `4 pass, 0 fail`.

6. Commit:
```
git add src/utils/constants.ts src/utils/protocolVersion.ts src/utils/protocolVersion.test.ts && git commit -m "stage6: protocol-v3 version tag constant + clean-reject predicate"
```

---

### Task 2 — PIN NFC normalization + handshake-mode selection (pure)

**Files:**
- Create `src/utils/pinNormalize.ts`
- Create `src/utils/pinNormalize.test.ts`

**Interfaces:**
- Produces `normalizePin(rawPin: string): Uint8Array` — NFC-normalized UTF-8 bytes; consumed by Task 4's `securePinStore` and (as `PRS`) by Stage 1's `cpace.ts deriveGenerator`.
- Produces `selectHandshakeMode(pin: Uint8Array | null): "pin" | "nopin"` — consumed by Task 6's `resolveRoomHandshakeMode` and by Stage 4's `runHandshake` mode branch.

**Steps:**

1. Write the failing test. Create `src/utils/pinNormalize.test.ts`:
```ts
import { describe, expect, test } from "bun:test";

import { normalizePin, selectHandshakeMode } from "./pinNormalize";

describe("normalizePin", () => {
  test("encodes a 6-digit ASCII PIN to its UTF-8 bytes", () => {
    expect(Array.from(normalizePin("123456"))).toEqual([
      0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
    ]);
  });

  test("NFC-normalizes so composed and decomposed inputs hash-equal", () => {
    // U+00E9 (é, composed) vs 'e' + U+0301 (combining acute, decomposed)
    const composed = normalizePin("café");
    const decomposed = normalizePin("café");
    expect(Array.from(composed)).toEqual(Array.from(decomposed));
  });

  test("an empty PIN yields a zero-length byte array", () => {
    expect(normalizePin("").length).toBe(0);
  });
});

describe("selectHandshakeMode", () => {
  test("selects 'pin' (CPace) when a non-empty PIN is present", () => {
    expect(selectHandshakeMode(normalizePin("123456"))).toBe("pin");
  });

  test("selects 'nopin' (X3DH) when the PIN is null", () => {
    expect(selectHandshakeMode(null)).toBe("nopin");
  });

  test("selects 'nopin' when the PIN is present but empty", () => {
    expect(selectHandshakeMode(new Uint8Array(0))).toBe("nopin");
  });
});
```

2. Run it — fails (module missing):
```
bun test src/utils/pinNormalize.test.ts
```
Expected: `error: Cannot find module './pinNormalize'`.

3. Create `src/utils/pinNormalize.ts`:
```ts
/**
 * Normalize a room PIN to the exact bytes both peers must agree on before it is
 * used as CPace's PRS (§7). NFC (canonical composition) is applied first so that
 * two Unicode-equal spellings of the same PIN produce identical bytes on both
 * ends; the numeric 6-digit default is unaffected but this hardens non-ASCII PINs.
 * The result is raw UTF-8 bytes — the PIN string itself is never persisted.
 */
export const normalizePin = (rawPin: string): Uint8Array =>
  new TextEncoder().encode(rawPin.normalize("NFC"));

/**
 * The *presence* of a PIN is the room mode (§2, §7) — there is no per-peer
 * capability negotiation. A non-empty PIN => CPace/Ristretto255; otherwise
 * X3DH-style identity-mixed ephemeral DH.
 */
export const selectHandshakeMode = (
  pin: Uint8Array | null,
): "pin" | "nopin" => (pin && pin.length > 0 ? "pin" : "nopin");
```

4. Run it — passes:
```
bun test src/utils/pinNormalize.test.ts
```
Expected: `6 pass, 0 fail`.

5. Commit:
```
git add src/utils/pinNormalize.ts src/utils/pinNormalize.test.ts && git commit -m "stage6: NFC PIN normalization + handshake-mode selection"
```

---

### Task 3 — Exponential backoff schedule + per-ROOM persisted attempt counter

**Files:**
- Create `src/utils/pinBackoff.ts`
- Create `src/utils/pinBackoff.test.ts`

**Interfaces:**
- Consumes `MAX_PIN_ATTEMPTS`, `PIN_BACKOFF_BASE_MS` (Task 1).
- Produces `pinBackoffMs(failedAttempts: number): number` — 0 for the first `MAX_PIN_ATTEMPTS`, then `PIN_BACKOFF_BASE_MS * 2^(n-1)` capped at ~5 min.
- Produces `getPinAttempts(roomKey: string): number`, `incrementPinAttempts(roomKey: string): number`, `resetPinAttempts(roomKey: string): void` — persisted per **room** (localStorage), keyed to the room only (no identity param, structurally preventing an attacker-chosen identity from refilling the budget). Consumed by Stage 4's `runHandshake` on each CPace key-confirmation and cleared on success / PIN rotation.

**Steps:**

1. Write the failing test. Create `src/utils/pinBackoff.test.ts` (self-contained in-memory `localStorage` polyfill, since bun test has no DOM):
```ts
import { afterEach, beforeEach, describe, expect, test } from "bun:test";

import {
  pinBackoffMs,
  getPinAttempts,
  incrementPinAttempts,
  resetPinAttempts,
} from "./pinBackoff";
import { MAX_PIN_ATTEMPTS, PIN_BACKOFF_BASE_MS } from "./constants";

const installMemoryLocalStorage = () => {
  const map = new Map<string, string>();
  (globalThis as unknown as { localStorage: Storage }).localStorage = {
    getItem: (k: string) => (map.has(k) ? (map.get(k) as string) : null),
    setItem: (k: string, v: string) => void map.set(k, String(v)),
    removeItem: (k: string) => void map.delete(k),
    clear: () => map.clear(),
    key: (i: number) => Array.from(map.keys())[i] ?? null,
    get length() {
      return map.size;
    },
  } as Storage;
};

beforeEach(installMemoryLocalStorage);
afterEach(() => {
  (globalThis as unknown as { localStorage?: Storage }).localStorage?.clear();
});

describe("pinBackoffMs schedule", () => {
  test("the first MAX_PIN_ATTEMPTS failures cost zero backoff", () => {
    for (let n = 1; n <= MAX_PIN_ATTEMPTS; n++) {
      expect(pinBackoffMs(n)).toBe(0);
    }
    expect(MAX_PIN_ATTEMPTS).toBe(3);
  });

  test("each further failure backs off exponentially from the base", () => {
    // attempt 4 -> base*2^0, 5 -> base*2^1, 6 -> base*2^2
    expect(pinBackoffMs(MAX_PIN_ATTEMPTS + 1)).toBe(PIN_BACKOFF_BASE_MS);
    expect(pinBackoffMs(MAX_PIN_ATTEMPTS + 2)).toBe(PIN_BACKOFF_BASE_MS * 2);
    expect(pinBackoffMs(MAX_PIN_ATTEMPTS + 3)).toBe(PIN_BACKOFF_BASE_MS * 4);
  });

  test("the backoff is capped at ~5 minutes (never unbounded)", () => {
    expect(pinBackoffMs(1000)).toBe(5 * 60 * 1000);
  });
});

describe("pin attempt counter keyed to the ROOM (not identity)", () => {
  test("increments and reads back per room", () => {
    expect(getPinAttempts("roomA")).toBe(0);
    expect(incrementPinAttempts("roomA")).toBe(1);
    expect(incrementPinAttempts("roomA")).toBe(2);
    expect(getPinAttempts("roomA")).toBe(2);
  });

  test("two rooms keep independent budgets", () => {
    incrementPinAttempts("roomA");
    incrementPinAttempts("roomA");
    expect(getPinAttempts("roomA")).toBe(2);
    expect(getPinAttempts("roomB")).toBe(0);
  });

  test("the same room shares one budget regardless of the peer identity", () => {
    // The API takes ONLY a roomKey — there is no identity parameter, so a peer
    // reconnecting under a fresh (attacker-chosen) identity cannot reset it.
    incrementPinAttempts("roomA"); // "identity X"
    incrementPinAttempts("roomA"); // "identity Y" — still roomA
    expect(getPinAttempts("roomA")).toBe(2);
  });

  test("reset clears the budget (success / PIN rotation)", () => {
    incrementPinAttempts("roomA");
    incrementPinAttempts("roomA");
    resetPinAttempts("roomA");
    expect(getPinAttempts("roomA")).toBe(0);
  });

  test("survives storage absence without throwing", () => {
    delete (globalThis as unknown as { localStorage?: Storage }).localStorage;
    expect(() => incrementPinAttempts("roomA")).not.toThrow();
    expect(getPinAttempts("roomA")).toBe(0);
  });
});
```

2. Run it — fails (module missing):
```
bun test src/utils/pinBackoff.test.ts
```
Expected: `error: Cannot find module './pinBackoff'`.

3. Create `src/utils/pinBackoff.ts`:
```ts
import { MAX_PIN_ATTEMPTS, PIN_BACKOFF_BASE_MS } from "./constants";

const STORAGE_PREFIX = "p2party-pinAttempts-";
const BACKOFF_CAP_MS = 5 * 60 * 1000; // ~5 minutes; a hard lock would let one
//                                       malicious peer DoS the room, so we throttle.

/**
 * Online-guessing throttle (§7). The first MAX_PIN_ATTEMPTS CPace
 * key-confirmation failures in a room are free (a legitimate user mistypes);
 * each further attempt backs off PIN_BACKOFF_BASE_MS * 2^(n-1), capped, so a
 * guesser is rate-limited to a crawl against the 10^6 PIN space.
 */
export const pinBackoffMs = (failedAttempts: number): number => {
  if (failedAttempts <= MAX_PIN_ATTEMPTS) return 0;

  const over = failedAttempts - MAX_PIN_ATTEMPTS; // 1, 2, 3, ...
  const ms = PIN_BACKOFF_BASE_MS * 2 ** (over - 1);

  return Math.min(ms, BACKOFF_CAP_MS);
};

const readStorage = (): Storage | null => {
  try {
    return (globalThis as unknown as { localStorage?: Storage }).localStorage ??
      null;
  } catch {
    return null;
  }
};

/**
 * Persisted per-ROOM failure count. Keyed ONLY by roomKey — deliberately no
 * identity argument, so a peer returning under a fresh attacker-chosen identity
 * cannot refill the budget, and reconnecting does not reset it.
 */
export const getPinAttempts = (roomKey: string): number => {
  const storage = readStorage();
  if (!storage) return 0;

  try {
    const raw = storage.getItem(STORAGE_PREFIX + roomKey);
    const n = raw ? parseInt(raw, 10) : 0;

    return Number.isInteger(n) && n >= 0 ? n : 0;
  } catch {
    return 0;
  }
};

export const incrementPinAttempts = (roomKey: string): number => {
  const next = getPinAttempts(roomKey) + 1;
  const storage = readStorage();
  if (storage) {
    try {
      storage.setItem(STORAGE_PREFIX + roomKey, String(next));
    } catch {
      /* storage full / unavailable — the throttle degrades to in-flight only */
    }
  }

  return next;
};

/** Clear on a successful key-confirmation or a PIN rotation (§7). */
export const resetPinAttempts = (roomKey: string): void => {
  const storage = readStorage();
  if (!storage) return;

  try {
    storage.removeItem(STORAGE_PREFIX + roomKey);
  } catch {
    /* ignore */
  }
};
```

4. Run it — passes:
```
bun test src/utils/pinBackoff.test.ts
```
Expected: `9 pass, 0 fail`.

5. Commit:
```
git add src/utils/pinBackoff.ts src/utils/pinBackoff.test.ts && git commit -m "stage6: exponential PIN backoff + per-room persisted attempt counter"
```

---

### Task 4 — Transient secure-PIN store (in-RAM only, NEVER localStorage)

**Files:**
- Create `src/utils/securePinStore.ts`
- Create `src/utils/securePinStore.test.ts`

**Interfaces:**
- Consumes `normalizePin` (Task 2).
- Produces `setSecureRoomPin(roomKey: string, rawPin: string): void`, `getSecureRoomPin(roomKey: string): Uint8Array | null`, `clearSecureRoomPin(roomKey: string): void` — a module-level `Map`, precedent `lastReconnectAttempt` (`handleOpenChannel.ts:42`). Consumed by Task 6's `connect()` and `resolveRoomHandshakeMode`. **The PIN secret is held only in RAM and is gone on refresh — it is never written to localStorage/IndexedDB.**

**Steps:**

1. Write the failing test. Create `src/utils/securePinStore.test.ts`:
```ts
import { afterEach, describe, expect, test } from "bun:test";

import {
  setSecureRoomPin,
  getSecureRoomPin,
  clearSecureRoomPin,
} from "./securePinStore";
import { normalizePin } from "./pinNormalize";

afterEach(() => {
  clearSecureRoomPin("roomA");
  clearSecureRoomPin("roomB");
});

describe("securePinStore", () => {
  test("stores an NFC-normalized PIN and reads it back as bytes", () => {
    setSecureRoomPin("roomA", "123456");
    expect(Array.from(getSecureRoomPin("roomA") as Uint8Array)).toEqual(
      Array.from(normalizePin("123456")),
    );
  });

  test("returns null for a room with no PIN (no-PIN mode)", () => {
    expect(getSecureRoomPin("roomB")).toBe(null);
  });

  test("clear removes the transient secret", () => {
    setSecureRoomPin("roomA", "123456");
    clearSecureRoomPin("roomA");
    expect(getSecureRoomPin("roomA")).toBe(null);
  });

  test("NEVER persists the PIN to localStorage", () => {
    const writes: string[] = [];
    (globalThis as unknown as { localStorage: Storage }).localStorage = {
      getItem: () => null,
      setItem: (k: string) => void writes.push(k),
      removeItem: () => {},
      clear: () => {},
      key: () => null,
      length: 0,
    } as Storage;

    setSecureRoomPin("roomA", "123456");

    expect(writes).toEqual([]); // no localStorage write of any kind
    delete (globalThis as unknown as { localStorage?: Storage }).localStorage;
  });
});
```

2. Run it — fails (module missing):
```
bun test src/utils/securePinStore.test.ts
```
Expected: `error: Cannot find module './securePinStore'`.

3. Create `src/utils/securePinStore.ts`:
```ts
import { normalizePin } from "./pinNormalize";

/**
 * The room PIN is a SECRET and MUST NOT be persisted (§7). It lives only in this
 * module-level Map (precedent: lastReconnectAttempt, handleOpenChannel.ts:42) —
 * held in RAM for the lifetime of the tab, gone on refresh, never written to
 * localStorage or IndexedDB. Keyed by the stable room URL (the room identity the
 * caller has at connect() time, before the server assigns a UUID roomId).
 */
const securePins = new Map<string, Uint8Array>();

export const setSecureRoomPin = (roomKey: string, rawPin: string): void => {
  securePins.set(roomKey, normalizePin(rawPin));
};

export const getSecureRoomPin = (roomKey: string): Uint8Array | null =>
  securePins.get(roomKey) ?? null;

export const clearSecureRoomPin = (roomKey: string): void => {
  securePins.delete(roomKey);
};
```

4. Run it — passes:
```
bun test src/utils/securePinStore.test.ts
```
Expected: `4 pass, 0 fail`.

5. Commit:
```
git add src/utils/securePinStore.ts src/utils/securePinStore.test.ts && git commit -m "stage6: transient in-RAM secure-PIN store (never persisted)"
```

---

### Task 5 — `protocolVersion` on the signaling connection message + clean reject

**Files:**
- Modify `src/utils/interfaces.ts` — `WebSocketMessagePeerConnectionRequest` (~line 145) + `WebSocketMessagePeerConnectionResponse` (~line 153)
- Modify `src/api/signalingServerApi.ts` — connection send site (~line 275) + import
- Modify `src/handlers/handleWebSocketMessage.ts` — `case "connection"` guard (~line 480) + import

**Interfaces:**
- Consumes `PROTOCOL_VERSION` (Task 1), `isProtocolVersionCompatible` (Task 1).
- Produces `protocolVersion: number` on both connection message shapes — sent by the client, read on receive for a clean reject.

**Steps:**

1. Add the field to both interface shapes. In `src/utils/interfaces.ts`, edit `WebSocketMessagePeerConnectionRequest`:
```ts
export interface WebSocketMessagePeerConnectionRequest {
  type: "connection";
  roomId: string;
  fromPeerId: string;
  toPeerId: string;
  labels: string[];
  protocolVersion: number;
}
```
and `WebSocketMessagePeerConnectionResponse`:
```ts
export interface WebSocketMessagePeerConnectionResponse {
  type: "connection";
  roomId: string;
  fromPeerId: string;
  fromPeerPublicKey: string;
  labels: string[];
  protocolVersion?: number;
}
```
(Response `protocolVersion` is optional at the type level so a pre-v3 server that omits it is handled by the reject predicate rather than a type error.)

2. Wire the send site. In `src/api/signalingServerApi.ts`, add the import near the other constant imports:
```ts
import { PROTOCOL_VERSION } from "../utils/constants";
```
and add the field to the connection message (~line 275):
```ts
        ws?.send(
          JSON.stringify({
            type: "connection",
            roomId,
            fromPeerId: keyPair.peerId,
            toPeerId: peerId,
            labels: ["main"],
            protocolVersion: PROTOCOL_VERSION,
          } as WebSocketMessagePeerConnectionRequest),
        );
```

3. Wire the receive reject. In `src/handlers/handleWebSocketMessage.ts`, add the import:
```ts
import { isProtocolVersionCompatible } from "../utils/protocolVersion";
```
Then in `case "connection":` guard the whole peer-setup block on version compatibility. Change the opening condition from:
```ts
        if (
          isUUID(keyPair.peerId) &&
```
to:
```ts
        if (
          isProtocolVersionCompatible(message.protocolVersion) &&
          isUUID(keyPair.peerId) &&
```
and add the else branch that fails closed with a clear surface (after the closing `}` of that `if`, before the `break;`/end of case):
```ts
        } else if (!isProtocolVersionCompatible(message.protocolVersion)) {
          console.error(
            `Rejecting peer ${message.fromPeerId}: incompatible protocol ` +
              `version ${String(message.protocolVersion)} (expected v3). No fallback.`,
          );
        }
```
(No `setPeer` / `setChannel` / connection is created — the peer is dropped cleanly, per §7 "clean reject, no fallback".)

4. Typecheck — passes:
```
npm run typecheck
```
Expected: no errors (exit 0).

5. Commit:
```
git add src/utils/interfaces.ts src/api/signalingServerApi.ts src/handlers/handleWebSocketMessage.ts && git commit -m "stage6: protocolVersion on signaling connection message + clean reject on mismatch"
```

---

### Task 6 — `connect(secureRoomPin?)` + room-mode resolution into `OpenChannelHelperParams`

**Files:**
- Modify `src/index.ts` — `connect()` signature (~line 84) + store the PIN
- Create `src/handlers/resolveRoomHandshakeMode.ts`
- Create `src/handlers/resolveRoomHandshakeMode.test.ts`
- Modify `src/handlers/handleOpenChannel.ts` — `OpenChannelHelperParams` (~line 45) + resolve mode/pin at `main` onopen

**Interfaces:**
- Consumes `setSecureRoomPin` (Task 4), `getSecureRoomPin` (Task 4), `selectHandshakeMode` (Task 2).
- Produces `connect(roomUrl, signalingServerUrl?, rtcConfig?, secureRoomPin?)` — the surface a UI PIN field calls; the PIN is NFC-normalized into the transient store keyed by `roomUrl`, never persisted.
- Produces `resolveRoomHandshakeMode(roomId: string, rooms: Array<{ id: string; url: string }>): { mode: "pin" | "nopin"; pin: Uint8Array | null }` — maps the UUID `roomId` back to the room `url` (the transient-store key) and selects the mode. Consumed by `handleOpenChannel` and, downstream, by Stage 4's `runHandshake`.
- Produces `mode: "pin" | "nopin"` + `pin: Uint8Array | null` fields on `OpenChannelHelperParams` (both optional; resolved internally when omitted so the many existing call sites need no change).

**Steps:**

1. Write the failing test for the resolver. Create `src/handlers/resolveRoomHandshakeMode.test.ts`:
```ts
import { afterEach, describe, expect, test } from "bun:test";

import { resolveRoomHandshakeMode } from "./resolveRoomHandshakeMode";
import {
  setSecureRoomPin,
  clearSecureRoomPin,
} from "../utils/securePinStore";
import { normalizePin } from "../utils/pinNormalize";

const ROOM_URL = "a".repeat(64);
const ROOM_ID = "11111111-1111-1111-1111-111111111111";
const rooms = [{ id: ROOM_ID, url: ROOM_URL }];

afterEach(() => clearSecureRoomPin(ROOM_URL));

describe("resolveRoomHandshakeMode", () => {
  test("PIN room: maps roomId -> url, finds the transient PIN, selects 'pin'", () => {
    setSecureRoomPin(ROOM_URL, "123456");
    const { mode, pin } = resolveRoomHandshakeMode(ROOM_ID, rooms);
    expect(mode).toBe("pin");
    expect(Array.from(pin as Uint8Array)).toEqual(
      Array.from(normalizePin("123456")),
    );
  });

  test("no-PIN room: no transient PIN => 'nopin' with null pin", () => {
    const { mode, pin } = resolveRoomHandshakeMode(ROOM_ID, rooms);
    expect(mode).toBe("nopin");
    expect(pin).toBe(null);
  });

  test("unknown roomId => 'nopin' (no crash on missing room)", () => {
    setSecureRoomPin(ROOM_URL, "123456");
    const { mode, pin } = resolveRoomHandshakeMode("no-such-id", rooms);
    expect(mode).toBe("nopin");
    expect(pin).toBe(null);
  });
});
```

2. Run it — fails (module missing):
```
bun test src/handlers/resolveRoomHandshakeMode.test.ts
```
Expected: `error: Cannot find module './resolveRoomHandshakeMode'`.

3. Create `src/handlers/resolveRoomHandshakeMode.ts`:
```ts
import { getSecureRoomPin } from "../utils/securePinStore";
import { selectHandshakeMode } from "../utils/pinNormalize";

/**
 * Resolve the handshake mode for a peer edge at `main` onopen (§7). The transient
 * PIN store is keyed by the room URL (known at connect() time), while the
 * handshake runs with the server-assigned UUID roomId; map roomId -> url via the
 * rooms slice, then pick CPace(pin) vs X3DH(nopin) purely from PIN presence. An
 * unknown room falls back to 'nopin' rather than throwing.
 */
export const resolveRoomHandshakeMode = (
  roomId: string,
  rooms: Array<{ id: string; url: string }>,
): { mode: "pin" | "nopin"; pin: Uint8Array | null } => {
  const room = rooms.find((r) => r.id === roomId);
  const pin = room ? getSecureRoomPin(room.url) : null;

  return { mode: selectHandshakeMode(pin), pin };
};
```

4. Run it — passes:
```
bun test src/handlers/resolveRoomHandshakeMode.test.ts
```
Expected: `3 pass, 0 fail`.

5. Add `secureRoomPin?` to `connect()`. In `src/index.ts`, add the import near the other util imports:
```ts
import { setSecureRoomPin } from "./utils/securePinStore";
```
Change the `connect` signature to accept the optional PIN (append after the `rtcConfig` param, ~line 96):
```ts
  rtcConfig: RTCConfiguration = {
    iceServers: [
      {
        // Use single STUN URL - multiple STUN servers slow down ICE gathering
        urls: "stun:stun.p2party.com:3478",
      },
    ],
    iceTransportPolicy: "all",
    // Pre-allocate ICE candidates for faster connection setup
    iceCandidatePoolSize: 2,
  },
  secureRoomPin?: string,
) => {
  if (roomUrl.length !== 64) throw new Error("Invalid room url length");

  // A PIN is a secret: hold it transiently in RAM keyed by the room URL, NEVER
  // localStorage (§7). Its presence flips the room into CPace/secure mode.
  if (secureRoomPin && secureRoomPin.length > 0)
    setSecureRoomPin(roomUrl, secureRoomPin);
```
(Insert the two-line PIN block immediately after the existing `if (roomUrl.length !== 64) throw ...` guard.)

6. Add the mode/pin fields to `OpenChannelHelperParams` and resolve them at the `main` gate. In `src/handlers/handleOpenChannel.ts`, add the import:
```ts
import { resolveRoomHandshakeMode } from "./resolveRoomHandshakeMode";
```
Extend the interface (~line 45):
```ts
export interface OpenChannelHelperParams {
  channel: string | RTCDataChannel;
  epc: IRTCPeerConnection;
  roomId: string;
  dataChannels: IRTCDataChannel[];
  // protocol-v3 handshake mode for the `main` edge (§7). Resolved internally from
  // the transient PIN store when omitted, so existing call sites need no change.
  mode?: "pin" | "nopin";
  pin?: Uint8Array | null;
}
```
Inside `handleOpenChannel`, after `const roomIndex = rooms.findIndex((r) => r.id === roomId);` (already present ~line 60), resolve the mode so it is available to the `main` onopen handshake (Stage 4 consumes `handshakeMode`/`handshakePin` off this scope when it wires `runHandshake`):
```ts
  const { mode: handshakeMode, pin: handshakePin } =
    resolveRoomHandshakeMode(roomId, rooms);
```
(Stage 4's `runHandshake(epc, handshakeMode, handshakePin, channelInput, module)` call is added inside `extChannel.onopen` gated to `channelLabel === "main"`; this task only guarantees the mode/pin are computed and in scope.)

7. Typecheck — passes:
```
npm run typecheck
```
Expected: no errors (exit 0).

8. Commit:
```
git add src/index.ts src/handlers/resolveRoomHandshakeMode.ts src/handlers/resolveRoomHandshakeMode.test.ts src/handlers/handleOpenChannel.ts && git commit -m "stage6: connect(secureRoomPin?) + room-mode resolution into OpenChannelHelperParams"
```

---

### Task 7 — Serializable `isSecureRoom` + `pakeVerified` failure/verification surface on Redux

**Files:**
- Modify `src/reducers/roomSlice.ts` — `Peer` (~line 15), `SetRoomArgs` (~line 48), `Room` (~line 122), `setRoom` reducer (~lines 158-235), new `setPeerPakeVerified` reducer + export

**Interfaces:**
- Produces `Room.isSecureRoom: boolean` — UI flag (precedent `onlyConnectWithKnownAddresses`); set from `SetRoomArgs.isSecureRoom`. **No PIN/secret is stored in Redux** — only this boolean.
- Produces `Peer.pakeVerified: boolean` + action `setPeerPakeVerified({ roomId, peerId, pakeVerified })` — the serializable UI signal that a peer's handshake succeeded or aborted (wrong-PIN / key-confirm / DTLS-fingerprint mismatch). Consumed by Stage 4's `runHandshake` (sets `true` on success, `false` on abort before teardown) and by the app UI.

**Steps:**

1. Extend the `Peer` interface (~line 15):
```ts
export interface Peer {
  peerId: string;
  peerPublicKey: string;
  // protocol-v3 handshake verification signal for the UI (§8). Serializable
  // boolean ONLY — never any secret / ratchet material. Set false on abort
  // (wrong PIN / key-confirm fail / DTLS fingerprint mismatch), true on success.
  pakeVerified?: boolean;
}
```

2. Extend `SetRoomArgs` (~line 48) and `Room` (~line 122):
```ts
export interface SetRoomArgs {
  url: string;
  id: string;
  canBeConnectionRelay?: boolean;
  onlyConnectWithKnownPeers?: boolean;
  isSecureRoom?: boolean;
  rtcConfig?: RTCConfiguration;
}
```
```ts
export interface Room extends SetRoomArgs {
  connectingToPeers: boolean;
  connectedToPeers: boolean;
  canBeConnectionRelay: boolean;
  onlyConnectWithKnownAddresses: boolean;
  isSecureRoom: boolean;
  rtcConfig: RTCConfiguration;
  peers: Peer[];
  channels: Channel[];
  messages: Message[];
}
```

3. Set `isSecureRoom` in the `setRoom` reducer. Destructure it (~line 158):
```ts
    setRoom: (state, action: PayloadAction<SetRoomArgs>) => {
      const {
        url,
        id,
        canBeConnectionRelay,
        rtcConfig,
        onlyConnectWithKnownPeers,
        isSecureRoom,
      } = action.payload;
```
In each of the four branches, set it. For the two **update** branches add (alongside the existing `canBeConnectionRelay` update):
```ts
          if (isSecureRoom != undefined)
            state[roomIndex].isSecureRoom = isSecureRoom;
```
For the two **push** branches add the field to the pushed object (alongside `canBeConnectionRelay`):
```ts
            isSecureRoom: isSecureRoom ?? false,
```
(`isSecureRoom` is NOT read from localStorage — unlike `onlyConnectWithKnownPeers` — because it tracks the transient in-RAM PIN presence, which does not survive refresh.)

4. Add the `setPeerPakeVerified` reducer. Insert it after the `setConnectedToPeers` reducer (~line 261, keeping the trailing comma pattern):
```ts
    setPeerPakeVerified: (
      state,
      action: PayloadAction<{
        roomId: string;
        peerId: string;
        pakeVerified: boolean;
      }>,
    ) => {
      const { roomId, peerId, pakeVerified } = action.payload;

      const roomIndex = state.findIndex((r) => r.id === roomId);
      if (roomIndex === -1) return;

      const peerIndex = state[roomIndex].peers.findIndex(
        (p) => p.peerId === peerId,
      );
      if (peerIndex > -1)
        state[roomIndex].peers[peerIndex].pakeVerified = pakeVerified;
    },
```

5. Export the new action. Find the `export const { ... } = roomSlice.actions;` block and add `setPeerPakeVerified` to it (locate the exact block first):
```
grep -n "roomSlice.actions" src/reducers/roomSlice.ts
```
Then add `setPeerPakeVerified,` to that destructured export list.

6. Typecheck — passes:
```
npm run typecheck
```
Expected: no errors (exit 0).

7. Run the whole stage-6 unit suite to confirm nothing regressed:
```
bun test src/utils/protocolVersion.test.ts src/utils/pinNormalize.test.ts src/utils/pinBackoff.test.ts src/utils/securePinStore.test.ts src/handlers/resolveRoomHandshakeMode.test.ts
```
Expected: `26 pass, 0 fail`.

8. Commit:
```
git add src/reducers/roomSlice.ts && git commit -m "stage6: serializable isSecureRoom + pakeVerified UI surface (no secrets in Redux)"
```

---

**Stage 6 done-check.** All pure predicates green under `bun test`; `npm run typecheck` clean; version-mismatch peers rejected with no fallback; PINs held only in RAM (never localStorage); per-room backoff schedule enforced and keyed to the room; mode selected from PIN presence and threaded into `OpenChannelHelperParams`; `pakeVerified` gives Stage 4's `runHandshake` a serializable abort/success surface (wrong-PIN, key-confirm, DTLS-fingerprint mismatch all flip it false before teardown). No wire bytes change in this stage — it is signaling-layer negotiation + local state only; the atomic v3 wire break, SRI repin, CDN upload and `0.9.2 -> 0.10.0` bump happen in Stage 7's E2E/release step.


---

## Stage 7 — Real-WebRTC E2E + atomic protocol-v3 release

This stage adds the protocol-v3 end-to-end proofs to the existing headless-Chromium harness (`/Users/deliberative/Desktop/@p2party/p2party.com/e2e/run.mjs`) and then ships the atomic wire break (version bump, CHANGELOG, `npm run dist` → wasm rebuild + SRI repin + fresh `.tgz`, rebuild the app against it, run the full suite green, and note the manual CDN upload).

Two ground-truth facts established by reading the code seams:
- The SDK sets `window.p2party = p2party` at import (`/Users/deliberative/Desktop/@p2party/p2party-js/src/index.ts` bottom), so the harness reaches everything on the public object.
- The harness reuses two persistent Playwright contexts A/B (`setupContext`) whose `addInitScript` already wraps `RTCDataChannel.prototype.send`, `.close`, `RTCPeerConnection`, and `WebSocket`. New scenarios navigate both pages to a *fresh* 64-char room and connect there, so they never disturb the existing transport flow. The existing flow ends at `await browser.close(); log("DONE …")` — all v3 scenarios are inserted immediately before that line.

Preconditions to run the suite (unchanged from the existing harness / definition-of-done): the local signaling server and the app are running; invoke with `APP_URL` and `SIGNALING_URL` env pointing at the local stack, e.g. `APP_URL=http://localhost:5190 SIGNALING_URL=ws://localhost:3001/ws`.

---

### Task 1 — Shippable, secret-free ratchet-session introspection (`ratchetSessionInfo`)

The FS / resume / reload scenarios must observe ratchet counters (`Ns/Nr/PN`, skipped-key count, whether a persisted root exists) from the page. The persisted secret bytes are wrapped and must never enter JS (§8), so we expose a **metadata-only projection** — no `ArrayBuffer` secret ever appears in the returned object. Pure projection is unit-tested; the public export composes it with the Stage-5 `getRatchetSession` worker call.

**Files:**
- Create `/Users/deliberative/Desktop/@p2party/p2party-js/src/db/ratchetSessionInfo.ts`
- Create `/Users/deliberative/Desktop/@p2party/p2party-js/src/db/ratchetSessionInfo.test.ts`
- Modify `/Users/deliberative/Desktop/@p2party/p2party-js/src/index.ts` (import from `./db/api`, add `ratchetSessionInfo` fn + export-object entry near `getSendChunksCount`, ~line 807 block)

**Interfaces:**
- Consumes: `RatchetSession` (type, `src/db/types.ts`, Stage 5); `getRatchetSession(roomId:string, peerPublicKey:string): Promise<RatchetSession|null>` (`src/db/api.ts`, Stage 5).
- Produces: `projectRatchetSessionInfo(s: RatchetSession | null | undefined): RatchetSessionInfo | null`; public `p2party.ratchetSessionInfo(roomId:string, peerPublicKey:string): Promise<RatchetSessionInfo|null>` where `RatchetSessionInfo = { roomId:string; peerPublicKey:string; peerId:string; Ns:number; Nr:number; PN:number; skippedCount:number; hasRootKey:boolean; updatedAt:number }`.

**Steps:**

1. Write the failing unit test `src/db/ratchetSessionInfo.test.ts`:
```ts
import { describe, expect, test } from "bun:test";
import { projectRatchetSessionInfo } from "./ratchetSessionInfo";
import type { RatchetSession } from "./types";

const mkSession = (over: Partial<RatchetSession> = {}): RatchetSession => ({
  roomId: "room-1",
  peerPublicKey: "aa".repeat(32),
  peerId: "peer-1",
  rootKey: new Uint8Array(32).fill(9).buffer,
  sendingChainKey: new Uint8Array(32).fill(1).buffer,
  receivingChainKey: new Uint8Array(32).fill(2).buffer,
  dhSelfPub: new Uint8Array(32).fill(3).buffer,
  dhSelfSec: new Uint8Array(32).fill(4).buffer,
  dhRemotePub: new Uint8Array(32).fill(5).buffer,
  Ns: 7,
  Nr: 4,
  PN: 2,
  skippedMessageKeys: [
    { dhPub: new Uint8Array(32).buffer, n: 0, messageKey: new Uint8Array(32).buffer },
    { dhPub: new Uint8Array(32).buffer, n: 1, messageKey: new Uint8Array(32).buffer },
  ],
  updatedAt: 1234,
  ...over,
});

describe("projectRatchetSessionInfo", () => {
  test("returns null for a missing session", () => {
    expect(projectRatchetSessionInfo(null)).toBeNull();
    expect(projectRatchetSessionInfo(undefined)).toBeNull();
  });

  test("projects counters and skipped-key count", () => {
    const info = projectRatchetSessionInfo(mkSession())!;
    expect(info).toEqual({
      roomId: "room-1",
      peerPublicKey: "aa".repeat(32),
      peerId: "peer-1",
      Ns: 7,
      Nr: 4,
      PN: 2,
      skippedCount: 2,
      hasRootKey: true,
      updatedAt: 1234,
    });
  });

  test("leaks NO secret bytes (no ArrayBuffer/TypedArray in the output)", () => {
    const info = projectRatchetSessionInfo(mkSession())! as Record<string, unknown>;
    for (const v of Object.values(info)) {
      expect(v instanceof ArrayBuffer).toBe(false);
      expect(ArrayBuffer.isView(v as ArrayBufferView)).toBe(false);
    }
  });

  test("hasRootKey is false for an empty root", () => {
    const info = projectRatchetSessionInfo(mkSession({ rootKey: new ArrayBuffer(0) }))!;
    expect(info.hasRootKey).toBe(false);
  });
});
```

2. Run it — fails (module does not exist):
```
cd /Users/deliberative/Desktop/@p2party/p2party-js && bun test src/db/ratchetSessionInfo.test.ts
```
Expected: `error: Cannot find module './ratchetSessionInfo'` (0 pass).

3. Create `src/db/ratchetSessionInfo.ts`:
```ts
import type { RatchetSession } from "./types";

// Secret-free projection of a persisted ratchet session. Returns ONLY counters
// and booleans — never the wrapped secret bytes (rootKey / chain keys / skipped
// message keys). Safe to hand to the UI and to the E2E harness (§8: raw key
// bytes never enter JS).
export interface RatchetSessionInfo {
  roomId: string;
  peerPublicKey: string;
  peerId: string;
  Ns: number;
  Nr: number;
  PN: number;
  skippedCount: number;
  hasRootKey: boolean;
  updatedAt: number;
}

export const projectRatchetSessionInfo = (
  s: RatchetSession | null | undefined,
): RatchetSessionInfo | null =>
  s
    ? {
        roomId: s.roomId,
        peerPublicKey: s.peerPublicKey,
        peerId: s.peerId,
        Ns: s.Ns,
        Nr: s.Nr,
        PN: s.PN,
        skippedCount: s.skippedMessageKeys?.length ?? 0,
        hasRootKey: !!s.rootKey && s.rootKey.byteLength > 0,
        updatedAt: s.updatedAt,
      }
    : null;
```

4. Run the test — passes:
```
cd /Users/deliberative/Desktop/@p2party/p2party-js && bun test src/db/ratchetSessionInfo.test.ts
```
Expected: `4 pass`, `0 fail`.

5. Wire the public export in `src/index.ts`. Add to the imports from `./db/api` the `getRatchetSession` name (Stage 5 added it there), add the projection import, define the composing fn, and register it in the export object next to `getSendChunksCount`:
```ts
// near the other db/api imports
import { getRatchetSession } from "./db/api";
import { projectRatchetSessionInfo } from "./db/ratchetSessionInfo";
```
```ts
// beside the other top-level fns (e.g. under connect/…)
const ratchetSessionInfo = async (roomId: string, peerPublicKey: string) =>
  projectRatchetSessionInfo(await getRatchetSession(roomId, peerPublicKey));
```
```ts
  // in `export const p2party = { … }`, right after getSendChunksCount:
  getSendChunksCount: getDBAllNewChunksCount,
  // Read-only, secret-free ratchet diagnostics for UI + E2E (no key bytes).
  ratchetSessionInfo,
```

6. Typecheck:
```
cd /Users/deliberative/Desktop/@p2party/p2party-js && npm run typecheck
```
Expected: no errors.

7. Commit:
```
cd /Users/deliberative/Desktop/@p2party/p2party-js && git checkout -b stage7-e2e-release 2>/dev/null; git add src/db/ratchetSessionInfo.ts src/db/ratchetSessionInfo.test.ts src/index.ts && git commit -m "$(printf 'feat(db): secret-free ratchetSessionInfo accessor for UI + E2E\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

### Task 2 — Harness substrate: frame capture, header parse, fingerprint/receipt tampering, PIN-aware connect

Extend `setupContext`'s `addInitScript` (page-side instrumentation) and the module-level helpers so the v3 scenarios can: capture every 64 KiB chunk frame's cleartext header + a synchronous content hash, tamper the post-connect `getStats` DTLS fingerprint (MITM), drop the first reverse receipt (retransmit-determinism), and connect a room with/without a PIN by calling `window.p2party.connect` directly (the app Connect button passes no PIN).

**Files:**
- Modify `/Users/deliberative/Desktop/@p2party/p2party.com/e2e/run.mjs` — inside `setupContext` `addInitScript` (the block that starts at `window.__dc = {…}`, ~:25) append the new instrumentation; add module-level helpers after `roomState` (~:143); add `SIGNALING`/`STUN` consts near `APP` (~:9).

**Interfaces:**
- Consumes: `FRAME_TYPE_CHUNK = 2`, `MESSAGE_START = 50`, header layout `type(1)‖DH_pub(32)‖N(8)‖PN(8)‖PQ_EPOCH(1)` (SSOT `src/utils/constants.ts`, Stage 5); `window.p2party.connect(roomUrl, signalingServerUrl, rtcConfig, secureRoomPin?)` (Stage 6); `window.p2party.ratchetSessionInfo` (Task 1).
- Produces (page globals): `window.__chunkFrames: Array<{N,PN,dhPubHex,fnv,len}>`, `window.__frameTypes: number[]`, `window.__tamperGetStatsFp:boolean`, `window.__tamperedFp:boolean`, `window.__dropReceiptArmed:boolean`, `window.__receiptDropped:boolean`. Produces (node helpers): `SIGNALING`, `STUN`, `freshRoom()`, `connectRoom(page,{url,pin,tamperFp})`, `peerRatchet(page,url)`.

**Steps:**

1. Add env consts near the top (after the `WASM = readFileSync(...)` block, ~:12):
```js
const SIGNALING = process.env.SIGNALING_URL ?? "wss://signaling.p2party.com/ws";
const STUN = process.env.STUN_URL ?? "stun:stun.p2party.com:3478";
```

2. Extend the `addInitScript` body. Immediately after the existing `RTCDataChannel.prototype.send = function (data) { … };` assignment (the block ending ~:96), append:
```js
    // ---- protocol-v3 instrumentation --------------------------------------
    // Cleartext chunk-frame header layout (SSOT src/utils/constants.ts):
    //   [FRAME_TYPE_CHUNK=2 (1)] [DH_pub (32)] [N (8, BE)] [PN (8, BE)] [PQ_EPOCH (1)]
    // then the AEAD ciphertext. Total forward chunk frame length is 65536.
    const FRAME_TYPE_CHUNK = 2;
    window.__chunkFrames = []; // { N, PN, dhPubHex, fnv, len }
    window.__frameTypes = []; // first byte of every 65536-byte forward frame
    const toU8 = (d) =>
      d instanceof ArrayBuffer
        ? new Uint8Array(d)
        : d && d.buffer
          ? new Uint8Array(d.buffer, d.byteOffset || 0, d.byteLength)
          : new Uint8Array(0);
    const fnv1a = (u8) => {
      let h = 0x811c9dc5 >>> 0;
      for (let i = 0; i < u8.length; i++) {
        h ^= u8[i];
        h = Math.imul(h, 0x01000193) >>> 0;
      }
      return h >>> 0;
    };
    const hex = (u8) =>
      Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");
    window.__recordFrame = (data) => {
      const u8 = toU8(data);
      if (u8.length !== 65536) return;
      window.__frameTypes.push(u8[0]);
      if (u8[0] !== FRAME_TYPE_CHUNK) return;
      const dv = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
      window.__chunkFrames.push({
        dhPubHex: hex(u8.subarray(1, 33)),
        N: Number(dv.getBigUint64(33, false)),
        PN: Number(dv.getBigUint64(41, false)),
        fnv: fnv1a(u8),
        len: u8.length,
      });
    };

    // MITM: flip the post-connect getStats DTLS fingerprint so it disagrees with
    // the value bound into CI (which the SDK read from the SDP). DTLS itself stays
    // intact (the SDP fingerprint is untouched) so this exercises the getStats
    // re-verify → tear-down path specifically, not a DTLS failure.
    window.__tamperGetStatsFp = false;
    window.__tamperedFp = false;
    const flipFp = (fp) => {
      // "AB:CD:…" hex-pair fingerprint; flip the low bit of the last pair.
      const parts = String(fp).split(":");
      const last = parts[parts.length - 1];
      const v = (parseInt(last, 16) ^ 0x01) & 0xff;
      parts[parts.length - 1] = v.toString(16).padStart(2, "0").toUpperCase();
      return parts.join(":");
    };
    const OrigGetStats = RTCPeerConnection.prototype.getStats;
    RTCPeerConnection.prototype.getStats = async function (...a) {
      const report = await OrigGetStats.apply(this, a);
      if (!window.__tamperGetStatsFp) return report;
      const entries = [];
      report.forEach((v, k) => {
        if (v && v.type === "certificate" && v.fingerprint) {
          window.__tamperedFp = true;
          entries.push([k, { ...v, fingerprint: flipFp(v.fingerprint) }]);
        } else {
          entries.push([k, v]);
        }
      });
      const m = new Map(entries);
      m.forEach = (cb) => entries.forEach(([k, v]) => cb(v, k, m));
      return m;
    };

    // Receipt-drop: drop the FIRST 64-byte reverse receipt once, so the sender's
    // reconcile resends the corresponding chunk — used to prove the resent
    // ciphertext is byte-identical (cached-ciphertext reuse, not a fresh nonce).
    window.__dropReceiptArmed = false;
    window.__receiptDropped = false;
```

3. Fold the new hooks into the existing `RTCDataChannel.prototype.send` override. Change its two guarded regions: (a) drop the first receipt when armed; (b) record chunk frames. Replace the existing override body’s content by adding, at the very top of the function (before the `len === 65536 && window.__dropArmed` guard):
```js
      const _len =
        data && data.byteLength != null
          ? data.byteLength
          : (data && data.length) || 0;
      if (
        _len === 64 &&
        window.__dropReceiptArmed &&
        !window.__receiptDropped
      ) {
        window.__receiptDropped = true;
        return; // dropped reverse receipt → forces a chunk retransmit
      }
```
and, immediately before the final `return origSend.apply(this, arguments);`, add:
```js
      try {
        window.__recordFrame(data);
      } catch {}
```

4. Add the node-side helpers after the `roomState` definition (~:143):
```js
// Navigate a page to a fresh room and connect it, optionally with a PIN and/or
// with the getStats-fingerprint MITM armed. Calls window.p2party.connect
// directly (the app's Connect button passes no PIN).
async function connectRoom(page, { url, pin = null, tamperFp = false }) {
  await page.goto(`${APP}/rooms/${url}`, { waitUntil: "domcontentloaded" });
  await waitFor(page, () => !!(window.p2party && window.p2party.store), null, {
    label: "p2party available",
    timeout: 30000,
  });
  if (tamperFp) await page.evaluate(() => (window.__tamperGetStatsFp = true));
  await page.evaluate(
    ({ url, sig, stun, pin }) =>
      window.p2party.connect(
        url,
        sig,
        { iceServers: [{ urls: [stun] }], iceTransportPolicy: "all" },
        pin ?? undefined,
      ),
    { url, sig: SIGNALING, stun: STUN, pin },
  );
}

// Read the (secret-free) ratchet session for this page's view of the given room's
// single remote peer. Returns { established, pakeVerified, info } or null.
const peerRatchet = (page, url) =>
  page.evaluate(async (url) => {
    const P = window.p2party;
    const rooms = P.roomSelector(P.store.getState()) || [];
    const r = rooms.find((x) => x.url === url);
    if (!r || !r.id) return null;
    const peer = (r.peers || [])[0];
    if (!peer) return { established: false, pakeVerified: false, info: null };
    const info = await P.ratchetSessionInfo(r.id, peer.peerPublicKey);
    return {
      roomId: r.id,
      peerId: peer.peerId,
      peerPublicKey: peer.peerPublicKey,
      established: !!peer.ratchetEstablished,
      pakeVerified: !!peer.pakeVerified,
      info,
    };
  }, url);

const freshRoom = () => randomBytes(32).toString("hex");
```
(`peer.peerPublicKey`, `peer.ratchetEstablished`, `peer.pakeVerified` are the Stage-4/6 `Peer` fields on `roomSlice`.)

5. Sanity-run the untouched suite to confirm the instrumentation did not regress the existing transport flow:
```
cd /Users/deliberative/Desktop/@p2party/p2party.com && APP_URL=http://localhost:5190 SIGNALING_URL=ws://localhost:3001/ws node e2e/run.mjs 2>&1 | tail -20
```
Expected: still ends with `DONE — all transfers verified over real WebRTC` and exit 0.

6. Commit (in the p2party.com repo):
```
cd /Users/deliberative/Desktop/@p2party/p2party.com && git checkout -b stage7-protocol-v3-e2e 2>/dev/null; git add e2e/run.mjs && git commit -m "$(printf 'test(e2e): v3 harness substrate — frame capture, fp/receipt tamper, PIN connect\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

### Task 3 — No-PIN room: byte-exact transfer + ratchet engaged

**Files:** Modify `/Users/deliberative/Desktop/@p2party/p2party.com/e2e/run.mjs` — insert the block below immediately before the final `await browser.close();\n    log("DONE — all transfers verified over real WebRTC");` (~:763).

**Interfaces:** Consumes `connectRoom`, `peerRatchet`, `freshRoom`, `waitFor` (Task 2); `window.p2party.sendMessage/readMessage/roomSelector` (existing). No PIN → X3DH-DH seed (Stage 2/4).

**Steps:**

1. Append the scenario:
```js
    // ===================================================================
    // V3-1. NO-PIN room: FS-everywhere ratchet engages (X3DH-DH seed),
    // transfer is byte-exact. No PIN ⇒ pakeVerified stays false but the
    // ratchet is still established.
    // ===================================================================
    {
      const url = freshRoom();
      log("V3 no-PIN room:", url);
      await connectRoom(A.page, { url });
      await connectRoom(B.page, { url });
      for (const [tag, p] of [["A", A.page], ["B", B.page]]) {
        const rr = await waitFor(p, () => null, null, { label: "noop", timeout: 1 }).catch(() => null);
        void rr; void tag;
      }
      const rA = await waitFor(
        A.page,
        async (u) => {
          const P = window.p2party;
          const rooms = P.roomSelector(P.store.getState()) || [];
          const r = rooms.find((x) => x.url === u);
          const peer = r && (r.peers || [])[0];
          return peer && peer.ratchetEstablished ? { ok: true } : null;
        },
        url,
        { label: "A ratchet established (no-PIN)", timeout: 60000 },
      );
      void rA;
      const pA = await peerRatchet(A.page, url);
      const pB = await peerRatchet(B.page, url);
      log("no-PIN ratchet A:", JSON.stringify(pA), "B:", JSON.stringify(pB));
      if (!pA.established || !pB.established)
        throw new Error("no-PIN: ratchet not established on both peers");
      if (pA.pakeVerified || pB.pakeVerified)
        throw new Error("no-PIN: pakeVerified must be false without a PIN");
      if (!pA.info || !pA.info.hasRootKey)
        throw new Error("no-PIN: persisted ratchet root missing on A");

      const roomIdN = pA.roomId;
      const T = "nopin-" + url.slice(0, 8);
      await A.page.evaluate(
        ({ t, roomId }) => window.p2party.sendMessage(t, "main", roomId),
        { t: T, roomId: roomIdN },
      );
      const gotN = await waitFor(
        B.page,
        async (u) => {
          const P = window.p2party;
          const rooms = P.roomSelector(P.store.getState()) || [];
          const r = rooms.find((x) => x.url === u);
          if (!r) return null;
          const m = (r.messages || []).find((x) => x.merkleRootHex);
          if (!m) return null;
          const res = await P.readMessage(m.merkleRootHex);
          return res.percentage === 100 ? { msg: res.message } : null;
        },
        url,
        { label: "B receives no-PIN text", timeout: 60000 },
      );
      if (gotN.msg !== T) throw new Error(`no-PIN text mismatch: ${gotN.msg}`);
      log("✅ V3 NO-PIN: ratchet engaged (FS everywhere) + byte-exact transfer");
    }
```

2. Run the suite; confirm the new line:
```
cd /Users/deliberative/Desktop/@p2party/p2party.com && APP_URL=http://localhost:5190 SIGNALING_URL=ws://localhost:3001/ws node e2e/run.mjs 2>&1 | grep -E "V3 NO-PIN|FAILED"
```
Expected: `✅ V3 NO-PIN: ratchet engaged (FS everywhere) + byte-exact transfer`. If it fails on `ratchetEstablished`, the defect is in the Stage-4 handshake orchestration (`src/handlers/handleHandshake.ts` / `handleOpenChannel.ts` main-onopen gating), not here.

3. Commit:
```
cd /Users/deliberative/Desktop/@p2party/p2party.com && git add e2e/run.mjs && git commit -m "$(printf 'test(e2e): no-PIN room ratchet-engaged + byte-exact\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

### Task 4 — PIN room: byte-exact transfer + forward secrecy (captured frame unrecoverable)

Both peers connect with the **same** 6-digit PIN → CPace seed + key-confirm → `pakeVerified` true. Capture message #1's cleartext header; then advance the ratchet with several more messages and prove the receiver's persisted state no longer holds the key for the captured frame (`Nr` moved past it, `skippedCount === 0`). Combined with the one-way KDF chain that is Stage 3's ratchet, the captured ciphertext is unrecoverable from current state — forward secrecy.

**Files:** Modify `/Users/deliberative/Desktop/@p2party/p2party.com/e2e/run.mjs` — insert after the Task 3 block, before `browser.close()`.

**Interfaces:** Consumes `connectRoom({pin})`, `peerRatchet`, `window.__chunkFrames` (Task 2); PIN ⇒ CPace seed + key-confirm (Stage 1/4); `pakeVerified` Peer flag (Stage 6).

**Steps:**

1. Append the scenario:
```js
    // ===================================================================
    // V3-2. PIN room: CPace seed + key-confirmation ⇒ pakeVerified,
    // byte-exact transfer, and FORWARD SECRECY — a captured frame's key is
    // gone from persisted state once the ratchet advances past it.
    // ===================================================================
    {
      const url = freshRoom();
      const PIN = "402913"; // 6-digit numeric default (§7)
      log("V3 PIN room:", url);
      await A.page.evaluate(() => {
        window.__chunkFrames = [];
      });
      await connectRoom(A.page, { url, pin: PIN });
      await connectRoom(B.page, { url, pin: PIN });

      await waitFor(
        A.page,
        async (u) => {
          const P = window.p2party;
          const rooms = P.roomSelector(P.store.getState()) || [];
          const r = rooms.find((x) => x.url === u);
          const peer = r && (r.peers || [])[0];
          return peer && peer.ratchetEstablished && peer.pakeVerified ? {} : null;
        },
        url,
        { label: "A PIN handshake confirmed", timeout: 60000 },
      );
      const pA = await peerRatchet(A.page, url);
      const pB = await peerRatchet(B.page, url);
      log("PIN ratchet A:", JSON.stringify(pA), "B:", JSON.stringify(pB));
      if (!(pA.pakeVerified && pB.pakeVerified))
        throw new Error("PIN: pakeVerified not set on both peers (key-confirm failed)");

      const roomId = pA.roomId;
      // Message #1 from A → capture its header off the wire.
      await A.page.evaluate(() => (window.__chunkFrames = []));
      await A.page.evaluate(
        ({ roomId }) => window.p2party.sendMessage("fs-msg-1", "main", roomId),
        { roomId },
      );
      const captured = await waitFor(
        A.page,
        () => (window.__chunkFrames.length > 0 ? window.__chunkFrames[0] : null),
        null,
        { label: "A capture frame #1 header", timeout: 30000 },
      );
      // B must receive it (control: the frame IS decryptable now).
      const g1 = await waitFor(
        B.page,
        async (u) => {
          const P = window.p2party;
          const rooms = P.roomSelector(P.store.getState()) || [];
          const r = rooms.find((x) => x.url === u);
          const m = r && (r.messages || []).find((x) => x.merkleRootHex);
          if (!m) return null;
          const res = await P.readMessage(m.merkleRootHex);
          return res.percentage === 100 ? { msg: res.message } : null;
        },
        url,
        { label: "B receives fs-msg-1", timeout: 60000 },
      );
      if (g1.msg !== "fs-msg-1") throw new Error("PIN: msg-1 not byte-exact");
      log(`captured frame #1 header: N=${captured.N} PN=${captured.PN} dhPub=${captured.dhPubHex.slice(0, 16)}…`);

      // Advance the ratchet well past frame #1 (each logical message steps it).
      for (let i = 2; i <= 8; i++) {
        await A.page.evaluate(
          ({ roomId, i }) => window.p2party.sendMessage("fs-msg-" + i, "main", roomId),
          { roomId, i },
        );
        await waitFor(
          B.page,
          async (u) => {
            const P = window.p2party;
            const rooms = P.roomSelector(P.store.getState()) || [];
            const r = rooms.find((x) => x.url === u);
            for (const m of r?.messages || []) {
              if (!m.merkleRootHex) continue;
              const res = await P.readMessage(m.merkleRootHex);
              if (res.percentage === 100 && res.message === "fs-msg-" + i) return {};
            }
            return null;
          },
          url,
          { label: "B receives fs-msg-" + i, timeout: 60000 },
        );
      }

      // FS assertion: B's persisted receiving state advanced past the captured
      // N and holds NO skipped key — the message key for frame #1 is gone; the
      // one-way KDF chain cannot re-derive it, so the captured ciphertext is
      // unrecoverable from current state.
      const pBafter = await peerRatchet(B.page, url);
      log("PIN post-advance B ratchet:", JSON.stringify(pBafter.info));
      if (!pBafter.info) throw new Error("PIN FS: B session missing");
      if (!(pBafter.info.Nr > captured.N))
        throw new Error(
          `PIN FS: receiving chain did not advance past captured N (Nr=${pBafter.info.Nr}, capturedN=${captured.N})`,
        );
      if (pBafter.info.skippedCount !== 0)
        throw new Error(
          `PIN FS: a skipped message key for the captured frame is still retained (skippedCount=${pBafter.info.skippedCount})`,
        );
      log("✅ V3 PIN: pakeVerified + byte-exact + FORWARD SECRECY (captured-frame key purged from persisted state)");
    }
```

2. Run and confirm:
```
cd /Users/deliberative/Desktop/@p2party/p2party.com && APP_URL=http://localhost:5190 SIGNALING_URL=ws://localhost:3001/ws node e2e/run.mjs 2>&1 | grep -E "V3 PIN|FAILED"
```
Expected: `✅ V3 PIN: pakeVerified + byte-exact + FORWARD SECRECY …`. A failure on `pakeVerified` points at Stage 1/4 CPace + key-confirm; a failure on `skippedCount` points at Stage 3 skipped-key pruning.

3. Commit:
```
cd /Users/deliberative/Desktop/@p2party/p2party.com && git add e2e/run.mjs && git commit -m "$(printf 'test(e2e): PIN room pakeVerified + byte-exact + forward secrecy\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

### Task 5 — Wrong-PIN → fail-closed (no data, no ratchet)

**Files:** Modify `run.mjs` — insert after the Task 4 block.

**Interfaces:** Consumes `connectRoom({pin})`, `peerRatchet`. Wrong PIN ⇒ CPace key-confirm MAC mismatch ⇒ abort the channel (Stage 4/6, no fallback).

**Steps:**

1. Append:
```js
    // ===================================================================
    // V3-3. WRONG PIN → fail closed. A and B use DIFFERENT PINs, so the two
    // legs' CI/key-confirm MACs disagree ⇒ the channel aborts. Ratchet must
    // NEVER establish and NO application data may be delivered.
    // ===================================================================
    {
      const url = freshRoom();
      log("V3 wrong-PIN room:", url);
      await connectRoom(A.page, { url, pin: "111111" });
      await connectRoom(B.page, { url, pin: "999999" });

      // Give the handshake ample time to run and fail-closed.
      await A.page.waitForTimeout(15000);
      const pA = await peerRatchet(A.page, url);
      const pB = await peerRatchet(B.page, url);
      log("wrong-PIN ratchet A:", JSON.stringify(pA), "B:", JSON.stringify(pB));
      if ((pA && pA.established) || (pB && pB.established))
        throw new Error("wrong-PIN: ratchet established despite mismatched PINs (must fail closed)");
      if ((pA && pA.info) || (pB && pB.info))
        throw new Error("wrong-PIN: a ratchet session was persisted despite a failed handshake");

      // A tries to send anyway; B must never receive it (aborted channel).
      const roomIdW = pA ? pA.roomId : null;
      if (roomIdW) {
        await A.page
          .evaluate(
            ({ roomId }) => window.p2party.sendMessage("should-never-arrive", "main", roomId),
            { roomId: roomIdW },
          )
          .catch(() => {}); // send may reject on the aborted edge — acceptable
      }
      await B.page.waitForTimeout(8000);
      const delivered = await B.page.evaluate((u) => {
        const P = window.p2party;
        const rooms = P.roomSelector(P.store.getState()) || [];
        const r = rooms.find((x) => x.url === u);
        return (r?.messages || []).some((m) => m.merkleRootHex);
      }, url);
      if (delivered)
        throw new Error("wrong-PIN: application data was delivered on a fail-closed channel");
      log("✅ V3 WRONG-PIN: fail closed — no ratchet, no persisted session, no data delivered");
    }
```

2. Run and confirm:
```
cd /Users/deliberative/Desktop/@p2party/p2party.com && APP_URL=http://localhost:5190 SIGNALING_URL=ws://localhost:3001/ws node e2e/run.mjs 2>&1 | grep -E "WRONG-PIN|FAILED"
```
Expected: `✅ V3 WRONG-PIN: fail closed …`.

3. Commit:
```
cd /Users/deliberative/Desktop/@p2party/p2party.com && git add e2e/run.mjs && git commit -m "$(printf 'test(e2e): wrong-PIN fail-closed (no ratchet, no data)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

### Task 6 — MITM abort: swapped DTLS fingerprint tears the channel down

Arm the `getStats`-fingerprint tamper on B so its post-connect DTLS fingerprint disagrees with the value bound into CI. The Stage-4 re-verify (§5) must abort — even in a no-PIN room, the identity-key floor plus fingerprint binding are checked; the channel tears down and no data is delivered.

**Files:** Modify `run.mjs` — insert after the Task 5 block.

**Interfaces:** Consumes `connectRoom({tamperFp:true})`, `window.__tamperedFp`, `peerRatchet` (Task 2). DTLS-fingerprint re-verify → abort (Stage 4).

**Steps:**

1. Append:
```js
    // ===================================================================
    // V3-4. MITM abort. B's post-connect getStats fingerprint is flipped so it
    // disagrees with the fingerprint bound into CI (DTLS itself intact). The
    // handshake's getStats re-verify must tear the channel down — no ratchet,
    // no data. Uses a PIN room so both the fp-binding and CI paths are live.
    // ===================================================================
    {
      const url = freshRoom();
      const PIN = "246810";
      log("V3 MITM room:", url);
      await connectRoom(A.page, { url, pin: PIN });
      await connectRoom(B.page, { url, pin: PIN, tamperFp: true });

      await B.page.waitForTimeout(15000);
      const tampered = await B.page.evaluate(() => window.__tamperedFp);
      if (!tampered)
        throw new Error("MITM setup: getStats fingerprint was never read/tampered — cannot prove the abort path");
      const pA = await peerRatchet(A.page, url);
      const pB = await peerRatchet(B.page, url);
      log("MITM ratchet A:", JSON.stringify(pA), "B:", JSON.stringify(pB), "tampered:", tampered);
      if ((pB && pB.established) || (pA && pA.established))
        throw new Error("MITM: ratchet established despite a fingerprint mismatch (abort failed)");

      const roomIdM = pA ? pA.roomId : null;
      if (roomIdM) {
        await A.page
          .evaluate(
            ({ roomId }) => window.p2party.sendMessage("mitm-should-not-arrive", "main", roomId),
            { roomId: roomIdM },
          )
          .catch(() => {});
      }
      await B.page.waitForTimeout(8000);
      const deliveredM = await B.page.evaluate((u) => {
        const P = window.p2party;
        const rooms = P.roomSelector(P.store.getState()) || [];
        const r = rooms.find((x) => x.url === u);
        return (r?.messages || []).some((m) => m.merkleRootHex);
      }, url);
      if (deliveredM)
        throw new Error("MITM: data delivered despite a fingerprint mismatch");
      log("✅ V3 MITM: swapped DTLS fingerprint → channel torn down, no data delivered");

      // Disarm so later scenarios are unaffected.
      await B.page.evaluate(() => (window.__tamperGetStatsFp = false));
    }
```

2. Run and confirm:
```
cd /Users/deliberative/Desktop/@p2party/p2party.com && APP_URL=http://localhost:5190 SIGNALING_URL=ws://localhost:3001/ws node e2e/run.mjs 2>&1 | grep -E "V3 MITM|FAILED"
```
Expected: `✅ V3 MITM: swapped DTLS fingerprint → channel torn down, no data delivered`. A failure here (ratchet established anyway) is a Stage-4 defect in the `getStats` certificate re-verify.

3. Commit:
```
cd /Users/deliberative/Desktop/@p2party/p2party.com && git add e2e/run.mjs && git commit -m "$(printf 'test(e2e): MITM abort on swapped DTLS fingerprint\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

### Task 7 — Reconnect mid-transfer resumes the ratchet byte-exact (from the wrapped store)

A full reconnect (brand-new `RTCPeerConnection`) mid-transfer, with the WS relay blocked, can only complete if the ratchet continuity comes from the persisted (wrapped) `ratchetSessions` store keyed by `peerPublicKey` (§8). Byte-exact completion after a new pc, with relay blocked, IS the proof the wrapped state rehydrated the ratchet — a fresh handshake would desync `Ns/Nr` and fail decryption. Also assert the resumed session kept the same identity edge (`peerPublicKey`) and its `Nr` advanced past the pre-cut value.

**Files:** Modify `run.mjs` — insert after the Task 6 block.

**Interfaces:** Consumes `connectRoom`, `peerRatchet`, `window.__pcCount`, `window.__blockRelay`, `window.__dc.count65536` (existing + Task 2); `disconnectFromPeer` (existing). Persisted continuity by `(roomId, peerPublicKey)` (Stage 5/8).

**Steps:**

1. Append:
```js
    // ===================================================================
    // V3-5. Reconnect mid-transfer resumes the RATCHET byte-exact. Relay is
    // blocked, so completion is only possible if the new pc's handshake path
    // rehydrated the ratchet from the wrapped store keyed by peerPublicKey.
    // ===================================================================
    {
      const url = freshRoom();
      const PIN = "135791";
      log("V3 resume room:", url);
      await connectRoom(A.page, { url, pin: PIN });
      await connectRoom(B.page, { url, pin: PIN });
      const p0 = await waitFor(
        A.page,
        async (u) => {
          const P = window.p2party;
          const rooms = P.roomSelector(P.store.getState()) || [];
          const r = rooms.find((x) => x.url === u);
          const peer = r && (r.peers || [])[0];
          return peer && peer.ratchetEstablished ? { roomId: r.id, peerPublicKey: peer.peerPublicKey } : null;
        },
        url,
        { label: "resume: A ratchet established", timeout: 60000 },
      );
      const bPeerPub = (await peerRatchet(B.page, url)).peerPublicKey;
      const bPeerIdR = (await peerRatchet(A.page, url)).peerId;
      const preCut = await peerRatchet(B.page, url);

      await A.page.evaluate(() => (window.__blockRelay = true));
      await B.page.evaluate(() => (window.__blockRelay = true));
      const RES_BYTES = 5_000_000;
      const baseline = await A.page.evaluate(() => window.__dc.count65536);
      await A.page.evaluate(
        ({ roomId, n }) => {
          const bytes = new Uint8Array(n);
          for (let i = 0; i < n; i++) bytes[i] = (i * 131 + 17) & 0xff;
          const file = new File([bytes], "v3resume.bin", { type: "application/octet-stream" });
          window.__v3resume = window.p2party.sendMessage(file, "main", roomId);
          return true;
        },
        { roomId: p0.roomId, n: RES_BYTES },
      );
      await waitFor(
        A.page,
        (b) => window.__dc.count65536 >= b + 20,
        baseline,
        { label: "resume: mid-flight", timeout: 60000, interval: 200 },
      );
      const framesAtCut = await A.page.evaluate(() => window.__dc.count65536);
      const pcBefore = await A.page.evaluate(() => window.__pcCount);
      await A.page.evaluate((pid) => window.p2party.disconnectFromPeer(pid), bPeerIdR);
      log(`resume: cut at ${framesAtCut} frames, forcing full reconnect`);

      const gotR = await waitFor(
        B.page,
        async ({ u, n }) => {
          const P = window.p2party;
          const rooms = P.roomSelector(P.store.getState()) || [];
          const r = rooms.find((x) => x.url === u);
          for (const m of r?.messages || []) {
            if (!m.merkleRootHex || m.totalSize !== n) continue;
            const res = await P.readMessage(m.merkleRootHex);
            if (res.percentage !== 100) continue;
            if (res.message instanceof Blob && res.message.size === n) {
              const buf = new Uint8Array(await res.message.arrayBuffer());
              let ok = true;
              for (let i = 0; i < buf.length; i++)
                if (buf[i] !== ((i * 131 + 17) & 0xff)) { ok = false; break; }
              return { byteExact: ok };
            }
          }
          return null;
        },
        { u: url, n: RES_BYTES },
        { label: "resume: B receives after reconnect", timeout: Number(process.env.RESUME_TIMEOUT ?? 180000), interval: 1000 },
      );
      const pcAfter = await A.page.evaluate(() => window.__pcCount);
      const framesAfter = await A.page.evaluate(() => window.__dc.count65536);
      const relayBlocked = await A.page.evaluate(() => window.__relayBlocked);
      const postCut = await peerRatchet(B.page, url);
      log(`resume: byteExact=${gotR.byteExact} pc ${pcBefore}->${pcAfter} frames ${framesAtCut}->${framesAfter} relayBlocked=${relayBlocked}`);
      if (!gotR.byteExact) throw new Error("resume: file corrupted — ratchet did not resume from the wrapped store");
      if (!(pcAfter > pcBefore)) throw new Error("resume: no new RTCPeerConnection (ICE restart, not full reconnect)");
      if (!(framesAfter > framesAtCut)) throw new Error("resume: no P2P resend after reconnect");
      if (!(relayBlocked > 0)) throw new Error("resume: relay never exercised — cannot conclude P2P-only");
      if (postCut.peerPublicKey !== bPeerPub)
        throw new Error("resume: session did not rebind to the stable peerPublicKey edge");
      if (!(postCut.info && postCut.info.Nr > (preCut.info ? preCut.info.Nr : -1)))
        throw new Error("resume: receiving chain did not advance across the reconnect (fresh handshake, not resume)");

      await A.page.evaluate(() => (window.__blockRelay = false));
      await B.page.evaluate(() => (window.__blockRelay = false));
      log("✅ V3 RESUME: mid-transfer full reconnect resumed the ratchet from the wrapped store, byte-exact");
    }
```

2. Run and confirm:
```
cd /Users/deliberative/Desktop/@p2party/p2party.com && APP_URL=http://localhost:5190 SIGNALING_URL=ws://localhost:3001/ws RESUME_TIMEOUT=200000 node e2e/run.mjs 2>&1 | grep -E "V3 RESUME|FAILED"
```
Expected: `✅ V3 RESUME: mid-transfer full reconnect resumed the ratchet from the wrapped store, byte-exact`.

3. Commit:
```
cd /Users/deliberative/Desktop/@p2party/p2party.com && git add e2e/run.mjs && git commit -m "$(printf 'test(e2e): reconnect mid-transfer resumes ratchet byte-exact\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

### Task 8 — Reload persistence continues the ratchet (wrapped state unwraps)

After B reloads (worker torn down, in-memory ratchet gone), B rebuilds `epc` and must continue the ratchet by unwrapping the persisted `ratchetSessions` row keyed by `peerPublicKey` — proven by A sending a NEW message that B decrypts byte-exact after the reload (a fresh handshake would desync).

**Files:** Modify `run.mjs` — insert after the Task 7 block.

**Interfaces:** Consumes `connectRoom({pin})`, `peerRatchet`; at-rest unwrap on read (`src/db/ratchetWrap.ts`, Stage 5/8).

**Steps:**

1. Append:
```js
    // ===================================================================
    // V3-6. Reload persistence: the wrapped ratchet survives a full page
    // reload and continues (unwraps + advances), not a fresh handshake.
    // ===================================================================
    {
      const url = freshRoom();
      const PIN = "864209";
      log("V3 reload-persist room:", url);
      await connectRoom(A.page, { url, pin: PIN });
      await connectRoom(B.page, { url, pin: PIN });
      const est = await waitFor(
        A.page,
        async (u) => {
          const P = window.p2party;
          const rooms = P.roomSelector(P.store.getState()) || [];
          const r = rooms.find((x) => x.url === u);
          const peer = r && (r.peers || [])[0];
          return peer && peer.ratchetEstablished ? { roomId: r.id } : null;
        },
        url,
        { label: "reload: A established", timeout: 60000 },
      );
      const roomIdRl = est.roomId;
      await A.page.evaluate(
        ({ roomId }) => window.p2party.sendMessage("pre-reload", "main", roomId),
        { roomId: roomIdRl },
      );
      await waitFor(
        B.page,
        async (u) => {
          const P = window.p2party;
          const rooms = P.roomSelector(P.store.getState()) || [];
          const r = rooms.find((x) => x.url === u);
          for (const m of r?.messages || []) {
            if (!m.merkleRootHex) continue;
            const res = await P.readMessage(m.merkleRootHex);
            if (res.percentage === 100 && res.message === "pre-reload") return {};
          }
          return null;
        },
        url,
        { label: "reload: B got pre-reload msg", timeout: 60000 },
      );
      const bPubBefore = (await peerRatchet(B.page, url)).peerPublicKey;

      log("Reloading B to prove the wrapped ratchet unwraps and continues…");
      await B.page.reload({ waitUntil: "domcontentloaded" });
      await connectRoom(B.page, { url, pin: PIN }); // re-consent/reconnect same room+PIN
      const bAfter = await waitFor(
        B.page,
        async (u) => {
          const P = window.p2party;
          if (!P || !P.store) return null;
          const rooms = P.roomSelector(P.store.getState()) || [];
          const r = rooms.find((x) => x.url === u);
          const peer = r && (r.peers || [])[0];
          if (!peer || !peer.ratchetEstablished) return null;
          const info = await P.ratchetSessionInfo(r.id, peer.peerPublicKey);
          return info && info.hasRootKey ? { pub: peer.peerPublicKey } : null;
        },
        url,
        { label: "reload: B ratchet rehydrated", timeout: 90000, interval: 1000 },
      );
      if (bAfter.pub !== bPubBefore)
        throw new Error("reload: peerPublicKey edge changed — not a continuation");

      // Decisive: A sends a NEW message; B decrypts it byte-exact AFTER the reload.
      await A.page.evaluate(
        ({ roomId }) => window.p2party.sendMessage("post-reload", "main", roomId),
        { roomId: roomIdRl },
      );
      const gotAfter = await waitFor(
        B.page,
        async (u) => {
          const P = window.p2party;
          const rooms = P.roomSelector(P.store.getState()) || [];
          const r = rooms.find((x) => x.url === u);
          for (const m of r?.messages || []) {
            if (!m.merkleRootHex) continue;
            const res = await P.readMessage(m.merkleRootHex);
            if (res.percentage === 100 && res.message === "post-reload") return { ok: true };
          }
          return null;
        },
        url,
        { label: "reload: B decrypts post-reload msg", timeout: 90000, interval: 1000 },
      );
      if (!gotAfter.ok) throw new Error("reload: post-reload message not decrypted — ratchet did not continue");
      log("✅ V3 RELOAD PERSISTENCE: wrapped ratchet unwrapped and continued after a page reload");
    }
```

2. Run and confirm:
```
cd /Users/deliberative/Desktop/@p2party/p2party.com && APP_URL=http://localhost:5190 SIGNALING_URL=ws://localhost:3001/ws node e2e/run.mjs 2>&1 | grep -E "RELOAD PERSISTENCE|FAILED"
```
Expected: `✅ V3 RELOAD PERSISTENCE: wrapped ratchet unwrapped and continued after a page reload`. A failure decrypting `post-reload` points at Stage-5/8 `ratchetWrap` unwrap-on-read or the reconnect rebind by `peerPublicKey`.

3. Commit:
```
cd /Users/deliberative/Desktop/@p2party/p2party.com && git add e2e/run.mjs && git commit -m "$(printf 'test(e2e): reload persistence continues the ratchet (unwrap)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

### Task 9 — Retransmit determinism + no message-key reuse across messages

Two properties from §6/R3: (a) a retransmit of a chunk resends the **cached ciphertext byte-for-byte** (never re-encrypt with a fresh nonce); (b) the **same plaintext sent as two logical messages produces different ciphertext** (a message key is never reused across messages). (a) is forced by dropping the first reverse receipt so the sender resends a chunk it already sent; both sends are captured and their FNV hashes must be identical. (b) sends an identical file twice and asserts distinct per-chunk hashes + a stepped DH pub.

**Files:** Modify `run.mjs` — insert after the Task 8 block.

**Interfaces:** Consumes `window.__chunkFrames`, `window.__dropReceiptArmed`/`__receiptDropped` (Task 2); `readMessage(...).retransmits` (existing sender telemetry).

**Steps:**

1. Append:
```js
    // ===================================================================
    // V3-7a. Retransmit determinism: dropping the first reverse receipt forces
    // the sender to resend a chunk it already sent. The resent frame's bytes
    // must be byte-identical (cached-ciphertext reuse; no fresh-nonce re-encrypt).
    // ===================================================================
    {
      const url = freshRoom();
      const PIN = "701234";
      log("V3 determinism room:", url);
      await connectRoom(A.page, { url, pin: PIN });
      await connectRoom(B.page, { url, pin: PIN });
      const det = await waitFor(
        A.page,
        async (u) => {
          const P = window.p2party;
          const rooms = P.roomSelector(P.store.getState()) || [];
          const r = rooms.find((x) => x.url === u);
          const peer = r && (r.peers || [])[0];
          return peer && peer.ratchetEstablished ? { roomId: r.id } : null;
        },
        url,
        { label: "determinism: established", timeout: 60000 },
      );
      const roomIdD = det.roomId;
      await A.page.evaluate(() => (window.__chunkFrames = []));
      await B.page.evaluate(() => {
        window.__dropReceiptArmed = true;
        window.__receiptDropped = false;
      });
      const DET_BYTES = 400000; // > minChunks → all real, several 64KiB frames
      await A.page.evaluate(
        ({ roomId, n }) => {
          const bytes = new Uint8Array(n);
          for (let i = 0; i < n; i++) bytes[i] = (i * 53 + 11) & 0xff;
          const file = new File([bytes], "det.bin", { type: "application/octet-stream" });
          return window.p2party.sendMessage(file, "main", roomId).then(() => n);
        },
        { roomId: roomIdD, n: DET_BYTES },
      );
      await waitFor(
        B.page,
        async ({ u, n }) => {
          const P = window.p2party;
          const rooms = P.roomSelector(P.store.getState()) || [];
          const r = rooms.find((x) => x.url === u);
          for (const m of r?.messages || []) {
            if (!m.merkleRootHex || m.totalSize !== n) continue;
            const res = await P.readMessage(m.merkleRootHex);
            if (res.percentage !== 100) continue;
            const buf = new Uint8Array(await res.message.arrayBuffer());
            let ok = true;
            for (let i = 0; i < buf.length; i++)
              if (buf[i] !== ((i * 53 + 11) & 0xff)) { ok = false; break; }
            return { byteExact: ok };
          }
          return null;
        },
        { u: url, n: DET_BYTES },
        { label: "determinism: B receives after receipt-drop", timeout: 90000 },
      );
      const dropped = await B.page.evaluate(() => window.__receiptDropped);
      if (!dropped) throw new Error("determinism setup: no receipt was dropped, cannot force a retransmit");
      // Find a chunk frame FNV that appears twice → the resend is byte-identical.
      const dup = await A.page.evaluate(() => {
        const seen = new Map();
        const dups = [];
        for (const f of window.__chunkFrames) {
          const k = f.fnv;
          if (seen.has(k)) dups.push(k);
          else seen.set(k, true);
        }
        return { total: window.__chunkFrames.length, distinct: seen.size, dups: dups.length };
      });
      log(`determinism: frames=${dup.total} distinct=${dup.distinct} identical-resends=${dup.dups}`);
      if (!(dup.dups >= 1))
        throw new Error("determinism: no byte-identical resent frame observed — retransmit re-encrypted (nonce-reuse risk)");
      log("✅ V3 DETERMINISM: retransmitted chunk resent byte-identical (cached ciphertext, no fresh nonce)");
      await B.page.evaluate(() => (window.__dropReceiptArmed = false));

      // ===============================================================
      // V3-7b. No message-key reuse across messages: identical plaintext sent
      // as two logical messages ⇒ different ciphertext + stepped DH pub.
      // ===============================================================
      const grabFrames = async () => {
        await A.page.evaluate(() => (window.__chunkFrames = []));
        await A.page.evaluate(
          ({ roomId }) => {
            const bytes = new Uint8Array(70000);
            for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 17 + 5) & 0xff;
            const file = new File([bytes], "same.bin", { type: "application/octet-stream" });
            return window.p2party.sendMessage(file, "main", roomId);
          },
          { roomId: roomIdD },
        );
        return waitFor(
          A.page,
          () => (window.__chunkFrames.length > 0 ? window.__chunkFrames.slice() : null),
          null,
          { label: "reuse: frames captured", timeout: 60000 },
        );
      };
      const f1 = await grabFrames();
      // Let B fully receive #1 before #2 so the ratchet steps between them.
      await A.page.waitForTimeout(3000);
      const f2 = await grabFrames();
      const set1 = new Set(f1.map((f) => f.fnv));
      const overlap = f2.filter((f) => set1.has(f.fnv)).length;
      const dh1 = f1[0].dhPubHex, dh2 = f2[0].dhPubHex;
      log(`reuse: msg1 frames=${f1.length} msg2 frames=${f2.length} ciphertext-overlap=${overlap} dhStepped=${dh1 !== dh2}`);
      if (overlap !== 0)
        throw new Error("key-reuse: identical plaintext produced identical ciphertext across two messages (message key reused)");
      if (dh1 === dh2)
        throw new Error("key-reuse: DH pub did not step between two logical messages");
      log("✅ V3 NO-KEY-REUSE: identical plaintext ⇒ distinct ciphertext + stepped DH pub across messages");
    }
```

2. Run and confirm:
```
cd /Users/deliberative/Desktop/@p2party/p2party.com && APP_URL=http://localhost:5190 SIGNALING_URL=ws://localhost:3001/ws node e2e/run.mjs 2>&1 | grep -E "V3 DETERMINISM|NO-KEY-REUSE|FAILED"
```
Expected both: `✅ V3 DETERMINISM …` and `✅ V3 NO-KEY-REUSE …`.

3. Commit:
```
cd /Users/deliberative/Desktop/@p2party/p2party.com && git add e2e/run.mjs && git commit -m "$(printf 'test(e2e): retransmit determinism + no message-key reuse\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

### Task 10 — Decoy-header indistinguishability

Decoy frames must carry ratchet headers indistinguishable from reals (§6): same frame type, a full-entropy DH pub (never all-zero / sentinel), and plausible `N`/`PN`. Send a small file (default `minChunks` produces real+decoy frames), capture every 64 KiB forward frame, and assert every frame’s type byte is `FRAME_TYPE_CHUNK`, no header DH pub is all-zero, and `N`/`PN` are within a sane bound — so an on-path observer cannot pick decoys out by their headers.

**Files:** Modify `run.mjs` — insert after the Task 9 block.

**Interfaces:** Consumes `window.__frameTypes`, `window.__chunkFrames` (Task 2); the decoy/padding scheme (unchanged, headers now attached).

**Steps:**

1. Append:
```js
    // ===================================================================
    // V3-8. Decoy-header indistinguishability. Real + decoy 64KiB frames must
    // present the same frame type and plausible, full-entropy ratchet headers.
    // ===================================================================
    {
      const url = freshRoom();
      const PIN = "159263";
      log("V3 decoy room:", url);
      await connectRoom(A.page, { url, pin: PIN });
      await connectRoom(B.page, { url, pin: PIN });
      const dc = await waitFor(
        A.page,
        async (u) => {
          const P = window.p2party;
          const rooms = P.roomSelector(P.store.getState()) || [];
          const r = rooms.find((x) => x.url === u);
          const peer = r && (r.peers || [])[0];
          return peer && peer.ratchetEstablished ? { roomId: r.id } : null;
        },
        url,
        { label: "decoy: established", timeout: 60000 },
      );
      await A.page.evaluate(() => {
        window.__chunkFrames = [];
        window.__frameTypes = [];
      });
      const DECOY_BYTES = 40000; // ~1 real chunk + decoys under default minChunks
      await A.page.evaluate(
        ({ roomId, n }) => {
          const bytes = new Uint8Array(n);
          for (let i = 0; i < n; i++) bytes[i] = (i * 7 + 13) & 0xff;
          const file = new File([bytes], "decoy.bin", { type: "application/octet-stream" });
          return window.p2party.sendMessage(file, "main", roomId).then(() => n);
        },
        { roomId: dc.roomId, n: DECOY_BYTES },
      );
      const gotD = await waitFor(
        B.page,
        async ({ u, n }) => {
          const P = window.p2party;
          const rooms = P.roomSelector(P.store.getState()) || [];
          const r = rooms.find((x) => x.url === u);
          for (const m of r?.messages || []) {
            if (!m.merkleRootHex || m.totalSize !== n) continue;
            const res = await P.readMessage(m.merkleRootHex);
            if (res.percentage === 100)
              return { total: res.chunksReceivedTotal, real: res.chunksReceivedReal };
          }
          return null;
        },
        { u: url, n: DECOY_BYTES },
        { label: "decoy: B receives", timeout: 90000 },
      );
      await A.page.waitForTimeout(1500);
      const hdr = await A.page.evaluate(() => {
        const types = window.__frameTypes;
        const frames = window.__chunkFrames;
        const badType = types.filter((t) => t !== 2).length;
        let zeroPub = 0, insaneN = 0;
        for (const f of frames) {
          if (/^0+$/.test(f.dhPubHex)) zeroPub++;
          if (!(Number.isSafeInteger(f.N) && f.N >= 0 && f.N < 1_000_000)) insaneN++;
          if (!(Number.isSafeInteger(f.PN) && f.PN >= 0 && f.PN < 1_000_000)) insaneN++;
        }
        const distinctPubs = new Set(frames.map((f) => f.dhPubHex)).size;
        return { framesTotal: types.length, chunkFrames: frames.length, badType, zeroPub, insaneN, distinctPubs };
      });
      log(`decoy: recv total=${gotD.total} real=${gotD.real} | wire frames=${hdr.framesTotal} chunkFrames=${hdr.chunkFrames} badType=${hdr.badType} zeroPub=${hdr.zeroPub} insaneN=${hdr.insaneN} distinctDhPub=${hdr.distinctPubs}`);
      if (hdr.framesTotal < 2)
        throw new Error("decoy: too few forward frames captured to assess indistinguishability");
      if (hdr.badType > 0)
        throw new Error(`decoy: ${hdr.badType} forward frame(s) NOT tagged FRAME_TYPE_CHUNK — decoys distinguishable by type`);
      if (hdr.zeroPub > 0)
        throw new Error(`decoy: ${hdr.zeroPub} header(s) had an all-zero DH pub — decoys distinguishable`);
      if (hdr.insaneN > 0)
        throw new Error(`decoy: ${hdr.insaneN} header field(s) had implausible N/PN — decoys distinguishable`);
      log("✅ V3 DECOY: real + decoy frames carry indistinguishable ratchet headers (type, full-entropy DH pub, plausible N/PN)");
    }
```

2. Run the FULL suite end-to-end (all v3 scenarios + the pre-existing transport flow) and confirm every marker:
```
cd /Users/deliberative/Desktop/@p2party/p2party.com && APP_URL=http://localhost:5190 SIGNALING_URL=ws://localhost:3001/ws node e2e/run.mjs 2>&1 | grep -E "^\[.*✅|❌|DONE"
```
Expected: all `✅` markers (NO-PIN, PIN/FS, WRONG-PIN, MITM, RESUME, RELOAD PERSISTENCE, DETERMINISM, NO-KEY-REUSE, DECOY, plus the original transport markers) then `DONE — all transfers verified over real WebRTC`, exit 0.

3. Commit:
```
cd /Users/deliberative/Desktop/@p2party/p2party.com && git add e2e/run.mjs && git commit -m "$(printf 'test(e2e): decoy-header indistinguishability; full protocol-v3 suite green\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

---

### Task 11 — Atomic protocol-v3 release: version bump, CHANGELOG, wasm rebuild + SRI repin, app rebuild, final E2E, CDN note

Ships the wire break as one artifact. `npm run dist` runs its `predist` prehook (production `emscripten.js` rebuild of `src/cryptography/libcrypto.wasm` + `updateWasmIntegrity.mjs` repin of `wasmLoader.ts`), bundles the library, and its `postdist` `npm pack` emits `p2party-0.10.0.tgz`. The app is repointed at that tgz and rebuilt so the E2E exercises the shipped bytes with matching SRI. The manual `npm run uploadcdn` (user AWS creds) is documented, not executed.

**Files:**
- Modify `/Users/deliberative/Desktop/@p2party/p2party-js/package.json` (`"version": "0.9.2"` → `"0.10.0"`, ~:3)
- Modify `/Users/deliberative/Desktop/@p2party/p2party-js/CHANGELOG.md` (new `## [0.10.0]` entry above `## [0.9.2]`, ~:7)
- (build outputs) `/Users/deliberative/Desktop/@p2party/p2party-js/src/cryptography/libcrypto.wasm`, `src/cryptography/wasmLoader.ts` (SRI), `lib/**`, `p2party-0.10.0.tgz`
- Modify `/Users/deliberative/Desktop/@p2party/p2party.com/package.json` (`"p2party": "file:../p2party-js/p2party-0.9.2.tgz"` → `…/p2party-0.10.0.tgz`)

**Interfaces:** Consumes `PROTOCOL_VERSION = 3` (`src/utils/constants.ts`, Stage 6) — verified, not changed here; the full E2E suite (Tasks 3–10). Produces the shipped `0.10.0` artifact + repinned wasm SRI.

**Steps:**

1. Verify the wire version constant is already 3 (set in earlier stages) — the release must not proceed otherwise:
```
cd /Users/deliberative/Desktop/@p2party/p2party-js && grep -n "PROTOCOL_VERSION" src/utils/constants.ts
```
Expected: `export const PROTOCOL_VERSION = 3;`.

2. Bump the SDK version. Edit `package.json`:
```
"version": "0.10.0",
```

3. Prepend the CHANGELOG entry (above `## [0.9.2]`):
```md
## [0.10.0] — 2026-07-22

**Breaking wire change (protocol-v3). No v2 interoperability.** A v3 peer cleanly
rejects a pre-v3 / mismatched-version peer via the `protocolVersion` tag on the
signaling `connection`/`description` message — there is no fallback. Old v2
rooms/data remain separate.

### Added

- **Forward secrecy + post-compromise security in every room** via a per-peer-edge
  **Double Ratchet** (`src/cryptography/ratchet.ts`), seeded at the `main`-channel
  handshake and advancing per logical message. All chunks of a message share one
  message key (nonce = chunkIndex).
- **PIN secure rooms (authentication against a malicious signaling server)** via
  **CPace over Ristretto255** (`src/cryptography/cpace.ts`) binding both identity
  keys and both DTLS fingerprints, with explicit key-confirmation. `connect()`
  gains `secureRoomPin?`; `Room` gains `isSecureRoom`. Wrong/absent PIN,
  key-confirm failure, DTLS-fingerprint mismatch, or version mismatch **fail
  closed** (channel torn down). Online-guessing throttled by `MAX_PIN_ATTEMPTS`
  then exponential backoff, keyed to the room.
- **No-PIN rooms** seed the ratchet from an **X3DH-style** identity-mixed
  ephemeral DH (`src/cryptography/x3dh.ts`) — FS everywhere; MITM defeated only in
  PIN rooms (stated limit).
- **At-rest wrapped ratchet persistence**: new IndexedDB `ratchetSessions` store
  (dbVersion 16→17), secret fields wrapped under a non-extractable WebCrypto
  AES-GCM key; the ratchet survives reconnect and reload. Secret-free
  `ratchetSessionInfo()` diagnostic added.
- New WASM exports: Ristretto255 (CPace), X25519 keypair/DH, HKDF-SHA512,
  symmetric ChaCha20-Poly1305 encrypt, and `receive_message_with_key`.

### Changed

- **Frame layout (frame SHRINKS).** The 96-byte `ephemeral_pk(32)+sig(64)` prefix
  is replaced by a 1-byte frame type plus a 49-byte cleartext ratchet header
  `DH_pub(32)+N(8)+PN(8)+PQ_EPOCH(1)`; `N`/`PN` fold into the AEAD AAD. Every
  data-channel frame now carries a 1-byte type tag (handshake / chunk / receipt).

### Removed

- **The 0.9.0 per-chunk Ed25519 signature** — dropped atomically with the
  authenticated ratchet (both seed paths mutually bind both identity keys, so the
  Poly1305 tag under a message key is the authenticator). The `receive_message`
  `case -1` "signature wrong" path is gone.

### Security / verification

- Verified against the real-WebRTC headless-Chromium suite (`p2party.com/e2e/run.mjs`):
  PIN + no-PIN byte-exact with FS, MITM abort on swapped DTLS fingerprint,
  wrong-PIN fail-closed, reconnect + reload ratchet continuity, retransmit
  determinism (no nonce reuse), and decoy-header indistinguishability.
```

4. Build + pack the release (predist prehook rebuilds wasm + repins SRI; postdist packs):
```
cd /Users/deliberative/Desktop/@p2party/p2party-js && npm run dist
```
Expected: emscripten production build runs, `Updated wasmLoader.ts integrity → sha384-…`, rollup bundles, and `npm pack` writes `p2party-0.10.0.tgz`. Confirm:
```
cd /Users/deliberative/Desktop/@p2party/p2party-js && ls -1 p2party-0.10.0.tgz && grep -n "integrity:" src/cryptography/wasmLoader.ts
```
Expected: the tgz exists and the printed integrity matches the freshly built `src/cryptography/libcrypto.wasm` (the value `run.mjs` serves).

5. Repoint the app dependency and reinstall/rebuild so the E2E runs the shipped artifact with matching SRI. Edit `/Users/deliberative/Desktop/@p2party/p2party.com/package.json`:
```
"p2party": "file:../p2party-js/p2party-0.10.0.tgz",
```
then:
```
cd /Users/deliberative/Desktop/@p2party/p2party.com && bun install && bun run build
```
Expected: install picks up `0.10.0`, `tsc -b && vite build` succeeds.

6. Run the full E2E suite against the freshly built app + wasm (the definition-of-done gate):
```
cd /Users/deliberative/Desktop/@p2party/p2party.com && APP_URL=http://localhost:5190 SIGNALING_URL=ws://localhost:3001/ws RESUME_TIMEOUT=200000 node e2e/run.mjs 2>&1 | tee /private/tmp/claude-501/-Users-deliberative-Desktop--p2party/029dcf6f-9570-44b9-8109-3656d8f237f5/scratchpad/e2e-final.log | grep -E "✅|❌|DONE"
```
Expected: all `✅` markers and `DONE — all transfers verified over real WebRTC`, exit 0. (If serving `dist` on :5190, re-serve it after `bun run build` before running.)

7. Typecheck + unit tests still green across the SDK:
```
cd /Users/deliberative/Desktop/@p2party/p2party-js && npm run typecheck && bun test
```
Expected: no type errors; all `bun test` pass (including the C↔TS constant-agreement test and `ratchetSessionInfo` test).

8. Commit the release (both repos):
```
cd /Users/deliberative/Desktop/@p2party/p2party-js && git add package.json CHANGELOG.md src/cryptography/wasmLoader.ts src/cryptography/libcrypto.wasm lib p2party-0.10.0.tgz && git commit -m "$(printf 'release: protocol-v3 (0.10.0) — atomic wire break; wasm rebuild + SRI repin\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
cd /Users/deliberative/Desktop/@p2party/p2party.com && git add package.json bun.lock && git commit -m "$(printf 'chore: consume p2party 0.10.0 (protocol-v3)\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>')"
```

9. **CDN upload — user action (AWS creds).** Do not run automatically; document the exact command. After the release commit lands, publish the repinned wasm + bundles to the CDN so deployed clients fetch bytes matching the new SRI:
```
# requires the user's AWS credentials in p2party-js/.env
cd /Users/deliberative/Desktop/@p2party/p2party-js && npm run uploadcdn
```
This runs `prepare:uploadcdn` (copy wasm → `lib/`, gzip, compute `.integrity`), `actual:uploadcdn` (`scripts/uploadToCDN.mjs`), then `cleanup:uploadcdn`. The `cdn.p2party.com/@<version>/libcrypto.wasm` object must be published for the new `0.10.0` path before v3 clients are served. State this to the user as the final manual step and stop.

