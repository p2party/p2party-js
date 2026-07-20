# Crypto hardening — Tier 1 (pure TypeScript) design

Date: 2026-07-20
Repo: `p2party-js`
Status: approved scope, pre-implementation

## Context

A deep review of the p2party crypto pipeline surfaced a set of defects. They split
into two classes by blast radius:

- **Tier 1 (this spec):** pure-TypeScript fixes that do **not** change the wire
  format, do **not** require a WASM rebuild, and are exercised by the app against
  the *existing* CDN-hosted `libcrypto.wasm`. Fully verifiable end-to-end on a local
  stack with headless Chromium. No interop break.
- **Tier 2 (separate `protocol-v2` spec, deferred):** C/WASM changes that break wire
  compatibility and require rebuilding + redeploying `libcrypto.wasm` to
  `cdn.p2party.com` with an SRI bump — Merkle leaf/node domain separation, signature
  domain separation + transcript binding, and the `chacha20poly1305.c:156` NULL-check.
  Also deferred: forward secrecy (a Noise/X3DH redesign, not a bug fix), replay
  protection, and metadata-leak closes (plaintext Merkle-root channel labels, read
  receipts, silent WS-relay fallback).

The WASM is loaded via `src/cryptography/wasmLoader.ts`, which `fetch()`es from
`https://cdn.p2party.com/@<version>/libcrypto.wasm` with a hardcoded `sha384` SRI.
This is why Tier 2 cannot reach the running app without a CDN redeploy, and why Tier 1
is cleanly separable.

## Tier 1 fixes

### 1. `randomNumberInRange` — 32-bit overflow + control-flow bugs (HEADLINE)

`src/cryptography/utils.ts:5-42`.

- `randomInteger <<= 8` (line 26) is a signed 32-bit op; for `BYTES_NEEDED > 4` the
  high bytes are discarded and the value can go negative.
- `if (min === max) resolve(min)` (line 11) does not `return`; execution continues
  with `RANGE = 0` → `Math.log2(0) = -Infinity`.
- The promise resolves both inside the loop (line 33) and after it (line 37).

Impact: called at `src/utils/splitToChunks.ts:167` for decoy `chunkEndIndex` over the
range `[chunkEnd + totalSize + 1, Number.MAX_SAFE_INTEGER - start]` (~2^53). The wrap
makes `r` small/negative, so `chunkEndIndex += r` can land in `[0, totalSize]`. A small
text message with default `minChunks = 3` forces ≥2 decoys; each has a high chance of a
bad value, so **sends fail ~75% of the time** (negative `chunkEndIndex` throws in
`serializeMetadata`'s `setBigUint64`), or worse, a decoy is silently accepted as real
data and corrupts reassembly.

Fix: reimplement with unbiased rejection sampling that is correct for 53-bit ranges
(`BigInt` accumulation, or `crypto.getRandomValues(BigUint64Array)` masked to the
range's bit length with rejection). Add the missing `return` and remove the
double-resolve. Once correct, the decoy range's lower bound `chunkEnd + totalSize + 1`
*structurally* guarantees `chunkEndIndex - chunkStartIndex > totalSize`, so the
"decoy accepted as real" path closes without touching the sentinel scheme (that
authenticated-flag-byte replacement is Tier 2).

Keep `min === max` returning `min`; keep the public signature `(min, max) => Promise<number>`.

### 2. WASM heap leak of secret-sized buffers on the send path

`src/utils/allocators.ts:36,59` allocate `ptr4` (`crypto_sign_ed25519_SECRETKEYBYTES`)
and `ptr8` (`crypto_hash_sha512_BYTES`) and return them (lines 81, 85) to
`src/handlers/handleSendMessage.ts` (destructured at line 100). Verify against the
per-iteration `ptr4`/`ptr8` allocated at `handleSendMessage.ts:410,418` and freed at
`490-491`: confirm whether the `allocateSendMessage`-returned pair is ever freed. If
not, each send leaks 128 bytes into the fixed, non-growable encryption heap → `_malloc`
eventually fails and sending stops until reload.

Fix: free the leaked pointers (and any siblings from `allocateSendMessage` not paired
with a `_free`) after use; prefer a single teardown that frees exactly what
`allocateSendMessage` returned. Confirm no double-free with the line-410/418 locals
(rename locals if shadowing is present).

### 3. Zeroize secret-key WASM buffers before `_free`

Secret material copied into WASM `_malloc` buffers is freed without wiping, leaving it
in the reusable ArrayBuffer: identity secret key and ephemeral seeds in
`handleSendMessage.ts`, receive-path secret in `handleOpenChannel.ts` (`_free(ptr4)` at
line 146 / set at 280-285), and ephemeral seed/secret in `ed25519.ts`.

Fix: `heapView.fill(0)` over each secret buffer's byte range before `_free`, matching
the `sodium_free` discipline already used C-side. A small helper
`zeroFree(module, ptr, len)` keeps call sites consistent.

### 4. Bounds-validate received chunk offsets before slicing

`src/handlers/handleReceiveMessage.ts:42-45` slices
`chunk.slice(metadata.chunkStartIndex, metadata.chunkEndIndex)` with sender-controlled
`u64`s, sanity-checked only against `totalSize`/`MESSAGE_LEN` (lines 52-57), never
against the actual chunk region. JS `slice` is memory-safe, but out-of-range values
silently truncate/misread.

Fix: reject (treat as an invalid chunk, same shape as the `chunkSize === 0` early
return) unless `0 <= chunkStartIndex <= chunkEndIndex <= chunk.length`. Compute this
before the `realChunk` slice.

### 5. Hygiene (no behavior change)

- Fix swapped size comments in `src/cryptography/chacha20poly1305.ts` (~lines 68, 249):
  actual box layout is `nonce(12) || ciphertext || tag(16)`, and the encrypt path uses
  `crypto_kx_server_session_keys` (comment names the client variant).
- Remove the dead `random_bytes.c` path in `scripts/paths.js` and the dead
  declarations in `ed25519.h` / `libcrypto.d.ts` that point at nonexistent symbols, so
  a from-source rebuild does not reference a missing file.

## Out of scope (Tier 2 / later sub-projects)

Merkle domain separation; signature domain separation + transcript binding;
`chacha20poly1305.c:156` NULL-check; forward secrecy (AKE redesign); replay protection;
metadata-leak closes; the authenticated decoy flag byte; PAKE short-URL rooms;
decentralized pkarr/DHT rendezvous; swarming/resumable/async transfer.

## Testing & verification

Definition of done (per user): verified end-to-end against the locally running stack
with headless Chromium like a normal user, then committed and merged to `master`.

- **Unit (`bun test`, added as a devDep-free runner):**
  - `randomNumberInRange`: red test first — assert current impl returns
    out-of-range/negative for a ~2^53 range; then green. Add uniformity smoke
    (chi-square-ish bucket check) for small ranges, `min === max` returns `min`,
    single-resolution.
  - decoy generation via `splitToChunks`: assert every decoy chunk satisfies
    `chunkEndIndex - chunkStartIndex > totalSize` and `chunkEndIndex >= chunkStartIndex`.
  - `handleReceiveMessage` bounds: out-of-range offsets are rejected, not sliced.
  - Leak/zeroization: a fake `LibCrypto` module recording `_malloc`/`_free`/writes
    asserts allocation balance and that secret ranges are zeroed before free.
- **E2E (Playwright + installed Chromium 131, added):** build `p2party-js` → pack →
  local `p2party.com` consuming the tarball → local signaling server. Two browser
  contexts join one room; send a small text and a small file; assert the receiver
  reassembles both (the send-reliability fix is the core assertion — pre-fix this
  fails intermittently). Prefer the simpler SQLite `p2party-server` for the signaling
  leg unless Postgres is trivially available.

## Risks / notes

- `bun test` and Playwright are new to this repo (no existing test suite). Adding them
  is part of the work.
- The E2E leg requires a local signaling server + a local `p2party.com` build wired to
  the freshly packed tarball; budget setup time.
- Fixes are on branch `crypto-hardening-tier1`; `master` is untouched until E2E passes.
