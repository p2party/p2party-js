# protocol-v3 — HANDOFF (2026-07-23)

Living handoff so any agent (Claude or Codex) can take over. Branch:
**`feat/pace-ratchet-protocol-v3`**. Full suite **97/0**, `npm run typecheck` clean.
Test runner: `bun test`. Package `p2party@0.9.2` (v3 release target **0.10.0**).

## GIT SAFETY (read first)
- There are **2 pre-existing user stashes** on `master` — `stash@{0}` (WIP "Disconnect
  from all rooms…") and `stash@{1}` (WIP "Persisting messages and identity"). **NEVER**
  `git stash`/`reset`/`checkout <branch>`/`clean`/`rebase`. Only `git add <files>` +
  `git commit` on this branch. Confirm with `git stash list` that both survive.
- Stay INSIDE the `@p2party` repos (this repo, plus the frontend + server siblings).

## Definition of done (in force)
Verify like a real user in **headless Chromium against the local stack** (Playwright),
then commit + **merge to master**. SSOT for constants in `src/utils/constants.ts`,
byte-matched in `src/cryptography/utils.h`. KISS/DRY, TDD. WASM deploy = the USER runs
`npm run predist && npm run uploadcdn` (needs their AWS creds — an agent cannot).

## DONE
- **Stages 1–3**: WASM crypto (Ristretto255/X25519/HKDF/AEAD on a fixed 2 MB heap),
  pure TS crypto units (cpace/x3dh/ratchet/hkdf), IndexedDB `ratchetSessions` + `meta`
  stores with a non-extractable-WebCrypto at-rest wrap (`db/ratchetWrap.ts`
  getWrapKey/wrapSecret/unwrapSecret).
- **Stage 4 (handshake orchestration) — COMPLETE**: T1 1-byte frame-type classifier
  (SSOT C↔TS), T2 per-peer `ratchetEstablished` promise gate, T3 DTLS-fingerprint
  MITM binding (`buildChannelInput` CI + `verifyDtlsFingerprints`, **fail-closed**),
  T4 handshake core (`performHandshakeCore`+`runHandshake`), T5 wired into
  `handleOpenChannel` main `onopen` + handshake frame routing (`42af319`).
- **D2=B (dedicated X25519 identity + key separation) — COMPLETE, reviewed APPROVED**:
  - Random X25519 identity, **WebCrypto-wrapped in IndexedDB** (`meta` store key
    `"identityX25519"`, reuses Stage-3 wrap) — NOT plaintext localStorage. api:
    `db/api.ts` get/set/deleteIdentityX25519; worker: `db/db.worker.ts` fn*.
  - **Domain-separated cross-signature** `IDENTITY_CROSS_SIGN_DOMAIN_BYTES =
    "p2party-x25519-idsig-v1"` (`src/cryptography/identityCrossSig.ts`) — closes
    **SECURITY-1**: a bare `sign(x25519pub, ed25519sec)` collides with the
    login-challenge signing oracle (`handleChallenge` signs a raw 32B server nonce),
    letting a malicious server forge a cross-sig. Regression-tested.
  - **D1 initiator-first CPace sid** (was a deliberate empty `sid`; now the responder
    recvs the initiator's HELLO first and derives `G` with the initiator's `sid`).
  - **T5 in-band, not the server**: X25519 pub + cross-sig ride the HELLO frame
    (97→193 B), verified before any DH, fail-closed. Signaling server unchanged.
  - **T6**: `runHandshake` unwraps the wrapped identity; wipes `idSelfSec`/`secret` in
    a `finally`. Fixed a latent **double-wrap** persistence bug.
  - Commits: `41de52e` T1, `38c2f24` T2, `fc01737` T3, `59b011a` T4, `d35045c`
    D1+T5+T6, `40d97b0` wipe. Spec: `docs/superpowers/specs/2026-07-22-d2b-x25519-key-separation-design.md`.
- **Paper/blog source** updated: `docs/protocol-v3-implementation-log.md` (Stage 4 +
  D2=B chapters, `9387085`), `docs/paper-prior-art-and-related-work.md`,
  `docs/protocol-evolution-decision-log.md`.

## Stage 4 Task 5 — review APPROVED (Stage 4 COMPLETE)
- The Task 5 review confirmed the make-or-break check: the CI IS built **role-aware**
  (`fpInitiator = amInitiator ? localFp : remoteFp`; `ik` likewise) so both peers
  produce a byte-identical CI; fingerprints are raw bytes (SDP case-immune); onmessage
  strips exactly 1 byte with sound length-disjoint ordering; handshake failure is
  fail-safe + single-invoke; message crypto untouched.
- 2 Minor deferred follow-ups (non-blocking, fold into the Stage-5 tagging pass):
  (a) on a reconnect, `setHandshakeChannel` orphans an in-flight `runHandshake`'s inbox
  (the old `recv()` promise hangs forever — benign leak); (b) build the CI BEFORE
  `setHandshakeChannel` so a degenerate-SDP throw can't leave a registered-but-idle inbox.
- ⚠️ getStats fingerprint timing at very-early onopen + live-cert CI equality are only
  verifiable in the Stage-7 headless-Chromium E2E (fail-safe either way).

## Stage 5 STATUS (2026-07-23)
- ✅ T1 `a9712e0` (frame codec+constants), ✅ T2 `90a7191` (C reads cleartext nonce), ✅ T3-core `293ce4c`+`2776f1a` (messageChunkCrypto, per-message cache + clone-rollback, **libsodium** decrypt), ✅ **T3-wiring `39ce532` — DONE but UNVERIFIED (E2E pending)**: live send/receive swapped onto the ratchet, `MESSAGE_START` 96→62 decoupled from `DECRYPTED_LEN` (zero Merkle/OPFS ripple), box left dead, 103/0, typecheck clean.
- **Top E2E risks to check (report: `.superpowers/sdd/task-s5t3-wiring-report.md`):** (1) responder-sends-first — `ratchetEncrypt` throws "no sending chain" until the responder receives once (graceful no-op now); (2) reconcile re-seals under the cached key with a fresh nonce (not "resend identical"); (3) WS relay drops v3 chunks (ratchet is per-data-channel-edge) → relay fallback disabled for v3.
- ✅ **T4-partial `98d6daa`** — removed box TS wrapper (`chacha20poly1305.ts`) + deprecated `p2party.encrypt`/`.decrypt` public API. typecheck clean, 103/0. Safe unit-verifiable slice; did NOT rebuild WASM.
- **REMAINING (T4 rest — do in the E2E-equipped session; each needs `predist` + a real transfer to verify, so held back deliberately):**
  1. C-source deletion: `chacha20poly1305.c/.h`, the `libcrypto.c` include, `utils.c::receive_message`.
  2. WASM export strip in `scripts/emscripten.js` + `scripts/libcrypto.d.ts`: `_encrypt/_decrypt_chachapoly_asymmetric`, `_receive_message`, **and now-also-dead `_receive_message_with_key`** (see divergence) → then `npm run predist` to rebuild + repin SRI.
  3. `memory.ts` `encrypt/decryptAsymmetricMemory` removal **+ REPOINT the LIVE send-path sizer** — `api/webrtc/index.ts:41 encryptionWasmMemory` is threaded via `sendMessageQuery.ts` and still sizes the send heap off the box layout; a wrong size OOMs/underallocates and the unit suite won't catch it (spec §6.3 risk R-include).
  4. `allocators.ts::allocateSendMessage` shrink (drop the per-chunk ephemeral-Ed25519 buffers).
  5. Ed25519-secret → WebCrypto wrap (mirror the Stage-3 X25519 store; broad — touches login/challenge signing).
- **Receive cut over to the single C call `_receive_message_with_key` (`0552ce3`) — DONE, and browser-verified.** `decryptMessageChunk` now derives the per-message key off the ratchet (clone-rollback, the only TS state) and does the ENTIRE receive crypto — decrypt + leaf-hash + Merkle + receipt — in ONE libsodium call, in place (DRY/KISS/SSOT per user). Returns `{decrypted, ok, stateAdvanced}`; rollback gated on C code `-2` (AEAD fail → rollback) vs `-3/-6` (Merkle fail → commit ratchet, drop). Removed dead `aeadOpen` + `encryptMessageChunks`. Tests rewritten to real valid-Merkle frames. (Interim `58c08fb` moved the leaf hash to C; superseded by this.) Send-side leaf hashing (`splitToChunks`, `getMerkleProof`) still WebCrypto — identical SHA-512, proofs verify.
- **Browser crypto E2E PASSED (headless Chromium, no WebRTC) — 11/11 checks.** Bundled the real crypto path (ratchetEncrypt+sealChunk encrypt, decryptMessageChunk decrypt) + fetched `libcrypto.wasm`, drove via playwright (`chromium.launch`, cache at `~/Library/Caches/ms-playwright`; the Playwright MCP wants the missing Chrome channel — self-drive instead). Verified byte-exact round-trip, C receipt leaf, ratchet step/cache, tamper-rejection. De-risks the cutover; the full WebRTC/OPFS/signaling E2E is still the remaining gate.
- **DX (user ask):** `generateKeyPair` now aliases `newKeyPair` (`d744f6b`, industry-standard). `verify(message, signature, publicKey)` arg order differs from the common `(sig, msg, pk)` — noted, not changed.
- **Standalone session API — DECIDED direction (needs a design pass before build):** user chose a designed `p2party.createSession({identitySecretKey, peerPublicKey, initiator}) → .encrypt(bytes):Uint8Array[] / .decrypt(frame) / .serialize()/restoreSession()`. NOT a thin wrap — two protocol blockers found: (1) `initRatchet` uses a RANDOM ratchet keypair (not seed-derived, `ratchet.ts`), so the initiator needs the responder's ratchet pub via an EXCHANGE → createSession needs a mini-handshake (X3DH from the X25519 identity keys = the protocol-v3 handshake minus transport) to derive the shared root + swap ratchet pubs; (2) `merkleRoot` is AAD, NOT in the frame (threaded in from `handleMessageQueueing`), so the session must convey the root itself (embed a per-message header frame, or return `{root, frames}`). Security-sensitive → brainstorm/spec first, verify against the browser harness AND ideally the full E2E. Browser crypto harness (scratchpad: bundle.js/index.html/libcrypto.wasm + `chromium.launch` self-drive) is reusable to validate it.
- **Deferred Ed25519→WebCrypto wrap: the AES-GCM wrap key is NON-EXTRACTABLE** (per user) — use `crypto.subtle.wrapKey`/`unwrapKey` (or encrypt/decrypt), never `exportKey`, mirroring the Stage-3 X25519 store.
- **T5** = headless-Chromium E2E vs local stack (frontend installs `file:../p2party-js/p2party-0.9.2.tgz`, a packed tarball — must rebuild+repack+reinstall the v3 branch first; `p2party.com/e2e/run.mjs` is the harness; Postgres already runs on :5432, DO NOT disturb — server may use SQLite) = the gate that makes T3-wiring + T4 trustworthy → merge to master.

## Stage 5 reference (message crypto onto the ratchet + box removal)
**READ FIRST: `docs/stage5-message-crypto-swap-design.md`** — the precise swap design,
incl. the **per-message-ratchet + messageKey-cache subtlety** (the #1 bug to avoid:
`ratchetDecrypt` is per-message, not per-chunk — call it once + cache the key), the
clone-rollback-dedup contract, the 62-byte frame layout, and a landable-green task
decomposition. Plan (older, amend per Q4): `docs/superpowers/plans/2026-07-22-pace-ratchet-protocol-v3.md`;
box-removal surface: D2=B spec **§6**.
1. **Swap message crypto to the ratchet AEAD** (the ratchet is seeded by the handshake
   but NOT yet used for messages):
   - `handleSendMessage.ts:256` `_encrypt_chachapoly_asymmetric` → `_encrypt_chachapoly_symmetric`
     keyed by the ratchet message key; drop the per-chunk ephemeral keypair
     (`_keypair_from_seed`) + the per-chunk `_sign`.
   - `handleReceiveMessage.ts:31` `_receive_message` → `_receive_message_with_key`
     (messageKey from the ratchet session).
   - **ratchetDecrypt is STATEFUL** — honor the clone+rollback+dedup caller contract
     (plan Global Constraints): run on a serialize/deserialize clone, commit state only
     after AEAD authenticates, dedup already-seen `(dhPub, N)`.
   - Gate sends on the per-peer `getRatchetGate(peerId)` (Stage 4 T2).
   - **Frame-layout fork to resolve (decision log F-4):** Global Constraints say
     `MESSAGE_START=62` with a random 12-byte cleartext nonce (`RATCHET_NONCE_LEN`), but
     the Stage-5 body still says 50/49 — reconcile to the 62/random-nonce design; the
     C-side `receive_message_with_key` must read the cleartext 12-byte nonce (currently a
     placeholder). Add a send↔receive round-trip KAT.
2. **Box scheme FULL REMOVAL (T8/T9, spec §6):** delete `chacha20poly1305.{c,h,ts}`,
   the wasm exports (`_encrypt/_decrypt_chachapoly_asymmetric` + the `_receive_message`
   cascade), `encryptAsymmetric`/`decryptAsymmetric` public API in `index.ts`, the
   `memory.ts` helpers, the `handleSendMessage`/`handleReceiveMessage` call sites, and —
   the headline — the `crypto_sign_ed25519_sk/pk_to_curve25519` usage (this is the LAST
   Ed25519→X25519 reuse; its removal completes D2=B's migration). Rebuild wasm via
   `npm run prebuild` (dev) / `predist` (prod) so the SRI in `wasmLoader.ts` re-pins.
   - **Also migrate the Ed25519 identity secret to the WebCrypto wrap HERE** (deferred
     from D2=B because the box scheme still read it plaintext; once removed, wrap it too).
3. **GOTCHA — amend the stale plan (Q4):** the plan (Stage 5 Task 2 step 7 ~line 4708 +
   exit criteria ~line 5367) says to KEEP `_receive_message`/`_decrypt_chachapoly_asymmetric`
   compiled — this **contradicts** D2=B full removal. Amend it before executing Stage 5.
   Also update the decision log's D2 "deprecated-in-place/seed-derived" wording (superseded).
4. **Frame-routing cleanup:** `handleOpenChannel` onmessage currently length-classifies
   box frames first, then `classifyFrame` for handshake (works because handshake framed
   lengths 98/194 are disjoint from 64/MESSAGE_LEN). Once Stage 5 tags EVERY frame with a
   FRAME_TYPE byte, fold into clean leading-byte-first classification.

## THEN
- **Stage 6**: protocol version tag + PIN plumbing (`MAX_PIN_ATTEMPTS`=3 + per-room
  exponential backoff) + failure states. Handshake currently hardcodes `mode="nopin"` in
  `handleOpenChannel` — Stage 6 selects pin/nopin per room + threads the PIN.
- **Stage 7**: real-WebRTC headless-Chromium E2E vs the local stack; SRI repin; bump
  `package.json` 0.9.2 → 0.10.0 (+ `wasmLoader.ts` `wasmVersion`). **This is the
  definition of done** — then merge to master.

## RESEARCH / PAPER threads (deferred, not blocking the code)
- Prior-art pass done (`docs/paper-prior-art-and-related-work.md`): **C3** (a uniform
  cover-chunk transport makes a PQ ratchet's KEM ciphertext free + hideable in decoy
  slots) is the ONLY novel claim; C1/C2/C4/C5 are prior-art-contested (frame as
  applied/systems). Sharpest open objection: **Kemeleon (RWC 2025)** — raw ML-KEM ct is
  NOT byte-uniform, so a raw ct in a decoy slot is fingerprintable → need
  Elligator/Kemeleon obfuscation. SPQR chunk size is **32 B** (not the widely-quoted 42).
- User wants **ONE combined SOTA-edge contribution**, not two forced novelties. Second
  angle = offensive crypto at the RENDEZVOUS layer, but **NOT decoy-flooding the server**
  (kills self-hosting economics) — use ELEGANT server-cheap unlinkability: OPRF-blinded
  rendezvous tokens + the PACE PAKE + epoch rotation.
- **Server-blind link** (deferred roadmap Phase-1): L1 (opaque-token rendezvous + in-band
  auth) is easy client-side engineering (rides on the built CPace — a high-entropy URL
  fragment is just a strong PAKE password); L2 (true unlinkability) is research-grade and
  the real bottleneck is the persistent server-visible Ed25519 identity + source IP, not
  the rendezvous tag. User wants L2 eventually, starting L1.
- Deferred capstone: awesome READMEs (p2party-js, p2party.com, server), the blog series,
  a LaTeX paper.

## Methodology + where the record lives
- Subagent-driven: one implementer per task + a focused adversarial review for
  security-critical crypto. The review keeps catching REAL bugs before ship (gate
  unhandled-rejection, DTLS fail-open, the SECURITY-1 cross-sig oracle in the SPEC, the
  double-wrap). Keep that gate for Stage 5's crypto swap.
- Durable ledger (gitignored, on disk): `.superpowers/sdd/progress.md`. Per-task
  reports/reviews: `.superpowers/sdd/*.md`. Specs: `docs/superpowers/specs/`. Plan:
  `docs/superpowers/plans/`. Decision arc: `docs/protocol-evolution-decision-log.md`.
