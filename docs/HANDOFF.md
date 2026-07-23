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

## NEXT — Stage 5 (the big remaining chunk: message crypto onto the ratchet + box removal)
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
