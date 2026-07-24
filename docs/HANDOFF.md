# protocol-v3 — HANDOFF (2026-07-23)

Living handoff so any agent (Claude or Codex) can take over. Branch:
**`feat/pace-ratchet-protocol-v3`**. The **97/0** suite and clean typecheck below are
historical Stage-4 checkpoints; see the dated checkpoints near the end for current
results and remaining gates. Test runner: `bun test`. Current v3 package/release
candidate: **`p2party@0.12.0`**.

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

- **Stages 1–3 (historical checkpoint)**: WASM crypto
  (Ristretto255/X25519/HKDF/AEAD; those small callers then used a 2-MiB cap),
  pure TS crypto units (cpace/x3dh/ratchet/hkdf), IndexedDB `ratchetSessions` + `meta`
  stores with a non-extractable-WebCrypto at-rest wrap (`db/ratchetWrap.ts`
  getWrapKey/wrapSecret/unwrapSecret). Current memory ownership is operation-scoped:
  the build permits growth, callers set explicit maxima, and larger Merkle/Argon2
  operations are not limited to 2 MiB.
- **Stage 4 (handshake orchestration) — COMPLETE**: T1 1-byte frame-type classifier
  (SSOT C↔TS), T2 the original `ratchetEstablished` promise gate, T3 DTLS-fingerprint
  MITM binding (`buildChannelInput` CI + `verifyDtlsFingerprints`, **fail-closed**),
  T4 handshake core (`performHandshakeCore`+`runHandshake`), T5 wired into
  `handleOpenChannel` main `onopen` + handshake frame routing (`42af319`). Current gates
  are leased and keyed by `(roomId, peerId)`; the handshake inbox uses a separate lease.
- **D2=B (dedicated X25519 identity + key separation) — COMPLETE, reviewed APPROVED**:
  - Random X25519 identity, **WebCrypto-wrapped in IndexedDB** (`meta` store key
    `"identityX25519"`, reuses Stage-3 wrap) — NOT plaintext localStorage. api:
    `db/api.ts` get/set/deleteIdentityX25519; worker: `db/db.worker.ts` fn*.
  - **Domain-separated cross-signature:** `IDENTITY_CROSS_SIGN_DOMAIN_BYTES` is
    `"p2party-x25519-idsig-v1"` (`src/cryptography/identityCrossSig.ts`). This closes
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

## SESSION 2026-07-23 (late) — standalone use, browser E2E, Redux coupling

- **BROWSER E2E PASSED (headless Chromium, no WebRTC):** message crypto 11/11, AND the **FULL standalone protocol 5/5** — real `performHandshakeCore` over in-memory transports + bidirectional byte-exact messaging + tampered-cross-sig rejection. Self-driven via playwright `chromium.launch` (Playwright MCP wanted the missing Chrome channel). Crypto is now browser-proven.
- **`examples/standalone-e2ee.ts` (NEW, verified `bun run` with no browser-global shim)** — E2EE-library-style demo (`const alice`/`const bob`, real handshake over two in-memory links = simulated channels, encrypt/decrypt both ways). The reference for using the machinery without WebRTC, and the exact flow `createSession()` should wrap.
- **KEY PARAM FACT:** `performHandshakeCore`'s `idSelfSec` = the **X25519 identity SECRET** (interactive 3DH), NOT Ed25519; the Ed25519 key only cross-signs the X25519 pub + is the pinned anchor (`peerIdentityEd25519Pub`). Copy `handleHandshake.test.ts:215-263`.
- **PRE-SPLIT REDUX/db COUPLING finding:** `handleHandshake.ts` imported `../store` + `../db/api`, and `runHandshake` read `store.getState().keyPair` + persisted via db, so importing `performHandshakeCore` dragged in Redux + a db Worker + localStorage. The core functions themselves used neither dependency, making a module split the enabling refactor for a clean standalone `createSession()` + smaller consumer bundles.
- **REDUX/db DECOUPLING COMPLETE:** `handshakeCore.ts` now owns `performHandshakeCore` / `buildChannelInput` / `HandshakeTransport` and imports only crypto + byte utilities. `handleHandshake.ts` retains Redux, DB persistence, DTLS/WebRTC transport, and ratchet gates. `messageChunkCrypto.ts` and `ratchet.ts` are confirmed store-free. The standalone example no longer needs `_env.ts`; the remaining crypto random calls it exercises use `globalThis.crypto`.

## Historical Stage 5 STATUS (2026-07-23; superseded by the 0.12 checkpoint)

This section preserves the state that the next session was originally asked to
read. It is not a current task list: the store-free session API, T4 removal, and
packaged frontend integration described as pending here have since landed. The
fresh exact-0.12 full-WebRTC T5 run is still pending.

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
- **T5** = headless-Chromium E2E vs local stack using the exact installed release
  artifact (`p2party.com/e2e/run.mjs` is the historical harness; Postgres already
  runs on :5432, DO NOT disturb). The frontend now installs the verified local
  `p2party-0.12.0.tgz`; a fresh exact-0.12 full-WebRTC run remains the merge gate.

## Historical Stage 5 reference (superseded; do not use as current instructions)

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
   - The old note said `getRatchetGate(peerId)`; current ownership is a leased
     `(roomId, peerId)` gate, separate from stable-identity persistence ownership.
   - **Frame-layout fork (resolved; decision log F-4):** Global Constraints say
     `MESSAGE_START=62` with a random 12-byte cleartext nonce (`RATCHET_NONCE_LEN`), but
     the Stage-5 body said 50/49. Current v3 uses the 62-byte/random-nonce design.
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
   **Current correction:** the box surface is gone and the decision log now labels the
   old “deprecated-in-place/seed-derived” wording as superseded.
4. **Frame-routing cleanup (current correction):** the box classifier is gone. Current
   routing accepts only exact 65-byte `FRAME_TYPE_RECEIPT(1) ‖ token(64)` receipts,
   v3 chunks by exact 65,490-byte length plus `FRAME_TYPE_CHUNK`, and handshake frames
   on `main` through `classifyFrame`. Raw untagged 64-byte receipts are rejected.

## THEN (historical plan; superseded where noted)

- **Stage 6 is no longer accurately described by the old hardcoded-`nopin` note.**
  Current room policy selects `pin`/`nopin`; durable PIN backoff is per stable identity
  within a room, with a soft room-wide in-memory aggregate. See the late checkpoint.
- **Stage 7**: real-WebRTC headless-Chromium E2E vs the local stack; SRI repin; bump
  `package.json` 0.9.2 → 0.10.0 (+ `wasmLoader.ts` `wasmVersion`). **This is the
  definition of done** — then merge to master.

## RESEARCH / PAPER / L2 threads (active alongside the core; claims remain unshipped)

- **COVER POLICY DECIDED (D3, 2026-07-23):** preserve one ephemeral
  DataChannel per logical message for isolated cancel/progress/backpressure/retry/
  cleanup. In the current immediate runtime, closing that message channel while the
  same authenticated peer connection remains current is peer cancellation; a failed
  or replaced connection is a resume case. There is no encrypted `CANCEL` frame.
  **Immediate/no-cover is the product default. Future cover is a room-wide
  config**, canonically encoded + authenticated in every peer handshake so the
  signaling server cannot downgrade it. An enabled room runs its fixed cadence:
  each peer edge provisions the same neutral message lanes when idle or active;
  real data and PQ control substitute for scheduled dummy frames. In that future mode,
  cancel is
  immediate in local state, but after admission it sends an encrypted CANCEL in
  the next scheduled slot and fills the remaining lane with cover; never close
  early in privacy mode. At `C=1,F=1`, 10 s cover gives 5 s mean admission but
  costs 565.8 MB/day outbound per endpoint (1.132 GB/day/pair); 60 s gives 30 s
  mean and 94.3 MB/day outbound (188.6 MB/day/pair), before overhead. Mesh cost
  scales by peer-pairs. Exact cadence/lane/frame counts and duration buckets
  remain evaluation parameters. This protects
  real-vs-cover activity/cancel timing on an already-established link, not IPs,
  connection/room existence, global correlation, suspension, or congestion.
  WebSocket payload fallback is forbidden in cover mode. Paper/blog wording and
  the ELI5 encrypted-train narrative, plus the 10 s / 15 s / 30 s / 60 s /
  2 min / 5 min / 10 min cost-and-latency matrix and large-file capacity
  trade-offs, are recorded in `docs/protocol-evolution-decision-log.md` D3.
  Never increase cadence in response to typing/data; a room-policy change is an
  authenticated all-peer transition at a future boundary.
- Prior-art pass independently re-adjudicated 2026-07-23
  (`docs/paper-prior-art-and-related-work.md` §1.1): RETRACT the older “C3 is the
  only NOVEL / no preemption” conclusion. The first pass correctly rejected primitive
  novelty, found SPQR/Triple Ratchet/PQ3, and corrected SPQR to **32 B** +
  generic erasure codes. It overfocused on Signal-like messaging and missed Post
  Quantum Sphinx, Outfox, CCS'24 OKE/Kemeleon, CRYPTO'25 Hybrid OKE, and the
  decisive applied comparator: Zerion v3 source commit `1f9d00f...` (4096-byte
  real-or-cover frames at ~750 ms with per-frame ML-KEM). p2party's surviving
  direction is **NOVEL-ADJACENT / open until evaluated**: sparse authenticated
  Triple-Ratchet PQ advances replace already-scheduled room cells in a
  browser/WebRTC mesh while one DataChannel per message preserves cancel/progress
  UX. Claim only zero marginal scheduled application frames/bytes, never “free.”
  Kemeleon was a layer error as a current blocker: keep PQ control inside
  application AEAD + DTLS, where the declared direct/TURN observer cannot inspect
  raw ML-KEM bytes; use published OKEM only if that boundary moves. p2party commits
  `6ba8558b...` / `68fd058f...` precede Zerion's v3 commit by ~28/~19 hours, but
  this is independent concurrent provenance, NOT academic priority. Tagged Zerion
  is tryable Android PQ today; its closest cover-v3 is source-only. `p2party.com`
  is the immediately-tryable browser mesh, but does not count as PQ-cover
  deployment until this branch is repacked/reinstalled and production-verified.
- User wants **ONE combined SOTA-edge contribution**, not two forced novelties. Strong
  L2 server-blind rendezvous is now part of that combined target, not a deferred
  OPRF-only Phase 1. A common opaque or OPRF-derived token is only L1 because equality
  still clusters co-members. The working L2 construction is a short-TTL anytrust
  service over independently operated replicas: a 256-bit fragment capability,
  rotating presence IDs, **DPF/Riposte-style private point writes plus batched IT-PIR
  reads** for the dynamic presence board, fixed-size encrypted SDP/ICE inbox records,
  and stable identities revealed only inside the authenticated peer handshake. Talek
  remains a comparator and may fit the later pairwise single-writer inbox/log after
  rendezvous; it is not the dynamic multi-writer presence primitive. Hidden subslot
  allocation/collisions, expiry, equivocation auditing, and WebRTC handoff are
  p2party-specific work. A human PIN stays separate from the capability so public
  records do not become an offline PIN oracle.
  L2a hides the application room graph; L2b additionally needs noncolluding ingress/TURN
  or an anonymity network to hide source IP and timing. Service-wide real/fake accesses
  are required for a timing claim; room cover begins too late to hide rendezvous.
- **Do not claim L2 is shipped:** current high-entropy/PIN rooms still send `roomUrl` +
  stable `peerId`, obtain the `roomId` peer roster (IDs/public keys), and broker every
  pair's SDP/ICE through the server. The server is content/secret-blind, not
  membership-blind. Separately, the shipped data plane is already an n>2 full WebRTC
  mesh; only signaling is star-shaped.
- **BitTorrent means an actual protocol extension**, not merely borrowing its DHT or
  running unchanged BitTorrent over p2party. The research direction is a fail-closed
  private-swarm mode: capability/private-L2 discovery; an X25519 + exact
  swarm-policy-selected ML-KEM-512/768/1024 outer session; conventional
  HAVE/request/piece/cancel semantics carried in fixed authenticated cells; a
  swarm-wide fixed rate class; no legacy tracker/DHT/PEX/LSD or plaintext downgrade;
  and useful-byte accounting that never rewards dummy traffic.
  Preserve BitTorrent's sparse bounded-neighbor topology—do not import room full-mesh
  cover into a large swarm. Content/piece semantics can interoperate, but strong-private
  wire/discovery cannot interoperate with legacy peers. I2P already combines deployed
  BitTorrent with a Double Ratchet and a completed hybrid ML-KEM ratchet, so never claim
  “first BitTorrent + ML-KEM/ratchet.” The narrower paper question is private logical
  swarm discovery + application-layer fixed cells/cover and its privacy/throughput/
  incentive trade-off against I2P, OneSwarm, Tribler, and Aqua. Treat this as a secondary
  `createSession()` transport-neutrality/evaluation target unless a real BEP-shaped
  implementation produces a separate result.
  Strong carriers are WebRTC/DTLS or TLS/QUIC with exporter binding: the current
  suite-specific 1,761/2,465/3,329-byte hybrid HELLO is fingerprintable if exposed on
  raw TCP, which would require published OKE/Kemeleon or a weaker claim. Do not copy
  chat's
  per-message physical DataChannel mapping into torrents; P2BT multiplexes
  logical transfers over a long-lived sparse-neighbor connection. One current
  cell/10 s is only ~49.5 kbit/s/link (~48 h/GiB from one source), so bulk cover
  needs a predeclared rate profile/bulk epoch, not cadence alone.
- Capstone status: the repository README/DX passes and five-part blog series have
  landed. The LaTeX paper, production deployment, and final visual/browser gate remain.

## LATE-SESSION TREE TRUTH (started 2026-07-23; updated by checkpoints below)

- **One exact mandatory protocol-v3 profile per room.** Interactive X25519 3DH
  possession proof runs in every room; `pin` additionally runs draft-21 CPace and
  contributes its ISK. The authenticated room policy selects exactly one of
  ML-KEM-512/768/1024 (768 is the default), producing `3DH ‖ ML-KEM` or
  `CPace-ISK ‖ 3DH ‖ ML-KEM`, with no negotiation or classical fallback. This is
  neither Signal X3DH (no prekey bundles) nor X-Wing (a specific hybrid-KEM
  combiner). Persisted sessions accept the matching
  `hybrid-3dh-mlkem{512,768,1024}-cpace21-v3` provenance only.
- **Provenance tags have distinct scopes.** Wire protocol is `3`; standalone snapshot
  format is `3` with root-suite bytes `4/3/5` for ML-KEM-512/768/1024; handshake
  channel input carries suite tags `0x02/0x01/0x03`. Do not conflate the snapshot
  suite byte with the handshake suite tag.
- **Ownership is leased.** Ratchet gates and handshake inboxes are separate
  `(roomId, transient peerId)` registries with opaque attempt leases. The gate opens
  only after handshake plus durable persistence. Stable identity alias exclusion and
  persistence ownership are separate `(roomId, stable Ed25519 identity)` /
  `(roomId, peerPublicKey)` concerns; stale callbacks cannot own a replacement attempt.
- **PIN throttling has two layers.** Durable exponential backoff is per
  `(roomId, stable Ed25519 identity)`, beginning on failure three at 500 ms and capped
  at five minutes. A soft in-memory room aggregate permits 30 failures per five minutes
  to constrain identity rotation; it resets with the process/page.
- **Transfers are v18 identities.** Each outbound logical send has a random 32-byte
  lowercase-hex `transferId`; `newChunks` is keyed `[transferId, chunkIndex]`, and
  hash/root selectors fail when ambiguous. A chunk token cryptographically binds only
  `domain ‖ merkleRoot ‖ u64(index) ‖ leafHash`; lookup is root-scoped and the handler
  then requires the resolved row's `transferId` to match the active send. Terminal
  completion is still the raw 64-byte content hash. A true receipt token is emitted
  only after the worker crosses its durability boundary; storage failure follows
  decoy/drop semantics. Production receipts are tagged 65-byte frames, and receipt
  processing/replay is bounded, serialized per edge, and SCTP-backpressured.
- **Memory and cancel semantics.** The WASM build enables growth, while callers set
  per-operation maxima: small v3/session modules currently choose 32 pages, whereas
  Merkle/Argon2 helpers may choose more. Immediate-mode remote cancel is the closure of
  one message DataChannel while the same authenticated peer connection remains current;
  replacement/failed transport resumes. No encrypted `CANCEL` frame exists.
- **Do not claim these research layers are shipped:** nonzero/sparse PQ epochs,
  scheduled cover and its future encrypted `CANCEL`, L2 server-blind rendezvous, or
  P2BT. Current runtime accepts PQ epoch zero, immediate/no-cover policy, and legacy
  rendezvous.
- **Verification boundary:** this late checkpoint is a source/doc truth pass. It records
  no new full-suite, typecheck, packed-frontend, full-WebRTC, release, or deployment
  success. The root controller must append the actual results after running them.

## ROOT-VERIFIED CHECKPOINT (2026-07-23; full WebRTC still pending)

- Core protocol-v3 hardening is committed as `bfe9e30`. Immediately before that
  checkpoint, `bun test` passed **276/0** with 11,854 assertions,
  `npm run typecheck` passed both TypeScript projects, and
  `bun run examples/standalone-e2ee.ts` printed `OK`.
- `handshakeCore.ts`, `messageChunkCrypto.ts`, and `cryptography/ratchet.ts` remain
  store/database-free. The two master stashes remain intact.
- A provisional transactional 0.10.0 pack succeeded and produced WASM SHA-256
  `7cdc87ed6341b4ca2c7db8ee37ebb2299c92b1b25c685bc7865c5862ebb9bd47`
  and tarball SHA-256
  `f0d961e1addd51ba70817a7959b957049eefddf666383936ac168ee184a29355`.
  npm and Bun audits reported zero known vulnerabilities.
- **Release blocker:** the custom WASM build currently consumes libsodium submodule
  `7014b204` from upstream `master`. That source explicitly emits the
  unstable-development warning, and the direct-file compile also emits the
  unsupported/unconfigured-build warning. A signed local `1.0.22` tag is available,
  but the no-checkout/reset/etc. constraint means the submodule must not be silently
  moved. Pin a stable release and use a supported configured build path, then repeat
  all vectors/tests/package/browser checks before calling 0.10.0 release-ready.
- The remaining functional gate is T5: real browser/WebRTC + signaling + IndexedDB
  round trips (including responder-first, PIN, reconnect/resume, and n>2 mesh),
  followed by the frontend/server OSS and production verification. Do not infer that
  scheduled cover, sparse PQ healing, L2 rendezvous, or P2BT has shipped.

## ROOT-VERIFIED RELEASE + LICENSE CHECKPOINT (2026-07-23)

- Release hardening is committed as `3c96270`. The build extracts exact stable
  libsodium commit `2ce4d906a68eae82b27b4867f3d4172ec508cb27` / tree
  `2dabe17c708edd7334e3316b5094b753859395d9` with read-only `git archive`, runs
  the supported configured static build, uses public sodium APIs plus checked
  `sodium_init`, and disables LTO. The custom RNG and private Argon2 ABI are gone.
- The final post-license local package is `p2party-0.10.0.tgz`, SHA-256
  `88b408db271304b70042e59c42d69111a598c0ad81b0c8325cc129eaec8a3092`.
  Its WASM is 177,858 bytes, SHA-256
  `ac8251be4ffcb66c5b01510cc81e3a2ae160b30bb54c15c13a84bf183eeff6e6`,
  with SRI
  `sha384-N/YT0GhVKVBWk5TRotqM0Hu+fos8xRq+AyFnRmqFQgQMyVm8edPWIZiSIDqqcG87`.
  The release script validates the WASM/glue exports, provenance, package export
  graph, store-free session ESM/CJS surfaces, tar contents, and archived bytes.
- Root reran `bun test` (**277/0**, 11,856 assertions), `npm run typecheck`, and
  `bun run examples/standalone-e2ee.ts`; all passed. Both master stashes remain
  intact.
- Final license split: `p2party-js` and `p2party-server` are Apache-2.0;
  `p2party.com` remains AGPL-3.0-only. Both Apache `LICENSE.md` files are verbatim
  copies of the canonical apache.org text. Server license commit: `4ab3c82`.
- This clears the prior libsodium release blocker. It does **not** establish
  frontend installation, browser/WebRTC T5, production deployment, scheduled
  cover, sparse PQ healing, L2 rendezvous, or P2BT; those remain separate gates.

## 0.11.0 CORE CHECKPOINT (2026-07-24; production integration still pending)

- Commit `6e13d81` adds exact room-selected FIPS 203 ML-KEM-512/768/1024
  bootstrap profiles with no negotiation, length inference, downgrade, or
  classical fallback. ML-KEM-768 keeps the existing suite/tag assignments and
  remains the default. Suite-specific KDF domains, persisted ratchet provenance,
  standalone snapshots, and room policy all reject cross-suite state.
- The handshake now has three chained cryptographic proofs:
  responder `mac_R`, initiator `mac_I` over `mac_R` and both initial ratchet
  keys, and responder `FINISH/mac_F` over both earlier proofs. The initiator
  establishes only after validating FINISH. An already-open RTCDataChannel is
  not that acknowledgement: it proves the earlier DTLS/SCTP transport, and
  `RTCDataChannel.send()` exposes no peer-verified application-MAC receipt.
  Responder completion still cannot prove final-packet delivery; that unavoidable
  lossy-transport edge is availability/state synchronization, not key disclosure.
- Commit `a426490` lands the internal sparse PQ-healing state-machine core:
  exact-suite OFFER/ADVANCE records, full transcript binding, u64
  epochs/counters, alternating turns, replay/fork/gap rejection, prepared/commit/
  acknowledgement phases, traffic gating, and secret wiping. It is **not yet a
  shipped nonzero PQ epoch**. Production still needs canonical authenticated ACK
  bytes, encrypted crash-safe checkpoint/restore, exact sealed-record
  retransmission, message-key combination, and WebRTC/cover-scheduler wiring.
- The formal scaffold is committed as `64dea1e`. It models the exact no-PIN
  ML-KEM-768/3DH/triple-confirmation transcript and preprocesses in baseline
  and compromise/HNDL profiles. ProVerif is not installed locally, so this is
  a model scaffold—not a solver result or proof claim.
- The formal baseline remains honest: PQXDH has substantially stronger published
  ProVerif/CryptoVerif assurance. The p2party model must cover this exact
  interactive no-PIN transcript and triple-confirmation boundary; it must not
  claim to prove PIN/CPace, Double Ratchet, sparse healing, deniability, or the
  whole browser/network stack until separate models exist.
- Current-Chromium entropy staging is fixed in `372735f`: WebCrypto fills a
  fixed ordinary buffer, copies into WASM, then wipes the temporary. Exact
  installed 0.11.0 passed Chromium 149 no-PIN delivery in both role
  directions (including responder-first), 5 MiB cancellation plus edge reuse,
  and a deterministic 450,000-byte file in nine 65,490-byte WebRTC frames with
  zero WebSocket payload fallback.
- Commits `9167400` and `eeccc41` close two independent concurrent-join mesh
  bugs: an accepted `connection` delta now allocates the missing local
  transport, and one-peer `peers` deltas are merged rather than misread as
  authoritative snapshots. The exact-artifact n=3 rerun remains the live T5
  gate; do not infer it passed from unit coverage.
- Root verification after `eeccc41`: `bun test` passed **327/0** with 12,106
  assertions, `npm run typecheck` was clean, and
  `bun run examples/standalone-e2ee.ts` printed `OK`. Transactional
  `release:pack` produced a 106-file `p2party-0.11.0.tgz`, SHA-256
  `a0de7a8b76f2e415193d86a095baa0d4df003f57c4095f9d4199ffcb4c175599`;
  its 208,966-byte WASM remains SHA-256
  `73f4eee322534665ebe99aab6b1494dc2fb32d859b3f55a3c2ae6fa477043789`.
- `p2party-server` commits `0b24196` and `7a6e098` make the current SQLite
  bootstrap Prisma-correct and reproducible from the real migration chain,
  remove dead contradictory adapters, and add relation/type smoke coverage.
  Server verification is 13/0 with clean typecheck/format. Historical
  `prisma/dev.db` blobs must still be removed by a fresh public history or an
  explicitly authorized history rewrite before publishing the repository.

## 0.12.0 RELEASE-CANDIDATE + GITHUB DX CHECKPOINT (2026-07-24)

- Protocol-v3 public release work through commit `8dbb90e` is committed on
  `feat/pace-ratchet-protocol-v3`. `p2party/session` is the supported
  store/DB/DOM/WebRTC-free entry point for Node, Bun, native shells, tests, and
  custom transports. The GitHub README now starts from an integration chooser
  under the canonical p2party cat logo and includes copyable browser-mesh,
  room-invite, PIN/exact-suite, send/cancel/read, custom-transport,
  serialize/restore, and self-hosted-WASM paths. The package exports and
  includes the byte-identical cat asset, `docs/getting-started.md`,
  `docs/session-api.md`, `docs/protocol-v3-security.md`, and the runnable
  `examples/standalone-e2ee.ts`.
- A release-candidate audit caught a real Node ESM defect: successful import did
  not imply usable cryptography because Emscripten's RNG fallback attempted
  CommonJS `require("crypto")`. Commit `5db2502` supplies explicit WebCrypto
  entropy to the module in browsers, workers, Node, and Bun. The release builder
  now performs actual packaged identity generation through both Node ESM and
  CommonJS. Commit `8dbb90e` additionally runs the complete packaged standalone
  handshake/encrypt/decrypt/serialize/restore example as a release gate. The
  browser root also exposes `setWasmSourceUrl()` for an exact self-hosted
  artifact while retaining the build-pinned SRI check.
- Two independent final-state `release:pack` runs produced the same 113-file
  `p2party-0.12.0.tgz`: SHA-256
  `761279e61908c7cacb7d6e016c0feb2445ed4a26ab141b29d2bca0690749a4e2`
  and SHA-512
  `8709571263cdd864fcb40ea6b18dda23f82e35c150ecaad1d6ebcf242eea46c8c22b319b5c23909774521ad323775b5aa528f75b9acc06be151df26d2367621c`.
  Its 208,966-byte WASM is SHA-256
  `73f4eee322534665ebe99aab6b1494dc2fb32d859b3f55a3c2ae6fa477043789`
  with SRI
  `sha384-gHNbEQ3KIbsYpXGbpz6O62xI1CjZDVeD8FnYA//PWGAHxKDuN2pMVpQvDopV6Qcg`.
  Generated crypto provenance remained clean. `npm run check` passed with
  **333/0**, 12,142 assertions, clean lint/format/typecheck, and standalone
  `OK`; the exact installed tarball's Node ESM identity-generation smoke
  returned Ed25519/X25519 secret sizes `64/32`.
- `p2party.com` commits `530a2a1`, `60b5091`, and `1279bd3` install and verify
  that exact tarball, serve a byte-identical self-hosted WASM, and wire the root
  loader to it before crypto use. The dependency verifier checks lock
  integrity, tar SHA-256, embedded provenance, and public-WASM identity.
  Frontend lint, formatting, typecheck, build, audit, and **16/0** tests with
  74 assertions passed. The installed package's standalone example also prints
  `OK`. The five-part protocol-v3 “road to today” series is published at
  `/blog` and `/blog/:slug`, with source-commit anchors and explicit
  shipped/gated/research boundaries. The only frontend worktree item is the
  protected pre-existing untracked
  `src/components/MessageInput/TextArea.tsx`.
- `p2party-server` is Apache-2.0 and its current OSS-preparation checkpoint
  `b42f770e7a536a27b84d1442486ccd682aecac21` passes **15/0**, typecheck, and
  formatting. Public histories still need a fresh/squashed publication using
  `@p2party.com` identities; no history rewrite was performed.
- **Do not overclaim this checkpoint.** The npm tag/CDN publication, production
  deployment, and a fresh exact-0.12 full-WebRTC T5 run remain pending. The
  final docs pass did not substitute another browser runner when the designated
  browser controller was unavailable. Scheduled cover, production sparse-PQ
  healing, L2 rendezvous, and P2BT remain gated/research work exactly as stated
  in the public security boundary. Both master stashes remain intact.

## Methodology + where the record lives

- Subagent-driven: one implementer per task + a focused adversarial review for
  security-critical crypto. The review keeps catching REAL bugs before ship (gate
  unhandled-rejection, DTLS fail-open, the SECURITY-1 cross-sig oracle in the SPEC, the
  double-wrap). Keep that gate for Stage 5's crypto swap.
- Durable ledger (gitignored, on disk): `.superpowers/sdd/progress.md`. Per-task
  reports/reviews: `.superpowers/sdd/*.md`. Specs: `docs/superpowers/specs/`. Plan:
  `docs/superpowers/plans/`. Decision arc: `docs/protocol-evolution-decision-log.md`.

## CAPSTONE (deferred — do after the core lands, or in parallel where it fits)

- p2party.com INTEGRATION: the frontend installs file:../p2party-js/p2party-0.9.2.tgz. Rebuild+repack the v3 branch (npm run predist && build:package && build:worker && npm pack) and reinstall it in p2party.com;
  wire the site to the v3 handshake + message crypto; surface a standalone createSession() demo. The blog also lives on p2party.com.
- BLOG SERIES on p2party.com: a 'road to today' narrative built from the git history, culminating in the Double Ratchet (the #1 NLnet/TrustChain grant promise = this protocol-v3 work). Voice = hacker / 'offensive
  cryptography'; match the grant prose + existing docs tone, not corporate. Source material: p2party-js/docs/protocol-v3-implementation-log.md, protocol-evolution-decision-log.md, and git log.
- PAPER (LaTeX, offensive-crypto systems paper): architecture-SPECIFIC, not another generic Double-Ratchet paper. Preserve the re-adjudicated **novel-adjacent systems hypothesis**, not a broad “first/free PQ” claim: only an implemented sparse PQ advance replacing a slot in an already-running authenticated schedule could have zero marginal scheduled application frames/bytes. Compare directly with SPQR, PQ3, Post Quantum Sphinx, Outfox, OKE/Hybrid OKE, and Zerion. Extend p2party-js/docs/paper-prior-art-and-related-work.md before drafting.
- VISUAL PASS on p2party.com: elevate to a professional polish (responsive, a11y, consistency) while KEEPING the retro-90s / hacker aesthetic and brand (the two-column retro landing). Do NOT sanitize it into
  generic SaaS.
