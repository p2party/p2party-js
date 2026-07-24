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

## TRUE-L2 ROADMAP CHECKPOINT (2026-07-24)

- The maintainer accepted a roadmap instead of rushing an unreviewed private
  rendezvous implementation during the 0.12 deployment. The self-contained
  architecture and acceptance gates live at
  `spec/spec-architecture-l2-blind-rendezvous.md`.
- This is not a transport toggle. It requires an isolated fixed-epoch board
  service over independently operated anytrust replicas; robust/verifiable DPF
  private writes plus private reads; fixed real-or-dummy cohort lanes;
  fork-accountable commitments; local-only room/edge identifiers; an injected
  store-free rendezvous adapter; a reviewed pre-WebRTC hybrid exchange; and
  exact-artifact `n >= 3` WebRTC, fault, privacy-classifier, and external-review
  gates.
- L2a means target/identifier privacy at the application protocol under the
  declared non-collusion and cohort schedule. Source IP, timing, ingress, and
  co-operated TURN remain explicit residuals; only the separately scoped L2b
  phase may claim network unlinkability. Opaque/OPRF common tokens, fragment
  URLs alone, or two replicas under one operator do not qualify.
- Current production remains content-blind but not membership-blind. The
  legacy signaling path still receives a common room value, stable identity,
  roster, SDP/ICE routing, and timing; `connect()` rejects the reserved blind
  modes. Do not label any current room server-blind.

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

## SESSION 2026-07-24 (late) — PROTOCOL-V4 PQ/COVER IMPLEMENTATION WIP HANDOFF

### Read this first: exact state and user intent

The maintainer explicitly corrected the previous roadmap-only response:
**implement production sparse PQ healing and room-wide scheduled timing cover;
do not merely describe them**. Immediate/no-cover remains the product default.
Scheduled cover is an authenticated, immutable-for-the-room option. This is a
clean protocol/version break; backward compatibility with protocol v3 is not a
requirement.

This session was stopped at the maintainer's request so Claude could resume from
an exact checkpoint. The current tree is deliberately a **WIP checkpoint, not a
green or shippable implementation**. Do not infer completion from the amount of
code present.

Repository state at handoff:

- Repository: `p2party-js`
- Branch: `feat/pace-ratchet-protocol-v3` (keep this branch name despite the
  protocol-v4 wire break)
- Starting/previous HEAD: `fb57b1e6d39b0ee25c4dd7815d20c402a02e2bf3`
- Protocol-v4 WIP implementation checkpoint:
  `4df71ab` (`wip: checkpoint protocol v4 PQ healing and cover cores`)
- Local `master` was also
  `fb57b1e6d39b0ee25c4dd7815d20c402a02e2bf3` before the WIP checkpoint commit.
- Package version is still `0.12.0`; no protocol-v4 tarball was built or
  installed in `p2party.com`.
- No merge or fast-forward to `master` has happened in this session.
- Postgres on `:5432` was not touched.
- The protected sibling frontend file
  `p2party.com/src/components/MessageInput/TextArea.tsx` was not touched.
- The filesystem authority in this session covered only `p2party-js`, so no
  current protocol-v4 frontend or server edits were made.
- Three parallel agents were stopped before this handoff. They have no live
  background work left to finish.

The two pre-existing `master` stashes are still exactly:

```text
stash@{0}: WIP on master: 56e87ba Disconnect from all rooms and various bug fixes
stash@{1}: WIP on master: a407fad Persisting messages and identity
```

Never use `git stash`, `git reset`, `git checkout`, `git clean`, or `git
rebase`. Continue with additive edits and ordinary commits only. Before and
after each eventual merge/fast-forward, verify the two stash entries remain.

### Accepted architecture written during this session

Read `docs/protocol-v4-pq-cover-architecture.md` before editing runtime code. It
records the implementation contract selected after a persistence, wire-format,
WebRTC, and cover-timing audit:

1. Protocol v4 is a clean break. The public epoch is now an authenticated
   unsigned 64-bit value, not the protocol-v3 one-byte reserved zero.
2. Every large message/PQ/cover cell remains exactly 65,490 bytes:

   ```text
   type(1) | dh-or-control-id(32) | N(8) | PN(8) | pqEpoch(8) | nonce(12)
   | padded plaintext(65,405) | tag(16)
   ```

   The seven additional epoch bytes consume padding rather than increasing the
   externally visible application-cell size.
3. Message AEAD authenticates the full clear header except the random nonce:
   type, DH public key, N, PN, and PQ epoch. Cache identities include the epoch.
4. The classical Double-Ratchet message key and current PQ root are combined
   with a domain-separated HKDF bound to the selected suite, edge binding,
   epoch, and ratchet header.
5. Classical skipped keys stay classical. Already-combined active receive keys
   must live in a separate epoch-bound collection and must be persisted there;
   they must never be inserted into `RatchetState.skipped`.
6. One encrypted stable-edge checkpoint must contain the DR state, PQ machine,
   exact sealed control outbox, replay/ACK cache, and active combined receive
   keys. Message and PQ mutations share one edge lock.
7. A sparse exchange uses exact OFFER/ADVANCE/ACK ordering:

   - prepare and seal OFFER under the current root;
   - persist its KEM secret plus exact sealed frame;
   - send only after durability;
   - seal ADVANCE under the old root before committing the candidate root;
   - persist new root plus exact old-root ADVANCE before sending;
   - commit an accepted ADVANCE, seal ACK under the new root, persist root plus
     exact ACK/replay cache, then send;
   - reopen application traffic only after the ACK transition is durable.

8. Scheduled cover uses absolute room-phased cycles. Exactly `C` lanes are
   opened at a cycle boundary, each emits exactly `F` cells per epoch for `D`
   epochs, and all close at the fixed boundary. Real data, PQ controls,
   receipts, and cancellation substitute for dummy cells. There is no early
   close, catch-up burst, or WebSocket payload fallback.
9. An admitted cancellation is local-UI-immediate but emits an encrypted
   CANCEL in the next slot and then a dummy tail through the fixed boundary.
10. Browser suspension or missed deadlines degrades/suspends cover; resume
    begins at a strictly future boundary. Never claim cover for the gap.

The architecture ADR was selected using the local `architecture` skill. Its
main influence was to make crash ordering, single-row atomicity, fixed lifecycle,
and claim boundaries explicit before connecting the independently developed
primitives.

### Files changed: protocol-v4 wire and key combiner

Parallel wire work is present in these files:

- `src/utils/constants.ts`
- `src/utils/constants.test.ts`
- `src/cryptography/utils.h`
- `src/cryptography/pake_ratchet.c`
- `src/cryptography/pake_ratchet.h`
- `src/handlers/chunkFrame.ts`
- `src/handlers/chunkFrame.test.ts`
- `src/handlers/messageChunkCrypto.ts`
- `src/handlers/messageChunkCrypto.test.ts`
- `src/cryptography/pqMessageKey.ts` (new)
- `src/cryptography/pqMessageKey.test.ts` (new)

Implemented wire-level behavior:

- `PROTOCOL_VERSION` is now `4`.
- `PQ_EPOCH_LEN` is `8`.
- `FRAME_TYPE_COVER = 4`.
- `FRAME_TYPE_PQ_CONTROL = 5`.
- `CHUNK_PLAINTEXT_LEN`/`DECRYPTED_LEN` drops from 65,412 to 65,405
  bytes, preserving `WIRE_CHUNK_FRAME_LEN === 65_490`.
- C and TypeScript now define:

  ```text
  CHUNK_AAD_HEADER_LEN = 57
  CHUNK_HEADER_LEN = 68
  MESSAGE_START = 69
  ```

- The C receive path authenticates:

  ```text
  merkleRoot(64) || type(1) || dhPub(32) || N(8) || PN(8) || pqEpoch(8)
  ```

- `packChunkFrameHeader(header, nonce, pqEpoch)` and
  `parseChunkFrameHeader(frame)` use the full u64 epoch.
- `messageCacheKey(dhPub, N, pqEpoch)` emits an epoch suffix when the
  explicit epoch is supplied. Omitting it retains the historical two-field
  form only for low-level/bootstrap tests.
- `PqMessageKeyContext` is:

  ```ts
  {
    rootKey: Uint8Array;
    binding: Uint8Array;
    rootSuite: RatchetRootSuite;
    epoch: bigint;
  }
  ```

- `combinePqMessageKey(classical, context, header, module)` consumes/wipes the
  owned classical input even when it throws, and does not wipe the context's
  live PQ root.
- `sealChunk(..., module, pqContext?)` emits epoch zero/raw classical behavior
  only when no context is supplied; production must always supply the runtime
  context.
- `decryptMessageChunk(..., module, pqContextResolver?)` rejects a nonzero,
  unknown, stale, mismatched-suite, or malformed epoch before mutating a ratchet
  clone. Production must pass the runtime resolver.

Important generated-artifact state:

- The agent temporarily rebuilt the WASM and reported the new message/C tests
  passing, then restored the generated artifacts before stopping.
- Consequently, the current tracked C source understands the v4 offsets but
  the checked-in `libcrypto.wasm` is still the prior artifact. This is the
  likely cause of all current message-decrypt failures.
- The next implementer must intentionally rebuild and retain the generated
  artifacts. Run `npm run prebuild` for the development verification artifact,
  then later `npm run predist` for the release artifact. Do not “fix” the tests
  by rolling back the C/TS wire change.
- After a retained rebuild, expect changes to the generated
  `src/cryptography/libcrypto.js`, `libcrypto.wasm`,
  `libcrypto.provenance.json`, and the pinned integrity in `wasmLoader.ts`.
  Verify provenance/integrity rather than hand-editing them.

### Files changed: sparse-PQ machine, canonical ACK, and control cells

The original store-free sparse state machine was expanded in:

- `src/cryptography/pqHealing.ts`
- `src/cryptography/pqHealing.test.ts`

New canonical fixed-cell codec:

- `src/cryptography/pqHealingFrame.ts`
- `src/cryptography/pqHealingFrame.test.ts`

Exact APIs now implemented:

```ts
encodePqHealingAck(ack, suite, binding): Uint8Array
decodePqHealingAck(bytes, suite, binding): PqHealingAdvanceAcknowledgement

snapshotPqHealing(machine): PqHealingSnapshot
restorePqHealing(snapshot, { module, backend, suite, binding }): PqHealingMachine
clonePqHealing(machine): PqHealingMachine
adoptPqHealing(live, next): void
wipePqHealingSnapshot(snapshot): void

sealPqControlFrame({
  module,
  suite,
  rootKey,
  binding,
  direction,
  keyEpoch,
  record,
}): Uint8Array

openPqControlFrame({
  module,
  suite,
  rootKey,
  binding,
  direction,
  keyEpoch,
  frame,
}): Uint8Array
```

The ACK is exactly 64 bytes and binds magic/version/type, suite, edge binding,
ADVANCE counter, and new epoch. OFFER/ADVANCE/ACK outer frames are all exactly
65,490 bytes. Their public header uses the 32-byte edge binding as a control ID,
the record counter as N, canonical-zero PN, and the full key epoch. The entire
header including nonce is AEAD AAD for the control codec. Directional keys
separate initiator-to-responder from responder-to-initiator traffic.

Focused tests at this checkpoint:

- `pqHealing.test.ts`: 15 pass / 0 fail.
- `pqHealingFrame.test.ts`: 3 pass / 0 fail.
- `pqMessageKey.test.ts`: 3 pass / 0 fail.

These are primitive/core results only. They do not mean WebRTC healing is wired.

### Files changed: handshake bootstrap and protocol domains

`src/handlers/handshakeCore.ts` now:

- changes handshake confirmation and hybrid-root domains from v3 to v4;
- derives a separate 32-byte PQ-healing root from the authenticated hybrid
  handshake secret;
- derives a public 32-byte edge binding over the channel input and ordered
  authenticated HELLO material;
- returns:

  ```ts
  {
    state: RatchetState;
    secret: Uint8Array;
    pqHealing: {
      rootKey: Uint8Array;
      binding: Uint8Array;
      nextOfferer: "local" | "remote";
    };
  }
  ```

- chooses the first OFFER turn from the stable identity role:
  initiator gets `"local"`, responder gets `"remote"`;
- wipes loose PQ derivation buffers on failure.

Critical integration gap:

- `src/handlers/handleHandshake.ts::runHandshake` still takes only
  `result.state` and `result.secret`. It does not construct/install a PQ runtime
  and does not currently take ownership of or wipe `result.pqHealing`. Fix this
  first; it is a secret-lifetime bug in the WIP tree.
- The initial encrypted edge row therefore still receives no real PQ
  checkpoint.
- `src/session.ts` merely captures and wipes the returned PQ root/binding.
  Session message encryption remains classical-only while the global protocol
  version is already 4. Do not ship this intermediate state.

Remember the established identity invariant: `idSelfSec` in
`performHandshakeCore` is the long-term **X25519 identity secret**, never the
Ed25519 secret. The canonical construction example remains
`handleHandshake.test.ts:215-263`.

### Files changed: encrypted edge checkpoint and database migration

Changed persistence files:

- `src/db/types.ts`
- `src/db/ratchetWrap.ts`
- `src/db/ratchetWrap.test.ts`
- `src/db/db.worker.ts`
- `src/db/db.worker.test.ts`
- `src/db/src/getDB.ts`
- `src/db/src/getDB.test.ts`
- `src/handlers/ratchetPersist.ts`
- `src/handlers/ratchetPersist.test.ts`
- `src/api/webrtc/interfaces.ts`
- `src/api/webrtc/disconnectFromPeerQuery.test.ts`

Current implementation:

- IndexedDB version is bumped from 18 to 19.
- An upgrade from any nonzero version below 19 clears `ratchetSessions` and
  `sendQueue`, while intending to preserve rooms/message history/received data.
- `RatchetSession` now has
  `edgeCryptoState: ArrayBuffer | null`.
- The ratchet at-rest envelope is version 2.
- `edgeCryptoState` is bounded to 256 KiB and is independently AES-GCM wrapped
  in the same authenticated row/record-ID scheme.
- Public metadata/nullability includes the presence of the edge checkpoint.
- Ciphertext-transplant and nullability tests cover the new field.
- Worker cleanup wipes its plaintext edge-state copy.
- `IRTCPC.serializeEdgeCryptoState?: () => Uint8Array` is a temporary hook.
- `withEdgeCryptoMutationLock` is now exported so PQ and DR transitions can
  share it.
- Initial and subsequent claimed-ratchet writes call the serializer hook and
  wipe the returned copy after the worker call.

Focused persistence result in the final diagnostic run:

- `ratchetWrap.test.ts`, `db.worker.test.ts`, and `getDB.test.ts` all passed
  (45 tests total in the earlier isolated run; all corresponding cases also
  passed in the later 78/8 aggregate).

Still missing or incorrect:

1. There is no live PQ runtime serializer installed by the handshake.
2. Receive-message persistence still copies the active message key into
   `candidate.skipped`. That violates the v4 architecture because the key is
   already PQ-combined and would be combined again or parsed as a classical
   skipped key after restore.
3. The staged receive cache is not included in the edge snapshot that is
   persisted before the live cache is published. `mutateRatchetDurably` needs
   an explicit candidate edge-state override, or it needs to clone/adopt the
   entire edge runtime alongside the ratchet.
4. The current stable-edge serialization uses locks and an authenticated
   timestamp/rollback guard, but it does **not** yet implement the ADR's
   cross-context generation/CAS. Either add an authenticated monotonically
   increasing generation and IndexedDB compare-and-swap semantics, or narrow
   the architecture/claim. For a production claim, implement CAS.
5. Add a direct v18 fixture proving that v19 clears existing ratchets and
   sendQueue while preserving message/chunk history. The current migration
   tests start primarily from v17/fresh state.
6. There is still no connection-time restore/resend of an outbox. A full page
   reload destroys WebRTC and performs a new handshake, so decide and document
   which crash class the persisted outbox covers. Do not claim cross-transport
   replay of old control ciphertext.

### New store-free PQ runtime file: present but intentionally unfinished

`src/handlers/pqHealingRuntime.ts` was added immediately before the stop
request. It is a large store-free controller draft and has **no tests and does
not typecheck yet**. Treat it as useful implementation material, not trusted
finished code.

Its intended responsibilities are:

- own `PqHealingMachine`, current message-combiner root/context, exact sealed
  outbox, retry metadata, exact inbound OFFER/ADVANCE replay frames, exact
  cached ACK frame, active combined receive keys, messages-since-heal, and
  last-heal time;
- choose directional control-frame keys from the stable initiator role;
- expose the current/epoch-resolving `PqMessageKeyContext`;
- trigger healing after 64 logical application messages or 24 hours;
- use 5-second retry spacing with a maximum of 8 attempts;
- prepare an exact sealed OFFER;
- accept/decrypt OFFER, ADVANCE, or ACK;
- answer exact duplicate OFFER/ADVANCE frames with the exact persisted response;
- clone/serialize/adopt/destroy without importing Redux, DB, WebRTC, or timers;
- encode a bounded, deterministic `P2EDGE4\0` checkpoint of at most 256 KiB.

Current TypeScript errors from `npm run typecheck` are exactly:

```text
src/handlers/pqHealingRuntime.ts(566,13): TS2314 generic PqHealingMachine needs an argument
src/handlers/pqHealingRuntime.ts(623,27): TS2314 generic PqHealingMachine needs an argument
src/handlers/pqHealingRuntime.ts(704,9):  TS2531 outbox possibly null
src/handlers/pqHealingRuntime.ts(706,5):  TS2322 nullable spread not assignable to PqHealingOutbox
src/handlers/pqHealingRuntime.ts(708,17): TS2531 outbox possibly null
src/handlers/pqHealingRuntime.ts(796,9):  TS2531 outbox possibly null
src/handlers/pqHealingRuntime.ts(861,9):  TS2531 outbox possibly null
src/handlers/pqHealingRuntime.ts(1014,18): TS2314 generic PqHealingMachine needs an argument
```

Precise first fixes:

1. Type machine references as
   `PqHealingMachine<MlKemParameterSet>` (including restore temporaries), or
   make the class itself generic and preserve the parameter through its suite.
2. Import/use `PqHealingPhase` for the `phase` getter; it is a property type,
   not a function for `ReturnType`.
3. In each branch, capture a non-null local:

   ```ts
   const outbox = this.#outbox;
   if (!outbox) fail(...);
   ```

   Then read/wipe/spread `outbox`, not `this.#outbox`, because TypeScript does
   not retain private-field narrowing across calls.
4. Run typecheck, then write a dedicated
   `src/handlers/pqHealingRuntime.test.ts` before integrating it.

Minimum runtime tests:

- all ML-KEM-512/768/1024 profiles complete OFFER → ADVANCE → ACK and end with
  byte-identical roots/epochs and alternating turns;
- serialize/restore at every durable boundary;
- discard a mutated clone on injected persistence failure and prove the live
  root/outbox/counters do not move;
- drop each flight, restore/retry, and prove exact frame bytes are reused;
- exact duplicate OFFER re-emits exact ADVANCE;
- exact duplicate ADVANCE re-emits exact ACK after the old root is gone;
- altered same-slot bytes fail as a fork;
- wrong suite/binding/direction/epoch fail closed;
- active receive keys round-trip separately and are wiped on retirement/destroy;
- retry exhaustion cannot generate a replacement record or fall back;
- checkpoint truncation, trailing bytes, impossible phase/outbox combinations,
  duplicate cache keys, and over-budget data fail closed.

Security review points in the draft:

- Verify that all public-record temporary copies are wiped consistently without
  accidentally wiping returned dispatch buffers.
- Verify that adopting a clone never aliases/wipes the live binding or current
  message root.
- Verify checkpoint restore has no secret-copy leaks on every throw path.
- Verify replay comparisons are constant-time where secrecy matters; exact
  public-frame comparisons need determinism more than secrecy.
- Verify `Date.now()` values and `now + retry` cannot cross the safe-integer/u64
  boundary.
- Reconcile `MAX_ACTIVE_RECEIVE_KEYS = 256` with transport admission and
  incomplete-transfer cleanup so a hostile peer cannot exhaust the encrypted
  row.

### New scheduled-cover core: implemented and focused tests pass

New files:

- `src/handlers/coverScheduler.ts`
- `src/handlers/coverScheduler.test.ts`

The core deliberately has no store, DB, DOM, or WebRTC dependency. Public
surface:

```ts
new CoverScheduler({
  schedule,
  clock,
  laneFactory,
  makeDummy,
  maxTimerDriftMs?,
  onStatusChange?,
  onJobResult?,
  onJobInterrupted?,
})

scheduler.start()
scheduler.stop()
scheduler.suspend(reason?)
scheduler.resume()
scheduler.enqueue(job)
scheduler.cancel(jobId)
scheduler.complete(jobId)
scheduler.getStatus()
scheduler.getQueuedJobIds()
```

Important scheduler semantics already covered by 6 passing tests:

- validates `C × F × D` geometry, max 16 lanes, and at least 25 ms slot spacing;
- derives cycles from an absolute phase offset;
- staggers `C × F` cells deterministically within each epoch;
- selects one queued control/real job per lane for a whole cycle;
- prioritizes cancel, then control, then real jobs;
- producers are lazy (`nextCell(slot)`), avoiding a multi-gigabyte frame matrix;
- declared job size must fit `F × D`;
- pre-admission cancel removes the job;
- admitted cancel uses `cancelCell` then leaves a dummy tail;
- completion leaves a dummy tail;
- backpressure/send failure/missed deadlines degrade without a catch-up burst;
- an unsent exact producer cell is retained for retry rather than regenerated;
- suspension closes only at the boundary and resume targets a future cycle.

The scheduler is only the clock/admission core. The following production pieces
do not exist yet:

- authenticated fixed-size dummy/CANCEL/terminal-receipt cover-cell codec;
- a `CoverRuntime` WebRTC adapter;
- neutral/constant-shape lane labels and `RTCDataChannel` lifecycle;
- integration into `handleOpenChannel`, `handleSendMessage`,
  receipt processing, cancellation, and disconnect cleanup;
- browser visibility/freeze/pagehide/offline hooks;
- packet-trace and direct-versus-TURN validation;
- UI status reporting;
- tests proving exactly `C × F × D` 65,490-byte cells on every edge.

### Room policy and signaling state

`src/roomPolicy.ts`/tests now use wire version 4 and enforce:

- maximum 16 cover lanes;
- minimum 25 ms between individual scheduled slots;
- existing room-wide cadence/lane/frame/duration validation.

Do not assume this means scheduled rooms connect. `src/index.ts` still contains:

```ts
if (policy.coverMode !== "immediate")
  throw new Error("Scheduled-cover room connections are not wired yet");
```

Keep that fail-closed guard until all send/receive/receipt/cancel/suspension
paths actually use the scheduler. Removing it early would falsely advertise
cover while the existing path bursts and closes channels.

Other protocol-version work still required:

- `src/utils/protocolVersion.test.ts` still explicitly expects `3`.
- Numerous comments/error strings say protocol v3. Some are historical domain
  names (for example receipt-token v1) and must not be mechanically renamed;
  others describe the live frame and should be updated after wiring.
- `src/handlers/handleWebSocketMessage.ts` now expects protocol version 4 in
  parsed messages, but close-reason strings still say v3.
- Check the sibling signaling server's accepted version contract before the
  browser E2E. No server v4 change was made in this session.
- The authenticated room policy KAT almost certainly needs recalculation after
  the wire-version byte change; run `bun test src/roomPolicy.test.ts`.
- Confirm the full canonical room policy is carried by the invite/site path.
  This session did not edit `p2party.com`.

### Public `createSession()` is currently inconsistent and must be repaired

`src/session.ts` exposes protocol version 4 because it reads the global
constant, but:

- `SESSION_SNAPSHOT_VERSION` is still 3;
- suite-tag constant names still end in `_V3`;
- snapshots contain only the Double Ratchet;
- the constructor still accepts only a ratchet state/module;
- `encrypt()` does not pass a PQ message context to `sealChunk`;
- `decrypt()` does not pass a PQ epoch resolver;
- `createSession()` captures the handshake's PQ root/binding and immediately
  wipes them instead of transferring ownership into the session;
- there is no public control-exchange surface for sparse healing.

Do not paper over this by changing only comments/version numbers. A correct v4
session snapshot must include the PQ state and active combined receive keys,
and restoration must reject v3 snapshots. Decide a store-free control API for
custom transports, for example explicit `prepareHealing()` /
`acceptControlFrame()` plus exact pending-control retrieval, or an injected
persistent control transport. The API must make the persist-before-send
boundary possible for non-browser consumers. Continue to support Node/Bun and
custom native shells without Redux, DB, DOM, or WebRTC.

### Current verification: exact commands and failures

Last known fully green pre-v4 baseline at commit
`fb57b1e6d39b0ee25c4dd7815d20c402a02e2bf3`:

```text
npm run check
333 pass / 0 fail / 12,142 expects
npm run typecheck clean
bun run examples/standalone-e2ee.ts -> OK
```

Diagnostics run immediately before writing this handoff:

```sh
npm run typecheck
```

Result: exit 2, with the eight `pqHealingRuntime.ts` errors listed above.

Focused command:

```sh
bun test \
  src/cryptography/pqHealing.test.ts \
  src/cryptography/pqHealingFrame.test.ts \
  src/cryptography/pqMessageKey.test.ts \
  src/handlers/messageChunkCrypto.test.ts \
  src/handlers/chunkFrame.test.ts \
  src/handlers/coverScheduler.test.ts \
  src/db/ratchetWrap.test.ts \
  src/db/db.worker.test.ts \
  src/db/src/getDB.test.ts
```

Result:

```text
78 pass
8 fail
534 expect() calls
```

All eight failures are in `messageChunkCrypto.test.ts`:

1. two-chunk round trip returns `ok: false`;
2. explicit v4 PQ epoch round trip returns `ok: false`;
3. good frame after corrupted-frame rollback returns `ok: false`;
4. AEAD-authentic/bad-Merkle case does not advance;
5. reconcile re-seal returns `ok: false`;
6. injected receive-persistence failure is not reached because decrypt did not
   authenticate;
7. restored active multi-chunk key case returns `ok: false`;
8. real-first completion never reports the first real cell complete.

The common symptom is exactly what an old C/WASM parser produces when TS sends
the new 69-byte header/AAD. Rebuild the WASM before investigating higher-level
ratchet logic. If failures remain after a retained rebuild, verify these exact
offsets on both sides:

```text
AAD clear prefix: bytes [0, 57)
nonce:            bytes [57, 69)
ciphertext:       bytes [69, 65490)
```

`git diff --check` was clean before the handoff append. No full `bun test`,
`npm run check`, standalone example, browser crypto, or full WebRTC run has
passed on this WIP tree. Do not record a green checkpoint until they do.

### Precise continuation plan

Execute in this order; each step has a local gate.

#### 0. Safety and inventory

```sh
cd /Users/deliberative/Desktop/@p2party/p2party-js
git status --short --branch
git stash list
git rev-parse HEAD
git rev-parse master
```

Confirm branch and both stashes. Read this section plus
`docs/protocol-v4-pq-cover-architecture.md`. Do not switch branches or touch
Postgres.

#### 1. Make the store-free PQ runtime compile and prove it independently

Fix the exact generic/null errors described above. Add
`pqHealingRuntime.test.ts` with the durable-boundary, replay, retry, restore,
wipe, and all-suite matrix. Do not add Redux/DB/WebRTC imports to the class.

Gate:

```sh
npm run typecheck
bun test src/handlers/pqHealingRuntime.test.ts \
  src/cryptography/pqHealing.test.ts \
  src/cryptography/pqHealingFrame.test.ts \
  src/cryptography/pqMessageKey.test.ts
```

#### 2. Rebuild the native v4 receive artifact and recover the crypto tests

```sh
npm run prebuild
bun test src/utils/constants.test.ts \
  src/handlers/chunkFrame.test.ts \
  src/cryptography/pqMessageKey.test.ts \
  src/cryptography/pqHealingFrame.test.ts \
  src/handlers/messageChunkCrypto.test.ts
npm run typecheck
```

Keep the correctly regenerated artifacts. Verify the C/TS constant-agreement
test and SRI/provenance update. If `libcrypto.js` cannot instantiate under Bun,
fix the explicit `wasmBinary` loader/environment path rather than restoring the
old v3 WASM.

#### 3. Install the PQ runtime atomically during every WebRTC handshake

In `runHandshake`:

1. derive stable role as already done;
2. create `SparsePqHealingState` from `result.pqHealing`, selected `pqMode`,
   `state.rootSuite`, and the role;
3. install a candidate serializer before
   `persistAndActivateClaimedRatchetState`;
4. persist ratchet plus initial PQ checkpoint in the same row;
5. in the synchronous activation callback, install both `epc.ratchetState` and
   `epc.pqHealingState`, then open the gate;
6. wipe/destroy every untransferred PQ root/binding/runtime on all failure and
   stale-lease paths;
7. make disconnect teardown destroy both ratchets, active keys, outbox/replay
   caches, timers, and waiter gates.

Add focused handshake tests proving persistence receives non-null edge state
and no PQ secret survives an injected persistence/open-gate failure.

#### 4. Make DR messages actually use and persist the PQ epoch

1. Add typed PQ runtime/context fields to `IRTCPeerConnection`.
2. Send path: wait for the PQ traffic gate, step the DR durably, obtain the
   current context, and pass it to every `sealChunk`.
3. Receive path: parse epoch first, resolve through PQ state, and pass the
   resolver into `decryptMessageChunk`.
4. Alias `epc.messageKeyCache` to the PQ runtime's separate active receive-key
   map, or clone/adopt it as one edge candidate.
5. Remove the current insertion of a combined key into
   `candidate.skipped`.
6. Extend `mutateRatchetDurably` so the exact staged active-key map is included
   in the encrypted edge checkpoint before plaintext/cache publication.
7. On complete/cancel, durably remove the active combined key and only then
   wipe the RAM copy.
8. Count one application message per logical DR step, never per chunk or
   retransmit.

Gate with first-chunk/cache-hit, restart-mid-message, persistence-failure,
wrong-epoch-before-clone, and concurrent send/receive/PQ-lock tests.

#### 5. Add the live sparse-healing orchestrator

Wrap the store-free state with a WebRTC owner that:

- serializes all transitions through `withEdgeCryptoMutationLock`;
- clones PQ state, mutates/authenticates, persists ratchet plus candidate edge
  state, adopts, then dispatches exact bytes;
- routes `FRAME_TYPE_PQ_CONTROL` only on authenticated transport/cover lanes;
- blocks new application admission during any non-idle phase;
- waits for real message channels to become quiescent before local initiation;
- starts a due exchange at 64 logical messages or 24 hours only when the local
  role owns the turn;
- retransmits the persisted exact frame every 5 seconds;
- persists retry metadata;
- after 8 failed attempts, fails/reconnects the authenticated edge rather than
  generating a replacement or falling back;
- uses the main DataChannel in immediate mode;
- enqueues a control job into scheduled cover mode;
- handles exact duplicate OFFER/ADVANCE with exact cached responses;
- treats different bytes in the same authenticated counter/epoch slot as a
  fatal fork.

Add an in-memory two-peer fault-injection E2E that drops each flight and injects
storage failure at every boundary.

#### 6. Build the authenticated cover-cell codec

Before WebRTC integration, define/test one exact 65,490-byte
`FRAME_TYPE_COVER` cell for dummy, CANCEL, and terminal receipt/control
subtypes. It must be directional, suite/edge/epoch bound, padded, and AEAD
authenticated. Do not send unauthenticated random bytes as dummy cells. Do not
reuse the 65-byte immediate receipt on a scheduled lane.

The receiver must be able to distinguish subtypes only after authentication.
Bind cancel/receipt to the transfer identity and root so a cell from another
lane/room/edge cannot terminate work.

#### 7. Add the WebRTC cover adapter without weakening immediate mode

Create a `CoverRuntime` around `CoverScheduler`:

- derive the absolute phase from authenticated room policy/hash;
- open exactly the configured lanes at every boundary on every peer edge;
- give dummy and real lanes constant-shape labels/lifecycle;
- enforce 65,490 bytes at the adapter boundary;
- use `bufferedAmount`/`bufferedamountlow` without late bursts;
- close only at the fixed cycle boundary;
- prohibit WebSocket payload fallback;
- surface `starting|active|degraded|suspended|stopped`;
- attach/detach browser visibility, freeze, pagehide, online/offline listeners;
- skip missed epochs and resume only in a future cycle.

Preserve the product's per-message-channel UX by assigning one admitted
message to one scheduled lane for the whole cycle. A dummy lane should use a
plausible same-shape random root label; a real lane can use its existing
Merkle-root label because labels are peer-visible but not signaling-server or
network-observer plaintext. Validate this assumption against actual SCTP/SDP
behavior.

#### 8. Refactor send, receive, receipt, completion, and cancel as one unit

Immediate mode stays as it is, except for mandatory PQ combination.

Scheduled mode:

- `handleSendMessage` creates a lazy cover job instead of calling
  `sendChunks()` in a burst;
- each scheduled slot loads/stages/seals at most one chunk;
- declared chunk count must fit `F × D`, otherwise fail before admission;
- reconcile work is scheduled, not burst;
- a terminal receipt is queued in a reverse scheduled control slot;
- normal completion does not close early or emit an extra immediate receipt;
- `cancelMessage` calls scheduler cancellation for every active peer job,
  updates local UI/data, sends CANCEL in the next slot, and does not use
  `disconnectFromChannelLabel` as the wire signal;
- receive-side channel close in scheduled mode never means remote cancel;
- tails remain dummy through the boundary;
- disconnect cleanup differentiates real message lanes from cover lanes.

Only after all these paths are tested should `connect()` stop rejecting
`coverMode: "scheduled"`.

#### 9. Repair the public session API and snapshots

Bump the session snapshot format to 4 and include:

- authenticated suite/binding;
- PQ machine/root/epoch/turn/counters;
- pending exact control state if exposed;
- active combined receive keys;
- DR state.

Make `.encrypt()`/`.decrypt()` always use the PQ context at epoch zero and
after healing. Add a store-free sparse-healing API with an explicit
persist-before-send contract. Verify source and installed-package Node ESM,
CJS, Bun, and browser examples. Continue wiping X25519/PQ/DR secrets on every
failure path.

#### 10. Protocol-wide cleanup and exact verification

Update tests/comments/version contracts intentionally, including
`src/utils/protocolVersion.test.ts`. Recalculate room-policy KATs. Check the
server and frontend version handling. Do not mechanically rename historical
v3 receipt/KDF domains unless the protocol design explicitly requires a new
domain.

Run continuously:

```sh
bun test
npm run typecheck
bun run examples/standalone-e2ee.ts
git diff --check
git stash list
```

Final source gate:

```sh
npm run check
```

Then run a real packet-timed browser E2E:

- immediate room, both directions and responder-first;
- scheduled room idle for multiple cycles;
- scheduled message/cancel/complete with identical lane lifetime;
- large file exactly at capacity and one cell above capacity;
- browser suspension and future-boundary resume;
- PQ OFFER/ADVANCE/ACK with a dropped flight and exact retry;
- n=3 full mesh;
- direct and TURN captures;
- zero WebSocket payload fallback.

Do not claim packet-trace indistinguishability from equal application cells
alone; SCTP/DTLS fragmentation, congestion, retransmission, and channel events
must be measured.

#### 11. Version, package, frontend, and merge only after green

This feature is a new incompatible protocol release; use a new package version
(the prior user direction was “new version for these things”; `0.13.0` is the
natural next candidate unless the maintainer chooses otherwise).

After all source/browser gates:

```sh
npm run predist
npm run build:package
npm run build:worker
npm pack
```

Install the exact tarball in `p2party.com`, update its verifier/provenance and
self-hosted WASM, expose room-wide cover selection/status and the standalone
session demo, then run frontend lint/typecheck/build/tests and exact-artifact
WebRTC E2E. Keep the retro hacker/cat brand and AGPL frontend license.

Commit on the feature branch. Verify both stashes. Fast-forward local `master`
only after the exact-artifact gates pass, using a compare-and-swap update rather
than branch switching if the no-checkout constraint remains. Production deploy
and CDN/npm publication still require the maintainer's deployment credentials
and explicit release action.

### Honest current claim boundary

At this checkpoint:

- canonical sparse-PQ state-machine, ACK, snapshot primitives, fixed control
  cells, v4 message-key combiner, v4 source wire geometry, encrypted edge-field
  wrapping, and the store-free scheduled clock/admission core exist;
- live WebRTC sparse healing does not exist;
- live scheduled dummy lanes do not exist;
- messages do not yet use the derived PQ root;
- the standalone session does not yet use or persist PQ state;
- `connect()` still rejects scheduled cover;
- current typecheck and message crypto tests are red;
- no protocol-v4 tarball, browser result, deployment, paper result, L2, or P2BT
  implementation should be claimed.

The likely paper-worthy systems finding remains conditional on finishing and
measuring the complete composition: fixed-size application cells can absorb
PQ/ratchet control overhead and allow real/control/cancel traffic to substitute
for already-scheduled dummy slots at zero **marginal scheduled
application-cell** cost. Never call the cryptography or network cost universally
“free,” and never claim anonymity or packet-trace indistinguishability without
the L2b and capture/classifier evidence.

## SESSION 2026-07-24 (resumed) — PROTOCOL-V4 CONTINUATION, STEPS 1–2 GREEN

Executed from the WIP checkpoint `038ede4` following the precise continuation
plan above. Both `master` stashes verified before and after every commit.

### Step 1 done — sparse-PQ runtime compiles, is coherent, and is fully tested

Commit: `9a0f943` ("fix: make the sparse-PQ runtime compile, coherent, and
fully tested").

- Fixed the exact eight TypeScript errors: the suite-erased machine is typed
  `PqHealingMachine<MlKemParameterSet>`, the `phase` getter uses
  `PqHealingPhase`, and each outbox branch captures a non-null local so
  narrowing survives `await`s.
- Fixed two real defects found while writing tests:
  1. the ACK-receipt branch never cleared `#lastInboundOfferFrame`, so a
     completed exchange serialized a checkpoint that its own
     `#validateCheckpointCoherence` rejected on restore;
  2. `writeActiveKeys` accepted non-canonical cache keys that
     `readActiveKeys` would reject, poisoning the persisted checkpoint;
     serialization now fails closed first.
- Fixed a latent `noImplicitReturns` error in `coverScheduler.test.ts` that
  the previously red source project had masked.
- Added `src/handlers/pqHealingRuntime.test.ts` (13 tests): all three
  ML-KEM suites end-to-end with byte-identical roots and alternating turns,
  byte-exact serialize/restore at every durable boundary, clone-discard
  rollback with byte-identical live checkpoints, exact dropped-flight
  retransmission for OFFER/ADVANCE/ACK, duplicate-vs-fork classification,
  wrong suite/binding/direction/epoch fail-closed, active-key wipe on
  adopt/destroy, retry exhaustion without replacement records, and
  checkpoint truncation/trailing/corruption/duplicate-key/over-budget
  fail-closed cases.

Gate result: `npm run typecheck` clean;
`bun test pqHealingRuntime pqHealing pqHealingFrame pqMessageKey`
37 pass / 0 fail / 501 expects.

### Step 2 done — v4 WASM rebuilt and retained, message crypto recovered

Commit: `ae5a140` ("feat: rebuild the protocol-v4 receive WASM and settle
version contracts").

- `npm run prebuild` regenerated `libcrypto.js` + `libcrypto.wasm` +
  provenance; the retained artifact authenticates the v4 69-byte
  header/AAD. All eight `messageChunkCrypto` failures recovered.
- The first rebuild could not instantiate under Bun: the development
  artifact (ASSERTIONS=2) emits emscripten's minimum-runtime environment
  check, which throws when `process.versions.node` exists. Fixed exactly as
  the prior handoff prescribed — the environment path, not the artifact:
  `scripts/emscripten.js` now sets `ENVIRONMENT=web,worker,node` for the
  development verification artifact only; the production/predist artifact
  remains `ENVIRONMENT=web,worker`.
- `wasmLoader.ts` SRI pin and `libcrypto.provenance.json` verified to match
  the retained wasm (sha256/sri recomputed independently). The `.wasm`
  binary itself is gitignored by design; only wrapper/provenance/pin are
  tracked.
- Intentional v4 contract updates pulled forward from step 10 to keep the
  tree green: `protocolVersion.test.ts` now expects exactly 4 and rejects
  3/5; the room-policy KAT was recomputed with the live encoder — encoding
  `5032525001040001…` (only byte 5 changes, 0x03→0x04), hash
  `9b0bf1033f93ae9b1b57f3771ca146ae13709c49d2d975d83a0adf2c311221fd`.

Gate result: full `bun test` 369 pass / 0 fail / 12,626 expects;
`npm run typecheck` clean; `bun run examples/standalone-e2ee.ts` → OK.
`git diff --check` reports only a blank EOF line inside the generated
`libcrypto.js` (emcc output, not hand-written).

### Still true after steps 1–2

- Live WebRTC sparse healing, scheduled dummy lanes, PQ-combined messages,
  and the v4 session snapshot do not exist yet; `connect()` still rejects
  scheduled cover; no tarball/browser/deploy claims.
- Next: continuation plan step 3 (install the PQ runtime atomically in
  `runHandshake`), then step 4 (PQ epoch on the DR message paths).

### Steps 3–4 done — PQ runtime installed by the handshake; messages use the epoch

Commits: `0f0850b` (step 3), `f5e9dad` (step 4).

Step 3 (atomic handshake install):

- `createHandshakePqRuntime` consumes the handshake PQ bootstrap (wipes the
  root/binding buffers on every path); `persistAndActivateEdgeCrypto`
  installs the candidate serializer BEFORE the initial row write, persists
  ratchet + initial `P2EDGE4` checkpoint in one row, then synchronously
  installs `epc.ratchetState` + `epc.pqHealingState` + aliases
  `epc.messageKeyCache = runtime.activeReceiveKeys` after the lease/gate
  checks. Failure removes the hook, rolls the seed row back, and
  runHandshake's finally destroys the untransferred runtime. Disconnect
  teardown destroys the runtime and clears the hook.
- Tests: first persisted row carries a byte-exact-reproducible non-null
  checkpoint; injected persistence/open-gate failures install nothing; a
  replacement handshake destroys/wipes the previous edge crypto.

Step 4 (PQ epoch on the message paths):

- Send: `sendWithReconcile` waits on the runtime traffic gate (bounded
  poll until the step-5 orchestrator lands), `ratchetEncryptDurably`
  returns an OWNED `pqContext` captured inside the edge transaction and
  counts one application message per logical DR step (commit hook); every
  `sealChunk` (initial/retransmit/rebind) gets the context; wiped with the
  message key.
- Receive: epoch parsed first and resolved through the runtime before any
  clone; cache identity `(dhPub, N, pqEpoch)`; combined keys live ONLY in
  `runtime.activeReceiveKeys`, persisted via the new
  `stageEdgeCryptoState` staged-serializer override in
  `mutateRatchetDurably` (same row as the ratchet successor, before RAM
  publication); `candidate.skipped` insertion removed on the runtime path
  (kept only for runtime-free bootstrap/test edges);
  `forgetReceiveMessageKeyDurably` retires from the staged checkpoint
  before wiping RAM; anti-DoS cache bound enforced pre-decrypt so the
  staged map never exceeds the 256-key checkpoint budget.
- Tests: checkpoint-carried keys (restored row + restored runtime decrypt
  the rest of a message with NO re-combination), unknown-epoch rejection
  before mutation/persistence, persistence-failure containment, durable
  retirement idempotence, concurrent send/receive under one lock.

Gate: full `bun test` 379 pass / 0 fail; typecheck clean; standalone
example OK; both master stashes intact.

Remaining after step 4: live healing orchestrator (5), cover codec (6),
CoverRuntime (7), scheduled transfer refactor (8), session API v4 (9),
cleanup + full verification (10), version/package/frontend (11).

### Step 5 done — live WebRTC sparse-healing orchestrator

Commit: `d5d2ad9`.

- New `src/handlers/pqHealingOrchestrator.ts` (WeakMap per connection):
  due-time initiation (64 msgs/24 h, local turn only, quiescent boundary
  only — zero live message channels + drained inbound edge queue via new
  `hasQueuedEdgeReceiveWork`/`waitForEdgeReceiveQuiescence` exports),
  durable 5 s × 8 exact-frame retransmission, inbound OFFER/ADVANCE/ACK.
- Transition discipline: clone → mutate/authenticate → persist unchanged
  ratchet + candidate `P2EDGE4` checkpoint in ONE row
  (`persistClaimedRatchetState` gained an edge-serializer override) →
  adopt → dispatch, all inside `withEdgeCryptoMutationLock`. Adoption
  re-aliases `epc.messageKeyCache` (adopt() moves the map object).
- Duplicates answered from the persisted cache with NO write; storage
  failures are transient (`PqPersistenceError`) and recovered by exact
  retransmit; retry exhaustion + forks fail the authenticated edge
  (close → normal reconnect/fresh handshake; never a fallback).
- `FRAME_TYPE_PQ_CONTROL` routed ONLY on the authenticated main channel
  behind the open ratchet gate (full unstripped 65,490-byte cell);
  orchestrator installed right after `runHandshake`, destroyed first in
  disconnect teardown; send admission consults
  `isPqApplicationTrafficBlocked` (machine phase + inbound gate).
- Two-peer in-memory E2E (9 tests): full exchange persist-before-send,
  quiescence gating, all three dropped flights byte-exact, storage
  failure at all four durable boundaries, exhaustion, fork, checkpoint
  restore. Full suite: 388 pass / 0 fail; typecheck clean; stashes intact.

Production sparse PQ healing (continuation plan steps 1–5) is COMPLETE for
immediate mode. Remaining: cover codec (6), CoverRuntime (7), scheduled
transfer refactor (8), session API v4 (9), cleanup/verification (10–11).

### Steps 6–9 done — cover cores, scheduled substrate, and the v4 session API

Commits: `2b68911` (cover-cell codec), `a02f579` (CoverRuntime),
`257e93f` (scheduled transfer substrate), `f1a3a92` (session API v4).

Step 6 — `src/cryptography/coverCell.ts`: one exact 65,490-byte
`FRAME_TYPE_COVER` cell (dummy / CANCEL / receipt) keyed from the current
epoch's PQ message root, domain-separated by suite/binding/direction/epoch;
subtype inside the ciphertext; CANCEL/receipt bound to the transfer root.

Step 7 — `src/handlers/coverRuntime.ts`: wraps CoverScheduler with the live
transport surface — absolute phase from the policy hash, exact lanes per
boundary, constant-shape labels, 65,490-byte enforcement, bufferedAmount
backpressure, boundary-only close, no WS fallback, sliding-window inbound
replay guard tolerating cross-lane reorder, browser
visibility/pagehide/freeze/offline suspend + future-cycle resume + surfaced
status.

Step 8 — `src/handlers/coverTransfer.ts`: `buildScheduledSendJob` (one
staged chunk per slot, F×D admission, un-acked-once then dummy tail),
per-edge scheduled receipt queue drained by a re-arming control job,
`cancelScheduledTransfer` routing to the scheduler; `handleOpenChannel`
routes inbound `FRAME_TYPE_COVER` to the runtime and a scheduled-mode
channel close is NEVER a remote cancel; disconnect teardown destroys the
CoverRuntime and wipes queued receipts.
**The `connect()` guard against `coverMode: "scheduled"` is intentionally
KEPT** — the live lane-channel wiring (CoverRuntime creating real
RTCDataChannels, feeding message chunks through the scheduler instead of the
immediate `sendWithReconcile`) and its browser E2E are NOT done; removing it
early would falsely advertise cover.

Step 9 — `src/session.ts`: the store-free Session owns a
`SparsePqHealingState`; encrypt/decrypt use the PQ epoch and block during
healing; snapshot format bumped to 4 (rejects v3) with the appended P2EDGE4
checkpoint; a store-free `prepareHealing`/`acceptControlFrame`/
`pendingControl` control API with an explicit persist-before-send contract;
the standalone example drives a healing exchange to epoch 1.

Gate after step 9: `bun test` 414 pass / 0 fail; `npm run typecheck` clean;
`bun run examples/standalone-e2ee.ts` OK (reaches PQ epoch 1); both master
stashes intact.

### Honest claim boundary after steps 1–9

- COMPLETE and tested: production sparse-PQ healing in immediate mode
  (handshake install → PQ-combined messages → live WebRTC orchestrator),
  the v4 wire/WASM, the scheduled-cover CORES (scheduler, authenticated
  cover-cell codec, CoverRuntime adapter), the scheduled-transfer SUBSTRATE
  (send job, receipts, cancel, inbound routing, close semantics), and the
  v4 public session API + snapshot with store-free healing.
- NOT yet wired/claimed: live scheduled cover lanes end to end
  (CoverRuntime installation on scheduled edges + real RTCDataChannel lane
  wiring + scheduled send replacing the immediate path); `connect()` still
  rejects scheduled cover; no protocol-v4 tarball, browser E2E result,
  deployment, or paper result.
- Remaining continuation-plan work: finish the live scheduled lane wiring
  and its focused tests, THEN remove the `connect()` guard (step 8 tail);
  protocol-wide cleanup + full browser E2E (step 10); version/package/
  frontend + merge (step 11).
