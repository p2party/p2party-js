# Protocol-v4 browser verification harnesses

Real headless-Chromium E2E harnesses used to verify protocol v4 over **real
WebRTC** (real `RTCPeerConnection` + DTLS/SCTP DataChannels). Preserved here
from the session scratchpad so they survive. They reference absolute paths on
the author's machine (`/Users/deliberative/Desktop/@p2party/...`) and the
`playwright-core` + cached Chromium under `p2party.com/node_modules` and
`~/Library/Caches/ms-playwright`; adjust paths if the tree moves.

All runs use the **development** WASM (`src/cryptography/libcrypto.wasm`,
`ENVIRONMENT=web,worker,node`, SRI-pinned in `wasmLoader.ts`). Do NOT run
`npm run predist` before these — it overwrites that artifact with the
web-only production build that cannot instantiate under Bun.

## `webrtc-e2e/` — session-API + CoverRuntime over real WebRTC

Bundles `src/session.ts` (and, for cover, the `CoverRuntime`) with
`bun build --target=browser`, drives N browser pages with a Node-side
SDP/ICE relay via `page.exposeFunction`.

- `entry.ts` + `mesh.mjs` — the store-free session API mesh: real handshake,
  byte-exact multi-chunk messaging, and a full sparse-PQ OFFER/ADVANCE/ACK
  healing exchange to a shared epoch, at **n=2, n=3, n=4**.
  Run: `bun build entry.ts --target=browser --outfile=bundle.js --define:process.env.NODE_ENV='"production"'`
  then `PLAYWRIGHT_BROWSERS_PATH=~/Library/Caches/ms-playwright node mesh.mjs`.
- `entry-cover.ts` + `cover.mjs` — the real `CoverRuntime` over real
  RTCDataChannel lanes: fixed C×F×D authenticated dummy cover cells, a real
  receipt-subtype cover cell, and a real ratchet+PQ **message chunk decrypted
  byte-exact** over a cover slot. `cover.html` stubs `document.visibilityState`
  because headless Chromium reports the page hidden (which the runtime
  correctly treats as a cover gap).
- `diag.mjs` / `index.html` — a minimal single-edge diagnostic and the shared
  page shell (process shim + bundle).

Key learning baked into the harness: the initiator must create a bootstrap
DataChannel **before** the SDP offer or no SCTP transport is negotiated and
lanes never open. In production the `main` channel plays that role.

## `appstack/` — the FULL app stack (Redux + IndexedDB + WebRTC)

Drives the real `p2party` public API end to end in the browser.

- `relay.ts` (Bun) — a minimal signaling relay: `?publickey=` upgrade →
  peerId challenge → accept (no crypto verify) → roomId → peers roster →
  route description/candidate/connection by `toPeerId`. Replaces the
  Postgres-backed `../server` so no DB is touched.
- `app-entry.ts` — bundles `src/index.ts` `p2party`; the DB worker is injected
  via `process.env.INDEXEDDB_WORKER_JS` from a `worker-inject.js` generated
  out of `npm run build:worker`'s `lib/db.worker.js`; serves the dev WASM whose
  SRI matches the `wasmLoader` pin; forces loopback rtcConfig (no STUN).
- `app-driver.mjs` — two pages each `connect()` → verify + discover →
  `sendMessage()` (which internally awaits the PACE + Double-Ratchet handshake)
  → `readMessage()` on the peer, asserting byte-exact for **immediate, PIN, and
  scheduled-cover** rooms.
- `app.html` — process shim + `worker-inject.js` + `app-bundle.js` +
  visibility stub.

To rebuild `worker-inject.js`:
```
npm run build:worker   # → lib/db.worker.js
node -e 'const fs=require("fs");const w=fs.readFileSync("lib/db.worker.js","utf8");fs.writeFileSync("worker-inject.js","window.process=window.process||{env:{}};window.process.env.INDEXEDDB_WORKER_JS="+JSON.stringify(w)+";")'
cp src/cryptography/libcrypto.wasm .   # into the appstack dir
```
Run: `bun build app-entry.ts --target=browser --outfile=app-bundle.js --define:process.env.NODE_ENV='"production"'`
then `PLAYWRIGHT_BROWSERS_PATH=~/Library/Caches/ms-playwright node app-driver.mjs`.

## Latest results (2026-07-25)

- session mesh: n=2 / n=3 / n=4 all PASS.
- cover lanes: real cover cells authenticated + real chunk decrypted byte-exact.
- full app stack: immediate / PIN / scheduled all deliver byte-exact.

## `frontend-audit-report.md`

The synthesized multi-agent UI/UX + v3/v4-wiring audit of `p2party.com`.
