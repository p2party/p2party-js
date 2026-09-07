# Blind two-store rendezvous — browser harnesses

Headless-Chromium harnesses for the **flagged prototype** of the two-store
blind rendezvous (`src/blindRendezvous/prototype/`, design:
`docs/blind-rendezvous-two-store-prototype-design.md`). Nothing here is a v0.4
release byte.

As with the other harnesses in `docs/e2e/`, these reference absolute paths on
the author's machine (`playwright-core` and the cached Chromium under
`p2party.com/node_modules` and `~/Library/Caches/ms-playwright`); adjust if the
tree moves. They run against the **development** WASM
(`src/cryptography/libcrypto.wasm`, SRI-pinned in `wasmLoader.ts`) — do NOT run
`npm run predist` first, it overwrites that artifact with the web-only
production build.

## `provider-smoke.*` — the WebRTC transport provider on its own

Proves `src/blindRendezvous/prototype/webrtcProvider.ts` in isolation: no store,
no carrier runtime, no pair driver. Two providers in **one page** hand each
other offer and answer by direct call (there is no signaling server anywhere in
this test), and everything downstream of that is real.

What one run asserts:

1. an initiator and a responder provider over `{ iceServers: [] }` — loopback
   host candidates only;
2. `createOffer` → `acceptOffer` → `acceptAnswer`, each with **complete** ICE
   gathering, exchanged as the exact UTF-8 SDP bytes;
3. both data channels `open` and both `connectionState === "connected"`;
4. the SHA-256 DTLS fingerprint parsed out of each side's exact SDP bytes
   (`src/utils/sdpFingerprint.ts`) matches the live certificate `getStats()`
   reports — `verifyCertificates` returns `"verified"` on both sides
   (`"unsupported"` is also accepted, for engines that report no certificate
   stats: that is Firefox, not Chromium);
5. a real protocol-v4 `createSession` on **both** sides over
   `dataChannelTransport(channel)`, `mode: "nopin"`, with the session role taken
   from the byte order of the two Ed25519 identity keys (independent of who
   dialled, so both assignments occur across runs);
6. a multi-chunk message each way — 140,000 bytes A→B (3 chunk frames) and
   90,000 B→A (2 frames) — decrypted **byte-exact** on the peer;
7. a `close()` rejects pending `channel()` and `recvApp()` waiters instead of
   leaving them unsettled.

### Build and run

From the SDK root:

```
bun build docs/e2e/blind-two-store/provider-smoke.ts --target=browser \
  --outfile=docs/e2e/blind-two-store/provider-smoke-bundle.js \
  --define:process.env.NODE_ENV='"production"'
cp src/cryptography/libcrypto.wasm docs/e2e/blind-two-store/
PLAYWRIGHT_BROWSERS_PATH=~/Library/Caches/ms-playwright \
  node docs/e2e/blind-two-store/provider-smoke.mjs
```

`provider-smoke-bundle.js` and `libcrypto.wasm` are generated — do not commit
them. Static server on port 5921 (`SMOKE_PORT` overrides); the run deadline is
`SMOKE_TIMEOUT_MS` (default 180 s). The driver prints the JSON result and exits
non-zero on any failure.

### Two environment facts the harness depends on

- **`--disable-features=WebRtcHideLocalIpsWithMdns`.** Chromium otherwise
  replaces host candidates with `<uuid>.local` mDNS names, and this headless
  sandbox has no mDNS responder. Because the blind profile is complete-gathering
  (the candidates ride inside the single SDP blob; there is no trickle channel),
  an unresolvable remote candidate is simply dropped and both connections sit at
  `iceConnectionState: "new"` forever with zero candidate pairs. Verified: with
  the flag, ICE connects in under 500 ms; without it, never.
  `docs/e2e/desync/probe-ice.mjs` carries the same flag for the same reason.
- **`<script type="module">` in `provider-smoke.html`.** A browser-target
  `bun build` emits ESM, and the bundled `src/cryptography/wasmLoader.ts`
  contains `import.meta.url` inside a Node-only branch this page never takes — a
  classic script cannot even parse it. The `process` shim stays a classic inline
  script so it still runs before the deferred module.

### Recorded result (2026-09-08, headless Chromium, macOS)

Five consecutive runs, all PASS, ~0.2 s each. One of them verbatim:

```
window.__providerSmoke present (http://localhost:5921/)
{
  "connected": true,
  "connectionStates": { "a": "connected", "b": "connected" },
  "dtls": { "a": "verified", "b": "verified" },
  "bytesExactAB": true,
  "bytesExactBA": true,
  "sdpBytes": { "offer": 694, "answer": 693 },
  "fingerprints": {
    "a": "7c6b2a6892ad2500b9d7a5317fbbb8feb0db94b5313f0078e2a79bd7b89539a7",
    "b": "750c98ea03610facfe71c7079082d5f74e381d50ca4706ac189d0614704f3eea"
  },
  "roles": { "a": "responder", "b": "initiator" },
  "frames": { "ab": 3, "ba": 2 },
  "closeRejectsWaiters": { "channel": true, "recvApp": true },
  "timings": {
    "createOfferMs": 129, "acceptOfferMs": 8, "acceptAnswerMs": 0,
    "connectMs": 4, "verifyCertificatesMs": 1, "identityMs": 7,
    "handshakeMs": 14, "messageAbMs": 27, "messageBaMs": 14, "totalMs": 209
  }
}
PROVIDER SMOKE PASS in 0.2s (dtls verified/verified, 3+2 chunk frames byte-exact)
```

Both identity-role assignments were observed across the five runs (`a` was
`responder` in four and `initiator` in one), which is the point of deriving the
session role from key order rather than from who dialled.

## `entry.ts` / `index.html` / `build.sh` / `run.mjs` — the whole rendezvous

The composition harness: `src/blindRendezvous/prototype/index.ts` wired into a
page, driven against two real store processes. Nothing here is stubbed — two
`bun` store servers with fresh SQLite databases and fresh identity keys, two
headless-Chromium pages that share nothing but a 32-byte room capability, and
**no signaling server anywhere in the test**.

`entry.ts` exposes one object on the page:

```js
window.__blind.run(optionsJson); // {capabilityHex, storeOrigins, rtcConfig, deliveryWindowMs?, wasmUrl?}
window.__blind.send(text, timeoutMs); // waits for `handoff`, then one encrypted message
window.__blind.recv(timeoutMs); // one decrypted message, as text
window.__blind.audit(); // capability / RoomContextId / stable key / both SDPs
window.__blind.topology(); // "multi-store-union" | "single-carrier-dependent" | ...
window.__blind.faults(); // store faults, JSON-safe (windows as decimal strings)
window.__blind.events(); // every event so far, if the driver missed any
window.__blind.stop();
```

Progress is pushed to `window.__blindEvent(json)` when the driver exposed one
(`{atMs, kind, detail?}`); the page still loads and runs standalone when it did
not. The event vocabulary IS the pair driver's phase machine — `presence-published`,
`peer-observed`, `hello-sent`, `hello-opened`, `accepted`, `offer-sent`,
`offer-opened`, `answered`, `handoff`, `failed` — plus `store-connected`,
`store-unreachable`, `store-fault`, `store-missed`, `topology`, `webrtc-role`,
`webrtc-connected`, `dtls-verified` / `dtls-unsupported`,
`session-authenticated`, `session-failed`, `message-sent`, `message-verified`.

What one `run.mjs` run asserts:

1. two store processes on 5910/5911 answer `/health`, with fresh
   `P2PARTY_STORE_DB` and `P2PARTY_STORE_KEY_FILE` in a temp dir and the same
   `P2PARTY_STORE_WINDOW_MS` as the pages (so both derive one profile hash, i.e.
   one bucket);
2. both pages reach `store-connected` for **both** origins and report
   `topology: multi-store-union` from their own completed reads;
3. the full pair exchange completes as pair-sealed operations the stores carry
   blind: `PRESENCE` → `IDENTITY_HELLO` → `IDENTITY_ACCEPT` → `TRANSPORT_OFFER`
   → `TRANSPORT_ANSWER`;
4. WebRTC connects from the exchanged SDP and `verifyCertificates` returns
   `verified` on **both** sides against the fingerprints the pair transcript
   bound;
5. a real protocol-v4 `createSession` authenticates on both sides, with the
   session role taken from the handoff facts;
6. one encrypted application message each way, decrypted **byte-exact**:
   140,005 bytes A→B (3 uniform chunk frames) and 9,005 B→A (1 frame), so one
   run covers both shapes of the app-lane framing;
7. neither store's `P2PARTY_STORE_LOG_BODIES` file contains the capability, the
   `RoomContextId`, either stable Ed25519 public key, or either SDP blob — the
   only privacy statement the run supports, and only about that run;
8. no `failed` phase and no store faults on either page.

### Build and run

From the SDK root:

```
bash docs/e2e/blind-two-store/build.sh
PLAYWRIGHT_BROWSERS_PATH=~/Library/Caches/ms-playwright \
  node docs/e2e/blind-two-store/run.mjs [--window-ms=4000] [--deadline-ms=180000]
```

`bundle.js` and `libcrypto.wasm` are generated — do not commit them. Ports:
5910/5911 for the stores and 5920 for the page server (`--store-a-port`,
`--store-b-port`, `--page-port` override). The driver prints a per-phase timing
table and exits non-zero on any failure.

This file covers the **healthy** path only. Task 9 owns the multi-scenario
driver (`kill-a`, `withhold-a`, `unreachable-b-for-one`, the full wire-log audit
and the latency table); this is its starting point.

### Two facts about the cadence

- **`--window-ms=4000` (the pinned profile) is the only cadence that works on
  this machine.** A store closes a window for ingress at
  `windowStart + chunkFinalizationOffsetMs` — 2,800 ms at the pinned profile,
  which leaves 700 ms of slack after the last append offset (2,100 ms).
  `withDeliveryWindowMs` scales both, so at `--window-ms=2000` the slack is
  350 ms, and every append then arrives after the close: the whole run stalls
  with `append window-finalized` from the first real window on. The cause is
  browser-side cost, not the protocol — each endpoint seals ~344 KB of carrier
  objects and AEAD-attempts ~2.75 MB of scanned objects per window across the
  two stores, and at 2 s that does not fit before the close. The design's §8
  latency table (4000/2000/1000) therefore needs either a smaller
  `publicChunkObjectCount` for the fast profiles or a client that seals ahead of
  its append instant.
- **Cross-origin.** A page is never served from a store's origin, so the store
  now answers with `access-control-allow-origin: *`,
  `access-control-expose-headers: x-p2party-store` (the client refuses any
  answer without that header, and it is not CORS-safelisted), and a 204
  preflight for the `application/p2party-*-prototype-v0` request media types.
  Without those, no browser reaches a store at all.

### Recorded result (2026-09-08, headless Chromium, macOS, `--window-ms=4000`)

Three consecutive runs, all PASS, 39.4 s / 40.2 s / 41.7 s to
`message-verified`. The third verbatim (the per-window `store-missed` cover
lines are elided):

```
store a healthy on 5910 (storeId b0fc6b10be6b9e4c4f16756b71a134334daa53835c97536e0fe4284426589577)
store b healthy on 5911 (storeId 4f10e06cc7454915e580568d6e1046d5bc6fe56d31e5ca1e3872ffa50252a7da)
page server on http://localhost:5920/
both pages loaded (capability 8f16cb4d21a1958d…)
  0.5s [A] store-connected — http://127.0.0.1:5910 …
  0.5s [A] store-connected — http://127.0.0.1:5911 …
  0.5s [A] presence-published
  0.5s [B] presence-published
  2.0s [A] topology — multi-store-union
 10.3s [A] peer-observed   10.3s [B] hello-sent
 18.1s [A] hello-opened    18.2s [A] accepted
 26.2s [B] accepted        26.3s [B] offer-sent
 34.0s [A] offer-opened    34.0s [A] answered     34.0s [A] handoff
 42.2s [B] handoff
 42.2s [A] webrtc-connected — responder   42.2s [B] webrtc-connected — initiator
 42.2s [A] dtls-verified                  42.2s [B] dtls-verified
 42.2s [A] session-authenticated — initiator
 42.2s [B] session-authenticated — responder
 42.2s [A] message-sent — 140005 bytes in 3 frames
 42.2s [A] message-verified — 9005 bytes from 1 frames
 42.2s [B] message-verified — 140005 bytes from 3 frames

phase                     A       B     (seconds after both endpoints armed)
presence-published         0.0s   0.0s
peer-observed              9.8s   9.8s
hello-sent                    —   9.8s
hello-opened              17.7s      —
accepted                  17.7s  25.7s
offer-sent                    —  25.8s
offer-opened              33.6s      —
answered                  33.6s      —
handoff                   33.6s  41.7s
webrtc-connected          41.7s  41.7s
dtls-verified             41.7s  41.7s
session-authenticated     41.7s  41.7s
message-sent              41.7s  41.7s
message-verified          41.7s  41.7s

topology            A=multi-store-union B=multi-store-union
store request bodies logged   a=172 b=174
faults              A=[] B=[]

TWO-STORE E2E PASS in 41.7s (window 4000ms; 140005 bytes A→B and 9005 bytes B→A decrypted byte-exact)
```

Both rendezvous-role assignments were observed across the three runs (`A` was
initiator once and responder twice), which is the point of taking the role from
the byte order of the two presence operation ids rather than from who started
first.

The eight seconds per flight are the profile's own geometry, not overhead: five
dependent flights, each readable one window after it is appended
(`publicReadLagWindows: 1`), plus the cold-start window whose appends are
unallocated cover. `presence-published` → `peer-observed` is two windows, and
each later flight is two more.
