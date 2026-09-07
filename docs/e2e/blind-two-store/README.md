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
