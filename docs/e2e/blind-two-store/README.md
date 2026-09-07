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
window.__blind.counters(); // {appendsReal, appendsDummy, scans, operationsSeen, backfills}
window.__blind.events(); // every event so far, if the driver missed any
window.__blind.stop();
```

Progress is pushed to `window.__blindEvent(json)` when the driver exposed one
(`{atMs, kind, detail?}`); the page still loads and runs standalone when it did
not. The event vocabulary IS the pair driver's phase machine —
`presence-published`, `peer-observed`, `hello-sent`, `hello-opened`, `accepted`,
`offer-sent`, `offer-opened`, `answered`, `handoff`, `failed` — plus
`store-connected`, `store-unreachable`, `store-fault`, `store-missed`,
`topology`, `webrtc-role`, `webrtc-connected`, `dtls-verified` /
`dtls-unsupported`, `session-authenticated`, `session-failed`, `message-sent`,
`message-verified`.

### The four scenarios

```
node docs/e2e/blind-two-store/run.mjs --scenario=<name>
```

| `--scenario`            | what is done to the stores                                                                                                                                                                           | what the run must still do                                                                                                                                                                                                                     |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `healthy`               | nothing                                                                                                                                                                                              | both pages `multi-store-union`, no faults, no `store-unreachable`                                                                                                                                                                              |
| `kill-a`                | store A is `SIGKILL`ed once both pages have published presence **and** A has logged ≥ 1 request body; the kill is then confirmed — the child's exit is awaited and `/health` polled until it refuses | both pages `message-verified` byte-exact each way, both end `single-carrier-dependent`, ≥ 1 fault or `store-missed` event naming A, and every recorded fault is kind `unreachable` against A — nothing naming B, and nothing of any other kind |
| `withhold-a`            | store A runs `P2PARTY_STORE_FAULT=withhold`: it answers `stored` to every append and finalizes dummies                                                                                               | both pages `message-verified` via B, ≥ 1 `custody-breach` against A, **no other fault of any kind**, and both pages drop to `single-carrier-dependent` — the observable consequence of A being marked inert                                    |
| `unreachable-b-for-one` | nothing; page B is _given_ only store A's origin                                                                                                                                                     | page A ends `multi-store-union`, page B `single-carrier-dependent`, page A's `counters.backfills ≥ 1`, and page B issues **zero** requests to store B                                                                                          |

`--scenario=all` (the default) runs all four in order, each on its own port pair
and its own temp database and key files, and prints one summary table. Every
scenario tears down both store processes and the browser on every path,
including a thrown assertion, and the driver exits non-zero if any scenario
fails.

### What every scenario asserts, in every scenario

1. two store processes answer `/health` with **different** store ids, from fresh
   `P2PARTY_STORE_DB` and `P2PARTY_STORE_KEY_FILE` in a per-scenario temp dir,
   at the same `P2PARTY_STORE_WINDOW_MS` as the pages (so both derive one
   profile hash, i.e. one bucket);
2. each page reached `store-connected` for exactly as many origins as it was
   given;
3. the full pair exchange completes as pair-sealed operations the stores carry
   blind: `PRESENCE` → `IDENTITY_HELLO` → `IDENTITY_ACCEPT` → `TRANSPORT_OFFER`
   → `TRANSPORT_ANSWER`;
4. **`dtls-verified` on both pages.** `verifyCertificates` returned `verified`
   against the fingerprints the pair transcript bound. A run where both pages
   reported `dtls-unsupported` fails; before Task 9 it printed a dash and
   exited 0;
5. `session-authenticated` on both pages — a real protocol-v4 `createSession`,
   with the session role taken from the handoff facts;
6. one encrypted application message each way, decrypted **byte-exact**:
   140,005 bytes A→B (3 uniform chunk frames) and 9,005 B→A (1 frame), so one
   run covers both shapes of the app-lane framing. The page hands back decoded
   text, so the harness compares the UTF-8 re-encoding of what arrived against
   the UTF-8 of what was sent — `Buffer.equals`, not string equality. Because
   UTF-8 encode/decode is injective on well-formed input and malformed bytes
   would have decoded to U+FFFD and re-encoded to `EF BF BD`, equal buffers do
   mean the plaintext the peer decrypted was the plaintext that was sent;
7. no `failed` phase and no `session-failed` on either page;
8. the privacy audit below, on **both** stores;
9. the per-scenario expectations in the table above — including the fault sets,
   which are asserted exactly rather than printed.

### The privacy audit, and exactly what it covers

Both stores run with `P2PARTY_STORE_LOG_BODIES`, which appends the hex of every
accepted request body **before parsing**, so the audit sees the bytes that
arrived rather than a re-encoding of what the store made of them.

For each run the harness looks, in every body, for:

- each page's room **capability**, `RoomContextId` and stable Ed25519 key (from
  `window.__blind.audit()`);
- each page's local and remote **SDP**, in full;
- the SDP markers `a=fingerprint`, `a=candidate`, `a=ice-ufrag` and `v=0\r\n`.

Each of those is searched in every encoding a client could plausibly have
produced: the raw bytes, the ASCII of the lower-case hex, the ASCII of the
upper-case hex, the ASCII of base64 and base64url, and — because a marker
embedded in a larger base64 blob starts wherever its byte offset mod 3 puts it —
base64 and base64url at all three alignments. That is 148 distinct byte
needles per run: 14 secrets at 11 encodings each, less the 6 alignment variants
of the 5-byte `v=0\r\n` marker whose stable cores fall below the 8-character
floor.

Five things keep the result from being theatre:

- **A missing or empty log fails the scenario.** So does a log with zero parsed
  bodies. A clean audit over nothing is not a clean audit.
- **A positive control runs over the same bytes with the same matcher.** The
  delivery-profile hash is a field of every allocation-token request body, so it
  _must_ be found; if it is not, the audit is not reading what it thinks it is
  and the scenario fails.
- **The harness cross-checks the capability.** `audit().capabilityHex` must
  equal the 32 bytes `run.mjs` itself generated, so the needle is known to be
  the real secret rather than whatever the page felt like returning. A secret
  shorter than 32 bytes, or an SDP under 64 bytes, is refused rather than
  quietly dropped from the search.
- **Short needles are refused, not searched.** `v=0` alone is three bytes and
  turns up by chance roughly once per 16 MB of ciphertext; these logs are
  6-8 MB. It is searched as `v=0\r\n`, which is what Chromium emits, and
  anything under four bytes is dropped from the needle set rather than counted
  as "not found".
- **The needle count is asserted, not printed.** A run that builds anything
  other than 148 needles fails, so an edit that drops a secret or an encoding
  cannot shrink the search and still report a clean audit.

**What the audit does not cover.** Three things, and the verdict line is worded
so as not to imply any of them:

1. **GET routes.** The store's body log sits inside the POST branch of the
   request handler, so it records request _bodies_ only. The chunk and
   checkpoint reads carry their coordinates in the URL path
   (`/chunk/<deliveryProfileHash>/<window>/<class>/<chunk>`) and are **not**
   examined by this audit at all. Those paths are public geometry by
   construction and hold no room-derived value, but this run does not check
   that; it checks the bodies.
2. **Bodies logged after the audit ran.** Each log is read exactly once, right
   after both pages report `message-verified` and **before** `stop()`, so the
   scheduled traffic of the windows that follow is outside the corpus. The
   counts the run prints are the counts the audit actually searched — they are
   carried out of the search loop rather than re-read afterwards, so the
   verdict line and the per-store audit line always name the same corpus.
3. **Source addresses, request timing and sizes**, all of which both stores see.

**What a run may therefore claim** is exactly: _on this run, none of the 148
needles for the room capability, the `RoomContextId`, either stable Ed25519 key,
either SDP blob, or those SDP markers appeared in any of the N request bodies
the audit searched_, where N is the number the run prints per store. Nothing
about what a store could infer, and nothing about independence.

### Honesty

- **Two store processes on one laptop are ONE fault domain.** They share a
  kernel, a disk, a clock, a power supply and an operator. Nothing in these runs
  is evidence that two stores would fail independently; the scenarios show that
  the _client_ keeps working when one of them stops or lies, which is a
  different statement.
- **The prototype earns no label.** Not "anonymous", not
  "censorship-resistant", not Byzantine fault tolerant, not conformant, and not
  a release version. Every route and media type says `prototype-v0`, allocation
  is open (no Privacy Pass issuer, so no Sybil or fairness claim at all), and
  the admission kernel is not consulted.
- **`withhold` is not an adversary-grade fault mode.** The store answers
  `stored` to _every_ append, including a repeat of bytes an honest store would
  have answered `already-present` for. A real adversary would not be caught this
  way — a client that re-appended the same object could tell the two apart. What
  the scenario exercises is the _detection_: the client holds a signed receipt
  naming a slot, reads that slot out of the finalized chunk, hashes it, and
  finds bytes the store never received. That receipt-versus-slot comparison is
  what is under test, not indistinguishability.
- **In `kill-a`, store A's clean audit is about very few bytes.** The kill lands
  in the first delivery window, so A had logged 2 request bodies. The run says
  so (`store a: 2 bodies`); the honest statement is about those two bodies.
- **A fault record is not always misbehaviour, and the kinds now say which.**
  Until `f1f5aa4` `storeClient.#request` filed every transport failure — a
  killed store's `ERR_CONNECTION_REFUSED` included — as `signature-invalid`, so
  `kill-a` produced 269 records indistinguishable from a store caught signing a
  lie. That is fixed upstream: a store that did not answer now files as kind
  `unreachable`, and `signature-invalid` is reserved for an answer that arrived,
  decoded, carried a signature and failed to verify. Neither kind marks a store
  inert. `kill-a` now asserts that store A's faults are **only** `unreachable`
  and that store B's are empty, and every run prints the two populations
  separately.

### Build and run

From the SDK root:

```
bash docs/e2e/blind-two-store/build.sh
PLAYWRIGHT_BROWSERS_PATH=~/Library/Caches/ms-playwright \
  node docs/e2e/blind-two-store/run.mjs \
    [--scenario=healthy|kill-a|withhold-a|unreachable-b-for-one|all] \
    [--window-ms=4000] [--cohort=8] [--deadline-ms=180000] \
    [--store-port-base=5910] [--page-port=5920]
```

`bundle.js`, `bundle.cohort-<n>.js`, `provider-smoke-bundle.js` and
`libcrypto.wasm` are generated and are covered by `.gitignore`, so "do not
commit them" is enforced rather than remembered. Ports: `--store-port-base` and
the next seven (one pair per scenario) plus 5920 for the page server; nothing
binds below 5000.

**`docs/e2e/**` is outside `tsconfig.json`.** Neither `entry.ts` nor
`profileTool.ts` nor `cohortPreload.ts` is type-checked by
`bunx tsc --noEmit -p tsconfig.json`, and `bun build` only transpiles. A green
build here is not a type check.

### Recorded result (2026-09-08, headless Chromium, macOS, `--window-ms=4000`, pinned cohort 8)

`node docs/e2e/blind-two-store/run.mjs --scenario=all`, exit 0, 4 of 4
scenarios. Verbatim, with the per-window `store-missed` cover lines, the
`run-stopped` lines and the store startup banners elided:

```
delivery profile: window 4000ms, cohort 8, chunks/window 3+2, hash 83a2261ee4c0f345…
per client per store per window: appends 172542 bytes, full scan 1380336 bytes
page server on http://localhost:5920/

=== scenario healthy (window 4000ms, cohort 8, ports 5910/5911) ===
store a healthy on 5910 (storeId f27c7a022e90fb587e738b58cdfe270da6f6a0439293956121461dd2fe98ff13)
store b healthy on 5911 (storeId 9324b1a430d7c3845eb6437926fa3e980f9ff7fc766d8c358a88702e91da7b14)
both pages loaded (capability 40674e118172ac1f…; A sees 2 store(s), B sees 2)
    0.5s [A] store-connected — http://127.0.0.1:5910 storeId=f27c7a022e90fb58…
    0.5s [A] store-connected — http://127.0.0.1:5911 storeId=9324b1a430d7c384…
    0.5s [A] presence-published            0.5s [B] presence-published
  0.5s both endpoints armed; delivery window 4000ms
    2.1s [A] topology — multi-store-union  2.1s [B] topology — multi-store-union
   10.2s [A] peer-observed                10.2s [A] hello-sent
   18.2s [B] hello-opened                 18.2s [B] accepted
   26.1s [A] accepted                     26.2s [A] offer-sent
   34.0s [B] offer-opened                 34.0s [B] answered      34.0s [B] handoff
   42.3s [A] handoff
   42.3s [A] webrtc-connected — initiator  42.3s [B] webrtc-connected — responder
   42.3s [A] dtls-verified                 42.3s [B] dtls-verified
   42.3s [A] session-authenticated — initiator
   42.3s [B] session-authenticated — responder
   42.3s [A] message-sent — 140005 bytes in 3 frames
   42.3s [A] message-verified — 9005 bytes from 1 frames
   42.3s [B] message-verified — 140005 bytes from 3 frames

time from this page's own presence-published to each milestone
  page  peer-observed   handoff  session-authenticated  message-verified
     A           9.7s     41.8s                  41.8s             41.8s
     B           9.7s     33.5s                  41.8s             41.9s

requests issued by page   A: a=162 b=163   B: a=163 b=164
privacy audit of the logged request bodies
  store a: 171 bodies (7636265 log bytes), 148 needles over 14 secrets, 0 found
  store b: 174 bodies (7670938 log bytes), 148 needles over 14 secrets, 0 found
topology                  A=multi-store-union B=multi-store-union
faults                    A: none   B: none
counters                  A={"appendsReal":8,"appendsDummy":100,"scans":22,"operationsSeen":6,"backfills":0}
                          B={"appendsReal":8,"appendsDummy":100,"scans":22,"operationsSeen":6,"backfills":0}

SCENARIO healthy PASS in 41.9s — 140005 bytes A→B and 9005 bytes B→A decrypted byte-exact; topology A=multi-store-union B=multi-store-union; 0 of 148 needles found in the 345 request bodies the audit searched

=== scenario kill-a (window 4000ms, cohort 8, ports 5912/5913) ===
store a healthy on 5912 (storeId 26016191fa9e1efa13158f8421d3b7d6ba5724fe4b11841d825394a44c094c03)
store b healthy on 5913 (storeId 7541edf4beed64d8286aa9b786e31f26aac9bf6277a0eed6c1f6d050f42388ea)
both pages loaded (capability b09f5675b65e7a34…; A sees 2 store(s), B sees 2)
    0.4s [A] store-connected — http://127.0.0.1:5912 …
    0.4s [A] store-connected — http://127.0.0.1:5913 …
    0.4s [A] presence-published            0.5s [B] presence-published
  0.5s both endpoints armed; delivery window 4000ms
  0.5s SIGKILL store a (pid 54781) after both presence-published and 2 logged bodies; process exited and http://127.0.0.1:5912/health now refuses
    3.5s [A] topology — single-carrier-dependent
    3.5s [B] topology — single-carrier-dependent
    7.5s [A] peer-observed                  7.7s [B] hello-sent
   15.6s [A] hello-opened                  15.6s [A] accepted
   23.7s [B] accepted                      23.8s [B] offer-sent
   31.0s [A] offer-opened                  31.0s [A] answered      31.0s [A] handoff
   35.6s [B] handoff
   35.6s [A] dtls-verified                 35.6s [B] dtls-verified
   35.6s [A] session-authenticated — responder
   35.6s [B] session-authenticated — initiator
   35.6s [A] message-verified — 9005 bytes from 1 frames
   35.6s [B] message-verified — 140005 bytes from 3 frames

time from this page's own presence-published to each milestone
  page  peer-observed   handoff  session-authenticated  message-verified
     A           7.1s     30.6s                  35.1s             35.2s
     B           7.2s     35.1s                  35.1s             35.2s

requests issued by page   A: a=133 b=117   B: a=135 b=117
note                      264 record(s) of kind "unreachable" (a store that did not answer; not an accusation, and does not mark it inert) and 0 of "signature-invalid" (an answer that arrived and did not verify)
privacy audit of the logged request bodies
  store a: 2 bodies (438 log bytes), 148 needles over 14 secrets, 0 found
  store b: 116 bodies (5580668 log bytes), 148 needles over 14 secrets, 0 found
topology                  A=single-carrier-dependent B=single-carrier-dependent
faults                    A: 131× unreachable vs 26016191fa9e1efa…   B: 133× unreachable vs 26016191fa9e1efa…
  A first fault           w447205564: /p2party/prototype-v0/allocation-token: the request failed (TypeError)
  B first fault           w447205564: /p2party/prototype-v0/allocation-token: the request failed (TypeError)
counters                  A={"appendsReal":18,"appendsDummy":68,"scans":16,"operationsSeen":5,"backfills":5}
                          B={"appendsReal":21,"appendsDummy":65,"scans":18,"operationsSeen":6,"backfills":6}

SCENARIO kill-a PASS in 35.2s — 140005 bytes A→B and 9005 bytes B→A decrypted byte-exact; topology A=single-carrier-dependent B=single-carrier-dependent; 0 of 148 needles found in the 118 request bodies the audit searched

=== scenario withhold-a (window 4000ms, cohort 8, ports 5914/5915) ===
store a healthy on 5914 (storeId ca64f93053d417ef8c07502c853e16206b1c2fd7ec7ed9dcbc3db6f3819e2cdf)
store b healthy on 5915 (storeId ef65eef2d5dc5d538dfebb0081938b016286d1c8f51205b4c4189d5813fc3233)
both pages loaded (capability 4867c022758a5f23…; A sees 2 store(s), B sees 2)
  0.4s both endpoints armed; delivery window 4000ms
    3.8s [A] topology — multi-store-union
    3.8s [B] topology — multi-store-union
    7.7s [A] topology — single-carrier-dependent
    7.8s [B] topology — single-carrier-dependent
    8.0s [A] peer-observed                  8.0s [A] hello-sent
   16.0s [B] hello-opened                 16.0s [B] accepted
   24.0s [A] accepted                     24.2s [A] offer-sent
   31.4s [B] offer-opened                 31.4s [B] answered      31.4s [B] handoff
   36.0s [A] handoff
   36.0s [A] dtls-verified                36.0s [B] dtls-verified
   36.0s [A] message-verified — 9005 bytes from 1 frames
   36.0s [B] message-verified — 140005 bytes from 3 frames

time from this page's own presence-published to each milestone
  page  peer-observed   handoff  session-authenticated  message-verified
     A           7.6s     35.6s                  35.6s             35.6s
     B           7.6s     30.9s                  35.6s             35.6s

requests issued by page   A: a=120 b=120   B: a=120 b=120
privacy audit of the logged request bodies
  store a: 128 bodies (6243664 log bytes), 148 needles over 14 secrets, 0 found
  store b: 128 bodies (6243664 log bytes), 148 needles over 14 secrets, 0 found
topology                  A=single-carrier-dependent B=single-carrier-dependent
faults                    A: 8× custody-breach vs ca64f93053d417ef…   B: 8× custody-breach vs ca64f93053d417ef…
  A first fault           w447205572: the object at class 0 chunk 0 slot 5 is not the one this store received
  B first fault           w447205572: the object at class 0 chunk 0 slot 2 is not the one this store received
counters                  A={"appendsReal":11,"appendsDummy":77,"scans":18,"operationsSeen":6,"backfills":6}
                          B={"appendsReal":11,"appendsDummy":77,"scans":18,"operationsSeen":6,"backfills":6}

SCENARIO withhold-a PASS in 35.6s — 140005 bytes A→B and 9005 bytes B→A decrypted byte-exact; topology A=single-carrier-dependent B=single-carrier-dependent; 0 of 148 needles found in the 256 request bodies the audit searched

=== scenario unreachable-b-for-one (window 4000ms, cohort 8, ports 5916/5917) ===
store a healthy on 5916 (storeId 95acc8f846076c1367e68e5a9c7575a5a3967221f7b54df48ee95b6c9de31603)
store b healthy on 5917 (storeId 99fc1f0b4ab2af9ad6f63d6339b9f2a788f3d13aeead5d90a93f18458f5351ce)
both pages loaded (capability c08f92911b34a47e…; A sees 2 store(s), B sees 1)
    0.4s [B] store-connected — http://127.0.0.1:5916 …
    0.4s [A] store-connected — http://127.0.0.1:5916 …
    0.4s [A] store-connected — http://127.0.0.1:5917 …
  0.4s both endpoints armed; delivery window 4000ms
    3.6s [A] topology — multi-store-union
    3.6s [B] topology — single-carrier-dependent
    7.7s [B] peer-observed                  7.7s [B] hello-sent
   15.8s [A] hello-opened                 15.8s [A] accepted
   23.8s [B] accepted                     23.9s [B] offer-sent
   31.1s [A] offer-opened                 31.1s [A] answered      31.1s [A] handoff
   35.8s [B] handoff
   35.8s [A] dtls-verified                35.8s [B] dtls-verified
   35.8s [A] message-verified — 9005 bytes from 1 frames
   35.8s [B] message-verified — 140005 bytes from 3 frames

time from this page's own presence-published to each milestone
  page  peer-observed   handoff  session-authenticated  message-verified
     A           7.4s     30.7s                  35.3s             35.4s
     B           7.2s     35.3s                  35.3s             35.4s

requests issued by page   A: a=136 b=136   B: a=118 b=0
privacy audit of the logged request bodies
  store a: 135 bodies (6245141 log bytes), 148 needles over 14 secrets, 0 found
  store b: 72 bodies (3123520 log bytes), 148 needles over 14 secrets, 0 found
topology                  A=multi-store-union B=single-carrier-dependent
faults                    A: none   B: none
counters                  A={"appendsReal":9,"appendsDummy":79,"scans":18,"operationsSeen":6,"backfills":3}
                          B={"appendsReal":3,"appendsDummy":41,"scans":9,"operationsSeen":6,"backfills":0}

SCENARIO unreachable-b-for-one PASS in 35.4s — 140005 bytes A→B and 9005 bytes B→A decrypted byte-exact; topology A=multi-store-union B=single-carrier-dependent; 0 of 148 needles found in the 207 request bodies the audit searched

=== summary (window 4000ms, cohort 8, scan 1380336 B/store/window) ===
scenario                 verdict   connect   A:peer→verified   B:peer→verified   topology A / B
healthy                  PASS        41.9s        9.7s→41.8s        9.7s→41.9s   multi-store-union / multi-store-union
kill-a                   PASS        35.2s        7.1s→35.2s        7.2s→35.2s   single-carrier-dependent / single-carrier-dependent
withhold-a               PASS        35.6s        7.6s→35.6s        7.6s→35.6s   single-carrier-dependent / single-carrier-dependent
unreachable-b-for-one    PASS        35.4s        7.4s→35.4s        7.2s→35.4s   multi-store-union / single-carrier-dependent

TWO-STORE E2E PASS (4 of 4 scenarios)
```

Every per-store body count above is the corpus the audit searched, and the
verdict line's total is their sum — 171 + 174 = 345, 2 + 116 = 118,
128 + 128 = 256, 135 + 72 = 207. Nothing logged after the audit ran is counted,
because nothing logged after the audit ran was searched.

Two things worth reading off that run:

- `unreachable-b-for-one`: page B issued **0** requests to store B and still
  reached `message-verified`, byte-exact both ways. Page A **queued 3 backfills
  for store B** — `CarrierCounters.backfills` counts `(operation, store)` pairs
  enqueued for replication, so it is evidence that page A decided store B was
  missing those operations, not evidence that any of them was appended or
  acknowledged; and nothing in store B's log distinguishes a backfilled object
  from cover. Page A ends `multi-store-union`, page B
  `single-carrier-dependent` — each reporting only what it read itself.
- `withhold-a`: both pages reported `multi-store-union` at 3.8 s (A's first
  window was still consistent, because a client can only compare a receipt
  against a window after that window is finalized) and dropped to
  `single-carrier-dependent` at 7.7-7.8 s, when the first custody comparison
  failed and A was marked inert. That is the detection latency of the check:
  one delivery window.

The four scenarios' wall-clock times differ by a few seconds in every direction
and the ordering is **not** stable across runs: in the run above `healthy` was
the slowest by 6.5 s, while across earlier `--scenario=all` runs of the same
four scenarios `kill-a` came out slower than `healthy` in one and faster in the
next. That ordering claim is deliberately qualitative — the multi-run tables it
used to cite were removed by an earlier review, because printing three runs of
single measurements invited exactly the causal reading this paragraph warns
against, and no number is quoted here that this document does not print. Read
the differences as run-to-run variance — chiefly where in a delivery window each
run happens to start — and not as a measurement of what reading one store
instead of two costs. The section below measures that deliberately, by changing
the geometry rather than by comparing scenarios.

### `--cohort=<n>`: window length and cohort size are exchangeable

Design §8 asked for a latency table over `deliveryWindowMs ∈ {4000, 2000, 1000}`.
Rescaling alone does not reach it: `withDeliveryWindowMs` scales the append
offsets and the finalization offset by the same ratio, so the slack between the
last append and the window's close shrinks with the window, and at 2,000 ms
every append arrives after `window-finalized`. Task 8b recorded that as a dead
end. It is not a dead end — it is a _cost_ problem, and the cost has a second
knob.

Per client, per store, per window the schedule costs a fixed **append** of
172,542 bytes (5 objects; set by `appendSchedule`, and independent of the cohort)
and a fixed **full scan** of `publicChunksPerWindow × publicChunkObjectCount ×
objectWireBytes` summed over the size classes — every object of which the client
AEAD-attempts, because a fixed scan that skipped anything would be
event-shaped. That scan is what `cohortAllocationsPerWindow` sizes:
`publicChunksPerWindow = ceil(cohort × roomSlotsPerClient × appendSchedule.length
/ publicChunkObjectCount)`.

`--cohort=<n>` rebuilds the profile at that cohort — deriving the chunk counts
from that inequality rather than guessing them, and re-running
`validateDeliveryProfileGeometry` — and applies it to **both** store processes
and **both** pages, so all four agree on one `DeliveryProfileHash`. (At
`--cohort=8` the rebuilt profile hashes to `83a2261e…`, byte-identical to the
pinned literal; that equality is the check that the rebuild is faithful.)

Measured on this machine — macOS, headless Chromium, both pages and both stores
in one process tree — time from `presence-published` to `message-verified`,
`--scenario=healthy`:

| window |         cohort | chunks/window | full scan, B/store/window |        per flight |                          time to `message-verified` |
| -----: | -------------: | :-----------: | ------------------------: | ----------------: | --------------------------------------------------: |
|   4000 | **8** (pinned) |      3+2      |                 1,380,336 | 8.0 s = 2 windows |                                          **39.9 s** |
|   4000 |              4 |      2+1      |                   723,344 |  4.0 s = 1 window |                                          **22.3 s** |
|   4000 |              2 |      1+1      |                   656,992 |  4.0 s = 1 window |                                          **23.8 s** |
|   2000 | **8** (pinned) |      3+2      |                 1,380,336 |                 — | **stalls**: every append answers `window-finalized` |
|   2000 |              4 |      2+1      |                   723,344 | 4.0 s = 2 windows |                                          **20.8 s** |
|   2000 |              2 |      1+1      |                   656,992 | 4.0 s = 2 windows |                                          **17.9 s** |
|   1000 |              2 |      1+1      |                   656,992 | 2.0 s = 2 windows |                                          **10.5 s** |

Read it as three findings, all about this machine and nothing else:

1. **The pinned cohort already costs a whole extra delivery window per flight.**
   The protocol's designed cadence is one window per flight: append in window
   `w`, the peer reads `w` at `publicReadOffsetMs` into `w+1` and appends its
   answer inside `w+1`. At cohort 8 the browser cannot finish 1.38 MB × 2 stores
   of scanning and sealing between the read offset (600 ms) and the last append
   offset (2,100 ms), so every flight slips to the window after — 8 s instead of
   4 s, and 39.9 s instead of ~22 s for the whole rendezvous. Halving the cohort
   halves the scan and recovers the designed cadence at the _same_ window length.
2. **A smaller cohort is exactly what makes a shorter window work.** At the
   pinned cohort, `--window-ms=2000` cannot append at all. At `--cohort=4` the
   same 2,000 ms profile completes in 20.8 s, and at `--cohort=2` a 1,000 ms
   profile completes in 10.5 s with zero `window-finalized` misses. So design
   §8's table _is_ reachable — by moving both knobs, not one.
3. **The knob that buys the latency is the one that sizes the shared bucket.**
   `cohortAllocationsPerWindow` is, by definition, how many allocations a store
   may hand out per window in one bucket; the fixed scan is large precisely
   because it is that whole bucket. Moving it from 8 to 2 measured a 2.1×
   smaller scan and a 3.8× faster rendezvous, and by definition it also
   quarters the number of allocations that share the bucket — 8 to 2 is 4×, and
   the three ratios are three different quantities, not one. What that means
   for what a store can tell apart is **not** measured by any run here and is
   not claimed. The table is a cost measurement, not a recommendation: the
   pinned profile is 8, and moving it is a change to how much unrelated traffic
   a client's objects sit among.

Each row above is a real `--scenario=healthy` run with both stores honest;
`bundle.cohort-<n>.js` is generated per cohort and is not committed. Note that
the numbers are wall clock on one laptop running two Chromium contexts and two
`bun` stores at once — they are an upper bound on what two real clients on two
machines would see, not a protocol constant.

### Environment facts the harness depends on

- **`--disable-features=WebRtcHideLocalIpsWithMdns`.** Chromium otherwise
  replaces host candidates with `<uuid>.local` mDNS names this headless sandbox
  cannot resolve, and because the blind profile is complete-gathering (the
  candidates ride inside the single SDP blob; there is no trickle channel) an
  unresolvable remote candidate is simply dropped and both connections sit at
  `new` forever.
- **`<script type="module">` in `index.html`.** A browser-target `bun build`
  emits ESM, and the bundled `src/cryptography/wasmLoader.ts` contains
  `import.meta.url` inside a Node-only branch this page never takes — a classic
  script cannot even parse it. The `process` shim stays a classic inline script
  so it still runs before the deferred module.
- **Cross-origin.** A page is never served from a store's origin, so the store
  answers with `access-control-allow-origin: *`,
  `access-control-expose-headers: x-p2party-store` (the client refuses any
  answer without that header, and it is not CORS-safelisted), and a 204
  preflight for the `application/p2party-*-prototype-v0` request media types.
  Without those, no browser reaches a store at all.
- **The cohort override is a build-time rewrite, not a runtime option.**
  `cohortPreload.ts` registers a Bun loader plugin that renames the pinned
  profile literal and re-exports it with the cohort and the derived chunk counts
  substituted; `profileTool.ts` applies the same rewrite through `Bun.build` for
  the page bundle and prints the geometry `run.mjs` needs. Neither
  `src/blindRendezvous/prototype/index.ts` nor the store server was changed to
  make the measurement possible — if a cohort override is ever wanted outside a
  measurement, it belongs in `PrototypeRunOptions` and in a
  `P2PARTY_STORE_COHORT` variable, not here.
