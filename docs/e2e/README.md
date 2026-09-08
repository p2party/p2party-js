# Protocol-v4 browser verification harnesses

Real headless-Chromium E2E harnesses used to verify protocol v4 over **real
WebRTC** (real `RTCPeerConnection` + DTLS/SCTP DataChannels). Preserved here
from the session scratchpad so they survive. They reference absolute paths on
the author's machine (`~/Desktop/@p2party/...`) and the
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

## `desync/` — the mobile peer-desync reproduction

The harness that reproduced, and then verified the fix for, the permanent peer
split described in the `CHANGELOG.md` entry for the peer-edge transport binding
and liveness release: **a phone backgrounded with its radio off for less than
the ~30 s ICE consent timeout woke holding a peer connection that still read
`connected`, while its peer had already torn that edge down and built a fresh
one.** The woken side reused the stale transport, its zombie `main` channel
blocked a replacement, no handshake ever ran on the peer's new transport, and
the split was permanent until a manual reconnect — one side showed the peer
reachable and its sends failed as undelivered, the other showed no handshake at
all and its sends hung forever.

Unlike `appstack/`, which drives two pages of **one** browser, this harness
launches **two separate Chromium processes** (one `chromium.launch()` each, so
each has its own process tree) and can SIGSTOP one of them whole-tree. That is
what makes the fault real: JS, the WebSocket and WebRTC ICE all stop together,
exactly as on a suspended phone.

### Files

- `relay.ts` (Bun) — the signaling relay, mirroring `p2party-server` 0.1.1's
  message flow (`?publickey=` upgrade → peerId challenge → room → peers roster
  → route `description`/`candidate`/`connection` by `toPeerId`; durable room
  membership; 10 s ping / 5 s pong eviction; **no** departure broadcast) with
  fault-injection control hooks on the same port:
  `POST /ctl/close`, `POST /ctl/blackhole?ms=`, `POST /ctl/keepalive?ms=`,
  `GET /ctl/registry`, `GET /ctl/log`. `RELAY_PEERID_MODE=stable` (default)
  reissues the same peerId to a reconnecting identity, as the real server's
  `peer.upsert({where:{publicKey}})` does; `fresh` issues a new one per socket.
- `app-entry-desync.ts` — the real `p2party` public API (Redux + IndexedDB
  worker + WebRTC) plus a store-subscription timeline recorder, a full state
  dump (`window.__app.dump`), data-channel accounting and RTK/mutex diagnostics.
- `app.html` — process shim, `worker-inject.js`, the bundle, a
  `visibilityState` stub, an **in-page** console recorder (Playwright timestamps
  console events when the driver receives them, which is useless for a
  SIGSTOPped page: every line logged around the freeze arrives in one burst at
  thaw) and an `RTCPeerConnection` subclass that registers every connection ever
  constructed with its DTLS fingerprints, ICE ufrags, host candidates and
  channels — that registry is what makes the stale-transport reuse observable.
- `desync-driver.mjs` — the driver: static server, relay, two browsers, the
  fault, the observation loop, the invariant evaluation and the JSON/log dump.
- `probe-ice.mjs` + `plain.html` — a standalone no-SDK ICE sanity probe (two
  contexts, manual SDP/ICE exchange), used to confirm loopback ICE works before
  blaming the SDK.

Not preserved (regenerated, see **Rebuild**): `app-bundle.js`,
`worker-inject.js`, `libcrypto.wasm`, and the `runs/` output directory.

### Running it

```
PLAYWRIGHT_BROWSERS_PATH=~/Library/Caches/ms-playwright \
  node desync-driver.mjs <scenario> <role> [flags]
```

`scenario` = `baseline` | `ws-drop` | `ws-drop-nofocus` | `two-tabs` |
`pin-typo` | `cover-stall` | `freeze-ws-90` | `offline-60` | `freeze-20` |
`proc-freeze-<seconds>`. `role` = `initiator` |
`responder`, and says which identity role the **faulted** page A holds (the
Ed25519 initiator is the lexically lower hex public key) — the bug is
role-asymmetric, so both must be run.

**Focus emulation, and the one scenario without it.** After the fault clears,
every transport-fault scenario except `ws-drop-nofocus` calls
`window.__app.focusReconnect()` on A — the site's `ChatLayout`
focus/visibilitychange/pageshow/online handler, which calls `connect(roomUrl)`
iff `!isConnected`. That poke is not something a **focused** desktop tab ever
receives: when its signaling socket dies underneath it, no focus,
`visibilitychange`, `pageshow` or `online` event fires, so nothing calls
connect. `ws-drop-nofocus` is byte-for-byte `ws-drop` with the poke withheld,
and is therefore the arm that tests the SDK's own bounded reconnect (C4) rather
than the driver's. Any new recovery scenario should say explicitly which of the
two it is; a fault arm that only recovers because the driver poked it is not
evidence about the SDK.

`two-tabs` opens a second page in A's existing browser context. The new page
must adopt A's persisted identity, replace its signaling socket with a new
generation, then authenticate and exchange byte-exact messages with B within
20 s of `connect()`. A's original tab stays open so the run also checks that it
stays disconnected and does not reclaim the socket. No focus event is injected.
`pin-typo` uses different PINs for the same room and requires a visible, stable
PIN mismatch with exactly one transport per side and no roster requests after
the terminal failure. `cover-stall` injects a main
thread stall spanning a scheduled cover boundary and checks resumed cover
traffic. These three scenarios and `baseline` also omit focus emulation.

`proc-freeze-<s>` is the "phone asleep" fault: A's whole Chromium process tree
is SIGSTOPped for `<s>` seconds; the driver never touches A while frozen (no
`evaluate`, no CDP), polling only B and the relay every 1 s. Thaw is SIGCONT,
and `t=0` is the thaw instant. 1 s after thaw the driver emulates the
`p2party.com` focus handler on A (`ChatLayout.tsx`: `connect(roomUrl)` iff
`!isConnected`).

Flags:

- `--mode=immediate|scheduled|pin` selects the room policy; `pin-typo` fixes this
  to `pin`. `--cadence=<ms>` configures scheduled mode only. `cover-stall`
  requires `--mode=scheduled`.
- `--cpuslow=<A|B>:<rate>` applies Chromium CPU throttling to that page before
  the fault and releases it 20 s after `t=0`.
- `--pin=<hex>` / `--pinb=<hex>` select the two PINs for `pin-typo` only.
- `--port=<n>` selects static HTTP port `n` and relay port `n+1` (default
  5810/5811). Unknown flags, invalid numeric values and flags that cannot affect
  the chosen scenario are rejected before starting either listener.
- `--udpflood=1` — **"radio off"**, and the flag that makes the bug reproduce.
  Right after the SIGSTOP, the driver fills the kernel receive buffer of every
  UDP host-candidate socket of A's live peer connections with junk datagrams,
  so every datagram B sends to A for the rest of the freeze (consent checks,
  ICE-restart STUN, the DTLS/SCTP close at B's teardown) is dropped by A's
  kernel instead of being queued for A to read at thaw. Without it, loopback
  delivers B's close into the frozen A and A's stale connection closes at thaw —
  i.e. the harness accidentally repairs the very thing under test.
- `--socket=evict|close2s|keep|stranded` — what happens to A's signaling socket
  during the freeze. `evict` (default): nothing but the freeze, so the relay's
  ping/pong timer evicts A. `close2s`: also close A's socket server-side 2 s in
  (iOS tears the socket down on suspend). `keep`: suppress the pong-timeout
  eviction for the whole freeze (Android-style — JS throttled but the socket
  survives, so the frontend focus handler sees `isConnected=true` and does
  nothing). `stranded`: `keep` plus a black-hole of A's frames in both
  directions until 40 s past the thaw, so A stays registered while no
  signalling reaches it either way.

  `stranded` is the only scenario that leaves **two healthy sockets and two
  empty rosters** with nothing inbound able to start the recovery: A's
  introductions were dropped and A's own requests never left, and the server
  answers a peers request by introducing the requester to the other members
  rather than replying to it. It is therefore what exercises the client's own
  roster reconciliation, and its liveness watchdog. Note that the relay's
  heartbeat shares the black-hole gate, deliberately: a real network fault does
  not spare pings, and sparing them meant the watchdog kept measuring a live
  socket right through the fault and could never be exercised at all.

- `--transfer=<A2B|B2A>:<MiB>` — a real in-flight file transfer across the
  fault. Random payload (SHA-256 recorded) generated while the link is healthy;
  `p2party.sendMessage(File, "main", roomId)` fired in the last instant before
  the SIGSTOP and its handle kept but never awaited, so the transfer is
  genuinely in flight when the page freezes. `A2B` sends from the frozen page,
  `B2A` from the untouched one. After thaw the receiver is polled every second,
  then materialized with `readMessage` and SHA-256 compared.
  `--transferdeadline=<s>` (default 90) bounds it.
- `--peerid=stable|fresh`, `--n=<run number>`, `--observe=<seconds>`,
  `--refocus=<seconds>` (re-run the focus handler every N s; 0 = off).

Output: `../runs/<scenario>-<role>-<n>.{json,log}` — every 1 s invariant
sample, both pages' timelines, per-connection state events, in-page consoles,
final state dumps and the relay frame log.

### Ports

5810 static (`app.html`, `app-bundle.js`, `worker-inject.js`,
`libcrypto.wasm`), 5811 relay (WebSocket + `/ctl`), 5812 the `probe-ice.mjs`
static server. Nothing below 5000 is touched and no database is involved.

### Pass criteria

Evaluated every second from `t=0` and recorded as
`invariants.firstSatisfiedSinceClear` / `heldAtEnd`:

- **I1** — each side's roster holds exactly one entry for the other.
- **I2** — both sides' handshake status for that entry is `authenticated`
  (or both rosters are empty).
- **I3** — exactly one non-closed `RTCPeerConnection` per side for that peer.
- **I4** — once I2 holds, a byte-exact `sendMessage`/`readMessage` round trip
  succeeds **in both directions** (retried up to 3×, 15 s apart).
- **I5** — no handshake or cover entries left for peerIds not in the roster.
- **I6** — every roster peerId is still live in the relay registry.
- **I7** — the pre-fault connection instances are kept or replaced
  _symmetrically_. A holding its pre-fault instance while B has replaced its
  own **is** the stale-transport reuse: this is the invariant that failed
  before the fix.
- **fpAgree** — the two live transports' DTLS fingerprints match pairwise
  (each side's local fingerprint is the other's remote).

A run counts as a pass when I1/I2/I3/I5/I6/I7 all hold in the actual final
sample and I4 was ever satisfied, `fpAgree` and `bothAuthenticated` hold in the final sample, the
diagnostics show no pending RTK mutations, no held per-peer mutexes, a drained
mutex registry, and an IndexedDB round trip under 3000 ms; the driver recorded no problems — and, for a freeze scenario, **I2 is first
satisfied within 15 s of thaw** (a split that only heals on a 30 s+ timeout is
not a fix). The first mutually authenticated edge must also meet that bound:
two empty rosters satisfy I2's consistency definition but cannot count as
restored communication. Missing final state, fingerprints, or diagnostics fail
the run. `pin-typo` instead requires I1/I5/I6, both `failed/pin-mismatch` states,
exactly one transport per side, and no peers requests after terminal failure; successful authentication is not its
expected outcome. With `--transfer`, additionally: the receiver's bytes are
SHA-256-identical to the sender's payload, it completed within the transfer
deadline, and the sender's `handle.done` resolved with a `delivered` outcome.

### Rebuild

From the SDK root, into this directory:

```
npm run build:worker   # → lib/db.worker.js
node -e 'const fs=require("fs");const w=fs.readFileSync("lib/db.worker.js","utf8");fs.writeFileSync("docs/e2e/desync/worker-inject.js","window.process=window.process||{env:{}};window.process.env.INDEXEDDB_WORKER_JS="+JSON.stringify(w)+";")'
cp src/cryptography/libcrypto.wasm docs/e2e/desync/
cd docs/e2e/desync
bun build app-entry-desync.ts --target=browser --outfile=app-bundle.js --define:process.env.NODE_ENV='"production"'
```

As with the other harnesses here, this runs against the **development** WASM
(`src/cryptography/libcrypto.wasm`, SRI-pinned in `wasmLoader.ts`); do not run
`npm run predist` first.

### Recorded results (2026-09-08, C4 bounded signaling reconnect)

`ws-drop-nofocus` is the new arm: A's socket is closed server-side and the
driver never emulates the site's focus handler, so only the SDK can recover.
`I2`/`I4` are seconds after the fault cleared; `I6` (every roster peerId still
live in the relay registry) is the invariant that flips.

| run                         | scenario                      | faulted role | socket   | I2   | I4     | I6      |
| --------------------------- | ----------------------------- | ------------ | -------- | ---- | ------ | ------- |
| ws-drop-nofocus-initiator-1 | ws-drop-nofocus **(pre-fix)** | initiator    | —        | +0 s | +0.5 s | `never` |
| ws-drop-nofocus-initiator-2 | ws-drop-nofocus               | initiator    | —        | +0 s | +0.5 s | +0 s    |
| ws-drop-nofocus-initiator-3 | ws-drop-nofocus               | initiator    | —        | +0 s | +0.5 s | +0 s    |
| ws-drop-nofocus-responder-1 | ws-drop-nofocus               | responder    | —        | +0 s | +0.5 s | +0 s    |
| ws-drop-initiator-1         | ws-drop                       | initiator    | —        | +0 s | +0.5 s | +0 s    |
| proc-freeze-20-initiator-2  | proc-freeze-20 `--udpflood=1` | initiator    | evict    | +2 s | +2.5 s | +1 s    |
| proc-freeze-20-responder-1  | proc-freeze-20 `--udpflood=1` | responder    | stranded | +6 s | +6.5 s | +1 s    |

The pre-fix run is the whole point of the arm: `I6` is `never`, A's
`signalingServer.isConnected` is false for all 150 s, and the relay log shows
**no second `OPEN sock`** for A after the close — the peer stays a room member
the server cannot reach. Post-fix, the relay records A opening a new socket
1.1–1.2 s after the close (the ladder's first 1 s rung plus jitter plus the
handshake), re-registering under the same peerId and re-joining the room. Run
`initiator-3` is the same arm re-run against the exact committed bundle, after
the last source edit, so the recorded pass corresponds to what shipped.

`I2` and `I4` do **not** discriminate here, contrary to the plan's prediction:
this fault kills only the signaling socket, so the already-established WebRTC
edge stays `authenticated` and messages keep round-tripping in both directions
throughout. `I6` is what the lost socket actually breaks. The last two rows are
the existing matrix, re-run to confirm no regression against runs 967 and 965
(+2 s/+2.5 s and +6 s/+6.9 s respectively).

Side effect worth noting: in `ws-drop` the driver's focus emulation now reports
`skipped by driver: isConnected=true at focus time` — by the time the poke
would land, the SDK has already reconnected on its own.

### Recorded results (2026-09-03, at the 0.14.7 branch tip)

Fifteen runs, `--udpflood=1` throughout, macOS + headless Chromium. These are
the numbers the three recovery fixes in 0.14.7 were accepted on. `I2` and `I4`
are seconds after the fault cleared.

| run             | scenario                          | faulted role | socket   | I2    | I4      |
| --------------- | --------------------------------- | ------------ | -------- | ----- | ------- |
| 961 / 962 / 963 | proc-freeze-20 `--transfer=A2B:8` | responder    | evict    | +12 s | +17.5 s |
| 964             | proc-freeze-20                    | initiator    | stranded | +6 s  | +6.5 s  |
| 965             | proc-freeze-20                    | responder    | stranded | +6 s  | +6.9 s  |
| 966             | ws-drop                           | initiator    | —        | +0 s  | +0.5 s  |
| 967             | proc-freeze-20                    | initiator    | evict    | +2 s  | +2.5 s  |
| 968             | proc-freeze-20                    | responder    | evict    | +2 s  | +2.5 s  |
| 969             | proc-freeze-20                    | initiator    | keep     | +6 s  | +6.5 s  |
| 970             | proc-freeze-20                    | responder    | keep     | +1 s  | +1.5 s  |
| 971             | proc-freeze-45                    | initiator    | evict    | +1 s  | +2.5 s  |
| 972             | proc-freeze-20 `--transfer=A2B:8` | initiator    | evict    | +2 s  | +7.5 s  |
| 973             | proc-freeze-20 `--transfer=B2A:8` | initiator    | evict    | +2 s  | +5.9 s  |

Two of those rows are the point of the release. Runs 961-963 are the
configuration that used to take 37.5 s, because recovery waited out the 30 s
handshake step timeout; the ten-second re-bind deadline replaced that wait, and
the three runs are identical to the tenth of a second. Runs 964 and 965 are the
`stranded` configuration, which before this release never recovered at all.

Every transfer run ended byte-exact with the sender resolving `delivered`
(151/151 real chunks, 0 retransmits). `I7`, the informational "both sides
replaced their transport symmetrically" invariant, is false in the
responder-frozen rows: that is the normal shape of that configuration, where
the frozen responder keeps its pre-fault connection while its peer holds a
fresh one.

### Recorded results (2026-09-02, at `e41d8c7`)

Eighteen runs, `--udpflood=1` throughout, macOS + headless Chromium. `I2` and
`I4` are seconds after thaw.

Seven-scenario regression matrix — all pass, both sides converge 1–6 s after
wake and exchange byte-exact messages both ways:

| run       | scenario       | faulted role | socket | I2          | I4              |
| --------- | -------------- | ------------ | ------ | ----------- | --------------- |
| 710       | baseline       | initiator    | —      | +0 s        | +0.5 s          |
| 711       | ws-drop        | initiator    | —      | +0 s        | +0.5 s          |
| 712 / 713 | proc-freeze-20 | initiator    | evict  | +2 s        | +2.5 s          |
| 714 / 715 | proc-freeze-20 | responder    | evict  | +2 s / +3 s | +2.5 s / +3.5 s |
| 716       | proc-freeze-20 | initiator    | keep   | +6 s        | +6.5 s          |
| 717 / 718 | proc-freeze-20 | responder    | keep   | +1 s        | +1.5 s          |
| 719       | proc-freeze-45 | initiator    | evict  | +1 s        | +2.5 s          |

In-flight 8 MiB transfers across a 20 s freeze — all four configurations
byte-exact with the sender resolving `delivered`:

| run             | direction               | faulted role | receiver complete | I2    |
| --------------- | ----------------------- | ------------ | ----------------- | ----- |
| 704 / 705       | A2B (frozen side sends) | initiator    | +7 s              | +2 s  |
| 706 / 707       | B2A (awake side sends)  | initiator    | +5 s              | +2 s  |
| 708             | B2A (awake side sends)  | responder    | +5 s              | +2 s  |
| 701 / 702 / 703 | A2B (frozen side sends) | responder    | +37 s             | +32 s |

Run 701–703 is the configuration that failed deterministically before the fix
and now passes 3/3 byte-exact.

**Known follow-up (not fixed):** that same configuration — a frozen _identity
responder_ carrying an in-flight transfer — converges in ~37 s rather than the
~7 s of every other configuration, because the surviving transport's SCTP
association accepts our new streams but not the peer's, so recovery waits out
the 30 s handshake step timeout. The outcome is correct; the latency is not yet.
It is the one arm of this matrix that misses the 15 s convergence bar above.

## `frontend-audit-report.md`

The synthesized multi-agent UI/UX + v3/v4-wiring audit of `p2party.com`.
