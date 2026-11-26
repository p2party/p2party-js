# Protocol-v4 browser verification harnesses

Real headless-Chromium E2E harnesses used to verify protocol v4 over **real
WebRTC** (real `RTCPeerConnection` + DTLS/SCTP DataChannels). Preserved here
as reproducible development fixtures. Keep `p2party-js`, `p2party-server`, and
`p2party.com` in sibling directories. The drivers resolve `playwright-core`
from `p2party.com/node_modules`; install the frontend dependencies with `npm ci`
and its Chromium browser with `npx playwright install chromium` before running
them. These are local, disposable test environments; use no production data or
credentials. Historical results below describe the exact versions originally
tested and do not certify later releases.

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
  because headless Chromium reports the page hidden. The runtime keeps cover
  armed on a hidden page, but a browser may throttle a hidden page's timers and
  late cells degrade the cycle; the stub keeps the run off that path.
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
- **I7 (diagnostic)** — whether the pre-fault connection objects were kept or
  replaced symmetrically. A responder can safely retain its connection object
  while resetting authentication for a new remote certificate; this is the
  intentional `reset-in-place` path. I7 can therefore be false in a healthy
  recovered session. Final mutual authentication, pairwise fingerprints and
  byte-exact I4 determine whether that rebind succeeded.
- **fpAgree** — the two live transports' DTLS fingerprints match pairwise
  (each side's local fingerprint is the other's remote).

A run counts as a pass when I1/I2/I3/I5/I6 all hold in the actual final
sample and I4 completed within the observation window, `fpAgree` and `bothAuthenticated` hold in the final sample, the
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

Scheduled text probes use a schedule-derived total budget. For the harness's
2-lane, 16-cell, 1-epoch preset and cadence `C` milliseconds, it is
`max(30000, 2*C + ceil(3*C/64) + 20000 + 10000)`: the SDK's two-cycle receipt
bound and margin, plus 10 s for browser IPC and materialization. At a 70 s
cadence this is **173.282 s**. Baseline and I4 probe both directions concurrently
in scheduled mode; immediate-mode probes keep their existing order and 30 s
budget. The final await allows the scheduled budget plus 5 s for cleanup, but
an I4 completion after `--observe` still fails. Freeze recovery stays bounded
by 15 s, and `--transferdeadline` is unchanged.

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

### Recorded results (2026-09-08, completed remediation)

The accepted C1–C5, C7–C8 and minimal C9 remediation is verified locally with
SDK **0.14.8**, server **0.1.2**, and the built site vendoring the tested SDK.
There are **22 passing arms and one established old-server non-convergence
residual**. This is macOS/headless Chromium, two peers over loopback; it does
not establish recovery across arbitrary networks or multi-peer rooms.

The [machine-readable record](desync-results-2026-09-08.json) contains every
arm's arguments, metrics, final invariants, raw-evidence hashes, matrix input
hashes, and actual-stack result. Raw JSON and console logs remain locally under
ignored `docs/e2e/runs/` and the site's `logs/desync/`.

Production SDK source is `7e09188`. The final browser bundle SHA-256 is
`ed5a62adfc169a25eeee6afc94853e2aedf1a989567690f510ffd192adb6323f`.
The packaged SDK tarball vendored in site `f88cd39` has SHA-256
`631bdc04b1b3591b644d48a0d63d35d20bf60af7f1d6c817e869015e7bbbc076`.
It was built from a committed SDK snapshot in an ignored nested release clone,
so release preparation did not overwrite the active checkout's development
WASM or include the unrelated dirty prototype work. Later harness and
measurement documentation commits do not change that production source.

The table combines six completed, unaffected immediate-mode arms from matrix
1200 (1, 2, 3, 5, 6, 7) with sixteen arms from matrix 1400 and CPU-throttled arm 1521 from matrix 1500.
All three manifests attest unchanged production inputs. Matrix 1200 was interrupted
after its first eight arms finished; its interrupted arms 9/10 are excluded.
Its responder arms 4/8 failed only the obsolete I7 object-replacement symmetry
assertion and were rerun in 1400. The responder can retain its connection
object while authenticating a new remote certificate: I7 remains recorded as a
diagnostic, with mutual authentication, matching fingerprints, delivery,
cleanup and the 15-second freeze recovery bound still required.

The final driver also budgets scheduled probes for their legal cadence instead
of a fixed 30 seconds. It rejects delivery after the original observation
window. The six retained immediate-mode runs already met these unchanged
bounds. Matrix 1100, occupied-relay smoke 801, exploratory drivers and the
superseded site run with hydration errors are excluded from acceptance.

CPU-throttled run 1421 remains a recorded **failure**: authentication took
22.877 s after thaw. The system power log independently shows the whole host
entered idle sleep at 16:00:04 UTC and woke at 16:00:26 UTC, immediately after
the browser thaw; the driver and relay heartbeat both stopped during that gap.
Run 1521 repeats the exact arm with the same input hashes under a confirmed
`caffeinate -i` assertion. Its original 15-second bound is unchanged. The raw
failed run and matching power-log hashes are retained in the result record.

Times below are seconds after fault clearance; for `two-tabs` they start when
the replacement connects. `I2` measures roster consistency and can hold with
empty rosters, so the separate mutually authenticated milestone is mandatory
for recovery. `I4` requires byte-exact text delivery in both directions.

| Arm / run | Scenario and faulted role                                                                                                        |     I2 | Authenticated |      I4 | Outcome                                                         |
| --------- | -------------------------------------------------------------------------------------------------------------------------------- | -----: | ------------: | ------: | --------------------------------------------------------------- |
| 1 / 1201  | `baseline initiator`                                                                                                             |  0.008 |         0.008 |   0.466 | PASS                                                            |
| 2 / 1202  | `ws-drop initiator`                                                                                                              |  0.008 |         0.008 |   0.877 | PASS                                                            |
| 3 / 1203  | `proc-freeze-20 initiator --udpflood=1`                                                                                          |  2.011 |         2.011 |   2.473 | PASS                                                            |
| 4 / 1404  | `proc-freeze-20 responder --udpflood=1`                                                                                          |   3.01 |          3.01 |   3.465 | PASS                                                            |
| 5 / 1205  | `proc-freeze-20 initiator --udpflood=1 --socket=keep`                                                                            |  6.013 |         6.013 |   6.493 | PASS                                                            |
| 6 / 1206  | `proc-freeze-20 responder --udpflood=1 --socket=keep`                                                                            |  1.008 |         1.008 |   1.465 | PASS                                                            |
| 7 / 1207  | `proc-freeze-20 initiator --udpflood=1 --socket=stranded`                                                                        |  6.015 |         6.015 |   6.483 | PASS                                                            |
| 8 / 1408  | `proc-freeze-20 responder --udpflood=1 --socket=stranded`                                                                        |  6.011 |         6.011 |   6.478 | PASS                                                            |
| 9 / 1409  | `proc-freeze-45 initiator --udpflood=1`                                                                                          |  1.014 |         2.015 |   2.486 | PASS                                                            |
| 10 / 1410 | `proc-freeze-20 initiator --udpflood=1 --transfer=A2B:8`                                                                         |  2.013 |         2.013 |   7.493 | PASS; byte-exact, receiver +7.018s / sender delivered +7.018s   |
| 11 / 1411 | `proc-freeze-20 initiator --udpflood=1 --transfer=B2A:8`                                                                         |  2.015 |         2.015 |   5.521 | PASS; byte-exact, receiver +5.021s / sender delivered +5.021s   |
| 12 / 1412 | `proc-freeze-20 responder --udpflood=1 --transfer=A2B:8`                                                                         | 12.023 |        12.023 |  15.497 | PASS; byte-exact, receiver +15.024s / sender delivered +15.024s |
| 13 / 1413 | `ws-drop-nofocus initiator --observe=150`                                                                                        |   0.01 |          0.01 |   0.479 | PASS                                                            |
| 14 / 1414 | `ws-drop-nofocus responder --observe=150`                                                                                        |  0.008 |         0.008 |   0.479 | PASS                                                            |
| 15 / 1415 | `pin-typo initiator --observe=120`                                                                                               |  never |         never |   never | PASS; stable PIN failure, one transport per side                |
| 16 / 1416 | `two-tabs responder --observe=300`                                                                                               |  0.221 |         0.221 |   0.684 | PASS                                                            |
| 17 / 1417 | `two-tabs initiator --observe=300`                                                                                               |  0.221 |         0.221 |   0.687 | PASS                                                            |
| 18 / 1418 | `cover-stall initiator --mode=scheduled --cadence=10000 --observe=180`                                                           |  0.009 |         0.009 |  18.582 | PASS                                                            |
| 19 / 1419 | `baseline initiator --mode=scheduled --cadence=70000 --observe=300`                                                              |  0.008 |         0.008 | 139.916 | PASS                                                            |
| 20 / 1420 | `proc-freeze-20 initiator --udpflood=1 --mode=scheduled --cadence=10000 --transfer=A2B:0.5 --observe=240 --transferdeadline=200` |  2.023 |         2.023 |  79.732 | PASS; byte-exact, receiver +56.106s / sender delivered +60.109s |
| 21 / 1521 | `proc-freeze-20 responder --udpflood=1 --transfer=A2B:8 --cpuslow=A:6 --observe=180 --transferdeadline=150`                      |  3.024 |         3.024 |    5.92 | PASS; byte-exact, receiver +4.025s / sender delivered +5.023s   |
| 22 / 1422 | `old server: proc-freeze-20 initiator --udpflood=1`                                                                              |  2.028 |         2.028 |   2.534 | PASS                                                            |
| 23 / 1423 | `old server: two-tabs responder --observe=300`                                                                                   |  never |         never |   never | bounded non-convergence                                         |

All five transfer arms were byte-exact, had monotonic received chunk counts,
and ended with sender outcome `delivered` within their transfer deadlines.
The historical “151/151 chunks, zero retransmits” was a delivery measurement,
not proof that selective resume ran. In run 1412 the sender recorded two
retransmits while the receiver recorded zero; these are different counters.
Scheduled resume still re-sends every chunk because scheduled per-chunk
receipts remain deferred.

The intentionally wrong-PIN arm passed its failure-state criteria for 120 s:
one transport on each side, both reporting PIN mismatch, and no additional
peer requests after terminal failure. It is not an authenticated connection.

Against a pre-generation server, the responder replacement arm 1423 **did not
converge**. Its independent evidence checker established exactly three
rebuilds, one exhaustion warning and four total replacement-page transports;
no transport was created or rebuilt after exhaustion. The final signaling and
cleanup diagnostics remained sound. The measured lower bound after replacement
connect was 300.479 s, including
240.439 s after budget exhaustion. This limits churn; it does not repair
C1 against server 0.1.1. The compatibility checker returns
`residual-established` with `driverPass: false`. A full matrix reports this
expected non-pass through exit 1; matrix 1400 also recorded the failed
host-sleep-affected CPU arm described above.

Reproduce the complete matrix from `docs/e2e/desync/` after rebuilding above:

```sh
# On macOS, keep the host awake while browsers deliberately drop their wake locks.
caffeinate -i node desync-matrix.mjs --jobs=3 --runbase=1600 --portbase=5860
node desync-compatibility.mjs ../runs/two-tabs-responder-1623.json ../runs/matrix-1600.json
```

Arm 21 runs alone so the sixfold CPU-throttle observation is not confounded by
other matrix browsers. Matrix 1400 was invoked with
`--arms=4,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23`; its raw manifest and
all retained 1200 arm hashes are in the machine-readable record. The final
CPU rerun used `--jobs=1 --runbase=1500 --portbase=5860 --arms=21`.

The actual built site (`f88cd39`) and server (`b901278`) were also tested through
the UI with isolated PostgreSQL on port 6543. Initial messaging, remembered
consent after reload (882 ms), unattended server-restart recovery (3,536 ms),
responder replacement (886 ms, then 10 s without competing socket opens),
120.6 s of stable visible PIN failure, and delivery after one-sided PIN
correction all passed. There were zero browser page errors, and every context
fetched the vendored WASM from the site's origin. The saved-preference hydration
regression passed navigation and reload on both `/r` and `/rooms` without an
unrequested connection. See the site's `e2e/desync-local-stack.mjs`,
`e2e/room-hydration.mjs`, and README for reproduction commands.

Final production checks: SDK **1,674 tests / 23,986 assertions** and both
TypeScript configurations; server **120 / 442** and TypeScript; site
**116 / 410**, TypeScript, lint, build, clean offline install and provenance.
The final three harness test files passed **50 tests / 134 assertions**.
Those counts overlap the full SDK run; the full SDK run also includes the
uncommitted prototype tests and is not a desync-only count. Negative controls
failed for missing final evidence, late recovery, bad diagnostics, PIN churn,
invalid compatibility evidence and the former scheduled probe deadline.

C6, C10, C11, C9's roster protocol half, per-chunk scheduled receipts and
old-server socket replacement remain in [ROADMAP](../../ROADMAP.md). No push,
package publication or deployment is part of this local verification.

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


## Desync follow-ups (2026-09-08, SDK 0.14.9)

SDK **0.14.9** with server **0.1.3** passed the four follow-up acceptance checks
on September 8–9, 2026: all nine new browser cases, the scoped regression
selection, and both actual site/server tests. The isolated production SDK suite
passed **1,771 tests / 24,568 assertions**. The validated package SHA-256 is
`61a719a28652704d1e6d599c9eed0cf394e1805d1a344e0e71320eb2423a917e`.

This section records the follow-ups implemented after the 0.14.8 report above.
The historical report and
[its machine-readable results](desync-results-2026-09-08.json) are preserved;
the earlier list of deferred follow-ups describes that release. The new
[evidence ledger](desync-followup-results-2026-09-08.json) separates valid
negative controls, exploratory results, excluded runs and final acceptance. No
exploratory pass is counted as a final release result.

| Follow-up                  | Implemented behavior                                                                                                                                                                              | Final browser evidence required                                                                                                         |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| C6                         | Pending real scheduled work defers local PQ healing; an incoming epoch change retires the old producer and resumes under the new epoch.                                                           | Local and incoming due-healing overlap, actual epoch advancement and byte-exact payloads.                                               |
| C9/C11                     | Correlated roster snapshots keep eligible membership separate from live transports; bounded per-member repair and trailing redial recover a missing edge while healthy siblings remain connected. | Three peers, A-C interruption plus a 12-second signaling blackhole, unchanged healthy A-B/B-C edges.                                    |
| C10                        | A fenced durable outbox retains the original staged payload across reload or exhausted in-memory retries, with bounded storage and cancellation/expiry cleanup.                                   | Immediate and scheduled reload, interruption longer than the original attempt budget, cancellation, and reload to an archived receiver. |
| Selective scheduled resume | Authenticated chunk receipts skip acknowledged nonzero indices; a single index-zero completion probe remains permitted.                                                                           | Compare actual emitted real-cell indices with the pre-fault ACK set, then verify the original payload and Merkle root.                  |

The first SDK **0.14.9** candidate with server **0.1.3** was superseded after
its 70-second scheduled-cadence regression failed. Its package SHA-256 was
`6bc7301e880b844d855bcdbdcad926566d34e01abbaefe1a4225874e3fa27fb5`. The package,
browser bundle, worker, production WASM and input manifest are preserved under
`runs/followups-2026-09-08/receipt-delay-candidate/`, with hashes in the ledger.
Production WASM is 211,350 bytes, SHA-256
`7fc91b615f6ca7f7f61497b784c8e75102751cdc84251bcadcd688aaa17c4d76`.

That candidate's isolated SDK suite at `0f13382` (runtime source `a9de0ef`)
passed **1,766 tests / 24,546 assertions**, with zero failures across 183 files.
The command exit and summary were recorded; a complete raw test log was not
archived. The earlier active-checkout count of 1,783 tests includes preserved,
unrelated prototype changes and is not the production package count. All seven
package checks passed for the superseded artifact; these results do not replace
final validation of the corrected package.

Commit `78067ce` fixes the receipt ordering. Its focused tests passed **94 tests
/ 503 assertions**; the final owned-file run after test-only type narrowing
passed **27 / 216**, overlapping the focused count. Source/test type checks and
scoped lint/format checks passed. Real-scheduler virtual 70-second cadence
regressions failed before the fix for F1, F16 and mixed-root ordering, then
passed after it. The corrected SDK 0.14.9 package at `78067ce` passed all seven
release checks, SHA-256
`61a719a28652704d1e6d599c9eed0cf394e1805d1a344e0e71320eb2423a917e`. Its frozen
browser bundle hash is
`a555f9070c8478f919e3eec55db20fc139960605b981fa0c2db9bd43abecd642`; the worker
and production WASM match the preserved prior-candidate assets. The ledger
records the complete new input manifest. The post-fix isolated SDK suite passed
**1,771 tests / 24,568 assertions** with zero failures across 183 files in 27.80
seconds. This is a reported command result; no raw log path was supplied. Both
final site/server browser checks passed.

The valid old-code browser controls use archived SDK 0.14.8. In
`mesh-recovery-before-3`, A-C never recovered through 71.826 seconds after the
fault, while all 143 samples retained healthy A-B and B-C edges. In
`sender-recovery-before-reload-immediate-1`, the original 8 MiB transfer
remained at 222,884 received bytes after sender reload and a 60-second
completion window. Both drivers correctly failed with unchanged inputs and no
page errors. An isolated leading-only debounce mutation also failed the trailing
redial regression: calls `[1]` instead of `[1, 3]`. That mutation used a copied
implementation and did not change production source.

The exploratory results established the following behavior before the final
release inputs were frozen:

| Run                                                                   | Observed result                                                                                                                                                                                       |
| --------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `mesh-recovery-after-1`                                               | A-C recovered 3.259 seconds after the 12-second blackhole cleared; both healthy sibling edges survived all 142 samples.                                                                               |
| `sender-recovery-after-reload-immediate-1`                            | Original 8 MiB payload completed byte-exactly 35.135 seconds after reload began; pending outbox entry cleared.                                                                                        |
| `sender-recovery-after-reload-scheduled-1`                            | Original 0.5 MiB scheduled payload completed byte-exactly in 30.735 seconds; pending entry cleared.                                                                                                   |
| `sender-recovery-after-cancel-immediate-1`                            | Public cancellation removed both the pending sender transfer and the receiver partial.                                                                                                                |
| `sender-recovery-after-mixed-immediate-1` / `after-mixed-scheduled-1` | Current sender reloaded against an archived 0.14.8 receiver; original immediate/scheduled payloads completed byte-exactly in 36.269 / 30.765 seconds.                                                 |
| `scheduled-selective-after-1`                                         | ACK set `[0,1,2,3]`; resumed real indices `[0,4,5,6,7,8,9]`: six missing chunks plus one completion probe, with final byte-exact delivery.                                                            |
| `scheduled-pq-after-1`                                                | Local due healing deferred until real work drained; an incoming exchange advanced epoch 1 to 2 during pending work on the same PC and cover runtime, then completed the 0.5 MiB payload byte-exactly. |

These exploratory runs passed with unchanged inputs and no page errors.
`mesh-recovery-before-1` and `before-2` are excluded fixture startup/ordering
failures. `sender-recovery-after-long-loss-immediate-1` is also **excluded**: it
delivered after 139.902 seconds, including a 100-second interruption, but
`inputsUnchanged=false` because harness files changed during the run. The failed
result remains recorded and cannot satisfy final acceptance.

The following three runs passed against the **superseded candidate**. Their
filenames contain `final`, but they do not count toward final acceptance of the
receipt fix:

| Prior-candidate artifact                                      | Observed result                                                                                                                                                                                                                                               |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sender-recovery-sender-recovery-final-long-loss-immediate-1` | PASS: 100-second pair signaling blackhole; original attempt rejected after 33.065 seconds while its durable manifest remained pending; the original 8 MiB payload and Merkle root recovered automatically, byte-exact, 139.949 seconds after the fault began. |
| `mesh-recovery-final-1`                                       | PASS: A-C recovered 3.242 seconds after the 12-second blackhole cleared; healthy A-B and B-C transports stayed authenticated and unchanged through all 143 samples.                                                                                           |
| `sender-recovery-final-reload-immediate-1`                    | PASS: original 8 MiB payload and root recovered automatically, byte-exact, 35.069 seconds after sender reload began.                                                                                                                                          |

All three used unchanged inputs and passed final authentication, reciprocal
fingerprints and cleanup diagnostics; the sender runs cleared their outbox
entries. The long-loss clock includes the 100-second interruption and does not
establish a general latency bound. Its duplicated filename prefix is retained
exactly as generated.

**Retained candidate failure:** `baseline-initiator-2019`, matrix arm 19, failed
both baseline directions at 173.281 seconds with a 173.282-second budget and
70-second cover cadence. Authentication and reciprocal fingerprints were
healthy; terminal receipts were delayed behind queued chunk-ACK work, leaving
both send mutations pending. The 300-second observation phase never started.
Commit `78067ce` makes a terminal receipt supersede unsent chunk-ACK batches for
the same root, allowing it into the first reverse receipt job. Cover cadence,
frame counts and harness budgets are unchanged.

Matrix 2000 completed all 23 arms on the earlier candidate with unchanged
inputs: **21 driver passes, the real arm 19 failure, and the expected arm 23
old-server non-convergence**. The compatibility checker established the latter
as a bounded residual: three rebuilds at the cap of three, one exhaustion event,
at least 300.506 seconds observed after connect and 240.420 seconds after
exhaustion. The underlying arm still has driver exit 1.

All 23 prior raw-result hashes and their original package/input provenance are
preserved in the ledger. Matrix 2100 passed all three affected scheduled arms
with unchanged inputs and budgets: arm 18 I4 = 18.439 seconds, arm 19 I4 =
140.005 seconds, and arm 20 I4 = 39.886 seconds. At 70-second cadence, arm 19's
initial sends completed in 131.746 / 131.607 seconds under the same
173.282-second budget; its observation window remained 300 seconds.

The combined regression selection contains **22 driver passes and one bounded
old-server residual** across all 23 arms. It retains unaffected arms 1–17 and
21–23 with their prior-candidate provenance and replaces only arms 18–20 with
the corrected-package runs. This is a scoped selection, not a claim that all 23
arms ran on the new package. The genuine earlier arm 19 failure remains
recorded. Corrected-package follow-up and site/server results are listed below.

Two site fixture startup failures are excluded: the September 8 attempt was
blocked from binding its loopback listener, and the September 9 05:58 UTC
attempt's owned server exited before readiness (the reported cause was local
Postgres SSL configuration). Neither executed a browser scenario or fetched
WASM; neither is counted as a product failure or an acceptance pass. No failed,
invalid or old-server bounded non-convergence result is relabeled as a
convergence pass.

<!-- final-followup-cases:start -->

Corrected-package follow-up cases: **9 / 9 passed**. Each recorded case matches
the frozen candidate, has no page errors and passes final authentication,
reciprocal fingerprints and cleanup diagnostics.

| Corrected-package artifact                    | Result                                                                                                                                        |
| --------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `mesh-recovery-final-2`                       | PASS: A-C recovered 3.270s after blackhole clearance; healthy siblings unchanged in 142 samples.                                              |
| `scheduled-pq-final-1`                        | PASS: Local due healing deferred; incoming epoch 1 to 2 overlapped real work on the same PC/runtime; both payloads byte-exact.                |
| `scheduled-selective-final-1`                 | PASS: ACKed [0, 1, 2, 3]; resumed [0, 4, 5, 6, 7, 8, 9]: six missing plus one completion probe; byte-exact.                                   |
| `sender-recovery-final-cancel-immediate-1`    | PASS: Public cancellation removed the sender pending transfer and receiver partial.                                                           |
| `sender-recovery-final-mixed-immediate-1`     | PASS: Original 8 MiB payload/root recovered byte-exactly in 34.772s; outbox cleared. Archived SDK0.14.8 receiver.                             |
| `sender-recovery-final-reload-scheduled-1`    | PASS: Original 0.5 MiB payload/root recovered byte-exactly in 30.657s; outbox cleared.                                                        |
| `sender-recovery-final-mixed-scheduled-1`     | PASS: Original 0.5 MiB payload/root recovered byte-exactly in 30.668s; outbox cleared. Archived SDK0.14.8 receiver.                           |
| `sender-recovery-final-reload-immediate-2`    | PASS: Original 8 MiB payload/root recovered byte-exactly in 34.591s; outbox cleared.                                                          |
| `sender-recovery-final-long-loss-immediate-2` | PASS: Original 8 MiB payload/root recovered byte-exactly in 140.127s; outbox cleared. Includes the 100s fault and exhausted original attempt. |

<!-- final-followup-cases:end -->

The built site's pending-transfer UI passed against the real signaling server:
`p2party.com/logs/desync/pending-ui-2026-09-09T06-03-40.989Z.json` records the
corrected SDK package hash and server **0.1.3 / protocol 4**. A partial 1 MiB
transfer remained visible after sender reload; automatic resume and a user retry
emitted new real frames for the same transfer/root. While that manual retry was
still active, navigation away and back preserved the enabled Cancel button;
cancellation removed both the sender outbox entry and receiver partial. This
case deliberately retains a frame fault and tests lifecycle behavior, not
completed delivery. Both peers fetched the versioned WASM URL successfully;
there were zero page errors. The local public WASM hash also matches the release
artifact. The earlier 06:01 UTC UI pass is retained but the stricter 06:03 UTC
report supplies final evidence.

The existing site-stack regression also passed:
`p2party.com/logs/desync/2026-09-09T06-30-31.903Z/result.json` records the same
SDK package/WASM hashes and real server 0.1.3 before and after restart. It
verified UI chat, remembered-consent reload (0.890 seconds), automatic recovery
after server restart (3.547 seconds), and second-tab replacement (0.683 seconds)
with the old owner closed by code 1008. Wrong-PIN observation lasted 120.945
seconds across 120 samples with exactly one PC created on each side; an explicit
corrected-PIN retry then authenticated and exchanged a message. There were no
captured errors and all 60 observed WASM responses returned 200. These local
timings describe the recorded runs and are not general bounds.

The new drivers are [mesh-recovery.mjs](desync/mesh-recovery.mjs),
[sender-recovery.mjs](desync/sender-recovery.mjs) and
[scheduled-recovery.mjs](desync/scheduled-recovery.mjs). Their `--run` value
names the output artifact. The sender driver selects `--fault=reload`,
`--fault=long-loss` or `--fault=cancel`, and `--mode=immediate` or
`--mode=scheduled`. `--legacy=receiver` archives only B; `--before=1` archives
both peers. The scheduled driver selects `--case=pq` or `--case=selective`.

The efficiency evidence concerns **real resumed cells**, bounded by missing
chunks plus one completion probe. Fixed cover traffic remains fixed; full roster
snapshots, staged-index scans and total system costs have no general sublinear
guarantee. Advanced roster behavior requires server 0.1.3, and bounded retries
do not make an indefinitely offline member recover. These are
macOS/headless-Chromium loopback checks; WAN/mobile behavior and a cryptographic
audit remain outside this evidence. Blind rendezvous, PoW, passkeys and
Sybil-resistance work are outside this release. Nothing in this report records a
package publication or deployment.
