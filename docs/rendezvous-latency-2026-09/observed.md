# Where the 35–42 s actually goes

Measurement of the flagged two-store blind-rendezvous prototype at the pinned
delivery profile (`--window-ms=4000`, cohort 8, `--scenario=healthy`), on
`feat/blind-two-store-prototype` @ `127ca95`, macOS 25.6.0 / arm64, headless
Chromium 1234, `bun 1.3.14`, `node v24.11.1`. Three converging runs plus two
isolating probes. Everything below is measured; nothing is modelled except
where a line says so.

**Tree state: clean.** `run.mjs` was temporarily instrumented (an env-gated
`P2PARTY_BLIND_TRACE` dump of the event log and a Playwright-side
`requestfinished` trace — driver-side observation only, nothing in the page or
in `src/`) and has been **reverted byte-for-byte** (`md5 398e9a616a83724b1aec95a697dca6b4`,
`git status` clean). The micro-benchmark and probe scripts live only in this
scratchpad. `docs/e2e/blind-two-store/bundle.js` and `libcrypto.wasm` were
rebuilt by `build.sh`; both are generated and `.gitignore`d.

---

## 0. The one-paragraph answer

**Nothing in this rendezvous is compute-bound, and almost nothing is
network-bound in the sense of bandwidth.** Client-side cryptography for one
window's entire scan — decode + trial-open of all 40 carrier objects,
1,380,336 bytes — is **4.0 ms per store, 8 ms for both**. The wall time of that
same scan in a real run is **~1,450 ms**, of which **~99.5 % is the store
process**: `storeSqlite.loadWindow` `JSON.parse`s the *entire* hex-encoded
window document on **every single chunk GET**, which costs a flat **97 ms per
request** and blocks the store's single-threaded event loop, so the five chunk
GETs of one scan are served strictly serially. That ~1,450 ms scan then lands
at **~+2,100 ms into the delivery window — after every append slot the profile
defines (the latest is 2,100 ms)** — so every answer misses its own window's
slot and waits for the next one. That is what turns the design's one-window-per-flight
cadence into **two windows per flight**, and five dependent flights × 8 s = the
35–40 s observed.

---

## 1. The three runs

Verbatim harness verdicts (full stdout in `run1.stdout.txt`, `run2.stdout.txt`,
`run3.stdout.txt` beside this file):

```
run1  SCENARIO healthy PASS in 35.5s — 140005 bytes A→B and 9005 bytes B→A decrypted byte-exact; topology A=multi-store-union B=multi-store-union; 0 of 148 needles found in the 290 request bodies the audit searched
run2  SCENARIO healthy PASS in 38.7s — 140005 bytes A→B and 9005 bytes B→A decrypted byte-exact; topology A=multi-store-union B=multi-store-union; 0 of 148 needles found in the 322 request bodies the audit searched
run3  SCENARIO healthy PASS in 40.4s — 140005 bytes A→B and 9005 bytes B→A decrypted byte-exact; topology A=multi-store-union B=multi-store-union; 0 of 148 needles found in the 328 request bodies the audit searched
```

All three converged. The spread (35.5 → 40.4 s) is explained exactly, and not
by variance-hand-waving: see §4.

The profile header both stores and both pages agreed on:

```
delivery profile: window 4000ms, cohort 8, chunks/window 3+2, hash 83a2261ee4c0f345…
per client per store per window: appends 172542 bytes, full scan 1380336 bytes
```

---

## 2. Per-phase breakdown, both pages, with the window each transition sits in

Post-processed from the raw event log (`PrototypeRunEvent.atMs` is
`Date.now()`, so window index = `floor(atMs / 4000)` exactly as
`ingressWindow()` computes it). `w0` is the delivery window that contained
`presence-published`; `offset` is ms into that window.

### run 1 — 35.44 s to `message-verified`

```
phase                     page   epochMs        t+ (s)  window  offset(ms)  Δprev(s)
presence-published        A    1788851698710     0.000  w0+0      2710
peer-observed             A    1788851706083     7.373  w0+2      2083        7.373
hello-sent                A    1788851706087     7.377  w0+2      2087        0.004
accepted                  A    1788851722106    23.396  w0+6      2106       16.019
offer-sent                A    1788851722243    23.533  w0+6      2243        0.137
handoff                   A    1788851734124    35.414  w0+9      2124       11.881
webrtc-connected          A    1788851734128    35.418  w0+9      2128        0.004
dtls-verified             A    1788851734129    35.419  w0+9      2129        0.001
session-authenticated     A    1788851734136    35.426  w0+9      2136        0.007
message-sent              A    1788851734142    35.432  w0+9      2142        0.006
message-verified          A    1788851734154    35.444  w0+9      2154        0.012

presence-published        B    1788851698710     0.000  w0+0      2710
peer-observed             B    1788851706082     7.372  w0+2      2082        7.372
hello-opened              B    1788851714122    15.412  w0+4      2122        8.040
accepted                  B    1788851714125    15.415  w0+4      2125        0.003
offer-opened              B    1788851729371    30.661  w0+8      1371       15.246
answered                  B    1788851729373    30.663  w0+8      1373        0.002
handoff                   B    1788851729373    30.663  w0+8      1373        0.000
webrtc-connected          B    1788851734127    35.417  w0+9      2127        4.754
dtls-verified             B    1788851734128    35.418  w0+9      2128        0.001
session-authenticated     B    1788851734136    35.426  w0+9      2136        0.008
message-sent              B    1788851734139    35.429  w0+9      2139        0.003
message-verified          B    1788851734176    35.466  w0+9      2176        0.037
```

### run 2 — 38.70 s

```
phase                     page   epochMs        t+ (s)  window  offset(ms)  Δprev(s)
presence-published        A    1788851743438     0.000  w0+0      3438
peer-observed             A    1788851750127     6.689  w0+2      2127        6.689
hello-opened              A    1788851758086    14.648  w0+4      2086        7.959
accepted                  A    1788851758090    14.652  w0+4      2090        0.004
offer-opened              A    1788851774161    30.723  w0+8      2161       16.071
answered                  A    1788851774162    30.724  w0+8      2162        0.001
handoff                   A    1788851774162    30.724  w0+8      2162        0.000
webrtc-connected          A    1788851782091    38.653  w0+10     2091        7.929
dtls-verified             A    1788851782092    38.654  w0+10     2092        0.001
session-authenticated     A    1788851782099    38.661  w0+10     2099        0.007
message-sent              A    1788851782105    38.667  w0+10     2105        0.006
message-verified          A    1788851782113    38.675  w0+10     2113        0.008

presence-published        B    1788851743438     0.000  w0+0      3438
peer-observed             B    1788851750127     6.689  w0+2      2127        6.689
hello-sent                B    1788851750131     6.693  w0+2      2131        0.004
accepted                  B    1788851766103    22.665  w0+6      2103       15.972
offer-sent                B    1788851766229    22.791  w0+6      2229        0.126
handoff                   B    1788851782088    38.650  w0+10     2088       15.859
webrtc-connected          B    1788851782092    38.654  w0+10     2092        0.004
dtls-verified             B    1788851782092    38.654  w0+10     2092        0.000
session-authenticated     B    1788851782099    38.661  w0+10     2099        0.007
message-sent              B    1788851782102    38.664  w0+10     2102        0.003
message-verified          B    1788851782137    38.699  w0+10     2137        0.035
```

### run 3 — 40.36 s

```
presence-published        A    1788852033720     0.000  w0+0      1720
peer-observed             A    1788852041601     7.881  w0+2      1601        7.881
hello-opened              A    1788852050107    16.387  w0+4      2107        8.506
accepted                  A    1788852050110    16.390  w0+4      2110        0.003
offer-opened              A    1788852066071    32.351  w0+8      2071       15.961
answered                  A    1788852066073    32.353  w0+8      2073        0.002
handoff                   A    1788852066073    32.353  w0+8      2073        0.000
webrtc-connected          A    1788852074035    40.315  w0+10     2035        7.962
dtls-verified             A    1788852074036    40.316  w0+10     2036        0.001
session-authenticated     A    1788852074043    40.323  w0+10     2043        0.007
message-sent              A    1788852074048    40.328  w0+10     2048        0.005
message-verified          A    1788852074062    40.342  w0+10     2062        0.014

presence-published        B    1788852033720     0.000  w0+0      1720
peer-observed             B    1788852042090     8.370  w0+2      2090        8.370
hello-sent                B    1788852042094     8.374  w0+2      2094        0.004
accepted                  B    1788852058060    24.340  w0+6      2060       15.966
offer-sent                B    1788852058187    24.467  w0+6      2187        0.127
handoff                   B    1788852074032    40.312  w0+10     2032       15.845
webrtc-connected          B    1788852074036    40.316  w0+10     2036        0.004
dtls-verified             B    1788852074036    40.316  w0+10     2036        0.000
session-authenticated     B    1788852074043    40.323  w0+10     2043        0.007
message-sent              B    1788852074046    40.326  w0+10     2046        0.003
message-verified          B    1788852074080    40.360  w0+10     2080        0.034
```

**Read the `window` column and everything else falls out.** Every phase event
that comes out of a read lands at **offset ≈ 2,050–2,160 ms** into its window,
and the milestones land in windows `w0+2, w0+4, w0+6, w0+8, w0+10` — one
flight every **two** windows, never one. `handoff → webrtc-connected →
dtls-verified → session-authenticated → message-sent → message-verified` on the
same page is **4 + 1 + 7 + 5 + 8 ms**; the whole WebRTC + protocol-v4 tail is
**~50 ms** and is a rounding error.

---

## 3. Flight budget: where each 8 s goes

The `(role, size class)` of an operation selects **exactly one append offset per
window** — `carrierRuntime.#pendingEntry(storeIdHex, role, sizeClassId)` matches
role *and* class, and the pinned profile gives:

| size class | identity-bootstrap | safety-control | state-replication |
| ---------- | -----------------: | -------------: | ----------------: |
| 0 (8,294 B wire) | **1,300 ms** | 1,700 ms | 2,100 ms |
| 1 (73,830 B wire) | *(none)* | **1,500 ms** | 1,900 ms |

and `workKinds.operationServiceRole` maps
`IDENTITY_HELLO`/`IDENTITY_ACCEPT` → identity-bootstrap,
`PRESENCE` → state-replication, `TRANSPORT_OFFER`/`TRANSPORT_ANSWER` →
safety-control (the `default:` branch).

> **Correction, 2026-09-08 (stage 1).** The reconstruction below puts both
> transport flights in the **class-1** safety-control slot at 1,500 ms. It is
> the class-**0** slot at 1,700 ms. The role mapping above is right and the size
> class was inferred from it, but the class is chosen by `padPairPlaintextV1`
> from the SDP's size, not by the role — and until `196c52e` nothing reported
> it. The harness now asserts it: `--scenario=all` prints
> `offer-sent — operationPayloadClass 0` and
> `answered — operationPayloadClass 0` on both pages, in every run recorded
> since. The `slot fired` column for the TRANSPORT rows below is therefore
> 200 ms early, and every "grid wait" derived from it is 200 ms short.

Reconstructed per flight from the event log + the request trace
(`budget.mjs`). `*` marks the one flight in 15 that caught a slot **in the same
window it was enqueued in**:

```
run     flight            producer      enqueue    slot fired   peer read   peer opened   grid wait  scan wall  open+drive  flight
run1    PRESENCE          A->B     2710ms    1900ms      2700ms       1482ms      5.89s      1.46s      0.015s   7.37s
run1    IDENTITY_HELLO    A->B     2087ms    1300ms      3300ms       1522ms      6.51s      1.50s      0.023s   8.04s
run1    IDENTITY_ACCEPT   B->A     2125ms    1300ms      3300ms       1506ms      6.47s      1.47s      0.030s   7.98s
run1    TRANSPORT_OFFER   A->B     2243ms    1500ms      3100ms        771ms      6.36s      0.73s      0.039s   7.13s
run1    TRANSPORT_ANSWER  B->A     1373ms    1500ms*     3100ms       1524ms      3.23s      1.50s      0.022s   4.75s

run2    PRESENCE          B->A     3438ms    1900ms      2700ms       1527ms      5.16s      1.51s      0.014s   6.69s
run2    IDENTITY_HELLO    B->A     2131ms    1300ms      3300ms       1486ms      6.47s      1.45s      0.030s   7.96s
run2    IDENTITY_ACCEPT   A->B     2090ms    1300ms      3300ms       1503ms      6.51s      1.47s      0.029s   8.01s
run2    TRANSPORT_OFFER   B->A     2229ms    1500ms      3100ms       1561ms      6.37s      1.53s      0.027s   7.93s
run2    TRANSPORT_ANSWER  A->B     2162ms    1500ms      3100ms       1488ms      6.44s      1.45s      0.032s   7.93s

run3    PRESENCE          B->A     1720ms    1900ms*     2700ms       5001ms      2.88s      1.25s      3.743s   7.88s   <- see note
run3    IDENTITY_HELLO    B->A     2094ms    1300ms      3300ms       1507ms      6.51s      1.48s      0.029s   8.01s
run3    IDENTITY_ACCEPT   A->B     2110ms    1300ms      3300ms       1460ms      6.49s      1.44s      0.018s   7.95s
run3    TRANSPORT_OFFER   B->A     2187ms    1500ms      3100ms       1471ms      6.41s      1.44s      0.026s   7.88s
run3    TRANSPORT_ANSWER  A->B     2073ms    1500ms      3100ms       1432ms      6.53s      1.41s      0.020s   7.96s

full two-store scan wall time (first chunk GET -> last byte): n=58 min=714.9 p50=1452.7 mean=1363.9 max=1531.2 ms
last scan byte -> phase event (decode+trial-open+validate+driver): n=15 min=13.9 p50=27.2 max=39.1 ms (excluding the run3 PRESENCE row)
```

*Note on the run3 PRESENCE row:* my reconstruction attributes it to `w0+0`'s
1,900 ms slot, but the page cold-started at `+1,720 ms`, i.e. **after**
`allocationRequestOffsetMs = 700`, so that window held no lease and the store
answered `unallocated-cover` and discarded the object (the harness prints the
`cold start past the allocation offset` line). `carrierRuntime.#append` returns
without clearing the outbox entry when `held === null`, so PRESENCE actually
rode `w0+1`'s slot. The 3.743 s in that cell is the artefact of my model, not a
measurement. This is the **cold-start window** and it is real: a client starting
anywhere in the 82 % of a window after `+700 ms` burns one whole window before
its first admitted append.

**Per-flight decomposition (median of 13 clean flights):**

| component | ms | share | what it is |
| --- | ---: | ---: | --- |
| enqueue → the matching `(role,class)` append slot | ~3,200 | 40 % | **waiting for a grid point** |
| that slot → the peer's read offset in the next window | ~3,300 | 41 % | **waiting for a grid point** |
| the peer's two-store scan (10 chunk GETs, 2.76 MB) | ~1,450 | 18 % | **the store process** |
| decode + trial-open + Merkle + validate + driver + reseal | ~27 | 0.3 % | **client compute** |
| **flight total** | **~7,980** | | |

Five flights ≈ 40 s; run 1 came out at 35.4 s because one flight (`TRANSPORT_ANSWER`)
caught its own window's slot and cost 4.75 s instead of 7.9 s.

**The 40 % "wait for a slot" is not independent of the 18 % store cost — it is
caused by it.** The read is armed at `publicReadOffsetMs = 600`. For a reply to
ride the *same* window it must be enqueued before its slot, i.e. the scan must
finish within:

| the reply | its slot | scan budget from the read offset |
| --- | ---: | ---: |
| IDENTITY_HELLO / IDENTITY_ACCEPT (class 0, identity-bootstrap) | 1,300 ms | **700 ms** |
| TRANSPORT_OFFER / ANSWER (class 1, safety-control) | 1,500 ms | **900 ms** |
| TRANSPORT_* (class 0, safety-control) | 1,700 ms | 1,100 ms |
| PRESENCE (class 1, state-replication) | 1,900 ms | 1,300 ms |
| PRESENCE (class 0, state-replication) | 2,100 ms | 1,500 ms |

Measured scan wall times: **min 715 ms, p50 1,453 ms, max 1,531 ms** (n = 58).
The identity flights need 700 ms and essentially never get it. The one flight
that made it (run 1, `TRANSPORT_ANSWER`) is the one whose preceding scan took
**732 ms** against a 900 ms budget. **That single data point is the whole
mechanism, observed.**

---

## 4. The per-window scan, measured directly

### 4a. Bytes fetched — matches the computed geometry

Per client, per store, per window (five chunk GETs, from the Playwright request
trace, `sizes.responseBodySize`):

| what | class 0 (×3 chunks) | class 1 (×2 chunks) | total |
| --- | ---: | ---: | ---: |
| observed body bytes per chunk | 66,534 | 590,822 | |
| observed per store per window | 199,602 | 1,181,644 | **1,381,246** |
| computed (`profileTool info`) | 199,056 | 1,181,280 | **1,380,336** |

The +910 B is the five chunks' canonical framing. **Class 1 is 85.6 % of the
scan** — that part of my prior belief is confirmed exactly. Both stores
together: **2,762,492 B per client per window.**

### 4b. Time in `openCarrierEnvelope` — 4 ms, not seconds

Micro-benchmark (`scanbench.ts`, built with `bun build`, run in the same
headless Chromium) that seals one whole bucket the way
`carrierRuntime.#coverObject` does and then decodes + trial-opens all 40
objects the way `carrierRuntime.#openObjects` does — i.e. the real
`decodeCarrierEnvelope` + `openCarrierEnvelope` path, every open failing,
which is what 39 of 40 objects in a real window are:

```
{
  "windowMs": 4000,
  "cohort": 8,
  "objectsPerStore": 40,
  "wireBytesPerStore": 1380336,
  "sealMsForOneWholeBucket": 8.3,
  "perStoreScan": [
    { "decodeMs": 2.8, "openMs": 1.9, "totalMs": 4.7 },
    { "decodeMs": 1.6, "openMs": 2.4, "totalMs": 4   },
    { "decodeMs": 1.4, "openMs": 2.9, "totalMs": 4.3 },
    { "decodeMs": 1.4, "openMs": 2.6, "totalMs": 4   },
    { "decodeMs": 2.2, "openMs": 1.8, "totalMs": 4   }
  ],
  "perClass": {
    "class0": { "n": 24, "decodeMs": 0.50, "openMs": 0.60 },
    "class1": { "n": 16, "decodeMs": 1.70, "openMs": 1.20 }
  },
  "medianTotalMsPerStore": 4
}
```

**4.0 ms per store, 8 ms for both stores, per window.** 1,380,336 bytes of
XChaCha20-Poly1305 trial decryption plus 40 HKDF-SHA256 key derivations in
4 ms. The in-run upper bound agrees: `last scan byte → phase event` (which also
contains the RFC 9162 Merkle root recomputation over all 40 object hashes, the
custody check, the union, the Ed25519 validation of the one real operation, and
the driver's HPKE open + reseal of the reply) is **13.9–39.1 ms, p50 27.2 ms**.

### 4c. Where the 1,450 ms actually is: the store

Per-route cost over a whole run, both pages, both stores (run 3, with full
Playwright `ResourceTiming`; `ms` are after `startTime`):

```
route                                               n  connectStart  connectEnd  requestStart  responseStart  responseEnd
POST /p2party/prototype-v0/allocation              42           0.0         0.0         209.8         1269.4       1269.8
GET /p2party/prototype-v0/chunk/<hash>/<win>/<c>/<k>  200         0.0         0.1           1.0          853.9        890.6
POST /p2party/prototype-v0/append                 195           0.0         0.0          24.7          410.2        410.8
GET /p2party/prototype-v0/checkpoint/<hash>/<win>   40           0.0         0.0           1.0          320.2        321.5
POST /p2party/prototype-v0/witness                 36           0.0         0.0           0.1          121.1        122.4
GET /p2party/prototype-v0/witness/<hash>/<win>     36           0.0         0.0           0.1            5.8          6.1
POST /p2party/prototype-v0/allocation-token        40           0.0         0.0           0.3            2.1          3.1
GET /.well-known/p2party-store/prototype-v0         4           0.1         0.2           0.2            0.8          1.2
```

`requestStart` for chunk GETs is **1.0 ms** — the browser is not queueing them
and there is no connection cost on loopback. `responseStart` (TTFB) is
**854 ms**. Every millisecond of it is the store thinking.

Chunk TTFB by chunk index (run 3, n = 40 each) shows a **serial ladder**:

```
what             n   body B   TTFB mean  TTFB p50  TTFB max   end mean
class 0 chunk 0  40    66534      486.5     520.4     947.6      488.1
class 0 chunk 1  40    66534      672.2     723.8    1101.9      673.9
class 0 chunk 2  40    66534      856.8     928.8    1219.2      858.6
class 1 chunk 0  40   590822     1048.3    1132.6    1336.4     1174.9
class 1 chunk 1  40   590822     1205.5    1234.5    1453.3     1257.7
```

Even steps of ~180 ms, **independent of the chunk's size** (66 KB and 591 KB
cost the same step). That is not bandwidth.

### 4d. Isolating probe: one store, no client, `curl`

`storeprobe.sh` — one store process, no browser, let it finalize an all-dummy
window, then time chunk GETs:

```
store up on 5941 (pid 40934), waiting for two windows to finalize...
probing finalized window 447213109

sequential, cold (one request at a time):
  class0 chunk0  66534 B  0.097124s ttfb  0.097215s total
  class0 chunk1  66534 B  0.097652s ttfb  0.097780s total
  class0 chunk2  66534 B  0.097908s ttfb  0.098018s total
  class1 chunk0  590822 B  0.098282s ttfb  0.098843s total
  class1 chunk1  590822 B  0.098202s ttfb  0.098695s total

the same five, all at once (what one client's scan actually does):
  class0 chunk1 66534 B ttfb 0.192603s total 0.192690s
  class0 chunk2 66534 B ttfb 0.289376s total 0.289474s
  class0 chunk0 66534 B ttfb 0.481708s total 0.481802s
  class1 chunk0 590822 B ttfb 0.096682s total 0.481885s
  class1 chunk1 590822 B ttfb 0.385961s total 0.482443s
  wall for the whole 5-chunk scan: 519 ms
```

**97 ms per chunk GET, flat, whatever the chunk holds. Perfectly serial: 96,
192, 289, 386, 482.** In a real run two pages scan each store at the same
instant, so it is 10 serial reads, which is the observed ~854 ms mean TTFB and
~1,450 ms scan wall.

### 4e. Root cause, in the source

> **Correction, 2026-09-08 (stage 1).** This section, and every report that
> cites it, names `JSON.parse` as the cost. That attribution is wrong. Measured
> component-wise afterwards, `JSON.parse` of the window document is **0.30 ms**;
> the cost is the hand-rolled hex codec `hexOf`/`bytesFrom` (`storeSqlite.ts`,
> then at l. 68-78), which converted one character pair at a time over a
> multi-megabyte string. On this laptop the whole `loadWindow` of a
> pinned-profile window measured **122 ms p50 (n=12)** before the codec was
> replaced and **6.7 ms p50 (n=12)** after, and `saveWindow` **106 ms → 2.0 ms**
> — with no other change. The direction of every conclusion below is unchanged
> (the cost is `O(whole window document)` in the store, not in the client, and
> it is why the cohort looked like a latency knob); only the named line is.
> Read "`JSON.parse`" below as "rebuilding the whole document", and see
> `optimization-plan.md` §6.2(d).

`src/blindRendezvous/prototype/store/storeCore.ts:1121`

```ts
const state = await this.#persistence.loadWindow(requested.ingressWindow);
const chunk = state?.finalized?.chunks.get(sizeClass.id)?.[Number(chunkIndex)];
```

`src/blindRendezvous/prototype/store/storeSqlite.ts:277`

```ts
async loadWindow(window: bigint): Promise<StoreWindowState | null> {
  const row = this.#db.query(...).get(window);
  if (row === null) return null;
  return fromDocument(JSON.parse(textDecoder.decode(row.state)) as StoredWindowDocumentV1);
}
```

and `toDocument` (same file, l. 138) stores **every object as a hex string**,
**twice** — once in `slots`, once again inside `finalized.chunks`:

```ts
slots: [...state.slots].map(([key, slot]) => ({
  key, objectHash: hexOf(slot.objectHash), object: hexOf(slot.object),
})),
...
chunks: chunks.map(encodeChunk),   // encodeChunk = hexOf(encodeCanonical(...))
```

So one window document is ≈ 2 × 1,380,336 bytes of payload × 2 chars/byte of
hex ≈ **5.5 MB of JSON**, and **every chunk GET decodes it, `JSON.parse`s it,
and hex-decodes every slot and every chunk back to bytes** in order to return
one of them. On a single-threaded `bun` server that also blocks every other
request. The README already notes the disk consequence (2,763,134 B/window);
this is the latency consequence, and it has not been written down.

**Confirming prediction, tested.** If the cost is `O(whole window document)`,
halving the window's byte count should halve the per-request cost. At
`--cohort=2` the profile is 1+1 chunks, 656,992 B/window (2.10× smaller):

```
cohort-2 store up on 5942
probing finalized window 447213131 (cohort 2: 1+1 chunks, 656,992 B/window)
sequential, cold:
  class0 chunk0  66534 B  0.048389s ttfb  0.048465s total
  class1 chunk0  590822 B  0.045694s ttfb  0.046222s total
the same two, at once:
  class0 chunk0 66534 B ttfb 0.092003s total 0.092080s
  class1 chunk0 590822 B ttfb 0.046563s total 0.092518s
  wall for the whole 2-chunk scan: 92 ms
```

97 → 47 ms per request (2.06×, against a 2.10× byte ratio) and **519 → 92 ms
for the whole scan (5.6×)**, because the cohort also drops the request count
from 5 to 2. That is the mechanism behind the README's cohort table, stated
causally for the first time: **the cohort buys latency by shrinking the store's
per-request `JSON.parse`, not by shrinking the client's AEAD.**

---

## 5. Verdicts on the three prior beliefs

**(1) "The floor is structural: five dependent flights each gated by
`publicReadLagWindows = 1`, so each costs at least one delivery window; plus a
cold-start window." — CONFIRMED, and it is worse than stated.**

- Five dependent flights: confirmed, visible as the `w0+2 / w0+4 / w0+6 / w0+8 /
  w0+10` ladder in all three runs.
- The cold-start window: confirmed, with the exact mechanism. `start()` at any
  instant past `allocationRequestOffsetMs = 700` (82 % of a window) emits
  `cold start past the allocation offset` and the window's appends go out as
  **unallocated cover that the store discards**; `#append` leaves the entry
  queued, so the first real publication is one window later. Observed in all
  three runs.
- **What was missed:** the gate is not one window per flight, it is one window
  per flight *plus a `(role, size class)` slot match*. Because
  `#pendingEntry` requires both, each operation has exactly **one** append
  offset per window, and because the read finishes after all of them, every
  flight costs **two** windows. 14 of the 15 flights measured cost 2 windows.

**(2) "The per-window scan is ~1.38 MB per store, dominated by size class 1
(86 %) — and that is what stops the window from shrinking, because the browser
could not finish the per-window AEAD in the remaining slack." — HALF CONFIRMED,
HALF REFUTED.**

- The bytes and the 86 %: **confirmed exactly** (1,381,246 B observed vs
  1,380,336 computed; class 1 = 85.6 %).
- "The browser could not finish the per-window AEAD": **refuted.** The browser
  finishes the entire per-window AEAD for both stores in **8 ms**. What cannot
  be finished in the slack is the **store's** service of the scan: ~1,450 ms of
  `JSON.parse`, on a budget of 700 ms (identity flights) to 1,500 ms.
  The `--window-ms=2000` failure the README records as "every append arrives
  after `window-finalized`" has the same single cause: at 2,000 ms the
  finalization offset scales to 1,400 ms while the store still needs ~1,450 ms
  to answer one scan — so the appends, which queue behind the scan on the same
  serial event loop, land after finalization. It is a **store throughput**
  failure, not a browser-crypto failure.

**(3) "The two big levers are (a) make class 1 much smaller so the window can
shrink, and (b) collapse flights." — DIRECTIONALLY RIGHT, WRONG REASON for (a).**

Shrinking class 1 does help, but not because it saves client AEAD (that is 8 ms).
It helps because it shrinks the store's window document, which is what the
per-request 97 ms is linear in, and because fewer chunks means fewer serial
requests. Measured: 2.10× fewer bytes → 2.06× cheaper per request → 5.6× faster
scan. (b) is right and is the larger lever: at two windows per flight, five
flights, 4 s windows, flights are 80 % of the wall clock.

---

## 6. Which transition is dominated by what

| transition | dominated by | measured |
| --- | --- | --- |
| `presence-published` → own first admitted append | **grid wait** (cold-start window + slot offset) | 1 window + up to 4 s |
| `presence-published` → `peer-observed` | **grid wait** (2 windows) + one scan | 6.69 / 7.37 / 7.88–8.37 s |
| `peer-observed` → `hello-sent` | **compute** (HPKE seal of the pair step) | **4 ms** |
| `hello-sent` → `hello-opened` | **grid wait** (2 windows), because the scan misses the 1,300 ms slot | 7.96–8.51 s |
| `hello-opened` → `accepted` (same page) | **compute** | **3–4 ms** |
| `accepted` → peer's `accepted` | **grid wait** (2 windows) | 7.95–8.01 s |
| `accepted` → `offer-sent` | **compute** (`createOffer` + complete ICE gathering) | **126–137 ms** |
| `offer-sent` → `offer-opened` | **grid wait** (2 windows) | 7.88–7.93 s |
| `offer-opened` → `answered` → `handoff` | **compute** (`acceptOffer` + gather) | **1–2 ms** |
| `handoff` → `webrtc-connected` | **network/WebRTC** (loopback ICE) | **4 ms** |
| `webrtc-connected` → `dtls-verified` | compute (`getStats` + fingerprint compare) | **0–1 ms** |
| `dtls-verified` → `session-authenticated` | compute (protocol-v4 handshake over the channel) | **7 ms** |
| `session-authenticated` → `message-verified` (140 kB, 3 frames) | compute + data channel | **8–35 ms** |
| **inside every read**: chunk GETs | **the store process** | **~1,450 ms** |
| **inside every read**: decode + trial-open + Merkle + validate | **compute** | **14–39 ms** |

Summed over run 1: **~33.4 s of grid wait, ~1.9 s of store service on the
critical path, ~0.2 s of everything else.**

---

## 7. What this says about the optimisation space

Stated as measurements and their direct implications, not as a plan. None of
these is implemented or endorsed here; each is flagged with what it would cost
in disclosure terms.

1. **Fix `loadWindow` — free, no privacy surface at all.** Serving a chunk
   should read one row, not `JSON.parse` the whole window. Storing the finalized
   chunks as their own rows of raw `BLOB` (no hex, no JSON) would take the
   per-request cost from ~97 ms to a `SELECT` plus a write. This changes **no
   byte on the wire**, no request shape, no geometry, and no disclosure. It is
   the single largest lever measured, and it is entirely inside
   `storeSqlite.ts`/`storeCore.ts`. Predicted effect from §4d: the two-store
   scan drops from ~1,450 ms to the tens of ms, which puts every flight back
   inside its own window's slot — that is 2 windows/flight → 1, i.e.
   **~40 s → ~20 s at the *same* pinned profile, with nothing given up.**
   Everything below is only worth doing after this, because until it is done
   every other measurement is measuring `JSON.parse`.

2. **The `(role, size class)` slot table costs a whole window whenever a reply
   misses its one slot.** With a fast store the identity flights need the read
   (armed at 600 ms) to finish by 1,300 ms. Widening that — more than one
   append offset per role per class, or moving `publicReadOffsetMs` earlier —
   is a *profile* change, not a code change, and it is visible to a store only
   as "this profile has more/other fixed offsets", which every client on the
   grid shares. It does not change the fixed-shape property. It does change the
   pinned profile, so it is a named deviation under spec:3392.

3. **The cold-start window is ~4 s of the ~40 s and is pure protocol.** A
   client that starts after `allocationRequestOffsetMs` cannot be admitted in
   its current window. Nothing measured here suggests a fix that does not
   change the allocation rule.

4. **The 5 dependent flights are the remaining floor.** At one window per
   flight and a 4 s window, the floor is 5 × 4 s + the cold-start window ≈ 24 s;
   at a 1 s window it is ~6 s. Collapsing flights (e.g. publishing PRESENCE and
   IDENTITY_HELLO material together, or making TRANSPORT_OFFER rideable on the
   same window as IDENTITY_ACCEPT) is the only way below that, and each
   collapse is a change to what a store can correlate within one window —
   **that one must be measured and disclosed, not assumed free.** Nothing here
   measures it.

5. **The cohort knob is real but it is not the same lever as (1).** The README's
   cohort table is a measurement of (1) seen through a proxy: cohort 8 → 2
   shrinks the store's window document 2.10×, which is why it shows up as
   latency. Fixing (1) would decouple them, and the cohort could then be chosen
   for what it is actually for — how much unrelated traffic a client's objects
   sit among — rather than for speed.

---

## 8. Two incidental observations, recorded because they were seen

- **The first window's request shape differs from every later window.** Per page
  per store: `w0+0` = 9 requests and **0 append POST bodies**; `w0+1 … w0+n` =
  15 requests and 174,470 bytes of append bodies (the 13 fixed + the witness
  pair). This is not a new leak — the appends of `w0+0` were skipped because
  their offsets were already past when the page started, which `#nextEvent`
  does by design — but a store watching a client's *first* window sees a
  different count than it sees afterwards, and design §3a does not list it.
  Worth checking against the fixed-shape claim before anyone quotes "thirteen
  fixed requests per window" without the qualifier "after the first".

  > **Correction, 2026-09-08 (stage 1, fix round).** The mechanism is right and
  > it is now design §3a item 15. **The number 9 is not.** The start window
  > carries one descriptor GET, exactly one allocation POST — the scheduled one
  > below `allocationRequestOffsetMs`, a cold-start one at or above it — and
  > every scheduled request at an offset `≥ p`, plus the witness pair under item
  > 14's condition. At the pinned profile the reachable totals are 16, 15, 7, 6,
  > 5, 4, 3 and 2; **9 is not among them at any `p`**. The rule is pinned at
  > every schedule boundary by "issues exactly the scheduled events still ahead
  > of its start phase" in
  > `tests/blindRendezvous/prototype/carrierRuntime.test.ts` and was observed at
  > sixteen unlocked start phases end to end
  > (`stage-1-fixround-report.md` §2). Also wrong here: "0 append POST bodies"
  > holds only above the last append offset — below `publicReadOffsetMs` the
  > start window carries **all five** appends and the whole fixed thirteen, and
  > at `100 < p ≤ 600` its total is exactly the steady-state 15.
- **The `allocation` POST is the slowest request in the run** (mean
  `responseEnd` 1,270 ms, of which 210 ms is client-side stall waiting for a
  socket and ~1,060 ms is the store). It fires at offset 700 ms, i.e. straight
  into the scan storm it shares an event loop with. It is not on the critical
  path today because it targets `window + 1`, but it is 100 ms from being on it.

---

## Files

| file | what |
| --- | --- |
| `run1.stdout.txt`, `run2.stdout.txt`, `run3.stdout.txt` | full harness output, three `--scenario=healthy` runs |
| `trace/healthy-run{1,2,3}.json` | raw event log (absolute `Date.now()`) + per-request Playwright trace |
| `analyze.mjs` | per-phase table with window/offset, per-window scan bytes, read decomposition |
| `slots.mjs` | per-route cost, observed append grid, flight accounting |
| `budget.mjs` | consolidated flight budget across the three runs |
| `scanbench.ts`, `bench.mjs`, `bench/` | the `openCarrierEnvelope` micro-benchmark and its driver |
| `storeprobe.sh`, `storeprobe.txt` | one store, no client, `curl` — cohort 8 |
| `storeprobe-c2.sh`, `storeprobe-c2.txt` | the same at `--cohort=2` |
| `run.mjs.orig` | the pristine `run.mjs` the tree was restored from |
