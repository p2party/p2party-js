# Attacking the scan cost, object sizes held fixed

Angle: the per-window scan. 2026-09-08, tree `feat/blind-two-store-prototype`
@ `127ca95` **plus two uncommitted experiments by a parallel agent** (see §0.1).
macOS 25.6.0 / arm64, `bun 1.3.14`, `node v24.11.1`. Everything numbered below
is measured in this session unless the line says "derived" or "estimate"; the
scripts are named at the end.

---

## 0. The one-paragraph answer to the brief

**There is no client-side scan cost worth attacking, and there never was.** The
whole client-side scan — decode, header filter and trial-AEAD of all 40 carrier
objects, 1,380,336 bytes — is 4.0 ms per store (`observed.md` §4b, unchallenged
and re-confirmed by my own attribution below). The thing the brief calls "the
scan" is 99.6 % **the store process**, and `observed.md` named the wrong line
inside it: it blamed `JSON.parse` of the window document. I measured that
directly. `JSON.parse` of the whole 5.5 MB document costs **0.30 ms**. The cost
is `bytesFrom` (`storeSqlite.ts:71-78`), a hex decoder written as
`value.slice(i*2, i*2+2)` + `Number.parseInt` per byte, which burns **107 ms**
turning one window's chunks back into bytes, and its write-side twin `hexOf`
(`storeSqlite.ts:68-69`), which burns **184 ms** per `saveWindow`. Every single
store route — every chunk GET, every checkpoint GET, every append POST, every
allocation POST, and the finalizer — pays one or both, in full, on a
single-threaded event loop behind an explicit global mutex
(`storeCore.ts:1190`). At the pinned cohort-8 profile with two clients that is
**≈3.8–5.8 s of CPU per 4,000 ms window**: the store is at or past saturation,
which is why the allocation POST takes 1,270 ms and why `--window-ms=2000`
never worked. The fix is a codec, is confined to one file, changes **no byte on
the wire, no request, no route, no geometry and no disclosure**, and takes the
two-store scan wall from a measured p50 of **1,453 ms to sub-millisecond
per request** — measured end to end over real HTTP at **0.54–0.81 ms TTFB**.
Everything else in my angle — short-circuiting the AEAD, caching, concurrency,
WASM-vs-WebCrypto — is worth between nothing and 8 ms and I recommend against
most of it, with numbers.

### 0.1 A change of baseline you need to know about

The working tree is **not** the tree the two measurement reports describe.
`git status` shows uncommitted modifications to `profile.ts` and
`carrierRuntime.ts` from a parallel experiment:

| Constant | `127ca95` (both reports) | working tree now |
| --- | ---: | ---: |
| `chunkFinalizationOffsetMs` | 2,800 | **3,200** |
| class 0 `appendSchedule` | 1,300 / 1,700 / 2,100 | **2,400 / 2,600 / 2,800** |
| class 1 `appendSchedule` | 1,500 / 1,900 | **2,450 / 2,650** |
| profile hash | `83a2261e…` | **`85984c40…`** |
| `carrierRuntime` | — | + "EXPERIMENT E3": a second allocation POST for the *current* window at cold start |

That is `floor.md` §8(a) plus its "third" item, already applied. It raises the
answering flights' scan budget from 700 ms to **1,800 ms**. It does **not**
make my candidates redundant — it makes the first one a *precondition*, and
§6 is the argument, with a specific prediction the maintainer should test
before trusting the profile move.

I could not take a live E2E baseline: the harness aborted with
`EADDRINUSE :::5920`, i.e. the parallel agent was mid-run. Every number below
therefore comes from isolated store processes and micro-benchmarks I ran
myself, plus the two reports.

---

## 1. (a) Trial decryption or transfer? Neither. It is the store's codec.

The reports settle the client half and I did not re-litigate it:
`openCarrierEnvelope` over the whole 40-object window is **4.0 ms per store,
8 ms for both** (`observed.md` §4b), and the in-run upper bound on *everything*
after the last scan byte — decode, header filter, 80 AEAD opens, RFC 9162 root
recomputation, custody check, union, Ed25519 validation, the driver's HPKE open
and reseal — is **13.9–39.1 ms, p50 27.2 ms** (`observed.md` §3). Transfer is
not it either: `requestStart` for chunk GETs is 1.0 ms, `connectStart` 0.0
(`observed.md` §4c), so nothing is queued and nothing is connecting.

What I added is the attribution *inside* the store. One store process, no
browser, an all-dummy finalized cohort-8 window, `curl` (`probe-attribute.sh`):

```
class0 chunk0  66534 B  ttfb 0.1058s      class1 chunk0  590822 B  ttfb 0.1040s
class0 chunk1  66534 B  ttfb 0.1030s      class1 chunk1  590822 B  ttfb 0.1031s
class0 chunk2  66534 B  ttfb 0.1021s      checkpoint         482 B  ttfb 0.1030s
the same chunk five times:  0.1023  0.1016  0.1032  0.1034  0.1036 s
```

**~103 ms per request, flat, regardless of the chunk's size, and with no warm
path whatsoever** — the sixth request for the same 590 KB chunk costs exactly
what the first did, and a 482-byte checkpoint costs exactly what a 590 KB chunk
does. That is the signature of a cost that is `O(whole window document)` and
not `O(response)`.

Then the same window, in-process (`benchload.ts`, n=12, state blob 2,763,134 B):

| step | ms | file:line |
| --- | ---: | --- |
| `SELECT state FROM "window"` | **0.69** | `storeSqlite.ts:278-283` |
| `TextDecoder.decode(blob)` | **0.28** | `storeSqlite.ts:285` |
| **`JSON.parse(text)`** | **0.30** | `storeSqlite.ts:285` |
| `persistence.loadWindow` (whole path) | **101.99** | `storeSqlite.ts:277-287` |
| ⇒ `fromDocument`, i.e. hex-decode + canonical decode | **100.72** | `storeSqlite.ts:164-205` |
| `encodePublicChunkReadV1` (the response) | **0.07–0.08** | `storeHttp.ts:320-325` |

`observed.md` §4c/§4e attributed this to `JSON.parse`. **That is wrong by a
factor of 340.** `JSON.parse` is 0.30 ms. Splitting `fromDocument`
(`benchload2.ts`, n=20 per chunk):

| chunk | hex string | `bytesFrom` as written | nibble-table hex | `decodeCanonicalStrict` | `encodeCanonical` |
| --- | ---: | ---: | ---: | ---: | ---: |
| class 0 ×3 | 133,064 chars ea. | 2.86 / 2.84 / 2.97 ms | 0.18 / 0.14 / 0.14 | 0.13 / 0.12 / 0.08 | 0.026 / 0.024 / 0.020 |
| class 1 ×2 | 1,181,640 chars ea. | **49.68 / 48.82 ms** | 1.23 / 1.23 | 0.55 / 0.51 | 0.10 / 0.10 |
| **total** | | **107.2 ms** | **2.9 ms** | **1.4 ms** | **0.3 ms** |

So: **the entire per-request cost of a chunk GET is one badly written hex
decoder.** `bytesFrom` (`storeSqlite.ts:71-78`) runs a regex over a 1.18 MB
string and then does 590,820 × (`String.prototype.slice` allocating a
two-character string + `Number.parseInt` on it). Replacing it with a
`charCodeAt` nibble table is **37× faster** and is 12 lines.

### 1.1 The realistic window is worse, and so is the write side

The probe window had `slots=0` (no client ever appended). A real window keeps
**both** the bound slots and the finalized chunks — `#finalizeWindow` sets
`state.finalized` and calls `saveWindow(state)` without clearing `state.slots`
(`storeCore.ts:1032-1034`), and `toDocument` hex-encodes both
(`storeSqlite.ts:151-162`). I rebuilt that window (`benchload3.ts`: the probe's
finalized chunks + 40 bound slots, 1,380,336 B of objects):

```
populated window: 40 slots (1,380,336 B) + finalized chunks; state blob 5,528,125 bytes

path 1 — today (loadWindow on every chunk GET)
  SqliteStorePersistence.loadWindow            136.88 ms
  encodePublicChunkReadV1(class 1)               0.10 ms
  => per chunk GET ≈ 137.0 ms
path 2 — one BLOB row per finalized chunk, served verbatim
  SELECT body (class 1, 590 KB)                  0.072 ms
path 3 — in-process Map of encoded responses
  Map.get                                        0.0002 ms

five-chunk scan, served strictly serially on one event loop:
  today  685 ms   |   per-chunk rows  0.4 ms   |   in-process cache  0.00 ms
```

And the write side (`benchsave.ts`, same populated window):

```
saveWindow (populated window)                183.95 ms
hexOf one class-1 object (current)             4.09 ms
hexOf one class-1 object (nibble table)        0.38 ms
Buffer.from(x).toString("hex")                 0.01 ms     ← 409× faster
```

`hexOf` is `[...value].map(b => b.toString(16).padStart(2,"0")).join("")`
(`storeSqlite.ts:68-69`) — it spreads a 73,728-byte `Uint8Array` into a
73,728-element array of numbers, allocates 73,728 two-character strings, and
joins them. Per `saveWindow` of a populated window that is **184 ms**.

### 1.2 The store is saturated, and that is the real disease

Every mutating route runs `loadWindow` + `saveWindow` inside one global mutex:
`#allocate` (`storeCore.ts:635`, save at `:701`), `#append` (`:766`, save at
`:873`), `#finalizeDue` (`:914`, save at `:1034`). Reads skip the mutex but
still block the single event loop for the same ~137 ms. Per store per delivery
window with the harness's two clients (13 fixed requests per client per store
per window, design §5), using the per-call costs above:

| route | count | ≈ CPU each | ≈ CPU total |
| --- | ---: | ---: | ---: |
| chunk GET | 10 | 137 ms | 1,370 ms |
| checkpoint GET (also `loadWindow`, `storeCore.ts:1059`) | 2 | 137 ms | 274 ms |
| append POST (load + save, doc still filling) | 10 | ~130–320 ms | 1,300–3,200 ms |
| allocation POST (load + save) | 2 | ~130–320 ms | 260–640 ms |
| `finalizeDue` (load + sign + save) | 1 | ~330 ms | 330 ms |
| allocation-token POST (no document) | 2 | ~1 ms | 2 ms |
| **total per 4,000 ms window** | | | **≈3,540–5,820 ms** |

That is a **load factor of 0.9–1.5 on one core for two clients** (derived from
measured per-call costs, not itself measured end to end). It explains, without
any further hypothesis: the 1,269.8 ms mean `responseEnd` on the allocation
POST; the ~180 ms even TTFB ladder that is independent of chunk size; the
measured two-store scan wall of p50 1,453 ms; and the README's `--window-ms=2000`
failure, which at half the window is a load factor of ~2–3 and therefore
guaranteed `window-finalized` on every append.

### 1.3 What it becomes when fixed, measured over real HTTP

`cachedstore.ts` is a scratch copy of `storeServer.ts`'s bootstrap that wraps
`createPrototypeStoreHandler` with an outer response cache on the two immutable
routes. It imports the repo; it changes nothing in it. `scanprobe.sh` then
issues the real 6-request scan (1 checkpoint + 5 chunks) three times:

```
[pass 1 (cold)]  102 / 204 / 304 / 406 / 508 / 610 ms TTFB   whole scan wall: 652 ms
[pass 2 (warm)]  41.5 / 41.6 / 41.6 / 41.6 / 41.7 / 41.9 ms  whole scan wall: 165 ms
[pass 3 (warm)]  0.54 / 0.66 / 0.69 / 0.77 / 0.77 / 0.81 ms  whole scan wall:  41 ms
```

Pass 1 is today's store and it reproduces the recorded serial ladder exactly.
Pass 3 is the ceiling: **sub-millisecond TTFB per request, 1.38 MB delivered,
41 ms of wall that is six `curl` process spawns rather than the store.** The
scan stops being a thing that exists.

---

## 2. (b) Can the AEAD trial be short-circuited? No — and it must not be.

There already **is** a pre-AEAD header filter, and it is exactly as strong as
it can safely be. `#openObject` (`carrierRuntime.ts:1161-1176`) rejects an
object before `openCarrierEnvelope` if any of `version`,
`deliveryProfileHash`, `ingressWindow`, `sizeClass` or `carrierContextId`
disagrees with what the scan asked for. The AAD is exactly those fields
(`derivations.ts:1341-1358`) — deliberately *not* the nonce, because "the nonce
is a key selector and the key schedule already binds it".

That is the whole point and it closes the question: **every one of those fields
is a bucket coordinate, identical for all 40 objects in the bucket, and the
store chose them.** They separate our bucket from another bucket; they cannot
separate our object from the 39 cover objects beside it, because there is
nothing in an object's plaintext-visible header that differs between rooms.
Any cheap check that *could* tell them apart would be a room label sitting in
bytes the store holds — the exact thing design §3a item 13 ("no labels") and §5
exist to deny. The trial AEAD is not an implementation detail that a smarter
index could replace; **it is the unlinkability mechanism.**

The one variant that survives that argument is a **key-derived recipient hint**:
`hint = truncate(PRF(RoomRoot, nonce), k)` written into the envelope, checkable
without the AEAD. A store without `RoomRoot` sees uniform bits, so it adds no
label per se. I still recommend against it, on its own numbers:

- It buys at most the AEAD half of the scan: **1.9–2.9 ms per store per
  window** (`observed.md` §4b `openMs`), against a 1,450 ms scan. Rounding
  error on a rounding error.
- The key is `HKDF-Expand(RoomRoot, … || nonce)` — **per object by
  construction** (`derivations.ts:1322-1338`) — so the hint costs its own PRF
  per object and the saving is smaller than the headline.
- It changes the carrier envelope wire format (`carrierEnvelopeV1Schema`), i.e.
  a codec deviation, for a new cryptographic assumption.
- It creates a k-bit equality class that a future adversary who learns
  `RoomRoot` can use to sieve historical logs faster than trial decryption —
  a small but real widening of §3a item 1 (replicated-write linkability).

**Verdict: reject.** Recorded here so nobody re-derives it.

---

## 3. (c) Does the client re-fetch or re-decrypt anything? Essentially no.

- **Windows are read once.** `#read` guards on `#readWindows`
  (`carrierRuntime.ts:1050-1053`, bounded at 64) and returns immediately on a
  second entry. ✔
- **Chunks are fetched once.** Each `(store, window, sizeClass, chunkIndex)` is
  requested exactly once per client, from `scanWindow`
  (`storeClient.ts:934-949`). There is no re-fetch to cache away, and the
  store's own `immutable` cache-control (`storeHttp.ts:86-88`) therefore buys a
  single client nothing. ✔
- **Objects are opened once**; `#seen` dedupes operation ids
  (`carrierRuntime.ts:1088-1093`).
- **Custody verification is bounded** to this client's own receipts for the
  window — at most 5 SHA-256 (`storeClient.ts:1660-1707`). ✔
- **One thing does grow.** `#verifyChain` calls
  `verifyStoreCheckpointChain(this.#observed, …)` on **every read**, over the
  whole retained observation run, which grows to `MAX_OBSERVED_CHECKPOINTS =
  256` (`storeClient.ts:238`, `:1605-1609`, `:1648`). Every recorded run is
  ~10 windows long, so this has **never been exercised past ~10 observations**.
  At 4,000 ms windows a tab crosses 256 after 17 minutes and then re-verifies a
  256-entry chain twice per window forever. Unmeasured; see C8.

The legitimate cache is therefore **not on the client**. It is on the store,
where the same five chunk bodies are rebuilt from scratch for every reader —
which is C1/C5.

---

## 4. (d) Is the fetch concurrency right? Yes on the client, no on the store.

Confirmed by reading:

- `scanWindow` issues the checkpoint GET and **all** chunk GETs up front and
  only then awaits them (`storeClient.ts:934-949`), which is what spec:5837-5841
  and AC-049 (spec:12560-12562) require. ✔
- The two stores' scans run under one `Promise.all`
  (`carrierRuntime.ts:1055-1057`) — genuinely parallel fetches. ✔
- The two stores' **opens** are sequential (`carrierRuntime.ts:1073-1085`), and
  within a store `#openObjects` awaits object by object
  (`carrierRuntime.ts:1145-1152`). 8 ms total. Not worth touching.
- Chromium's HTTP/1.1 cap is 6 connections per origin and a scan is exactly 6
  requests per origin, so today nothing queues (`requestStart` = 1.0 ms,
  `observed.md` §4c). **But the tree's new profile moves the five append POSTs
  to 2,400–2,800 ms**, and on today's saturated store a scan launched at 600 ms
  is still in flight then. Those POSTs then queue behind the GETs on the same
  origin. Another reason C1 comes first.

The real serialization is inside the store and it is threefold: one event loop,
one explicit mutex over every mutating route (`storeCore.ts:1190`), and a
137 ms `loadWindow` in front of each. My cold probe is the picture:
102/204/304/406/508/610 ms — six requests, perfectly serial, indifferent to
size.

One genuine client-side defect: `Promise.all` over the stores means **the
slower store gates the faster one for the whole read**, and a store that
accepts a connection and then stalls costs `requestDeadlineMs` = one whole
delivery window (`storeClient.ts:276-283`, `:426`) on *every* read. See C7.

---

## 5. (e) WASM vs WebCrypto for the AEAD. Not available, not needed.

The suite is XChaCha20-Poly1305 from the pinned libsodium WASM build
(`carrierEnvelope.ts:23-26`, `:112-127`). **WebCrypto has no XChaCha20** — only
AES-GCM/AES-CTR/AES-CBC — so this is not a port, it is a different AEAD, and
`carrierEnvelope.ts:19-20` records that substituting one is forbidden by
SEC-002 and SEC-019. The prize would be part of 4.0 ms per store per window.
**Verdict: not a candidate.** The same applies to the SHA-256 in
`publicChunkHash`/`publicChunkSigningHash` (two passes over 1.38 MB per store)
and the 5 Ed25519 chunk-signature verifies: all of it together is inside the
measured 13.9–39.1 ms post-fetch bound.

---

## 6. Why the profile move already in the tree needs C1 to be safe

The working tree moved the appends to 2,400–2,800 and finalization to 3,200.
Read at 600 + a p50 scan of 1,453 ms ⇒ the answer is ready at ~2,050 ms, so it
now makes the 2,400 ms identity slot. Good. But:

1. **The margin is thin.** Max recorded scan wall is 1,531 ms (`observed.md`
   §3), and my populated-window arithmetic puts a two-client two-store scan at
   ~1,644 ms of store CPU. A scan that ends after 2,400 ms misses again.
2. **The appends now land in the store's busiest 800 ms.** Five append POSTs
   per client per store between 2,400 and 2,800, each costing 130–320 ms of
   store CPU behind the mutex, with 10 of them across two clients. Serially
   that is 1.3–3.2 s starting at 2,400 ms, and `#windowIsClosed` is *clock*-based
   — "a window is closed once its finalization instant has passed, whether or
   not `finalizeDue` has run" (`storeCore.ts:1209-1212`). **Prediction: on
   today's store, the tree's profile trades `missed append slot` for
   `window-finalized`, and the run does not improve — or gets worse.** That is
   testable in one run: grep the harness's `store-missed` lines for
   `window-finalized`, and compare `appendsReal + appendsDummy` against the
   `127ca95` baseline.
3. With C1 the store answers a chunk GET in ~0.07 ms and an append in a few ms,
   the 800 ms append band is empty of contention, and the 1,800 ms scan budget
   is **60× the need instead of 1.2×**.

So the ordering is: **C1/C2 first, then the profile move is safe, and only then
is a shorter delivery window even discussable.**

---

## 7. Candidates

Format per the brief. "§3a" is the design doc's residual-leak list. Savings are
per delivery window unless stated; window counts are per rendezvous (six
dependent windows: cold start + five flights).

---

### C1 — Serve finalized chunks and checkpoints from their own precomputed rows

**Mechanism.** At finalization, alongside `saveWindow`, write one row per
finalized chunk holding the exact `encodePublicChunkReadV1` response bytes, and
one row for the checkpoint response. Add
`loadChunkResponse(window, sizeClass, chunkIndex)` and
`loadCheckpointResponse(window)` to `StorePersistencePort`
(`storePersistence.ts:64-71`); `readChunk` (`storeCore.ts:1090-1124`) and
`readCheckpoint` (`storeCore.ts:1043-1075`) call those instead of
`loadWindow`, and `storeHttp.ts:303-325` hands the bytes back verbatim. Fall
back to today's path when the row is absent (old databases, `not-final`,
`out-of-range`) so nothing regresses.
New table: `chunkrow("window" INTEGER, cls INTEGER, idx INTEGER, body BLOB,
PRIMARY KEY("window", cls, idx))`, WAL as today.

**Saving.** Per chunk GET **137.0 ms → 0.072 ms** (measured, `benchload3.ts`).
Per scan per store, six requests: **~820 ms → ~0.4 ms**. Two-store scan wall
p50 **1,453 ms → tens of ms** (measured over HTTP at 0.54–0.81 ms TTFB,
`scanprobe.sh` pass 3). In windows: at the tree's current profile it converts
"the answer *usually* makes its 2,400 ms slot" into "the answer always makes it
with 1,760 ms to spare", i.e. it *secures* the 4 windows / 16.0 s that
`floor.md` §8 attributes to missed slots, and removes the risk in §6.2 that the
profile move backfires. It buys **0 windows on its own** at W = 4,000 if the
profile move already worked, and **4 windows** if it did not.

**Privacy cost.** **None.** Same routes, same request count, same request
sizes, same response bytes byte-for-byte, same signatures (the chunk was signed
once at finalization and is never re-signed — `storeCore.ts:982-988`), same
cache-control, same geometry. Maps to **no §3a item; adds none, widens none.**
The store's *timing* changes (it answers faster) — that is a property of the
store, identical for every client, and it makes the fixed schedule easier to
hold, not harder.

**Spec deviation.** None. The wire is unchanged; this is storage layout, which
the spec does not constrain. `storePersistence.ts:11-16` explicitly says the
port is "whole-window replace … the SQLite implementation lands in a later task
behind this same interface" — this is that task.

**Implementation cost.** `storeSqlite.ts` (+~90 LOC: schema, two writers, two
readers), `storePersistence.ts` (+~12 LOC of port + in-memory impl),
`storeCore.ts` (~25 LOC changed across the two read paths),
`storeHttp.ts` (~10 LOC to pass bytes through), plus store tests. **≈140 LOC,
4 files.**

**How to measure it worked.** (i) `probe-attribute.sh` unchanged: chunk GET
TTFB must drop from ~103 ms to <2 ms. (ii) `scanprobe.sh` cold pass: the
102/204/304/406/508/610 ladder must collapse to a flat sub-2 ms row.
(iii) A `--scenario=healthy` run: the harness's per-flight milestones must land
in consecutive windows (`w0+1, w0+2, …`, not `w0+2, w0+4, …`), `store-missed`
must contain no `window-finalized`, and `appendsReal + appendsDummy` must be
unchanged. (iv) The four existing scenarios must still pass with identical
audit verdicts (0 needles).

---

### C2 — Replace the hex codec in `storeSqlite.ts` (the 20-line version of C1)

**Mechanism.** `bytesFrom` (`storeSqlite.ts:71-78`): replace
`slice`+`parseInt` with a `charCodeAt` nibble table (keep the strict validation
— reject any non-`[0-9a-f]` nibble, keep the odd-length check). `hexOf`
(`storeSqlite.ts:68-69`): replace the spread/map/join with either a 256-entry
lookup table or, since this file is store-only and Node/Bun-resident,
`Buffer.from(value).toString("hex")`.

**Saving.** Measured: hex decode of one window's chunks **107.2 ms → 2.9 ms**
(37×, `benchload2.ts`); `hexOf` of one class-1 object **4.09 ms → 0.38 ms**
(table) or **0.01 ms** (`Buffer`, 409×). Per chunk GET on a populated window
**137 ms → ~5 ms**; per `saveWindow` **184 ms → ~5 ms**. Store load factor
per 4,000 ms window with two clients: **≈0.9–1.5 → ≈0.05**. Window saving:
same as C1 (it secures the same 4 windows / 16.0 s), at ~25× less remaining
per-request cost than C1's 0.072 ms but **1/7th of the code**.

**Privacy cost.** **None.** Identical to C1 — it is a codec inside the store's
own database. **No §3a item.**

**Spec deviation.** None.

**Implementation cost.** `storeSqlite.ts` only. **≈25 LOC, 1 file.**

**How to measure it worked.** Same as C1(i)/(ii)/(iv), plus re-run
`benchload2.ts` against the same database and require total hex-decode < 5 ms.

*This is C1's little brother and should ship first, in the same hour it is
written. C1 is then a refinement, not a rescue.*

---

### C3 — Stop rewriting the finalized chunks on every append

**Mechanism.** Split the window row: `allocations` + `slots` in one blob (the
mutable half), `finalized` in another (written once, never rewritten). `#append`
and `#allocate` then load and save only the mutable half; the read routes touch
only the immutable half. Requires a `loadWindowMutable` / `saveWindowMutable`
pair beside the existing port methods, keeping `loadWindow` for the finalizer
and for `create`'s `lastFinalizedWindow` path.

**Saving.** Removes the finalized chunks (1.38 MB of objects ⇒ 2.76 MB of hex)
from every append's load *and* save. On today's codec that is the difference
between the 5,528,125 B document and the ~2.76 MB one: **`loadWindow` 137 ms →
~66 ms, `saveWindow` 184 ms → ~90 ms** (derived by linearity, which
`benchload2.ts` establishes: 107.2 ms of hex for 1.38 MB, 2.86 ms for 66 KB —
linear to within 4 %). With C2 already in, C3's remaining value is ~2 ms per
call and it is **not worth doing on its own**; it matters only if C2 is
rejected. Listed for completeness and because it also halves the store's disk
(README already records 2,763,134 B/window).

**Privacy cost.** None. **No §3a item.**

**Spec deviation.** None.

**Implementation cost.** `storeSqlite.ts` + `storePersistence.ts` +
`storeCore.ts`. **≈120 LOC, 3 files.**

**How to measure it worked.** `benchsave.ts` on a populated window: append-path
`saveWindow` must not scale with the finalized chunks. Disk per window must
halve.

---

### C4 — Drop `slots` from the document once the window is finalized

**Mechanism.** In `#finalizeWindow` (`storeCore.ts:1032-1034`), clear
`state.slots` before `saveWindow`: every bound object is already inside
`finalized.chunks` at its exact coordinates, and nothing reads `slots` after
finalization (`#append` refuses a closed window at `storeCore.ts:788-790`;
`readChunk`/`readCheckpoint` read `finalized` only). Custody verification is
client-side and reads the chunk (`storeClient.ts:1697`), not the slot.

**Saving.** Document 5,528,125 B → 2,763,134 B; on today's codec
`loadWindow` **137 ms → ~102 ms** (measured: the slots=0 probe window loads in
101.99 ms). With C2 in, ~2.5 ms saved. Halves store disk.

**Privacy cost.** None on the wire. One honest caveat: it deletes the store's
own record of *which append landed in which slot*, which is exactly the
provenance an operator would need to answer "did I really store what I signed
a receipt for". The signed chunk still proves it, so I believe nothing is lost —
but this is the one candidate here with a *correctness* argument to check
rather than an obvious yes. **No §3a item.**

**Spec deviation.** None (retention of the finalized chunks is unchanged).

**Implementation cost.** `storeCore.ts`. **≈5 LOC, 1 file**, plus a test that
a finalized window still serves every chunk after a restart.

**How to measure it worked.** `SELECT length(state)` per window must halve;
restart the store and re-serve an old window; the store test suite unchanged.

---

### C5 — Bounded in-process cache of immutable responses

**Mechanism.** An LRU in `PrototypeStoreCore` keyed
`(window, sizeClass, chunkIndex)` (plus the checkpoint) holding the encoded
response bytes, populated at finalization and on a miss, bounded to a few
windows. This is exactly what `cachedstore.ts` does as an outer wrapper.

**Saving.** **0.0002 ms per chunk GET** (measured). Over HTTP, TTFB
**0.54–0.81 ms** for a 590 KB body (measured, `scanprobe.sh` pass 3). Strictly
better than C1's 0.072 ms, but it is RAM: 1.38 MB per window per store, so 10
windows = 13.8 MB. In production it is the right answer *in front of* C1, not
instead of it, because a cold cache after a restart must not cost 137 ms.

**Privacy cost.** None on the wire. One subtlety worth stating rather than
hiding: a hit and a miss have different timings, so a client can tell whether
*someone else* recently read the same public chunk — a coarse "is anyone else
using this store" signal over public, immutable data that the store already
publishes to anyone. It reveals nothing about rooms, membership or which
objects a client cares about, because every client reads every chunk of every
window. **Adds no §3a item; if the maintainer wants it airtight, populate the
cache eagerly at finalization so every chunk is always a hit.**

**Spec deviation.** None.

**Implementation cost.** `storeCore.ts` (+~40 LOC) or `storeHttp.ts`
(+~35 LOC). **1 file.**

**How to measure it worked.** `scanprobe.sh` pass 1 must already be flat (with
eager population). RSS must stay bounded across a long run.

---

### C6 — Put a caching reverse proxy in front of the immutable routes

**Mechanism.** No code: the store already labels finalized chunks and
checkpoints `public, max-age=31536000, immutable` and everything else
`no-store` (`storeHttp.ts:86-88`, `:294-325`). A CDN or nginx in front serves
the chunk and checkpoint routes from cache.

**Saving.** In the harness, nothing (two clients, one machine). In production,
it is the difference between a store that serves N clients and one that serves
N × 1.38 MB of rebuild per window. It removes the store's CPU from the
critical path for reads entirely.

**Privacy cost.** **Real and new: it adds an observer.** The CDN sees every
client's source address and read schedule for both stores if the same CDN
fronts both — which would collapse the two-store separation that the whole
design rests on, and hand §3a item 2 (source addresses) and item 1
(replicated-write linkability) to one party. **Deployable only with different
CDNs per store, stated as a §3a addition, and named in the independence
statement of §3a item 8** ("operator, ASN, hosting, jurisdiction and funding
must be stated and auditable" — a shared CDN makes two stores one fault and
one observation domain).

**Spec deviation.** None in the client. It is a deployment fact.

**Implementation cost.** 0 LOC; a deployment note and a §3a item.

**How to measure it worked.** Store CPU per window at N clients must stop
scaling with N for the read routes. Assert the two stores' CDN ASNs differ.

---

### C7 — Do not let the slow store gate the fast one

**Mechanism.** `#read` awaits `Promise.all` over both stores'
`scanWindow` (`carrierRuntime.ts:1055-1057`) and only then opens anything, so
the union — and every flight that depends on it — waits for the slower store,
up to `requestDeadlineMs` = one whole delivery window
(`storeClient.ts:276-283`). Change to: settle each store's scan independently,
open and deliver its operations as it lands, and compute `carriedBy` /
`#queueBackfills` from whatever has arrived when the last one settles (or at
the deadline). Deduplication already exists (`#seen`,
`carrierRuntime.ts:1088-1093`) so a second delivery of the same operation is a
no-op.

**Saving.** 0 on the healthy path. Up to **one whole window per flight** — 4.0 s
each, up to 20 s per rendezvous — whenever one store is slow or stalled. This
is exactly the `kill-a` / `withhold-a` / `unreachable-b-for-one` scenarios, and
it is the difference between "degrades honestly" and "degrades by 2×".

**Privacy cost.** **None on the wire**: the requests were already issued
together and are unchanged. It does change *when the client acts on* what it
learns, which is a §3a item 4 concern ("polling shape must stay
schedule-shaped, never event-shaped") — but the acting is a *send* at the next
scheduled slot regardless, so no request moves. I would still want the
maintainer to confirm that no new send can be triggered off-schedule by
early delivery.

**Spec deviation.** None found: spec:5838-5841 requires the requests be
dispatched together without awaiting responses, and says "responses may
complete in any order; checkpoint silence, failure, or a never-resolving body
never cancels or delays a chunk request". Delivering per store is consistent
with that sentence's spirit; the maintainer should re-read 5837-5845 before
calling it non-deviating.

**Implementation cost.** `carrierRuntime.ts` `#read` and `#queueBackfills`.
**≈60 LOC, 1 file**, plus a test on the degraded scenarios.

**How to measure it worked.** `--scenario=withhold-a` and `kill-a`: per-flight
cost must equal the healthy run's, not 2×. `docs/e2e` topology strings must be
unchanged (`multi-store-union` where both are healthy).

---

### C8 — Memoize the checkpoint-chain verdict instead of re-verifying 256 observations per read

**Mechanism.** `#verifyChain` re-runs `verifyStoreCheckpointChain` over the
whole retained run on every read (`storeClient.ts:1596-1622`), and the run grows
to 256 (`:238`, `:1648`). Keep the last verdict plus the last verified window,
and verify only the newly-appended observation against its predecessor, falling
back to a full re-verification when `#observe` inserts out of order or keeps
both sides of an equivocation (`:1626-1650`) — which is rare and is exactly
when the full pass is wanted.

**Saving.** Unknown, and that is the point: **never measured, because no
recorded run is longer than ~10 windows.** The cost is O(256) hashes and
possibly O(256) Ed25519 verifies per read per store, twice per window, forever,
after ~17 minutes of uptime. If it is 50 µs per observation it is 13 ms per
store per window — comparable to the *entire* rest of the client's post-fetch
work.

**Privacy cost.** None. **No §3a item.**

**Spec deviation.** None (the verdict is unchanged; only the work to reach it).

**Implementation cost.** `storeClient.ts`. **≈50 LOC, 1 file.**

**How to measure it worked.** First: *measure the problem* — run a store and a
client for 300 windows with a timer around `#verifyChain`, and plot cost against
`#observed.length`. Only implement if the curve is real.

---

### C9 — REJECTED: a cheap pre-AEAD recipient hint

See §2. Buys ≤2.9 ms per store per window, costs a wire-format change, a new
assumption, and a k-bit sieve that widens §3a item 1. **Do not build.**

### C10 — REJECTED: WebCrypto for the AEAD

See §5. WebCrypto has no XChaCha20; substitution is forbidden by SEC-002 /
SEC-019 (`carrierEnvelope.ts:19-20`); the prize is part of 4.0 ms. **Do not
build.**

### C11 — PARKED: one request for the whole window instead of five

Would cut request count 6 → 1 per store per scan, worth 5× on *today's*
per-request cost and **nothing at all once C1/C2 land** (0.072 ms × 5 = 0.36 ms).
It is also a **spec deviation** against REQ-007 (spec:876-879, "reads the one
checkpoint followed by every chunk of the one-lag finalized window"),
spec:5837-5841 ("dispatches the checkpoint GET … followed by every chunk GET in
canonical request-initiation order") and AC-049 (spec:12560-12562, "the full
canonical chunk scan … a never-resolving checkpoint still produces every chunk
request"), and it changes design §5's fixed trace from 13 requests to 9. Bad
trade. **Park.**

### C12 — PARKED: read the finalized window *early*, inside the window it belongs to

The store finalizes `w−1` at 3,200 ms into `w−1`, i.e. **1,400 ms before `w`
starts**, yet the read fires at 600 ms into `w` — 2,000 ms after the data
existed. A read scheduled at 3,400 ms into `w−1` (effectively
`publicReadOffsetMs = −600`) would hand the answering side a budget of
`4,000 − 3,400 + 2,400 = 3,000 ms` without moving a single append slot. It is a
uniform schedule change, so it keeps the fixed shape and adds no §3a item, but
`publicReadOffsetMs < 0` fails the validator (`profile.ts:252-254`, spec:5815)
and would be a **named deviation**. With C1/C2 in place the budget is already
60× the need, so this buys robustness, not seconds. **Park; revisit only if the
window is shortened below ~1,000 ms.**

### C13 — NOT A CANDIDATE, A CEILING: the scan's bandwidth is structural

Holding object sizes fixed, nothing above changes the **2,762,492 bytes per
client per window** (both stores, cohort 8, measured `observed.md` §4a). That
is **5.5 Mbit/s sustained just to be idle** at W = 4,000, and **22 Mbit/s** at
W = 1,000 — 4.7 GB/hour at cohort 2 and W = 1,000. Any plan that reaches
"blazing fast" by shrinking the delivery window runs into this before it runs
into anything else, and no store-side fix touches it.

The levers that do touch it all leave my angle, and each is a disclosed trade:

| lever | scan bytes/store/window | what it costs |
| --- | ---: | --- |
| cohort 8 (pinned) | 1,380,336 | — |
| cohort 4 | 723,344 | the anonymity set halves; §3a items 3 and 13 |
| cohort 2 | 656,992 | the anonymity set is 2; the prototype's own `minMeasuredSharedCohort` is 2 |
| drop size class 1 | 199,056 (**6.9×**) | **spec deviation at spec:5770-5774**, enforced at `profile.ts:190-203` ("exactly two classes with operationPayloadClass values [0, 1]"), and no operation may exceed 4,096 payload bytes — a real-network SDP can (`floor.md` §3 puts the class-0 ceiling at 3,613 bytes of SDP) |

Worth saying plainly because it is the honest answer to "blazing fast": the
class-1 pool is **86 % of every client's traffic forever**, and in every
recorded run **no flight ever used it** (`floor.md` §3: loopback SDPs are
class 0). Collapsing to one wider class — e.g. one class of 16,384 B — would cut
the scan ~3.5× and cover any realistic SDP, at the price of a named spec
deviation and the loss of a cover pool nothing is currently hiding in. That is
the maintainer's call, not mine, and it must be measured and disclosed, not
assumed free.

---

## 8. Ranking by saving-per-risk

| # | Candidate | Saving | Risk | Files / LOC |
| ---: | --- | --- | --- | --- |
| 1 | **C2** hex codec | 137 → ~5 ms per read, 184 → ~5 ms per write; store load factor ≈1.2 → ≈0.05 | **zero** — no wire, no shape, no §3a | 1 / ~25 |
| 2 | **C1** precomputed chunk rows | 137 → **0.072 ms**; scan p50 1,453 ms → <50 ms | **zero** — same bytes, same routes | 4 / ~140 |
| 3 | **C5** immutable response cache | → 0.0002 ms; measured 0.54–0.81 ms TTFB over HTTP | near-zero (state the hit/miss timing) | 1 / ~40 |
| 4 | **C7** unblock the union | up to 1 window per flight when a store is degraded | low; re-read spec:5837-5845 | 1 / ~60 |
| 5 | **C4** drop slots after finalization | halves the document and the disk | low; check the provenance argument | 1 / ~5 |
| 6 | **C3** split the document | subsumed by C2 | low | 3 / ~120 |
| 7 | **C8** memoize the chain verdict | unknown; measure first | low | 1 / ~50 |
| 8 | **C6** CDN | production scale | **adds an observer**; §3a items 2, 8 | 0 |
| — | C9, C10 | ≤3 ms | reject | — |
| — | C11, C12, C13 | 0 after C1/C2 | park / disclose | — |

**Do C2 today. Do C1 this week. Re-run the four scenarios. Then, and only then,
argue about the delivery window.**

---

## 9. Where I would be wrong, and what would make me drop C1/C2

I am asked to be skeptical of my best idea, and there are three ways it
disappoints:

1. **The saving may already have been spent.** If the parallel agent's profile
   move (§0.1) makes every flight catch its slot on today's slow store, then at
   W = 4,000 the rendezvous is already ~24 s and C1/C2 buy **0 seconds and 0
   windows** on the healthy path — they buy margin, robustness, and the right to
   shorten the window. I would still ship them (they are 25 lines and remove a
   1.4× CPU load factor), but I would stop calling them a latency fix and start
   calling them a **precondition**. **The one run that settles it** is a
   `--scenario=healthy` on the current tree with `store-missed` grepped for
   `window-finalized`; §6.2 predicts the profile move alone *fails* that grep,
   and if it passes, my framing is the thing that is wrong.
2. **The load-factor number is derived, not measured.** §1.2's 3.5–5.8 s per
   4,000 ms window multiplies measured per-call costs by counted requests. It
   assumes appends cost 130–320 ms on a partially-filled document, interpolated
   from two measured points (102 ms at 2.76 MB, 137 ms at 5.53 MB). If the real
   append path is much cheaper than that — because most of a window's document
   is small until the last appends land — the store is merely slow rather than
   saturated, and C1's story becomes "a 20× faster read" instead of "the store
   cannot keep up". It would still be worth doing; it would be less urgent.
   **One instrumented run** with `Server-Timing` on every route settles it, and
   `cachedstore.ts` already emits exactly that header.
3. **The measurements are `bun` on arm64 loopback.** `Number.parseInt` on a
   two-character slice is pathologically slow in this engine; another JS engine
   might optimize it and the 107 ms could be 20 ms elsewhere. That would move
   the ratios, not the conclusion — `Buffer.from().toString("hex")` is 409×
   faster here and is not going to be slower anywhere — but it means the
   *absolute* store-side numbers are about this deployment, and a production
   store should be re-measured rather than assumed.

Two things I did **not** do that a next pass should: (i) take a live
`--scenario=healthy` baseline on the current tree — the harness aborted with
`EADDRINUSE :::5920` because a parallel agent was running, and I chose not to
fight over ports; (ii) implement C2 in the repo and re-run the scenarios, which
would turn every prediction in §6 into a measurement.

---

## 10. Files (all in this scratchpad, nothing in the repo was modified)

| file | what it measures |
| --- | --- |
| `probe-attribute.sh` | one store, no client, `curl`: the flat ~103 ms chunk GET, the absence of any warm path, then the in-process attribution |
| `benchload.ts` | `SELECT` / `TextDecoder` / **`JSON.parse` (0.30 ms)** / `loadWindow` (102 ms) / `encodePublicChunkReadV1` |
| `benchload2.ts` | the split inside `fromDocument`: **hex 107.2 ms vs 2.9 ms**, canonical decode 1.4 ms, re-encode 0.3 ms |
| `benchload3.ts` | a realistic populated window (5,528,125 B): **137 ms today, 0.072 ms per-chunk rows, 0.0002 ms cache** |
| `benchsave.ts` | the write side: `saveWindow` **184 ms**, `hexOf` 4.09 → 0.38 → **0.01 ms** |
| `cachedstore.ts` | a scratch `storeServer` with an outer immutable-response cache and a `Server-Timing` header; imports the repo, changes nothing in it |
| `scanprobe.sh` | the real 6-request scan over HTTP: **652 ms cold (the serial ladder) → 41 ms warm, 0.54–0.81 ms TTFB** |
| `attr-ws/`, `cache-ws/` | the throw-away store databases those produced |
