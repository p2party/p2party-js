# Append slot order in the two-store prototype

The experimental profile saved about eight seconds when local chunk replies
were delayed by 800 ms. The two profiles finished in the same delivery
window at every native-read start phase. All 24 two-way exchanges passed.
Prototype clients and stores can opt in with `experimental-critical-later-v1`.

## Results

Each cell is the slower endpoint's time in seconds from publishing presence
to verifying its peer's message. The delta is candidate minus release.
The first matrix tested the proposed schedule through a harness override.

| Added chunk delay | Target phase | Release | Candidate | Delta |
| ---: | ---: | ---: | ---: | ---: |
| 0 ms | 350 ms | 24.354 | 24.356 | +0.002 |
| 0 ms | 1,650 ms | 23.055 | 23.066 | +0.011 |
| 0 ms | 2,350 ms | 22.354 | 22.373 | +0.019 |
| 800 ms | 350 ms | 33.100 | 25.160 | −7.940 |
| 800 ms | 1,650 ms | 31.861 | 23.869 | −7.992 |
| 800 ms | 2,350 ms | 31.157 | 23.168 | −7.989 |

We repeated all 12 trials on the implemented profiles at commit `3a059c0`.
Both stores and browsers used the ordinary runtime selectors and a single
browser bundle. The final column accounts for startup variation. It compares
the slower endpoint on each profile after adding each page's observed start
phase to its own verification time.

| Added chunk delay | Target phase | Release | Candidate | Delta | Phase-adjusted delta |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 0 ms | 350 ms | 24.367 | 24.292 | −0.075 | 0.000 |
| 0 ms | 1,650 ms | 23.089 | 23.077 | −0.012 | −0.016 |
| 0 ms | 2,350 ms | 22.365 | 22.366 | +0.001 | +0.001 |
| 800 ms | 350 ms | 33.165 | 25.163 | −8.002 | −7.998 |
| 800 ms | 1,650 ms | 31.857 | 23.856 | −8.001 | −7.956 |
| 800 ms | 2,350 ms | 31.161 | 23.161 | −8.000 | −8.000 |

All 24 exchanges passed the existing two-store checks. Each pair verified
140,005 bytes in one direction and 9,005 in the other, with zero appends
refused because the window had finalized. The time saved under delay is
consistent with two dependent identity flights each reaching a slot one
4-second window earlier. Each matrix sampled one exchange per condition on
the same shared laptop. These observations cover foreground Chromium with
both stores available. Estimating real-device latency percentiles or the
frequency of this read delay requires additional measurements across devices.
[Harness trial data](bench/slot-order-samples-2026-11-27.jsonl) ·
[Runtime confirmation data](bench/slot-order-confirmation-2026-11-27.jsonl)

## Experiment

On November 27, 2026 we tested step 4 of the September plan using the flagged
two-store prototype from SDK v0.15.1 (`bf3b368`). The harness runs two fresh
Chromium contexts and two fresh local SQLite stores for every exchange.
Clients use their normal WebRTC, WASM and store request paths, with local
host candidates and synthetic messages in both directions. The released
signaling service is outside this experiment.

We kept the 4,000 ms window, cohort of eight, scan offset of 600 ms, and
finalization at 2,800 ms. Only the roles at existing append slots changed.
The table gives milliseconds after the start of each window.

| Class | Role | Release | Candidate |
| --- | --- | ---: | ---: |
| 0 | State replication | 2,100 | 1,300 |
| 0 | Identity bootstrap | 1,300 | 1,700 |
| 0 | Safety control | 1,700 | 2,100 |
| 1 | State replication | 1,900 | 1,500 |
| 1 | Safety control | 1,500 | 1,900 |

The identity flight has 700 ms from scan start to its release slot and
1,100 ms to the candidate slot. Both validated profiles append 172,542 bytes
and scan 1,380,336 bytes per client, store and window. The encoded role
assignment contributes to the profile hash, so the stores and clients in an
exchange must select the same profile.

| Profile | SHA-256 delivery profile hash |
| --- | --- |
| Release | `83a2261ee4c0f345977e94416591372007578db22619b80afa583d2082c68a38` |
| Candidate | `9728493b6acbc77e9a819a64011fce9f72b12e73b3d3c0951fca275ed3cbef3c` |

We launched each pair of pages at three offsets in the window. The 350 ms
offset precedes the scan, 1,650 ms falls between the candidate and release
class-0 state slots, and 2,350 ms follows all append slots. The launcher
records when each page reports publishing presence. Startup and the driver
callback account for the difference between requested and observed phases.
The two profiles alternate which runs first across successive pairs.

In the delayed trials each page holds successful chunk GET responses from
its local stores for 800 ms after the native fetch resolves, before its store
client can consume them. Concurrent requests wait in parallel. We chose
800 ms to fall between the two identity-slot budgets. This isolates client
read availability. It does not emulate link bandwidth, loss, jitter or store
CPU load. Delayed-read counts include successful fetches handed to the
clients by the time both messages have arrived.

## Prototype implementation

Both sides can select the measured profile before deriving the hash. Set
`P2PARTY_STORE_DELIVERY_PROFILE=experimental-critical-later-v1` on each
local prototype store and pass `deliveryProfile: "experimental-critical-later-v1"`
to each `runBlindRendezvousPrototype` client. Pinned is the default. Use a
fresh store database for a different profile. The store checks the hash
persisted at its first successful start, and each client checks its chosen
profile against the store's signed descriptor before reading a window.

The original matrix used a harness-only role override. Its hashes are now
fixtures for the named profiles, and the runner selects them through the
prototype API. A future default change would require a coordinated profile
migration and measurements on representative devices with a range of read
latencies. [Store configuration](../blind-rendezvous-two-store-prototype.md)

## Reproduce

Use the existing browser harness prerequisites, build its assets, and run
from the SDK root. The study uses loopback ports 18410, 18411 and 18422.

```sh
bash docs/e2e/blind-two-store/build.sh
node docs/rendezvous-latency-2026-09/bench/slot-order-study.mjs > samples.jsonl
```

The runner emits one JSON row per trial, and exits unsuccessfully on a failing
trial. Reported milestone times use each page's own `presence-published`
event as time zero. The run machine had an Apple M2 Max, macOS 27.2.1,
Node 26.13.1, Bun 1.4.5 and Playwright 1.65.1 with Chromium headless shell
159.0.8154.6. [Browser harness setup](../e2e/blind-two-store/README.md)
