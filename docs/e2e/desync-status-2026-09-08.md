# Desync remediation status — 8 September 2026

The accepted desync remediation is complete and verified locally across
`p2party-js`, `p2party-server` and `p2party.com`. The production SDK changes are
committed through `7e09188`; SDK `0.14.8` is vendored in site `f88cd39`, paired
with server `0.1.2` at `b901278`. Publication and deployment remain separate.

## Verification

The [complete browser results](README.md#recorded-results-2026-09-08-completed-remediation)
and [machine-readable evidence](desync-results-2026-09-08.json) cover all 23
planned arms: 22 pass, and one old-server replacement case is an established
bounded non-convergence residual. The residual has exactly three rebuilds and
no further churn after the budget is spent; it remains a driver failure.

Six completed, unaffected immediate-mode arms come from matrix 1200; sixteen
come from completed matrix 1400, and the CPU-throttled arm from matrix 1500,
all with the same production bundle. CPU run 1421 remains a recorded failure:
the power log confirms 22 s of whole-host idle sleep immediately after thaw.
Run 1521 repeats its unchanged inputs and deadline with idle sleep prevented.
The interrupted 1200 arms are excluded. Its two object-symmetry-only failures
were rerun after keeping I7 diagnostic; real authentication, fingerprint and
delivery requirements remain mandatory. Scheduled probes now allow their
configured cadence while retaining the original observation deadline.

The actual site/server run passed UI messaging, reload/rejoin, unattended
server-restart recovery, same-identity responder replacement, stable visible
wrong-PIN failure, and one-sided corrected-PIN retry. Every context used the
vendored WASM. There were zero browser page errors. Saved server preferences
also hydrate and reload without errors or an unintended connection.

- SDK: **1,674 tests / 23,986 assertions**, no failures; both TypeScript
  configurations passed. This includes unrelated uncommitted prototype tests.
- Final harness: **50 tests / 134 assertions** across verdict, cadence-budget
  and compatibility checks. These overlap the SDK suite, so totals are not
  additive. Deliberate negative controls establish that failures are detected.
- Server: **120 tests / 442 assertions** and TypeScript passed.
- Site: **116 tests / 410 assertions**, TypeScript, lint, build, clean offline
  install, artifact provenance and real-browser checks passed.
- The focused scheduled-send review passed 57 tests and six regression
  mutations; the terminal-handshake review passed 78 focused tests, including
  one-sided retry and identity aliases. These overlap the suite totals.

Missing final evidence cannot inherit stale success. Mutual authentication and
matching DTLS fingerprints are required for recovery, and RTK/mutex/database
cleanup is checked. Freeze recovery must authenticate within 15 seconds. A
real second tab shares the original browser context and must authenticate and
exchange messages within 20 seconds. These are measured two-peer loopback
scenarios, not a general network latency bound.

## Remaining scope

C6 (sparse-PQ healing during a scheduled transfer), C10 (durable sender outbox
and stale partials), C11 and C9's roster protocol half, and per-chunk scheduled
receipts remain explicitly deferred in [ROADMAP.md](../../ROADMAP.md).
Socket-generation recovery requires the updated server; server 0.1.1 cannot
supply the missing generation. Sender recovery across a page reload remains
unsupported.

Only the three project repositories are part of this closure. Unrelated
prototype/mobile work and both SDK stashes are preserved. Test services are
stopped after verification. No push, publication or deployment is performed.
