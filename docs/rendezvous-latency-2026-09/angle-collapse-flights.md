# Collapsing the five dependent flights

Angle: reduce the number of dependent flights in the two-store blind
rendezvous. Everything below is anchored to
`scratchpad/latency/floor.md` (the structural derivation) and
`scratchpad/latency/observed.md` (the three instrumented runs), plus four
new measurements I took for this report (§3). Paths are relative to
`~/Desktop/@p2party/p2party-js`, branch
`feat/blind-two-store-prototype`.

---

## 0. The verdict, before the detail

1. **The flight count is worth 4.0 s per flight at the pinned profile once
   the store is fixed, and 8.0 s per flight today.** Both numbers are in the
   recorded cohort table already: `4000/8` costs 8.0 s per flight, `4000/4`
   and `4000/2` cost 4.0 s per flight
   (`docs/blind-rendezvous-two-store-prototype.md:427-433`).
2. **One window is available with no new disclosure at all**, by having the
   *responder* send the first transport offer alongside its ACCEPT (C1).
   Every SDP still travels to an endpoint whose stable identity the sender
   verified first. What is given up is an *ordering* rule (spec REQ-012 line
   927 and spec:10220), not a *recipient set*.
3. **The second window costs exactly one admission gate — the initiator's —
   and nothing else.** Both mechanisms that buy it (SDP-in-HELLO, or a
   speculative offer under a HELLO-derived root) disclose the initiator's
   SDP to a presence author whose stable identity it has never seen. In the
   prototype's OPEN policy that is a one-window earliness plus the loss of a
   signed artifact; in *any* policy room it is a REQ-012 violation and the
   fast path must refuse to run.
4. **The brief's option (a) — SDP inside HELLO — is dominated and I recommend
   dropping it.** Suite 1 has no class-1 bootstrap form
   (`pairStepEnvelope.ts:113`, `pairPlaintext.ts:588`), so a merged
   HELLO+OFFER has **1,136 bytes** of SDP headroom against a **2,919-byte**
   bootstrap plaintext target. I measured a real Chromium offer at 716 B
   (2 mDNS host candidates) and 987 B (one STUN, 4 candidates): the fast path
   dies at roughly **five ICE candidates**, silently, with no larger class to
   fall back to. Option (b) buys the identical window at the identical
   privacy price with no size cliff.
5. **The brief's option (c) — a room-derived rendezvous key — is the worst
   saving-per-risk of the four.** One window, in exchange for a new
   `PairStepKindV1` member, a room-wide stable-identity broadcast, and a pair
   root derived from one KEM encapsulation instead of two.
6. **A ~10-line bug fix gates all of it.** `ingest` makes one pass over
   `state.activePairOuterOperationIds` (`pairDriver.ts:751`), which
   `coreReduce` sorts by *operation id* — i.e. randomly
   (`coreReduce.ts:1589`). Every collapse puts two causally ordered
   operations in one read batch, so a naive implementation delivers its
   promised window **about half the time**.

---

## 1. What I verified, and what I refute

The brief's stated belief, restated: five dependent flights, each gated by
`publicReadLagWindows = 1`, plus a cold-start window.

**Verified, with one correction that changes the price of this whole angle.**
A flight is gated by *two* things, not one:

- **Gate A, the read lag.** What a peer publishes in window `w` is legible at
  `(w+1)×W + publicReadOffsetMs` and no earlier (floor.md §2, Gate 3;
  `carrierRuntime.ts:621`, `:709-711`, validator `profile.ts:255-257`).
- **Gate B, the `(role, sizeClassId)` slot.** `#pendingEntry`
  (`carrierRuntime.ts:1325-1337`) matches role *and* size class, and the
  profile gives exactly one offset per pair. A missed slot costs a whole
  window; there is no same-window retry (`carrierRuntime.ts:668-673`).

Gate B is what makes this angle cheap. **Two operations of different service
roles ride different slots in the same window.** `operationServiceRole`
(`workKinds.ts:38-52`) maps `IDENTITY_HELLO`/`IDENTITY_ACCEPT` to
`identity-bootstrap` (class 0 @ 1,300 ms) and `TRANSPORT_OFFER`/`ANSWER` to
`safety-control` (class 0 @ 1,700 ms, class 1 @ 1,500 ms). So an
identity flight and a transport flight **already have separate append
opportunities inside one window**, at the pinned profile, with no profile
change, no extra request, and no change to the fixed shape a store sees.

That is the mechanical fact this entire angle rests on, and it is free.

**What I refute:** the framing that collapsing flights is expensive because
it "changes what a store can correlate within one window" (observed.md §7
item 4, which flags it as unmeasured). It does not. `#eventsForWindow`
schedules the same five append POSTs whether the outbox holds nothing, one
operation, or two; a slot with no matching entry sends a dummy of the exact
same size at the exact same instant (`carrierRuntime.ts:788-812`,
`#buildObject`). Collapsing a flight changes which slot carries a real object
— and real and cover objects are computationally indistinguishable by
construction. **Every candidate in this report leaves design §5's "thirteen
fixed requests" table byte-for-byte unchanged.** The privacy question for
this angle is entirely about what the *peer* learns, never about the store.

One second-order store-visible effect, stated for honesty: a rendezvous that
completes in 4 windows instead of 6 means a client that stops its runtime at
handoff is active for fewer windows. Session start/stop is already visible
(spec §1.6 lists "client restart"), and design §3a does not claim otherwise,
so this adds no item — but it is a real, if tiny, change in the observable.

---

## 2. The dependency chain, and what each link actually needs

| Flight | Sender | Needs before it can be built | Sealed under | Openable by |
|---|---|---|---|---|
| `PRESENCE` | both | nothing | room-visible operation | any capability holder |
| `IDENTITY_HELLO` | initiator | the peer's **presence** (its KEM key + id) | HPKE to presence KEM key, psk = `RoomRoot` | the presence author |
| `IDENTITY_ACCEPT` | responder | an opened HELLO | HPKE to HELLO response key, psk = `HelloRoot` | the HELLO author |
| `TRANSPORT_OFFER` | initiator | `EstablishedPairRoot` = f(`HelloRoot`, `AcceptRoot`, helloId, acceptId) | `SealPairStep(EstablishedPairRoot, …)` | the confirmed pair |
| `TRANSPORT_ANSWER` | responder | the opened OFFER (WebRTC needs it) | same | the confirmed pair |

Two observations settle candidates (a) and (b):

- **The responder can derive `EstablishedPairRoot` the instant it seals its
  ACCEPT.** `sendAccept` calls `promoteEstablishedRoot(helloId, acceptId)` at
  `pairDriver.ts:1313`, *before* it publishes (`:1321`). So an
  `EstablishedPairRoot`-sealed OFFER from the responder is available in the
  same turn as the ACCEPT, with **no key-schedule change whatsoever**. This
  is C1.
- **The initiator cannot derive `EstablishedPairRoot` before ACCEPT exists** —
  `AcceptRoot` is the responder's HPKE bootstrap root and `acceptId` is the
  ACCEPT's operation id. The brief asks whether an honest alternative key
  schedule exists. **Yes, and it is not a weakening of key confirmation so
  much as a relocation of it:** `HelloRoot` is available to the initiator at
  HELLO-seal time (`sealPairBootstrapV1` returns `bootstrapRoot`,
  `pairDriver.ts:905-907`) and to the responder at HELLO-open time
  (`:1212-1213`). A domain-separated child,

  ```text
  SpeculativeTransportRoot =
      HKDF(HelloRoot, "p2party/prototype-v0/speculative-transport-root" || HelloOperationId)
  ```

  is computable by exactly the two parties that hold `HelloRoot` and by
  nobody else. `openPairStepV1` already takes `baseSecret` as a parameter
  (spec:10037, `SealPairStep(baseSecret, expectedPairSlot, …)`), so this is a
  key-schedule deviation, not a codec change. This is C2.

  What it costs is precise and worth stating exactly: `HelloRoot`'s recipient
  set is *the author of the presence the initiator encapsulated to*. That
  author's **stable identity is unverified at HELLO time** — it arrives only
  in the ACCEPT. So a speculative offer is SDP released to an unverified
  identity. Key confirmation itself is not weakened (the pair AEAD still
  authenticates); what is lost is the *admission* precondition.

---

## 3. Four measurements this report adds

All taken today, on this machine, with the same headless Chromium the harness
uses (`playwright-core` from `../p2party.com/node_modules`).

**3.1 — Real SDP offer sizes** (`RTCPeerConnection` + one data channel,
complete gathering):

| config | candidates | offer bytes |
|---|---:|---:|
| `iceServers: []` (the harness, `entry.ts:116`) | 2 (mDNS `.local` host) | **716** |
| one STUN server | 4 (2 host + 2 srflx) | **987** |

Per additional candidate line: **≈ 135 bytes**. Candidate-free base: ≈ 445 B.

Two facts from the sampled SDP that matter for §4's privacy accounting:
Chromium's host candidates are **mDNS names, not raw addresses**, so a
loopback offer discloses no LAN address; but the STUN configuration's srflx
candidates carry **the public IPv4 address and a global IPv6 address in
clear text**, alongside the SHA-256 DTLS fingerprint. That is the concrete
content of "early SDP disclosure" in production.

**3.2 — Canonical pair-plaintext sizes** (encoded against
`pairPlaintextV1Schema`, `pairPlaintextTargetBytesV1`):

```
bootstrap  class 0 plaintext target :  2,919 B   (4096 − 1,161 envelope − 16 tag)
established class 0 plaintext target:  4,017 B
established class 1 plaintext target: 69,553 B
IDENTITY_HELLO  today (no SDP)      :  1,561 B   → 1,358 B spare
IDENTITY_ACCEPT today (no SDP)      :    376 B   → 2,543 B spare
TRANSPORT_OFFER  body at sdp = 0    :    222 B
TRANSPORT_ANSWER body at sdp = 0    :    249 B
```

**3.3 — Headroom for the brief's option (a), computed from 3.2:**

```
merged HELLO + OFFER  = 1,561 + 222 = 1,783 B  →  SDP headroom 1,136 B
merged ACCEPT + ANSWER=   376 + 249 =   625 B  →  SDP headroom 2,294 B
```

With 3.1's numbers: the merged HELLO tolerates `(1,136 − 445)/135 ≈ 5` ICE
candidates. Four is what one STUN server already produces. A TURN-enabled
client (relay udp + relay tcp + relay tls, dual-stack) routinely produces
eight to twelve. **The binding constraint is the HELLO, and there is no
escape hatch**: `pairOperationPayloadClassForV1` permits `[0]` only when a
bootstrap header is present (`pairPlaintext.ts:588`) and
`pairCiphertextAndTagTargetBytesV1` fails closed on class 1 + bootstrap
(`pairStepEnvelope.ts:112-114`, comment: "Suite 1 deliberately has no class-1
bootstrap form"). Today's `TRANSPORT_OFFER` has 3,613 B of SDP room in class
0 and 69 KB in class 1; option (a) throws both away.

**3.4 — Batch ordering.** `coreReduce` sorts the active set by
`compareBytes(operationId, …)` (`coreReduce.ts:1589`) — operation ids are
hashes, so the order is uniform-random with respect to causality. `ingest`
makes exactly one pass (`pairDriver.ts:751`) and `handlePairOperation`
"returns false to defer: the operation stays unhandled so a **later ingest**
can retry" (`pairDriver.ts:1157`). A later ingest is the **next delivery
window**. Every collapse in this report puts a causally ordered pair
(ACCEPT before OFFER, or HELLO before speculative OFFER) into one batch.
**Probability the dependent one is processed first: 1/2. Cost when it is:
one full delivery window — exactly the window the collapse just bought.**
This is C5 and it must land first.

---

## 4. The candidates

Common notation: `F` = number of dependent flights;
`T_floor = W × (1 + F) + publicReadOffsetMs − p`, `p` uniform in `[0, W)`
(floor.md §4). "Windows saved" is exact and structural. Seconds are quoted
twice, because the value of a collapse depends on whether the store's
`loadWindow` `JSON.parse` (observed.md §4e) has been fixed:

- **pre-fix** (today, 2 windows per flight, measured 7.98 s median per
  flight, observed.md §3): a removed flight is worth **8.0 s**.
- **post-fix** (1 window per flight, the design's intent, verified by the
  cohort-4 and cohort-2 rows at 22.3 s / 23.8 s): a removed flight is worth
  **4.0 s** at `W = 4,000`, and **1.0 s** at `W = 1,000`.

---

### C5 — Fixpoint the ingest batch  *(enabler; ship first)*

**Mechanism.** Replace the single pass at `pairDriver.ts:751-768` with a loop
that repeats over the still-unhandled candidates until one whole pass makes
no progress. Roughly:

```ts
let progressed = true;
while (progressed && !this.isFailedEdge()) {
  progressed = false;
  for (const pairOperationId of state.activePairOuterOperationIds) {
    /* …existing body… */
    if (await this.handlePairOperation(snapshot)) {
      this.handledPairOperationIds.add(key);
      progressed = true;
    }
  }
}
```

**Saving.** Zero on its own. Without it, C1 and C2 deliver their window with
probability 1/2 — i.e. **C1's expected saving halves from 4.0 s to 2.0 s**,
and C2's from 8.0 s to 4.0 s.

**Privacy.** None. Purely local ordering inside one already-completed read;
no operation is created, no request is issued, `#eventsForWindow` is
untouched. **Maps to no §3a item.**

**Spec deviation.** None. §4.11's causal chain is a constraint on what may be
*created*, not on the order a receiver drains one batch.

**Implementation.** `src/blindRendezvous/prototype/pairDriver.ts`, ~10 LOC.
One test in `tests/blindRendezvous/prototype/pairDriver.test.ts` (~40 LOC):
feed a driver an ACCEPT and an OFFER in one `ingest` call, in both orders,
and assert both are handled in that single call.

**Measurement.** The unit test is the measurement. In the harness, no run
should ever show a phase event whose window is two greater than the window
that carried its predecessor once C1 is in.

---

### C1 — Responder sends the first transport offer  *(recommended)*

**One line.** The responder publishes `IDENTITY_ACCEPT` and
`TRANSPORT_OFFER` in the same delivery window, on the two different role
slots it already owns; the initiator answers.

**Mechanism.**
- `sendAccept` (`pairDriver.ts:1259-1323`) already calls
  `promoteEstablishedRoot` at `:1313` before publishing. Immediately after
  `this.publish(operation, "IDENTITY_ACCEPT")`, call `sendOffer()` — sealed
  under `EstablishedPairRoot`, unchanged, but with `direction = 1`
  (spec:10676: `PairPlaintextV1.direction` is the sender's persisted
  `RendezvousRole`), `previousPairOperationId = acceptId`,
  `pairDependencies = [helloId]`.
- The ACCEPT rides `identity-bootstrap` class 0 @ 1,300 ms; the OFFER rides
  `safety-control` class 0 @ 1,700 ms (or class 1 @ 1,500 ms for a large
  SDP). Two slots, one window, no profile change.
- `handleIncomingOffer` moves from the responder branch to the initiator
  branch and `handleIncomingAnswer` the reverse
  (`pairDriver.ts:1163-1168`); the initiator, on the same batch, opens the
  ACCEPT (deriving `EstablishedPairRoot`), then the OFFER, then publishes
  `TRANSPORT_ANSWER` (`direction = 0`) on `safety-control` in that same
  window.
- `LazyTransportProvider` (`index.ts:293-333`) currently binds the WebRTC
  offerer to the *rendezvous* initiator. Rebind: the WebRTC offerer (and
  therefore the data-channel creator, `webrtcProvider.ts:169-171`) becomes
  the rendezvous responder. `SessionRole` for `createSession`
  (`index.ts:699`) is derived from stable-key order and is unaffected.
- **Mandatory companion: pre-gather the offer at `start()`.** See "what
  would make me drop this" below.

**Flights saved.** One (`TRANSPORT_OFFER` stops being its own round trip).
`F: 5 → 4`.

**Windows saved.** One.

**Seconds.** Post-store-fix, `W = 4,000`: `E[T_floor]` 22.6 s → **18.6 s**
(−4.0 s). Pre-fix: −8.0 s, i.e. ≈ 41.8 s → ≈ 33.8 s. At the "blazing fast"
target of `W = 1,000`, cohort 2 (floor.md §9): −1.0 s.

**Privacy cost, in the design doc's vocabulary.** *None to a store* (§5's
thirteen fixed requests are unchanged; the same five append POSTs go out at
the same offsets with the same byte counts). *None to the room* (the OFFER is
sealed under `EstablishedPairRoot` exactly as today). *None to the peer's
recipient set*: the responder releases SDP only after it has opened, verified
and admitted the initiator's HELLO — its own gate — and the initiator
releases SDP only after opening and verifying the ACCEPT — its own gate. The
§1.6 sentence "**a client that is denied by the receiving frontend obtains no
SDP/ICE from that endpoint**" holds verbatim in both directions.

**Maps to no new §3a item, and widens none.** It touches §4.6's recorded
observation that "`TRANSPORT_OFFER` and `TRANSPORT_ANSWER` are not recorded
and not previewed [in the pair ledger] — they are guarded instead by being
sealed under `EstablishedPairRoot`" — that guard is unchanged; only its
direction flips.

**What *is* given up, named exactly.** The spec's *ordering* rule, in two
places:

1. **spec:10184-10188** — "The first transport offer is initiator key
   confirmation… an authenticated offer proves the initiator received and
   admitted ACCEPT. Thus no standalone confirmation round-trip is needed."
   Under C1 the responder's SDP is *emitted* before that proof exists. It is
   still only *readable* by an endpoint that can derive
   `EstablishedPairRoot`, which requires the HELLO response KEM secret key —
   held only by the endpoint whose identity the responder verified. So the
   recipient set is identical; the emission order is not.
2. **spec:10220** — "`RendezvousRole=initiator` sends the first transport
   offer so that offer proves it received and admitted ACCEPT." Directly
   contradicted.
3. **spec REQ-012, line 927** — "Only after **both** identity gates succeed
   may either side emit a pair-encrypted transport offer, SDP, ICE, or
   transport answer." Strictly, C1 emits after *one* gate. The mitigating
   fact is that the emitted bytes are unreadable until the second gate's
   input (the ACCEPT) has been opened, and the *denied* party never obtains
   SDP.

**Room-policy gating.** None required. C1 is safe under open, denylist-only,
address-book and authority modes, because each side's own release still
follows its own `Admit()`. (An address-book deployment may still prefer the
strict order for defence in depth; make it a policy flag, defaulting to fast
in open mode.)

**Deviation status.** A **named spec deviation** under spec:3392, covering
lines 10184-10188, 10220, and REQ-012's "both gates" wording. It is a
*protocol* deviation, not a profile one — so unlike floor.md's re-slotting it
cannot be waved through as "profile values".

**Implementation cost.**

| file | change | LOC |
|---|---|---:|
| `src/blindRendezvous/prototype/pairDriver.ts` | `sendAccept` tail calls `sendOffer`; swap the two role branches in `handlePairOperation`; flip `direction`/`previousPairOperationId`/`pairDependencies` on both transport flights and both validators | ~180 |
| `src/blindRendezvous/prototype/index.ts` | rebind `LazyTransportProvider` roles; update the phase-order comments at `:11-18`, `:79`, `:163`, `:293-294` | ~40 |
| `src/blindRendezvous/prototype/webrtcProvider.ts` | pre-gather hook (see below) | ~50 |
| `tests/blindRendezvous/prototype/pairDriver.test.ts` | new flight order; assert two publications from one `sendAccept` turn | ~120 |
| `docs/…-design.md`, `docs/e2e/blind-two-store/README.md` | the deviation, named | ~70 |

≈ **460 LOC across 5 files.**

**How to measure it worked.**
1. Re-run `analyze.mjs` over a fresh `P2PARTY_BLIND_TRACE` capture. The
   milestone ladder must shorten from `w0+2, w0+4, w0+6, w0+8, w0+10`
   (observed.md §2) to four rungs, and the responder's ACCEPT window must
   show **two** real appends, not one — read it off `appendsReal` in that
   window's `store-missed`/`append` emissions (`carrierRuntime.ts:830-836`).
2. Assert the fixed shape did not move: per page per store per window,
   exactly 13 requests plus the conditional witness pair, and
   `appendsDummy + appendsReal == 5`. `windowShape()` in
   `carrierRuntime.test.ts` already does this; it must stay green unchanged.
3. Re-run the wire-log audit. `0 of N needles found` must hold with the SDP
   needles for both pages.
4. `--scenario=all` must still be 4 of 4, including `kill-a`, where the
   collapse has one fewer window in which a store can die.

**What would make me drop C1.** ICE gathering. The responder's window budget
is: read completes at `publicReadOffsetMs + S`, ACCEPT must be sealed by
1,300 ms and the OFFER by 1,700 ms — and between them sit `createOffer()`
**and complete gathering**. Measured on loopback with `iceServers: []`,
`accepted → offer-sent` is **126–137 ms** (observed.md §6). With STUN or TURN
it is unbounded up to `DEFAULT_GATHERING_TIMEOUT_MS = 15,000`
(`webrtcProvider.ts:55`). If gathering misses the 1,700 ms slot, the OFFER
waits a window and **C1 delivers exactly zero**. So C1 is only worth shipping
together with **pre-gathering at `start()`** — creating the
`RTCPeerConnection` and its data channel before any peer is known, which
floor.md §11 already notes "costs nothing — `createOffer()` depends on no
peer state".

And pre-gathering has its own honest cost, which I have not seen written
down anywhere in this repo: a session-long `RTCPeerConnection` means **one
DTLS certificate fingerprint and one ICE ufrag/pwd reused across every pair
attempt in that session**. The SDP never leaves the pair envelope, so no
store sees it — but any *peer* that completes two attempts with this endpoint
sees the same fingerprint both times and can link them. Today each attempt
gets a fresh connection. That is a new, small, peer-visible linkability
surface and it needs a §3a line of its own, or a rule that the pre-gathered
connection is discarded and regenerated per pair attempt (which costs the
gathering time back on the second attempt only). **If the maintainer will not
accept either, drop C1 and take C6 instead.**

---

### C2 — Speculative offer under a HELLO-derived transport root

**One line.** The initiator publishes HELLO and, in the same window, a
`TRANSPORT_OFFER` sealed under a domain-separated child of `HelloRoot`; the
responder replies with ACCEPT and `TRANSPORT_ANSWER` in one window.

**Mechanism.**
- New derivation next to the others in `derivations.ts`:
  `SpeculativeTransportRoot = HKDF(HelloRoot, "p2party/prototype-v0/speculative-transport-root" || HelloOperationId)`.
  Deriving a child rather than reusing `HelloRoot` directly is deliberate:
  `HelloRoot` is already the HPKE psk for the ACCEPT
  (`pairDriver.ts:1296`), and feeding one secret to two different
  constructions is exactly the kind of thing that needs a proof rather than
  a shrug.
- `sendHello` seals the HELLO, signs it, derives its `operationId`, then in
  the same turn seals a `TRANSPORT_OFFER` under
  `SpeculativeTransportRoot` with `previousPairOperationId = helloId` and
  `pairDependencies = []` (legal: spec:9698 caps deps at one, "either no
  cross-direction dependency or exactly one"). Two publications, two role
  slots (identity-bootstrap @1,300 and safety-control @1,700), one window.
  `nextAuthorFields`/`recordOwnOperation` already chain two operations in one
  window correctly (`pairDriver.ts:963-982`) — verified, no change needed.
- The responder, on opening the HELLO, derives the same root, opens the
  speculative offer, and publishes ACCEPT + `TRANSPORT_ANSWER` (the latter
  under `EstablishedPairRoot`, unchanged) in its own single window.
- The initiator's final read opens the ACCEPT (deriving
  `EstablishedPairRoot`) and then the ANSWER — the C5 fixpoint is
  load-bearing here.

**Flights saved.** Two. `F: 5 → 3`.

**Windows saved.** Two.

**Seconds.** Post-fix, `W = 4,000`: 22.6 s → **14.6 s** (−8.0 s). Pre-fix:
−16.0 s. At `W = 1,000`: −2.0 s.

**Privacy cost.** *None to a store* — same argument as C1; the shape is
identical. *One admission gate lost, asymmetrically*: the responder's SDP is
still released only after it verified the initiator (its ANSWER rides the
ACCEPT window), but **the initiator's SDP is released to the author of a
presence whose stable identity, cross-signature and transcript signature it
has never seen.** Concretely, from §3.1: any capability holder that publishes
a presence and waits one window harvests, per initiator, the DTLS SHA-256
fingerprint and — in any STUN/TURN deployment — the initiator's **public
IPv4 and global IPv6 addresses**, without a round trip and **without leaving
a signed artifact** (today the harvester must publish an ACCEPT signed by a
stable key over the pair transcript).

**Maps to a NEW §3a item.** Proposed wording:

> 15. **Pre-admission transport disclosure (fast path only).** With the
>     speculative-offer fast path enabled, an initiator releases its SDP,
>     ICE candidates and DTLS fingerprint to the author of the presence it
>     selected, one flight before that author has proved a stable identity.
>     A capability holder that publishes presences and never answers harvests
>     transport metadata from every initiator that selects it, leaving no
>     signed artifact. The prototype runs an OPEN policy, where admission is
>     a no-op and the same disclosure occurs one window later regardless — so
>     the delta is one window of earliness plus the loss of the signed ACCEPT.
>     Under any non-open policy the disclosure precedes `Admit()` and the
>     fast path must be refused.

**Room-policy gating.** **Mandatory.** Refuse the fast path unless
`eligibility === "open"` (spec:7469) and the frontend is not in
`onlyConnectWithKnownPeers` / denylist-with-teeth mode. In
`local-address-book-proved` or `authority-permit-proved` mode the fast path
violates REQ-012 outright ("an initiator shall not send its identity hello to
an unproved presence" — a fortiori not its SDP). **PIN is orthogonal**: the
PACE/PIN step runs inside protocol-v4 *after* the data channel exists
(`mode: "nopin"` is passed to `createSession`, `index.ts:699`), so PIN does
not gate SDP release and is neither weakened nor helped — but PIN also does
not protect against the harvest above, because an IP address is disclosed
whether or not the session is later MITM-proof.

**Deviation status.** Two named deviations under spec:3392: the key-schedule
(a `SealPairStep` base secret that is not `EstablishedPairRoot`,
spec:10037), and REQ-012 line 927 plus spec:10182-10188 ("No SDP … appears in
the two identity flights" is preserved literally — the SDP is in a *third*
operation — but its purpose is not).

**Implementation cost.**

| file | change | LOC |
|---|---|---:|
| `src/blindRendezvous/derivations.ts` | `speculativeTransportRoot` | ~20 |
| `src/blindRendezvous/prototype/pairDriver.ts` | speculative seal in `sendHello`; open it in `handleIncomingHello`; ANSWER moves into `sendAccept`; slot/dependency edits on all four validators; a `fastPath` option gated on room policy | ~230 |
| `src/blindRendezvous/prototype/index.ts` | pre-gather + provider role wiring | ~50 |
| `tests/blindRendezvous/prototype/pairDriver.test.ts` | fast-path sequence, plus a **refusal test** under a non-open policy | ~160 |
| `docs/…-design.md` §3a item 15, §4.6, §5 | disclosure | ~90 |

≈ **550 LOC across 5 files** (and it subsumes C1, so do not price both).

**How to measure it worked, and measure what it cost.**
1. The ladder must show three rungs, and both the HELLO window and the ACCEPT
   window must show two real appends each.
2. **Add a harvest scenario to `run.mjs`.** `--scenario=harvest`: a third
   headless page joins with the same capability, publishes a presence, and
   never sends a HELLO or ACCEPT. Assert whether it ends up holding an
   openable `TRANSPORT_OFFER`, and print the SDP byte count it obtained. On
   the current protocol this must be 0 bytes; with C2 it will not be, and
   **the number the harness prints is the disclosure, measured rather than
   argued.** That scenario is what turns §3a item 15 from a claim into a
   fact, and it is the single most valuable test in this whole report.
3. Re-run the wire-log audit unchanged — the store must still find 0 needles,
   which is the point: C2 costs the *peer*, never the store.

**What would make me drop C2.** If the harvest scenario shows a third party
obtaining SDP that the current protocol denies it — which it will, by
construction — and the maintainer is not willing to carry §3a item 15 into
the outward doc, C2 is dead and C1 is the ceiling. I would also drop it if
the project ever intends to demo a non-open policy room, because then the
fast path is off exactly when the demo runs and the code is dead weight with
a security review attached.

---

### C3 — SDP inside HELLO and ACCEPT  *(the brief's option (a) — recommend REJECT)*

**One line.** Extend `PairIdentityHelloV1` with the initiator's transport
candidates and `PairIdentityAcceptV1` with the responder's answer.

**Flights saved / windows saved / seconds.** Identical to C2: two, two,
−8.0 s post-fix.

**Privacy cost.** Identical to C2 — same recipient set, same §3a item 15,
same mandatory policy gate. The brief asks "in an OPEN-policy room admission
is a no-op — so what exactly is lost?" The answer, precisely: *for the
responder direction, nothing* (it verified the HELLO first); *for the
initiator direction*, the SDP goes to a presence author whose stable identity
was never verified, so a capability holder harvests transport metadata with
one presence and no signed artifact. That answer is the same for C2 and C3.

**Why it is dominated.** Three costs C2 does not have:

1. **The size cliff (§3.3).** 1,136 bytes of SDP headroom, ≈ 5 ICE
   candidates, with `pairPlaintextTargetBytesV1(1, true)` failing closed —
   there is no class-1 bootstrap form to grow into. Today's transport
   flights have 3,613 B in class 0 and 69,553 B in class 1. The failure is
   *silent and data-dependent*: `padPairPlaintextV1` throws
   "pair plaintext fits no permitted operation payload class"
   (`pairPlaintext.ts:596`) at exactly the moment a user connects from a
   machine with one interface too many.
2. **It breaks the pinned codec vectors.** `PairIdentityHelloV1` and
   `PairIdentityAcceptV1` are frozen §4.11 types with known-answer bytes in
   `tests/blindRendezvous/prototype/schemas.test.ts`; C2 adds no field to any
   frozen type.
3. **It writes SDP into the flight the spec singles out.** spec:10182 — "No
   SDP, ICE, DTLS fingerprint, local radio address, asynchronous mailbox
   locator, or protocol-v4 handshake byte appears in the two identity
   flights." C2 leaves that sentence literally true.

**Implementation cost.** ≈ 700–900 LOC across `schemas.ts`,
`pairPlaintext.ts`, `derivations.ts`, `pairDriver.ts`, `index.ts`, and three
test files, plus regenerated known-answer vectors.

**Verdict.** Same saving, same privacy price, strictly more code, one silent
production failure mode. Drop it in favour of C2.

---

### C4 — Unconditional room-keyed identity beacon  *(the brief's option (c))*

**One line.** Both endpoints publish, in the same window as their PRESENCE, a
room-sealed identity beacon, so the first identity flight does not wait to
observe a peer.

**Mechanism and the key.** The key would be
`RoomRendezvousKey = HKDF(RoomRoot, "…/room-rendezvous/v0" || logicalWindow)`.
A beacon rides `identity-bootstrap` class 0 @ 1,300 ms in the same window as
PRESENCE @ 2,100 ms — different roles, so this collapse is slot-legal like
the others.

**But it cannot be an `IDENTITY_HELLO`.** `PairPlaintextV1` requires
`pairEdgeId` and `endpointPresenceOperationIds`, and
`pairEdgeId = H(RoomContextId, Sort2(localPresenceId, remotePresenceId))`
(`pairDriver.ts:1066-1070`). Neither is computable before a peer's presence
has been read. So C4 needs a **new `PairStepKindV1` member** and therefore a
new byte in the closed `PairStepKindByte` registry (spec:9530-9534) — which
changes the union tag of every `PairStepBodyV1` and every KDF that encodes a
slot. That is the largest codec deviation in this report.

**Flights saved / windows saved.** One (the observe→HELLO dependency is
removed, not the read). `F: 5 → 4`.

**Seconds.** −4.0 s post-fix; composes with C1 (`F → 3`) or with C2
(`F → 2`, `E[T_floor] = 10.6 s`).

**Privacy cost — three separate ones.**

1. **Room-wide stable-identity broadcast.** A room-derived key is held by
   *every* capability holder. §1.6's open-mode concession is that "**the
   selected** capability holder may learn that first sender identity"; C4
   widens "the selected" to "every". That is a widening of a disclosed leak
   and a new §3a item, and it makes room size and co-membership legible to
   any capability holder rather than to the peer it chose.
2. **Halved KEM contribution to the pair root.** Today `HelloRoot` binds an
   encapsulation to the *responder's* presence key and `AcceptRoot` an
   encapsulation to the *initiator's* response key — both endpoints
   contribute an ephemeral KEM public key. Under C4 the beacon is symmetric
   and room-keyed, so the bootstrap collapses to one encapsulation
   (responder → initiator's advertised beacon key). The pair root would rest
   on one hybrid KEM instead of two. That is a cryptographic weakening, not
   a disclosure, and it is the reason I would not ship C4 even if the
   broadcast were acceptable.
3. **Refused outright under address-book/authority mode** — REQ-012's first
   sentence ("a presence first proves eligibility without revealing a raw
   stable key to the room") is exactly what a room-keyed identity beacon
   violates.

**Deviation status.** A codec deviation (new `PairStepKindV1` member and
registry byte, spec:9517-9534), a key-schedule deviation, and a REQ-012
deviation.

**Implementation cost.** ≈ 900–1,100 LOC across `schemas.ts`,
`pairPlaintext.ts`, `derivations.ts`, `coreReduce.ts` (the new kind must be
classified and reduced), `pairDriver.ts`, `workKinds.ts`, `index.ts`, plus
regenerated vectors in three test files.

**Answer to the brief's "does it actually save a window given both sides
still have to read each other?"** Yes — exactly one, and the saving comes
from removing the *observe → act* dependency (today's HELLO cannot be built
until a presence has been read), not from the read itself. Both sides still
read each other once; the difference is that the identity material is already
in flight when they do.

**Verdict.** Worst saving-per-risk of the four. One window for a codec
change, a room-wide identity broadcast, and a weaker pair root. **Reject.**

---

### C6 — Symmetric transport parameters  *(alternative to C1; keeps the offerer role)*

**One line.** Replace offer/answer with a symmetric "connection parameters"
record (fingerprint + ice-ufrag + ice-pwd + candidates) that each side
publishes once and each side synthesises the peer's SDP from locally.

**Mechanism.** Generate the DTLS certificate up front with
`RTCPeerConnection.generateCertificate` so the fingerprint is known before any
peer exists; gather once; publish a `webrtc-parameters` transport candidate
kind instead of `webrtc-complete`. Each endpoint reconstructs the peer's SDP
offer/answer text locally and feeds it to `setRemoteDescription`. This is a
standard technique (libp2p-webrtc, Cloudflare Calls); the SDP text is
deterministic given the parameters.

**Flights saved.** One. The `TRANSPORT_ANSWER`'s dependency on the
`TRANSPORT_OFFER` disappears, so the responder can publish its parameters
with its ACCEPT and the initiator publishes its own one window later —
`F: 5 → 4`, the same as C1, **without flipping who is the WebRTC offerer**
and therefore without C1's `index.ts` rewiring or its role-naming confusion.

**Privacy.** Identical to C1: each side's parameters are released only after
its own gate. **No new §3a item.** One nuance in its favour: the parameters
record is smaller than a full SDP (no `v=0`/`o=`/`m=` boilerplate — roughly
445 B of the 716 B measured in §3.1 is boilerplate), so it makes the class-0
budget less tight everywhere, including for a hypothetical C3.

**Deviation.** A new `PairTransportCandidateV1` kind (spec §4.12's candidate
union) — smaller than C4's kind change but larger than C1's zero. Also
touches REQ-012's "transport offer, SDP, ICE, or transport answer" language,
which C1 touches too.

**Implementation.** `transportCandidates.ts` + `webrtcProvider.ts` SDP
synthesis (~250 LOC, and SDP synthesis is fiddly and browser-version
sensitive), `schemas.ts` candidate kind (~60), tests (~150). ≈ **460 LOC**,
but with real cross-browser risk that C1 does not have.

**Verdict.** Same saving as C1, no role flip, no pre-gathering linkability
caveat — but it hand-rolls SDP, which is the kind of thing that works on
Chromium and breaks on Safari. **Keep as the fallback if C1's pre-gathering
caveat is refused.**

---

### Considered and rejected in one line each

- **Both sides publish an offer, lower id wins.** The loser must still create
  and deliver a real answer; WebRTC will not accept a peer's independent
  offer as an answer. Saves nothing.
- **ICE-lite / derive the peer's ufrag from the pair root.** ICE still needs
  the peer's candidate *addresses*, and the DTLS fingerprint cannot be
  derived from a shared secret. Saves nothing without C6's parameter record.
- **Trickle ICE over the carrier.** Trickling costs *more* flights, not
  fewer; the profile's complete-gathering choice is right for this transport.
- **Fold the identity bundle into `PresenceCoreV1`.** A strictly worse C4:
  same room-wide broadcast, same one window, plus a change to a frozen
  core type.

---

## 5. Ranking by saving-per-risk

| rank | candidate | windows | Δs @ W=4,000 post-fix | new §3a item | spec deviation | LOC |
|---:|---|---:|---:|:---:|---|---:|
| 1 | **C5** fixpoint the ingest batch | 0 (enabler) | — | none | none | ~50 |
| 2 | **C1** responder offers | 1 | **−4.0** | none | REQ-012:927, spec:10184, spec:10220 (ordering) | ~460 |
| 3 | **C2** speculative offer under a HELLO-derived root | 2 | **−8.0** | **item 15** | + key schedule (spec:10037) | ~550 |
| 4 | **C6** symmetric transport parameters | 1 | −4.0 | none | §4.12 candidate kind | ~460 |
| 5 | **C3** SDP inside HELLO/ACCEPT | 2 | −8.0 | item 15 | + frozen §4.11 body types | ~800 |
| 6 | **C4** room-keyed identity beacon | 1 | −4.0 | new item + widens §1.6 | codec + key schedule + REQ-012 | ~1,000 |

**Recommended order to ship:** the store's `loadWindow` fix (observed.md §7
item 1, free, ~40× on the scan) → **C5** → **C1** with pre-gathering → stop
and look at the number. If it is not fast enough, **C2** behind an
`eligibility === "open"` gate and §3a item 15, with the `--scenario=harvest`
measurement landing in the same commit.

---

## 6. What the floor becomes

`E[T_floor] = W × (1 + F) + publicReadOffsetMs − W/2`, plus the final scan
`S` (observed.md §4b: client compute is 8 ms; `S` is the store, and the store
fix takes it from ~1,450 ms to tens of ms).

| configuration | W | F | E[floor] | + S | vs. the recorded 41.8 s |
|---|---:|---:|---:|---:|---:|
| today, pinned, store unfixed | 4,000 | 5 | 22.6 s + 16.0 s slip | ≈ 40.6 s | (measured 35.4–42.3 s) |
| store fixed only | 4,000 | 5 | 22.6 s | ≈ 22.7 s | −46% |
| + floor.md (a) re-slot + cold-start reclaim | 4,000 | 5 | 20.6 s | ≈ 20.7 s | −50% |
| **+ C5 + C1** | 4,000 | **4** | **16.6 s** | **≈ 16.7 s** | **−60%** |
| + C2 instead of C1 | 4,000 | **3** | 12.6 s | ≈ 12.7 s | −70% |
| + C2 + C4 | 4,000 | 2 | 8.6 s | ≈ 8.7 s | −79% |
| all of the above at W = 1,000, cohort 2, F = 4 | 1,000 | 4 | **4.2 s** | ≈ 4.3 s | **−90%** |
| the same with F = 3 (C2) | 1,000 | 3 | **3.2 s** | ≈ 3.3 s | −92% |

Two honesty notes on this table. First, **the flight-count rows are the
smallest term until the store is fixed** — before the fix each flight costs
two windows and the collapse is worth double, but you would be measuring
`JSON.parse`. Second, the `W = 1,000` rows are only reachable because the
store fix removes the reason a short window currently stalls (observed.md §5,
verdict 2): at 1,000 ms the request deadline is 1,000 ms
(`storeClient.ts:276-283`) and the store needs ~1,450 ms to answer one scan.
The measured `W=1000, cohort=2` run already reached **10.5 s** with none of
this.

---

## 7. Where I think I am most likely wrong

- **C1's pre-gathering caveat may be the whole story.** I asserted that
  `createOffer` + complete gathering fits between the 1,300 ms and 1,700 ms
  slots because loopback measured 126–137 ms. I have no production
  measurement, and `DEFAULT_GATHERING_TIMEOUT_MS = 15,000` says the code
  authors expected it to be slow. If gathering with a real TURN server takes
  more than ~400 ms, C1 without pre-gathering is worth nothing, and C1 with
  pre-gathering carries a fingerprint-reuse disclosure I do not know the
  maintainer will accept.
- **I have not proved the domain separation for C2's root.** Deriving a child
  of `HelloRoot` for `SealPairStep` while `HelloRoot` remains the HPKE psk for
  the ACCEPT is *probably* fine — the constructions are distinct and the
  transcripts differ — but "probably fine" is not a security argument and
  this is exactly where a real review belongs.
- **The §3.3 headroom is computed with `senderAdmissionGrant: null`.** A room
  with authority permits carries an `AdmissionGrantV1` in the HELLO, which
  shrinks C3's already-fatal 1,136 B further. That only strengthens the
  rejection, but it means my number is an upper bound, not a bound.
- **I did not measure the harvest.** §4/C2's disclosure claim is an argument
  from the key schedule, not a run. The `--scenario=harvest` proposal exists
  precisely because I could not, in this pass, turn it into a measurement,
  and nobody should quote §3a item 15's severity until someone has.

---

## 8. Deviations this report proposes, named as such

Per the brief's rule, and mirroring floor.md §10:

1. **C5, the ingest fixpoint** — *not a deviation.* A receiver-side batch
   drain order; §4.11 constrains creation, not draining.
2. **C1, responder-offers** — a **spec deviation**: REQ-012 line 927 ("only
   after both identity gates succeed"), spec:10184-10188 (the first offer as
   initiator key confirmation), spec:10220 (`RendezvousRole=initiator` sends
   the first offer). Permitted for a flagged prototype by spec:3392. **No new
   §3a item; no change to design §5's fixed trace.**
3. **C1's pre-gathering** — not a spec deviation, but a **new peer-visible
   linkability surface** (one DTLS fingerprint and ICE credential pair per
   session rather than per attempt) and therefore a new §3a line.
4. **C2, the speculative offer** — a **spec deviation** on the `SealPairStep`
   base secret (spec:10037) and on REQ-012, **plus a new §3a item 15
   (pre-admission transport disclosure)**, **plus a mandatory room-policy
   gate** (`eligibility === "open"` only).
5. **C3** — everything in 4, plus a deviation on the frozen §4.11
   `PairIdentityHelloV1`/`PairIdentityAcceptV1` types and their pinned
   vectors. Recommended rejected.
6. **C4** — a codec deviation on the closed `PairStepKindV1` union and its
   byte registry (spec:9517-9534), a key-schedule deviation (one KEM
   encapsulation instead of two), and a widening of §1.6's open-mode
   concession from "the selected capability holder" to every capability
   holder. Recommended rejected.

None of C1–C6 changes what a store sees in a window: the same thirteen fixed
requests at the same offsets carrying the same byte counts, with cover and
real objects indistinguishable. Every privacy cost in this report is paid to
a **peer**, never to a store — which is the right place for this prototype to
be spending, and the reason the flight-collapse angle is worth taking
seriously at all.
