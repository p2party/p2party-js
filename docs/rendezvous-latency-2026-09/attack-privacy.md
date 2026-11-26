# The privacy adversary's pass over every latency candidate

2026-09-08. Branch `feat/blind-two-store-prototype`. Paths relative to
the repository root.

Inputs: `floor.md`, `observed.md`, and the six angle reports
(`angle-shrink-class-1.md`, `angle-collapse-flights.md`,
`angle-schedule-shape.md`, `angle-scan-cost.md`,
`angle-presence-discovery.md`, `angle-product-shape.md`), read in full,
against `docs/blind-rendezvous-two-store-prototype-design.md` §2/§3a/§4.2/
§4.5/§4.6/§5 and the code each candidate touches.

My lens is one question asked forty times: **what does somebody learn that
they could not learn before?** Not "is it faster", not "is it a spec
deviation" — the other six reports settled those. Where I disagree with an
angle report's own privacy verdict I say so and give the mechanism.

---

## 0. The verdict table, all forty candidates

Codes: **SC** = shrink-class-1, **CF** = collapse-flights, **SS** =
schedule-shape, **SCAN** = scan-cost, **PD** = presence-discovery,
**PS** = product-shape. Where two reports proposed the same thing I fold them
and say so.

| # | Candidate | Verdict | Who pays |
|---|---|---|---|
| SCAN-C1 | precomputed chunk rows in the store | **SURVIVES** | nobody |
| SCAN-C2 | hex codec in `storeSqlite.ts` | **SURVIVES** | nobody |
| SCAN-C3 | split the window document | **SURVIVES** | nobody |
| SCAN-C4 | drop `slots` after finalization | **SURVIVES** | nobody — but it is not a privacy win, see §6.4 |
| SCAN-C5 | in-process immutable response cache | **SURVIVES WITH A DISCLOSURE** (or eager-populate and it survives clean) | any client, a store-population oracle |
| SCAN-C6 | CDN in front of the immutable routes | **NEEDS A GATE** (distinct operators + ASNs, per store) — **KILL** if one CDN fronts both | a third observer |
| SCAN-C7 | do not let the slow store gate the fast one | **SURVIVES WITH A CONSTRAINT** (§6.7) | nobody, if the constraint holds |
| SCAN-C8 | memoize the checkpoint-chain verdict | **SURVIVES WITH A CONSTRAINT** (§6.8) | nobody |
| SCAN-C9 | pre-AEAD recipient hint | **KILL** | a future capability holder |
| SCAN-C10 | WebCrypto for the AEAD | **KILL** | — |
| SCAN-C11 | one request for the whole window | **KILL** | — |
| SCAN-C12 | negative read offset (read inside `w−1`) | **KILL** | §3a item 14 |
| SCAN-C13 | "drop size class 1 entirely" (the table's last row) | **KILL** — it is SC-C6 | — |
| SS-C1 | late slots, reversed roles, `cf` 3,500 | **SURVIVES** | nobody |
| SS-C2 / PD-D2 | cold-start allocation for the current window | **SURVIVES WITH A DISCLOSURE** (new item 18) | a store, one bit, first window |
| SS-C3 / PD-D3 | `publicReadOffsetMs` → 0 | **SURVIVES WITH A CONSTRAINT** — keep `r ≥ maxScheduleSkewMs` (§6.11) | §3a item 14, if taken to 0 |
| SS-C4 | a second append slot per critical role | **SURVIVES WITH A DISCLOSURE** (13 → 14 fixed requests, +4.8% scan) | nobody |
| SS-C5 / PD-D9 | `publicReadLagWindows` → 0 | **KILL** | §3a item 7 — detection becomes nothing |
| SC-C1 | class-1 carrier object 73,728 → 8,448 | **SURVIVES WITH A DISCLOSURE** (new item 19) + a correctness gate (§6.14) | nobody at a store; a future archivist |
| SC-C2 | + payload class 1 → 8,192 | **SURVIVES WITH A DISCLOSURE** (item 19) | as SC-C1 |
| SC-C3 | class 1 → 36,864 | **SURVIVES WITH A DISCLOSURE** (item 19) | as SC-C1 |
| SC-C4 | `publicChunkObjectCount` 8 → 24 | **SURVIVES WITH A DISCLOSURE** (§5's table: 13 → 10 requests; +20% scan) | nobody |
| SC-C5 | §4.12 operation-carrier fallback | **SURVIVES WITH A DISCLOSURE** (§6.18) | the peer, one bit |
| SC-C6 | class 1 → 4,097 (the pure-cover floor) | **KILL** | — |
| CF-C5 | fixpoint the ingest batch | **SURVIVES** | nobody |
| CF-C1 | responder sends the first transport offer | **SURVIVES WITH A DISCLOSURE** (a named spec deviation, no §3a item) | nobody |
| CF-C1b / PS-C7 | pre-gathered ICE | **SURVIVES WITH A DISCLOSURE** as a *pool* of fresh connections; **NEEDS A GATE** as one session-long connection (§6.21) | a peer and an on-path observer — and it **removes** a leak, see item 16 |
| CF-C2 | speculative offer under a HELLO-derived root | **NEEDS A GATE** — `maxRoomMembers === 2` **and** a single-use capability **and** `eligibility === "open"` — + new item 21 | a presence author the initiator never verified |
| CF-C3 | SDP inside HELLO/ACCEPT | **KILL** | — |
| CF-C4 | room-keyed identity beacon | **KILL** | every capability holder |
| CF-C6 | symmetric transport parameters record | **SURVIVES WITH A DISCLOSURE** (§6.24) | nobody |
| PD-D1 / PS-C0 | store `loadWindow` fix | **SURVIVES** — same as SCAN-C1/C2 | nobody |
| PD-D4 | presence's append slot later | **SURVIVES** — subsumed by SS-C1 | nobody |
| PD-D5 / PS-C2 | standing presence / presence heartbeat | **SURVIVES WITH A DISCLOSURE** (new item 20) + a mandatory cap and coarsening | every capability holder, now and retroactively |
| PD-D6 / PS-C1 | warm start from a retained peer presence | **SURVIVES WITH A DISCLOSURE** (new item 22) + mandatory encryption at rest | anyone who gets the device |
| PD-D7 | shorten `deliveryWindowMs` | **SURVIVES WITH A DISCLOSURE** (§6.29 — and the usual framing of the cost is wrong) | §3a item 1, linearly in 1/W |
| PD-D8 | shrink class 0's carrier object | **SURVIVES** — privacy-neutral, correcting the report (§6.30) | nobody |
| PS-C5 | symmetric transport flight (both publish SDP) | **SURVIVES WITH A DISCLOSURE** — an *alternative* to CF-C1, not additive | nobody |
| PS-C3 | ICE parameters ride in PRESENCE | **KILL** | every capability holder, retroactively, forever |
| PS-C6 | store as a fast SDP drop | **KILL** | the store — a peer-equality handle |
| PS-C8 | legacy signaling as a fast path | **KILL** | a third party gets everything |
| PS-C9 | long-lived push read (Cwtch-shaped) | **KILL** | §3a item 1, strengthened |

**Nine kills, four gates, seventeen clean survivals, ten survivals with a
disclosure.** The five sentences that must be added to §3a are in §4; three of
them are owed **whether or not any candidate ships**.

---

## 1. Three corrections that change how every candidate is priced

Before the verdicts. These are not opinions about the candidates; they are
facts about the system that several angle reports priced wrongly, and each one
moves a whole column of the table.

### 1.1 The cohort is not an anonymity set against a store

`angle-scan-cost.md` §7/C13 prices `cohort 8 → 4` as "the anonymity set
halves"; `angle-shrink-class-1.md` §3/C1 sells its candidate as buying "the
latency the cohort knob buys, without paying the cohort knob's price";
`angle-product-shape.md` and `angle-presence-discovery.md` inherit the
framing. **The framing is wrong, and it makes several candidates look more
expensive than they are.**

A store issues the lease. `#append` computes
`objectOrdinal = roomSlot × appendSchedule.length + entryIndex`
(`carrierRuntime.ts:785`) and signs an admission over
`(lease, sizeClass, objectOrdinal, object)`; `storeCore` verifies the lease
under its own key and the admission under the lease's ephemeral key, then
places the object at exactly
`appendSlotCoordinates(geometry, sizeClass, allocationOrdinal, ordinal)`
(`publicWindow.ts:281-322`), where
`globalObjectOrdinal = allocationOrdinal × perAllocation + objectOrdinal`.
The client also POSTs each object from its own address on its own connection.

So a store already knows, exactly and by construction, **which object
positions in which chunk belong to which allocation and therefore to which
source address**. The 40 objects per window are not a crowd a client hides in
*at its own store*. What they are is a crowd a client hides in **from a
reader** — and that property comes from the *fixed full scan* (every client
GETs every chunk of every window, so a store cannot tell which object a client
came for), not from `cohortAllocationsPerWindow`.

What the cohort actually is: capacity, scan cost, and the **measurable shared
cohort** (`minMeasuredSharedCohort = 2`) — the number of distinct allocations
a client can verify were present in a window, which is a "am I alone at this
store" assurance number, not an unlinkability number.

Two consequences, and they run in opposite directions:

- **SC-C1/C2/C3/C4 and PD-D7 get cheaper.** Nothing that changes object sizes,
  chunk packing or the window length reduces any anonymity set, because there
  was no anonymity set of that kind. What they change is bytes and the crowd
  number a client can *measure*.
- **Anything that breaks the fixed full scan gets much more expensive.** No
  candidate here does — SCAN-C11 collapses six requests into one but still
  fetches everything — but it is the property to guard, and it is the reason
  SCAN-C9's recipient hint is a kill rather than a shrug.

### 1.2 Carrier objects have no forward secrecy, and retention cost is the only thing limiting the damage

The carrier envelope key is `HKDF(RoomRoot, … || nonce)`
(`derivations.ts:1322-1338`); `RoomRoot` is derived from the capability and
never rotates. Stores retain finalized windows for `carrierRetentionWindows`
= 160,000 ≈ 7.4 days, and design §9 measures the cost at **59.7 GB per store
per day** and observes that nothing sweeps it.

Therefore: **a capability obtained at any point within the retention horizon
retroactively opens every object of that room, at both stores, for the whole
horizon.** The prototype's own headline privacy properties are all
*store-facing*; none of them survives a later capability compromise, and the
design doc does not say so anywhere.

This is the axis on which four candidates should be judged and currently are
not:

- **PS-C3** (ICE parameters in PRESENCE) moves every member's IP address from
  "sealed under an ephemeral hybrid KEM" to "sealed under a non-rotating room
  secret". That is the difference between a leak and an archive. It is why I
  kill it (§6.34) rather than gate it.
- **PD-D5 / PS-C2** (standing presence) turns a point event into an interval,
  and the interval is retroactively readable for 7.4 days at 4-second
  resolution. That is what item 20 has to say.
- **SC-C1/C2/C3, SCAN-C3/C4** all cut the bytes an adversary must archive by
  4× or 2×. That is a genuine, if second-order, *cost* of those candidates:
  today's 59.7 GB/store/day is a practical deterrent to total retention, and
  they remove three quarters of it. It does not change the verdict — the
  bandwidth win for real users is worth more — but it belongs in the same
  sentence.
- **SCAN-C9** (the pre-AEAD recipient hint) is a k-bit sieve that turns
  post-compromise archive mining from "trial-decrypt 40 objects per window" to
  "filter, then decrypt". At 2.9 ms of saving that trade is absurd.

### 1.3 "No new store leak" is true for almost every candidate, and it is the wrong place to have been looking

Every angle report checks the store. Every angle report is right: with two
exceptions (SS-C2's extra POST, SC-C4's request count) **not one candidate in
the whole set changes the thirteen fixed requests, their routes, their sizes,
or their offsets**, and real-versus-cover indistinguishability is preserved by
construction — `#coverObject` (`carrierRuntime.ts:964-1000`) deliberately runs
the identical HKDF and AEAD over a throwaway root precisely so that a store
reading its own clock cannot see real appends land systematically later than
cover.

So the store-facing question is close to settled, and the interesting
adversaries are the other three:

1. **A capability holder** — every candidate that moves plaintext earlier in
   the chain (CF-C2, CF-C3, CF-C4, PS-C3) or repeats it (PD-D5) pays here.
2. **A future capability holder with an archive** — §1.2.
3. **An observer outside the carrier** — the STUN/TURN path (item 16), the
   CDN (SCAN-C6), the device (PD-D6).

That reordering is the single most useful output of this pass.

---

## 2. The second fixed-shape exception — found, and there are three

The brief asked for one. The witness pair (§3a item 14) is conditional on the
*other store's* behaviour. I found three more conditionals, **all present in
the code as shipped**, none disclosed:

### 2.1 The first window of a session is a different shape (session state)

`#nextEvent` (`carrierRuntime.ts:660-673`) skips any scheduled event whose
instant has already passed — deliberately, because "firing it late would move
this client's traffic off the profile's grid". So a client starting at phase
`p` into a window issues only the events after `p`.

`observed.md` §8 measured it: **`w0+0` = 9 requests with 0 append bodies;
every later window = 15 requests and 174,470 bytes of append bodies.**

A store therefore reads off its own log, with no cooperation from anyone: (a)
that this client's session began in this window, and (b) the start phase `p`
to within one offset gap — six resolvable bands over `[0, 2100]` at the pinned
profile. The descriptor GET, "once per store per session, not per window"
(design §5), states the same bit a second time.

This is not room state. It is session state, and it is the anchor a
cross-store observer uses to align two logs before anything else — which makes
it directly adjacent to §3a item 1, the leak the doc calls the worst one.

### 2.2 ICE gathering is event-shaped, and it is conditional on room state (the real answer)

The carrier schedule is fixed. **ICE gathering is not.** `createOffer()` plus
complete gathering runs only when a pair reaches the transport flight — after
ACCEPT opens (`pairDriver.ts`, `sendOffer`), measured at `accepted →
offer-sent` = 126–137 ms on loopback (`observed.md` §6). In the recorded runs
this is invisible only because `entry.ts:116` passes `iceServers: []`.

In any production deployment with STUN or TURN, a client emits STUN binding
requests **if and only if** it has found a peer in this room, passed both
identity gates, and reached the transport stage — and at a predictable offset
inside a specific delivery window. An on-path observer, or the STUN/TURN
operator, learns *that a rendezvous is in progress and at which stage*,
without reading one carrier byte.

§3a item 4 says "Polling shape must stay schedule-shaped, never event-shaped:
no burst after a hit". This **is** a burst after a hit. Item 4 is stated about
the store routes and does not cover the route where the property actually
fails. **This is the second exception, it is conditional on room state in the
strictest sense, and it is the one to name.**

It also has a fix that a latency candidate already wants: **PS-C7 /
CF-C1b pre-gathering removes it**, because gathering then happens at session
start, uncorrelated with any peer. That makes pre-gathering a privacy
improvement, which no report claims for it. Conversely the mitigation CF-C1
proposes for its own fingerprint-reuse problem — "discard and regenerate the
pre-gathered connection per pair attempt" — puts the leak straight back. See
§6.21 for the form that gets both.

### 2.3 The per-window request count is a room counter (room state)

`PrototypeCarrierRuntime` holds one `#roomRoot` (`carrierRuntime.ts:319`) and
runs one scheduler per store. So a client in **K** rooms issues **13K** fixed
requests per store per window, from one source address, at the same six
offsets. A store divides its own log by thirteen and reads `K`, and joins all
`K` rooms' traffic to one address.

The profile field that exists to prevent exactly this — `roomSlotsPerClient`,
which lets one allocation carry several room slots behind one fixed per-client
object count (`publicWindow.ts:293-296`, `appendSlotCoordinates`'s
`perAllocation`) — is pinned to **1** and unused.

This does not tell a store *which* rooms. It tells it how many, and that they
are the same person. §3a item 2 discloses the address; it does not disclose
the multiplier.

---

## 3. What no candidate is allowed to do (the invariants I checked each one against)

For the record, the exact tests I applied:

1. **Fixed count.** Thirteen requests per store per window, plus the
   conditional witness pair, idle or busy — **in every window after the
   client's first**, which is design §3a item 15 and is a shape of its own.
   Two candidates change the count
   (SS-C2: +1 in the first window; SC-C4: 13 → 10 uniformly); both are
   disclosable, neither is conditional.
2. **Fixed sizes.** Every append is one class's exact object length. Four
   candidates change the length (SC-C1/C2/C3, PD-D8); all change it uniformly
   for every client on the grid.
3. **Fixed offsets.** SS-C1, SS-C3, PD-D4 move offsets uniformly. None makes
   an offset depend on anything the client observed.
4. **Cover/real indistinguishability.** `#buildObject` → `#coverObject`
   (`carrierRuntime.ts:891-1000`) does identical work for both. Every
   candidate that puts a *second real object* in one window (CF-C1, CF-C2,
   PS-C1, PS-C5, PD-D5) fills a slot that was going to fire with cover
   anyway. **None of them is observable at a store.** The angle reports are
   right about this and I could not break it.
5. **No new conditional.** The witness pair is the disclosed one; §2 above
   adds three that already exist. Only SS-C2 adds a fourth (and only in the
   first window).
6. **No plaintext reaches a party that could not have it.** This is where the
   kills are: CF-C2, CF-C3, CF-C4, PS-C3, PS-C8, PS-C6.
7. **Nothing at rest gains a room-derived tag.** §3a item 12. PD-D6/PS-C1
   breaks this and must pay for it.

---

## 4. The exact sentences to add to §3a

Numbered continuing from the doc's fourteen. **Items 15, 16 and 17 are owed
whether or not any candidate ships** — they describe the code as merged.

> **15. The first window of a session is a different shape.** `#nextEvent`
> skips any scheduled event whose instant has already passed
> (`carrierRuntime.ts:660-673`), so a client that starts at phase `p` into a
> delivery window issues only the events after `p`: measured at **9 requests
> and no append bodies in the start window against 15 requests and 174,470
> bytes in every later one**. A store therefore reads off its own log, with no
> cooperation from anyone, both that this client's session began in this
> window and — from which of the six scheduled offsets are present — the start
> phase to within one offset gap. The descriptor GET, issued once per store
> per session rather than per window, states the same bit again. This is the
> alignment anchor a cross-store observer would use before anything else, so
> it sits directly against item 1. Removing it would mean deferring the first
> window entirely and starting on a grid boundary, at a cost of up to one
> delivery window of latency; the prototype does not do that.

> **16. ICE gathering is event-shaped, on a route the fixed schedule does not
> cover.** Item 4 requires the polling shape to stay schedule-shaped and never
> event-shaped, and it is stated about the store routes. `createOffer()` and
> complete ICE gathering run only when a pair has been found, both identity
> gates have passed, and the transport flight is being built
> (`pairDriver.ts`, `sendOffer`, measured at 126–137 ms after `accepted`).
> With any STUN or TURN server configured — the recorded runs use
> `iceServers: []` and therefore cannot see this — a client emits gathering
> traffic **if and only if a rendezvous in this room reached the transport
> stage**, at a predictable offset inside one delivery window. An on-path
> observer or the STUN/TURN operator learns that a rendezvous is in progress
> and at what stage without reading a carrier byte. Gathering once at session
> start, before any peer is known, removes the correlation; gathering again
> per pair attempt restores it.

> **17. The per-window request count is a room counter.** One carrier runtime
> holds one `RoomRoot` and runs one scheduler per store, so a client with `K`
> open rooms issues `13K` fixed requests per store per window from one source
> address at the same six offsets, and a store divides its own log by thirteen
> to read `K` and to join all `K` rooms' traffic to one address. Item 2
> discloses the address; it does not disclose the multiplier. The profile
> field that exists to fold several rooms behind one fixed per-client object
> count, `roomSlotsPerClient`, is pinned to 1 and unused.

Candidate-conditional. Add only the ones whose candidate ships.

> **18. Cold start allocates twice** *(only if the current-window allocation
> reclaim ships)*. A client that starts early enough in its window requests a
> lease for that window in addition to the scheduled request for `w+1`, so the
> first window of a session carries two allocation POSTs where every later
> window carries one; with item 15 the first window becomes fully
> self-identifying. The proposed byte-identical-replay variant does not remove
> the bit — a store distinguishes a request whose bytes it has already seen
> from a fresh one, so the count is levelled while the content still separates
> cold start from steady state. The only genuinely shape-preserving form is
> two *fresh* allocation requests every window, one for `w` and one for `w+1`,
> which halves the number of distinct clients a window's cohort can admit
> unless `cohortAllocationsPerWindow` is doubled, and doubling it doubles the
> scan.

> **19. Size class 1 carries no real object, and it is 86% of every client's
> traffic** *(state this whether or not the class is shrunk; it is a fact
> about the prototype as merged)*. The pair codec routes a step to class 1
> only above 3,613 bytes of SDP, and complete-gathering SDP measured in the
> supported browser is 692 bytes with no ICE servers and 1,002 with one STUN
> server, so class 1 is cover in every recorded run — confirmed by a run with
> the class-1 payload pinned to 4,097 bytes, one byte above class 0, which
> passed. Shrinking the class-1 carrier object changes the size table in §5
> and nothing else a store sees, and it shrinks no anonymity set, because a
> store binds every object to a lease it issued and to the address that
> requested it. It does cut by the same factor the cost of archiving a room's
> entire traffic; carrier objects are sealed under a non-rotating `RoomRoot`
> and are retained for `carrierRetentionWindows`, so a capability obtained
> later opens the whole archive, and cheaper archival is a real cost to set
> against the bandwidth win.

> **20. A standing presence is a retroactive liveness trace** *(only if
> presence republication ships)*. Republishing PRESENCE into the
> `state-replication` slot changes nothing a store sees — that slot fires with
> cover otherwise, and cover and real are the same bytes sealed with the same
> work at the same instant — but every republication carries the same
> `stableIdentityCommitment(roomContextId, stableKey)`, so any capability
> holder joins them into one endpoint's online interval at the delivery
> window's resolution. Because carrier objects are sealed under a
> non-rotating `RoomRoot` and stores retain them for `carrierRetentionWindows`
> (~7.4 days at the pinned window), a capability obtained after the fact turns
> that interval into an activity trace over the whole retention horizon at the
> republication interval's resolution, for every member who republished.
> Republication is therefore bounded by `presenceRepublishWindows`, stops the
> moment an edge is established, and its interval is a privacy parameter
> rather than a tuning constant.

> **21. Pre-admission transport disclosure (fast path only)** *(only if the
> speculative offer ships)*. With the speculative-offer fast path enabled, an
> initiator releases its SDP, ICE candidates and DTLS fingerprint one flight
> before the selected presence's author has proved a stable identity — the
> step is sealed under a domain-separated child of `HelloRoot`, so its
> recipient is exactly the author of the presence the initiator encapsulated
> to, and that author's identity arrives only in the ACCEPT. In any room with
> more than two capability holders, a holder that publishes presences and
> never answers harvests transport metadata — in any STUN or TURN deployment,
> the initiator's public IPv4 and global IPv6 addresses — from every initiator
> that selects it, leaving no signed artifact, where today the harvester must
> publish an ACCEPT signed by a stable key over the pair transcript. The fast
> path is therefore refused unless the room policy fixes membership at two and
> the capability is single-use, in addition to `eligibility === "open"`.

> **22. Retained peer presences are a co-membership record at rest** *(only if
> the warm start ships)*. Item 12 states that persisted state is keyed by
> per-store opaque ids and never by room-derived tags. A retained peer
> presence is a room-derived record: it carries the peer's
> `stableIdentityCommitment`, its hybrid receiver key and its presence
> operation id, and it is retained for `receiverKeyValidThrough` — 24 hours at
> the default policy. Anyone who obtains the device obtains the social edge
> that the wire protocol spends 86% of its bandwidth hiding from stores. The
> retained store is therefore encrypted under a key derived from the identity
> vault and wiped on identity reset; without that, the warm start is not
> shipped.

> **23. A pre-gathered connection is reused across pair attempts** *(only if
> pre-gathering is implemented as one session-long connection)*. Creating the
> `RTCPeerConnection` and gathering once at session start gives every pair
> attempt in that session the same DTLS certificate fingerprint and the same
> ICE ufrag and password. No store sees them — they never leave the pair
> envelope — but any peer that completes two attempts with this endpoint links
> them, and any on-path observer links the STUN binding requests of both
> attempts by their ufrag. Pre-gathering a small pool of independently
> generated connections at session start, one consumed per attempt, keeps
> item 16's fix and removes this one.

---

## 5. Room-policy gates

Two candidates must be refused under some policies, in code, with the refusal
unit-tested. The prototype runs one policy (open, `Admit()` is a no-op), so
these gates protect a future, not a present — which is exactly why they must
be enforced at a type level rather than by a runtime `if`, per
`angle-product-shape.md` §9.3, whose argument I endorse.

| Candidate | Admissible only when | Refused under |
|---|---|---|
| **CF-C2** speculative offer | `eligibility === "open"` **and** `maxRoomMembers === 2` **and** the capability is single-use | any room admitting more than two capability holders; `local-address-book-proved`; `authority-permit-proved`; any denylist-with-teeth or `onlyConnectWithKnownPeers` frontend |
| **SCAN-C6** CDN | the two stores' CDNs are different operators in different ASNs, stated in the §3a item 8 independence statement | one CDN fronting both stores — that is a kill, not a gate |

**I tightened CF-C2's gate.** `angle-collapse-flights.md` gates it on
`eligibility === "open"` alone. That is not enough. The speculative offer is
readable by the author of the presence the initiator selected; in an open room
with ten capability holders, nine of them can publish presences and wait to be
selected. Open eligibility says admission is a no-op; it does not say the room
has two members. The harvest disappears only when the only presence author who
can be selected *is* the peer, which is a two-member room with a single-use
capability — the same gate `angle-product-shape.md` demands for PS-C3, and for
the same reason.

PIN is not a gate here and must not be sold as one: the PACE/PIN step runs
inside protocol-v4 *after* the data channel exists (`mode: "nopin"` is passed
to `createSession`, `index.ts:699`), so it cannot gate SDP release, and an IP
address disclosed before the session exists is disclosed whether or not the
session is later MITM-proof.

---

## 6. The candidates, one at a time

Only where I have something to add to, or take away from, the angle report's
own privacy section.

### 6.1–6.3 SCAN-C1, SCAN-C2, SCAN-C3 — store internals · **SURVIVES**

Storage layout inside one process. No wire byte, no route, no request, no
offset, no geometry, no signature changes — the chunk was signed once at
finalization and is never re-signed (`storeCore.ts:982-988`). Maps to no §3a
item and widens none. The only observable change is that the store answers
faster, uniformly, for every client. **Do these first**; they are the only
candidates in the set that are unambiguously free, and until they land every
other measurement is measuring a hex decoder.

One thing to state rather than assume: a store that answers a chunk GET in
0.07 ms instead of 137 ms **narrows the timing spread between clients**, which
is a small improvement to the fixed-schedule property, not a regression.

### 6.4 SCAN-C4 — drop `slots` after finalization · **SURVIVES**, but not as a privacy win

`angle-scan-cost.md` flags a provenance question and calls it correctness. It
is correctness, and the answer is yes: the signed chunk proves custody and the
client's check reads the chunk (`storeClient.ts:1697`), not the slot.

**The correction:** do not report this as reducing what a seized store holds.
It deletes a duplicate of the object bytes; it does **not** touch the
`allocation` table, so the store still holds the binding from allocation
ordinal to lease to the connection that requested it. The thing that makes a
store's retained state sensitive — "this address wrote this exact object at
this exact position in this window" — survives SCAN-C4 intact.

### 6.5 SCAN-C5 — in-process response cache · **SURVIVES WITH A DISCLOSURE**

The report names the hit/miss timing difference and calls it "is anyone else
using this store". That is right and it is small: every client reads every
chunk of every window, so a probe reveals population, never room, membership
or interest.

Sharpen it once: a client probing cache timing across many windows can
estimate the store's **concurrent client population over time** — which is
precisely the number §3a item 8 says is a business fact and precisely the
number a store operator might prefer not to publish. It is a store-operator
concern, not a user-privacy one.

**Eager population at finalization removes it entirely** (every chunk is
always a hit), costs nothing, and is what the report itself suggests.
Implement it that way and the candidate SURVIVES clean; implement the lazy
version and disclose the oracle in one sentence.

### 6.6 SCAN-C6 — CDN · **NEEDS A GATE**, and one CDN is a **KILL**

The report gets this right and I want to make the kill unambiguous.

Design §3a item 8: "operator, ASN, hosting, jurisdiction and funding must be
stated and auditable. Two processes on one laptop are one fault domain."
A single CDN fronting both stores is not merely one fault domain — it is
**one observation domain**, and it hands one party:

- every client's source address for both stores (item 2, doubled into one
  log), and
- both stores' read schedules for the same client at the same instants, which
  is item 1's join **handed over pre-computed** rather than inferred.

That is the worst disclosed leak in the document, granted to a party that
today has to be two parties. And CDNs are shared infrastructure: two operators
who each independently "chose a CDN" have a high prior of choosing the same
one, which is the failure mode item 8 exists to catch.

So: gate on distinct operators in distinct ASNs, verified rather than
asserted, and add that verification to the §3a item 8 independence statement.
If it cannot be verified, do not deploy it.

### 6.7 SCAN-C7 — do not let the slow store gate the fast one · **SURVIVES WITH A CONSTRAINT**

The report asks the maintainer to confirm no new send can be triggered
off-schedule by early delivery. I checked, and the answer is: not by itself,
**provided two things**.

1. **The witness pair must still fire only after both scans settle.**
   `#witness(window, scans)` is called at `carrierRuntime.ts:1090` with the
   full `scans` array after the `Promise.all`, and fires per witnessed store
   only when `scans[index].status === "finalized"` and neither store is inert
   (`carrierRuntime.ts:1262-1268`). If a per-store delivery refactor also
   makes the witness fire per store as each scan lands, then the *timing* of
   the witness pair — not just its presence — starts tracking the other
   store's speed, which sharpens §3a item 14 from a presence oracle into a
   presence-and-latency oracle. Keep `#witness` on the joint path.
2. **`carriedBy` and `#queueBackfills` must be computed at last-settle-or-
   deadline, not eagerly.** Computed eagerly, an operation that store B
   actually held but delivered late is queued as a backfill to B. That is not
   observable — the backfill rides a fixed slot and displaces cover — but it
   is a *real* object where cover would have been, and §3a item 5 exists
   because the backfill path is the one place the runtime's behaviour towards
   store B depends on store A's behaviour. Do not widen it for a latency win
   that does not need it.

With both constraints the candidate changes only when the client *acts on*
what it already fetched, and every send still leaves on the profile's grid.

### 6.8 SCAN-C8 — memoize the chain verdict · **SURVIVES WITH A CONSTRAINT**

No privacy surface. One security constraint the report states loosely and I
want exact: the memoized verdict must be **discarded and a full
re-verification run** whenever `#observe` inserts an observation out of order
or retains both sides of an equivocation (`storeClient.ts:1626-1650`).
Otherwise a store that equivocates late escapes detection, and the property
§3a item 7 claims — "a client detects forged or altered entries, replays, and
set disagreement" — quietly stops holding. Measure the problem before building
it, as the report says; no recorded run exceeds ~10 observations against a
256-entry bound.

### 6.9 SCAN-C9 — pre-AEAD recipient hint · **KILL**

One sentence for the implementer: *a hint derived from `RoomRoot` gives anyone
who later obtains the capability an O(1) filter over seven days of archived
carrier objects at both stores, replacing the trial decryption that is the
only thing making archive mining expensive — for a saving of 2.9 ms against a
1,450 ms scan.*

To be precise about what it does **not** do, so nobody re-derives it as safe:
with a fresh nonce per object the hint is not a deterministic room-equality
handle *to a store that lacks `RoomRoot`*, so it does not literally violate
spec:480-482. The cost is entirely post-compromise, and §1.2 is why that
matters here more than it would in a system with forward secrecy.

### 6.10 SCAN-C10, SCAN-C11 — · **KILL**

C10: WebCrypto has no XChaCha20; substituting an AEAD is forbidden by
SEC-002/SEC-019 (`carrierEnvelope.ts:19-20`); the prize is part of 4.0 ms.

C11: one request per window buys 0.36 ms after SCAN-C1/C2 and changes §5's
fixed trace from thirteen requests to nine — and, less obviously, it deletes
the AC-049 property that a never-resolving checkpoint still produces every
chunk request, which is a *fixed-shape* property, not a liveness one. Bad
trade at any price.

### 6.11 SS-C3 / PD-D3 — `publicReadOffsetMs` → 0 · **SURVIVES WITH A CONSTRAINT**

Both reports call this privacy-neutral. It is, at `r = 200`. It is **not** at
`r = 0`, and the mechanism connects two things neither report connected.

At `r = 0` the read fires exactly at the window boundary. A client whose clock
runs even slightly fast reads a window the store has not finalized and gets
`not-final`. And `#witness` skips a store whose scan status is not
`finalized` — so a `not-final` read at store A **suppresses the witness pair
to store B**. Store B then observes the absence of the pair, which §3a item 14
already tells us is the signal. So `r = 0` converts a clock-skew event into a
store-visible distinguisher, on a route the doc has already identified as the
one non-fixed part of the trace.

**Constraint: keep `publicReadOffsetMs ≥ maxScheduleSkewMs` (200 ms) with the
finalize-to-read margin ≥ the same.** At `r = 200` the candidate is free and
the saving (0.4 s of a 24 s run, once) is unchanged in order of magnitude.
`angle-schedule-shape.md`'s own C3 already recommends 150–300 ms on liveness
grounds; this is the privacy reason for the same number.

### 6.12 SS-C1 — late slots, reversed roles · **SURVIVES**

The strongest candidate in the whole set from my seat: measured, no deviation,
byte-identical `scannedBytesPerWindow` and `appendedBytesPerWindow`, same
routes, same count, same sizes, offsets moved uniformly for every client on a
public profile.

Three things I checked and confirm:

- **`cf = 3,500` is load-bearing and the report is right to insist.** At
  `cf = 3,200` the §3a item-1 admissible phase band collapses from 599 ms to
  299 ms. The doc's own argument is that the band was useless (15% of a
  window, crossing no window boundary) — but the argument is *quoted with
  numbers*, and halving them without saying so is exactly the arithmetic drift
  a maintainer revisiting per-store phase offsets would be misled by.
- **It makes item 15 coarser and rarer, not worse.** With slots at 2,400–2,800
  instead of 1,300–2,100, 60% of clients emit the full five-append shape in
  their start window against 32.5% today, and the resolvable phase bands are
  wider at the front. It does not fix item 15; item 15 is owed regardless.
- **Clustering the five appends into a 400 ms band does not create a new
  fingerprint.** The profile hash is in every chunk GET's URL path
  (`GET …/chunk/{profileHashHex}/…`), so any on-path observer already
  identifies the application and the exact profile. A tighter burst identifies
  the same thing.

One constraint to carry, and the report states it well enough that I only
underline it: the two inequalities `cf − min(appendOffset) > store drain time`
and `min(appendOffset) − publicReadOffsetMs > S` are **absolute
milliseconds**; `withDeliveryWindowMs` scales the profile and cannot check
them. The measured `W=1000, cohort 2` failure is that rule biting.

### 6.13 SS-C2 / PD-D2 — cold-start current-window allocation · **SURVIVES WITH A DISCLOSURE**

New §3a item 18 (§4). The candidate is fine; the *mitigation* proposed for it
is not, and that is the finding.

`angle-schedule-shape.md` proposes a "shape-preserving variant": send two
allocation POSTs every window forever, the second a **byte-identical replay**
of the request that won the current window's lease, since `#allocate` returns
the same lease for an exact duplicate and consumes no second ordinal
(`storeCore.ts:670-674`). At cold start there is nothing to replay, so a fresh
request goes instead — "same route, same size, same offset, indistinguishable
on the wire".

**It is not indistinguishable.** A store that has already seen those exact
bytes, and that must recognise them to return the same lease rather than a new
ordinal, distinguishes a replay from a fresh request *by construction*. The
variant levels the count and leaves the content carrying the same bit: this
window's second allocation is fresh, therefore this is a cold start.

The only genuinely shape-preserving form is **two fresh allocation requests
every window, one targeting `w` and one targeting `w+1`**, of which the client
uses one. That costs two allocation ordinals per client per window, which
halves the number of distinct clients one window's cohort admits — or doubles
`cohortAllocationsPerWindow`, which doubles the scan. That is a real price and
it should be named rather than discovered later.

Given §1.1 (the cohort is not an anonymity set against a store) halving it
costs less than it sounds — it costs the *measurable shared cohort*, i.e. the
`minMeasuredSharedCohort = 2` assurance floor, which at cohort 8 → effective 4
still clears. So the honest form is affordable. But it should be a decision,
not a surprise.

`angle-presence-discovery.md`'s D2 also corrects the hit rate from 20% to 40%
(binding slot is presence's own at 2,100, not the earliest at 1,300). That is
right, and under SS-C1's re-slotting it rises again.

### 6.14 SC-C1 — class-1 carrier 73,728 → 8,448 · **SURVIVES WITH A DISCLOSURE** + a correctness gate

Privacy: new §3a item 19 (§4). No new store leak, no widened one, no anonymity
set shrunk (§1.1). The class-1 family becomes provably empty, so a store
learns strictly *less* from it than spec:9836 permits. The cost that belongs
in the same sentence is §1.2's: archiving a room's whole traffic gets 4×
cheaper for a future capability holder.

**The correctness gate, and the report gets the mechanism wrong in a way that
matters.** `angle-shrink-class-1.md` §3/C1 says an oversized SDP "throws in
`buildCarrierPlaintext` (`carrierEnvelope.ts:156`) and fails the edge". It
does not fail the edge. `#buildObject` (`carrierRuntime.ts:891-930`) catches
that throw *deliberately* — the docblock explains that an unguarded throw
would take the slot down for every store forever — **drops the outbox entry**,
emits a `missed` event, and sends cover instead. So the failure mode is:

> the client's traffic is completely unchanged, the operation silently
> vanishes, no edge failure is raised, no error reaches the user, and the
> rendezvous hangs until the harness deadline.

That is worse than a failed edge, it is invisible in a run that does not grep
the `missed` lines, and it is the exact failure a real-network SDP with ~21+
ICE candidates would produce. **SC-C1 must not ship without either SC-C5 (the
§4.12 carrier fallback) or, at minimum, a typed, surfaced failure and a
harness assertion on the published `operationPayloadClass`.** That assertion
is asked for independently by `floor.md` §11, `angle-shrink-class-1.md` §6.4
and `angle-product-shape.md` C7; it is one line and three reports want it.

### 6.15 SC-C2 — payload class 1 → 8,192 · **SURVIVES WITH A DISCLOSURE**

Same item 19. Strictly better than C1 on the privacy axis in one narrow sense:
the class-1 family is reachable again, so the design keeps a property
spec:9836 already discloses instead of emptying it, and the codec's own
validator can express what changed rather than the profile silently violating
`RoomProfileCompatible`.

The SDP ceiling drops from 32,768 to 7,709 bytes (~47 ICE candidates). That is
a **capability limit facing the peer**, not a disclosure: it changes who can
connect, not who learns what. Disclose it in §2 ("what this is not"), not in
§3a.

### 6.16 SC-C3 — class 1 → 36,864 · **SURVIVES WITH A DISCLOSURE**

Identical privacy profile to SC-C2, half the saving, preserves spec:10389's
SDP ceiling exactly. Nothing to add from my seat; it is a spec-conformance
preference, not a privacy question.

### 6.17 SC-C4 — `publicChunkObjectCount` 8 → 24 · **SURVIVES WITH A DISCLOSURE**

Design §5's table changes from **thirteen fixed requests to ten** (5 chunk GETs
→ 2). Both numbers are fixed and uniform; items 3 and 4 hold. Scan bytes rise
20.3%, which must be reported.

Two things I checked that the report did not:

- **Fewer chunks make a targeted split view *harder*, marginally.** With three
  class-0 chunks a store wanting to serve one client a divergent view can fork
  one chunk; with one chunk it must fork the whole class. Both are detected by
  the same checkpoint recomputation, so this is a footnote, not a benefit to
  claim.
- **The 8 unscheduled class-1 slots per chunk are store-generated CSPRNG
  padding**, which the store already produces for every absent position at
  finalization (`storeCore` `finalize`). They add store cost and reveal
  nothing.

Per §1.1 this is a request-count-for-bytes trade with no anonymity component
at all. Revert it once SCAN-C1/C2 land, as the report says.

### 6.18 SC-C5 — §4.12 operation-carrier fallback · **SURVIVES WITH A DISCLOSURE**

The report says "no privacy cost to a store" and "one peer-visible bit". Both
right. Two additions:

- The one bit — "this endpoint could not offer WebRTC" — is a **network-shape
  inference about the peer** (too many interfaces, or an unusual relay set).
  It is in the spec by design. One sentence in §2, not a §3a item.
- If the fallback ever runs a *real session* over the operation carrier, the
  client stays active for the whole session instead of stopping at handoff.
  Session start and stop are already visible; session *duration* multiplying
  by an order of magnitude is a different observable, and it also multiplies
  the number of §3a item-1 joinable write pairs for that client. The cheap
  version of C5 — emit a carrier-only offer and surface a typed "no WebRTC
  path" outcome instead of a dead edge — has none of that and is the one to
  build.

### 6.19 SC-C6 — class 1 → 4,097 · **KILL**

*It is not measurably faster than 8,448 at any window where both work, and it
deletes the large-body class outright, leaving no room at all above a 3,613-byte
SDP and making spec:9836 vacuous.*

### 6.20 CF-C5 — ingest fixpoint · **SURVIVES**

Purely local ordering inside one already-completed read. No operation is
created, no request is issued, `#eventsForWindow` is untouched. Maps to no
§3a item. It is also the **enabler** for CF-C1, CF-C2, PS-C1 and PS-C5 — every
one of those puts two causally ordered operations in one read batch, and
`coreReduce` sorts the active set by operation id, i.e. randomly with respect
to causality (`coreReduce.ts:1589`), while `ingest` makes one pass
(`pairDriver.ts:751`). Half the time the collapse delivers nothing. Ship it
first.

### 6.21 CF-C1b / PS-C7 — pre-gathered ICE · **SURVIVES WITH A DISCLOSURE** (pool) / **NEEDS A GATE** (single connection)

This is the candidate whose privacy sign both reports get backwards, in
opposite directions, and the resolution is a third option neither proposed.

- `angle-product-shape.md` C7 says "no privacy cost on the carrier" and notes
  in passing that moving the STUN disclosure to session start "decouples it
  from the rendezvous — a small improvement". **It is not small. It is the fix
  for §3a item 16** (§2.2), which is the second room-state-conditional
  exception in the whole system and is undisclosed today.
- `angle-collapse-flights.md` C1 identifies the real cost — one DTLS
  fingerprint and one ICE ufrag/pwd reused across every pair attempt in a
  session — and proposes, as the mitigation, discarding and regenerating the
  pre-gathered connection per attempt. **That mitigation reinstates item 16
  exactly**, because the regather is again triggered by rendezvous progress.

You cannot have per-attempt credential freshness *and* schedule-independent
gathering from one connection. You can from several: **pre-gather a small pool
of `k` independently generated `RTCPeerConnection`s at session start** — fresh
certificate, fresh ufrag and pwd each — and consume one per attempt. All
gathering happens before any peer is known, so item 16 is fixed; every attempt
carries fresh credentials, so item 23 never arises. The cost is `k` × gathering
at start-up and `k` certificates, both off the critical path by construction.

Also worth stating: the fingerprint reuse is **not only peer-visible**. The
ICE ufrag travels in STUN binding requests on the wire, so an on-path observer
or the TURN operator links a client's attempts within a session by it, without
any pair envelope. That widens the report's own framing from "any peer that
completes two attempts" to "anyone watching the network".

**Verdict: pool form SURVIVES WITH A DISCLOSURE (one sentence in §2 that
gathering happens at session start, deliberately, and why). Single-connection
form NEEDS item 23 and I would not take it.**

### 6.22 CF-C1 — responder sends the first transport offer · **SURVIVES WITH A DISCLOSURE**

I tried to break this and could not. The recipient set is identical: the OFFER
is sealed under `EstablishedPairRoot = f(HelloRoot, AcceptRoot, helloId,
acceptId)`, and deriving it requires the HELLO's response KEM secret, held only
by the endpoint whose identity bundle, commitment, cross-signature and
transcript signature the responder verified in step 4 before sealing anything.
The §1.6 sentence — "a client that is denied by the receiving frontend obtains
no SDP/ICE from that endpoint" — holds verbatim in both directions. No store
sees a different request. `windowShape()` is unchanged.

Two additions the report does not make:

- **It flips which party discloses its address first**, from the initiator to
  the responder. Since the initiator is "the lexicographically lower
  `PresenceOperationId`", that is a coin flip per attempt either way, so no
  party is systematically first. Worth one line so nobody discovers it later
  and thinks it is a finding.
- **What is actually lost is liveness confirmation, not confidentiality.** If
  the initiator vanished after HELLO, the responder's SDP sits in both stores
  sealed under a root nobody can derive, for the retention horizon. Under
  §1.2 that is the same exposure as any other pair step, so it adds nothing —
  but it does mean the responder now emits SDP on attempts that never
  complete, where today it emits none. In a room where a hostile capability
  holder repeatedly sends HELLOs and never reads, the responder's SDP is
  produced each time and, per §1.2, is recoverable by that holder only if it
  can derive `EstablishedPairRoot` — which it can, because *it* wrote the
  HELLO. So: **a capability holder that HELLOs and disappears harvests the
  responder's SDP one window earlier than today, and today it must send an
  ACCEPT-triggering... no — today it must simply send a HELLO and wait one
  more window for the OFFER, which it also gets.** Same harvest, one window
  earlier. Not a new leak.

**Disclosure:** the named spec deviation (REQ-012 line 927's "both gates",
spec:10184-10188, spec:10220). No §3a item.

### 6.23 CF-C2 — speculative offer under a HELLO-derived root · **NEEDS A GATE**

Gate in §5, item 21 in §4. The report's own §3a item-15 wording is good and I
have rewritten it only to tighten the gate from "open eligibility" to "open
eligibility **and** two members **and** a single-use capability", for the
reason in §5.

Three things to add:

- **The harvest is measurable and the report's proposed `--scenario=harvest`
  is the single most valuable test in any of the six reports.** A third page
  joins with the same capability, publishes a presence, never answers, and the
  harness prints the SDP byte count it obtained. Today that must be 0. With
  CF-C2 it will not be, and the printed number is the disclosure, measured
  rather than argued. Ship it in the same commit or do not ship CF-C2.
- **The domain separation is unproven.** `HelloRoot` is already the HPKE psk
  for the ACCEPT (`pairDriver.ts:1296`); deriving a `SealPairStep` base secret
  from it is a second construction over one secret. The report says "probably
  fine" and flags it. I agree it is probably fine and I agree that is not an
  argument. It is a real review item, not a footnote.
- **Under §1.2, the harvested SDP is archived.** A harvester that never
  answers still holds the capability, so it can decrypt the speculative offer
  at leisure from either store's retained window. The harvest is not
  ephemeral.

### 6.24 CF-C6 — symmetric transport parameters · **SURVIVES WITH A DISCLOSURE**

Each side's parameters are released only after its own gate, so the recipient
set is identical to today. No §3a item. Its one genuine privacy nuance is in
its favour and the report states it: the parameters record is smaller than an
SDP, which loosens the class-0 budget everywhere.

The disclosure is a *correctness* one and it should be in §2: hand-synthesised
SDP is browser-version sensitive, it is tested on one engine, and a synthesis
bug is a connection failure, not a leak. Same class of risk as PS-C3's SDP
munging without any of PS-C3's disclosure.

### 6.25 CF-C3 — SDP inside HELLO and ACCEPT · **KILL**

*It buys exactly what the speculative offer buys, at exactly the same privacy
price, and adds a silent data-dependent death at roughly five ICE candidates
— 1,136 bytes of headroom in a bootstrap plaintext that `pairStepEnvelope.ts`
fails closed on, with no class-1 bootstrap form to grow into.*

The failure would be worse than the report thinks, for the reason in §6.14:
`padPairPlaintextV1`'s throw is swallowed by `#buildObject`, the entry is
dropped, cover goes out, and the rendezvous hangs with no error.

### 6.26 CF-C4 — room-keyed identity beacon · **KILL**

*It broadcasts a stable identity to every capability holder rather than to the
one the initiator selected, which is a direct widening of §1.6's open-mode
concession, and it collapses the pair root from two hybrid KEM encapsulations
to one.*

### 6.27 PD-D4 — presence's append slot later · **SURVIVES**

Subsumed by SS-C1's re-slotting, which does the same thing with a measured
run behind it. `angle-presence-discovery.md`'s statement that the §3a item-1
band "stays ~600 ms wide" is right only at `cf = 3,500`; at `cf = 3,400` with
the last append at 3,100 the band is 299 ms, the same collapse SS-C1 found and
fixed. Take SS-C1's literals, not D4's.

### 6.28 PD-D5 / PS-C2 — standing presence · **SURVIVES WITH A DISCLOSURE**

New §3a item 20 (§4). Both reports independently found this and both are right
that it costs nothing at a store: the `state-replication` slot fires with cover
every window anyway, and `#coverObject` does identical work, so a real object
in that slot is invisible.

The disclosure both reports write is "co-members see a liveness interval". I
have made it sharper on two axes:

- **The linkage is unavoidable, not a design choice.** `PresenceCoreV1`
  carries `stableIdentityCommitment(roomContextId, stableKey)`, which is
  identical across republications by construction. `angle-product-shape.md`
  C2's fresh-author-epoch-per-presence is necessary — for the
  `maxOperationsPerAuthorWindow` quota and to avoid an author chain
  fingerprint — but it does **not** unlink the presences, because the
  commitment does the linking. Do not let anyone believe the epoch key buys
  unlinkability.
- **It is retroactive.** §1.2: no forward secrecy, 7.4-day retention. A
  capability compromise on day 7 yields a 7-day online/offline activity trace
  at the republication interval's resolution for every member who republished.
  One presence per session is a point; a heartbeat is a surveillance artifact.

**Two things are mandatory, not optional, if this ships:** (a) republish every
`k` windows with `k` chosen as a privacy parameter — one logical window (15
delivery windows, 60 s) is the natural coarsening and costs at most 60 s of
late-join latency, against 4 s at `k = 1`; (b) stop the instant an edge is
established, and cap the total.

And ship `angle-presence-discovery.md`'s metering assertion in the same commit
— a `healthy` run whose republication count exceeds 1 must fail — or the
heartbeat converts every lost-presence fault into a silent 4-second retry and
the system becomes less observable, which is its own kind of dishonesty.

### 6.29 PD-D7 — shorten the delivery window · **SURVIVES WITH A DISCLOSURE**

Both reports call this "a smaller mixing epoch" and ask for it to be
re-argued. Per §1.1 that framing is imprecise, and the precise version is
worse in one way and better in another:

- **Better than stated:** the per-window crowd does not shrink. Cohort 8, 40
  objects, the same fixed full scan, the same real/cover indistinguishability.
  The `minMeasuredSharedCohort` assurance floor is unaffected by `W`.
- **Worse than stated, and this is the real cost:** §3a item 1's join is
  per-window and already has 0 ms separation. Shortening `W` multiplies the
  number of joinable write-pairs per rendezvous. At `W = 4,000` a rendezvous
  spans ~11 windows; at `W = 1,000` with the same flight count it spans ~44.
  An observer of both logs gets four times as many independent confirmations
  of the same join, and four times as many grid points at which one client's
  jitter can separate it from the crowd. **The confidence of the worst
  disclosed leak scales as 1/W.**
- Also: sustained bandwidth scales as 1/W. 2,762,492 B per client per window
  is 5.5 Mbit/s at `W = 4,000` and 22 Mbit/s at `W = 1,000` at the pinned
  geometry — which is its own privacy fact, because a client that cannot
  afford to stay on the grid leaves it.

So the disclosure sentence is not "the mixing epoch shrinks"; it is *"the
per-window anonymity properties are unchanged, and the number of cross-store
joinable events per session, and the sustained bandwidth, both scale as 1/W."*

### 6.30 PD-D8 — shrink class 0's carrier object · **SURVIVES**, privacy-neutral

`angle-presence-discovery.md` calls this "a mild negative on §3a item 3 — less
padding is less padding". **That is wrong and the distinction matters.**

The operation is padded to `OPERATION_PAYLOAD_CLASS_BYTES[0] = 4,096` by the
codec; the carrier is then padded to `fixedCarrierObjectBytes = 8,192`. The
padding that hides payload length is the *first* one, and it is unchanged.
The 3,841 bytes between 4,351 (the measured floor,
`payloadClass + 231 + 8 + 16`) and 8,192 hide nothing: every class-0 object is
the same length either way, and there are still 24 of them per store per
window. It is dead weight, not privacy.

Verdict: privacy-neutral, worth ~6.7% of the scan, not worth a profile churn
on its own — but free if the profile is being edited anyway, and it should not
be argued against on privacy grounds.

### 6.31 PD-D6 / PS-C1 — warm start from a retained peer presence · **SURVIVES WITH A DISCLOSURE**

New §3a item 22 (§4). Nothing at a store; the peer's presence never leaves the
device. The cost is entirely at rest and it is a direct reversal of item 12.

Say the reversal plainly, because it is the sharpest sentence in this report:
**the design spends 86% of its bandwidth hiding the social edge from stores,
and this candidate writes the same edge to disk.** The retained presence
carries the peer's `stableIdentityCommitment`, its hybrid receiver key and its
presence operation id, for 24 hours (`receiverKeyValidThrough`), and
`pairControlRetentionWindows` is 7 days.

**Mandatory, not advisory:** the retained store is encrypted under a key
derived from the identity vault — which already exists in this codebase, the
argon2id identity backup shipped in 0.14.6 — and is wiped on identity reset.
`angle-product-shape.md` §9 says "if the retained store cannot be encrypted
under the identity vault key, C1 is worth less than it looks". I would put it
harder: without that, do not ship it. Four seconds is not worth a plaintext
contact list.

### 6.32 PS-C5 — symmetric transport flight · **SURVIVES WITH A DISCLOSURE**

Same class of loss as CF-C1 and the report states it correctly: the responder
still seals to `EstablishedPairRoot`, so no SDP reaches an unadmitted
identity; what is forfeited is the *liveness confirmation* that spec:10184-10187
gets for free from the ordering. No §3a item.

**Do not double-count.** PS-C5 and CF-C1 are alternatives — both take `F` from
5 to 4 by removing the same alternation — and stacking them saves one window,
not two. `angle-product-shape.md`'s table and `angle-collapse-flights.md`'s
table each price theirs against the same baseline; a reader adding them gets a
number that does not exist. What *is* additive with either is PS-C1/PD-D6 (the
warm start, which collapses the PRESENCE→HELLO alternation) and CF-C2 (which
subsumes CF-C1 and should not be priced alongside it).

### 6.33 PS-C6 — store as a fast SDP drop · **KILL**

*Deriving a store-visible location from `EstablishedPairRoot` hands the store
a deterministic peer-equality handle, which spec:480-482 forbids in as many
words, and the aggressive polling it needs is the event-shaped burst §3a item
4 exists to forbid.*

### 6.34 PS-C3 — ICE parameters ride in PRESENCE · **KILL**

The report gates it on `maxRoomMembers === 2` plus a single-use capability
enforced at the type level, and is sceptical of its own idea for five good
reasons. I go one step further and kill it, for a sixth reason the report does
not state:

*Under §1.2 the transport parameters would be sealed under a non-rotating
`RoomRoot` and retained by both stores for 7.4 days, so a capability obtained
at any point in that window retroactively yields every member's public IPv4,
global IPv6 and DTLS fingerprint for the entire period — where today the same
data is sealed under an ephemeral ML-KEM-768 + X25519 pair bootstrap and a
capability compromise reveals none of it.*

That is not "forfeiting forward secrecy of the SDP" as an abstraction. It is
converting a live-only disclosure into a seven-day archive of every member's
address, in a project whose headline promise — the one in the grant, the one
the whole protocol-v3 Double Ratchet work exists to deliver — is forward
secrecy. Breaking AC-005's final clause (spec:11697-11699) is bad for the
FOSDEM talk; building an IP archive is bad for the users.

**And the gate is the wrong shape.** `maxRoomMembers === 2` plus single-use is
enforceable at a type level today and unenforceable against the future: a
"join by link" feature, a re-shared invite, or a group room three quarters
later silently converts it into an address broadcast, with no memory of this
document. The report says exactly this in its §9.3 and then proposes shipping
it anyway behind the gate. I would not.

**The constructive routing:** the thing PS-C3 wants — transport parameters
early — survives as **CF-C2**, where they ride a step sealed under a child of
`HelloRoot`, i.e. under the hybrid KEM, recoverable only by the selected
presence's author rather than by every capability holder now and forever.
CF-C2 costs one window more than PS-C3 and is the version that keeps the
project's own promise. Take that.

### 6.35 PS-C8 — legacy signaling as a fast path · **KILL**

The report's five reasons are correct and I will not restate them. The one I
would put first, because it is the one that cannot be argued away:

*A client that is sometimes blind and sometimes not has no statement it can
make about any given session, and the user cannot tell which they got — which
is the exact opposite of the prototype's whole discipline, "claim no labels,
disclose everything".*

The second-order one is worth keeping too: if the fast path wins and the blind
attempt stops, **the stopping is itself event-shaped** and correlated with a
room forming on a server the same operator may run. §3a item 4, broken from a
direction nobody would think to test.

### 6.36 PS-C9 — long-lived push read · **KILL**

The report calls this second-order (0.6 s per flight after the store fix) and
flags session clustering. I kill it, because the clustering is not a vague
worry — it is §3a item 1 made stronger.

Today the cross-store join works on per-window request pairs at 0 ms
separation, and a client that sends nothing still emits the same thirteen
requests in every window after its first (§3a item 15). Under a long-lived push read, **each store holds one open connection
per client for the session's duration**, and an observer of both stores' logs
joins them by connection open and close timestamps, continuously and at
sub-millisecond precision, rather than at grid points. A client that stops its
runtime at handoff closes both at the same instant — a cleaner join than
anything available today. Cwtch's own handbook concedes the server "can track
new messages for each suspected unique profile" via session patterns; Cwtch
pays that price behind Tor, where the source address is already gone. Here the
source address is disclosed (item 2), so the price is paid twice.

*It buys 0.6 s per flight after the store fix and strengthens the leak the
design doc names as the worst one.*

---

## 7. What survives together, ordered by what it costs a human

Not a latency plan — the other reports have those — but the composition that
carries the least disclosure, in the order I would defend it:

1. **SCAN-C2, then SCAN-C1** (store internals). Zero privacy surface, the
   largest measured effect, and every other measurement is noise until they
   land.
2. **CF-C5** (ingest fixpoint). Zero surface, and it is load-bearing for
   everything in step 4.
3. **SS-C1** with `cf = 3,500`, and **SS-C3 at `r = 200`, not 0**. Profile
   integers, no deviation, no new disclosure, and SS-C1 makes item 15 coarser
   as a side effect.
4. **CF-C1 with the pre-gathered pool** (§6.21). One named spec deviation, no
   §3a item, and the pool *fixes* item 16 — the only candidate in the whole
   set that removes an existing leak.
5. **SC-C1 + SC-C5** together, never SC-C1 alone (§6.14). Item 19, plus the
   bandwidth win that no store fix can give.
6. **PD-D5/PS-C2 with `k` = one logical window and a hard cap.** Item 20. Ship
   it for robustness, not for speed — it buys zero seconds in every recorded
   run and fixes a permanent deadlock the harness cannot see.
7. **PD-D6/PS-C1 only if the retained store is encrypted under the identity
   vault.** Item 22.

Everything past that — CF-C2, PD-D7 — is a real trade with a real disclosure
and belongs in front of the maintainer as a question, not in a commit.

And three items are owed regardless of which of the above ships: **15, 16 and
17**. They describe the prototype as merged, and the outward doc's honesty
claim — "claim no labels, disclose everything" — is what makes them owed.

---

## 8. What I could not settle

- **Item 16's severity is unmeasured.** I have the mechanism from the code and
  the harness cannot see it, because `entry.ts:116` passes `iceServers: []`. A
  run with a real STUN server and a packet capture would turn it from an
  argument into a measurement, and would also settle whether ICE gathering
  blows the transport slot budget in production — which `floor.md` §6 row 8
  prices at a whole window per transport flight.
- **The `--scenario=harvest` number does not exist.** CF-C2's item 21 is an
  argument from the key schedule. Nobody should quote its severity until the
  harness prints the byte count.
- **Item 17's multiplier is read off the code, not run.** One client, two
  rooms, one store, count the requests. Ten minutes.
- **I did not verify that the retained-presence path in PD-D6 re-runs
  `validateAndIdentifyOperationCandidate`.** `angle-product-shape.md` §10
  raises it and it is a correctness question with a privacy tail: a seeded
  presence that skips validation is a way to inject a peer.
- **The store's `allocation` table retention is unpriced.** §6.4 establishes
  that a store holds "this address wrote this exact object at this position"
  for the retention horizon. Nobody has written down how long the allocation
  rows live or whether anything sweeps them, and it is the substrate under
  §3a items 2 and 11.
