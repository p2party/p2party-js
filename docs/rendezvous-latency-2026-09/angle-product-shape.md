# Blind rendezvous latency — the product-shape angle

Question the *problem*, not the mechanism. 2026-09-08, branch
`feat/blind-two-store-prototype` @ `127ca95`. Every constant is cited
`file:line`; every second is anchored to `floor.md` or `observed.md` in this
same directory. Paths are relative to
`~/Desktop/@p2party/p2party-js`.

---

## 0. The result in one page

**The 41.8 s is real but it is measured under an assumption a chat product
cannot make.** The harness starts both pages in the same delivery window
(`README.md:377` — both `presence-published` at 0.5 s). The prototype reads
exactly one window back, ever (`carrierRuntime.ts:711`, `#read(event.window -
1n)`), and enqueues `PRESENCE` exactly once (`pairDriver.ts:624-626` refuses a
second one). So two peers who do not overlap inside roughly one delivery window
**never meet at all**. The measured 41.8 s is not the product's latency; it is
the latency of the one case the product will almost never be in. Fixing that —
a standing presence in the state-replication slot that already fires with cover
every window — costs **zero wire bytes and zero shape change** and is the first
thing I would do.

**The structural law is one line, and only two of its four terms are yours:**

```
T = deliveryWindowMs × (1 + F) + publicReadOffsetMs − p        (floor.md §4)
```

`F` = dependent flights (5 today), the `1 +` is the cold-start allocation
window, `p` is the uniform start phase. `publicReadLagWindows` is pinned to
exactly 1 by the frozen spec (`profile.ts:255-257`, spec line 5816) and is not
negotiable. **So the only two levers a product decision can pull are `F` and
`deliveryWindowMs`.** Every candidate below is one of those two, and I price
each in flights, not in hand-waves.

**The spec's own answer to "what must two peers do again next time" is:
almost everything.** A reconnect is "a full new pair attempt over two fresh
presence operation IDs and therefore a fresh `PairEdgeId`; HELLO, transport,
v4, or PQ slots on the old pair edge are never reused" (spec:10229-10232), and
"a matching existing `StableEdgeId` may resume or replace its transport only
after the *new transcript* authenticates the same stable identities"
(spec:10225-10227). The spec knows this is a gap and has parked it: "In-place
refresh remains roadmap priority 18" (spec:11621). **There is exactly one
spec-blessed warm saving and it is worth exactly one flight**: the *peer's*
presence and its HPKE receiver key stay valid for
`operationRetentionWindows` = 1,440 logical windows × `logicalWindowMs`
60,000 = **24 hours** (`roomPolicyV4.ts:190-193`), so a returning client
never has to wait a window to observe a peer it already knows.

**The 5 flights are not 5 exchanges. They are 5 *alternations*.** Only two of
them (identity, transport) are genuinely bidirectional. A symmetric flight —
both sides publish in the same window, both read in the next — costs **one**
window for both directions. Every candidate that is worth more than 4 s works
by turning an alternation into a symmetry.

**Ranked answer** (details in §7, ranking in §8):

| # | Candidate | Δ flights | Δ floor @W=4,000 | Δ measured today | New store leak? |
|---|---|---:|---:|---:|---|
| C0 | *(prerequisite, not mine)* fix `storeSqlite.loadWindow` | 0 | 0 | **−20 s** | none |
| C2 | Standing presence in the cover slot | 0 | 0 | 0 (fixes ∞) | none |
| C1 | Warm start: reuse the peer's retained presence | −1 | **−4.0 s** | **−8.0 s** | none at the store |
| C5 | Symmetric transport flight | −1 | **−4.0 s** | **−8.0 s** | none |
| C7 | Pre-gathered ICE | 0 | 0 | 0 lab / **−8.0 s** prod | none |
| C3 | Open-policy direct transport (params in presence) | −4 | **−16.0 s** | **−32.0 s** | none at the store; **new capability-holder leak** |
| C9 | Long-lived push read (Cwtch-shaped) | 0 | −0.6 s/flight | −0.6 s/flight | session clustering |
| C6 | Store as a fast SDP drop | −4 | −16 s | −32 s | **rejected — kills the room-equality property** |
| C8 | Legacy signaling as a fast path | n/a | n/a | n/a | **rejected — see §5** |

C2 + C1 + C5 + C7 is the honest package: **no new store-visible leak, one
narrow spec deviation, F = 5 → 3**, and with C0 already applied that is
**14.6 s expected** at the pinned profile and **~3.7 s** at `W = 1,000,
cohort 2`. C3 is the only thing that reaches "blazing" (F = 1, **6.6 s** at
W = 4,000, **1.65 s** at W = 1,000) and it is the one I would argue hardest
against shipping without the room-policy gate in §7.6.

---

## 1. What I verified and what I refuted of the brief's priors

The brief asked me to verify or refute, not repeat.

- **"Five dependent flights, each gated by `publicReadLagWindows = 1`, plus a
  cold-start window."** — Confirmed, and `floor.md §4` already proves the
  arithmetic (24,600 − p ms) and `observed.md §2` already shows the
  `w0+2 / w0+4 / w0+6 / w0+8 / w0+10` ladder. I add one thing: **the flight
  count `F` is not a constant of the design, it is a consequence of the chain
  being strictly alternating.** Two of the five flights are avoidable without
  removing any exchange, only by making the exchange symmetric (C1, C5).
- **"Class 1 is 86% of the scan and that is what stops the window from
  shrinking."** — `observed.md §4b` refutes the *reason*: the browser does the
  whole 1.38 MB × 2 AEAD scan in **8 ms**. The 1,450 ms is
  `storeSqlite.loadWindow` `JSON.parse`ing a ~5.5 MB hex-JSON window document
  on every chunk GET (`storeSqlite.ts:277`, `storeCore.ts:1121`), measured at a
  flat 97 ms per request whatever the chunk holds (`observed.md §4d`). I take
  that as settled and treat it as a prerequisite (C0), not as a candidate of
  mine.
- **"The two big levers are (a) shrink class 1 and (b) collapse flights."** —
  (b) is right and is the bigger lever. (a) is right for the store's sake, not
  the browser's. **But the brief's framing misses a third lever that is bigger
  than both: the product does not need every rendezvous to be a cold pairing,
  and today it cannot do anything else.**

**What neither report noticed**, and what changes the problem: **the prototype
cannot rendezvous two peers who are not online in the same delivery window.**
`#read` only ever scans `w − 1` (`carrierRuntime.ts:711`); presence is
published once (`pairDriver.ts:624-626`); nothing re-enqueues it. `floor.md`
§6 row 7 prices non-simultaneous starts at "k × 4.0 s" — that is wrong, and
generously so. If A starts and B starts two windows later, B never sees A's
presence and A never sees B's; the run fails on the harness deadline. The
41.8 s is conditional on a simultaneity the harness manufactures.

---

## 2. Question the problem: what a chat product actually asks of rendezvous

### 2.1 Three distinct product events, one implementation

| Product event | Frequency | What is genuinely unknown | What today's code does |
|---|---|---|---|
| **First contact** ("add this person") | once per contact, ever | identity, keys, reachability | 5 flights, 41.8 s |
| **Reconnect** (app reopened, peer already a contact) | many times a day | reachability only | 5 flights, 41.8 s |
| **Reachability refresh** (network changed mid-session) | occasional | reachability only | not implemented at all |

Today all three are the same code path and the same 41.8 s. **A 41.8 s first
contact is a defensible ceremony** — it is a QR scan or a one-time invite,
both parties are present and looking at the screen, and every deployed
identifier-free messenger in the shelf also makes first contact a deliberate
act. **A 41.8 s reconnect is not a product**, and it is the case that happens
a hundred times more often.

So the honest reframing is not "make rendezvous fast". It is: **stop paying
first-contact cost on every reconnect, and stop paying reachability cost
inside the identity chain.**

### 2.2 Where the seconds actually are, restated for a product decision

Recomposed from `floor.md §5` and `observed.md §3`, with each row labelled by
who can decide to remove it:

| Term | ms | % of 41.8 s | Whose decision |
|---|---:|---:|---|
| four answering flights missing their own window's slot | 16,000 | 38.3% | **engineering** — `loadWindow` (C0) or the slot offsets (`floor.md §8a`) |
| five dependent flights × 1 window | 20,000 | 47.8% | **product/protocol** — this is `F`, and it is what §7 attacks |
| cold-start allocation window | 4,000 | 9.6% | protocol (`carrierRuntime.ts:704`, `:447`) |
| final read offset | 600 | 1.4% | profile |
| final ingest `S − p` | 1,100 | 2.6% | engineering (C0) |
| WebRTC + DTLS + v4 handshake + 149 KB of payload | ≤ 100 | ≤ 0.2% | **nobody — it is already free** |

`observed.md §2` prints the whole WebRTC + protocol-v4 tail as
`4 + 1 + 7 + 5 + 8 ms`. **The thing p2party is actually good at costs
0.2% of the run.** Everything else is the carrier's cadence.

### 2.3 The law, and what each candidate does to it

```
E[T] = W × (0.5 + F) + R        (floor, averaging the uniform start phase p)
E[T] = W × (0.5 + 2F) + R + S   (today, because every answer misses its slot)
```

Baseline check: `W=4000, F=5, R=600` → floor 22.6 s (matches `floor.md §4`),
today 42.6 s (measured 41.8 s, `README.md:394`). `R` scales with `W`
(`withDeliveryWindowMs`), so at `W=1000`, `R=150`.

| Package | F | E[floor] @4,000 | E[today] @4,000 | E[floor] @1,000/cohort 2 |
|---|---:|---:|---:|---:|
| baseline | 5 | 22.6 s | 42.6 s | 5.65 s |
| + C1 | 4 | 18.6 s | 34.6 s | 4.65 s |
| + C5 | 4 | 18.6 s | 34.6 s | 4.65 s |
| **C1 + C5** | **3** | **14.6 s** | **26.6 s** | **3.65 s** |
| **C3** | **1** | **6.6 s** | **10.6 s** | **1.65 s** |
| C3 + cold-start reclaim | 1 | 2.6 s\* | — | 0.65 s\* |

\* the cold-start reclaim fires only for start phases below the threshold in
`floor.md §8` (expected 0.8 s today, 2.0 s after the slot move), so treat it
as an expectation, not a floor.

Cross-check against the recorded cohort table
(`docs/blind-rendezvous-two-store-prototype.md:427-433`): the `4000 / cohort 4`
row measured **22.3 s** at "per flight 4.0 s = 1 window", i.e. the F=5 floor.
My F=3 row predicts 14.6 s at the same geometry, and the `1000 / cohort 2` row
already measured **10.5 s** at F=5 with two windows per flight — consistent
with my 3.65 s prediction for F=3 at one window per flight.

---

## 3. (a) The warm path: what the spec actually permits, quoted

**Question: once two peers have completed one rendezvous, what must they do
again?**

**Must do again — the spec is explicit and restrictive:**

- spec:10229-10232 — "Everywhere this specification says an edge *requires a
  fresh hybrid handshake*, it means a full new pair attempt over two fresh
  presence operation IDs and therefore a fresh `PairEdgeId`; HELLO, transport,
  v4, or PQ slots on the old pair edge are never reused."
- spec:10225-10227 — "Pair bootstrap state is provisional. A matching existing
  `StableEdgeId` may resume or replace its transport only after **the new
  transcript** authenticates the same stable identities and current room
  policy."
- spec:10440-10442 — transport failure recovery "creates fresh presences and a
  fresh `PairEdgeId`".
- spec:11803-11806 (AC-012) — "both endpoints retry successfully with fresh
  claims/`PairEdgeId`".
- spec:11621 — "In-place refresh remains roadmap priority 18." **The spec
  itself records that there is no warm path and has not designed one.**

**A hard structural reason, not just a rule.**
`PairEdgeId = H("p2party/pair-edge/v1" || RoomContextId ||
Sort2(PresenceOperationIdA, PresenceOperationIdB))` (spec:9273-9278,
`derivations.ts:641-664`), and for any `(PairEdgeId, direction,
pairSequence)` slot "the first accepted exact pair-operation ID is the only
value: the same ID is a replay; any other fully authenticated ID is a fork"
(spec:9894-9897). **So reusing *both* presences is not merely discouraged: the
second session's HELLO would land in slot `0/0` of the same `PairEdgeId` and
fail the edge as a fork.** Any warm path that reuses both presences is broken
before it is slow.

**May reuse — and this is the whole warm saving:**

- The *peer's* presence and its HPKE receiver key, for
  `receiverKeyValidThroughLogicalWindow` (`pairDriver.ts:650-660`), which the
  driver sets to `logicalWindow + operationRetentionWindows`. At
  `DEFAULT_BLIND_POLICY_V4_0` that is 1,440 × `logicalWindowMs` 60,000 ms =
  **24 hours** (`roomPolicyV4.ts:190-193`). `pairControlRetentionWindows` is
  10,080 = **7 days**.
- Because `PairEdgeId` is a hash of *both* presence ids, minting a fresh
  **own** presence while reusing the peer's retained one produces a fresh
  `PairEdgeId` and a clean slot table. **The asymmetric warm path is
  spec-clean.** That is C1.
- spec:5958-5962 also names a catch-up path — "A suspended or new client
  catches up old retained windows through the bounded public reconciliation
  path and reports `on-demand-public-scan` until caught up" — which the
  prototype does not implement. I price it in §7.9 and recommend against it:
  catching up one hour at 4 s windows is 900 windows × 2.76 MB = **2.5 GB**.
  The fixed-scan carrier cannot be a mailbox. C2 (standing presence) is the
  correct answer instead, and it is free.

**Is there a "pre-shared next-window slot"?** No, and the spec forbids
inventing one. Append coordinates are derived by the store from the lease
(`appendSlotCoordinates`, design §4.3), the allocation is "lowest free
ordinal", and a client-chosen slot would be exactly the "room-linked slot" the
architecture decision rejected as contradicting the targetless-bucket model
(design §3, column C). A client-derived slot is also a deterministic
peer-equality handle, which spec:480-482 forbids outright: "The store shall not
receive a deterministic room-equality or peer-equality handle with which to
join its observations."

**Answer to (a): the legitimate warm path exists, is spec-clean, and is worth
exactly one flight (4.0 s of floor, 8.0 s as measured today). Anything more is
a deviation.**

---

## 4. (c) The hybrid: which half carries the metadata that matters

Taking (c) before (b), because (b)'s verdict depends on it.

**Discovery carries the metadata that matters, by a wide margin.** The spec's
own one-server L2 claim (spec:494-505) lists what a store must not learn, and
the list is almost entirely discovery-side: "no room number/identifier,
room-equality tag, membership or co-membership edge, social-graph/pair edge,
recipient, mailbox, target index, stable peer identity, pair identifier".
Exactly one item on that list is connection-side: "raw SDP/ICE".

The asymmetry is decisive for three reasons:

1. **The edge is permanent, the SDP is ephemeral.** A co-membership edge, once
   learned, is true forever. An ICE candidate set is true for one NAT binding.
2. **The peer learns your IP anyway.** WebRTC's whole purpose is to give the
   peer your address. The marginal disclosure of SDP is bounded by *who else*
   sees it and *whether it links across sessions* — the DTLS fingerprint is
   the linkable part, and it is regenerated per `RTCPeerConnection`.
3. **Both stores already see every client IP on every request** (design §3a
   item 2). Handing SDP to a store you are *already* revealing your IP to adds
   the peer-pairing, not the address.

So the useful hybrid is **not** "blind discovery + a signaling server for
SDP". It is: **keep both halves on the blind carrier, but stop making the SDP
half wait behind an admission decision that this deployment has already
declared to be `yes`.** That is C3, and it is why C3 adds no new *store* leak —
the objects on the wire are byte-identical fixed-size cover-or-real; what
changes is who among the *capability holders* can decrypt them.

The inverse hybrid — blind connection, non-blind discovery — is strictly the
worst option available and I mention it only to close it off: it hands a third
party the exact list of items spec:494-505 is built to protect, in exchange for
saving the cheapest half of the chain.

---

## 5. (b) The legacy fast path, brutally

**The proposal:** connect over the existing signaling server immediately, run
the blind path in the background, switch over when it completes (or never).

**What the existing signaling path gives the server**, read off the code:

- A **stable Ed25519 identity** and a stable `peerId` UUID, asserted per socket
  (`signalingServerApi.ts:198-328`, `assertCanonicalEd25519Identity`), reused
  across sessions from `localStorage` (`:223-229`).
- A **`roomUrl`** — a deterministic room-equality tag, joined by every member
  (`requestRoom.ts:47-59`, `signalingServerApi.ts:686-707`).
- Therefore the **complete membership and co-membership set** of the room.
- **Raw SDP and raw ICE candidates**: `{ type: "description"; description:
  RTCSessionDescription }` and `{ type: "candidate"; candidate:
  RTCIceCandidateInit }` (`utils/interfaces.ts:79-109`) — relayed in the clear
  to the server.
- Source IP, timing, sizes, and join/leave events.

**That is every single item on spec:494-505, plus the one connection-side item.
The legacy path is the exact complement of the blind path's guarantee.**

**Verdict: reject.** Five reasons, in descending force:

1. **It is not a fallback, it is a bypass.** Design §6 already records the
   deliberate decision — "WebRTC never connects → the run fails the E2E
   deadline; **no fallback to legacy signaling exists or is added**". Adding
   one now is not an optimisation, it is a reversal of the architecture
   decision in design §3.
2. **The spec names this exact behaviour and forbids it under SP1.** REQ-027,
   spec:1098-1100 — "A direct, unregistered, stale, saturated, or
   response-dependent route is unavailable rather than fallback"; and the
   failure table, spec:11607 — "Do not send the public-store request; report
   source privacy unavailable/unknown. **Never fall back to a direct route.**"
   *Honesty requires the caveat*: that row is scoped to an SP1 interval, and
   the prototype does not claim SP1 (outward doc §9). So this is not literally
   binding today. It is the spec telling you what it thinks of the idea.
3. **It makes the blind path's traffic event-shaped, which is the one thing
   design §3a item 4 forbids.** Item 4: "Polling shape must stay
   schedule-shaped, never event-shaped: no burst after a hit, no coordinated
   dial phase between stores." If the fast path wins and the client stops the
   blind attempt, the blind traffic *stops* — and its stopping is correlated
   with a room forming on a server the same operator may also run. If the
   client instead keeps running the blind schedule forever, the fast path saves
   nothing operationally and costs the full 59.7 GB/store/day (outward doc §9)
   for traffic nobody reads.
4. **It creates a cross-observer join key that neither observer has today.**
   The prototype's worst disclosed leak, §3a item 1, is that an observer of
   *both stores*' logs can join a client's two writes with no identifiers. The
   fast path adds a third log — the signaling server's — that *does* carry
   identifiers, and it is timestamped against the same room formation. This is
   precisely the attack that
   `docs/rendezvous-prior-art-delta-2026-09.md` cluster C records against Tor's
   introduction protocol (Constantinides, arXiv 2602.23560): "the
   request-to-answer timing window is the join key and one vantage point
   suffices". Here the vantage point is a server that already knows the room.
5. **It cannot be flagged honestly.** The prototype's whole discipline is
   "claim no labels, disclose everything" (design §2). A client that is
   sometimes blind and sometimes not has no statement it can make about any
   given session, and the user cannot tell which they got.

**The only version of (b) I would not reject** is the strict inverse and it is
not a fast path: **use the legacy path for first contact only, in a deployment
that has already accepted the legacy server, and use the blind path for
everything after.** That is a migration story, not an optimisation, it saves
nothing on reconnect (which is where the seconds are), and it still hands the
server the edge. I mention it for completeness and do not propose it.

---

## 6. (d) What the deployed identifier-free messengers do, and their real
latencies

From `docs/rendezvous-prior-art-delta-2026-09.md`. I quote only numbers the
shelf records as VERIFIED, and say so where it records none.

**Cluster I — deployed identifier-free multi-server messengers
(delta:926-1011).** The shelf's own table (delta:1000-1008) is the honest
comparison, and **not one of its five rows carries a published rendezvous
latency**. What it does carry is the architecture, and the architecture is the
explanation:

| System | Read model | Why it is fast | What its server learns |
|---|---|---|---|
| Nostr NIP-17 (delta:928-948) | recipient publishes a kind:10050 list of **1-3 inbox relays**; sender writes one copy to each; relay serves kind:1059 under NIP-42 AUTH | **push over a subscription** — event-shaped by construction | recipient's long-term pubkey (a stable membership anchor), sender IP, arrival time, size, which pubkey polls |
| Signal sealed sender (delta:949-959) | server push | event-shaped | recipient identity, sender IP, time, size, delivery-token check; Signal's own post says timing/IP correlation "are areas of ongoing development" |
| Cwtch server (delta:960-980) | **"the server sends everything, and the peers sift through it"**; a joining peer "downloads all messages from the server, and from then on downloads only new messages" | **a long-lived streamed full scan** over a Tor onion service — no polling schedule at all | no IP (Tor), no identities — but the handbook concedes it "can track new messages for each suspected unique profile" via session patterns |
| Session swarm (delta:981-998) | replicated dead-drop **addressed by a public key**, polled behind onion requests | client-driven polling of *its own* mailbox | recipient Session ID; and EuroS&P 2026 (ePrint 2026/773) shows the swarm's non-collusion assumption is capturable via Oxen consensus |
| HyperDHT / Keet | k-closest DHT announce/lookup on a topic hash | DHT lookup | announcer pubkey, topic hash, the announce+lookup edge |

**The one published sub-second number in the entire shelf for
identifier-free discovery is Arke** (Mohnblatt, Sonnino, Gurkan, Jovanovic,
ACM CCS 2024, delta:180-192): "over 1,500 requests/s at **under 0.5 s**
geo-distributed", with "unlinkability, enumeration resistance, no single point
of trust or failure, per-request cost independent of user count". The shelf
also records what that costs: **"it too uses ≥ 4 servers."** Pudding (IEEE S&P
2024, delta:170-179) is the same story from the other direction: "tolerating
one faulty server while keeping a server-blind guarantee via BFT costs four
servers, so a two-store prototype may claim crash/omission tolerance with
detection, never BFT."

The other numbers the shelf verifies are all *slower* than the prototype:

- Scalable Private Signaling (ePrint 2023/572, delta:126-133): "under 60 ms per
  sent message and **under 6 s** retrieval at 1M recipients / 10M messages" —
  and it needs a **TEE**. The shelf's own note: "p2party has no TEE, so this
  bounds the passive-server cost floor rather than offering a design."
- Private Signaling Secure Against Actively Corrupted Servers (ePrint
  2025/1056, delta:134-144): two non-colluding servers, either may be actively
  corrupt — "for a 2^19-message board the digest is 33.57 KB and retrieval
  takes about **2 minutes** on 16 LAN threads… 2 minutes at 2^19 is **far too
  slow for WebRTC rendezvous**." That is the closest published system to this
  prototype's threat model, and it is 3× slower than 41.8 s.
- UnifOMR (ACM CCS 2026, delta:83-91): 2^19 messages of 612 B in **about 25 s**
  with 4 MB communication, and it proves OMR with strong detection-key
  unlinkability is **at least as hard as PIR**.

**The conclusion I draw, and it is the most useful thing in this section:**
every deployed system in cluster I buys its speed by being **event-shaped** —
a subscription push (Nostr, Signal), a streamed full scan on a live connection
(Cwtch), or on-demand polling of an identity-addressed mailbox (Session). Every
*research* system that is both fast and server-blind buys it with **more
servers** (Arke ≥ 4, Pudding ≥ 3f+1) or a **TEE**. p2party's prototype is the
only design in the set that is fixed-schedule, two-server, TEE-free and
browser-native — and the fixed schedule is *precisely* what §3a item 4 exists
to protect and precisely what costs the seconds. **You are not slow because you
did something wrong. You are slow because you chose the one property none of
them has.** That is the sentence for the FOSDEM talk, and it also tells you
where the remaining wins must come from: not from making the schedule
event-shaped, but from **needing fewer trips around it** — which is `F`.

One inference of mine, flagged as an inference and not a citation: Cwtch's
streamed-full-scan model (delta:970-974) is the only deployed read model that
is *both* low-latency *and* free of a per-recipient address, and it is the
closest thing in the shelf to what the prototype could adopt without becoming
event-shaped (C9, §7.7). Its cost is the one Cwtch itself admits: session-level
profile clustering.

---

## 7. The candidates

Each carries: mechanism, saving in seconds **and** flights anchored to the
measurement reports, privacy cost in the design doc's vocabulary mapped to
§3a, spec deviation with the line, implementation cost, and the measurement
that would prove it.

### C0 — *Prerequisite, and it is not mine:* stop `JSON.parse`ing the whole window per chunk GET

Credited to `observed.md §4c-§4e, §7 item 1`. `storeCore.ts:1121` calls
`this.#persistence.loadWindow(...)` per chunk GET; `storeSqlite.ts:277`
`JSON.parse`s a ~5.5 MB hex-JSON document to return one chunk, measured at a
flat **97 ms per request** and serialising the store's event loop. Serve chunks
from their own `BLOB` rows.

**Saving:** ~1,450 ms → tens of ms per scan, which restores one window per
flight instead of two: **−20 s, 41.8 → ~22 s**, at the same pinned profile.
**Flights:** 0. **Privacy:** no wire byte changes; no §3a item touched.
**Deviation:** none. **Cost:** `storeSqlite.ts` (360 LOC) + `storeCore.ts`
chunk path, ~150 LOC. **Measure:** re-run `storeprobe.sh` and assert per-chunk
TTFB < 10 ms; re-run `--scenario=healthy` and assert `per flight 4.0 s = 1
window`.

**Every number below assumes C0 is done.** Until it is, every candidate's
saving doubles (because every flight costs two windows) and every measurement
is measuring `JSON.parse`.

---

### C1 — Warm start: reuse the peer's retained presence; publish PRESENCE and HELLO in the same window

**Mechanism.** Persist three things per room across sessions, in the local
schema that already exists for exactly this (`retainedOperationStore.ts` —
"Exact local persistence boundary for retained blind-rendezvous operations…
preserves the exact canonical operation bytes needed by the existing operation
validator and CoreReduce after a restart"; it has no adapter yet):

1. the peer's exact `PRESENCE` operation bytes and its `OperationId`;
2. our own stable identity (already persisted by the SDK's identity vault);
3. nothing else — **not** our own old presence, and **not** the old receiver
   secret key.

On `start()`, if a retained peer presence is still within
`receiverKeyValidThroughLogicalWindow` (24 h,
`roomPolicyV4.ts:190-193`), seed it into `knownOperations` before the first
`coreReduce`, then: mint a **fresh** own presence as today, and — in the same
delivery window — enqueue `IDENTITY_HELLO` immediately if the fresh
`PairEdgeId` ordering makes us the initiator.

**Why it is one window and not two.** `PRESENCE` maps to `state-replication`
(spec:5997-5998, `workKinds.ts:47-49`) → class-0 slot at 2,100 ms;
`IDENTITY_HELLO` maps to `identity-bootstrap` (spec:5995-5996) → class-0 slot
at **1,300 ms**. **Different role slots in the same window**
(`profile.ts:107-111`). Both land in the same finalized chunk set and are read
together by the peer at `publicReadOffsetMs` into `w+1`
(`floor.md §2`, Gate 3). The peer then holds our fresh presence *and* our
HELLO in one scan and can validate ownership and ACCEPT.

**Why the fresh own presence is required, not optional.** Reusing both
presences reproduces the same `PairEdgeId` (spec:9273-9278) and the second
HELLO lands in slot `0/0`, which is a pair fork and fails the edge
(spec:9894-9897). A fresh own presence gives a fresh `PairEdgeId`. This is the
part that is easy to get wrong.

**Saving.** F: 5 → 4. **−1 delivery window.** At `W=4,000`: **−4.0 s** of
floor (E[floor] 22.6 → 18.6 s); **−8.0 s** as measured today before C0
(41.8 → 33.8 s). At `W=1,000`: −1.0 s.

**Privacy cost.** *At the store: none.* Same 13 fixed requests, same sizes,
same offsets; the peer's presence never leaves the device. **At rest on the
device: a new surface, and it widens §3a item 12.** Item 12 currently reads
"Local forensics. Persisted seen-sets and checkpoints are keyed by per-store
opaque ids, never by room-derived tags." A retained peer presence *is* a
room-derived record and it is a durable co-membership fact — exactly what the
wire protocol works to avoid. This must be written into §3a as an amendment to
item 12, and it argues for encrypting the retained store under a key derived
from the identity vault rather than storing it plainly.

**Spec deviation.** **None.** Presence validity is `receiverKeyValidThrough`
(spec:8827, `PresenceCoreV1`); the eligibility rule spec:9288-9290 requires
only that "both exact presences were valid in the local room at the HELLO
logical window", which holds; the slot table (spec:9884-9889) puts HELLO's pair
dependencies at "empty" and requires only a public header. Nothing in §4.3 says
a presence must be observed by the peer in an earlier window than the HELLO.

**Implementation cost.** `retainedOperationStore` IndexedDB adapter (~250 LOC,
new file); `pairDriver.ts` — a `resume({ retainedPeerPresence })` option and
the immediate-HELLO branch in `start()` (~120 LOC); `prototype/index.ts`
wiring (~40 LOC); `entry.ts` + `run.mjs` a `--scenario=warm-restart` (~120 LOC).
**~530 LOC across 5 files.**

**How I would measure it.** New harness scenario `warm-restart`: run `healthy`
to `message-verified`, close both pages preserving origin storage, reopen, and
assert (i) neither page emits `peer-observed` before `hello-sent`, (ii) the
first `store-missed`/append trace shows PRESENCE and HELLO in the **same**
ingress window, (iii) `presence-published → message-verified` is one delivery
window shorter than the cold run in the same process tree, and (iv) the privacy
audit still finds 0 of 148 needles. Assert (iii) as a window count, not a wall
clock, so it is not a variance measurement.

---

### C2 — Standing presence: republish PRESENCE in the cover slot that already fires

**Mechanism.** `pairDriver.start()` publishes presence once
(`pairDriver.ts:624-626` refuses a second) and `#read` only ever scans `w − 1`
(`carrierRuntime.ts:711`). Instead: re-enqueue a fresh `PRESENCE` every `k`
delivery windows while the room has no established edge. The
`state-replication` class-0 slot at 2,100 ms **fires every window regardless**
and carries a random-body dummy when the outbox is empty (design §4.5). Filling
it with a real presence changes **nothing** on the wire — a real object and
cover are the same bytes at the same instant (design §3a item 1's own words).

Mint a **fresh author epoch key per standing presence** (sequence 0,
`previousAuthorOperationId` null), separate from the pair chain's author. Two
reasons: `maxOperationsPerAuthorWindow` is 16 per author per 60 s logical
window (`roomPolicyV4.ts:197`), and 15 delivery windows fit in one logical
window, so a shared author would saturate; and a long author chain across
windows is a cross-window fingerprint. Rotating presences are what the spec
assumes anyway ("This rotating role only prevents duplicate provisional
attempts", spec:9283).

**Saving.** **Zero, in the lab.** Formally infinite in the field: without it,
two peers who do not overlap in one delivery window never rendezvous at all
(§2.1). With it, a peer that comes online at any moment is discoverable within
one window. It is also the precondition that makes C1's 24-hour retained
presence actually meet a live peer.

**Privacy cost.** *At the store: none* — same slot, same byte count, same
instant, and the store cannot distinguish real from cover. *At the room:* a
new disclosure to **capability holders**, who now see continuous presence
rather than a single beacon, i.e. an online/availability signal. The spec has
vocabulary for this and it is not §3a (which is about stores): it is the
"capability-holder coalition" case at spec:478-480. It should be disclosed as
such. Choosing `k > 1` (say every 4 windows ≈ 16 s) coarsens the online signal
at no latency cost worth mentioning.

**Spec deviation.** None. `OperationServiceRole(PRESENCE) =
state-replication` (spec:5997-5998) and "Unselected work remains in the bounded
outbox for the next same-role slot until expiry; no backlog creates an extra
append" (spec:6019-6020) — the schedule is designed for exactly this.

**Implementation cost.** `pairDriver.ts`: lift the once-only guard, extract
presence construction into `#mintPresence()`, re-enqueue on a window tick,
retire the previous presence locally (~90 LOC). `run.mjs`: a `--start-skew=N`
option and a `late-join` scenario (~100 LOC). **~190 LOC across 2 files.**

**How I would measure it.** `--scenario=late-join --start-skew=5`: start page A,
wait five delivery windows, start page B, and assert `message-verified` both
ways. **Today that run must fail**; assert that it fails before the change and
passes after, which is the only honest way to demonstrate a correctness fix.
Then assert page A's per-window request count and byte total are byte-identical
between the idle and standing-presence builds.

---

### C5 — Symmetric transport flight: both sides publish transport parameters in the same window

**Mechanism.** Today the transport exchange is an alternation: initiator's
`TRANSPORT_OFFER` in `w+3`, responder's `TRANSPORT_ANSWER` in `w+4`
(`floor.md §4`). But the responder derives `EstablishedPairRoot` the moment it
seals ACCEPT (`pairDriver.ts:1512-1533`), and the initiator derives it the
moment it opens ACCEPT — one window later. So: have **both** sides publish
their own complete SDP, sealed under `EstablishedPairRoot`, in the *same*
delivery window (`w+3`), each side reading the other's at `w+4`. Each side then
uses the spec's existing deterministic `SessionRole` (lexicographic order of
the confirmed stable Ed25519 keys, spec:10211-10213) to decide who treats their
own description as the offer and the peer's as the answer, and munges the
peer's `a=setup:` line accordingly.

**Saving.** F: 5 → 4. **−1 delivery window** = **−4.0 s** floor, **−8.0 s** as
measured today. Composes with C1: **C1 + C5 → F = 3, E[floor] 14.6 s.**

**Privacy cost.** **None at the store**, and none new at the room: the SDP is
still sealed under `EstablishedPairRoot`, which only a peer that completed
HELLO/ACCEPT holds. No §3a item is added or widened.

**Spec deviation — one, narrow, and I can name exactly what is lost.** The
bootstrap slot table (spec:9884-9889) fixes `TRANSPORT_OFFER` at direction
`0/1` with the exact HELLO as same-direction predecessor and the exact ACCEPT
as pair dependency, and `TRANSPORT_ANSWER` at `1/1` depending on the exact
OFFER. A symmetric flight makes the responder's transport step depend on ACCEPT
rather than on OFFER. What that forfeits is stated at **spec:10184-10187**:
"The first transport offer is initiator key confirmation… an authenticated
offer proves the initiator received and admitted ACCEPT. Thus no standalone
confirmation round-trip is needed and neither side sends SDP to an identity it
has not admitted."

Be precise about the loss: the responder still seals to
`EstablishedPairRoot`, which only the HELLO sender it already admitted can
derive — so **no SDP reaches an unadmitted identity**. What is lost is
*liveness confirmation*: the responder no longer learns, before publishing,
that the initiator actually received ACCEPT. If the initiator vanished, the
responder's SDP sits in the store encrypted under a root nobody else can
derive. **Confidentiality is unchanged; only the confirmation ordering is.**
That is a defensible deviation and it must be written down as one.

Second, smaller deviation: `docs/…-design.md §4.6 step 9` has the responder
`setRemoteDescription` before `createAnswer`. Under C5 both sides call
`createOffer` and one side must synthesise the peer's answer. That is SDP
munging and it is the implementation risk (see C3's risk note, which applies in
milder form).

**Implementation cost.** `pairDriver.ts` — collapse `handleIncomingAccept` to
emit transport immediately and accept a peer transport step in either role
(~200 LOC); `webrtcProvider.ts` — a `createSymmetricDescription()` that emits a
local offer and consumes a peer offer as an answer with a rewritten `a=setup:`
(~120 LOC); `pairPlaintext.ts` slot constants (~40 LOC); tests
(`pairDriver.test.ts`) (~120 LOC). **~480 LOC across 4 files.**

**How I would measure it.** Assert on window indices, not wall clock: in the
event trace, `offer-sent` (A) and `answered` (B) must carry the **same**
`floor(atMs / deliveryWindowMs)`, and `handoff` must land one window earlier
than the baseline run in the same process tree. Add a `pairDriver.test.ts` case
proving both role assignments produce a connectable pair and that a
`SessionRole` tie is impossible (the spec already rejects byte-equal stable
keys, spec:10206-10209).

---

### C7 — Pre-gather ICE at start-up

**Mechanism.** `createOffer()` needs nothing from the peer
(`webrtcProvider.ts:219-232`, and the data channel is created in the
constructor precisely so an offer can be made at any time). Run
`createOffer` + complete gathering at `driver.start()`, not after ACCEPT
opens.

**Saving.** **Zero in the harness** — `entry.ts:116` passes `iceServers: []`,
so gathering is milliseconds. **Up to one whole window per transport flight in
production**: `DEFAULT_GATHERING_TIMEOUT_MS` is 15,000
(`webrtcProvider.ts:55`), and the transport flight's compute budget from the
read offset to its slot is **1,100 ms** (`floor.md §7.2`). With STUN/TURN,
complete gathering routinely exceeds that, so today's production behaviour is
one lost window per transport flight, i.e. **−8.0 s** in the field, invisible
in every recorded run. `floor.md §11` flags this; I price it and make it a
candidate.

**Privacy cost.** None on the carrier. One caveat worth stating: STUN/TURN
requests are a separate source-metadata disclosure, and the spec already
handles it — "Blind mode never obtains TURN credentials from a server
room/roster response… A dynamic request contains no capability, room context,
peer ID, presence, or SDP and its source/timing disclosure is separately
reported" (spec:10444-10450). Pre-gathering moves that disclosure to session
start, which *decouples* it from the rendezvous — a small improvement.

**Spec deviation.** None.

**Implementation cost.** `pairDriver.ts` (~50 LOC), `webrtcProvider.ts` relax
the "createOffer() may only be called once" guard's interaction with the
pre-gather (~30 LOC). **~80 LOC across 2 files.**

**How I would measure it.** A harness variant with real STUN
(`--ice-servers=stun:…`), asserting the transport flight's window index is
unchanged from the `iceServers: []` run. Also add the assertion `floor.md §11`
asks for: assert the transport flight's **payload class**, because an SDP over
**3,613 bytes** silently moves from the class-0 slot at 1,700 ms to the class-1
slot at 1,500 ms — *earlier*, so 200 ms *less* budget — and grows the carrier
object from 8,192 to 73,728 bytes (`floor.md §3`). Real STUN/TURN SDPs reach
that.

---

### C3 — Open-policy direct transport: transport parameters ride in PRESENCE

**This is the only candidate that reaches "blazing fast", and the one I am
most sceptical of. Read §9 before adopting it.**

**Mechanism.** Add an optional prototype-scoped field to the presence payload
carrying the endpoint's **ICE parameters and DTLS fingerprint** — `ice-ufrag`,
`ice-pwd`, the SHA-256 fingerprint, and the gathered host/srflx candidates —
not a whole SDP. Each side, on reading the peer's presence, synthesises the
peer's session description locally from those parameters plus the spec's
deterministic `SessionRole` ordering (spec:10211-10213) and connects. Identity
is then authenticated **on the wire** by the existing protocol-v4 handshake
over the data channel, which already binds `channelId`, `localFingerprint` and
`remoteFingerprint` into its transcript (design §4.6 step 10) — the same
handshake that already runs today, unchanged.

**Size check.** `PresenceCoreV1` encodes to 1 + 32 + 1,216 + 8 + 32 + 8 = 1,297
bytes (`schemas.ts:1877-1887`), plus a 64-byte signature and the optional
permit tag ≈ 1,362 B, inside an `operationPayloadClass` 0 budget of **4,096
bytes** (`schemas.ts:47-48`). **~2,700 bytes free.** ICE parameters are
~300-800 B. It fits comfortably, and it fits *without changing the carrier
object size, the chunk geometry, the scan, or the append volume* — the object
is padded to 8,192 bytes either way.

**Why this collapses four flights and not two.** Once both presences carry
transport parameters, the identity flights are not on the connection path at
all. The prototype's admission policy is, in its own words, "an explicit open
policy: any capability holder is admitted" (design §2). **HELLO and ACCEPT
therefore gate a decision that has already been made.** They still buy three
things and I price each honestly:

1. **SDP confidentiality against other capability holders.** Under C3 the
   transport parameters are readable by anyone who can open the room AEAD, i.e.
   any capability holder. In a 2-party room with a single-use capability the
   only such party is your peer, who is about to learn your address anyway.
   **In a room with more than two members, or with a shared/leaked capability,
   this is an IP-address broadcast and C3 must be forbidden.** Hence the gate
   below.
2. **Forward secrecy of the SDP against later capability compromise.** Today
   the pair bootstrap's ML-KEM-768 + X25519 (`PairBootstrapHeaderV1`,
   `hybridKemCiphertext` 1,120 bytes, spec:9535-9539) means recorded SDP stays
   sealed even if the capability leaks later. Under C3 the SDP is only as
   strong as `RoomRoot`. That is a real loss and it must be disclosed in those
   words.
3. **Fork detection at the identity slot** (design §4.6, "the prototype detects
   a fork at the identity slot, not at the transport slots"). Under C3 there is
   no identity slot to detect at. Mitigation: keep HELLO/ACCEPT running
   **concurrently, off the critical path**, purely to populate the pair ledger
   and the audit — they cost no latency because they use different role slots
   in windows the client is already paying for.

**Saving.** F: 5 → **1**. Cold rendezvous becomes: window `w`, both publish
presence-with-parameters; window `w+1` at `publicReadOffsetMs`, both read and
connect. **E[floor] = 4,000 × 1.5 + 600 = 6.6 s** at the pinned profile
(−16.0 s of floor, −32.0 s of today's measured 41.8 s). At `W=1,000, cohort 2`
— which the recorded cohort table already shows is reachable
(`…-prototype.md:433`, 10.5 s at F=5 with two windows per flight) —
**E[floor] = 1.65 s**. With the cold-start reclaim from `floor.md §8`,
expected ~0.65 s. **That is the number the maintainer asked for.**

**Privacy cost, stated in the design doc's vocabulary.**
- **At the store: none, and I want to be precise about why.** Same 13 fixed
  requests per window, same offsets, same 8,192/73,728-byte objects, same
  cover-or-real indistinguishability, same union, same witness pair. **No §3a
  item is added or widened.** The store's view is byte-identical.
- **At the room: a new leak that is not in §3a because §3a is about stores.**
  It belongs beside design §2's "what this is not": *every capability holder
  learns every member's ICE candidates, DTLS fingerprint and therefore IP
  addresses, without any admission step.* And: *recorded transport parameters
  are decryptable by anyone who later obtains the capability.*
- The design doc would need a **fifteenth** item, or better, a new subsection,
  because it is a different axis from the fourteen.

**Spec deviations — four, and they are not small.**
1. **spec:10182** — "No SDP, ICE, DTLS fingerprint, local radio address,
   asynchronous mailbox locator, or protocol-v4 handshake byte appears in the
   two identity flights." C3 puts ICE *before* the identity flights entirely.
2. **spec:11697-11699 (AC-005)** — "The attacker cannot decrypt SDP/ICE
   exchanged by any two allowed members from its complete server state, all
   carrier objects, **and its room-level plaintext view**." C3 breaks the last
   clause by construction. This is the sharpest one and it should be quoted in
   any disclosure.
3. **spec:11704-11706 (AC-006)** — "No SDP, ICE, DTLS fingerprint, final
   transport locator, or protocol-v4 handshake byte is released" before the
   identity transcript passes.
4. **spec:8821-8831** — `PresenceCoreV1` is a closed record; a new field is a
   codec deviation. Keep it prototype-scoped, exactly as
   `prototypeStoreCompatibilityHash` already is (design §2), so it can never be
   mistaken for the frozen family.

Also relevant, and it is what makes the gate below mandatory: the failure
table, **spec:11617-11618** — a capability holder that fails admission
"receives no SDP/ICE" in both strict and open modes.

**The gate, without which I would not build it.** C3 is admissible **only**
when the room policy says `maxRoomMembers === 2` **and** the capability is
single-use, and it must be refused in code otherwise, with the refusal
unit-tested. A room-policy-gated fast mode is defensible; a global one is not.

**Implementation cost.** `schemas.ts` new optional presence field + codec +
known-answer vectors (~180 LOC); `pairDriver.ts` mint/consume parameters, and
demote HELLO/ACCEPT to a concurrent non-blocking path (~300 LOC);
`webrtcProvider.ts` build a description from parameters and extract parameters
from a local description (~250 LOC); `profile.ts`/policy gate (~60 LOC);
tests (~250 LOC); `run.mjs` scenario + a new audit needle set (~150 LOC).
**~1,190 LOC across 6 files, plus the browser-compatibility risk in §9.**

**How I would measure it.** (i) Window-index assertion: `presence-published`
and `webrtc-connected` must be exactly two ingress windows apart. (ii) The
privacy audit must be *extended* and must then *fail* honestly: add the peer's
ICE ufrag/pwd and fingerprint to the needle list for the **store body log**
(where they must still be 0 of N found, proving the store sees nothing) and
record separately, in the disclosure, that a room-level decryptor does find
them. (iii) A negative test: a three-member room must refuse the mode. (iv)
Assert the per-window append bytes and full-scan bytes are **unchanged**
(172,542 and 1,380,336) so the wire shape is provably untouched.

---

### C6 — Store as a fast SDP drop *(considered and rejected)*

**Mechanism considered.** After ACCEPT, both peers hold `EstablishedPairRoot`.
Derive a location from it, write the SDP there, and poll it aggressively
off-grid — sub-second SDP exchange.

**Why I reject it.** It creates a **deterministic peer-equality handle at the
store**, which spec:480-482 forbids in as many words: "The store shall not
receive a deterministic room-equality or peer-equality handle with which to
join its observations." And aggressive polling is event-shaped, breaking §3a
item 4 outright ("no burst after a hit"). It would trade the single most
important property the prototype has for 8 seconds. Recorded so the maintainer
can see it was priced, not missed.

---

### C9 — Long-lived push read (the Cwtch shape)

**Mechanism.** Instead of the client polling checkpoint + 5 chunks at
`publicReadOffsetMs` into every window, hold one long-lived response per store
into which the store writes the finalized chunk set the instant it finalizes
(at `chunkFinalizationOffsetMs`, 1,200 ms *before* the next window even
begins — `floor.md §2`, Gate 3). Prior art: Cwtch, delta:970-974, "the server
sends everything, and the peers sift through it".

**Saving.** Removes `publicReadOffsetMs` (600 ms) and the scan wall time from
every flight. After C0 the scan is tens of ms, so this is worth roughly
**0.6 s per flight** = 3.0 s at F=5, 1.8 s at F=3. It does **not** reduce the
window count, so it is a second-order candidate.

**Privacy cost.** A long-lived connection per store is a **session-clustering**
signal, which Cwtch's own handbook concedes: the server "can track new messages
for each suspected unique profile" via session patterns (delta:975-977). That
is a new disclosure adjacent to §3a item 2 (source addresses) and item 4
(polling shape) — arguably it *improves* item 4 (there is no polling shape at
all) while worsening the session-linkage story. It needs measuring, not
arguing.

**Spec deviation.** Yes: §4.3's read is a scheduled `publicReadOffsetMs` event
(spec:5816 pins the lag, `profile.ts:100`), and a push read is a different
mechanism. Also needs chunked OHTTP-style streaming if it is ever to run behind
a relay — the shelf notes base RFC 9458 is "strictly one request, one response"
and `draft-ietf-ohai-chunked-ohttp-08` is what a long-poll needs (delta:642-654).

**Implementation cost.** `storeHttp.ts` streaming route + `storeCore` finalize
hook (~250 LOC); `storeClient.ts` reader (~200 LOC); `carrierRuntime.ts` read
path (~120 LOC). **~570 LOC across 3 files.** **Measure:** per-flight window
index unchanged, `read-start → onOperations` latency, and a new
session-clustering measurement (connection lifetimes per source, correlated
across the two stores) before any claim.

---

## 8. Ranking by saving per risk

Risk = (new store-visible leak) + (spec deviations) + (implementation
fragility). Saving is post-C0, at the pinned `W = 4,000`.

| Rank | Candidate | Saving | Risk | Why here |
|---:|---|---|---|---|
| 1 | **C0** (not mine) | −20 s | none | Nothing else is measurable until it is done. |
| 2 | **C2** standing presence | 0 s lab / makes the product possible | none at the store; a capability-holder online signal | ~190 LOC, no deviation, and without it there is no rendezvous outside a synchronised lab. Highest value per line of code in the whole list. |
| 3 | **C7** pre-gathered ICE | 0 s lab / −8 s prod | none | ~80 LOC, no deviation, and it removes a failure the recorded runs structurally cannot see. |
| 4 | **C1** warm start | −4.0 s | none at the store; widens §3a item 12 (local forensics) | Spec-clean, one window, and the only warm saving the spec actually grants. |
| 5 | **C5** symmetric transport | −4.0 s | none at the store; one narrow deviation (spec:9887 / spec:10184) whose loss is confirmation ordering, not confidentiality | Same saving as C1 for slightly more risk and slightly less code. |
| 6 | **C9** push read | −0.6 s/flight | session clustering; a real deviation | Second-order; do it only if C1+C5 are not enough. |
| 7 | **C3** open-policy direct transport | **−16.0 s** | none at the store; a **new capability-holder leak**, four spec deviations, browser fragility | Biggest saving by 4×, biggest risk by more than that. Gate it or drop it (§9). |
| — | **C6** fast SDP drop | −16 s | **destroys the room-equality property** | Rejected. |
| — | **C8** legacy fast path | n/a | **hands a third party everything spec:494-505 protects** | Rejected (§5). |

**What I would actually do, in order:** C0, then C2 + C7 (together ~270 LOC,
zero deviations, and they fix two real defects rather than shaving seconds),
then C1, then C5. That lands at **F = 3, E[floor] 14.6 s at the pinned
profile** and, once the cohort/window can move (C0 makes that possible —
`observed.md §7 item 5`), **~3.7 s at `W = 1,000, cohort 2`**. That is a 41.8 →
~4 s story with **no new store-visible leak and one narrow, nameable spec
deviation**, which is a much better thing to present at FOSDEM than a 1.6 s
number with an asterisk.

Then, and only as a separately flagged mode with the two-party gate, C3.

---

## 9. Being sceptical of my own best idea

C3 is my biggest number and I would drop it for any of these five:

1. **The SDP-munging path does not survive a second browser.** Synthesising a
   peer description from ICE parameters requires a well-formed `m=` line, mid,
   `a=setup:`, `a=sctp-port`, and matching bundle semantics. Chromium accepts
   munged remote descriptions; Safari is materially stricter, and the harness
   only ever runs headless Chromium (`README.md:357`). **If a two-browser test
   does not pass on the first afternoon, drop C3.** The prototype's whole point
   is that it works in a browser.
2. **ICE without a trickle channel is brittle on real networks.** Under C3 the
   only candidate exchange is the one carried in the presence. A NAT rebinding,
   a Wi-Fi-to-cellular switch, or a late TURN allocation has no channel to
   travel on, and the recovery is a fresh presence — one whole window, on a
   network that just changed. The recorded runs cannot see this because
   `entry.ts:116` passes `iceServers: []`. **Measure C3 with real STUN before
   believing any of its seconds.**
3. **The two-party gate is the whole safety argument, and gates rot.** C3 is
   only defensible when `maxRoomMembers === 2` with a single-use capability. If
   anyone ever relaxes that — a group room, a re-shared invite link, a
   "join by link" feature — C3 silently becomes an IP-address broadcast to
   everyone holding the link. That is a foot-gun with a long fuse, and it is
   the kind of thing that gets relaxed by a product decision three quarters
   later with no memory of this document. If the gate cannot be enforced at the
   *type* level (a distinct room type, not a runtime check), I would not ship
   it.
4. **It forfeits a property the spec has an acceptance criterion for.**
   AC-005's final clause (spec:11697-11699) is a *named, testable* guarantee
   that a capability-holding, store-operating, malicious-client attacker
   "cannot decrypt SDP/ICE exchanged by any two allowed members". Breaking a
   guarantee that has an AC number is different in kind from deviating from a
   constant. If the FOSDEM story is "we implemented the spec's blind
   rendezvous", handing back AC-005 to buy 5 seconds is a bad trade for the
   talk even if it is a good trade for the app.
5. **The arithmetic may not need it.** C1 + C5 + a movable window already gets
   to ~3.7 s. The difference between 3.7 s and 1.65 s is not the difference
   between unusable and usable; the difference between 41.8 s and 3.7 s is.
   **If C1 + C5 measure out, C3's marginal value is 2 seconds for four spec
   deviations, and I would drop it on that ground alone.**

I am also sceptical of one thing in my own C1: **the retained peer presence is
a durable, plaintext, room-derived co-membership record on the device.** The
prototype has been careful never to write a room-derived tag to disk (§3a item
12). C1 breaks that carefulness for 4 seconds. If the retained store cannot be
encrypted under the identity vault key, C1 is worth less than it looks.

---

## 10. What I did not verify, and what would settle it

- **I did not run anything.** Every second above is arithmetic over
  `floor.md` and `observed.md` plus the constants I cited. The two claims most
  in need of a run are C1's "PRESENCE and HELLO land in the same window" (it
  depends on the responder accepting a presence and a HELLO from the same
  scan, which no test exercises) and C3's browser behaviour.
- **I did not verify that `coreReduce` accepts a presence seeded from local
  storage without the operation having arrived through a carrier.** The
  retained-operation module says it "deliberately performs neither of those
  protocol validations" (`retainedOperationStore.ts:5-8`), so C1's seeding path
  must re-run `validateAndIdentifyOperationCandidate` on the retained bytes.
  If anything in that validator is bound to the ingress window the operation
  was *carried* in, rather than its logical window, C1 needs more work than
  530 LOC.
- **The shelf records no rendezvous latency for any of the five deployed
  identifier-free messengers** (delta:1000-1008). My claim that their speed
  comes from being event-shaped is an inference from their described read
  models, not a cited measurement, and I have marked it as such in §6. The one
  cited sub-second number is Arke's <0.5 s at ≥4 servers (delta:186-192).
- **I did not price what C2's standing presence costs the store in retention.**
  A real object and a dummy cost the same bytes, so the 59.7 GB/store/day
  figure (outward doc §9) is unchanged — but the *number of clients* who now
  have a reason to stay connected all day is not, and that is an operator
  question the retention section should absorb.
- **The `maxOperationsPerAuthorWindow` interaction in C2 is reasoned, not
  measured.** 16 operations per author per 60,000 ms logical window
  (`roomPolicyV4.ts:197`) against 15 delivery windows per logical window is why
  I specified a fresh author epoch per standing presence; a run should confirm
  no author-quota rejection appears.
</content>
</invoke>
