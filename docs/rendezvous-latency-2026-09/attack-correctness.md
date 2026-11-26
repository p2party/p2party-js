# The correctness attack on the thirty-five latency candidates

Written 2026-09-08 as the adversary pass over `floor.md`, `observed.md` and the
six angle reports. Every claim below was checked by reading the source at
`/Users/deliberative/Desktop/@p2party/p2party-js` (branch in the tree:
`fix/peer-desync-2026-09`; the blind-rendezvous sources are identical to the
ones the reports cite). Citations are `file:line`. I ran no E2E — my job is to
say what breaks, name the invariant, and name the test.

**One-line posture.** Four candidates are outright KILLs for reasons no report
found; three more are safe only under a constraint no report states; and the
two most-recommended packages (schedule-shape C1 and shrink-class-1 C1+C4) have
never been stacked, and their two failure modes push in opposite directions on
the same knob.

---

## 0. The seven systemic facts every candidate must be judged against

These are properties of the code, not of any candidate. Five of them are not in
any of the six reports and they change several verdicts.

### F1 — A carrier seal that fails silently drops the operation. There is no failEdge.

`carrierRuntime.ts:900-923` (`#buildObject`): if `#sealObject` throws, the entry
is passed to `#dropEntry` and the slot carries cover. The only trace is a
`missed` event with `an outbox entry could not be sealed into size class N and
was dropped` (`carrierRuntime.ts:920`). **The pair driver is never told.** It has
already run `setPhase("offer-sent")` and recorded `offerOperationId`, so the
edge is neither failed nor retried: the rendezvous hangs to the harness
deadline.

The comment at `carrierRuntime.ts:884-892` explains why this design is right for
the *schedule* (a throw would silence that (role, class) slot forever) and is
therefore not going to change. It means: **any candidate that can produce an
operation too large for its size class produces a silent hang, not an error.**

### F2 — The outer operation is padded to the exact class length, so the carrier must hold the whole class.

`operation.ts:418-423`: `fixedPayload.length + operationPadding.length !==
OPERATION_PAYLOAD_CLASS_BYTES[class]` fails validation. A class-1 operation is
therefore *always* 69,632 payload bytes plus ~231 bytes of outer framing, no
matter how small the real body is. `buildCarrierPlaintext`
(`carrierEnvelope.ts:146-162`) refuses anything larger than
`fixedCarrierObjectBytes - 24`. There is no "small class-1 operation".

### F3 — `maxConsecutiveMissedAppendOpportunities` is validated and never enforced.

`profile.ts:101` sets it to 3, `profile.ts:258-265` validates it, and it appears
**nowhere else in `src/`** (grep: only the schema field, the type, the literal
and the validator). Every candidate that reasons "the client will notice it is
missing its slots" is reasoning about a guard that does not exist. A client that
misses its append slot forever emits `missed` events and nothing else.

### F4 — `#seen` means an identical republish delivers nothing to a peer that already has it.

`carrierRuntime.ts:1067-1071`: `fresh` is the union minus `#seen`, and
`#onOperations` is called **only when `fresh.length > 0`**. So re-publishing the
identical operation bytes is invisible to any peer that already saw them — it
does not re-trigger `ingest`, and therefore does not retry a deferred pair
operation. Angle-presence-discovery D5's self-healing claim ("a responder that
holds an unopenable HELLO retries it on the very next ingest — the republished
presence *is* that fresh operation") is **false** for exactly the peer that
matters. D5 still fixes the late-joiner case; it does not fix the
deferred-handler case.

### F5 — `observePeer` binds one peer presence, once, and a wrong `pairEdgeId` is fatal.

`pairDriver.ts:1046-1077`: it takes the **first** non-local presence in
`state.observedPresences` and `break`s; `ingest` calls it only
`if (this.remotePresence === null)` (`pairDriver.ts:743`). `pairEdgeId` is then
frozen for the life of the driver (`pairDriver.ts:1065-1070`). A HELLO whose
`expectedPairEdgeId` disagrees is rejected inside
`openIdentityHelloOpenPolicyPrototype` and, if it rejects by throwing, is a
`failEdge` (`pairDriver.ts:1194-1197`).

**Consequence: any candidate that puts more than one live presence per author in
the room is a race whose loser is a permanently failed edge.** `coreReduce`
sorts the active set by operation id (`coreReduce.ts:1589`), which is a hash, so
which of a peer's presences each side picks is a coin flip.

### F6 — `withDeliveryWindowMs` scales `maxScheduleSkewMs` down with the window.

`profile.ts:425-459`: every offset **and `maxScheduleSkewMs`** is scaled by
`newW/oldW` with integer division. At `W=1000` the conformance skew band is
**50 ms**; at `W=500` it is 25 ms. The store's `#windowIsClosed`
(`storeCore.ts:1209-1218`) is a pure clock comparison against
`chunkFinalizationOffsetMs`. Browser timer coalescing alone exceeds 50 ms.
**Every candidate that shrinks the window silently shrinks the drift the
protocol calls conforming**, and the failure is `append window-finalized`, which
is exactly the failure both `E6-w2000.txt` and `E8-w1000-c2.txt` recorded.
Integer division can also collapse two adjacent offsets onto one value, which
then fails `appendSchedule must be sorted by strictly increasing offsetMs`
(`profile.ts:290-293`) — that one at least fails loudly, at rescale time.

### F7 — Backfill rides `state-replication`, and `carriedBy` decides who gets one.

`workKinds.ts:39-40` maps `REPLICATION_OR_BACKFILL` to `state-replication`;
`carrierRuntime.ts:1209-1246` enqueues a backfill for every store not in
`carriedBy` for that operation. So the class-0 `state-replication` slot is
shared by PRESENCE, any heartbeat, and every backfill of every kind, and
`#pendingEntry` (`carrierRuntime.ts:1325-1338`) is strict FIFO over the whole
outbox. **One slot per window, one queue, three claimants.**

---

## 1. The cross-cutting checklist

A candidate is not admissible until each row is answered. I use these headings
in every verdict below.

| # | Invariant | Where it is enforced | Failure signature |
|---|---|---|---|
| I1 | Exactly two size classes, payload classes {0,1} | `profile.ts:196-203` | `ProfileGeometryError` at construction |
| I2 | `publicChunksPerWindow` is the **minimum** integer ≥ `ceil(cohort × slots × len(appendSchedule) / publicChunkObjectCount)` | `profile.ts:313-331` | `ProfileGeometryError`; also breaks `#openObjects`' flat class walk (`carrierRuntime.ts:1113-1128`) |
| I3 | `alloc + allocBudget + skew < min(appendOffset)` | `profile.ts:336-345` | `ProfileGeometryError` |
| I4 | every `appendOffset + skew < chunkFinalizationOffsetMs` | `profile.ts:348-353` | `ProfileGeometryError`; at runtime `append window-finalized` |
| I5 | `cf + skew < W + publicReadOffsetMs`, `0 < cf < W`, `0 ≤ r < W`, `lag == 1` | `profile.ts:239-257` | `ProfileGeometryError` |
| I6 | The §3a item-1 phase band is exactly 100/499/599 | `carrierRuntime.test.ts:1439-1470` (computed from the validator, not a literal) | test failure |
| I7 | Carrier fits the class: `fixedCarrierObjectBytes ≥ OPERATION_PAYLOAD_CLASS_BYTES[c] + 255` | **NOT ENFORCED ANYWHERE** — F1/F2 | silent hang |
| I8 | Pair minimal-class rule, checked again by the receiver | `pairPlaintext.ts:617-640` | `pair plaintext does not use its smallest permitted payload class` |
| I9 | No class-1 bootstrap form | `pairStepEnvelope.ts:112-115` | `a bootstrap header is permitted only in payload class 0` |
| I10 | Pair slot uniqueness on `(edge, direction, pairSequence)` | ledger preview/record, `pairDriver.ts:1207-1216`, `:1312-1320` | `pair edge fork/conflict at the HELLO slot` → `failEdge` |
| I11 | Store window close is clock-based, not finalizer-based | `storeCore.ts:1209-1218` | `window-finalized` on append |
| I12 | Checkpoint chain: adjacent-pair `previousCheckpointHash`, ordered observations, gaps blame-free | `publicWindow.ts:940-1040`, `storeClient.ts:1593-1622` | `chain-fault` breach → store inert |
| I13 | Fixed shape per window: 1 token + 1 allocation + `Σ len(appendSchedule)` appends + 1 checkpoint + `Σ publicChunksPerWindow` chunks, plus the conditional witness pair | `carrierRuntime.test.ts:668-676` `FIXED_WINDOW_SHAPE` (parameterised) | `windowShape` test |
| I14 | Witness pair fires **only** on a `finalized` scan | `carrierRuntime.ts:1263-1268` | request count drops 13→11, which is itself a signal |
| I15 | Fault taxonomy per scenario | `run.mjs:820-880` | `kill-a` must show ONLY `unreachable` against a and NOTHING against b; `withhold-a` ONLY `custody-breach` against a |

---

## 2. Verdicts

### 2.1 `angle-shrink-class-1`

---

**A-C1 — class-1 `fixedCarrierObjectBytes` 73,728 → 8,448, payload class left at 69,632.**

**KILL.**

*One sentence for the implementer:* a carrier that cannot hold its own payload
class turns every pair step larger than 3,613 bytes of SDP into a silently
dropped outbox entry and a hung rendezvous, with no `failEdge`, no fault, and no
counter that moves.

*The chain, exactly.* `padPairPlaintextV1` (`pairPlaintext.ts:661-691`) still
selects payload class 1 for any established plaintext over 4,017 bytes. F2: the
signed operation is then 69,632 + ~231 bytes. `publish` →
`#enqueue(bytes, 1, …)` → `sizeClassForPayloadClass(profile, 1)` returns the
8,448-byte class (`profile.ts:373-383` — it looks up by
`operationPayloadClass`, and never checks the size). The next
`safety-control` class-1 slot calls `#sealObject` → `buildCarrierPlaintext`
throws `operation does not fit this profile's carrier size class`
(`carrierEnvelope.ts:157`) → F1 drops it. The report's claim that this "throws
in `buildCarrierPlaintext` and fails the edge" is wrong in the second half, and
the second half is the whole risk: a clean `failEdge` would be a tolerable
prototype cliff; a silent hang is not.

*Invariant violated:* I7 (which nothing enforces) and, one level up,
`RoomProfileCompatible`. *Test that would fail:* none today — that is the
finding. The test that **must** be added before anyone ships any carrier shrink
is a unit test in `tests/blindRendezvous/prototype/carrierRuntime.test.ts` that
publishes a class-1 operation into a profile whose class-1 carrier is too small
and asserts the runtime raises a typed, driver-visible failure rather than a
`missed` event.

*What survives instead:* A-C2, which restores I7 by construction, plus A-C5.

---

**A-C2 — A-C1 plus `OPERATION_PAYLOAD_CLASS_BYTES = {0: 4096, 1: 8192}`.**

**SURVIVES WITH A DISCLOSURE — and only shipped together with A-C5.**

*Exact disclosure sentence:*

> The prototype narrows payload class 1 from 69,632 to 8,192 bytes and its
> carrier object from 73,728 to 8,448. This is a named codec deviation from the
> frozen class table: it lowers the §4.12 complete-SDP ceiling from 32,768
> bytes to 7,709 (offer) / 7,682 (answer) — about 47 ICE candidates against the
> 2-4 this prototype measures — evicts the `PQ_CONTROL` re-key path from the
> operation carrier entirely, and moves one cross-language conformance vector.
> A store sees the same thirteen fixed requests per window at the same offsets,
> 4.11× smaller.

*What actually breaks, beyond what the report says.* `MAX_OPERATION_PAYLOAD_BYTES`
is `OPERATION_PAYLOAD_CLASS_BYTES[1]` (`schemas.ts:50`) and is the `varBytes`
bound on `fixedPayload` and `operationPadding` in the canonical operation
schema (`schemas.ts:251-252`, `:290`). Lowering it changes the **decoder's
acceptance bound for every operation in every room**, not just in
`blindRendezvous/prototype/`. That is a fork of the shared codec family, and an
unmodified peer and a modified peer cannot interoperate at all. The report calls
this "medium risk"; it is more precisely "the prototype and the SDK no longer
share an operation codec", which must be said in those words.

`MAX_PAIR_PADDING_BYTES_V1 = 0xffff` (`schemas.ts:73`) survives as a bound
(largest real suffix becomes 8,113 − 4,018 = 4,095), so `pairPadding`'s schema
does not need to move — only its derivation comment.

*The reason A-C5 is mandatory, not optional.* `MAX_PAIR_WEBRTC_SDP_BYTES_V1`
stays 32,768 (`schemas.ts:78`), and `validateWebRtcSdp` still accepts an SDP of
20,000 bytes. That SDP now fits **no** payload class, so
`pairOperationPayloadClassForV1` fails
(`pairPlaintext.ts:597`) inside `padPairPlaintextV1`, inside
`sealEstablishedFlight` — which `sendOffer` does **not** wrap in a try
(`pairDriver.ts:1565-1584`, `:1865-1880`). The throw escapes `sendOffer` →
`handleIncomingAccept` → `handlePairOperation` → `ingest`, and is finally
swallowed by `#read`'s handler guard (`carrierRuntime.ts:1078-1086`), which
emits `the operations handler threw` and moves on. **The driver is left in phase
`accepted` with no offer, forever.** Same user-visible outcome as A-C1's silent
drop, different mechanism.

*Verdict conditions:* (a) ship A-C5; (b) add the I7 assertion to
`validateDeliveryProfileGeometry` with the prototype's deviation as an explicit
allow — three lines, and it converts a silent hang into a construction-time
error; (c) lower `MAX_PAIR_WEBRTC_SDP_BYTES_V1` to the class-1 ceiling so the
schema and the codec agree, or make `sendOffer` catch and `failEdge`.

*Tests:* `pairPlaintextVectors.test.ts:315-320` (one regenerated SHA-256
conformance vector), `pairOpenBudget.test.ts` (8 sites),
`projections.test.ts:248`, and
`tests/blindRendezvous/reference/pair_plaintext_vectors.py:283,344,363` must
move in lockstep. If the Python reference is not regenerated, the
cross-language check is silently testing a different codec.

---

**A-C3 — class 1 = 36,864 / carrier 37,120.**

**SURVIVES WITH A DISCLOSURE, but dominated.** Same disclosure shape as A-C2
minus the SDP-ceiling clause (the 32,768-byte ceiling survives: 36,864 − 79 =
36,785 ≥ 35,229). It therefore does **not** need A-C5 to be safe, which is its
one real virtue and the report understates it. But it does not reach the
one-window-per-flight floor (measured 27.6-30.9 s at W=4,000), and once the
store is fixed (D-C1/D-C2) its remaining value is bandwidth only. Take it only
if the maintainer wants the §4.12 ceiling preserved *and* refuses A-C5.

---

**A-C4 — `publicChunkObjectCount` 8 → 24, both `publicChunksPerWindow` → 1.**

**SURVIVES WITH A DISCLOSURE.** I checked I2: class 0 scheduled = 8×1×3 = 24,
`ceil(24/24) = 1` ✓; class 1 scheduled = 8×1×2 = 16, `ceil(16/24) = 1` ✓. It
also holds at `--cohort=4` and `--cohort=2`. `appendSlotCoordinates`
(`publicWindow.ts:281-330`) maps class 1 into object indices 0-15 of a
24-object chunk, and `#finalizeWindow` fills 16-23 with
`randomBytes(objectBytes)` (`storeCore.ts:959-967`).

*The disclosure the report is missing, and it is the important half:*

> Eight of the twenty-four class-1 objects in every window are generated by the
> store itself. They are indistinguishable from client cover to a third party,
> but they are **not cover against the store**, which is the adversary this
> design is built for. The +20.3 % scan is therefore bought entirely for
> request-count reduction and buys zero additional anonymity.

*Also:* design §5's "thirteen fixed requests" becomes ten, and
`finalizedChunkCount` in every checkpoint drops from 5 to 2
(`profileFinalizedChunkCount`, used at `storeCore.ts:1015`) — a value a store's
published descriptor and the client's `structurallyValidCheckpoint` both key on.
Old finalized windows under the old geometry become unverifiable against the new
one, so **the profile change is not backwards compatible with a store's existing
chain**; the `--cohort` rebuild already handles this in the harness by starting
fresh stores, and that is the only supported path.

*Test:* `carrierRuntime.test.ts`'s `FIXED_WINDOW_SHAPE` is parameterised
(`:668-676`) and will follow. `storeCore.test.ts`'s restart-replay tests must be
re-run against a store whose database was written under the old geometry, to
confirm it refuses rather than mis-serves.

---

**A-C5 — implement the §4.12 operation-carrier fallback so the SDP cliff fails soft.**

**SURVIVES — and it is a prerequisite for A-C2 and A-C3, not an optional
companion.**

*What the report under-specifies.* Two call sites, not one. `buildOfferCandidates`
(`transportCandidates.ts:135-146`) always emits `webrtc-complete`, and
`selectWebRtcCandidate` (`transportCandidates.ts:184-188`) **hard-fails** on a
carrier-only offer with `transport offer advertises no webrtc candidate` — and
that `fail` is inside `handleIncomingOffer`'s try, so the *responder* answers a
carrier-only offer with `failEdge("TRANSPORT_OFFER rejected: …")`
(`pairDriver.ts:1650-1653`). So the fallback must change the **selector** as
well as the builder, or the soft failure is converted back into a hard one by
the peer.

*Also:* `selectWebRtcCandidate` enforces `countOf("operation-carrier") === 1`,
so the carrier member is already mandatory on the wire; only the client-side
requirement that a WebRTC member exist has to move.

---

**A-C6 — class 1 = 4,097.** **KILL** — its own author already rejects it; I
confirm the reason: it makes `sizeClassForPayloadClass(1)` a class no
`PairStepBodyV1` can reach, which is I7 violated by construction and F1's silent
drop for any plaintext over 4,017 bytes.

---

### 2.2 `angle-collapse-flights`

---

**B-C5 — fixpoint the ingest batch.**

**SURVIVES.** Verified the premise end to end: `ingest` makes exactly one pass
(`pairDriver.ts:751-767`), `coreReduce` sorts the active set by
`compareBytes(operationId)` (`coreReduce.ts:1589`), operation ids are hashes,
and `handleIncomingOffer`/`handleIncomingAnswer` return `false` when the
established root is not yet derived (`pairDriver.ts:1590-1598`,
`:1699-1710`). Probability 1/2 is exactly right.

*Two constraints the patch must respect, neither of which the report states.*

1. `state.activePairOuterOperationIds` is a **snapshot** taken before the loop.
   Operations the loop itself publishes are not in it, and `coreReduce` is not
   re-run. That is correct and must stay correct — a loop that re-runs
   `coreReduce` inside itself would re-derive the room state mid-drive and could
   re-observe a peer (F5).
2. The loop must terminate on `isFailedEdge()` (already checked at
   `pairDriver.ts:752`) **and** must bound its passes. A handler that returns
   `false` forever with `progressed` set by a *different* handler is a live
   loop; bound it at `state.activePairOuterOperationIds.length` passes, which is
   the maximum useful depth of the dependency chain.

*Test to add:* `pairDriver.test.ts` — feed one `ingest` an ACCEPT and an OFFER
in both orders and assert both are in `handledPairOperationIds` after that
single call.

---

**B-C1 — the responder sends the first transport offer.**

**SURVIVES WITH A DISCLOSURE, and NEEDS one implementation constraint the report
does not name.**

*Slot table check.* Under C1 the responder occupies `(direction 1, sequence 0)`
= ACCEPT and `(1, 1)` = OFFER; the initiator occupies `(0, 0)` = HELLO and
`(0, 1)` = ANSWER. Every slot is used once, `MAX_PAIR_DEPENDENCIES_V1 = 1`
(`schemas.ts:64`) still holds with `pairDependencies = [helloId]` on the OFFER
and `[offerId]` on the ANSWER, and `previousPairOperationId` remains the
sender's own previous same-direction step. **I10 holds.** The seal binds
`{kind, direction, pairSequence}` (`pairDriver.ts:1608-1613`), so the swapped
kinds are a distinct key on both sides — symmetric, no ambiguity.

*Routing.* `handlePairOperation` (`pairDriver.ts:1160-1171`) dispatches on
`bootstrapHeader !== null` and `rendezvousRole` alone. The swap is two lines.
Note that the responder's own OFFER is filtered by `ownOperationIds`
(`pairDriver.ts:755-758`), so it does not self-route.

*The constraint nobody states — role-slot ordering is load-bearing under a
collapse.* The two co-published operations use two different append offsets, and
they are **not atomic**. Under the pinned profile identity-bootstrap (1,300)
precedes safety-control (1,700), so a late enqueue splits as "ACCEPT lands,
OFFER slips" — harmless, costs one window. Under angle-schedule-shape's C1 the
order is reversed (`safety-control 2,600` before `identity-bootstrap 2,800`), so
the same split delivers **an OFFER the peer cannot open** (no
`EstablishedPairRoot` yet), which `handleIncomingOffer` defers
(`pairDriver.ts:1590-1598`) and retries a window later. Recoverable, but it
means **B-C1 and schedule-shape C1 must not both be taken without putting
`identity-bootstrap` at the earlier of the two late slots.** That is a one-line
constraint and it is invisible unless you read both reports at once.

*Disclosure sentence:*

> The prototype deviates from the specification's transport ordering: the
> responder emits the first transport offer alongside its identity accept,
> rather than waiting for the initiator's offer to prove it admitted that
> accept (spec REQ-012 line 927, spec:10184-10188, spec:10220). No SDP reaches
> an unadmitted identity in either direction — both offers remain sealed under
> `EstablishedPairRoot` — and no store-visible request, offset, size or count
> changes. What is given up is emission ordering and the standalone key
> confirmation the specification derives from it.

*Pre-gathering, which B-C1 depends on, carries its own disclosure:*

> A pre-gathered `RTCPeerConnection` reuses one DTLS certificate fingerprint
> and one ICE ufrag/pwd across every pair attempt in a session, so a peer that
> completes two attempts with this endpoint can link them. No store sees any of
> it; today each attempt gets fresh credentials.

*Tests:* `carrierRuntime.test.ts`'s `windowShape` must stay byte-identical (it
will — `#eventsForWindow` is indifferent to outbox contents,
`carrierRuntime.ts:600-651`). `run.mjs --scenario=all` must stay 4/4, and
`kill-a`'s sharp assertion (`run.mjs:846-859`) must still show only
`unreachable` against store a.

---

**B-C2 — speculative offer under a `HelloRoot`-derived transport root.**

**NEEDS A GATE.** Refuse the fast path under every policy except an open one,
in code, unit-tested:

- refuse unless `roomPolicy.admissionFloor.mode === "capability"` **and** the
  session policy's eligibility is `open`;
- refuse under `local-address-book-proved` and `authority-permit-proved` —
  REQ-012's "shall not send its identity hello to an unproved presence" is a
  fortiori a bar on its SDP;
- refuse under denylist-with-teeth / `onlyConnectWithKnownPeers`;
- refuse when `roomPolicy.maxRoomMembers > 2`. The report does not include this
  one and it should: `DEFAULT_BLIND_POLICY_V4_0.maxRoomMembers` is **64**
  (`roomPolicyV4.ts:200`), so "the only capability holder is your peer" is not a
  property of the default policy, it is a property of the harness's two-page
  world.

*Plus the new §3a item the report drafts (item 15), which I endorse verbatim.*

*One correctness item the report misses.* Deriving a domain-separated child of
`HelloRoot` for `SealPairStep` while `HelloRoot` is simultaneously the HPKE psk
for the ACCEPT (`pairDriver.ts:1296`) is a two-construction reuse of one secret.
The report flags this as "needs a review". It is worse than that in one
specific way: the responder derives `HelloRoot` at HELLO-open time
(`pairDriver.ts:1212-1213`) and *then* uses it as the ACCEPT psk, and
`promoteEstablishedRoot` **wipes it** (`pairDriver.ts:1528-1533`:
`helloRoot.fill(0)`). A speculative-transport child must be derived and stored
before that wipe, or the responder cannot open the speculative offer after it
has accepted. That is an ordering bug waiting to happen, and it will present as
"the fast path works when the offer arrives first and hangs when it arrives
second".

---

**B-C3 — SDP inside HELLO and ACCEPT.**

**KILL.** Confirmed at source: `pairCiphertextAndTagTargetBytesV1` fails closed
on class 1 with a bootstrap header (`pairStepEnvelope.ts:112-115`,
"Suite 1 deliberately has no class-1 bootstrap form"), and
`pairOperationPayloadClassForV1` permits only `[0]` when a bootstrap header is
present (`pairPlaintext.ts:586-589`). *One sentence:* a merged HELLO+OFFER has
1,136 bytes of SDP headroom and no larger class to grow into, so it dies at
roughly five ICE candidates — one STUN server already produces four — via
`pair plaintext fits no permitted operation payload class`, which per §2.1's
A-C2 analysis escapes uncaught and hangs the driver.

---

**B-C4 — room-keyed identity beacon.**

**KILL.** *One sentence:* it needs a new member of the closed `PairStepKindV1`
registry, broadcasts a stable identity to every capability holder rather than to
the selected one, and collapses the pair root from two hybrid KEM
encapsulations to one — three separate deviations for one delivery window.

---

**B-C6 — symmetric transport parameters.**

**SURVIVES WITH A DISCLOSURE**, as the fallback if B-C1's pre-gathering
disclosure is refused. Two things to add to its cost: it needs a new member of
the `PairTransportCandidateV1` kind union, which means `selectWebRtcCandidate`'s
composition rules (`transportCandidates.ts:172-183`) and
`identifiedCandidates`' canonical-id sort all move; and the SDP text it
synthesises must survive `validateWebRtcSdp` on the *peer's* browser, which the
harness (headless Chromium only) cannot test. Do not ship it without a
second-browser run.

---

### 2.3 `angle-schedule-shape`

---

**C-C1 — late slots, reversed roles, `chunkFinalizationOffsetMs` 3,500.**

**SURVIVES.** I re-derived every inequality against the real validator:

- I3: `700 + 300 + 200 = 1,200 < 2,400` ✓ (`profile.ts:336-345`)
- I4: `2,800 + 200 = 3,000 < 3,500` ✓; class 1 `2,650 + 200 = 2,850 < 3,500` ✓
- I5: `0 < 3,500 < 4,000` ✓; `3,500 + 200 = 3,700 < 4,000 + 600 = 4,600` ✓
- roles: each class has ≥1 of each required role, offsets strictly increasing ✓
- I2: `appendSchedule.length` is unchanged, so `publicChunksPerWindow` 3/2 stays
  minimal ✓
- **I6 — I re-derived the phase band by hand and it survives exactly.**
  `shiftIngressSchedule` (`carrierRuntime.test.ts:704-718`) shifts the token,
  allocation and append offsets but **not** `cf` or `r`. Later bound:
  `2,800 + δ + 200 < 3,500` ⇒ δ ≤ 499. Earlier bound: token offset reaches 0 at
  δ = −100. So `PHASE_EARLIER = 100`, `PHASE_LATER = 499`, `PHASE_SPAN = 599` —
  byte-identical to the three literals `carrierRuntime.test.ts:1444-1446`
  asserts, and the trailing property
  `2,800 + 499 + 200 = 3,499 < 4,000` still holds. **`cf = 3,500` is not a
  taste call, it is the exact value that keeps this test green**, and the
  report's insistence on it is correct.

*The one thing to add to its disclosure.* The report says the first-window shape
leak gets "coarser and rarer". It does, but state the other tail too: a client
starting at `p ∈ (2,800, 4,000)` now emits **zero** appends, zero token and zero
allocation-token requests in its first window, versus `p ∈ (2,100, 4,000)`
today. The band in which a store sees a near-empty first window widens from
47.5 % to 30 %… of a *different* shape. Either way this leak is real, unlisted,
and belongs in §3a on its own merits (`observed.md` §8 first recorded it).

*The rule it must ship with, restated as a test rather than prose:* add a
harness assertion that `store-missed` contains **zero** `append
window-finalized` lines, and fail the run on it. That single assertion is what
converts C-C1 from "measured on one laptop" to "guarded".

---

**C-C2 — reclaim the cold-start window by allocating for the current window.**

**SURVIVES WITH A DISCLOSURE** in its simple form; the shape-preserving replay
variant **NEEDS A GATE** on an implementation detail the report does not state.

*What I verified.* `storeCore.#allocate` refuses only `target < current` or
`target > current + maxFutureIngressWindows` (`storeCore.ts:660-665`) and then
`#windowIsClosed` (`:667`). The allocation token is a 32-byte zero placeholder
in open mode (`storeClient.ts:604`, `:664`), so a same-window allocation needs
no matching token event. Cohort capacity is per window
(`storeCore.ts:675-676`), and a client still consumes exactly one ordinal per
window in steady state, so an 8-client cohort is unaffected.

*Exact disclosure sentence for the simple form:*

> A client that starts early enough in a delivery window issues one additional
> allocation request, for the window it is standing in. Its first window
> therefore carries two allocation POSTs where every later window carries one,
> which tells that store the session began in that window — one bit, once, per
> session per store. The current code already emits a weaker form of the same
> bit: a client starting after the allocation offset issues an off-grid
> allocation POST at an arbitrary instant. Both belong on the residual-leak
> list; neither is on it today.

*The trap in the shape-preserving replay variant.* The duplicate-detection path
is keyed on `requestHash = publicAllocationRequestHash(request)`
(`storeCore.ts:674-677`), and the request binds
`allocationEd25519PublicKey`. The runtime generates **one fresh key pair per
window per store** (`carrierRuntime.ts:735`) and `stop()` plus the
`MAX_HELD_LEASES = 8` eviction both zero the secret
(`carrierRuntime.ts:614-617`, `:760-765`). So a byte-identical replay requires
retaining the **encoded request bytes**, separately from the lease and its
secret, for one extra window. Retaining the key pair instead would be worse: it
would give a store a value that appears in two windows, which is precisely the
cross-window link the "one fresh key per window" comment
(`carrierRuntime.ts:733-735`) exists to prevent. **Retain the request bytes, not
the key.**

*Second correctness item.* The report's own caveat — `allocationResponseBudgetMs`
is 300 ms against a measured 1,394-1,629 ms allocation POST — is not a
tuning note, it is a correctness note: raising it to an honest ~1,600 ms forces
`min(appendOffset) > 700 + 1,600 + 200 = 2,500` by I3, which pushes C-C1's
earliest slot from 2,400 to 2,500 and re-narrows the phase band. Do the honest
budget **after** the store fix, when the number will be small again.

---

**C-C3 / E-D3 — `publicReadOffsetMs` → 0.**

**KILL at 0. SURVIVES WITH A DISCLOSURE at `r ≥ maxScheduleSkewMs`.**

*One sentence for the implementer:* at `r = 0` a client whose clock runs fast by
any amount reads a window the store has not finalized, and a `not-final` scan
does not merely lose the read — it suppresses the witness pair
(`carrierRuntime.ts:1263-1268` gates on `status !== "finalized"`), so the
client's per-window request count silently drops from thirteen to eleven and the
fixed-shape claim in design §5 becomes false for exactly the clients with fast
clocks.

That is the finding: the witness pair is the **only** conditional request in the
trace (design §3a item 14), and its condition is the scan status. Any candidate
that makes `not-final` reachable on the healthy path converts a disclosed
one-bit exception into a clock-skew-correlated fingerprint. `r = 200-300` keeps
the whole `maxScheduleSkewMs` band inside the finalized region and buys
300-400 ms of the 600, which is the whole prize anyway (`floor.md` corollary 2:
`r` is worth `r` once, not per flight).

---

**C-C4 — a second append slot per critical role.**

**SURVIVES WITH A DISCLOSURE** (the traffic increase, +4.8 % at length 4 or
+14.4 % at length 6). I2 recomputes correctly: length 4 ⇒
`ceil(8×1×4 / 8) = 4` chunks for class 0, and the literal must move with it or
the validator rejects (`profile.ts:325-331`). `appendSlotCoordinates`'
`perAllocation` follows from `appendScheduleLength`
(`publicWindow.ts:293-296`) on both client and store, so no coordinate drift.
`FIXED_WINDOW_SHAPE` is parameterised and follows.

*The report's own verdict — do not ship it with C-C1 — is right, and F3 sharpens
it:* since `maxConsecutiveMissedAppendOpportunities` is never enforced, a client
whose `S` has crept past the budget has **no** signal that it is now paying two
windows per flight. C-C4 is the only candidate that makes that regression
invisible-but-harmless instead of invisible-and-costly. Ship it the day someone
measures a real-device `S` tail, not before.

---

**C-C5 / E-D9 — `publicReadLagWindows` → 0.**

**KILL.** *One sentence:* the validator pins it to exactly 1
(`profile.ts:255-257`) and the append→finalize→read order inside a window is
forced by I4 and I5 anyway, so lag 0 does not save a window per flight — it
saves a one-off 1.7 s phase shift while deleting the margin that keeps a
`not-final` read (and with it the witness pair, per C-C3) off the healthy path.

---

### 2.4 `angle-scan-cost`

This is the strongest report of the six and I could not break its top four.

---

**D-C2 — replace `bytesFrom`/`hexOf` in `storeSqlite.ts`.**

**SURVIVES.** No wire byte, no route, no geometry, no disclosure. One
correctness note for the implementer: keep the strict validation
`bytesFrom` performs today (reject any non-`[0-9a-f]` nibble, keep the
odd-length check) — a `charCodeAt` nibble table that maps an unexpected
character to 0 would turn a corrupt database row into a silently wrong object,
and the store signs whatever it serves.

---

**D-C1 — serve finalized chunks and checkpoints from precomputed rows.**

**SURVIVES.** The response bytes are byte-identical and the chunk was signed
once at finalization and is never re-signed (`storeCore.ts:982-988`), so I12 is
untouched. Keep the `loadWindow` fallback for rows written by an older build —
without it, an existing database serves nothing and the store's chain looks
broken to every client (I12 → `chain-fault` → the store goes inert, which is
`withhold-a`'s signature on a store that did nothing wrong).

---

**D-C3 — split the mutable and immutable halves of the document.**
**SURVIVES**, subsumed by D-C2. Not worth doing on its own.

---

**D-C4 — drop `slots` from the document once the window is finalized.**

**SURVIVES WITH A DISCLOSURE.** I checked the read paths: `readChunk` and
`readCheckpoint` touch `finalized` only (`storeCore.ts:1090-1124`, `:1043-1075`);
`#append` refuses a closed window before it ever reads `state.slots`
(`storeCore.ts:788-790`, I11); client-side custody verification reads the
fetched **chunk**, not the store's slot map (`storeClient.ts:1660-1707`). The
one behaviour that changes is the `already-present` / `slot-conflict`
distinction (`storeCore.ts:860-868`), and it is unreachable after finalization
because `#windowIsClosed` shadows it. *Disclosure:* the store keeps no record of
which append landed in which slot after finalization, so an operator answering
"did I store what I signed a receipt for" must reason from the signed chunk
rather than from its own slot table.

---

**D-C5 — bounded in-process cache of immutable responses.**

**SURVIVES WITH A DISCLOSURE**, and the report's own mitigation should be
mandatory rather than optional: **populate eagerly at finalization.** A lazy
cache makes hit/miss timing a "did anyone else read this chunk recently"
oracle; an eagerly-populated one has no miss on the healthy path and the
question does not arise.

---

**D-C6 — caching reverse proxy in front of the immutable routes.**

**NEEDS A GATE.** Refuse any deployment where both stores sit behind the same
CDN, the same operator, or the same ASN. A shared CDN collapses the two-store
separation the whole design rests on and hands §3a items 1 and 2 to one party in
one log. Make it a checked deployment invariant (assert the two stores' resolved
ASNs differ) and add it to §3a item 8's independence statement, not a note in a
runbook.

---

**D-C7 — do not let the slow store gate the fast one.**

**SURVIVES WITH A DISCLOSURE, and NEEDS one implementation constraint that the
report only half-states.**

*The constraint.* `carriedBy` must be computed from the **final joined set**,
never from what has arrived so far. `#queueBackfills`
(`carrierRuntime.ts:1209-1246`) enqueues a `REPLICATION_OR_BACKFILL` for every
store not in `carriedBy`. If per-store delivery also drives per-store
`carriedBy`, then **every operation delivered by the fast store alone is
immediately queued as a backfill to the slow store**, which by F7 seizes the
class-0 `state-replication` slot. Consequences, in order of severity:

1. The same operation now appears at store B in two different windows on the
   **healthy** path, where today it appears in one. That is a new cross-store
   timing-linkability input for §3a item 1, created by a change the report calls
   privacy-neutral.
2. PRESENCE, any heartbeat, and genuine backfills all queue behind it (F7,
   strict FIFO at `carrierRuntime.ts:1325-1338`).
3. `counters.backfills` rises on healthy runs, which destroys the counter as a
   fault signal.

*Disclosure sentence:* "The client acts on each store's scan as it lands rather
than waiting for both; the requests it issues, their instants and their sizes
are unchanged, and replication decisions are still taken once, from the joined
set."

*Test:* `--scenario=withhold-a` and `unreachable-b-for-one` must show per-flight
cost equal to `healthy`, and `healthy` must show `backfills: 0`.

---

**D-C8 — memoize the checkpoint-chain verdict.**

**SURVIVES**, with one correctness constraint: `#observe`
(`storeClient.ts:1626-1650`) inserts **out of order** (it walks backwards to the
correct position) and deliberately keeps both sides of a same-window
equivocation. The memo is therefore only valid when the new observation appended
at the tail with a strictly greater ingress window; any other insertion must
force a full re-verification. And the report is right that the problem itself is
unmeasured — `MAX_OBSERVED_CHECKPOINTS = 256` (`storeClient.ts:238`) is reached
after ~17 min at W=4,000 and after **4 min at W=1,000**, so every
window-shrinking candidate makes this arrive sooner. Measure before building.

---

**D-C9 (pre-AEAD recipient hint), D-C10 (WebCrypto AEAD).** **KILL**, confirmed.
The header filter at `carrierRuntime.ts:1143-1150` already rejects on every
public bucket coordinate before the AEAD, and those coordinates are identical
for all 40 objects in a bucket by construction — so the trial AEAD is the
unlinkability mechanism, not an inefficiency.

**D-C11 (one request per window).** **KILL** — it changes design §5's fixed
trace from thirteen requests to nine and contradicts AC-049's canonical chunk
scan, to save 0.36 ms once D-C1/D-C2 land.

**D-C12 (read early / negative read offset).** **KILL** — same one-sentence
reason as C-C3 at `r = 0`: a read that can land before the store's finalizer has
run produces a `not-final` scan, which suppresses the witness pair and changes
the request count. `finalizeDue` polls on a 250 ms interval and is serialised
behind that window's appends (`storeCore.ts:914`, `:929`), so "the data exists
at `cf`" is a statement about the clock, not about the finalizer.

---

### 2.5 `angle-presence-discovery`

D1 = D-C1, D2 = C-C2, D3 = C-C3, D4 ⊂ C-C1, D7 = the window shrink, D9 = C-C5.
Verdicts as above. The two that are its own:

---

**D5 — presence heartbeat, re-publishing the identical operation bytes.**

**SURVIVES WITH A DISCLOSURE — and two of its claims are wrong.**

*Wrong claim 1 (F4).* "It self-heals the asymmetric deadlock in one window,
because the republished presence is the fresh operation that triggers the next
`ingest`." It is not: `#read` calls `#onOperations` **only when `fresh.length >
0`** (`carrierRuntime.ts:1073`), and a republish of identical bytes has the same
`OperationId`, which `#seen` already holds (`carrierRuntime.ts:1067-1071`). For
a peer that has already seen the presence, the republish delivers nothing and
retries nothing. D5 fixes the late joiner and the missed-window case; it does
**not** fix a deferred pair handler. If that path matters, the fix is B-C5.

*Wrong claim 2 (F7).* "A re-queued presence never starves a genuine backfill
because `#pendingEntry` returns the oldest match." True only if there is at most
**one** outstanding heartbeat entry at a time. Re-enqueue unconditionally per
window and the outbox grows one entry per window while draining one per window;
a backfill enqueued at time T then waits behind every heartbeat ahead of it.
**Constraint: re-enqueue at most one heartbeat entry, and only after the
previous one has been appended to every target** (i.e. from the
`entry.targets.size === 0` branch at `carrierRuntime.ts:866-867`).

*And the constraint that makes it safe at all (F5).* **It must republish the
identical bytes, never a rotated presence.** With identical bytes, the operation
id, the `PresenceSemanticSlot`
(`derivations.ts:470-480`, bound to author epoch key + logical window + nonce)
and therefore `pairEdgeId` are all stable, and the carrier envelope still
carries a fresh nonce and this window's ingress window, so the two stores never
see byte-identical ciphertext. Rotate the presence and you are in F5's race.
Validity holds for 24 h: `operationRetentionWindows = 1440` at
`logicalWindowMs = 60_000` (`roomPolicyV4.ts:191-193`), i.e. 1,440 logical
windows against 15 delivery windows per logical window at W=4,000.

*Disclosure sentence:*

> A standing presence converts "this endpoint was present at window w" into
> "this endpoint was online across windows w…w+n" for every capability holder,
> and for anyone who obtains the capability later and has archived carrier
> objects. It is bounded by `presenceRepublishWindows`. No store-visible
> request, size, count or offset changes: a slot that carried cover now carries
> a real object, and the two are indistinguishable by construction.

*Test the report is right to demand first:* `--stagger-ms=12000` must **fail**
on today's code before it passes on the patched code. Also assert
`counters.backfills` and the republication count are ≤ 1 on
`--scenario=healthy --stagger-ms=0`, or D5 will silently mask real faults (F3
means nothing else will notice).

---

**D6 / F-C1 — warm start from a cached peer presence.** See F-C1 below. **KILL.**

**D8 — shrink class 0's carrier.** **SURVIVES**, worth ~6.7 % of the scan and
≈0 s after D-C1. Its refutation of "presence could ride a smaller class" is
correct: `PRESENCE` is pinned to payload class 0 by
`OPERATION_KIND_RULES` (`operation.ts:413-416` checks `rules.payloadClasses`)
and I1 pins one size class per payload class.

---

### 2.6 `angle-product-shape`

---

**F-C1 — warm start: reuse the peer's retained presence.**

**KILL.**

*One sentence for the implementer:* the retained peer presence's HPKE receiver
secret key does not survive the **peer's** own restart, so a warm HELLO
addressed to it opens for nobody — the warm path fires only when the peer never
restarted, which is exactly when it is not needed, and in that case the peer's
driver has already bound a different `pairEdgeId` and will reject the HELLO
anyway.

*The full chain.* The initiator seals its HELLO to the retained presence's
`presenceHybridKemPublicKey`. The peer generates its `receiverSecretKey` at
`start()` and wipes it in `destroy()` (`pairDriver.ts:800-806`); nothing
persists it, and F-C1 explicitly declines to persist it. Two cases:

1. **Peer restarted.** It holds no secret for the retained presence. The HPKE
   decapsulation fails, `openIdentityHelloOpenPolicyPrototype` returns `null`,
   `handleIncomingHello` returns `true` (`pairDriver.ts:1198`) — the HELLO is
   *silently consumed*, no fault, no failEdge. The initiator waits for an
   ACCEPT forever.
2. **Peer still running.** Its `remotePresence` is already bound (F5: `ingest`
   calls `observePeer` only when it is `null`), so its `requirePairEdge()` is
   the **old** edge. The initiator's HELLO names the new edge → the
   `expectedPairEdgeId` check inside the opener rejects → `failEdge`
   (`pairDriver.ts:1194-1197`). The warm attempt kills the peer's live edge.

`receiverKeyValidThroughLogicalWindow` is a claim about how long the *publisher*
will keep answering, not a durable key. Making F-C1 work needs persisted
receiver secret keys and a per-edge driver instance — a different project from
530 LOC, and one with its own §3a item about a long-lived KEM secret at rest.

---

**F-C2 — standing presence with a fresh presence every k windows.**

**KILL.**

*One sentence:* minting a fresh presence per heartbeat puts two or more live
presences per author in the room, and `observePeer` picks the first by
operation-id order (`pairDriver.ts:1049-1061`, `coreReduce.ts:1589`), so the two
endpoints can bind different `pairEdgeId`s and the HELLO then fails the edge
permanently.

Take **D5's identical-bytes form instead**; it achieves the same product
outcome. The report's own reasoning for rotation — `maxOperationsPerAuthorWindow
= 16` per author per 60 s logical window (`roomPolicyV4.ts:198`) — does not
apply to an identical republish, because no new operation is created.

---

**F-C3 — transport parameters ride in PRESENCE.**

**NEEDS A GATE**, and the gate must be structural, not a runtime `if`.

Refuse unless **all** of: `roomPolicy.maxRoomMembers === 2` (the default is
**64**, `roomPolicyV4.ts:200`); the capability is single-use; and the room was
constructed as a distinct *type*, so no later product change can relax it. Plus
a §2 subsection (not a §3a item — §3a is about stores) stating that every
capability holder learns every member's ICE candidates, DTLS fingerprint and
therefore IP addresses without an admission step, and that recorded transport
parameters are decryptable by anyone who later obtains the capability.

*Correctness items the report does not price.* `PresenceCoreV1` feeds
`presenceSemanticSlot` and the presence payload's exact class-0 encoding
(`pairDriver.ts:699-707`); adding a field moves the pinned known-answer vectors
and every presence's `semanticSlot` preimage. And the synthesised peer
description must pass `validateWebRtcSdp` and the candidate-set rules in
`selectWebRtcCandidate` (`transportCandidates.ts:172-190`), which today require
exactly one `operation-carrier` member — so a parameters-only path needs a new
candidate kind, i.e. B-C6's work as well.

*My honest read:* it forfeits AC-005's final clause, which is a named testable
guarantee, to buy 2 s over the C1+C5 package. Gate it or drop it; do not ship it
by default.

---

**F-C5 — symmetric transport flight.**

**SURVIVES WITH A DISCLOSURE.** Slot check: initiator at `(0,1)`, responder at
`(1,1)`, each once, `pairDependencies` = the peer's ACCEPT/HELLO as appropriate,
`MAX_PAIR_DEPENDENCIES_V1 = 1` respected. I10 holds. The routing dispatch
(`pairDriver.ts:1160-1171`) must gain a symmetric handler rather than a swap,
because both roles now receive a non-bootstrap step they must treat the same
way.

*Disclosure sentence:*

> Both endpoints publish their transport description in the same delivery
> window, sealed under `EstablishedPairRoot` as before. Confidentiality is
> unchanged — only a peer that completed the identity exchange can derive that
> root — but the responder no longer learns, before publishing, that the
> initiator received and admitted its accept. What is deviated from is the
> specification's confirmation ordering (spec:9887, spec:10184-10187), not its
> recipient set.

Same second-browser caveat as B-C6: one side must consume a peer *offer* as an
answer with a rewritten `a=setup:`, and `validateWebRtcSdp` runs on both ends.

---

**F-C7 — pre-gather ICE at start-up.**

**SURVIVES WITH A DISCLOSURE** — the same fingerprint/ufrag-reuse sentence as
B-C1's companion. Add the assertion `floor.md` §11 and this report both want:
assert the transport flight's `operationPayloadClass` in the harness. Today the
class flip at SDP > 3,613 bytes is completely silent and moves the flight to an
*earlier* slot with *less* budget (class-1 safety-control at 1,500 vs class-0 at
1,700), which is the wrong direction.

---

**F-C6 (store as a fast SDP drop), F-C8 (legacy signaling fast path).**
**KILL**, both, confirmed. F-C6 creates a deterministic peer-equality handle at
the store — the one thing spec:480-482 forbids by name. F-C8 hands a third party
the complete list spec:494-505 exists to protect, and makes the blind path's
traffic event-shaped (its *stopping* becomes the signal), which is §3a item 4.

---

**F-C9 — long-lived push read.**

**KILL for this prototype.** *One sentence:* it replaces the thirteen fixed
per-window requests that design §5 and §3a item 4 rest on with one long-lived
connection whose lifetime is itself the fingerprint, and it deletes the
canonical scan order that AC-049 pins — for 0.6 s per flight that D-C1 already
delivers without touching the wire.

---

## 3. The stack: what nobody measured, and the two knobs that fight

Three composition hazards, none of which appears in any single report because
each is visible only across two.

**S1 — schedule-shape C1 and shrink-class-1 C1/C4 push opposite ways on the same
knob.** C-C1 moves the appends to 2,400-2,800 and finalization to 3,500, which
*reduces* `cf − min(appendOffset)` from 1,500 ms to 1,100 ms — the store's drain
headroom. A-C1/A-C4 *reduce* the store's per-request cost, which increases
effective headroom. The two were measured separately: C-C1 at W=1,000 **FAILS**
with 17 × `append window-finalized` (`E8-w1000-c2.txt`), while A-C1+A-C4 at
W=1,000 **PASSES** 4/4. Their stack is untested and the outcome is not
predictable from either measurement, because F6 also shrinks the skew band to
50 ms at that window. **Do not quote a stacked number without a stacked run.**

**S2 — B-C1 (responder offers) and C-C1 (reversed roles) conflict on slot
ordering.** See §2.2. If both are taken, `identity-bootstrap` must sit at the
*earlier* of the two late slots, or a partially-late enqueue delivers an
unopenable OFFER a window before its ACCEPT.

**S3 — every candidate that shortens the window pulls three absolute constants
under it.** `requestDeadlineMs = deliveryWindowMs` (`storeClient.ts:276-283`),
`maxScheduleSkewMs` scaled by `W` (F6), and
`MAX_OBSERVED_CHECKPOINTS = 256` reached in wall-clock time proportional to `W`
(§2.4 D-C8). None of the three scales with the store's actual speed. The
harness's `kill-a` assertion (`run.mjs:846-859`) is the sharp edge here: at
W=1,000 the *surviving* store filed three `unreachable` faults for missing the
1,000 ms append deadline, which that assertion correctly calls a regression.

---

## 4. The five tests that must exist before any of this ships

1. **`carrierRuntime.test.ts` — the class-fit guard.** Publish an operation whose
   payload class has no carrier large enough, and assert the runtime surfaces a
   typed failure the driver can see. Today it emits a `missed` event and hangs
   (F1). This test is what makes A-C2 shippable and what would have caught
   A-C1.
2. **`pairDriver.test.ts` — the ingest fixpoint.** One `ingest` carrying two
   causally ordered pair operations, in both orders, both handled in that call
   (B-C5).
3. **`run.mjs` — fail on `append window-finalized`.** Any occurrence in
   `store-missed` fails the run. This is the single assertion that guards C-C1,
   C-C4, A-C4 and every window shrink at once (I11).
4. **`run.mjs --stagger-ms=<n>`.** Must fail at n ∈ {4000, 12000, 60000} on
   today's code and pass after D5. Without the failing baseline, D5 is a
   disclosure paid for an unproven bug.
5. **`run.mjs` — assert the transport flight's `operationPayloadClass`** and
   print `Date.now() % deliveryWindowMs` at `presence-published`. The first
   makes the silent class flip visible (F-C7); the second turns every `p`-
   dependent estimate in `floor.md`, `angle-schedule-shape` and
   `angle-presence-discovery` from an inference into a measurement.

---

## 5. Summary table

| Candidate | Verdict | The thing that breaks / the gate |
|---|---|---|
| A-C1 carrier 8,448 only | **KILL** | I7 unenforced → F1 silent drop → hung rendezvous |
| A-C2 + payload class 8,192 | SURVIVES w/ DISCLOSURE | needs A-C5, the I7 assertion, and an SDP-ceiling that matches; forks the shared operation codec |
| A-C3 class 36,864 | SURVIVES w/ DISCLOSURE | dominated; but does not need A-C5 |
| A-C4 `pcoc` 24 | SURVIVES w/ DISCLOSURE | 8 of 24 class-1 objects are store-authored: bytes up, anonymity flat |
| A-C5 §4.12 fallback | SURVIVES | must change `selectWebRtcCandidate` too, not only the builder |
| A-C6 class 4,097 | **KILL** | I7 by construction |
| B-C5 ingest fixpoint | SURVIVES | bound the passes; do not re-run `coreReduce` inside the loop |
| B-C1 responder offers | SURVIVES w/ DISCLOSURE | slot ordering vs C-C1 (S2); pre-gather fingerprint reuse |
| B-C2 speculative offer | **NEEDS A GATE** | open policy only, `maxRoomMembers === 2`, no address-book/authority/denylist; derive the child **before** `promoteEstablishedRoot` wipes `HelloRoot` |
| B-C3 SDP in HELLO | **KILL** | no class-1 bootstrap form (I9); dies at ~5 ICE candidates |
| B-C4 room-keyed beacon | **KILL** | new `PairStepKindV1` byte + room-wide identity + one KEM instead of two |
| B-C6 symmetric params | SURVIVES w/ DISCLOSURE | new candidate kind; needs a second browser |
| C-C1 late slots, `cf` 3,500 | **SURVIVES** | I6 re-derived and green at 3,500 exactly; ship with test 3 |
| C-C2 cold-start allocation | SURVIVES w/ DISCLOSURE | replay variant must retain request **bytes**, never the key |
| C-C3 / E-D3 `r → 0` | **KILL at 0**, survives at `r ≥ skew` | `not-final` suppresses the witness pair → 13 requests become 11 |
| C-C4 second slot per role | SURVIVES w/ DISCLOSURE | +4.8 %/+14.4 % traffic; the only guard against F3 |
| C-C5 / E-D9 read lag 0 | **KILL** | pinned by validator; buys 1.7 s once and deletes the finalize→read margin |
| D-C2 hex codec | **SURVIVES** | keep the strict nibble validation |
| D-C1 chunk rows | **SURVIVES** | keep the `loadWindow` fallback or old databases break I12 |
| D-C3 split document | SURVIVES | subsumed by D-C2 |
| D-C4 drop slots | SURVIVES w/ DISCLOSURE | store loses its own slot provenance |
| D-C5 response cache | SURVIVES w/ DISCLOSURE | populate eagerly; a lazy cache is a read oracle |
| D-C6 CDN | **NEEDS A GATE** | different CDN/operator/ASN per store, asserted |
| D-C7 unblock the union | SURVIVES w/ DISCLOSURE | `carriedBy` from the **joined** set or every healthy read spawns backfills (F7) |
| D-C8 memoize chain | SURVIVES | invalidate on any non-tail `#observe` insert; measure first |
| D-C9/C10/C11/C12 | **KILL** | trial AEAD *is* the mechanism; AC-049; `not-final` |
| D5 presence heartbeat | SURVIVES w/ DISCLOSURE | **identical bytes only**; one outstanding entry; F4 kills its self-heal claim |
| D8 class-0 shrink | SURVIVES | ≈0 s after D-C1 |
| F-C1 warm start | **KILL** | the peer's receiver secret does not survive the peer's restart |
| F-C2 rotating standing presence | **KILL** | multiple live presences → `observePeer` race → permanent `failEdge` (F5) |
| F-C3 params in PRESENCE | **NEEDS A GATE** | 2-party room *type*, single-use capability; forfeits AC-005 |
| F-C5 symmetric transport | SURVIVES w/ DISCLOSURE | confirmation ordering only; second browser |
| F-C7 pre-gathered ICE | SURVIVES w/ DISCLOSURE | fingerprint/ufrag reuse per session |
| F-C6/F-C8/F-C9 | **KILL** | peer-equality handle / event-shaped bypass / deletes the fixed trace |

---

## 6. The order I would ship, given the above

1. **D-C2** (25 lines, one file, zero risk), then **D-C1**. Nothing else is
   measurable until the store stops being `O(whole window document)` per
   request.
2. **Test 3** (`fail on window-finalized`) and **test 5** (class assertion +
   start phase). Two harness lines that turn the next four changes from
   arguments into measurements.
3. **C-C1** at `cf = 3,500` — the only change in this whole set that is measured,
   deviation-free, and passes I1-I6 with the phase-band test green.
4. **B-C5**, then **B-C1** with **F-C7**, honouring S2's ordering constraint.
5. **A-C2 + A-C5 + the I7 assertion** if the bandwidth argument matters (it does
   on mobile: 5.5 Mbit/s sustained to be idle), *not* A-C1.
6. Only then argue about `deliveryWindowMs`, with S3's three absolute constants
   re-derived at the new value and a full `--scenario=all` run.

Everything else in the list is either gated, disclosed, or dead.
