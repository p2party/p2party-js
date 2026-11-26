# Blind rendezvous: two-store prototype — design

Date: 2026-09-07. Status: design for a flagged prototype. Not a v0.4 release
artifact; see "What this is not" before anything else.

## 1. Purpose

Build the smallest end-to-end demonstration of server-blind rendezvous that
is **fault tolerant** across two independently run store processes and
**as private per store as the spec's single-store baseline (S1)**, using the
protocol library that already exists under `src/blindRendezvous/` and the
store-free protocol-v4 session API.

Success is one reproducible run: two headless Chromium contexts holding the
same room capability, two store processes on separate ports, and

1. each browser publishes a `PRESENCE` operation to **both** stores;
2. each discovers the other's presence through **either** store;
3. the pair completes `IDENTITY_HELLO → IDENTITY_ACCEPT → TRANSPORT_OFFER →
   TRANSPORT_ANSWER` as pair-sealed operations carried by the stores;
4. WebRTC connects from the exchanged SDP and the **existing protocol-v4
   handshake** (hybrid 3DH + ML-KEM, Double Ratchet) runs over the data
   channel via `createSession`;
5. one encrypted application message round-trips byte-exact;
6. the same run succeeds with one store **killed** and, separately, with one
   store **withholding** (accepting appends, serving dummies only); and
7. a wire log proves neither store ever received the capability, the
   `RoomContextId`, a stable Ed25519 key, or an SDP byte in the clear.

## 2. What this is not

The spec (line 3392) permits prototypes behind internal flags and forbids
inventing release bytes and calling them v0.4. Therefore:

- Every new wire byte lives under a route prefix and media types that say
  `prototype-v0`. **No route path and no media type here is interoperable
  with, or a proposal for, the frozen §4.6 route family.** The *signed
  artifacts* are a narrower statement and the sentence above must not be read
  over them: §4.1 signs under the specification's own frozen transcript domain
  strings, so a lease, an append result, a chunk and a checkpoint carry exactly
  the transcripts the spec defines, and only `prototypeStoreCompatibilityHash`
  is prototype-scoped. That is deliberate — a codec tested against strings this
  prototype invented would be testing nothing — and the mitigation is at the
  door rather than in the bytes: `PrototypeStoreClient.connect` refuses any
  descriptor whose `compatibilityHash` is not the prototype hash for this
  profile, before it reads a window, a chunk or a checkpoint. A store
  advertising release compatibility bytes is not half-spoken to; it is not
  spoken to at all.
- The prototype earns **no** label: not S1, not R2-BEC, not SP1, not L2, not
  "anonymous", not "censorship-resistant", not "BFT". The only claim its
  README may make is the wire-log fact in §1 item 7, stated as "on this run".
- Two stores add availability (f=1: either may fail or withhold), not
  privacy. Both stores see the same source address at the same instants;
  colluding stores learn nothing a single store did not.
- The admission kernel (`Admit()`, reservations, trials, topology custody,
  14-row CAS captures) is **not** consulted. The prototype runs an explicit
  open policy: any capability holder is admitted. This is the honest
  equivalent of the spec's `eligibility="open"` room with no deny-list, and
  it is labelled as such in code.
- Allocation is **open**: the Privacy Pass (Blind-RSA, RFC 9578) issuance
  path is stubbed by a store mode that ignores the token bytes. Abuse control
  is therefore absent, and the prototype says so.

## 3. Architecture decision

Three candidate architectures were considered against the spec and the
literature shelf (`docs/rendezvous-prior-art.md`):

| | (A) replicated additive stores | (B) OHTTP relay/gateway split | (C) DPF secret-shared writes |
|---|---|---|---|
| Privacy vs one malicious store | S1 (spec baseline) | S1 | S1 plus hidden write slot |
| Privacy vs two colluding stores | S1 (nothing lost, nothing gained) | S1 (spec 4206: a split proxy "does not satisfy SP1 merely by name") | broken (both keys reveal the slot) |
| f=1 fault tolerance | yes: union of two chains | no: relay is a single point unless doubled (4 servers) | no: a lost share is a lost write |
| Fits the spec's model | exactly Phase 1 + Phase 4 ("client-additive multi-store") | needs an SP1 profile and mixing evidence | contradicts the targetless-bucket model (there is no room-linked slot to hide) |
| Browser cost | AEAD + Ed25519 + HPKE, all present | plus HPKE-over-HTTP layer | DPF eval per write, new WASM |

**Decision: (A).** It is what the spec already describes for two stores, it
is the only one of the three that delivers fault tolerance with two
processes, and it reuses every primitive in the tree.

## 3a. Why (A), and what it still leaks

A literature sweep across eight angles (2024-2026, kept as the untracked
shelf `docs/rendezvous-prior-art-delta-2026-09.md` beside the existing
`docs/rendezvous-prior-art.md`) scored the three candidates 34, 28 and 18
out of 40 and settled the question with one structural fact:

> Two stores cannot buy fault tolerance **and** privacy beyond S1 from any
> cryptographic family in the literature. Secret-shared writes (Express,
> Sabre, Spectrum, Pepper) leave the survivor holding pseudorandom noise
> when either store is down. Robust designs (Blinder, Trellis, Pudding,
> Arke) need 3-4+ servers. Two-server private-read and detection schemes
> (Myco, HomeRun, multi-server FMD) need both servers online, usually
> talking to each other. Replicated self-authenticating logs give safety
> against any number of Byzantine replicas for free and need one honest
> reachable replica for liveness.

So (A) is not a compromise that a bigger budget would improve at n = 2; it
is the only shape that survives one store failing.

**Residual leaks this prototype must disclose** (none is hidden by S1,
which excludes source anonymity and traffic patterns by definition):

1. **Replicated-write timing linkability — the worst one.** Writing the
   same operation to both stores milliseconds apart lets anyone who sees
   both request logs join them into one client with no identifiers at all.
   The mitigation is an independent random per-store delay drawn wide
   against the window, and a measured linkage fraction; it trades directly
   against rendezvous latency. **The runtime schedules both stores at the
   profile's offsets, and the measured separation between the two stores'
   writes of one operation is 0 ms — minimum, median and maximum** over
   three operations in three consecutive windows
   (`tests/blindRendezvous/prototype/carrierRuntime.test.ts`, "writes one
   operation to both stores in the same millisecond, measured"; the clock
   is injected, so 0 ms is the schedule's own contribution with network
   jitter removed). A per-store phase offset was measured against this
   profile and **rejected rather than shipped**, because the profile has no
   room for one that would help. The geometry admits at most 100 ms earlier
   (the token offset reaches zero) and 499 ms later
   (`chunkFinalizationOffsetMs` 2800, less `maxScheduleSkewMs` 200, less the
   last append at 2100, less one — that inequality is strict, so 500 itself
   fails validation): a 599 ms band against a 4000 ms window, 15% of one
   epoch, crossing zero window boundaries. A join partitions both logs
   by window before it does anything else, so a separation of 599 ms
   against a 4000 ms window leaves the candidate set an observer works over
   exactly as it was — it reduces the join by nothing measurable rather
   than reducing it a little, and a wide draw would need a profile whose
   append band is wide against the window rather than 15% of it. Two
   further facts settle it: derived from the `PublicCarrierContextId` the
   phase is `H(StoreId || DeliveryProfileHash)`, public and shared by every
   client of that store, so it is the same grid under a different name and
   an observer subtracts one known constant (129 ms, for the store pair and
   derivation that test measures); derived per client instead it would be a
   stable cross-window timing fingerprint at each store, and would put that
   client outside the 200 ms band the profile itself defines as conforming
   drift, which is the anonymity set a fixed schedule exists to create.
   **What would work needs no new geometry:** hold the second store's copy
   for a whole number of windows drawn from a wide distribution and let its
   slot carry cover meanwhile — nothing changes on the wire, because a real
   object and cover are already the same bytes at the same instant, and the
   schedule stays exactly fixed; the price is k windows (k x 4000 ms) of
   replication latency and a longer stretch in which one store is the only
   carrier. Recorded as follow-up work with its numbers, not as a solved
   problem.
2. **Source addresses.** Both stores see the client's IP on every write and
   poll; a single store can recover a write-then-read pairing in a few
   rounds. The co-membership edge is hidden at the identifier level only.
3. **Size and count** are visible; the fixed schedule pads both.
4. **Polling shape** must stay schedule-shaped, never event-shaped: no
   burst after a hit, no coordinated dial phase between stores.
5. **Retry oracle.** Retrying at the surviving store after an omission is an
   active cross-store tagging channel; retries happen only at the next
   scheduled slot.
6. **The witness channel is itself a beacon** — cross-store checkpoint
   writes are replicated writes and are scheduled independently of user
   traffic for that reason. Their *timing* is independent of user traffic;
   their *presence* is not, which is item 14.
7. **Detection, not prevention.** A client detects forged or altered
   entries, replays, and set disagreement; omission evidence needs signed
   checkpoints; a targeted split view needs a second observer. Both stores
   colluding on omission is undetectable, as is a first-write omission
   before any checkpoint exists.
8. **Independence is a business fact**, not a cryptographic one: operator,
   ASN, hosting, jurisdiction and funding must be stated and auditable. Two
   processes on one laptop are one fault domain, and the E2E says so.
9. **Key split-view.** Each store can serve a per-client descriptor to
   partition the anonymity set; witnessing the descriptor digest mitigates
   but does not solve it.
10. **No uniqueness.** Two concurrent offers for one room in one window
    cannot be prevented; the tie-break is part of the protocol.
11. **Token and quota shape.** If two stores ever share a double-spend
    database, redemptions become a cross-store membership edge.
12. **Local forensics.** Persisted seen-sets and checkpoints are keyed by
    per-store opaque ids, never by room-derived tags.
13. **No labels.** Two stores give crash and omission tolerance with
    detection, not Byzantine tolerance.
14. **The witness channel is a cross-store status oracle.** Item 6 is about
    when the witness writes happen; this is about whether they happen at all.
    `#witness` (`carrierRuntime.ts`) posts a record about store A to store B
    **only if** A's scan of that window came back `finalized` and neither store
    is inert, and reads B's records back in the same condition. So store B
    learns, directly off its own request log and with no cooperation from
    anyone, whether store A served this client a finalized window. Count it per
    store: a store receives **one witness POST and one witness GET, or
    neither** — never one of the two — and it receives them exactly when the
    *other* store's scan of that window came back `finalized` and neither store
    is inert. Both stores healthy: each receives the pair. One store's scan
    degrades: the pair to the **healthy** store disappears, and its absence is
    the signal — the healthy store is the one that reads it. Either store goes
    inert: the traffic stops in both directions. It is the only part of the
    per-window trace that is not fixed — §5 counts it as the conditional
    pair — and it points the wrong way: the shape of what this client sends to
    one store varies with the other store's behaviour towards it. Nothing in
    the test suite would notice a change here: `windowShape()` in
    `tests/blindRendezvous/prototype/carrierRuntime.test.ts` counts five
    hardcoded routes (token, allocation, append, checkpoint, chunk) and does
    **not** include the witness route, so the fixed-shape invariance test would
    pass unchanged if witness traffic varied arbitrarily. That is the test's
    scope, and a reader comparing the test against the claim deserves to know
    it. **What would fix it** is one sentence and is not attempted here: post a
    witness record to every other store every window regardless, carrying cover
    when there is nothing to witness, exactly as an append slot carries cover
    when the outbox is empty. Making the traffic unconditional is a design
    change with its own cost, so it is disclosed rather than done.

What no sweep found published together — and therefore the only thing this
work may present as novel — is the *composition*: a capability-authenticated
Byzantine grow-only set, fixed-scan reads, mutual transparency-log-style
witnessing treated as evidence rather than validity, replicated
writes, and browser-side cost measurements. That is a systems contribution
for a flagged prototype, not a cryptographic result.

## 4. Components

All new code lives under `src/blindRendezvous/prototype/` and is **not**
exported from `src/index.ts`. The prototype flag is that directory boundary
plus the store's environment gate; nothing in the package barrel or the
`p2party/session` subpath changes.

### 4.1 Shared codec additions (`src/blindRendezvous/schemas.ts`)

The store request/response types the spec defines in §4.3/§4.6 but the tree
lacks get canonical descriptors in the one schema file, so client and server
share one encoder (rule: no second authority for wire fields):

`PublicAppendAdmissionV1`, `PublicAppendRequestV1`,
`PublicAppendResultBodyV1`, `PublicAppendResultV1`,
`AllocationTokenIssueRequestV1`, `AllocationTokenIssueResultBodyV1` (union),
`AllocationTokenIssueResultV1`, `PublicAllocationRequestV1`,
`PublicAllocationLeaseBodyV1`, `PublicAllocationLeaseV1`,
`PublicAllocationStatusBodyV1`, `PublicAllocationResultV1` (union),
`PublicStoreCheckpointStatusBodyV1`, `PublicStoreCheckpointReadV1` (union),
`PublicChunkStatusBodyV1`, `PublicChunkReadV1` (union), and a
`PrototypeStoreDescriptorDocumentV1 = { descriptor, routes[] }`.

Field order and widths follow the spec's TS types verbatim; bigint fields are
`u64`, ordinals `u32`, `sizeClass` `u8`, status enums `u8` in declaration
order. Signing transcripts are the spec's:

```text
AllocationLease:   "p2party/public-allocation-lease-signature/v1"  || H(Canonical(body))
AllocationStatus:  "p2party/public-allocation-status-signature/v1" || H(Canonical(body))
AppendResult:      "p2party/public-append-result/v1"               || H(Canonical(body))
AppendRequestHash: H("p2party/public-append-request/v1"            || Canonical(request))
AllocationAppend:  "p2party/allocation-append-signature/v1" || H(Canonical(leaseBody)) || Byte(sizeClass) || U32BE(objectOrdinal) || H(exactFixedObject)
ChunkStatus:       H("p2party/public-chunk-status/v1"      || Canonical(body))
CheckpointStatus:  H("p2party/public-checkpoint-status/v1" || Canonical(body))
```

These go in `derivations.ts` next to the existing chunk/checkpoint hashes.

### 4.2 Prototype delivery profile (`prototype/profile.ts`)

One constant, `PROTOTYPE_DELIVERY_PROFILE_V0`, validated at import by the
§4.3 arithmetic (a `validateDeliveryProfileGeometry` helper is added and
unit-tested against the inequalities):

```text
deliveryWindowMs 4000        carrierRetentionWindows 160000 (covers the
                             default policy's 7-day semantic horizon)
maxFutureIngressWindows 2    roomSlotsPerClient 1
cohortAllocationsPerWindow 8 publicChunkObjectCount 8
tokenIssueOffsetMs 100  tokenIssueResponseBudgetMs 300  maxScheduleSkewMs 200
allocationRequestOffsetMs 700  allocationResponseBudgetMs 300
chunkFinalizationOffsetMs 2800  publicReadOffsetMs 600  publicReadLagWindows 1
sizeClasses:
  0: fixedCarrierObjectBytes 8192  payloadClass 0
     appendSchedule [1300 identity-bootstrap, 1700 safety-control, 2100 state-replication]
     publicChunksPerWindow 3
  1: fixedCarrierObjectBytes 73728 payloadClass 1
     appendSchedule [1500 safety-control, 1900 state-replication]
     publicChunksPerWindow 2
maxConsecutiveMissedAppendOpportunities 3  minMeasuredSharedCohort 2
maxAssuranceEvidenceAgeMs 3600000
```

Rendezvous latency is one window per dependent flight: presence (w), HELLO
(w+1), ACCEPT (w+2), OFFER (w+3), ANSWER (w+4), each readable ~0.6 s into the
following window, so roughly 20–25 s to a WebRTC connection. The E2E may
shorten `deliveryWindowMs` by passing a different profile to both sides; the
constant is the only place the geometry lives.

Room policy is `copyBlindDefaultPolicy()` (the bare `v2.` invitation
default), unchanged.

### 4.3 Store process (`prototype/store/`)

- `storeCore.ts` — pure per-`(profileHash, ingressWindow)` window machine:
  `allocate(request, nowMs)` → lowest free ordinal, signed lease, or signed
  status (`capacity-exhausted`, `window-closed`); `append(request, nowMs)`
  → verifies the lease under the store key and the allocation signature under
  the lease's ephemeral key, derives `(chunkIndex, objectIndexWithinChunk)`
  with `appendSlotCoordinates`, binds the object hash atomically:
  empty slot → `stored`, same hash → `already-present`, other hash →
  `slot-conflict`; `admission: null` → `unallocated-cover` and discard;
  after close → `window-finalized`. `finalize(window)` runs at
  `IngressWindowStart(w) + chunkFinalizationOffsetMs`: pads every absent
  position with a CSPRNG body of the exact class object length, signs
  exactly `publicChunksPerWindow` chunks per class (`previousChunkHash`
  chain from `ZERO32`), builds the checkpoint over `checkpointLeafEntries` +
  `rfc9162MerkleTreeHash`, links `previousCheckpointHash` to the prior
  window (or `ZERO32` at `chainStartIngressWindow`), signs, and the window
  becomes immutable. Windows between the chain start and now that received
  nothing still get an all-dummy checkpoint (spec: "including a wholly
  all-dummy window").
- `storePersistence.ts` — `bun:sqlite` (no new dependency) behind a small
  port; tables: `allocation`, `slot`, `chunk`, `checkpoint`, keyed by the
  public coordinates only. Restart replays state; a finalized window is
  never re-signed.
- `storeHttp.ts` — `Bun.serve` handler. Route family (prefix is the flag):

  | Method and path | Body / result |
  |---|---|
  | `GET /.well-known/p2party-store/prototype-v0` | canonical `PrototypeStoreDescriptorDocumentV1`; `application/p2party-store-descriptor-prototype-v0` |
  | `POST /p2party/prototype-v0/allocation-token` | `AllocationTokenIssueRequestV1` → `AllocationTokenIssueResultV1`; open mode answers `issued` with 32 zero bytes |
  | `POST /p2party/prototype-v0/allocation` | `PublicAllocationRequestV1` → `PublicAllocationResultV1` |
  | `POST /p2party/prototype-v0/append` | `PublicAppendRequestV1` → `PublicAppendResultV1` |
  | `GET /p2party/prototype-v0/checkpoint/{profileHashHex}/{window}` | `PublicStoreCheckpointReadV1` |
  | `GET /p2party/prototype-v0/chunk/{profileHashHex}/{window}/{sizeClass}/{chunkIndex}` | `PublicChunkReadV1` |
  | `GET /health` | `{ status, role: "store-prototype", storeId, protocol: "prototype-v0" }` |

  Every protocol response is HTTP 200 with a canonical body; a malformed
  outer length or media type is one constant 400 before parsing. No
  redirects, cookies, compression, or per-room headers. The store logs only
  request class, window, and byte counts — never bodies.
- `storeServer.ts` — entrypoint. Refuses to start unless
  `P2PARTY_STORE_PROTOTYPE=1`. Env: `P2PARTY_STORE_PORT` (the E2E uses
  5910/5911; nothing binds below 5000 locally), `P2PARTY_STORE_KEY_FILE`
  (32-byte Ed25519 seed, generated on first start), `P2PARTY_STORE_DB`,
  `P2PARTY_STORE_OPEN_ALLOCATION=1` (required today; the only allocation
  mode implemented), `P2PARTY_STORE_FAULT=withhold` (test-only: accept
  appends, finalize all-dummy chunks — `withhold` is its only value), and
  `P2PARTY_STORE_LOG_BODIES=<path>` (test-only, a separate variable: the hex
  of every accepted POST body, written before parsing). Script:
  `bun run store:prototype`. A finalized window costs about 2.76 MB of state;
  §9 carries what that means for anyone who runs one.

The descriptor is signed at start with `storeDescriptorSignedMessage`;
`compatibilityHash = H("p2party/blind-store-prototype-v0/compatibility" ||
DeliveryProfileHash)`, `supportedDeliveryProfileHashes = [profileHash]`,
`checkpointChainStarts = [{ profileHash, chainStartIngressWindow = the
window of first start }]`, a 30-day validity interval, and one signed
`StoreRouteV1` whose `opaqueLocator` is the origin.

### 4.4 Store client adapter (`prototype/storeClient.ts`)

Implements the spec's `PublicStoreOperationCarrierAdapter` shape over
`fetch` for the prototype route family. On construction it fetches and
validates the descriptor (`validateStoreDescriptor`, prototype
`compatibilityHash`, profile support) and pins `storeId` and the signing key.
Every signed response is verified under that key or rejected. Every request —
the descriptor fetch included — carries an `AbortSignal.timeout` of one
delivery window (`requestDeadlineMs`), the same value on every route: a
request that has not answered by the time the fixed schedule reissues it can
change nothing, and without a bound a store that accepts the connection and
answers nothing would stall the union described in §4.5.

`reconcile({kind:"public-fixed-scan", window w})` issues the checkpoint GET
and every chunk GET for `w` without awaiting, then: verifies each chunk
signature and bucket coordinates, recomputes the checkpoint root from the
complete chunk set (`checkpointLeafEntries` + `rfc9162MerkleTreeHash`) and
requires it to equal `finalizedChunkRoot`, runs
`verifyStoreCheckpointChain` over the observed checkpoints for that store,
and yields the fixed objects. A store whose chain verdict is anything but
`chain-verified` or `unverified-chain-gap` is marked **inert**: its objects
are still unioned (spec: "union every observed branch") but it is excluded
from availability.

### 4.5 Carrier runtime (`prototype/carrierRuntime.ts`)

One scheduler per active store context, driven by the profile's fixed
offsets (`ingressWindowStartMs` + offset, wall clock via an injected clock):

- at `tokenIssueOffsetMs`: one issuance POST for `w+1` (fixed shape);
- at `allocationRequestOffsetMs`: one allocation POST for `w+1` with a fresh
  ephemeral Ed25519 allocation key;
- at each `appendSchedule[c][i].offsetMs`: exactly one append per room slot,
  real if the outbox holds a compatible operation for that role, else a
  dummy with the exact header and random body;
- at `publicReadOffsetMs`: checkpoint + all chunk reads for `w-1`;
- at `chunkFinalizationOffsetMs - maxScheduleSkewMs` (2600 at the pinned
  profile), waiting for nothing but the other store's scan of `w-1`: a
  witness POST and a witness GET to each *other* store, which is the one
  part of the shape that is **conditional** rather than fixed (§3a item 14,
  counted in §5). Its timing does not depend on what the read decrypted or
  on the application's handling of it.

A timer delivered late fires its events late rather than dropping them;
uploads more than one delivery window late are not sent and are reported
`missed` (`#takeDue`). Nothing is retried (no same-window retry). Outbox:
operations queue with their `ServiceWorkKindV1`; role mapping and ordering follow
`OperationServiceRole`/`OperationServiceOrder` from §4.3. Each publication
wraps the **same operation bytes** per store with `sealCarrierEnvelope`
under `carrierContextId = PublicCarrierContextId(storeId, profileHash)` and
a fresh 24-byte nonce, so the two stores never receive byte-identical
ciphertext.

Inbound: every fixed object from every store is decoded, opened under
`RoomRoot` (a failed open is cover), `decodeOperation` →
`validateAndIdentifyOperationCandidate` → `mergeOperationCandidateSets`
across stores by `OperationId` → `coreReduce`. Any operation first seen from
only one store is re-queued as `REPLICATION_OR_BACKFILL` for the other
(bounded to once per operation per store).

Store failure handling: a rejected fetch or a bad signature marks that
event missed for that store; nothing about the other store changes. The
runtime exposes `storeTopology: "multi-store-union" | "single-carrier-dependent"
| "no-usable-carrier"` computed only from locally observed successful reads
in the last window, and nothing else — no umbrella label.

### 4.6 Pair driver (`prototype/pairDriver.ts`)

State per room: stable Ed25519 identity, X25519 identity + cross-signature
(`generateSessionIdentity`), a hybrid receiver seed
(`createMlKem768X25519Backend(module).deriveKeyPair(seed)`), the local
presence, an in-memory `pairLedger`, and one edge record.

1. **PRESENCE**: `PresenceCoreV1` with the 1,216-byte hybrid key,
   `stableIdentityCommitment(roomContextId, stableKey)`, random nonce,
   `validThrough = receiverKeyValidThrough = logicalWindow + operationRetentionWindows`;
   `stableOwnershipSignature` over `presenceOwnershipSignedMessage`;
   `authorityPermit: null`; outer op signed by a fresh author epoch key;
   `semanticSlot = presenceSemanticSlot(...)`; enqueued once.
2. **Selection**: after each reduce, the remote presence is the other
   `observedPresence` whose ownership proof verifies. Initiator is the
   lexicographically lower `PresenceOperationId`;
   `endpointPresenceOperationIds = [initiator, responder]`.
3. **HELLO** (initiator): fresh response hybrid keypair;
   `sealPairBootstrapV1` with `psk = RoomRoot`, `recipientBinding
   {presence, responderPresenceId}`, plaintext body `PairIdentityHelloV1`
   (`attemptMode:"planner"`, sender identity bundle, commitment, no grant,
   response hybrid public key, `identityTranscriptSignature` over
   `pairIdentitySignedMessage(binding, projection)`), padded by
   `padPairPlaintextV1`; wrapped as `PAIR_STEP` class 0 with
   `semanticSlot = pairSemanticSlot(tag)`; retain `HelloRoot`, HELLO op id,
   response seed.
4. **HELLO open** (responder): for each active `PAIR_STEP` candidate with a
   bootstrap header whose endpoint pair names the local presence at index 1,
   `openPairBootstrapV1` with the receiver seed and `psk = RoomRoot`. Inside
   the validator, the same checks `identityHelloOpen.ts` performs: slot
   `(0,0,null,[])`, tag and semantic-slot equality, `pairEdgeId`
   recomputation, not-self, commitment, cross-signature, transcript
   signature, response key well-formedness, and remote presence ownership.
   Record the slot in the ledger (fork → fail the edge). This bypasses the
   reservation/trial/admission chain deliberately; the function is named
   `openIdentityHelloOpenPolicyPrototype` and its docblock says why.
5. **ACCEPT** (responder): `sealPairBootstrapV1` with `psk = HelloRoot`,
   recipient = HELLO's response hybrid key, `recipientBinding
   {hello-response, helloOperationId}`, slot `(1,0,null,[helloId])`, body
   `PairIdentityAcceptV1` signed by the responder; class 0; retain
   `AcceptRoot`.
6. **ACCEPT open** (initiator): `openPairBootstrapV1` with the response
   seed, `psk = HelloRoot`; validate responder commitment, identity,
   dependency `= helloId`, signature.
7. **Established root**: both sides
   `establishedPairRoot(HelloRoot, AcceptRoot, helloId, acceptId)`;
   `StableEdgeId`, `SessionRole` (stable-key order), `ConfirmedPairTranscriptId`.
8. **OFFER** (initiator): `RTCPeerConnection` with the injected
   `rtcConfig`; create the bootstrap data channel **before** the offer;
   `createOffer` + complete ICE gathering; SDP must be 1..32,768 UTF-8 bytes
   with exactly one SHA-256 fingerprint; body `PairTransportOfferV1` with a
   signed `StableEdgeAttemptClaimV1` (windows copied from the HELLO window
   and `helloWindow + pairControlRetentionWindows`) and candidates
   `[operation-carrier, webrtc-complete]` sorted by
   `transportOfferCandidateId`; slot `(0,1,helloId,[acceptId])`; sealed with
   `sealPairStepV1` under `EstablishedPairRoot` with a fresh persisted
   24-byte nonce; class chosen by `padPairPlaintextV1`.
9. **ANSWER** (responder): `openPairStepV1` over the single expected slot;
   validate the claim (`stableEdgeId` recompute, claimant key, signature,
   pair edge and transcript ids); `setRemoteDescription`, `createAnswer`,
   complete gathering; body `PairTransportAnswerV1` with the responder's
   matching claim, `selectedOfferCandidateId` of the `webrtc-complete`
   candidate; slot `(1,1,acceptId,[offerId])`; sealed likewise.
10. **Handoff** (initiator): open ANSWER, validate the claim match,
    `setRemoteDescription`. Both compute
    `TransportNegotiationTranscriptId`, `RendezvousChannelId`, parse both
    fingerprints from the exact SDP bytes, and once the data channel opens
    run `createSession({ transport: dataChannelTransport, role: SessionRole,
    identity, peerIdentityEd25519PublicKey, channel: { channelId:
    RendezvousChannelId, localFingerprint, remoteFingerprint }, mode:
    "nopin", pqMode })`, then `verifyDtlsFingerprints` semantics via
    `getStats()` where available. Bootstrap secrets are wiped after the
    session exists. **The tripwire is fail-closed only in the harness.** A
    genuine mismatch throws and ends the session (the peer connection
    closes; the carrier schedule runs on until the run is stopped), but an
    engine that reports no certificate statistics yields `unsupported`:
    `index.ts` emits
    `dtls-unsupported` and proceeds to `createSession` anyway, and it is
    `run.mjs` — not the library — that treats a run without `dtls-verified` on
    both pages as failed. So "DTLS verified on both sides" is a statement about
    the recorded runs, never an unconditional property of the composition.
11. **Message**: `session.encrypt(bytes)` → frames over the channel →
    `session.decrypt` on the peer; the E2E asserts byte equality both ways.

Duplicate delivery from two stores is idempotent by construction: identical
op ids merge in `mergeOperationCandidateSets` and replay in the ledger.

**The pair ledger guards half the exchange, and only half.** Fork detection
runs over the identity flights: step 4 previews and step 5 records the HELLO
slot in `pairLedger`, so a second HELLO id landing in that slot fails the edge.
`TRANSPORT_OFFER` and `TRANSPORT_ANSWER` are not recorded and not previewed
(`pairDriver.ts`, `handleIncomingOffer` and `handleIncomingAnswer`) — they are
guarded instead by being sealed under `EstablishedPairRoot`, which only a peer
that already completed HELLO/ACCEPT holds. That is not a hole, but it is not
the same property either, and the difference belongs on the record: the
prototype detects a fork at the identity slot, not at the transport slots.

### 4.7 Browser entry and E2E harness (`docs/e2e/blind-two-store/`)

- `entry.ts`: bundles the pair driver + carrier runtime + store client with
  `bun build --target=browser`, exposes `window.p2partyBlindPrototype.run({
  capabilityHex, storeOrigins, profileOverride?, rtcConfig })` returning
  progress events (`presence-published`, `peer-observed`, `hello-sent`,
  `accepted`, `offer-sent`, `answered`, `webrtc-connected`,
  `session-authenticated`, `message-verified`) plus the running
  `storeTopology`.
- `index.html`: process shim + bundle + WASM served locally with the dev
  build (same pattern as `docs/e2e/webrtc-e2e`).
- `run.mjs` (Playwright, Node): starts two store processes on 5910/5911
  with fresh key files and DBs in a temp dir, two browser contexts, one
  capability; scenarios selected by `--scenario`:
  `healthy`, `kill-a` (SIGKILL store A right after both `presence-published`),
  `withhold-a` (store A started with `P2PARTY_STORE_FAULT=withhold`),
  and `unreachable-b-for-one` (browser B is given only store A's origin —
  proves union plus backfill through browser A). Each asserts
  `message-verified` within a deadline and prints per-store request counts.
- Wire-log check: the stores run with `P2PARTY_STORE_LOG_BODIES=<path>` only
  in the harness — its own variable, separate from `P2PARTY_STORE_FAULT`,
  whose only value is `withhold` — writing every request body to a file
  **before parsing**; the harness asserts
  that neither file contains the capability, `RoomContextId`, either stable
  Ed25519 public key, or any `a=fingerprint` / `v=0` SDP substring. This is
  the only privacy statement the run supports.

### 4.8 Tests

- `tests/blindRendezvous/prototype/schemas.test.ts` — round trips and
  known-answer bytes for every new codec, generated once and pinned.
- `storeCore.test.ts` — allocation ordinals, capacity, slot bind semantics
  (stored / already-present / slot-conflict / unallocated-cover /
  window-finalized), finalization with dummies, checkpoint root equals the
  client's recomputation, chain linking across all-dummy windows, restart
  replay from persistence.
- `storeClient.test.ts` — against an in-process `Bun.serve` store: descriptor
  validation, signature rejection, chain verdicts, inert marking on a forged
  equivocating checkpoint (re-signed with the store's real key).
- `carrierRuntime.test.ts` — fixed event count per window with and without
  outbox work (object counts identical), per-store envelope separation,
  union of two divergent stores, backfill once per store, one store failing
  every request while the other carries the room, and one store *stalling*
  every request (accepted, never answered) while the other carries the room.
  Note the scope of the invariance check: `windowShape()` counts five
  hardcoded routes — token, allocation, append, checkpoint, chunk — and not
  the witness route, so it cannot see the conditional traffic of §3a item 14.
- `pairDriver.test.ts` — two in-memory drivers through a fake carrier:
  the full HELLO/ACCEPT/OFFER/ANSWER sequence with a stubbed transport
  candidate, fork detection when a second HELLO id lands in the slot,
  self-HELLO rejection, wrong-commitment rejection, claim mismatch rejection.
- E2E (§4.7) is the definition of done, per the project's rule.

## 5. Data flow

```
browser A ──(PRESENCE_A, wrapped for S1)──► store S1 ──┐
        ──(PRESENCE_A, wrapped for S2)──► store S2 ──┤ fixed scan each window
browser B ◄───────────── union by OperationId ◄──────┘
   ↓ reduce → observed presences → initiator = lower presence id
A: HELLO ──► S1,S2 ──► B opens (RoomRoot PSK) → ACCEPT ──► S1,S2 ──► A opens (HelloRoot PSK)
   both: EstablishedPairRoot
A: OFFER(SDP_A) ──► S1,S2 ──► B: ANSWER(SDP_B) ──► S1,S2 ──► A
   RTCPeerConnection ⇄ DataChannel ⇄ createSession (v4) ⇄ encrypted message
```

### What a store sees, per client, per window

Counted from `carrierRuntime.ts` — `#eventsForWindow` for the scheduled events
and `storeClient.scanWindow` for what one read expands into — at the pinned
profile, and stated as fixed and conditional rather than as one number.

**Thirteen fixed requests**, issued whether or not anything real was sent:

| Count | Request | Route | Offset in the window |
|---:|---|---|---|
| 1 | allocation-token issue | POST `…/allocation-token` | `tokenIssueOffsetMs` = 100 |
| 1 | allocation | POST `…/allocation` | `allocationRequestOffsetMs` = 700 |
| 5 | append | POST `…/append` | class 0 at 1300, 1700, 2100; class 1 at 1500, 1900 |
| 1 | checkpoint read | GET `…/checkpoint/…` | `publicReadOffsetMs` = 600 |
| 5 | chunk read | GET `…/chunk/…` | `publicReadOffsetMs` = 600 |

Five appends is Σ over the size classes of `appendSchedule.length` at one room
slot (3 + 2); five chunk reads is Σ over the size classes of
`publicChunksPerWindow` (3 + 2). Each append carries 8,192 or 73,728
ciphertext bytes plus the envelope header. The token-issue POST is part of the
fixed shape even though open mode issues no authority — a client that skipped
it would be distinguishable from one that did not (`#issueToken`).

**Two conditional requests, or none** — one witness POST and one witness GET
(`…/witness`), never one without the other. A store receives that pair in a
window exactly when the *other* store's scan of that window came back
`finalized` and neither store is inert:

| Situation | This store receives |
|---|---:|
| both stores healthy, the other's scan `finalized` | 2 |
| the other store's scan not `finalized` | 0 |
| either store inert | 0 |

Which of the two it is, is a fact about the *other* store, not about this one.
That conditioning is a cross-store status oracle and is disclosed as §3a item
14; it is the only part of this trace that is not fixed.

The descriptor GET is once per store per session, not per window. Every one of
these requests is bounded by a deadline of one delivery window
(`storeClient.ts`, `requestDeadlineMs`), so a store that accepts a connection
and never answers cannot hold the union — or this trace — open.

## 6. Error handling

- Store unreachable or signature invalid → event missed for that store;
  runtime keeps the other; `storeTopology` degrades honestly.
- Store accepts the connection and then answers nothing → the same outcome as
  above, because every request carries a deadline of one delivery window
  (`storeClient.ts`, `requestDeadlineMs`): an `unreachable` fault, no `inert`,
  no throw out of the scan, and the union completes on the other store's
  objects. Each store's read is its own handler, so the honest store's
  objects are delivered without waiting for the silent one; without the
  deadline, the silent store's scan would never settle and the witness event
  that waits for it would never finish. The path is defended in
  code and exercised by a unit test (`carrierRuntime.test.ts`, "keeps
  delivering through the other store when one stalls and answers nothing");
  **no end-to-end scenario covers it yet** — `kill-a` refuses the connection
  and `withhold` lies at full speed, so both of the harness's fault modes fail
  fast. A stall scenario for `run.mjs` is follow-up work, not done here.
- Envelope fails to open → cover, silently.
- Operation fails validation → dropped with a counter, never reduced.
- HELLO/ACCEPT authenticated but malformed → edge failed (spec: rejected
  attempt); tag/AEAD mismatch → not-this-candidate.
- Fork in the ledger → edge failed; the driver does not retry in the
  prototype (a retry requires fresh presences; documented).
- WebRTC never connects → the run fails the E2E deadline; no fallback to
  legacy signaling exists or is added.
- Store startup without `P2PARTY_STORE_PROTOTYPE=1` or without
  `P2PARTY_STORE_OPEN_ALLOCATION=1` → refuses to start with a message naming
  both flags.

## 7. Files

New: `src/blindRendezvous/prototype/{profile,storeClient,carrierRuntime,pairDriver,transportCandidates,index}.ts`,
`src/blindRendezvous/prototype/store/{storeCore,storePersistence,storeHttp,storeServer}.ts`,
`tests/blindRendezvous/prototype/*.test.ts`, `docs/e2e/blind-two-store/{entry.ts,index.html,run.mjs,README.md}`,
`docs/blind-rendezvous-two-store-prototype.md`.

Modified: `src/blindRendezvous/schemas.ts` (codecs), `derivations.ts`
(transcripts), `package.json` (`store:prototype` script),
`docs/blind-rendezvous-implementation-status.md` (B3 note), `ROADMAP.md`
(one paragraph under server-blind rendezvous), `docs/HANDOFF.md`.

Untouched: `src/index.ts`, `src/session.ts`, the Redux/RTK layer, the
signaling server, `p2party.com`.

## 8. Research extensions (FOSDEM 2027 track)

The stated objective is a FOSDEM 2027 presentation of the findings and the
implementation, and research-frontier variants are welcome. Two extensions
are planned on top of the minimum, each measurable and each labelled for
exactly what it is:

- **Client-mediated cross-store witnessing.** After a client verifies store
  A's checkpoint for window `w`, it posts a public
  `StoreWitnessRecordV1 { witnessedStoreId, deliveryProfileHash,
  ingressWindow, checkpointHash }` to every *other* store it uses, and reads
  the witness records the other stores hold about A. A record whose hash
  differs from the checkpoint A showed this client is a **split-view hint**:
  it triggers a re-fetch and is logged as `checkpoint-split-view-hint`. It
  is not a proof (the spec's conflict proof needs two checkpoints signed by
  A); it is Certificate-Transparency-style gossip with the other store as
  the gossip carrier and no witness network. Cost: one fixed POST and one
  fixed GET per other store per window, so the trace stays fixed. Records
  carry no room data.
- **Custody-breach detection on the fixed scan.** A client that holds a
  signed `stored` receipt for window `w` locates its own slot in the
  finalized chunk and compares the object hash. A mismatch is exactly the
  spec's `PublicCustodyBreachProofV1` contradiction; the prototype records
  the fault and excludes the store from availability. The `withhold` fault
  mode of the store exercises it in the E2E.
- **Latency measurement.** The E2E prints time-to-connect for
  `deliveryWindowMs ∈ {4000, 2000, 1000}` to quantify the fixed-schedule
  cost of pre-SDP admission (five dependent flights).

## 9. Open items the prototype leaves for the spec's phases

Blind-RSA allocation tokens (RFC 9474/9578; `@cloudflare/blindrsa-ts` is a
viable implementation), the reservation/trial/admission kernel and its
IndexedDB ports, persistent scheduler cursors and restart-safe outboxes,
`STORE_HINT` discovery, SP1, assurance derivation, retention garbage
collection, the frontend (B4), and every release-registry freeze.

Retention is the one of those that bites an operator immediately, so it gets a
number. Every finalized window is padded to the profile's full geometry whether
or not anything real was appended, and nothing ever deletes one. A store left
running with no traffic at all was measured at **2,763,134 bytes of state per
finalized window** (seven consecutive all-dummy windows, every row identical;
19,390,464 bytes of SQLite file for the seven). At the pinned 4,000 ms window
that is 21,600 windows a day, so **about 59.7 GB per store per day** — and the
profile's own `carrierRetentionWindows` of 160,000, roughly 7.4 days, would be
about 442 GB even once a sweep exists to enforce it. Reproduce with:

```sh
P2PARTY_STORE_PROTOTYPE=1 P2PARTY_STORE_OPEN_ALLOCATION=1 \
  P2PARTY_STORE_PORT=5931 P2PARTY_STORE_DB=/tmp/storage.sqlite \
  P2PARTY_STORE_KEY_FILE=/tmp/storage.key bun run store:prototype
# after ~25 s, stop it and read the per-window state size:
# select window, length(state) from window;
```

A stall scenario for the E2E harness (a store that accepts connections and
answers nothing) belongs on this list too: the path is defended in code and
covered by a unit test, and by no end-to-end run.
