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
  `prototype-v0`. Nothing here is interoperable with, or a proposal for, the
  frozen §4.6 route family.
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
  appends, finalize all-dummy chunks). Script: `bun run store:prototype`.

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
Every signed response is verified under that key or rejected.

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
- at `publicReadOffsetMs`: checkpoint + all chunk reads for `w-1`.

Missed events are missed (no same-window retry). Outbox: operations queue
with their `ServiceWorkKindV1`; role mapping and ordering follow
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
    session exists.
11. **Message**: `session.encrypt(bytes)` → frames over the channel →
    `session.decrypt` on the peer; the E2E asserts byte equality both ways.

Duplicate delivery from two stores is idempotent by construction: identical
op ids merge in `mergeOperationCandidateSets` and replay in the ledger.

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
- Wire-log check: the stores run with `P2PARTY_STORE_FAULT=logbodies` only
  in the harness, writing every request body to a file; the harness asserts
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
  every request while the other carries the room.
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

Stores see, per client per window: one allocation, five appends of
8,192 or 73,728 ciphertext bytes plus headers, five chunk reads and one
checkpoint read — regardless of whether anything real was sent.

## 6. Error handling

- Store unreachable or signature invalid → event missed for that store;
  runtime keeps the other; `storeTopology` degrades honestly.
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
