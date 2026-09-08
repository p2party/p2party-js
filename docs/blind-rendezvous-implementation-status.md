# Blind rendezvous: implementation status and blockers

Status of the implementation of
[`spec/spec-architecture-l2-blind-rendezvous.md`](../spec/spec-architecture-l2-blind-rendezvous.md)
(v0.4-proposed) across the three repositories, as of 2026-07-28, with the
prototype additions of 2026-09-08 marked where they change a statement.

**Nothing here is a conformance claim.** The specification requires that every
acceptance criterion, vector, benchmark, deployment, and review be displayed as
`not-implemented` or `not-evaluated` until it is generated and independently
checkable. This document records what executes, not what is claimed.

## What exists

The blind-specific modules are in `p2party-js/src/blindRendezvous/`, none
exported from the package barrel:

| Module                | Owns                                                                                                            |
| --------------------- | --------------------------------------------------------------------------------------------------------------- |
| `canonicalSchema.ts`  | Descriptor-driven canonical binary codec: field order, integer widths, enum bytes, collection ordering, bounds. |
| `schemas.ts`          | Descriptors for implemented room operations, pair/non-pair payloads, store objects, and canonical Core facts.   |
| `projections.ts`      | Generated key tables and enum projections; no hand-maintained duplicate remains.                                |
| `derivations.ts`      | Domain-separated hashes, HKDF-SHA-256, room/pair/operation/carrier identifiers, and pair transcript inputs.    |
| `roomPolicyV4.ts`     | `RoomPolicyV4` validation, canonical codec, and `DEFAULT_BLIND_POLICY_V4_0`.                                    |
| `roomInviteV2.ts`     | Closed `v1 \| v2` invitation parsing, both v2 fragment forms, and the two typed errors.                         |
| `pairStepEnvelope.ts` | Schema-derived `PairStepEnvelopeV1` framing and the three exact suite-1 class targets.                          |
| `pairPlaintext.ts`    | Closed ten-body pair codec, minimal class/padding, initial slots, candidate shape/order, and v4-frame gates.    |
| `admissionPolicy.ts`  | Internal semantic-only frontend/authority policy order and bootstrap/stable-edge lease arithmetic.             |
| `operation.ts`        | Operation codec/signatures, process-private room context, active/candidate outer validation, pair-slot binding. |
| `operationPayload.ts` | Closed non-pair codecs and intrinsic validation for grant/revoke, presence/permit, leave, and store hints.      |
| `coreReduce.ts`       | Provenance-checked candidate ingress, payload reduction, historical dependency evidence, canonical Core state.  |
| `carrierEnvelope.ts`  | Envelope framing, key schedule, AAD, and object identity, over the shipped XChaCha20-Poly1305.                  |
| `publicWindow.ts`     | Bucket/chunk/checkpoint hashing, append slot mapping, and RFC 9162 inclusion verification.                      |
| `storeDescriptor.ts`  | Store/route identity, timeless authenticity and explicit-time activation, scopes, chain-start equivocation.     |
| `normativeKernel.ts`  | Registry shape validators, now consuming the generated projections.                                             |

That table names the modules documented at the 2026-07-28 snapshot; the
directory has grown since and now holds thirty-two release-candidate modules
alongside the prototype directory below.

### `src/blindRendezvous/prototype/` — the flagged prototype (2026-09-08)

Fifteen further modules, 10,508 lines, added on the branch
`feat/blind-two-store-prototype`. **The directory boundary is the flag.**
Nothing here is exported from `src/index.ts`, nothing outside the directory
imports it, and the store process refuses to start without two environment
flags. Every route and media type it defines says `prototype-v0`; those bytes
are not the frozen §4.6 route family and are not a proposal for it. The whole
artifact is described in
[`blind-rendezvous-two-store-prototype.md`](blind-rendezvous-two-store-prototype.md),
which states at length what it does not claim.

| Module                        | Owns                                                                                                                     |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `profile.ts`                  | The pinned prototype delivery profile, the wire constants, and `validateDeliveryProfileGeometry` over the §4.3 arithmetic. |
| `storeWire.ts`                | Typed strict-canonical encode/decode wrappers over the `schemas.ts` descriptors; a projection, never a second authority.  |
| `storeRoutes.ts`              | The `prototype-v0` route table and media types, shared by the browser client and the server.                              |
| `store/storeCore.ts`          | The per-window machine: allocation, append slot binding, finalization with dummies, the chunk and checkpoint chains.       |
| `store/storePersistence.ts`   | The persistence port and its in-memory implementation.                                                                    |
| `store/storeSqlite.ts`        | `bun:sqlite` persistence; a restarted store re-serves byte-identical signed objects.                                      |
| `store/storeHttp.ts`          | The `Bun.serve` handler, constant-shaped refusals, cross-origin headers, and the optional pre-parse body log.             |
| `store/storeServer.ts`        | The entrypoint, its two mandatory gate flags, and the once-chosen persisted chain start.                                   |
| `storeClient.ts`              | Descriptor validation, per-answer signature verification, checkpoint-root recomputation, chain verdicts, fault taxonomy.  |
| `carrierRuntime.ts`           | The fixed per-store schedule, the union across stores, backfill, and cover that is byte- and latency-identical to real work. |
| `pairDriver.ts`               | Presence, HELLO/ACCEPT, OFFER/ANSWER, the pair ledger, the established root, and the handoff facts.                       |
| `workKinds.ts`                | The §4.3 service-role classifier for outbox entries.                                                                     |
| `transportCandidates.ts`      | The strict SDP validator and the derived transport-candidate ordering.                                                   |
| `webrtcProvider.ts`           | The browser transport: complete-gathering offer/answer and `verifyCertificates` over `getStats()`.                       |
| `index.ts`                    | The composition and the run's event vocabulary.                                                                          |

The shared protocol-v4 frame-length/tag geometry lives in
`src/handlers/handshakeFrame.ts`; both `pairPlaintext.ts` and the existing
semantic/cryptographic parser in `handshakeCore.ts` consume it.

Two of the specification's own published constants were re-derived rather than
trusted, and both match exactly:

- `DEFAULT_BLIND_SESSION_POLICY_V1` = `5032525001040001020000…` re-encodes from
  the shipped `encodeRoomPolicyV1`;
- its published hash `87456f93…d704bb` reproduces under the shipped
  `hashRoomPolicyV1`.

The KDF is checked against RFC 5869 Appendix A.1 and A.3 vectors.

## Current Phase-0 checkpoint

The following is implemented on local `p2party-js` `master` but is not yet a
frozen or released protocol surface:

- canonical schemas, codecs, and domain-separated derivations for
  `AdmissionGrantV1`, `AdmissionRevokeV1`, `PresenceCoreV1`,
  `PresencePermitV1`, `PresenceV1`, `LeaveV1`, and
  `StoreHintOperationV1`;
- independent known-answer constants for those payloads/transcripts, generated
  once with a standalone Python standard-library reference encoder and kept
  hardcoded to detect protocol-visible drift;
- closed intrinsic validation selected by the signed non-pair operation kind,
  including capability/authority permit closure, exact intervals and semantic
  slots, pinned authority signatures, descriptor authenticity, and a separate
  pair-private/trusted-local presence-ownership check;
- a process-private `OperationValidationContext` constructed from the room
  capability and canonical policy, plus separate active-operation and bounded
  reducer-candidate gates. Public async validation snapshots caller-owned bytes
  before its first asynchronous boundary;
- `CoreRoomStateV1` canonical encode/decode and deterministic reduction of
  observed presences, effective leaves, descriptor-only store facts,
  revocation floors, capacity, pair outer IDs, and three closed fault variants.
  The codec requires a nonempty author proof, exact two-item semantic/store
  proofs, and derived `RouteId` order/uniqueness over private snapshots;
- fixed-point promotion of bounded historical presence evidence needed by a
  current cross-window `LEAVE`, while future custody and unrelated expired
  bytes remain unable to change current Core state;
- store descriptor/route validation split into timeless authenticity and
  explicit-time activation, with private snapshots and cheap lease/shape checks
  before signature work;
- the proposed `PairPlaintextV1` schema and all ten body variants, exact
  `2919/4017/69553` targets, unique zero padding, minimal class selection,
  initial pair-slot shapes, derived transport-candidate ordering, room-selected
  v4 handshake geometry, pair/identity/transcript derivations, and partial
  standalone-reference KATs;
- an explicitly untrusted semantic admission helper that fixes local
  blacklist/address-book/authority precedence, revocation/fault selection,
  grant denial mapping, and decision-lease horizons. It is not `Admit()` and
  cannot construct a trusted snapshot, custody view, provenance brand, or
  outbound authorization.

Tests cover canonical round trips and vectors, mutable-input races,
process-private provenance, delivery permutation/duplication, author
fork/quota precedence, semantic forks, cross-window dependency evidence,
store-generation forks, revocation ordering, and near-`u64` evidence overflow.
This is executable component evidence only. It does not freeze the whole Phase-0
registry, implement HPKE/pair AEAD or the trusted admission/pre-SDP boundary,
provide store wire interoperability, or constitute a conformance claim. The
independent pair vectors are deliberately partial: AC-035 still requires
deterministic independent vectors for every pair-step body before a freeze.
Answer-to-offer candidate matching, adapter-registry validation, and strict
SHA-256 SDP fingerprint parsing are also state/integration gates, not
implemented by the intrinsic candidate shape/order checks.

Verification, re-run on 2026-09-08 on the prototype branch:
`bun test tests/blindRendezvous` — **580 pass, 0 fail, 3,390 assertions across
40 files**, of which nine files are the prototype's own. Both TypeScript
configurations, targeted ESLint, and `git diff --check` also pass. (The
2026-07-28 snapshot this document was first written against reported 259 pass
across 17 files.)

## Blockers

### B1 — cleared: `carrierAeadSuite = 1` now ships

The specification freezes the carrier AEAD as XChaCha20-Poly1305
(`draft-irtf-cfrg-xchacha-03`, 32-byte key, 24-byte nonce, 16-byte tag), which
the WASM module did not export. It now does: `src/cryptography/carrierAead.c`
wraps libsodium's construction from the same pinned commit the module already
builds, and `createCarrierAeadProvider` binds it to the envelope.

The rebuilt artifact reproduces the published Appendix A.3.1 vector byte for
byte, ciphertext and tag. `libcrypto.wasm` grew from 209,081 to 210,504 bytes
and its SRI moved to
`sha384-5bfyPJcX2JVKEJA8MK+YuBYDFu6VMg8Jphdt30CQBqHI8NIQSMwP1advvY5iuzXE`,
which `wasmLoader.ts` and `libcrypto.provenance.json` record. **Any dependent
that pins the old hash — `p2party.com` vendors this package by tarball digest —
must re-vendor before it can load the new module.**

Sealing still fails closed with `CarrierAeadUnavailableError` when a build
supplies no conforming provider, so a future build that drops the export cannot
silently fall back to another construction.

### B2 — Phase 0 is not frozen, so no wire interoperability follows

Integer widths in `schemas.ts` are this artifact's _proposal_ for the Phase-0
freeze. Section 4.1 is explicit that until the binary schema, executable
kernel, claim/formal registries, HTTP protocol, default profile/planner/
resource values, allocation scheme, and compatibility hash are frozen and
vector-tested, the design is architecture-complete but not wire-interoperable —
and that implementations "shall not independently invent release bytes and call
them v0.4". No release-registry hash has been computed or published.

### B3 — the frozen store wire protocol still does not exist; a prototype one now does

**Narrowed on 2026-09-08.** This blocker used to read "the store wire protocol
is not implemented anywhere". That is no longer literally true, and the
distinction matters.

`p2party-server` still has no append, allocation, chunk, or checkpoint endpoint;
its only entrypoint is the legacy WebSocket signaling server. Nothing about the
deployed server has changed.

What now exists is a **prototype store under `prototype-v0`**, entirely inside
`src/blindRendezvous/prototype/store/`: a window machine, `bun:sqlite`
persistence, a `Bun.serve` handler and an entrypoint that refuses to start
without `P2PARTY_STORE_PROTOTYPE=1` and `P2PARTY_STORE_OPEN_ALLOCATION=1`. Two
such processes have been driven end to end by two headless browsers against a
matching browser-side client adapter, including under a killed store, a
withholding store, and a client that can reach only one of the two. That work is
described in
[`blind-rendezvous-two-store-prototype.md`](blind-rendezvous-two-store-prototype.md).

It is not the Section 4.6 route family and does not narrow B2. Its route paths
and media types say `prototype-v0` precisely so that they cannot be mistaken for
release bytes; the exact §4.6 request/response target lengths, status enum
bytes, and signature transcripts remain Phase-0 freeze items, and writing them
now would still mean inventing the exact bytes the freeze exists to fix. The
content-addressed route-family registry and parsers are still absent, so
nonempty `STORE_HINT.routes` deliberately fails closed and the prototype takes
its store origins as run options instead. The scheme-1 Privacy Pass allocation
path (Section 4.3.12) is still unimplemented: the prototype store runs open
allocation, answering `issued` with 32 zero bytes and ignoring the token, so it
carries no abuse-control, Sybil, or fairness claim at all.

Beside the client's reusable verification primitives — canonical descriptor and
route authenticity, explicit-time lease checks, store/carrier/route-instance
identity, window geometry and slot mapping, chunk and checkpoint hashing, RFC
9162 inclusion proofs, structural checkpoint validity, chain succession, and
chain-start/same-window equivocation checks — the prototype adds a client that
composes them against a live process: it recomputes the checkpoint root from the
complete chunk set, verifies the chain, and compares a signed append receipt
against the slot the finalized chunk actually published. Those are executable
component facts on a flagged prototype, not wire interoperability.

### B4 — `p2party.com` cannot reach any of this

The frontend consumes `p2party` as a hash-verified vendored tarball. These
modules are deliberately absent from the package barrel, so the current
production WebRTC correctness baseline cannot call them. Blind integration
requires a reviewed public API, a new vendored artifact/hash, and coordinated
frontend/server work; that should not be presented as interoperable before B2.

The 2026-09-08 prototype does not change this in any respect. It is reached only
from a test harness page that bundles the directory directly; the barrel, the
`p2party/session` subpath, the vendored tarball and `connect()`'s rejection of
every rendezvous mode other than `legacy-signaling` are all untouched.

## Defects found by adversarial review and fixed

A four-dimension adversarial review of this code against the specification
produced thirteen findings; four were refuted on verification and nine were
confirmed and fixed:

- the `text` encoder was non-injective — an unpaired surrogate is NFC-stable
  but `TextEncoder` rewrites it to U+FFFD, so two distinct strings encoded to
  identical bytes. It now rejects ill-formed UTF-16;
- `optional(optional(T))` gave `null` two encodings; nesting is now refused at
  descriptor construction;
- `carrierKey` did not check the `RoomRoot` length, so an empty PRK would have
  produced a key derived under a zero-filled HMAC key;
- `formalAssumptionSetHash` restated an array descriptor that `schemas.ts`
  already owns;
- `CoreReduce` never verified author-chain contiguity or predecessor linkage,
  so an author could publish sequence 5 alone and have it reduce as though
  0–4 existed;
- `roomCapacityState` was derived from a local storage cap, which Section 4.7
  forbids the reducer from reading; the interim reducer marked it pending, and
  the current reducer derives it from the active presence count;
- the authority chain accepted non-revocation operations under the pinned
  authority key;
- the fault array sorted by a nested proof ID rather than by its canonical
  identifying tuple;
- `resolveInviteRoomPolicy` returned the module singleton, whose
  `sessionPolicyV1` bytes are writable despite `Object.freeze`, so any holder
  could silently repoint every later bare-v2 invitation at a different room.

An earlier defect was caught by the property suite itself: author-quota
counting used array entries rather than distinct operations, so a carrier
redelivering one operation could forge an overquota fault against an honest
author. Each fix has a regression test.

A continuation review found and fixed one additional reducer defect: the
then-named `mergeOperationSets()` compared only `authorSignature` when two
entries claimed one `OperationId`. The current
`mergeOperationCandidateSets()` compares the complete canonical signed
operation, so a same-signature/different-body collision cannot pass as an exact
duplicate. That increment also added the missing
pinned-authority/non-revocation regression. Its interim five-field pending
payload contract has since been replaced by the concrete canonical Core
projections described above.

A second continuation closed the room-visible pair-envelope boundary without
claiming the still-absent pair protocol:

- the envelope codec derives its 1,161-byte bootstrap and 63-byte established
  overheads from the canonical schema rather than copying a target table;
- the three permitted suite-1 forms derive exact ciphertext/plaintext targets
  `2935/2919`, `4033/4017`, and `69569/69553`; class-1 bootstrap, alternate
  header/nonce states, non-empty operation padding, and noncanonical encodings
  fail closed;
- outer operation validation recomputes the pair semantic slot from the decoded
  routing tag and reuses that one decode for the asynchronous check;
- `coreReduce()` no longer accepts structurally fabricated
  `{operationId, operation}` pairs. Its sole ingress snapshots the operation
  and validation context before the first `await`, performs bounded candidate
  outer validation, derives the ID, and records process-local provenance in a
  private `WeakMap`. Object spread, structured clone, and post-validation
  typed-array mutation are rejected before reduction.

The pair-plaintext continuation then fixed two review findings before this
checkpoint:

- v4 HELLO framing is validated against the immutable room-selected PQ mode,
  rather than accepted when it matches any registered ML-KEM length; and
- the canonical outer prebinding/binding, flight-slot, and bootstrap-info
  constructors reject broad-enum values that cannot exist in the protocol.

One reported tuple-ordering defect was refuted: Section 4.10 makes the
lexicographically lower presence-operation ID the rendezvous initiator, and
Section 4.11 orders the tuple `[initiator, responder]`, so strict ascending
order is required. The partial Python-reference pair KATs do not satisfy the
remaining AC-035 every-body vector gate and are not described as a freeze.

## What is deliberately not implemented

- **Pair cryptography and edge-local state.** `PairPlaintextV1` now has a
  proposed codec, but there is no RFC 9180 hybrid HPKE implementation, pair
  AEAD seal/open, one-use routing-tag key schedule, exact predecessor-ID/state
  transition, answer-to-offer/adapter/fingerprint validation, durable fork
  ledger, or persist-before-publish outbox. A
  `PAIR_STEP` in `activePairOuterOperationIds` therefore remains an outer Core
  fact, not an admitted edge.
- **The trusted admission kernel and authority snapshot.** The semantic policy
  order and lease arithmetic execute, but `VerifyAdmissionContext`,
  `CaptureTrustedAdmissionSnapshot`, protected authority custody/view
  construction, private provenance brands, `Admit()`, atomic persistence and
  action recheck wrappers do not. The semantic helper's caller-supplied
  structural inputs are explicitly not authorization. No SDP/ICE promotion is
  gated by this code yet.
- **Nonempty `STORE_HINT` routes.** Descriptor-only hints validate and reduce to
  source facts. Any nonempty route sequence fails closed because the
  content-addressed route-family registry/parsers are absent. Derived
  `RouteId` ordering is implemented and vector-tested, and store-route
  authenticity primitives exist independently; neither is permission to accept
  an unknown route family.
- **Store wire profiles, allocation, and append.** The reference HTTP suffixes,
  media types, fixed target lengths, status/signature bytes, delivery profile
  registry, Privacy Pass issuance/redemption, and append admission signature are
  not frozen, and the release forms of them are not implemented. The
  `prototype-v0` route family and its fixed client schedule execute (B3), under
  their own prefix and behind two environment flags, and are neither
  interoperable with the frozen family nor a proposal for it.
- **SDK/frontend/server integration.** The blind modules remain outside the
  package barrel; no frontend room flow, pre-SDP gate, store transport, peer
  store role, or backend blind endpoint consumes them. The existing WebRTC path
  is only the proven correctness baseline of the shipped release.
- **Claim evaluation.** `normativeKernel.ts` validates artifact _shape_ only. It
  runs no predicate, verifies no evidence, and exposes no positive-wording
  authorizer. Kernel module 8 does not exist.
- **Later delivery and assurance layers.** Sparse planning, additive/multi-peer
  stores, transport handoff, L3 adapters, shutdown-survival demonstrations, and
  the measurement/formal/external-review programme remain future work.

## Labels this work does not earn

Not S1, not R2-BEC, not SP1, not L3 control compatibility, not
shutdown-surviving anything, and neither PQ healing nor PQ authentication. Each
of those requires evidence that does not exist: a deployed store, multi-client
E2E, browser and non-IP runs, measured cohorts, classifier experiments, formal
results, and external review. The only defensible statements today are that
specific deterministic components execute and that their tests pass.

The 2026-09-08 prototype adds one more defensible statement and no label: those
components **compose**, in two real browsers against two prototype store
processes with no signaling server, far enough to open a WebRTC edge with DTLS
verified on both sides and to carry a protocol-v4 session over it. It is a
demonstration of a shape; it establishes no property. It is not a deployed
store, two store processes on one laptop are one fault domain, both stores still
see every client address, and the run's privacy statement is about a searched
corpus of request bodies on that run and nothing else.

The specification now also records two successor boundaries without changing
the executable v0.4 surface:

- optional proof-of-work is future store-scoped, room-blind
  allocation-token-issuance costing only; it is not personhood, room
  admission, blacklist enforcement, store independence, BFT, or fairness;
- the preferred PQ-authentication candidate is both-required
  Ed25519 + ML-DSA-65 over one exact shared transcript in a fresh
  v3/`RoomPolicyV5` successor. V0.4 remains Ed25519-authenticated and no PQ
  successor schema is implemented.
