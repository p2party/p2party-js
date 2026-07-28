# Blind rendezvous: implementation status and blockers

Status of the implementation of
[`spec/spec-architecture-l2-blind-rendezvous.md`](../spec/spec-architecture-l2-blind-rendezvous.md)
(v0.4-proposed) across the three repositories, as of 2026-07-28.

**Nothing here is a conformance claim.** The specification requires that every
acceptance criterion, vector, benchmark, deployment, and review be displayed as
`not-implemented` or `not-evaluated` until it is generated and independently
checkable. This document records what executes, not what is claimed.

## What exists

All of it in `p2party-js/src/blindRendezvous/`, none of it exported from the
package barrel:

| Module                | Owns                                                                                                            |
| --------------------- | --------------------------------------------------------------------------------------------------------------- |
| `canonicalSchema.ts`  | Descriptor-driven canonical binary codec: field order, integer widths, enum bytes, collection ordering, bounds. |
| `schemas.ts`          | Descriptors for the Section 4.0–4.5 objects implemented so far.                                                 |
| `projections.ts`      | Generated key tables and enum projections; no hand-maintained duplicate remains.                                |
| `derivations.ts`      | Domain-separated hashes, HKDF-SHA-256, and the room/stable-peer/operation/carrier identifiers.                  |
| `roomPolicyV4.ts`     | `RoomPolicyV4` validation, canonical codec, and `DEFAULT_BLIND_POLICY_V4_0`.                                    |
| `roomInviteV2.ts`     | Closed `v1 \| v2` invitation parsing, both v2 fragment forms, and the two typed errors.                         |
| `pairStepEnvelope.ts` | Schema-derived `PairStepEnvelopeV1` framing and the three exact suite-1 class targets.                          |
| `operation.ts`        | `AuthenticatedRoomOperationV1` codec, outer validation, pair-slot binding, and Ed25519 signing/verification.    |
| `coreReduce.ts`       | Validated-operation ingress, set union, and deterministic outer reduction with author faults.                   |
| `carrierEnvelope.ts`  | Envelope framing, key schedule, AAD, and object identity, over the shipped XChaCha20-Poly1305.                  |
| `publicWindow.ts`     | Bucket/chunk/checkpoint hashing, append slot mapping, and RFC 9162 inclusion verification.                      |
| `normativeKernel.ts`  | Registry shape validators, now consuming the generated projections.                                             |

Two of the specification's own published constants were re-derived rather than
trusted, and both match exactly:

- `DEFAULT_BLIND_SESSION_POLICY_V1` = `5032525001040001020000…` re-encodes from
  the shipped `encodeRoomPolicyV1`;
- its published hash `87456f93…d704bb` reproduces under the shipped
  `hashRoomPolicyV1`.

The KDF is checked against RFC 5869 Appendix A.1 and A.3 vectors.

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

### B3 — the store wire protocol is not implemented anywhere

`p2party-server` has no append, allocation, chunk, or checkpoint endpoint; its
only entrypoint is the legacy WebSocket signaling server.

The client can now verify a store end to end short of the wire protocol: its
identity and routes (Section 4.2), its window geometry and slot mapping, its
chunk and checkpoint hashing, RFC 9162 inclusion proofs, structural checkpoint
validity, chain succession, and both chain-start and same-window equivocation
(Section 4.3).

What remains is the Section 4.6 HTTP route family itself — and its exact
request/response target lengths, status enum bytes, and signature transcripts
are Phase-0 freeze items (B2). Writing them now would mean inventing the exact
bytes the freeze exists to fix. The scheme-1 Privacy Pass allocation path
(Section 4.3.12) is likewise unimplemented: it needs the frozen allocation
registry, including the RFC 9578 token bytes and issuance vectors.

### B4 — `p2party.com` cannot reach any of this

The local frontend release candidate vendors `p2party@0.14.4` as a verified
tarball; the coordinated production deployment is still pending. These modules
are deliberately absent from the package barrel. No frontend change is possible
until the API is exported and re-vendored, which should not happen before B2.

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
  forbids the reducer from reading; it is now listed as pending, since the
  specification derives it from the active presence count;
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

A continuation review found and fixed one additional reducer defect:
`mergeOperationSets()` compared only `authorSignature` when two entries claimed
one `OperationId`. It now compares the complete canonical signed operation, so
a same-signature/different-body collision cannot pass as an exact duplicate.
The same increment added the missing pinned-authority/non-revocation regression
and made the five pending payload projections an exact test contract.

A second continuation closed the room-visible pair-envelope boundary without
claiming the still-absent pair protocol:

- the envelope codec derives its 1,161-byte bootstrap and 63-byte established
  overheads from the canonical schema rather than copying a target table;
- the three permitted suite-1 forms derive exact ciphertext/plaintext targets
  `2935/2919`, `4033/4017`, and `69569/69553`; class-1 bootstrap, alternate
  header/nonce states, non-empty operation padding, and noncanonical encodings
  fail closed;
- `validateOperation()` recomputes the pair semantic slot from the decoded
  routing tag and reuses that one decode for the asynchronous check;
- `coreReduceOuter()` no longer accepts structurally fabricated
  `{operationId, operation}` pairs. Its sole ingress snapshots the operation
  and validation context before the first `await`, performs complete current
  outer validation, derives the ID, and records process-local provenance in a
  private `WeakMap`. Object spread, structured clone, and post-validation
  typed-array mutation are rejected before reduction.

## What is deliberately not implemented

- **Payload-level reduction.** `coreReduceOuter` derives the active operation
  set, pair-step projection, faults, and `operationsDigest`. It names
  `observedPresences`, `effectiveLeaveOperationIds`, `storeCatalogFacts`, and
  `revocationFloors` as pending rather than returning empty arrays that would
  read as observations. These need the Sections 4.2/4.8/4.9 nested payload
  codecs. This is not merely mechanical: `PairPlaintextV1` and its closed body
  union have no codec; `STORE_HINT` orders routes by derived `RouteId`, which
  the current generic array descriptor cannot express; and timeless
  store-signature validation must be split from absolute route-lease evaluation
  before core reduction can reuse it.
- **Closed operation validation.** `validateOperation()` currently proves the
  outer canonical frame, room/window/lifetime/class/dependency shape, and
  Ed25519 signature. For `PAIR_STEP` it additionally proves the canonical
  envelope/class/header state and routing-tag semantic slot. It does not yet
  open pair AEAD or prove the decrypted minimal class, pair sequence,
  pair predecessor, body discriminator, or one-use routing tag; the other
  operation kinds still lack their nested canonicality, interval, target,
  store-signature, and authority-signature checks. Consequently the current
  `activeOperationIds` is an outer-framed candidate projection, not yet the
  specification's complete `OuterValidOperationSet`.
- **Admission kernel.** Section 4.8 now names an explicit
  `AdmissionEvaluationInputV1`, versioned decision/pair leases, the exact lease
  minimum, and a validated atomic authority view. Code still waits for Phase 0
  to freeze the grant codec and the sole authority-view/custody constructor;
  no caller-supplied availability boolean may become a security decision.
- **Claim evaluation.** `normativeKernel.ts` validates artifact _shape_ only. It
  runs no predicate, verifies no evidence, and exposes no positive-wording
  authorizer. Kernel module 8 does not exist.
- **Allocation and append.** Scheme-1 Privacy Pass issuance, redemption, the
  append admission signature, and the fixed client schedule are not
  implemented; they depend on the frozen allocation registry.
- **Everything in Phases 2–6.** Presence, admission, the sparse planner,
  transport handoff, additive stores, L3, and the measurement/review programme
  are untouched.

## Labels this work does not earn

Not S1, not R2-BEC, not SP1, not L3 control compatibility, not
shutdown-surviving anything, and neither PQ healing nor PQ authentication. Each
of those requires evidence that does not exist: a deployed store, multi-client
E2E, browser and non-IP runs, measured cohorts, classifier experiments, formal
results, and external review. The only defensible statements today are that
specific deterministic components execute and that their tests pass.

The specification now also records two successor boundaries without changing
the executable v0.4 surface:

- optional proof-of-work is future store-scoped, room-blind
  allocation-token-issuance costing only; it is not personhood, room
  admission, blacklist enforcement, store independence, BFT, or fairness;
- the preferred PQ-authentication candidate is both-required
  Ed25519 + ML-DSA-65 over one exact shared transcript in a fresh
  v3/`RoomPolicyV5` successor. V0.4 remains Ed25519-authenticated and no PQ
  successor schema is implemented.
