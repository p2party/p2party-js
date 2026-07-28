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

| Module               | Owns                                                                                                            |
| -------------------- | --------------------------------------------------------------------------------------------------------------- |
| `canonicalSchema.ts` | Descriptor-driven canonical binary codec: field order, integer widths, enum bytes, collection ordering, bounds. |
| `schemas.ts`         | Descriptors for the Section 4.0–4.5 objects implemented so far.                                                 |
| `projections.ts`     | Generated key tables and enum projections; no hand-maintained duplicate remains.                                |
| `derivations.ts`     | Domain-separated hashes, HKDF-SHA-256, and the room/operation/carrier identifiers.                              |
| `roomPolicyV4.ts`    | `RoomPolicyV4` validation, canonical codec, and `DEFAULT_BLIND_POLICY_V4_0`.                                    |
| `roomInviteV2.ts`    | Closed `v1                                                                                                      | v2` invitation parsing, both v2 fragment forms, and the two typed errors. |
| `operation.ts`       | `AuthenticatedRoomOperationV1` codec, outer validation, and Ed25519 signing/verification.                       |
| `coreReduce.ts`      | Set union and deterministic outer-layer reduction with author fork/overquota faults.                            |
| `carrierEnvelope.ts` | Envelope framing, key schedule, AAD, and object identity, over the shipped XChaCha20-Poly1305.                  |
| `publicWindow.ts`    | Bucket/chunk/checkpoint hashing, append slot mapping, and RFC 9162 inclusion verification.                      |
| `normativeKernel.ts` | Registry shape validators, now consuming the generated projections.                                             |

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

The client half of Section 4.3 now exists (`publicWindow.ts`), so a store's
geometry, slot mapping, chunk and checkpoint hashing, and inclusion proofs are
all verifiable. What is still missing on the server side is the Section 4.6
HTTP route family and the Section 4.2 `StoreDescriptorV1` that every
descriptor-bound predicate joins against — and the exact request/response
target lengths, status enum bytes, and signature transcripts those routes need
are Phase-0 freeze items (B2). Writing them now would mean inventing the exact
bytes that the freeze exists to fix.

### B4 — `p2party.com` cannot reach any of this

The frontend vendors `p2party@0.14.3` as a verified tarball, and these modules
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

## What is deliberately not implemented

- **Payload-level reduction.** `coreReduceOuter` derives the active operation
  set, pair-step projection, faults, and `operationsDigest`. It names
  `observedPresences`, `effectiveLeaveOperationIds`, `storeCatalogFacts`, and
  `revocationFloors` as pending rather than returning empty arrays that would
  read as observations. These need the Section 4.2/4.9 nested payload codecs.
- **Claim evaluation.** `normativeKernel.ts` validates artifact _shape_ only. It
  runs no predicate, verifies no evidence, and exposes no positive-wording
  authorizer. Kernel module 8 does not exist.
- **Descriptor-bound checkpoint predicates.** `StructurallyValidCheckpoint`,
  the complete `ChainValidSuccessor`, and the three fault proofs need
  `StoreDescriptorV1` from Section 4.2. `publicWindow.ts` implements only the
  parts that need no descriptor and names the rest in its module docstring.
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
