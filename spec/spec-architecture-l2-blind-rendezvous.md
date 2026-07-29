---
title: L2/L3 Capability-Sealed Eventually Consistent Rendezvous Architecture
version: 0.4-proposed
date_created: 2026-07-24
last_updated: 2026-07-28
owner: P2Party maintainers
tags:
  - architecture
  - privacy
  - rendezvous
  - censorship-resistance
  - disruption-tolerance
  - post-quantum
---

# Introduction

This specification defines the proposed blind rendezvous and signaling control
plane for p2party rooms. Its shared/core room-event source of truth is a
bounded set of immutable, capability-sealed, end-to-end-authenticated room
operations interpreted under one immutable room policy.
Servers, authenticated peer links, delay-tolerant stores, local radio adapters,
and removable-media bundles are interchangeable carriers of those operations;
none is a room, roster authority, sequencer, conflict winner, or cryptographic
endpoint.

That scope matters: immutable room/release policy, local frontend admission
and carrier policy, the private pair ledger/v4 outbox, and assurance evidence
are separate authoritative scoped facts because erasure, local trust, and
measurements cannot safely be reconstructed from the shared operation set.
Within each scope there is one SSOT and every cache/projection is derived from
it; “one SSOT” never means one database object for all security domains.

The release makes those scoped sources mechanically checkable. The canonical
binary schema owns bytes and bounds; one content-addressed executable kernel
owns the closed deterministic validators, reducers, schedulers, assurance
derivations, and claim evaluator; one claim registry owns claim composition and
semantic wording IDs; and one formal-obligation registry binds proofs and
bounded model results to the exact release. Generated TypeScript, protocol
tables, UI claim keys, and whitepaper tables are projections, not additional
authorities. A disagreement fails the release.

The S1 deployment target and conformance package require one conforming
store-only server; once its acceptance evidence passes, that is a complete
functional S1 deployment. A client may add further compatible servers or
non-IP carriers without changing the room identifier, room policy, pair
transcript, or existing session.
Clients publish to and reconcile from every locally active carrier, union
valid operations, and deterministically derive the same core room state only
when every still-required operation reaches the named correct participants
before retention expires and reconciliation continues. Local admission and
connection planning remain intentional frontend projections. There is no
server-to-server consensus or federation protocol to operate.

An end-user device may perform carrier work without acquiring protocol
authority. It may expose the exact same conforming public-store interface as
the reference server, or an existing authenticated peer contact may exchange
bounded inventories and store-carry-forward operations as an opportunistic
bridge. “Peer-hosted” is a deployment fact, not a new wire kind, room role,
roster, signaling protocol, or trust shortcut. A peer-hosted public store earns
only the guarantees evidenced for any other store; a contact bridge contributes
only the path and custody actually measured while it remains usable.

Rooms remain capability-scoped security and topology domains. A public
delivery cohort is only potential shared cover infrastructure; anonymity or
traffic-analysis protection is claimed only for the exact measured cohort and
bearer. Its clients do not become one room and never become automatic
connection candidates. Inside one room the default local connection planner
is a deterministic bounded-degree sparse overlay, not a profile-wide or
room-wide full mesh. The planner is an availability accelerator, not room
identity or convergent room state. Each accepted edge owns an independent
protocol-v4 session and post-quantum-healing state.

The reference fixed-scan construction underpinning the L2 target and access
privacy claim uses a targetless append-only cohort log and fixed public
full-chunk reads. It needs no private-write primitive: there is no room,
recipient, mailbox, or index in a server request. This moves cost from
cryptographic servers to cohort-wide bandwidth and client trial decryption.
Optional OMR or PIR retrieval may accelerate the same immutable log only after
separate review; it never becomes authoritative state.
Each finalized public window additionally has one profile-wide signed
checkpoint. Existing signed append results become bounded custody promises;
conflicting checkpoints or a committed wrong object produce portable
room-blind fault evidence. Checkpoints detect signed misbehavior after
evidence meets, but neither force publication nor create consensus.

The same operation codec and reducer are normative for L3 disruption-tolerant
operation in this release. Here “L3” is a p2party availability profile, not
OSI Layer 3. It permits asynchronous store-carry-forward exchange without DNS,
HTTP, TCP, UDP, or IP. L3 preserves content security and supports
bounded-horizon conditional convergence under the delivery assumptions in
Section 1.6, but it earns an L2 traffic-analysis label only when its bearer
independently satisfies the L2 cover and observer assumptions.

An optional SP1 profile strengthens only the public-store source claim. It
requires a prewarmed response-independent fixed trace through a registered,
measured batching/mixing mechanism and fails closed before any direct or
unregistered store request. SP1 does not follow from using two stores, OHTTP,
Tor, or any named transport; it is asserted only for the exact corruption,
observer, cohort, interval, topology/selection mass, cumulative linkable-volume
budget, fragmentation/tagging model, and classifier evidence that passes its
predicate.

The user-facing invitation flow remains one action: `generateRoomInvite()`
produces one capability fragment, the user copies one `/r` link or QR code,
and `joinRoom(invite)` joins it. Blind rendezvous uses a new
`v2.<base64url>` fragment so an old `v1` link is never silently reinterpreted.
The default form stays short; the existing advanced-room flow gets a
policy-bearing v2 fragment so its PIN prompt, PQ choice, and cover choice
survive sharing without putting either the capability or policy in an HTTP
query. Delivery profiles and initial stores come from the same frontend
defaults/options that choose today's signaling server; extra stores are local
learned availability state and are not appended to the room link.

SDP, ICE, stable identity bundles, protocol-v4 handshake records, and
post-quantum control frames are never protected only by the shared room
capability. They are double sealed for their exact pair. Strict rooms require
a presence-level address-book proof or authority permit before the first
identity flight; every room then applies its frontend-governed allowlist,
blacklist, and any room-authority admission grant before SDP. Consequently, a
denied capability holder cannot decrypt another pair's SDP, even when it
colludes with the only server. Open and denylist-only rooms do not hide the
first revealer's identity from an unknown capability holder selected as a
candidate; they still withhold SDP until bilateral admission.

This is a proposed architecture, not a shipped property. The current runtime
continues to reject `blind-meeting-point`; no UI, API, paper, or README may
claim conformance until the release gates in this document pass.
V0.4 also remains classically authenticated. A PQ-authenticated successor is a
new invitation, room-policy, identity, operation, store/contact
authentication, and session version with a fresh room context; this document
defines its non-downgrade and migration boundary but assigns no successor
suite numbers and grants it no v0.4 claim.

## 1. Purpose & Scope

### 1.1 Purpose

The implementation shall replace explicit server-side room registration,
server-issued peer identifiers, authoritative roster snapshots, and addressed
SDP/ICE forwarding with:

1. one canonical room-operation codec;
2. one associative, commutative, and idempotent merge rule;
3. one deterministic reducer;
4. one small bearer-neutral carrier boundary;
5. one frontend-owned peer and carrier admission boundary; and
6. the existing independently persisted protocol-v4 session per accepted
   pair.

The reference server accepts opaque fixed-size objects into public profile
windows and returns immutable public chunks. Every room in the profile uses
the same public buckets. Clients, not servers, decrypt, authenticate,
deduplicate, resolve explicit protocol slots, enforce admission, select sparse
neighbors, and bridge retained operations to newly added carriers.

### 1.2 Normative scope

This specification covers:

- the existing `/r`, fragment-only, 256-bit-capability invitation UX and
  codec;
- the byte-frozen default policy assigned to the capability-only v2 invite
  and the canonical policy-bearing v2 variant used by today's advanced-room
  sharing flow;
- canonical `RoomPolicyV4` and `DeliveryProfileV1` objects;
- one-server cold deployment, client-additive multi-store operation,
  peer-hosted public stores, and authenticated peer bridges;
- targetless public cohort append and full-chunk reconciliation;
- one room-blind signed public-window checkpoint chain, append-custody
  promises, and portable signed-fault proofs;
- capability-separated rooms and fixed concurrent room slots;
- canonical immutable operations and deterministic convergence;
- bounded retention, replay, fork, dependency, compaction, and garbage
  collection rules;
- locally governed server allowlists, denylists, compatibility checks, safe
  discovery, route leases, and automatic retained-operation backfill;
- locally governed peer address-book-only mode and blacklist behavior;
- optional room-authority-signed short-lived admission grants;
- strict-mode presence eligibility proofs and one-use authority permits;
- a pre-SDP pair identity gate and pair-private SDP/ICE;
- a local bounded-degree connection planner whose default is a deterministic
  sparse room overlay;
- typed WebRTC and non-WebRTC transport candidates;
- bearer-neutral online and store-carry-forward carrier contracts;
- a required non-IP portable-bundle reference carrier;
- protocol-v4 hybrid handoff and pair-scoped `OFFER → ADVANCE → ACK`
  post-quantum healing over unordered eventual delivery;
- explicit application-layer target-privacy, source-metadata, traffic-shape,
  consistency, censorship-resistance, and disruption-tolerance boundaries;
- an optional fail-closed SP1 bounded measured public-store source-
  unlinkability package;
- one executable deterministic kernel, compiled claim/evidence registry,
  formal-obligation registry, implementation-refinement boundary, and
  generated projections;
- the version/migration/non-downgrade boundary for a separately specified
  PQ-authenticated successor, without assigning or enabling its suites; and
- release-blocking correctness, privacy, performance, recovery, and external
  review gates.

### 1.3 Non-goals

- Hiding a direct transport address from the peer using that transport.
- Treating possession of a room capability as proof of one person, one
  device, or one presence.
- Recognizing the same human after they replace every cryptographic identity.
  A key blacklist blocks exact identities; a strict allowlist or
  authority-signed grant is required to reject unissued replacement keys.
- Providing instantaneous globally consistent revocation during an
  unbounded partition. Local frontend denial is immediate; distributed policy
  convergence is conditional on delivery and short grant expiry bounds stale
  authority.
- Promising a finite proof that an asynchronous roster is globally complete.
- Hiding the roster from a capability holder that is admitted to the room.
- Hiding room-level plaintext, pseudonymous presence commitments, or pair
  activity metadata from a malicious client that possesses the capability.
- Hiding the first identity flight from an arbitrary selected capability
  holder in an open or denylist-only room. Strict presence proofs or anonymous
  credentials are required for that stronger property.
- Hiding all source, location, contact, or timing metadata from every bearer.
- Calling a unique self-hosted store a large anonymity cohort.
- Claiming that adding servers automatically improves privacy. It primarily
  adds delivery paths and may add observers.
- Treating a signed checkpoint, append receipt, or fault proof as delivery,
  global-completeness, non-omission, or consensus evidence. A silent store
  remains an availability failure.
- Treating SP1 as protection against a global observer, long-horizon
  intersection outside its exact volume/model scope, a compromised endpoint,
  or an entry operator/local ISP observing that endpoint.
- Claiming one server tolerates that server being blocked, seized, or
  maliciously silent.
- Claiming any finite transport set is unconditionally uncensorable.
- Treating a transient peer contact, browser tab, cache, or co-located process
  as durable store custody, an independent fault domain, or first-contact
  discovery without the corresponding protocol and evidence.
- Defining the application-message data plane in v0.4. This specification
  carries rendezvous, transport setup, reconciliation, and pair-control
  records. A separately versioned sparse-room data-plane contract is a
  production dependency, not an extension of this control log; application
  data over sparse or L3 paths requires its own routing, confidentiality,
  deduplication, retry, receipt, watermark, and old-root-retention rules.
- Inventing a new AEAD, signature, PAKE, KEM, hybrid combiner, OMR, PIR,
  credential, or ratchet primitive.
- Silent fallback to legacy signaling, an unsealed room token, plaintext
  namespaces, or classical-only session establishment.
- Relabelling a v0.4 invitation, room, Ed25519 identity, authority, store,
  contact session, history, or v4 edge as PQ authenticated. The successor
  requires a disjoint version and fresh room context.

### 1.4 Specification, implementation, and evidence boundary

This document is a normative protocol and architecture contract. It specifies:

- canonical inputs, wire objects, domain separation, state transitions, and
  deterministic reduction rules;
- security invariants and the assumptions under which each claim is valid;
- frontend/backend responsibility boundaries and sources of truth;
- resource and failure behavior needed for interoperable safe
  implementations; and
- acceptance criteria and evidence that a future implementation must produce.

It does **not** demonstrate that those properties currently execute, fix a
database/module layout where interoperability does not require one, substitute
pseudocode for the canonical binary codec, or turn an acceptance criterion into
a passing test result. Before Phase 0 freezes artifacts, type declarations and
equations labelled canonical are the proposed data/derivation contracts. A
conforming release then has this closed scoped authority split:

1. the canonical binary schema is the SSOT for bytes, fields, enums, widths,
   collection order, and bounds;
2. `ExecutableRendezvousKernelManifestV1` binds the pure modules that are the
   SSOT for the named deterministic predicates, transitions, scheduler, and
   reducers;
3. `ClaimRegistryV1` is the SSOT for claim prerequisites, evidence kinds,
   formal obligations, states, and semantic wording IDs;
4. `FormalObligationRegistryV1` defines proof statements and scopes, while
   signed proof results are evidence rather than another semantics source; and
5. this document remains the SSOT for architectural ownership, threat scope,
   mandatory artifacts, and requirements not generated from those closed
   machine sources.

Generated TypeScript types/codecs, fixtures, protocol tables, frontend claim
keys, whitepaper tables, and API constants are projections. A conflict among
scoped sources or projections is a release failure; no precedence rule silently
chooses one. Interface and transaction sketches still define observable
atomicity and ownership, not mandatory filenames, classes, or frameworks.
Implementations may choose any internal structure that refines the frozen
kernel and preserves specified bytes, transitions, bounds, and behavior.

All deterministic vectors, benchmarks, browser/bearer runs, deployments,
formal models, audits, commit provenance, and paper claims named below are
future conformance evidence. Until generated and independently checkable, they
shall be displayed as `not-implemented` or `not-evaluated`, never inferred from
the prose. The implementing pass may refine an underspecified mechanism only
by revising this versioned specification first; code is not an undocumented
second source of protocol truth. The initial non-public TypeScript registry
scaffold named in Section 1.5 is therefore implementation preparation only; it
does not become canonical until the schema, vectors, manifest, and AC-047/048
checks freeze it.

### 1.5 Existing three-repository baseline and production delta

This baseline is a static source audit updated 2026-07-28, not execution or
conformance evidence. The inspected workspace packages identify the SDK as
0.14.4 while the public npm `latest` observed during the audit was older; the
public release and workspace state shall not be conflated. No commit is pinned
in this proposal, and existing local changes in sibling worktrees are not
attributed to a release.

The repository boundary is:

| Repository       | Normative product ownership                                                                                                               |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `p2party-js`     | Protocol/client SDK, codecs, cryptography, room/session state, persistence, public API, carrier adapters.                                 |
| `p2party.com`    | `/r` route, creation/join/copy/share/QR UX, frontend allow/deny and store policy, assurance presentation, privacy/TOS/marketing copy.     |
| `p2party-server` | Legacy signaling during migration and the new public fixed-store service, quotas, immutable chunks, retention, deployment, observability. |

The current source already supplies valuable substrate:

- 32-byte capabilities; compact, v1, word, and legacy invitation conversion;
- the exact immutable 32-byte `RoomPolicyV1` session-policy codec, including the reserved
  blind rendezvous enum;
- the bearer-neutral two-party `HandshakeTransport`/`p2party/session`
  boundary;
- interactive 3DH plus ML-KEM-512/768/1024, optional CPace, cross-signed
  X25519 identities, triple confirmation, independent Double Ratchets, and
  atomic per-edge persistence;
- the direct-edge `OFFER → ADVANCE → ACK` PQ-healing machine with exact
  65,490-byte frames, durable outbox/replay state, and scheduled direct-edge
  cover;
- address-book, blacklist, and known-peer frontend controls with several
  honest-client fail-closed checks;
- a mature `/r#v1...` one-link, copy/share/QR/universal-link frontend flow;
  and
- a deployable legacy signaling service shell with TLS/proxy deployment,
  bounds, health/version surfaces, PostgreSQL migrations, and multi-worker
  routing; and
- an initial non-public-barrel
  `src/blindRendezvous/normativeKernel.ts` scaffold with closed TypeScript
  registry/evaluation types, structural validators, and focused tests. It has
  intentionally no canonical encoder, production predicate implementation, or
  public package export and is not conformance evidence.

Those facts reduce implementation risk but do **not** evidence the composition
specified here. The production delta is:

| Surface                 | Delivered behavior                                                                                                                                                                                                                                                                                             | Required v0.4/product change                                                                                                                                                                                                                                                               |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Invitation              | SDK currently normalizes accepted capabilities toward legacy form; the frontend route is `/r`; query fields carry auth/PQ shorthands and the full scheduled-cover policy, while an immediate policy's revision is not portable in today's link and private-rendezvous choices are disabled.                    | Preserve version, add both closed v2 fragment forms, keep `/r`/share/QR behavior, make the complete immutable policy portable in the v2 fragment, reject v2 policy queries, and vault the capability under `LocalRoomId`.                                                                  |
| Room IDs/API            | Join waits for a server UUID; public room/peer helpers and persistence use capability/server IDs.                                                                                                                                                                                                              | Local initialization must resolve offline; migrate every named namespace to `LocalRoomId`, `PresenceRef`, and `LocalPeerId`; expose observed members, edges, and data peers separately.                                                                                                    |
| Admission               | Repeated local checks exist, but address-book/blacklist rows can prefer a server-scoped peer UUID when both identifiers are supplied; that UUID is stable only within the current server database/public key and the server already sees identity and signaling.                                               | Stable Ed25519 key is the primary portable policy identity; one room-scoped `EvaluatePeerAdmissionPolicy()` kernel is consumed by bootstrap `Admit()` and post-promotion `ReauthorizeStableEdge()`; strict proof and pair-private pre-SDP admission are new.                               |
| Topology/data           | The server roster causes a room-wide WebRTC mesh, and `sendMessage(room)` fans out only over directly connected channels.                                                                                                                                                                                      | Implement the bounded sparse control overlay; production-default whole-room messaging additionally requires REQ-021/AC-043.                                                                                                                                                                |
| v4/PQ                   | Strong direct, ordered-transport session and healing implementation exists.                                                                                                                                                                                                                                    | Reuse its raw state machine; add the causal operation-backed adapter, bilateral quiescence, eventual custody, and rejection of restored older authenticated edge counters/transcripts.                                                                                                     |
| Cover/privacy           | Fixed 65,490-byte scheduled cover exists per direct WebRTC edge.                                                                                                                                                                                                                                               | Public cohort allocation, fixed scheduled append/full-chunk reads, trial decryption, evidence, and classifier evaluation are wholly new.                                                                                                                                                   |
| L3                      | `p2party/session` can run pair crypto over an injected whole-message transport.                                                                                                                                                                                                                                | Room-operation convergence, canonical portable bundles, real non-IP custody, causal pair control, and integrated shutdown UX are new.                                                                                                                                                      |
| Frontend stores         | One editable signaling URL and ICE list exist.                                                                                                                                                                                                                                                                 | Bounded signed store/profile/route catalog, explicit permissions, additive activation/backfill, health/partition/assurance UI, and room-independent TURN provisioning.                                                                                                                     |
| Backend                 | The raw capability is observed at legacy join; the server persists its deterministic SHA-512 room identifier, durable membership, stable peer keys/UUIDs, and cross-worker pending addressed plaintext SDP/ICE.                                                                                                | Blind mode is a separate targetless append/allocation/chunk path. It receives no capability, room, peer, roster, recipient, SDP, or ICE and does not reuse legacy membership as an ACL.                                                                                                    |
| Socket/package boundary | The SDK root statically installs `signalingServerApi`; its main join path opens the legacy socket and only `p2party/session` is presently bearer-neutral. The frontend room hooks/alerts are WSS-state shaped. The server has one WebSocket-instantiating start target and its deployment probes HTTP Upgrade. | Add a socket-free blind SDK/frontend entrypoint and store-only server build/deploy profile. Isolate addressed WebSocket behavior in an optional `legacy-signaling` compatibility module; v2 UI derives status from generic carrier/room assurance, never `signalingServerConnectionState`. |
| Kernel/claims           | A non-public-barrel SDK scaffold now validates proposed kernel, claim, evaluation, and formal-obligation record shapes, but it has no frozen codec or generated cross-repository projections.                                                                                                                  | Freeze the schema and executable modules, generate/check every projection, bind the three registries in the release registry, and make claim evaluation the sole positive-label path.                                                                                                      |

The implementation handoff starts from these audited source seams:

- SDK invitation/policy/API:
  `src/roomInvite.ts`, `src/roomPolicy.ts`, `src/index.ts`,
  `src/reducers/roomSlice.ts`, and `src/utils/signalingBounds.ts`;
- SDK cryptographic reuse:
  `src/handlers/handshakeCore.ts`, `handleHandshake.ts`,
  `pqHealingRuntime.ts`, `pqHealingOrchestrator.ts`, `coverRuntime.ts`,
  `ratchetPersist.ts`, and `src/session.ts`;
- SDK legacy signaling/admission/persistence:
  `src/store.ts`, `src/index.ts`, `src/api/signalingServerApi.ts`,
  `src/handlers/handleWebSocketMessage.ts`, `src/db/src/getDB.ts`,
  `src/db/db.worker.ts`, `package.json`, and current room/key listener
  middleware;
- frontend invite/room/policy:
  `p2party.com/src/protocol/roomAccess.ts`, `App.tsx`,
  `RoomSetupAlert.tsx`, `ConnectAlert.tsx`, `useRoom.tsx`, saved-room
  components, and settings/blacklist copy;
- frontend claims:
  `p2party.com/src/pages/privacy.tsx` and `src/pages/tos.tsx`; and
- backend legacy/data retention:
  `p2party-server/src/wsServer.ts`, room/peer/description/candidate handlers,
  `src/pubsub.ts`, `src/index.ts`, `package.json`, `prisma/schema.prisma`,
  `deploy/ansible/templates/Caddyfile.j2`,
  `deploy/ansible/group_vars/production/vars.yml`,
  `deploy/ansible/templates/turnserver.conf.j2`, and
  `deploy/ansible/playbooks/setup-coturn.yml` plus the Upgrade probe in
  `deploy/ansible/playbooks/deploy.yml`.

The SDK migration is broader than one room table. At minimum it covers
`uniqueRoom`, `messageData`, `ratchetSessions`, current-room middleware and
localStorage, key registration, peer/negotiation/ICE/receive queues, transfer/
reconcile/cover/PIN state, public helper arguments/results, and every log/error
namespace. Existing per-edge atomic transaction patterns should be reused,
not duplicated.

Two current compatibility boundaries are explicit. First, blind complete SDP
is deliberately profiled below the legacy 256-KiB parser ceiling and needs
browser/NAT/TURN vectors before release. Second, some Firefox versions do not
expose live certificate stats; Section 4.12 uses exact authenticated SDP plus
a release-reviewed native DTLS binding, with live stats as an additional
tripwire where available, rather than warning-only trust or a blanket Firefox
failure.

Current source/legal claims must be reconciled before production. The frontend
currently contains absolute blocked-peer discoverability/IP language and says
some signaling identifiers/SDP are memory-only or destroyed on disconnect,
while the inspected server schema persists stable keys, UUIDs, room
membership, and can persist cross-worker pending SDP/ICE payloads. The legacy
application logs stable peer UUIDs on connect/disconnect. The inspected
production automation enables Caddy access logs with 30-day retention and
coturn file logging with daily rotation plus 14 archives. Its visible Caddy
filter masks remote IP but does not establish URI/query redaction; because the
WebSocket URL carries the stable Ed25519 key as a query value, release evidence
must test the effective logger rather than assume redaction. Current ICE
defaults also contain plaintext `stun:` and `turn:` URLs alongside `turns:`,
so absolute “TLS for all signaling/STUN/TURN” and “no retained STUN/TURN logs”
copy does not survive the source audit.

Frontend saved-room copy additionally says invitation links are never
uploaded, while the legacy join path sends the decoded capability to signaling
as `roomUrl`. The fragment stays out of the initial page HTTP request, but the
capability is not client-only on that legacy application path. v0.4 cannot
inherit these statements. Blind-mode and legacy storage, application/access/
TURN logging, redaction, transport schemes, and retention must match deployed
behavior. Privacy policy, TOS, UI, DPIA/threat model, and marketing must be
generated or reviewed against the same claim/evidence registry.

After this audit, the already-delivered claims that survive are limited to the
capability/policy substrate, pairwise v4 hybrid security under its stated
authentication assumptions, direct-edge PQ healing and cover, frontend policy
inputs, and generic bearer-neutral pair sessions. Server blindness, target and
co-membership privacy, sole-server denied-peer SDP confidentiality,
client-additive convergence, sparse rooms, public fixed-scan privacy,
eventual-carrier healing, non-IP room convergence, conditional censorship
resistance, and shutdown-surviving room control remain proposed until their
gates pass. Existing generic transports, set union, fragment links, full-mesh
WebRTC, ratchets, PQ frames, and frontend lists are implementation foundation,
not novelty.

### 1.6 Threat model and exact claims

The adversary may:

- operate the only store or any subset of additional stores;
- retain and jointly analyze complete store databases, access logs, route
  logs, allocation state, timing, size classes, source addresses, and every
  public request/response seen by those stores;
- observe requests, responses, public bucket identifiers, object lengths,
  public chunk schedules, bearer source metadata, and timing at those stores;
- delay, omit, duplicate, reorder, replay, fork, or corrupt carrier objects;
- return different append-log views to different clients;
- issue valid signed append receipts and later withhold a checkpoint, commit a
  different object, fork a checkpoint chain, or show signed branches to
  different observers;
- operate or collude with privacy-path domains up to the exact bound declared
  by an SP1 profile and attempt timing, tagging, route-failure, and
  response-manipulation attacks;
- operate malicious clients with or without the room capability;
- collude as a store operator and a room-capability holder;
- possess a copied or revoked invitation;
- claim arbitrary routes, server descriptors, identities, presences, and
  transport candidates;
- trigger browser suspension, loss, retries, partitions, and clock skew;
- enumerate public profiles and public server routes;
- block by IP, prefix, DNS, SNI, ASN, CDN, protocol, account, radio channel,
  physical location, route distributor, or traffic classifier; and
- compromise a room member or one durable pair session.

The adversary cannot break the selected reviewed cryptographic primitives or
forge uncompromised stable identity, store identity, room-authority, or
admission-issuer signatures.

The malicious-rendezvous privacy goal is explicit. From protocol fields and
stored objects alone, a store without the capability shall not recover or
receive the uniformly random room capability, feasibly recover it without an
external candidate, or derive `RoomContextId`, a room number/handle, stable
identity, membership relation, room size, co-membership relation,
pair/social-graph edge, admission decision, or SDP/ICE. The ciphertext is not
claimed to protect a leaked/externally supplied capability; that case is the
capability-holder coalition below. The store shall not receive a deterministic
room-equality or peer-equality handle with which to join its observations.
This is a cryptographic and protocol-shape claim, not automatic network-layer
anonymity. A direct bearer may still reveal a source address, account, timing,
client restart, public profile, and cohort; colluding stores may correlate
those observations. Claims that those observations do not reveal room count,
co-membership, join/leave, or pair activity require the prewarmed fixed trace,
measured shared cohort, declared source-metadata class, and AC-022 classifier
evidence. Cold start, a room-unique cohort, a uniquely used additional store,
or a distinctive physical contact is labelled as such.

The reference one-server L2 claim is:

> For a pre-warmed client that performs the profile's fixed writes and complete
> public chunk reads, a store that lacks the room capability learns the public
> profile cohort, source/bearer metadata, public windows, and aggregate
> occupancy, but receives no room number/identifier, room-equality tag,
> membership or co-membership edge, social-graph/pair edge, recipient,
> mailbox, target index, stable peer identity, pair identifier, raw SDP/ICE,
> protocol-v4 frame, or room admission decision. Fixed-size real and dummy
> objects are computationally indistinguishable under the selected AEAD. A
> sole malicious store may omit, equivocate, or partition all service; it
> cannot forge an accepted room or pair operation.

The public-store accountability claim is narrower:

> A valid signed `stored` or `already-present` result for an admitted append
> promises that exact opaque object will occupy its deterministic slot in
> every checkpoint the store finalizes for that public profile/window. Once two conflicting
> signed checkpoints meet, or one signed checkpoint and inclusion proof commit
> a different object at the promised slot, any verifier can prove the exact
> store fault without a room capability. A missing checkpoint, withheld chunk,
> unavailable proof path, or view that never meets another observer is only an
> availability/accountability-unknown result, not a cryptographic proof of
> omission or global absence.

The optional stronger source claim is:

> **SP1 — bounded measured public-store source unlinkability:** For the exact
> evidence interval, source-privacy profile, route set, observer/corruption
> model, and attacker-unknown source population named by a satisfied compiled
> claim, every store-bound request uses a prewarmed response-independent fixed
> trace through a registered measured batching/mixing mechanism. If no more
> than `t` privacy-path operator domains collude with every target store/egress,
> the exact set contains at least `max(2,t + 1)` independently evidenced
> mixing domains disjoint from the target store/egress operators, at least one
> remains honest and outside the observer's joint view, and the endpoint
> remains uncompromised, the release-bound formal result limits the modeled
> request-to-source linking probability to at most `1/k + ε`, for the record's
> conservative measured `k` and non-vacuous formal `ε`. The result binds the
> exact security/session definition, topology, per-layer operator-selection
> mass, traffic/mix parameters, fragmentation/drop/delay model, and cumulative
> linkable packet/byte volume; domain count alone never establishes the bound.
> Current deployment measurements establish the theorem's named
> population/path assumptions and attempt to falsify them with
> entry-and-egress-collusion classifiers at a preregistered low base rate;
> classifier non-success is not itself the theorem. Under the registered
> egress-disclosure contract, the target store receives only the privacy
> egress's protocol identifiers, not an originating identifier carried by the
> protocol.

SP1 is conditional formally bounded unlinkability with measured deployment
assumptions, not universal anonymity. It excludes a global passive/active
observer, long-horizon intersection beyond the measured claim interval,
rollback/deletion of the local source-exposure or volume ledger, and
compromised clients, evaluators, mechanisms, or registries. It also stops
rather than resetting when its cumulative linkability budget is exhausted. A
split proxy without measured batching/mixing does not qualify.

The pair-confidentiality claim is:

> SDP, ICE, identity bundles, handshake records, and PQ-healing controls are
> pair-private inside the capability-sealed room operation. A client that is
> denied by the receiving frontend obtains no SDP/ICE from that endpoint.
> Another capability holder, the sole store, and their coalition cannot
> decrypt traffic for an admitted pair unless they compromise one endpoint,
> an accepted stable identity, or the pair cryptography. In strict
> address-book or authority mode, the first identity flight is emitted only
> toward a presence that proves eligibility. In open or denylist-only mode,
> the selected capability holder may learn that first sender identity; the
> surviving claim is pre-SDP bilateral transport disclosure and pair-payload
> confidentiality, not anonymous peer identity.

A store without the capability sees only the public cohort and bearer
metadata. A store colluding with a capability holder additionally obtains the
complete room-level plaintext set it delivered, can correlate store source and
timing with room participation, can dictionary-test commitments for stable
keys it already suspects, and can observe pseudorandom pair-step activity.
Pair ciphertext, SDP, and v4/PQ payloads remain cryptographically private, but
that coalition is outside the room-metadata claim.

The same role separation applies when a store or bridge runs on a peer device.
The public-store process receives no additional room field because of its host,
but a co-located endpoint that holds the capability may independently know
room-level facts and may correlate them with its local store observations; that
is exactly the store-plus-capability-holder coalition above. An authenticated
contact carrier necessarily exposes its direct counterparty, session, bearer,
timing, and the registered source-metadata class to the contact peer. If that
peer is also a room member, its endpoint role learns whatever the room policy
permits a capability holder or admitted endpoint to learn. Pair double sealing
still hides another pair's SDP/ICE, v4, and PQ payloads. Neither peer-carrier
mode establishes anonymity from a direct contact, a malicious admitted
endpoint, or a co-located endpoint/store coalition.

The convergence claim is conditional:

```text
If every still-required valid operation reaches every relevant participant
through the time-varying client/store/carrier graph before that operation's
retention horizon, and participants continue reconciliation, then their valid
operation sets and deterministic core room state converge for the same
immutable policy and reference window. Local projections converge only when
their frontend/planner facts also match.
```

No protocol can make disconnected components converge without a later path.
No observed local set proves that a malicious carrier has not withheld another
valid operation. The runtime therefore reports `reconciling` or `partitioned`,
never invented global finality.

The censorship-resistance claim is also conditional:

> An operation remains deliverable while at least one pre-positioned,
> participating path from its author to each required recipient continues to
> accept, retain, and carry it before expiry. Each measured independent store,
> route family, peer bridge, or physical carrier may add a delivery path. One
> conforming store-only server whose S1 acceptance evidence passes is a
> complete functional S1 deployment but has zero server-fault tolerance.

Two conformance packages make the deployment boundary precise without
inventing a server quorum:

- **S1 — single-carrier safety baseline:** with one carrier, end-to-end
  confidentiality, authenticity, room isolation, frontend admission,
  pre-SDP disclosure control, deterministic union/reduction, and the stated
  PQ-healing safety properties hold against a Byzantine carrier. Availability,
  global completeness, traffic-source anonymity, and Byzantine omission
  tolerance do not.
- **R2-BEC — bounded-horizon Byzantine eventual consistency and multi-path
  delivery resilience:** authenticated union gives the safety half against
  any number of Byzantine carriers: two correct clients with the same
  validated operation set, immutable policy, and reference window derive the
  same core state. The delivery half is asserted only by one conformance
  record that binds the exact participant-presence set `P`, required
  operation/frontier set `O`, global temporal carrier graph `E`, fault-unit
  universe `D = HonestFaultUnitIds(record)`, and registered
  `1 <= f < |D|`. For every allowed
  `B ⊆ D`, `|B| <= f`, and every `(operation, participant) ∈ O × P`, `E \ B`
  must contain a fair, authenticated, time-respecting path that delivers the
  operation before its expiry; clients continue reconciliation and resource
  state remains within bounds. All selected honest-store units must have
  pairwise-distinct measured operator, availability-path, and
  blocking-domain IDs under the registered model.
  Servers do not vote, agree on a log, or prove absence; clients authenticate
  and union everything delivered.
  Two proactively used, independently operated honest stores, each covering
  all of `P`, are the smallest two-honest-server instance and give `f=1`
  delivery resilience to loss, omission, or blocking of either path while the
  other remains fair and in time. Arbitrarily many additional Byzantine
  stores cannot forge an accepted operation or make equal validated sets
  reduce differently. They can change a client's observed subset, timing, and
  availability by withholding or selectively revealing genuine operations,
  and authorized valid-work saturation remains an explicit availability
  boundary. “Honest” and complete temporal coverage are
  conformance/deployment assumptions backed by fault-injection evidence, not
  facts inferred by a client at runtime.
  Operator, route, or blocking-domain collusion beyond the registered model
  invalidates the corresponding independence/privacy claim. R2-BEC alone is
  not an Internet-shutdown theorem. A combined
  `R2-BEC ∧ shutdown-surviving rendezvous/control` release claim separately
  requires the AC-024/025 global participant vectors, a fresh
  `tested-non-ip-control-ready` path, and sufficient L3 capacity before every
  required horizon.

Only a pair operation's two confirmed endpoints need decrypt or act on its
inner payload. The R2-BEC operation-set convergence claim is deliberately
simpler and stronger: every operation in `O`, including an opaque pair
operation, must reach every named participant in `P`. There is no
per-operation recipient exception in `R2Conforms`. The participant scope is
the exact participant-presence set and
`(referenceWindow, operationsDigest)` frontier named by that claim's
conformance/evaluation record; undiscovered or omitted members are outside the
scope and prohibit wording such as “the complete room.” Every named
participant must independently satisfy the required path/domain/operator and
capacity predicates. One client's two routes are only that client's local
path diversity and cannot upgrade peers that authorize one route. Because the
protocol deliberately has no globally final roster, ordinary runtime
assurance never infers a room-wide R2-BEC theorem from local carrier facts.

R2-BEC is the requested two-honest-server bounded-fault delivery target only
under those assumptions and only as the conjunction of the granular assurance
fields and acceptance evidence. The UI and paper shall not collapse it into an
unqualified “fully secure,” “Byzantine-fault-tolerant,” “anonymous,” or
“uncensorable” badge. With two selected assumed-honest, independently
evidenced paths and `f=1`, the liveness theorem tolerates loss of one only
while the other remains honest, usable, and reaches all required participants
in time.
“At least two honest stores” is not a generic Byzantine-consensus threshold
against an unbounded number of faulty replicas. R2 has no votes: its exact
locally selected/capped carrier set and fault subsets are inputs to a
bounded-delivery theorem. Any future consensus/finality claim would require a
separate explicit `n`, `f`, quorum-intersection, authentication, and synchrony
model.

The following strictly stronger threat models are not satisfied by v0.4 and
must remain explicit non-claims:

- a global passive observer that correlates every bearer source, timing trace,
  physical contact, and all carrier logs, or an active global observer that
  induces path failures for long-term intersection/tagging;
- linearizability, serializability, Byzantine consensus/quorum finality,
  globally complete membership, or proof of absence—even with two honest
  stores;
- liveness, global absence/finality, or convergence when every usable path
  omits/blocks traffic, or when a partition exceeds semantic retention;
- first-contact discovery from an unestablished peer session, or from a
  peer-hosted-store hint that is itself trapped behind the missing path;
- durable custody, availability, R2 honest-store status, or operator/path/
  blocking-domain independence inferred only from a transient peer, browser
  tab, process, route, or session count;
- portable proof that a silent store withheld data, or split-view detection
  before inconsistent signed artifacts meet an observer;
- R2-BEC liveness after both assumed-honest stores become Byzantine, share an
  unmodelled common blocking/operator failure, or lose fair reachability to
  any named participant; the authenticated safety result remains;
- room-metadata privacy from a capability holder, or from a store colluding
  with one, beyond the pair-double-sealing boundary stated above;
- protection from a malicious admitted endpoint, compromised room authority,
  persistently compromised pair endpoint, or leaked invitation capability;
- personhood/Sybil resistance or identity-rotation linkage in capability-open
  rooms;
- SP1 protection from the entry operator, local ISP, physical observer,
  account provider, or any observer that jointly sees both sides of every
  supposedly honest mixing domain; nor retrospective erasure after a direct
  store request;
- authentication against an active cryptographically relevant quantum
  adversary, because v0.4 authentication remains classically rooted;
- whole-device snapshot rollback detection without an external monotonic
  anchor;
- guaranteed delivery through power loss, radio jamming, physical seizure, or
  absent human/device custody;
- protection from a compromised release registry, conformance evaluator,
  frontend/SDK supply chain, browser/OS, or endpoint random-number generator;
  and
- anonymity merely from deploying two servers. Multiple paths improve
  omission/blocking tolerance only when their measured trust and blocking
  domains actually differ.

Post-quantum healing means post-compromise security after a successful fresh
hybrid exchange with uncompromised endpoint entropy. Replication adds no
entropy, does not make past plaintext secret again, and does not heal a leaked
room capability or a compromised endpoint that remains under adversarial
control. The v0.4 `post-quantum` label is scoped to hybrid confidentiality and
root healing. Stable, room-author, authority, and store authentication remains
Ed25519, while protocol-v4 3DH and CPace retain their classical elliptic-curve
components; v0.4 therefore does not claim authentication against an active
cryptographically relevant quantum attacker capable of forging those
identities. A PQ-authenticated rendezvous requires a new reviewed room/session
suite and protocol version.

That successor never mutates a v0.4 room. It uses a disjoint v3 invitation,
`RoomPolicyV5`, operation/authentication suites, fresh 32-byte capability,
fresh `RoomContextId`, and fresh session roots. A continuity statement can
link identities only when the frontend has one exact pre-quantum
non-rollback anchor, out-of-band reverification, or PQ-authority
certification. A classical signature first observed after an active quantum
attacker enters scope cannot bootstrap the successor. Allowlist grants,
operations, pair roots, healing epochs, and history never transfer
automatically.

## 2. Definitions

| Term                       | Definition                                                                                                                                                                                                                                                                                            |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Active carrier             | A compatible store or contact carrier that passes local frontend trust policy and is currently used for publish/reconcile work.                                                                                                                                                                       |
| Admission grant            | A short-lived signature by a room-policy-pinned authority over an exact stable identity, room context, generation, and validity interval.                                                                                                                                                             |
| Bearer                     | A mechanism that carries opaque objects, including an IP service, local radio, delay-tolerant bundle network, authenticated peer link, or removable medium.                                                                                                                                           |
| Blocking domain            | An equivalence class under one registered censor-action model: paths one modeled atomic action removes together share one ID. Examples include one operator, prefix, ASN, CDN, protocol, proxy pool, distributor, radio channel, or physical checkpoint.                                              |
| Carrier                    | A store or contact adapter implementing immutable, unordered, at-least-once object exchange.                                                                                                                                                                                                          |
| Carrier envelope           | One fixed-size, carrier-separated encryption of a canonical authenticated room operation.                                                                                                                                                                                                             |
| Claim evaluation           | A pure scoped result produced from one registered claim definition, complete bounded inputs, prerequisite evaluations, formal results, and current evidence. Only `satisfied` selects positive wording.                                                                                               |
| Cohort                     | Clients using the same public delivery profile and bucket schedule. A cohort intentionally contains unrelated rooms and is never a connection set.                                                                                                                                                    |
| Contact carrier            | A store-carry-forward or peer-contact adapter that exchanges inventories and opaque objects without requiring an always-online public service.                                                                                                                                                        |
| Delivery profile           | A content-addressed public definition of codecs, size classes, public windows, retention, cover schedule, limits, and primitive suites. It contains no room capability or concrete mutable store list.                                                                                                |
| Delivery window            | A coarse public time bucket used for carrier retention and cover. It is not a roster-finality or cryptographic-ratchet epoch.                                                                                                                                                                         |
| Executable kernel          | The content-addressed closed set of pure deterministic validators, reducers, scheduler/transition functions, assurance derivations, and claim evaluator named by the release registry.                                                                                                                |
| Formal obligation          | One content-addressed property, model, abstraction/refinement map, assumptions, toolchain, and explicit finite, symbolic, or computational scope required by named claims.                                                                                                                            |
| Frontend                   | The trusted local application boundary that owns address-book policy, peer deny state, authority credentials, store trust, route permission, and user disclosures.                                                                                                                                    |
| L2                         | The application-layer target/access-privacy properties explicitly earned by a profile and measured bearer behavior. It is not OSI Layer 2.                                                                                                                                                            |
| L3                         | The p2party disruption-tolerant availability profile defined here. It is not OSI Layer 3.                                                                                                                                                                                                             |
| Operation ID               | A private hash of one exact canonical signed room operation, computed only after carrier decryption.                                                                                                                                                                                                  |
| Operation set              | The grow-only set of validated canonical operations retained inside a bounded horizon. Logical expiry and reduction do not mutate a server object.                                                                                                                                                    |
| Pair edge                  | One independently authenticated relationship between two exact room presences, promoted after stable identity verification to one durable protocol-v4 session.                                                                                                                                        |
| Peer bridge                | A room client that exchanges bounded inventories over authenticated contacts and, after ordinary room validation, rewraps retained operations across its active carrier contexts. It is not a public store or durable-custody claim unless the device separately satisfies the public-store protocol. |
| Peer-hosted store          | A conforming public store whose process runs on an end-user or room-participant device. Host placement is not a wire field, room role, authority, or independence claim.                                                                                                                              |
| PQ-authenticated successor | A separately specified v3-invitation/`RoomPolicyV5` protocol with fresh room context and complete hybrid-authentication coverage. It is not a v0.4 mode or label.                                                                                                                                     |
| Portable bundle            | A canonical bounded file containing an inventory and fixed-size opaque carrier envelopes for manual or removable-media store-carry-forward.                                                                                                                                                           |
| PQ-healing epoch           | The counter owned by one durable protocol-v4 edge's existing `OFFER → ADVANCE → ACK` state machine. It is unrelated to delivery windows and cover epochs.                                                                                                                                             |
| Public cohort log          | A targetless append-only collection partitioned only by public delivery profile and public ingress window.                                                                                                                                                                                            |
| Public-store checkpoint    | A store-signed profile/window-wide commitment to the complete fixed public chunk vector and its exact predecessor checkpoint. It is delivery evidence, never room state or consensus.                                                                                                                 |
| Room                       | The capability-and-policy-scoped membership, admission, topology, and key domain.                                                                                                                                                                                                                     |
| Room capability            | A uniformly random 256-bit secret distributed outside the rendezvous service.                                                                                                                                                                                                                         |
| Room slot                  | One local fixed cover lane for a concurrently active room. Slot ordinals never cross a bearer.                                                                                                                                                                                                        |
| Sparse overlay             | The deterministic bounded-degree graph computed from locally observed valid room presences.                                                                                                                                                                                                           |
| SP1                        | The optional formally bounded and deployment-measured public-store source-unlinkability package, scoped to one profile, interval, route/mechanism set, corruption model, cohort lower bound, and linking theorem.                                                                                     |
| Stable identity commitment | A room-scoped pseudonym for a stable Ed25519 public key, revealed inside room encryption and confirmed before SDP. It is dictionary-testable by a capability holder that knows a candidate public key.                                                                                                |
| Store                      | An online or intermittently reachable carrier that retains opaque objects under public profile windows.                                                                                                                                                                                               |
| Store hint                 | A room-encrypted, leased advertisement for a signed compatible store descriptor and route records. A hint is not permission to contact it.                                                                                                                                                            |
| Transport candidate        | A typed endpoint-private proposal for a final pair transport, such as WebRTC, a local-radio session, or an asynchronous control mailbox.                                                                                                                                                              |

## 3. Requirements, Constraints & Guidelines

### 3.1 Protocol requirements

- **REQ-001 — Version-safe, unchanged one-link UX:** The invitation secret
  remains the existing uniformly random 32-byte capability. Existing compact,
  `v1.<43-character-base64url>`, hash-prefixed, 24-word, and legacy-hex forms
  keep their deployed legacy-signaling meaning forever. Blind rendezvous uses
  the canonical `v2.<43-character-base64url>` default fragment, for example
  `https://p2party.com/r#v2.<capability>`, and maps it forever to the
  byte-frozen `DEFAULT_BLIND_POLICY_V4_0`. A non-default room policy uses the
  canonical
  `v2.<43-character-capability>.<base64url-canonical-room-policy>` fragment;
  it preserves today's one-link
  advanced/PIN/PQ/cover-room sharing without a query. `generateRoomInvite()`,
  `joinRoom(invite)`, copy-link, paste-link, QR, `/r`, and `location.hash`
  remain the same user actions and function shapes; a conforming
  blind-default release emits v2 and every build parses/classifies both
  versions without reinterpretation. Executing v1 requires the separately
  installed legacy-signaling adapter. Without it, `joinRoom(v1)` rejects its
  existing promise with the frozen typed
  `LegacySignalingAdapterUnavailableError`/code
  `legacy-signaling-adapter-unavailable` before adapter or network work and
  before capability/identity disclosure; it never maps v1 to v2 or widens the
  successful `Promise<Room>` contract. An old client rejects v2 as unsupported instead of joining a different
  room. The webpage
  extracts `location.hash` before calling the decoder; the library is not
  required to parse a whole URL. Neither capability nor PIN appears in HTTP
  paths, queries, `Referer`, analytics, profile lookup, store admission,
  bucket names, or route addresses. The room policy is public protocol
  configuration, but v2 keeps it in the fragment so it is not sent in the
  initial HTTP request. The policy suffix is length-bounded by the invitation
  codec and contains the exact canonical `RoomPolicyV4`, which already nests
  the existing 32-byte session-policy SSOT.

- **REQ-002 — Room identity:** `RoomContextId` is derived only from the
  capability and canonical room-policy hash. Concrete stores, routes, local
  allow/deny lists, cursors, current roster views, and carrier availability
  are excluded. Unknown versions, fields, enums, algorithms, and
  non-canonical encodings fail closed.

- **REQ-003 — One-server minimum:** A conforming deployment starts and
  provides correct rendezvous with one public-store
  `OperationCarrierAdapter`. It requires no peer store, second operator,
  quorum, leader, selected cell, consensus service, or server-to-server
  protocol. “One server” means one independently operated logical store; its
  process may use a database, TLS terminator, or local workers within that same
  trust/failure domain. A literal one-binary/no-database appliance is a
  deployment option, not a protocol claim. The reference minimum is the
  store-only HTTP artifact with no legacy WebSocket/Upgrade path; co-hosting
  an optional compatibility sidecar does not make it a protocol dependency.

- **REQ-004 — Client-additive carriers:** Clients may activate compatible
  stores and contact carriers up to `ClientResourcePolicyV1`'s hard per-room
  profile, work, and active-carrier caps and
  `ClientGlobalResourcePolicyV1`'s client-wide initialized-room, public
  catalog, public-context/route, contact-context, and L3-work caps. Every
  locally created retained operation is proactively published to every active
  writable carrier context, and
  every newly validated retained operation is backfilled to the other active
  carriers. Success, failure, count, or order of carriers never selects room
  state.

- **REQ-005 — Immutable shared-event SSOT:** The canonical authenticated
  operation and private `OperationId` are the shared/core room-event source of
  truth under immutable `RoomPolicyV4`. Carrier envelopes,
  store object IDs, cursors, chunks, manifests, cache records, and Merkle roots
  are derived delivery artifacts. Merge is set union; the reducer is
  deterministic and independent of arrival or server order. This requirement
  does not overwrite the separate scoped SSOTs for frontend policy, private
  pair/v4 state, release policy, or assurance evidence.

- **REQ-006 — Targetless reference store:** The reference L2 store accepts
  fixed-size opaque appends and serves complete immutable public chunks
  plus their one signed public checkpoint, selected only by
  `DeliveryProfileHash` and public ingress window. It accepts
  no room-derived namespace, recipient, mailbox, pair locator, query index, or
  arbitrary client filter. The reference online route is bounded
  request/response HTTP; no correctness, availability, traffic-analysis, or
  convergence property depends on WebSocket, server push, or a long-lived
  connection. A future registered WebSocket route may carry the identical
  client-global fixed schedule, but cannot add subscriptions, push hints, or
  room/peer targets. The current per-room signaling WebSocket is a
  migration-only legacy path and is never a blind-mode fallback.

- **REQ-007 — Fixed room slots and reads:** An L2 `fixed-cohort-scan` client
  emits exactly one real-or-dummy object for every
  `(size class, appendSchedule entry, room slot)` and reads the one checkpoint
  followed by every chunk of the one-lag finalized window at the public
  cadence. One client-global scheduler
  owns each `(StoreId, DeliveryProfileHash)` context across all local rooms; it
  performs one issuance/allocation/checkpoint/read sequence, not one per room.
  One active
  room consumes one persisted local slot in that scheduler; unused slots emit
  dummies; exceeding the bound fails before traffic shape changes. Join, leave,
  room size, sparse degree, pair success, retry, and store health never add a
  lane or targeted read. A frontend-default or explicitly prewarmed public
  context starts independently of room activity and keeps the same all-dummy
  trace with zero assigned rooms. Room-count and join/leave indistinguishability
  are claimed only after that context has completed prewarming; an on-demand
  cold start is labelled separately.

- **REQ-008 — Room isolation:** A client derives room state only from
  operations that decrypt and authenticate under its exact room context.
  Other rooms in the same cohort are cover, not members. No cohort-wide peer
  list exists. Every pre-auth edge, stable edge, replay cache, policy lookup,
  admitted application-relay namespace, and persistence key is room-bound.

- **REQ-009 — Sparse-by-default planner:** The local connection planner is
  `explicit`, `sparse-ring`, or `full-mesh-small-room`. It is excluded from
  `RoomContextId` and canonical room reduction. The application default is
  `sparse-ring` with hard provisional and stable degree bounds. Full mesh is
  never inferred from cohort membership and requires explicit local choice
  plus a local planner-fixed small-room ceiling no larger than immutable
  `roomPolicy.maxRoomMembers`. In `mode="explicit"` with no requested edges,
  operation reconciliation remains correct; explicit requests remain subject
  to bilateral admission and both peers' hard caps.

- **REQ-010 — No roster finality fiction:** Presence produces an observed
  eventually convergent set, not an authoritative server snapshot. Pair IDs
  bind the two exact endpoint presence operations, never a purported complete
  roster hash. A local view digest is diagnostic and may schedule attempts; it
  is not durable session key input.

- **REQ-011 — Frontend peer admission:** The frontend owns the local peer
  blacklist and `onlyConnectWithKnownPeers`/address-book-only setting. Denial
  wins over allowance. An authority-grant room additionally requires a valid
  unexpired room-authority signature. Every connection path applies the same
  admission function and fails closed for an indeterminate local lookup.

- **REQ-012 — Pre-SDP bilateral identity gate:** In strict address-book or
  authority mode, a presence first proves eligibility without revealing a raw
  stable key to the room, and an initiator shall not send its identity hello
  to an unproved presence. Pair bootstrap then exchanges endpoint-encrypted
  stable identity proofs and optional admission grants without SDP or ICE.
  Each side verifies the remote stable identity commitment and applies its
  frontend policy. Only after both identity gates succeed may either side emit
  a pair-encrypted transport offer, SDP, ICE, or transport answer. A denied
  side receives no negative response that contains endpoint material. Open
  and denylist-only mode explicitly accepts first-flight identity disclosure
  to the selected capability holder.

- **REQ-013 — Pair-private sensitive control:** Stable identities, admission
  grants, SDP/ICE, DTLS fingerprints, transport locators, protocol-v4
  handshake bytes, and PQ control frames are inside a pair-private envelope,
  which is itself inside a room carrier envelope. Room capability alone never
  decrypts these fields.

- **REQ-014 — Bearer-neutral core:** Canonical operations and pair records
  cross injected byte/object adapters. Core room, reducer, connection planner,
  admission, and cryptographic modules do not import DNS, URL, HTTP, TCP, UDP,
  WebSocket, WebRTC, IP address, or a concrete socket API.

For every L3 requirement and gate, **hardware-in-loop** means the actual
non-IP adapter, device, radio/media interface, driver, fragmentation, and
custody code path running under laboratory control while every IP API is
tripwired to fail. **Field-tested** means that same registered path was
exercised in the physical and custody environment named by the claim and
produced the complete measured dataset required below. A byte-injection
harness is neither.

- **REQ-015 — Normative L3 operation:** The first conforming release includes
  portable-bundle export/import and one automated non-IP contact-carrier
  integration. A byte-injection harness is required for portability tests but
  is not enough for `non-IP-control-compatible`. A hardware-in-loop non-IP path
  may establish that compatibility result when all-IP-disabled
  store-carry-forward contacts converge presence and complete the pre-SDP
  identity gate, pair bootstrap, protocol-v4 handshake, and one post-quantum
  healing cycle. The stronger practical phrase
  `shutdown-surviving rendezvous/control` additionally requires one deployed,
  field-tested non-IP custody path with the Section 4.14 range, loss, energy,
  MTU, capacity, contact-duration, human-latency, power, and physical-custody
  evidence current for the claimed scope. The hardware-in-loop compatibility
  result is the v0.4 release gate; shutdown-survival wording is conditional on
  the additional field evidence rather than a future protocol version. Neither
  result covers application messaging; that additionally requires
  REQ-021/AC-043 on the same measured path.

- **REQ-016 — Typed transport handoff:** WebRTC is one fast transport
  candidate, not a prerequisite of rendezvous. Candidate codecs are
  endpoint-private and policy-bounded. A stable cryptographic edge, and
  separately any data-capable final transport, is promoted only after its
  channel binding and stable identities are confirmed by the fresh
  protocol-v4 hybrid handshake. The mandatory operation-carrier fallback is a
  control-only handshake path, not an application-data queue.

- **REQ-017 — Protocol-v4 reuse:** Every accepted stable edge uses the
  existing fresh interactive 3DH plus room-selected ML-KEM protocol-v4
  handshake, independent Double-Ratchet and PQ-healing roots, atomic
  persist-before-dispatch state, stable-identity role ordering, and exact
  `OFFER → ADVANCE → ACK` frames. Rendezvous does not create a second ratchet,
  room-wide healing root, or carrier-owned crypto state.

- **REQ-018 — Eventual pair-control adapter:** When v4 control crosses an
  unordered carrier, an edge-owned persisted ingress ledger releases only the
  next authenticated admissible record to the unchanged healing machine.
  Reordering, duplication, carrier count, and arrival order do not enter v4
  state. Direct-channel retry timers are replaced by durable republish-on-
  contact behavior for this adapter.

- **REQ-019 — Safe automatic store discovery:** Default, local deployment
  configuration, user-added, and valid leased room hints form a discovered
  catalog.
  Activation remains local frontend authority. A remote hint never by itself
  authorizes a URL fetch, local-network access, credential disclosure, new
  transport adapter, or source-metadata exposure.

- **REQ-020 — No downgrade:** Failure of every carrier yields a persisted
  outbox and explicit unavailable/partitioned state. It never sends the room
  capability to a fallback, exposes room-derived addressing, accepts an
  unsigned roster, drops the peer policy gate, or falls back to legacy or
  classical-only signaling.

- **REQ-021 — Sparse product data-plane dependency:** This control-plane
  specification may conform without carrying application messages, but the
  p2party product shall not make sparse blind rooms the default while
  `sendMessage(room)` reaches only direct neighbors. Before production
  replacement of today's room-wide UX, a separately versioned companion
  specification and implementation shall define end-to-end multi-hop or group
  delivery over the bounded sparse graph: stable message IDs, destination/
  group semantics, end-to-end confidentiality and sender authentication,
  deduplication, loop/hop bounds, admission/relay authorization, retry/resume,
  receipts, churn/partition recovery, quotas/DoS, attachment transfer, and
  interaction with ratchet/PQ epochs. A product-level
  `shutdown-surviving messaging` label additionally requires its application
  data and receipts to use the normative non-IP custody path; control-plane
  L3 alone is not that claim. It reuses `LocalRoomId`,
  `LocalPeerId`, stable edges, and assurance facts as inputs; it neither
  expands this rendezvous log into an application queue nor creates a second
  room-membership SSOT.

- **REQ-022 — Removable WebSocket compatibility:** Every WebSocket route or
  adapter is optional and removable, never a blind-protocol dependency. No blind-v2
  codec, room transition, admission decision, cryptographic transcript,
  persistence key, retry/deadline, correctness, privacy, liveness, cover,
  assurance, or L3 result may consume WebSocket connection, ordering, push,
  subscription, heartbeat, close, or socket-bound identity semantics. The
  reference online path is the finite HTTP `OperationCarrierAdapter`; the
  reference offline paths are contact and portable adapters. The blind SDK,
  frontend, and store-only server artifacts build, start, and run with the
  WebSocket modules, global constructor, and HTTP Upgrade endpoint absent. The
  currently deployed addressed signaling WebSocket is a separately registered
  legacy compatibility adapter, is not an `OperationCarrierAdapter`, and is
  never selected for v2 or as a failure fallback. Removing any optional
  carrier changes local availability/evidence and may make the room
  unavailable when no path remains; it never changes canonical room,
  operation, or session state.

- **REQ-023 — One-server safety, additive bounded-fault delivery target:** The
  S1 safety package is mandatory with the single shipped store. A release or
  explicitly scoped consented test deployment may publish an R2-BEC
  conformance result only when its one canonical
  `R2ConformanceRecordV1` satisfies `R2Conforms`, including at least two
  assumed-honest independently operated public stores, exact global temporal
  participant coverage under every registered fault subset, and current
  retention/capacity evidence. Privacy, admission, PQ, and shutdown remain
  separately named claims rather than being folded into a “full” label. Local
  path evidence is necessary but not sufficient for a scoped R2-BEC result.
  Runtime/UI wording never says that a live room “is BFT”; positive wording
  says that the exact release passed participant/frontier-scoped R2-BEC
  conformance under the named censor-action and temporal-coverage model.
  Adding a
  locally authorized carrier automatically schedules independent wrapping,
  reconciliation, and backfill; it never introduces server consensus,
  server-to-server configuration, a new room, or a changed invitation.

- **REQ-024 — Executable normative kernel and generated projections:** A
  conforming release ships one content-addressed
  `ExecutableRendezvousKernelManifestV1`. Its closed pure modules implement
  canonical operation-set validation, `CoreReduce`, current/historical
  pair-scoped `Project` plus `Admit`,
  `DeriveAssurance`, L3 required-work derivation, the production delivery
  scheduler and `R2Conforms`, eventual pair-control transitions, and claim
  evaluation. A kernel module has no ambient clock, randomness, network,
  filesystem, mutable global, UI, or carrier input beyond its explicit
  canonical arguments. The binary schema remains the SSOT for bytes and
  bounds; the kernel is the SSOT only for those deterministic semantics.
  Types, codecs, fixtures, protocol/claim tables, UI claim keys, and
  whitepaper tables are generated or mechanically checked projections. A
  mismatch fails the build/release.

- **REQ-025 — Formal obligations and implementation refinement:** The release
  ships one content-addressed `FormalObligationRegistryV1` and reproducible
  results for every obligation required by an advertised claim. Each binds
  its exact model, property, assumptions, abstraction/refinement map,
  toolchain, and finite, symbolic, or computational scope. The formal
  transition alphabet is the kernel's canonical input/output alphabet. Every
  production implementation of a kernel-owned transition differentially
  replays the same canonical traces. A counterexample, inconclusive result,
  missing refinement map, admitted unchecked lemma, or result outside the
  advertised scope prevents every dependent positive claim.

- **REQ-026 — Room-blind accountable public custody:** Every public store
  emits exactly one signed `PublicStoreCheckpointV1` for each supported
  profile/window, including all-dummy windows, and serves it through one
  targetless fixed-schedule request. A valid signed `stored` or
  `already-present` append result is the sole custody promise and commits the
  request's exact opaque object to its deterministic finalized slot.
  Checkpoint chains, conflicts, and breach proofs are public carrier evidence,
  never room operations, reducer inputs, consensus, or a runtime R2-BEC
  upgrade.

- **REQ-027 — Optional fail-closed SP1:** A frontend may select one
  client-global `SourcePrivacyFloorV1` for public-store contexts. Under SP1,
  every store-bound descriptor/profile request not shipped locally, token
  issuance, allocation, append, checkpoint, chunk read, status, and scheduled
  retry uses only a registered conforming privacy mechanism after the complete
  prewarm interval. A direct, unregistered, stale, saturated, or
  response-dependent route is unavailable rather than fallback. SP1 is
  compiled only from the exact measured population, corruption/observer
  model, security/session definition, topology and route-selection mass,
  route/mechanism, visible formal parameters, trace, fragmentation,
  drop/delay tagging, cumulative linkable packet/byte volume, clock, and
  evidence interval. Every prewarm, dummy, cover, request, retry, and
  failure-control emission is charged before egress and fails closed.

- **REQ-028 — Version-separated PQ authentication successor:** V0.4 assigns no
  PQ-authentication suite identifiers and never reinterprets its v1/v2
  invitations or classically authenticated objects. A successor may activate
  only under a separately reviewed `PqAuthenticationSuccessorManifestV1`,
  disjoint v3 invitation and `RoomPolicyV5`, complete hybrid-authentication
  coverage, fresh capability/room context, and frozen migration contract.
  Unsupported successor material fails before state mutation or disclosure
  and never falls back to v0.4. The successor manifest is publication-only in
  this release and cannot make a v0.4 claim `satisfied`.

- **REQ-029 — Peer-executed carriers without a protocol fork:** Any device,
  including a room participant or an unrelated volunteer, may expose the
  public-store role. A room client may additionally bridge its authenticated
  peer contacts and other active carriers after ordinary room validation. In
  the public-store role the device exposes the exact
  `PublicStoreOperationCarrierAdapter`, signed descriptor/routes,
  Blind-RSA allocation, fixed schedule and geometry, immutable chunks, signed
  append results/checkpoints, retention, quota, privacy, and frontend route
  controls required of every public store. In the contact role an already
  authenticated session exchanges only the registered bounded inventory and
  fixed opaque objects through `kind="contact"`; it creates no roster,
  recipient subscription, room target, or connection-planner edge. The host
  process, device class, and whether it also runs a p2party endpoint never enter
  a room operation, invitation, `RoomContextId`, `StoreId`, carrier kind, merge,
  admission decision, pair transcript, or claim by themselves.
  Both roles may carry presence, admission control, pair steps, transport
  offers/answers, protocol-v4 records, and PQ-healing controls under the same
  operation semantics; only the pair endpoints can open pair-private payloads.
  A contact bridge contributes a time-respecting delivery edge only while its
  authenticated contact, bounded custody, and capacity remain usable. It is
  never counted as a public store, signed durable custody, or an honest-store
  unit in R2-BEC unless it separately implements the complete public-store role
  and satisfies the same current evidence. A peer-hosted store is likewise not
  independent merely because it is another process: co-located endpoint/store,
  operator, availability-path, or blocking-domain identities collapse under
  the existing assurance rules. Adding either role leaves invitations and rooms
  unchanged and remains subject to local frontend authorization and resource
  caps. No peer contact can bootstrap itself: a fresh participant still needs
  a pre-positioned store route, existing authenticated contact, portable
  exchange, or other out-of-band discovery path. Because carrier envelopes are
  context-separated, an unrelated courier without the room cryptographic
  context cannot rewrap an operation between distinct contact contexts; it may
  only carry already wrapped bytes inside the exact registered shared context
  or portable-custody contract that produced them.

### 3.2 Privacy and security requirements

- **SEC-001 — Forbidden store inputs:** A store shall not receive a room
  capability, PIN, room-derived common tag, stable peer key, room admission
  decision, recipient, pair edge, raw identity proof, raw SDP/ICE, DTLS
  fingerprint, protocol-v4 record, PQ counter, or application target.

- **SEC-002 — Canonical reviewed sealing:** Carrier envelopes use the exact
  reviewed AEAD and key schedule selected by the delivery profile. All
  real/dummy public bodies have profile-fixed lengths. Application TypeScript
  shall not implement or modify cryptographic primitives.

- **SEC-003 — Authenticated operation:** Every real operation has one
  canonical encoding, author signature, bounded predecessor/dependency set,
  semantic slot, lifetime class, validity interval, and fixed payload class.
  Signature and room AEAD verification complete before an operation can
  mutate any set, roster, admission view, catalog, or pair ledger.

- **SEC-004 — Carrier separation:** The same logical operation is independently
  wrapped for every carrier context with carrier-domain-separated keys and
  nonce material. Different stores do not receive byte-identical ciphertext
  or a common object identifier. Multiple routes to one store/profile context
  carry the exact same persisted envelope/request. Exact retries in one
  context reuse it; a nonce/key pair is never reused for different plaintext.

- **SEC-005 — Pair double sealing:** Pair-sensitive payloads use a
  purpose-, direction-, role-, pair-, and transcript-bound pair key before
  room/carrier sealing. Decrypting a room operation never reveals another
  pair's identity bundle, admission credential, SDP, ICE, transport address,
  v4 handshake, or PQ frame.

- **SEC-006 — Admission before disclosure:** The receiver of a pair identity
  hello authenticates the stable key and grant, checks the exact room-scoped
  frontend policy, and persists the decision before generating SDP/ICE.
  Strict-mode initiators also authenticate the target presence proof/permit
  before generating the hello. Forged stable commitments, permits, grants,
  signatures, or identity substitutions fail only the candidate edge and
  release no sensitive response.

- **SEC-007 — Rechecked admission:** The exact stable identity is checked at
  pair hello, pair auth, transport offer/answer, v4 promotion, reconnection,
  admitted application/data-plane relay enablement, and before delivery of
  decrypted pair control. A newly local-blacklisted peer is disconnected from
  pair/final transports and loses endpoint and decrypted-relay eligibility. A
  local-policy database error is denial for that peer, not an open-room
  fallback. This room-admission decision does not silently mutate the separate
  `FrontendCarrierPolicyV1` or `RoomCarrierAssignmentPolicyV1`: an explicitly
  carrier-authorized `kind="contact"` context may continue opaque operation
  carriage, but gains no planner edge, endpoint promotion, pair plaintext, or
  admission bypass. Denying that exact carrier context stops its use
  independently.

- **SEC-008 — Authority grant limits:** In `authority-grant` mode, grants bind
  `RoomContextId`, exact stable Ed25519 public key, credential generation,
  `notBefore`, and `notAfter`. They are pair-private. Local denial still wins.
  Grants are short-lived; no specification text may claim instantaneous
  remote revocation during a partition. Public revocations name the
  room-scoped stable-identity commitment and a minimum accepted credential
  generation, never the raw stable key or a pair-private grant ID.

- **SEC-009 — Explicit identity-rotation limit:** A denylist entry blocks the
  exact stable identity and its room-scoped commitment. It does not identify a
  person who generates an unrelated key. Rooms requiring that property shall
  use address-book-only or authority-grant mode and issue no grant to the
  replacement key.

- **SEC-010 — Deterministic conflict scope:** An exact duplicate is a no-op.
  Different authenticated bytes for one author/window/sequence slot fork and
  exclude that author's positive/transient state for the bounded window; a
  pinned-authority fork/overquota additionally makes authority admission fail
  closed through the complete credential horizon. Different authenticated bytes for one
  pair/direction/control slot fail only that pair edge. Invalid or
  unauthenticated bytes are bounded garbage and never fail an honest edge.
  Arrival time and server preference never choose a winner.

- **SEC-011 — Retention and replay:** Presence, hints, and provisional pair
  operations expire by public bounds. Missing dependencies buffer only within
  fixed count, byte, and future-window limits. Expired operations never
  resurrect state. Pair-sensitive predecessors are encrypted inside the pair
  ledger. An exact pair-control operation/outbox remains until its
  protocol-defined authenticated successor or pair-private checkpoint; only
  then may it compact to the minimal protected replay/fork audit. That audit is
  retained through the accepted control's inclusive
  `pairControlRetentionWindows` horizon. Deletion is permitted only at the
  start of the following logical window and never manufactures success.

- **SEC-012 — Crash and rollback boundary:** Persisted room frontiers, author
  high-water marks, pair ledgers, v4 checkpoints, exact control outboxes, and
  grant generations update atomically. IndexedDB alone provides crash
  consistency, not proof against restoration of an older complete local
  snapshot. Missing room operations/frontiers simply reconcile after restore;
  this protocol has no signed global room-frontier checkpoint and does not
  claim generic snapshot detection. Only a restored existing pair edge that
  later presents an older authenticated v4 transcript/counter to an
  uncompromised peer retaining newer edge state is peer-rejected and
  rehandshaken. Stronger pre-contact or room/frontend rollback detection
  requires a named non-rollback platform/synchronization anchor.

- **SEC-013 — Safe store hints:** A store descriptor proves possession of its
  stable store key and exact compatibility. Route records are separately
  store-signed, leased, scheme-bounded, and canonical. The frontend rejects
  unsupported schemes, remotely supplied private-network targets, ambient
  credentials, route confusion, invalid signatures, and incompatible
  retention before any room-derived request. A user may explicitly authorize
  an exact local/LAN route; remote hints can never grant that authority.

- **SEC-014 — Local carrier allow/deny:** The frontend may allow exact
  `StoreId`s and deny exact stores, routes, origins, or adapter families.
  Denial wins. Remote room members and stores cannot clear local denial.
  Stopping a carrier affects delivery only; it never deletes or rolls back
  logical room state.

- **SEC-015 — Proactive path use:** When evaluating the conditional
  censorship-resilience claim in Section 1.6 under one registered blocking
  model, every carrier/path included in that claim is exercised at its fixed
  or locally declared contact boundary. A secret is not sent to a new path
  only after another path fails. Store contexts are independently wrapped;
  alternative routes to one context replay the exact idempotent request under
  the fixed route cycle.

- **SEC-016 — Honest independent-path evidence:** Operator names, hostnames,
  process counts, regions, and route counts are not independence evidence.
  Any published conditional censorship-resilience wording under Section 1.6
  requires measured blocking-domain diversity from declared vantage points
  and names the events that exhaust it.

- **SEC-017 — Unlinkable or fixed admission to stores:** Public stores enforce
  size and rate quotas without receiving room or stable application identity.
  Profile v1 uses the exact scheme-1 Blind-RSA Privacy Pass issuance and fixed
  public allocation contract, with its explicit source/timing and Sybil
  limits. Copies of one logical request across store routes are idempotent,
  not multiple redemptions. Any future proof-of-work gate is only
  resource-weighted Sybil-costing: it cannot establish one-human/personhood,
  identity continuity, room admission, blacklist enforcement, store
  honesty/operator independence, BFT membership/quorum, or fair issuance.
  Such work is store/profile/window/request scoped, contains no room-derived
  input, is bounded by local client resource policy, and cannot raise an R2 or
  independence claim.

- **SEC-018 — Privacy-safe observability:** Logs and metrics contain only
  public profile/window, size class, chunk, route class, aggregate count,
  latency, outcome, and a bounded public-accountability fault kind/evidence
  digest. Proof/receipt/chunk bodies, capabilities, trial-decryption results,
  operation IDs, stable commitments, pair slots, grants, and decrypted state
  are forbidden.

- **SEC-019 — No custom-crypto release path:** Every AEAD, signature, PAKE,
  KEM, hybrid combiner, credential, OMR, PIR, and anonymous-token
  instantiation requires a cited specification, deterministic vectors,
  browser-capable implementation where applicable, misuse tests, and external
  review.

- **SEC-020 — Fresh PQ healing:** Provisional rendezvous DH/KEM keys protect
  only pair bootstrap and are erased after v4 handoff. Accepted operation IDs
  remain non-secret replay evidence, but after erasure an alternate old
  bootstrap ciphertext may be classifiable only as bounded stale garbage;
  late bootstrap equivocation can therefore be missed under store omission.
  Only post-promotion causal PQ slots retain their bounded one-use audit
  secrets. Durable healing uses the fresh v4 roots and stable session role. A
  detected fork, rollback, causal expiry, or retry exhaustion marks that edge
  stalled and requires a fresh hybrid handshake; it never resets to epoch zero
  or changes another edge, room roster, or carrier set.

- **SEC-021 — Bounded adversarial work:** Immutable room policy fixes
  operation validity/lifetime bounds, each delivery profile fixes only its
  public carrier geometry, one local `ClientResourcePolicyV1` fixes per-room
  carrier, parser, custody, dependency-buffer, pair-open, pair-ledger,
  and outbox work, and one `ClientGlobalResourcePolicyV1` bounds initialized
  rooms, public catalogs/routes/schedulers, authenticated contact contexts,
  L3 due work, and pending exact exports. Pair-open budgets include header
  validation, hybrid-KEM decapsulation, KDF/export, tag comparison, and
  AEAD—not merely successful decryptions. Saturation is an explicit
  availability failure; it never authorizes a traffic burst, an arrival-order
  winner, or a locally truncated set presented as convergent.

- **SEC-022 — Pair-step metadata minimization:** A room-visible pair step
  exposes only a one-use routing tag, optional bootstrap header, payload/size
  class, fixed ciphertext length, bootstrap-vs-established class, and the
  containing operation author/timing. The common identity-bootstrap schedule
  and equal envelope class do not directly distinguish HELLO from ACCEPT.
  Within one payload class it does not reveal the exact established kind, but
  codec-v1 class 1 reveals that the pair step belongs to the large-body family
  (for example, a complete SDP candidate or `PQ_CONTROL`). Direction,
  sequence, predecessor, presence IDs, pair ID, admission material, and
  pair-sensitive dependencies are inside pair AEAD. The outer operation
  dependency list for `PAIR_STEP` is empty.

- **SEC-023 — Malicious rendezvous non-disclosure:** Store request schemas,
  allocation state, object identifiers, persistence keys, logs, metrics, and
  route protocols contain no capability-derived, room-equality,
  protocol-carried application stable-identity-equality, membership,
  co-membership, social-edge, admission, or pair target value. A store may
  process only the public profile/window/class/ordinal geometry defined here.
  Cryptographic blindness holds even when every store colludes; bearer source
  addresses, access accounts, route credentials, timing, shared host/locator
  observations, and cohort use may still correlate requests or roles and are
  claimed only at the separately measured L2/source-metadata level. A store
  colluding with a capability holder has the room-level view already disclosed
  in the threat model, but still cannot decrypt another admitted pair's
  double-sealed identity, SDP/ICE, v4, or PQ payload.

- **SEC-024 — Evidence-compiled claims fail closed:** Every positive protocol,
  product, UI, whitepaper, and publication claim resolves one
  `ClaimDefinitionV1` and one current `ClaimEvaluationV1` under the release
  registry. Positive wording is renderable only for `state="satisfied"` when
  every transitive assumption, implementation, test, formal-result, deployment,
  and measurement reference resolves, is current, matches the exact scope, and
  passes its registered predicate. Missing, expired, stale, saturated,
  inconclusive, contradicted, or out-of-scope evidence produces a non-positive
  state; a cached sentence cannot outlive its evaluation.

- **SEC-025 — Room-blind accountability evidence:** Store custody promises,
  checkpoints, inclusion paths, breach proofs, and conflict proofs are
  store-signed public-profile evidence with no room-derived or pair-derived
  field. A valid proof may downgrade or exclude the exact store/profile/window
  from availability claims, but never becomes a room operation, store vote,
  delivery receipt, completeness proof, reducer input, or proof that an
  unavailable store misbehaved. Evidence is retained under fixed byte/count
  caps partitioned by exact store/profile; saturation fails that partition
  closed and cannot select a flattering subset, but a Byzantine unselected
  store cannot suppress claims over independent selected stores.

- **SEC-026 — No source-private fallback:** While SP1 is required, the global
  frontend route filter rejects every nonconforming or unmeasured public-store
  route before dispatch. Every network-capable public-store adapter is behind
  one kernel-owned egress gate, and every privacy-mechanism packet emitter is
  behind the same kernel boundary. Before any prewarm, dummy, cover, request,
  retry, or failure-control bytes can leave the device, the atomic
  source-exposure/volume ledger records the exact context set, request/event,
  route, mechanism, profile, policy generation, interval, volume epoch,
  privacy-message ID when applicable, and exact privacy packet/byte charge. A
  direct or otherwise nonconforming exposure permanently taints the
  `(context, interval)` across policy generations; policy rotation, retry,
  route expiry, evidence deletion, restart, or a later private request cannot
  erase it. The client-global cumulative volume budget likewise cannot reset
  on any of those events; it rotates only with mechanism-specific
  unlinkability evidence. A floor/profile change invalidates prewarm and no
  positive result is possible until one new wholly covered interval completes.
  Failure to preserve the complete floor history, egress audit, volume ledger,
  prewarm, or evidence caps is unavailability/unknown, not a direct-network
  fallback.

- **SEC-027 — No cross-version authentication downgrade:** V0.4 rejects a
  successor invitation, room policy, authenticated object, or migration
  statement before state mutation or disclosure. A future PQ-authenticated
  successor verifies every hybrid-signed object under its complete
  classical-and-PQ rule, verifies every transcript-bound category, and exposes
  every out-of-band trust assumption; negotiation is never remotely weakened
  and claimed partial coverage is invalid. It creates a fresh room context,
  capability, and successor session. Identity continuity is selected locally,
  never by the sender, and requires a pre-compromise nonrollback classical
  anchor, out-of-band re-verification, or a previously trusted PQ authority;
  otherwise the successor explicitly presents a new identity rather than
  silently importing v0.4 trust or permissions.

### 3.3 Metadata and assurance boundary

For every normative equation from this point onward, unless an algorithm is
named explicitly, `H(x) = SHA-256(x)`, `||` is byte concatenation, quoted
domain strings are their exact ASCII octets, and `ZERO32` is exactly 32 zero
octets. `Base64urlNoPad(x)` is the unique RFC 4648 URL-safe base64 encoding
with no padding; lowercase or alternate `base64url` functions do not exist.
`Byte(x)`, `U16BE(x)`, `U32BE(x)`, and `U64BE(x)` are respectively the exact
unsigned 8-, 16-, 32-, and 64-bit big-endian encodings and reject out-of-range
or JavaScript-unsafe inputs before any preimage is formed.

Assurance is scoped evidence, not one flattering tier:

```ts
type CohortScope =
  "measured-shared" | "declared-shared" | "room-unique" | "unknown";
type AccessPattern =
  | "fixed-cohort-scan"
  | "on-demand-public-scan"
  | "contact-dependent"
  | "oblivious-access-reviewed"
  | "unknown";
type SourceMetadata =
  | "bearer-visible"
  | "split-relay-gateway"
  | "anonymity-network-measured"
  | "unknown";
type SourcePrivacyState =
  "not-required" | "measured-bound-met" | "tainted-or-insufficient" | "unknown";
type TransportDisclosure = "pre-sdp-admission-pair-sealed" | "not-conformant";
type TransportBindingEvidence =
  | "live-certificate-match"
  | "registered-native-enforcement"
  | "not-applicable"
  | "not-conformant";
type IdentityDisclosure =
  | "strict-presence-proof-gated"
  | "first-flight-visible-to-selected-capability-holder"
  | "not-conformant";
type PqState =
  | "fresh-hybrid"
  | "healing-in-progress"
  | "healed-after-fresh-entropy"
  | "stalled"
  | "not-established";
type CarrierAvailability = "active-exercised" | "failed-or-expired" | "unknown";
type NonIpControlReadiness =
  "ready-before-retention" | "exhausted" | "not-applicable" | "unknown";

type CohortEvidenceValueV1 = {
  scope: CohortScope;
  observedRawPopulation: number | null;
  // Conservative lower bound after subtracting evaluator-known or
  // adversary-controlled/Sybil sources under the registered method.
  attackerUnknownCoverLowerBound: number | null;
};

type BlockingDomainEvidenceValueV1 = {
  blockingDomainId: Bytes32 | "unknown";
  blockingModelId: Bytes32 | "unknown";
  jointExperimentId: Bytes32 | "unknown";
  availabilityPathId: Bytes32 | "unknown";
  availabilityPathEvidenceId: Bytes32 | "unknown";
  availabilityEvidenceId: Bytes32 | "unknown";
};

type NonNegativeRationalV1 = {
  numerator: bigint; // >= 0
  denominator: bigint; // > 0
};

// Parameter IDs and units resolve human-readable, typed definitions in the
// release's formal-obligation registry. Values remain visible here rather
// than disappearing behind one opaque trace hash.
type SourcePrivacyFormalParameterBindingV1 = {
  parameterId: Bytes32;
  unitId: Bytes32;
  relation: "exact" | "lower-bound" | "upper-bound";
  value: NonNegativeRationalV1;
  measurementEvidenceId: Bytes32;
};

type SourcePrivacyRouteSelectionMassV1 = {
  layerIndex: number;
  operatorDomainId: Bytes32;
  selectionMass: NonNegativeRationalV1;
};

type SourcePrivacyClassifierEvaluationV1 = {
  version: 1;
  sourcePrivacyProfileId: Bytes32;
  mechanismVersionHash: Bytes32;
  measurementPopulationId: Bytes32;
  adversaryModelId: Bytes32;
  preregistrationDigest: Bytes32;
  boundedDatasetDigest: Bytes32;
  entryObservationPointDigest: Bytes32;
  egressObservationPointDigest: Bytes32;
  collusionModel: "entry-and-egress";
  results: readonly {
    requestClass: PublicStoreRequestClassV1;
    outcomeClass:
      "success" | "drop" | "delay" | "timeout" | "retry" | "route-failure";
    baseRate: NonNegativeRationalV1;
    prAuc: NonNegativeRationalV1;
    configuredFalsePositiveRate: NonNegativeRationalV1;
    truePositiveRateAtConfiguredFpr: NonNegativeRationalV1;
  }[];
  acceptancePolicyHash: Bytes32;
  result: "thresholds-met" | "thresholds-not-met";
};

type SourcePrivacyEvidenceValueV1 = {
  sourcePrivacyProfileId: Bytes32;
  mechanismId: Bytes32;
  mechanismVersionHash: Bytes32;
  publicCarrierContextId: Bytes32;
  intervalNumber: bigint;
  intervalStartMs: bigint;
  intervalEndMs: bigint;
  sourceExposureRecordDigest: Bytes32;
  usedRouteSetDigest: Bytes32;
  floorHistoryDigest: Bytes32;
  operatorDomainSetDigest: Bytes32;
  measurementPopulationId: Bytes32;
  adversaryModelId: Bytes32;
  formalSecurityDefinitionId: Bytes32;
  privacySessionDefinitionId: Bytes32;
  topologyModelId: Bytes32;
  routeSelectionModelId: Bytes32;
  traceModelId: Bytes32;
  taggingModelId: Bytes32;
  clockModelId: Bytes32;
  topologyLayerCount: number;
  formalParameterBindings: readonly SourcePrivacyFormalParameterBindingV1[];
  formalParameterBindingsDigest: Bytes32;
  routeSelectionMassByLayer: readonly SourcePrivacyRouteSelectionMassV1[];
  routeSelectionMassDigest: Bytes32;
  volumeEpochId: Bytes32;
  anonymitySetLowerBoundK: number;
  corruptMixingDomainsUpperBoundT: number;
  independentMixingDomainsLowerBound: number;
  mixingDomainBindings: readonly {
    operatorDomainId: Bytes32;
    independenceEvidenceId: Bytes32;
  }[];
  storeAndEgressOperatorDomainIds: readonly Bytes32[];
  advantageEpsilonNumerator: bigint;
  advantageEpsilonDenominator: bigint;
  formalResultDigest: Bytes32;
  measurementSampleCount: number;
  classifierEvaluationDigest: Bytes32;
  result: "bound-met" | "bound-not-met";
};

const UNKNOWN_BLOCKING_DOMAIN_EVIDENCE_V1 = {
  blockingDomainId: "unknown",
  blockingModelId: "unknown",
  jointExperimentId: "unknown",
  availabilityPathId: "unknown",
  availabilityPathEvidenceId: "unknown",
  availabilityEvidenceId: "unknown",
} as const;

type EvidenceV1<T> = {
  value: T;
  evidenceClass: "measured" | "declared";
  observedAtMs: bigint;
  expiresAtMs: bigint;
  vantageId: string;
  methodId: string;
  measurementSeriesId: Bytes32;
  seriesGeneration: bigint;
  subjectScopeId: Bytes32;
  rawEvidenceDigest: Bytes32;
  evaluatorAttestation: Uint8Array;
  evidenceId: Bytes32;
};

type CarrierAssuranceBindingV1 =
  | {
      kind: "public-store";
      routeId: Bytes32;
    }
  | {
      kind: "contact";
      adapterProtocolId: number; // unsigned 16-bit
      authenticatedSessionContextId: Bytes32;
    }
  | {
      kind: "portable-bundle";
      adapterProtocolId: number; // unsigned 16-bit
      bundleCarrierContextId: Bytes32;
      custodyPathContextId: Bytes32;
    };

type CarrierAssuranceV1 = {
  carrierContextId: Bytes32;
  carrierInstanceId: Bytes32;
  kind: "public-store" | "contact" | "portable-bundle";
  binding: CarrierAssuranceBindingV1;
  storeId: Bytes32 | null;
  deliveryProfileHash: Bytes32;
  cohortScope: readonly EvidenceV1<CohortEvidenceValueV1>[];
  accessPattern: readonly EvidenceV1<AccessPattern>[];
  sourceMetadata: readonly EvidenceV1<SourceMetadata>[];
  operatorDomain: readonly EvidenceV1<Bytes32 | "unknown">[];
  availabilityPath: readonly EvidenceV1<Bytes32 | "unknown">[];
  blockingDomain: readonly EvidenceV1<BlockingDomainEvidenceValueV1>[];
  availability: readonly EvidenceV1<CarrierAvailability>[];
  nonIpControlReadiness: readonly EvidenceV1<NonIpControlReadiness>[];
};

type EdgeAssuranceV1 = {
  stableEdgeId: Bytes32;
  transportDisclosure: TransportDisclosure;
  transportBindingEvidence: TransportBindingEvidence;
  identityDisclosure: IdentityDisclosure;
  pqState: PqState;
};

type SourcePrivacyRuntimeSnapshotV1 = {
  floor: SourcePrivacyFloorV1;
  evaluationIntervalNumber: bigint | null;
  floorHistory: readonly {
    policyGeneration: bigint;
    effectiveAtMs: bigint;
    floor: SourcePrivacyFloorV1;
  }[];
  floorHistoryDigest: Bytes32;
  // Complete client-global set, not the current room's carrier projection.
  exposures: readonly PublicContextSourceExposureV1[];
  volumeEpochs: readonly SourcePrivacyVolumeEpochV1[];
  evaluatedIntervalTrafficCharges: readonly SourcePrivacyTrafficChargeV1[];
  evaluatedIntervalTrafficChargeSetDigest: Bytes32;
  evaluatedIntervalTrafficChargeChainStartDigest: Bytes32;
  evaluatedIntervalTrafficChargeChainEndDigest: Bytes32;
  evidence: readonly EvidenceV1<SourcePrivacyEvidenceValueV1>[];
  exposureSetDigest: Bytes32;
  volumeEpochSetDigest: Bytes32;
  evidenceSaturated: boolean;
  evidenceSaturationUntilMs: bigint | null;
  evidenceSaturationWitnessId: Bytes32 | null;
};

type AssuranceRuntimeFactsV1 = {
  localRoomId: LocalRoomId;
  localVaultAssuranceContextId: Bytes32;
  referenceWindow: bigint;
  carrierPolicyGeneration: bigint;
  assuranceTimeHighWaterMs: bigint;
  assuranceClockUncertaintyMs: bigint;
  assuranceClockState: "safe" | "unsafe";
  observedDeliveryFrontierId: Bytes32;
  l3RequiredWorkDigest: Bytes32;
  blockingModelId: Bytes32;
  consistency: "converged-to-observed-frontier" | "reconciling" | "partitioned";
  resourceState: "within-bounds" | "overcapacity";
  activeCarrierContextIds: readonly Bytes32[];
  // Current public-route and authenticated-contact instance IDs. Portable
  // bundle IDs are episodic and never enter this set.
  activeCarrierInstanceIds: readonly Bytes32[];
  // Contact/portable carrierInstanceIds with a current accepted bounded L3
  // custody obligation/path; this does not make a bundle an active scheduler.
  readyL3CarrierInstanceIds: readonly Bytes32[];
  assuranceEvidenceSaturated: boolean;
  assuranceEvidenceSaturationUntilMs: bigint | null;
  assuranceEvidenceSaturationWitnessId: Bytes32 | null;
  sourcePrivacyRuntime: SourcePrivacyRuntimeSnapshotV1;
  l3RequiredIntentState: "complete-within-bounds" | "missing-or-saturated";
  l3CapacityBeforeExpiry: "sufficient" | "insufficient" | "unknown";
};

type RoomAssuranceV4 = {
  roomIsolation: "capability-bound-e2e";
  consistency: "converged-to-observed-frontier" | "reconciling" | "partitioned";
  carriers: readonly CarrierAssuranceV1[];
  edges: readonly EdgeAssuranceV1[];
  summary: {
    storeTopology:
      | "no-usable-carrier"
      | "single-carrier-dependent"
      | "multi-store-union"
      | "multi-carrier-store-carry-forward";
    cohortScope: CohortScope;
    accessPattern: AccessPattern;
    sourceMetadata: SourceMetadata;
    publicStoreSourcePrivacy: SourcePrivacyState;
    operatorIndependence: "measured-independent" | "declared" | "unknown";
    censorshipResilience:
      | "not-established"
      | "single-domain-dependent"
      | "measured-diverse-active"
      | "exhausted-or-unknown";
    shutdownControl:
      | "not-established"
      | "tested-non-ip-control-ready"
      | "exhausted"
      | "unknown";
    transportDisclosure: TransportDisclosure | "not-established";
    identityDisclosure: IdentityDisclosure | "not-established";
    pqState: PqState;
    evidenceIds: readonly Bytes32[];
  };
};

type R2NodeV1 =
  | {
      kind: "participant";
      presenceOperationId: Bytes32;
    }
  | {
      kind: "operation-author";
      operationId: Bytes32;
      authorEpochEd25519Key: Bytes32;
    }
  | {
      kind: "public-store";
      storeId: Bytes32;
      carrierInstanceId: Bytes32;
    };

type R2ScopedEvidenceValueV1 =
  | {
      kind: "participant-coverage";
      presenceOperationId: Bytes32;
      carrierInstanceIds: readonly Bytes32[];
      resourceState: "within-bounds";
    }
  | {
      kind: "edge-reachability";
      temporalEdgeId: Bytes32;
      result: "fair-authenticated";
    }
  | {
      kind: "edge-capacity";
      temporalEdgeId: Bytes32;
      maxDeliverableObjects: number;
      maxDeliverableBytes: bigint;
      scheduleSimulationDigest: Bytes32;
    }
  | {
      kind: "proactive-store-use";
      faultUnitId: Bytes32;
      participantPresenceOperationIds: readonly Bytes32[];
      operationIds: readonly Bytes32[];
      custodyBindings: readonly {
        operationId: Bytes32;
        custodyPromiseDigest: Bytes32;
        finalizedCheckpointHash: Bytes32;
        publicChunkHash: Bytes32;
      }[];
    };

type R2ScopedEvidenceV1 = {
  claimScopeId: Bytes32;
  value: R2ScopedEvidenceValueV1;
  observedAtMs: bigint;
  expiresAtMs: bigint;
  methodId: string;
  rawEvidenceDigest: Bytes32;
  evaluatorAttestation: Uint8Array;
  evidenceId: Bytes32;
};

type R2HonestStoreFaultUnitV1 = {
  faultUnitId: Bytes32;
  storeId: Bytes32;
  carrierInstanceIds: readonly Bytes32[];
  operatorDomainId: Bytes32;
  availabilityPathId: Bytes32;
  blockingDomainId: Bytes32;
  proactiveUseEvidenceId: Bytes32;
};

type R2SchedulerWorkloadV1 = {
  version: 1;
  referenceWindow: bigint;
  entries: readonly {
    workId: Bytes32;
    kind:
      | "required-operation"
      | "fixed-public-event"
      | "authorized-competing-operation"
      | "l3-control";
    carrierInstanceId: Bytes32;
    operationId: Bytes32 | null;
    scheduledEventId: Bytes32 | null;
    usableFromLogicalWindow: bigint;
    expiresAfterLogicalWindow: bigint;
    maxObjects: number;
    maxBytes: bigint;
  }[];
  resourcePolicyDigest: Bytes32;
  fairEdgeAssumptionDigest: Bytes32;
  authorizedValidWorkBoundDigest: Bytes32;
};

// Publication/conformance artifact only; never a runtime room badge.
type R2ConformanceRecordV1 = {
  version: 1;
  claimScopeId: Bytes32;
  referenceWindow: bigint;
  evaluationTimeMs: bigint;
  evaluationClockUncertaintyMs: bigint;
  operationsDigest: Bytes32;
  participants: readonly {
    presenceOperationId: Bytes32;
    currentAssuranceEvidenceIds: readonly Bytes32[];
    coverageEvidenceId: Bytes32;
  }[];
  requiredOperations: readonly {
    operationId: Bytes32;
    authorNodeId: Bytes32;
    expiresAfterLogicalWindow: bigint;
  }[];
  nodes: readonly R2NodeV1[];
  temporalEdges: readonly {
    temporalEdgeId: Bytes32;
    fromNodeId: Bytes32;
    toNodeId: Bytes32;
    carrierInstanceId: Bytes32;
    faultUnitId: Bytes32;
    usableFromLogicalWindow: bigint;
    usableThroughLogicalWindow: bigint;
    reachabilityEvidenceId: Bytes32;
    capacityEvidenceId: Bytes32;
  }[];
  // Exact independently operated public-store units assumed honest for this
  // bounded delivery theorem; all other carriers are outside its liveness set.
  honestStoreFaultUnits: readonly R2HonestStoreFaultUnitV1[];
  scopedEvidence: readonly R2ScopedEvidenceV1[];
  faultThresholdF: number;
  blockingModelId: Bytes32;
  schedulerSemanticsHash: Bytes32;
  schedulerImplementationArtifactSetDigest: Bytes32;
  schedulerCanonicalTraceSetDigest: Bytes32;
  schedulerWorkloadDigest: Bytes32;
  schedulerRefinementResultDigest: Bytes32;
  rawDatasetDigest: Bytes32;
  evaluatorAttestation: Uint8Array;
};
```

`RoomAssuranceV4 = DeriveAssurance(carriers, edges, runtimeFacts, now)` is the
only aggregate. `runtimeFacts` is the exact pre-assurance
`AssuranceRuntimeFactsV1` projection of active carrier selection, local
delivery consistency, current accepted L3 custody-path instances, L3 due-work
caps, assurance-evidence custody, the complete client-global source-privacy
floor/exposure snapshot, capacity, and semantic horizons; it
contains no UI label or derived assurance value. Records and the contributing
`evidenceIds` are sorted and
deduplicated by ID. A carrier is _used_ when the room published to, reconciled
from, or accepted custody from it during the unexpired evidence interval.
SP1 is evaluated only from
`runtimeFacts.sourcePrivacyRuntime.{floorHistory,exposures,volumeEpochs,evaluatedIntervalTrafficCharges,evidence}`;
it never reads ambient frontend policy or a room-local carrier subset. This
snapshot is the source-privacy SSOT and includes every public context touched
in the evaluated interval plus every still-linkable client-global volume
epoch and every privacy-traffic charge in the evaluated interval, including
inactive, failed, and unassigned contexts.

`localVaultAssuranceContextId` is 32 CSPRNG bytes generated once before the
vault accepts assurance evidence, atomically persisted with that vault, never
sent to a carrier or synchronized as a device/account identifier, and rotated
only on explicit vault reset. A missing, duplicated migration constant, or
corrupt value makes assurance unavailable until a fresh local context and
measurements are created.

`l3RequiredWorkDigest` is derived in the same protected atomic snapshot as
the other runtime facts:

```text
L3RequiredWorkId(localRoomId, operationId, deliveryProfileHash) =
  H(
    "p2party/delivery-work/v1" ||
    Byte(0x03) || // registered L3 due-work kind
    Canonical(localRoomId, operationId, deliveryProfileHash)
  )

l3RequiredWorkDigest =
  H(
    "p2party/l3-required-work-snapshot/v1" ||
    Canonical(localRoomId) ||
    U64BE(referenceWindow) ||
    observedDeliveryFrontierId ||
    Canonical(
      Sort(
        exact current room-scoped
        (L3RequiredWorkId, semanticExpiryLogicalWindow,
         semanticDeadlineUnixMs, DeliveryProfileHash)
        tuples required from L3
      )
    ) ||
    Canonical(
      l3RequiredIntentState,
      l3CapacityBeforeExpiry,
      requiredWorkSaturated,
      firstSaturatedRequiredWorkId
    )
  )
```

The tuple set includes work that is required but not currently representable;
the bounded saturation witness commits that case. Adding/removing work,
changing a semantic horizon/profile/frontier, or changing the capacity or
saturation result therefore invalidates earlier L3-readiness evidence.

V0.4 defines no closed runtime `L2`, `R2-BEC`, “fully secure,” or
“censorship-resistant” badge. The UI renders the granular closed fields above
and their registry-pinned explanatory copy; it shall not hand-code a second
umbrella derivation. S1/R2-BEC are conformance/evaluation packages asserted only
by the versioned machine-readable claim/evidence registry for an exact scope,
not values inside `RoomAssuranceV4`.
The client persists `assuranceTimeHighWaterMs =
max(previousHighWater, trustedClockEstimateMs)` before assurance derivation.
If the estimate plus its captured uncertainty is below the prior high-water,
or uncertainty exceeds the release method's bound,
`assuranceClockState="unsafe"` and every time-based carrier field projects to
unknown/exhausted until a trusted reading at or above the high-water and a
fresh measurement restore `"safe"`. A wall-clock rollback therefore cannot
resurrect expired evidence. In the safe state, `now` below means the persisted
high-water value.

Evidence is valid only when
`runtimeFacts.assuranceClockState == "safe"`,
`observedAtMs <= now < expiresAtMs`,
`expiresAtMs - observedAtMs <= maxAssuranceEvidenceAgeMs` for that carrier's
delivery profile, `vantageId` and `methodId` name registered release methods,
and:

```text
EvidenceId(
  carrierInstanceId,
  binding,
  field,
  recordWithoutEvidenceId
) =
  H(
    "p2party/assurance-evidence/v1" ||
    carrierInstanceId ||
    Canonical(binding) ||
    EvidenceFieldByte(field) ||
    Canonical(recordWithoutEvidenceId)
  )

EvidenceFieldByte =
  cohortScope 0x00 | accessPattern 0x01 |
  sourceMetadata 0x02 | operatorDomain 0x03 |
  availabilityPath 0x04 | blockingDomain 0x05 |
  availability 0x06 | nonIpControlReadiness 0x07
```

equals `evidenceId`. `cohortScope.value.scope="measured-shared"` requires
`evidenceClass="measured"`, non-negative safe integers
`observedRawPopulation >= attackerUnknownCoverLowerBound >=
minMeasuredSharedCohort`, and a registered adversarial-subtraction method for
the exact delivery profile; its semantic validation requires
`minMeasuredSharedCohort >= 2`. The lower bound excludes sources the evaluator
or malicious-store model can identify as controlled/Sybil and is not a
personhood claim. Every other cohort scope requires both population fields to
be null.
`sourceMetadata.value="anonymity-network-measured"` requires
`evidenceClass="measured"`;
every global `sourcePrivacyRuntime.evidence` record is measured and uses the
separate `SourcePrivacySubjectScopeId` formula. It binds the exact
context/interval/exposure/floor-history/route/mechanism/profile/domain sets,
formal security/session definitions, topology and per-layer selection mass,
visible formal parameters, cumulative volume epoch, and one registry-pinned
SP1 experiment; its validity span is at most the selected profile's
`evidenceMaxAgeMs`. `result="bound-met"` additionally requires safe integers
`anonymitySetLowerBoundK >= 2`, at least `max(2,t+1)` exact independently
evidenced mixing domains disjoint from store/egress domains, checked canonical
probability/parameter rationals, both packet/byte caps, the checked
non-vacuity inequality from Section 4.2, and a validated `formalResultDigest`
resolving one release-bound `proved-within-scope` computational result that
covers all those exact coordinates. `measurementSampleCount` is a positive
safe integer satisfying the profile minimum, and
`classifierEvaluationDigest` resolves the exact preregistered low-base-rate
entry/egress-collusion deployment falsification/evaluation report and its
per-class PR-AUC/TPR-at-FPR results;
`cohortScope.value.scope="declared-shared"` requires
`evidenceClass="declared"`. `availability="active-exercised"` and
`nonIpControlReadiness="ready-before-retention"` require measured evidence.
`blockingDomain.value` is valid only when all six IDs are `"unknown"` or all
six are `Bytes32`. A mixed tuple is invalid and reduces to exact
`UNKNOWN_BLOCKING_DOMAIN_EVIDENCE_V1`. Every all-Bytes32 value requires
measured evidence, byte-equality between its `availabilityPathId` and the
instance's current path projection, membership of
`availabilityPathEvidenceId` in that current projection's contributing IDs,
and membership of `availabilityEvidenceId` in the current fresh measured
`active-exercised` projection's contributing IDs. The joint-method
attestation covers this complete composite; unrelated path/availability series
cannot be spliced into its group.
The carrier binding is valid only when its kind equals the outer kind and:

```text
public-store:
  storeId != null
  and carrierContextId ==
      PublicCarrierContextId(storeId, deliveryProfileHash)
  and carrierInstanceId ==
      PublicRouteInstanceId(carrierContextId, binding.routeId)

contact:
  storeId == null
  and carrierContextId == carrierInstanceId
  and carrierInstanceId ==
      H(
        "p2party/contact-carrier-instance/v1" ||
        U16BE(binding.adapterProtocolId) ||
        binding.authenticatedSessionContextId ||
        deliveryProfileHash
      )

portable-bundle:
  storeId == null
  and carrierContextId == binding.bundleCarrierContextId
  and carrierInstanceId ==
      PortableCarrierInstanceId(
        binding.adapterProtocolId,
        binding.bundleCarrierContextId,
        binding.custodyPathContextId,
        deliveryProfileHash
      )
```

The registered method supplies an immutable `measurementUniverseId`.
`subjectScopeId` must equal:

```text
cohortScope:
  H("p2party/assurance-subject/cohort/v1" ||
    deliveryProfileHash || measurementUniverseId)

accessPattern:
  H("p2party/assurance-subject/access/v1" ||
    runtimeFacts.localVaultAssuranceContextId ||
    carrierContextId ||
    U64BE(runtimeFacts.carrierPolicyGeneration))

sourceMetadata | operatorDomain | availabilityPath |
blockingDomain | availability:
  H("p2party/assurance-subject/carrier/v1" ||
    Canonical(kind, carrierContextId, carrierInstanceId, binding,
              storeId, deliveryProfileHash) ||
    measurementUniverseId)

nonIpControlReadiness:
  H("p2party/assurance-subject/l3/v1" ||
    Canonical(runtimeFacts.localRoomId) ||
    U64BE(runtimeFacts.referenceWindow) ||
    runtimeFacts.observedDeliveryFrontierId ||
    runtimeFacts.l3RequiredWorkDigest ||
    carrierInstanceId)
```

For the global source-privacy SSOT, `subjectScopeId` instead equals the
`SourcePrivacySubjectScopeId` formula in Section 4.2 and:

```text
SourcePrivacyEvidenceId =
  H(
    "p2party/source-privacy-evidence/v1" ||
    Canonical(evidence record without evidenceId)
  )
```

An evidence record for another vault scheduler, profile, route/contact,
room/frontier, or backlog therefore fails scope validation even when its
method and times are fresh.

Assurance evidence is never accepted from a room operation, store response, or
carrier-provided label. `methodId` resolves to one release-pinned local
measurement module or external attestation verifier and its trust keys,
dataset schema, path-ID derivation, corruption/Sybil bound, and conservative
value mapping. Before acceptance, that verifier authenticates
`evaluatorAttestation` over the exact
`(kind, carrierContextId, carrierInstanceId, binding, storeId,
deliveryProfileHash, field, value, evidenceClass,
vantageId, methodId, measurementSeriesId, seriesGeneration, subjectScopeId,
observedAtMs, expiresAtMs,
rawEvidenceDigest)` transcript; the digest resolves
to retained bounded raw evidence or a publication artifact. For a
source-privacy record, the registered verifier instead authenticates the
complete `EvidenceV1<SourcePrivacyEvidenceValueV1>` projection without
`evaluatorAttestation/evidenceId`, including its exposure, floor-history,
route-set, domain-set, formal-parameter, selection-mass, volume-epoch,
interval, formal-result, and classifier digests.
Without an
independently authenticated population mechanism or a registered
corruption/Sybil bound, `attackerUnknownCoverLowerBound` is exactly zero and
raw population is informational only. Failure yields the field's exact
unknown value and cannot upgrade assurance.
The model ID resolves under `assuranceMethodRegistryHash` to one
content-addressed censor action set, vantage set, clock interval, and joint
multi-path experiment method plus one non-negative integer
`faultThresholdF`; the joint experiment ID verifies under that method.
`runtimeFacts.blockingModelId` is the one locally selected registered model
for this aggregate. Evidence measured under another model is retained for
audit but cannot contribute to this aggregate.

`R2ConformanceRecordV1` is the sole R2-BEC conformance-result SSOT. Every array
in the record and its raw dataset is sorted by the complete canonical tuple,
duplicate-free, and bounded by the release registry's publication limits.
Every reference resolves exactly once. The following derivations close its
graph and evidence namespaces:

```text
R2NodeId(node) =
  H("p2party/r2-node/v1" || Canonical(node))

R2TemporalEdgeId(edge) =
  H(
    "p2party/r2-temporal-edge/v1" ||
    Canonical(
      edge.fromNodeId,
      edge.toNodeId,
      edge.carrierInstanceId,
      edge.faultUnitId,
      edge.usableFromLogicalWindow,
      edge.usableThroughLogicalWindow
    )
  )

R2FaultUnitId(unit, blockingModelId) =
  H(
    "p2party/r2-store-fault-unit/v1" ||
    blockingModelId ||
    unit.storeId ||
    Canonical(unit.carrierInstanceIds) ||
    unit.operatorDomainId ||
    unit.availabilityPathId ||
    unit.blockingDomainId
  )

R2TemporalGraphCoordinatesDigest =
  H(
    "p2party/r2-temporal-graph/v1" ||
    Canonical(nodes) ||
    Canonical(
      Sort(
        for each temporal edge:
          (fromNodeId, toNodeId, carrierInstanceId, faultUnitId,
           usableFromLogicalWindow, usableThroughLogicalWindow)
      )
    ) ||
    Canonical(
      Sort(
        for each honest store unit:
          (faultUnitId, storeId, carrierInstanceIds, operatorDomainId,
           availabilityPathId, blockingDomainId)
      )
    )
  )

R2SchedulerWorkloadDigest =
  H(
    "p2party/r2-scheduler-workload/v1" ||
    Canonical(R2SchedulerWorkloadV1)
  )

R2SchedulerWorkId =
  H(
    "p2party/r2-scheduler-work/v1" ||
    Canonical(workload entry without workId)
  )

claimScopeId =
  H(
    "p2party/r2-claim-scope/v1" ||
    U64BE(referenceWindow) ||
    U64BE(evaluationTimeMs) ||
    U64BE(evaluationClockUncertaintyMs) ||
    operationsDigest ||
    Canonical(participant presence IDs) ||
    Canonical(requiredOperations) ||
    R2TemporalGraphCoordinatesDigest ||
    U64BE(faultThresholdF) ||
    blockingModelId ||
    schedulerSemanticsHash ||
    schedulerImplementationArtifactSetDigest ||
    schedulerCanonicalTraceSetDigest ||
    schedulerWorkloadDigest ||
    schedulerRefinementResultDigest
  )

R2ScopedEvidenceId(evidence) =
  H(
    "p2party/r2-scoped-evidence/v1" ||
    evidence.claimScopeId ||
    Canonical(
      evidence.value,
      evidence.observedAtMs,
      evidence.expiresAtMs,
      evidence.methodId,
      evidence.rawEvidenceDigest
    )
  )

R2ScopedEvidenceSignedMessage(evidence) =
  "p2party/r2-scoped-evidence-attestation/v1" ||
  R2ScopedEvidenceId(evidence)

R2ConformanceRecordSignedMessage(record) =
  "p2party/r2-conformance-record-attestation/v1" ||
  H(Canonical(record without evaluatorAttestation))
```

Each `methodId` resolves under `assuranceMethodRegistryHash` to the exact
evaluator verification key, clock-uncertainty bound, evidence lifetime,
dataset schema, path/fault-unit derivation, and joint capacity simulator.
Every scoped evidence ID must recompute, and its attestation verifies the
signed message above under that method's key. Its full uncertainty interval
must be fresh:

```text
evidence.observedAtMs
  <= evaluationTimeMs - evaluationClockUncertaintyMs
  <= evaluationTimeMs + evaluationClockUncertaintyMs
  < evidence.expiresAtMs
```

checked without underflow/overflow and within the registered maximum age and
uncertainty. The evaluation-time uncertainty interval must map wholly inside
the record's `referenceWindow` under the fixture's immutable room cadence; a
boundary-straddling interval is invalid. The record attestation verifies under the release-pinned
conformance-evaluator key. `rawDatasetDigest` resolves the exact operation
bytes, local assurance records, graph measurements, and simulator inputs.
Every referenced ordinary `EvidenceV1` is revalidated with this record's
`evaluationTimeMs` and uncertainty interval, never ambient wall clock or the
publication download time.

`requiredOperations` is not a favorable subset. The verifier resolves each
exact canonical operation from that dataset, recomputes its `OperationId`,
author key, and expiry, requires it active at `referenceWindow`, requires
`authorNodeId` to equal `R2NodeId` of its exact `operation-author` node, and
requires:

```text
operationsDigest =
  H(
    "p2party/core-operation-set/v1" ||
    Canonical(Sort(required operation IDs))
  )
```

Each participant has one exact participant node. Every graph endpoint equals
one `R2NodeId`, and every public-store node's `(storeId, carrierInstanceId)`
matches exactly one honest-store unit. Every edge ID and fault-unit ID
recomputes, and every edge makes this exact relational join: its
`faultUnitId` resolves one unit; its `carrierInstanceId` is a member of that
unit's `carrierInstanceIds`; exactly one edge endpoint is the public-store node
with that unit's `storeId` and that same `carrierInstanceId`; and the other
endpoint is an operation-author for an author-to-store edge or a participant
for a store-to-participant edge. Store-to-store, author-to-participant, reversed,
and cross-unit edges are invalid in this finite R2-BEC graph. Removing a fault
unit therefore removes every and only edge carried by that exact unit. For
each unit, every participant's referenced current `EvidenceV1` set contains
the matching fresh records for each incident carrier instance and the unit's
exact measured operator/path/blocking values. Its proactive-use evidence names
the exact complete participant and operation sets plus exactly one
`custodyBinding` for every distinct operation ID and no extra binding. Each
tuple resolves one verified promise for the independently derived
operation/store/profile envelope, the exact signed chunk containing its
deterministic slot, and the finalized checkpoint committing that chunk before
the operation's expiry; all tuple coordinates join the selected fault unit's
`StoreId`. The raw dataset resolves every promise, signed chunk, and bounded
inclusion path. Operation/promise/checkpoint/chunk substitution, a custody
fault, checkpoint conflict/unverified gap, or saturation of that selected
store/profile's evidence invalidates that unit for the record. Receipts are
custody-at-finalization evidence only; they do not replace participant
reachability, capacity, or fairness. This is publication evidence, not a
runtime liveness upgrade. Each participant-coverage
evidence names that participant and the exact incident carrier instances.
Each edge's two evidence references resolve respectively to
`edge-reachability` and `edge-capacity` values for that exact edge ID. Thus a
global carrier measurement may be shared, but participant reachability cannot
be replayed as another participant's coverage.

The raw dataset also resolves exactly one `R2SchedulerWorkloadV1` whose
canonical hash equals `record.schedulerWorkloadDigest`. Each `workId`
recomputes from the remaining entry, the nullable operation/scheduled-event
coordinate matches its closed kind, and its window/object/byte bounds are
checked. The entry set is the complete production due-work snapshot plus the
registered worst-case authorized-valid competing-work envelope; omitting
non-R2 work that consumes the same fixed slot, reserve, byte, or object budget
invalidates the record. Its resource and fair-edge digests equal the record's
exact simulation assumptions.

The R2-BEC conformance-result predicate is exactly:

```text
R2Conforms(record) =
  all schema, bounds, derivations, operation/dataset resolutions,
      freshness checks, reference checks, and attestations above pass
  and record.claimScopeId equals the formula above
  and record.blockingModelId is the registered joint model
  and record.schedulerSemanticsHash equals KernelModuleSemanticsHash(
      executable kernel module 6
    )
  and record.schedulerRefinementResultDigest resolves one current
      "proved-within-scope" result for FPO-002 under this release
  and ProofScopeCovers(
        that result,
        record's exact scheduler/profile/resource/fair-edge/workload tuple
      )
  and that result.implementationArtifactSetDigest ==
      record.schedulerImplementationArtifactSetDigest ==
      the active build manifest's scheduler artifact-set digest
  and that result.canonicalTraceSetDigest ==
      record.schedulerCanonicalTraceSetDigest
  and that result.schedulerWorkloadDigest == record.schedulerWorkloadDigest
  and 1 <= record.faultThresholdF < count(record.honestStoreFaultUnits)
  and count(record.honestStoreFaultUnits) >= 2
  and StoreId, operatorDomainId, availabilityPathId, blockingDomainId,
      and faultUnitId are each pairwise distinct across
      honestStoreFaultUnits
  and for every B subset of HonestFaultUnitIds(record)
      with |B| <= faultThresholdF:
        RunJointR2DeliverySimulation(
          complete demand = every required operation to every participant,
          temporal graph with all units in B removed,
          each edge's one shared schedule/capacity budget,
          every operation's exact expiry
        ) == "pass"
```

`HonestFaultUnitIds(record)` is the exact sorted projection of
`honestStoreFaultUnits[].faultUnitId`. The registered simulator returns pass
only with a directed fair/authenticated path from each operation's
`authorNodeId` to each participant node before expiry while charging all
simultaneous demands jointly; edge capacity cannot be reused independently for
each pair. It executes the exact production
`OperationServiceOrder`, public scheduled-event order, missed-opportunity
rules, retry horizon, reserve accounting, and byte/object capacity semantics;
it does not existentially choose another legal ordering or reroute work after
observing a modeled fault. `faultThresholdF` counts failed honest-store units, not colloquial
“incidents.” The registered blocking model must assign the same
`blockingDomainId` to every unit removed by one modeled atomic censor action;
pairwise distinct blocking domains therefore assert that no modeled atomic
action removes two selected honest units. A newly discovered correlated action
invalidates that record rather than being counted as one harmless fault.
Fields or summaries from another record, participant, graph, fault universe,
evaluation time, or frontier cannot be combined.

The record is deliberately an offline finite conformance check, not an
exponential runtime algorithm or UI label. Records use synthetic release
fixtures or explicit research consent only. They are never generated from
production room telemetry, uploaded by a room client, or used as a carrier
input; publication must not turn the conformance graph into a production
social graph.
`ready-before-retention` is valid only for a contact/portable carrier whose
registered method measured the current custody path, remaining semantic
horizon, pending backlog, and enough bounded capacity for the required control
chain; public/IP-only carriers use `not-applicable`. A mismatched, expired, future, or otherwise
invalid record is replaced by that field's exact `unknown` value. Empty sets
never satisfy an `all` predicate vacuously.

Assurance evidence is charged before insertion to
`maxAssuranceEvidenceEntriesPerRoom` and
`maxAssuranceEvidenceBytesPerRoom`; locally retained raw datasets are
separately charged to `maxAssuranceRawEvidenceBytesPerRoom`. Each distinct field-level `EvidenceV1`
identified by its `evidenceId` consumes one entry; the byte cap charges the
exact canonical carrier coordinates plus that evidence record once, with
shared coordinates charged by the release codec's fixed record layout. The
retained set is the exact canonical
fresh record set; no implementation may discard an inconvenient route,
bundle, field, or failed measurement and aggregate the flattering remainder.
If another still-fresh required record cannot fit,
the transaction sets `assuranceEvidenceSaturated=true`, stores the
bytewise-lowest rejected `evidenceId` witness, and raises
`assuranceEvidenceSaturationUntilMs` to the maximum rejected `expiresAtMs`.
The fixed witness/watermark bytes are reserved by policy. Saturation cannot
clear before that watermark and then clears only after a canonical full rescan
or complete replacement proves every still-fresh required record and locally
retained raw dataset fits atomically. While saturated, `cohortScope`,
`accessPattern`, `sourceMetadata`, `publicStoreSourcePrivacy`, and
`operatorIndependence` reduce to their exact `unknown` branches;
`censorshipResilience="exhausted-or-unknown"`; and
`shutdownControl` is `"exhausted"` when required L3 state/capacity is
insufficient, otherwise `"unknown"`. `storeTopology` may report only
`no-usable-carrier` or `single-carrier-dependent`. Edge-local admission and PQ
facts remain independently derivable, but no carrier-resilience field is
upgraded from a selected subset.

The saturation fields are a closed tuple:
`assuranceEvidenceSaturated=false` if and only if both the watermark and
witness are null; `true` requires both non-null, a valid rejected evidence ID,
and a watermark equal to the greatest still-retained rejected expiry observed
by the canonical rescan. A malformed combination makes the complete
carrier-resilience projection unavailable.

Every field array is sorted by `evidenceId`, duplicate-free, and contains all
retained records for that exact binding/instance/field. A
`measurementSeriesId` names one registry-pinned method/vantage-set series whose
attestation requires a complete measurement over that set; its unsigned
`seriesGeneration` increases monotonically. Before freshness filtering, a
bounded high-water map keyed by
`(subjectScopeId, field, measurementSeriesId)` persists the greatest accepted
generation through the maximum possible evidence horizon and is charged to the
same evidence entry/byte caps. The current projection considers only records
at that high-water generation. If they are missing/expired or unequal, that
series is unknown; a lower generation never reappears after a newer one
expires or compacts. Older generations remain audit evidence but are
authentically superseded only inside that same series.

All current series then meet conservatively: cohort, access-pattern, and
source-metadata use the table's existing adverse-first rules; source privacy
is `tainted-or-insufficient` if any exact current interval is tainted or any
current evidence says `bound-not-met`, otherwise `unknown` if a required
record is missing, invalid, or heterogeneous, and `measured-bound-met` only
when all required public-store records validate under one selected
`SourcePrivacyFloorV1`; operator,
availability-path, and blocking-domain values must each be one identical known
value or become unknown;
availability is `failed-or-expired` if any series says so, otherwise unknown
if any is unknown, and `active-exercised` only when all say active;
non-IP readiness is exhausted if any says exhausted, otherwise unknown on an
unknown or heterogeneous ready/not-applicable mix, and retains a value only
when homogeneous. Thus a later favorable record from another method/vantage
cannot hide a still-fresh adverse record. Every current series evidence ID
contributes; no lowest ID or favorable measurement wins.
There is exactly one `CarrierAssuranceV1` per
`(carrierInstanceId, deliveryProfileHash, binding)`; a duplicate outer record
is invalid rather than another vote.

`CurrentResilienceCarrierSet` contains only used records whose exact instance
is in `runtimeFacts.activeCarrierInstanceIds` or
`runtimeFacts.readyL3CarrierInstanceIds` and whose current availability
projection is fresh measured `active-exercised`. Distinct-count upgrades for
`storeTopology`, `operatorIndependence`, and `censorshipResilience` use only
this set. Inactive-but-fresh historical observations may still make cohort,
access-pattern, or source-metadata privacy aggregates more conservative, but
can never add an operator, store, path, or blocking domain.

The pure aggregate is defined field by field:

| Summary field              | Exact conservative rule over used carriers / active edges                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `storeTopology`            | Empty `CurrentResilienceCarrierSet` → `no-usable-carrier`; at least two distinct known current measured availability-path values in at least two current fresh measured `blockingDomainId` values from one joint experiment under the exact runtime blocking model, with at least one `contact` or `portable-bundle` path → `multi-carrier-store-carry-forward`; otherwise at least two distinct set-member public `StoreId` values → `multi-store-union`; otherwise `single-carrier-dependent`. Multiple routes to one context, sessions on one bearer, or bundles through one custody path never increase this count.                                                                                                                                                                                                                                                      |
| `cohortScope`              | Read each valid `CohortEvidenceValueV1.scope`. Empty → `unknown`; any `room-unique` → `room-unique`; otherwise any `unknown` → `unknown`; otherwise any `declared-shared` → `declared-shared`; otherwise all are fresh valid `measured-shared`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| `accessPattern`            | Empty or any `unknown` → `unknown`; any `contact-dependent` → `contact-dependent`; otherwise any `on-demand-public-scan` → `on-demand-public-scan`; otherwise a homogeneous set retains `fixed-cohort-scan` or `oblivious-access-reviewed`; a mixed fixed/oblivious set reports `unknown` rather than inventing an order.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `sourceMetadata`           | Empty or any `unknown` → `unknown`; otherwise use the explicit strength order `bearer-visible < split-relay-gateway < anonymity-network-measured` and return the minimum.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `publicStoreSourcePrivacy` | If `runtimeFacts.sourcePrivacyRuntime.floor` disables SP1, `not-required`. Otherwise consider every public-store context touched in the greatest wholly completed safe-clock exposure interval, including now-inactive or failed routes and every policy generation, plus every client-global volume epoch linkable under the selected model. Any tainted exposure, exhausted cap, or current valid `bound-not-met` record → `tainted-or-insufficient`; an incomplete/live interval is never selected. Any missing, expired, saturated, wrong-profile, wrong-mechanism, incomplete floor/volume history, or heterogeneous required record → `unknown`; only complete current measured evidence satisfying `SP1Conforms` for every such client-global context → `measured-bound-met`. Contact and portable carriers neither satisfy nor degrade this public-store-only field. |
| `operatorIndependence`     | `measured-independent` only when every member of `CurrentResilienceCarrierSet` has a current fresh measured `operatorDomain.value` that is `Bytes32` and at least two distinct byte values occur; `declared` only when every set-member value is a known `Bytes32` with fresh measured/declared evidence, at least two distinct values occur, and at least one is merely declared; otherwise `unknown`. Repeated values are allowed but do not increase the distinct count.                                                                                                                                                                                                                                                                                                                                                                                                  |
| `censorshipResilience`     | Empty `CurrentResilienceCarrierSet` → `not-established`. Consider only its members whose context is in `runtimeFacts.activeCarrierContextIds` and whose current blocking-domain projection names the exact `runtimeFacts.blockingModelId`. `measured-diverse-active` requires one exact non-unknown current `jointExperimentId` group that itself contains at least two distinct known current measured availability-path values and at least two distinct current fresh measured `blockingDomainId` values; predicates cannot be satisfied by different groups. A nonempty qualifying group with exactly one distinct known measured blocking domain under that model → `single-domain-dependent`; no qualifying joint group, or an empty, failed, expired, model-mismatched, inactive-instance, unknown-path, or unknown-domain usable set → `exhausted-or-unknown`.       |
| `shutdownControl`          | No used contact/portable carrier → `not-established`; `runtimeFacts.l3RequiredIntentState="missing-or-saturated"`, `runtimeFacts.l3CapacityBeforeExpiry="insufficient"`, or every current non-IP projection is exhausted → `exhausted`; otherwise at least one used non-IP carrier's exact `carrierInstanceId` is in `runtimeFacts.readyL3CarrierInstanceIds` and its current availability projection is fresh measured `active-exercised` while its current readiness projection is fresh measured `ready-before-retention`, with intent state complete and capacity sufficient → `tested-non-ip-control-ready`; otherwise `unknown`. Portable IDs enter only this episodic L3 set, never `activeCarrierContextIds` or a fixed scheduler slot.                                                                                                                              |
| `transportDisclosure`      | No active edge → `not-established`; otherwise `not-conformant` if any edge has it, else `pre-sdp-admission-pair-sealed`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `identityDisclosure`       | No active edge → `not-established`; otherwise use `not-conformant < first-flight-visible-to-selected-capability-holder < strict-presence-proof-gated` and return the minimum.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `pqState`                  | No active edge → `not-established`; otherwise any `stalled` wins, then any `not-established`, then any `healing-in-progress`, then any `fresh-hybrid`; only an all-healed set reports `healed-after-fresh-entropy`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |

`consistency` is the reducer/reconciliation state, not a carrier vote. No
hostname, operator declaration, best carrier, or unrelated edge silently
upgrades the room.

`runtimeFacts.activeCarrierInstanceIds` is exactly the sorted union of every
currently selected `PublicRouteInstanceId` under the active public contexts
and every current `ContactCarrierInstanceId` under the room's active contact
contexts. Denial, expiry, session rollover, route removal, or policy
replacement removes the exact instance in the same transaction that stops its
use, even when another route keeps the parent context active. Portable bundle
instances enter only `readyL3CarrierInstanceIds`.

`measured-diverse-active` means resistance only to the registered, freshly
tested blocking actions and vantage/domain model; it is never an unconditional
“uncensorable” claim. Evidence expiry, a failed exercise, loss of a distinct
domain, or path deactivation recomputes and downgrades the summary
immediately. `tested-non-ip-control-ready` is likewise a live,
room-and-backlog-scoped readiness statement and may support the product phrase
`shutdown-surviving rendezvous/control` only when the release-wide AC-024/025
evidence is also current. It does not promise future contacts, power, physical
custody, or application messaging.

The current `availabilityPath` projection is an evidence-registry identifier
for one independently measured blocking/custody path or exact `unknown`. A public route uses its registry-measured
route/gateway/anonymity path ID; two routes share the ID when measurement says
the same block disables both. Without such fresh route-path evidence, every
route of that public context projects to `unknown` and cannot manufacture
diversity. Contact/portable records analogously use their registered measured physical/custody path. The
ID is not a cryptographic context, room input, or user-chosen string. Fresh
sessions, routes, and bundle contexts on the same measured path retain one ID.
`storeTopology="multi-store-union"` still counts distinct `StoreId` values,
never routes; route diversity affects only the explicitly measured
censorship/path fields.

- `single-carrier-dependent` means end-to-end confidentiality and authenticity
  survive a malicious carrier where its bearer assumptions hold, but liveness
  does not.
- `multi-store-union` means no quorum. One delivering path can suffice for an
  operation; a bridge is still needed between disjoint sets.
- `multi-carrier-store-carry-forward` means measured eventual delivery over a
  time-varying contact graph, not continuous reachability.
- `room-unique` means an extra server works for availability but its observed
  user population may identify one room. It cannot inherit a shared-cohort L2
  claim.
- `fixed-cohort-scan` hides application targets under the profile assumptions;
  it does not hide bearer source or the fact that a client participates in the
  profile.
- `contact-dependent` describes honest L3 operation whose timing and volume may
  reveal physical contacts.
- More servers can increase availability while increasing the metadata
  observer set.
- A server can omit forever. “Converged” means convergence to the operations
  actually delivered at the displayed frontier, not proof of global
  completeness.

The following local facts are necessary but not sufficient for the R2-BEC package
from Section 1.6:
`censorshipResilience="measured-diverse-active"`,
`operatorIndependence="measured-independent"`, consistency is not
`partitioned`, `resourceState="within-bounds"`, evidence is not saturated, and every other property being
claimed has its own conforming value and unexpired acceptance evidence. Its
exact joint group must contain at least `faultThresholdF + 1` distinct measured
operator-domain, availability-path, and blocking-domain values; the
publication record still requires every selected honest-store unit to be
pairwise distinct on each coordinate. Only the
separately named combined
`R2-BEC ∧ shutdown-surviving rendezvous/control` claim additionally requires
`shutdownControl="tested-non-ip-control-ready"` and the AC-024/025 global
participant evidence; it is not an input to `R2Conforms`.
The one `R2ConformanceRecordV1` must bind those facts into the exact global
temporal graph and pass `R2Conforms`; independently passing local sets do not
prove an author-to-participant path. `RoomAssuranceV4` alone is local and never
emits a scoped R2-BEC label. Every contributing local method's
`faultThresholdF` and `blockingModelId` must exactly equal the record values.
These predicates express authenticated-union Byzantine safety plus registered
bounded-fault delivery resilience: a Byzantine carrier may omit, replay, fork,
or equivocate but cannot become a logical winner. They do not express server
consensus or make an empty result a proof of global absence.

### 3.4 Formal obligations and refinement boundary

The formal model is evidence for sharply bounded claims, not decorative
notation and not a replacement for implementation tests. The release's
`FormalObligationRegistryV1` contains at least these closed obligations:

- **FPO-001 — Core-set confluence:** For every schema-valid bounded operation
  multiset and every permutation/duplication of its delivery trace, canonical
  validation, set union, and `CoreReduce` produce the same state and fork
  facts.
- **FPO-002 — Production scheduler refinement:** For every accepted
  `R2ConformanceRecordV1`, every production trace admitted by that record's
  exact fair-edge assumptions, complete competing-workload digest, resource
  limits, and any fault set `|B| <= f` refines executable kernel module 6.
  The implementation scheduler, the `R2Conforms` joint simulator, and module 6
  use one registered work order, missed-opportunity, retry, reserve, and
  byte/object-capacity semantics; the simulator may not search for a favorable
  order or route that production would not take. Under that refinement,
  simulator result `pass` implies that every operation-to-participant demand
  in the record is delivered before its exact expiry. The proof scope binds
  the production implementation artifact set, canonical differential trace
  set, scheduler workload (including worst-case authorized valid competing
  work), profile, resource limits, and fair-edge assumptions.
- **FPO-003 — Pre-SDP non-disclosure:** Within one current, persisted
  `BootstrapAdmissionDecisionLeaseV1`, transport disclosure in every admission
  mode requires a genuine current or historical
  `VerifiedPairAttemptTopologyV1`, a current `Admit() == allow` result, and an
  authenticated pair transcript, all bound to the same exact attempt and CAS
  fences. Strict modes additionally emit no HELLO before their exact
  eligibility proof passes. A frontend policy-generation, topology, or
  resource-fence change invalidates the lease immediately. Revocation after an
  otherwise unchanged modeled lease interval is outside this property and is
  covered by the explicit recheck requirements.
- **FPO-004 — Sole-store non-disclosure:** For two executions differing only
  in room, stable identity, membership, pair edge, or SDP plaintext, a sole
  store's protocol-view distributions are computationally indistinguishable
  whenever the executions have identical declared public leakage: delivery
  profile, source-privacy class, timing, request count, response sizes, and
  transport metadata. The symbolic abstraction may use equality only after
  replacing the reviewed randomized primitives with their ideal
  functionalities. This is not a claim that those declared leakage values are
  equal in the real world.
- **FPO-005 — Eventual PQ-control safety:** Duplication, reordering, omission,
  bounded replay, atomic crash recovery, and admissible concurrent control
  frames preserve the pair-control safety invariants and cannot make two
  different authenticated successors win one slot. Atomic crash recovery
  cannot regress an accepted edge. A one-sided whole-device snapshot restore
  may load old local state, but on authenticated contact the newer peer never
  accepts an old successor and the edge fails/rehandshakes. Simultaneous
  whole-device restore remains explicitly out of scope under SEC-012.
- **FPO-006 — Claim downgrade safety:** For every claim-evaluation trace,
  removing, expiring, contradicting, saturating, or taking evidence out of
  scope cannot move a claim to `satisfied`, and positive wording is impossible
  whenever the evaluated state is not `satisfied`.

Each obligation binds a canonical model hash, property hash,
abstraction/refinement-map hash, toolchain hash, proof-scope schema, scope
coverage entrypoint, and a sorted set of assumption IDs. Its assumption-set
hash is derived from the resolved assumption records rather than stored a
second time. A result is usable only when it binds those exact values plus the
current release/registry hashes, a resolvable canonical proof-scope artifact,
the exact production implementation-artifact and trace-set digests, and is
`proved-within-scope`. Module 8 must also execute the obligation's registered
scope-coverage predicate against the evaluated claim scope; sharing an
obligation ID is not coverage. A counterexample or inconclusive result is
published but cannot satisfy a claim. No proof result is included inside the
registry whose hash it binds, avoiding a hash cycle. Differential trace replay
against every bound production implementation is part of the refinement
evidence, and any mismatch invalidates the dependent result.

### 3.5 Engineering guidelines

- **GUD-001 — DRY:** One canonical operation, validation pipeline, set union,
  reducer, pair ledger, carrier envelope, and assurance derivation serve every
  store and bearer. HTTP, WebRTC, BLE, and files are adapters, not protocols.

- **GUD-002 — KISS:** The correctness baseline is append, scan/exchange,
  authenticate, union, and reduce. No selected cell, quorum, leader,
  failure detector, mutable server roster, consensus, or private-write
  construction is required.

- **GUD-003 — Scoped SSOT:** Serialize each source fact once: immutable room/
  release policy, shared operation, local frontend/carrier policy, private
  pair ledger/outbox, and assurance evidence. Derive operation/carrier/store
  IDs, room contexts, roles, sparse neighbors, active catalogs, observed
  frontiers, and labels only inside the scope that owns their inputs.

- **GUD-004 — Separate policy from transport:** The frontend decides whom and
  which carriers to trust. Stores transport opaque objects. The cryptographic
  core authenticates facts. No layer impersonates another.

- **GUD-005 — Optimize behind the interface:** OMR, PIR, set reconciliation,
  CDNs, peer gossip, and private routes may reduce cost or add paths only if
  the canonical operation set remains sufficient for correctness.

## 4. Interfaces & Data Contracts

The TypeScript-like schemas in this section are normative logical field
contracts but are not, by themselves, a byte layout. A frozen companion
binary-schema artifact is required before implementation conformance or wire
interoperability can be claimed. That artifact shall implement these fields,
closed unions, bounds, and equations using fixed-width integers, fixed enum
values, exact lengths, sorted unique collections, duplicate-field rejection,
and one encoding per value. Where this proposal writes `Canonical(x)`, it
means the unique encoding in that artifact. Free-form algorithm names, the
TypeScript sketches, implementation object layout, and JSON are not wire
formats. If the implementing pass discovers that a field or bound is missing,
it revises this versioned contract and binary schema first; an encoder choice
cannot silently become protocol law.

### 4.0 Executable kernel, claims, and formal artifacts

The following publication artifacts make the normative subset mechanically
checkable. `Uint16` below is an unsigned 16-bit integer. All arrays are
bounded, sorted by their complete canonical key, and duplicate-free. Module
IDs are closed: `1 validate-operation-set`, `2 core-reduce`,
`3 project-and-admit`,
`4 derive-assurance`, `5 derive-l3-required-work`,
`6 delivery-scheduler-and-r2-conforms`,
`7 eventual-pair-control-transition`, and `8 evaluate-claim`.
Entrypoint IDs are also closed in v1: modules `1..5` own entrypoints `1..5`;
module 6 owns `6 delivery-scheduler` and `7 r2-conforms`; module 7 owns
`8 eventual-pair-control-transition`; and module 8 owns `9 evaluate-claim`.
Entrypoint `3 project-and-admit` is one composite pure boundary, not separate
public `Project` and `Admit` entrypoints. Its frozen input and output schemas
are closed tagged unions with exactly these input branches:

- `current-project`, which returns the cloneable diagnostic projection;
- `current-attempt`, which projects and authorizes one exact unpublished
  outbound attempt or, when given a verified identity flight, immediately
  consumes that topology in admission; and
- `historical-attempt`, which reconstructs the exact HELLO-window projection
  and decides or rechecks the corresponding bootstrap flight whenever the
  exact endpoints are no longer both in current projection.

The attempt branches take every canonical input required for their applicable
internal phases and return only the final closed outbound-attempt
authorization, admission decision/lease, or denial. A
`VerifiedPairAttemptTopologyV1` may exist as an implementation-private
refinement between those phases in one invocation, but it is never a
canonical entrypoint input or output and cannot cross an invocation,
serialization, worker, or persistence boundary. This keeps one executable
entrypoint and one admission decision SSOT while allowing the production
wrapper to enforce process-local provenance. ACCEPT and later transport-offer
reauthorization use the applicable attempt branch with the persisted exact
attempt coordinates/evidence and freshly captured current fences; they do not
import a prior opaque handle. The owning effectful wrapper invokes this
entrypoint itself and immediately consumes its result in the same prepared
transition; no public adapter or later transition may supply or reimport a
caller-assembled outbound authorization, admission decision, or lease as
authority.

```ts
type KernelModuleIdV1 = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8;
type KernelEntrypointIdV1 = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9;

type KernelEntrypointV1 = {
  entrypointId: KernelEntrypointIdV1;
  inputSchemaHash: Bytes32;
  outputSchemaHash: Bytes32;
  normativeSourceHash: Bytes32;
};

type ExecutableRendezvousKernelModuleV1 = {
  moduleId: KernelModuleIdV1;
  executableArtifactHash: Bytes32;
  normativeSourceTreeHash: Bytes32;
  entrypoints: readonly KernelEntrypointV1[];
  canonicalVectorSetHash: Bytes32;
};

type ExecutableRendezvousKernelManifestV1 = {
  version: 1;
  canonicalBinarySchemaHash: Bytes32;
  modules: readonly ExecutableRendezvousKernelModuleV1[]; // exactly 1..8
};

type BlindRendezvousImplementationBuildManifestV1 = {
  version: 1;
  releaseRegistryHash: Bytes32;
  implementationArtifactSetDigest: Bytes32;
  executableModuleArtifactHashes: readonly Bytes32[]; // projection of 1..8
  productionSchedulerArtifactHash: Bytes32;
  canonicalTraceSetDigest: Bytes32;
};

type ClaimEvaluationStateV1 =
  | "not-implemented"
  | "not-evaluated"
  | "unknown"
  | "expired"
  | "failed"
  | "satisfied";

type ClaimScopeKindV1 =
  | "release"
  | "deployment"
  | "room"
  | "carrier-instance"
  | "edge"
  | "r2-conformance-record";

type ClaimAssumptionV1 = {
  assumptionId: Uint16;
  kind: "cryptographic" | "protocol" | "deployment" | "environmental";
  canonicalStatement: string;
  verification:
    | { kind: "declared-foundational" }
    | {
        kind: "evidence-verified";
        verifierEntrypointId: KernelEntrypointIdV1;
      };
};

type ClaimEvidenceKindV1 = {
  evidenceKindId: Uint16;
  canonicalSchemaHash: Bytes32;
  verifierEntrypointId: KernelEntrypointIdV1;
};

type ClaimDefinitionV1 = {
  claimId: Uint16;
  scopeKind: ClaimScopeKindV1;
  scopeSchemaHash: Bytes32;
  predicateEntrypointId: KernelEntrypointIdV1;
  assumptionIds: readonly Uint16[];
  requiredEvidenceKindIds: readonly Uint16[];
  prerequisiteClaimIds: readonly Uint16[];
  requiredFormalObligationIds: readonly Uint16[];
  wordingIdByState: {
    notImplemented: Uint16;
    notEvaluated: Uint16;
    unknown: Uint16;
    expired: Uint16;
    failed: Uint16;
    satisfied: Uint16;
  };
  forbiddenWordingIds: readonly Uint16[];
};

type ClaimWordingCatalogV1 = {
  version: 1;
  wording: readonly {
    claimId: Uint16;
    wordingId: Uint16;
    state: ClaimEvaluationStateV1;
    canonicalText: string;
  }[];
  reasons: readonly {
    reasonId: Uint16;
    canonicalText: string;
  }[];
};

type ClaimRegistryV1 = {
  version: 1;
  assumptions: readonly ClaimAssumptionV1[];
  evidenceKinds: readonly ClaimEvidenceKindV1[];
  claims: readonly ClaimDefinitionV1[];
  wordingCatalogHash: Bytes32;
};

type ClaimEvidenceBindingV1 = {
  evidenceKindId: Uint16;
  evidenceId: Bytes32;
};

type ClaimPrerequisiteBindingV1 = {
  claimId: Uint16;
  evaluationDigest: Bytes32;
};

type ClaimFormalResultBindingV1 = {
  obligationId: Uint16;
  resultDigest: Bytes32;
};

type ClaimAssumptionBindingV1 =
  | {
      assumptionId: Uint16;
      kind: "declared-foundational";
    }
  | {
      assumptionId: Uint16;
      kind: "evidence-verified";
      evidenceId: Bytes32;
    };

type ClaimEvaluationDatasetV1 = {
  version: 1;
  releaseRegistryHash: Bytes32;
  claimRegistryHash: Bytes32;
  claimId: Uint16;
  canonicalScope: Uint8Array;
  assumptionBindings: readonly ClaimAssumptionBindingV1[];
  evidenceBindings: readonly ClaimEvidenceBindingV1[];
  prerequisiteBindings: readonly ClaimPrerequisiteBindingV1[];
  formalResultBindings: readonly ClaimFormalResultBindingV1[];
  evidenceSaturated: boolean;
  firstSaturatedEvidenceId: Bytes32 | null;
};

type ClaimEvaluationInputV1 = {
  releaseRegistryHash: Bytes32;
  claimRegistryHash: Bytes32;
  claimId: Uint16;
  scopeDigest: Bytes32;
  evaluatedAtMs: bigint;
  evaluationClockUncertaintyMs: bigint;
  implementationPresent: boolean;
  evaluationDatasetDigest: Bytes32;
};

type ClaimEvaluationV1 = {
  version: 1;
  input: ClaimEvaluationInputV1;
  state: ClaimEvaluationStateV1;
  validThroughMs: bigint | null;
  reasonIds: readonly Uint16[];
  selectedWordingId: Uint16;
};

type FormalObligationV1 = {
  obligationId: Uint16;
  kind: "algebraic" | "safety" | "liveness-refinement" | "computational-game";
  modelSourceHash: Bytes32;
  propertySourceHash: Bytes32;
  abstractionMapHash: Bytes32;
  toolchainLockHash: Bytes32;
  proofScopeSchemaHash: Bytes32;
  scopeCoverageEntrypointId: KernelEntrypointIdV1;
  assumptionIds: readonly Uint16[];
};

type FormalObligationRegistryV1 = {
  version: 1;
  obligations: readonly FormalObligationV1[];
};

type FormalProofScopeArtifactV1 = {
  version: 1;
  obligationId: Uint16;
  canonicalScope: Uint8Array;
};

type FormalProofResultV1 = {
  version: 1;
  releaseRegistryHash: Bytes32;
  formalObligationRegistryHash: Bytes32;
  obligationId: Uint16;
  modelSourceHash: Bytes32;
  propertySourceHash: Bytes32;
  assumptionSetHash: Bytes32;
  abstractionMapHash: Bytes32;
  toolchainLockHash: Bytes32;
  proofScopeDigest: Bytes32;
  implementationArtifactSetDigest: Bytes32;
  canonicalTraceSetDigest: Bytes32;
  schedulerWorkloadDigest: Bytes32;
  result: "proved-within-scope" | "counterexample" | "inconclusive";
  proofArtifactDigest: Bytes32;
  counterexampleTraceDigest: Bytes32 | null;
};
```

Every reference resolves exactly once, the prerequisite-claim graph is
acyclic, canonical statements are nonempty bounded NFC text, and unknown or
accessor-backed fields are rejected. `ClaimDefinitionV1` is the sole
claim-to-obligation relation; no reverse relation is serialized. A v0.4
release-conformance check additionally requires obligation IDs `1..6` with
their exact FPO-001 through FPO-006 meanings; any extra obligation uses a new
ID and cannot reinterpret these. Every entrypoint ID is globally unique and resolves
inside exactly one module. `normativeSourceTreeHash` is computed over the
canonical sorted sequence of normalized relative source paths and their file
digests; absolute paths, timestamps, filesystem order, and build-host metadata
are excluded. The hashes are:

```text
ExecutableKernelManifestHash =
  H("p2party/executable-rendezvous-kernel/v1" || Canonical(manifest))

ImplementationBuildManifestHash =
  H("p2party/blind-rendezvous-build-manifest/v1" || Canonical(manifest))

KernelModuleSemanticsHash(module) =
  H(
    "p2party/executable-kernel-module-semantics/v1" ||
    module.moduleId ||
    Canonical(
      for each sorted entrypoint:
        (entrypointId, inputSchemaHash, outputSchemaHash, normativeSourceHash)
    )
  )

KernelSourceTreeHash(files) =
  H(
    "p2party/executable-kernel-source-tree/v1" ||
    Canonical(Sort(normalizedRelativePath, H(fileBytes)))
  )

ClaimRegistryHash =
  H("p2party/rendezvous-claim-registry/v1" || Canonical(registry))

ClaimWordingCatalogHash =
  H("p2party/claim-wording-catalog/v1" || Canonical(catalog))

FormalObligationRegistryHash =
  H("p2party/formal-obligation-registry/v1" || Canonical(registry))

ClaimScopeDigest =
  H(
    "p2party/claim-scope/v1" ||
    U16BE(claimId) ||
    ClaimScopeKindByte(scopeKind) ||
    scopeSchemaHash ||
    canonicalScope
  )

ClaimEvaluationDatasetDigest =
  H("p2party/claim-evaluation-dataset/v1" || Canonical(dataset))

FormalAssumptionSetHash =
  H(
    "p2party/formal-assumption-set/v1" ||
    claimRegistryHash ||
    Canonical(resolved sorted ClaimAssumptionV1 records)
  )

FormalProofScopeDigest =
  H(
    "p2party/formal-proof-scope/v1" ||
    U16BE(obligationId) ||
    proofScopeSchemaHash ||
    canonicalScope
  )

EmptySchedulerWorkloadDigest =
  H("p2party/scheduler-workload/v1/none")

ClaimEvaluationDigest =
  H("p2party/claim-evaluation/v1" || Canonical(evaluation))

FormalProofResultDigest =
  H("p2party/formal-proof-result/v1" || Canonical(result))
```

Only FPO-002 accepts a nonempty `schedulerWorkloadDigest`; every other
obligation uses `EmptySchedulerWorkloadDigest`. This closed sentinel avoids a
nullable field without allowing unrelated workload bytes to alter another
property's identity.

Kernel module 8 applies SEC-024 and selects exactly the wording ID for the
computed state. It accepts the expected current release, kernel, claim,
formal-obligation, and wording-catalog hashes plus a resolved
`ClaimEvaluationDatasetV1`; byte-looking roots supplied by the dataset are
never trusted. It reparses `canonicalScope` under `scopeSchemaHash`,
recomputes `ClaimScopeDigest` and the dataset digest, resolves each typed
binding, and executes the registered entrypoints. For R2, the scope contains
the exact `claimScopeId` and `R2ConformanceRecordV1` digest.

`satisfied` requires implementation presence, no evidence saturation, exactly
the declared assumption set, at least one verified binding for every evidence
kind, exactly one current satisfied binding per prerequisite, exactly one
current proved result per required formal obligation, every
`ProofScopeCovers(formal result scope, evaluated claim scope)` predicate true,
and the claim predicate true. A declared-foundational assumption remains
visible in the positive output and documentation; it cannot masquerade as an
evidence-verified fact. The derived `validThroughMs` is the minimum of all
temporal evidence, prerequisite, proof, release, and deployment validity
bounds and is non-null only for `satisfied`.

An explicit current counterexample, contradiction, or false predicate is
`failed`; a formerly complete evaluation invalid only because temporal
evidence expired is `expired`; missing, stale, saturated, out-of-scope,
heterogeneous, uncovered-proof, or inconclusive input is `unknown`; absent
implementation is `not-implemented`. `not-evaluated` is the closed projection
used when no conforming evaluation has run for the current scope. The wording
catalog resolves every `(claimId, state, wordingId)` exactly once, a satisfied
wording ID is distinct from every non-positive/forbidden ID, and every reason
ID resolves. A renderer must resolve the dataset and run module 8 again with
`nowUpper < validThroughMs`; a serialized `state="satisfied"` or a
shape-valid object never authorizes positive wording. No implementation may
choose a friendlier state.

The initial SDK foothold in
`src/blindRendezvous/normativeKernel.ts` validates these logical shapes only.
Its shape validator does not evaluate a claim and exposes no positive-wording
authorization helper. It is deliberately absent from the package's public
barrel and defines no canonical encoder or protocol hash. It becomes normative
implementation code only after the Phase-0 schema, vectors, generated
projections, module-8 resolver/evaluator, and AC-047/048 gates are frozen.

### 4.1 Room access, policy, and public delivery profile

```ts
type Bytes16 = Uint8Array;
type Bytes24 = Uint8Array;
type Bytes32 = Uint8Array;
type Bytes64 = Uint8Array;
// Logical schema aliases; canonical encoding still enforces exact range.
type Uint16 = number;
// Canonically sorted, duplicate-free, bytewise-equality collection.
type CanonicalBytes32SetV1 = readonly Bytes32[];
// Exact unpadded base64url text derived by LocalRoomId below.
type LocalRoomId = string;

// Existing deployed invitation; it remains legacy-signaling forever.
type LegacyRoomInviteV1 = {
  version: 1;
  capability: Bytes32;
};

// Blind invitation. Its only secret is still exactly one 32-byte capability.
// The optional value is the exact public canonical RoomPolicyV4.
type BlindRoomInviteV2 =
  | {
      version: 2;
      form: "default";
      capability: Bytes32;
    }
  | {
      version: 2;
      form: "room-policy";
      capability: Bytes32;
      roomPolicy: RoomPolicyV4;
    };

type ParsedRoomInvite = LegacyRoomInviteV1 | BlindRoomInviteV2;

type LegacySignalingAdapterUnavailableError = Error & {
  name: "LegacySignalingAdapterUnavailableError";
  code: "legacy-signaling-adapter-unavailable";
  inviteVersion: 1;
};

type BlindStoreAliasResolutionError = Error & {
  name: "BlindStoreAliasResolutionError";
  code: "blind-store-alias-unmapped";
  option: "signalingServerUrl";
};

// Exact existing source policy; its canonical encoder remains the SSOT for
// PIN/CPace, PQ suite, rendezvous mode, and scheduled data-plane cover.
type RoomPolicyV1 = {
  version: 1;
  revision: number;
  wireVersion: 4;
  authMode: "nopin" | "pin";
  pqMode: "hybrid-mlkem512" | "hybrid-mlkem768" | "hybrid-mlkem1024";
  rendezvousMode: "legacy-signaling" | "opaque-token" | "blind-meeting-point";
  coverMode: "immediate" | "scheduled";
  coverCadenceMs: number;
  coverLanes: number;
  coverFramesPerCell: number;
  coverDurationEpochs: number;
};

// Immutable security semantics. Delivery profiles, stores, routes, planner
// preferences, and local frontend controls deliberately do not appear here.
type RoomPolicyV4 = {
  version: 4;
  sessionPolicyV1: Bytes32; // exact encodeRoomPolicyV1(...) bytes
  roomCryptoSuite: 1;
  operationCodec: 1;
  pairBootstrapSuite: 1;
  protocolLimits: RoomProtocolLimitsV1;
  admissionFloor:
    | { mode: "capability" }
    | {
        mode: "authority-grant";
        authorityEd25519PublicKey: Bytes32;
        maxAuthorityCredentialLifetimeWindows: number;
      };
  maxRoomMembers: number;
};

type RoomProtocolLimitsV1 = {
  logicalWindowMs: bigint;
  maxClockSkewWindows: number;
  operationRetentionWindows: number;
  pairControlRetentionWindows: number;
  receiverKeyOverlapWindows: number;
  maxFutureLogicalWindows: number;
  maxDependenciesPerOperation: number;
  maxOperationsPerAuthorWindow: number;
};

type ConnectionPlannerPolicyV1 = {
  version: 1;
  mode: "explicit" | "sparse-ring" | "full-mesh-small-room";
  sparseRadius: number;
  maxProvisionalEdges: number;
  maxActiveStableEdges: number;
  fullMeshMaxMembers: number;
  allowOnDemandEdges: boolean;
};

// Local delivery-only frontend control. It never enters RoomContextId,
// PolicyHash, CoreRoomState, or the client-global public route cycle.
type RoomCarrierAssignmentPolicyV1 = {
  version: 1;
  policyGeneration: bigint;
  disabledCarrierContextIds: CanonicalBytes32SetV1;
};

// Local resolved join context, never a new serialized invitation blob.
type BlindRoomAccessV4 = {
  capability: Bytes32;
  roomPolicy: RoomPolicyV4;
  deliveryProfiles: readonly DeliveryProfileV1[];
  frontendControls: FrontendRoomControlsV1;
  // Read-only reference to the one client/vault-global carrier policy.
  carrierPolicy: FrontendCarrierPolicyV1;
  resourcePolicy: ClientResourcePolicyV1;
  connectionPlanner: ConnectionPlannerPolicyV1;
  carrierAssignments: RoomCarrierAssignmentPolicyV1;

  // Local/default/bootstrap availability data. Excluded from RoomContextId
  // and PolicyHash. It can change without creating another room.
  bootstrapStoreHints: readonly BootstrapStoreHintV1[];
};

type DeliveryProfileV1 = {
  version: 1;
  carrierEnvelopeCodec: 1;
  publicStoreProtocol: 1;
  carrierAeadSuite: 1;
  admissionScheme: 1;

  deliveryWindowMs: bigint;
  carrierRetentionWindows: number;
  maxFutureIngressWindows: number;

  roomSlotsPerClient: number;

  // Exact public capacity. One anonymous allocation covers every local room
  // slot for one window; the store pads every unclaimed allocation.
  cohortAllocationsPerWindow: number;
  publicChunkObjectCount: number;
  maxScheduleSkewMs: bigint;
  tokenIssueOffsetMs: bigint;
  tokenIssueResponseBudgetMs: bigint;
  allocationRequestOffsetMs: bigint;
  allocationResponseBudgetMs: bigint;
  chunkFinalizationOffsetMs: bigint;
  publicReadLagWindows: 1;
  publicReadOffsetMs: bigint;
  maxConsecutiveMissedAppendOpportunities: number;
  sizeClasses: readonly {
    id: number;
    fixedCarrierObjectBytes: number;
    operationPayloadClass: 0 | 1;
    appendSchedule: readonly {
      offsetMs: bigint;
      role: "safety-control" | "identity-bootstrap" | "state-replication";
    }[];
    publicChunksPerWindow: number;
  }[];

  minMeasuredSharedCohort: number;
  maxAssuranceEvidenceAgeMs: bigint;
};
```

Every semantic integer is range-checked before hashing, persistence, adapter
construction, or allocation. The companion schema assigns its exact unsigned
width; values outside that width, JavaScript unsafe integers in a `number`
field, negative values, and checked-arithmetic overflow are invalid. At
minimum:

```text
logicalWindowMs > 0
maxClockSkewWindows >= 0
operationRetentionWindows > 0
pairControlRetentionWindows >= operationRetentionWindows
receiverKeyOverlapWindows >= 0
checkedAdd(operationRetentionWindows, receiverKeyOverlapWindows)
  <= pairControlRetentionWindows
0 <= maxFutureLogicalWindows <= maxClockSkewWindows
maxDependenciesPerOperation >= 1
1 <= maxOperationsPerAuthorWindow <= 65534
2 <= maxRoomMembers

deliveryWindowMs > 0
carrierRetentionWindows > 0
maxFutureIngressWindows >= 0
roomSlotsPerClient > 0
cohortAllocationsPerWindow > 0
publicChunkObjectCount > 0
sizeClasses.length == 2
every sizeClasses[i].id is unique
0 <= every sizeClasses[i].id <= 255
checkedMultiply(
  roomSlotsPerClient,
  every sizeClasses[i].appendSchedule.length
) <= UINT32_MAX
every fixedCarrierObjectBytes > 0
every appendSchedule.length > 0
every publicChunksPerWindow > 0
minMeasuredSharedCohort >= 2
maxAssuranceEvidenceAgeMs > 0

maxInitializedBlindRooms > 0
maxActivePublicCarrierContexts > 0
maxRoutesPerPublicCarrierContext > 0
maxPublicCatalogStores > 0
maxPublicCatalogRoutes > 0
maxPublicCatalogBytes > 0
maxAuthenticatedContactContexts > 0
maxAuthenticatedContactContextBytes > 0
maxL3DueWorkEntries > 0
maxL3DueWorkBytes > 0
maxPortableBundleBytes > 0
maxContactInventoryEntries > 0
maxPendingL3Exports > 0
maxPendingL3ExportBytes >=
  maxPortableBundleBytes
maxStoreAccountabilityEvidenceEntries > 0
maxStoreAccountabilityEvidenceBytes > 0
maxSourcePrivacyEvidenceEntries > 0
maxSourcePrivacyEvidenceBytes > 0
```

All policy/profile collections are closed, canonically sorted, unique, and
bounded by the binary schema. Every `ClientResourcePolicyV1` count/byte cap
except the two named reserves is a positive safe integer; both reserved outbox
byte caps are non-negative,
their sum fits `maxOutboxBytesPerRoom`, and each reserved role fits its
profile's largest exact request. Every frontend priority array is unique and
bounded by its corresponding resource cap. A zero divisor, zero capacity,
unbounded collection, or unknown enum invalidates the containing object.
`acceptedSourceMetadataDisclosureIds` is a bounded canonical decoded set; an
empty set deliberately authorizes no route or contact adapter and is never
replaced by an implicit release default.
Every contact-adapter allow/deny list is a sorted-unique unsigned-16-bit
collection; denial wins and an adapter ID in both lists makes the policy
invalid rather than relying on iteration order. Every prewarmed
public-context ID is canonical and resolves uniquely from the client-global
catalog before network work.
An SP1 floor resolves exactly one profile under
`sourcePrivacyProfileRegistryHash`; every prewarmed public context it may use
has at least one allowed route whose registered mechanism-version hash matches that
profile. Disabling or changing the floor is a new policy generation and cannot
rewrite an existing exposure interval.
`maxSourcePrivacyEvidenceEntries/Bytes` charge the exact canonical
floor-history rows, exposure records, egress-audit entries, independence
evidence, volume-epoch rows, evaluated-interval traffic charges,
formal-parameter/route-mass bindings, classifier records, measurement records,
and saturation witness required for the greatest completed interval. The fixed
witness bytes are reserved. If the complete client-global snapshot cannot fit
atomically, it records saturation, blocks SP1-required egress, and forces
`unknown`; it never truncates to a favorable context, route, request,
generation, volume epoch, traffic class, or domain set.
`ClientGlobalResourcePolicyV1` is validated and persisted before the first
blind room. Every replacement—not only a numerically smaller cap—is an
explicit global action that first proves all currently retained rooms,
profiles, contexts, catalogs, routes, work, and schedulers satisfy every new
cross-field invariant or leaves the complete old policy unchanged. In
particular, increasing `maxInitializedBlindRooms` is rejected when any retained
profile has fewer `roomSlotsPerClient`.
Every room-local `ClientResourcePolicyV1` replacement follows the same
validate-or-keep-old rule. Lowering `maxActiveCarriersPerRoom` below the
persisted sticky room set fails; the frontend must first atomically disable
named exact context IDs through `RoomCarrierAssignmentPolicyV1`, let the room
reconcile, and only then commit the lower cap.
Every `ContactAdapterRegistryEntryV1` field is canonically bounded; its
profile list is sorted and unique, all byte/count/MTU/fragment bounds are
positive safe integers, and its protocol, codec, fragmentation,
authentication, clock, and bearer-constraint identifiers resolve exactly once
under `transportAdapterRegistryHash`. Duplicate adapter IDs or an entry that
cannot carry every fixed class of a claimed profile invalidate the registry.
Each adapter's authentication attempt window, attempt cap, concurrent-context
cap, and authenticated-context byte cap is positive and is enforced before
session transcript allocation. The client-global contact count/byte caps are
enforced across adapters before any candidate enumeration.
Every `RouteFamilyRegistryEntryV1` is canonical and unique by unsigned-16-bit
`routeFamily`; its parser/adapter hash and
`sourceMetadataDisclosureId` and optional
`sourcePrivacyMechanismVersionHash` are
immutable release-registry facts. A non-null mechanism hash resolves exactly
one audited mechanism under `sourcePrivacyMechanismRegistryHash`; null means
that route can never satisfy SP1. Duplicate family IDs or an unregistered
parser/adapter invalidate the registry rather than choosing one by load
order.

#### Release-registry SSOT

The capability-only one-call flow is executable only with one shipped,
content-addressed registry:

```ts
type BlindRendezvousReleaseRegistryV1 = {
  version: 1;
  canonicalBinarySchemaHash: Bytes32;
  executableKernelManifestHash: Bytes32;
  claimRegistryHash: Bytes32;
  formalObligationRegistryHash: Bytes32;
  publicHttpProtocolHash: Bytes32;
  storeCompatibilityHash: Bytes32;
  defaultBlindPolicyBytes: Uint8Array;
  defaultBlindPolicyHash: Bytes32;
  defaultDeliveryProfileBytes: Uint8Array;
  defaultDeliveryProfileHash: Bytes32;
  defaultPlannerPolicy: ConnectionPlannerPolicyV1;
  defaultRoomCarrierAssignmentPolicy: RoomCarrierAssignmentPolicyV1;
  defaultResourcePolicy: ClientResourcePolicyV1;
  defaultGlobalResourcePolicy: ClientGlobalResourcePolicyV1;
  defaultBootstrapStoreHints: readonly BootstrapStoreHintV1[];
  routeFamilyRegistryHash: Bytes32;
  transportAdapterRegistryHash: Bytes32;
  assuranceMethodRegistryHash: Bytes32;
  allocationSchemeRegistryHash: Bytes32;
  storeAccountabilityRegistryHash: Bytes32;
  sourcePrivacyMechanismRegistryHash: Bytes32;
  sourcePrivacyProfileRegistryHash: Bytes32;
};
```

The SDK package, frontend deployment, store deployment, protocol vectors, and
whitepaper manifest name the exact same registry hash and therefore the same
kernel, claim, formal-obligation, accountability, and source-privacy
registries. The kernel manifest's `canonicalBinarySchemaHash` byte-equals this
registry's field. Release validation resolves the exact manifest and both
registries, recomputes their canonical hashes, and byte-compares them with
`executableKernelManifestHash`, `claimRegistryHash`, and
`formalObligationRegistryHash`; a well-shaped arbitrary `Bytes32` is never an
accepted root. Every module's `executableArtifactHash` resolves the exact
shipped executable bytes and every `normativeSourceTreeHash` recomputes from
the published normalized source tree. The default policy and
profile bytes reparse canonically and hash to the adjacent fields; the default
policy equals `DEFAULT_BLIND_POLICY_V4_0`. Registry updates may add locally
selectable profiles, stores, routes, or adapters, but cannot reinterpret an
invite, policy, profile hash, compatibility hash, or persisted room.

```text
BlindRendezvousReleaseRegistryHash =
  H(
    "p2party/blind-rendezvous-release-registry/v1" ||
    Canonical(BlindRendezvousReleaseRegistryV1)
  )
```

`storeCompatibilityHash` is the exact result of the Section 4.2 compatibility
preimage frozen by Phase 0; its canonical limits preimage and hash vector ship
beside the registry. It does not recursively include
`BlindRendezvousReleaseRegistryHash`.

This architecture document deliberately does not fabricate those final
deployment bytes. Until the binary schema, executable kernel, claim/formal
registries, HTTP protocol, complete default profile/planner/per-room/global
resource values, allocation scheme, compatibility hash,
accountability/source-privacy registry entries, and bootstrap
descriptor/routes are frozen and vector-tested in Phase 0, the document is
architecture-complete but not wire-interoperable or implementation-ready.
Implementations may prototype behind internal flags; they shall not
independently invent release bytes and call them v0.4.

The hashes are:

```text
PolicyHash =
  H("p2party/room-policy/v4" || Canonical(RoomPolicyV4))

RoomRoot =
  HKDF-Extract(
    salt = PolicyHash,
    ikm = capability
  )

RoomContextId =
  H("p2party/room-context/v4" || capability || PolicyHash)

DeliveryProfileHash =
  H("p2party/delivery-profile/v1" || Canonical(DeliveryProfileV1))

LocalRoomId =
  Base64urlNoPad(
    H("p2party/local-room-id/v1" || RoomContextId)
  )
```

`RoomRoot` and `RoomContextId` are local secrets and never cross a carrier.
`LocalRoomId` replaces the legacy server-assigned room UUID in local state and
is resolved synchronously once access is initialized; it never crosses a
carrier. A delivery-profile hash authenticates one carrier's public geometry,
not the room. The same canonical operation may therefore be independently
wrapped into multiple compatible delivery profiles without rekeying the room.
A store list, route, cursor, delivery profile, availability result, frontend
setting, planner policy, roster digest, and measured assurance value shall not
enter `RoomPolicyV4`.

In blind mode the public runtime object exposes `Room.id = LocalRoomId`.
Legacy `Room.url` is deprecated and temporarily exposes the tagged non-secret
handle `local.v1.<LocalRoomId>`; the tag is deliberately disjoint from bare
compact capabilities and never contains the invite. APIs that currently
accept `roomUrl` first parse a closed `RoomRef = invite | local-handle`; a
local handle can only look up an already-vaulted room and is never decoded as
a capability. `connect`, `joinRoom`, and `waitForRoom` parse the invitation
version, initialize and atomically persist the local room, then resolve even
when every carrier is offline. Carrier readiness is a separate
observable/wait and cannot resurrect the old server-UUID dependency.

The capability and `RoomRoot` live only in a protected vault keyed by
`LocalRoomId`. Upgrade migrates Redux `currentRoomUrl`, public `Room.url`,
localStorage keys, ordinary database indexes, purge/middleware namespaces, and
the legacy server-UUID mapping transactionally. It deletes a plaintext
capability index only after the wrapped vault and new indexes commit. A crash
at any boundary resumes or rolls back that migration without losing the room
or exposing the secret.

`roomCryptoSuite=1` fixes the room hash and confirmation function to SHA-256,
root derivation to HKDF-SHA-256, operation/stable/authority signatures to
Ed25519 with the exact domain-separated transcripts below, and canonical
public-key validation. It is available before any delivery profile is chosen.
`pairBootstrapSuite=1` fixes the complete bootstrap/pair suite: the
MLKEM768-X25519 hybrid KEM and vectors from the frozen
`draft-irtf-cfrg-concrete-hybrid-kems-04` snapshot, its HPKE mapping from
`draft-ietf-hpke-pq-05` (KEM ID `0x647a`; KEM-internal
`suite_id = "KEM" || 0x647a`), RFC 9180 PSK mode with HKDF-SHA-256
(KDF ID `0x0001`) and ChaCha20Poly1305 (AEAD ID `0x0003`). The HPKE
key-schedule suite ID is exactly
`"HPKE" || 0x647a || 0x0001 || 0x0003`, distinct from the KEM-internal ID.
Suite 1 also fixes the post-bootstrap
XChaCha20Poly1305 pair envelope with a 24-byte public nonce. This active
Internet-Draft pair is a version-pinned release dependency, not a claim of
final standard status; changing its bytes requires a new suite number. A delivery
profile chooses only carrier sealing, public admission, schedule, and
geometry. It cannot change room or pair validity.

The existing `RoomPolicyV1` session-policy bytes are nested, not copied field by field:
`authMode`, `pqMode`, `rendezvousMode`, cover mode, and cover schedule have one
encoder and one source of truth. `RoomPolicyV4` validation requires
`decodeRoomPolicyV1(sessionPolicyV1).rendezvousMode ===
"blind-meeting-point"`. The PIN bytes remain transient frontend input and are
never serialized into either policy.

Every `ConnectionPlannerPolicyV1`, including an application default and a
caller-supplied policy, validates:

```text
all numeric fields are safe integers
1 <= sparseRadius < roomPolicy.maxRoomMembers
1 <= maxActiveStableEdges < roomPolicy.maxRoomMembers
min(
  checkedMultiply(2, sparseRadius),
  roomPolicy.maxRoomMembers - 1
) <= maxActiveStableEdges
maxActiveStableEdges <= maxProvisionalEdges
maxProvisionalEdges <= resourcePolicy.maxPairLedgerEntriesPerRoom
1 <= fullMeshMaxMembers <= maxActiveStableEdges + 1
fullMeshMaxMembers <= roomPolicy.maxRoomMembers
mode == "explicit" implies sparseRadius is ignored
allowOnDemandEdges is an explicit closed boolean
```

`ConnectionPlannerPolicyV1` is local source state: peers may intentionally
choose different modes or stricter caps. Such differences may yield different
desired edge sets and do not violate room-state convergence. Mutual admission,
the receiver's applicable planner/on-demand rule, and both hard degree caps
still apply.

#### Byte-frozen v2 blind policy resolution

The v2 grammar is ASCII and canonical:

```text
default-v2 = "v2." || Base64urlNoPad(capability[32])
policy-v2  = default-v2 || "." ||
             Base64urlNoPad(Canonical(RoomPolicyV4))
```

The capability component is exactly 43 characters, has no `=`, and decodes to
exactly 32 bytes. The policy component is non-empty, unpadded base64url and
decodes within `MAX_INVITE_POLICY_BYTES` to the one canonical encoding of a
valid `RoomPolicyV4`. `MAX_INVITE_POLICY_BYTES` and the exact binary policy
codec are frozen in the release registry. A leading `#` is accepted only by
the fragment parser and is not part of the canonical invite. Extra
components, alternate alphabets, padding, whitespace, noncanonical
re-encodings, unknown policy fields, or a nested session policy whose
rendezvous mode is not `blind-meeting-point` fail closed.

The capability-only form has no policy field. Its blind-rendezvous meaning is
fixed once here rather than inferred from mutable application defaults. A v1
invitation never selects this policy:

```text
DEFAULT_BLIND_SESSION_POLICY_V1 =
  5032525001040001020000000000000000000000000000000000000000000000

hashRoomPolicyV1(decodeRoomPolicyV1(DEFAULT_BLIND_SESSION_POLICY_V1)) =
  87456f93e509440102dbd4c77534963820c77a32d98a5b18de9af1dedfd704bb

DEFAULT_BLIND_POLICY_V4_0 = Canonical({
  version: 4,
  sessionPolicyV1: DEFAULT_BLIND_SESSION_POLICY_V1,
  roomCryptoSuite: 1,
  operationCodec: 1,
  pairBootstrapSuite: 1,
  protocolLimits: {
    logicalWindowMs: 60000,
    maxClockSkewWindows: 5,
    operationRetentionWindows: 1440,
    pairControlRetentionWindows: 10080,
    receiverKeyOverlapWindows: 5,
    maxFutureLogicalWindows: 5,
    maxDependenciesPerOperation: 8,
    maxOperationsPerAuthorWindow: 16
  },
  admissionFloor: { mode: "capability" },
  maxRoomMembers: 64
})
```

Those 32 session-policy bytes are the existing canonical v1 default
(`revision=0`, no PIN, ML-KEM-768, immediate cover) with only
`rendezvousMode="blind-meeting-point"`. The canonical
`DEFAULT_BLIND_POLICY_V4_0` vector and hash are a release artifact and become
immutable before blind mode is enabled. A later application default may
change only under a new explicit policy or invitation version; it shall not
reinterpret a bare v2 invitation. `admissionFloor: "capability"` means the
canonical room has no portable authority requirement; local blacklist and
address-book-only controls still apply.

The policy-v2 form resolves to the exact decoded `RoomPolicyV4`; it does not
merge application defaults into that object. This single suffix supports the
existing advanced/PIN/PQ/cover sharing flow and future creation-time authority
mode without copying individual policy fields into the URL grammar. Removing
or changing it derives a different `RoomContextId` and therefore fails closed,
not into the original room.

For a current explicit `ConnectRoomOptions.policy`, the creator's migration
adapter canonicalizes it once with the existing `encodeRoomPolicyV1`, places
those exact 32 bytes in `sessionPolicyV1`, constructs the complete immutable
`RoomPolicyV4`, and emits that object through policy-v2. It does not
independently copy `pqMode`, `authMode`, or cover fields. Blind connection
requires the nested policy to already name `blind-meeting-point`. A persisted
legacy-signaling room remains legacy until an explicit migration
creates/persists its blind immutable policy; an upgrade shall not silently
reinterpret an already persisted legacy room.

The frontend resolves `BlindRoomAccessV4` from existing inputs:

```text
parsedInvite =
  parseRoomInvite(invite) // preserves version; closed v1 | v2 result

capability =
  parsedInvite.capability

roomPolicy =
  DEFAULT_BLIND_POLICY_V4_0 when parsedInvite == v2/default
  or parsedInvite.roomPolicy when parsedInvite == v2/room-policy
  with exact persisted/options policy permitted only when it byte-matches
  that invite-derived value

deliveryProfiles =
  locally shipped/configured content-addressed profiles
  ∪ compatible profiles required by explicitly authorized stores

bootstrapStoreHints =
  configured/default signed public-store descriptors and routes
  ∪ explicit local stores passed in options

frontendControls, connectionPlanner =
  current frontend room controls and local planner preferences

carrierAssignments =
  current persisted room-local carrier-assignment policy, or the release
  registry's one canonical fresh-room default
  { version: 1, policyGeneration: 0, disabledCarrierContextIds: [] }

carrierPolicy =
  read-only reference to the current vault/client-global carrier-policy
  generation

resourcePolicy =
  current local storage/work limits

globalResourcePolicy =
  one SDK-runtime/vault policy, defaulted from the release registry and never
  supplied by an invitation or independently overridden by a room join
```

This preserves today's public API shape and `/r` one-link flow:

```ts
const invite = p2party.generateRoomInvite();
history.replaceState(null, "", `/r#${invite}`);
const room = await p2party.joinRoom(location.hash.slice(1) || invite);
```

The version-preserving `parseRoomInvite` keeps accepting compact capability,
`v1.`, `#v1.`, and legacy 64-hex migration forms as legacy signaling, and adds
both closed v2 forms as blind signaling. The existing asynchronous
`decodeRoomCapabilityWords` remains the separate legacy word-conversion path;
direct word parsing is not silently added to `joinRoom`. `joinRoom` consumes
the closed parsed result directly. Existing capability-only helpers remain
legacy helpers and reject v2; they shall not normalize v2 to bare bytes/hex
and erase the rendezvous version. Copy/paste of a complete URL remains a
frontend action: the page requires or canonically redirects to `/r`, extracts
`new URL(value).hash`, and passes that fragment to `joinRoom`; the library
does not gain a second URL parser. Existing v1 links may retain their deployed
`?auth=`, `?pq=`, or `?policy=` compatibility path. A v2 creator emits no
room-policy query: advanced-room options are encoded once in the policy-v2
fragment, so the recipient still sees the same PIN/advanced-room prompt
without leaking configuration in the initial HTTP request.

For v1, the existing optional `signalingServerUrl` is consumed only by the
optional legacy-signaling adapter. For v2, a source-compatible migration alias
must resolve it exactly once, when present, through trusted local configuration to an exact signed
public-store descriptor/route. If the argument is present and no exact trusted
alias exists, `joinRoom` rejects with
`BlindStoreAliasResolutionError`/`blind-store-alias-unmapped` before network
work; it never silently ignores the value or substitutes the default. The raw
URL cannot authorize or open a WebSocket, create an unsigned store, or enter
room identity. An additive
`rendezvousStores` option may supply more signed descriptors without changing
positional calls. `rtcConfig` remains the WebRTC-candidate configuration and
is irrelevant to non-WebRTC carriers.

The v2 frontend derives join readiness, room availability, peers, and
messaging gates from the generic room/carrier projections and assurance
vector. It never waits on or interprets `signalingServerConnectionState`.
Legacy signaling controls and copy render only when the parsed room is v1 and
the optional compatibility adapter is installed.

The deployed compact/word/v1 forms remain legacy because their creation-era
semantics cannot be inferred from random capability bytes. The v2 prefix is
the minimum version discriminator needed for safe migration; it does not add
another secret. Blind rendezvous policy selection comes from v2 plus the
exact invite-derived authenticated room policy. No invitation form is ever
sent to a store.

Two clients using the same capability but different policy suffixes derive
different room contexts and fail closed before pair disclosure, as current
policy immutability already requires. A PIN value, private authority grant, or
non-default first store continues to be supplied through the frontend/API or
a separately authenticated deployment configuration. The public policy may
be in the fragment; the PIN, grants, carrier policy, and store routes never
are.

Bootstrap hints are availability aids. Clients with the same capability and
policy but different profiles and valid bootstrap hints address the same room.
They can exchange an operation only through a carrier/profile that both can
process or through a bridging client that rewraps it into each side's profile.
First contact still requires at least one common store or physical carrier
path.
Once contact exists, encrypted store hints and client backfill expand paths
automatically. Adding a store never requires regenerating or resharing the
room invitation.

### 4.2 Store identity, routes, and frontend carrier policy

```ts
type StoreDescriptorV1 = {
  version: 1;
  storeIdentityEd25519Key: Bytes32;
  allocationIssuerPublicKeyDer: Uint8Array;
  descriptorGeneration: bigint;
  compatibilityHash: Bytes32;
  supportedDeliveryProfileHashes: readonly Bytes32[];
  checkpointChainStarts: readonly {
    deliveryProfileHash: Bytes32;
    chainStartIngressWindow: bigint;
  }[];
  notBeforeUnixMs: bigint;
  notAfterUnixMs: bigint;
  descriptorSignature: Bytes64;
};

type StoreRouteV1 = {
  version: 1;
  storeId: Bytes32;
  descriptorHash: Bytes32;
  routeFamily: number; // unsigned 16-bit release-registry ID
  opaqueLocator: Uint8Array;
  routePublicParameters: Uint8Array;
  notBeforeUnixMs: bigint;
  notAfterUnixMs: bigint;
  routeSignature: Bytes64;
};

type BootstrapStoreHintV1 = {
  descriptor: StoreDescriptorV1;
  routes: readonly StoreRouteV1[];
};

// Canonical encoding uses sequence order because the semantic order key is
// the derived RouteId rather than the route's own encoded bytes.
const MAX_STORE_HINT_ROUTES_V1 = 255;

type StoreHintOperationV1 = {
  version: 1;
  descriptor: StoreDescriptorV1;
  routes: readonly StoreRouteV1[]; // <= MAX_STORE_HINT_ROUTES_V1
  hintExpiresAfterLogicalWindow: bigint;
};

type SourcePrivacyFloorV1 =
  { mode: "disabled" } | { mode: "sp1"; sourcePrivacyProfileId: Bytes32 };

type PublicStoreRequestClassV1 =
  | 0 // descriptor/profile fetch not satisfied from a shipped local artifact
  | 1 // anonymous-token issuance
  | 2 // allocation
  | 3 // append
  | 4 // checkpoint read
  | 5 // chunk read
  | 6 // status
  | 7; // scheduled retry

type SourcePrivacyFragmentationModeV1 =
  | {
      mode: "single-privacy-packet";
      maximumRequestPlaintextBytes: number;
      allOrNothingFragmentationCodecId: null;
    }
  | {
      mode: "mix-layer-all-or-nothing";
      maximumRequestPlaintextBytes: number;
      allOrNothingFragmentationCodecId: number;
    };

type SourcePrivacyMechanismRegistryEntryV1 = {
  version: 1;
  mechanismId: Bytes32;
  mechanismVersionHash: Bytes32;
  privacyPacketBytes: number;
  fragmentation: SourcePrivacyFragmentationModeV1;
  retryMode: "whole-message-with-fresh-privacy-message-id";
  reassemblyBoundary: "before-store-request-semantics";
  dropTagFormalObligationId: Uint16;
  delayTagFormalObligationId: Uint16;
  pathPersistenceMode:
    "independent-per-message" | "sticky-bounded-session" | "fixed-cascade";
  coverTrafficMode:
    | "full-response-independent-cover"
    | "loop-plus-additional-cover"
    | "loop-only";
  additionalNonLoopCoverModelId: Bytes32 | null;
  implementationArtifactHash: Bytes32;
  measurementVerifierArtifactHash: Bytes32;
  egressDisclosureContractHash: Bytes32;
};

type SourcePrivacyProfileV1 = {
  version: 1;
  sourcePrivacyProfileId: Bytes32;
  mechanismId: Bytes32;
  mechanismVersionHash: Bytes32;
  adversaryModelId: Bytes32;
  formalSecurityDefinitionId: Bytes32;
  privacySessionDefinitionId: Bytes32;
  topologyModelId: Bytes32;
  routeSelectionModelId: Bytes32;
  traceModelId: Bytes32;
  taggingModelId: Bytes32;
  clockModelId: Bytes32;
  formalObligationId: Uint16;
  pathCompromiseFormalObligationId: Uint16;
  requiredFormalParameterIds: readonly Bytes32[];
  classifierAcceptancePolicyHash: Bytes32;
  // Mechanism/egress-gate coverage, including optional and failure paths.
  coveredRequestClasses: readonly PublicStoreRequestClassV1[]; // exactly 0..7
  // The fixed five scheduler request kinds: issuance through chunk read.
  scheduledRequestClasses: readonly PublicStoreRequestClassV1[]; // exactly 1..5
  completePrewarmIntervalMs: bigint;
  exposureIntervalMs: bigint;
  evidenceMaxAgeMs: bigint;
  maxPrivacyPacketsPerExposureInterval: bigint;
  maxPrivacyBytesPerExposureInterval: bigint;
  maxLinkablePrivacyPacketsPerVolumeEpoch: bigint;
  maxLinkablePrivacyBytesPerVolumeEpoch: bigint;
  minimumMeasurementSampleCount: number;
  anonymitySetLowerBoundK: number;
  corruptMixingDomainsUpperBoundT: number;
  independentMixingDomainsLowerBound: number;
  advantageEpsilonNumerator: bigint;
  advantageEpsilonDenominator: bigint;
};

// Protected local audit entry. It is never a room operation or carrier field.
type PublicStoreEgressAuditEntryV1 = {
  attemptOrdinal: bigint;
  requestDigest: Bytes32;
  requestClass: PublicStoreRequestClassV1;
  scheduledEventId: Bytes32 | null;
  routeInstanceId: Bytes32 | null;
  mechanismVersionHash: Bytes32 | null;
  volumeEpochId: Bytes32 | null;
  privacyMessageId: Bytes32 | null;
  privacyPacketCount: bigint;
  privacyByteCount: bigint;
  policyGeneration: bigint;
  outcome:
    | "dispatched-conforming"
    | "blocked-nonconforming"
    | "dispatched-nonconforming";
};

// Local protected meter input. One emission shared by several contexts is
// charged once globally and in full to each named context (conservative).
type SourcePrivacyTrafficChargeV1 = {
  version: 1;
  chargeOrdinal: bigint;
  previousChargeDigest: Bytes32;
  volumeEpochId: Bytes32;
  chargedPublicCarrierContextIds: readonly Bytes32[];
  intervalNumber: bigint;
  kind: "prewarm" | "dummy-cover" | "request" | "retry" | "failure-control";
  sourceEventId: Bytes32;
  privacyPacketCount: bigint;
  privacyByteCount: bigint;
};

type PublicContextSourceExposureV1 = {
  version: 1;
  publicCarrierContextId: Bytes32;
  // null means the interval began without an SP1 floor.
  sourcePrivacyProfileId: Bytes32 | null;
  intervalNumber: bigint;
  intervalStartMs: bigint;
  intervalEndMs: bigint;
  firstCarrierPolicyGeneration: bigint;
  lastCarrierPolicyGeneration: bigint;
  touchedRequestClasses: readonly PublicStoreRequestClassV1[];
  mechanismVersionHashes: readonly Bytes32[];
  usedRouteInstanceIds: readonly Bytes32[];
  requestCountByClass: readonly {
    requestClass: PublicStoreRequestClassV1;
    count: bigint;
  }[];
  volumeEpochId: Bytes32 | null;
  privacyPacketCount: bigint;
  privacyByteCount: bigint;
  trafficChargeSetDigest: Bytes32;
  expectedScheduledRequestSetDigest: Bytes32;
  attemptedRequestSetDigest: Bytes32;
  egressAuditDigest: Bytes32;
  prewarmStartedAtMs: bigint;
  prewarmCompletedAtMs: bigint;
  prewarmTraceDigest: Bytes32;
  state: "clean-conforming" | "tainted-nonconforming";
  firstNonconformingRequestDigest: Bytes32 | null;
};

// Client-global and protected. A new wall-clock interval, route, policy,
// context, restart, or login never resets this cumulative linkability budget.
type SourcePrivacyVolumeEpochV1 = {
  version: 1;
  volumeEpochId: Bytes32;
  linkabilityScopeId: Bytes32;
  sourcePrivacyProfileId: Bytes32;
  mechanismVersionHash: Bytes32;
  privacySessionDefinitionId: Bytes32;
  randomEpochNonce: Bytes32;
  openedAtMs: bigint;
  closedAtMs: bigint | null;
  predecessorVolumeEpochId: Bytes32 | null;
  predecessorUnlinkabilityEvidenceId: Bytes32 | null;
  cumulativeLinkablePrivacyPacketCount: bigint;
  cumulativeLinkablePrivacyByteCount: bigint;
  trafficChargeChainHeadDigest: Bytes32;
  state: "active" | "cap-exhausted" | "rotated-with-unlinkability-evidence";
};

type FrontendCarrierPolicyV1 = {
  version: 1;
  policyGeneration: bigint;
  sourcePrivacyFloor: SourcePrivacyFloorV1;
  allowedStoreIds: CanonicalBytes32SetV1 | "any-compatible";
  deniedStoreIds: CanonicalBytes32SetV1;
  deniedRouteIds: CanonicalBytes32SetV1;
  deniedRouteFamilies: readonly number[];
  deniedOrigins: readonly string[];
  explicitlyAllowedPrivateRouteIds: CanonicalBytes32SetV1;
  authorizedBrowserDirectRouteIds: CanonicalBytes32SetV1;
  preauthorizedRemoteRouteIds: CanonicalBytes32SetV1;
  autoActivateRemoteHints: "never" | "preauthorized-only";
  preferredDeliveryProfileHashes: readonly Bytes32[];
  preferredStoreIds: readonly Bytes32[];
  preferredRouteIds: readonly Bytes32[];
  preferredContactAdapterProtocolIds: readonly number[];
  // Exact disclosure documents accepted by this frontend. Route/contact
  // activation fails closed when the registry entry's ID is absent.
  acceptedSourceMetadataDisclosureIds: CanonicalBytes32SetV1;
  allowedContactAdapterProtocolIds: readonly number[] | "any-compatible";
  deniedContactAdapterProtocolIds: readonly number[];
  // Exact PublicCarrierContextId values whose all-dummy scheduler starts
  // independently of room activity.
  prewarmedPublicCarrierContextIds: CanonicalBytes32SetV1;
};

type ClientResourcePolicyV1 = {
  maxActiveDeliveryProfilesPerRoom: number;
  maxActiveCarriersPerRoom: number;
  maxRetainedCandidateObjectsPerRoom: number;
  maxRetainedCandidateBytesPerRoom: number;
  maxRetainedValidOperationsPerRoom: number;
  maxRetainedValidOperationBytesPerRoom: number;
  maxReconcileObjectsPerPass: number;
  maxReconcileBytesPerPass: number;
  maxBufferedDependencyBytesPerRoom: number;
  maxPairOpenTrialsPerPresenceWindow: number;
  maxPairOpenBytesPerPresenceWindow: number;
  maxPairLedgerEntriesPerRoom: number;
  maxPairLedgerBytesPerRoom: number;
  maxOutboxBytesPerRoom: number;
  reservedSafetyControlOutboxBytesPerRoom: number;
  reservedIdentityBootstrapOutboxBytesPerRoom: number;
  maxAssuranceEvidenceEntriesPerRoom: number;
  maxAssuranceEvidenceBytesPerRoom: number;
  maxAssuranceRawEvidenceBytesPerRoom: number;
};

type ClientGlobalResourcePolicyV1 = {
  version: 1;
  maxInitializedBlindRooms: number;
  maxActivePublicCarrierContexts: number;
  maxRoutesPerPublicCarrierContext: number;
  maxPublicCatalogStores: number;
  maxPublicCatalogRoutes: number;
  maxPublicCatalogBytes: number;
  maxAuthenticatedContactContexts: number;
  maxAuthenticatedContactContextBytes: number;
  maxL3DueWorkEntries: number;
  maxL3DueWorkBytes: number;
  maxPortableBundleBytes: number;
  maxContactInventoryEntries: number;
  maxPendingL3Exports: number;
  maxPendingL3ExportBytes: number;
  maxStoreAccountabilityEvidenceEntries: number;
  maxStoreAccountabilityEvidenceBytes: number;
  maxSourcePrivacyEvidenceEntries: number;
  maxSourcePrivacyEvidenceBytes: number;
};

type ContactAdapterRegistryEntryV1 = {
  version: 1;
  adapterProtocolId: number; // unsigned 16-bit
  adapterCodecVersion: number;
  sourceMetadataDisclosureId: Bytes32;
  supportedDeliveryProfileHashes: readonly Bytes32[];
  maxReassembledObjectBytes: number;
  maxInventoryEntries: number;
  maxBatchBytes: number;
  minimumUsableBearerMtuBytes: number;
  maxFragmentsPerObject: number;
  fragmentationCodecId: number;
  sessionAuthenticationSuiteId: number;
  authenticationAttemptWindowMs: bigint;
  maxAuthenticationAttemptsPerWindow: number;
  maxConcurrentAuthenticatedContexts: number;
  maxAuthenticatedContextBytes: number;
  requiresBoundedClockSnapshot: true;
  bearerConstraintHash: Bytes32;
};

type RouteFamilyRegistryEntryV1 = {
  version: 1;
  routeFamily: number; // unsigned 16-bit
  routeCodecVersion: number; // unsigned 16-bit
  sourceMetadataDisclosureId: Bytes32;
  sourcePrivacyMechanismVersionHash: Bytes32 | null;
  parserAndAdapterHash: Bytes32;
};

type AuthenticatedContactContextV1 = {
  version: 1;
  adapterProtocolId: number; // unsigned 16-bit
  sessionAuthenticationSuiteId: number; // unsigned 16-bit
  sessionAuthenticationTranscriptHash: Bytes32;
  authenticatedSessionContextId: Bytes32;
  bearerMtuBytes: number; // unsigned 32-bit
  bearerConstraintHash: Bytes32;
};
```

`sourceMetadataDisclosureId` is
`H("p2party/source-metadata-disclosure/v1" ||
Canonical(the release-published bounded disclosure document))`. The document
enumerates the bearer-visible source, account, discovery, timing, locator,
physical-observer, and permission metadata for that exact adapter family.
Consent is to this immutable content hash; changing the document requires a new
ID and cannot inherit an earlier acceptance.

`SourcePrivacyProfileV1` is release-published rather than room-selected:

```text
SourcePrivacyProfileId =
  H(
    "p2party/source-privacy-profile/v1" ||
    Canonical(profile without sourcePrivacyProfileId)
  )

SourcePrivacyMechanismVersionHash(entry) =
  H(
    "p2party/source-privacy-mechanism/v1" ||
    entry.mechanismId ||
    Canonical(entry without mechanismVersionHash)
  )

SP1EvaluationInterval(now, uncertainty, profile) =
  greatest n such that
    IntervalEnd(n, profile) <= checkedSubtract(now, uncertainty)
  or null when the clock is unsafe, subtraction fails, or no n >= 0 exists

IntervalStart(n, profile) = checkedMultiply(n, profile.exposureIntervalMs)
IntervalEnd(n, profile) = checkedMultiply(n + 1, profile.exposureIntervalMs)

SourceExposureRecordDigest =
  H("p2party/source-exposure-record/v1" || Canonical(exposure))

SourcePrivacyFloorHistoryDigest =
  H(
    "p2party/source-privacy-floor-history/v1" ||
    Canonical(sourcePrivacyRuntime.floorHistory)
  )

UsedRouteSetDigest =
  H(
    "p2party/source-privacy-used-route-set/v1" ||
    Canonical(exposure.usedRouteInstanceIds)
  )

SourceExposureSetDigest =
  H(
    "p2party/source-exposure-set/v1" ||
    Canonical(
      sorted complete exposures and floorHistory for evaluationIntervalNumber
    )
  )

SourcePrivacyLinkabilityScopeId =
  H(
    "p2party/source-privacy-linkability-scope/v1" ||
    localVaultAssuranceContextId
  )

SourcePrivacyVolumeEpochId =
  H(
    "p2party/source-privacy-volume-epoch/v1" ||
    linkabilityScopeId ||
    sourcePrivacyProfileId ||
    mechanismVersionHash ||
    privacySessionDefinitionId ||
    predecessorVolumeEpochId-or-zero ||
    randomEpochNonce
  )

SourcePrivacyVolumeEpochSetDigest =
  H(
    "p2party/source-privacy-volume-epoch-set/v1" ||
    Canonical(sourcePrivacyRuntime.volumeEpochs)
  )

EgressAuditDigest =
  H(
    "p2party/public-store-egress-audit/v1" ||
    Canonical(entries sorted by unique attemptOrdinal)
  )

AttemptedRequestSetDigest =
  H(
    "p2party/public-store-attempted-request-set/v1" ||
    Canonical(entries' (attemptOrdinal, requestDigest, outcome) projection)
  )

SourcePrivacyTrafficChargeDigest(charge) =
  H(
    "p2party/source-privacy-traffic-charge/v1" ||
    Canonical(charge)
  )

SourcePrivacyTrafficChargeSetDigest =
  H(
    "p2party/source-privacy-traffic-charge-set/v1" ||
    Canonical(
      evaluatedIntervalTrafficCharges sorted by unique chargeOrdinal
    )
  )

SourcePrivacyOperatorDomainSetDigest =
  H(
    "p2party/source-privacy-operator-domain-set/v1" ||
    Canonical(
      evidence.mixingDomainBindings,
      evidence.storeAndEgressOperatorDomainIds
    )
  )

SourcePrivacyFormalParameterBindingsDigest =
  H(
    "p2party/source-privacy-formal-parameters/v1" ||
    Canonical(evidence.formalParameterBindings)
  )

SourcePrivacyRouteSelectionMassDigest =
  H(
    "p2party/source-privacy-route-selection-mass/v1" ||
    Canonical(evidence.routeSelectionMassByLayer)
  )

SourcePrivacySubjectScopeId =
  H(
    "p2party/source-privacy-subject/v1" ||
    localVaultAssuranceContextId ||
    evidence.publicCarrierContextId ||
    evidence.sourcePrivacyProfileId ||
    U64BE(evidence.intervalNumber) ||
    U64BE(evidence.intervalStartMs) ||
    U64BE(evidence.intervalEndMs) ||
    evidence.sourceExposureRecordDigest ||
    evidence.usedRouteSetDigest ||
    evidence.floorHistoryDigest ||
    evidence.operatorDomainSetDigest ||
    evidence.formalParameterBindingsDigest ||
    evidence.routeSelectionMassDigest ||
    evidence.volumeEpochId ||
    evidence.measurementPopulationId
  )
```

The profile is valid only when both intervals and all four packet/byte caps are
positive,
`coveredRequestClasses` is exactly `0..7`,
`scheduledRequestClasses` is exactly `1..5`,
`anonymitySetLowerBoundK >= 2`,
`independentMixingDomainsLowerBound >=
max(2, corruptMixingDomainsUpperBoundT + 1)`, and the following checked
non-vacuity inequality holds with a non-negative numerator and positive
denominator:

```text
advantageEpsilonNumerator * anonymitySetLowerBoundK
  <
advantageEpsilonDenominator * (anonymitySetLowerBoundK - 1)
```

`minimumMeasurementSampleCount > 0`; `requiredFormalParameterIds` is bounded,
sorted, unique, and nonempty; and `formalObligationId` resolves the umbrella
computational-game obligation required by the SP1 claim. That obligation
imports the distinct `pathCompromiseFormalObligationId` and the resolved
mechanism entry's distinct drop-tag and delay-tag obligations. A release cannot
use one generic “tagging considered” artifact for all three.
The interval caps count every mechanism emission assigned to the context,
including prewarm and cover; the volume-epoch caps count each physical
emission once across the complete client-global linkability scope.

The exact `SourcePrivacyMechanismRegistryEntryV1` is canonical and its
`mechanismVersionHash` recomputes by the formula above. Packet and request
limits are positive. `single-privacy-packet` rejects any request that does not
fit one packet. `mix-layer-all-or-nothing` requires a registered nonzero codec
whose proof covers all-or-nothing disclosure; application-layer
fragmentation never qualifies. Reassembly completes before target-store
request semantics become visible, and every retry resends the whole message
under a fresh `privacyMessageId`. A fixed-cascade entry with `loop-only` cover
is invalid; fixed cascades plus loops require a non-null measured additional
non-loop-cover model. Drop resistance does not imply delay-tag resistance.

The mechanism registry entry names the concrete
multi-domain construction, browser implementation, padding/batching policy,
entry selection, domain/operator independence method, tagging defenses,
failure semantics, measurement verifier, and an egress-disclosure contract.
The mechanism version hash is derived only by the formula above and every
route entry refers to that value. Under that registered contract, the store
receives only the privacy egress's protocol identifiers, not an originating
identifier carried by the protocol; this is not a categorical claim about
lower-layer observers. OHTTP, a generic VPN, Tor, two ordinary stores, or
“uses a relay” does not satisfy SP1 merely by name.

For one context and the greatest wholly completed safe-clock interval, the
exact predicate is:

```text
SP1Conforms(context, profile, sourcePrivacyRuntime, evidence, now) =
  sourcePrivacyRuntime.floor ==
      { mode: "sp1", sourcePrivacyProfileId: profile.sourcePrivacyProfileId }
  and sourcePrivacyRuntime.evaluationIntervalNumber ==
      SP1EvaluationInterval(now, evaluationClockUncertainty, profile)
  and sourcePrivacyRuntime.floorHistory is the complete protected policy
      history covering prewarm through IntervalEnd
  and sourcePrivacyRuntime.floorHistoryDigest ==
      SourcePrivacyFloorHistoryDigest
  and sourcePrivacyRuntime.exposureSetDigest == SourceExposureSetDigest
  and every floorHistory entry across that range requires this exact profile
  and ExposureSet(context, evaluationInterval) contains the one complete
      record across every policy generation and route touching the interval
  and exposure.publicCarrierContextId == context
  and exposure.sourcePrivacyProfileId == profile.sourcePrivacyProfileId
  and exposure.intervalNumber == sourcePrivacyRuntime.evaluationIntervalNumber
  and exposure.intervalStartMs == IntervalStart(intervalNumber, profile)
  and exposure.intervalEndMs == IntervalEnd(intervalNumber, profile)
  and exposure.state == "clean-conforming"
  and exposure.firstNonconformingRequestDigest == null
  and exposure.expectedScheduledRequestSetDigest equals the scheduler's exact
      fixed event set for scheduled request classes
  and exposure.attemptedRequestSetDigest and requestCountByClass account for
      every fixed, optional, failure, and on-demand request through the sole
      kernel-owned egress gate
  and exposure.attemptedRequestSetDigest == AttemptedRequestSetDigest
  and exposure.egressAuditDigest binds each attempted request to its request
      class, scheduled-event-or-request digest, route instance, mechanism
      version, volume epoch, fresh privacy-message ID, exact privacy
      packet/byte charge, policy generation, and dispatched/blocked result
  and the bounded audit entries resolve and recompute EgressAuditDigest
  and every dispatched conforming request has a non-null volumeEpochId and
      privacyMessageId, a positive packet/byte charge, and the selected
      mechanism's exact fragmentation/retry semantics
  and every blocked request has null volumeEpochId/privacyMessageId and zero
      packet/byte charge; every nonconforming dispatch taints the interval
  and every conforming request audit's packet/byte charge equals the exact
      joined request/retry/failure-control traffic-charge projection
  and sourcePrivacyRuntime.evaluatedIntervalTrafficChargeSetDigest ==
      SourcePrivacyTrafficChargeSetDigest
  and evaluatedIntervalTrafficCharges are a canonical contiguous
      charge-ordinal segment whose first previousChargeDigest equals
      evaluatedIntervalTrafficChargeChainStartDigest, whose adjacent charge
      digests chain exactly, and whose final digest equals
      evaluatedIntervalTrafficChargeChainEndDigest
  and that segment covers every privacy-mechanism emission in the evaluated
      interval, including prewarm, dummy cover, request, retry, and
      failure-control traffic, with no volume-epoch rotation inside the
      interval
  and every charge has positive packet/byte counts, a nonempty sorted-unique
      context set, the selected volume epoch, and the exact interval
  and exposure.trafficChargeSetDigest equals the digest of the exact charge
      projection naming this context
  and exposure.privacyPacketCount/privacyByteCount equal the checked sums of
      that complete projection; a shared emission is conservatively counted in
      full for each named context and once in the global volume epoch
  and those sums are <= profile.maxPrivacyPacketsPerExposureInterval and
      profile.maxPrivacyBytesPerExposureInterval
  and exposure.volumeEpochId resolves exactly one complete client-global
      volume epoch under sourcePrivacyRuntime.volumeEpochSetDigest
  and sourcePrivacyRuntime.volumeEpochSetDigest ==
      SourcePrivacyVolumeEpochSetDigest
  and every volume epoch has linkabilityScopeId ==
      SourcePrivacyLinkabilityScopeId
  and volume epochs form one canonical predecessor-complete, cycle-free,
      non-forking chain with at most one active epoch; the first has null
      predecessor/evidence, and every successor names the exact prior epoch
  and that epoch matches the profile, mechanism, privacy-session definition,
      and linkability scope; its cumulative counts equal all linkable traffic,
      not merely this room/context/interval
  and its trafficChargeChainHeadDigest commits every emitted prewarm, dummy,
      cover, request, retry, and failure-control charge since the epoch opened
  and its cumulative counts, including this request, are <=
      profile.maxLinkablePrivacyPacketsPerVolumeEpoch and
      profile.maxLinkablePrivacyBytesPerVolumeEpoch
  and a successor volume epoch exists only when its predecessor is closed and
      predecessorUnlinkabilityEvidenceId proves unlinkability from every
      retained prior observation under the same formal security definition
  and every touched request class is in profile.coveredRequestClasses
  and exposure.usedRouteInstanceIds equals the sorted unique route projection
      of every dispatched audit entry, with no extra or omitted route
  and UsedRouteSetDigest == evidence.usedRouteSetDigest
  and every used route resolves a registry entry whose
      sourcePrivacyMechanismVersionHash == profile.mechanismVersionHash
  and exposure.prewarmCompletedAtMs - exposure.prewarmStartedAtMs >=
      profile.completePrewarmIntervalMs
  and exposure.prewarmTraceDigest resolves the exact safe-clock/profile/
      context/mechanism/policy trace before the first real request
  and evidence is fresh measured sourcePrivacy evidence for this exact
      context, used route set, exposure digest, profile, complete interval,
      population, adversary, trace, tagging, and clock model
  and evidence.intervalNumber/start/end and publicCarrierContextId exactly
      equal the exposure coordinates
  and evidence.sourceExposureRecordDigest ==
      SourceExposureRecordDigest(exposure)
  and evidence.floorHistoryDigest == sourcePrivacyRuntime.floorHistoryDigest
  and evidence.operatorDomainSetDigest ==
      SourcePrivacyOperatorDomainSetDigest
  and evidence.formalParameterBindingsDigest ==
      SourcePrivacyFormalParameterBindingsDigest
  and evidence.routeSelectionMassDigest ==
      SourcePrivacyRouteSelectionMassDigest
  and evidence.volumeEpochId == exposure.volumeEpochId
  and every declared bound/model value in evidence exactly equals profile
  and evidence.formalParameterBindings are sorted/unique by parameterId,
      contain exactly profile.requiredFormalParameterIds, use the registered
      units/relations, and expose conservative measured values for every
      theorem parameter, including traffic/mix rates when the selected theorem
      uses them
  and evidence.topologyLayerCount is positive and its topology/path/session
      definitions exactly match the selected theorem and live mechanism
  and evidence.routeSelectionMassByLayer is canonical, covers every eligible
      operator domain in every topology layer, contains probabilities in
      [0,1], and each layer's exact checked rational sum is one
  and evidence.mixingDomainBindings are sorted/unique by operatorDomainId,
      their count is at least independentMixingDomainsLowerBound, and each
      binding resolves current independence evidence for that exact domain
  and every routeSelectionMassByLayer operatorDomainId resolves exactly one
      mixingDomainBinding and the proof takes the worst allowed set of at most
      corruptMixingDomainsUpperBoundT domains under those masses
  and evidence.storeAndEgressOperatorDomainIds are sorted and unique and
      disjoint from every mixingDomainBindings[].operatorDomainId
  and evidence.formalResultDigest resolves a current proved-within-scope
      result for profile.formalObligationId and this exact release/model/scope
  and ProofScopeCovers(that result, the exact profile, interval, route,
      domain-set, exposure, population, adversary, trace, tagging, clock,
      formal security/session definitions, topology, layer/domain selection
      mass, formal parameters, volume-epoch semantics and profile caps,
      fragmentation, drop/delay tagging, k, t, and epsilon tuple)
  and evidence.measurementSampleCount >=
      profile.minimumMeasurementSampleCount
  and evidence.classifierEvaluationDigest resolves the exact preregistered
      SourcePrivacyClassifierEvaluationV1 under the same live mechanism,
      trace, population, and interval; it uses entry-and-egress collusion,
      covers every request/outcome class, reports preregistered base rate,
      PR-AUC, and TPR at the configured low FPR, matches
      profile.classifierAcceptancePolicyHash, and has thresholds-met
  and evidence.result == "bound-met"
  and sourcePrivacyRuntime.evidenceSaturated == false
  and no required evidence or exposure custody is saturated
```

Every network-capable public-store adapter and every privacy-mechanism network
emitter is reachable only through the kernel-owned gates. Before dispatch, one
atomic transaction records the exact attempted
request/route/mechanism/policy coordinates. Before any prewarm, dummy, cover,
request, retry, or failure-control emission, the same kernel commits one
`SourcePrivacyTrafficChargeV1`, advances the hash-chain head, and charges the
complete privacy-packet and byte cost against both every named exposure
context and the client-global linkability epoch. The compare-and-charge commits
before any byte leaves; a cap race, overflow, uncertain packet expansion, or
partial charge blocks the whole emission/request. A blocked nonconforming
attempt remains an availability event and is not itself a source exposure; if
any nonconforming bytes leave the device, the transaction changes the interval
to `tainted-nonconforming` with the first exact request digest. A fragment loss
can therefore cause only whole-message unavailability/retry under a fresh
privacy-message ID, never partial target-visible reassembly.

The taint is monotone and keyed by `(context, interval)`, not policy
generation, and is retained through the maximum evidence horizon. The volume
ledger is stricter: it is keyed by the theorem's client-global
`linkabilityScopeId`, so a new wall-clock interval, room, public context,
route, policy, process, account login, or restart cannot reset cumulative
linkable volume. A new volume epoch is permitted only after exact
mechanism-specific evidence proves the old and new epochs unlinkable against
all observations in scope; otherwise the old counter continues. Reaching a
volume cap makes SP1 unavailable until such a boundary exists—it does not
silently weaken the claim.

A policy, profile, mechanism, or floor change cannot create a clean sibling
record or reset prewarm. Any disabled-floor period, profile change, unaccounted
egress, or nonconforming exposure in the evaluated interval taints it;
re-enabling SP1 cannot be positive until a new, wholly prewarmed interval
completes. A live/incomplete interval reports `warming` internally and can
produce only a non-positive public state. If the floor-history, egress
transaction, prewarm, privacy mechanism, volume ledger, or evidence custody
cannot complete within the global caps, the request is not sent and SP1 is
`unknown`. Room policy and remote hints cannot disable or weaken the
vault-global floor.

Conditional on the exact formal model and the currently measured deployment
facts satisfying its assumptions, a current SP1 evaluation claims only that
the modeled adversary's source-identification probability for a
profile-conforming public-store request is at most
`1/k + epsilon`, where `k=anonymitySetLowerBoundK` and
`epsilon=advantageEpsilonNumerator/advantageEpsilonDenominator`. The adversary
may jointly control at most `t=corruptMixingDomainsUpperBoundT` of the exact
measured set containing at least `max(2,t+1)` independently operated mixing
domains, each disjoint from the target store and egress operators, leaving at
least one eligible domain outside that joint view. Domain count alone is not
treated as path safety: the formal bound also consumes the measured
per-layer/operator route-selection mass and complete cumulative linkable
volume. SP1 does not claim entry-ISP/operator anonymity, resistance to a global
passive observer, long-term intersection resistance beyond the volume/model
scope, protection after direct exposure, room anonymity against a capability
holder, or safety against a malicious client endpoint. The empirical
entry/egress-collusion classifier suite is a falsification/deployment check and
performance measurement; failure invalidates SP1, but classifier non-success
alone is not a proof against every adversary.

Security-identifier collections use bytewise equality only. Their persisted,
UI, import, and public-API text forms are the following exact ASCII grammar,
where the suffix is 43-character unpadded canonical base64url decoding to
exactly 32 bytes:

```text
store-ref      = "store.v1."      || Base64urlNoPad(StoreId)
route-ref      = "route.v1."      || Base64urlNoPad(RouteId)
disclosure-ref = "disclosure.v1." || Base64urlNoPad(sourceMetadataDisclosureId)
stable-key-ref = "ed25519.v1."    || Base64urlNoPad(stableEd25519PublicKey)
commitment-ref = "commitment.v1." || Base64urlNoPad(StableIdentityCommitment)
peer-ref       = "peer.v1."       || Base64urlNoPad(LocalPeerIdDigest)
presence-ref   = "presence.v1."   || Base64urlNoPad(OperationId)
```

The parser rejects padding, alternate alphabets, case-folding, extra
components, wrong prefixes/lengths, and noncanonical re-encoding before policy
lookup. A migration-only parser may recognize an explicitly enumerated legacy
form once, decode it to bytes, deduplicate bytewise, and commit only the
canonical ref. Ambiguous or invalid legacy rows become policy-unavailable and
therefore fail closed. `CanonicalBytes32SetV1` is the decoded sorted-unique
form; no security decision compares JavaScript object identity or unchecked
strings.

`LocalPeerIdDigest` is the exact 32-byte hash in the `LocalPeerId` formula in
Section 4.8; the text handle is not hashed a second time. Every public helper
accepting `LocalPeerId` or `PresenceRefV1` runs the same prefix/43-character
decode/re-encode check before lookup. It never case-folds, compares an
unchecked string, or guesses between a legacy UUID and a blind handle.

In the equations below, `roomPolicy`, `connectionPlanner`,
`carrierAssignments`, and `resourcePolicy` are the exact room-local fields of the current
`BlindRoomAccessV4`; `releaseRegistry` is the exact content-addressed registry
selected by this build; `carrierPolicy` and `globalResourcePolicy` are the one
SDK-runtime policies shared by every blind room and tab/worker in the local
vault; capitalized names denote types, not mutable defaults. The two global
policies are each stored once; room access holds a read-only reference, not an
independently mutable copy.

```text
StoreId =
  H("p2party/store-id/v1" || storeIdentityEd25519Key)

DescriptorHash =
  H(
    "p2party/store-descriptor/v1" ||
    Canonical(StoreDescriptorV1 without descriptorSignature)
  )

RouteId =
  H(
    "p2party/store-route/v1" ||
    Canonical(StoreRouteV1 without routeSignature)
  )

StoreDescriptorSignedMessage =
  "p2party/store-descriptor-signature/v1" || DescriptorHash

StoreRouteSignedMessage =
  "p2party/store-route-signature/v1" || RouteId

StoreDescriptorAuthentic(descriptor) =
  descriptor has the one canonical StoreDescriptorV1 encoding
  and descriptor.version == 1
  and descriptor.notBeforeUnixMs < descriptor.notAfterUnixMs
  and its supported-profile/chain-start projection is complete and canonical
  and descriptorSignature verifies StoreDescriptorSignedMessage under
      descriptor.storeIdentityEd25519Key

StoreRouteAuthentic(route, descriptor) =
  StoreDescriptorAuthentic(descriptor)
  and route has the one canonical StoreRouteV1 encoding
  and route.version == 1
  and route.notBeforeUnixMs < route.notAfterUnixMs
  and route.storeId == StoreId(descriptor)
  and route.descriptorHash == DescriptorHash(descriptor)
  and routeSignature verifies StoreRouteSignedMessage under
      descriptor.storeIdentityEd25519Key

StoreDescriptorActiveAt(descriptor, atUnixMs) =
  StoreDescriptorAuthentic(descriptor)
  and descriptor.notBeforeUnixMs <= atUnixMs < descriptor.notAfterUnixMs

StoreRouteActiveAt(route, descriptor, atUnixMs) =
  StoreRouteAuthentic(route, descriptor)
  and route.notBeforeUnixMs <= atUnixMs < route.notAfterUnixMs

RoomLogicalWindowStartUnixMs(roomPolicy, logicalWindow) =
  checkedMultiply(logicalWindow, roomPolicy.protocolLimits.logicalWindowMs)

RoomLogicalWindowEndUnixMsExclusive(roomPolicy, logicalWindow) =
  RoomLogicalWindowStartUnixMs(
    roomPolicy,
    checkedAdd(logicalWindow, 1)
  )

CanonicalRouteOrigin(route) =
  the exact canonical origin returned by route.routeFamily's release-registry
  parser, or null for a registered originless route family

RouteRequiresExplicitPrivateAuthorization(route) =
  the same registered parser classifies the locator as loopback, link-local,
  private/LAN, local-name, file, Unix-socket, or equivalent local authority

ResolvedNetworkRouteAllowed(route, resolvedEndpoints) =
  RouteId(route) is in carrierPolicy.explicitlyAllowedPrivateRouteIds
  or every endpoint in the nonempty resolvedEndpoints is globally routable
      after canonical IPv4, IPv6, IPv4-mapped-IPv6, special-use, link-local,
      loopback, private, carrier-grade-NAT, and cloud-metadata classification

FrontendDenied(store, route) =
  StoreId(store) is in carrierPolicy.deniedStoreIds
  or RouteId(route) is in carrierPolicy.deniedRouteIds
  or route.routeFamily is in carrierPolicy.deniedRouteFamilies
  or (
    CanonicalRouteOrigin(route) != null
    and CanonicalRouteOrigin(route) is in carrierPolicy.deniedOrigins
  )

FrontendAllowed(store, route) =
  (
    carrierPolicy.allowedStoreIds == "any-compatible"
    or StoreId(store) is in carrierPolicy.allowedStoreIds
  )
  and route.routeFamily resolves to exactly one installed, locally authorized
      RouteFamilyRegistryEntryV1
  and that entry.sourceMetadataDisclosureId is in
      carrierPolicy.acceptedSourceMetadataDisclosureIds
  and (
    the route family can enforce ResolvedNetworkRouteAllowed below
    or RouteId(route) is a release-shipped/configured route
    or RouteId(route) is in
      carrierPolicy.authorizedBrowserDirectRouteIds
  )
  and (
    not RouteRequiresExplicitPrivateAuthorization(route)
    or RouteId(route) is in
      carrierPolicy.explicitlyAllowedPrivateRouteIds
  )

RemoteHintActivationAuthorized(store, route) =
  store/route has a live release-shipped, configured, or explicit-local source
  or (
    its only live source is one or more remote STORE_HINT operations
    and carrierPolicy.autoActivateRemoteHints == "preauthorized-only"
    and carrierPolicy.allowedStoreIds != "any-compatible"
    and StoreId(store) is in carrierPolicy.allowedStoreIds
    and RouteId(route) is in carrierPolicy.preauthorizedRemoteRouteIds
  )

DiscoveredStoreCatalog(
  roomAccess: BlindRoomAccessV4,
  capturedReferenceWindow
) =
    valid roomAccess.bootstrapStoreHints
  ∪ explicit local additions
  ∪ valid STORE_HINT source records whose logical hint lease is live at
      capturedReferenceWindow

RequiredRoomRetentionWindows(roomPolicy) =
  max(
    checkedMultiply(
      2,
      roomPolicy.protocolLimits.operationRetentionWindows
    ),
    roomPolicy.protocolLimits.pairControlRetentionWindows,
    if roomPolicy.admissionFloor.mode == "authority-grant"
      then checkedAdd(
        roomPolicy.admissionFloor.maxAuthorityCredentialLifetimeWindows,
        roomPolicy.protocolLimits.maxFutureLogicalWindows
      )
      else 0
  )

// The doubled transient term is inert dependency custody, not authorization
// or semantic lifetime. A presence can be referenced by a full-lifetime LEAVE
// created at the end of that presence's own transient interval.

RoomProfileCompatible(roomPolicy, plannerPolicy, resourcePolicy, profile) =
  profile passes every DeliveryProfileV1 structural/capacity equation
  and checked(
        profile.deliveryWindowMs * profile.carrierRetentionWindows
      )
      >= checked(
        (
          RequiredRoomRetentionWindows(roomPolicy)
          + 1
          + 2 * roomPolicy.protocolLimits.maxClockSkewWindows
        )
        * roomPolicy.protocolLimits.logicalWindowMs
      )
  and each operation payload class permitted by roomPolicy.operationCodec
      maps to exactly one profile size class whose fixedCarrierObjectBytes
      fit the exact canonical operation, carrier framing, padding, and tag
  and the release schedule simulator accepts this room/planner/resource
      bound under the profile's exact role slots and missed-opportunity bound

StoreProfileCompatible(store, profile) =
  StoreDescriptorAuthentic(store)
  and DeliveryProfileHash(profile)
      is in store.supportedDeliveryProfileHashes
  and store.compatibilityHash ==
      releaseRegistry.storeCompatibilityHash
  and profile.publicStoreProtocol == 1
  and profile.admissionScheme == 1
  and store.allocationIssuerPublicKeyDer is the exact valid scheme-1 key

ActiveDeliveryProfiles(room: BlindRoomAccessV4) =
  TakeByLocalPriorityAndDeliveryProfileHash(
    profiles in room.deliveryProfiles where
      RoomProfileCompatible(
        room.roomPolicy,
        room.connectionPlanner,
        room.resourcePolicy,
        profile
      ),
    room.resourcePolicy.maxActiveDeliveryProfilesPerRoom
  )

PublicCarrierContextId =
  H(
    "p2party/public-carrier-context/v1" ||
    StoreId ||
    DeliveryProfileHash
  )

PublicRouteInstanceId =
  H(
    "p2party/public-route-instance/v1" ||
    PublicCarrierContextId ||
    RouteId
  )

DerivedAuthenticatedSessionContextId(contactContext) =
  H(
    "p2party/contact-session-context/v1" ||
    U16BE(contactContext.adapterProtocolId) ||
    U16BE(contactContext.sessionAuthenticationSuiteId) ||
    contactContext.sessionAuthenticationTranscriptHash ||
    U32BE(contactContext.bearerMtuBytes) ||
    contactContext.bearerConstraintHash
  )

ContactCarrierInstanceId(contactContext, deliveryProfileHash) =
  H(
    "p2party/contact-carrier-instance/v1" ||
    U16BE(contactContext.adapterProtocolId) ||
    contactContext.authenticatedSessionContextId ||
    deliveryProfileHash
  )

PortableCarrierInstanceId(
  adapterProtocolId: Uint16,
  bundleCarrierContextId: Bytes32,
  custodyPathContextId: Bytes32,
  deliveryProfileHash: Bytes32
) =
  H(
    "p2party/portable-carrier-instance/v1" ||
    U16BE(adapterProtocolId) ||
    bundleCarrierContextId ||
    custodyPathContextId ||
    deliveryProfileHash
  )

UNKNOWN_CUSTODY_PATH =
  H("p2party/unknown-custody-path/v1")

ContactAdapterCompatible(
  adapter,
  contactContext,
  profile,
  resourcePolicy,
  globalResourcePolicy
) =
  adapter's exact ContactAdapterRegistryEntryV1 is present in the sorted
      registry committed by releaseRegistry.transportAdapterRegistryHash
  and contactContext is the adapter's current live authenticated session
  and contactContext.adapterProtocolId == adapter.adapterProtocolId
  and contactContext.sessionAuthenticationSuiteId ==
      adapter.sessionAuthenticationSuiteId
  and contactContext.authenticatedSessionContextId ==
      DerivedAuthenticatedSessionContextId(contactContext)
  and DeliveryProfileHash(profile) is in
      adapter.supportedDeliveryProfileHashes
  and every profile fixed object fits adapter.maxReassembledObjectBytes
  and the checked fragmentation simulation for
      contactContext.bearerMtuBytes uses at most
      adapter.maxFragmentsPerObject
  and contactContext.bearerMtuBytes is at least
      adapter.minimumUsableBearerMtuBytes
  and the registered inventory/batch codecs bound every count and byte by
      the adapter entry, resourcePolicy, and globalResourcePolicy
  and the exact fragmentation codec, session-authentication suite,
      bounded clock-snapshot method, and
      contactContext.bearerConstraintHash all match the registry entry

ActivePublicCarrierContextCandidates(
  room: BlindRoomAccessV4,
  activationAtUnixMs
) =
  {
    { kind: "public-store", store, profile,
      carrierContextId: PublicCarrierContextId } |
      store is in ClientPublicCarrierCatalog
      and StoreDescriptorActiveAt(store, activationAtUnixMs)
      and profile in ActiveDeliveryProfiles(room)
      and PublicCarrierContextId is not in
          room.carrierAssignments.disabledCarrierContextIds
      and profile.roomSlotsPerClient >=
          globalResourcePolicy.maxInitializedBlindRooms
      and StoreProfileCompatible(store, profile)
      and at least one route in
          ClientPublicCarrierCatalogRoutes belongs to store,
          satisfies StoreRouteActiveAt(route, store, activationAtUnixMs),
          has a live authorized source,
          satisfies RemoteHintActivationAuthorized(store, route),
          satisfies FrontendAllowed(store, route),
          and does not satisfy FrontendDenied(store, route)
  }

FrontendContactAdapterAllowed(adapter) =
  (
    carrierPolicy.allowedContactAdapterProtocolIds == "any-compatible"
    or adapter.adapterProtocolId is in
      carrierPolicy.allowedContactAdapterProtocolIds
  )
  and adapter.adapterProtocolId is not in
      carrierPolicy.deniedContactAdapterProtocolIds
  and adapter.sourceMetadataDisclosureId is in
      carrierPolicy.acceptedSourceMetadataDisclosureIds

ActiveContactCarrierContextCandidates(room: BlindRoomAccessV4) =
  {
    { kind: "contact", adapter, contactContext, profile,
      carrierContextId:
        ContactCarrierInstanceId(
          contactContext,
          DeliveryProfileHash(profile)
        ) } |
      profile in ActiveDeliveryProfiles(room)
      and adapter is installed and locally authorized
      and FrontendContactAdapterAllowed(adapter)
      and contactContext is supplied by that adapter from the bounded
          current authenticated-context set
      and the adapter's attempt-window, concurrent-context, and byte caps
          and the client-global contact-context count/byte caps hold
      and ContactAdapterCompatible(
            adapter,
            contactContext,
            profile,
            room.resourcePolicy,
            globalResourcePolicy
          )
  }

capturedRoomReferenceWindows =
  canonical sorted unique tuples
    (LocalRoomId(room), roomReferenceWindow)
  for every initialized blind room in the one client-global catalog snapshot

ClientPublicCarrierCatalogCandidates(capturedRoomReferenceWindows) =
  valid release-shipped default bootstrap descriptors/routes
  ∪ explicit local additions
  ∪ union of DiscoveredStoreCatalog(
      room,
      capturedRoomReferenceWindows[LocalRoomId(room)]
    ) across initialized blind rooms

ClientPublicCarrierCatalogAggregates(
  capturedRoomReferenceWindows,
  activationAtUnixMs
) =
  AggregateByStoreId(
    ClientPublicCarrierCatalogCandidates(capturedRoomReferenceWindows)
  ) where:
    exactly one aggregate consumes one store-count slot;
    maximumGeneration is the maximum valid signed descriptor generation;
    retainedDescriptorState at maximumGeneration is exactly one of:
      { kind: "singleton", descriptorHash } or
      { kind: "fork", proofHashes: [h0, h1] };
    h0 and h1 are the bytewise-lowest two distinct valid DescriptorHash values
      ever observed at that generation; two hashes are sufficient proof, and
      later branches never grow the tombstone;
    an already retained fork at maximumGeneration remains a fork even when
      one source expires;
    a strictly higher generation replaces the prior state, initially as a
      singleton, and a second distinct hash converts it to the fixed fork
      proof;
    activeDescriptorHash is the singleton hash, or null for a fork;
    descriptorStateOrderKey is:
      the active DescriptorHash when non-null, otherwise
      H(
        "p2party/store-descriptor-state-order/v1" ||
        U64BE(maximumGeneration) ||
        Canonical(retainedDescriptorState.proofHashes) ||
        Byte(0x01)
      );
    the aggregate retains and charges its exact high-water/fork tombstone;
    each admitted store slot reserves the release-bounded maximum encoded
      descriptor-state size, so an authenticated higher generation or second
      fork hash replaces that state atomically without retaining a lower
      generation as active;
    route candidates are exact routes for activeDescriptorHash satisfying
      StoreRouteActiveAt(route, activeDescriptor, activationAtUnixMs) and
      having at least one live source, and are empty when it is null

CatalogRouteActivationUsable(
  storeAggregate,
  route,
  activationAtUnixMs
) =
  StoreDescriptorActiveAt(
    storeAggregate.activeDescriptor,
    activationAtUnixMs
  )
  and StoreRouteActiveAt(
    route,
    storeAggregate.activeDescriptor,
    activationAtUnixMs
  )
  and route has a live authorized source
  and RemoteHintActivationAuthorized(storeAggregate, route)
  and FrontendAllowed(storeAggregate, route)
  and not FrontendDenied(storeAggregate, route)

RemoteCatalogActivationRank(storeAggregate, activationAtUnixMs) =
  0 when at least one route for the aggregate satisfies
      CatalogRouteActivationUsable(
        storeAggregate,
        route,
        activationAtUnixMs
      )
  1 otherwise // discovery-only UI evidence

CatalogStoreSourceRank(storeAggregate) =
  0 when retained/pinned by release-shipped/configured provenance
  1 otherwise when retained/pinned by an explicit local addition
  2 otherwise // remote-only or high-water-only, including expired sources

CatalogStoreOrder(storeAggregate, activationAtUnixMs) =
  (
    CatalogStoreSourceRank,
    RemoteCatalogActivationRank(storeAggregate, activationAtUnixMs),
    preferred store index,
    descending maximumGeneration,
    StoreId,
    descriptorStateOrderKey
  )

CatalogStorePinned(storeAggregate) =
  the aggregate has a live release-shipped/configured or explicit-local source
  or supplies a prewarmed context
  or supplied a previously active context at the reconciliation snapshot

MandatoryCatalogRoutes(storeAggregate, activationAtUnixMs) =
  every previously selected route for that aggregate that still satisfies
    CatalogRouteActivationUsable(storeAggregate, route, activationAtUnixMs)
  ∪, when CatalogStorePinned and that set is empty but a usable route exists,
    the first route satisfying
      CatalogRouteActivationUsable(storeAggregate, route, activationAtUnixMs)
    in (RoutePriority, RouteId) order

CatalogRouteRetentionRank(storeAggregate, route, activationAtUnixMs) =
  0 when route is in
      MandatoryCatalogRoutes(storeAggregate, activationAtUnixMs)
  1 when CatalogRouteActivationUsable(
      storeAggregate,
      route,
      activationAtUnixMs
    )
  2 otherwise // live discovery evidence only; denied/expired routes are absent

CatalogRouteOrder(storeAggregate, route, activationAtUnixMs) =
  (
    CatalogRouteRetentionRank(storeAggregate, route, activationAtUnixMs),
    zero-based ordinal within that aggregate's
      (CatalogRouteRetentionRank, RoutePriority, RouteId) route order,
    CatalogStoreOrder(storeAggregate, activationAtUnixMs),
    RoutePriority,
    RouteId
  )

ReconcileClientPublicCarrierCatalog(
  capturedRoomReferenceWindows,
  activationAtUnixMs
) -> (ClientPublicCarrierCatalog, ClientPublicCarrierCatalogRoutes) =
  PersistedBoundedCatalogAndRouteReconcile(
    ClientPublicCarrierCatalogAggregates(
      capturedRoomReferenceWindows,
      activationAtUnixMs
    ),
    stage1AtomicPinnedFootprints =
      for every CatalogStorePinned aggregate, its exact
      descriptor/high-water/fork-tombstone bytes plus
      MandatoryCatalogRoutes(storeAggregate, activationAtUnixMs)
      and their exact bytes,
    stage2AtomicRemoteFootprints =
      each remaining aggregate plus its first active non-denied route in
      CatalogRouteOrder(storeAggregate, route, activationAtUnixMs), admitted
      as one indivisible footprint in
      CatalogStoreOrder(storeAggregate, activationAtUnixMs),
    stage3OptionalRoutes =
      every remaining active non-denied route in
      CatalogRouteOrder(storeAggregate, route, activationAtUnixMs),
    caps =
      (
        globalResourcePolicy.maxPublicCatalogStores,
        globalResourcePolicy.maxPublicCatalogRoutes,
        globalResourcePolicy.maxPublicCatalogBytes
      )
  )

ClientActiveRouteInstances(context, activationAtUnixMs) =
  TakeByLocalPriorityAndRouteId(
    {
      { route, routeInstanceId: PublicRouteInstanceId } |
      route is in ClientPublicCarrierCatalogRoutes
      and belongs to context.store in ClientPublicCarrierCatalog
      and StoreDescriptorActiveAt(context.store, activationAtUnixMs)
      and StoreRouteActiveAt(route, context.store, activationAtUnixMs)
      and route has a live authorized source
      and RemoteHintActivationAuthorized(context.store, route)
      and FrontendAllowed(context.store, route)
      and not FrontendDenied(context.store, route)
    },
    globalResourcePolicy.maxRoutesPerPublicCarrierContext
  )

ClientPrewarmedPublicCarrierContexts(activationAtUnixMs) =
  {
    { kind: "public-store", store, profile,
      carrierContextId: PublicCarrierContextId } |
      PublicCarrierContextId is in
        carrierPolicy.prewarmedPublicCarrierContextIds
      and store/profile resolve uniquely in ClientPublicCarrierCatalog
      and profile passes every DeliveryProfileV1 structural/capacity equation
      and profile.roomSlotsPerClient >=
          globalResourcePolicy.maxInitializedBlindRooms
      and StoreProfileCompatible(store, profile)
      and StoreDescriptorActiveAt(store, activationAtUnixMs)
      and at least one route in
          ClientPublicCarrierCatalogRoutes belongs to store,
          satisfies StoreRouteActiveAt(route, store, activationAtUnixMs),
          has a live authorized source,
          satisfies RemoteHintActivationAuthorized(store, route),
          satisfies FrontendAllowed(store, route),
          and does not satisfy FrontendDenied(store, route)
  }

ClientActivePublicCarrierContextCandidates(activationAtUnixMs) =
  UniqueByCarrierContextId(
    ClientPrewarmedPublicCarrierContexts(activationAtUnixMs)
    ∪ union of ActivePublicCarrierContextCandidates(
        room,
        activationAtUnixMs
      )
        across all locally initialized rooms
  )

ClientPublicContextPriority(context) =
  (
    PublicContextPriority(context),
    context.carrierContextId
  )

ClientPublicContextSourceRank(context) =
  0 when context is release-shipped, configured, explicitly local,
      or prewarmed by frontend policy
  1 when its only live source is a remote STORE_HINT

ClientActivePublicCarrierContexts(activationAtUnixMs) =
  PersistedStickyReconcile(
    previousActive =
      still-compatible, still-allowed, explicitly active-at-
        activationAtUnixMs members of the prior persisted set
      excluding explicit local removals,
    fillCandidates =
      ClientActivePublicCarrierContextCandidates(activationAtUnixMs)
        minus previousActive,
    fillOrder =
      (
        ClientPublicContextSourceRank,
        ClientPublicContextPriority
      ),
    cap = globalResourcePolicy.maxActivePublicCarrierContexts
  )

RoomAdmissibleCarrierContextCandidates(room, activationAtUnixMs) =
  {
    context |
    context is in (
      ActiveContactCarrierContextCandidates(room)
      ∪ {
          publicContext |
          publicContext is in ActivePublicCarrierContextCandidates(
            room,
            activationAtUnixMs
          )
          and publicContext.carrierContextId is in
            CarrierContextIds(
              ClientActivePublicCarrierContexts(activationAtUnixMs)
            )
        }
    )
    and context.carrierContextId is not in
      room.carrierAssignments.disabledCarrierContextIds
  }

RoomCarrierSourceRank(room, context) =
  0 when context was previously active for room,
      is a locally authorized contact, or is a release-shipped,
      configured, explicitly local, or frontend-prewarmed public context
  1 when a public context's only live source is a remote STORE_HINT

ActiveCarrierContexts(room, activationAtUnixMs) =
  PersistedStickyRoomCarrierReconcile(
    previousActive =
      prior room-set entries whose carrierContextId is still in
        CarrierContextIds(
          RoomAdmissibleCarrierContextCandidates(room, activationAtUnixMs)
        ),
    fillCandidates =
      RoomAdmissibleCarrierContextCandidates(room, activationAtUnixMs)
        minus previousActive,
    fillOrder =
      (
        RoomCarrierSourceRank(room, context),
        CarrierContextPriority(context)
      ),
    cap = room.resourcePolicy.maxActiveCarriersPerRoom
  )

ActiveStores(room, activationAtUnixMs) =
  UniqueStoreIds(
    public-store entries in ActiveCarrierContexts(room, activationAtUnixMs)
  )
```

`U16BE` and `U32BE` above are the schema's exact unsigned big-endian
encodings; out-of-range or JavaScript-unsafe inputs fail before hashing.
`AuthenticatedContactContextV1` is emitted only after the registered
session-authentication transcript succeeds and is invalid as soon as that
live session ends or rolls generation. Reusing a transcript hash with a
different adapter, suite, MTU, or bearer constraint therefore derives a
different ID and fails the exact current-context check.
`bundleCarrierContextId`, `custodyPathContextId`,
`deliveryProfileHash`, and `UNKNOWN_CUSTODY_PATH` are all exactly `Bytes32`;
raw strings or variably encoded adapter IDs never enter either
carrier-instance preimage.

For a peer-hosted public store, the store-identity signing key and allocation
issuer private key are generated independently of and persisted separately from
every endpoint stable-identity, room capability, room-author, admission,
presence, pair, protocol-v4, PQ, and contact-session key. No cross-role KDF or
key import is permitted, and byte equality between a store public key and any
co-located endpoint public key fails provisioning and regenerates the store
key. Store route locators and route credentials name only the store service;
they are never copied from, derived from, or interpreted as endpoint transport
candidates. This key/route separation prevents the public store protocol from
creating a cryptographic or protocol-carried peer-equality/room-equality handle
merely because roles share a device. A shared host, locator, route, timing
trace, source address, account, physical observer, or device compromise may
still correlate the roles. Co-location remains one compromise/operator domain
in assurance.

The co-located endpoint uses its store through the same authorized
`PublicStoreOperationCarrierAdapter`, client-global scheduler, allocation,
fixed append/read trace, and validation boundary as a remote endpoint. An
in-process optimization may remove serialization or loopback syscalls only
when its store-bound transcript, cadence, and every advertised
bearer/source-observation class remain equivalent; otherwise it is a separately
registered route whose unsupported access/source claims are downgraded. It
shall not inject logical operations directly into store persistence or the
client reducer, read private store internals, skip
allocation/dummy/full-scan work, or label a bypassing path as conforming L2,
public-store custody, SP1, or R2 evidence.

Each preferred array is ordered, contains unique canonical identifiers, and
is the local priority SSOT. A value's priority is its zero-based array index or
`UINT32_MAX` when absent. Every selection is a total order:

```text
DeliveryProfilePriority = (preferred profile index, DeliveryProfileHash)
PublicContextPriority   = (preferred store index, StoreId,
                           DeliveryProfilePriority)
RoutePriority           = (preferred route index, RouteId)
ContactPriority         = (preferred adapter index, adapterProtocolId,
                           DeliveryProfilePriority, carrierContextId)

CarrierKindByte =
  public-store 0x00 | contact 0x01

CarrierContextPriority(context) =
  if context.kind == "public-store":
    (
      CarrierKindByte(public-store),
      PublicContextPriority(context),
      context.carrierContextId
    )
  else:
    (
      CarrierKindByte(contact),
      ContactPriority(context),
      context.carrierContextId
    )
```

The closed kind byte makes the public/contact union one lexicographic total
order under the per-room cap; implementations never compare different tuple
shapes. It is only a deterministic saturation rule. It does not claim that a
public path is more independent or trustworthy than a contact path.

`FrontendCarrierPolicyV1` is vault/client-global because one
`PublicCarrierContextId` has one fixed append/read trace and route cycle shared
by all rooms. Two rooms cannot give that shared trace contradictory route,
origin, or store permissions. `policyGeneration` increases monotonically; one
transaction persists the complete new policy and recomputes every affected
scheduler before any request under that generation. Denial wins and stops the
shared context before another wrap is emitted. Room-local state decides only
whether that room is assigned to an otherwise globally permitted context.
Peer allow/deny and authority admission remain independently room-local
frontend policy. Source-metadata consent has the same SSOT: changing the
accepted disclosure-ID set is a policy-generation change and deactivates every
route/contact whose exact registry disclosure ID is no longer accepted before
another network or discovery action.

`RoomCarrierAssignmentPolicyV1` is that room-local delivery SSOT.
`policyGeneration` increases monotonically, and an exact decoded
`PublicCarrierContextId` or `ContactCarrierInstanceId` in
`disabledCarrierContextIds` makes the context inadmissible for only that room.
The frontend atomically persists the replacement object and recomputes
`ActiveCarrierContexts(room, activationAtUnixMs)` from a newly captured
explicit activation time before the next room-slot substitution or import.
This object does not authorize a globally denied route, create a scheduler, or
alter another room. Alternate textual encodings, unknown-length identifiers,
and legacy aliases fail before its canonical set is stored.

`prewarmedPublicCarrierContextIds` is also client-global. A shipped default or
explicit frontend action can place an exact context ID in this set before any
room is initialized. After validation and global-cap admission, the scheduler
starts at the next complete delivery-window boundary, assigns no room slots,
and emits the ordinary all-dummy append grid and full scans. It continues with
zero assigned rooms until an explicit policy change removes it. Adding or
removing a room slot inside an already evidenced prewarmed context does not
start, stop, or resize the trace. Before its first complete successful window,
the context reports `on-demand-public-scan`/prewarming and makes no
join/leave-indistinguishability claim. Prewarming hides room activity from the
store only within the stated fixed schedule; it does not hide application
startup or the fact that this client uses that public context.

Every `TakeBy...` sorts by the named complete tuple before taking the cap; no
map iteration, discovery time, health response, or arrival order is a
tie-break. Fresh room fills use `CarrierContextPriority` after source rank.
When any client-global public-catalog count/route/byte cap is reached,
release-shipped/configured descriptors and explicit local additions are
retained first, and every store/descriptor candidate uses the complete
`CatalogStoreOrder`; eviction follows the reverse order and never removes an
installed/configured store without a user action. A remote hint can fill a
free catalog slot but cannot evict any of those locally sourced entries. An
explicit addition that would make locally retained entries alone exceed the
cap fails before persistence or network access and asks the user to remove
one; it does not evict by recency.
Within remote-only capacity, an activation-authorized rank-0 entry may replace
a discovery-only rank-1 entry; a rank-1 hint can never occupy capacity needed
by a present rank-0 entry. The rank is recomputed on each relevant policy
generation, so disallowed hints observed first cannot eclipse a later exact
preauthorization. Neither rank performs network access.

Catalog admission is one atomic count/route/byte reconciliation. It first
preflights every pinned descriptor/high-water/fork tombstone together with all
still-usable previously selected routes, or the first usable route when the
pinned entry otherwise has none. If that mandatory base does not fit all three
caps, a user/policy/addition transition leaves the complete old catalog and
policy unchanged; objective expiry/denial merely removes the now-ineligible
route and reports the affected context unavailable. It next admits a
remote-only store only when the descriptor/tombstone plus its first live
non-denied route fit as one footprint. Only then may remaining routes consume
slack in `CatalogRouteOrder`. Thus descriptor-only churn and denied,
expired, or discovery-only routes cannot consume the byte/route capacity
needed by a pinned usable route. One `StoreId` consumes exactly one store
slot, including when its maximum generation is forked; the
`descriptorStateOrderKey` gives that fork a unique total-order key. These are
the sole cross-store fairness/order rules; no map iteration or unspecified
“best route” participates.

`PersistedStickyReconcile` retains each previously active context while it
remains compatible, permitted, and live; retained contexts keep their
persisted scheduler identity and fill ordinal. It then fills only vacant
global-cap positions in the complete source/priority order shown above and
persists the new set at one fenced delivery-window boundary. A remote hint,
including one with a grind-generated lower `StoreId`, never displaces a live
active context.
Replacement requires an explicit local removal/replacement action or an
objective expiry, deny, registry incompatibility, or loss of every authorized
route. Tightening a cap below the retained count leaves the old policy
unchanged, as does any replacement that breaks a profile/cross-field invariant.
These transition rules, rather than arrival time or health, are the
client-global active-context SSOT.

`deniedOrigins` contains only canonical origins produced by registered route
parsers; noncanonical entries fail policy validation. `deniedRouteIds`
contains exact decoded IDs of complete signed route records. `FrontendDenied`
is evaluated after `FrontendAllowed` and always wins, including when the same
route is private-authorized, browser-authorized, preauthorized for a remote
hint, or otherwise allowed. Neither parser
classification nor an origin allow can create private-route authorization:
only the exact locally persisted `RouteId` in
`explicitlyAllowedPrivateRouteIds` can do that.

For a native or reviewed proxy/OHTTP DNS route family, authorization is also
enforced at resolution and connection time, not only while parsing the signed
locator. That adapter resolves through its policy-enforcing resolver,
canonicalizes all answers, requires `ResolvedNetworkRouteAllowed`, pins the
chosen address to the authenticated origin for that connection, and repeats
the check on every new connection. A mixed public/private answer, DNS
rebinding, IPv4-mapped special address, proxy-discovered destination, or
cloud-metadata endpoint is rejected unless that exact `RouteId` was explicitly
authorized for private access.

Ordinary browser `fetch` cannot inspect or pin DNS answers. A browser-direct
HTTPS route is therefore eligible only when its exact `RouteId` is
release-shipped/configured or was explicitly authorized by the local user and
persisted in `authorizedBrowserDirectRouteIds`; a remotely advertised route
can never broaden that set or trigger a permission prompt. Deployments needing
remote route autoactivation in a browser use a reviewed gateway/OHTTP family
that enforces the resolver rule. Redirects remain forbidden in every family.
Remote bytes can neither cause an authorization prompt nor add any route to a
private or browser-direct allow set.

`ClientActivePublicCarrierContexts` is the local custody-domain scheduling
SSOT after the client-global cap. Only then does
`PersistedStickyRoomCarrierReconcile` apply the room cap to locally authorized
contacts plus that room's globally admitted public candidates. It retains a
still-valid room context before filling vacancies, so a remote hint cannot
displace an already working/default/local path at either cap layer. Explicit
room deactivation means atomically adding the exact context ID to
`room.carrierAssignments.disabledCarrierContextIds`; that action or objective
expiry/deny/incompatibility releases its active-carrier-cap membership
immediately. A private public-scheduler room ordinal may remain reserved under
the bounded outstanding-wrap rule below, but it carries only dummies.
`ActiveStores`, active route instances, publication, reconciliation, backfill,
`LocalDeliveryStateV1`, and assurance are derived only from this final set; an
eligible-but-inactive context is never reported or contacted as active.

The same client-global catalog and
`ClientActiveRouteInstances(context, activationAtUnixMs)` are the sole
route-cycle inputs for a
shared public scheduler. A route learned from a valid live hint in one room is
merely another locally authorized route to the same store/profile; it cannot
create a room-specific cycle. Differing room resource policies never alter the
route count. The global route cap and frontend carrier-policy generation are
applied once before the scheduler emits anything.

One durable scheduler, issuance request, allocation request, allocation key,
lease, append grid, route cycle, and full-chunk read cursor exists per
`PublicCarrierContextId`, shared by every local room and tab/worker using that
exact store/profile and vault. Creating a second room or browser tab in the
same context cannot create a second allocation or scan. Cross-context
scheduler ownership uses a persisted fenced lease/transaction; the specific
browser or native coordination API is not normative, but a contender that
cannot prove exclusive current ownership emits nothing and reports the context
unavailable. Candidate contexts outside the client-global cap remain
discovered/inactive; every affected room reports that path unavailable and may
become `partitioned`. Selection uses only the total priority tuple above,
never discovery/response time or room traffic. An explicit user action that
would require a new public context beyond the cap fails before persistence or
network access and asks the user to deactivate one; it never silently evicts a
working context. Joining more than `maxInitializedBlindRooms` likewise fails
before capability-vault or carrier mutation.

The scheduler persists a private bijection from at most
`roomSlotsPerClient` active `LocalRoomId` values to local room-slot ordinals.
Public profile activation requires
`roomSlotsPerClient >= maxInitializedBlindRooms`, so this mapping is total for
every initialized local room that uses the context. A deleted/deactivated room
whose ordinal is retained for a published or outstanding exact wrap continues
to count against `maxInitializedBlindRooms` until every such assignment
releases; a new join cannot reuse that capacity early. An explicit local
discard may atomically record loss/terminal status for all outstanding wraps,
release the assignments, and degrade consistency, but silent reuse is
forbidden. There is no second room-selection planner or unreported “active
without a slot” state. A join above the resulting live-plus-retained room cap
fails before room/vault/carrier mutation, and tightening the global cap follows
the already specified validate-or-leave-old-policy rule.
It assigns the lowest free ordinal before the room can enqueue a carrier wrap,
retains the assignment through every published/outstanding exact wrap, and
releases it only after the room is inactive and its scheduled work is
terminal/expired. Slot maps, `LocalRoomId`, and slot-to-room meaning never cross
a carrier. Restart restores the map before scheduling; loss/corruption fails
the context closed into recovery rather than allocating another trace. Empty
ordinals still send dummies. Different public contexts may assign a room a
different local ordinal without changing room or operation identity.

At every append slot, a mapped room substitutes a real object only when its
current `RoomCarrierAssignmentPolicyV1.policyGeneration` still admits that
exact context and the context remains globally active. Otherwise the slot
emits the ordinary dummy immediately. The private ordinal and any already
derived exact wrap may remain retained until terminal/expiry or explicit
discard, but no pre-disable wrap is published and re-enabling the context
requires the then-current generation check.

Authenticity and current activation are deliberately separate predicates.
Core reduction, historical checkpoint verification, and `STORE_HINT`
validation call the timeless `StoreDescriptorAuthentic`/
`StoreRouteAuthentic` predicates and then apply the exact signed-operation or
historical interval they are validating. A network adapter calls
`StoreDescriptorActiveAt`/`StoreRouteActiveAt` with its explicit transaction
time before every activation or connection. No core reducer reads an ambient
clock, and an expired route does not retroactively invalidate a signed
historical hint or checkpoint that it covered.

The descriptor signature proves possession of
`storeIdentityEd25519Key` and signs the complete
`StoreDescriptorSignedMessage`. Every route signature signs
`StoreRouteSignedMessage` with that key and thereby binds the exact `StoreId`,
`DescriptorHash`, locator, parameters, route family, and lease. `StoreId` is stable across compatible
descriptor/route rotation; changed descriptor facts get a new
`DescriptorHash` and monotonic generation. Routes are mutable leased delivery
facts; neither descriptor nor route is part of room identity.
For scheme 1, `allocationIssuerPublicKeyDer` is the exact canonical
RSASSA-PSS SPKI required by RFC 9578 token type `0x0002`; its truncated token
key ID is derived exactly by that RFC. A noncanonical key, unsupported PSS
parameters, an unsorted, duplicate, unbounded, or unsupported
`supportedDeliveryProfileHashes` list, or issuer-key change without a higher
descriptor generation invalidates activation. The signed list contains exact
content hashes, so `DeliveryProfileV1` remains the sole source of retention,
object-size, admission, and schedule semantics rather than copying partial
profile facts into the descriptor. `checkpointChainStarts` contains exactly
one entry for each supported profile in the same bytewise profile-hash order.
For one `StoreId` and profile its start window is immutable across descriptor
generations; changing it is signed store equivocation and makes that
store/profile inert. A clean accountability-chain reset therefore requires a
new store identity and `StoreId`, not a generation bump.

For a public store, `(StoreId, DeliveryProfileHash)` is the one wrapping,
allocation, idempotency, and scheduled-work domain. Routes are alternative
network paths to that same domain. One persisted allocation request, append
request, and exact carrier envelope is replayed byte-for-byte across route
attempts; a route never causes independent wrapping, another allocation, or
another public object. At each scheduled opportunity the client tries exactly
one route chosen by the persisted canonical-`RouteId` cycle over the
`RoutePriority`-capped active set, independent of room,
payload kind, and prior response. Failure has no immediate fallback request;
the next profile-scheduled opportunity advances the cycle. A
`PublicRouteInstanceId` scopes path health and assurance evidence, while
`PublicCarrierContextId` scopes cryptography and store idempotency. Contact
carriers use their one authenticated session context for both roles.

For each `StoreId` retained in the bounded catalog, its entry includes and
charges the maximum valid signed `descriptorGeneration`, active/forked hash
state, and high-water tombstone bytes against the catalog count/byte caps.
A lower generation cannot reactivate while that entry is retained, including
after a newer descriptor or hint expires. At the maximum generation,
one `DescriptorHash` is active; two different valid hashes mark that generation
forked and make the store inert until one strictly higher valid generation is
observed. For the one active descriptor hash, independently signed `RouteId`
values from bootstrap, local, and `STORE_HINT` sources are unioned
only in an activation projection where
`StoreRouteActiveAt(route, descriptor, activationAtUnixMs)` holds.
Exact historical descriptor bytes referenced by a retained checkpoint,
receipt, or fault proof are separately charged to that store/profile's
accountability partition through the evidence horizon; they are not replaced
by the active catalog descriptor.
Hint operations are lease instances: refreshing an equal descriptor with a
different route subset or expiry neither forks the descriptor nor overwrites
another route. An individual route is usable only while both its own absolute
lease and at least one authorized source for it are live.

Release-shipped/configured, explicit-local, prewarmed, and currently active
entries pin their high-water state and cannot be evicted by remote churn.
An inactive remote-only entry, including its tombstone, is evicted only by the
same reverse `RemoteCatalogActivationRank`/priority order as the full catalog;
there is no separate unbounded StoreId log. If that StoreId is later
rediscovered, it is treated as newly discovered/inactive and must pass current
signature, exact activation authorization, descriptor, route, and policy
validation again. The no-generation-rollback claim is therefore scoped to
retained or locally pinned entries, not all StoreIds ever advertised by an
adversary.

`compatibilityHash` is:

```text
H(
  "p2party/store-compatibility/v1" ||
  canonicalBinarySchemaHash ||
  publicHttpProtocolHash ||
  allocationSchemeRegistryHash ||
  Canonical(store protocol limits, overwrite/error/lease/skew rules)
)
```

It commits to the public store protocol, canonical request and response
codecs, supported admission-proof verifier, overwrite prohibition, error
semantics, maximum descriptor/route lease milliseconds, and accepted clock
skew. It is not a marketing version string. Descriptor and route leases
use absolute Unix milliseconds because one signed object may serve delivery
profiles with different window durations; an ingress or logical window is
never inferred for them.

The frontend treats a locator received from another peer as untrusted data.
Automatic activation is permitted only when all of the following hold:

1. the exact descriptor and route signatures verify;
2. the compatibility hash is implemented;
3. `RoomProfileCompatible` and `StoreProfileCompatible` both hold for the
   exact delivery-profile hash;
4. the adapter and route family were installed and locally authorized;
5. a remote-only source passes `RemoteHintActivationAuthorized`, including
   exact preauthorized store and route IDs;
6. no store, exact route, route family, or parsed origin matches a local deny rule;
7. parsing performs no DNS lookup, URL fetch, credential use, redirect, or
   private-network access before authorization;
8. the route-family registry entry's exact
   `sourceMetadataDisclosureId` is in
   `FrontendCarrierPolicyV1.acceptedSourceMetadataDisclosureIds`.
9. when the global floor is SP1, the route-family entry's
   `sourcePrivacyMechanismVersionHash` matches the selected profile and the complete
   prewarm/evidence/exposure transaction can pass `SP1Conforms`; otherwise the
   route remains unavailable.

An explicit user action that adds a parsed store descriptor is local
authorization for that exact descriptor and selected routes. It is not
authorization for later redirects or arbitrary route hints signed by room
members. Loopback, link-local, RFC 1918/4193, `.local`, Unix-socket, file, and
equivalent LAN/private locators received remotely are always inert. A user may
explicitly authorize an exact private `RouteId`; that local fact is never
created or broadened by a room operation.

`autoActivateRemoteHints="preauthorized-only"` means automatic activation is
allowed only when the existing frontend policy names the exact `StoreId` in
its finite allow set and the exact `RouteId` in
`preauthorizedRemoteRouteIds`, in addition to permitting the route family,
origin, adapter, and source-metadata disclosure. `"any-compatible"` is
discovery permission, not remote activation preauthorization.
`autoActivateRemoteHints="never"` keeps every remote-only hint inactive even
when it is otherwise valid/allowed. Otherwise the hint remains
discovered/inactive until a user changes local policy. Thus adding one server is one action for that user,
immediately enables bridge/backfill, and can become automatic for peers whose
prior frontend policy already permits it; no peer's denylist is overridden.

Each active public carrier context binds exactly one store and delivery
profile and has one or more bounded alternative route instances; each contact
context binds one installed adapter, profile, and authenticated session
context. Portable-bundle import is episodic and uses its own byte/pass cap
rather than an active slot. Logical validation never depends on which context
or route delivered an operation. Catalog, route, profile, and active-set caps
are enforced before network access.
Candidates beyond a cap are retained only if the bounded catalog has room;
given the same local authorization facts, selection and eviction sort by
explicit local priority, descriptor generation, and `StoreId`, never arrival
or server response time.

Adding a store performs:

```text
validate and persist local authorization
→ begin fixed/public reconciliation
→ derive carrier-separated envelopes
→ backfill every locally retained valid operation
  through fixed scheduled slots only
→ publish a bounded leased STORE_HINT in each active room's existing slot
```

No room ID, pair ID, PQ epoch, or operation ID changes. Peers that later
receive the hint may activate it under their own policy. If no old path or
physical contact delivers the hint, they cannot discover it magically.

A local removal stops future contact and publication. Remote hints expire
rather than creating a distributed delete protocol. Logical operations
obtained from the removed store remain in the validated local set.

### 4.3 Public windows, buckets, and immutable chunks

```ts
type PublicBucketV1 = {
  deliveryProfileHash: Bytes32;
  ingressWindow: bigint;
  sizeClass: number;
};

type PublicChunkBodyV1 = {
  version: 1;
  bucket: PublicBucketV1;
  chunkIndex: bigint;
  previousChunkHash: Bytes32;
  fixedObjects: readonly Uint8Array[];
};

type PublicChunkV1 = PublicChunkBodyV1 & {
  storeSignature: Bytes64;
};

type PublicStoreCheckpointBodyV1 = {
  version: 1;
  storeId: Bytes32;
  descriptorHash: Bytes32;
  deliveryProfileHash: Bytes32;
  ingressWindow: bigint;
  chainStartIngressWindow: bigint;
  previousCheckpointHash: Bytes32;
  finalizedChunkCount: number;
  finalizedChunkRoot: Bytes32;
};

type PublicStoreCheckpointV1 = PublicStoreCheckpointBodyV1 & {
  storeSignature: Bytes64;
};

type PublicCheckpointChunkLeafV1 = {
  sizeClass: number;
  chunkIndex: bigint;
  publicChunkHash: Bytes32;
};

type PublicCheckpointChunkInclusionProofV1 = {
  version: 1;
  checkpointHash: Bytes32;
  leaf: PublicCheckpointChunkLeafV1;
  leafIndex: number;
  siblingHashes: readonly Bytes32[];
};

type PublicCheckpointConflictProofV1 = {
  version: 1;
  firstDescriptor: StoreDescriptorV1;
  first: PublicStoreCheckpointV1;
  secondDescriptor: StoreDescriptorV1;
  second: PublicStoreCheckpointV1;
};

type PublicCheckpointChainBreachProofV1 = {
  version: 1;
  previousDescriptor: StoreDescriptorV1;
  previous: PublicStoreCheckpointV1;
  nextDescriptor: StoreDescriptorV1;
  next: PublicStoreCheckpointV1;
};

type PublicCheckpointChainStartConflictProofV1 = {
  version: 1;
  firstDescriptor: StoreDescriptorV1;
  secondDescriptor: StoreDescriptorV1;
  deliveryProfileHash: Bytes32;
};

// Protected local anchor, not a carrier-visible or room-synchronized object.
type PinnedPublicCheckpointHeadV1 = {
  version: 1;
  storeId: Bytes32;
  deliveryProfileHash: Bytes32;
  ingressWindow: bigint;
  descriptorHash: Bytes32;
  checkpointHash: Bytes32;
};

type AllocationTokenIssueRequestV1 = {
  version: 1;
  storeId: Bytes32;
  deliveryProfileHash: Bytes32;
  ingressWindow: bigint;
  privacyPassTokenRequest: Uint8Array;
};

type AllocationTokenChallengeV1 = {
  version: 1;
  storeId: Bytes32;
  deliveryProfileHash: Bytes32;
  ingressWindow: bigint;
};

type AllocationTokenIssueResultBodyV1 =
  | {
      version: 1;
      kind: "issued";
      requestHash: Bytes32;
      privacyPassTokenResponse: Uint8Array;
    }
  | {
      version: 1;
      kind: "status";
      requestHash: Bytes32;
      status: "quota-denied" | "invalid-request" | "issuer-unavailable";
      fixedErrorPadding: Uint8Array;
    };

type AllocationTokenIssueResultV1 = AllocationTokenIssueResultBodyV1 & {
  storeSignature: Bytes64;
};

type PublicAllocationRequestV1 = {
  version: 1;
  deliveryProfileHash: Bytes32;
  ingressWindow: bigint;
  allocationEd25519PublicKey: Bytes32;
  privacyPassToken: Uint8Array;
};

type PublicAllocationLeaseBodyV1 = {
  version: 1;
  storeId: Bytes32;
  deliveryProfileHash: Bytes32;
  ingressWindow: bigint;
  requestHash: Bytes32;
  allocationOrdinal: number;
  allocationEd25519PublicKey: Bytes32;
};

type PublicAllocationLeaseV1 = PublicAllocationLeaseBodyV1 & {
  storeSignature: Bytes64;
};

type PublicAllocationStatusBodyV1 = {
  version: 1;
  storeId: Bytes32;
  deliveryProfileHash: Bytes32;
  ingressWindow: bigint;
  requestHash: Bytes32;
  status:
    "invalid-token" | "token-spent" | "capacity-exhausted" | "window-closed";
  fixedErrorPadding: Uint8Array;
};

type PublicAllocationResultV1 =
  | { kind: "allocated"; lease: PublicAllocationLeaseV1 }
  | ({ kind: "status"; value: PublicAllocationStatusBodyV1 } & {
      storeSignature: Bytes64;
    });

type PublicAppendAdmissionV1 = {
  version: 1;
  lease: PublicAllocationLeaseV1;
  objectOrdinalWithinAllocation: number;
  allocationSignature: Bytes64;
};

type PublicAppendRequestV1 = {
  version: 1;
  bucket: PublicBucketV1;
  exactFixedObject: Uint8Array;
  // null has one fixed all-zero wire representation and is cover-only.
  admission: PublicAppendAdmissionV1 | null;
};
```

```text
IngressWindow(profile, now) =
  floor(now / profile.deliveryWindowMs)

RoomLogicalWindow(roomPolicy, now) =
  floor(now / roomPolicy.protocolLimits.logicalWindowMs)

PublicBucketId =
  H("p2party/public-bucket/v1" || Canonical(PublicBucketV1))

PublicChunkSigningHash =
  H(
    "p2party/public-chunk/signing/v1" ||
    Canonical(PublicChunkBodyV1)
  )

PublicChunkHash =
  H(
    "p2party/public-chunk/signed/v1" ||
    Canonical(PublicChunkV1)
  )

PublicCheckpointChunkLeafInput(leaf) =
  "p2party/public-checkpoint-chunk-leaf/v1" ||
  Canonical(leaf)

PublicStoreCheckpointSigningHash =
  H(
    "p2party/public-store-checkpoint/signing/v1" ||
    Canonical(PublicStoreCheckpointBodyV1)
  )

PublicStoreCheckpointHash =
  H(
    "p2party/public-store-checkpoint/signed/v1" ||
    Canonical(PublicStoreCheckpointV1)
  )

PublicCheckpointConflictProofDigest =
  H(
    "p2party/public-checkpoint-conflict-proof/v1" ||
    Canonical(PublicCheckpointConflictProofV1)
  )

PublicCheckpointChainBreachProofDigest =
  H(
    "p2party/public-checkpoint-chain-breach-proof/v1" ||
    Canonical(PublicCheckpointChainBreachProofV1)
  )

PublicCheckpointChainStartConflictProofDigest =
  H(
    "p2party/public-checkpoint-chain-start-conflict-proof/v1" ||
    Canonical(PublicCheckpointChainStartConflictProofV1)
  )

AllocationTokenIssueRequestHash =
  H(
    "p2party/allocation-token-issue-request/v1" ||
    Canonical(AllocationTokenIssueRequestV1)
  )

AllocationTokenIssueResultSignedMessage =
  "p2party/allocation-token-issue-result-signature/v1" ||
  H(Canonical(AllocationTokenIssueResultBodyV1))

PublicAllocationRequestHash =
  H(
    "p2party/public-allocation-request/v1" ||
    Canonical(PublicAllocationRequestV1)
  )

PublicAllocationLeaseSignedMessage =
  "p2party/public-allocation-lease-signature/v1" ||
  H(Canonical(PublicAllocationLeaseBodyV1))

PublicAllocationStatusSignedMessage =
  "p2party/public-allocation-status-signature/v1" ||
  H(Canonical(PublicAllocationStatusBodyV1))

MaxClockSkewWindows(roomPolicy) =
  roomPolicy.protocolLimits.maxClockSkewWindows

RequiredCarrierRetentionMs(roomPolicy) =
  checkedMultiply(
    checkedAdd(
      RequiredRoomRetentionWindows(roomPolicy),
      1,
      checkedMultiply(2, roomPolicy.protocolLimits.maxClockSkewWindows)
    ),
    roomPolicy.protocolLimits.logicalWindowMs
  )

profile.deliveryWindowMs
  * profile.carrierRetentionWindows
  >= RequiredCarrierRetentionMs(roomPolicy)
```

All rooms in one delivery profile and public window use the same bucket.
`PublicBucketV1` contains no room-derived value. A profile defines exactly one
carrier size class for each operation payload class. Every pre-warmed client
follows the fixed schedule for both classes. A real object replaces a
scheduled dummy; it never adds an object.

`RoomLogicalWindow` is operation-codec time and is immutable room policy.
`IngressWindow` is carrier geometry. They are never substituted for one
another, so two delivery profiles with different cadences can carry the same
operation without changing its validity or reducer result. A profile is
compatible with a room only if its carrier retention covers the room's maximum
semantic/replay horizon as above and its object classes fit every operation
class the room permits.

The `sizeClasses` array is sorted by unique `id`; for codec v1 its
`operationPayloadClass` values are exactly `[0, 1]`, each once. Class selection
is therefore the total function
`CarrierSizeClassForPayloadClass(payloadClass)`, not a sender preference.
Every other class's scheduled position is a dummy. For every size class, the
profile is valid only if:

```text
IngressWindowStart(w) =
  checkedMultiply(w, deliveryWindowMs)

scheduledObjects =
  cohortAllocationsPerWindow
  * roomSlotsPerClient
  * appendSchedule.length

chunkCapacity =
  publicChunksPerWindow
  * publicChunkObjectCount

scheduledObjects <= chunkCapacity
and publicChunksPerWindow is the minimum integer satisfying that inequality.

0 <= tokenIssueOffsetMs < deliveryWindowMs
0 <= tokenIssueResponseBudgetMs
tokenIssueOffsetMs
  + tokenIssueResponseBudgetMs
  + maxScheduleSkewMs
  < allocationRequestOffsetMs
0 <= allocationRequestOffsetMs < deliveryWindowMs
0 <= allocationResponseBudgetMs
allocationRequestOffsetMs
  + allocationResponseBudgetMs
  + maxScheduleSkewMs
  < deliveryWindowMs
allocationRequestOffsetMs
  + allocationResponseBudgetMs
  + maxScheduleSkewMs
  < min(all appendSchedule.offsetMs)
0 <= every appendSchedule.offsetMs
every appendSchedule.offsetMs + maxScheduleSkewMs
  < chunkFinalizationOffsetMs
0 < chunkFinalizationOffsetMs < deliveryWindowMs
chunkFinalizationOffsetMs + maxScheduleSkewMs
  < deliveryWindowMs + publicReadOffsetMs
0 <= publicReadOffsetMs < deliveryWindowMs
publicReadLagWindows == 1
appendSchedule is sorted by offsetMs and offsets are unique
every role is a closed value above
maxConsecutiveMissedAppendOpportunities is a non-negative safe integer
0 < maxAssuranceEvidenceAgeMs

count(identity-bootstrap) >= 1 when operationPayloadClass == 0
count(safety-control) >= 1
count(state-replication) >= 1
```

All arithmetic is checked before profile activation; overflow invalidates the
profile. In this section, “per active public carrier context” means one entry
of the client-global `ClientActivePublicCarrierContexts` set, never one
room-local projection. At
`IngressWindowStart(w) + tokenIssueOffsetMs`, a resident client
makes exactly one scheme-1 blind-token issuance request for `w+1` per active
public carrier context. At
`IngressWindowStart(w) + allocationRequestOffsetMs`, it makes exactly one
allocation request for `w+1` per active public carrier context.
Allocation completion after the pinned response budget is a failed allocation;
it cannot race the first append of the next window. At each class's
append-schedule offset the client makes exactly one real-or-dummy
append for every local room slot. At `publicReadOffsetMs` the scheduler
pre-reserves and dispatches the checkpoint GET for window `w-1` followed by
every chunk GET in canonical request-initiation order, without awaiting any
response. Responses may complete in any order; checkpoint silence, failure,
or a never-resolving body never cancels or delays a chunk request. The
one-window read lag removes a same-window store/client clock race. There is no
event-driven same-window retry. A failed allocation,
append, or read is retried only in the next profile-scheduled opportunity and
degrades availability.

All events due to one `PublicCarrierContextId` are serialized by one canonical
key, including when offsets are equal:

```text
PublicScheduledEventKey =
  (
    absoluteScheduledUnixMs,
    eventKindByte, // issuance=0, allocation=1, append=2, checkpoint=3, read=4
    sizeClassIdOrZero,
    roomSlotOrdinalOrZero,
    appendEntryOrdinalOrChunkIndexOrZero
  )

PublicScheduledEventId =
  H(
    "p2party/public-scheduled-event/v1" ||
    PublicCarrierContextId ||
    U64BE(schedulerWindow) ||
    Canonical(PublicScheduledEventKey)
  )
```

`schedulerWindow=w` is always the window whose
`IngressWindowStart(w)` anchors `absoluteScheduledUnixMs`. Issuance and
allocation events in scheduler window `w` target ingress window `w+1`, append
events target `w`, and checkpoint/read events target `w-1`; that target mapping never
changes the event-ID window. Negative targets are not scheduled. This
definition makes otherwise identical restart calculations byte-identical
across the five event kinds.

For append, the entry ordinal is its index in the profile's canonical
size-class schedule and the room-slot ordinal is exact; for reads, the last
component is the chunk index. A checkpoint read uses zero for every
inapplicable component; its lower event-kind byte orders it before all chunk
reads at the same offset. Inapplicable components are zero and the kind keeps
tuple forms disjoint. The scheduler processes due keys in this total order. In
the same transaction, before dispatch, it records the exact event ID
as attempted, advances the route cursor to the attempted `RouteId`, and, when
SP1 is selected, commits the exact conforming or tainted
`PublicContextSourceExposureV1`; a crash
therefore produces a visible missed event, not an arrival-order-dependent
second request.

Attempt state is one replace-only object per `PublicCarrierContextId`, not an
append log or unbounded set:

```ts
type PublicSchedulerAttemptCursorV1 = {
  // Monotone activation/recovery floor.
  notBeforeSchedulerWindow: bigint;
  lastAttempted: {
    schedulerWindow: bigint;
    eventKey: PublicScheduledEventKey;
    eventId: Bytes32;
  } | null;
};
```

Before a due event can dispatch, its scheduler window must be at least
`notBeforeSchedulerWindow` and its `(schedulerWindow, eventKey)` must be
strictly greater than `lastAttempted`, when non-null. The pre-dispatch
transaction replaces `lastAttempted` with the exact coordinate and ID. Every
lower or equal coordinate is permanently attempted/missed. Moving to a later
window replaces the earlier coordinate, so the persisted attempt-state count
is exactly one fixed-size object for an initialized context and restart cannot
make it grow or dispatch an old event.

On first activation, or recovery after the scheduler was not continuously
resident across any due boundary, one transaction sets
`notBeforeSchedulerWindow` to the next complete scheduler window, never lower
than its prior value. `lastAttempted` may become null only inside that new
floor epoch. Every earlier scheduled event is durably classified as missed by
the floor; it is not dispatched and does not advance the route cursor.
Corrupt/missing cursor recovery uses the same next-complete-window rule and
suspends fixed-access assurance. A bounded reconciliation scan may fetch old
retained public chunks, but it is separate from `PublicScheduledEventId` and
never issues late token, allocation, append, or scheduled-read events.

The route cursor is `{ lastAttemptedRouteId: Bytes32 | null,
carrierPolicyGeneration }`, never an array index. From the current active
route set sorted by raw `RouteId`, the next route is the least ID strictly
greater than `lastAttemptedRouteId`, wrapping to the least ID; null chooses the
least. Adding a route inserts it into that order. Removing, denying, or
expiring a route cannot retarget an index: the next event takes the canonical
successor of the persisted last ID. If no route is active, the event is
durably missed without changing `lastAttemptedRouteId`. Policy replacement,
event-cursor mutation, route selection, and request reservation are fenced by
the one scheduler lease.

Every accepted `FrontendCarrierPolicyV1` replacement atomically stores the new
`carrierPolicyGeneration` in this cursor while preserving
`lastAttemptedRouteId`. The first event under the new generation computes the
canonical successor of that preserved raw ID in the new active set, wrapping
when needed. `lastAttemptedRouteId=null` is permitted only for a never-attempted
context or after explicit recovery from a proven empty/corrupt route cursor;
resetting the scheduler event floor does not reset it. A policy change, route
removal, ordinary context restart, or catch-up never resets it.

The fixed-access claim is suspended whenever measured carrier clock skew plus
request jitter exceeds `maxScheduleSkewMs`; the client does not compensate
with a data-dependent retry. It is also suspended for the affected evidence
interval on the first missed scheduled allocation, append, checkpoint read, or
full-chunk read;
`maxConsecutiveMissedAppendOpportunities` is a causal-liveness tolerance, not
permission to retain a fixed-trace privacy label. Catch-up is
`on-demand-public-scan`, and fresh `fixed-cohort-scan` evidence begins only
after one complete subsequent window executes every scheduled event.

A suspended or new client catches up old retained windows through the bounded
public reconciliation path and reports `on-demand-public-scan` until caught
up; it does not claim a resident fixed-access trace during catch-up. Scheduled
cover resumes only at its persisted next-complete-window floor, with no burst
or compression of missed work. Once caught up and after one complete scheduled
window it returns to the exact schedule. A later profile version may add fixed
retry offsets, but v1 has no adaptive retry.

The append schedule is also the outbox-service SSOT. At each reserved slot,
the client first resolves that context's persisted room-slot mapping. An
unassigned ordinal emits a dummy. An assigned ordinal considers only due
operations from its exact mapped `LocalRoomId` whose
`operationPayloadClass` maps to that exact size class and whose work maps to
that role. Every wrap intent carries exactly one local:

```ts
type ServiceWorkKindV1 =
  | "REPLICATION_OR_BACKFILL"
  | "PRESENCE"
  | "LEAVE"
  | "STORE_HINT"
  | "ADMISSION_REVOKE"
  | PairStepKindV1;
```

For live non-pair work it equals the exact outer operation kind. For a locally
created live `PAIR_STEP`, it equals the authenticated sender-known
`PairStepBodyV1.kind` and is persisted atomically with those exact operation
bytes. Every imported copy, later replica, and backfill uses
`REPLICATION_OR_BACKFILL` without inspecting pair plaintext. A mismatch at
local creation fails the transaction; this metadata never crosses a carrier
or affects `CoreRoomState`. One total classifier is used by public scheduling,
the release simulator, outbox reserves, and L3:

```text
OperationServiceRole(intent) =
  if intent.serviceWorkKind == "REPLICATION_OR_BACKFILL":
    "state-replication"
  else if intent.serviceWorkKind is IDENTITY_ACCEPT or IDENTITY_HELLO:
    "identity-bootstrap"
  else if intent.serviceWorkKind is PRESENCE or STORE_HINT:
    "state-replication"
  else:
    "safety-control"

IdentitySubpriority(intent) =
  0 when intent.serviceWorkKind == "IDENTITY_ACCEPT"
  1 when intent.serviceWorkKind == "IDENTITY_HELLO"

OperationServiceOrder(intent) =
  if OperationServiceRole(intent) == "identity-bootstrap":
    (IdentitySubpriority, semanticExpiryLogicalWindow, OperationId)
  else:
    (semanticExpiryLogicalWindow, OperationId)
```

Thus live leave/revocation, transport/v4, PQ/barrier, and terminal-checkpoint
work is safety control; a later replica or backfill of any kind is state
replication. Within identity work every pending ACCEPT sorts before every new
HELLO, then expiry and ID decide. The client selects the first exact compatible
item under this tuple, persists its wrap/slot, and otherwise sends a dummy.
Unselected work remains in the bounded outbox for the next same-role slot
until expiry; no backlog creates an extra append. Pair-attempt capacity and
per-role throughput are derived solely from schedule entries, not duplicated
fields. Profile activation runs the release's deterministic schedule simulator
over the worst simultaneous set of identity, transport, v4, PQ, leave,
revocation, and replication chains permitted by `maxProvisionalEdges`,
`maxActiveStableEdges`, the author quota, room slots, and every shared role
queue—not merely one causal chain in isolation. With up to
`maxConsecutiveMissedAppendOpportunities` consecutive missed opportunities per
required transition, the next compatible role/class slot must occur before
that transition's earliest semantic expiry. Otherwise the profile is
incompatible. The simulator, longest-chain inputs, and boundary vectors are
release artifacts; there is no informal “declared loss” input.

Local outbox custody follows the same role order. State-replication intents
cannot consume either reserved byte region; identity-bootstrap cannot consume
the safety-control region. A safety-control enqueue may transactionally discard
and later rederive an unpublished lower-role _carrier wrap intent_, and an
identity-bootstrap enqueue may do the same to state-replication intent. It
never deletes a canonical logical operation, a published exact wrap, or an
accepted pair response. The two reserves are non-negative, their sum is at
most `maxOutboxBytesPerRoom`, and each fits the largest compatible exact wrap.
If a safety response still cannot commit, that edge stalls and availability
degrades; the client does not publish before persistence or borrow an extra
slot.

`admissionScheme=1` is the sole v1 allocation scheme. It reuses the RFC 9578
Section 6 public Blind-RSA algorithms and keeps the inner `TokenRequest`,
`TokenResponse`, and `Token` bytes unchanged, using token type `0x0002` and
RSABSSA-SHA384-PSS-Deterministic from RFC 9578/RFC 9474 with the DER issuer key
in `StoreDescriptorV1`. The enclosing `AllocationTokenIssueRequestV1` and
fixed p2party HTTP response mapping, challenge application, and
`PublicAllocationRequestV1` redemption are custom. This is not wire
conformance to the RFC 9577 HTTP authentication scheme. The opaque `challenge`
input supplied to the RFC 9578 issuance algorithm is exactly:

```text
Canonical(
  AllocationTokenChallengeV1{
    version=1,
    storeId=StoreId,
    deliveryProfileHash=DeliveryProfileHash,
    ingressWindow=ingressWindow
  }
)
```

The Phase-0 allocation registry freezes the complete RFC `TokenRequest`,
`TokenResponse`, and `Token` bytes; the canonical RSASSA-PSS SPKI parameters;
the full `token_key_id = SHA256(DER SPKI)` and least-significant-byte request
truncation; challenge encoding; fixed p2party HTTP padding; redemption
verification; spent-token namespace; key rotation; and imported RFC test
vectors. No metadata extension is permitted in scheme 1. Truncated key IDs of
keys accepted concurrently by one store are unique. A higher-generation
descriptor may rotate the key only at a delivery-window boundary; the store
continues to verify already issued tokens for their exact target window under
the prior key through that window's allocation close.

The outer `storeId`, `deliveryProfileHash`, and `ingressWindow` on an issuance
request are fixed schedule/routing hints. Because the challenge and token input
are blinded, the issuer cannot verify during issuance that those outer values
match the hidden challenge and no quota/fairness claim relies on such a check.
At redemption the store recomputes the exact canonical challenge from its own
`StoreId` and the allocation request's profile/window, requires the token's
`challenge_digest` to equal its SHA-256 digest, verifies the complete token
under `Token.token_key_id`, and only then commits `SpentTokenId`.

At the fixed token-issuance slot, the client prepares one fresh 32-byte token
nonce for `w+1`, blinds the exact challenge-bound input, and sends one
`AllocationTokenIssueRequestV1`. An operator may return the fixed
`quota-denied` result under a local abuse policy, but that policy is outside
v0.4 conformance/assurance, receives no room or stable application identity,
and establishes no fairness or Sybil claim; the cryptographic issuer does not
learn the blinded token input. At the later allocation slot, the client
finalizes and redeems the token exactly once, alongside one fresh ephemeral
allocation public key. The store atomically commits the exact `SpentTokenId` and
`PublicAllocationRequestHash`, assigns the lowest free
`allocationOrdinal`, and signs `PublicAllocationLeaseBodyV1`, including that
request hash. It admits at most `cohortAllocationsPerWindow` leases.

Both scheduled POSTs are transport-replay safe without an attacker-sized
cache. For issuance, only a successful `issued` result mutates quota and
atomically persists
`{AllocationTokenIssueRequestHash, exact signed issued result}`. Successful
records are bounded by `cohortAllocationsPerWindow`; an exact duplicate on any
route or after restart returns those byte-identical bytes without consuming
quota twice. `quota-denied`, `invalid-request`, and `issuer-unavailable` are
canonical fixed-shape stateless responses for the current request/state and
create no replay row or forever byte-identity promise.

Allocation first validates the token without persistence. Only when the token
is valid and capacity is available does one transaction persist
`{SpentTokenId, PublicAllocationRequestHash, exact signed allocated result}`
with the ordinal/capacity mutation. Exact duplicate returns the byte-identical
allocated result without another mutation; reuse of that `SpentTokenId` with a
different request hash returns the fixed signed `token-spent` status.
`invalid-token`, preexisting `token-spent`, `capacity-exhausted`, and
`window-closed` responses do not create another replay row.

Successful issuance/allocation replay records are count/byte bounded by the
profile's public allocation geometry and retained only until the target
allocation/append window has irreversibly finalized and can no longer mutate;
chunk retention is separate. Malformed/invalid-token floods therefore allocate
no durable replay state. A conflicting valid store signature for one successful
request hash marks that public context equivocal/inert; client arrival order
never chooses a lease.
These replay rules defend against proxy/transport duplication and store
restart; they do not add a client retry offset. A lost scheduled response
follows the degraded-cover/no-same-window-retry rule below.

The spent-token key committed atomically with allocation is:

```text
SpentTokenId =
  H(
    "p2party/allocation-spent-token/v1" ||
    StoreId ||
    DeliveryProfileHash ||
    U64BE(ingressWindow) ||
    Token.token_key_id ||
    Token.nonce
  )
```

An allocation is a public traffic entitlement, not a room, peer, or stable
account. One lease authorizes the exact ordinals for every local room slot and
size class in one public window. Redemption and every append are linkable
within that allocation/window. Under the RFC assumptions, blind RSA provides
blind-signature transcript unlinkability between issuance and token
presentation; it does not provide source/timing anonymity. Because the same
store observes tightly scheduled issuance and redemption for a per-window
challenge, timing or bearer metadata may collapse the effective anonymity set.
The assurance model therefore reports that observer and makes no stronger
unlinkability claim. Scheme 1 provides one-more-forgery resistance, not Sybil
resistance or fair issuance; global hard capacity remains enforceable, while
malicious quota exhaustion is an explicit availability attack.

V0.4 standardizes no proof-of-work algorithm, difficulty encoding, or work
claim. An implementation-specific puzzle cannot be advertised as v0.4
Sybil resistance and cannot silently alter the fixed request trace. The
post-v0.4 roadmap records the compatible construction: check optional
store-scoped work only while issuing the existing blinded allocation token,
then redeem that same token unchanged. Directly attaching work to room
membership, presence, allocation redemption, or append would either create a
second admission authority or link later activity and is outside this design.

For size class `c`, the append slot mapping is:

```text
allocationOrdinal = admission.lease.allocationOrdinal

q_c =
  roomSlotsPerClient
  * appendSchedule(c).length

0 <= allocationOrdinal < cohortAllocationsPerWindow
0 <= objectOrdinalWithinAllocation < q_c

globalObjectOrdinal =
  allocationOrdinal * q_c + objectOrdinalWithinAllocation

chunkIndex =
  floor(globalObjectOrdinal / publicChunkObjectCount)

objectIndexWithinChunk =
  globalObjectOrdinal mod publicChunkObjectCount

roomSlotOrdinal =
  floor(
    objectOrdinalWithinAllocation /
    appendSchedule(c).length
  )

objectOrdinalWithinRoomSlot =
  objectOrdinalWithinAllocation mod
  appendSchedule(c).length
```

For each append, the ephemeral allocation key signs:

```text
AllocationAppendSignedMessage =
  "p2party/allocation-append-signature/v1" ||
  H(Canonical(PublicAllocationLeaseBodyV1)) ||
  Byte(sizeClass) ||
  U32BE(objectOrdinalWithinAllocation) ||
  H(exactFixedObject)
```

The store verifies its lease signature and the allocation signature, so the
admission verifier binds
`(StoreId, DeliveryProfileHash, ingressWindow, sizeClass,
allocationOrdinal, objectOrdinalWithinAllocation, H(exactFixedObject))`.
Redemption is atomic:
an empty slot binds that exact object hash; the same hash returns
`already-present`; a different hash returns `slot-conflict`; overwrite is
impossible. This conflict is carrier evidence, never a logical-state winner.

If token issuance misses its budget, the scheduled allocation request still
uses the exact request length with a syntactically sized random invalid token.
If allocation is absent or fails, every later scheduled append still sends a
fixed-size `PublicAppendRequestV1` with `admission=null` and a random fixed
object. The store performs the same bounded parse, returns the one fixed-size
`unallocated-cover` result, and discards it; the absent allocation position is
padded at finalization. These requests preserve scheduled count/size but are
distinguishable to the store as degraded cover, so fixed-access assurance is
suspended as already required. No failure creates an extra issuance,
allocation, append, route attempt, or chunk.

At `chunkFinalizationOffsetMs`, the store closes every index, fills all absent
allocation positions and the final partial chunk with random dummy bodies, and
signs exactly `publicChunksPerWindow` full chunks per size class. A read before
the close returns one fixed `not-final` response; a read after the close
returns the full signed chunk for every in-range index, including wholly
absent input. Out-of-range indexes have one fixed signed error. There is no
data-dependent extra chunk, absent-index 404, long poll, or retry stream.

Immediately after every chunk is finalized, the store signs exactly one
`PublicStoreCheckpointV1` for that `(StoreId, DeliveryProfileHash,
ingressWindow)`, including a wholly all-dummy window. The leaf sequence is the
complete profile-fixed sequence sorted by `(sizeClass, chunkIndex)` and has
exactly `sum(sizeClass.publicChunksPerWindow)` entries. Each entry is
`PublicCheckpointChunkLeafInput` for the corresponding signed
`PublicChunkHash`; `finalizedChunkRoot` is the Merkle Tree Hash of that
nonempty sequence using the RFC 9162 Section 2.1 leaf/node domain separation
and recursive algorithm, and `finalizedChunkCount` is its exact fixed count.
The inclusion-path codec and verification algorithm are the same RFC 9162
audit-path construction frozen by the accountability registry; no
implementation-selected Merkle convention is permitted.

Checkpoint structure and local carrier authorization are deliberately
separate. `StructurallyValidCheckpoint(descriptor, checkpoint, profile)` holds
only when the descriptor signature is valid,
`DescriptorHash(descriptor) == checkpoint.descriptorHash`,
`StoreId(descriptor) == checkpoint.storeId`, the descriptor supports the
checkpoint profile and names the identical chain start, the profile-fixed
count/root checks pass, the descriptor interval contains the exact checkpoint
finalization instant, and the checkpoint signature verifies under the
descriptor's stable store key. This portable predicate uses the descriptor
embedded in a read/proof; verifier-local authorization, catalog arrival order,
and “latest descriptor” state are not inputs. A separate local-use predicate
decides whether the frontend may contact that store. Historical verification
retains the exact descriptor bytes; later descriptor expiry or a higher
nonforked generation does not erase already valid evidence.

At the descriptor's `chainStartIngressWindow`, `previousCheckpointHash` is
`ZERO32`. At every later supported window it equals the exact
`PublicStoreCheckpointHash` for the immediately preceding window, including
all-dummy windows. Before the start the store returns the fixed out-of-range
status. Skipping a checkpoint, changing chain start, or signing two different
checkpoint bodies for one profile/window never creates a preferred branch.
`ChainValidSuccessor(previous, next)` requires two structurally valid
checkpoints under their embedded descriptors, identical store/profile/chain
start, adjacent windows, and
`next.previousCheckpointHash == PublicStoreCheckpointHash(previous)`;
structural validity alone does not assert predecessor continuity.
Two structurally valid distinct checkpoints with equal store/profile/window form a
`PublicCheckpointConflictProofV1`; either a broken predecessor or conflict
makes the exact store/profile chain unusable for positive custody/availability
claims until a new `StoreId` is explicitly authorized.
Each embedded descriptor must hash to its adjacent checkpoint's
`descriptorHash`, derive the same `StoreId`/stable store key, and be valid for
that checkpoint's finalization instant. The proof is canonical only when
`PublicStoreCheckpointHash(first)` is bytewise lower than
`PublicStoreCheckpointHash(second)`.
A `PublicCheckpointChainBreachProofV1` instead contains two individually
structurally valid checkpoints for the same store/profile/chain start at
adjacent windows, with
`next.ingressWindow = previous.ingressWindow + 1`, whose
`next.previousCheckpointHash` does not equal
`PublicStoreCheckpointHash(previous)`. Descriptor joins use the same rules.
A missing adjacent checkpoint cannot instantiate this proof.
A `PublicCheckpointChainStartConflictProofV1` verifies only when its two
canonically descriptor-hash-ordered, valid signed descriptors derive the same
`StoreId`, both support the named profile, and name different chain starts.
This fault is permanent for that store/profile; a higher descriptor generation
cannot clear it.

A `PublicCheckpointChunkInclusionProofV1` is valid only when the checkpoint
hash and signature verify, the leaf coordinate is the unique expected
profile-order index, its `publicChunkHash` equals the supplied signed chunk,
the bounded RFC 9162 path recomputes `finalizedChunkRoot`, and the checkpoint
count equals the profile-fixed count. These checkpoints and proofs are public
carrier evidence. They reveal only store/profile/window/class/chunk geometry
and opaque object bytes already public to that cohort; they contain no room,
operation, author, member, recipient, or pair value.

The exact inclusion-coordinate checks are:

```text
chunk.bucket.deliveryProfileHash == checkpoint.deliveryProfileHash
chunk.bucket.ingressWindow == checkpoint.ingressWindow
chunk.bucket.sizeClass == proof.leaf.sizeClass
chunk.chunkIndex == proof.leaf.chunkIndex
proof.leaf.publicChunkHash == PublicChunkHash(chunk)
proof.leafIndex ==
  ProfileChunkOrdinal(profile, chunk.bucket.sizeClass, chunk.chunkIndex)
0 <= proof.leafIndex < checkpoint.finalizedChunkCount
checkpoint.finalizedChunkCount ==
  checkedSum(profile.sizeClasses[].publicChunksPerWindow)
```

The checked sum and `leafIndex` fit their frozen unsigned wire bounds. The
audit path has exactly the RFC 9162 sibling count for `(leafIndex,
finalizedChunkCount)`; missing or extra siblings and every cross-coordinate
relocation are invalid.

Retention is inclusive and has one wire meaning. A finalized bucket with
`ingressWindow = w` remains readable through the end of ingress window
`w + carrierRetentionWindows`. The store may delete it only at or after the
start of `w + carrierRetentionWindows + 1`, using checked arithmetic. Thus a
recovery read at `currentIngressWindow = w + carrierRetentionWindows` still
includes `w`; the next ingress window excludes it. This matches the client's
inclusive lower bound below. `RequiredCarrierRetentionMs` includes the extra
logical window because an operation created at the start of logical window
`x` and valid through `x + RequiredRoomRetentionWindows` spans that many
windows plus its creation window. Delivery/logical-window misalignment and
both clock-skew margins are therefore covered without giving carrier time any
effect on logical validity.

Checkpoint bodies and inclusion paths have the same inclusive
`carrierRetentionWindows` service horizon as their chunks. After older bodies
expire, the store retains one fixed latest checkpoint head and its descriptor
per supported profile; each client retains at most one protected
`PinnedPublicCheckpointHeadV1` per active store/profile under its catalog
caps. Positive continuity starts at that exact pinned head and covers only a
fully available retained successor segment. An offline gap beyond retention
is `unverified-chain-gap`, not blame. A deliberate local trust-on-first-use
anchor may start future accountability after the gap, but cannot certify or
repair the missing history.

The store signs `PublicChunkSigningHash` with the descriptor's Ed25519 key.
`previousChunkHash` is `ZERO32` for chunk zero and otherwise the exact
`PublicChunkHash` of the preceding chunk on that observed branch. Chunks are
immutable after signature. The store shall not mutate, reuse an
index for different bytes, or replace an object. The signature provides cache
integrity and equivocation evidence; it does not make the store's view complete
or authoritative. If a store signs two different chunks for the same bucket
and index, clients retain equivocation evidence and union every independently
valid room operation recovered from every observed branch. Neither the
previous-hash chain, arrival order, nor one branch selects logical state.

Late or backfilled logical operations are wrapped under the current ingress
window and retain their original logical validity interval inside encryption.
An append that misses finalization rolls to an already-reserved position in
the next window; it never reopens a chunk or emits a catch-up burst. If the
next allocation is unavailable or full, the outbox reports bounded
backpressure. Honest liveness is claimed only while the profile capacity,
retention, and reconciliation assumptions hold. This prevents a carrier bucket
from becoming a room clock. A resident fixed-access client reads the exact
one-lag window schedule; only cold start, cursor loss, or recovery scans older
retained windows, under the degraded `on-demand-public-scan` label.

The reference fixed-scan client asks for public chunk indexes, not object IDs.
It retrieves every complete fixed chunk in order. A cursor is merely a cached
public chunk index; losing it may cost a rescan but cannot change correctness.
Targeted `get(objectId)`, room filters, Bloom filters of room objects, and
per-room WebSocket subscriptions do not satisfy `fixed-cohort-scan`.

### 4.4 Canonical authenticated room operation

```ts
type OperationKindV1 =
  "PRESENCE" | "LEAVE" | "PAIR_STEP" | "STORE_HINT" | "ADMISSION_REVOKE";

type OperationLifetimeV1 = "WINDOW_TRANSIENT" | "GRANT_HORIZON" | "PAIR_CAUSAL";

type OperationPayloadClassV1 = 0 | 1;

type AuthenticatedRoomOperationV1 = {
  version: 1;
  roomContextConfirmation: Bytes32;
  logicalWindow: bigint;
  expiresAfterWindow: bigint;
  lifetime: OperationLifetimeV1;

  authorEpochEd25519Key: Bytes32;
  authorSequence: bigint;
  previousAuthorOperationId: Bytes32 | null;

  kind: OperationKindV1;
  semanticSlot: Bytes32;
  dependencies: readonly Bytes32[];
  operationPayloadClass: OperationPayloadClassV1;
  fixedPayload: Uint8Array;
  operationPadding: Uint8Array;
  authorSignature: Bytes64;
};

type DecodedOperationPayloadV1 =
  | { kind: "PRESENCE"; value: PresenceV1 }
  | { kind: "LEAVE"; value: LeaveV1 }
  | { kind: "PAIR_STEP"; value: PairStepEnvelopeV1 }
  | { kind: "STORE_HINT"; value: StoreHintOperationV1 }
  | { kind: "ADMISSION_REVOKE"; value: AdmissionRevokeV1 };
```

The signature input is
`"p2party/room-operation-signature/v1" || Canonical(every preceding field)`;
the length-disjoint domain prefix is part of the signed bytes.
Collections are sorted and unique. `operationPadding` is the sole all-zero
suffix required by the selected class; any other length or byte value is
noncanonical. Operation codec v1 fixes the signed inner length independently
of every carrier:

```text
OPERATION_PAYLOAD_CLASS_BYTES = { 0: 4096, 1: 69632 }
```

The following table is a generated human-readable projection of
`OPERATION_PAYLOAD_CLASS_BYTES`, never a second source of truth:

| Operation payload class | `fixedPayload + operationPadding` bytes | Use                                                   |
| ----------------------- | --------------------------------------- | ----------------------------------------------------- |
| `0`                     | 4,096                                   | presence, leave, hints, revocations, small pair steps |
| `1`                     | 69,632                                  | exact large pair steps, including SDP and v4 controls |

`PRESENCE`, `LEAVE`, `STORE_HINT`, and `ADMISSION_REVOKE` permit only class
0; their closed nested codecs must fit it. `PAIR_STEP` permits classes 0 and

1. The outer operation decoder has enough information to enforce only that
   closed class set, the class-fixed outer length, and canonical
   `PairStepEnvelopeV1` framing. Its SSOT is:

```text
OperationPayloadClassFor(kind, decodedPayload) =
  the numerically smallest class permitted for kind whose frozen codec can
  encode decodedPayload plus its unique required inner/operation padding
```

The sender must use that class and the receiver recomputes it after decoding;
a larger-than-necessary class or a value that fits no permitted class is
noncanonical. The outer calculation above applies directly to every non-pair
kind. `PAIR_STEP` deliberately has a second, post-authentication calculation:

```text
PairOperationPayloadClassFor(
  unpaddedPairPlaintext,
  bootstrapHeaderPresence
) =
  the numerically smallest class whose frozen pair-plaintext target and
  enclosing PairStepEnvelopeV1 fit that exact plaintext/header form
```

Only after `OpenPairStep` authenticates and exposes the pair plaintext does the
receiver strip and validate the unique all-zero `pairPadding`, recompute
`PairOperationPayloadClassFor`, and require it to equal the signed outer
`operationPayloadClass`. It is impossible and forbidden to infer this
minimality from pair ciphertext before AEAD opening. The sender starts with the
exact `PairPlaintextV1` and empty `pairPadding`, selects that class, fills its
unique all-zero `pairPadding`, and encodes the envelope to consume the complete
class with empty `operationPadding`. Section 4.11 derives those target lengths
from the schema rather than restating them. Release vectors prove that the
exact current 65,490-byte v4 frame plus all pair/operation overhead fits payload
class 1. Carrier-specific padding is outside the signed operation.

Operation validation never accepts a caller-assembled
`(RoomContextId, RoomContextConfirmation, RoomPolicyV4)` tuple. The sole local
constructor snapshots the 32-byte capability and canonical policy, derives
`PolicyHash`, `RoomContextId`, and `RoomContextConfirmation`, and returns a
process-private initialized-room context. Rebinding that context to another
explicit reference window preserves the same private room/policy provenance.
Object spread, structured clone, persistence, a changed exposed byte array, or
combining a genuine room ID with another policy does not recreate that
provenance. This is an implementation trust boundary inside the client kernel,
not protection after arbitrary code execution in that kernel.

`logicalWindow` is `RoomLogicalWindow(roomPolicy, authorTime)`, never an
ingress window.
At an explicit `referenceWindow`, active-or-future classification requires,
with checked arithmetic:

```text
logicalWindow
  <= referenceWindow + roomPolicy.protocolLimits.maxFutureLogicalWindows
referenceWindow
  <= expiresAfterWindow + roomPolicy.protocolLimits.maxClockSkewWindows
logicalWindow <= expiresAfterWindow
dependencies.length <= roomPolicy.protocolLimits.maxDependenciesPerOperation
```

Outer authentication and reference classification are separate executable
stages. Canonical shape, room confirmation, class, lifetime, author-chain
fields, semantic-slot framing, and the outer signature are timeless. A newly
received or restored operation may receive the process-private reducer-
candidate provenance after its outer lifetime only when:

```text
referenceWindow <=
  checkedAdd(
    operation.logicalWindow,
    checkedAdd(
      RequiredRoomRetentionWindows(roomPolicy),
      roomPolicy.protocolLimits.maxClockSkewWindows
    )
  )
```

That evidence horizon is checked for every reducer candidate before it enters
the room set, including a currently active candidate. Arithmetic overflow
rejects only that candidate; it cannot abort reduction of other candidates.
An outer-expired candidate is inert unless the deterministic rules below need
it as exact author-prefix, dependency, or pinned-authority fault evidence. It
never becomes active merely because its signature still verifies.

An otherwise valid operation with `logicalWindow > referenceWindow` is held
only in the bounded future-candidate partition. It cannot affect
`CoreRoomState`, admission, presence, store catalogs, pair trials, scheduling,
or any local projection until a later explicit reference window satisfies
`logicalWindow <= referenceWindow`. Future custody is charged to the ordinary
candidate count/byte caps; there is no unbounded quarantine.

For
`WINDOW_TRANSIENT`, `expiresAfterWindow - logicalWindow` is at most
`roomPolicy.protocolLimits.operationRetentionWindows`; for `PAIR_CAUSAL` it is
at most `roomPolicy.protocolLimits.pairControlRetentionWindows`.
`GRANT_HORIZON` is used only by
`ADMISSION_REVOKE` and has the exact future-candidate-plus-credential lifetime
defined below. Its outer expiry is checked at the outer/candidate gate before
the operation may contribute to author quota or fork classification; nested
validation then binds the same value to the authority-signed revoke payload.
Subtraction is checked without unsigned overflow.

```text
RoomContextConfirmation =
  H("p2party/room-confirmation/v1" || RoomContextId)

OperationId =
  H(
    "p2party/room-operation/v1" ||
    Canonical(AuthenticatedRoomOperationV1)
  )
```

`OperationId` is derived only after carrier AEAD and operation validation. It
is never sent to a store as a logical identifier. Dependencies refer to exact
private operation IDs.

`authorEpochEd25519Key` is a fresh rotating operation-authentication key. It
distinguishes and chains operations from one observed presence; it is not a
stable personhood credential. A capability holder can create Sybil authors up
to public capacity and local resource bounds. The sole closed exception is
`ADMISSION_REVOKE`: its outer `authorEpochEd25519Key` must equal the immutable
room-policy-pinned authority key, its chain may contain only revocations, and
the same key verifies the inner authority transcript. The authority is already
public room policy; this deliberate stable author binding prevents an
arbitrary relay author from suppressing a revoke by wrapping it under another
outer key. Valid floors from nonfaulted authority windows reduce by maximum.
An authority author-slot fork, authority-window overquota, or inability to
retain the bounded authority proof/floor set instead makes the sole derived
authority view unavailable and authority admission fail closed as
`policy-unavailable/overcapacity` through the credential horizon; the reducer
may retain old grant facts for audit/recovery but admits none while that view
has `status="unavailable"`.

An author chain is valid when:

1. for each `(authorEpochEd25519Key, logicalWindow)`, sequence zero has a null
   predecessor;
2. every later sequence in that same window increments by one and names the
   exact preceding `OperationId`; chains never cross a window;
3. every operation is canonical, in bounds, correctly signed, and either
   semantically live or valid solely as bounded author-prefix evidence under
   the rule below; and
4. no authenticated different byte string occupies the same
   `(authorEpochEd25519Key, logicalWindow, authorSequence)` slot.

Semantic activity and author-chain evidence are separate. A canonically
authenticated operation from the same author/logical window may prove a later
operation's exact contiguous prefix after its own semantic expiry only when:

```text
prefix.authorSequence < descendant.authorSequence
referenceWindow
  <= descendant.expiresAfterWindow
    + roomPolicy.protocolLimits.maxClockSkewWindows
referenceWindow <=
  checkedAdd(
    prefix.logicalWindow,
    checkedAdd(
      RequiredRoomRetentionWindows(roomPolicy),
      roomPolicy.protocolLimits.maxClockSkewWindows
    )
  )
```

Such a prefix is reauthenticated from its exact signed operation bytes, is
charged to the retained-valid-operation and byte caps, and contributes only
its author key/window/sequence/predecessor/ID/fork evidence. It never re-enters
`activeOperationIds`, presence, leave, hint, admission, pair, or local
projection semantics. Every accepted author-window candidate is therefore
retained as exact prefix evidence through this bounded maximum-descendant
horizon even when no descendant has arrived yet. This permits first delivery
of a live long-horizon pair control after a shorter transient prefix without
resurrecting that prefix.

Candidate selection for a relevant author/window includes every retained
candidate whose sequence is _less than or equal to_ the maximum relevant
sequence. Equality is load-bearing: a short-expiry byte-different branch in
the same author slot as a live branch is still author-fork evidence. Using
only `< maximumSequence` would let the live branch escape the fork after its
sibling's outer expiry.

A live, intrinsically valid `LEAVE` may also require an exact `PRESENCE` from
another logical window after that presence's outer lifetime. The reducer
promotes, as inert dependency evidence, the exact referenced presence, every
retained candidate in its `PresenceSemanticSlot`, and the same-window prefixes
needed to prove each branch. It first rejects a missing reference, wrong outer
kind, wrong author key, noncanonical presence payload, mismatched derived
presence semantic slot, presence not valid at the LEAVE effective window, or a
LEAVE whose outer expiry does not cover the presence's remaining roster
lifetime;
intrinsically invalid or chain-unproven LEAVE payloads cannot promote
unrelated historical evidence. Before any would-be sibling or its author
prefixes enter historical author classification, that sibling must itself
canonically decode as `PRESENCE`, have its core validity interval contained by
its outer interval, remain inside the evidence horizon, and reproduce its
declared semantic slot from its outer author key/window and decoded nonce.
Copying another presence's declared slot therefore promotes nothing. The
promoted operations are reauthenticated from exact signed bytes, remain inside
`RequiredRoomRetentionWindows(roomPolicy)`, and participate only in
author/dependency/semantic-fork proof. They do not re-enter
`activeOperationIds` or the roster. Dependency discovery and author/payload/
chain validation iterate monotonically to a fixed point over the already
bounded candidate set; no network fetch or arrival order occurs inside
`CoreReduce`.

For author quota, a _non-quota candidate_ is a distinct, canonically decoded,
room-opened operation whose outer signature, room confirmation, author key,
logical/future window, fixed class/length, and author slot are valid before
the per-author quota and nested-payload work are applied. The reducer counts
every such candidate for an `(authorEpochEd25519Key, logicalWindow)`. If the
count exceeds
`roomPolicy.protocolLimits.maxOperationsPerAuthorWindow`, that author/window
is `overquota/forked` and
all of its transient state and dependents are excluded, independent of which
operations arrived first. Physical proof needs at most the canonical
lexicographically lowest
`roomPolicy.protocolLimits.maxOperationsPerAuthorWindow + 1` operation IDs;
after overquota is proved, later candidates for that author/window are dropped
before payload work. One author/window emits at most one fault, with this
canonical proof precedence:

1. if overquota, the bytewise-lowest `maxOperationsPerAuthorWindow + 1`
   operation IDs;
2. otherwise, if any sequence slot forks, the bytewise-lowest two operation
   IDs at the numerically lowest forked sequence; or
3. otherwise, for an authority chain containing a non-`ADMISSION_REVOKE`
   operation, the bytewise-lowest offending operation ID.

Thus simultaneous violations cannot change output according to discovery or
validation order. If that author is the policy-pinned authority, the sole
derived authority view is unavailable for every authority-gated decision whose
reference window is no later than the checked sum of the fault window,
`roomPolicy.protocolLimits.maxFutureLogicalWindows`,
`roomPolicy.admissionFloor.maxAuthorityCredentialLifetimeWindows`, and
`roomPolicy.protocolLimits.maxClockSkewWindows`. The persisted authority
fault—not a guessed revoke
value—is sufficient to deny, so dropping later nested payloads is safe. Once
that horizon passes, all credentials that could have been affected have
expired; a conforming authority still obeys its durable generation floors. An
accepted pair operation whose required outer author slot or chain prefix later
becomes forked/overquota stalls only that provisional or established edge and
requires a fresh handshake. Durable v4 state is never rolled back. To make
that later check executable, an accepted pair slot's edge audit retains the
exact outer author operation IDs from sequence zero through the accepted
operation, plus any fork/overquota proof IDs, for the longer of that pair
slot's replay and causal horizons. Those bytes are charged to
`maxPairLedgerBytesPerRoom`; exhaustion fails the pair transaction before
publication.

Fork/overquota classification precedes payload reduction. If the pinned
authority is faulted for a logical window, no `ADMISSION_REVOKE` operation from
that authority/window contributes a floor, including one whose nested payload
was validated before the conflicting operation arrived. Excluding the whole
window is arrival-independent; the persisted authority-unavailable horizon is
the fail-closed protection until every possibly affected credential expires.

An operation may depend on pair or policy operations outside its author chain.
A missing dependency suspends only that operation
until the dependency arrives or the buffer/retention limit expires.

Every non-pair semantic slot is exact and domain separated:

```text
PresenceSemanticSlot =
  H(
    "p2party/presence-slot/v1" ||
    authorEpochEd25519Key ||
    U64BE(logicalWindow) ||
    presence.core.presenceNonce
  )

LeaveSemanticSlot =
  H(
    "p2party/leave-slot/v1" ||
    leave.presenceOperationId ||
    U64BE(leave.effectiveLogicalWindow)
  )

StoreHintSemanticSlot =
  H(
    "p2party/store-hint-slot/v1" ||
    StoreId(hint.descriptor) ||
    U64BE(hint.descriptor.descriptorGeneration)
  )

AdmissionRevokeSemanticSlot =
  H(
    "p2party/admission-revoke-slot/v1" ||
    revoke.stableIdentityCommitment ||
    U64BE(revoke.minimumAcceptedGeneration) ||
    U64BE(revoke.effectiveLogicalWindow) ||
    U64BE(revoke.expiresAfterLogicalWindow)
  )
```

All four `U64BE` inputs are exact checked unsigned-64-bit schema fields.

The payload decoder is a closed discriminated union: `kind`, `lifetime`,
`operationPayloadClass`, fixed payload length, semantic slot, dependency rule, and
authorization must match this table or validation fails:

| Kind               | Lifetime           | Semantic slot                                   | Outer dependencies             | Additional authorization                                                                                                                                |
| ------------------ | ------------------ | ----------------------------------------------- | ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PRESENCE`         | `WINDOW_TRANSIENT` | `PresenceSemanticSlot`                          | empty                          | author signature; authority proof is core-verifiable, address-book proof is verified by local projection                                                |
| `LEAVE`            | `WINDOW_TRANSIENT` | `LeaveSemanticSlot`                             | exact referenced presence only | exact same `authorEpochEd25519Key` as the referenced presence; own current-window author chain; referenced presence valid at the leave effective window |
| `STORE_HINT`       | `WINDOW_TRANSIENT` | `StoreHintSemanticSlot`                         | empty                          | descriptor and route signatures                                                                                                                         |
| `ADMISSION_REVOKE` | `GRANT_HORIZON`    | `AdmissionRevokeSemanticSlot`                   | empty                          | room-policy-pinned authority is both the outer author key and inner signer                                                                              |
| `PAIR_STEP`        | `PAIR_CAUSAL`      | `H("p2party/pair-slot/v1" \|\| pairRoutingTag)` | empty                          | none for outer/core inclusion; only a matching endpoint applies pair AEAD and inner edge-ledger rules                                                   |

Outer validity is deliberately endpoint-independent. Every room member can
validate the canonical `PAIR_STEP` outer operation, author chain, lifetime,
class, envelope framing, tag slot, and signature, so the same delivered bytes
enter every member's core operation IDs/digest. Pair AEAD, inner payload class,
dependencies, sequence, and state-machine rules are a second edge-local
acceptance step run only by an endpoint that derives a matching one-use tag.
Failure there never removes the outer operation from `CoreRoomState`; a fully
authenticated inner violation fails only that edge. This split prevents
another pair's private plaintext from becoming an input to room convergence.

Nested validity intervals are part of the closed codec:

```text
PRESENCE:
  outer.logicalWindow
    <= core.validThroughLogicalWindow
    <= core.receiverKeyValidThroughLogicalWindow
    <= outer.expiresAfterWindow
  and if roomPolicy.admissionFloor.mode == "capability":
        authorityPermit == null
      else:
        authorityPermit is exactly one valid policy-authority permit for this
        presence transcript and covers the complete
        [outer.logicalWindow, core.receiverKeyValidThroughLogicalWindow]
        interval

LEAVE:
  outer.logicalWindow
    == effectiveLogicalWindow
    <= outer.expiresAfterWindow
  and the exact referenced presence:
        has the same authorEpochEd25519Key as this LEAVE,
        is named by the sole outer dependency, and
        is valid at effectiveLogicalWindow
  and outer.expiresAfterWindow
        >= referencedPresence.core.validThroughLogicalWindow

STORE_HINT:
  outer.logicalWindow
    <= hintExpiresAfterLogicalWindow
    <= outer.expiresAfterWindow
  and StoreDescriptorAuthentic(descriptor)
  and descriptor.notBeforeUnixMs
        <= RoomLogicalWindowStartUnixMs(roomPolicy, outer.logicalWindow)
  and RoomLogicalWindowEndUnixMsExclusive(
        roomPolicy,
        hintExpiresAfterLogicalWindow
      )
        <= descriptor.notAfterUnixMs
  and routes has at most MAX_STORE_HINT_ROUTES_V1 entries
  and routes is sequence-encoded, sorted by derived RouteId, duplicate-free
  and the complete canonical StoreHintOperationV1 fits payload class 0
  and for every route:
        StoreRouteAuthentic(route, descriptor)
        route.notBeforeUnixMs
          <= RoomLogicalWindowStartUnixMs(roomPolicy, outer.logicalWindow)
        RoomLogicalWindowEndUnixMsExclusive(
          roomPolicy,
          hintExpiresAfterLogicalWindow
        )
          <= route.notAfterUnixMs
        the registered route-family codec accepts the exact signed route bytes

ADMISSION_REVOKE:
  outer.logicalWindow
    == effectiveLogicalWindow
  checkedAdd(
    checkedAdd(
      effectiveLogicalWindow,
      roomPolicy.protocolLimits.maxFutureLogicalWindows
    ),
    roomPolicy.admissionFloor.maxAuthorityCredentialLifetimeWindows
  )
    == expiresAfterLogicalWindow
    == outer.expiresAfterWindow
```

A bootstrap admission lease ends no later than its retained presence evidence,
grant, pair-attempt, and admitted identity-operation horizons. It is never
required after stable-edge promotion. A stable-edge admission lease instead
binds the confirmed stable transcript and has no presence or pair-attempt
horizon; authority mode remains bounded by its current grant. Local policy and
revocation do not acquire invented future horizons: their exact generation and
decision-state digest are rechecked at every sensitive boundary. Any
contradictory inner/outer interval is invalid rather than resolved by taking a
locally chosen minimum.

`semanticSlot` scopes candidate grouping; it is not a universal conflict
resolver and does not select a mutable value. Generic same-slot fork behavior
applies only where the table and reducer say so. `STORE_HINT` uses
generation-fork/route-union rules, and `ADMISSION_REVOKE` uses monotone maximum
generation floors.
Pair direction, sequence, predecessor, pair ID, presence IDs, and pair
dependencies are deliberately absent from the outer operation and are checked
only after pair AEAD. There is no generic room `CHECKPOINT` kind. An author
chain restarts at sequence zero each window; pair checkpoints, where required,
are pair-private protocol steps.

### 4.5 Carrier-separated envelope and dummy generation

```ts
type CarrierEnvelopeV1 = {
  version: 1;
  deliveryProfileHash: Bytes32;
  ingressWindow: bigint;
  sizeClass: number;
  carrierContextId: Bytes32;
  nonce: Bytes24;
  ciphertextAndTag: Uint8Array;
};

type CarrierPlaintextV1 = {
  operationBytes: Uint8Array; // exact canonical signed operation
  carrierPadding: Uint8Array; // fills this profile's carrier size class
};
```

`carrierContextId` is `PublicCarrierContextId` for a public store, a
session-specific authenticated contact identifier for a peer exchange, or a
fresh public domain identifier for a portable bundle. It identifies a
wrapping domain, not a room.

```text
CarrierKey =
  HKDF-Expand(
    RoomRoot,
    "p2party/carrier-envelope-key/v1" ||
    DeliveryProfileHash ||
    carrierContextId ||
    U64BE(ingressWindow) ||
    Byte(sizeClass) ||
    nonce,
    32
  )

CarrierAAD =
  "p2party/carrier-envelope-aad/v1" ||
  Byte(version) ||
  DeliveryProfileHash ||
  U64BE(ingressWindow) ||
  Byte(sizeClass) ||
  carrierContextId

CarrierCiphertextAndTag =
  XChaCha20Poly1305.Seal(
    key = CarrierKey,
    nonce = nonce,
    aad = CarrierAAD,
    plaintext = Canonical(CarrierPlaintextV1)
  )

CarrierObjectId =
  H("p2party/carrier-object/v1" || Canonical(CarrierEnvelopeV1))
```

`carrierAeadSuite=1` is the frozen XChaCha20-Poly1305 construction with a
32-byte key, 24-byte nonce, and 16-byte tag from
`draft-irtf-cfrg-xchacha-03`; HKDF is HKDF-SHA-256 and every output length is
explicit above. `Open` is the exact inverse and returns no plaintext on tag,
length, profile, context, class, or canonical-padding failure. Changing any
primitive, length, or encoding requires a new carrier suite/profile hash.

The envelope encrypts one exact canonical `CarrierPlaintextV1`. Its operation
bytes are identical across carriers/profiles; only carrier padding and the
outer envelope differ. The delivery size class is exactly
`CarrierSizeClassForPayloadClass(operationPayloadClass)` and must have room for
operation bytes, length framing, padding, and AEAD tag. The sender samples the public
24-byte `nonce` independently for each
`(OperationId, DeliveryProfileHash, carrierContextId, ingressWindow,
sizeClass)` wrap slot. The nonce is a key selector available before
decryption; `OperationId` deliberately is not. Before first publication, one
transaction persists the protected operation, nonce, exact envelope, and
scheduled wrap slot. Exact retries resend those bytes and never re-encrypt.
A canonical operation that needs continued republishing gets one newly sampled
and persisted envelope in each protocol-permitted later ingress window. The
nonce/key pair is never used for different plaintext.

Each carrier context receives an independently keyed and nonced envelope;
multiple routes to one public context carry the exact same bytes. A
`CarrierObjectId` is therefore useful only inside that carrier context. A
client deduplicates rewrapped copies by the private `OperationId` after
decryption. A local unique constraint on
`(OperationId, profile, carrierContextId, ingressWindow, sizeClass)` permits
at most one
persisted wrap. Backfill and reconciliation schedule it only through fixed
carrier slots; neither a new store nor a reconnect creates an
\(O(members \times operations \times retries)\) burst.

A dummy has the exact public header and body length of a real envelope and a
cryptographically random body that fails room AEAD authentication. Dummy
generation consumes no room operation sequence. A receiver performs the same
bounded length and header checks before trial decryption.

Before any room-key trial, a receiver computes the profile's current ingress
window and rejects or queues an envelope unless:

```text
currentIngressWindow - carrierRetentionWindows
  <= envelope.ingressWindow
  <= currentIngressWindow + maxFutureIngressWindows
```

Subtraction/addition is checked and clamped at unsigned zero. Older recovery
reads never exceed the lower retained bound; future envelopes consume bounded
candidate custody but are not opened before their window. This is a carrier
admission rule, never a room logical clock.

The public object size includes all operation, signature, pair-envelope, AEAD,
and carrier-padding overhead. The profile's largest class shall fit operation
class 1 inside carrier sealing; the future release vector, not an informal arithmetic
estimate, fixes its final byte count.

### 4.6 Store and contact-carrier adapters

```ts
interface OperationCarrierAdapter {
  readonly carrierContextId: Bytes32;
  readonly kind: "public-store" | "contact" | "portable-bundle";

  publish(
    items: readonly CarrierPublishItemV1[],
    signal: AbortSignal,
  ): Promise<readonly CarrierPublishResultV1[]>;

  reconcile(
    scope: CarrierReconcileScopeV1,
    frontier: Uint8Array | null,
    signal: AbortSignal,
  ): AsyncIterable<CarrierBatchV1>;
}

interface PublicStoreOperationCarrierAdapter extends OperationCarrierAdapter {
  readonly kind: "public-store";

  issueAllocationToken(
    request: AllocationTokenIssueRequestV1,
    signal: AbortSignal,
  ): Promise<AllocationTokenIssueResultV1>;

  allocate(
    request: PublicAllocationRequestV1,
    signal: AbortSignal,
  ): Promise<PublicAllocationResultV1>;

  readCheckpoint(
    deliveryProfileHash: Bytes32,
    ingressWindow: bigint,
    signal: AbortSignal,
  ): Promise<PublicStoreCheckpointReadV1>;
}

type CarrierPublishItemV1 = {
  exactFixedObject: Uint8Array;
  publicAdmission: PublicAppendAdmissionV1 | null;
};

type CarrierPublishStatusV1 =
  | "stored"
  | "already-present"
  | "queued"
  | "slot-conflict"
  | "unallocated-cover"
  | "window-finalized"
  | "capacity-exhausted";

type PublicAppendResultBodyV1 = {
  version: 1;
  storeId: Bytes32;
  descriptorHash: Bytes32;
  bucket: PublicBucketV1;
  requestHash: Bytes32;
  status: Exclude<CarrierPublishStatusV1, "queued">;
  fixedStatusPadding: Uint8Array;
};

type PublicAppendResultV1 = PublicAppendResultBodyV1 & {
  storeSignature: Bytes64;
};

type PublicCustodyBreachProofV1 = {
  version: 1;
  descriptor: StoreDescriptorV1;
  appendRequest: PublicAppendRequestV1;
  custodyPromise: PublicAppendResultV1;
  checkpoint: PublicStoreCheckpointV1;
  finalizedChunk: PublicChunkV1;
  inclusionProof: PublicCheckpointChunkInclusionProofV1;
};

type CarrierPublishResultV1 = {
  status: CarrierPublishStatusV1;
  publicStoreReceipt: PublicAppendResultV1 | null;
};

type CarrierReconcileScopeV1 =
  | {
      kind: "public-fixed-scan";
      profileHash: Bytes32;
      firstIngressWindow: bigint;
      lastIngressWindow: bigint;
      // Always every [0, publicChunksPerWindow) index for each tuple.
      completeChunkRange: true;
    }
  | {
      kind: "contact-fixed-inventory";
      profileHashes: readonly Bytes32[];
      maxInventoryEntries: number;
    }
  | {
      kind: "portable-bundle";
      maxBundleBytes: number;
    };

type CarrierBatchV1 =
  | {
      kind: "opaque-batch";
      publicFrontier: Uint8Array;
      fixedObjects: readonly Uint8Array[];
      proofOrManifest: Uint8Array;
    }
  | {
      kind: "public-checkpoint";
      read: PublicStoreCheckpointReadV1;
    }
  | {
      kind: "public-fixed";
      read: PublicChunkReadV1;
    };

type PublicStoreCheckpointStatusBodyV1 = {
  version: 1;
  storeId: Bytes32;
  deliveryProfileHash: Bytes32;
  ingressWindow: bigint;
  status: "not-final" | "out-of-range" | "chain-unavailable";
};

type PublicStoreCheckpointReadV1 =
  | {
      kind: "finalized";
      descriptor: StoreDescriptorV1;
      checkpoint: PublicStoreCheckpointV1;
    }
  | {
      kind: "status";
      value: PublicStoreCheckpointStatusBodyV1;
      storeSignature: Bytes64;
    };

type PublicChunkStatusBodyV1 = {
  version: 1;
  bucket: PublicBucketV1;
  chunkIndex: bigint;
  status: "not-final" | "out-of-range";
};

type PublicChunkReadV1 =
  | { kind: "finalized"; chunk: PublicChunkV1 }
  | {
      kind: "status";
      value: PublicChunkStatusBodyV1;
      storeSignature: Bytes64;
    };
```

`AsyncIterable` permits bounded streaming/backpressure within one adapter call;
it conveys no server-push, subscription, long-lived-connection, connection
ordering, or heartbeat contract. A conforming finite HTTP adapter yields the
same batches and terminates. A separately registered non-default WebSocket
route, if a release ever includes one, is independently removable and
evidenced and may contribute only ordinary route availability; its connection
state cannot enter protocol state, liveness truth, or assurance by itself.

The semantic contract is:

- immutable object bytes;
- unordered, at-least-once delivery;
- omission, delay, duplication, and reordering permitted;
- overwrite forbidden;
- bounded object, batch, inventory, and parser sizes;
- no server-generated room or peer state; and
- cursor/frontier values are optimizations, never correctness inputs.

Host placement is deliberately absent from `OperationCarrierAdapter`. The same
interfaces cover peer execution as follows:

| Deployment role           | Existing adapter contract                            | Work performed                                                                                               | Maximum claim without further evidence                                                                                           |
| ------------------------- | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------- |
| Authenticated peer bridge | `kind="contact"` with one registered contact adapter | Bounded inventory exchange, reassembly, store-carry-forward, reconciliation, and retained-operation backfill | One currently usable time-respecting contact edge; never public-store custody, store independence, or an R2 honest-store unit    |
| Peer-hosted public store  | `PublicStoreOperationCarrierAdapter`                 | The complete descriptor/allocation/append/checkpoint/chunk protocol and fixed public schedule                | The same store/custody evidence as an identically conforming store; S1 or scoped R2 only through the existing package predicates |

An implementation shall not add a `peer-store` or `peer-relay` operation kind,
room role, reducer branch, signaling message family, or invitation field. A
single device may run an endpoint, one or more authenticated contact adapters,
and a public store concurrently, but each role keeps its existing context IDs,
keys, persistence, policy checks, resource accounting, and assurance records.
Co-location never creates an extra fault, operator, blocking, availability, or
privacy domain and never permits the same physical path to be counted twice.

A contact bridge can carry every control operation needed to converge presence,
apply admission/revocation, exchange pair-private transport offers and answers,
complete protocol-v4, and deliver PQ-healing controls. The contact adapter is
not given a roster, room identifier, pair target, or connection-planner output
and does not decide who should connect. A co-located room endpoint may
independently decrypt the room-level operation because it holds the capability,
but a peer that is not one of a pair's endpoints cannot open that pair's inner
payload. Sharing one contact across two delivery profiles or rooms does not
merge their operation sets, admission, topology, or sessions.

Cross-context bridge/backfill is a client operation, not blind ciphertext
translation. The bridging room client first recovers and validates the canonical
operation under its normal room context, then independently wraps the retained
operation for each destination carrier context under SEC-004. An unrelated
volunteer that lacks that room context cannot transform one contact envelope
into another. It may still host a public store, or transport unchanged wrapped
bytes where one registered shared contact/portable context explicitly permits
that custody; neither case grants room access.

The public-store role is conforming only if the peer-hosted process passes the
same black-box protocol, fixed-traffic, retention, restart, equivocation,
accountability, quota, and resource tests as the reference store. An
intermittent browser tab, cache, relay, or contact session that cannot do so
remains a contact carrier or unavailable path; labeling it a store does not
upgrade its evidence. Conversely, a store process does not cease to be a public
store merely because it runs on a participant's device.

Neither role creates first contact from nothing. A peer bridge is usable only
after an authenticated bearer contact already exists. A peer-hosted store is
usable only after its signed descriptor and exact route arrive through release
configuration, explicit local addition, an already reachable authorized
`STORE_HINT`, or an out-of-band exchange. Route parsing and activation retain
all Section 4.2 frontend authorization, SSRF, private-network, credential, and
source-metadata checks.

`OperationCarrierAdapter` deliberately has no singular
`carrierInstanceId`: one public context can cycle several routes. Each actual
custody/use observation emits assurance evidence under this exact mapping:

| Use                                           | `carrierContextId`                    | `carrierInstanceId`                                                                       |
| --------------------------------------------- | ------------------------------------- | ----------------------------------------------------------------------------------------- |
| Public-store request on route `r`             | `PublicCarrierContextId`              | `PublicRouteInstanceId(context, r)`                                                       |
| Authenticated contact session                 | `ContactCarrierInstanceId`            | the same `ContactCarrierInstanceId`                                                       |
| Portable bundle import/export for profile `p` | the bundle's fresh `carrierContextId` | `PortableCarrierInstanceId(adapterProtocolId, carrierContextId, custodyPathContextId, p)` |

There is one `CarrierAssuranceV1` record per actually used public route, not
one flattering record per store. A heterogeneous portable bundle emits one
record per distinct inventory `deliveryProfileHash`; those records share the
same measured `availabilityPathId`, so adding profiles cannot manufacture
path diversity. `custodyPathContextId` is an exact
evidence-registry identifier for the locally authenticated import/export
provenance and physical custody path; when no such provenance exists it is the
registry's single `UNKNOWN_CUSTODY_PATH` value and every path-dependent
assurance field remains `unknown`. It is local evidence, never room
authorization or a wire-level target. Multiple routes/bundles can share one
`availabilityPathId` only when the assurance registry's measured method says
they share that same blocking/custody path.

The reference HTTP route family is a frozen mapping, not implementer choice.
`StoreRouteV1.opaqueLocator` supplies only the authorized origin/base; the
following ASCII suffixes and media types are exact:

| Method and suffix                                                       | Canonical body/result                                                                                       |
| ----------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `GET /.well-known/p2party-store/v1`                                     | signed `StoreDescriptorV1` plus its signed routes; `application/p2party-store-descriptor-v1`                |
| `POST /p2party/v1/allocation-token`                                     | `AllocationTokenIssueRequestV1` / `AllocationTokenIssueResultV1`; `application/p2party-allocation-token-v1` |
| `POST /p2party/v1/allocation`                                           | `PublicAllocationRequestV1` / `PublicAllocationResultV1`; `application/p2party-allocation-v1`               |
| `POST /p2party/v1/append`                                               | `PublicAppendRequestV1` / fixed signed append status; `application/p2party-append-v1`                       |
| `GET /p2party/v1/checkpoint/{profileHash}/{window}`                     | `PublicStoreCheckpointReadV1`; `application/p2party-checkpoint-v1`                                          |
| `GET /p2party/v1/chunk/{profileHash}/{window}/{sizeClass}/{chunkIndex}` | `PublicChunkReadV1`; `application/p2party-chunk-v1`                                                         |

The Phase-0 HTTP artifact freezes the binary encoding, unsigned integer text
encoding in the public chunk path, request/response target lengths, status
enum bytes, store-signature transcripts, content types, cache headers, and the
constant response for malformed fixed-length POSTs. A syntactically
fixed-length protocol request receives HTTP 200 with one canonical
application status; application states are never encoded as variable HTTP
status/body shapes. Redirects, cookies, HTTP authentication, compression,
content negotiation, ranges, room-derived headers, and per-room cache keys are
forbidden. A malformed outer HTTP length/media type receives one constant
400 response before parsing and earns no fixed-trace claim. Finalized signed
chunks may be cached immutably; pre-finalization status is not.

This mapping is a route adapter for the one carrier interface, not a second
logical protocol. Other registered route families may carry the byte-identical
requests and responses through OHTTP, a proxy, or another reviewed path. A
portable-bundle implementation serializes a bounded inventory plus envelopes
into a canonical file. A BLE or other contact implementation exchanges
bounded inventories and batches. None changes operation semantics.

For `public-fixed-scan`, the adapter initiates exactly one checkpoint request
and every canonical chunk request without awaiting a response. It eventually
yields exactly one `public-checkpoint` response for each requested ingress
window and one `public-fixed` response for every canonical
`(ingressWindow, sizeClass, chunkIndex)` tuple in the requested complete
range; response yield order is not an input to protocol state. The size-class
set is exactly the profile's full sorted set and cannot be supplied or narrowed
by a caller. The count is derived from the profile.
The range must fit `ClientResourcePolicyV1` before any request. A status
signature covers
`H("p2party/public-chunk-status/v1" ||
Canonical(PublicChunkStatusBodyV1))`, and each status discriminator has one
profile-fixed wire size. A checkpoint status signature covers
`H("p2party/public-checkpoint-status/v1" ||
Canonical(PublicStoreCheckpointStatusBodyV1))` and has the checkpoint
response's fixed target length. That target reserves the profile-bounded
descriptor plus checkpoint and padding, so historical descriptor rotation
does not create a response-size branch. Contact and portable scopes use `opaque-batch` and
their existing inventory/bundle limits. Public frontiers are cache hints only;
they never suppress a required tuple.

For append receipts,
`requestHash = H("p2party/public-append-request/v1" ||
Canonical(PublicAppendRequestV1))` and the store signature covers
`"p2party/public-append-result/v1" ||
H(Canonical(PublicAppendResultBodyV1))`. A public-store adapter returns the
verified receipt only when `storeId` and `descriptorHash` join the exact
active request target/descriptor and its stable signing key;
contact/portable adapters return `publicStoreReceipt=null`.

A verified `stored` or `already-present` result is a public custody promise for
the request whose hash it names. It promises that the exact
`H(appendRequest.exactFixedObject)` occupies the deterministic
`(sizeClass, chunkIndex, objectIndexWithinChunk)` obtained from the signed
allocation lease and slot equations in Section 4.3 when that window finalizes.
No other status makes this promise. Its evidence identifier is:

```text
PublicCustodyPromiseDigest =
  H(
    "p2party/public-custody-promise/v1" ||
    Canonical(appendRequest, custodyPromise)
  )
```

`PublicCustodyBreachProofV1` verifies only when the promise signature and
request hash are valid, promise status is `stored` or `already-present`,
admission is non-null, lease/profile/window/bucket coordinates join exactly,
the embedded descriptor hash equals both receipt/checkpoint descriptor hashes
and derives their common `storeId`/signing key, the checkpoint and finalized
chunk signatures verify, and the inclusion path places that exact chunk in
that exact checkpoint. The final contradiction is exactly:

```text
H(finalizedChunk.fixedObjects[derivedObjectIndex]) !=
H(appendRequest.exactFixedObject)
```

Its digest is:

```text
PublicCustodyBreachProofDigest =
  H(
    "p2party/public-custody-breach-proof/v1" ||
    Canonical(PublicCustodyBreachProofV1)
  )
```

The proof is self-contained evidence that the signing store broke one exact
custody promise; it says nothing about room plaintext or global delivery.
Failure to obtain a checkpoint, inclusion path, or chunk is an availability
failure/unknown result, not a cryptographic breach proof. A valid checkpoint
conflict proof analogously requires two distinct structurally valid signed checkpoint
hashes for the same store/profile/window. Clients retain minimal fault
tombstones keyed by
`(StoreId, DeliveryProfileHash, ingressWindow-or-profile-scope, faultKind,
evidenceDigest)` and exclude the affected store/profile from positive custody
or R2 evidence.

Full promise/proof objects disclose the allocation ordinal, public slot,
opaque carrier object, and precise window to whoever receives them. They are
kept local by default and exported only by an explicit diagnostic/research
action. Because `appendRequest.exactFixedObject` permits offline trial
decryption by a holder of a candidate room capability and can aid correlation,
public research export uses only synthetic rooms or explicit affected-room
consent. Logs contain only the bounded local fault kind and evidence digest,
never the proof body. Normal room operations, public-store appends, automatic
telemetry, and room gossip contain neither accountability proof nor digest; an
explicitly registered room-independent diagnostic exchange is required.

Entries and exact canonical bytes are charged before acceptance to
per-`(StoreId, DeliveryProfileHash)` accountability partitions under the
client-global cap. The policy reserves enough bytes for one maximum proof or
compact fault/saturation tombstone per active selected store/profile and keeps
at most one canonical proof/tombstone per fault kind in each partition. Once a
store/profile is faulted, later proofs for it have no additional semantic
effect. If its next required proof cannot fit, the client persists the compact
first-rejected saturation/fault tombstone and excludes only that
store/profile. Unrelated profiles and an R2 record that does not select the
attacker remain evaluable; the implementation still cannot discard an
inconvenient record or choose a favorable subset within a selected partition.

An authenticated room peer may reconcile private `OperationId` inventories
over an established pair link to avoid retransmitting known operations. Before
pair authentication, a contact adapter exchanges only carrier object
inventories or fixed batches; it never exposes a room-derived inventory to an
untrusted bearer.

### 4.7 Client reconciliation, reduction, and convergence

Every client runs the same pipeline:

```text
create:
  canonicalize and sign operation
  → persist protected operation and outbox intent
  → derive independent envelope for every active carrier context
  → publish/queue on every context at its fixed/contact boundary

receive:
  parse fixed public envelope
  → try only locally active room keys for that public profile/horizon
  → authenticate room AEAD
  → require canonical operation bytes and context confirmation
  → verify author signature and all bounds
  → derive OperationId
  → insert into OuterValidOperationSet if new
  → outer dependency/fork validation
  → deterministic CoreReduce
  → for a matching local edge only, run pair AEAD/inner edge-ledger validation
  → backfill to every other active carrier context
```

Formally:

```ts
type CoreStoreFactV1 = {
  storeId: Bytes32;
  descriptorGeneration: bigint;
  descriptorHash: Bytes32;
  sourceOperationId: Bytes32;
  descriptor: StoreDescriptorV1;
  // Exact routes carried by this one STORE_HINT source; never a flattened
  // cross-lease union.
  routes: readonly StoreRouteV1[];
  hintValidThroughLogicalWindow: bigint;
};

type CorePresenceFactV1 = {
  presenceOperationId: Bytes32;
  authorEpochEd25519Key: Bytes32;
  logicalWindow: bigint;
  presence: PresenceV1;
};

type CoreRevocationFloorV1 = {
  stableIdentityCommitment: Bytes32;
  minimumAcceptedGeneration: bigint;
  effectiveLogicalWindow: bigint;
  validThroughLogicalWindow: bigint;
  revokeOperationId: Bytes32;
};

type CoreFaultV1 =
  | {
      kind: "author-fork-or-overquota";
      authorEpochEd25519Key: Bytes32;
      logicalWindow: bigint;
      proofOperationIds: readonly Bytes32[];
    }
  | {
      kind: "presence-or-leave-fork";
      semanticSlot: Bytes32;
      proofOperationIds: readonly Bytes32[];
    }
  | {
      kind: "store-generation-fork";
      storeId: Bytes32;
      descriptorGeneration: bigint;
      // Bytewise-lowest two distinct hashes; sufficient fixed-size proof.
      descriptorHashes: readonly [Bytes32, Bytes32];
    };

type CoreRoomStateV1 = {
  version: 1;
  referenceWindow: bigint;
  roomCapacityState: "within-policy" | "overcapacity";
  activeOperationIds: readonly Bytes32[];
  observedPresences: readonly CorePresenceFactV1[];
  effectiveLeaveOperationIds: readonly Bytes32[];
  storeCatalogFacts: readonly CoreStoreFactV1[];
  revocationFloors: readonly CoreRevocationFloorV1[];
  activePairOuterOperationIds: readonly Bytes32[];
  faults: readonly CoreFaultV1[];
  operationsDigest: Bytes32;
};
```

The canonical schema registry, not TypeScript object insertion order, is the
SSOT for these bytes. In particular, `CoreStoreFactV1` encodes its identifying
tuple first as `(storeId, descriptorGeneration, descriptorHash,
sourceOperationId)`, and `CoreRevocationFloorV1` encodes
`(stableIdentityCommitment, minimumAcceptedGeneration,
effectiveLogicalWindow, validThroughLogicalWindow, revokeOperationId)`.
Top-level Core arrays are sorted and duplicate-free by their complete canonical
item encoding. Because the identifying fields lead those encodings, this is
equivalent to bytewise operation-ID order for operation-ID and presence
arrays, the tuples above for store and revocation facts, and the following
fault order:

1. `author-fork-or-overquota`, by
   `(authorEpochEd25519Key, logicalWindow)`;
2. `presence-or-leave-fork`, by `semanticSlot`; and
3. `store-generation-fork`, by `(storeId, descriptorGeneration)`.

For a semantic-slot fork, `proofOperationIds` is the bytewise-lowest two
distinct operation IDs. For a maximum-generation store fork,
`descriptorHashes` is the bytewise-lowest two distinct descriptor hashes.
Each store fact's nested `routes` remains sequence-encoded but must be strictly
sorted and duplicate-free by derived `RouteId`; both Core encode and strict
decode enforce that asynchronous derivation over a private byte snapshot.
The author-fault proof selection is the precedence rule in Section 4.4.
Changing any variant, field, or order requires a new core-state version and
new independent known-answer vectors.

```ts
type LocalAdmissiblePeerV1 = {
  localPeerId: string; // canonical "peer.v1." handle
  presenceOperationId: Bytes32;
  stableIdentityCommitment: Bytes32;
  rank: Bytes32;
  eligibility: "open" | "local-address-book-proved" | "authority-permit-proved";
  // Diagnostic/UI union only. It is never an attempt-mode authorization bit.
  desiredEdge: boolean;
};

declare const VERIFIED_LOCAL_PRESENCE_OWNERSHIP_V1: unique symbol;

// Canonical persisted capture row. Decoding it proves only shape and byte
// ownership; it does not prove key custody or local presence ownership.
type LocalPresenceOwnershipRecordV1 = {
  version: 1;
  localPresenceOperationIds: CanonicalBytes32SetV1;
  localStableIdentityKeys: CanonicalBytes32SetV1;
};

// Module-private result of verifying one exact captured record against the
// retained Core facts plus live local author, stable-identity, and receiver-key
// custody in the same projection transaction.
type VerifiedLocalPresenceOwnershipV1 = {
  version: 1;
  localPresenceOperationIds: CanonicalBytes32SetV1;
  localStableIdentityKeys: CanonicalBytes32SetV1;
  readonly [VERIFIED_LOCAL_PRESENCE_OWNERSHIP_V1]: true;
};

type LocalAdmissibleStateV1 = {
  version: 1;
  referenceWindow: bigint;
  coreOperationsDigest: Bytes32;
  // Both are null unless exactly one current local presence is in the
  // bounded selected vertex set.
  localPresenceOperationId: Bytes32 | null;
  localPresenceRank: Bytes32 | null;
  // Selected remote vertices only; the room cap includes the local vertex.
  peers: readonly LocalAdmissiblePeerV1[];
  requestedExplicitPeerIds: readonly string[];
};

type LocalAdmissibleProjectionStatusV1 =
  | "ready"
  | "policy-unavailable"
  | "projection-resource-overcapacity"
  | "no-unambiguous-local-presence";

type LocalAdmissiblePlannerStatusV1 =
  "ready" | "unavailable" | "full-mesh-overcapacity";

type LocalTopologySelectionFactV1 = {
  presenceOperationId: Bytes32;
  plannerSelected: boolean;
  // Outbound local user intent only; never required for an incoming explicit
  // HELLO.
  locallyRequestedExplicit: boolean;
};

type LocalAdmissibleProjectionV1 = {
  version: 1;
  projectionStatus: LocalAdmissibleProjectionStatusV1;
  plannerStatus: LocalAdmissiblePlannerStatusV1;
  observedRosterHash: Bytes32;
  state: LocalAdmissibleStateV1;
  // Exactly one entry per state.peers item, in the same canonical order.
  topologySelections: readonly LocalTopologySelectionFactV1[];
};

type LocalDeliveryStateV1 = {
  version: 1;
  referenceWindow: bigint;
  activationAtUnixMs: bigint;
  carrierPolicyGeneration: bigint;
  roomCarrierAssignmentPolicyGeneration: bigint;
  activeDeliveryProfileHashes: readonly Bytes32[];
  activeCarrierContextIds: readonly Bytes32[];
  activeRouteInstanceIds: readonly Bytes32[];
  observedDeliveryFrontierId: Bytes32;
  consistency: "converged-to-observed-frontier" | "reconciling" | "partitioned";
  resourceState: "within-bounds" | "overcapacity";
  assurance: RoomAssuranceV4;
};

type DeliveryConsistencyEvidenceV1 = {
  version: 1;
  referenceWindow: bigint;
  observedDeliveryFrontierId: Bytes32;
  usablePathIds: readonly Bytes32[];
  pendingRequiredWorkIds: readonly Bytes32[];
  impossibleRequiredWorkIds: readonly Bytes32[];
  hasLiveOrRetainedDeliveryObligation: boolean;
  requiredWorkSaturated: boolean;
  firstSaturatedRequiredWorkId: Bytes32 | null;
  coreRoomOvercapacity: boolean;
  protectedCustodyOvercapacity: boolean;
  assuranceEvidenceSaturated: boolean;
};
```

All arrays above are sorted by their complete canonical identifying tuples and
contain unique canonical values. In particular, store facts sort by
`(storeId, descriptorGeneration, descriptorHash, sourceOperationId)`,
revocation facts sort by
`(stableIdentityCommitment, minimumAcceptedGeneration,
effectiveLogicalWindow, validThroughLogicalWindow, revokeOperationId)`, and
nested route/proof arrays sort by `RouteId`/`OperationId`.
`activeOperationIds` contains exactly
the non-expired, non-future operations eligible for reduction after canonical
outer author/fork/dependency rules, including every outer-valid `PAIR_STEP`
without consulting pair plaintext. `activePairOuterOperationIds` is the exact
sorted projection of those pair-step IDs. `operationsDigest` is
`H("p2party/core-operation-set/v1" || Canonical(activeOperationIds))`.
`CoreRoomStateV1` contains no local carrier, frontend, planner, or physical
capacity fact. Each logically active valid `STORE_HINT` emits one exact
`CoreStoreFactV1` whose `sourceOperationId`, route subset, and hint lease
remain separate. At the maximum descriptor generation, every live source fact
is retained canonically, including all hash branches when that generation is
forked; one sorted `store-generation-fork` fault then makes every fact at that
maximum generation inert in `ProjectDelivery`; its proof tuple is the
bytewise-lowest two distinct hashes, regardless of further branches. This core fault is a
current-reference-window fact: if one live branch later expires, clients with
the same live operation set may again derive a singleton core projection. The
client-global carrier catalog is stricter: any client that observed two valid
hashes persists the fixed two-hash fork tombstone and keeps that store
generation inert until a strictly higher singleton generation is
authenticated. Core convergence therefore does not depend on which client
previously observed the fork, while a local observer never reactivates a
known-forked generation after compaction. For a non-forked active descriptor,
`ProjectDelivery` unions only routes from source facts whose individual hint
lease is live, and then requires the route's own absolute lease and local
authorization. It never places a route from one source under another source's
later expiry. Each distinct valid `ADMISSION_REVOKE` similarly emits one exact
`CoreRevocationFloorV1`; maximum-floor evaluation does not delete the other
facts from `CoreRoomStateV1`. Absolute route time, local permission,
compatibility, and reachability are evaluated only by `ProjectDelivery`.
`LocalDeliveryStateV1` contains those delivery/assurance facts but cannot
alter peer admissibility.

```text
Merge(A, B) = A ∪ B

AuthorPrefixEvidenceSet =
  {
    op |
    op was delivered, decrypts for this room, passes canonical framing,
    signature, room, author-slot, and bounded prefix-evidence validation, but
    is semantically expired at referenceWindow
  }

OuterValidOperationSet =
  {
    op |
    op was delivered, decrypts for this room, and OuterValid(op)
    without pair AEAD or inner pair-ledger input,
    and its complete author chain is proven by semantically live operations
    plus AuthorPrefixEvidenceSet
  }

CoreRoomState(referenceWindow) =
  CoreReduce(
    SortByOperationId(OuterValidOperationSet),
    immutable RoomPolicyV4,
    referenceWindow
  )

EdgePairAcceptedSet(edge, referenceWindow) =
  EdgePairValidateAndReduce(
    outer-valid PAIR_STEP operations matching edge-owned expected tags,
    atomic edge snapshot,
    referenceWindow
  )

snapshot =
  CaptureTrustedAdmissionSnapshot(
    transaction,
    initializedRoom,
    referenceWindow
  )

LocalAdmissibleProjection(referenceWindow) =
  Project(
    snapshot,
    capturedPlannerAndExplicitState,
    capturedResourceState
  )

LocalAdmissibleState(referenceWindow) =
  LocalAdmissibleProjection(referenceWindow).state

LocalDeliveryState(referenceWindow) =
  ProjectDelivery(
    CoreRoomState(referenceWindow),
    FrontendCarrierPolicyV1,
    RoomCarrierAssignmentPolicyV1,
    ClientResourcePolicyV1,
    ClientGlobalResourcePolicyV1,
    DeliveryConsistencyEvidenceV1,
    activationAtUnixMs,
    active carrier evidence
  )
```

`Merge` is associative, commutative, and idempotent. `CoreReduce` shall not
read arrival timestamps, server identity, fetch order, frontend allow/deny
state, planner preferences, local wall-clock beyond its explicit reference
window, “first response” state, pair secrets, or inner pair validity. Given the same outer-validated operations,
immutable policy, and reference window, clients derive byte-identical
`CoreRoomState`. `Project` is intentionally local: different peer whitelists,
blacklists, or planner modes may produce different admissible peers and edges
without violating core convergence. Different carrier permissions change
`LocalDeliveryState`, not peer admissibility.

`Project` is invoked only with the one `TrustedAdmissionSnapshotV1` captured
by the local projection transaction. That snapshot contains the exact core
state, immutable room policy/context, frontend controls (or lookup failure),
module-private verified local presence ownership, and authority custody from
the same atomic source. The exact planner/explicit row and trusted resource row
are separate inputs captured by that same logical optimistic transaction and
are exact CAS fences; caller-supplied scalar limits or reconstructed planner
booleans are not authority. `Project` fails closed when any required input is
absent, mismatched, or unbranded, or when the trusted physical
custody/resource projection is incomplete, saturated, or at or over a
retained-operation count/byte cap. A complete Core whose
`roomCapacityState="overcapacity"` is not a physical resource failure:
`Project` must still apply the deterministic eligible-vertex rank and
`maxRoomMembers` cap. For each authority-mode commitment it calls the sole
`DeriveAuthorityAdmissionView`; it cannot accept a caller-supplied permit
winner, authority availability bit, revocation floor, or view. Thus
`maxRoomMembers`, room/policy binding, local ownership, and authority custody
are explicit inputs rather than ambient dependencies.

The cloneable `LocalAdmissibleProjectionV1` is diagnostic output, not a
capability. It may drive the room/member/edge UI, but no topology, HELLO,
admission, persistence, or publication transition accepts it back as proof.
Only the module-private projection call operating on genuine captured handles
may mint the pair-scoped opaque topology authorization defined below.

`ProjectDelivery` captures `activationAtUnixMs` once in the same atomic input
snapshot as `referenceWindow`. Every catalog, prewarm, active-context, and
route-selection derivation above is a pure function of that explicit value and
threads it into `StoreDescriptorActiveAt`/`StoreRouteActiveAt`; a “live”
source means a retained signed hint/bootstrap/local authorization at that
captured snapshot, never an ambient clock read. Adapters recapture and
revalidate a new explicit time immediately before network activation.

Delivery consistency has one conservative derivation. At one atomic
`referenceWindow` snapshot, `observedDeliveryFrontierId` hashes the reference
window, current `coreOperationsDigest`, final active context/route IDs, and
each active adapter's persisted scan/import/custody cursor. A _required work_
item is one of:

- a fixed public scan or already accepted authenticated import due through
  that captured frontier;
- a retained operation/profile backfill or due outbox intent whose scheduled
  deadline is through that frontier;
- a bounded buffered dependency needed by such an operation; or
- an accepted L3 delivery/export intent due through that frontier.

Each item has one canonical
`H("p2party/delivery-work/v1" || kindByte || exact canonical coordinates)`
identifier. It is `pending` until its exact cursor, receipt, or terminal record
is durably committed. It is `impossible` when the registered schedule
simulator, using only currently authorized usable paths, remaining fixed
opportunities, bytes, and semantic expiry, proves it cannot complete before
expiry. `usablePathIds` contains only routes or authenticated custody paths
that are currently authorized, live, and have at least one registered
opportunity before the earliest outstanding semantic deadline.

The release registry assigns L3 due work kind byte `0x03`; its exact canonical
coordinates are `(LocalRoomId, OperationId, DeliveryProfileHash)`, so its
delivery-work identifier is exactly `L3RequiredWorkId` above. No independent
L3 queue key or implementation-chosen serialization is permitted.

`requiredWorkSaturated` is true if and only if at least one already known
canonical required-work item cannot be durably represented, inserted, or
enqueued because its applicable dependency-buffer, candidate/reconcile,
outbox, L3 due-work, pending-export, count, or byte cap is full. The
transaction sets `firstSaturatedRequiredWorkId` to the bytewise-lowest such
known ID (or null exactly when the bit is false) before declining it. This
single witness is bounded; a deterministic bounded rescan in canonical work
order reconstructs the complete condition and retries admission when capacity
frees. Dropping invalid unauthenticated
garbage, a pre-core unauthenticated bootstrap/discovery candidate, or work not
yet known at the captured frontier does not set this bit. An outer-valid
authenticated `STORE_HINT` is already known canonical room work: failure to
retain/reconcile its fixed store-state footprint because a catalog
count/byte/route cap is full sets this bit before rejection. More generally,
silently omitting any known required item because a queue is full must set it.

```text
DeriveConsistency(evidence) =
  if evidence.requiredWorkSaturated
     or evidence.impossibleRequiredWorkIds is nonempty
     or (
       evidence.usablePathIds is empty
       and evidence.hasLiveOrRetainedDeliveryObligation
     ):
    "partitioned"
  else if evidence.pendingRequiredWorkIds is nonempty:
    "reconciling"
  else:
    "converged-to-observed-frontier"
```

The sets are sorted, duplicate-free, and recomputed from the same atomic
snapshot as `LocalDeliveryStateV1`; a restart cannot clear pending work, and an
expired contact or route cannot remain in `usablePathIds`.
`LocalDeliveryStateV1.consistency` is exactly
`DeriveConsistency(DeliveryConsistencyEvidenceV1)`. This label says only that
all obligations known at the captured observed frontier are complete. A
malicious carrier may omit an unseen operation, and no local empty scan proves
global completeness.

`LocalDeliveryStateV1.resourceState` is `"overcapacity"` if and only if
`evidence.coreRoomOvercapacity`,
`evidence.protectedCustodyOvercapacity`,
`evidence.requiredWorkSaturated`, or
`evidence.assuranceEvidenceSaturated` is true; otherwise it is
`"within-bounds"`. Those four booleans and
`hasLiveOrRetainedDeliveryObligation` are copied from the same explicit atomic
snapshot as the work sets, not read from ambient state during derivation.
`AssuranceRuntimeFactsV1.resourceState` and its assurance-saturation tuple
must byte-match this result and evidence bit before assurance is derived.
Restart cannot clear them without the corresponding bounded
rescan/expiry/replacement, and ambient rejected garbage cannot set or clear
them.

Conflict rules are:

| Input                                                                           | Deterministic result                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Same `OperationId`                                                              | No-op.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Same carrier object ID and same bytes                                           | Carrier duplicate; no-op.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Same carrier object ID and different bytes                                      | Record carrier equivocation; independently validate both bytes and union every distinct valid logical operation recovered. Neither carrier branch is authoritative.                                                                                                                                                                                                                                                                                                                                                     |
| Invalid room AEAD, signature, context, codec, or bound                          | Drop as untrusted garbage before state mutation.                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| Same authenticated author sequence slot, different operations                   | Mark that author forked for the logical window and exclude its dependent state. For the pinned authority, every revoke carried by that faulted/overquota authority window is excluded before floor reduction; record the fault and make authority admission unavailable through the complete affected horizon. Revokes from other nonfaulted windows still reduce normally.                                                                                                                                             |
| Same authenticated pair-control slot, different authenticated pair operation ID | Fail only that stable pair edge, even if the plaintext is byte-equal.                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Distinct operation IDs in the same `PRESENCE`/`LEAVE` semantic slot             | While at least two branches are current or promoted as exact dependency evidence, mark that semantic subject forked and exclude both branches, every operation with an explicit dependency on either branch, and every later operation in either branch's same author/window chain. This applies even when decoded payloads are byte-equal; exact duplicates already have one `OperationId`, so no representative is selected.                                                                                          |
| `STORE_HINT` values for the same `(StoreId, descriptorGeneration)`              | Retain every live per-source fact at every generation. Equal `DescriptorHash` values preserve each exact source route subset and hint lease; delivery unions only currently live sources. At the greatest live generation, different current-live hashes retain all live branches plus one core fault and make that generation's projection inert. The client-global catalog also persists the canonical two-hash fork proof and requires a strictly higher singleton generation before that observer reuses the store. |
| Distinct valid `ADMISSION_REVOKE` values                                        | Retain every canonical fact and compute the applicable commitment floor by maximum generation at the queried reference window; never pick or flatten one tombstone by arrival order.                                                                                                                                                                                                                                                                                                                                    |
| Missing bounded dependency                                                      | Buffer only the dependent operation within room-policy dependency/window limits and local resource bytes.                                                                                                                                                                                                                                                                                                                                                                                                               |
| Operation after semantic expiry                                                 | Ignore for derived state; keep only bounded replay evidence if required.                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Store omission or stale frontier                                                | Continue union from other paths and report availability/consistency degradation.                                                                                                                                                                                                                                                                                                                                                                                                                                        |

Core semantic faults are reference-window facts, not unbounded tombstones. A
presence/leave fault disappears from a later `CoreRoomStateV1` after fewer than
two branches remain current or are promoted for a current dependency; an old
branch never becomes active merely because its sibling expired. The
client-global store-generation fork tombstone is deliberately different:
once observed, it persists until a strictly higher singleton generation, as
specified above.

The abstract grow-only set contains every successfully validated operation
inside its semantic horizon. It is never truncated to manufacture a
different, apparently convergent set. Physical custody and work are bounded
separately:

- presence, leave, and store-hint operations are ignored after
  `expiresAfterWindow + MaxClockSkewWindows(roomPolicy)`;
- their exact signed bytes may remain inert author-prefix evidence through the
  bounded maximum-descendant horizon defined in Section 4.4;
- a fresh presence or leave does not delete old bytes; the reducer selects the
  latest contiguous valid author-chain state inside the retained horizon;
- authority grants expire by their signed interval;
- revocation evidence is kept at least through the maximum affected grant
  lifetime;
- provisional pair steps expire after pair establishment or attempt timeout;
- each exact durable pair-control operation/outbox remains until the
  protocol-defined authenticated successor or pair-private checkpoint proves
  consumption; after that proof it may compact to `PqSlotAuditV1`, whose
  inclusive deletion horizon is derived from the accepted control window;
- if a required causal pair operation expires before that proof, the edge
  becomes `stalled` and requires a fresh hybrid handshake; expiry never
  guesses success, reopens a gate, or resets an epoch; and
- local physical deletion occurs only after every semantic and replay horizon
  has passed.

Before activating a profile, carrier, or import, the client computes its
worst-case candidate-object and byte contribution from the profile's public
geometry, retained windows, fixed inventories, and the local carrier policy.
It refuses activation when the combined bound exceeds any local cap. Each
reconciliation pass is also count- and byte-bounded. Dependency, pair-open,
provisional-edge, pair-ledger, outbox, and parser bounds are enforced before
expensive work. Candidate carrier objects and protected validated logical
operations use their separately named count/byte caps; neither is charged to
the other implicitly.

If accepted valid operations reach
`maxRetainedValidOperationsPerRoom` or
`maxRetainedValidOperationBytesPerRoom`, the client
does not evict a subset and continue claiming convergence. It stops accepting
new carrier work at a deterministic public scan/import boundary, persists
`overcapacity/partitioned`, and reports that its
`OuterValidOperationSet` may be
incomplete until capacity is raised or the horizon expires. Per-author
operation limits remain canonical validity rules because they can be checked
without arrival order. Strict authority/address-book proofs supply eligibility
and one-live-presence deduplication. In capability-open rooms an adversarial
holder can Sybil/grind until the physical bounds cause `overcapacity` or
`pair-control-DoS`; the protocol preserves memory safety and fails closed but
cannot promise honest progress or logical convergence in that state.

Convergence is a property of delivery, not store voting. Let a temporal graph
contain clients and carriers as vertices and successful custody/contact events
as time-labelled edges. Participants converge for an operation if a
time-respecting path carries it from its author to each participant before
expiry. A server need not share another server's state; a client or
authenticated peer can be the bridge. This theorem covers
`CoreRoomState`; local projections converge only when their frontend and
planner facts also match.

### 4.8 Frontend-governed peer admission

```ts
type FrontendRoomControlsV1 = {
  version: 1;
  policyGeneration: bigint;
  onlyConnectWithKnownPeers: boolean;
  allowedStableIdentityKeys: CanonicalBytes32SetV1;
  deniedStableIdentityKeys: CanonicalBytes32SetV1;
  deniedRoomIdentityCommitments: CanonicalBytes32SetV1;
};

type AdmissionGrantV1 = {
  version: 1;
  roomContextId: Bytes32;
  stableEd25519PublicKey: Bytes32;
  generation: bigint;
  issuedAtLogicalWindow: bigint;
  notBeforeLogicalWindow: bigint;
  notAfterLogicalWindow: bigint;
  authoritySignature: Bytes64;
};

type AdmissionRevokeV1 = {
  version: 1;
  roomContextId: Bytes32;
  stableIdentityCommitment: Bytes32;
  minimumAcceptedGeneration: bigint;
  effectiveLogicalWindow: bigint;
  expiresAfterLogicalWindow: bigint;
  authoritySignature: Bytes64;
};

type BootstrapAdmissionDecisionLeaseV1 = {
  version: 1;
  roomContextId: Bytes32;
  stableEd25519PublicKey: Bytes32;
  stableIdentityCommitment: Bytes32;
  grantId: Bytes32 | null;
  grantGeneration: bigint | null;
  localPolicyGeneration: bigint;
  authorityAdmissionStateDigest: Bytes32 | null;
  admittedPresenceOperationId: Bytes32;
  admittedIdentityOperationId: Bytes32;
  decidedAtLogicalWindow: bigint;
  validThroughLogicalWindow: bigint;
};

type StableEdgeAdmissionLeaseV1 = {
  version: 1;
  roomContextId: Bytes32;
  stableEdgeId: Bytes32;
  confirmedPairTranscriptId: Bytes32;
  rendezvousChannelId: Bytes32;
  v4WireBinding: Bytes32;
  remoteStableEd25519PublicKey: Bytes32;
  remoteStableIdentityCommitment: Bytes32;
  grantId: Bytes32 | null;
  grantGeneration: bigint | null;
  localPolicyGeneration: bigint;
  authorityAdmissionStateDigest: Bytes32 | null;
  decidedAtLogicalWindow: bigint;
  // Null only in capability mode. Authority mode is bounded by the grant.
  validThroughLogicalWindow: bigint | null;
};

type PairAttemptLeaseV1 = {
  version: 1;
  helloOperationId: Bytes32;
  pairEdgeId: Bytes32;
  endpointPresenceOperationIds: readonly [Bytes32, Bytes32];
  attemptMode: "planner" | "explicit";
  helloLogicalWindow: bigint;
  validThroughLogicalWindow: bigint;
};

declare const VERIFIED_ADMISSION_CONTEXT_V1: unique symbol;
declare const TRUSTED_ADMISSION_SNAPSHOT_V1: unique symbol;
declare const VERIFIED_PAIR_ATTEMPT_TOPOLOGY_V1: unique symbol;
declare const VERIFIED_AUTHORITY_VIEW_V1: unique symbol;
declare const VERIFIED_STABLE_EDGE_CONTEXT_V1: unique symbol;

// Module-private result of VerifyAdmissionContext. There is no public
// constructor, decoder, serializer, object-spread adapter, or type assertion
// for this local fact.
type VerifiedAdmissionContextV1 = {
  version: 1;
  roomContextId: Bytes32;
  decisionRole: "hello-responder" | "accept-initiator";
  operationId: Bytes32;
  kind: "IDENTITY_HELLO" | "IDENTITY_ACCEPT";
  logicalWindow: bigint;
  validThroughLogicalWindow: bigint;
  pairEdgeId: Bytes32;
  endpointPresenceOperationIds: readonly [Bytes32, Bytes32];
  direction: 0 | 1;
  pairSequence: bigint;
  previousPairOperationId: Bytes32 | null;
  pairDependencies: readonly Bytes32[];
  stableEd25519PublicKey: Bytes32;
  claimedStableIdentityCommitment: Bytes32;
  optionalGrant: AdmissionGrantV1 | null;
  pairIdentitySignatureHash: Bytes32;
  admittedPresenceOperationId: Bytes32;
  admittedPresenceEvidenceRetainThroughLogicalWindow: bigint;
  // Grant-agnostic horizon derived from authenticated pair coordinates.
  // Only Admit may narrow and persist it.
  basePairAttemptLease: PairAttemptLeaseV1;
  readonly [VERIFIED_ADMISSION_CONTEXT_V1]: true;
};

type AuthorityWindowFaultV1 = {
  logicalWindow: bigint;
  proofOperationIds: readonly Bytes32[];
};

type AuthorityCustodyProjectionV1 =
  | {
      status: "complete";
      authorityCustodyStateDigest: Bytes32;
      firstSaturatedRequiredWorkId: null;
    }
  | {
      status: "saturated";
      authorityCustodyStateDigest: Bytes32;
      firstSaturatedRequiredWorkId: Bytes32;
    };

// The one module-private current-state snapshot used by Project, bootstrap
// admission, and stable-edge reauthorization. There is no public constructor,
// decoder, serializer, object-spread adapter, or type assertion for it.
type TrustedAdmissionSnapshotV1 = {
  version: 1;
  roomContextId: Bytes32;
  roomPolicy: RoomPolicyV4;
  referenceWindow: bigint;
  coreRoomState: CoreRoomStateV1;
  frontendControls: FrontendRoomControlsV1 | null;
  authorityCustody: AuthorityCustodyProjectionV1 | null;
  localPresenceOwnership: VerifiedLocalPresenceOwnershipV1;
  readonly [TRUSTED_ADMISSION_SNAPSHOT_V1]: true;
};

// Pair-scoped, non-serializable topology result. It contains no reusable
// roster authority and cannot be reconstructed from LocalAdmissibleStateV1.
type VerifiedPairAttemptTopologyV1 = {
  version: 1;
  roomContextId: Bytes32;
  helloOperationId: Bytes32;
  helloLogicalWindow: bigint;
  pairEdgeId: Bytes32;
  endpointPresenceOperationIds: readonly [Bytes32, Bytes32];
  attemptMode: "planner" | "explicit";
  projectionSource: "current" | "hello-time-historical";
  sourceCoreOperationsDigest: Bytes32;
  evaluatedAtReferenceWindow: bigint;
  readonly [VERIFIED_PAIR_ATTEMPT_TOPOLOGY_V1]: true;
};

// Module-private, commitment-scoped result of the sole authority constructor.
type VerifiedAuthorityAdmissionViewV1 = {
  version: 1;
  roomContextId: Bytes32;
  stableIdentityCommitment: Bytes32;
  referenceWindow: bigint;
  status: "available" | "unavailable";
  revocationFacts: readonly CoreRevocationFloorV1[];
  blockingAuthorityWindowFaults: readonly AuthorityWindowFaultV1[];
  unavailableThroughLogicalWindow: bigint | null;
  sourceCoreOperationsDigest: Bytes32;
  authorityCustodyStateDigest: Bytes32;
  // Hashes only decision-relevant state. It deliberately excludes
  // referenceWindow, the whole core digest, and unrelated authority facts.
  authorityAdmissionStateDigest: Bytes32;
  // Full snapshot-scoped reproducibility/drift witness.
  viewDigest: Bytes32;
  readonly [VERIFIED_AUTHORITY_VIEW_V1]: true;
};

// Module-private result of confirming both identity flights and protocol-v4
// promotion. It is independent of rotating presence and pair-attempt leases.
type VerifiedStableEdgeContextV1 = {
  version: 1;
  roomContextId: Bytes32;
  stableEdgeId: Bytes32;
  confirmedPairTranscriptId: Bytes32;
  rendezvousChannelId: Bytes32;
  v4WireBinding: Bytes32;
  remoteStableEd25519PublicKey: Bytes32;
  remoteStableIdentityCommitment: Bytes32;
  latestAdmissionGrant: AdmissionGrantV1 | null;
  latestAdmissionGrantCarriedAtLogicalWindow: bigint | null;
  readonly [VERIFIED_STABLE_EDGE_CONTEXT_V1]: true;
};

type AdmissionInputError = Error & {
  name: "AdmissionInputError";
  code: "invalid-admission-kernel-input";
};

type PairAdmissionDecision =
  | {
      result: "allow";
      reason: "open" | "address-book" | "authority-grant";
      bootstrapLease: BootstrapAdmissionDecisionLeaseV1;
      pairAttemptLease: PairAttemptLeaseV1;
    }
  | {
      result: "deny";
      reason:
        | "blacklisted"
        | "not-in-address-book"
        | "missing-grant"
        | "invalid-grant"
        | "revoked"
        | "policy-unavailable";
    };

type StableEdgeAdmissionDecision =
  | {
      result: "allow";
      reason: "open" | "address-book" | "authority-grant";
      lease: StableEdgeAdmissionLeaseV1;
    }
  | {
      result: "deny";
      reason:
        | "blacklisted"
        | "not-in-address-book"
        | "missing-grant"
        | "invalid-grant"
        | "revoked"
        | "policy-unavailable";
    };
```

`VerifyAdmissionContext` is the sole constructor for
`VerifiedAdmissionContextV1`. It is module-private and consumes one exact,
atomically captured edge projection: the immutable room policy/context,
explicit reference window and decision role, exact outer
`AuthenticatedRoomOperationV1`, its
`PairOuterBindingV1`, the successfully opened identity `PairPlaintextV1`, the
exact retained `HistoricalPairPresenceEvidenceV1`, and the module-private
current pair-attempt state. For a responder's first HELLO it derives the
grant-agnostic `basePairAttemptLease`; for ACCEPT it loads and revalidates the
persisted admitted HELLO lease. It does not trust a field merely
because a caller named it “verified.” It:

1. revalidates the closed outer and pair codecs, room-context confirmation,
   `PolicyHash`, outer signature, pair AEAD result, and recomputed
   `OperationId`;
2. recomputes `PairEdgeId` from the room context and exact ordered endpoint
   presence IDs;
3. checks the decision-role tuple index, kind, direction, sequence,
   predecessor, HELLO dependency, and exact presence-operation ID, then
   derives/recomputes rather than accepts the pair-attempt
   coordinates/mode/horizon;
4. decodes and revalidates the retained presence bytes, recomputes their
   operation ID, requires that presence to have been valid at the HELLO
   logical window, and derives the evidence retention horizon from that record
   rather than accepting a scalar;
5. recomputes `StableIdentityCommitment`, the complete
   `PairIdentitySignatureHash`, and verifies the stable Ed25519 transcript
   signature and presence commitment; and
6. copies the optional grant only after all of those bindings succeed.

Failure produces `AdmissionInputError` and no branded value. The brand and
constructor are not exported; raw network bytes, JSON, IndexedDB records,
public SDK inputs, object spread, and TypeScript assertions cannot instantiate
the type. This is a client-kernel architecture boundary, not a cryptographic
sandbox inside one compromised JavaScript realm: code execution in the trusted
worker/module, browser, OS, or storage transaction can bypass local policy and
remains an explicit platform-compromise nonclaim.

`CaptureTrustedAdmissionSnapshot(transaction, initializedRoom,
referenceWindow)` is the sole constructor for
`TrustedAdmissionSnapshotV1`. It owns one atomic read-only capture of the
immutable room policy/context, exact `CoreRoomStateV1`, current frontend
controls, protected authority custody, canonical
`LocalPresenceOwnershipRecordV1`, and the exact local author, stable-identity,
and receiver-key records needed to verify it. It requires the core reference
window and initialized room policy/context to match exactly. After the read
transaction completes, its sole private verifier derives every listed stable
public key from a currently custodied local key handle and, for every claimed
local presence operation ID:

1. finds the exact retained Core fact and re-derives its operation ID;
2. binds its author key to current local author/private-key custody;
3. binds its stable commitment to exactly one listed locally custodied stable
   key and verifies the presence ownership signature; and
4. binds its advertised hybrid receiver key to current local receiver-key
   custody and revision.

Every claimed local presence corresponds to exactly one listed key; a
currently custodied local stable key may remain listed without a currently
owned presence. Both sets are complete for the captured local identity/key
revision, canonical, and duplicate-free rather than caller-selected subsets.
Only that complete verification mints
`VerifiedLocalPresenceOwnershipV1`; canonical decoding of the persisted record
alone never does. In authority mode, a missing, ambiguous,
rollback-failed, or saturated custody source is represented faithfully and
never becomes an empty complete partition; in capability mode authority
custody is canonically null. The branded result is ephemeral trusted state,
not persisted or decoded. Its private side-table entry is bound by object
identity to the exact Core/snapshot/key capture; object spread, structured
clone, deserialization, or a TypeScript assertion cannot recreate it.

In the browser adapter, that read transaction copies every exact canonical
projection and must reach `transaction.oncomplete` before signature, KEM,
authority-view, or other asynchronous work begins. No cryptographic or other
promise is awaited while an IndexedDB transaction is live.

The public effectful boundary `EvaluateBootstrapAdmissionAndPersist` owns one
logical optimistic admission transaction:

```text
atomic read-only capture
→ transaction.oncomplete
→ construct branded snapshot/context
→ asynchronous verification + current/historical opaque pair projection
→ pure Admit + exact response preparation
→ one atomic readwrite CAS of every captured fence
→ persist pair-attempt lease + bootstrap lease + pair/author state
  + exact response custody + outbox
→ transaction.oncomplete
→ report committed
```

This is not one continuously live IndexedDB transaction. Any exact-fence
mismatch aborts every write, publishes no byte, discards and wipes the prepared
mutation, and returns the closed retry/stale result that requires recapture.
The write transaction compares, in a fixed order, the exact initialized-room
policy/context, current Core bytes, HELLO-time historical-evidence view,
receiver-key revision, local-presence ownership, frontend controls,
authority-custody projection, planner/on-demand state, local identity/key
revision, local author-chain head, pair ledger, provisional pair record, and
bounded outbox/resource state captured by the read transaction. A digest may
index a row but never replaces exact canonical-byte or exact-absence
comparison. The adapter performs no cryptography while the write transaction
is live and reports success only from `transaction.oncomplete`.
The private topology handle remains valid only while all of its
current/historical Core, endpoint evidence, ownership/key,
frontend/authority, planner/on-demand, degree/ledger, and count/byte resource
fences compare exactly; any mismatch discards it and emits no sensitive byte.

One private policy kernel is the SSOT for both bootstrap and stable-edge
decisions:

```text
EvaluatePeerAdmissionPolicy(
  snapshot: TrustedAdmissionSnapshotV1,
  stableEd25519PublicKey: Bytes32,
  stableIdentityCommitment: Bytes32,
  optionalGrant: AdmissionGrantV1 | null,
  grantCarriedAtLogicalWindow: bigint | null
):
  require snapshot was created by CaptureTrustedAdmissionSnapshot
  roomPolicy = snapshot.roomPolicy
  referenceWindow = snapshot.referenceWindow
  frontendControls = snapshot.frontendControls
  if frontendControls is null:
      DENY(policy-unavailable)

  require StableIdentityCommitment(
    snapshot.roomContextId,
    stableEd25519PublicKey
  ) == stableIdentityCommitment

  if stableEd25519PublicKey is in
       frontendControls.deniedStableIdentityKeys
     or stableIdentityCommitment is in
       frontendControls.deniedRoomIdentityCommitments:
      DENY(blacklisted)

  if roomPolicy requires authority grant:
      if snapshot.authorityCustody is null:
        DENY(policy-unavailable)
      authorityView =
        DeriveAuthorityAdmissionView(snapshot, stableIdentityCommitment)
      if authorityView.status != "available":
        DENY(policy-unavailable)
      if optionalGrant is null:
        DENY(missing-grant)
      if grantCarriedAtLogicalWindow is null:
        DENY(invalid-grant)
      require a valid grant for the exact room and stable key, signed by the
        pinned authority, with:
          issuedAtLogicalWindow
            <= grantCarriedAtLogicalWindow
            <= referenceWindow
          issuedAtLogicalWindow
            <= notBeforeLogicalWindow
            <= referenceWindow
            <= notAfterLogicalWindow
          notAfterLogicalWindow - issuedAtLogicalWindow
            <=
              roomPolicy.admissionFloor
                .maxAuthorityCredentialLifetimeWindows
        otherwise DENY(invalid-grant)
      require AuthorityGenerationAllowed(
        optionalGrant.generation,
        authorityView
      ),
        otherwise DENY(revoked)
      grantId = AdmissionGrantId(optionalGrant)
      grantGeneration = optionalGrant.generation
      authorityAdmissionStateDigest =
        authorityView.authorityAdmissionStateDigest
      grantValidThroughLogicalWindow =
        optionalGrant.notAfterLogicalWindow
  else:
      require snapshot.authorityCustody == null
      require optionalGrant == null, otherwise DENY(invalid-grant)
      require grantCarriedAtLogicalWindow == null,
        otherwise DENY(invalid-grant)
      grantId = null
      grantGeneration = null
      authorityAdmissionStateDigest = null
      grantValidThroughLogicalWindow = null

  if frontendControls.onlyConnectWithKnownPeers:
      require stableEd25519PublicKey in
        frontendControls.allowedStableIdentityKeys,
        otherwise DENY(not-in-address-book)

  return ALLOW_POLICY(
    reason =
      authority-grant if roomPolicy requires it,
      else address-book if frontendControls.onlyConnectWithKnownPeers,
      else open,
    localPolicyGeneration=frontendControls.policyGeneration,
    grantId,
    grantGeneration,
    authorityAdmissionStateDigest,
    grantValidThroughLogicalWindow
  )

Admit(snapshot: TrustedAdmissionSnapshotV1,
      ctx: VerifiedAdmissionContextV1,
      topology: VerifiedPairAttemptTopologyV1):
  require ctx was created by VerifyAdmissionContext
  require topology was created by the sole current or historical pair
    projection constructor for this exact snapshot/context/planner/resource
    capture
  require ctx.roomContextId == snapshot.roomContextId
  require topology.roomContextId == ctx.roomContextId
  require topology.helloOperationId ==
    ctx.basePairAttemptLease.helloOperationId
  require topology.helloLogicalWindow ==
    ctx.basePairAttemptLease.helloLogicalWindow
  require topology.pairEdgeId == ctx.pairEdgeId
  require topology.endpointPresenceOperationIds ==
    ctx.endpointPresenceOperationIds
  require topology.attemptMode ==
    ctx.basePairAttemptLease.attemptMode
  require topology.evaluatedAtReferenceWindow == snapshot.referenceWindow
  require ctx.logicalWindow
    <= snapshot.referenceWindow
    <= ctx.validThroughLogicalWindow

  policy = EvaluatePeerAdmissionPolicy(
    snapshot,
    ctx.stableEd25519PublicKey,
    ctx.claimedStableIdentityCommitment,
    ctx.optionalGrant,
    ctx.logicalWindow if ctx.optionalGrant != null else null
  )
  if policy is DENY: return policy

  pairAttemptValidThrough =
    ctx.basePairAttemptLease.validThroughLogicalWindow
  if policy.grantValidThroughLogicalWindow != null:
    pairAttemptValidThrough = min(
      pairAttemptValidThrough,
      policy.grantValidThroughLogicalWindow
    )
  admittedPairAttemptLease =
    ctx.basePairAttemptLease with
      validThroughLogicalWindow = pairAttemptValidThrough

  leaseHorizons = [
    admittedPairAttemptLease.validThroughLogicalWindow,
    ctx.admittedPresenceEvidenceRetainThroughLogicalWindow,
    ctx.validThroughLogicalWindow
  ]
  validThrough = min(leaseHorizons)
  require snapshot.referenceWindow <= validThrough,
    otherwise DENY(policy-unavailable)

  bootstrapLease =
    BootstrapAdmissionDecisionLeaseV1{
      version=1,
      roomContextId=snapshot.roomContextId,
      stableEd25519PublicKey=ctx.stableEd25519PublicKey,
      stableIdentityCommitment=ctx.claimedStableIdentityCommitment,
      grantId=policy.grantId,
      grantGeneration=policy.grantGeneration,
      localPolicyGeneration=policy.localPolicyGeneration,
      authorityAdmissionStateDigest=policy.authorityAdmissionStateDigest,
      admittedPresenceOperationId=ctx.admittedPresenceOperationId,
      admittedIdentityOperationId=ctx.operationId,
      decidedAtLogicalWindow=snapshot.referenceWindow,
      validThroughLogicalWindow=validThrough
    }
  return ALLOW(
    policy.reason,
    bootstrapLease,
    admittedPairAttemptLease
  )
```

`Admit()` is the module-private pure phase of composite kernel entrypoint 3,
not another manifest entrypoint. Its signature above specifies the internal
refinement boundary; the opaque topology argument is created and consumed
within one `project-and-admit` invocation. It performs no persistence or
network action. A policy allow without the genuine pair-scoped topology
handle is still pre-topology and cannot prepare, persist, or publish a
response. Only the effectful wrapper above may capture the trusted inputs or
atomically persist the returned leases with the exact outbound intent.
`EvaluateBootstrapAdmissionAndPersist` persists exactly the
`pairAttemptLease` returned by `Admit`; no opener, caller, adapter, or later
flight may persist or reconstruct `basePairAttemptLease`. A failed top-level
canonical shape, version, role/flight coordinate, transcript fact,
room-policy/context, trusted-provenance check, or impossible interval raises
`AdmissionInputError`; the caller fails closed and emits only the same
fixed-schedule dummy/no-response behavior as any denial. These are local
kernel/provenance failures, not remotely distinguishable policy reasons.
Missing frontend state or an absent/unavailable authority view returns
`DENY(policy-unavailable)`. A well-framed but wrong, malformed, expired,
wrong-room, wrong-key, future-issued, excessive-lifetime, or bad-signature
grant returns `DENY(invalid-grant)`.

`ConstructVerifiedStableEdgeContext` is the sole module-private constructor
for `VerifiedStableEdgeContextV1`. It runs at protocol-v4 promotion from the
endpoint's verified remote bootstrap context, matching current bootstrap
lease, local stable identity, confirmed two-flight transcript, transport
transcript, and authenticated protocol-v4 promotion output in one transaction.
It recomputes `StableEdgeId`, `ConfirmedPairTranscriptId`, and
`RendezvousChannelId`; requires the exact current
`PqHealingMachine.binding` as `v4WireBinding`; binds the remote stable
key/commitment and latest accepted grant plus the exact logical window that
carried it; and requires the bootstrap coordinates and v4 stable identities to
match. It contains no rotating-presence validity requirement. The promotion
transaction immediately calls `ReauthorizeStableEdge` with its fresh trusted
snapshot and atomically persists the canonical promoted-edge record, replaces
the bootstrap lease with the first stable-edge lease, and erases provisional
secrets; a promotion that cannot obtain that allow is not exposed to the
application.

`LoadVerifiedStableEdgeContext(transaction, stableEdgeId)` is the only other
trusted path, needed after restart. It reads that canonical durable
promoted-edge record inside the same stable-edge transaction, rejects a
replaced/stalled/noncurrent record, and recomputes the room-bound
`StableEdgeId`, `ConfirmedPairTranscriptId`, `RendezvousChannelId`, remote
stable key/commitment, retained grant/carrier logical window, and exact current
v4 binding before restoring the process-local brand. A symbol/nominal brand is
never serialized, and a generic IndexedDB decoder cannot restore it.

`ReauthorizeStableEdge(snapshot, stableContext)` first verifies both private
provenance brands, exact room binding, and stable transcript, then calls the
same `EvaluatePeerAdmissionPolicy` with the remote key/commitment, latest
grant, and its exact carrying logical window. It has no duplicate
allow/deny/address-book/authority order. On policy success it returns:

```text
StableEdgeAdmissionLeaseV1{
  version=1,
  roomContextId=snapshot.roomContextId,
  stableEdgeId=stableContext.stableEdgeId,
  confirmedPairTranscriptId=stableContext.confirmedPairTranscriptId,
  rendezvousChannelId=stableContext.rendezvousChannelId,
  v4WireBinding=stableContext.v4WireBinding,
  remoteStableEd25519PublicKey=
    stableContext.remoteStableEd25519PublicKey,
  remoteStableIdentityCommitment=
    stableContext.remoteStableIdentityCommitment,
  grantId=policy.grantId,
  grantGeneration=policy.grantGeneration,
  localPolicyGeneration=policy.localPolicyGeneration,
  authorityAdmissionStateDigest=policy.authorityAdmissionStateDigest,
  decidedAtLogicalWindow=snapshot.referenceWindow,
  validThroughLogicalWindow=policy.grantValidThroughLogicalWindow
}
```

Authority mode therefore sets the finite horizon to the grant's
`notAfterLogicalWindow`; capability mode sets it to null. Both modes bind the
exact current frontend policy generation. Authority mode additionally binds
`authorityAdmissionStateDigest`; that digest changes only when the
commitment's decision-relevant revoke/fault/custody state changes, not merely
because a reference window advances or an unrelated room operation arrives.

`AuthorizeStableEdgeActionAndPersist` is the sole post-promotion effectful
boundary. In one transaction it captures a fresh
`TrustedAdmissionSnapshotV1`, obtains the opaque stable-edge context through
`LoadVerifiedStableEdgeContext`, and calls `ReauthorizeStableEdge`; a stored
lease is evidence/audit state and
never skips this current policy call. Only then does it atomically persist the
replacement lease and exact outbound/dispatch intent. Presence evidence,
identity-operation expiry, and `PairAttemptLeaseV1` are not inputs after
promotion. A current deny, policy lookup failure, authority-view
unavailability, state-digest change that cannot be reauthorized, or expired
grant permits no post-promotion application, reconnect, transport, or pair
control action. In v1, authority-grant renewal is a fresh automatic pair
attempt carrying a new grant; the frontend preserves the room/invitation UX
but does not pretend an expired stable edge remains authorized. A future
pair-private in-place credential-refresh step may remove that interruption
only after its PQ slot, replay, causal, expiry, and atomic-persistence rules
are frozen.

The Phase-0 binary schema uses declaration order for the wire admission
objects.
Every `version`, closed enum, direction, and status tag is one unsigned byte;
every logical window, generation, and policy generation is unsigned 64-bit;
every named digest/key is fixed 32 bytes; and every Ed25519 signature is fixed
64 bytes. `AdmissionGrantV1` and `AdmissionRevokeV1` each have one unsigned
projection consisting of every declaration-order field preceding
`authoritySignature`; their signature transcripts and `AdmissionGrantId` use
that projection/complete signed record respectively. Optional values use one
closed presence byte, endpoint tuples have exactly two entries, and all
variable operation-ID/fact arrays are bounded, bytewise canonical, and
duplicate-free. The companion schema and vectors—not TypeScript object
property order—remain the byte SSOT. The branded contexts, snapshots, views,
and leases are local kernel/persistence facts: they have
versioned canonical persistence schemas where needed, but no untrusted wire
decoder can produce their private provenance brands.

Local denial wins over a grant and over the address book. A remote operation
cannot remove a local deny. `ADMISSION_REVOKE` is accepted only when signed by
the policy-pinned authority and is eventually replicated like any other
operation. Because a carrier may withhold it, remote revocation is not
instantaneous; short grant lifetime bounds that stale window. The local
frontend can deny immediately.

Authority mode and `onlyConnectWithKnownPeers=true` are cumulative: the peer
must pass both gates, and the deterministic success reason is
`"authority-grant"`. The reason is diagnostic only and never changes the
lease or authorization result.

`FrontendRoomControlsV1` is one room-local atomically replaced object.
`policyGeneration` is unsigned, increases monotonically on every effective
allow/deny/address-book/mode change, and is persisted before any newly
permitted action. A delete, deny, migration, rollback/fork, or unavailable
policy lookup that the current process detects invalidates outstanding
admission leases before response construction. The shared
`EvaluatePeerAdmissionPolicy()` compares
only decoded canonical bytes from `CanonicalBytes32SetV1`; it never reparses an
unchecked identifier string at a sensitive boundary.

A whole older local snapshot can predate a private blacklist and is not
locally detectable without an external non-rollback/synchronization anchor.
Absent such an anchor or later peer evidence, the successfully loaded restored
`FrontendRoomControlsV1` is the current local SSOT; this specification does not
claim durability of a forgotten deny across whole-device rollback. The
sole-server SDP theorem is conditioned on each endpoint's current successfully
loaded policy. Platforms claiming stronger local-policy rollback resistance
must name and test their monotonic anchor.

```text
AdmissionGrantId =
  H("p2party/admission-grant/v1" || Canonical(AdmissionGrantV1))

AdmissionGrantSignedMessage =
  "p2party/admission-grant-signature/v1" ||
  H(Canonical(AdmissionGrantV1 without authoritySignature))

AdmissionRevokeSignedMessage =
  "p2party/admission-revoke-signature/v1" ||
  H(Canonical(AdmissionRevokeV1 without authoritySignature))

PresencePermitSignedMessage =
  "p2party/presence-permit-signature/v1" ||
  H(Canonical(PresencePermitV1 without authoritySignature))
```

A revocation names only the room-scoped commitment and never serializes the raw
stable key. Grant-specific tombstones are deliberately absent: grants and
permits share one unsigned-64-bit authority generation namespace per
`(RoomContextId, StableIdentityCommitment)`. The pinned authority monotonically
increments it. Among effective, unexpired revocations, the maximum
`minimumAcceptedGeneration` is the floor, and either credential is allowed only
when `generation >= floor`.

One `AuthorityGenerationAllowed(generation, authorityView)` function is used
by authority presence projection before HELLO and by
`EvaluatePeerAdmissionPolicy()`, invoked through `Admit()` before promotion and
`ReauthorizeStableEdge()` afterward. The view is already scoped to one room
commitment and reference window by its sole constructor. Revocations are
monotone deny facts: distinct valid floors coexist and reduce by maximum rather
than forking. Exact duplicates are no-ops, while two differently signed
operations in one authority author/sequence slot are still ordinary authority
forks.

```text
ApplicableRevocationFacts(commitment, referenceWindow) =
  Sort(
    {
      fact |
      fact.stableIdentityCommitment == commitment
      and fact.effectiveLogicalWindow <= referenceWindow
      and referenceWindow <= fact.validThroughLogicalWindow
    },
    (
      minimumAcceptedGeneration,
      effectiveLogicalWindow,
      validThroughLogicalWindow,
      revokeOperationId
    )
  )

AuthorityGenerationAllowed(generation, authorityView) =
  authorityView.status == "available"
  and (
    authorityView.revocationFacts is empty
    or generation >=
      max(
        fact.minimumAcceptedGeneration
        for fact in authorityView.revocationFacts
      )
  )
```

`DeriveAuthorityAdmissionView(snapshot, commitment)` is the sole constructor
for `VerifiedAuthorityAdmissionViewV1`. It accepts only a
`TrustedAdmissionSnapshotV1` with private provenance. It reads every retained
`CoreRevocationFloorV1` directly from `snapshot.coreRoomState`, projects every
`author-fork-or-overquota` fault whose author is the room-policy-pinned
authority into `AuthorityWindowFaultV1`, and consumes
`snapshot.authorityCustody`. The trusted snapshot constructor permits
`authorityCustody.status="complete"` only when every required authority
operation, revocation fact, fault, predecessor, saturation witness, and
retained horizon fits. A retained authority fork is represented in the
projected fault set. The first known required item that did not fit produces
`status="saturated"` and its bytewise-lowest required-work ID. A missing,
failed, ambiguous, or rollback-detected authority source never becomes empty
complete custody.

`revocationFacts` is sorted by
`(stableIdentityCommitment, minimumAcceptedGeneration,
effectiveLogicalWindow, validThroughLogicalWindow, revokeOperationId)`.
The projected authority faults are sorted by
`(logicalWindow, canonical proofOperationIds)`, and every proof list is sorted
and duplicate-free. The custody digest covers the complete bounded retained
authority partition and saturation state. No caller supplies a separate
availability boolean, revocation list, fault list, completeness bit, source
digest, or custody digest. The derived view carries its own private provenance
brand and has no wire or public persistence decoder. Its public digests are
deterministic drift/audit witnesses only; an unkeyed self-hash is never treated
as proof that omitted source facts never existed.

The constructor selects
`ApplicableRevocationFacts(commitment, snapshot.referenceWindow)` and every
projected authority window fault for which:

```text
fault.logicalWindow
  <= snapshot.referenceWindow
  <= AuthorityFaultValidThrough(snapshot.roomPolicy, fault.logicalWindow)
```

The selected faults become `blockingAuthorityWindowFaults`. The derived status
is unavailable when that array is nonempty or custody is saturated. If custody
is complete and selected faults are empty, status is available and
`unavailableThroughLogicalWindow=null`. If only known selected faults block
it, the unavailable horizon is their maximum recomputed
`AuthorityFaultValidThrough(snapshot.roomPolicy, fault.logicalWindow)`; if
custody is
saturated, the horizon is null because the missing fact may have a later
defensible horizon. Missing trusted state is handled by `Admit()` as
`policy-unavailable`, never as an empty available view. Status, not nullness,
decides availability.

```text
AuthorityAdmissionStateDigest =
  H(
    "p2party/authority-admission-state/v1" ||
    Canonical(
      roomContextId,
      stableIdentityCommitment,
      status,
      revocationFacts,
      blockingAuthorityWindowFaults,
      snapshot.authorityCustody.status,
      snapshot.authorityCustody.firstSaturatedRequiredWorkId
    )
  )

AuthorityAdmissionViewDigest =
  H(
    "p2party/authority-admission-view/v1" ||
    Canonical(
      serializable fields of VerifiedAuthorityAdmissionViewV1
      without viewDigest
    )
  )
```

The state digest deliberately omits `referenceWindow`,
`sourceCoreOperationsDigest`, `authorityCustodyStateDigest`, and unrelated
authority facts. Their full values remain in `viewDigest` for drift/audit
evidence. This makes a stable-edge lease sensitive to every fact that can
change its admission decision without invalidating it every logical window or
when an unrelated room/authority operation arrives.

The admission transaction loads the current frontend policy generation and
constructs the snapshot/view from the same atomic source; it may not accept a
persisted earlier view or caller projection. Before a bootstrap lease is used,
the same wrapper reconstructs the current view and requires the exact policy
generation, decision-state digest, coordinates, and finite horizon still to
match, or reruns `Admit()` from its still-valid opaque bootstrap context.
After stable promotion it instead uses
`AuthorizeStableEdgeActionAndPersist`, which never depends on the expired
bootstrap context. Phase 0 freezes both authority constructors, the custody
input projection, ordering, negative vectors, and canonical digests before
the admission kernel is called interoperable.

The fact array, not a singular flattened floor, is the SSOT. Equal maximum
generations with different effective/valid-through windows remain distinct
and therefore yield the same answer under every delivery permutation.

```text
AuthorityFaultValidThrough(roomPolicy, faultWindow) =
  require roomPolicy.admissionFloor.mode == "authority-grant"
  checkedAdd(
    checkedAdd(
      faultWindow,
      roomPolicy.protocolLimits.maxFutureLogicalWindows
    ),
    checkedAdd(
      roomPolicy.admissionFloor.maxAuthorityCredentialLifetimeWindows,
      roomPolicy.protocolLimits.maxClockSkewWindows
    )
  )

```

Both authority presence projection and `Admit()` consume the sole derived view
and require `status="available"`; failure is local `policy-unavailable`, never
an old-grant allow. There is no second `AuthorityAdmissionAvailable`
predicate.

For canonical `GRANT_HORIZON` encoding, a revocation is immediate and exact:

```text
effectiveLogicalWindow == outer.logicalWindow
expiresAfterLogicalWindow
  == checkedAdd(
       checkedAdd(
         effectiveLogicalWindow,
         roomPolicy.protocolLimits.maxFutureLogicalWindows
       ),
       roomPolicy.admissionFloor.maxAuthorityCredentialLifetimeWindows
     )
outer.expiresAfterWindow == expiresAfterLogicalWindow
```

The extra `roomPolicy.protocolLimits.maxFutureLogicalWindows` covers an already
admitted bounded-future presence or identity operation carrying a credential
issued after the revocation's effective window; that credential's own maximum
lifetime has also elapsed before the floor leaves the reconstructable set. A conforming
pinned authority encodes its actual current room logical window as
`issuedAtLogicalWindow`, never pre-signs a future issuance window, durably
remembers each commitment's generation floor, and never later issues a
credential below it. The authority is a policy trust anchor: a
malicious authority can always issue a higher generation and authorize a peer,
so no client-side cache is misrepresented as protection from that authority.

The policy-pinned authority signs the complete prefixed message for each
object above, never its bare 32-byte hash. Verification first enforces the
closed canonical codec, exact room context, validity domain, and policy key.

An initial allow persists exactly the bootstrap lease returned by `Admit()`.
Its temporal horizon is the minimum defined above. “Presence horizon” means
`HistoricalPairPresenceEvidenceV1.retainThroughLogicalWindow`, so courier
delivery does not incorrectly require the rotating presence to remain in the
current roster. That lease gates only identity response, transport
offer/answer, SDP/ICE, and protocol-v4 bootstrap through promotion. The stable
lease returned by `ReauthorizeStableEdge` gates later work without extending
or reusing the bootstrap evidence. Local policy and revocation have no
invented future time horizon: each lease binds the exact policy generation and
decision-state digest and the wrapper reloads/rechecks them before every use.
A lease is evidence of the last allow, never an authorization cache.

Before dispatch of an identity response, transport offer/answer, SDP/ICE, or
pre-promotion v4 handshake, the frontend atomically requires the matching
unexpired bootstrap lease, local policy generation,
room/key/commitment/presence/identity/pair coordinates, and current
deny/revocation/authority state. Before reconnect, admitted
application/data-plane work, or post-promotion pair control, it instead
requires the matching stable-edge lease and stable transcript; it must not
consult an expired presence or pair-attempt record. The successful recheck and
exact outbound/dispatch intent commit atomically. A changed or unavailable
policy/view invalidates the relevant lease unless the same transaction
successfully reauthorizes it. A later deny/revoke tears down future use, but
bytes already pair-encrypted and published cannot be clawed back; the UI and
audit log must not imply retroactive secrecy.

The stable room commitment is:

```text
StableIdentityCommitment =
  H(
    "p2party/stable-identity-commitment/v1" ||
    RoomContextId ||
    stableEd25519PublicKey
  )

LocalPeerIdDigest =
  H(
    "p2party/local-peer-id/v1" ||
    RoomContextId ||
    StableIdentityCommitment
  )

LocalPeerId =
  "peer.v1." || Base64urlNoPad(LocalPeerIdDigest)
```

Presence reveals this commitment only inside room encryption. It is a
room-scoped pseudonym, not key hiding: a capability holder that knows a
candidate public key can recompute it and test the guess. An
address-book-only frontend can match known keys without publishing a stable
key to the cohort. During pair identity exchange, the peer reveals the exact
stable key inside pair encryption and signs the transcript; the verifier
recomputes the commitment. A false commitment can at most induce bounded
provisional work and cannot pass promotion. `LocalPeerId` is a non-secret,
room-scoped application handle for an admitted stable identity. It never
crosses a carrier and cannot correlate the same identity across rooms.

Every code path that currently uses `getDBPeerIsBlacklisted`,
`getDBAddressBookEntry`, or `onlyConnectWithKnownPeers` shall call the shared
admission function rather than reimplementing the order. A storage failure
continues the current fail-closed behavior for the affected peer.
Address-book and blacklist persistence is migrated to the exact stable
Ed25519 key as its primary identity, with the room commitment as a derived
index. A legacy server-scoped `peerId`—stable only for one server
database/public key and nonportable across stores, reinstalls, or key
replacement—is never preferred over or substituted for that key. Legacy rows
are resolved and committed before blind presence; an ambiguous/unmigrated row
is policy-unavailable and therefore denied.

### 4.9 Presence, observed roster, and room isolation

```ts
type PresenceCoreV1 = {
  version: 1;
  stableIdentityCommitment: Bytes32;

  // Suite-1 MLKEM768-X25519 public key for pair-private bootstrap.
  rendezvousHybridKemPublicKey: Uint8Array; // exactly 1,216 bytes
  receiverKeyValidThroughLogicalWindow: bigint;

  presenceNonce: Bytes32;
  validThroughLogicalWindow: bigint;
};

type PresencePermitV1 = {
  version: 1;
  roomContextId: Bytes32;
  presenceProofTranscriptHash: Bytes32;
  permitSerial: Bytes32;
  generation: bigint;
  issuedAtLogicalWindow: bigint;
  notBeforeLogicalWindow: bigint;
  notAfterLogicalWindow: bigint;
  authoritySignature: Bytes64;
};

type PresenceV1 = {
  core: PresenceCoreV1;
  stableOwnershipSignature: Bytes64;
  authorityPermit: PresencePermitV1 | null;
};

type LeaveV1 = {
  version: 1;
  presenceOperationId: Bytes32;
  effectiveLogicalWindow: bigint;
};

type ObservedPresenceV1 = {
  presenceOperationId: Bytes32;
  authorEpochEd25519Key: Bytes32;
  stableIdentityCommitment: Bytes32;
  rank: Bytes32;
  eligibility: "open" | "local-address-book-proved" | "authority-permit-proved";
  status: "active";
};

type HistoricalPairPresenceEvidenceV1 = {
  exactPresenceOperationBytes: Uint8Array;
  presenceOperationId: Bytes32;
  retainThroughLogicalWindow: bigint;
};

declare const VERIFIED_HISTORICAL_LOCAL_PRESENCE_CUSTODY_V1: unique symbol;

// Module-private proof that one exact historical local presence remains
// operable for one HELLO window. This is neither the structural ownership row
// nor the current-Core ownership brand.
type VerifiedHistoricalLocalPresenceCustodyV1 = {
  version: 1;
  roomContextId: Bytes32;
  helloLogicalWindow: bigint;
  localPresenceOperationId: Bytes32;
  sourceHistoricalCoreOperationsDigest: Bytes32;
  stableEd25519PublicKey: Bytes32;
  rendezvousHybridKemPublicKey: Uint8Array; // exactly 1,216 bytes
  stableKeyCustodyRecordRevision: bigint;
  receiverKeyCustodyRecordRevision: bigint;
  readonly [VERIFIED_HISTORICAL_LOCAL_PRESENCE_CUSTODY_V1]: true;
};
```

A `PRESENCE` payload is inside the canonical room operation. Its
`authorEpochEd25519Key` signs the operation and anchors the bounded author
chain. The canonical eligibility transcript is:

```text
PresenceProofTranscript =
  Canonical(
    RoomContextId,
    PolicyHash,
    logicalWindow,
    authorEpochEd25519Key,
    PresenceCoreV1
  )

PresenceProofTranscriptHash =
  H(
    "p2party/presence-proof/v1" ||
    PresenceProofTranscript
  )

PresenceOwnershipSignedMessage =
  "p2party/presence-ownership-signature/v1" ||
  PresenceProofTranscriptHash
```

Every presence carries the stable Ed25519 signature of
`PresenceOwnershipSignedMessage`, not a bare 32-byte challenge-compatible
value. An open receiver need not identify the signer before selecting a
candidate. A local address-book receiver verifies it against its allowed keys
and checks that the matched key recomputes the commitment. Thus a peer
published under open local settings remains reachable by another peer with
strict local settings. The raw stable key is not published.

In capability-mode rooms, `authorityPermit` is canonically null; a non-null
permit is a cross-mode encoding error, not an optional credential. When
canonical authority admission is required, `authorityPermit` is mandatory
and the pinned authority signs the exact
`presenceProofTranscriptHash = H("p2party/presence-proof/v1" ||
PresenceProofTranscript)`, serial, generation, and validity
through `PresencePermitSignedMessage`. The hash binds the outer author key and
logical window as well as the complete core, so a capability holder cannot
copy the permit into a grindable author operation. At any explicit
`referenceWindow`, at most one overlapping live presence for each
`(permitSerial,generation)` is eligible; duplicates across all of their
logical windows select the lowest canonical presence operation ID and all
other uses are permit-equivocation evidence.

Both permits and admission grants require, with checked arithmetic,

```text
issuedAtLogicalWindow
  <= notBeforeLogicalWindow
  <= referenceWindow
  <= notAfterLogicalWindow

notAfterLogicalWindow - issuedAtLogicalWindow
  <= roomPolicy.admissionFloor.maxAuthorityCredentialLifetimeWindows
```

and `issuedAtLogicalWindow` cannot exceed the exact logical window of the
credential-carrying PRESENCE, HELLO, or ACCEPT operation. A permit additionally
must contain the presence operation's exact logical window. The issuing
authority sets `issuedAtLogicalWindow` to its actual current room logical
window and never pre-signs a future issuance value. Already received outer
operations can still be at most
`roomPolicy.protocolLimits.maxFutureLogicalWindows` ahead, which is why
the revocation floor's exact retention includes that additional bound. These
issuance and end bounds make the revocation horizon executable; interval
length alone would not bound a far-future presigned credential.

`receiverKeyValidThroughLogicalWindow` is no earlier than
`validThroughLogicalWindow` and no later than
`logicalWindow + operationRetentionWindows`. A conforming
L3-capable default advertises it through the full operation-retention horizon.
The matching hybrid receiver private key and
`HistoricalPairPresenceEvidenceV1.retainThroughLogicalWindow` remain available
through the checked
`receiverKeyValidThroughLogicalWindow + receiverKeyOverlapWindows +
MaxClockSkewWindows(roomPolicy)` sum. A HELLO is valid only if its own logical window fell
inside the target presence's active interval; delayed delivery may still open
while the advertised receiver-key horizon remains. After that it is a stale
attempt and requires a fresh presence/contact.

The exact signed presence operation/core is retained over that same checked
horizon as `HistoricalPairPresenceEvidenceV1`, charged to the ordinary retained
valid-operation count/bytes. It may prove only that the exact presence was
valid at `HELLO.logicalWindow`, bind its receiver key/commitment, and satisfy
the HELLO implicit dependency. It never re-enters the current roster,
current `LocalAdmissibleStateV1`, current presence rank/cap selection, or
current leave state. Its only topology use is inside the non-serializable,
pair-scoped HELLO-time projection below; that function cannot return a room
roster or UI member. The
`operationRetentionWindows + receiverKeyOverlapWindows <=
pairControlRetentionWindows` profile invariant ensures carrier and local
prefix custody cover this historical-pair horizon.

For every logical window still reachable by any advertised receiver-key
overlap, historical topology custody retains in the ordinary
content-addressed operation-byte SSOT the complete validated operation and
author-prefix evidence capable of affecting `CoreReduce` at that window. This
retention exists before a delayed HELLO is first observed. Once an attempt is
observed, its historical view references the exact set used at the decision
boundary; it does not copy a second operation set. Shared bytes are charged
once and every window/reference/retention obligation is bounded. On restart
the client reauthenticates the exact bytes available for that historical
window and reruns the ordinary reducer. Persisted decoded
`CoreRoomStateV1` bytes, `operationsDigest`, or an endpoint-only evidence
subset never mint historical topology provenance by themselves. If the
complete set cannot be retained within both count and byte caps, the affected
historical window is persistently incomplete/overcapacity and any attempt
using it produces no response.

`VerifyHistoricalLocalPresenceCustody` is the sole constructor for
`VerifiedHistoricalLocalPresenceCustodyV1`. In the same optimistic admission
capture it consumes the exact `HistoricalPairPresenceEvidenceV1`, the complete
authenticated operation/author-prefix set for `HELLO.logicalWindow`, and the
live protected stable-identity and receiver-key custody records. After the
read transaction completes it reauthenticates and reduces that exact
historical set, requires the evidence operation to be its exact selected local
presence candidate, recomputes the operation ID and stable commitment,
verifies the stable ownership signature under the retained local stable key,
and derives the advertised hybrid receiver public key from the retained
private key seed. Its object-identity side-table binds the exact historical
Core digest, HELLO window, operation bytes, both key handles and revisions,
and retention/resource fences.

Canonical decoding of `LocalPresenceOwnershipRecordV1`, reuse of
`VerifiedLocalPresenceOwnershipV1`, decoded historical Core bytes, or a
caller-assembled object cannot mint this brand. The old presence author
private key need not be retained after its signed operation and complete
author-prefix evidence authenticate; construction of any new response
separately requires current local author-key custody and its exact CAS head.
The stable identity private key and matching historical hybrid receiver
private key do remain required. Every named operation/evidence/key revision
is compared again by the allow transaction, so rotation, erasure, or drift
invalidates the brand and emits no response.

Only pair-local derived outputs, response private keys, and bootstrap roots
are erased after that pair completes. Retiring the shared presence receiver
key early would break other concurrent honest attempts. This bounded
retention supports hour-scale courier delay within the declared horizon; it
does not claim indefinite discovery during a shutdown.

`Project` assigns presence eligibility with one closed precedence rule:

```text
strictProjectionStableKeys =
  snapshot.frontendControls.allowedStableIdentityKeys
  ∪ snapshot.localPresenceOwnership.localStableIdentityKeys

if snapshot.roomPolicy requires an authority permit:
  require the canonical valid permit winner
  if snapshot.frontendControls.onlyConnectWithKnownPeers:
    require one unambiguous key in strictProjectionStableKeys whose room
      commitment matches and whose stable signature verifies this exact fact
  eligibility = "authority-permit-proved"
else if snapshot.frontendControls.onlyConnectWithKnownPeers:
  require one unambiguous key in strictProjectionStableKeys whose room
    commitment matches and whose stable signature verifies this exact fact
  eligibility = "local-address-book-proved"
else:
  eligibility = "open"
```

For every authority-mode candidate, “canonical valid permit winner” includes
`view = DeriveAuthorityAdmissionView(snapshot,
presence.stableIdentityCommitment)`, `view.status == "available"`, and
`AuthorityGenerationAllowed(permit.generation, view)`. Missing custody or
frontend state produces no strict-mode vertex; there is no fallback to open
mode and no second authority-availability predicate.

An optional address-book match in open mode does not upgrade the label or
rank. In authority mode it never substitutes for the permit. Canonical
duplicate/reused-permit resolution runs first over all active core presences;
frontend denial then removes its winner and never promotes a losing reuse.
Strict-mode duplicate stable-commitment reduction runs after denial and before
rank/cap selection. It verifies candidates in canonical
`PresenceOperationId` order and retains the lowest valid fact for the
commitment; an invalid lower fact does not block a later valid fact. The same
stable key appearing in both the address book and verified local-key set is
one key, not an ambiguity; two distinct keys producing the same commitment
fail closed. An unavailable or ambiguous lookup denies at the relevant step.
Thus local policy may remove vertices but cannot select a different
credential-reuse winner or change eligibility by implementation order.

The v1 label `"local-address-book-proved"` names this strict local-known rank
class. For a local vertex, verified stable-key custody is implicit local
knowledge, so the user need not add their own key to the remote-peer address
book. That exception is identity-wide, not operation-ID-wide, and it never
bypasses signature verification. If a lower valid `P1` and a higher locally
owned `P2` share the same locally custodied stable key, `P1` is the canonical
strict winner; `P2` cannot become the local vertex merely because its
operation ID is listed as locally owned.
This union exists only inside local presence projection. It does not add the
client's own keys to `EvaluatePeerAdmissionPolicy` for a remote identity or
bypass the pair layer's equal-stable-key/self rejection.

```text
EligiblePresenceRank =
  if authority-permit-proved:
    H("p2party/presence-rank/authority/v1" ||
      snapshot.roomContextId || permitSerial || U64BE(generation))
  else if local-address-book-proved:
    H("p2party/presence-rank/address-book/v1" ||
      snapshot.roomContextId || StableIdentityCommitment)
  else:
    H("p2party/presence-rank/open/v1" ||
      snapshot.roomContextId || PresenceOperationId)

ObservedRosterHash =
  H(
    "p2party/observed-roster/v1" ||
    U64BE(snapshot.referenceWindow) ||
    Canonical(Sort(valid active PresenceOperationIds))
  )
```

`ObservedRosterHash` is local diagnostic and reconciliation state. It may be
sent pair-privately to compare inventories, but it shall not enter
`PairEdgeId`, `StableEdgeId`, `RendezvousChannelId`, protocol-v4 roots, or a
server request.

`CoreReduce` first requires each non-forked author chain to be contiguous, but
does not collapse different presence semantic slots into one “latest author
state.” Each exact valid `PRESENCE` is a separate fact. A valid `LEAVE`
deactivates only its exact `presenceOperationId` at its
`effectiveLogicalWindow`; because v1 requires that value to equal the LEAVE
outer logical window, it is never applied earlier. Thus
`P1 → P2 → LEAVE(P1)` leaves P2 active. Multiple otherwise-valid LEAVEs for
the same presence at different effective windows are redundant facts, not a
fork: each has a different semantic slot, and the earliest effective one
already makes that exact presence inactive. A valid LEAVE's outer expiry covers
the referenced presence's complete remaining `validThroughLogicalWindow`, so
the presence cannot reappear when the LEAVE expires. The reducer excludes
expired, left, forked, and malformed presences from `observedPresences`, which
therefore
contains active facts only in canonical operation-ID order. Leave IDs and
faults remain in their dedicated arrays; historical UI state is outside this
core projection. The reducer never reads a local denylist, address book, or
physical storage cap. It retains every otherwise-valid active core presence
and sets
`roomCapacityState="overcapacity"` when their count exceeds
`maxRoomMembers`; it does not invent a core member winner.
`Project` verifies mode-specific eligibility and applies frontend denial. It
sorts all remaining local and remote vertices solely by
`(EligiblePresenceRank, PresenceOperationId)` and takes the first
`snapshot.roomPolicy.maxRoomMembers`; there is no separate or
implementation-chosen eligibility class order. The cap includes the local
vertex. The selected subset is deliberately local projection state, not
convergent core state; arrival order and server choice never select it.

`LocalAdmissibleStateV1.peers` contains only selected remote vertices.
`Project` recognizes local ownership only from
`snapshot.localPresenceOwnership.localPresenceOperationIds`. The associated
`localStableIdentityKeys` participate in strict proof and identity-wide
deduplication before this exact operation-ID ownership test; they do not make
an arbitrary matching fact locally owned. If exactly one
such current locally owned presence is in the selected set,
`localPresenceOperationId` and `localPresenceRank` contain its exact values.
If local ownership is absent, ambiguous, forked, or outside the bounded
selection, both fields are null, every `desiredEdge` is false, and the planner
creates no new edge. This fail-closed state cannot be repaired by pretending
that the first remote peer is the local vertex.

`projectionStatus` reports that local projection result independently of the
planner. `plannerStatus="full-mesh-overcapacity"` empties only the planner
selection when the bounded full-mesh rule cannot run; it does not rewrite a
ready projection and does not erase a separately permitted explicit request.
If there is no unambiguous selected local presence, `plannerStatus` is
`"unavailable"` regardless of full-mesh size.

The status precedence is normative. Invalid canonical shape, room binding, or
trusted provenance is an input error and returns no projection. For a
well-formed call, `Project` evaluates statuses in this exact order:

1. incomplete/saturated trusted physical custody or resource state, including
   an exact retained-operation count or byte count at its cap, yields
   `projectionStatus="projection-resource-overcapacity"`;
2. otherwise missing frontend controls or unavailable required authority
   custody/view yields `projectionStatus="policy-unavailable"`;
3. otherwise absence or ambiguity of the selected local presence yields
   `projectionStatus="no-unambiguous-local-presence"`; and
4. otherwise `projectionStatus="ready"`.

`CoreRoomStateV1.roomCapacityState="overcapacity"` does not trigger step 1;
it is a complete logical input that is deterministically rank-capped. Planner
status is then evaluated in this exact order: any non-ready projection or
missing unambiguous local vertex yields `"unavailable"`; otherwise an
infeasible bounded full-mesh selection yields `"full-mesh-overcapacity"`;
otherwise it yields `"ready"`. Thus resource state precedes policy state,
policy precedes local ambiguity, and planner unavailability precedes
full-mesh overflow.

`topologySelections` is the SSOT for the two origins:
`plannerSelected` and `locallyRequestedExplicit`. For a selected remote peer,
`desiredEdge` is exactly their UI-friendly OR. No admission path may infer
either origin from that boolean or from a non-`ready` planner status.

The room boundary is exact:

```text
Profile cohort
  ├── Room A: decryptable OperationSet(A) → ObservedRoster(A) → SparseGraph(A)
  ├── Room B: decryptable OperationSet(B) → ObservedRoster(B) → SparseGraph(B)
  └── unrelated opaque objects and dummies
```

No operation that fails the exact room context contributes a presence,
neighbor, pair candidate, admitted application/data-plane relay permission, or
admission decision. One client
may occupy several fixed local room slots; the sets, reducers, pair registries,
and durable sessions remain disjoint.

Possession of the capability permits presence creation and discovery. It does
not bypass frontend admission, prove a stable identity, reveal another pair's
payload, or authorize a final transport.

Open ranks are intentionally grindable by a capability holder and open rooms
have no Sybil-resistant fairness or eclipse guarantee. Strict address-book
mode admits only the lowest `PresenceOperationId` among the overlapping live
presences for one `StableIdentityCommitment` whose ownership signature
verifies under the one unambiguous eligible stable key at the explicit
`referenceWindow`; an invalid lower fact is skipped, while other valid
presences signed by that same stable key are retained as duplicate-identity
evidence but are not planner vertices.
Authority mode applies both that commitment rule and the same lowest-operation
rule across every overlapping live presence for one
`(permitSerial,generation)`. The deduplication key never includes a presence's
own logical window. Stronger anonymous eligibility without room-visible
pseudonyms requires a separately reviewed anonymous credential/quota
construction.

### 4.10 Local connection planner and sparse default

The planner consumes only the local admissible projection; it never consumes
the delivery cohort. Define `V` as the exact selected local presence plus the
selected remote `peers`. If the selected local presence is null, `V` has no
local vertex and no new edge is produced. Its modes are:

- `explicit`: only locally requested edges, subject to mutual admission and
  hard caps;
- `sparse-ring`: the default deterministic bounded-degree overlay below; and
- `full-mesh-small-room`: all vertices in `V` only when
  `|V| <= fullMeshMaxMembers` and the degree cap permits it. Otherwise it fails
  closed with `plannerStatus="full-mesh-overcapacity"` and an empty
  planner-selected set; it does not silently expand the cap or disable a
  separately valid explicit selection.

The explicit-request channel is orthogonal to automatic planner mode:
`mode="explicit"` makes the automatic planner select nothing, while bounded
user requests may augment sparse or full-mesh modes when
`allowOnDemandEdges=true`.

A local explicit request names `LocalPeerId`, but the transition records an
exact presence operation. It resolves the request to at most one selected
remote vertex: the first matching vertex in `V`'s canonical
`(EligiblePresenceRank, PresenceOperationId)` order. It never fans one request
out to every overlapping open-mode presence, and it never reaches beyond the
bounded selected set. No match means no attempt. The resulting
`locallyRequestedExplicit` fact remains distinct from planner selection even
when both select the same presence.

For `sparse-ring`, use `V` in its already canonical
`(EligiblePresenceRank, PresenceOperationId)` order. Let `p` be the exact
`localPresenceOperationId`. With local radius `k`, the desired neighbors of
`p` are its first `k` predecessors and first `k`
successors on the circular order:

```text
DesiredNeighbors(p, V, k) =
  if p is null or p is not exactly one vertex in V: {}
  else Predecessors(p, V, k) ∪ Successors(p, V, k)
```

For `|V| > 1` and `k >= 1`, the union of incident desired edges computed by
participants with the same `V` contains a cycle and is connected. Its maximum
canonical degree is `min(2k, |V|-1)`. Each client materializes only edges
incident to its own `p`; it never tries to connect two remote vertices.

The pre-auth pair identifier is view-independent:

```text
PairEdgeId =
  H(
    "p2party/pair-edge/v1" ||
    RoomContextId ||
    Sort2(PresenceOperationIdA, PresenceOperationIdB)
  )
```

The lower lexicographic `PresenceOperationId` is
`RendezvousRole=initiator`.
This rotating role only prevents duplicate provisional attempts. It does not
choose the stable protocol-v4 session role. `EligiblePresenceRank` remains
planner priority only; local address-book/authority classifications can never
change a pair's direction or transcript.

A new pair attempt is eligible when:

1. both exact presences were valid in the local room at the HELLO logical
   window and that fact is proved by a genuine current or retained historical
   Core/evidence capture;
2. the target's strict presence proof/permit verifies whenever strict local or
   canonical policy requires it, and neither known commitment is locally
   denied;
3. the initiator's local planner selects the remote presence or the user made
   an explicit bounded request and its local `allowOnDemandEdges` is true;
4. on receipt, the receiver's current planner policy applied to the applicable
   current or exact HELLO-time private projection independently selects the
   initiator, or the signed request is explicit and current
   `allowOnDemandEdges=true`;
5. the fixed attempt slot, author quota, pair-open trial budget, and retained
   byte budget permit it; and
6. neither side exceeds its hard active/provisional degree cap.

For an exact selected remote presence, outgoing attempt provenance has one
deterministic precedence rule:

```text
OutboundAttemptMode(presence) =
  if topologySelections[presence].locallyRequestedExplicit
     and local allowOnDemandEdges == true:
    "explicit"
  else if topologySelections[presence].plannerSelected:
    "planner"
  else:
    no attempt
```

Thus a real explicit API request remains the authenticated origin when both
bits are true; implementations cannot choose different persisted modes.

For an incoming authenticated HELLO, the receiver never consults
`locallyRequestedExplicit`: that bit records its own outbound UI intent, not
the sender's. The receiver requires the exact initiator presence to be a
selected vertex and then applies:

```text
attemptMode="planner"
  => exact initiator presence is planner-selected by the receiver

attemptMode="explicit"
  => receiver allowOnDemandEdges == true
```

Both branches still require current frontend/authority admission, exact room
and endpoint binding, unambiguous local ownership/custody, and all pair,
degree, replay/fork, outbox, and count/byte resource fences.

`ProjectHistoricalPairAttempt` resolves the apparent conflict between current
topology and delayed delivery. It is a distinct module-private constructor,
run only after an authenticated HELLO has opened and before response
preparation. It takes:

- the genuine exact local `CoreRoomStateV1` re-derived at
  `HELLO.logicalWindow` from the retained authenticated operation/prefix set,
  not decoded Core bytes, a peer-supplied roster, or an endpoint-only set;
- retained authenticated evidence for both exact endpoint presences and
  a genuine `VerifiedHistoricalLocalPresenceCustodyV1` for the exact local
  endpoint;
- the current `TrustedAdmissionSnapshotV1`;
- the current exact planner/explicit row; and
- the exact historical and current resource/degree/ledger fences.

Historical projection has two explicit clocks and no ambient notion of
“current.” Its `projectionWindow` is exactly `HELLO.logicalWindow`; its
`decisionReferenceWindow` is exactly `snapshot.referenceWindow`, with
`HELLO.logicalWindow <= decisionReferenceWindow`. The re-derived historical
Core must have `referenceWindow == projectionWindow`.

At `projectionWindow`, the shared semantic kernel evaluates presence activity,
LEAVEs and presence/author faults, presence and receiver-key intervals,
presence-permit issuance/not-before/not-after validity, canonical permit
reuse, stable-commitment deduplication, eligibility rank, the bounded vertex
cap, and the planner topology over that vertex set. At
`decisionReferenceWindow`, it evaluates the successfully loaded current
frontend controls and deny/known-key state, required authority custody,
authority faults/availability and revocation floor, current planner and
`allowOnDemandEdges` policy, sender admission grant through `Admit`, pair
degree/ledger/outbox state, and every current or retained-historical
count/byte resource fence. An authority presence permit must therefore have
been valid at `projectionWindow` and its generation must also pass
`AuthorityGenerationAllowed` against the current authority view at
`decisionReferenceWindow`. A delayed HELLO neither uses current presence
activity to reject a once-valid endpoint nor uses historical policy state to
bypass a current deny or revocation.

The constructor reuses the same eligibility, proof, duplicate resolution,
rank, cap, and planner semantic kernel as current `Project` under that
two-clock split. It requires the historical local endpoint to be the unique
selected locally owned/custodied vertex and the remote endpoint to be one
exact selected vertex. Missing, incomplete, ambiguous, expired,
physically at-cap/overcapacity, or caller-assembled historical state fails
closed; a logically over-cap but completely retained historical Core is
rank-capped exactly like current Project. Two endpoint facts are never treated
as a complete roster.

The constructor mints one `VerifiedPairAttemptTopologyV1` bound to the exact
HELLO operation, pair edge, endpoint tuple, signed attempt mode, snapshot,
planner row, and resource fences. It authorizes only that attempt and cannot
be serialized, decoded, cloned, spread, asserted, or reused for another
transition. Its `projectionSource` is `"hello-time-historical"`. The ordinary
current/outbound projector may mint the same opaque type with source
`"current"`, but a cloneable `LocalAdmissibleProjectionV1` never can.

Historical projection never inserts a presence into current Core or
`LocalAdmissibleStateV1`, never emits a roster/member event, never changes
current UI rank/cap state, and never creates a general current neighbor. It
only lets one still-within-horizon pair attempt use the topology facts that
were genuine at its signed HELLO window while current denial, revocation,
authority availability, resource, and degree state remain vetoes.

The receiver therefore uses only its own current or exact retained historical
Core capture. A malicious initiator cannot present a hand-picked fake roster
to make itself everyone's neighbor. View mismatch may delay an honest edge;
it never authorizes a cross-room or over-degree edge.

Different partial views and planner policies can create harmless tentative or
extra edges.
Established authenticated stable sessions are not rolled back merely because
a later presence arrives. At each topology reconciliation boundary, a client:

1. preserves healthy stable edges still selected by current policy;
2. prefers missing canonical neighbors;
3. retires unselected provisional edges first;
4. retires a stable extra edge only after the configured grace/checkpoint and
   only if doing so cannot interrupt an active transfer; and
5. never exceeds its local `maxActiveStableEdges`.

Once all relevant presences reach participants that use the same sparse
planner, byte-identical eligibility facts/ranks, and admissible vertex set,
their desired neighbor sets converge and repeated fixed attempt slots
establish the connected sparse graph, subject to peer and carrier
availability. Different local planners or allowlists can intentionally
produce a different graph or partition a room; the runtime reports that local
policy result rather than bypassing admission for connectivity. In
`mode="explicit"` with no requested edges, canonical operation convergence
still works; a requested explicit edge is separately authenticated below.

Before pair opening, candidates are processed in deterministic bounded batches
only by routing tag, outer operation ID, and fixed trial ordinal; authorization
class is encrypted and is applied only after Open.
A capability holder that learns a one-use tag can copy it under unlimited
outer-author Sybils with invalid pair ciphertext, so per-author limits alone
are insufficient. Each local presence enforces the local resource policy's
pair-open trial count and byte budgets. One trial includes header/input
validation, hybrid-KEM decapsulation, HPKE setup/export, tag comparison, and
ciphertext opening.

The exact persisted budget coordinate is
`(LocalRoomId, localPresenceOperationId, budgetLogicalWindow)`, where
`budgetLogicalWindow` is the monotone persisted maximum of the previous budget
window and the current captured `referenceWindow`. Before any expensive trial,
one atomic transaction reserves one count and the complete candidate envelope
byte length. Restart, duplicate delivery, another carrier, and another
reconciliation pass reuse the same counters. A reset occurs only when a later
captured room logical window is durably greater; the old record is deleted
only in that same fenced transition. It never resets on wall-clock rollback,
adapter reconnect, or failure. Saturation reports
`pair-control-DoS/stalled` until that exact next logical-window boundary; it
never lets arrival order select a logical winner. No protocol can guarantee
honest progress against a malicious capability holder and malicious sole
store that consumes/withholds all available capacity. Authority permits or a
separately reviewed anonymous quota credential are required for a stronger
availability claim.

The sparse overlay may gossip encrypted room operation inventories and carry
end-to-end pair signaling for an explicitly requested on-demand edge. It is
not a cohort overlay and never relays plaintext SDP, identity credentials, or
PQ records. Application-message routing over the sparse overlay is governed by
the mandatory production data-plane specification in REQ-021.

#### SDK-facing room and peer views

Observed room membership and a usable direct peer are different states. The
blind public API exposes them without making degree look like room size:

```ts
type PresenceRefV1 = string; // "presence.v1." || Base64urlNoPad(OperationId)

type ObservedMemberViewV1 = {
  presenceId: PresenceRefV1;
  localPeerId: string; // commitment-derived; not yet a verified Peer
  eligibility: ObservedPresenceV1["eligibility"];
  status: ObservedPresenceV1["status"];
};

type EdgeViewV1 = {
  localPeerId: string;
  stableEdgeId: Bytes32 | null;
  state: "desired" | "provisional" | "authenticated" | "promoted" | "stalled";
  applicationDataCapable: boolean;
};
```

- `Room.observedMembers` is the canonical local projection of live presence
  facts; it is eventually observed, never advertised as a complete roster.
- `Room.edges` contains desired/provisional/authenticated edge state.
- For compatibility, blind `Room.peers` contains only authenticated,
  promoted, directly application-data-capable peers. `Peer.peerId` is the
  canonical `LocalPeerId`; it is stable across presence refresh for the same
  stable identity, rotates when that stable identity changes, and is never a
  server UUID.
- `waitForPeers(count)` retains its meaning as waiting for `count` such direct
  data peers. New `waitForObservedMembers(count)` is explicitly an observed
  lower bound, not global room size.
- Direct-peer helpers such as disconnect, per-peer send/progress,
  address-book, and blacklist operations accept `LocalPeerId` in blind mode.
  Legacy rooms retain their UUID behavior behind the closed legacy room
  variant; a UUID and `peer.v1.` handle are never guessed across modes.
- Whole-room `sendMessage(room)` retains today's recipient semantics only
  after the REQ-021 data plane passes. The control-plane implementation shall
  not fake that behavior by sending only to `Room.peers` or by restoring a
  full mesh.

The protected `LocalRoomId` migration ledger names every namespace that must
commit or resume atomically: `uniqueRoom`, `messageData`, `ratchetSessions`,
current-room middleware and localStorage, key-pair registration,
peer/negotiation/ICE/receive queues, ratchet and cover registries, transfer/
reconcile/PIN state, public helper arguments/results, and logs/errors. No raw
capability, legacy server room UUID, or server-scoped peer UUID survives in
a blind-mode ordinary index or map merely because it was omitted from a
database migration.

### 4.11 Pair step, pre-SDP identity exchange, and pair bootstrap

```ts
type PairStepKindV1 =
  | "IDENTITY_HELLO"
  | "IDENTITY_ACCEPT"
  | "TRANSPORT_OFFER"
  | "TRANSPORT_ANSWER"
  | "V4_HANDSHAKE"
  | "PQ_CONTROL"
  | "QUIESCE_PROPOSE"
  | "QUIESCE_ACK"
  | "HEAL_COMPLETE"
  | "PAIR_CHECKPOINT";

// Canonical PairStepKindByte registry, in union order above:
// 0x00 HELLO, 0x01 ACCEPT, 0x02 TRANSPORT_OFFER,
// 0x03 TRANSPORT_ANSWER, 0x04 V4_HANDSHAKE, 0x05 PQ_CONTROL,
// 0x06 QUIESCE_PROPOSE, 0x07 QUIESCE_ACK, 0x08 HEAL_COMPLETE,
// 0x09 PAIR_CHECKPOINT.

type PairBootstrapHeaderV1 = {
  version: 1;
  suiteId: 1;
  hybridKemCiphertext: Uint8Array; // exactly 1,120 bytes for suite 1
};

const PAIR_AEAD_TAG_BYTES_V1 = 16;
const PAIR_BOOTSTRAP_ENVELOPE_OVERHEAD_BYTES_V1 = 1_161;
const PAIR_ESTABLISHED_ENVELOPE_OVERHEAD_BYTES_V1 = 63;

// The complete room-visible pair payload.
type PairStepEnvelopeV1 = {
  version: 1;
  pairRoutingTag: Bytes32;
  bootstrapHeader: PairBootstrapHeaderV1 | null;
  // null for HPKE-sealed HELLO/ACCEPT; random Bytes24 for every later step.
  nonce: Bytes24 | null;
  pairCiphertextAndTag: Uint8Array;
};

// Available only after pair AEAD succeeds.
type PairPlaintextV1 = {
  version: 1;
  kind: PairStepKindV1;
  pairEdgeId: Bytes32;
  endpointPresenceOperationIds: readonly [Bytes32, Bytes32];
  direction: 0 | 1;
  pairSequence: bigint;
  previousPairOperationId: Bytes32 | null;
  pairDependencies: readonly Bytes32[];
  body: PairStepBodyV1;
  pairPadding: Uint8Array; // exact all-zero inner padding
};

type PairStepBodyV1 =
  | { kind: "IDENTITY_HELLO"; value: PairIdentityHelloV1 }
  | { kind: "IDENTITY_ACCEPT"; value: PairIdentityAcceptV1 }
  | { kind: "TRANSPORT_OFFER"; value: PairTransportOfferV1 }
  | { kind: "TRANSPORT_ANSWER"; value: PairTransportAnswerV1 }
  | { kind: "V4_HANDSHAKE"; value: Uint8Array }
  | { kind: "PQ_CONTROL"; value: Uint8Array }
  | { kind: "QUIESCE_PROPOSE"; value: QuiesceProposeV1 }
  | { kind: "QUIESCE_ACK"; value: QuiesceAckV1 }
  | { kind: "HEAL_COMPLETE"; value: HealCompleteV1 }
  | { kind: "PAIR_CHECKPOINT"; value: PairCheckpointV1 };

type StableIdentityBundleV1 = {
  ed25519PublicKey: Bytes32;
  x25519PublicKey: Bytes32;
  x25519CrossSignature: Bytes64;
};

type PairIdentityHelloUnsignedV1 = {
  version: 1;
  attemptMode: "planner" | "explicit";
  senderIdentity: StableIdentityBundleV1;
  senderPresenceCommitment: Bytes32;
  senderAdmissionGrant: AdmissionGrantV1 | null;
  responseHybridKemPublicKey: Uint8Array; // exactly 1,216 bytes for suite 1
};

type PairIdentityHelloV1 = PairIdentityHelloUnsignedV1 & {
  identityTranscriptSignature: Bytes64;
};

type PairIdentityAcceptUnsignedV1 = {
  version: 1;
  responderIdentity: StableIdentityBundleV1;
  responderPresenceCommitment: Bytes32;
  responderAdmissionGrant: AdmissionGrantV1 | null;
};

type PairIdentityAcceptV1 = PairIdentityAcceptUnsignedV1 & {
  identityTranscriptSignature: Bytes64;
};

type PairIdentityUnsignedFlightV1<
  K extends "IDENTITY_HELLO" | "IDENTITY_ACCEPT",
  B,
> = {
  version: 1;
  kind: K;
  pairEdgeId: Bytes32;
  endpointPresenceOperationIds: readonly [Bytes32, Bytes32];
  direction: 0 | 1;
  pairSequence: bigint;
  previousPairOperationId: Bytes32 | null;
  pairDependencies: readonly Bytes32[];
  body: { kind: K; value: B };
  pairPadding: Uint8Array;
};

type PairIdentityUnsignedProjectionV1 =
  | PairIdentityUnsignedFlightV1<"IDENTITY_HELLO", PairIdentityHelloUnsignedV1>
  | PairIdentityUnsignedFlightV1<
      "IDENTITY_ACCEPT",
      PairIdentityAcceptUnsignedV1
    >;

type PairCheckpointV1 = {
  version: 1;
  pqEpoch: bigint;
};

// Exact canonical projection of every variable outer operation field that is
// available before pair encryption. Constants are still encoded, not implied.
type PairOuterPrebindingV1 = {
  version: 1;
  roomContextConfirmation: Bytes32;
  policyHash: Bytes32;
  logicalWindow: bigint;
  expiresAfterWindow: bigint;
  lifetime: "PAIR_CAUSAL";
  authorEpochEd25519Key: Bytes32;
  authorSequence: bigint;
  previousAuthorOperationId: Bytes32 | null;
  kind: "PAIR_STEP";
  dependencies: readonly [];
  operationPayloadClass: OperationPayloadClassV1;
  bootstrapHeaderHash: Bytes32; // ZERO32 when header is null
  nonce: Bytes24 | null;
};

type PairOuterBindingV1 = {
  prebinding: PairOuterPrebindingV1;
  pairRoutingTag: Bytes32;
  semanticSlot: Bytes32;
};

type PairFlightSlotV1 = {
  kind: PairStepKindV1;
  direction: 0 | 1;
  pairSequence: bigint;
};

// Available before HPKE Setup; it deliberately excludes the generated
// bootstrap ciphertext/header.
type PairBootstrapInfoV1 = {
  version: 1;
  pairBootstrapSuite: 1;
  roomContextConfirmation: Bytes32;
  policyHash: Bytes32;
  stepKind: "IDENTITY_HELLO" | "IDENTITY_ACCEPT";
  logicalWindow: bigint;
  expiresAfterWindow: bigint;
  authorEpochEd25519Key: Bytes32;
  authorSequence: bigint;
  previousAuthorOperationId: Bytes32 | null;
  operationPayloadClass: OperationPayloadClassV1;
  recipientBinding:
    | { kind: "presence"; presenceOperationId: Bytes32 }
    | { kind: "hello-response"; helloOperationId: Bytes32 };
};
```

The proposed Phase-0 inner codec fixes the previously implicit byte choices as
follows. `PairPlaintextV1` uses declaration order. `version`, `kind`, and
`direction` are one byte (`direction` is restricted to `0x00 | 0x01`);
`pairSequence` is unsigned 64-bit big-endian; all optional fields use the
closed one-byte presence tag. `endpointPresenceOperationIds` is a sequence with an
unsigned-16 count that must equal two. `pairDependencies` is a sorted,
duplicate-free sequence with an unsigned-16 count and a closed maximum of one:
every v1 flight has either no cross-direction dependency or exactly one.

`PairStepBodyV1` uses a one-byte closed-union tag in `PairStepKindByte` order.
As in the canonical union codec, the selected variant then encodes its declared
`kind` enum field before `value`; the plaintext `kind`, union tag, and body
`kind` must all agree. The body byte fields are:

- `V4_HANDSHAKE.value`: unsigned-32 length plus at most 3,329 bytes. Before
  pair-state mutation it must be exactly one existing protocol-v4 frame:
  HELLO tag `0x01` with length 1,761, 2,465, or 3,329 for the room-selected
  ML-KEM-512/768/1024 suite respectively; CONFIRM tag `0x02` with length 97;
  or FINISH tag `0x03` with length 65. These values are derived by the neutral
  `handshakeFrame` geometry consumed by `handshakeCore`; that shared geometry
  is the byte-length/tag SSOT, while `handshakeCore` remains the semantic and
  cryptographic parser. Every pair-plaintext validation/encode/decode boundary
  receives the immutable room-selected `RoomPqMode`; it has no default and
  must not accept a HELLO merely because its length belongs to another
  registered room suite.
- `PQ_CONTROL.value`: exactly 65,490 bytes with no additional length prefix,
  preserving the complete existing `WIRE_CHUNK_FRAME_LEN` frame byte-for-byte.
- WebRTC SDP and registered-local-link candidate bytes: unsigned-32 length,
  respectively 1..32,768 and 1..2,048 bytes. A v1 offer carries one to three
  candidates in derived-`TransportOfferCandidateId` order; the sequence count
  is unsigned 16-bit.
- All keys, commitments, hashes, signatures, KEM keys, and operation IDs use
  their declared fixed widths. Every other declared `bigint` is unsigned
  64-bit big-endian, `adapterProtocolId` is unsigned 16-bit, and every version,
  suite, attempt-mode, candidate-kind, and body-kind enum is one byte.

`pairPadding` is unsigned-32-length-prefixed bytes and is restricted to the
all-zero string. Its schema maximum is 65,535 bytes, derived rather than
chosen: an established class-1 plaintext is minimal only when its empty-padding
encoding is at least `4,017 + 1 = 4,018` bytes, so its largest required suffix
is `69,553 - 4,018 = 65,535`. The validator encodes the same plaintext with
empty padding, selects the smallest legal target, and requires the supplied
suffix to be exactly the remaining length. Thus the descriptor bound is not a
second target table.

The canonical `PairStepEnvelopeV1` field order is exactly the declaration
order above. `version` and `suiteId` are unsigned 8-bit values,
`pairRoutingTag` is fixed 32 bytes, each optional uses one closed
`0x00`/`0x01` presence byte, `hybridKemCiphertext` is fixed 1,120 bytes,
`nonce` is fixed 24 bytes when present, and `pairCiphertextAndTag` uses one
unsigned-32-bit length followed by those bytes. The two overhead constants
include that length prefix and are derived from this schema:

```text
PAIR_BOOTSTRAP_ENVELOPE_OVERHEAD_BYTES_V1 =
  1 version
  + 32 routing tag
  + 1 present tag + 1 header version + 1 suite + 1120 KEM ciphertext
  + 1 absent nonce tag
  + 4 ciphertext length
  = 1161

PAIR_ESTABLISHED_ENVELOPE_OVERHEAD_BYTES_V1 =
  1 version
  + 32 routing tag
  + 1 absent bootstrap-header tag
  + 1 present nonce tag + 24 nonce
  + 4 ciphertext length
  = 63
```

Suite 1 permits a bootstrap header only in payload class 0 and requires
`operationPadding` to be the unique empty byte string for every `PAIR_STEP`.
The pair ciphertext therefore consumes every remaining byte of the signed
operation payload class:

```text
PairCiphertextAndTagBytes(class, bootstrap) =
  OPERATION_PAYLOAD_CLASS_BYTES[class]
  - (
      PAIR_BOOTSTRAP_ENVELOPE_OVERHEAD_BYTES_V1
        if bootstrap
      else PAIR_ESTABLISHED_ENVELOPE_OVERHEAD_BYTES_V1
    )

PairPlaintextTargetBytes(class, bootstrap) =
  PairCiphertextAndTagBytes(class, bootstrap)
  - PAIR_AEAD_TAG_BYTES_V1

suite-1 exact values:
  class 0 bootstrap:   ciphertext+tag 2,935; plaintext 2,919
  class 0 established: ciphertext+tag 4,033; plaintext 4,017
  class 1 established: ciphertext+tag 69,569; plaintext 69,553
```

Class 1 with a bootstrap header is invalid. These equations, rather than
another hand-maintained target table, are the SSOT. The Phase-0 vector set
must derive the three values from the canonical schema and payload-class
table and fail if either source changes without a new codec/suite.

`PairStepEnvelopeV1` is the payload of a canonical `PAIR_STEP` operation. A
capability holder sees its one-use tag, optional bootstrap header, fixed
length, bootstrap-vs-established class, author, and timing, but not HELLO
versus ACCEPT or any established kind, direction, sequence, predecessor,
pair/presence IDs, dependencies, or body. The room operation's outer
dependencies are empty and its semantic slot is the hash of
`pairRoutingTag`. Pair chains are independently monotonic in each encrypted
direction. Direction 0 is rendezvous initiator → responder; direction 1 is
responder → initiator. Envelope class constraints must agree with state:
`bootstrapHeader != null && nonce == null` is permitted only for an expected
HELLO or ACCEPT, while `bootstrapHeader == null && nonce != null` is required
for every later step. After opening, the state-derived expected kind, decrypted
`kind`, and body discriminator must agree exactly.

`attemptMode` exists only in the signed HELLO body and is therefore
pair-private and bound by `identityTranscriptSignature`; ACCEPT and every
later flight inherit it from the admitted attempt ledger. An honest sender
sets `"explicit"` only for a bounded explicit API request. A receiver accepts
that mode only when the exact initiator presence is selected/admissible in the
applicable current or HELLO-time historical private projection and its own
current `allowOnDemandEdges` is true. It does not require the receiver's own
explicit-request row, `locallyRequestedExplicit`, or diagnostic
`desiredEdge`. `"planner"` instead requires the exact initiator presence's
private `plannerSelected` fact. The field authenticates the remote endpoint's
declared attempt origin, not the truth of a human gesture; a malicious peer
can request an edge, but cannot bypass the receiver's current
frontend/authority admission, exact room/pair binding, degree policy, or
resource/replay/fork fences.

Pair parsing verifies only the closed credential framing, pair/room
transcript, stable identity signature, and exact identity-to-commitment
binding. It does not authorize a grant. The sole `Admit()` function below owns
room mode, grant presence/absence, authority signature, interval, generation,
revocation, and frontend-policy semantics for both HELLO and ACCEPT. A permit
authorizes an encrypted presence commitment; a grant binds the subsequently
revealed stable key. They are distinct objects, and neither may be copied into
the other room mode.

The pair codec and `PairOperationPayloadClassFor` fix the encoded
`PairPlaintextV1` length for each operation payload class. `pairPadding` is the
unique all-zero suffix needed to reach that length and is authenticated inside
HPKE/pair AEAD. Consequently,
`pairCiphertextAndTag` has one exact length for
`(operationPayloadClass, bootstrapHeader present/null)`; outer padding cannot
reveal the exact same-class inner step kind. The payload class remains visible:
in codec v1 class 1 identifies the large-body pair family, which includes
complete SDP and `PQ_CONTROL`, while small established controls share class 0.
This bounded size-family leakage is reported rather than mislabeled as
exact-kind hiding. A nonzero, short, long, or noncanonical padding
encoding fails before pair-state mutation.

`endpointPresenceOperationIds` is always ordered
`[RendezvousRole initiator, RendezvousRole responder]`. HELLO treats both
exact presence operations as mandatory implicit pair-private dependencies: a
missing presence buffers within the pair count/byte/horizon limits, and either
presence must have been valid at `HELLO.logicalWindow`. A currently active
presence or its exact unexpired `HistoricalPairPresenceEvidenceV1` may prove
that past fact; inert generic prefix evidence alone may not. They remain absent
from the outer dependency list.

After HELLO cryptographic validation, the opener derives only a
grant-agnostic `basePairAttemptLease`: its horizon is the minimum of HELLO's
outer expiry and
`checkedAdd(HELLO.logicalWindow, pairControlRetentionWindows)`. It is an
opaque input to sole `Admit()` and is never persisted. The genuine
`VerifiedPairAttemptTopologyV1` is its second opaque input and is likewise
never serialized; only the exact mode/coordinates and source fences it
authorized are persisted or CAS-bound. After validating topology, the sender
grant, and all current frontend policy, `Admit()` returns the initial
persistable `PairAttemptLeaseV1`, narrowing that base horizon by the sender
grant's `notAfterLogicalWindow` in authority mode. The allow transaction
persists exactly that returned lease together with the bootstrap admission
lease and outbound intent.

When ACCEPT validates, the same logical optimistic transaction narrows the
persisted pair-attempt lease to the minimum of its prior value, ACCEPT's outer
expiry, and the responder grant's `notAfterLogicalWindow` in authority mode.
It never extends. These are pair-visible immutable inputs, so both endpoints
derive the same claim horizon; local admission-policy changes can invalidate
use earlier but cannot rewrite it. Its `attemptMode` is copied only from the
successfully opened and stable-identity-signed HELLO in the same atomic
commit; replay/restore requires exact equality and no later flight can rewrite
or infer it. ACCEPT, transport negotiation, and v4 promotion validate the
exact dependencies, endpoint tuple, and inherited mode against that lease
rather than requiring rotating presences to remain live during courier delay.
Current local deny and authority revocation are still rechecked before every
sensitive dispatch. After promotion, PQ/checkpoint steps validate the tuple
against the persisted confirmed stable-edge transcript, not against presence
bytes.

The bootstrap slots are:

| Step               | Direction/sequence | Same-direction predecessor | Pair dependencies      | Public header |
| ------------------ | ------------------ | -------------------------- | ---------------------- | ------------- |
| `IDENTITY_HELLO`   | `0/0`              | null                       | empty                  | required      |
| `IDENTITY_ACCEPT`  | `1/0`              | null                       | exact HELLO operation  | required      |
| `TRANSPORT_OFFER`  | `0/1`              | exact HELLO operation      | exact ACCEPT operation | forbidden     |
| `TRANSPORT_ANSWER` | `1/1`              | exact ACCEPT operation     | exact OFFER operation  | forbidden     |

Later steps increment their direction's sequence by one, name that direction's
exact predecessor, and name only the pair-private cross-direction facts
required by their kind. A missing predecessor/dependency buffers within the
pair limits and never escapes to the outer room dependency list. For any
`(PairEdgeId, direction, pairSequence)` slot, the first accepted exact
pair-operation ID is the only value: the same ID is a replay; any other fully
authenticated ID is a fork even if it decrypts to equal plaintext.

The first operation-backed `V4_HANDSHAKE` step names exact
`TRANSPORT_ANSWER` as its dependency and the sender's exact transport
offer/answer as its same-direction predecessor. Each later v4 handshake step
uses the sender/step order already fixed by protocol v4, increments that
sender's pair sequence, names its exact previous outbound pair operation, and
depends on the exact immediately preceding inbound v4 operation. No adapter
may invent another ordering.

`PairOuterPrebindingV1` is the exact canonical projection above. It excludes
only tag-derived `semanticSlot`, ciphertext, fixed pair-plaintext padding,
signed operation padding, and the operation signature. HELLO and ACCEPT use
HPKE's internal sequence-zero nonce and therefore encode `nonce=null`; every
later pair flight samples and persists a public 24-byte nonce before
encryption. Every flight derives
`semanticSlot = H("p2party/pair-slot/v1" || pairRoutingTag)`.
`PairOuterBindingV1` is the prebinding plus that tag and semantic slot. Its
canonical encoding is the complete pair AAD:

```text
BindPairOuter(prebinding, pairRoutingTag) =
  PairOuterBindingV1(
    prebinding=prebinding,
    pairRoutingTag=pairRoutingTag,
    semanticSlot=H("p2party/pair-slot/v1" || pairRoutingTag)
  )

PairAAD(binding) =
  "p2party/pair-aad/v1" || Canonical(binding)
```

so ciphertext cannot be relocated to another expiry, author slot, payload
class, room, policy, or operation.

#### Non-circular two-flight identity bootstrap

Suite 1 runs the standard RFC 9180 HPKE key schedule rather than defining a
new hybrid combiner. `MLKEM768-X25519` is used unchanged as the HPKE KEM. For
HELLO, the sender calls `SetupPSKS` with the target presence's suite-fixed
hybrid public key, `psk=RoomRoot`, and:

```text
helloPskId =
  H(
    "p2party/identity-hello-psk-id/v1" ||
    PolicyHash ||
    responderPresenceOperationId
  )

helloInfo =
  Canonical(PairBootstrapInfoV1 {
    stepKind: "IDENTITY_HELLO",
    recipientBinding: {
      kind: "presence",
      presenceOperationId: responderPresenceOperationId
    },
    ...exact pre-Setup outer fields
  })

helloHeader =
  PairBootstrapHeaderV1(suiteId=1, hybridKemCiphertext=enc)

helloPrebinding =
  PairOuterPrebindingV1(
    bootstrapHeaderHash=H(Canonical(helloHeader)),
    nonce=null,
    ...exact outer fields
  )

helloTag =
  helloHpkeContext.Export(
    "p2party/bootstrap-tag/v1" || Canonical(helloPrebinding),
    32
  )

helloBinding =
  BindPairOuter(helloPrebinding, helloTag)

helloCiphertext =
  helloHpkeContext.Seal(
    PairAAD(helloBinding),
    exactFixedPairPlaintext
  )
```

The responder calls the matching `SetupPSKR`, trying only the closed,
state-dependent set of live receiver keys and expected HELLO info values
within the pair-open budget. It compares the exported tag before HPKE Open.
The decrypted hello validates the exact pair/presence IDs, sender
commitment/identity/grant, suite-fixed response hybrid public key, and stable
transcript signature. Only after all validation is:

```text
HelloRoot =
  helloHpkeContext.Export(
    "p2party/validated-hello-root/v1" ||
    H(Canonical(PairPlaintextV1)),
    32
  )
```

The responder uses the same construction for ACCEPT with the response hybrid
public key from HELLO, `psk=HelloRoot`,
`recipientBinding={kind:"hello-response", helloOperationId}`, and:

```text
acceptPskId =
  H(
    "p2party/identity-accept-psk-id/v1" ||
    PolicyHash ||
    HelloOperationId
  )

AcceptRoot =
  acceptHpkeContext.Export(
    "p2party/validated-accept-root/v1" ||
    H(Canonical(PairPlaintextV1)),
    32
  )

ConfirmedPairTranscriptId =
  H(
    "p2party/confirmed-pair-transcript/v1" ||
    HelloOperationId ||
    AcceptOperationId
  )

EstablishedPairRoot =
  HKDF-Extract(
    salt = HelloRoot,
    ikm =
      AcceptRoot ||
      ConfirmedPairTranscriptId
  )
```

Every non-HPKE flight uses one DRY construction. Pre-promotion
`baseSecret=EstablishedPairRoot`; post-promotion Section 4.13 supplies a
one-use `PqSlotSecret`. The sender first samples and durably reserves the
envelope nonce, forms the exact prebinding, and calls
`SealPairStep(baseSecret, expectedPairSlot: PairFlightSlotV1,
exactPrebinding, exactPlaintext)`:

```text
PairFlightRoot =
  HKDF-Expand(
    baseSecret,
    "p2party/pair-flight-root/v1" ||
    PairStepKindByte(expectedPairSlot.kind) ||
    Byte(expectedPairSlot.direction) ||
    U64BE(expectedPairSlot.pairSequence),
    32
  )

PairFlightSecret =
  HKDF-Expand(
    PairFlightRoot,
    "p2party/pair-flight/v1" ||
    PairStepKindByte(expectedPairSlot.kind) ||
    Canonical(exactPrebinding),
    32
  )

pairRoutingTag =
  HMAC-SHA-256(PairFlightSecret, "p2party/pair-flight-tag/v1")

binding =
  BindPairOuter(exactPrebinding, pairRoutingTag)

pairAeadKey =
  HKDF-Expand(
    PairFlightSecret,
    "p2party/pair-flight-key/v1" ||
    Canonical(binding),
    32
  )

pairCiphertextAndTag =
  XChaCha20Poly1305.Seal(
    key=pairAeadKey,
    nonce=exactPrebinding.nonce,
    aad=PairAAD(binding),
    plaintext=Canonical(exactPlaintext)
  )
```

The helper requires `exactPrebinding.bootstrapHeaderHash=ZERO32`, a non-null
24-byte nonce, and exact equality between `expectedPairSlot` and the
plaintext's kind/direction/sequence before sealing. It returns the binding and complete
`PairStepEnvelopeV1`; the caller persists the nonce, exact operation, edge
state, and outbox before publication. `OpenPairStep` is the exact inverse: for
the closed state-derived candidate-slot set, it derives the expected tag,
constant-time compares it with the envelope tag, constructs the one possible
binding/key, opens XChaCha20-Poly1305, and validates the complete plaintext
slot/body/padding before mutation. Every attempted candidate counts against
pair-open work.

`PairStepKindByte`, `Byte(direction)`, and the XChaCha/HKDF suite are exact
suite-1 encodings; `U64BE` is the canonical unsigned sequence encoding. No
HKDF call has an implicit output length, and the public nonce is never derived
from a root.

The exact operation IDs—not ciphertext copies or duplicated body hashes—are
the transcript SSOT. Suite 1 fixes all HPKE, hybrid-KEM, pair-AEAD, validation,
and vector bytes. It is not permission to substitute a custom KEM combiner.

For each identity flight, `PairIdentityUnsignedProjectionV1` is the canonical
`PairPlaintextV1` projection with `identityTranscriptSignature` absent; no
other field is omitted. The signature input is:

```text
PairIdentitySignatureHash(
  binding: PairOuterBindingV1,
  unsignedProjection: PairIdentityUnsignedProjectionV1
) =
  H(
    "p2party/pair-identity-transcript/v1" ||
    Canonical(binding) ||
    Canonical(unsignedProjection)
  )

PairIdentitySignedMessage(
  binding: PairOuterBindingV1,
  unsignedProjection: PairIdentityUnsignedProjectionV1
) =
  "p2party/pair-identity-signature/v1" ||
  PairStepKindByte(unsignedProjection.kind) ||
  PairIdentitySignatureHash(binding, unsignedProjection)
```

The stable Ed25519 key signs the complete length-disjoint
`PairIdentitySignedMessage`, never a bare 32-byte hash that could collide with
the existing server-challenge signing API. HELLO is signed by the initiator,
and ACCEPT by the responder. The
`x25519CrossSignature` continues to use the exact existing
`IDENTITY_CROSS_SIGN_DOMAIN_BYTES || x25519PublicKey` construction and vectors;
it binds the later protocol-v4 3DH identity and is not replaced by the
rendezvous hybrid receiver key.

After the identity bootstrap, pre-promotion transport and v4-handshake steps use
purpose/direction/sequence-separated expansions of `EstablishedPairRoot`.
Post-promotion PQ/quiescence/checkpoint controls derive only from the current
protocol-v4 PQ root as specified in Section 4.13; there is no second
“v4 delivery secret.” Tags contain no stable server locator.

The pre-SDP state machine is:

```text
initiator:
  create response private-key package
  → create HPKE context and exact HELLO
  → invoke current-attempt with the exact unpublished HELLO and selected
    presence; it internally creates and consumes the opaque topology handle
  → if authorized, atomically persist keys, exact ciphertext, slot, and outbox
  → publish exact pair ciphertext

responder:
  open HELLO
  → verify pair/presence binding, commitment, and stable signature
  → derive opaque exact HELLO-time historical pair projection under current
    frontend/authority/planner/resource fences
  → run frontend Admit() within that same project-and-admit invocation
  → if denied: generate no sensitive response
  → if allowed: atomically persist bootstrap lease, exact ACCEPT, and outbox

initiator:
  open ACCEPT
  → verify responder commitment, identity, exact dependency, and signature
  → recapture the persisted outbound attempt coordinates/evidence and current
    fences, then rederive a fresh opaque applicable current or HELLO-time
    historical topology handle
  → run frontend Admit() within that same project-and-admit invocation
  → if denied: generate no SDP/ICE
  → if allowed: derive EstablishedPairRoot and atomically persist
    bootstrap lease, exact TRANSPORT_OFFER, and outbox

responder:
  authenticate TRANSPORT_OFFER under EstablishedPairRoot
  → require exact ACCEPT dependency
  → recapture the persisted admitted-attempt coordinates/evidence and current
    fences, then rederive a fresh opaque historical topology handle
  → re-run frontend Admit() within that same project-and-admit invocation
  → only then release the pair-private SDP/candidate to the transport
```

No SDP, ICE, DTLS fingerprint, local radio address, asynchronous mailbox
locator, or protocol-v4 handshake byte appears in the two identity flights.
The first transport offer is initiator key confirmation: the responder had
already admitted HELLO before ACCEPT, and an authenticated offer proves the
initiator received and admitted ACCEPT. Thus no standalone confirmation
round-trip is needed and neither side sends SDP to an identity it has not
admitted. Negative responses are fixed cover/dummy substitutions; they contain
no endpoint secret or policy reason.

After a provisional identity flight passes its stable signature, the receiver
persists a fork ledger keyed by
`(PairEdgeId, endpointPresenceOperationIds, direction, pairSequence)`. The
exact same operation ID replays the cached exact response. A different
stable-authenticated operation ID in that slot is a provisional pair fork and
fails that candidate; arrival order never selects it. The ledger survives
restart and remains through the pair-attempt horizon. After the first
EstablishedPairRoot-authenticated operation, the same rule is enforced by
established pair authentication and the durable edge ledger.

Each endpoint recomputes
`StableIdentityCommitment(RoomContextId, stableEd25519PublicKey)` and requires
it to equal the exact presence commitment. Both identity bundles are
byte-valid and cross-signed. If the confirmed Ed25519 public keys are
byte-equal, the provisional pair is rejected before role ordering or durable
identity; self/cloned presences cannot alias one edge owner. Otherwise:

```text
SessionRole =
  lexicographic order of the confirmed stable Ed25519 public keys

StableEdgeId =
  H(
    "p2party/stable-edge/v1" ||
    RoomContextId ||
    Sort2(stableEd25519PublicKeyA, stableEd25519PublicKeyB)
  )
```

`RendezvousRole=initiator` sends the first transport offer so that offer proves
it received and admitted ACCEPT. `SessionRole` controls the main protocol-v4
initiator/responder roles, Double-Ratchet direction, and the first PQ `OFFER`.
It never derives from rotating presence order.

Pair bootstrap state is provisional. A matching existing `StableEdgeId` may
resume or replace its transport only after the new transcript authenticates
the same stable identities and current room policy. The stable-edge claim slots
in Section 4.12 arbitrate duplicate handshakes; a local stable-edge lock only
serializes their atomic persistence. Everywhere this specification says an edge
“requires a fresh hybrid handshake,” it means a full new pair attempt over two
fresh presence operation IDs and therefore a fresh `PairEdgeId`; HELLO,
transport, v4, or PQ slots on the old pair edge are never reused. The newly
confirmed transcript may atomically replace the stalled record under the same
`StableEdgeId` only after its fresh protocol-v4 handshake succeeds. Until
then, the prior record remains closed/stalled and neither root set is mixed.

Every flight obeys persist-before-publish. An exact authenticated duplicate
replays the exact cached response. Before established-pair authentication,
malformed/invalid identity candidates are bounded rejected attempts. After a
confirmed pair transcript exists, valid pair AEAD with an invalid inner codec,
binding, signature, or expected slot is an authenticated endpoint violation
and fails that edge; invalid pair AEAD is bounded garbage. Any different
authenticated operation ID in the same encrypted direction/sequence slot is a
pair fork and fails only that edge, even when its plaintext is byte-equal,
while the provisional secret for that slot exists. Promotion atomically
records accepted operation IDs and erases bootstrap/pre-promotion roots. An
exact late ID is then ignored as a replay; any other old envelope is bounded
stale garbage and cannot mutate the stable edge, but omitted late equivocation
may no longer be provable. Section 4.13 defines the stronger retained-secret
rule only for post-promotion causal PQ slots.

Creating any pair response acquires one room-author allocation lock and uses
one durable atomic transaction—IndexedDB in the reference browser—over the
room author-chain tip, allocated outer sequence/predecessor, exact signed
operation, pair/edge candidate state, accepted-slot audit, cached response,
and outbox. Edge state is not adopted and bytes are not published until that
transaction commits. Concurrent edges therefore cannot allocate the same
author slot, and restore can always replay the exact operation rather than
reconstructing it from advanced state.

### 4.12 Transport negotiation and protocol-v4 handoff

```ts
type PairTransportCandidateV1 =
  | {
      version: 1;
      kind: "webrtc-complete";
      exactSdpUtf8: Uint8Array;
    }
  | {
      version: 1;
      kind: "operation-carrier";
    }
  | {
      version: 1;
      kind: "registered-local-link";
      adapterProtocolId: number;
      fixedCanonicalCandidate: Uint8Array;
    };

type StableEdgeAttemptClaimUnsignedV1 = {
  version: 1;
  stableEdgeId: Bytes32;
  pairEdgeId: Bytes32;
  confirmedPairTranscriptId: Bytes32;
  claimantStableEd25519PublicKey: Bytes32;
  claimNotBeforeLogicalWindow: bigint;
  claimNotAfterLogicalWindow: bigint;
};

type StableEdgeAttemptClaimV1 = StableEdgeAttemptClaimUnsignedV1 & {
  claimantSignature: Bytes64;
};

type PairTransportOfferV1 = {
  version: 1;
  initiatorStableEdgeClaim: StableEdgeAttemptClaimV1;
  candidates: readonly PairTransportCandidateV1[];
};

type PairTransportAnswerV1 = {
  version: 1;
  responderStableEdgeClaim: StableEdgeAttemptClaimV1;
  selectedOfferCandidateId: Bytes32;
  answer: PairTransportCandidateV1;
};

type TransportBindingV1 = {
  sessionInitiatorBinding: Bytes32;
  sessionResponderBinding: Bytes32;
};
```

Only after validating and admitting ACCEPT may `RendezvousRole=initiator` send a
`TRANSPORT_OFFER`. The complete offer and answer are pair encrypted and padded
to the class selected by `PairOperationPayloadClassFor`.

Stable-edge arbitration is bilateral and cannot use local arrival order. Each
stable identity maintains at most one unexpired durable claim for one
`StableEdgeId`. `claimNotBeforeLogicalWindow` equals the exact current
`PairAttemptLeaseV1.helloLogicalWindow`, and
`claimNotAfterLogicalWindow` equals its exact
`validThroughLogicalWindow`; a shifted, shorter, longer, future-starting, or
already-expired claim is invalid. The claimant signs:

```text
StableEdgeAttemptClaimSignedMessage =
  "p2party/stable-edge-attempt-claim-signature/v1" ||
  H(Canonical(StableEdgeAttemptClaimUnsignedV1))
```

Before either claim can be persisted or answered, both endpoints recompute
`StableEdgeId` from the two confirmed stable keys and require byte equality
with `claim.stableEdgeId`. In the offer claim,
`claimantStableEd25519PublicKey` must byte-equal the authenticated confirmed
rendezvous initiator key; in the answer claim it must byte-equal the
authenticated confirmed responder key. The signature is verified under that
exact key, and `pairEdgeId` plus `confirmedPairTranscriptId` must equal the
current admitted pair attempt. A wire-selected substitute key is never a claim
owner and cannot allocate or bypass an identity's one-live-claim slot.

The initiator atomically persists its first claim with
`TRANSPORT_OFFER`. The responder emits `TRANSPORT_ANSWER` only after it
atomically persists a matching claim for the same stable edge, pair edge,
confirmed transcript, and exact start/end interval, with the responder's own
claimant key. The
initiator validates that match before
feeding the answer to the transport or v4 handshake. One honest identity never
signs different claims whose inclusive
`[claimNotBeforeLogicalWindow, claimNotAfterLogicalWindow]` intervals overlap
for one stable edge, never overwrites an overlapping claim because a lower ID
arrived later, and never promotes without both exact claims in the protocol-v4
transcript.

If two distinct authenticated attempt IDs have overlapping claim intervals for
the same `(claimantStableEd25519PublicKey, StableEdgeId)`, the client
atomically retains their two exact claim/attempt IDs as one canonical conflict
audit and neither candidate wins: offers, answers, and v4 promotion for both
attempts stall. Every later answer/promotion checks the retained audit before
acting. The block ends only after the later
`claimNotAfterLogicalWindow + MaxClockSkewWindows(roomPolicy)` boundary.
After that boundary, each exact claim compacts to a bounded signed overlap
audit. It is charged to the room pair-ledger count/bytes, has
`retainThroughLogicalWindow = checkedAdd(claimNotAfterLogicalWindow,
pairControlRetentionWindows)`, and is deleted only at the start of the next
window. A detected overlap uses one bounded fault record through the greater
of the two retention horizons; it does not create a generation history. Retry
uses fresh presences and a fresh `PairEdgeId`; there is no
generation counter to desynchronize under loss or restore. A valid pair of
overlapping claims signed by one identity is a stable-edge fork and fails that
identity's edge. A claim replayed after its horizon cannot block or promote a
fresh attempt. Thus an asynchronous mutex need only serialize local
persistence; it is not misrepresented as distributed arbitration.

```text
TransportOfferCandidateId(candidate) =
  H(
    "p2party/transport-offer-candidate/v1" ||
    Canonical(candidate)
  )
```

An offer contains one to three candidates, sorted by unique
`TransportOfferCandidateId`. It contains exactly one `operation-carrier`,
at most one `webrtc-complete`, and at most one `registered-local-link`.
`operation-carrier` is mandatory and implemented by every conforming client,
so the control-plane handshake is never stranded merely because its browser or
bearer cannot satisfy an optional transport. It is control-only in v0.4 and
does not imply an application-data connection. A WebRTC SDP is 1 through
32,768 exact UTF-8 bytes. A registered local candidate is 1 through 2,048
bytes and its
`adapterProtocolId` is an unsigned 16-bit release-registry value. These bounds
are checked before adapter allocation and the complete offer/answer must still
fit the class selected by the shared codec rule.

`LocalTransportAdapterAllowed(adapterProtocolId)` requires exactly one
release-registry entry, installation, `FrontendContactAdapterAllowed`, prior
explicit local authorization for its discovery/source-metadata disclosure,
and every required platform permission already granted. Offer creation omits a
local-link candidate unless this predicate already holds. Answer selection
rechecks it before candidate parsing, hardware discovery, permission API, or
adapter allocation; failure selects the mandatory operation carrier. Remote
offer bytes can never create authorization or trigger a browser/OS permission
prompt. Policy generation is rechecked again at transport handoff.

The 32,768-byte SDP ceiling is a deliberate blind-profile interoperability
limit, not the legacy signaling parser's larger 256-KiB bound. Phase 0 must
measure complete offer/answer sizes across the supported browser, ICE, TURN,
IPv4/IPv6, and network matrix and freeze successful boundary vectors. A client
whose complete local SDP exceeds it omits WebRTC and offers the mandatory
operation carrier; a responder gathers before selection and does likewise.
The release does not silently truncate SDP or claim WebRTC compatibility for
that case. Raising the limit changes the pair/class codec and profile.

WebRTC mode uses complete ICE gathering and preserves the exact bounded UTF-8
SDP bytes produced and consumed by the implementation; no semantic
parse/reserialize “canonicalization” is permitted. One strict parser is the
SSOT for bounds and RFC 8122 syntax and requires exactly one valid SHA-256 DTLS
fingerprint. That parsed fingerprint is the transport-binding SSOT; invalid
UTF-8, zero/multiple/conflicting/non-SHA-256 fingerprints, or post-signing byte
changes fail before handoff. Future release vectors contain the exact SDP
bytes and parsed fingerprint. Demand-shaped trickle ICE is not part of the
v0.4 reference profile. `operation-carrier` has no locator, uses the
established pair-operation path, and carries only v4 handshake and pair-control
records. Every `adapterProtocolId` is a release registry entry fixing its
candidate codec, maximum length, endpoint binding, validation, and whether it
is control-only or application-data-capable; an unknown ID fails closed.

The responder selects exactly one advertised candidate by its exact offer
candidate ID and returns the corresponding answer. The answer kind must equal
the selected offer kind. A registered-local-link answer must also use the same
`adapterProtocolId`, and the registry must permit the exact offer/answer
candidate pair. Unknown kinds/IDs, a missing/duplicate selected ID, an
incompatible pair, or a noncanonical candidate fails before any adapter
receives it. A denied or no-longer-authorized local-link candidate is treated
as locally unavailable and selects `operation-carrier`; it does not fail the
room or ask the remote peer for authority. Selection is an endpoint-local availability preference, not
convergent room state; persist-before-publish makes its retry byte-identical.
If an optional selected transport fails after the answer, this one-shot pair
attempt stalls. Recovery creates fresh presences and a fresh `PairEdgeId` and
selects the mandatory operation carrier rather than writing a second value
into the old answer slot.

Blind mode never obtains TURN credentials from a server room/roster response.
`rtcConfig` is frontend-supplied from the shipped deployment registry or from
a room-independent credential service configured there. A dynamic request
contains no capability, room context, peer ID, presence, or SDP and its
source/timing disclosure is separately reported; credentials are scoped to
TURN abuse limits, not a room. A production deployment claiming ordinary
hard-NAT WebRTC reachability includes and tests that path in its one logical
deployment. If no usable STUN/TURN configuration exists, the client omits
WebRTC and honestly exposes a control-only edge rather than reusing legacy
room signaling.

The exact transport offer and answer operation IDs are the negotiation SSOT:

```text
TransportNegotiationTranscriptId =
  H(
    "p2party/transport-negotiation-transcript/v1" ||
    TransportOfferOperationId ||
    TransportAnswerOperationId
  )
```

Non-WebRTC candidates define two domain-separated 32-byte endpoint transport
bindings from that authenticated negotiation transcript. They shall not
substitute zeroes or pretend to be DTLS fingerprints.

For the operation-backed carrier transport, both endpoint bindings are
derived by the one formula below. `EndpointSessionRoleByte` is `0x00` for the
stable-key-ordered protocol-v4 initiator and `0x01` for the responder:

```text
OperationCarrierTransportBinding(endpointSessionRole, endpointStableKey) =
  H(
    "p2party/operation-carrier-transport-binding/v1" ||
    RoomContextId ||
    StableEdgeId ||
    ConfirmedPairTranscriptId ||
    TransportNegotiationTranscriptId ||
    EndpointSessionRoleByte ||
    endpointStableKey
  )
```

Concrete store IDs, routes, IP addresses, and arrival order are excluded, so
adding a carrier cannot change the authenticated transport. A carrier adapter
must reproduce this exact logical binding across HTTP, BLE, radio, or portable
files.

One rendezvous channel identifier binds the handoff:

```text
RendezvousChannelId =
  H(
    "p2party/rendezvous-channel/v1" ||
    RoomContextId ||
    PairEdgeId ||
    ConfirmedPairTranscriptId ||
    TransportNegotiationTranscriptId
  )
```

For WebRTC, the existing `buildChannelInput` receives
`RendezvousChannelId`, both stable Ed25519 keys, and both DTLS fingerprints.
For a non-WebRTC adapter, the same byte layout receives the two explicitly
domain-separated `TransportBindingV1` endpoint values. The implementation
shall rename/generalize the parameter semantics rather than create another
channel-input construction. Offer/answer bindings are first attached to the
authenticated stable key that sent them, then reordered by `SessionRole` for
the existing byte layout; `RendezvousRole` never controls that ordering.

The conformance binding is the exact pair-authenticated SDP bytes and their one
SHA-256 fingerprint passed byte-for-byte into a release-registered WebRTC
engine whose DTLS implementation is documented and tested to enforce the
remote SDP fingerprint. After DTLS establishment and before exposing a WebRTC
`HandshakeTransport`, `verifyDtlsFingerprints` additionally compares live
local and remote certificate stats whenever that registered engine exposes
them; any available mismatch, missing referenced certificate ID, or
unsupported algorithm fails closed. An engine such as a supported Firefox
version that does not expose certificate stats may conform only through the
exact WebRTC binding entry committed by the release registry's
`transportAdapterRegistryHash` and browser E2E vectors proving the native
SDP/DTLS enforcement path; absence of optional stats is then reported
as `transportBindingEvidence: "registered-native-enforcement"`, not
warning-based trust. An unknown or
unreviewed engine uses `operation-carrier`. Thus live stats are a
defense-in-depth tripwire, not a Firefox-breaking second source of truth.

The existing:

```ts
interface HandshakeTransport {
  send(bytes: Uint8Array): void | Promise<void>;
  recv(): Promise<Uint8Array>;
}
```

is the DRY protocol-v4 handshake boundary, not proof that its adapter can carry
application data. A WebRTC data channel, registered local-radio session, and
operation-backed pair-step adapter implement it. The operation-backed adapter
persists every outbound v4 handshake step as a pair operation and releases
only the next authenticated inbound step from its causal ledger.

The fresh protocol-v4 handshake must confirm:

- the exact pre-SDP stable identity bytes;
- `SessionRole`;
- `RendezvousChannelId`;
- both transport bindings;
- room PIN through CPace when configured;
- the room-selected ML-KEM suite; and
- its own fresh 3DH and ML-KEM transcript.

Only then is the stable cryptographic edge promoted. A selected WebRTC or
registry-declared application-data-capable local adapter is additionally
promoted as the application transport. With `operation-carrier` or a
control-only local adapter, the stable edge and PQ control path are established
but the runtime reports application transport unavailable; Section 4.13 does
not turn rendezvous operations into a data queue.
Pair-bootstrap X25519/ML-KEM secrets, temporary pair response private keys, and
provisional plaintexts are erased. The shared presence receiver private key
remains until its advertised validity/overlap horizon because other attempts
may still need it. The durable Double-Ratchet root, PQ-healing root, non-secret
edge binding, outbox, replay caches, and counters remain exclusively in the
existing atomic stable-edge state.

The current PIN/CPace check occurs in this v4 handshake, after WebRTC SDP/ICE
has already been exchanged under the admitted pair envelope. It is session
authentication and transport-promotion protection, not pre-SDP PIN privacy.
Blacklist, address-book proof, and authority admission protect SDP. A product
that promises “the PIN hides SDP” must instead specify and review a
pre-SDP PAKE; v0.4 makes no such claim.

### 4.13 Post-quantum healing over eventual delivery

The existing protocol-v4 `PqHealingMachine`, record codecs, uniform
65,490-byte control frame, root schedule, counter/turn rules, exact duplicate
behavior, and atomic persist-before-dispatch contract remain the SSOT.
Rendezvous changes only how an exact persisted frame can be delivered.

The raw current `pqHealingFrame` is not a valid store object by itself. Its
authenticated but clear header contains a stable edge-control binding,
counter, direction-related material, and PQ epoch. The complete exact frame,
including that header, shall be ciphertext inside a pair-private delivery
envelope, which is then inside the room carrier envelope.

For one expected v4 or barrier slot:

```ts
type PqDeliverySlotV1 = {
  version: 1;
  sessionDirection: 0 | 1;
  recordKind: "OFFER" | "ADVANCE" | "ACK";
  counter: bigint;
  fromEpoch: bigint;
  toEpoch: bigint;
  keyEpoch: bigint;
  suiteId: number;
  v4WireBinding: Bytes32;
};

type PqPairControlSlotV1 = {
  version: 1;
  sessionDirection: 0 | 1;
  controlKind:
    "QUIESCE_PROPOSE" | "QUIESCE_ACK" | "HEAL_COMPLETE" | "PAIR_CHECKPOINT";
  pqEpoch: bigint;
  keyEpoch: bigint;
  suiteId: number;
  v4WireBinding: Bytes32;
};

type PqSlotV1 =
  | {
      version: 1;
      slotClass: 0;
      value: PqDeliverySlotV1;
    }
  | {
      version: 1;
      slotClass: 1;
      value: PqPairControlSlotV1;
    };

type PqPairSlotCandidateV1 = {
  exactPqSlot: PqSlotV1;
  exactPairSlot: PairFlightSlotV1;
};

// Exact canonical AuthenticatedRoomOperationV1 bytes containing one
// pair-encrypted response; never a reconstructed logical object.
type ExactPairOperationBytesV1 = Uint8Array;

type PqSlotAuditV1 = {
  exactPqSlot: PqSlotV1;
  exactPairSlot: PairFlightSlotV1;
  acceptedPairOperationId: Bytes32;
  pqSlotSecret: Bytes32;
  cachedExactResponse: ExactPairOperationBytesV1 | null;
  acceptedLogicalWindow: bigint;
  retainThroughLogicalWindow: bigint;
};

type QuiesceProposeV1 = {
  version: 1;
  pqEpoch: bigint;
};

type QuiesceAckV1 = {
  version: 1;
  pqEpoch: bigint;
};

type HealCompleteV1 = {
  version: 1;
  newPqEpoch: bigint;
};
```

Every `bigint` counter/epoch is unsigned 64-bit big-endian on wire.
`slotClass`, directions, kinds, and `suiteId` are one byte. Slot classes are
`delivery=0x00` and `pair-control=0x01`; delivery record kinds are
`OFFER=0x01`, `ADVANCE=0x02`, and `ACK=0x03`, matching the decrypted v4
record type bytes. Pair-control kinds reuse the `PairStepKindByte` registry:
`QUIESCE_PROPOSE=0x06`, `QUIESCE_ACK=0x07`, `HEAL_COMPLETE=0x08`, and
`PAIR_CHECKPOINT=0x09`. Unknown/reserved values fail before KDF use.

Every slot's `suiteId` equals the stable edge's persisted room-selected v4
suite. A raw `pqHealingFrame` does **not** expose that suite in its public
header. Only after `openPqControlFrame` succeeds must the decrypted inner
OFFER/ADVANCE/ACK record's suite byte at offset 6 equal the slot and persisted
suite. `sessionDirection=0`
means the lower confirmed stable Ed25519 key (`SessionRole=initiator`) sends
to the higher key; `1` is the reverse. `PairPlaintextV1.direction` is
independently determined by the sender's persisted `RendezvousRole`; the two
numeric direction domains may differ and are never copied.

`ExpectedPqPairSlots(edgeSnapshot)` is one total state-derived mapping that
produces `PqPairSlotCandidateV1` tuples before either rendezvous-slot or
pair-flight KDF use. For a delivery slot, `exactPairSlot.kind="PQ_CONTROL"`;
for a pair-control slot it equals the slot's exact `controlKind`.
`exactPairSlot.direction` is the expected sender's persisted
`RendezvousRole` direction and `exactPairSlot.pairSequence` is that direction's
next pair-ledger sequence. `exactPqSlot.value.sessionDirection` is derived
separately from stable-key `SessionRole` and the v4 machine transition.
Sender construction rejects a control body/raw frame that does not match both
slots before sealing. Receiver opening derives the same tuple from its
snapshot, uses only those typed values in their respective KDFs, and after
AEAD validates that the plaintext/body/raw frame match both. No numeric
direction is cast or copied between domains.

Let `e` be the current epoch and `d` the existing v4 machine's next-OFFER
sender direction. The only causal chain is:

| Pair step / raw record      | Sender session direction | Key epoch | Exact `pairDependencies`   |
| --------------------------- | ------------------------ | --------- | -------------------------- |
| `QUIESCE_PROPOSE(e)`        | `d`                      | `e`       | empty                      |
| `QUIESCE_ACK(e)`            | `1-d`                    | `e`       | PROPOSE operation ID       |
| `PQ_CONTROL/OFFER(e→e+1)`   | `d`                      | `e`       | QUIESCE_ACK operation ID   |
| `PQ_CONTROL/ADVANCE(e→e+1)` | `1-d`                    | `e`       | OFFER operation ID         |
| `PQ_CONTROL/ACK(e→e+1)`     | `d`                      | `e+1`     | ADVANCE operation ID       |
| `HEAL_COMPLETE(e+1)`        | `1-d`                    | `e+1`     | ACK operation ID           |
| `PAIR_CHECKPOINT(e+1)`      | `d`                      | `e+1`     | HEAL_COMPLETE operation ID |

Same-direction predecessor and sequence rules still apply. Body fields never
duplicate those exact operation IDs. For raw v4 frames, only these slots are
canonical:

| Frame     | Counter                   | `fromEpoch` | `toEpoch` | `keyEpoch` |
| --------- | ------------------------- | ----------- | --------- | ---------- |
| `OFFER`   | existing `offerCounter`   | `e`         | `e+1`     | `e`        |
| `ADVANCE` | existing `advanceCounter` | `e`         | `e+1`     | `e`        |
| `ACK`     | the same `advanceCounter` | `e`         | `e+1`     | `e+1`      |

`toEpoch` must equal `fromEpoch + 1`. `v4WireBinding` is byte-for-byte the
existing 32-byte authenticated `PqHealingMachine.binding`; rendezvous does not
hash or reconstruct a second binding. It and `suiteId` are included in every
slot and KDF/AAD.

Rendezvous code never reads or copies a raw `PqRoot`. The v4 healing machine
owns one narrow transaction-scoped hook:

```ts
deriveRendezvousSlotSecret(exactPqSlot: PqSlotV1): Bytes32;
```

It succeeds only for a slot legal in the machine's current cloned state and
selects the exact old/new root required by `exactPqSlot.value.keyEpoch`. Its
suite-1 vector is:

```text
PqSlotPrk =
  HKDF-SHA512-Extract(
    salt =
      "p2party/l3-pq-slot/extract/v1" ||
      RendezvousChannelId,
    ikm = machineOwnedPqRoot[exactPqSlot.value.keyEpoch]
  )

PqSlotSecret =
  HKDF-SHA512-Expand(
    PqSlotPrk,
    "p2party/l3-pq-slot/expand/v1" ||
    Canonical(exactPqSlot),
    32
  )
```

The copied 32-byte result is immediately wrapped into the same atomic
candidate commit, then zeroized by the caller; the raw root never crosses the
machine boundary. A future v4 KDF change requires a new rendezvous slot suite
and vectors, not an implicit switch to the room's HKDF-SHA-256.

Every post-promotion control calls the single
`SealPairStep(PqSlotSecret, exactPairSlot, exactPrebinding, exactPlaintext)`
path from Section 4.11; only `exactPqSlot` enters
`deriveRendezvousSlotSecret`. That path samples and persists the public 24-byte
pair nonce and derives only the one-use tag and pair AEAD key. A slot secret
never derives a nonce. Exact retry resends the persisted operation bytes. The
complete pair envelope remains inside carrier encryption, so the store sees no
edge, direction, kind, counter, or epoch.

For every post-promotion `PQ_CONTROL`, `QUIESCE_PROPOSE`, `QUIESCE_ACK`,
`HEAL_COMPLETE`, or `PAIR_CHECKPOINT`, the canonical outer lifetime is exact:

```text
outer.lifetime == "PAIR_CAUSAL"
outer.expiresAfterWindow ==
  checkedAdd(
    outer.logicalWindow,
    roomPolicy.protocolLimits.pairControlRetentionWindows
  )
```

A shorter or longer encoding is invalid before pair-state mutation. This is
the same inclusive horizon used by `PqSlotAuditV1`, so ordinary outer
validation can still authenticate an exact boundary replay or fork.
Pre-promotion identity, transport, and v4-handshake steps may use a shorter
exact attempt/lease horizon, still bounded above by
`pairControlRetentionWindows`; they receive no post-promotion audit claim.

While testing an `OFFER` against a cloned pre-state, the responder derives the
candidate outbound `ADVANCE` wrapping material from the old root. It persists
that material only in the same atomic commit that authenticates the exact
OFFER operation and adopts the v4 transition; invalid candidates never advance
durable state. ACK wrapping uses the newly committed root. The existing exact
v4 outbox remains the raw-frame SSOT; the adapter stores only protected
wrapping intent and verifies after restore that it encloses byte-identical
outbox bytes.

Every existing v4 transition that replaces the active PQ root/epoch commits
that root, epoch, accepted-operation audit, and active scheduled-cover sealing
context in the same atomic stable-edge mutation. A cover send opportunity
after the commit seals only from the new snapshot; root/epoch switches never
reset cadence or its monotonic cover counters and never create a catch-up
burst. Any inbound cover frame whose public epoch differs from the loaded exact
epoch is discarded before decryption, subtype classification, replay-counter,
healing-machine, gate, or edge mutation and is never retried. Quiescence
ensures honest frames crossing the commit boundary contain dummy cover only.
Dummy cells are neither causal pair operations nor retained successors, so
their continuous cadence cannot hold `Quiescent(edge)` false or keep an old
root alive.

The per-edge ingress algorithm is:

```text
load one atomic stable-edge snapshot
→ enumerate the closed union of:
    (a) ExpectedPqPairSlots(snapshot) legal as the next machine transition, and
    (b) unexpired retained slot-audit tuples
→ derive routing tags with a current machine-owned slot secret for (a)
  or the retained one-use audit secret for (b);
  every attempted open counts against pair-open work
→ collect matching room-authenticated pair operations from all carriers
→ authenticate pair envelope and exact pair operation ID
→ for an audit tuple: exact accepted ID replays only its cached exact response;
  any other authenticated ID fails the edge as a fork; never transition v4
→ classify the raw frame, when present, at the v4 layer
→ run each unique candidate against a clone of pre-state
→ atomically persist candidate v4 state, accepted-operation audit,
  response wrapping intent, exact response, and existing raw outbox
→ adopt the clone and publish the exact response on active carriers
```

The adapter does not feed a future slot into v4, invent reordering inside the
healing machine, wait for a quorum, or let a store decide a fork:

| Candidate                                                                                                              | Result                                                                                                                                          |
| ---------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| Invalid carrier/room signature or AEAD, invalid pair AEAD, unknown tag, or out-of-budget bytes                         | Drop as bounded unauthenticated garbage; do not fail an honest edge.                                                                            |
| Valid established-pair AEAD but wrong pair codec, expected kind/slot, raw v4 length/header, or inner v4 authentication | Authenticated endpoint violation; fail only that edge.                                                                                          |
| Exact previously accepted pair operation ID in the slot                                                                | Replay the cached exact response without another transition; the terminal `PAIR_CHECKPOINT`, whose response is null, is an authenticated no-op. |
| Any other fully authenticated pair operation ID in the slot                                                            | Authenticated pair fork; fail only that edge, even if the raw frame is equal.                                                                   |

The accepting transaction constructs exactly one `PqSlotAuditV1` and requires:

```text
retainThroughLogicalWindow =
  checkedAdd(
    acceptedLogicalWindow,
    roomPolicy.protocolLimits.pairControlRetentionWindows
  )
```

`acceptedLogicalWindow` is the authenticated room operation's exact logical
window, not arrival time. `cachedExactResponse` is null only for terminal
`PAIR_CHECKPOINT`. The raw accepted operation, exact response/outbox, and
audit are initially one atomic edge record. After the exact successor proof
listed below, the raw predecessor and its publication outbox may compact, but
the minimal audit remains in the closed candidate union through the end of
`retainThroughLogicalWindow`, inclusive. It is deletable only when the
captured `referenceWindow > retainThroughLogicalWindow`—equivalently at the
start of the next logical window—and that comparison and deletion are one
checked atomic transition.

An audit tuple may authenticate only an exact replay or fork; it cannot derive
a new response, become current again, or mutate v4 state. It does not retain
an old `PqRoot` merely to classify replay. Omission may hide an equivocation
from one peer and is reported as an availability limit.

Retention follows the table's exact successor proofs:

- PROPOSE remains through the exact QUIESCE_ACK;
- QUIESCE_ACK remains through the exact OFFER;
- OFFER remains through the exact ADVANCE;
- ADVANCE remains through the exact v4 ACK;
- the offerer retains ACK until exact HEAL_COMPLETE proves the responder
  consumed it;
- the responder retains and republishes HEAL_COMPLETE until exact
  PAIR_CHECKPOINT;
- the responder may compact the HEAL_COMPLETE operation/outbox after that
  checkpoint while retaining its minimal slot audit; and
- PAIR_CHECKPOINT is the finite terminal receipt. Its raw operation and
  terminal audit remain through its own inclusive
  `retainThroughLogicalWindow` and are deleted only at the start of the next
  window.

If `referenceWindow` first becomes greater than a required control's
`retainThroughLogicalWindow` without its exact successor, one transaction
marks the edge `stalled` before deleting expired publish custody. It does not
infer success, reset the epoch, reopen a gate, or discard an uncertain
transfer; recovery is a fresh hybrid v4 handshake for that stable pair.

#### Quiescence state machine

`Quiescent(edge)` is one shared predicate:

1. the application gate is durably non-open;
2. every admitted outbound old-epoch transfer has an authenticated remote
   terminal receipt, or a transport-specific completed cancellation proving
   that no already-sent old-epoch frame can arrive;
3. no inbound transfer is active or queued; and
4. all admitted real-transfer and terminal receipt/cancel jobs in the
   scheduled queues are settled and empty.

For an ordered direct WebRTC transport, a reviewed terminal channel-close
procedure may be the cancellation proof. A local cancel or generic WebRTC
drain signal alone is not. Scheduled dummy cover continues and is excluded
from `Quiescent`; pair/PQ controls may replace dummies only in their fixed
public roles. Scheduled mode requires authenticated terminal receipts and
empty durable _real-job_ queues. PROPOSE and ACK are authenticated
assertions that the sender's local predicate held; they cannot prove a
malicious peer's hidden state.

Healing executes:

```text
offerer:
  atomically persist gate=QUIESCING(e), with no outbound proposal
  → drain/cancel until Quiescent(edge), retaining durable terminal witnesses
  → atomically persist exact QUIESCE_PROPOSE + outbox

responder:
  authenticate exact proposal/dependency/epoch
  → atomically persist gate=QUIESCING(e), with no outbound ACK
  → drain/cancel until Quiescent(edge)
  → atomically persist exact QUIESCE_ACK + outbox

offerer:
  authenticate exact ACK and require local Quiescent(edge)
  → atomically persist gate=BARRIER_LOCKED(e) and exact v4 OFFER

both:
  execute existing OFFER → ADVANCE → ACK with gates closed

responder after consuming ACK:
  atomically persist new-root state, exact HEAL_COMPLETE, and
  pqGate=OPEN(e+1)

offerer:
  authenticate exact HEAL_COMPLETE under e+1
  → atomically persist exact PAIR_CHECKPOINT and pqGate=OPEN(e+1)
```

`pqGate=OPEN` means only that the PQ epoch barrier permits application
cryptography. The independent application-send predicate is:

```text
ApplicationCanSend(edge) =
  pqGate(edge) == OPEN &&
  selectedTransport(edge).applicationDataCapable == true &&
  selectedTransport(edge).status == PROMOTED
```

An operation-carrier or another control-only adapter can reach `pqGate=OPEN`
but never satisfies `ApplicationCanSend`; no application send is queued into
the operation layer. Restore keeps every non-OPEN PQ gate closed until the
exact successor completes
or a fresh hybrid handshake safely replaces the edge. New-epoch application
frames that race HEAL_COMPLETE are authenticated, buffered without dispatch
behind the offerer's gate under `maxPairLedgerBytesPerRoom`, and released only
after HEAL_COMPLETE. Overflow stalls the edge. The checkpoint is not
acknowledged again, so there is no acknowledgement recursion. Gate, causal
operation IDs, terminal witnesses, slot audits, and exact outboxes are one
atomic edge record at every transition.

This v0.4 operation layer does not carry asynchronous application data. If a
future profile does, it must add durable bilateral send/receive watermarks and
acknowledge every operation at or below the barrier before `OFFER`, or retain
bounded old roots under a separately reviewed construction. It shall not
silently reuse this control-only rule.

`DeliveryWindow`, protocol-v4 `PqHealingEpoch`, and data-plane
`CoverEpochIndex` are distinct types, KDF domains, counters, and persistence
fields even when numeric values coincide.

### 4.14 Normative L3 portable and contact operation

```ts
type PortableBundleInventoryEntryV1 = {
  deliveryProfileHash: Bytes32;
  ingressWindow: bigint;
  sizeClass: number;
  carrierObjectId: Bytes32;
};

type PortableBundleV1 = {
  version: 1;
  carrierContextId: Bytes32;
  createdAtUnixMs: bigint; // diagnostic only; never a validity input
  deliveryProfileHashes: readonly Bytes32[];
  objectInventory: readonly PortableBundleInventoryEntryV1[];
  fixedObjects: readonly Uint8Array[];
};

type L3DueWorkAttemptV1 = {
  localRoomId: LocalRoomId; // protected canonical text handle; never exported
  operationId: Bytes32;
  deliveryProfileHash: Bytes32;
  serviceWorkKind: ServiceWorkKindV1;
  semanticExpiryLogicalWindow: bigint;
  // Exclusive absolute deadline derived from this room's immutable cadence.
  semanticDeadlineUnixMs: bigint;
  deliveryAttemptCount: bigint;
};

type L3RoomExportScopeV1 = {
  localRoomId: LocalRoomId;
  roomCarrierAssignmentPolicyGeneration: bigint;
  activeDeliveryProfileHashesDigest: Bytes32;
};

type L3ExportTargetV1 =
  | {
      kind: "portable-bundle";
      adapterProtocolId: number; // unsigned 16-bit
      // Generated only inside the prepare transaction; never caller-supplied.
      bundleCarrierContextId: Bytes32;
      deliveryProfileHashes: readonly Bytes32[]; // exact permitted set
      roomScopes: readonly L3RoomExportScopeV1[];
    }
  | {
      kind: "authenticated-contact";
      adapterProtocolId: number; // unsigned 16-bit
      authenticatedSessionContextId: Bytes32;
      contactCarrierInstanceId: Bytes32;
      deliveryProfileHash: Bytes32; // exactly one profile per contact batch
      roomScopes: readonly L3RoomExportScopeV1[];
    };

type L3ExportCommitV1 = {
  version: 1;
  state: "prepared";
  exportSequence: bigint;
  target: L3ExportTargetV1;
  exportCompatibilityId: Bytes32;
  selectedWork: readonly {
    localRoomId: LocalRoomId;
    operationId: Bytes32;
    deliveryProfileHash: Bytes32;
  }[];
  exactOutputHash: Bytes32;
};
```

The encoder is canonical, streaming, length-prefixed, and bounded before
allocation. v1 has no continuation, page token, or recursive bundle: an export
is one self-contained bounded snapshot. If more retained work exists, a later
independent bundle uses a fresh context and rewraps its own bounded selection.

Portable export and automated contact use one persisted due-work scheduler;
they do not each invent a backlog policy. `L3DueWorkAttemptV1` is bounded
delivery metadata derived from the canonical retained operation/outbox, not a
second logical queue. Its role is derived by the exact
`OperationServiceRole` classifier already used by the public append schedule;
the stored `serviceWorkKind` and referenced operation are its SSOT. Within each
role, due work uses:

```text
L3DueWorkOrder =
  if role == "identity-bootstrap":
    (
      IdentitySubpriority(intent),
      deliveryAttemptCount,
      semanticDeadlineUnixMs,
      OperationId,
      DeliveryProfileHash
    )
  else:
    (
      deliveryAttemptCount,
      semanticDeadlineUnixMs,
      OperationId,
      DeliveryProfileHash
    )
```

Thus no new HELLO passes a pending ACCEPT, while attempt count still prevents
one same-subpriority record from monopolizing repeated contact. One record is one exact
`(LocalRoomId, OperationId, DeliveryProfileHash)` wrap intent whose fixed
class and worst-case encoded bytes are known before budgeting; selecting an
operation never implicitly expands into multiple profiles or objects.

For the intent's exact immutable room policy:

```text
semanticDeadlineUnixMs =
  checkedMultiply(
    checkedAdd(
      semanticExpiryLogicalWindow,
      checkedAdd(roomPolicy.protocolLimits.maxClockSkewWindows, 1)
    ),
    roomPolicy.protocolLimits.logicalWindowMs
  )
```

It is the first Unix millisecond outside the inclusive
expiry-plus-clock-skew horizon, so work must complete strictly before it.
The scheduler validates this derivation whenever loading the record. Raw
logical-window indices from rooms with different `logicalWindowMs` are never
compared as deadlines.

Selection is target-specific before any role head is chosen:

```text
EligibleL3DueWork(target, activationAtUnixMs) =
  {
    work |
    one exact scope in target.roomScopes has
      scope.localRoomId == work.localRoomId
    and the protected room record still exists and has not been discarded
    and scope.roomCarrierAssignmentPolicyGeneration ==
        room.carrierAssignments.policyGeneration
    and scope.activeDeliveryProfileHashesDigest ==
        H(
          "p2party/active-delivery-profile-set/v1" ||
          Canonical(room's exact current active delivery profile hashes)
        )
    and work.deliveryProfileHash is in that exact active profile set
    and the referenced operation/outbox intent remains retained, required,
        and nonterminal
    and activationAtUnixMs < work.semanticDeadlineUnixMs
    and if target.kind == "portable-bundle":
      work.deliveryProfileHash is in target.deliveryProfileHashes
      and the adapter is installed, locally authorized, and passes
          FrontendContactAdapterAllowed
      and the exact profile/class/object fits the registered portable codec,
          reassembly, inventory, object-count, and bundle-byte bounds
    else:
      work.deliveryProfileHash == target.deliveryProfileHash
      and target.contactCarrierInstanceId ==
          ContactCarrierInstanceId(current authenticated contact context,
                                   target.deliveryProfileHash)
      and target.authenticatedSessionContextId equals that current context
      and target.contactCarrierInstanceId is in
          CarrierContextIds(
            ActiveCarrierContexts(room, activationAtUnixMs)
          )
      and target.contactCarrierInstanceId is not in
          room.carrierAssignments.disabledCarrierContextIds
      and the adapter is installed, locally authorized, and passes
          FrontendContactAdapterAllowed
      and ContactAdapterCompatible holds for that exact adapter/context/profile
      and the fixed class fits its fragmentation, reassembly, inventory,
          batch-count, and batch-byte bounds
  }
```

Role heads, fit tests, and `L3DueWorkOrder` are evaluated only over this
projection. Ineligible records and their attempt counters/cursors remain
unchanged and cannot head-of-line block compatible work. A portable target may
be heterogeneous; an authenticated-contact target is deliberately
single-profile because `ContactCarrierInstanceId` is profile-bound. Multiple
profiles on one physical contact use separate bounded commits/batches.
`roomScopes` is nonempty, sorted by canonical `LocalRoomId`, duplicate-free,
protected local metadata, and never exported. The explicit caller/UI action
selects this bounded room scope before work selection; a request scoped to room
A cannot select room B's same-profile backlog.

```text
L3ExportCompatibilityId(target) =
  H(
    "p2party/l3-export-compatibility/v1" ||
    Canonical(
      target kind,
      if portable:
        adapterProtocolId and exact sorted deliveryProfileHashes
        // deliberately excludes the per-export bundleCarrierContextId
      else:
        adapterProtocolId, authenticatedSessionContextId,
        contactCarrierInstanceId, and deliveryProfileHash,
      exact sorted roomScopes,
      BlindRendezvousReleaseRegistryHash,
      H(Canonical(globalResourcePolicy)),
      carrierPolicy.policyGeneration,
      exact adapter/codec registry entry,
      exact effective count/byte/fragment/reassembly limits
    )
  )
```

The value is recomputed before replay or dispatch; it is an exact pending-byte
compatibility key, not a room or wire target.

`AssuranceRuntimeFactsV1.readyL3CarrierInstanceIds` is derived from this same
scheduler snapshot. It contains a contact or portable
`carrierInstanceId` only while an authenticated current custody path or
durable-handoff-acknowledged portable handoff has an unexpired measured
`ready-before-retention` result, includes every required intent selected for
that path, and passes the exact remaining-capacity simulation. Expiry,
cancellation, missing intents, unacknowledged export loss, or cap saturation
removes it atomically. The set is room-scoped, sorted, and duplicate-free; it
is assurance evidence for episodic custody, not permission to allocate a
public/contact active-carrier slot. A portable handoff contributes one
profile-bound `PortableCarrierInstanceId` for each profile whose exact required
intents and capacity simulation pass; all such IDs retain the same measured
custody `availabilityPathId`.

The scheduler persists one role cursor over the closed order
`safety-control → identity-bootstrap → state-replication`. A fresh bounded
target-bound export visits roles cyclically from that cursor, selects the
eligible head that fits
the remaining exact byte/count budget, advances past every selected role, and
ends when no visited head fits. A compatible adapter/bundle bound must fit the
largest single permitted fixed object, so a head skipped in a partly filled
batch fits when its role begins a later empty batch. The next export begins
after the last selected role; an empty role is skipped but does not reset the
cursor. Thus repeated capacity cannot resend one low-ID prefix forever, while
the attempt count rotates work within each role.

Before exposing any byte, one transaction allocates `exportSequence`, persists
the exact target, compatibility ID, ordered work refs and wraps, increments
each selected work record's `deliveryAttemptCount`, advances the role cursor,
and persists `L3ExportCommitV1` plus the exact output bytes. A portable export
request supplies only kind, adapter, permitted profiles, and room scopes. The
transaction samples `bundleCarrierContextId` as uniform 32-byte CSPRNG output,
rejects and resamples a collision with any retained/pending bundle context,
persists it before wrapping, and then forms the committed target; callers
cannot select this cryptographic/assurance domain. Exact replay retains that
same value. An authenticated-contact export allocates no fresh context: every
wrap is under its one current exact profile-specific
`ContactCarrierInstanceId`. A crash re-presents that byte-identical committed
output; it never selects a new prefix or context under the same sequence.

Immediately before every first dispatch or replay, one transaction recomputes
the compatibility ID and `EligibleL3DueWork(target)` for every `selectedWork`.
If any selected item or room scope no longer matches—because of disable,
policy/profile generation change, room discard, terminal/expired operation,
session rollover, or deadline—the exact prepared bytes are not exposed. The
transaction records target loss, deletes that unusable commit/bytes, and
leaves every still-required canonical due intent available for another
currently authorized target.

`prepared` has one exact lifecycle. The pending commit and exact bytes are
charged before selection to both client-global pending-export count/byte caps.
The caller or automated adapter then gives an explicit durable-handoff
acknowledgement only after the file/removable-medium write is flushed or the
contact transport has accepted durable custody. One transaction consumes that
ack and deletes the pending exact bytes/commit; a crash before it re-presents
the exact prepared output, and a crash after it cannot resurrect it. An
unacknowledged portable export is also deletable when every selected intent is
terminal/expired or by an explicit local discard that records loss and
degrades availability. A pending contact output is replayable only while its
exact authenticated session and `contactCarrierInstanceId` remain current.
Session expiry/rollover atomically records loss, deletes those unusable pending
bytes, leaves the canonical due intents queued, and permits a later wrap under
a new instance; old-session ciphertext is never relabelled.
At cap, a request re-presents the oldest pending exact output only when its
recomputed `L3ExportCompatibilityId` byte-equals the request's value (and, for
contact, the exact live instance still matches). An explicit resume by exact
`(exportSequence, exactOutputHash)` revalidates and returns that commit
independently of the cap; an automatic request selects the oldest matching
commit, not the oldest incompatible global commit. Only when no matching
commit exists does a full cap make creation fail with
`pending-l3-export-capacity` and does not advance the cursor, attempts, or
sequence. Repeated manual export clicks therefore cannot create unbounded
storage.

Acknowledged completion permits a later independent bundle or contact batch.
Import duplicates remain idempotent. An authenticated contact
inventory may suppress objects it proves the remote already has at the
permitted inventory layer, but it uses the same due-work order/cursor for
everything else and cannot reset attempt counts.

The liveness claim is conditional and finite: if enough successful
bundle/contact capacity occurs before each semantic expiry, each compatible
export can carry at least one due object, and the custody path does not
permanently omit a recipient, every continuously due retained item is
eventually selected. Otherwise the client reports backlog/partition and does
not claim L3 convergence.

Creation of an exact `(room, operation, profile)` due intent and its initial
attempt record is transactional and succeeds only if both client-global L3
count/byte caps still fit. Saturation never evicts an accepted operation,
truncates an export, or silently chooses a convenient subset. The canonical
bounded operation/outbox remains, the affected room/path reports
`l3-backlog-saturated`/partitioned, and a bounded scan in the same
role/absolute-deadline/ID/profile order admits missing intents when terminal/expired work
frees space. No L3 convergence or shutdown-survival claim holds while a
required intent is missing. Attempt records are garbage-collected only when
that exact operation/profile intent is terminal, semantically expired, or the
profile is explicitly deactivated; restart and ordinary failed contacts never
reset their counters. Release resource simulation must fit the permitted
worst-case safety/identity chains or reject the configuration before
activation.

The exact manifest invariants are:

1. `objectInventory.length == fixedObjects.length`;
2. the length is positive and no larger than both
   `globalResourcePolicy.maxContactInventoryEntries` and the count derived from
   `globalResourcePolicy.maxPortableBundleBytes`;
3. entries are unique and sorted by
   `(deliveryProfileHash, ingressWindow, sizeClass, carrierObjectId)`;
4. each object at index `i` canonically decodes as `CarrierEnvelopeV1`, its
   profile/window/class/context equal entry `i` and the bundle context, its
   byte length equals that profile class, and recomputing `CarrierObjectId`
   equals entry `i`;
5. `deliveryProfileHashes` is the exact sorted unique projection of inventory
   profile hashes, every profile is locally implemented, and no unlisted
   profile or trailing object exists; and
6. the complete encoded bundle, including every prefix and object, is at most
   `globalResourcePolicy.maxPortableBundleBytes`; arithmetic is checked before
   allocation.

Those two vault-global limits are selected before manifest allocation or room
decryption and are identical for every room in a bundle/contact batch. Adapter
registry limits may only lower them. After an object opens, its room-local
candidate/reconcile/outbox caps apply normally; no room policy can enlarge the
outer parse. Two rooms with different per-room work policies therefore share
one bounded outer parse while retaining independent inner admission.

`objectInventory` contains carrier object hashes, not room operation IDs. The
bundle is untrusted; room AEAD, operation signatures, pair AEAD, and
protocol-v4 authentication provide integrity. An optional sender/device
signature is custody evidence only and does not authorize room state.

A portable exchange is:

```text
export:
  run the persisted fair due-work selection
  → choose a fresh carrierContextId
  → rewrap that exact fixed/bounded selection for the context
  → include scheduled dummies/padding where the chosen profile requires
  → atomically persist L3ExportCommitV1 and finalize exact bundle bytes

import:
  parse under fixed limits
  → verify public object hashes
  → run the ordinary receive pipeline
  → queue newly valid operations for all active carriers
```

Repeated manual file, QR-for-small-control, NFC, USB, or removable-media
exchange can therefore drive the same causal pair state machine. The reference
large-control path is a file/removable-media bundle; it shall not claim that a
65-kilobyte v4 frame fits one QR symbol.

An automated non-IP contact adapter uses the same inventory/batch semantics.
It may run over BLE, Wi-Fi Aware without IP, acoustic modem, packet radio, or
another reviewed bearer. Its adapter specification declares discovery
metadata, framing, MTU/fragmentation, authentication, retry, power, custody,
contact duration, and physical observer set.

L3 does not assume a synchronized online round. It uses coarse public windows,
persisted outboxes, bounded clock skew, causal dependencies, expiry, and
republish-on-contact. If contacts partition longer than retention, availability
is exhausted. Every bounded L3 ingestion transaction—one portable-bundle
import or one automated contact adapter batch—is one atomic
preflight-and-commit transaction. Let `clockEstimateMs` and
`clockUncertaintyMs` be one captured non-negative wall-clock estimate and its
non-negative upper error bound supplied by the platform's reviewed clock
source at ingestion. The pair is immutable throughout that transaction.
Before opening any object, the ingestor requires, for every exact profile
named by the bundle manifest or contact-batch inventory,

```text
clockUncertaintyMs <= profile.maxScheduleSkewMs

lowerMs = checkedSubtract(clockEstimateMs, clockUncertaintyMs)
upperMs = checkedAdd(clockEstimateMs, clockUncertaintyMs)

floor(lowerMs / profile.deliveryWindowMs)
  == floor(upperMs / profile.deliveryWindowMs)
```

and, for every successfully opened room operation,

```text
clockUncertaintyMs
  <= roomPolicy.protocolLimits.maxClockSkewWindows
     * roomPolicy.protocolLimits.logicalWindowMs

floor(lowerMs / roomPolicy.protocolLimits.logicalWindowMs)
  == floor(upperMs / roomPolicy.protocolLimits.logicalWindowMs)
```

All arithmetic is checked and `clockEstimateMs >= clockUncertaintyMs`; a
negative lower bound is not clamped. The equal carrier/logical window values
are the transaction's sole ingress/reference-window snapshots. No later wall
clock read can change validation or reduction within that import. An
unavailable estimate/bound, overflow/underflow, failed comparison,
boundary-straddling uncertainty interval, or changed source snapshot makes the
whole bundle/batch return `clock-out-of-range` and persist no bundle, batch,
carrier, operation, state, outbox, or cursor bytes; the user or contact
adapter may retry at a later bounded contact after correcting the clock or
after the uncertainty interval lies within one window. A contact adapter
cannot split or reorder an otherwise rejected batch to make a subset commit.
Within both declared bounds and a single window, carrier/logical future
candidates use only the already specified bounded future partitions and never
activate early. There is no unbounded manual-review quarantine. Continuous
NTP is not required; the release's reviewed clock method must expose a
conservative offline error bound rather than assuming `Date.now()` is exact.

A p2party shutdown-survival claim requires an end-to-end tested path with:

1. no DNS, URL fetch, IP socket, WebSocket, WebRTC, or TURN;
2. a pre-positioned client and room invitation;
3. at least one field-tested non-IP custody/contact mechanism;
4. enough contacts before retention to complete the required interactive
   steps; and
5. measured delivery, loss, energy, capacity, and human/contact latency.

Portable files demonstrate protocol independence and practical
store-carry-forward. They do not by themselves prove reachability across a
city, border, or physical seizure.

### 4.15 PQ-authenticated successor publication boundary

V0.4's hybrid KEM and pair-control healing provide forward/post-compromise
confidentiality recovery under their stated assumptions; its Ed25519
identities, room-operation signatures, grants, and revocations remain
classical. Ordinary invitation provenance is an out-of-band capability
assumption, not identity authentication. None of these may be relabelled
post-quantum-authenticated. A successor starts only from this publication
contract:

```ts
type AuthenticationCoverageModeV1 =
  | "hybrid-signed"
  | "bound-by-hybrid-authenticated-transcript"
  | "out-of-band-trust-assumption"
  | "not-claimed";

type IdentityContinuityDispositionV1 =
  | {
      kind: "accepted";
      value: {
        statementDigest: Bytes32;
        basis:
          | {
              kind: "pre-compromise-classical-anchor";
              nonRollbackAnchorEvidenceId: Bytes32;
            }
          | {
              kind: "out-of-band-reverification";
              verificationEvidenceId: Bytes32;
            }
          | {
              kind: "previously-trusted-pq-authority";
              authorityEvidenceId: Bytes32;
            };
        acceptedAtHighWaterMs: bigint;
      };
    }
  | { kind: "new-unlinked-identity" };

// Publication artifact only. It allocates no v0.4 wire or suite identifier.
type PqAuthenticationSuccessorManifestV1 = {
  version: 1;
  predecessorReleaseRegistryHash: Bytes32;
  successorProtocolVersionHash: Bytes32;
  successorCanonicalBinarySchemaHash: Bytes32;
  successorExecutableKernelManifestHash: Bytes32;
  successorClaimRegistryHash: Bytes32;
  invitationV3SchemaHash: Bytes32;
  roomPolicyV5SchemaHash: Bytes32;
  successorOperationSchemaHash: Bytes32;
  hybridAuthenticationSuiteRegistryHash: Bytes32;
  completeAuthenticationCoverageMatrixHash: Bytes32;
  invitationTrustModelHash: Bytes32;
  freshContextDerivationHash: Bytes32;
  successorSessionAdapterHash: Bytes32;
  migrationContractHash: Bytes32;
  identityContinuitySchemaHash: Bytes32;
  canonicalVectorSetHash: Bytes32;
  formalObligationRegistryHash: Bytes32;
  externalReviewEvidenceDigest: Bytes32;
};
```

A successor release registry contains
`PqAuthenticationSuccessorManifestHash =
H("p2party/pq-authentication-successor-manifest/v1" ||
Canonical(PqAuthenticationSuccessorManifestV1))`; the manifest does not
contain that release-registry hash and therefore creates no hash cycle.

A future companion specification may activate the manifest only after
standardized browser-viable PQ signature choices, canonical encodings, key and
signature size/resource bounds, deterministic vectors, implementation
availability, formal/refinement results, and external review are frozen. It
assigns the successor's suite IDs there—not in this document—and defines one
non-negotiable hybrid rule requiring both the classical and PQ authentication
components. Failure of either component is failure; a peer or server cannot
negotiate classical-only operation.

The preferred initial candidate for measurement and external review is
`Ed25519 + ML-DSA-65`, with AND verification. This is a design recommendation,
not a v0.4 suite allocation or permission to widen any v0.4 `Bytes32` key or
`Bytes64` signature field. `RoomPolicyV5` and the successor manifest pin the
eventual suite without negotiation. Both components sign the same complete
canonical, versioned, length-disjoint, domain- and suite-bound transcript; a
combiner that signs different projections is invalid. The companion
specification freezes the pure/prehash/context choice, public/private-key and
signature encodings, deterministic-versus-randomized signing behavior, size
and work bounds, and positive and negative vectors. ML-DSA-65 is the preferred
online-object candidate; SLH-DSA is considered only for rare offline
roots/manifests where its much larger signatures are acceptable. FN-DSA is not
eligible until FIPS 206 is final and a reviewed constant-time implementation
for every claimed platform exists.

PQ authentication continuity and post-compromise confidentiality healing are
separate claims. FIPS 204 ML-DSA and FIPS 205 SLH-DSA can supply signature
components; signatures alone contribute no new shared secret and cannot heal a
compromised session. Any successor that claims PQ healing therefore also binds
an approved fresh KEM contribution such as FIPS 203 ML-KEM to the exact
transcript and epoch, and declares recovery only after an uncompromised
contribution has been authenticated, processed, committed, and erased under
the successor's formal state machine. PQXDH is relevant initial-key-agreement
precedent, not by itself continuous healing.

The coverage matrix assigns one closed `AuthenticationCoverageModeV1` to
every object category. An ordinary capability link has invitation provenance
`out-of-band-trust-assumption`; immutable policy integrity may be
`bound-by-hybrid-authenticated-transcript`; peer/operation identities may be
`hybrid-signed`. A self-signature by a key introduced inside the same
untrusted link proves integrity, not identity provenance. PQ-authenticated
invitation provenance therefore requires a hybrid signature by an already
trusted inviter/authority or explicit external verification.
“Complete matrix” means that every category has an explicit row, including
`not-claimed`; it does not mean every category has hybrid authentication.
“Complete hybrid-authentication coverage” is the stricter umbrella condition
below.

An umbrella “PQ-authenticated rendezvous” claim requires a complete matrix
with no ambiguous “where relied on” escape: stable/epoch identities; room
operations; presence permits; authority grants/revocations; pair
HELLO/ACCEPT/key confirmation; transport offer/answer binding; store
descriptors/routes; allocation-issuer identity/key; blind issuance
request/response/token authentication; allocation leases and allocation-status
signatures; append/status receipts; checkpoints/chunk signatures; authenticated
contact sessions; strict-presence proofs; pair/transport bindings; successor
session key confirmation; migration/continuity statements; and every
registry/publication artifact used to choose those suites. Every
`hybrid-signed` entry verifies both components, every
transcript-bound entry reaches an exact hybrid-authenticated transcript, and
public wording exposes every out-of-band assumption. If carrier/publication
authentication is not covered, the registry may publish only narrower
granular room-operation, endpoint/session, or authority-authentication claims,
not the umbrella. A category may be explicitly `not-claimed`, but that forces
the same narrower wording; in particular, retaining v0.4's classical
Blind-RSA allocation path forbids an umbrella PQ-authenticated rendezvous
claim. One uncovered claimed object invalidates that claim.

For pair/session authentication, the common hybrid-authenticated transcript
binds both hybrid identity public keys, every X25519 and ML-KEM public
key/ciphertext/contribution, endpoint and session roles, the `RoomPolicyV5`
hash, exact pair-edge and presence identifiers, SDP/ICE hashes, DTLS
fingerprints, and key confirmation. No component may authenticate an
algorithm, key, policy, role, or transport binding supplied outside that
transcript.

Migration creates a fresh random capability, v3 invitation, `RoomPolicyV5`,
room context, operation namespace, admission grants, pair transcripts, and
fresh successor-session instances under `successorProtocolVersionHash`. A
reviewed v0.4 ratchet/healing component may be reused only through the
manifest's explicitly versioned successor adapter; the successor never reuses
v0.4's authentication transcript, labels, pair-control root/counter, or
session version. It never mutates a v0.4 room in place, imports an old
operation as successor state, or accepts a remote downgrade. Application
state may be explicitly republished only after successor admission as new
hybrid-authenticated operations labelled imported application data with
predecessor provenance; it is not authenticated historical successor state.

The wire identity-continuity statement contains no trust-basis selector. Its
successor schema binds predecessor and successor identity IDs, both policy
hashes, successor-manifest hash, a nonce, validity interval, and both required
signatures. “Both required signatures” here means the successor's complete
Ed25519-plus-ML-DSA hybrid signature; a predecessor proof is additionally
required when continuity from v0.4 is asserted. A local evaluator alone emits
`IdentityContinuityDispositionV1`. “Pre-compromise” means anchored under a
named local nonrollback mechanism before the local active-quantum threat
profile was enabled, not merely before a sender-provided timestamp. Trusted-PQ
authority evidence additionally binds authority generation, scope, and
current revocation state. A classical signature observed only after a
plausible quantum compromise cannot prove historical continuity. Without one
of the three local bases, the UI presents `new-unlinked-identity`; capability
possession, a remote basis field, or a v0.4 room message cannot silently
upgrade it.

Allowlist entries transfer only with locally accepted continuity evidence;
authority grants never transfer and the successor authority issues a new
hybrid grant. A deny entry transfers only when accepted continuity links the
successor identity; blocking an unrelated-key rotation remains an explicit
nonclaim. A failed continuity check creates a new peer identity with no old
permissions. V0.4 pair roots, counters, healing state, and authentication
transcripts are never successor authentication inputs.

The v0.4 Blind-RSA allocation boundary remains classical against a
quantum-capable attacker unless a companion specification separately replaces
it. CPace/PIN proves a shared low-entropy secret only in its stated role and
never substitutes for mandatory hybrid identity authentication.

### 4.16 Failure semantics

| Event                                                        | Required result                                                                                                                                                                                                                                                                                                                                                |
| ------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Sole store unavailable or maliciously silent                 | Persist outboxes, report `single-carrier-dependent` and unavailable/partitioned; no privacy downgrade.                                                                                                                                                                                                                                                         |
| One of several stores fails                                  | Continue fixed reconciliation with the others; do not roll state back or adapt room traffic shape.                                                                                                                                                                                                                                                             |
| All rendezvous stores collude without the capability         | They receive no deterministic protocol field encoding a room, stable application identity, social edge, target, or pair plaintext. Bearer/source/account/timing/cohort correlation remains outside that field-level guarantee; report only the measured L2/source-metadata claim, never network anonymity.                                                     |
| Every usable path omits or is blocked                        | Preserve authenticated safety and outboxes, report partitioned/exhausted, and remove R2-BEC liveness; no empty view becomes finality.                                                                                                                                                                                                                          |
| New compatible store explicitly added                        | Validate, persist authorization, scan, independently wrap, backfill retained operations, and emit bounded hints; no room/session rekey.                                                                                                                                                                                                                        |
| Public cohort allocation/capacity is exhausted               | Keep the bounded outbox, roll only into already reserved future slots, and report backpressure/unavailable; never append an extra chunk or burst.                                                                                                                                                                                                              |
| Remote store hint passes crypto but not local policy         | Keep it discovered/inactive or discard at expiry; perform no network access.                                                                                                                                                                                                                                                                                   |
| Store is locally denied                                      | Stop contacting it; retain validated logical operations.                                                                                                                                                                                                                                                                                                       |
| Store supports only a shorter retention/other codec          | Reject as incompatible before room-derived traffic.                                                                                                                                                                                                                                                                                                            |
| Two clients have disjoint store sets                         | Queue safely and report partitioned until a bridge/contact exists; never invent convergence.                                                                                                                                                                                                                                                                   |
| Store omits, reorders, or duplicates                         | Union other sources; omission is availability failure, duplicates are idempotent.                                                                                                                                                                                                                                                                              |
| Store equivocates one object/chunk index                     | Record signed evidence, independently validate every observed branch, and union every distinct valid logical operation; no branch chooses logical state.                                                                                                                                                                                                       |
| Checkpoint is missing or a chunk/path is withheld            | Report availability/unknown and exclude that store/profile from accountability-dependent positive claims; absence alone is not a cryptographic fault proof.                                                                                                                                                                                                    |
| Store signs conflicting checkpoints or breaks the chain      | Retain the bounded conflict evidence, make the exact store/profile chain inert, and require an explicitly authorized new `StoreId` for a clean chain.                                                                                                                                                                                                          |
| Finalized checkpoint contradicts a signed custody promise    | Verify and retain `PublicCustodyBreachProofV1`, mark the exact store/profile faulty, and remove it from positive custody/R2 evidence; never interpret the proof as room state.                                                                                                                                                                                 |
| Accountability evidence cap is reached                       | Persist the exact store/profile saturation tombstone, exclude that partition from positive accountability-dependent claims, and never select a favorable subset; unrelated selected store/profiles remain evaluable.                                                                                                                                           |
| SP1 route/prewarm/evidence/exposure check fails              | Do not send the public-store request; report source privacy unavailable/unknown. Never fall back to a direct route.                                                                                                                                                                                                                                            |
| A nonconforming public request occurs in an SP1 interval     | Atomically taint that context/interval and report `tainted-or-insufficient`; later private traffic, route deletion, or restart cannot repair the historical interval.                                                                                                                                                                                          |
| Malformed flooding                                           | Drop under fixed parser, per-source, per-window, dependency, and storage limits.                                                                                                                                                                                                                                                                               |
| Valid operation arrives late but before expiry               | Authenticate, deduplicate, dependency-order, reduce, and backfill.                                                                                                                                                                                                                                                                                             |
| Operation arrives after semantic/GC horizon                  | Ignore for current state; do not resurrect.                                                                                                                                                                                                                                                                                                                    |
| Author forks one authenticated sequence slot                 | Exclude that author's transient window state; do not fail the room.                                                                                                                                                                                                                                                                                            |
| Pair forks one authenticated control slot                    | Fail and rehandshake only that pair edge.                                                                                                                                                                                                                                                                                                                      |
| Frontend blacklist lookup fails                              | Deny that peer and emit no SDP/ICE; do not open the whole room.                                                                                                                                                                                                                                                                                                |
| Peer is exact-blacklisted                                    | Suppress/tear down pair, admitted application/data-plane relay, final transport, and decrypted control; other room edges continue. A separately carrier-authorized opaque contact context remains governed only by carrier policy/assignment and cannot bypass admission.                                                                                      |
| Blacklisted person uses a new unrelated key in an open room  | Treat as a new cryptographic identity; disclose this limitation. Strict rooms use address-book-only or authority grants.                                                                                                                                                                                                                                       |
| Capability holder fails admission in strict mode             | It may see room-level plaintext allowed by capability semantics, but an unproved presence receives no initiator identity flight and no SDP/ICE or pair control.                                                                                                                                                                                                |
| Capability holder fails admission in open/denylist-only mode | A selected candidate may learn the initiator's first stable identity; it receives no SDP/ICE and cannot decrypt another pair's payload. Report the weaker identity-disclosure label.                                                                                                                                                                           |
| Authority revocation is withheld during partition            | Local deny is immediate; remote clients may honor an unexpired old grant until delivery/expiry. Do not claim instantaneous global revocation.                                                                                                                                                                                                                  |
| Stable-edge authority grant expires                          | Stop post-promotion sensitive work and start a fresh automatic pair attempt carrying a current grant; preserve the room/invitation UX, but do not extend the old lease or reuse expired presence evidence. In-place refresh remains roadmap priority 18.                                                                                                       |
| Sparse views differ                                          | Continue operation reconciliation and bounded attempts; preserve safe edges; no cross-room or degree-limit bypass.                                                                                                                                                                                                                                             |
| Pair-tag/candidate budget saturates                          | Stop pair AEAD trials at the fixed count/byte cap, report `pair-control-DoS/stalled`, and retry only after the persisted next room logical-window boundary; no arrival-order winner.                                                                                                                                                                           |
| Selected final transport fails                               | Stall that one-shot pair attempt, keep its authenticated audit, and report transport unavailable. Recovery uses fresh presences/a fresh `PairEdgeId` and selects the mandatory operation-carrier candidate; never overwrite the old answer slot or expose SDP elsewhere.                                                                                       |
| PQ control is duplicated/reordered                           | Edge ingress ledger releases only the exact expected authenticated slot.                                                                                                                                                                                                                                                                                       |
| Authenticated v4 PQ-control fork/rollback                    | Fail only that stable edge and require fresh hybrid handshake.                                                                                                                                                                                                                                                                                                 |
| Required PQ/quiescence control expires                       | Keep the application gate safe, mark the edge stalled, and require a fresh hybrid handshake; never infer an epoch transition.                                                                                                                                                                                                                                  |
| Entire old local database snapshot is restored               | Preserve atomic crash consistency and reconcile missing room operations normally. If a restored existing edge presents an older authenticated v4 transcript/counter to an uncompromised peer with newer edge state, reject/rehandshake only that edge. Without an external monotonic anchor, claim no generic room/frontend or pre-contact rollback detection. |
| V0.4 receives v3/PQ-successor or partial-hybrid material     | Reject before state mutation or disclosure; do not negotiate, reinterpret v0.4 bytes, import predecessor state, or fall back to classical-only authentication.                                                                                                                                                                                                 |
| Wrong PIN after frontend admission                           | The pair-encrypted SDP may already have been exchanged; CPace prevents v4 promotion. Do not describe PIN as pre-SDP privacy.                                                                                                                                                                                                                                   |
| All IP paths are shut down                                   | Continue only through pre-positioned non-IP carriers; otherwise report unavailable honestly.                                                                                                                                                                                                                                                                   |
| Browser suspends fixed cover                                 | Mark L2 access cover suspended/degraded; do not retain the L2 label from cached configuration.                                                                                                                                                                                                                                                                 |
| Assurance evidence custody saturates                         | Preserve protocol state, set the saturation fact, and reduce carrier privacy/resilience fields only through their conservative unknown/exhausted branches until a complete bounded replacement fits.                                                                                                                                                           |

## 5. Acceptance Criteria

- **AC-001 — Version-safe one-link UX:** Existing deterministic capability,
  compact, v1 fragment, 24-word, legacy-hex, decoding, and
  `normalizeRoomCapability()` vectors remain byte-identical and classify only
  as legacy signaling. In a compatibility build with the separately installed
  legacy adapter they retain legacy execution; in a socket-free build they
  reject with exactly `LegacySignalingAdapterUnavailableError` and code
  `legacy-signaling-adapter-unavailable` before network/adapter work or secret
  disclosure. New deterministic v2 default and policy-bearing vectors
  carry the same 32-byte capability; the short form resolves only to
  `DEFAULT_BLIND_POLICY_V4_0` and the long form to its exact canonical policy.
  For a copy/pasted `https://p2party.com/r#v2.<capability>`, the frontend
  extracts the hash and invokes the same `joinRoom(fragment)` flow; advanced
  `/r` links, QR codes, and universal links do the same with the policy
  suffix. A v1 link on a fresh upgraded client stays legacy; a v2 link on an
  old client fails unsupported; cross-version clients never silently enter
  different contexts.
  `parseRoomInvite` preserves the version and capability-only normalization
  rejects v2 instead of downgrading it. The library is not changed into a
  whole-URL parser. Network capture proves that the fragment,
  capability, normalized hex, and PIN never enter an HTTP/store request. With
  v2, the shipped/default legacy-named second positional
  `signalingServerUrl` alias resolves to the exact signed default descriptor;
  an unmapped self-hosted URL rejects with
  `BlindStoreAliasResolutionError`/`blind-store-alias-unmapped` before network
  work and never silently selects the default.

- **AC-002 — One-server cold deployment:** Given one fresh conforming
  store-only public server with no WebSocket/Upgrade endpoint, one standard
  socket-free frontend build with a WebSocket-constructor tripwire, and no
  other rendezvous infrastructure,
  three fresh browsers using the same invite, immutable policy, and one
  compatible delivery profile discover the same
  room, apply admission, form their bounded sparse room overlay, and establish
  independent protocol-v4 stable edges. No second server or server-to-server
  configuration is present.

- **AC-003 — Rooms do not merge:** Given at least two rooms and dummies in one
  delivery cohort, clients derive separate operation sets, rosters, topology
  graphs, persistence namespaces, and sessions. No client attempts a pair
  merely because another source scanned or wrote the same cohort bucket.

- **AC-004 — No room or target at the store:** In AC-002 and AC-003, decoded
  request objects, structured logs, metrics, traces, cache keys, and database
  rows at the sole store contain no capability, room number/handle,
  room confirmation/equality tag, stable identity/equality tag, membership or
  co-membership edge, room-size fact, social-graph/pair edge, recipient, pair
  routing tag, admission result, SDP, ICE, fingerprint, v4 frame, or PQ epoch.
  The same field-level result holds after all store databases/logs are joined;
  the separate AC-022 experiment determines what source/timing/profile
  observations can infer. Whole-client
  network capture also contains no WebSocket construction/Upgrade, `wss:`,
  `?publickey=`, roster/signal frame, or heartbeat.

- **AC-005 — Single-server denied-peer SDP confidentiality:** Given an
  attacker that knows the room capability, operates the only store, controls a
  malicious client, and is absent from an address-book-only/authority policy
  or uses an exactly blacklisted stable key, strict honest endpoints emit no
  first identity flight to an unproved presence and no SDP/ICE before
  bilateral admission. The same result holds for prompt and delayed HELLOs,
  current and historical pair projection, and store/contact/portable
  carriers.
  The attacker cannot decrypt SDP/ICE exchanged by any two allowed members
  from its complete server state, all carrier objects, and its room-level
  plaintext view.

- **AC-006 — Identity-substitution rejection:** Given a malicious client that
  publishes an allowlisted stable commitment but cannot sign with that stable
  key, its strict presence proof fails before an identity hello or its
  identity transcript fails before `TRANSPORT_OFFER`. No SDP, ICE,
  DTLS fingerprint, final transport locator, or protocol-v4 handshake byte is
  released.

- **AC-007 — Frontend policy parity:** For every current signaling path that
  checks blacklist or address book, the blind store, direct peer gossip,
  portable bundle, reconnect, admitted application/data-plane relay, WebRTC,
  and non-WebRTC paths yield the same
  `EvaluatePeerAdmissionPolicy` decision through `Admit()` before promotion or
  `ReauthorizeStableEdge()` afterward. Opaque carrier
  carriage remains separately governed as stated in SEC-007. Deny wins, and an
  IndexedDB/worker error fails closed for only that peer. Race vectors
  change/delete `policyGeneration` after a provisional allow and before each
  ACCEPT, transport offer/answer, SDP/ICE creation or publication, reconnect,
  admitted application/data-plane relay, protocol-v4 promotion/control, and
  application handoff. Each path reloads
  the exact generation and atomically binds it to its publish/dispatch intent;
  a mismatch emits no sensitive byte and invalidates the lease. Cross-path
  vectors also vary the captured reference window, admitted HELLO/ACCEPT
  coordinates, retained-presence evidence horizon, pair-attempt lease, grant
  horizon, trusted core/frontend/custody snapshot, authority decision-state
  digest, and stable transcript. Equivalent inputs return byte-identical
  versioned bootstrap or stable leases with their specified horizons. A stale,
  mismatched, unavailable, saturated, unbranded, deserialized, or
  caller-fabricated context/snapshot/view never becomes an allow. After stable
  promotion, expiry of the original presence, identity operation, or
  pair-attempt lease does not deny an otherwise current stable edge; an expired
  authority grant does. Structural/cloned local-ownership rows or
  current/historical topology results never authorize a response. Changing
  either local stable-key set, historical Core/evidence bytes,
  planner/on-demand row, degree/ledger row, or count/byte resource fence
  between projection and CAS invalidates the opaque topology handle and
  publishes nothing.

- **AC-008 — Strict admission and rotation:** An authority-grant room rejects
  a fresh attacker key without a valid grant even if it holds the capability.
  An expired or wrong-room grant fails. A current valid grant does not override
  a local blacklist. Cross-mode vectors require null presence permits and
  null HELLO/ACCEPT grants in capability mode, and require exactly one valid
  permit plus the appropriate endpoint grant in authority mode; copied,
  surplus, missing, or wrong-mode credentials fail before SDP. Pinned-authority
  fork, overquota, or custody exhaustion makes every affected authority
  decision `policy-unavailable` through the complete future-plus-credential
  horizon, including when the highest revoke candidate arrives last. Tests and
  vectors derive the same `VerifiedAuthorityAdmissionViewV1` under every
  operation/fault delivery permutation and never treat missing custody as an
  empty available floor set. Authority mode combined with
  `onlyConnectWithKnownPeers=true` requires both checks and deterministically
  reports `authority-grant` on success. Role-binding vectors admit tuple index
  0 only for HELLO-at-responder and index 1 only for ACCEPT-at-initiator;
  wrong pair edge, endpoint tuple, direction, sequence, predecessor, HELLO
  dependency, operation ID, room/policy binding, retained evidence, trusted
  snapshot provenance, or core/custody source
  raises `AdmissionInputError` or `policy-unavailable`, fails closed, and is outwardly
  indistinguishable from the fixed denial behavior. Tests and UI also disclose that an
  open/denylist-only
  room cannot recognize a person after complete identity rotation.

- **AC-009 — Pair double-sealing:** A capability holder that is not an endpoint
  can decrypt the containing room operation where policy permits but cannot
  recover another pair's identity bundle, grant, SDP/ICE, transport binding,
  v4 handshake, or PQ control header. It may observe the one-use tag,
  bootstrap-header presence, payload/size class (including the large
  pair-body family), author, length, and timing. Bit flips fail before
  pair-state mutation.

- **AC-010 — Deterministic sparse default:** For randomized room sizes from one
  through `maxRoomMembers`, clients with byte-identical
  selected vertex set, exact local presence, and ranks produce the same
  radius-`k` incident neighbor set under every operation permutation; the
  union across members with that same set is connected for
  `n > 1`, and its canonical degree is at most `min(2k, n-1)`. No cohort size
  affects it. Boundary vectors cover immutable `maxRoomMembers` 2 and 3,
  observed `n <= 2k`, mixed open/address-book/authority eligibility at
  overcapacity (ordered only by rank then operation ID), a local presence just
  inside/outside the cap, missing/ambiguous local presence producing no edge,
  and checked multiplication at every numeric limit. Additional vectors cover
  independent projection/planner statuses, exact-cap resource saturation,
  full-mesh planner overflow with a surviving explicit selection, one
  `LocalPeerId` matching several selected open presences but resolving to the
  first canonical one only, and a request whose matches are all outside the
  cap producing none.

- **AC-011 — Divergent roster safety and convergence:** Model-checked clients
  receiving every permutation, duplicate, and bounded partition of the same
  operations never create a cross-room or over-degree edge. After all required
  operations arrive, their `CoreRoomState` values are byte-identical.
  Desired graphs derived from the two `topologySelections` origin bits are
  byte-identical only when local frontend/planner facts also match; changing
  diagnostic `desiredEdge` alone cannot authorize a transition. A presence
  authored in window `x` and an exact same-author-key LEAVE
  in its own chain in window `x+1` reduces correctly when the presence remains
  valid there. This must also hold when the LEAVE is first delivered after
  restart and after the presence's outer lifetime, using only retained,
  reauthenticated dependency evidence; delayed delivery never resurrects the
  presence.

- **AC-012 — No complete-roster key binding:** Adding a late valid presence
  does not invalidate or rekey an authenticated stable edge between two
  existing members. Pair and stable-edge test vectors remain identical when
  unrelated roster operations are added. Simultaneous fresh/reconnect attempts
  for one `StableEdgeId` cannot promote different roots: only matching
  bilateral stable-edge claims promote, while conflicting unexpired claims
  stall both candidates. Asymmetric lost-offer and restart vectors prove that
  both endpoints retry successfully with fresh claims/`PairEdgeId` after the
  later exact claim horizon, without a generation-skew loop.

- **AC-013 — Add one server locally:** Starting from AC-002, one user adds a
  compatible second store through the frontend. Its client validates and
  persists permission, reconciles, backfills retained operations, and emits a
  leased hint in fixed slots. When retained backlog, scheduled replication
  throughput, and remaining lifetime satisfy the profile simulator,
  authorized peers discover and activate it
  without a new invite,
  new room context, new pair ID, server restart, consensus, or v4 rehandshake.

- **AC-014 — Store hint cannot cause SSRF:** A malicious room member advertises
  loopback, link-local, cloud-metadata, file, credential-bearing, redirecting,
  invalidly signed, expired, unsupported, and denied routes. The frontend
  performs no network or filesystem access to them and records no ambient
  credentials in an error. Network-route vectors also cover DNS rebinding,
  mixed public/private answers, IPv4-mapped IPv6, carrier-grade NAT,
  link-local/special-use addresses, proxy-resolved destinations, and redirects
  toward metadata. Resolution/connection rejects before room-derived traffic
  unless the exact private `RouteId` was locally authorized. Browser E2E
  vectors prove a remotely hinted HTTPS origin remains inert because `fetch`
  cannot enforce DNS pinning; only an exact shipped/configured or
  user-authorized browser-direct `RouteId`, or a reviewed enforcing gateway
  route, is contacted. A valid, otherwise compatible remote-only hint under
  `autoActivateRemoteHints="never"` causes no resolver, adapter, scheduler, or
  network mutation. Under `"preauthorized-only"`, activation requires both the
  finite exact allowed `StoreId` and exact
  `preauthorizedRemoteRouteIds` membership; `allowedStoreIds="any-compatible"`
  alone is discovery permission and remains inactive.

- **AC-015 — Frontend store allow/deny:** Given the same room state on two
  clients with different local store policy, each contacts exactly its active
  set. Denying a store stops future contact but does not delete logical
  operations, alter the room, or force another peer to deny it. On one client,
  two rooms sharing a public context use one carrier-policy generation and one
  route cycle; a global deny cannot be bypassed by either room, while either
  room may independently stop assigning its own slot through a persisted
  assignment-policy generation. A fresh/migrated room starts with generation
  zero and an empty disabled set; restart preserves later exact disables.
  An exact `deniedRouteIds` entry overrides store, private-route,
  browser-direct, and remote-preauthorization allows. Canonical-ref vectors
  reject alternate prefixes, padding, case/alphabet variants, wrong lengths,
  duplicate decoded IDs, and legacy aliases at the security-decision boundary.
  Differing per-room resource policies cannot produce different route cycles.
  With the global cap full, adversarial compatible hints and grind-generated
  low IDs
  cannot evict a live active/default/explicit context; only an explicit local
  replacement or objective expiry/deny/incompatibility changes it. In a
  cap-one explicit S→T replacement, every room drops S because it is absent
  from the global admitted-ID projection before admitting/contacting T; no
  room retains an extra scheduler outside the global SSOT.
  At a cap-one remote catalog, discovery-only adversarial hints observed first
  cannot retain the slot over a later activation-authorized store/route.
  A cap-one route vector presents a denied/discovery-only preferred route
  before a later authorized route and still retains the authorized route.
  Another vector fills the shared byte cap with descriptor candidates and
  proves the atomic pinned descriptor/tombstone/usable-route footprint either
  fits in full or leaves the old catalog byte-identical. Forked maximum
  generations consume one StoreId slot and sort by the exact descriptor-state
  key under every permutation. Removing one accepted source-metadata
  disclosure ID atomically stops every affected route/contact before network
  work; an absent or alternate disclosure ID cannot inherit consent.
  Disabling a room context with a pending exact wrap emits a dummy at the next
  mapped slot and never publishes that wrap. A tombstoned room with a retained
  ordinal continues to consume initialized-room capacity across restart until
  terminal/expiry or an explicit loss-recording discard.
  Replacing any global policy preflights all invariants, including an increased
  room cap versus profile slots; room-cap tightening below the sticky set and
  global invariant failure both leave the old policy byte-identical.

- **AC-016 — Automatic bridge and backfill:** Given two stores that initially
  contain different valid subsets and a backlog that the fixed replication
  schedule can drain before semantic expiry, a client authorized for both
  converges, rewraps private logical operations independently for each store,
  and backfills them. Other clients later converge through either store. If the
  bound is not met, clients remain honestly `reconciling`/`partitioned` rather
  than bursting or claiming convergence. The two stores never exchange room
  state directly. Exact consistency vectors persist every pending work ID and
  observed frontier across restart, move from reconciling to converged only
  after all captured obligations commit, and move to partitioned when a route
  or authenticated contact expires or remaining capacity cannot meet expiry.
  At every exact dependency/outbox/reconcile/L3 cap boundary, rejection of a
  known required item sets the boolean and bytewise-lowest saturation witness,
  `resourceState="overcapacity"`, and `consistency="partitioned"` across
  restart; freeing capacity plus the canonical rescan clears them only after
  the work is represented. Invalid garbage and pre-core unauthenticated
  bootstrap/discovery candidates do not toggle those facts; an outer-valid
  room `STORE_HINT` rejected at a catalog boundary does. Pure-derivation
  vectors hold ambient room/storage state different while keeping one
  `DeliveryConsistencyEvidenceV1` byte-identical and obtain the same
  consistency/resource result; changing each explicit obligation or
  overcapacity boolean changes only its specified branch.

- **AC-017 — Honest no-path failure:** Given two participants with no common
  store, authenticated peer bridge, or time-respecting physical carrier path,
  both persist outboxes and, once no registered opportunity can meet the
  required semantic deadline, report `partitioned`; neither reports a complete
  room or falls back to a room-revealing server. Adding a later path before
  expiry and with sufficient scheduled capacity permits convergence.

- **AC-018 — Set-law/property tests:** For generated valid and invalid
  operations, merge satisfies associativity, commutativity, and idempotence.
  Every permutation and duplication of one delivered set yields byte-identical
  derived state and conflict results. Generation-forked descriptors,
  independently expiring per-source route leases, monotone revocation facts,
  same-payload/different-operation presence and leave forks,
  semantic-slot conflicts, and author overquota all have permutation tests.
  Independent implementations byte-match every domain-separated non-pair
  semantic-slot formula and the canonical `CoreRoomStateV1` encoding, beginning
  with the empty-state known-answer vector and extending to every fault
  variant before release. A pinned-authority quota-plus-one set whose
  highest-floor revoke is last in every permutation never admits an old grant;
  it deterministically reports authority policy unavailable. Equal-generation
  revocations with unequal effective/valid-through windows remain distinct and
  byte-match their reference-window decisions. Staggered same-descriptor
  hints `{route A, expiry 10}` and `{route B, expiry 20}` retain only B at
  window 15 under forward/reverse delivery and restart. Forked maximum
  descriptor branches are all retained with one sorted fault and are all
  delivery-inert. `P1 → P2 → LEAVE(P1)` leaves exactly P2 in the active-only
  `observedPresences`; left/expired/forked facts never appear there.

- **AC-019 — Malicious store behavior:** Omission, delay, duplication,
  reordering, stale chunk heads, conflicting object bytes, and per-client
  chunk forks cannot forge an accepted operation, policy, presence, pair step,
  admission, or PQ transition. Every distinct operation that passes canonical
  validity and remains within the declared semantic horizon and accepted
  candidate/valid-set custody bounds is unioned from every observed signed
  chunk branch. The abstract fork set is not a claim that overquota garbage or
  bytes beyond a fail-closed physical cap remain stored forever. Detected
  store faults affect assurance and availability, not logical winner
  selection. Outside a fixed-trace scheduler run, store-integration fault
  injection duplicates exact _previously committed successful_
  issuance/allocation POST bytes through alternate route handlers and across
  store restart; those `issued`/`allocated` requests return byte-identical
  signed results without a second quota, spent-token, capacity, or ordinal
  mutation. Stateless invalid/quota/unavailable cases are checked only for
  their canonical signed shape and absence of a durable row; they need not be
  byte-identical after external state changes. This verifies server
  idempotency, not permission for a live client retry. A conflicting signed result for one request hash makes
  the context equivocal/inert. Invalid-request/token floods across restart
  create no replay rows; bounded successful issuance/allocation caches
  garbage-collect only after the target window is irreversibly finalized,
  without changing retained signed chunks.

- **AC-020 — Retention and resurrection:** Late operations inside the horizon
  converge. Expired presence, old leave, expired store hint, old grant, stale
  pair attempt, and causally checkpointed pair controls do not resurrect state
  after garbage collection and restart. Expiry of an uncheckpointed required
  pair control stalls the edge rather than guessing a transition. A
  generation-floor revoke remains reconstructable through the maximum
  future-operation-plus-credential horizon; an otherwise-valid
  lower-generation grant, including one at the last permitted future window,
  cannot become admissible merely because revoke custody reached its boundary.
  A credential with `issuedAtLogicalWindow` after its carrying operation is
  rejected, and the test authority never pre-signs a future issuance value. Boundary
  vectors use zero skew and deliberately misaligned delivery/logical windows:
  a bucket `w` is readable through the end of
  `w + carrierRetentionWindows` and deletable only at the start of the next
  ingress window; an operation created at the start of logical window `x`
  remains recoverable through the end of its inclusive
  `expiresAfterWindow`. Additional vectors exercise both declared skew
  margins and checked-arithmetic overflow. For a pair control accepted in
  logical window `x`, exact replay/fork audit succeeds through the end of
  `x + pairControlRetentionWindows`; deletion before that boundary fails, and
  deletion occurs only at the start of the following window. With no exact
  successor at that transition, the edge is atomically stalled before custody
  deletion. Every post-promotion causal control encodes the exact full
  `pairControlRetentionWindows` expiry; shortest/longest noncanonical expiry
  encodings are rejected, and a valid exact replay or fork at the final
  inclusive window still authenticates through the retained slot audit. A
  first-delivered live pair step whose same-window chain begins with an already
  semantically expired transient prefix authenticates after restart from the
  bounded inert prefix evidence; the prefix's old semantic fact does not
  reappear, and prefix evidence is deleted only after its exact
  maximum-descendant-plus-skew boundary. A delayed HELLO at the last receiver
  overlap window reconstructs and revalidates the genuine exact HELLO-window
  Core from its content-addressed operation/prefix references after roster
  expiry, applies current
  frontend/deny/authority/planner/on-demand/degree/resource fences, and mints
  at most one opaque authorization for that exact pair attempt. Vectors vary
  each current veto, historical byte, endpoint, attempt mode, and exact
  capacity boundary. No branch mutates current Core, UI membership, rank,
  roster, or general neighbor state. A first-delivered cross-window
  LEAVE after restart likewise promotes the exact referenced presence's full
  semantic slot and required author prefixes only through the checked room
  evidence horizon; a sibling branch still proves the same semantic fork, a
  missing branch is never fetched inside reduction, and none of that evidence
  re-enters the roster. Profile validation accepts
  `operationRetentionWindows + receiverKeyOverlapWindows ==
pairControlRetentionWindows` and rejects the one-greater boundary; size
  class `255`/`UINT32_MAX` ordinal geometry encodes, and plus one rejects.

- **AC-021 — Fixed L2 traffic:** Under `fixed-cohort-scan`, packet/application
  traces, after a context has completed one prewarming window, for zero through
  `roomSlotsPerClient` assigned active rooms have the same
  request count, response count, public chunk sequence, size-class sequence,
  and scheduled boundaries within preregistered tolerances. Real operations
  replace dummies. Every window closes with exactly the profile's chunk count;
  missing/late allocations are padded, late writes roll forward, and capacity
  exhaustion never creates another request/chunk. Vectors cover fixed token
  issuance, valid and invalid-token allocation, allocated and null-admission
  cover appends, route cycling without immediate retry, each exact schedule
  role, ACCEPT-before-HELLO identity priority, simultaneous saturated queues,
  every operation kind as live versus later replica/backfill, reserved outbox
  exhaustion, allocation-response deadline, and restart. Equal-offset events
  byte-match the canonical event-key order across tabs and restart. Route-set
  insertion, exact denial, expiry, and removal advance from the persisted raw
  `RouteId`, never a mutable array index, and no event is attempted twice after
  the pre-dispatch transaction. Issuance/allocation/append/read vectors use
  scheduler window `w` while targeting `w+1`/`w`/`w-1` exactly, and
  independent implementations byte-match every event ID. Across many windows
  and restart, attempted-event persistence remains one replace-only
  high-water cursor per context. Cold activation, OS suspension across a due
  boundary, missing/corrupt-cursor recovery, and reactivation set the monotone
  `notBeforeSchedulerWindow` to the next complete boundary: every older event
  is missed without dispatch or route-cursor advance, and catch-up reads never
  become scheduled-event retries or a burst. A carrier-policy generation replacement
  preserves `lastAttemptedRouteId` and selects its successor in the new set;
  it never resets to the lowest route merely because generation changed.
  Lost issuance/allocation response vectors make no same-window or alternate-
  route client retry, emit the already scheduled degraded cover, and suspend
  fixed-access assurance. The server-side duplicate/idempotency cases remain
  AC-019 fault-injection vectors; same token with a different allocation
  request receives signed `token-spent`.
  Multi-room vectors prove that two or more rooms sharing one public carrier
  context still produce exactly one issuance, allocation, route cycle, append
  grid, and full-chunk scan per client/context/window, with a crash-safe private
  slot map and no room-count-dependent request. Multi-tab/worker race and
  takeover vectors prove fencing prevents duplicate traces.
  Prewarm-start and cold on-demand activation are separately labelled traces;
  join/leave tests never compare them to an already resident context.
  Profile activation rejects
  `roomSlotsPerClient < maxInitializedBlindRooms`; initializing exactly the
  cap fills every ordinal deterministically across restart, while cap plus one
  fails before vault/carrier mutation and never reports an active path without
  a slot. A deactivated room retaining an outstanding-wrap ordinal continues
  to count against that cap and emits only dummies until release.

- **AC-022 — L2 inference evaluation:** A preregistered target-room,
  co-membership, room-size, join/leave, and pair-activity classifier trained on
  sole-store observations does not exceed the release threshold over the
  declared prior and cohort. The registration fixes class base rates,
  train/validation/test separation, minimum sample size, statistical power,
  confidence interval method, PR-AUC, ROC-AUC, and TPR at the named low FPR
  before traces are collected; the report publishes all of them rather than
  selecting the friendliest metric. Cold start, suspension, loss, and
  malicious selective failure are separate labelled datasets. Classifier
  non-success is falsification evidence for the exact dataset/model only; it
  is not a cryptographic proof that no other observer or classifier can infer
  the event.

- **AC-023 — Cohort honesty:** A newly added store used by only one measured
  room reports `cohortScope: "room-unique"` even if its ciphertext format is
  correct. It does not inherit `measured-shared` from the default store or
  from operator declaration.

- **AC-024 — Portable non-IP rendezvous:** With DNS and every IP socket,
  WebSocket, WebRTC, fetch, and TURN disabled, two clean clients using the same
  invite exchange only canonical portable bundles and reach converged
  presence, bilateral admission, and completed protocol-v4 handshake through
  the operation-backed `HandshakeTransport`. Atomic-import vectors cover exact
  carrier/logical boundaries: an uncertainty interval wholly inside one
  relevant window commits using its captured window snapshot, while an
  interval straddling any relevant boundary rejects and persists nothing.
  A two-room bundle whose rooms have different per-room work limits is parsed
  under the one vault-global outer byte/inventory bound; each opened object
  then observes only its own room caps.
  A backlog larger than one bundle, including heterogeneous compatible
  profiles and all three schedule roles, is exported through repeated fresh
  bundles without prefix starvation. Crash after selection re-presents the
  byte-identical committed bundle; duplicated imports are idempotent. Under
  the stated sufficient-capacity/before-expiry condition every due wrap is
  eventually selected. Unacknowledged-export/restart and export-click-spam
  vectors hit the pending count/byte boundary, automatically return the oldest
  matching exact bytes, and allow explicit resume only by byte-equal
  `(exportSequence, exactOutputHash)`. An older incompatible room-A commit
  cannot block a matching room-B resume; typed capacity failure occurs only
  when no matching commit exists and creation capacity is full. No case
  advances selection or exceeds storage, and durable-handoff ack releases the
  exact pending bytes once. Same-profile rooms A/B with an A-only `roomScopes`
  request emit no B work. Disable, assignment/profile-generation change,
  operation terminality, or expiry between prepare and first dispatch/replay
  exposes no bytes, records loss, deletes the unusable commit, and leaves
  still-required work eligible elsewhere. Portable context vectors prove
  caller selection, retained/pending collision, or context change on exact
  replay is rejected. A heterogeneous bundle emits one
  profile-bound portable assurance instance per profile while all instances
  share one custody-path ID and cannot count as diverse paths.
  The same all-IP-disabled portable path then completes
  `QUIESCE_PROPOSE → QUIESCE_ACK → OFFER → ADVANCE → ACK → HEAL_COMPLETE →
PAIR_CHECKPOINT` under duplicate/reorder/restart schedules.

- **AC-025 — Automated non-IP carrier:** The selected reference non-IP contact
  adapter exchanges fragmented fixed objects on a hardware-in-loop non-IP path
  under loss, duplication,
  reordering, short contacts, interruption, and restart. Custody resumes
  without logical duplicates or room leakage outside the adapter's declared
  metadata. The same inside-one-carrier-window and
  inside-one-logical-window clock vectors as AC-024 run on each bounded
  contact batch: a boundary-straddling uncertainty interval rejects the
  complete batch with no state/cursor persistence, while a wholly contained
  interval commits under its one captured snapshot. Activation vectors
  accept only the exact registry entry/profile/MTU/fragmentation/session-auth/
  clock/bearer-constraint combination and reject unknown IDs, unsupported
  profile hashes or size classes, undersized MTU, excessive fragment/object/
  inventory/batch bounds, stale session context, and mismatched registry hash
  before custody or network work. Flood vectors exceed authentication-attempt,
  concurrent-context, context-byte, and client-global contact caps before
  transcript/candidate allocation. Short repeated contacts share the portable
  due-work cursor/attempt counts and cannot starve a later eligible item or
  reset fairness after restart. Disjoint-profile adapters prove role heads are
  selected only from `EligibleL3DueWork(target)`: an incompatible earlier head
  neither emits nor blocks a compatible later record. Every authenticated
  contact commit contains exactly one profile and its current
  `ContactCarrierInstanceId`; a second profile uses a separate batch. Session
  rollover records loss for pending old-instance bytes, retains the due
  intents, and rewraps only under the new instance. Contact variants repeat
  the A-only room-scope and prepare-then-disable/profile/terminal/expiry
  revalidation cases; no stale-session or newly denied batch is exposed on
  first dispatch or replay. A two-room vector with unequal
  `logicalWindowMs` proves L3 orders the checked absolute exclusive deadlines,
  not incomparable raw logical-window indices, including equality/one-ms
  boundaries and restart. With all IP/browser-network tripwires active,
  the selected automated adapter also completes the full AC-024 PQ chain
  under loss, reordering, interruption, and restart. A hardware-in-loop run
  satisfies `non-IP-control-compatible` only. The practical
  `shutdown-surviving rendezvous/control` wording additionally requires a
  deployed field dataset for that exact bearer/custody path measuring range,
  delivery/loss, energy, MTU/fragmentation, usable capacity before retention,
  contact duration, human latency, restart, power loss, and physical custody;
  its claim scope and validity interval name those measurements.

- **AC-026 — Exact PQ frame hiding:** Store and non-endpoint capability-holder
  traces contain no raw current `pqHealingFrame` header, edge-control binding,
  counter, direction, or PQ epoch. The pair endpoint recovers the exact
  byte-identical 65,490-byte frame held by the existing v4 outbox.

- **AC-027 — PQ reorder/restart:** For every `OFFER`, `ADVANCE`, and `ACK`
  crash boundary, duplicated and reordered carrier objects plus process
  restart yield either the exact successful existing state or an explicit
  edge-only failure. No double root combination, epoch rollback, second raw
  outbox, or cross-edge mutation occurs. Vectors redeliver every exact accepted
  control and an authenticated conflicting operation after each successor,
  after root replacement, and after restart: retained audit tuples replay only
  the cached exact response or fail the edge as a fork and never transition
  the machine again. Boundary vectors replay at
  `retainThroughLogicalWindow`, delete only in the next window, and prove that
  a missing successor stalls before deletion. Separate vectors make
  `exactPqSlot.value.sessionDirection` numerically
  differ from `RendezvousRole` direction and prove each enters only its typed
  slot/KDF.

- **AC-028 — PQ quiescence:** Healing cannot start while an application
  transfer is active or its terminal state is unknown. After a bilateral
  quiescence proposal/ack, application traffic remains gated through ACK; the
  offerer remains gated until authenticated `HEAL_COMPLETE`. A delayed old
  control operation cannot unlock or roll back the edge.

- **AC-029 — Current v4 byte match:** The final `RendezvousChannelId` enters
  the existing channel-input construction exactly once. Both peers byte-match
  stable identities, transport bindings/fingerprints, suite, and handshake
  transcript before promotion. WebRTC tests require exact authenticated SDP
  fingerprint enforcement in every release-registered engine. When live
  certificate stats exist they must match; a registered engine without stats
  passes only its reviewed native-enforcement vectors and reports
  `"registered-native-enforcement"`. Unknown engines and every observed
  mismatch fail closed.
  Cross-capability tests pair a WebRTC-capable initiator with an
  operation-carrier-only responder, which selects the mandatory advertised
  fallback without an answer-slot fork. Failure after an optional selection
  creates a fresh-presence/fresh-`PairEdgeId` attempt and never reuses an old
  pair slot.
  Registered-local-link vectors deny/uninstall an advertised adapter, withhold
  platform permission, and change frontend policy before answer/handoff. No
  adapter allocation, discovery, source-metadata exposure, or permission
  prompt occurs; the mandatory operation carrier is selected. Remote bytes
  never grant local transport authority.
  Pair-specific bootstrap keys, response credentials, and provisional
  plaintexts are erased and the existing stable edge owns all durable roots.
  A shared presence receiver private key follows its advertised
  validity/overlap horizon and is not erased merely because one pair promoted.

- **AC-030 — Optional accelerator transparency:** Enabling, disabling,
  corrupting, or timing out an OMR/PIR/set-reconciliation accelerator changes
  cost and assurance only. Given the same validated operations, the canonical
  set and reducer output are byte-identical to full public-chunk scan.

- **AC-031 — Bounded resources:** Fuzzing verifies fixed maximum allocation,
  parsing, trial-decryption rooms, candidate and validated-operation
  count/bytes, dependency buffers, per-author operations, pair-open
  KEM/KDF/AEAD trial count/bytes, provisional edges, pair ledger, role-reserved
  outboxes, client-global store catalogs/routes/bytes, active
  carriers, authenticated contact attempts/contexts/bytes, retained windows,
  assurance evidence entries/bytes/raw-dataset bytes, L3 due-work metadata, pending export
  commits/exact bytes, and bundle size. It also covers the client-global
  initialized-room and public scheduler caps across adversarially many rooms,
  stores, profiles, hints, tabs, and workers. A cap-one regression grinds a
  remote store ID before and after a live default context exists and proves
  neither the global nor room-local selection layer can displace the live
  context or partition the room. Cap-one denied-first/authorized-second route
  and descriptor-byte-fill vectors retain the atomic usable footprint; a
  remote descriptor or inert route cannot starve it. Backlog-greater-than-bundle/restart vectors
  keep due-work attempt counters/cursors bounded. Excluded contexts remain
  inert and affected rooms report unavailable/partitioned. Rejection cannot
  create an unbounded log or request fan-out. Descriptor high-water/fork
  tombstones consume the same catalog bytes; remote-only StoreId churn,
  deterministic eviction, expiry, and rediscovery cannot create a hidden
  forever set or reactivate a lower generation while its entry remains pinned.
  Repeated failed stable-edge claims compact/delete after their exact bounded
  horizons, and many-attempt/restart fuzzing never grows a per-edge generation
  log or permanently consumes the pair ledger. Pair-open count/byte counters
  survive restart and carrier duplication within one exact local
  presence/logical-window coordinate, reject cap plus one, and reset once—only
  once—at the next persisted logical-window boundary. Repeated acknowledged
  portable bundles, contact-instance rollover, and public-route rotation
  cannot grow fresh assurance custody without bound; the exact evidence cap
  sets saturation and the aggregate takes only conservative branches until a
  complete replacement fits.

- **AC-032 — No misleading fallback or labels:** When cover suspends, cohort
  falls below threshold, store independence is unknown, a route blocks, the
  temporal graph partitions, or non-IP contacts exceed retention, the
  closed granular assurance vector changes immediately and the UI renders its
  registry-pinned explanation: respectively `accessPattern`/`cohortScope`,
  `operatorIndependence`, `censorshipResilience`, `consistency`, or
  `shutdownControl` takes the documented conservative value. Runtime UI
  contains no ad hoc `L2`, `R2-BEC`, `censorship-resistant`,
  `shutdown-surviving`, or `fully secure` badge; `pqState` alone controls the
  scoped healed wording. Vectors expire/fail one of two measured
  blocking domains and exhaust/saturate the current non-IP backlog: the closed
  `censorshipResilience` and `shutdownControl` states downgrade before the UI
  can retain either label. Two different blocking-domain bytes measured under
  different models, action sets, or joint-experiment IDs never upgrade the
  label; one exact non-unknown joint-experiment group must itself contain both
  path and blocking-domain cardinalities. Two routes sharing a public context
  are exercised, then one exact route is denied/expired while the other keeps
  the context active; the removed `carrierInstanceId` ceases contributing
  immediately despite its unexpired evidence. Only two currently active paths
  jointly exercised under the exact registered runtime blocking model can
  upgrade. Mixed/all-unknown blocking tuples, measured
  unknown operator IDs, and active-edge PQ sets containing `not-established`
  hit their exact conservative branches rather than counting as diversity or
  falling through the aggregate. S1 never claims omission tolerance. R2-BEC
  is never a runtime `RoomAssuranceV4` badge. The machine-readable
  conformance/evaluation registry may assert it only when the one canonical
  participant-bound temporal graph passes `R2Conforms`; a locally diverse set,
  independently passing but disconnected participant sets, removal of the
  last honest/time-respecting path in any tested fault subset invalidates that
  scoped registry claim. Removing a required non-IP path invalidates the
  separately named combined shutdown claim.

- **AC-033 — Frozen v2 policy resolution:** The published v2 capability,
  capability-only and canonical policy-bearing `/r` fragments,
  `DEFAULT_BLIND_POLICY_V4_0`, policy hash, room context, and local-room-ID
  vectors match exactly across browser, worker, frontend routing/QR/share
  tests, fresh install, upgrade, and restart. A changed application default
  cannot reinterpret either invitation version; v2 rejects policy query
  parameters. A non-default policy mismatch fails before pair disclosure.

- **AC-034 — Core/local separation:** For the same valid operation set,
  immutable room policy, and reference window, clients with different peer
  allow/deny lists and planner modes derive byte-identical `CoreRoomState` and
  intentionally different complete `LocalAdmissibleProjectionV1` values,
  including independent status axes and topology-origin facts. Different client-global
  carrier policies alter only `LocalDeliveryState`; they cannot make a peer
  admissible or inadmissible. In a three-member room, an identical outer-valid
  pair step between A and B appears in A, B, and C's
  `activeOperationIds`, `activePairOuterOperationIds`, and core digest; only A
  and B attempt Open/reduce it. An authenticated invalid inner value fails
  that edge only and never changes any member's core set.

- **AC-035 — Closed operation and pair codecs:** Unknown kinds, lifetime
  mismatches, wrong payload classes, illegal outer dependencies, pair-sensitive
  outer metadata, wrong inner predecessor/sequence, and noncanonical encodings
  all fail at the specified layer. Per-source store-hint lease retention and
  monotone revocation-fact evaluation use their kind-specific reducers rather
  than the generic fork rule. Boundary vectors prove outer decoding checks only its closed permitted
  class/length/envelope constraints, then post-`OpenPairStep`
  `PairOperationPayloadClassFor` selects the smallest fitting permitted class
  from authenticated unpadded pair plaintext and bootstrap-header presence.
  Vectors derive exact suite-1 plaintext targets `2919`, `4017`, and `69553`
  from the schema/class table, reject class-1 bootstrap, require empty pair
  `operationPadding`, and fail if a duplicated target table diverges.
  `STORE_HINT` vectors sequence-encode routes in derived-`RouteId` order,
  reject duplicate/unsorted/over-255 routes, and prove deterministic full
  logical-window coverage by every absolute descriptor/route lease without an
  ambient clock. Oversized values, pre-open plaintext inference, nonminimal
  classes, and non-unique pair padding all fail. Deterministic vectors cover
  every operation kind and every pair-step body.

- **AC-036 — Strict presence gate and honest open-mode label:** Address-book
  signatures and authority permits bind the exact presence core; forgeries,
  reused permits, and commitment substitution cannot trigger a strict
  initiator identity hello. Strict-self vectors cover a verified locally
  custodied stable key absent from the address book, deny overriding that
  implicit local-known key, an invalid lower duplicate followed by a valid
  higher duplicate, and a lower valid unowned `P1` defeating a higher locally
  owned `P2` of the same identity so no local vertex is invented. A structural
  ownership record or corrupt claimed local signature never substitutes for
  the genuine custody brand. Open/denylist-only tests demonstrate the possible
  first-flight identity disclosure and require
  `identityDisclosure: "first-flight-visible-to-selected-capability-holder"`.

- **AC-037 — Non-circular pair bootstrap:** HELLO and ACCEPT vectors contain
  the exact public bootstrap headers, HPKE suite/PSK/info/export inputs,
  prebindings, tags, AAD, roots, inner fields, operation-ID transcript, and
  persist-before-publish snapshots. Vectors also exercise the shared
  `SealPairStep`/`OpenPairStep` construction for every non-HPKE pair kind. The
  first authenticated TRANSPORT_OFFER is initiator key confirmation and no
  standalone CONFIRM exists. Either endpoint derives each flight without
  requiring an encrypted field first. Equal stable keys, ciphertext
  relocation, exact replay, authenticated slot fork, forged/changed
  `attemptMode`, and planner-vs-explicit receiver policy have the required
  rejection behavior. Incoming explicit succeeds without a reciprocal local
  request only when the exact initiator vertex is selected and current
  `allowOnDemandEdges=true`; it fails when false. Planner mode requires the
  private exact `plannerSelected` fact, and neither `desiredEdge` nor
  `locallyRequestedExplicit` can substitute. When both outbound origin bits
  are true, `"explicit"` deterministically wins and that exact mode survives
  restart. Claim vectors substitute attacker-owned claimant keys
  into concurrent offers/answers and fail before persistence because the keys
  do not byte-equal the confirmed flight senders; both signatures,
  `StableEdgeId`, `PairEdgeId`, and transcript ID are recomputed exactly.
  Unequal attempt intervals that overlap at either inclusive boundary retain
  one canonical two-claim audit and block offer/answer/promotion for both
  attempt IDs through the later end plus skew; disjoint intervals do not
  conflict, and neither arrival order nor restart changes the result.
  Restart/crash vectors at every boundary after HELLO and
  before ACCEPT/offer/answer/promotion restore the exact atomically persisted
  `PairAttemptLeaseV1.attemptMode`; no later flight, planner recomputation, or
  default can rewrite or infer it.

- **AC-038 — Pair-edge rollback boundary:** Restore a byte-for-byte older
  durable snapshot (IndexedDB in the reference browser). Missing room
  operations/frontiers reconcile without being mislabelled rollback. For an
  existing edge only, presenting its restored older authenticated v4
  transcript/counter to an uncompromised peer retaining newer edge state is
  rejected and rehandshakes that edge. Restoration before contact,
  simultaneous restoration of both peers, and private frontend-policy
  rollback are not claimed detectable without a named platform monotonic
  anchor. Root/epoch replacement and cover sealing context are atomic;
  stale/future cross-epoch dummy cells cannot mutate counters or edge state.

- **AC-039 — Scoped assurance evidence:** Every carrier-scoped field is
  derived from timestamped evidence for each active carrier; room and edge
  fields use their own scoped facts, and the pure aggregate applies the
  documented conservative rule. Adding a room-unique or unmeasured server may
  increase path availability but cannot upgrade cohort privacy or operator
  independence. Empty carrier/edge sets and every expired/heterogeneous
  evidence combination produce the exact non-vacuous summary values. Vectors
  cover multiple routes to one public context, multiple bundles on one custody
  path, and a measured public path combined with a merely declared or unknown
  contact/bundle path; the latter combinations cannot report
  `measured-independent`. Censorship vectors distinguish two paths in one
  blocking domain from two freshly exercised measured domains, then expire,
  fail, or deactivate each. Heterogeneous portable-bundle vectors produce
  distinct profile-bound instance IDs but one shared custody-path ID and
  therefore no false diversity. Repeated fresh instances cross the exact
  evidence count/byte cap and force the documented saturated conservative
  aggregate rather than a selected subset; saturation cannot clear before its
  rejected-record watermark and raw datasets obey their own byte cap.
  Same-series generation, newer-failure/older-active expiry, and concurrent
  method/vantage vectors prove no superseded or favorable record reappears.
  Reclassifying one unchanged route instance onto conflicting measured paths
  yields one unknown current path rather than two paths. Cross-profile
  portable, cross-route/contact, cross-vault scheduler, cross-room/backlog, and
  cross-frontier attestation substitutions fail exact binding/scope checks.
  Byte-exact vectors derive `L3RequiredWorkId` and the sorted
  `l3RequiredWorkDigest`; adding one work item, changing either horizon,
  profile/frontier, capacity result, or saturation witness changes the digest,
  rejects stale readiness evidence, and conservatively downgrades
  `shutdownControl`.
  A backward clock jump or excessive uncertainty makes time-based fields
  unknown/exhausted until trusted time and fresh measurement recover. Raw
  cohort population filled by attacker-known or unknown Sybils cannot raise
  `attackerUnknownCoverLowerBound`; absent a pinned corruption bound it is
  zero. Shutdown vectors combine non-IP readiness with
  remaining horizon, due-work saturation, capacity, and stale/unknown
  evidence. Every permutation yields the exact conservative closed summary.

- **AC-040 — Versioned protocol publication:** The release produces the
  generated web whitepaper, machine-readable claim/evidence registry,
  bibliography, protocol vectors, version manifest, and implementation
  provenance required by Section 6.3. The proposal/current-implementation
  boundary and literature cutoff are visible on every version.

- **AC-041 — Local-ID/API migration:** Upgrade, restart, store-unavailable,
  abort, timeout, and crash-at-every-transaction-boundary tests prove that
  blind `Room.id` equals `LocalRoomId`, deprecated `Room.url` equals the
  disjoint `local.v1.<LocalRoomId>` handle, and every current helper accepting
  `roomUrl` round-trips that handle without treating it as an invite. Join
  resolves after local durable initialization independently of carrier
  readiness. Blind `Peer.peerId` equals the canonical room-scoped
  `LocalPeerId`; `Room.observedMembers`, `Room.edges`, `Room.peers`,
  `waitForObservedMembers`, and `waitForPeers` exhibit the distinct semantics
  in Section 4.10. Migration/crash vectors enumerate every named DB,
  middleware, negotiation, ICE, ratchet, cover, transfer, PIN, localStorage,
  public-helper, log, and error namespace; outside the sole wrapped
  capability record in the protected vault keyed by `LocalRoomId`, no
  ordinary/plaintext index, map, log, or error contains a capability or legacy
  server UUID in blind mode. Legacy rooms remain usable and plaintext indexes
  are removed only after the protected-vault commit in a compatibility build
  with the legacy-signaling adapter. A socket-free build preserves legacy
  records/migration metadata but rejects with that exact typed error without
  connecting. Canonical-ref migration vectors cover every enumerated legacy
  alias, bytewise duplicate, malformed/wrong-prefix row, interrupted
  transaction, and ambiguous multi-row mapping; they either commit one
  canonical value or keep policy unavailable/fail closed, never choose by
  iteration order.

- **AC-042 — Frozen interoperability registry:** Before blind mode can be
  enabled, the canonical binary schema, executable-kernel manifest, claim and
  formal-obligation registries, HTTP carrier protocol, exact default
  delivery/planner/per-room/global resource values, scheme-1 allocation messages and RFC
  vectors, exact issuance/allocation request hashes, lease/status signature
  transcripts and idempotent replay records, default store descriptor/routes,
  compatibility hash, `L3RequiredWorkId`/`l3RequiredWorkDigest`, the complete
  R2-BEC node/edge/fault/evidence/claim/record codecs and ID vectors, complete
  contact/portable/WebRTC adapter entries, accountability and source-privacy
  mechanism/profile registries, enum/adapter registries, and all
  request/response target lengths are published under one
  release-registry hash. Independent client and server implementations
  byte-match every vector. The Section 6.3 version manifest is keyed to that
  registry hash and separately enumerates each build profile and exact
  optional-adapter manifest. Absence or mismatch is a build/release failure,
  not an implementation-selected default.

- **AC-043 — Sparse room messaging parity:** Before sparse blind rooms replace
  the production default, a companion versioned data-plane conformance suite
  proves that a room message and attachment reach every currently reachable
  admitted recipient across multi-hop sparse topologies under duplication,
  loops, churn, partitions, retry/restart, malicious relays, quota pressure,
  and PQ epoch transitions, without revealing plaintext to intermediaries or
  exceeding degree bounds. A shutdown-messaging release repeats the suite with
  all IP APIs disabled over the selected real non-IP carrier. Running only the
  control-plane suite may claim rendezvous conformance, never unchanged
  whole-room product behavior or application messaging through a blackout.

- **AC-044 — Deployed-claim reconciliation:** A release audit compares the
  SDK, frontend, server schema/runtime, retention jobs, telemetry, privacy
  policy, TOS, blocked-peer/known-peer UI, marketing, application/access/TURN
  logs and rotations, ICE transport schemes, query/identifier redaction, and
  assurance registry.
  It removes or qualifies every memory-only, deletion, anonymity, IP-hiding,
  censorship, shutdown, and PQ statement not supported by the deployed blind
  path. Legacy-path capability upload, transport security, and database/log
  retention are disclosed separately; passing blind-mode tests cannot
  sanitize contradictory legacy behavior or legal copy. The audit verifies
  the effective presence/absence of optional legacy modules, Upgrade routes,
  socket logs, proxy rules, deployment probes, TURN/signaling secrets, and
  frontend legacy controls for each published build profile.

- **AC-045 — WebSocket-free composition:** Build the blind SDK/frontend
  without importing, re-exporting, or precaching any WebSocket adapter. Run
  once with `globalThis.WebSocket` absent and separately with a throwing
  getter/constructor sentinel. Start
  one store-only server whose listener/proxy has no Upgrade route, socket peer
  registry/pubsub, heartbeat, or TURN/signaling-secret dependency. With
  HTTPS/fetch available but every WebSocket attempt blocked, repeat AC-002
  through presence, bilateral admission, pair-private WebRTC SDP/ICE, a stable
  protocol-v4 edge, and one operation-carried PQ cycle; then repeat AC-024 and
  AC-025. Inspection observes no WebSocket construction/Upgrade, `wss:`,
  `?publickey=`, roster/signal frame, or heartbeat. With the reference HTTP
  path delivering, removing every WebSocket adapter leaves v2 IDs, canonical
  bytes, state, fixed trace, and rendezvous outcome unchanged. If no other
  path remains, it reports unavailable rather than changing state or
  downgrading. A separate compatibility artifact
  proves v1 invokes WebSocket only when its explicit legacy adapter is
  installed and that v2 never selects it.

- **AC-046 — Declared S1/R2-BEC threat boundary:** With one Byzantine store,
  confidentiality, authenticity, room isolation, strict admission, pre-SDP
  control, deterministic reduction, and PQ state safety pass while forced
  omission yields explicit S1 unavailability, never invented liveness.
  Canonical vectors byte-match `R2ConformanceRecordV1`,
  every node/edge/fault/evidence ID, `R2TemporalGraphCoordinatesDigest`,
  `claimScopeId`, both attestation transcripts, and `R2Conforms`. A
  dropped operation, forged author/expiry, favorable subset, cross-participant
  evidence replay, graph-coordinate mutation, carrier/fault-unit cross-label,
  scheduler-semantics/artifact/trace/workload/refinement mutation, missing or
  contradicted custody promise/checkpoint evidence, selected-store/profile
  accountability saturation, wrong evaluator key,
  expired evidence, or evaluation-time/uncertainty change fails its exact
  check. A
  capacity vector in which each operation-to-participant demand fits alone but
  the complete simultaneous demand exceeds one shared edge fails the joint
  simulator. A second vector where an existentially favorable route/order
  succeeds but the exact production service/event order misses an expiry also
  fails.
  The positive case has two proactively used honest stores under distinct
  operator/path/blocking fault units, arbitrary additional Byzantine stores,
  whose partitioned fault-evidence floods cannot saturate either selected
  honest store, `f=1`, and a global time/capacity graph from every operation author to every
  named participant. Enumerating each one-unit fault preserves safety and
  delivery before expiry through the surviving honest store; Byzantine
  duplication, reordering, and equivocation cannot forge an accepted
  operation or make equal validated sets reduce differently. Selective
  revelation may change an interim observed subset and state, and omission
  fails liveness whenever the surviving honest paths do not repair it in time.
  Removing both honest paths, exceeding authorized valid-work capacity, or
  making the survivor late fails R2-BEC liveness without inventing finality.
  An asymmetric vector gives Alice two active stores while Bob/Carol authorize
  only one; Alice may report local diversity, but the global graph fails
  `R2Conforms`. Participant/evidence substitution and two independently
  passing but disconnected local graphs also fail. Joint-model, operator,
  blocking-domain, reachability, and capacity/evidence-cap predicates are
  removed one at a time and invalidate the exact record. Removing non-IP
  readiness invalidates only the separately named combined shutdown claim.
  Removing a separately named privacy, admission, or PQ result does not
  rewrite R2-BEC; it prevents only the broader explicit release conjunction.
  Documentation/UI tests enumerate the unsatisfied stronger models from
  Section 1.6 and reject unqualified `anonymous`, `uncensorable`,
  `quantum-secure`, `globally complete`, or `fully Byzantine` wording.

- **AC-047 — Executable normative SSOT:** The release manifest contains
  exactly kernel modules 1 through 8 in order, binds the same canonical-schema
  hash as the release registry, resolves every globally unique entrypoint, and
  binds the exact executable artifact and normalized source-tree hash for each
  module. Independent implementations byte-match the manifest.
  Types/codecs, fixtures, requirement and claim tables, UI wording keys, and
  whitepaper protocol tables are generated from or mechanically checked
  against the schema/kernel/claim SSOT. Removing, reordering, adding an
  accessor/unknown field, changing one artifact/source/entrypoint/vector hash,
  substituting any child registry root, or changing a
  generated projection without its source makes validation or the release
  build fail. The initial non-public-barrel SDK scaffold passes its logical
  shape/reference/cycle/root-binding tests, exposes no positive-wording
  authorizer, and does not count as the missing canonical codec or module-8
  evaluator.

- **AC-048 — Formal result and refinement gate:** Reproducible artifacts cover
  FPO-001 through FPO-006 and bind every
  model/property/derived-assumption/refinement/toolchain/scope/release hash
  exactly. Module 8 resolves canonical claim/proof scopes and rejects a proof
  whose registered coverage predicate does not cover the evaluated scope.
  FPO-002 additionally binds the active implementation artifact set,
  canonical traces, complete competing scheduler workload, profile/resource
  tuple, and delivery implication. Production implementations differentially
  replay the canonical transition traces. A changed scheduler order,
  retry/reserve rule, admission lease, reducer transition, PQ-control
  persistence boundary, claim dataset, registry root, or claim state creates a
  refinement mismatch. A serialized `state="satisfied"`, counterexample,
  inconclusive result, hidden/unchecked assumption, absent result, stale
  release binding, expired `validThroughMs`, or proof outside its declared
  scope prevents every dependent positive wording while preserving the
  published negative result.

- **AC-049 — Room-blind store accountability:** One-store and multi-store
  fixtures finalize all-real, mixed, and all-dummy windows. Each yields the
  complete fixed chunk set, exact RFC 9162 root, one signed checkpoint, and one
  continuous retained successor segment from an exact pinned head. Scheduled
  clients initiate one targetless checkpoint GET and the full canonical chunk
  scan without awaiting a response; a never-resolving checkpoint still
  produces every chunk request.
  Positive vectors verify a signed custody promise at its deterministic slot;
  mutation vectors prove wrong-object custody breach, same-window checkpoint
  conflict, broken predecessor, chain-start conflict, historical descriptor
  rotation, wrong descriptor/profile/window, reordered or omitted Merkle leaf,
  an extra sibling, every cross-coordinate relocation, and invalid
  path/signature. Retention-end vectors verify the exact inclusive boundary;
  a post-retention gap becomes `unverified-chain-gap`, and a new local anchor
  certifies only future continuity. Operation/promise/checkpoint/chunk
  substitution in each R2 `custodyBinding` fails. Silence, a missing response,
  or a withheld proof remains availability/unknown and never fabricates blame.
  Schema/log/network inspection finds no room, identity, member, pair,
  operation, admission, proof, or proof-digest field in room operations,
  public-store appends, logs beyond the local bounded tombstone, or automatic
  telemetry. An unselected malicious store may exhaust only its partition and
  cannot suppress an R2 result using two honest selected stores. Cap, restart,
  tombstone, explicit export-consent, and saturation vectors preserve every
  negative proof or conservatively suppress only the affected
  accountability/R2 input.

- **AC-050 — Optional measured SP1:** A release advertising SP1 publishes the
  exact mechanism/profile registries, browser implementation, preregistered
  source-classification experiment, raw bounded dataset, and current
  evaluation. One reproducible computational result proves the modeled
  `1/k + epsilon` bound with at most `t` corrupt mixing domains among at least
  `max(2,t+1)` named independently operated domains disjoint from the target
  store/egress operators; checked profile validation requires
  `1/k + epsilon < 1`. The proof scope exposes the exact security/session
  definition, topology/layer count, per-layer operator-selection mass,
  theorem parameter values and units, corruption weight, cumulative linkable
  packet/byte volume, fragmentation mode, and separate drop- and delay-tag
  obligations. Domain count or a trace hash cannot substitute for those
  bindings.

  Current measurements establish the exact deployment assumptions, route set,
  eligible population, completed interval, and trace. On the live selected
  mechanism, preregistered entry-and-egress-collusion classifiers cover every
  request and success/drop/delay/timeout/retry/route-failure class and report
  the preregistered base rate, PR-AUC, and TPR at a configured low FPR with
  confidence intervals. Classifier non-success alone never satisfies the
  claim.

  Every request class 0 through 7 passes the same kernel-owned egress gate
  after prewarm; only the fixed scheduler subset 1 through 5 is required to
  occur in every interval. The expected fixed event digest, attempted-request
  digest, per-class counts, exact route set, privacy-message IDs, volume epoch,
  packet/byte charges, traffic-charge chain, and egress audit join without
  omissions. The chain meters prewarm, dummy, cover, request, retry, and
  failure-control packets—not only real requests. An oversize request either
  fits one privacy packet or uses the registered mix-layer all-or-nothing
  transform; fragment suppression, partial reassembly, same-ID partial retry,
  application-layer fragmentation, and delay tagging have negative vectors.
  Whole-message retries use fresh IDs.

  The atomic gate rejects the whole emission/request before egress if either
  interval or cumulative linkability cap would overflow. A new interval, room,
  context, route, policy, process, login, or restart does not reset the
  client-global volume epoch; rotation requires exact unlinkability evidence
  against all retained prior observations. A live interval never becomes
  positive, and evidence from one interval, context, exposure digest, route
  set, domain set, or volume epoch cannot replay into another. Throwing direct-network and
  unregistered-route sentinels, mechanism/domain loss, evidence expiry,
  tag/clock/model mutation, restart, cap saturation, incomplete floor history,
  and prewarm failure all prevent dispatch rather than fallback. A blocked
  request is unavailable but not falsely called an exposure; injected egress
  taints the exact `(context, interval)` monotonically. Policy rotation,
  profile change, and disable/re-enable attempts cannot launder the taint,
  reuse prewarm, or reset volume.

  A registry vector rejects fixed cascades plus loop-only cover; an accepted
  fixed-cascade profile includes measured additional non-loop cover and the
  relevant last-hop/intersection obligations. Entry-ISP, global-observer,
  long-term-intersection beyond the exact volume/model scope, and
  post-direct-exposure experiments are displayed as nonclaims. A release with
  `{mode:"disabled"}` may pass core v0.4 but cannot emit SP1 wording.

- **AC-051 — PQ successor and downgrade boundary:** V0.4 vectors reject every
  v3 invitation, `RoomPolicyV5`, successor object, partial-hybrid signature,
  unknown successor suite, and migration statement before persistence or
  disclosure and never fall back. A successor claim cannot become satisfied
  until a separate companion spec and manifest freeze all suite IDs and the
  complete authentication-coverage matrix. Every `hybrid-signed` entry
  verifies both components, every transcript-bound entry reaches its exact
  hybrid-authenticated transcript, and every out-of-band assumption is
  rendered. Ordinary invitation provenance is never upgraded by a
  same-invitation self-signature. A fresh capability/context/successor session
  is created and external/formal/vector evidence passes. The sender cannot
  select continuity trust; local vectors accept only the three named evidence
  bases, enforce the allowlist/denylist/grant migration rules, and otherwise
  render `new-unlinked-identity`. No v0.4 test, hybrid KEM, CPace/PIN, classical
  Blind-RSA, or eventual PQ-healing result is accepted as PQ-authentication
  evidence. Successor negative vectors cover a missing, malformed, invalid, or
  swapped component; key/suite/policy substitution; different component
  transcripts; role, KEM, SDP/ICE, DTLS-fingerprint, and key-confirmation
  substitution; unknown suites; classical-only negotiation; and every
  downgrade/fallback path. Browser evidence additionally distinguishes
  wrapped-at-rest JS/Wasm key custody from native non-extractability.

- **AC-052 — Peer-executed carrier equivalence and role boundaries:** The
  conformance suite exercises both REQ-029 roles without a peer-specific wire
  codec. First, three room participants have pre-existing authenticated
  contacts `Alice ↔ Bob` and `Bob ↔ Carol`, while Alice and Carol share no
  public store or direct bearer. Bob's contact adapter bridges bounded retained
  operations. Before expiry, Alice and Carol converge the required presence and
  admission facts, complete their bilateral identity gate, exchange
  pair-private transport offer/answer operations, finish protocol-v4, and
  complete one PQ-healing cycle through Bob. Duplicate, reorder, restart,
  intermittent contact, and bounded backfill schedules yield the same canonical
  operation set as direct delivery. Bob is not selected as a roster authority,
  sequencer, pair endpoint, or mandatory topology hub; without the Alice/Carol
  pair root his endpoint and contact adapter cannot decrypt their SDP/ICE,
  v4, or PQ payloads. Reusing the same physical contact for a second room or
  delivery profile neither merges rooms nor makes unrelated peers candidates.
  When Bob's contact disappears and no path can meet the next semantic
  deadline, pending work persists and the clients report `partitioned`; no
  public-store custody, public-store availability, or R2 honest-store unit is
  inferred.

  Second, the unmodified reference public-store process runs on a room
  participant's device and exposes one signed descriptor and authorized route.
  It passes the same allocation, append, complete fixed-scan, checkpoint,
  custody, quota, retention, restart, omission, and equivocation black-box tests
  as a separately hosted store. Explicit local addition leaves the invitation,
  room context, sparse plan, and pair sessions byte-identical, schedules
  reconciliation/backfill, and publishes the existing bounded `STORE_HINT`.
  A peer whose frontend has preauthorized the exact store and route may activate
  it; another peer performs no DNS, fetch, credential, private-network, or
  adapter work. Co-locating endpoint and store produces separate role evidence
  but one shared operator/availability/blocking domain wherever the measurement
  registry says they coincide; duplicating processes or routes cannot satisfy
  independence. If the hosted process omits any mandatory store behavior, it
  remains an opportunistic/nonconforming carrier and earns no public-store or
  R2 claim.

  The peer-hosted branch reruns AC-003, AC-005, AC-009, AC-014, and AC-015 with
  the store co-located with a malicious denied capability holder. Store,
  allocation, endpoint, room, pair, v4/PQ, and contact keys are generated in
  their required disjoint domains; equality, imported-key, cross-role-KDF,
  endpoint-locator-as-store-route, direct-persistence, reducer-injection, and
  fixed-scheduler-bypass mutations fail before a positive claim. Co-location
  reveals no extra store-protocol field, does not merge rooms, does not activate
  an unapproved route, and does not let the denied host decrypt another pair's
  payload.

  Endpoint admission and carrier authorization remain separate frontend SSOTs.
  Blacklisting or rejecting Bob prevents endpoint promotion and releases no
  SDP, regardless of whether an explicitly authorized opaque contact-carrier
  path remains. Removing or denying that contact context stops its carrier use
  atomically; retaining it cannot bypass `Admit()` or create a planner edge.
  Neither endpoint decision silently authorizes or denies Bob's separately
  signed public store, whose exact store/route policy is evaluated independently.

  Finally, a fresh client given only a room invitation and no reachable
  configured store, authorized route, authenticated contact, portable bundle,
  or out-of-band path remains honestly unavailable/partitioned. The
  implementation neither invents peer discovery nor falls back to addressed
  signaling.

## 6. Test Automation Strategy

### 6.1 Test levels

1. **Canonical-vector tests** cover every codec, hash/KDF domain, signature,
   room context, operation ID, carrier envelope, role, topology edge, pair
   transcript, transport binding, and portable bundle.
2. **Property/model tests** cover set laws, reducer determinism, author/pair
   forks, dependencies, expiry, partitions, late delivery, and sparse graph
   convergence.
3. **Primitive and misuse tests** use the selected libraries' vectors plus
   nonce, key/domain separation, invalid-input, rollback, zeroization, and
   exact-frame tests.
4. **Store integration tests** run one and several real server processes under
   reorder, duplicate, omission, equivocation, restart, quota, and retention
   faults.
5. **Browser E2E tests** exercise the unchanged invite/join UX, frontend peer
   and store policy, IndexedDB failure, WebRTC handoff, reconnect, and
   protocol-v4 state in independent browser contexts.
6. **L3 E2E tests** disable networking and use only portable/automated non-IP
   carriers across interrupted contacts and restarts.
7. **Privacy experiments** capture sole-store and multi-store observations,
   preregister inference tasks, compare baselines, and report confidence
   intervals and overhead.
8. **Censorship experiments** use declared independent vantage points and
   blocking actions, including route discovery and distribution failure.
9. **Fuzzing and adversarial review** cover every untrusted parser, state
   transition, admission boundary, and persistence crash point.
10. **External review** covers the threat model, construction composition,
    primitive instantiations, formal games, and implementation before labels
    graduate.
11. **Normative-SSOT and refinement tests** regenerate every projection,
    replay kernel traces against SDK/frontend/store implementations, reproduce
    FPO results, inject counterexamples, and prove the claim compiler
    downgrades rather than retaining stale positive wording.
12. **Peer-carrier role tests** run the same operations through authenticated
    peer bridges and endpoint-cohosted public stores, verify role-separated
    metadata/evidence and room isolation, and reject bootstrap, durability, or
    independence claims not earned by the exercised path.

### 6.2 Required fixtures

- current invite/capability/word vectors and public API examples;
- two rooms, overlapping identities, multiple concurrent room slots, and
  unrelated cohort dummies;
- open, address-book-only, local-blacklist, authority-grant, expired-grant,
  wrong-room-grant, and withheld-revocation rooms;
- one default store, one room-unique self-hosted store, one
  endpoint-cohosted peer store, two independent public stores, disjoint store
  partitions, and authenticated peer bridges under transient and retained-work
  contact schedules;
- valid, expired, incompatible, malicious, loopback, redirecting, and denied
  store routes;
- every presence count through `maxRoomMembers`, churn, forks, collisions,
  partial views, suspension, and overcapacity;
- each ML-KEM suite and largest exact v4 control frame;
- every v4 handshake/PQ persist-before-dispatch crash boundary;
- portable bundles at minimum, maximum, malformed, truncated, duplicated,
  inventory/object mismatch, wrong-context, wrong-profile, and clock-skew
  boundaries;
- automated non-IP and pre-existing peer-contact
  loss/reorder/fragmentation/restart traces;
- cold-start, resident-prewarmed, fixed-scan, on-demand, and contact-dependent
  traffic datasets; and
- all-real, mixed, and all-dummy checkpoint chains; valid custody inclusions,
  signed wrong-object breaches, conflicts, gaps, withheld paths, restarts,
  chain-start changes, and evidence saturation;
- SP1 conforming and direct-exposure traces across every request/outcome class,
  with low-base-rate entry/egress flow correlation, domain selection-mass
  corruption/loss, cumulative-volume exhaustion, restart/reset attempts,
  single-packet and all-or-nothing fragmentation, fragment suppression,
  whole-message fresh-ID retry, distinct drop/delay tagging, fixed-cascade
  loop-only rejection, clock, prewarm, and evidence-expiry variants;
- claim-registry prerequisite cycles/missing references, every evaluation
  state, stale/mismatched formal results, and production/model refinement
  mutations;
- v3/successor downgrade, partial-hybrid, fresh-context, and identity-continuity
  boundary vectors; and
- simulated and real censorship/blocking-domain datasets.

### 6.3 Release artifacts

A conforming release publishes:

- canonical binary specifications and deterministic vectors;
- the executable-kernel manifest, claim/wording registry, formal-obligation
  registry, reproducible proof/refinement results, and generated-projection
  consistency report;
- one browser/client implementation and one single-process reference store that
  runs unchanged as a standalone service or co-hosted on an end-user device;
- portable-bundle, one hardware-in-loop non-IP contact adapter, and a separate
  deterministic byte harness; a release using only
  hardware-in-loop evidence publishes `non-IP-control-compatible`, while
  shutdown-survival wording additionally publishes the deployed field dataset
  required by REQ-015/AC-025;
- state-machine/model tests and reproducible fault schedules;
- dependency/SBOM, exact primitive versions, reproducible-build evidence, and
  external review report;
- preregistered privacy tasks, raw/sanitized trace schema, evaluation code,
  confidence intervals, and resource/latency tables;
- public-store checkpoint/Merkle/custody-promise/breach/conflict vectors and
  the bounded disclosure/accountability report;
- for any SP1 build, its mechanism/profile registries, implementation,
  measured source-classification dataset, corruption/observer model, and
  fail-closed exposure audit;
- operator and route threat-model templates;
- a machine-readable assurance vector and UI copy for every degraded state;
- a generated, versioned public web whitepaper describing the complete
  frontend/backend protocol, threat model, wire versions, rollout status, and
  evidence;
- a machine-readable claim/evidence registry and dated bibliography/research
  ledger from which the whitepaper's claims and related-work tables are
  rendered;
- a version manifest naming the spec version, invitation/policy/operation/
  carrier/pair/v4 wire versions, frontend and backend release versions,
  repository identities, exact source commits, build digest, publication
  date, literature cutoff, and conformance status;
- downloadable canonical spec, protocol vectors, BibTeX, version manifest,
  and archival PDF;
- an implementation ledger recording the first release/commit for each
  requirement and every later security-relevant change, plus explicit AI-tool
  and human-review provenance;
- migration tests proving current invite and frontend API compatibility; and
- the publication-only PQ-successor manifest and v0.4 downgrade vectors; a
  successor additionally publishes its separate companion specification and
  complete hybrid-coverage/continuity evidence.

The web publication is a generated view, not a second hand-maintained
specification. One reviewable manifest/claim registry is the SSOT for version,
commit, evidence, and status facts; the normative Markdown and canonical wire
vectors remain authoritative protocol inputs. The site includes:

1. a visible `proposal`, `experimental`, or `conformant` banner;
2. abstract and scoped contribution claims;
3. threat/claim/assurance matrix, including every stricter unsatisfied model
   and the distinction between local granular assurance and scoped S1/R2-BEC
   conformance evidence;
4. room, targetless-store, operation-set, admission, pair, v4/PQ, and L3
   architecture;
5. exact cost/capacity model and residual limitations;
6. closest literature and implementation comparisons, with a dated search
   method and cutoff;
7. implementation/evidence status and reproducibility instructions; and
8. a permanent version selector and changelog.

It is static, accessible, printable, and usable without invasive analytics.
Every publication build injects the commit of the exact spec/source tree it
rendered and digests of every generated artifact. Implementation-specific
fields are explicitly `not-implemented` until a conforming implementation
exists; this proposal intentionally pins no future implementation commit.
For each mutable external source, the research ledger records
`evidence_class`, `checked_at`, resolved version/tag/commit when available,
content digest or archive locator, and the claim it supports. A URL alone is
not reproducible provenance. No page may turn an unevaluated candidate
contribution into a proven novelty or shipped property.

## 7. Rationale, Prior Art & Research Positioning

The current raw literature shelf is
[rendezvous-prior-art.md](../docs/rendezvous-prior-art.md). The protocol-v4
security and PQ decisions are in
[protocol-v4-security.md](../docs/protocol-v4-security.md) and
[protocol-v4-pq-cover-architecture.md](../docs/protocol-v4-pq-cover-architecture.md).
This section records the architectural consequences; it does not turn a cited
idea into a shipped property. The hand-maintained shelf is research input, not
publication SSOT. Before each publication cutoff it must be regenerated or
reconciled against the machine-readable ledger, with unresolved/stale entries
marked rather than silently copied.

At this cutoff the shelf's broad statements that a private write always needs
multiple servers and that federation and blindness must be one mechanism are
superseded by the targetless-broadcast qualification below. Its earlier broad
browser novelty language is also superseded by the reviewed implementation
comparators in this section. The shelf remains useful search history, but it
cannot support a publication claim until those entries and the newly added
PerfOMR, UDM, Pudding, Alpenhorn, Tor, DTN, and deployed-mesh comparators are
reconciled.

### 7.1 ADR-001: immutable operation set, not a selected server/cell

**Decision:** Adopt the canonical authenticated operation set and deterministic
client reducer as the only logical state. Treat every store and bearer as an
unordered carrier.

**Why:**

- one server works without a distributed setup ceremony;
- adding a server is a local monotone delivery action, not a consensus
  membership change;
- server partitions can be safely unioned because operations are independent
  authenticated inputs, not competing authoritative snapshots;
- the same bytes survive asynchronous and non-IP carriage;
- no failure detector, quorum, leader, selected cell, or globally finalized
  roster is needed; and
- the design has one implementation path for online, federated, peer-gossip,
  and portable-bundle delivery.

The earlier two-cell VDPF/PIR draft required four independently operated
replicas, synchronized geometry, cell selection, matching commitments, and
failure semantics that conflicted with “deploy one server” and arbitrary
client additions. It also made L3 a separate future design. It is superseded.

Set union is not itself novel. Secure Scuttlebutt uses signed append-only
per-author feeds in decentralized applications, and
[2P-BFT-Log](https://arxiv.org/abs/2307.08381) studies eventual fork detection
for adversarial single-author logs. This specification uses the simpler
bounded rule needed for ephemeral rendezvous: a witnessed authenticated author
fork excludes that author/window; a pair fork fails that pair. The candidate
contribution is the privacy/admission/rendezvous composition and evaluation,
not invention of eventual consistency.

The stronger BFT wording also has clear prior art.
[Kleppmann and Howard's Byzantine Eventual
Consistency](https://arxiv.org/abs/2012.00472) gives authenticated causal
broadcast and convergence without a Byzantine-majority assumption;
[Making CRDTs Byzantine Fault
Tolerant](https://doi.org/10.1145/3517209.3524042) makes the essential
connectivity condition explicit: correct replicas must eventually communicate
through a path not controlled by Byzantine nodes.
[Jacob, Bayreuther, and Hartenstein](https://arxiv.org/abs/2109.10554) show
that state-based and some operation-based CRDTs tolerate arbitrary
equivocation, leaving omission as the eventual-delivery problem.
[Depot](https://www.usenix.org/conference/osdi10/depot-cloud-storage-minimal-trust)
is the deployed-systems lineage for safety/liveness with minimally trusted
cloud storage and fork-join-causal consistency;
[SUNDR](https://www.usenix.org/conference/osdi-04/secure-untrusted-data-repository-sundr)
is the weaker fork-consistency contrast for one untrusted server.
[Bounding Byzantine Impact in Open CRDT
Systems](https://doi.org/10.1145/3806077.3806698) is the 2026 resource frontier
most relevant to malicious but well-formed update floods: convergence alone
does not bound damage, so influence needs explicit cost/rate policy.
The June 2026 preprint [A Composable CRDT Layer for Byzantine-Resilient
Deterministic Reconstruction](https://arxiv.org/abs/2606.18966) is an even
closer mechanism preemption for “accepted set plus pure deterministic
projection,” although it is not yet a reviewed deployment result.
The July 2026 preprint [Byzantine Accountability Without
Consensus](https://arxiv.org/abs/2607.10305) likewise formalizes lifting a pure
deterministic function over converged authenticated sets; it is too recent and
domain-specific to treat as independent validation, but it removes any
plausible novelty claim in that generic lifting step.

R2-BEC is a scoped application of that literature, not a new BFT algorithm:
correct p2party clients are the replicas, honest stores are fair indirect
communication paths, authenticated room operations are the updates, and
union/reduction is the convergent datatype. The finite semantic retention
horizon is stricter than standard eventual delivery, so the spec says
“bounded-horizon” and requires the explicit temporal-coverage predicate.
Classic Byzantine quorum storage, linearizability, and consensus thresholds do
not justify or describe this carrier-union design. P2party's author quotas,
fixed carrier admission, and fail-closed resource bounds limit memory/work but
do not solve the open-system influence/personhood problem identified by the
2026 bounded-impact work.

SUNDR and Depot also preempt novelty in detecting server forks or reconciling
signed updates. This design deliberately asks less of its stores:
clients authenticate and union room operations independently, while public
checkpoints prove only contradictions to the store's own opaque custody
promises. That narrower promise preserves the one-server targetless geometry
and avoids putting client/social state into the storage consistency protocol.

### 7.2 ADR-002: targetless broadcast is the one-server correctness baseline

**Decision:** A public store exposes append plus complete public cohort chunks.
Every L2 client scans the cohort. OMR/PIR is an optional accelerator.

The important qualification to the common “private writes need two servers”
statement is:

> Two non-colluding servers (or FHE/TEE machinery) are needed to hide the
> destination of an indexed/addressed write. They are not needed when every
> write is an opaque append to one common public bucket and every reader
> obtains that entire bucket.

The targetless log has no private write index to protect. Its costs are instead
linear cohort bandwidth, client trial decryption, fixed cover traffic, public
aggregate occupancy, and bearer-visible source/timing. Those costs are real
release gates.

Relevant design points:

| System/primitive                                                                                                                                         | Server assumption and strength                                                                                                                                                                                 | Consequence here                                                                                                                                                                                                                                                                                              |
| -------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [DP5](https://petsymposium.org/popets/2015/popets-2015-0008.pdf)                                                                                         | Multi-server PIR private presence with pre-shared friend secrets                                                                                                                                               | Preempts generic private-presence/PIR novelty; useful evaluation comparator.                                                                                                                                                                                                                                  |
| [UDM](https://doi.org/10.1080/01611194.2021.1911876)                                                                                                     | One untrusted discovery service indexes encrypted platform identifiers by shared-secret-derived tags                                                                                                           | Direct one-server private-user-discovery predecessor. Its addressed tag exposes equality/linkability unlike the targetless full scan, while v0.4 pays the corresponding cohort bandwidth and cover cost.                                                                                                      |
| [Pudding](https://martin.kleppmann.com/2024/05/20/pudding-private-user-discovery.html)                                                                   | Byzantine-fault-tolerant private user discovery over anonymity networks; hides registrations and relationships and supports intermittent mobile clients                                                        | Stronger discovery/privacy comparator under a multi-server and anonymity-network deployment; preempts broad private-discovery novelty.                                                                                                                                                                        |
| [Alpenhorn](https://www.usenix.org/conference/osdi16/technical-sessions/presentation/lazar)                                                              | Anytrust multi-server relationship initiation with metadata forward secrecy and out-of-band usernames                                                                                                          | Canonical private-channel-bootstrap predecessor; stronger relationship-metadata semantics, but not a one-server/additive-carrier/L3 target.                                                                                                                                                                   |
| [Tor v3 onion-service rendezvous](https://spec.torproject.org/rend-spec/protocol-overview.html)                                                          | Deployed anonymous introduction/rendezvous with blinded service identities, targeted descriptors, introduction points, and Tor circuits                                                                        | Preempts generic anonymous-rendezvous claims. Its addressed directory/circuit architecture and online anonymity network differ from a targetless room-operation cohort.                                                                                                                                       |
| [Talek](https://eprint.iacr.org/2020/066)                                                                                                                | Topic-secret oblivious logs, anytrust PIR, fixed-rate polling                                                                                                                                                  | Closest room-shaped metadata-private log; validates capability-derived topics and shows the operational cost of stronger reads.                                                                                                                                                                               |
| [2PPS](https://arxiv.org/abs/2108.08624)                                                                                                                 | DPF private publish plus PIR subscribe, anytrust servers and global rounds                                                                                                                                     | Strong indexed publish/subscribe privacy, but paired synchronized servers conflict with additive arbitrary stores.                                                                                                                                                                                            |
| [Private Signaling](https://eprint.iacr.org/2021/853)                                                                                                    | TEE or two-server private notification                                                                                                                                                                         | Definitional pair-signaling comparator; does not supply the one-server/additive/L3 architecture.                                                                                                                                                                                                              |
| [Private Signaling against active servers](https://eprint.iacr.org/2025/1056)                                                                            | Two non-colluding servers; active security; reported roughly two-minute retrieval at a \(2^{19}\) board in its example                                                                                         | Stronger outsourced retrieval than our baseline, but not a one-server fast path.                                                                                                                                                                                                                              |
| [Sabot](https://doi.org/10.1145/3719027.3744803)                                                                                                         | \(k \ge 2\) non-colluding servers; clients cooperatively build a private relationship matrix and use PIR                                                                                                       | Closest reviewed anonymous-channel-bootstrap comparator; it preempts generic anonymous-bootstrap novelty and offers stronger relationship privacy, but not the one-server/additive-store/L3 deployment contract.                                                                                              |
| [Pung](https://www.usenix.org/conference/osdi16/technical-sessions/presentation/angel)                                                                   | One untrusted server with computational PIR and broadcast-style messaging                                                                                                                                      | Demonstrates the single-server zero-trust cost frontier.                                                                                                                                                                                                                                                      |
| [SecureDrop Protocol](https://securedrop.org/news/introducing-securedrop-protocol/)                                                                      | Proof-of-concept, non-finalized protocol with a preliminary audit; explicitly analyzes trial-decrypt-all, then uses remixed clues so recipients fetch pertinent payloads without exposing server-state changes | Its comparison preempts novelty in “download and trial-decrypt everything” and clearly states the bulk-collection/state-leak costs our bounded cohort must evaluate; it is not production evidence.                                                                                                           |
| [Strong Anonymity for Mesh Messaging](https://arxiv.org/abs/2207.04145)                                                                                  | Mesh-oriented anonymous broadcast design with cover/traffic-analysis goals                                                                                                                                     | Important comparator for metadata protection when delivery moves from a public store to opportunistic mesh contacts.                                                                                                                                                                                          |
| [Group Oblivious Message Retrieval](https://eprint.iacr.org/2023/534)                                                                                    | Ad-hoc and fixed-group OMR lets one clue address several recipients without one independent clue per recipient                                                                                                 | Direct group/persistent-room retrieval comparator; it preempts treating multi-recipient detection as new and remains an optional detector, not a rendezvous correctness core.                                                                                                                                 |
| [PerfOMR](https://www.usenix.org/conference/usenixsecurity24/presentation/liu-zeyu)                                                                      | Reviewed single-server OMR constructions reducing server computation or communication with Ring-LWE techniques                                                                                                 | Mandatory direct baseline for any optional OMR accelerator and for the later SophOMR/InstantOMR performance comparisons.                                                                                                                                                                                      |
| [HomeRun](https://eprint.iacr.org/2024/188)                                                                                                              | Two semi-honest non-colluding servers; very efficient OMR                                                                                                                                                      | Attractive paired accelerator, not the correctness core.                                                                                                                                                                                                                                                      |
| [Myco](https://eprint.iacr.org/2025/687)                                                                                                                 | IEEE S&P 2025 asymmetric two-server oblivious structure; \(O(N\log^2N)\), with reported throughput gains up to 302× over multi-server PIR systems                                                              | Current strong cryptographic scale comparator. Its fixed asymmetric roles/non-collusion assumption do not provide elastic multi-provider federation, Byzantine custody, room policy, or censorship-resistant signaling; the contribution here is composition and assurance, not a better retrieval primitive. |
| [PingPong](https://doi.org/10.1109/TON.2026.3672821)                                                                                                     | Uniform-traffic metadata-private notification/retrieval using hardware enclaves; prototype with 32 eight-core servers                                                                                          | A 2026 usability/coordination frontier under hardware trust, not a one-server untrusted-store baseline.                                                                                                                                                                                                       |
| [Pepper](https://arxiv.org/abs/2606.04411)                                                                                                               | Two-server DC-net anonymous broadcast with VDPF registration, batching, and lightweight access control                                                                                                         | Strong sender-anonymity/broadcast and access-control comparator; its non-collusion topology and global-broadcast goal differ from additive arbitrary stores.                                                                                                                                                  |
| [Kerblam](https://eprint.iacr.org/2025/997)                                                                                                              | Two non-colluding servers combine OMR, oblivious shuffling, and distributed ORAM-like storage                                                                                                                  | Stronger sender-and-receiver unlinkability frontier for asynchronous messaging; currently a preprint and a different trust/deployment target, not a one-server rendezvous core.                                                                                                                               |
| [UnifOMR](https://eprint.iacr.org/2026/910)                                                                                                              | Single-server OMR; strong detection-key unlinkability linked to PIR hardness; [listed by an author as ACM CCS 2026 to appear](https://zeyuthomasliu.github.io/publications/)                                   | One 2026 single-server frontier point: reports about 25 seconds and 4 MB for \(2^{19}\) messages of 612 bytes, with two rounds; still too heavy to make a correctness prerequisite.                                                                                                                           |
| [SophOMR](https://www.usenix.org/conference/usenixsecurity26/presentation/lee-keewoo)                                                                    | Accepted/prepublication USENIX Security 2026 single-server FHE OMR with SIMD-aware homomorphic compression                                                                                                     | A 2026 throughput/digest frontier: reports 3.4× runtime, 2.2× digest, and 1.5× key reductions versus PerfOMR at 65,536 payloads; useful optional-accelerator baseline. The conference had not occurred at the cutoff.                                                                                         |
| [InstantOMR](https://www.usenix.org/conference/usenixsecurity26/presentation/liang)                                                                      | Accepted/prepublication USENIX Security 2026 single-server FHE OMR optimized for latency and parallelism                                                                                                       | A distinct 2026 latency/parallelism frontier point: reports about 600× lower latency than SophOMR and near-optimal core scaling; promising optional accelerator with substantial server-compute/evaluation obligations. The conference had not occurred at the cutoff.                                        |
| [Privacy Pass issuance (RFC 9578)](https://www.rfc-editor.org/rfc/rfc9578) and [RSA blind signatures (RFC 9474)](https://www.rfc-editor.org/rfc/rfc9474) | Standardized publicly verifiable Blind-RSA token issuance with blindness and one-more-forgery goals                                                                                                            | Selected conservative v1 allocation primitive. It hides the token input from issuance and separates issuance from redemption cryptographically, but does not itself rate-limit Sybils, hide network timing/source, or make a same-store issuer/origin non-colluding.                                          |
| [Certificate Transparency v2 (RFC 9162)](https://www.rfc-editor.org/rfc/rfc9162)                                                                         | IETF-specified domain-separated Merkle tree hash, signed tree heads, inclusion/consistency proofs, and misbehaving-log analysis                                                                                | Supplies the checkpoint tree/proof algorithm and preempts Merkle-log novelty. V0.4 uses a fixed profile/window root and predecessor chain for narrow custody evidence, not CT's growing certificate-log semantics or a claim of global gossip/completeness.                                                   |
| [Anonymous Rate-Limited Credentials draft](https://datatracker.ietf.org/doc/draft-ietf-privacypass-arc-crypto/)                                          | Keyed-verification credential with a fixed number of unlinkable presentations to one server                                                                                                                    | Close candidate for one-server fixed allocation admission. At the cutoff revision 01 is an unexpired Internet-Draft, but the Datatracker WG state is `Dead WG Document`; it is not a release dependency.                                                                                                      |

An OMR accelerator must address shared-room/multi-recipient detection keys,
key rotation/linkability, malicious correctness, pertinent-message bounds,
browser key cost, and presence discovery where recipients are not yet known.
Its results enter the same validated set. Periodic full-log audit or another
complete authenticated path remains necessary unless the accelerator proves
complete active security.

The reference profile deliberately chooses the least magical construction
that meets one-server correctness today. If measured cohort traffic is too
large, the honest choices are to bound cohorts, deploy reviewed OMR, deploy a
paired private-access accelerator, or offer a lower-assurance addressed
mailbox. They are not to smuggle a room equality tag into an L2-labelled API.

### 7.3 ADR-003: rooms and sparse topology are client facts

**Decision:** A profile cohort is never a room. A room is capability/policy
state reduced locally. Its default graph is a radius-`k` sparse ring over exact
presence operations.

Plaintext namespaces in
[libp2p Rendezvous](https://github.com/libp2p/specs/blob/master/rendezvous/README.md),
server-managed membership in
[Matrix federation](https://spec.matrix.org/latest/server-server-api/), and
plaintext interest filters in
[Nostr NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md) are
useful functional baselines and privacy anti-patterns. A DHT such as Kademlia
distributes lookup observation but does not hide the key or querier from path
nodes.

Binding a stable pair root to a complete roster would make safe pair progress
impossible under ordinary asynchronous omission. Binding only the two exact
presence operations lets safe partial views establish edges; deterministic
recomputation converges when delivery does. The sparse graph keeps expected
connections linear in room size. Full mesh is an explicit small-room/on-demand
policy, not a consequence of sharing infrastructure.

[WebRTC Swarms](https://www.mdpi.com/1999-5903/18/1/13) is the closest current
browser-signaling comparator: it combines onion-routed decentralized signaling,
shared-secret designated-verifier authentication, token-based Sybil/relay
incentives, TLA+ models, and an author-reported production
implementation/evaluation. That is implementation evidence, not independent
field validation. It preempts any generic
claim to “decentralized, private, authorized WebRTC signaling.” Its published
join is \(O(n)\), with one SDP exchange per existing swarm peer, and relies on
an online overlay of incentivized full nodes. Its peer authentication occurs
after the DataChannel is open but not yet verified, whereas this specification
places bilateral stable-identity admission before SDP is released. The
remaining distinctions are the one-server fixed-scan/additive-store
operation-set core, local sparse planning, the same logic over non-IP custody,
and eventual v4 PQ control. Those distinctions must be measured, not asserted
as superiority.

[Open Relay Protocol](https://www.openrelayprotocol.com/docs/whitepaper/) is
the closest current implementation-level blind-WebRTC comparator. It publishes
signed presence/intent and sealed SDP/ICE through a blind bulletin board and
explicitly states that the board still sees the rendezvous social graph. It
therefore preempts a broad “blind WebRTC board” claim. Its documented board is
target/routing-state based and RAM-oriented; it does not document this
specification's targetless fixed cohort scan, canonical eventually consistent
operation union across arbitrary stores, sparse room projection, or common
non-IP/PQ causal path. Those are testable deltas, not priority claims.

### 7.4 ADR-004: frontend admission precedes endpoint disclosure

**Decision:** Keep current local blacklist/address-book behavior as frontend
SSOT, optionally add room-authority grants, and put a bilateral identity-only
gate before any SDP/ICE.

A blind store cannot both remain blind and decide which stable room member is
allowed. Delegating membership to the server also recreates the Matrix
malicious-homeserver class of failure. Conversely, capability encryption alone
is insufficient: a copied capability or later-blacklisted member could decrypt
room-wide SDP if SDP were merely a room payload.

Pair double sealing and the two-flight pre-SDP identity gate solve the narrower
requirement cleanly:

- the server sees no membership rule or decision;
- a capability holder can discover room-level presence but not another pair's
  sensitive payload;
- an endpoint releases SDP only to an exact stable identity its own frontend
  admits; and
- a sole server colluding with a denied user still lacks the pair secret.

The [Signal private group system](https://eprint.iacr.org/2019/1416) is the
stronger single-server membership-hiding comparator if server-enforced group
access is later required. It is not needed for endpoint-controlled SDP
confidentiality. A future anonymous-credential layer remains modular,
especially because post-quantum private-group credentials are still evolving.

[PriSrv](https://www.ndss-symposium.org/ndss-paper/prisrv-privacy-enhanced-and-highly-usable-service-discovery-in-wireless-communications/)
and its 2026 successor
[PriSrv+](https://www.ndss-symposium.org/ndss-paper/prisrv-privacy-and-usability-enhanced-wireless-service-discovery-with-fast-and-expressive-matchmaking-encryption/)
are the strongest direct pre-connection bilateral-policy comparators found.
They use anonymous-credential matchmaking encryption for mutual, selectively
disclosed policy satisfaction and integrate with BLE, mDNS, Wi-Fi, and related
wireless discovery. They provide stronger attribute/privacy semantics than the
exact-key local allowlist here. Adopting that frontier would be a separately
reviewed credential suite; v0.4 chooses the simpler frontend-key/authority
boundary and does not claim anonymous attribute matching.

[Sabot](https://doi.org/10.1145/3719027.3744803) is the strongest direct
metadata-private channel-bootstrap comparator found. It privately constructs
prospective relationships and retrieves them with PIR under at least two
non-colluding servers. It therefore preempts any broad claim that anonymous
bilateral channel bootstrapping is new. The v0.4 design instead targets a
different deployment point: one untrusted server is sufficient, arbitrary
locally added carriers need no shared server ceremony, and the same room/pair
state survives non-IP custody. Those distinctions trade Sabot's stronger
relationship privacy for deployability and must be evaluated as such.

[webwormhole](https://github.com/saljam/webwormhole) already protects WebRTC
offer/answer session descriptions—including DTLS fingerprints—with CPace and a
one-time code, so PAKE-protected fingerprint signaling is not novel here. It
also labels its cryptography early/unreviewed and does not provide this room
operation set, persistent stable-identity admission, additive stores, or
eventual L3/PQ path.

The 2026
[WebRTC ecosystem study](https://www.usenix.org/conference/usenixsecurity26/presentation/bach)
found DTLS-layer authentication breaks in 19 of 33 tested media-server
implementations. It does not analyze this protocol, but it makes exact live
certificate-to-authenticated-SDP verification and adversarial cross-browser
testing a release requirement rather than an assumed browser property.

An exact-key blacklist cannot identify a human after key rotation. This is not
papered over: address-book-only mode or an authority that refuses a replacement
grant provides the strict admission property.

### 7.5 ADR-005: client-side federation for censorship resistance

**Decision:** Replicate proactively across a locally authorized union of
stores/routes. Distribute leased hints through the same encrypted operation
set. Do not require server federation.

[Snowflake](https://www.usenix.org/conference/usenixsecurity24/presentation/bocovich)
demonstrates the deployment value of a large changing set of temporary WebRTC
proxies, but its broker can see matching. [Raceboat](https://petsymposium.org/popets/2024/popets-2024-0027.php)
shows the value of modular low-bandwidth signaling channels.
[Lox](https://petsymposium.org/popets/2023/popets-2023-0029.php) shows that
bridge enumeration and malicious users require explicit credential and trust
policy. [Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458) offers a
standard relay/gateway split for source/content separation but does not hide
timing and fails if the roles collude.

[Loopix](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/piotrowska)
is the reviewed low-latency mix-network baseline for layered mixing, cover
traffic, and tagging resistance.
[Echomix](https://arxiv.org/abs/2501.02933) is the stronger current candidate
frontier found for messaging-oriented mix transport, including active/global
traffic-analysis goals, compromised infrastructure, and hybrid-PQ packet
protection, but at this cutoff it is a preprint and its concrete deployment
assumptions must be independently evaluated.
[Mixnets on a Tightrope](https://doi.org/10.1109/SP61157.2025.00233)
shows why low-delay topology/routing choices need quantitative leakage
evaluation rather than an anonymity label. These works motivate SP1's
mechanism hash, corruption/domain count, trace/tagging/clock model, and
measured classifier bound. They also preempt novelty in source mixing itself.
[MixMatch](https://petsymposium.org/popets/2024/popets-2024-0050.pdf)
demonstrates flow-matching attacks against both laboratory and live Nym
mixnet traces; it is a direct reason to bind the exact interval/route set and
preregister active classifiers as falsification attempts rather than treating
classifier failure as proof.
[Shift Your
Shape](https://www.research.ed.ac.uk/en/publications/shift-your-shape-correlating-and-defending-mixnet-flows-based-on-/)
reports PR-AUC 0.9998 after one minute against default Nym at a paired-flow
base rate of \(1.9\times10^{-4}\). It makes accuracy at an artificial balanced
base rate inadequate: SP1 requires live entry/egress-collusion tests with
PR-AUC and TPR at a preregistered low FPR for every request/failure shape.
[When Mixnets
Fail](https://www.ndss-symposium.org/ndss-paper/when-mixnets-fail-evaluating-quantifying-and-mitigating-the-impact-of-adversarial-nodes-in-mix-networks/)
shows that independent packet routing can turn cumulative destination volume
into full session deanonymization in its model—reported at about 4 MB with 10%
and 30 MB with 5% compromised mixnodes—and that conventional packet-level
anonymity metrics can mislead. This is why SP1 has a non-resettable
client-global volume epoch and binds topology plus operator-selection mass;
counting nominally independent domains is insufficient.
[Breaking and (Partially) Fixing Onion Routing with
Fragmentation](https://petsymposium.org/popets/2026/popets-2026-0120.pdf)
demonstrates fragment-suppression tagging against Nym. Its all-or-nothing
mitigation turns fragment loss into denial of service but explicitly does not
solve delay tagging. SP1 therefore accepts only one-packet requests or
mix-layer all-or-nothing fragmentation, retries the entire message with a
fresh ID, and keeps drop- and delay-tag obligations separate.
[Are Continuous Stop-and-Go Mixnets Provably
Secure?](https://petsymposium.org/popets/2024/popets-2024-0136.php)
derives its bounds from traffic and node-processing rates and establishes an
inherent pairwise-unlinkability lower bound. It motivates visible
theorem-parameter bindings rather than treating `k`, `t`, and a trace hash as
a complete formal model.
[The Last Hop
Attack](https://petsymposium.org/popets/2025/popets-2025-0067.pdf) proves that
sender-receiver pair unlinkability is impossible for fixed cascades with
loop-only cover and no additional cover. Such a registry entry is invalid
here; adding mixes without changing that model is not a fix.
[Karaoke](https://www.usenix.org/conference/osdi18/presentation/lazar) and
[Groove](https://www.usenix.org/conference/osdi22/presentation/barman) are
stronger metadata-private-messaging comparators with distributed trust and
quantitative privacy/latency tradeoffs. They preempt broad metadata-privacy
novelty, but their multi-server mixchain/round architecture is not the
one-server targetless-store baseline or an automagically additive carrier set.
An implementation should evaluate a reviewed Loopix-class or rigorously
specified Echomix/Katzenpost-class route before inventing another mixnet; SP1
allows that route without making it a correctness dependency.

The transferable lesson is path agility with explicit observer assumptions,
not a claim that WebRTC or an opaque route is uncensorable. This specification
adds:

- stable signed store identity separated from rotating route locators;
- proactive use of every already-authorized path;
- no failure-triggered secret fallback;
- frontend-safe hint activation and SSRF prevention;
- client bridging/backfill with no server coordination; and
- measured blocking-domain assurance rather than route counting.

Peer participation uses those same two mechanisms rather than a DHT, brokered
peer-role election, room-wide gossip mesh, or new federation protocol. A
temporary authenticated peer contact is a bounded contact carrier. A device
that wants to provide stranger-to-stranger retained rendezvous runs the same
room-blind public-store protocol and publishes the same signed descriptor/route
material as any other operator. This is the KISS/DRY boundary: placement changes
deployment and evidence, not operation semantics or trust.

If a user adds a private server and only one room uses it, availability
improves but the source population may identify that room. A conforming runtime
reports `room-unique`.

### 7.6 ADR-006: L3 is the same operation protocol, not a future fork

**Decision:** Ship portable and non-IP carriers against the same canonical
operation/reducer boundary now.

[The DTN architecture](https://datatracker.ietf.org/doc/html/rfc4838)
separates a delay-tolerant overlay from heterogeneous regional transports and
defines custody, persistent storage, late binding, and long/variable-delay
concerns. [Bundle Protocol v7](https://www.rfc-editor.org/rfc/rfc9171.html)
standardizes its current application-layer store-carry-forward wire format for
intermittent, high-delay, and opportunistic connectivity, with
convergence-layer adapters.
[BPSec](https://www.rfc-editor.org/rfc/rfc9172.html) adds bundle integrity and
confidentiality but does not define p2party's room, metadata, admission, or
ratchet semantics. [Briar](https://briarproject.org/how-it-works/) is the
deployed product proof that Bluetooth, Wi-Fi, and memory-card synchronization
can keep messaging functional during Internet blackouts.
[Briar Mailbox](https://briarproject.org/download-briar-mailbox/) is the
closer asynchronous-delivery comparator: a separately paired device holds
encrypted messages while either contact is offline.
[Meshtastic](https://meshtastic.org/docs/configuration/module/store-and-forward-module/)
is an operational non-IP LoRa/store-and-forward comparator with bounded
history and explicit device constraints; its channel cryptography and metadata
model are not privacy-equivalent to this design. Secure Scuttlebutt
demonstrates signed log reconciliation between intermittently connected peers.

[Reticulum](https://reticulum.network/manual/understanding.html) is the
closest implemented bearer-neutral networking comparator: one packet and
identity model spans packet radio, serial, LoRa, local links, and IP-backed
interfaces. [Bitchat's protocol v2 whitepaper
(2026-07-06)](https://github.com/permissionlesstech/bitchat/blob/main/WHITEPAPER.md)
is a current implementation comparator for a common router/store-forward model
across BLE mesh and Nostr relays. Neither it nor Reticulum makes p2party's room
capability, frontend admission, pair-private SDP, or v4/PQ eventual-control
guarantees,
but both are directly relevant to adapter ergonomics, MTU/contact behavior,
and honest shutdown-survival claims.

The v0.4 carrier boundary deliberately resembles a convergence-layer adapter,
but the canonical object is a room operation rather than a BP endpoint-addressed
bundle. BPv7/BPSec may be one future carrier encoding; they are not mandatory
and do not confer metadata privacy by citation.

Portable files are the KISS baseline because they prove zero TCP/IP dependency
and can carry the largest frame without pretending a globally deployed mesh
exists. A measured BLE/radio integration is needed before claiming practical
mobility or blackout range.

### 7.7 ADR-007: reuse v4 PQ healing; adapt only delivery

**Decision:** Keep one pairwise protocol-v4 healing machine and exact outbox.
Encrypt its complete existing frame inside a root-derived one-use delivery
slot and feed it through a persisted causal ingress ledger.

[MLS](https://www.rfc-editor.org/rfc/rfc9420.html) standardizes asynchronous
group key establishment with forward secrecy and post-compromise security and
is the principal group-state comparator. P2party already has independent
pairwise Double Ratchets and an existing sparse ML-KEM healing state-machine
core; rendezvous integration remains future work. A second room/group ratchet
would duplicate state and expand the proof surface.

[Signal's Sparse Post-Quantum Ratchet/Triple Ratchet
specification](https://signal.org/docs/specifications/doubleratchet/) and
[published rollout](https://signal.org/blog/spqr/) form the strongest current
sparse pairwise-PQ deployment comparator found. The
[ML-KEM Braid](https://signal.org/docs/specifications/mlkembraid/) is the
closest continuous-key-agreement comparator to the existing p2party healing
machine. It makes the relevant eventual-delivery limitation explicit: dropped
chunks can be tolerated, but healing requires reciprocal traffic and the
maximum vulnerable-message set/healing delay is unbounded when one side never
replies. P2party therefore claims PQ healing only after the bilateral committed
epoch and quiescence conditions below, never merely because an OFFER was
published. The
[formal analysis of Apple's
PQ3](https://www.usenix.org/conference/usenixsecurity25/presentation/linker)
provides machine-checked post-quantum post-compromise claims for another
deployed pair ratchet. The
[PQXDH analysis](https://www.usenix.org/conference/usenixsecurity24/presentation/bhargavan)
also demonstrates that seemingly small KEM binding and deployment details can
change a hybrid protocol's proof. These works preempt novelty in “periodically
mix ML-KEM into a ratchet” and set the formal-analysis bar. V0.4 does not claim
its existing v4 machine is a superior ratchet; it reuses that local SSOT and
requires external review. A later migration to SPQR, PQ3-like machinery, or
ML-KEM Braid, or another reviewed session core can preserve the carrier/causal
adapter only under a new session suite and byte-frozen vectors.

The nontrivial L3 issue is not the KEM. It is crash-safe sequencing when a
carrier duplicates, reorders, withholds, or resurrects exact controls. The
one-use root-derived slot:

- hides the current raw v4 control header from stores and non-endpoint room
  members;
- does not introduce a stable mailbox key;
- preserves the existing root/turn/counter schedule;
- keeps the existing exact outbox as SSOT; and
- scopes any fork or stall to one edge.

The quiescence barrier is mandatory because the current runtime accepts only
the expected PQ epoch. Eventual delivery of application data would otherwise
let old-epoch ciphertext arrive after its root is gone.

### 7.8 ADR-008: accountable custody without room-visible consensus

**Decision:** Treat a signed successful append as a narrow custody promise and
commit every finalized public window to one room-blind RFC 9162 checkpoint
chain.

The receipt already binds opaque bytes to deterministic public geometry.
Adding one profile-wide checkpoint makes a contradictory finalized slot and a
same-window checkpoint fork publicly verifiable without giving the store a
room identifier or turning it into a logical authority. The fixed checkpoint
also covers all-dummy windows and does not add a data-dependent request.

This is intentionally not transparency-log gossip, consensus, reliable
broadcast, proof of delivery to a client, or proof that a silent server is
dishonest. It supplies portable negative evidence for promises the server
actually signed; the authenticated operation union remains the correctness
mechanism. RFC 9162 machinery proves one log view's internal Merkle
relationships; it does not prevent an isolated split view. Global
non-equivocation would additionally require explicit witness quorum,
consistency-proof, and gossip rules. V0.4 claims only conflict detection after
two incompatible signed views meet.

### 7.9 ADR-009: compile claims from the executable normative kernel

**Decision:** Freeze the deterministic normative subset as eight pure kernel
modules and compile every positive claim/wording choice from one registry of
assumptions, evidence, prerequisites, and formal obligations.

The codebase otherwise has at least five places that can drift: SDK behavior,
store behavior, frontend labels, tests, and the public whitepaper. A shared
manifest plus generated projections is smaller than keeping those prose and
code paths mutually synchronized by review. Formal results remain scoped
evidence and production differential replay closes the model/implementation
gap; neither a proof artifact nor a TypeScript interface is allowed to become
unqualified truth by itself.

[OwlC](https://www.usenix.org/conference/usenixsecurity25/presentation/singh)
sets a substantially stronger implementation frontier for cryptographic
protocols by compiling verified high-level designs to verified,
interoperable, performant libraries.
[Sift](https://www.usenix.org/conference/atc22/presentation/ma) similarly
demonstrates refinement-guided proofs extending to executable distributed
implementations. They preempt novelty in executable/proof refinement and set
the bar above this proposal's initial differential-replay scaffold. The
candidate contribution here is the narrower cross-layer claim/evidence SSOT
for a bearer-neutral rendezvous system; a serious formal paper should adopt or
match an established refinement methodology rather than treating FPO registry
entries as proofs.

The initial validator scaffold deliberately stops before encoding or protocol
exports. That boundary keeps SSOT from becoming premature wire law.

### 7.10 ADR-010: source privacy and PQ authentication are explicit packages

**Decision:** Keep the v0.4 target-blind core deployable with one ordinary
server, make stronger public-store source privacy an optional fail-closed
measured SP1 package, and put PQ authentication in a disjoint successor
version.

Target privacy, source-network anonymity, and signature security are different
properties. Combining them behind one “private” or “quantum secure” switch
would hide failures and make the simple single-server baseline depend on an
unselected anonymity system or unfinished PQ signature stack. SP1 therefore
names one exact mechanism/population/adversary/trace bound and sends nothing
when it cannot meet the floor. The successor allocates fresh invitation,
policy, context, and authentication suites, so v0.4 KEM healing cannot be
mistaken for PQ identity authentication.

### 7.11 Candidate novelty and claim boundary

No cited primitive is new here. Append-only sets, AEAD, per-author logs,
sparse rings, client multi-homing, DTN carriers, pair ratchets, ML-KEM, OMR,
PIR, anonymous credentials, and fixed cover all have substantial prior art.

In a provisional search completed **2026-07-27** across the cited local shelf
and primary sources covering private
presence/signaling, OMR/PIR, anonymous broadcast, malicious replicated logs,
browser swarms, censorship circumvention, DTN/mesh implementations, pair/group
ratchets, and post-compromise security, neither a reviewed paper nor a
documented implementation was found that combines all nine properties below.
The current workspace does not yet contain the dated query/inclusion ledger
required to make that negative search independently reproducible. The release
artifact in Section 6.3 must record it and rerun the search through the stated
cutoff. Until then this is provisional corpus-bounded evidence, not a universal
priority or “first” claim.

The potentially publishable systems contribution is the particular
composition:

1. a malicious-rendezvous interface with no protocol-level room,
   identity/membership, social-edge, or pair target, plus an explicitly
   measured rather than assumed traffic-analysis boundary;
2. a one-server S1 minimum and client-additive R2-BEC temporal path graph,
   without server consensus, whose logical state is one capability-sealed
   authenticated operation set;
3. one correctness core spanning fixed-scan L2 target privacy and actual
   store-carry-forward/non-IP L3 operation;
4. strict room separation plus bounded sparse pair safety independent of
   divergent local planner views, while the operation core converges under
   eventual delivery;
5. frontend-owned whitelist/blacklist/authority admission before pair-private
   SDP, including a sole-server/denied-member confidentiality result; and
6. crash-safe hybrid-PQ pair healing over duplicate/reorder-prone online and
   offline carriers without a stable mailbox tag;
7. room-blind signed custody promises and profile-wide checkpoint fault proofs
   that improve malicious-store accountability without introducing server
   consensus or a room-visible log;
8. one executable deterministic kernel and evidence-compiled claim/wording
   registry spanning protocol code, conformance, frontend labels, and
   whitepaper projections; and
9. an optional fail-closed, quantitatively measured source-privacy floor that
   composes with the targetless store without pretending that relay use alone
   defeats a global or entry observer.

Reusing the existing v4 healing machine and outbox is a DRY engineering
advantage, not itself a novelty claim. The candidate mechanism is the exact
causal wrapping/quiescence/retention composition needed to preserve that
machine across eventual carriers.

At specification stage this is an architecture hypothesis, not a research
result. A credible paper needs:

- a formal ideal functionality/security games for store target privacy,
  pair disclosure, malicious operations, admission, and convergence;
- a working one-server/browser implementation;
- real additive-store partitions and recovery;
- a hardware-in-loop non-IP adapter and, for shutdown-survival wording, a
  field-tested blackout/contact evaluation;
- v4/PQ crash and compromise experiments;
- public-checkpoint/custody-fault and production-scheduler refinement
  evaluation;
- preregistered metadata classifiers;
- SP1 mechanism/domain-corruption experiments for any advertised source bound;
- bandwidth, CPU, storage, latency, energy, and cohort-scaling results;
- comparison to broadcast, OMR, PIR/anytrust, and plaintext federation
  baselines; and
- external cryptographic and systems review.

Until those exist, language such as “first,” “novel protocol,” “state of the
art,” “censorship resistant,” “post-quantum healed,” and “Internet-shutdown
surviving” shall be qualified as proposed, candidate, measured, or
property-specific.

### 7.12 Contribution level and publication fit

The honest assessment at specification stage is:

| Dimension                    | Current level                                      | What raises it                                                                                                                                                                                                                                          |
| ---------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| New cryptographic primitive  | None                                               | Not an objective; reuse reviewed primitives.                                                                                                                                                                                                            |
| Protocol-mechanism novelty   | Moderate candidate                                 | Formalize the non-circular admission/pair/PQ composition, accountable-custody/checkpoint boundary, exact scheduler refinement, and scoped games.                                                                                                        |
| Architecture/systems novelty | Moderate-to-strong candidate                       | Demonstrate malicious-store metadata minimization, S1/additive R2-BEC without consensus, one operation SSOT across online/non-IP carriers, and evidence-compiled cross-layer claims. BEC, Merkle logs, and claim registries individually are prior art. |
| Empirical contribution       | Not yet present                                    | Browser/server implementation, real bearer, adversarial faults, privacy classifiers, and resource/censorship measurements.                                                                                                                              |
| Eventual paper contribution  | Potentially strong systems-and-privacy composition | All release evidence, closest-baseline comparisons, external review, and reproducibility.                                                                                                                                                               |

The audited v4/PQ/session code materially improves feasibility and artifact
reuse, but static source presence is not empirical evidence for blind
rendezvous, additive carriers, sparse rooms, or L3 convergence. It lowers
implementation risk; it does not raise the current contribution tier by
itself.

One strong eventual venue fit is
[PoPETs/PETS](https://petsymposium.org/), the journal whose accepted work is
presented at PETS, because the central result is a privacy system with explicit
threat games and deployable evaluation. It is not uniquely strongest:
USENIX Security, IEEE S&P, ACM CCS, and NDSS have published the closest OMR,
rendezvous, private-discovery, and PQ-ratchet comparators and are peer top-tier
choices. The final emphasis should select the venue: privacy analysis for
PoPETs, measured systems/security for USENIX Security or NDSS, and a stronger
cryptographic/formal protocol result for IEEE S&P or ACM CCS.
[IEEE Transactions on
Privacy](https://www.computer.org/digital-library/journals/pr/cfp-general-submissions)
is a direct
journal fit for a mature privacy/security treatment.
[ACM Transactions on Privacy and
Security](https://dl.acm.org/journal/tops) fits a formal plus implemented
security contribution. [IEEE Transactions on Dependable and Secure
Computing](https://www.computer.org/digital-library/journals/tq/cfp-dependable-secure-computing)
becomes plausible if the
eventual-consistency, rollback, disruption-tolerance, and fault evaluation are
the dominant contribution. [IEEE Transactions on
Networking](https://www.comsoc.org/publications/journals/ieee-tnet) is a better
fit if bearer-neutral transport, scheduling, scalability, and recovery become
the main measured result. At proposal-only maturity, a focused workshop such
as HotPETS or FOCI is more credible than a journal submission; this document
alone is not an evaluated research result.

## 8. Dependencies & External Integrations

### 8.1 Required components

- **Repository ownership:** `p2party-js` owns the invitation codec, canonical
  operation/pair/carrier core, SDK projections, persistence, authenticated
  peer-contact bridging, and adapters;
  `p2party.com` owns `/r` extraction/routing, creation/join/share/QR UX,
  frontend peer/carrier policy, assurance display, and legal copy;
  `p2party-server` owns the versioned public-store HTTP surface, allocation,
  immutable chunks/checkpoints, custody receipts, retention, standalone and
  peer-cohosted deployment artifacts, and privacy-safe operations. A
  field or default has one normative owner and is imported by hash across the
  other repositories.
- **Canonical client core:** room-access resolution, operation codec,
  carrier envelope, validation pipeline, core reducer/local projection,
  connection planner, admission, pair ledger, persistence, and assurance
  derivation, plus the executable-kernel/claim projections, checkpoint proof
  verifier, accountability custody, and global SP1 route/exposure gate.
- **Reference public store:** one deployable store-only build/profile
  implementing fixed opaque
  append, anonymous fixed allocation, deterministic chunk finalization/padding,
  immutable public chunks, one signed checkpoint per window, retained-segment
  continuity from pinned heads, bounded retention, admission/rate limits,
  signatures, and privacy-safe
  observability. It has no legacy socket handler,
  Upgrade route, socket peer registry/pubsub lifecycle, TURN/signaling secret,
  WSS-only proxy setting, or Upgrade health probe. A deployment may co-host a
  separately disclosed legacy sidecar/path, but “one server” correctness never
  depends on it.
- **Delivery-profile distribution:** content-addressed immutable profile bytes
  shipped with the client or obtained from a public integrity-checked registry.
  Fetching a profile is independent of room activity.
- **Frontend policy store:** current address book, blacklist, immutable room
  policy, optional authority keys/grants, store trust, route permissions, and
  disclosure acceptance.
- **Protocol-v4 session core:** current 3DH+ML-KEM handshake, CPace option,
  Double Ratchet, atomic edge persistence, PQ-healing machine, exact frame
  codecs, and scheduled-cover status.
- **Fast online adapters:** reference HTTP public-store adapter and optional
  WebRTC final-transport adapter.
- **Optional source-privacy adapter:** an SP1 build includes one
  registry-pinned, measured multi-domain mechanism for every public-store
  request class. The direct HTTP adapter remains available only when the
  global floor is disabled; it is never an SP1 fallback.
- **L3 adapters:** canonical portable-bundle implementation and at least one
  hardware-in-loop non-IP contact integration, plus a
  deterministic byte harness. A practical shutdown-survival claim additionally
  depends on one deployed field-tested path and its current REQ-015 evidence.
- **Sparse room data plane:** a separately versioned component satisfying
  REQ-021/AC-043 before production-default whole-room messaging. It consumes
  promoted edges and room/member projections; it does not alter the
  rendezvous operation codec or reducer.

### 8.2 Cryptographic dependencies

Cryptographic ownership is layered and unambiguous:

- `RoomPolicyV4.roomCryptoSuite` pins the room hash/HKDF, Ed25519
  operation/identity/authority transcripts, validation, and canonical domains;
- `RoomPolicyV4.pairBootstrapSuite` pins the complete hybrid KEM, HPKE-PSK,
  post-bootstrap pair AEAD, nonce/tag lengths, encodings, and vectors;
- the nested `RoomPolicyV1` session-policy codec remains the SSOT for the existing
  protocol-v4 ML-KEM suite, CPace mode, Double Ratchet, healing, and cover;
- each `DeliveryProfileV1.carrierAeadSuite=1` pins exactly the
  XChaCha20-Poly1305/HKDF-SHA-256 key, nonce, tag, AAD, and `Open`/`Seal`
  construction in Section 4.5, while the profile alone owns public-store
  quota/admission, schedule/geometry, and optional retrieval accelerators;
- `admissionScheme=1` pins RFC 9578 public Blind-RSA tokens and RFC 9474
  RSABSSA only for anonymous allocation entitlement. Its classical security
  affects quota availability, not room/pair confidentiality or the scoped
  post-quantum session claim;
- the public-accountability registry pins SHA-256 with RFC 9162's exact
  domain-separated Merkle Tree Hash and audit-path algorithm; it does not
  invent another tree construction; and
- the existing stable-identity X25519 cross-signature construction and vectors
  are reused exactly for protocol-v4 3DH; rendezvous does not define a second
  identity-key binding.

FIPS 203 ML-KEM is the standardized KEM family relevant to fresh PQ secret
contribution. FIPS 204 ML-DSA and FIPS 205 SLH-DSA are standardized
authentication-successor candidates, not v0.4 dependencies or assigned suite
IDs. A signature choice does not replace the KEM contribution needed for
post-compromise healing. Selection requires the separate successor review,
browser performance/resource results, canonical-key and signature encodings,
hybrid composition, complete coverage matrix, and migration analysis in
Section 4.15.

As of this specification's cutoff, browser WebCrypto has no native ML-DSA
`CryptoKey`. A JS/Wasm implementation may wrap a PQ secret at rest under a
non-extractable browser key, but the origin runtime still receives the PQ
secret while signing; that is not equivalent to a native non-extractable
ML-DSA key. No browser PQ-authentication claim activates until the selected
implementation has independent review plus browser measurements for
side-channel exposure, memory/CPU limits, key lifecycle/erasure, suspension,
and hostile-origin compromise boundaries. Platform passkeys or hardware keys
remain classical unless their exact advertised algorithm is independently
PQ-authenticated.

Every pinned item requires its exact reviewed specification snapshot,
deterministic vectors, browser-capable implementation where applicable, and
explicit work-in-progress status. No delivery profile can alter a canonical
room operation, pair bootstrap, identity transcript, or protocol-v4 state.

Keys are non-extractable where the platform permits. Protected durable state
uses the existing atomic wrapped-edge pattern and equivalent atomic room/outbox
records. Secret copies are bounded, zeroized, and never placed in Redux, logs,
exceptions, crash reports, service-worker caches, or network-visible URL
components. The explicit shareable location fragment is the sole intended URL
copy; it is never copied into paths, queries, headers, or analytics.

### 8.3 Platform dependencies

- A cryptographically secure random source and WebCrypto-compatible hash/AEAD
  support, plus the pinned p2party cryptographic WASM.
- IndexedDB or another transactional durable store for atomic crash
  consistency. A platform monotonic/non-rollback anchor is additionally
  required for pre-contact or room/frontend rollback detection; otherwise only
  older authenticated existing-edge transcript/counter rejection by an
  uncompromised peer with newer edge state is claimed.
- A monotonic timer for local deadlines and a coarse wall clock for public
  windows. L3 tolerates bounded skew and does not require continuous NTP.
- `AbortSignal`-style cancellation at every adapter boundary.
- Streaming bounded parsers for chunks and portable bundles.
- Browser lifecycle signals so cover and availability claims degrade on
  suspension.
- Explicit user permission for local devices/files/radio and for every route
  family that exposes additional metadata.

### 8.4 Operational dependencies

- At least one configured compatible store or later physical contact for
  first rendezvous.
- Store storage sufficient for the advertised retention and immutable chunks.
- A measured shared client population before
  `cohortScope: "measured-shared"` is displayed.
- Pre-positioned alternative stores/routes/carriers before the path they use
  is censored.
- Independent distribution for private route material if endpoint-enumeration
  resistance is claimed.
- TURN/STUN and WebRTC only when that final transport is selected; neither is a
  rendezvous-core dependency.
- Physical custody, power, device availability, and enough contacts for an L3
  blackout claim.

No optional external system may become an undeclared source of room truth.
CDNs, OHTTP relays/gateways, anonymity networks, DTN bundle agents, OMR
detectors, and peer caches are carriers/accelerators behind the same
validation boundary.

## 9. Examples & Edge Cases

### 9.1 Today's invitation, new rendezvous

Alice runs:

```ts
const invite = p2party.generateRoomInvite();
history.replaceState(null, "", `/r#${invite}`);
const room = await p2party.joinRoom(invite);
```

The visible/shareable URL is
`https://p2party.com/r#v2.<43-character capability>`. Alice's
frontend resolves `DEFAULT_BLIND_POLICY_V4_0`, its local delivery profile, and
default store adapter. It writes fixed cohort objects; it never sends the
capability or normalized 64-hex form.

Bob pastes the complete URL; the frontend extracts its fragment and runs the
same `joinRoom(fragment)` flow. His default
store overlaps Alice's, so their capability-sealed presence operations
converge. The store sees two sources participating in a public cohort, not a
room token or SDP target.

### 9.2 Adding a server without changing the link

Alice explicitly adds a signed compatible self-hosted store through the
frontend. Her client:

1. validates and persists the descriptor and route permission;
2. scans its public profile windows;
3. independently wraps and backfills retained operations;
4. publishes a leased encrypted hint through all current stores; and
5. continues using both stores proactively.

Bob's policy already names the exact signed `StoreId` and current `RouteId`, so
he activates it and backfills.
Carol's policy does not, so she retains it as inactive. All three remain in the
same room and keep the same stable sessions. If the default server later
blocks, Alice and Bob can continue through the added store; Carol cannot until
another authorized path delivers the operations/hint.

Refreshing a room hint around the same signed route does not change its
`RouteId`. A descriptor or route-record rotation does; Bob must receive a new
local authorization/preauthorization for that exact signed route before it can
activate. No remote room operation silently broadens this boundary.

If no unrelated room uses the new store, Alice and Bob see
`cohortScope: "room-unique"` for it.

### 9.3 Two rooms share one cohort

Alice participates in rooms A and B. Bob holds A; Carol holds B. All scan the
same public chunks. Alice's fixed `roomSlotsPerClient` schedule has one real
presence substitution for each room and dummies in unused slots.

Bob opens only A operations; Carol opens only B operations. Bob and Carol never
become candidates or neighbors. The store cannot test which envelope belongs
to A or B without a capability. Compromising Bob reveals room A's room-level
state but not Alice/Carol pair ciphertext in room B.

### 9.4 Denied capability holder and sole malicious server

Mallory copied the room capability and controls the only store. Alice has
blacklisted Mallory's stable key; Bob's room is address-book-only and does not
contain it.

Mallory can submit bounded valid room-level presence and observe every opaque
store object. Her forged strict-presence proof fails before Alice or Bob sends
an identity hello. Her honest own identity/permit fails `Admit()` before they
generate `TRANSPORT_OFFER`. Alice and Bob's SDP exchange is pair double-sealed
under a root Mallory lacks. Complete access to the store database does not help
decrypt it.

If Mallory creates an unrelated new identity, Alice's exact-key denylist alone
does not recognize the human. Bob's address-book-only rule still rejects it.
An authority-grant room would also require a grant that Mallory lacks.

### 9.5 Six-member sparse room

With six converged presences and local `sparseRadius=1`, sorted ranks form a
six-cycle.
Each member has two canonical stable neighbors, not five. With
`sparseRadius=2`,
each has four. Fixed pair-attempt slots establish missing mutual neighbors over
successive windows.

An unrelated seventh client in the same delivery cohort is not in the graph.
A late valid room member changes desired neighbors at the next reconciliation
boundary but does not rekey healthy existing stable edges. Graceful retirement
restores the degree cap.

### 9.6 Divergent stores merge

During a partition, store S1 receives Alice's presence and S2 receives Bob's.
Carol can reach both. Carol validates both operations, unions them, and
backfills independently rewrapped copies. Alice and Bob later scan one
bridged store and converge.

No store declares the roster complete. If Carol never appears and the stores
never reconnect through a client/contact before expiry, the two components
remain honestly `partitioned`.

### 9.7 Wrong PIN or admission grant

A capability holder with the wrong PIN can reach pre-SDP identity admission if
the frontend otherwise allows it, but the protocol-v4 CPace transcript fails
before stable transport promotion. Pair-encrypted SDP may already have been
exchanged: PIN is session authentication, not pre-SDP privacy. It cannot cause
a classical fallback.

In an authority-grant room, a wrong-room, expired, future, malformed, revoked,
or wrong-key grant fails earlier at pre-SDP admission and releases no SDP.

### 9.8 Internet shutdown with portable custody

Alice and Bob already have the application, room invite, delivery profile, and
portable carrier. All IP APIs are disabled.

Alice exports a bounded bundle containing her presence. A courier/removable
medium delivers it to Bob; Bob imports, adds his presence and identity
response, and exports the next bundle. Repeated exchanges drive causal pair
steps and the operation-backed protocol-v4 handshake. The human latency may be
hours; the state machine remains the same.

A release satisfying REQ-015, AC-024/025, and the Section 10.4 field-evidence
gate may claim shutdown-surviving rendezvous/control and completion of one v4
PQ-healing cycle (`pqState="healed-after-fresh-entropy"`) under v0.4's
classical-authentication assumptions for this exact measured bearer/custody
scope. This example alone demonstrates only the intended state-machine path.
Room messages or files through the blackout are claimed only when the
separately versioned data plane passes the non-IP branch of AC-043 on that
path.

If the contacts cease beyond retention, liveness expires. If the physical
carrier is searched, its observer sees a padded p2party bundle and physical
custody/contact metadata; room and pair payloads remain encrypted.

### 9.9 PQ healing through duplicates and delay

Alice closes the application gate, completes `QUIESCE_PROPOSE`/`QUIESCE_ACK`,
and emits an exact v4 `OFFER`. Her adapter puts independent carrier envelopes
on two stores and a portable bundle. Bob sees
three rewrapped copies, derives one private operation/frame identity, accepts
the exact expected slot once, and persists `ADVANCE` before publishing.

Alice receives duplicates and a stale malformed object. Unauthenticated
objects drop; the exact valid `ADVANCE` transitions once. ACK uses the new root
and remains durable through Bob's `HEAL_COMPLETE`. A different authenticated
frame in the same v4 slot fails only Alice/Bob's edge.

### 9.10 Store route is malicious

A room member advertises a signed-looking route for `127.0.0.1`, a cloud
metadata address, `file:`, and a redirect to an ambient-credential origin.
The descriptor signature is invalid or the parsed route violates local policy.
It remains inactive. No resolver, fetch, redirect, credential provider, file,
or radio permission is touched.

### 9.11 Cold start and browser suspension

A new tab starts only after an invite is opened. It may perform correct
on-demand public scan, but it reports the cold-start/access-pattern boundary
rather than pretending it was pre-warmed cover. If the browser freezes during
fixed cadence, it marks cover suspended and resumes at a future public
boundary; it never sends a catch-up burst labelled L2.

### 9.12 Signed promise, wrong finalized slot

The sole store returns signed `stored` for Alice's opaque fixed object. Its
later signed checkpoint includes a valid chunk at the deterministic slot, but
the slot contains different opaque bytes. Alice combines the request, receipt,
checkpoint, chunk, and RFC 9162 path into one
`PublicCustodyBreachProofV1`. The frontend excludes that store/profile from
positive custody/R2 evidence and keeps the room state obtained from all valid
operations unchanged. If the store had simply remained silent, Alice could
report only unavailable/unknown.

### 9.13 SP1 fails closed

The frontend's global floor selects an SP1 profile. One mixing domain is
unreachable and the measured evidence can no longer meet the declared
`t+1`-domain bound. Token issuance, append, checkpoint, and read events become
durably missed/unavailable; none goes directly to the store. If a buggy
adapter nevertheless exposes one direct request, the pre-dispatch ledger
taints that context/interval and a later conforming retry cannot relabel the
interval source-private.

### 9.14 PQ successor is a new room

Alice's v0.4 room completes ordinary ML-KEM healing, then receives a purported
v3 migration object. V0.4 rejects it because healing did not change Ed25519
authentication. After a separately conforming successor exists, Alice may
create a fresh capability and successor room and re-publish application state.
Bob's identity carries over only with one accepted continuity basis; otherwise
the frontend asks him to verify a new unlinked identity.

### 9.15 Peer bridge and peer-hosted store are distinct

Alice and Carol are members of one room but cannot reach the default store.
Each has an already authenticated local-radio contact with Bob. Bob exchanges
the contact adapter's bounded inventories and store-carry-forward objects with
both sides. Alice and Carol can therefore discover each other's retained
presence, pass admission, and exchange their pair-private transport and v4/PQ
operations through Bob. Bob helps perform signaling carriage but never declares
the roster, chooses their edge, or opens their inner SDP/ICE. If Bob's contacts
end before required operations cross them, the path is exhausted and pending
work remains `partitioned`; his prior presence is not a durability promise.

Separately, Bob may start the exact public-store process on his device. Its
signed `StoreDescriptorV1` and routes are added and authorized exactly like any
other store, after which retained operations are rewrapped/backfilled and a
bounded `STORE_HINT` may propagate. The shared invitation and room remain
unchanged. Bob's store process is targetless and room-blind at its protocol
boundary, but Bob's co-located endpoint may already know room facts as a
capability holder; the system does not claim anonymity against that coalition.
The hosted store counts toward custody or scoped R2-BEC only if it passes the
ordinary store and independence evidence. Starting two processes on Bob's
device does not create two operators or blocking domains.

If Carol has not preauthorized Bob's exact signed store and route, the hint
remains inactive and causes no network access. If she has no reachable store,
authenticated contact, portable exchange, or other pre-positioned path, the
room invitation alone cannot discover Bob's device.

## 10. Validation Criteria

### 10.1 Correctness invariants

- Canonical encoding has one byte string per value and rejects unknown input.
- Room identity is independent of delivery profile, concrete store/route, and
  local planner state.
- Every accepted logical mutation names one authenticated operation.
- Merge and `CoreReduce` are permutation/duplication independent; local
  projection differences are explicit frontend facts.
- Bounded future custody cannot affect core, admission, presence, catalog, or
  planning before its explicit logical window.
- No server output is authoritative absence, roster finality, or conflict
  selection.
- Store addition/removal cannot rekey or split a room.
- Multiple routes to one public carrier context replay one exact
  wrap/allocation/request and cannot multiply logical work.
- Pair identity depends on exact endpoint presences; stable session identity
  depends on exact stable keys.
- Sparse degree and fixed attempt budgets hold under malicious inputs.
- Every v4 mutation retains clone → authenticate/mutate → CAS-persist → adopt
  ordering.
- Every kernel-owned implementation transition refines the same canonical
  module trace; the R2 simulator uses the production scheduler semantics.
- Every public window has one fixed complete checkpoint commitment, while
  checkpoint/custody evidence never selects or mutates logical room state.
- Claim satisfaction is monotone downward under evidence removal, expiry,
  contradiction, saturation, or refinement failure.

### 10.2 Confidentiality and admission invariants

- No capability, room/equality tag, stable identity/equality tag, membership,
  co-membership/social edge, admission fact, or pair target enters the public
  store boundary.
- No pair-sensitive payload is only room-encrypted.
- No endpoint creates SDP/ICE before bilateral stable-identity admission.
- In strict mode, no initiator identity hello targets an unproved presence.
- A sole store plus denied capability holder cannot decrypt another pair's
  SDP/ICE.
- Blacklist/address-book/authority decisions are frontend facts and are
  rechecked on every path.
- Deny-state lookup failure never becomes allow.
- Store/route hints never become ambient network authority.
- Raw v4 control headers never become store objects.
- Checkpoint, receipt, breach, conflict, source-exposure, and route-mechanism
  records contain no room-derived, identity-derived, or pair-derived field.
- V0.4 successor/downgrade input reaches neither persistence nor disclosure.

### 10.3 Privacy and performance gates

- Public trace shape matches the configured size/cadence model.
- Every bucket finalizes at the exact capacity/chunk geometry; late and
  overflow behavior cannot add traffic.
- Scheme-1 issuance/allocation, null-admission cover, and route scheduling use
  their frozen fixed shapes and disclose only their stated degraded state.
- The target/co-membership classifiers meet preregistered thresholds.
- Room-count/size/join-leave/social-edge inference claims are made only for
  the exact prewarmed cohort/source-metadata dataset that passed them.
- Minimum measured cohort and cold-start/suspension states gate labels.
- The reference one-server store meets declared throughput/retention/resource
  budgets for bounded cohorts.
- Client full-scan bandwidth, CPU, battery, memory, trial decryption, and
  latency are published for realistic mobile/browser populations.
- An OMR/PIR accelerator cannot graduate without equivalent active-integrity,
  correctness-equivalence, and browser/server resource evidence.
- Checkpoint cadence/size is fixed even for all-dummy windows; signed promise,
  inclusion, breach, conflict, withholding, and saturation behavior passes
  AC-049.
- An SP1 build passes the exact measured `1/k + epsilon` experiment and
  fail-closed direct-network tripwires; otherwise the source-privacy field is
  disabled/unknown and no stronger wording is available.

### 10.4 Censorship and L3 gates

- Independent-path claims are supported by measured blocking domains, not
  counts.
- Local path diversity is never promoted to scoped R2-BEC; the one exact
  participant/frontier temporal graph must pass `R2Conforms` under every
  allowed fault subset.
- Store hint distribution and activation pass SSRF/credential/source-metadata
  review.
- Authenticated peer bridges count only as the contact/custody paths actually
  exercised; peer-hosted public stores pass the identical store protocol and
  evidence gates, and co-located roles never manufacture path or operator
  independence.
- Network-disabled portable and non-IP E2E tests pass through v4 and one PQ
  cycle.
- At least one hardware-in-loop non-IP adapter, not only an injected byte
  harness, supports `non-IP-control-compatible`; only a deployed,
  field-tested custody path with the complete REQ-015/AC-025 measurement set
  supports practical shutdown-survival wording.
- Contact loss/partition durations and retention exhaustions are measured.
- UI wording names physical custody, power, route distribution, and
  observation limits.
- A production-default sparse room passes the separate whole-room data-plane
  gate; control-only or direct-neighbor behavior is labelled honestly.

### 10.5 Review gate

Before stable labels, an external review shall resolve:

1. frozen invitation/policy resolution and migration;
2. target-privacy, capacity/finalization, and pair-disclosure games;
3. exact carrier/pair key schedules, non-circular bootstrap, and nonce
   construction;
4. capability-holder/malicious-store composition, room/social-graph metadata
   games, and strict presence proofs;
5. author, store-chunk, and pair fork semantics;
6. frontend admission, decision leases, and authority grant/revoke freshness;
7. v4 slot-secret extraction/erasure, quiescence, expiry, and rollback
   behavior;
8. asynchronous core convergence/retention claims;
9. cover schedule and classifier methodology;
10. non-IP adapter metadata and resource bounds; and
11. binary/HTTP/default/allocation registry completeness, cross-repository
    API migration, and deployed legal/telemetry consistency;
12. sparse room data-plane isolation from the rendezvous SSOT; and
13. executable-kernel/claim generation, formal scope, production refinement,
    and counterexample publication;
14. checkpoint/custody proof privacy, fork/gap semantics, evidence caps, and
    their non-consensus boundary;
15. SP1 mechanism/domain independence, active tagging/global-observer
    nonclaims, prewarm/exposure atomicity, and no-fallback enforcement;
16. PQ-successor hybrid coverage, fresh-context migration, continuity and
    downgrade semantics;
17. peer-bridge/public-store role separation, bootstrap, co-location,
    room-isolation, pair-confidentiality, and assurance accounting; and
18. whether any claimed research contribution is already preempted by work
    published after the literature cutoff.

## 11. Delivery Roadmap

All phases through Phase 6 are mandatory for v0.4 control-plane conformance.
AC-043 and its separately versioned data plane are additionally mandatory
before p2party makes sparse blind rooms the production default or claims
unchanged whole-room messaging. The ordering is an implementation sequence,
not permission to ship an “L3-compatible” label before the L3 tests pass.

### Phase 0 — Freeze games, codecs, and model

- Freeze invitation compatibility, the complete release registry, canonical
  binary schema, HTTP protocol, default room/profile/planner/per-room/global
  resource bytes,
  scheme-1 Privacy Pass allocation mapping, store/routes/compatibility hash,
  executable-kernel manifest, claim/wording registry, formal-obligation
  registry and FPO-001..006 model/refinement boundaries,
  accountability and source-privacy registries,
  operation and carrier codecs, `DEFAULT_BLIND_POLICY_V4_0`, domains, exact
  cohort capacity/finalization, size classes, retention,
  dependency/resource bounds, and assurance semantics.
- Freeze the three formerly implicit nested boundaries explicitly:
  `PairStepEnvelopeV1` derives its exact three ciphertext/plaintext targets
  from the canonical schema and operation-class table; `STORE_HINT` uses
  sequence encoding plus derived-`RouteId` ordering and deterministic
  logical-window/Unix lease coverage; and admission freezes grants/revokes,
  opaque bootstrap/stable subjects, one trusted current-state
  snapshot, derived authority view/state digest, decisions, and bootstrap/
  stable leases together with their sole constructors and negative vectors.
- Split timeless store authenticity from explicit-time route activation in
  every implementation and vector. No core reducer reads an ambient clock, no
  admission caller supplies an availability boolean, and no duplicated target
  length or route bound becomes a second SSOT.
- Write target/room/social-graph privacy, denied-peer SDP, malicious-operation,
  scoped R2-BEC convergence/censorship, and PQ-delivery games.
- Build a deterministic multi-client/multi-carrier model with arbitrary
  reorder, duplicate, omission, partition, clock skew, and restart.
- Generate every schema/kernel/claim projection and reject any hand-maintained
  mismatch before downstream implementation starts.
- Obtain focused external review of the construction before production
  cryptography.

**Gate:** AC-042, canonical vectors, and model/property suite pass; no
unresolved high-severity construction finding. No interoperable implementation
branch proceeds under invented placeholder bytes.

### Phase 1 — One-server operation core

- Implement canonical operation, envelope, protected outbox, validation,
  union, core reducer/local projection, retention, author fork, fixed-capacity
  chunk/checkpoint, custody proof verification, and per-carrier assurance
  modules.
- Implement one deployable public-store process with fixed append/chunk API,
  immutable content, signed custody results/checkpoint chain, admission,
  signatures, retention, and safe metrics.
- Add socket-free blind SDK/frontend and store-only server entrypoints; isolate
  addressed WebSocket signaling behind the optional legacy build/module.
- Wire one default store through an injected adapter.
- Preserve the current `generateRoomInvite()`/frontend fragment extraction/
  `/r`/QR/share/`joinRoom()` call flow, add both version-safe v2 forms while
  keeping all v1 forms legacy, derive the local room ID, and reject raw
  capability use at the store boundary.

**Gate:** AC-001's codec/error/local-initialization branches, AC-004's
store-boundary schema/integration branch, the build/start/no-Upgrade portions
of AC-045, and operation set/fault properties pass with one store-only server.
The full multi-peer AC-002 through AC-004 E2E gate is deferred until pair
admission/topology/v4 exist in Phases 2–3.

### Phase 2 — Room presence and frontend admission

- Add capability-sealed presence/leave, stable commitments, local address-book
  and blacklist integration, strict presence signatures/permits, optional
  authority grants/revocations, bootstrap admission leases, and one shared
  `EvaluatePeerAdmissionPolicy` implementation consumed by bootstrap
  `Admit()`.
- Add pair double sealing and the exact non-circular two-flight pre-SDP
  identity gate.
- Migrate pre-auth state away from server UUIDs to room/presence/pair derived
  identifiers.
- Fuzz every policy and storage-failure boundary.

**Gate:** single-server denied-peer SDP confidentiality, identity substitution,
grant, and the bootstrap/pre-SDP branch of current frontend-parity tests pass.

### Phase 3 — Sparse topology and transport handoff

- Implement the `explicit`/`sparse-ring`/bounded-small-full-mesh local planner,
  fixed attempt/trial slots, mutual eligibility, hard degree cap, late join,
  and graceful retirement.
- Wrap the cloneable projection semantics behind genuine captured
  ownership/resource/planner custody, and implement the distinct opaque
  pair-scoped HELLO-time historical projection without mutating current
  room/UI state.
- Carry complete pair-encrypted WebRTC offer/answer through the operation log.
- Generalize transport bindings and adapt the existing `HandshakeTransport`.
- Run the fresh existing v4 handshake and promote only byte-matched identities
  and transport bindings.
- Construct and durably reload the verified stable-edge context; route every
  post-promotion sensitive action through `ReauthorizeStableEdge()` and the
  shared policy kernel, with the phase-correct stable lease.
- Expose observed members, desired/provisional edges, promoted data peers,
  `LocalPeerId`, and their distinct wait semantics.
- In the companion data-plane workstream, implement and test REQ-021 without
  changing this control operation codec.
- Run browser WebRTC E2E with the WebSocket constructor tripwire and no Upgrade
  endpoint.

**Gate:** topology model, browser WebRTC E2E, no-roster-binding, v4 byte/
erasure tests, the post-promotion branch of AC-007, and full AC-002 through
AC-004 pass for control-plane conformance. AC-043 also passes before
the product default or whole-room UX is switched.

### Phase 4 — Additive stores and censorship paths

- Implement signed store/route descriptors, local allow/deny, safe hint
  catalog, compatibility, leases, proactive multi-homing, and backfill.
- Package the same reference public-store process for standalone operation and
  endpoint co-hosting; do not add peer-specific storage, signaling, discovery,
  operation, or reducer semantics.
- Implement client bridging across divergent stores and signed chunk
  equivocation evidence, local checkpoint/conflict verification, explicit
  room-independent diagnostic export, bounded custody breach/tombstone
  handling, and R2 accountability evidence.
- Add at least two independently operated test deployments and reviewed route
  families/OHTTP where selected.
- Run blocking-domain and metadata observer experiments.

**Gate:** automatic addition, no-SSRF, partition merge, room-unique disclosure,
and local path-diversity tests pass; the exact participant/frontier-scoped
R2-BEC conformance record passes `R2Conforms` under its registered
censor-action model. AC-049 passes, and asymmetric carrier-policy clients
never produce a scoped result. The public-store and co-location branches of
AC-052 pass the identical black-box suite.

### Phase 5 — Normative L3 and eventual PQ control

- Implement canonical portable-bundle streaming import/export.
- Implement one hardware-in-loop non-IP contact adapter;
  retain the injected harness for deterministic conformance tests, and exercise
  the same registered contact boundary as an authenticated peer bridge. Field
  test one deployed custody path before enabling shutdown-survival wording.
- Add operation-backed handshake transport, causal pair ledger, v4 PQ slot
  delivery wrapper, durable republish, quiescence barrier, and rollback
  protection.
- Run network-disabled presence → admission → v4 → PQ E2E with crash/loss/
  duplicate/reorder schedules.
- Complete the full online/offline WebSocket-removal composition in AC-045.

**Gate:** AC-024 through AC-028 and the operation-carrier/non-IP branches of
AC-029 pass without any IP API, and AC-045 passes end to end. AC-029's
WebRTC/DTLS branch remains a Phase 3 browser gate. These gates permit
`non-IP-control-compatible`; only current deployed field evidence under
REQ-015/AC-025 permits shutdown-survival wording for rendezvous/control within
its stated physical boundary. Application shutdown messaging still requires
the AC-043 branch. The authenticated-contact, partition,
pair-confidentiality, and bootstrap branches of AC-052 also pass.

### Phase 6 — Privacy, scale, and release review

- Measure full-scan cohort bounds, mobile/browser overhead, cold start,
  suspension, traffic classifiers, store scale, and sparse-room latency.
- Compare broadcast, plaintext signaling, anytrust/PIR, and available OMR
  accelerators.
- Complete independent cryptographic, systems, frontend-policy, censorship,
  and non-IP reviews.
- Reproduce FPO results, replay every production implementation against the
  executable kernel, and compile all deployed/UI/publication claims through
  the release-pinned claim registry.
- If this build advertises SP1, ship and measure its selected mechanism and
  pass AC-050; otherwise freeze the global floor as disabled and emit no SP1
  wording.
- Reconcile deployed SDK/frontend/server persistence and telemetry with
  privacy policy, TOS, blocked-peer UI, assurance, and marketing under AC-044.
- Ship experimental opt-in, publish artifacts, then graduate labels only when
  their exact evidence remains current.
- Generate and publish the Section 6.3 web whitepaper, research/implementation
  ledger, manifest, claim/evidence registry, and downloadable artifacts from
  their SSOT.

**Gate:** every acceptance criterion applicable to the advertised release and
every Section 10 gate passes; a production-default p2party release also passes
AC-043. Documentation and UI disclose all residuals.

### Post-v0.4 strengthening roadmap

This is a non-normative research and implementation backlog for after the
initial control-plane release. It is deliberately not another release
specification: priority may change with measurements, and an item earns no
claim until its own reviewed design and evidence exist.

#### First hardening wave

| Priority | Candidate work                                                                 | What it would strengthen                                                                                                                                                                   | Boundary retained                                                                                                                                           |
| -------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1        | Complete the sparse application-data plane over the existing carrier boundary  | On a path that already earned shutdown-surviving control, extends that result to room messages, attachments, receipts, retries, and recovery.                                              | Reuses the operation, admission, carrier, pair-session, and assurance SSOTs; it does not turn the rendezvous log into an application queue.                 |
| 2        | Expand field-tested BLE/Wi-Fi Direct coverage, then add LoRa/BPv7 where useful | Earns the first field-scoped shutdown result if absent, or extends existing measured coverage with more range, latency, loss, energy, MTU, custody, restart, and blocking-domain evidence. | No bearer is called shutdown-resilient outside its measured physical and custody envelope; jamming, seizure, absent power, and absent custodians remain.    |
| 3        | Add optional external rollback anchors                                         | Detects whole-device snapshot restoration of identity, admission, ratchet/PQ, source-volume, and assurance high-water state.                                                               | Uses a hardware counter, paired witness, or privacy-safe remote anchor; operation without one remains supported but keeps the rollback nonclaim.            |
| 4        | Add privacy-safe checkpoint witnesses and gossip                               | Makes signed store split views meet systematically and turns observed equivocation into portable room-blind conflict evidence sooner.                                                      | Witnesses see only public profile checkpoints. Silence, an isolated branch, global completeness, and consensus are still not proved.                        |
| 5        | Strengthen executable refinement and reproducible assurance                    | Reduces model/implementation, build, evaluator, frontend-label, and whitepaper drift using independent implementations, reproducible builds, and richer replay.                            | OwlC/Sift-class refinement is the research bar; this reduces supply-chain risk but does not protect a compromised browser, OS, compiler, or signing quorum. |

#### Optional privacy, censorship, and scale packages

| Priority | Candidate work                                                               | What it would strengthen                                                                                                                                                             | Research basis and boundary                                                                                                                                                                             |
| -------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 6        | Deploy one production SP1 mix route                                          | Adds fail-closed, quantitatively bounded public-store source unlinkability under one exact observer, topology, operator, traffic, fragmentation, and cumulative-volume model.        | Start from a reviewed Loopix/Echomix/Katzenpost-class mechanism and the MixMatch, Shift Your Shape, fragmentation, last-hop, and cumulative-volume findings already cited here.                         |
| 7        | Add private, rate-limited route-distribution credentials                     | Makes bridge enumeration and targeted route blocking harder while avoiding a stable room or peer handle at the distributor.                                                          | A Lox-like issuer/distributor design still needs explicit issuer trust, abuse budgets, blocking measurements, and source-network privacy; possessing two routes is not anonymity.                       |
| 8        | Add optional room-blind work-gated allocation-token issuance                 | Raises the marginal cost of mass anonymous allocations and unsolicited store writes without creating accounts or changing room authorization.                                        | Reuse the existing Blind-RSA issuance/redemption SSOT. This is Sybil-costing only—not personhood, blacklist enforcement, server independence, BFT, or fairness—and mobile/non-IP costs remain explicit. |
| 9        | Add a reviewed single-server OMR retrieval accelerator                       | Reduces full-cohort client bandwidth while retaining the immutable targetless log and complete authenticated scan as the correctness/audit fallback.                                 | PerfOMR, UnifOMR, SophOMR, and InstantOMR are direct baselines. The accelerator must not create a stable room/detection key visible to the store or become the only completeness path.                  |
| 10       | Add paired PIR/Myco-like retrieval islands only where operators justify them | Offers a stronger access-pattern/performance trade-off for deployments willing to assume distinct non-colluding roles.                                                               | This is an optional accelerator, never a requirement for one-server correctness or automatic arbitrary-store addition.                                                                                  |
| 11       | Add anonymous eligibility and admission credentials                          | Can hide the first identity flight from unauthorized capability holders and make replacement-key re-entry subject to unlinkable issuer policy before SDP.                            | Signal private groups, PriSrv+, and matchmaking-encryption systems set the comparison bar. Issuer compromise, revocation latency, Sybil/personhood, and PQ credential maturity stay explicit.           |
| 12       | Research source privacy stronger than SP1                                    | Could address entry-observer and multi-epoch intersection risk through access-network diversity, multi-entry mixing, long-horizon cover, and formally bounded path/session rotation. | This remains research until one model covers the global observations it claims; more relays, fixed cascades, or a classifier that failed to link flows are not sufficient evidence.                     |

For priority 8, a successor store-descriptor revision signs either one
canonical per-profile `AbuseAdmissionPolicyV1` or its exact hash; difficulty is
never in an invitation or `RoomPolicy`. A noninteractive work preimage is
bound to a domain, `StoreId`, delivery-profile hash, target ingress window,
policy hash, the exact blinded RFC 9578 `TokenRequest` digest, and a
nonce—never a capability, room context/slot, stable key, commitment, presence,
grant, target, or source account. Verification occurs only at the one fixed
token-issuance slot. A successful issuance returns the existing Blind-RSA
token, whose later redemption remains cryptographically unlinkable from
issuance under the registered assumptions; the successful issuance request
hash/replay row remains the sole idempotency SSOT.

The descriptor prepublishes signed bounded difficulty, while
`ClientGlobalResourcePolicyV1` supplies an upper local acceptance ceiling and
maximum work budget. A
store demanding more work becomes inactive/unavailable instead of consuming
unbounded CPU, battery, or radio time. A malicious store can waive, raise, or
selectively reject work and network timing/source may still link issuance and
redemption; neither event upgrades availability, fairness, anonymity, store
independence, or BFT evidence. Exact puzzle/encoding/difficulty and fixed-shape
vectors require a reviewed successor delivery-profile revision before any
implementation or claim.

#### Successor-version candidates

| Priority | Candidate work                                                                         | What it would strengthen                                                                                                                                    | Why it needs a new version                                                                                                                                                                  |
| -------- | -------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 13       | Ship granular hybrid-PQ identity/operation/session coverage and continuous PQ ratchet  | Adds hybrid-PQ authentication for the explicitly covered identities, operations, authorities, stores, checkpoints, contact sessions, and migration objects. | Requires the fresh invitation/context and Section 4.15 matrix; the umbrella rendezvous claim remains unavailable while allocation or another relied-on category is classical.               |
| 14       | Add single-use/expiring invitations and explicit room-capability replacement           | Limits future entry after an invitation leak and supports deliberate migration into a fresh room context with selectively reauthorized peers.               | A leaked holder cannot be made to forget old room data or keys. Safe recovery therefore creates a fresh context rather than mutating the meaning of a v2 capability.                        |
| 15       | Add PQ anonymous credentials and PQ-private allocation when mature                     | Removes remaining classical authentication/linkability boundaries in anonymous admission, route distribution, and quota issuance.                           | Only after every relied-on matrix category is hybrid-covered may the successor publish the umbrella `PQ-authenticated rendezvous` wording; primitive maturity remains separately reviewed.  |
| 16       | Consider explicit quorum finality only if a future product truly requires it           | Could provide a closed-roster notion of committed membership, revocation, or proof of absence that R2-BEC intentionally does not offer.                     | It would require explicit membership, `n`, `f`, quorum intersection, synchrony, recovery, and metadata costs; the KISS default remains authenticated union without consensus.               |
| 17       | Consider MLS or another group data plane only if sparse pair sessions fail             | May improve large-room group-key and application-data efficiency.                                                                                           | It replaces—not layers beside—the pair data-plane SSOT under a new reviewed migration; MLS delivery metadata alone does not solve blind rendezvous.                                         |
| 18       | Add pair-private in-place authority-grant refresh if measured interruptions justify it | Avoids a fresh automatic pair attempt when a stable edge's finite authority grant rotates, while retaining current frontend/revocation checks.              | Requires a new established pair step with exact PQ-slot derivation, replay/causal ordering, expiry, generation replacement, and atomic persistence; v1 instead fails closed and reattempts. |

The recommended order is: finish whole-room data delivery and field-tested
non-IP evidence; add rollback and checkpoint monitoring; deploy SP1 only if
its measured cost is acceptable; then select retrieval/credential packages
from observed bottlenecks. Granular hybrid-PQ authentication remains the first
planned semantic successor; umbrella rendezvous wording waits for complete
hybrid coverage. Consensus, a new group ratchet, and stronger-than-SP1
anonymity are research choices, not automatic milestones. In-place grant
refresh is added only if measurements show that automatic fresh pair attempts
materially interrupt authority-mode rooms; it is not allowed to become a
second admission-policy implementation.

Across every item, adapters may add carriage, measurement, monitoring, or
acceleration but may not fork room operations, deterministic reduction,
frontend admission, pair-session state, or compiled claim semantics. New
security semantics require a new version. No roadmap item makes unconditional
promises against a global observer, every path being jammed, total device/power
loss, malicious admitted endpoints, a compromised authority/platform, or
Sybil/personhood without an external trust source.

## 12. Related Specifications / Further Reading

### Local p2party sources

- [Server-blind rendezvous and federated discovery: prior art](../docs/rendezvous-prior-art.md)
- [Paper prior art and related work](../docs/paper-prior-art-and-related-work.md)
- [Protocol-v4 security boundary](../docs/protocol-v4-security.md)
- [Protocol-v4 sparse PQ healing and scheduled cover](../docs/protocol-v4-pq-cover-architecture.md)
- [Store-free session API](../docs/session-api.md)
- [Design decisions and security findings](../docs/design-decisions-and-security-findings.md)

### Private presence, signaling, and access

- [DP5: A Private Presence Service](https://petsymposium.org/popets/2015/popets-2015-0008.pdf)
- [Private Signaling](https://eprint.iacr.org/2021/853)
- [Private Signaling Secure Against Actively Corrupted Servers](https://eprint.iacr.org/2025/1056)
- [Sabot: Efficient and Strongly Anonymous Bootstrapping of Communication Channels](https://doi.org/10.1145/3719027.3744803)
- [UDM: Private user discovery with minimal information disclosure](https://doi.org/10.1080/01611194.2021.1911876)
- [Pudding: Private User Discovery in Anonymity Networks](https://martin.kleppmann.com/2024/05/20/pudding-private-user-discovery.html)
- [Alpenhorn: Bootstrapping Secure Communication without Leaking Metadata](https://www.usenix.org/conference/osdi16/technical-sessions/presentation/lazar)
- [Tor v3 onion-service rendezvous protocol](https://spec.torproject.org/rend-spec/protocol-overview.html)
- [Talek](https://eprint.iacr.org/2020/066)
- [2PPS](https://arxiv.org/abs/2108.08624)
- [Myco](https://eprint.iacr.org/2025/687)
- [Group Oblivious Message Retrieval](https://eprint.iacr.org/2023/534)
- [PerfOMR](https://www.usenix.org/conference/usenixsecurity24/presentation/liu-zeyu)
- [HomeRun](https://eprint.iacr.org/2024/188)
- [UnifOMR](https://eprint.iacr.org/2026/910)
- [SophOMR](https://www.usenix.org/conference/usenixsecurity26/presentation/lee-keewoo)
- [InstantOMR](https://www.usenix.org/conference/usenixsecurity26/presentation/liang)
- [PingPong: Metadata-private Messaging without Coordination](https://doi.org/10.1109/TON.2026.3672821)
- [Pepper](https://arxiv.org/abs/2606.04411)
- [Kerblam](https://eprint.iacr.org/2025/997)
- [Pung](https://www.usenix.org/conference/osdi16/technical-sessions/presentation/angel)
- [SecureDrop Protocol](https://securedrop.org/news/introducing-securedrop-protocol/)
- [Strong Anonymity for Mesh Messaging](https://arxiv.org/abs/2207.04145)
- [Signal Private Group System](https://eprint.iacr.org/2019/1416)
- [PriSrv](https://www.ndss-symposium.org/ndss-paper/prisrv-privacy-enhanced-and-highly-usable-service-discovery-in-wireless-communications/)
- [PriSrv+](https://www.ndss-symposium.org/ndss-paper/prisrv-privacy-and-usability-enhanced-wireless-service-discovery-with-fast-and-expressive-matchmaking-encryption/)
- [Open Relay Protocol whitepaper](https://www.openrelayprotocol.com/docs/whitepaper/)
- [webwormhole](https://github.com/saljam/webwormhole)
- [Analyzing the WebRTC Ecosystem and Breaking Authentication in DTLS-SRTP](https://www.usenix.org/conference/usenixsecurity26/presentation/bach)

### Eventual and disruption-tolerant delivery

- [Delay-Tolerant Networking Architecture — RFC 4838](https://datatracker.ietf.org/doc/html/rfc4838)
- [Bundle Protocol Version 7 — RFC 9171](https://www.rfc-editor.org/rfc/rfc9171.html)
- [Bundle Protocol Security — RFC 9172](https://www.rfc-editor.org/rfc/rfc9172.html)
- [Secure Scuttlebutt](https://conferences.sigcomm.org/acm-icn/2019/proceedings/icn19-19.pdf)
- [2P-BFT-Log](https://arxiv.org/abs/2307.08381)
- [SUNDR](https://www.usenix.org/conference/osdi-04/secure-untrusted-data-repository-sundr)
- [Depot](https://www.usenix.org/conference/osdi10/depot-cloud-storage-minimal-trust)
- [Certificate Transparency Version 2.0 — RFC 9162](https://www.rfc-editor.org/rfc/rfc9162)
- [Briar: How it works](https://briarproject.org/how-it-works/)
- [Briar Mailbox](https://briarproject.org/download-briar-mailbox/)
- [Meshtastic store-and-forward](https://meshtastic.org/docs/configuration/module/store-and-forward-module/)
- [Meshtastic security model](https://meshtastic.org/docs/overview/encryption/)
- [Reticulum: Understanding Reticulum](https://reticulum.network/manual/understanding.html)
- [Bitchat protocol whitepaper](https://github.com/permissionlesstech/bitchat/blob/main/WHITEPAPER.md)
- [WebRTC Swarms](https://www.mdpi.com/1999-5903/18/1/13)
- [MIRAGE](https://www.ndss-symposium.org/ndss-paper/mirage-private-mobility-based-routing-for-censorship-evasion/)
- [Dolphin](https://petsymposium.org/popets/2023/popets-2023-0034.php)

### Censorship resistance and route privacy

- [Snowflake](https://www.usenix.org/conference/usenixsecurity24/presentation/bocovich)
- [Raceboat](https://petsymposium.org/popets/2024/popets-2024-0027.php)
- [Lox](https://petsymposium.org/popets/2023/popets-2023-0029.php)
- [CenPush](https://petsymposium.org/popets/2025/popets-2025-0153.pdf)
- [Oblivious HTTP — RFC 9458](https://www.rfc-editor.org/rfc/rfc9458)
- [The Loopix Anonymity System](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/piotrowska)
- [Echomix](https://arxiv.org/abs/2501.02933)
- [Mixnets on a Tightrope](https://doi.org/10.1109/SP61157.2025.00233)
- [MixMatch: Flow Matching for Mixnet Traffic](https://petsymposium.org/popets/2024/popets-2024-0050.pdf)
- [Shift Your Shape: Correlating and Defending Mixnet Flows](https://www.research.ed.ac.uk/en/publications/shift-your-shape-correlating-and-defending-mixnet-flows-based-on-/)
- [When Mixnets Fail](https://www.ndss-symposium.org/ndss-paper/when-mixnets-fail-evaluating-quantifying-and-mitigating-the-impact-of-adversarial-nodes-in-mix-networks/)
- [Breaking and (Partially) Fixing Onion Routing with Fragmentation](https://petsymposium.org/popets/2026/popets-2026-0120.pdf)
- [Are Continuous Stop-and-Go Mixnets Provably Secure?](https://petsymposium.org/popets/2024/popets-2024-0136.php)
- [The Last Hop Attack](https://petsymposium.org/popets/2025/popets-2025-0067.pdf)
- [Karaoke: Distributed Private Messaging Immune to Passive Traffic Analysis](https://www.usenix.org/conference/osdi18/presentation/lazar)
- [Groove: Flexible Metadata-Private Messaging](https://www.usenix.org/conference/osdi22/presentation/barman)
- [Privacy Pass Architecture — RFC 9576](https://www.rfc-editor.org/rfc/rfc9576)
- [Privacy Pass HTTP Authentication Scheme — RFC 9577](https://www.rfc-editor.org/rfc/rfc9577)
- [Privacy Pass Issuance Protocols — RFC 9578](https://www.rfc-editor.org/rfc/rfc9578)
- [RSA Blind Signatures — RFC 9474](https://www.rfc-editor.org/rfc/rfc9474)
- [Anonymous Rate-Limited Credentials Cryptography — Internet-Draft](https://datatracker.ietf.org/doc/draft-ietf-privacypass-arc-crypto/)
- [The Sybil Attack — Douceur](https://www.microsoft.com/en-us/research/publication/the-sybil-attack/)
- [Pricing via Processing or Combatting Junk Mail — Dwork and Naor](https://www.wisdom.weizmann.ac.il/~naor/PAPERS/pvp.pdf)
- [Waku RLN Relay: Economic Spam Protection for P2P Messaging](https://arxiv.org/abs/2207.00117)

### Pair/group cryptography and wire obfuscation

- [Hybrid Public Key Encryption — RFC 9180](https://www.rfc-editor.org/rfc/rfc9180)
- [Concrete Hybrid KEMs — draft-irtf-cfrg-concrete-hybrid-kems-04](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-concrete-hybrid-kems-04)
- [Post-Quantum KEMs for HPKE — draft-ietf-hpke-pq-05](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-05)
- [XChaCha — expired draft-irtf-cfrg-xchacha-03 snapshot](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03)
- [CPace, a balanced composable PAKE — draft-irtf-cfrg-cpace-21](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-cpace-21)
- [Edwards-Curve Digital Signature Algorithm — RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)
- [Elliptic Curves for Security / X25519 — RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)
- [Connection-Oriented Media Transport over TLS / SDP fingerprints — RFC 8122](https://www.rfc-editor.org/rfc/rfc8122)
- [ML-KEM — FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
- [ML-DSA — FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
- [SLH-DSA — FIPS 205](https://csrc.nist.gov/pubs/fips/205/final)
- [Post-Quantum Cryptography for Engineers — RFC 9958](https://www.rfc-editor.org/rfc/rfc9958.html)
- [Signal Sparse Post-Quantum Ratchet and Triple Ratchet](https://signal.org/docs/specifications/doubleratchet/)
- [Signal SPQR rollout](https://signal.org/blog/spqr/)
- [Signal ML-KEM Braid](https://signal.org/docs/specifications/mlkembraid/)
- [Formal analysis of Apple PQ3](https://www.usenix.org/conference/usenixsecurity25/presentation/linker)
- [Formal verification of Signal PQXDH](https://www.usenix.org/conference/usenixsecurity24/presentation/bhargavan)
- [ML-KEM and Hybrid Cipher Suites for MLS — Internet-Draft](https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites/)
- [Messaging Layer Security — RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html)
- [MLS Architecture — RFC 9750](https://www.rfc-editor.org/rfc/rfc9750.html)
- [Asynchronous Ratcheting Trees](https://eprint.iacr.org/2017/666)
- [Obfuscated Key Exchange / Kemeleon](https://eprint.iacr.org/2024/1086)
- [Elligator](https://eprint.iacr.org/2013/325)

### Executable specifications and refinement

- [OwlC: Compiling Security Protocols to Verified, Secure, High-Performance Libraries](https://www.usenix.org/conference/usenixsecurity25/presentation/singh)
- [Sift: Using Refinement-guided Automation to Verify Complex Distributed Systems](https://www.usenix.org/conference/atc22/presentation/ma)
- [Rule-Based Static Analysis of Network Protocol Implementations](https://www.usenix.org/legacy/event/sec06/tech/full_papers/udrea/udrea_html/)
- [Model Checking Large Network Protocol Implementations](https://www.usenix.org/events/nsdi0/tech/full_papers/musuvathi/musuvathi_html/main.html)
