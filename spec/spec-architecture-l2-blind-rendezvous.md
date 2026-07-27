---
title: L2 Server-Blind N-Party Rendezvous Architecture
version: 0.2-proposed
date_created: 2026-07-24
last_updated: 2026-07-27
owner: p2party maintainers
tags:
  - architecture
  - privacy
  - rendezvous
  - webrtc
  - pir
  - dpf
---

# Introduction

This specification defines the roadmap and security boundary for a true L2
server-blind rendezvous layer for p2party rooms. The target is a control plane
that privately assembles an `n`-peer WebRTC full mesh without directly
disclosing the room capability, stable peer identities, room roster, room
graph, or raw SDP/ICE signaling to any one rendezvous replica. Residual
source-IP and timing inference is treated separately and must be measured, not
silently folded into the cryptographic claim.

This is a proposed architecture, not a shipped property. The current runtime
uses `legacy-signaling`; `opaque-token` and `blind-meeting-point` are reserved
policy values that the public `connect()` path rejects. As observed on
2026-07-24, the public p2party.com deployment still used the older room-path
bundle, so even the branch's fragment invite integration was not yet a
production L2 property.

Version 0.2 adds four things that 0.1 either forbade or did not consider, and
each is a deliberate change rather than a clarification. A **single-replica
L1.5 tier** now exists, so the architecture can run on one operator while
naming precisely the property it therefore lacks; SEC-001 is unchanged as the
bar for the L2a *label*. **Replica endpoints may be embedded in the invite**,
so self-hosted and federated rooms work without a registry, at the stated cost
that a room-unique replica set is itself a fingerprint and drops the room one
tier. **Board groups** separate private-write sharing from replication, which
0.1 conflated: under 0.1 every replica was a single point of failure, so an
architecture built for censorship resistance could be disabled by taking one
server offline. **Censorship resistance** itself becomes an explicit,
separately labelled property under SEC-019 and Phase 9, on the principle that
an adversary who cannot read the board can still stop anyone from reaching it,
and that this is a transport problem the cryptography does not address.
Phase 0 also gains two measured figures — signaling record sizes and the
import-cycle count — alongside derived budgets for DPF cost and delta-stream
bandwidth, each tagged with its provenance so the two are not read as one.

## 1. Purpose & Scope

### 1.1 Purpose

The implementation shall replace explicit room registration, roster lookup,
and addressed SDP/ICE forwarding with private writes and private reads over an
anytrust replica set. Once two peers discover each other and establish a
WebRTC edge, application payloads remain peer-to-peer.

### 1.2 Scope

This specification covers:

- fragment-only room invitations, optionally carrying the room's replica
  endpoints so a room can name self-hosted boards without a registry;
- an authenticated, versioned room policy;
- an epoch-based private presence board;
- a single-replica L1.5 tier that runs the same wire protocol on one operator
  and states plainly which property it does not provide;
- board groups: private-write sharing *within* a group and replication
  *across* groups, so replica failure or blocking is survivable;
- censorship resistance of the control plane — multi-route board access,
  probing resistance, and enumeration resistance — as a property measured and
  labelled separately from graph blindness;
- private pairwise signaling inboxes;
- deterministic WebRTC offerer selection;
- `n - 1` independently authenticated sessions per room member;
- access-pattern cover required by the L2 control plane;
- collision, replay, expiry, equivocation, abuse, and replica-failure handling;
- an explicit distinction between protocol-level graph blindness and
  network-level unlinkability;
- evaluation and release gates.

### 1.3 Non-goals

- Hiding a peer's network address from another peer in a direct WebRTC
  connection.
- Hiding the roster from a compromised room member.
- Claiming privacy if every rendezvous replica colludes.
- Treating an opaque or OPRF-derived common room token as L2.
- Routing application content through the rendezvous service.
- Inventing a new DPF, PIR, PAKE, KEM, or ratchet primitive.
- Backward compatibility or silent fallback to legacy signaling.
- Claiming that immediate/no-cover data-plane rooms hide message timing.

## 2. Definitions

| Term                  | Definition                                                                                                                                                                                                                                                                                      |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| AEAD                  | Authenticated Encryption with Associated Data.                                                                                                                                                                                                                                                  |
| Anytrust              | A distributed trust model in which privacy holds if at least one participating replica is honest and does not collude.                                                                                                                                                                          |
| DPF                   | Distributed Point Function; clients split a private point operation into shares sent to separate replicas.                                                                                                                                                                                      |
| IT-PIR                | Information-Theoretic Private Information Retrieval; a client reads an index without any one non-colluding replica learning that index.                                                                                                                                                         |
| L1                    | An opaque-address mode that may hide the room input but still exposes a common co-membership handle. L1 is not server-blind.                                                                                                                                                                    |
| L1.5                  | A blind board that does not qualify for L2a — either because some group has one replica, or because the replica set is room-unique. Records, epochs, and schedule are the L2a ones; what varies is which of L2a's properties are actually delivered, which the deployment must state. Intended to be stronger than L1 (no persistent common handle) and weaker than L2a (no write privacy where a group has one replica); the ordering against L1 is an argument, not a measured result — see AC-003. |
| L2a                   | Protocol-level target and identifier privacy: under the declared anytrust and cohort-schedule model, one replica cannot derive the room, stable peers, roster, or edges from private-query application data. Source-IP and timing inference remain separately visible unless L2b controls them. |
| L2b                   | L2a plus network unlinkability against source-IP, timing, ingress, and co-operated TURN correlation.                                                                                                                                                                                            |
| Presence board        | A short-lived fixed-capacity data structure used for private room-member discovery.                                                                                                                                                                                                             |
| Rendezvous capability | A uniformly random 256-bit room secret distributed out of band in the URL fragment.                                                                                                                                                                                                             |
| Replica               | One independently operated server participating in private writes and reads.                                                                                                                                                                                                                    |
| Room policy           | The canonical, transcript-authenticated configuration shared by every peer in a room.                                                                                                                                                                                                           |
| Signaling inbox       | A short-lived private directional log carrying encrypted fixed-size SDP/ICE fragments.                                                                                                                                                                                                          |
| Stable identity       | The long-lived p2party Ed25519 identity and its cross-signed X25519 identity key.                                                                                                                                                                                                               |

## 3. Requirements, Constraints & Guidelines

### 3.1 Current-state and protocol requirements

- **REQ-001**: A blind invitation shall use a URL fragment, for example
  `https://p2party.com/r#v2.<encoded-access>`. The room capability shall never
  appear in the HTTP path, query, `Referer`, analytics event, or server log.
- **REQ-002**: L2 shall be a protocol-version break using a canonical
  `RoomPolicyV2`; backward compatibility is not required.
- **REQ-003**: Selecting `blind-meeting-point` shall fail closed if its complete
  transport is unavailable. It shall never downgrade to `legacy-signaling` or
  `opaque-token`.
- **REQ-004**: One room member shall own one independent cryptographic session
  for each remote member. A room with `n` members therefore gives each member
  `n - 1` sessions.
- **REQ-005**: Session roots, ML-KEM state, ratchet epochs, counters, skipped
  keys, transfer state, and serialized secrets shall never be shared across
  peer edges.
- **REQ-006**: L2 shall leave the data path after it bootstraps or repairs a
  WebRTC edge. Messages and files shall continue to use pairwise WebRTC data
  channels and the p2party message crypto.
- **REQ-007**: The human PIN shall remain a separate CPace authentication input.
  A PIN shall not derive a public-board address or AEAD key because that would
  provide an offline PIN-verification oracle.
- **REQ-008**: L2 shall replace signaling-issued room/peer UUIDs with local-only
  private context identifiers. `RoomContextId = H(domain || capability ||
canonicalPolicy)` may key local room state; rotating epoch/edge handles may
  key only pre-auth registries, gates, and WebRTC state. None shall be
  serialized onto the rendezvous wire. Durable session ownership shall use the
  verified stable identity under the local room context, not a rotating
  pre-auth handle.
- **REQ-009**: Possession of the 256-bit capability grants presence-discovery
  authority. A room PIN adds peer authentication through CPace; a wrong PIN
  prevents session establishment but does not retroactively hide presence from
  another capability holder. In the specified post-DTLS CPace ordering, that
  holder can also learn exchanged SDP/ICE, peer network endpoints, and the
  stable identity carried in HELLO before PIN confirmation fails.
- **REQ-010**: A public profile shall bound maximum room membership, presence
  and signaling operations per epoch, and signaling fragments per edge. Each
  client emits the same number of real-or-dummy lanes regardless of actual room
  size or signaling demand.

### 3.2 Privacy and security requirements

- **SEC-001**: The production L2a deployment shall use at least two replicas
  controlled by operationally independent entities. Two processes, accounts,
  or regions under one operator do not satisfy this requirement.
- **SEC-001a**: A single-replica deployment shall be permitted, shall use the
  identical records, epochs, profiles, and access schedule as L2a — a
  wire-compatible superset, not an identical protocol, since it adds the
  endpoints of §4.5 that L2a does not use — and shall label itself **L1.5**,
  never L2a. The reason for the split is cost, not impossibility, and the
  specification shall not claim otherwise: single-server private writes do
  exist computationally, in the PIR-writing line (Ostrovsky–Shoup;
  Boneh–Kushilevitz–Ostrovsky–Skeith; Lipmaa–Zhang) and as homomorphic slot
  accumulation under a cohort-held key the replica does not hold. They are
  rejected here on replica-CPU and client-bandwidth grounds, on the same
  evidence that rejects single-server computational PIR — which addresses
  reads, not writes, and is not an escape hatch for this requirement. An L1.5
  client shall satisfy every requirement in this section except SEC-003 and
  SEC-004, for which it substitutes the measures below, and shall in addition:
  - **write to a uniformly random unoccupied slot**, not to a
    capability-derived candidate index. This is the load-bearing rule of the
    tier. A derived index is needed only when reads are position-addressed,
    and at L1.5 they are not — the client already retrieves the whole board.
    Were the derived index kept, every member of one room would write into the
    same small candidate set in plain view of the replica, which would let it
    reconstruct that room's membership within a single epoch: precisely the
    property §1.1 exists to remove, given away for nothing.
  - obtain **read-request unlinkability by construction** — the request
    carries no index — by fetching an epoch snapshot and thereafter the common
    append-only delta stream. It shall not request an individual position, and
    it shall not use tag-prefix bucketing, which spends anonymity linearly per
    poll and exponentially across epochs (Phase 0). Read privacy in the
    stronger sense additionally requires the replica to serve the identical
    committed snapshot and delta to every client; it fails under equivocation
    or selective omission, which is an assumption about replica behaviour and
    not a property of the client. An L1.5 profile shall therefore name a
    concrete SEC-017 instantiation — the delta stream covered by the signed
    epoch commitment, plus an external witness or client gossip — before the
    tier may be labelled at all.
  - accept, in place of SEC-003, that a non-blind write is a write the replica
    can validate: the replica shall enforce one slot per write, reject writes
    to slots already occupied in the epoch, and enforce per-admission-token
    write quotas. Without this a malicious client overwrites the whole board
    for the cost of one write per slot, and honest clients cannot distinguish
    that from the ordinary collision of §9.2.
  - emit the profile's fixed real-or-dummy write lanes, so the observable
    write count does not reveal peer degree;
  - surface the tier to the application as a read-only property, and refuse to
    present any L2a-labelled UI string;
  - state in user-facing documentation, where a group has one replica, that
    the operator observes the source address and the timing of every poll and
    write, and that it learns which source addresses wrote in the same epoch —
    though not, given random slot selection, which of them share a room.
- **SEC-001b**: Moving between tiers shall be an explicit configuration change
  in the invite's replica set. A client shall never silently downgrade from a
  multi-replica room to a single replica because replicas are unreachable;
  that path is an availability error under SEC-010 and §9.4.
- **SEC-002**: No one replica shall receive a room capability, room-derived
  common token, stable peer identity, explicit application-layer
  sender/recipient identifier, roster, raw SDP, raw ICE candidate, or DTLS
  fingerprint. An ordinary L2a replica still receives source network metadata
  unless an L2b ingress layer removes it.
- **SEC-003**: Presence writes shall use a verifiable/robust DPF private-write
  construction, or reviewed equivalent, that prevents one malformed client
  share from corrupting many board positions.
- **SEC-004**: Presence and signaling reads shall use batched IT-PIR with a
  reviewed response-correctness/integrity mechanism, or a reviewed equivalent.
  The design shall state which omissions are fundamentally indistinguishable
  from honest absence.
- **SEC-005**: Requests, responses, board records, and signaling records shall
  have profile-defined fixed lengths. Length overflow shall fail closed or move
  to a separately authenticated larger public class; it shall not emit a
  demand-shaped tail. The L1.5 snapshot and delta responses of §4.5 are the one
  exception, because their size is a function of board-wide activity and not of
  the requesting client's demand: every client fetches byte-identical ranges,
  so the length carries no per-client signal. They shall be padded to
  profile-defined quanta, and the aggregate-activity leakage they do carry —
  how busy the board is, epoch by epoch — shall be documented rather than
  denied.
- **SEC-006**: Every active client in the profile's public anonymity cohort
  shall issue scheduled real-or-dummy operations independently of room
  activity for the declared access window. Entering a particular room shall
  not start, stop, or accelerate that schedule. A real operation substitutes
  for a dummy operation.
- **SEC-007**: Stable identities shall first appear inside fixed-size
  `PAIR_INIT`/`PAIR_ACCEPT` records encrypted under the capability-bound hybrid
  rendezvous root, then be confirmed by the DTLS-protected,
  room-policy-transcript-bound handshake. They shall never appear at the
  replica adapter.
- **SEC-008**: Each epoch shall use rotating presence identifiers, inbox
  handles, encryption keys, and expiry. Epoch material shall be domain
  separated from message-session and room-cover keys.
- **SEC-009**: SDP and ICE shall be encrypted, authenticated, padded, fragmented
  into fixed-size records, replay protected, and bound to the room policy,
  epoch, and pre-WebRTC pair-bootstrap transcript. The resulting pair-bootstrap
  transcript hash shall then be bound into the later post-DTLS p2party channel
  input; signaling cannot depend on a transcript that does not yet exist.
- **SEC-010**: Detectable malformed responses, replays, equivocation, and
  selective failures shall cause rejection or an explicit availability error
  without privacy downgrade. Undetectable omission shall be documented as an
  availability limit and measured; the specification shall not promise that
  every omitted presence record is distinguishable from honest absence.
- **SEC-011**: The implementation shall use an externally reviewed or
  specification-backed DPF/PIR implementation with test vectors. Application
  TypeScript shall not invent a new private-write primitive.
- **SEC-012**: Admission and abuse controls shall not introduce a stable
  application identity. Candidate mechanisms include unlinkable, rate-limited
  anonymous tokens such as Privacy Pass; an OPRF may support admission but
  shall not become the rendezvous address. Selection guidance: keyed-verification
  credentials (ARC, `draft-ietf-privacypass-arc-crypto`) fit the single-replica
  tier because issuer and verifier coincide and one issuance yields N mutually
  unlinkable presentations; publicly verifiable Blind RSA tokens (RFC 9578 type
  0x0002) fit board groups, because a replica must verify a token it did not
  issue without contacting the issuer. Neither token type carries metadata, so
  any room or epoch binding lives in the redemption context, not the token.
- **SEC-012a**: Token issuance may be gated by payment, including
  cryptocurrency, provided the payment channel cannot be linked to token
  redemption. The unlinkability requirement is the whole of the design
  constraint: a blind-signature issuance in the Chaum lineage satisfies it,
  while any scheme where the issuer records a per-purchaser token serial, or
  where an on-chain transaction is observable at redemption time, does not and
  shall not ship. Payment introduces a second observer — the payment rail —
  whose view shall be documented alongside the replica's. A deployment shall
  keep a payment-free issuance path, so that inability to pay is never
  equivalent to inability to establish a private room.
- **SEC-013**: The implementation shall wipe expired epoch secrets and
  decrypted signaling records as soon as the application no longer needs them.
- **SEC-014**: Room policy mismatch, replica-set mismatch, suite mismatch, or
  access-schedule mismatch shall fail before a peer accepts the room edge.
- **SEC-015**: Privacy-visible replica sets, record sizes, board capacities,
  epochs, access cadences, and signaling classes shall come from a small public
  profile registry shared by a measured anonymity cohort. A unique per-room
  profile or endpoint shall not qualify for L2.
- **SEC-016**: Joining or leaving an anonymity cohort shall occur only at
  profile-defined public boundaries independent of a particular room join,
  exit, or repair. Each profile shall set and report a minimum observed cohort
  size below which the client withholds an L2 graph-blindness label.
- **SEC-017**: Signed epoch commitments shall be made fork accountable through
  an append-only witness/transparency service, client gossip, or another
  reviewed consistency mechanism. A replica signature by itself does not
  prevent the replica from signing different views for different clients.
- **SEC-018**: Clients shall prefetch/cache public profiles and replica
  descriptors independently of room activity. A profile fetch triggered only
  by one room join shall not qualify for the L2 label.
- **SEC-019**: Censorship resistance is a distinct property from graph
  blindness and shall be specified, measured, and labelled separately. A
  network adversary who cannot read the board can still prevent it from being
  reached, and an architecture whose privacy story depends on contacting
  several replicas fails closed — correctly — when they are blocked. The
  following are therefore requirements of the transport, not of the
  cryptography:
  - **SEC-019a**: A `ReplicaDescriptorV1` shall be able to name more than one
    way to reach the same board — direct HTTPS, an Oblivious HTTP relay, a
    CDN-fronted origin, or a browser-proxy transport in the manner of
    Snowflake. Reusing Snowflake means depending on an external proxy pool
    whose capacity and health are outside this project (CON-006); a shared
    WebRTC substrate is not by itself an integration argument. Reaching a board
    by a different route shall not change the record bytes or the client's send
    schedule. It may well change the tier, and the requirement shall not
    pretend otherwise: every route inserts its own observer of the client's
    source address and access timing — a relay operator, a fronting CDN, a
    volunteer proxy — or removes one, in the OHTTP case. Each route shall carry
    a documented observer set enumerated under COM-003 and evaluated against
    CON-001 and CON-002. Route choice never raises the effective tier and can
    lower it.
  - **SEC-019b**: Board endpoints shall be resistant to active probing, within
    a boundary this requirement states rather than assumes. A censor that can
    confirm an endpoint speaks this protocol can block it by address, which
    makes every other measure moot. Probing resistance shall rest on a
    per-endpoint out-of-band secret — the room capability, or a per-board key
    distributed with the descriptor — in the manner of an obfs4 bridge
    certificate. It shall not rest on SEC-012 admission tokens, which are by
    design globally issuable and, under SEC-012a, obtainable without payment:
    a censor simply gets one. The private endpoints so gated shall return
    responses to unauthenticated or malformed requests that are
    indistinguishable from those of an unrelated service. The public endpoints
    are explicitly out of scope and shall not be claimed as probing-resistant:
    `GET /v1/profiles/{profileId}` must answer un-tokened callers because
    SEC-018 requires activity-independent prefetch, and
    `GET /v1/epochs/{e}/commitment` must answer witnesses because SEC-017
    requires public auditability. A deployment that needs those hidden must
    place them behind a separate distribution channel and say so.
  - **SEC-019c**: The fixed record sizes and fixed cadence required by SEC-005
    and SEC-006 for anonymity also produce a distinctive traffic shape. Where
    that shape is itself a blocking signature, the profile shall say so. A
    uniform pattern unique to this protocol is good for the anonymity claim and
    bad for the blocking claim, and the specification shall not pretend one
    setting optimises both.
  - **SEC-019d**: Blocking resistance shall not be claimed on the basis of
    replica count alone. Two replicas in one jurisdiction, one CDN, or one
    autonomous system are one blocking target; the profile shall record the
    jurisdictional and network diversity of each board group, and the
    measurement in §6.3 shall report reachability from censored vantage points
    rather than from the maintainers' network.
  - **SEC-019e**: Enumeration resistance is the reason embedded endpoints
    (§4.1) exist alongside registered profiles. A small registry is the easiest
    thing in this architecture to block: a censor need only collect the
    published profile list. Permitting rooms to name self-hosted boards means
    the set of reachable boards is not enumerable from any one document, at the
    cost in cohort anonymity that §4.1 states. Deployments shall choose
    knowingly between the two and shall not describe either as strictly better.

### 3.3 Metadata boundary

- **CON-001**: L2a protects the application-level target and room graph under
  the non-collusion assumption. It does not by itself hide source IP, connection
  timing, or a co-operated TURN service.
- **CON-002**: An L2b claim requires independently operated ingress, board, and
  TURN roles plus a defined trust split, or a suitable mix/onion transport.
  Oblivious HTTP may split ingress from request processing but does not hide a
  shared mailbox and does not survive ingress/processor collusion.
- **CON-003**: Direct WebRTC discloses endpoints to the connected peers by
  design.
- **CON-004**: The product default may remain immediate/no-cover for the
  post-connection data plane. Selecting L2 still incurs the control-plane
  access schedule required to make L2's graph-blindness claim.
- **CON-005**: The room-wide message-cover cadence is a separate authenticated
  policy field. It must not be inferred from the L2 query cadence.
- **CON-006**: Censorship resistance under SEC-019 concerns reachability of the
  rendezvous control plane only. It does not conceal that a user runs p2party
  from an adversary with endpoint access, does not protect the WebRTC data
  plane once peers connect directly, and does not survive an adversary willing
  to block whole transports — CDNs, WebRTC, or UDP — rather than one service.
  Where a deployment's blocking resistance rests on a shared circumvention
  network, its capacity and health are an external dependency, and blocking
  that network blocks p2party with it.

### 3.4 Engineering guidelines

- **GUD-001**: Keep board codecs, query construction, record encryption, and
  transcript verification store-free and runtime-neutral so non-browser
  clients can reuse them.
- **GUD-002**: Run the cryptographic core in reviewed Rust/WASM or another
  auditable portable implementation where practical; keep network adapters
  replaceable.
- **GUD-003**: Make privacy-sensitive fields impossible to log by representing
  them with opaque redacted types at the adapter boundary.
- **GUD-004**: Record quantitative cost separately for client CPU, replica CPU,
  memory, storage, egress, join latency, battery, and dummy traffic.
- **GUD-005**: Measure against a global trial-decryption-board baseline,
  2PPS/Riposte-style DPF private writes plus PIR reads, Talek-like pairwise
  logs, Pung's single-server computational-PIR trust point, distributed PIR
  using client devices, Myco's published efficiency frontier, Signal Private
  Groups and its access-pattern attacks, Alpenhorn's metadata-private dialing,
  and Tor onion-service rendezvous.
- **GUD-006**: Extract WebRTC discovery and signaling behind an injected,
  store-free `RendezvousTransport`. The L2 client shall not call the Redux RTK
  WebSocket API directly, and the legacy adapter shall remain a separate
  implementation.

## 4. Interfaces & Data Contracts

The following contracts define information flow, not final byte layouts. Exact
encodings require a separate reviewed wire-format specification before
implementation.

### 4.1 Room access

```ts
type BlindRoomAccessV2 = {
  version: 2;
  capability: Uint8Array; // exactly 32 uniformly random bytes
  policy: RoomPolicyV2;
};

type BoardRoute = {
  kind: "direct-https" | "ohttp" | "fronted" | "proxy";
  origin: string; // canonical HTTPS origin for this route
};

type ReplicaDescriptorV1 = {
  // Every route reaches the same board with the same record bytes and the
  // same client send schedule, but each carries its own observer set
  // (SEC-019a). The first entry is the direct route.
  routes: readonly BoardRoute[];
  role: "private-board";
  signatureAlgorithm: "Ed25519";
  publicKey: Uint8Array;
  // Diversity metadata required by SEC-019d. These are operator assertions
  // that a client cannot independently verify; they inform the label, they do
  // not prove it.
  operatorId: string;
  jurisdiction: string;
  asn: number;
};

type RoomPolicyV2 = {
  policyVersion: 2;
  wireProtocolVersion: 4;
  revision: 0;
  rendezvousMode: "blind-meeting-point";
  rendezvousProfileId: number;
  rendezvousProfileHash: Uint8Array;
  // Either a reference to a registered replica set, or the set itself for a
  // self-hosted room. The inline form is hashed into the policy commitment
  // exactly as the referenced form is, so both are handshake-authenticated
  // (SEC-014). An inline set is by definition room-unique and therefore
  // carries cohortAnonymity "room-unique" and tier "L1.5" (section 4.1).
  replicaSet:
    | { kind: "registered"; profileId: number; profileHash: Uint8Array }
    | {
        kind: "inline";
        groups: readonly BoardGroupV1[];
        maxColludingReplicasAcrossGroups: number;
        writePrivacy: "none" | "anytrust-per-group";
        cohortAnonymity: "room-unique";
        tier: "L1.5";
      };
  bootstrapKem: "ML-KEM-512" | "ML-KEM-768" | "ML-KEM-1024";
  pinMode: "none" | "cpace-required";
  messageCover:
    | { mode: "immediate" }
    | {
        mode: "scheduled-future";
        cadenceProfileId: number;
        transferClassId: number;
      };
};

type RendezvousProfileV1 = {
  profileVersion: 1;
  profileId: number;
  revision: number;
  epochDurationMs: number;
  accessCadenceMs: number;
  cohortWindowEpochs: number;
  cohortBoundaryEveryEpochs: number;
  cohortWarmupEpochs: number;
  presenceTtlEpochs: number;
  epochOverlap: number;
  maxClockSkewMs: number;
  minAnonymityCohort: number;
  maxRoomMembers: number;
  presenceBucketSlots: number;
  presenceRecordBytes: number;
  signalingRecordBytes: number;
  presenceWriteLanesPerEpoch: number;
  presenceReadLanesPerEpoch: number;
  signalingWriteLanesPerEpoch: number;
  signalingReadLanesPerEpoch: number;
  maxSignalingFragmentsPerEdge: number;
};

type BoardGroupV1 = {
  // Stable opaque identifier, assigned once and surviving replica rotation.
  // Both the candidate-index derivation and the per-group AEAD key/nonce
  // derivation are domain separated by this value (section 4.2), so it must
  // NOT be derived from the replica list — rotating a replica would otherwise
  // relocate every index in the group mid-profile.
  groupId: Uint8Array;
  // Private-write shares are split WITHIN a group: privacy holds while one
  // replica in the group is honest. A group of one provides no write privacy.
  replicas: readonly ReplicaDescriptorV1[];
  requiredWriteShares: number; // === replicas.length in the initial profile
  requiredReadShares: number; // === replicas.length in the initial profile
  maxColludingReplicas: number; // === replicas.length - 1 initially
};

type ReplicaSetProfileV1 = {
  profileVersion: 1;
  profileId: number;
  revision: number;
  // Records are REPLICATED ACROSS groups: any one reachable group is
  // sufficient to assemble a room, which is what makes replica failure and
  // regional blocking survivable. Replication and share-splitting are
  // deliberately on different axes; conflating them makes every replica a
  // single point of failure.
  groups: readonly BoardGroupV1[];
  contactAllReplicasEveryLane: true;
  // A coalition drawing one replica from each of several groups is within
  // every per-group budget while defeating cross-group independence, so it is
  // budgeted separately.
  maxColludingReplicasAcrossGroups: number;
  // Two ORTHOGONAL properties. Collapsing them would force a self-hosted room
  // that genuinely has write privacy to publish the single-replica leak
  // disclosure of SEC-001a, which would be false.
  writePrivacy: "none" | "anytrust-per-group";
  cohortAnonymity: "registered-profile" | "room-unique";
  // Derived, never asserted independently: tier is "L2a" if and only if
  // writePrivacy is "anytrust-per-group" AND cohortAnonymity is
  // "registered-profile"; otherwise "L1.5". A client shall recompute this from
  // the other two fields and the group contents, and shall reject a profile
  // whose stated tier disagrees — a label a client cannot check is a label an
  // operator can inflate.
  tier: "L1.5" | "L2a";
};
```

The encoded access object lives only after `#`. The canonical policy bytes and
replica-set commitment are authenticated by every pairwise handshake.
`encodeRoomPolicyV2` and the two profile encoders shall map every enum to a
fixed numeric identifier, length-prefix variable fields, reject
unknown/duplicate fields, and produce one byte representation per object.
Replica ordering is two-level and shall not be flattened: sort descriptors by
canonical encoded bytes *within* each group, then sort the groups by their
canonical encoded bytes, and length-prefix the group array. A global sort of
descriptors would destroy group membership, which is privacy-load-bearing once
shares are split within a group and indexes are derived per group, and would
let two encoders produce different commitments for the same set — surfacing as
spurious replica-set mismatches under SEC-014 and AC-007. Routes within a
descriptor keep their declared order, the direct route first. The
policy/profile hashes are included in the existing room channel context.
Free-form profile or algorithm strings are not permitted on the wire.

The room policy references the rendezvous profile by registered ID and content
hash. The replica set may either be referenced the same way or, for
self-hosted and federated rooms, embedded directly in the invite as inline
board groups — descriptors carrying a hostname and an Ed25519 key, per the key
requirement below.

Embedding is a deliberate, bounded exception to SEC-015, and it costs
something real: a replica set unique to one room *is itself* a room
fingerprint, which is exactly the common handle this architecture exists to
remove. The rule that keeps both properties honest is therefore:

- a room whose replica set matches a registered profile — one shared by a
  measured anonymity cohort of many rooms — may carry the tier its group
  structure earns;
- a room with a novel replica set is functional, self-hosted, and federated,
  but never earns L2a whatever its group structure, because a board selection
  unique to one room distinguishes that room from every cohort member. It sets
  `cohortAnonymity: "room-unique"`, is labelled L1.5, and shall disclose that
  its replica set is itself an identifying feature.

The two fields are deliberately separate. A self-hosted room with two
independently operated replicas in every group genuinely has write privacy and
sets `writePrivacy: "anytrust-per-group"`; it is L1.5 only because its set is
room-unique. Such a room shall **not** publish the single-replica disclosure of
SEC-001a, which for it would be false, and shall not run the L1.5 snapshot and
delta read path, which it does not need. An honest under-claim on the cohort
axis must never become a false claim on the write-privacy axis; that is the
whole reason the tier enum is not the only thing recorded.

This preserves self-hosting and interoperability, which no registry-only
design can offer, without letting a room-unique endpoint list be presented as
cohort-anonymous.

An embedded descriptor shall carry the board's Ed25519 public key, not only its
hostname. A blind replica does not hold the room capability and therefore
cannot authenticate its responses with anything capability-derived: what binds
a response to a particular board is the signed epoch commitment of SEC-017, and
verifying that signature requires the board's key. Relying on WebPKI alone
would make a mis-issued certificate or a hijacked name sufficient to serve a
forked view, which is the precise failure SEC-017 exists to catch.

Computed encoding budget, from standard QR and GSM-7 capacity tables rather
than from ISO/IEC 18004 or 3GPP TS 23.038 directly, and to be confirmed
against a real encoder in Phase 0: the fragment encodes the whole
`BlindRoomAccessV2`, so the budget shall be taken over the capability, the
`rendezvousProfileHash`, the inline replica set including one 32-byte Ed25519
key per descriptor, and the remaining policy fields — not over the capability
and hostnames alone. Two key-bearing descriptors plus the rendezvous profile
hash land near 300 characters, which is a version-13 QR code at medium error
correction and two concatenated SMS segments. The single-segment SMS property
of the hostname-only sketch does not survive, and the correct response is to
state the real figure rather than to drop the key: an unverifiable epoch
commitment is worth less than a shorter link. Registered profiles carry the
same keys by reference and stay far shorter.

The initial full-anytrust profile contacts every replica of every group on
every scheduled lane, sets both required share counts within a group to that
group's `replicas.length`, and sets that group's `maxColludingReplicas =
replicas.length - 1`. Any threshold construction with different privacy or
availability semantics requires a new reviewed profile.

The initial L2 runtime accepts only `messageCover.mode === "immediate"`.
`scheduled-future` reserves the room-wide authenticated direction but remains
fail-closed until the separate data-plane cover and sparse-PQ integration phase
passes its release gates.

The initial cohort schedule uses fixed public windows. A client enters only at
`cohortBoundaryEveryEpochs`, sends dummy-only lanes for
`cohortWarmupEpochs`, and may then substitute room presence, signaling, and
repair into the fixed lanes until the public window ends. A room join, leave,
late join, or repair never changes the window or lane count. Browser suspension
invalidates the current cover claim; on resume the client waits for the next
permitted boundary/warm-up rather than emitting catch-up traffic. Clients
contact the complete registered replica set even when a replica is unavailable
so availability does not change the observable target pattern.

### 4.2 Presence record

After AEAD encryption and padding, every presence record has the exact length
defined by `rendezvousProfile`.

```ts
type PresencePlaintextV1 = {
  version: 1;
  epoch: bigint;
  policyHash: Uint8Array;
  rotatingPresenceId: Uint8Array;
  bootstrapInboxHandle: Uint8Array;
  expiresAtEpoch: bigint;
  capabilities: number;
  ephemeralX25519PublicKey: Uint8Array;
  ephemeralMlKemEncapsulationKey: Uint8Array;
  offerSelectionNonce: Uint8Array;
  replayNonce: Uint8Array;
};
```

Where writes are private — a group of two or more replicas — the client derives
a fixed candidate set of bucket/subslot indexes from the room capability,
epoch, profile, and the `groupId` of the board group being written to. It
privately writes one candidate and privately reads the entire candidate set.
Candidate selection, collision recovery, and capacity are profile parameters,
not hidden implementation defaults.

Where writes are not private — a group of one replica, the L1.5 case — the
client writes to a uniformly random unoccupied slot instead, and reads the
common snapshot and delta stream (SEC-001a). A derived index earns its keep
only when reads are position-addressed; here they are not, and keeping it would
place every member of one room in the same small candidate set in full view of
the replica, handing it that room's membership within a single epoch.

Random placement has a price the tier must own: with no derived candidate set,
a reader has no way to narrow the search and must trial-decrypt every record it
receives. At the recommended ceiling of 2^16 slots that is an AEAD verification
per slot per epoch — tens of megabytes of authenticated decryption, which is
seconds of work on a weak mobile device and is additional to the snapshot
bandwidth already accounted for in Phase 0. It also rules out the obvious
optimisation: attaching a capability-derived marker to each record so holders
can filter cheaply would hand the replica the very equality handle random
placement just removed, and rotating that marker per epoch does not help,
because records sharing a marker within one epoch still cluster the room. Phase
0 shall measure trial-decryption cost on target hardware and set
`presenceBucketSlots` from the result; if it proves prohibitive, the honest
response is a smaller board with shorter epochs, not a marker.

An L1.5 writer must also learn which slots are free, which it does from the
snapshot it already holds, choosing uniformly among the slots that were free at
its cursor. Two writers can still choose the same slot concurrently; §9.2
covers that case, and the replica's rejection is what makes it detectable
rather than silently destructive.

Per-group derivation is load-bearing wherever derived indexes are used at all.
A record replicated across groups at the same index would give any two groups
that compare notes an immediate equality handle — the same common
co-membership handle this architecture exists to remove, reintroduced through
the availability mechanism. Distinct per-group derivation means a colluding
pair must break the underlying construction rather than compare integers.

Record ciphertexts shall likewise be encrypted per group: the AEAD key and
nonce derivation shall be domain separated by `groupId`, so that two groups
holding the same logical record hold different bytes. Without that, byte
equality alone rebuilds exactly the handle the index derivation just removed.
The write shares sent to different groups shall additionally be generated from
independently sampled randomness, since a shared keygen tape yields correlated
keys across groups and reconstitutes the correlation in a third form.

The bootstrap inbox handle is a receive-only meeting point inside the
capability-encrypted presence record; it is not a pairwise inbox seed. Every
capability holder may learn that handle, consistent with the non-goal of hiding
the roster from a compromised room member. Pairwise directional indexes and
AEAD keys are derived only after the hybrid rendezvous exchange below.

### 4.3 Pre-WebRTC pair bootstrap

For each pair in one epoch:

1. The lexicographically smaller tuple `(epoch, rotatingPresenceId)` is the
   rendezvous initiator. This role, both rotating IDs, the policy hash, and the
   room context are bound into every subsequent transcript.
2. The initiator computes ephemeral X25519 DH with the receiver's published
   rendezvous key and encapsulates to the receiver's published rendezvous
   ML-KEM key.
3. A separately specified and reviewed domain-separated combiner derives a
   short-lived rendezvous root from both secrets, the room capability, epoch,
   policy hash, and ordered rotating IDs.
4. The initiator privately writes a fixed-size `PAIR_INIT` containing the
   ML-KEM ciphertext plus an inner AEAD-encrypted initiator identity bundle and
   SDP offer to the receiver's bootstrap inbox. The identity bundle is the
   Ed25519 public key, dedicated X25519 identity public key, and Ed25519
   cross-signature. Failed inner authentication is indistinguishable from an
   unused/dummy slot.
5. The receiver decapsulates, derives the same root, and both sides derive
   independent directional signaling indexes and AEAD keys. A fixed-size
   `PAIR_ACCEPT` carries the receiver's inner AEAD-encrypted identity bundle and
   SDP answer. Later ICE fragments use only the pairwise indexes.
6. Both identity bundles are provisional pins. Before the existing handshake
   starts, both sides therefore know the two Ed25519 identities required by
   `buildChannelInput` and CPace. The existing HELLO's X25519 identity and
   Ed25519 cross-signature must byte-match and verify against the provisional
   bundle, while interactive 3DH proves X25519 possession. The fixed
   rendezvous-binding hash—policy, epoch, ordered rotating IDs, ML-KEM
   ciphertext, and initial offer/answer commitments—is included in the room
   channel input. Every trickled signaling record is independently bound to
   the rendezvous root, edge context, and replay counter; it is not falsely
   claimed to authenticate a future or complete WebRTC transcript.
7. The rotating-ID role replaces stable-identity ordering for pre-auth
   offer/main-channel initiation. Role, provisional identities, and the
   rendezvous-binding hash are fixed before HELLO and cannot be changed when
   the stable edge is committed.
8. Rendezvous X25519/ML-KEM secrets are destroyed after handoff. The existing
   p2party handshake runs a fresh room-selected ML-KEM exchange for the durable
   ratchet root; rendezvous KEM state is never reused as session KEM state.

The exact combiner and `PAIR_INIT`/`PAIR_ACCEPT` byte formats are Phase-0
cryptographic design outputs and require external review. The sequence above
is an interface constraint, not a claim that a new hybrid construction has
already been proved.

### 4.4 Store-free rendezvous adapter

```ts
type RoomContextId = string; // local-only hash-derived identifier
type LocalEdgeId = string; // local-only pre-auth epoch/peer handle
type StableEdgeId = string; // local-only RoomContextId + verified identity
type EdgeRole = "initiator" | "responder";
type ProvisionalIdentityBundle = {
  ed25519PublicKey: Uint8Array;
  x25519PublicKey: Uint8Array;
  x25519CrossSignature: Uint8Array;
};
type RendezvousEdgeDescriptor = {
  edgeId: LocalEdgeId;
  role: EdgeRole;
  epoch: bigint;
  localRotatingPresenceId: Uint8Array;
  remoteRotatingPresenceId: Uint8Array;
  provisionalPeerIdentity: ProvisionalIdentityBundle;
  rendezvousBindingHash: Uint8Array;
};
type IceCandidateRecord = {
  candidate: string;
  sdpMid?: string | null;
  sdpMLineIndex?: number | null;
  usernameFragment?: string | null;
};

type RendezvousEvent =
  | {
      type: "peer";
      edgeId: LocalEdgeId;
      role: EdgeRole;
      epoch: bigint;
      localRotatingPresenceId: Uint8Array;
      remoteRotatingPresenceId: Uint8Array;
    }
  | { type: "offer"; edgeId: LocalEdgeId; sdp: string }
  | { type: "answer"; edgeId: LocalEdgeId; sdp: string }
  | { type: "ice"; edgeId: LocalEdgeId; candidate: IceCandidateRecord }
  | { type: "edge-ready"; edge: RendezvousEdgeDescriptor }
  | { type: "expired"; edgeId: LocalEdgeId };

interface RendezvousTransport {
  readonly roomContextId: RoomContextId;
  events(signal: AbortSignal): AsyncIterable<RendezvousEvent>;
  sendOffer(edgeId: LocalEdgeId, sdp: string): Promise<void>;
  sendAnswer(edgeId: LocalEdgeId, sdp: string): Promise<void>;
  sendIce(edgeId: LocalEdgeId, candidate: IceCandidateRecord): Promise<void>;
  completeEdge(edgeId: LocalEdgeId, stableEdgeId: StableEdgeId): Promise<void>;
  abortEdge(edgeId: LocalEdgeId, reason: string): Promise<void>;
  close(): Promise<void>;
}
```

`handleConnectToPeer`, SDP description handling, ICE handling, and reconnect
logic shall depend on this interface rather than importing the Redux/WebSocket
API. WebRTC registries, negotiation locks, ratchet gates, handshake inboxes,
and pre-auth transfer queues shall migrate from server UUIDs to
`RoomContextId` plus `LocalEdgeId`. After HELLO verifies the remote identity,
durable ratchet ownership shall re-key to local `StableEdgeId`; transient
epoch handles shall never own durable session state. The legacy signaling
adapter remains a separate implementation and is never a fallback from the L2
adapter.

### 4.5 Replica API

```text
POST /v1/epochs/{publicEpoch}/presence-write-share
POST /v1/epochs/{publicEpoch}/presence-read-share
POST /v1/epochs/{publicEpoch}/inbox-write-share
POST /v1/epochs/{publicEpoch}/inbox-read-share
GET  /v1/profiles/{profileId}
GET  /v1/epochs/{publicEpoch}/commitment

# L1.5 only — a group of one replica, where writes are not split and reads
# are not position-addressed. An L2a client never calls these.
POST /v1/epochs/{publicEpoch}/presence-write     # direct write, random slot
POST /v1/epochs/{publicEpoch}/inbox-write        # direct write
GET  /v1/epochs/{publicEpoch}/snapshot
GET  /v1/epochs/{publicEpoch}/delta?from={cursor}
```

Requirements for all private endpoints:

- the request and response body size is fixed by the public profile;
- no stable account, peer public key, room token, target index, or
  application-layer sender/recipient identifier appears in the HTTP
  method/path/headers or plaintext body; source network metadata remains an
  L2a residual unless anonymous ingress is used;
- an unlinkable admission proof may accompany the fixed body;
- replicas publish signed epoch/profile commitments into the selected
  witness/gossip/transparency mechanism so clients can expose inconsistent
  views;
- error responses do not disclose whether a target exists.

Additional requirements for the L1.5 endpoints:

- the snapshot and delta responses are exempt from the fixed-size rule under
  the SEC-005 carve-out, because their length is a function of board-wide
  activity rather than of the requesting client's demand, and every client
  fetches byte-identical ranges. They are padded to profile-defined quanta;
- the delta stream shall be covered by the signed epoch commitment of SEC-017,
  so that omission, insertion, or reordering is detectable against a witness
  rather than merely unnoticed. Without that binding, the tier's read-privacy
  argument rests on a promise instead of a check;
- `presence-write` and `inbox-write` are non-blind by construction, so the
  replica shall validate what it can see: one slot per write, rejection of
  writes to slots already occupied in the epoch, and per-admission-token write
  quotas (SEC-001a);
- these endpoints exist only for groups of one replica. A client whose group
  holds two or more replicas shall not call them, and a replica in such a group
  shall not serve them, so that no room can be quietly moved onto the weaker
  path.

### 4.6 Pairwise signaling

After private presence discovery, peers derive independent directional inbox
keys and indexes. Fixed-size encrypted records carry:

- protocol and fragment version;
- epoch and replay counter;
- rotating sender/recipient commitments;
- offer, answer, or ICE fragment;
- total padded signaling class;
- transcript hash and room-policy hash;
- expiry;
- padding.

Rotating presence identifiers deterministically select exactly one WebRTC
offerer. Both peers then run the existing transcript-bound hybrid handshake,
including CPace for PIN-required rooms.

## 5. Acceptance Criteria

- **AC-001**: Given two independently operated replicas and a valid fragment
  invite, when three fresh browsers join a room, then all three form exactly
  three authenticated WebRTC edges and each browser owns two independent
  keyed and durably persisted edge sessions.
- **AC-002**: Given instrumented replicas, when the L2 E2E test runs, then
  neither replica's application logs or decoded request objects contain a room
  capability, stable identity, common room token, peer edge, raw SDP, raw ICE,
  or DTLS fingerprint. This field-absence test is necessary but is not by
  itself evidence that the private-write/read construction is secure.
- **AC-003**: Given two different target rooms with the same public profile,
  when a single replica observes client protocol transcripts, then request and
  response counts, lengths, and scheduled times conform to the same public
  distribution. Phase 0 shall preregister the replica-visible features,
  anonymity population, target-room and co-membership leakage games, trivial
  and state-of-the-art attack baselines, dataset split, metric, and release
  threshold. The evaluation shall publish the classifier, data, and result,
  and a stable L2 label requires passing the preregistered threshold.
- **AC-004**: Given a detectably modified, replayed, or forked replica response,
  when the client combines replica results, then it rejects or reports an
  availability error without using legacy signaling. Omission tests shall
  distinguish detectable faults from the documented absence/omission limit.
- **AC-005**: Given a room with a single board group, or one in which no other
  group is reachable, when a replica of the required group is unavailable, then
  the client reports an explicit L2 availability failure and does not reveal
  the target to the remaining replicas through a fallback.
- **AC-005a**: Given a room whose profile defines two board groups, when every
  replica of one group is unreachable or blocked, then the room still assembles
  through the surviving group, no share is ever reassembled for a partial
  group, and the tier label is unchanged.
- **AC-005b**: Given an L1.5 room whose group holds one replica, when the
  client polls the board, then it fetches the epoch snapshot and the common
  delta stream only and never an individual position; when it writes, it
  targets a uniformly random unoccupied slot and not a capability-derived
  index; and the exposed tier property reads `L1.5` while no L2a-labelled
  string is reachable in the UI.
- **AC-005c**: Given a board reachable directly, through an OHTTP relay, and
  through a fronted or proxied route, when the same record is written over each
  route, then the record bytes, sizes, and the client's send schedule are
  identical across routes within a stated timing tolerance — round-trip time
  and jitter necessarily differ and are not part of this criterion.
- **AC-005d**: Given a preregistered probing distinguisher, adversary model,
  and pass threshold in the style of AC-003, when the distinguisher probes a
  gated board endpoint without the per-endpoint out-of-band secret, then it
  fails to identify the service above the threshold. This criterion is
  satisfied by a documented external review artifact, never by an automated
  banner-absence check, and it makes no claim about the public profile and
  commitment endpoints, which SEC-019b places out of scope.
- **AC-006**: Given simultaneous writers that collide, when the next permitted
  retry epoch arrives, then clients recover using the profile-defined alternate
  slots without emitting extra demand-shaped requests.
- **AC-007**: Given a wrong PIN, wrong room policy, wrong replica set, wrong
  ML-KEM suite, replayed presence record, or expired epoch, when peers attempt
  to connect, then no pairwise session establishes.
- **AC-008**: Given a room configured for immediate message delivery, when a
  message is sent after L2 handoff, then L2 provides no false claim of
  data-plane timing cover.
- **AC-009**: Given a room configured for scheduled message cover, when a
  logical message, cancellation, sparse PQ advance, or cover event occupies a
  scheduled cell, then the room policy and handshake authenticate the same
  cadence and transfer class on every edge.
- **AC-010**: Given a compromised room member, when it completes the room
  protocol, then documentation and tests acknowledge that it learns the room
  roster; L2 shall not claim otherwise.
- **AC-011**: Given colluding rendezvous replicas, when they combine their
  private-query shares, then the security documentation states that L2a privacy
  may fail; no stronger claim is made.
- **AC-012**: Before a production L2 label is enabled, an external cryptographic
  review, an implementation audit, browser packet captures, and a published
  residual-leakage statement shall exist.
- **AC-013**: Given rooms of different sizes within one public profile, when one
  replica observes an epoch, then every active cohort member emits the same
  profile-defined presence/signaling lane counts and record lengths; demand
  above `maxRoomMembers` or `maxSignalingFragmentsPerEdge` fails without
  on-demand expansion. The read-lane half of this criterion applies to L2a
  only: an L1.5 client has no read lanes, because it makes one snapshot fetch
  and one shared delta subscription at `accessCadenceMs` instead. Write lanes
  apply at both tiers.
- **AC-014**: Given a capability holder with the wrong PIN, when it reads the
  presence board, then documentation and tests acknowledge that it can discover
  presence, exchange SDP/ICE, learn peer endpoints, and receive the provisional
  stable identity bundle before CPace rejects; it cannot establish an
  authenticated peer session.

## 6. Test Automation Strategy

### 6.1 Test levels

- **Unit**: canonical policy encoding, domain separation, epoch derivation,
  AEAD records, DPF/PIR test vectors, padding, replay windows, offerer
  selection, collision scheduling, and secret erasure.
- **Property**: arbitrary `n`, join/leave churn, reordered and duplicated
  records, maximum-size SDP/ICE, epoch rollover, clock skew, collision bursts,
  and corrupted shares.
- **Integration**: one-replica (L1.5), two-replica, three-replica, and
  multi-group (at least two groups) in-memory deployments with honest,
  unavailable, stale, equivocating, and selectively failing replicas. The
  single-replica case matters most for equivocation, since it has no second
  view to compare against and depends entirely on the SEC-017 witness.
- **End-to-end**: real browsers, three or more peers, direct and TURN paths,
  PIN/no-PIN rooms, reconnect/repair, and exact production package artifacts.
- **Privacy evaluation**: packet and replica traces labelled only in the test
  harness; target-room inference, co-membership clustering, timing
  classification, and traffic-volume accounting.

### 6.2 Required automation

- Existing `bun test`, `npm run typecheck`, and standalone-session examples
  remain green throughout implementation.
- Every DPF/PIR dependency is pinned, reproducibly built, covered by upstream
  vectors, and fuzzed at the language boundary.
- CI runs an `n = 3` full-mesh L2 E2E test and asserts that no privacy-forbidden
  field reaches replica adapters or structured logs.
- A deterministic network-fault harness exercises loss, delay, duplication,
  reordering, replica partition, epoch skew, and selective failure.
- Release CI blocks `blind-meeting-point` unless all security and E2E gates are
  enabled for the exact package and server artifacts being published.

### 6.3 Measurement outputs

Every research or release candidate shall report:

- join latency and failure rate as room size and churn increase;
- collision rate and epochs-to-recovery;
- client CPU, memory, battery proxy, upload, and download;
- per-replica CPU, memory, storage, and egress;
- dummy-to-real control-plane traffic ratio;
- classifier AUC or equivalent inference metric;
- direct/TURN differences and L2a/L2b residuals;
- behavior under one malicious, one unavailable, and colluding replicas;
- reachability per board group from censored vantage points, the jurisdiction
  and autonomous-system diversity of each group, and the accuracy of a flow
  classifier trained to recognise the profile's traffic shape.

## 7. Rationale & Context

The current signaling star can read the normalized room value, stable peer
identity, roster, and every SDP/ICE routing edge. Encrypting the roster or
hashing/blinding one common room value hides content but preserves a shared
handle, so the server can still reconstruct co-membership.

Private point writes and PIR reads remove that common visible handle under an
anytrust assumption. 2PPS is the closest direct construction family because it
already combines DPF private writes, PIR private reads, and round
participation. A short-lived presence board fits dynamic rooms better than
treating the room as one permanent mailbox. After discovery, pairwise
single-writer logs fit SDP/ICE exchange better than continued multi-writer
presence traffic.

This architecture is intentionally a systems synthesis. Riposte and 2PPS
supply the direct private-write/private-read lineage; Pung and distributed PIR
show different trust and cost points; Talek supplies hidden-access group-log
techniques; Myco is the current efficiency comparator for two-server
metadata-private messaging; Peer2PIR prevents any generic claim that private
queries in a P2P network are new. The candidate paper contribution is the
evaluated adaptation to dynamic capability rooms and browser WebRTC full-mesh
handoff, combined with p2party's pairwise hybrid sessions and optional
future scheduled data plane.

Signal Private Groups is the required encrypted-roster comparison, while
traffic analysis of sealed-sender groups shows why encrypted contents do not
hide access patterns. Alpenhorn is the metadata-private dialing/bootstrap
comparison. Tor onion-service rendezvous is the deployed blind-meeting
baseline, but it connects clients to one location-hidden service rather than
privately assembling a dynamic browser room mesh.

### 7.1 ADR-001: Anytrust private board instead of a common opaque token

- **Status:** Proposed
- **Date:** 2026-07-24
- **Deciders:** p2party maintainers

#### Decision

Prototype two independently operated replicas using DPF/private point writes
and batched IT-PIR reads for the presence board. Evaluate Talek-like
directional logs after pairwise discovery. Keep a global fixed-record
trial-decryption board as an experimental baseline, not the default
architecture.

#### Options considered

| Option                                                   | Privacy result                                                 | Complexity | Cost               | Decision                         |
| -------------------------------------------------------- | -------------------------------------------------------------- | ---------- | ------------------ | -------------------------------- |
| Raw, hashed, or encrypted common room token              | Server still clusters the room                                 | Low        | Low                | Reject as L2                     |
| OPRF-derived common token                                | Hides token input, not common output access                    | Medium     | Low                | Use only for admission if needed |
| Single trusted private-signaling server                  | Operator remains a graph observer                              | Medium     | Medium             | Reject for L2a                   |
| Global board download and trial decryption               | Strong simple baseline only with uniform service-wide accesses | Medium     | High client egress | Benchmark                        |
| 2PPS/Riposte-style anytrust DPF writes plus IT-PIR reads | Hides target from one non-colluding replica                    | High       | Medium to high     | Prototype                        |
| Single-server computational PIR, following Pung          | Removes non-collusion but raises server computation            | High       | High               | Benchmark trust/cost point       |
| User-device distributed PIR                              | Shifts trust and work to an ephemeral client committee         | Very high  | To measure         | Research comparator              |
| Myco-like oblivious data structure                       | Better asymptotic target, more integration/research risk       | Very high  | To measure         | Comparator/future prototype      |
| Mix/onion rendezvous                                     | Can address L2b, adds latency and infrastructure               | Very high  | High               | Later L2b layer                  |

#### Consequences

- Privacy depends on replica non-collusion and operational independence.
- Self-hosting a strong L2 room requires a federation, not one p2party server;
  single-operator self-hosting is supported at L1.5 under ADR-002.
- Browsers pay scheduled dummy access, private-query CPU, and response egress.
- Collision handling and board capacity become explicit protocol concerns.
- Abuse resistance cannot rely on stable authenticated accounts.
- The result is publishable only if measurements show a useful point on the
  privacy/performance frontier.

### 7.2 ADR-002: A single-replica tier, board groups, and embedded endpoints

- **Status:** Proposed
- **Date:** 2026-07-27
- **Deciders:** p2party maintainers

#### Decision

Ship the architecture in a tier below L2a that runs on one replica, named
L1.5, with random-slot writes and a common snapshot/delta read path. Separate
private-write sharing (within a board group) from replication (across board
groups). Permit a room to embed its replica set in the invite, at the cost of
the L2a label.

#### Options considered

| Option | Privacy result | Availability | Decision |
| --- | --- | --- | --- |
| Wait for two independent operators before shipping anything | Full L2a or nothing | n/a | Rejected: leaves the current single-operator deployment on legacy signaling indefinitely |
| Single-replica blind board with derived write indexes | Replica reconstructs room membership per epoch | Good | Rejected: gives away the target property for no gain |
| Single-replica blind board with random-slot writes (L1.5) | No write privacy; no per-epoch room clustering; read requests carry no index | Good | **Adopted** |
| Single-server private writes (PIR-writing, homomorphic slot accumulation) | Genuine single-server write privacy | Good | Rejected on replica-CPU and client-bandwidth cost, not impossibility; revisit if costs move |
| Flat replica list, all replicas required (ADR-001 as written) | L2a | Every replica is a single point of failure | Superseded by board groups |
| Registered replica profiles only | Best cohort anonymity | Registry is a blocking target | Kept as the L2a path; embedded sets added alongside |

#### Consequences

- The deployment can ship blind rendezvous on one server while stating exactly
  which property it lacks, instead of shipping nothing.
- L1.5 depends entirely on the SEC-017 witness for equivocation detection,
  because a single replica offers no second view to compare against. That
  dependency is the tier's weakest joint and its release gate.
- Two orthogonal labels (write privacy, cohort anonymity) must both be tracked;
  a single tier enum would force false disclosures on self-hosted rooms.
- Embedded endpoints make the reachable board set non-enumerable, which helps
  blocking resistance and hurts cohort anonymity. Neither is strictly better,
  and deployments must choose knowingly.
- Board groups add a replication axis, and with it the requirement that indexes
  and record keys be domain separated per group — otherwise availability
  reintroduces the co-membership handle.

## 8. Dependencies & External Integrations

### External systems

- **EXT-001**: Rendezvous replica operators. L1.5 needs one. L2a needs at least
  two independent administrative and infrastructure trust domains in *every*
  board group, and the group-survivability property of AC-005a needs at least
  two groups — four operators in total, in distinct jurisdictions and
  autonomous systems per SEC-019d.
- **EXT-002**: TURN service — independently operated for an L2b claim; current
  co-operation leakage must be documented for L2a.
- **EXT-003**: Optional ingress privacy relay — OHTTP, mix, or onion layer with a
  stated non-collusion boundary.
- **EXT-004**: Isolated private-board service — a separately deployable
  fixed-epoch artifact with no imports from the legacy signaling Room/Peer
  schema, WebSocket roster handlers, or database.

### Technology dependencies

- **PLT-001**: Reviewed DPF/private-write implementation with deterministic test
  vectors and a browser-capable build.
- **PLT-002**: Reviewed batched IT-PIR implementation with deterministic test
  vectors and a browser-capable build.
- **PLT-003**: Branch-local p2party 0.12 release-candidate store-free session,
  ML-KEM, CPace, ratchet, and message-cell code. npm/CDN/production publication
  is a separate release gate.
- **PLT-004**: Browser WebRTC and RTCDataChannel support.

### Compliance and operational dependencies

- **COM-001**: Logs, metrics, traces, and abuse controls must be designed so
  privacy-forbidden fields cannot be collected accidentally.
- **COM-002**: Replica retention shall be bounded to public short-lived epochs.
- **COM-003**: A public deployment shall document operators, jurisdictions,
  retention, incident response, and the exact non-collusion assumption.

## 9. Examples & Edge Cases

### 9.1 Three-peer room

1. Alice, Bob, and Carol receive the same fragment capability and canonical
   policy out of band.
2. At the public cadence, each sends the profile-defined fixed write/read lanes
   to every replica. Dummy operations are indistinguishable at one replica.
3. Each reconstructs and trial-decrypts the room's candidate presence slots.
4. Each derives pairwise directional inboxes with the other two members.
5. Fixed-size encrypted SDP/ICE fragments create edges `A-B`, `A-C`, and
   `B-C`; rotating IDs select one offerer per edge.
6. Each edge runs its own p2party handshake and serializable ratchet.
7. Every active cohort member continues the profile's fixed real-or-dummy
   presence and signaling lanes until the public cohort window ends; room
   operations only substitute within that schedule. Application data stays on
   the WebRTC edges.

### 9.1a The same room at L1.5

The flow above is the L2a one. On a single replica it differs in three places
and nowhere else: each member writes its presence record to a uniformly random
unoccupied slot rather than a derived candidate; each fetches the epoch
snapshot once and then the common delta stream, trial-decrypting as before; and
the replica validates that each write claims one unoccupied slot within the
writer's token quota. The records, epochs, schedule, pairwise bootstrap, and
WebRTC handoff are unchanged. What the operator sees is that some set of
addresses wrote and polled at the scheduled cadence — not which of them share a
room, and not what any record contains.

### 9.2 Presence collision

Two writers choose the same subslot and the combined record cannot authenticate.
Both clients continue their unchanged schedule and use the next
profile-defined candidate in the next allowed epoch. They do not send an
immediate retry that would reveal a real collision.

At L1.5 the replica rejects the second write outright, since it can see that
the slot is occupied and SEC-001a requires it to enforce that. The writer
treats the rejection exactly as it treats a silent collision — no immediate
retry, next random slot at the next permitted epoch — so that the visible
behaviour does not distinguish a contested slot from an uncontested one.

### 9.3 Oversized SDP

If SDP/ICE exceeds the selected signaling class, the sender either uses a
larger class already authenticated in `RoomPolicyV2` or fails. It does not emit
an unpadded variable tail or silently switch to legacy forwarding.

### 9.4 Replica failure

If a replica within a group cannot answer, that whole group is unusable: the
private-write shares are meaningless without every share, and the client shall
not reassemble the write for the surviving replica, which would hand it the
target position it was split to hide.

If another group is reachable, the room proceeds there, because records are
replicated across groups. This is the case the design is for — one operator
seized, blocked, or offline, and the room continues. If no group is reachable,
the client presents an L2 availability error and may retry on the public
schedule. It never falls back to a smaller group, a different replica set, or
legacy signaling, and it never sends the room token to whatever server happens
to be available.

### 9.5 PIN room

The high-entropy capability selects and decrypts private board records. The
human PIN is supplied only to CPace during the pairwise handshake. A board
snapshot cannot be used to test PIN guesses offline. A capability holder may
still discover the roster and, under the post-DTLS CPace ordering, receive
peer endpoints and provisional stable identity bundles; the PIN authenticates
peers rather than hiding presence.

## 10. Validation Criteria

Conformance is indexed by tier, because a single list would make the L1.5
deployment that SEC-001a permits permanently non-conformant and therefore
unshippable.

Every tier requires:

1. the exact production artifacts pass unit, integration, `n >= 3` browser E2E,
   fault-injection, and privacy-trace suites;
2. no legacy fallback is reachable from `blind-meeting-point`;
3. the room policy and replica set are handshake authenticated;
4. the public documentation labels the deployment L1.5, L2a, or L2b, states the
   remaining leakage, and — where a group holds one replica — carries the
   SEC-001a disclosure;
5. the paper or release note reports negative and positive results, including
   cost, collisions, failures, inference attacks, and comparison baselines.

**L1.5** additionally requires that every applicable `SEC-*` requirement has an
automated test or a documented external review artifact, with SEC-003 and
SEC-004 replaced by their SEC-001a substitutes — random-slot writes, replica-side
slot validation and token quotas, and a named SEC-017 instantiation covering the
delta stream — each of which is itself tested; and that AC-005b passes.

**L2a** additionally requires that all `SEC-*` requirements have automated tests
or a documented external review artifact; that the deployed replicas of every
group are controlled by independent operators; that the replica set matches a
registered profile; and that an external cryptographic review approves the
selected DPF/PIR composition and wire format.

**L2b** additionally requires everything in Phase 8, and a blocking-resistance
claim additionally requires Phase 9 with AC-005c and AC-005d.

`blind-meeting-point` remains disabled in stable releases until the items for
the tier being shipped are satisfied.

## 11. Delivery Roadmap

### Phase 0 — Threat model and primitive selection

- Freeze the L2a and L2b adversaries, leakage, replica-failure policy, board
  capacity, public epochs, and abuse model.
- Preregister target-room/co-membership inference tasks, datasets, and release
  thresholds before tuning the transport.
- Define activity-independent anonymity-cohort entry/exit and repair behavior,
  plus the minimum cohort size for any graph-blindness label.
- Evaluate maintained DPF/PIR implementations and their browser/WASM boundary.
- Build the global-board baseline and size realistic SDP/ICE workloads.
- Obtain external review of the chosen construction before production coding.

**Gate:** accepted wire-format draft, dependency audit, test vectors, and
quantitative prototype budget.

**Phase-0 inputs (2026-07-27).** Two measured figures, two derived budgets, and
a survey. Each bullet is tagged with its provenance, because the difference
between "we ran this" and "we computed this from someone else's benchmark"
is exactly the distinction this project refuses to collapse elsewhere. None of
it is release evidence.

- *Real signaling sizes* — **measured** (headless Chromium, data-channel-only
  offer with trickle ICE, 2026-07-27): offer SDP 458 characters, answer 457,
  ICE candidates 128–150 (TURN relay 150–170), 4 candidates per side without
  TURN. The existing `MAX_SDP_CHARS` of 256 KiB is a denial-of-service ceiling
  roughly 573× the typical size and is not sizing guidance. A 1 KiB
  `signalingRecordBytes` holds any single record with padding slack; 2 KiB
  holds an offer plus its bundled candidates.
- *DPF write cost* — **derived**, from the BGI16 cost model together with
  published Express and GPU-DPF benchmarks on other people's hardware; nothing
  was run here. On that basis per-write replica cost is roughly 4–30 ms per
  core at 2^16 slots, 60–140 ms at 2^20, and 1–2 s at 2^24, so the recommendation
  is to set `presenceBucketSlots` at or below 2^16 and rotate epochs rather
  than grow the board. Client key generation is sub-millisecond and keys are
  0.5–1.5 KB, so the browser is not the constraint; the replica is. These
  numbers want re-measuring on target hardware before any capacity decision
  rests on them.
- *DPF implementation path* — **survey** (2026-07-27) of libdpf, dpf++,
  Google's `distributed_point_functions`, `myl7/fss`, and libprio-rs's IDPF.
  Each of the C and C++ libraries depends on hardware AES, which WASM does not
  expose; the Rust ones prove browser-WASM DPF is viable but would add a second
  toolchain. Instantiating the PRG with ChaCha20 sidesteps the AES dependency,
  and libsodium already provides ChaCha20 inside the pinned `libcrypto.wasm`.
  The estimate is roughly 400–600 lines of new C compiled for both the browser
  and the replica — an estimate for code that does not exist and has not been
  reviewed, and which SEC-011 requires be externally reviewed before use.
- *SEC-003 has an architectural cost that must be decided in Phase 0*:
  preventing one malformed share from corrupting the board requires either
  Express-style SNIP auditing, which needs a replica-to-replica channel within
  a group, or a verifiable DPF at roughly double the evaluation cost. A
  replica-to-replica channel is a real weakening of the "replicas share
  nothing" story and shall be stated explicitly wherever the tier is
  described.
- *L1.5 read bandwidth* — **computed** from stated assumptions, and the least
  comfortable number here. Every client must receive every live cell at least
  once, so the steady-state cost is the cohort's write volume times the record
  size divided by the epoch: at 10^4 live 1 KiB cells that is about 10.2 MiB
  per epoch, roughly 34 KiB/s at five-minute epochs — not the 1–5 KiB/s an
  earlier draft claimed by confusing per-epoch churn with board occupancy. On
  top of that sits a snapshot of about 10 MiB on every join, and again on every
  resume, since §4.1 forces a fresh cohort entry after browser suspension; that
  snapshot, not the steady state, is what governs mobile join latency. Because
  SEC-006 makes every cohort member write real-or-dummy lanes each epoch, live
  cells scale with cohort size — so this cost grows with precisely the
  parameter SEC-016 wants large, and the feasible board size must be re-derived
  from that tension rather than assumed.
- *Tag-prefix bucketing is rejected as a bandwidth knob* — **analytic**. With b
  bits of prefix and P concurrently active pairs, a replica intersects rotating
  bucket sequences and uniquely links a pair after ceil(log2(P)/b) epochs: at
  b=4 and P=10^4 that is 4 epochs, i.e. 20 minutes at five-minute epochs.
  Bucketing does not shrink the anonymity set, it schedules its collapse.
- *Trickle ICE does not survive a polled board* — **structural**.
  Per-candidate posting turns each candidate into a separately timed write.
  Blind mode shall wait for `icegatheringstatechange === "complete"` and post
  one complete-SDP record per direction, which also makes
  `signalingWriteLanesPerEpoch` constant per edge.
- *Invite encoding budget* — **computed**; see §4.1 for the figure and its
  caveats. The budget is taken over the whole encoded `BlindRoomAccessV2`,
  including the rendezvous profile hash and one Ed25519 key per embedded
  descriptor, and it must be confirmed against a real encoder.
- *Integration blocker* — **measured** with `madge` (2026-07-27): the SDK has
  62 elementary import cycles. The store, the RTK Query layer, and the handlers
  are mutually entangled such that no board client can reuse
  `handleConnectToPeer` without importing the WebSocket API. Extracting
  `RendezvousTransport` per GUD-006 is therefore a prerequisite to Phase 1
  rather than a cleanup that can follow it.

### Phase 1 — Store-free client core and simulator

- Implement canonical `RoomPolicyV2`, fragment encoding, epoch/key derivation,
  fixed record codecs, padding, replay protection, and secret erasure.
- Add DPF/PIR adapters behind store-free interfaces.
- Extract the injected `RendezvousTransport`, local-only room/edge identifiers,
  and signaling event model before touching browser room behavior.
- Build a deterministic in-memory multi-replica/fault simulator.
- Preserve Node/Bun/non-browser compatibility for the crypto and codec core.

**Gate:** unit/property/fuzz suites and simulator privacy assertions pass.

### Phase 2 — Replica service

- Implement fixed-body share endpoints, epoch boards, signed commitments,
  expiry, anonymous admission hooks, metrics, and safe logging.
- Ship the board as a separate artifact/service with no legacy Room/Peer
  database, roster, or signaling-WebSocket imports.
- Integrate robust/verifiable private writes, read integrity, and the selected
  commitment witness/gossip mechanism.
- Add collision profiles, bounded storage, overload behavior, and
  equivocation/partition detection.
- Implement the L1.5 endpoints of §4.5 — direct write with replica-side slot
  validation and token quotas, epoch snapshot, and the commitment-covered delta
  stream — and refuse to serve them from a replica belonging to a group of two
  or more. This is the tier that runs on the existing single-operator
  deployment, so it is delivered here rather than deferred to the federated
  phases.
- Produce independently deployable Apache-licensed server artifacts.

**Gate:** malicious-replica and load tests pass without target-bearing logs;
AC-005b passes against a single-replica deployment.

### Phase 3 — Browser room integration

- Add `blind-meeting-point` transport selection and explicit fail-closed UX.
- Integrate fragment invites, PIN/no-PIN input separation, authenticated
  replica sets, and room-wide access policy.
- Migrate WebRTC registries, negotiation locks, ratchet gates, handshake
  inboxes, and transfer queues from server UUIDs to local-only room/pre-auth
  edge identifiers; migrate durable ownership to room context plus verified
  stable identity.
- Remove all stable identity and room addressing from the L2 adapter boundary.

**Gate:** no privacy-forbidden field reaches an L2 replica request or the L2
adapter/replica structured logs; concurrently used legacy rooms and ordinary
site requests are outside this assertion.

### Phase 4 — Full WebRTC handoff

- Implement and review the pre-WebRTC hybrid rendezvous exchange, pairwise
  inbox derivation, and post-DTLS stable-identity pinning.
- Implement private pairwise inboxes, fixed-size SDP/ICE fragmentation,
  deterministic offerer selection, reconnect, and repair.
- Run the existing hybrid p2party handshake independently on every edge.
- Complete exact-artifact `n = 3` and larger full-mesh E2E tests.

**Gate:** edge/session correctness, identity/PIN failure, replica field-absence,
and no-legacy-fallback tests pass. Full privacy acceptance waits for Phase 5.

### Phase 5 — Access cover, abuse, and adversarial evaluation

- Implement real-or-dummy control-plane accesses at the authenticated cadence.
- Fix membership, presence, signaling, and repair lane counts independently of
  room size and demand for the full public cohort window.
- Test churn, clock skew, collision bursts, replay, selective failure,
  equivocation, flooding, and quota-token unlinkability.
- Capture browser, replica, ingress, and TURN traces; train and publish
  room-target and co-membership classifiers.

**Gate:** AC-001, AC-002, AC-003, AC-004, AC-005, AC-005a, AC-005b, AC-006,
AC-007, AC-008, AC-010, AC-011, AC-013, and AC-014 pass; the evaluated
privacy/cost result passes the preregistered L2a thresholds. AC-005c and
AC-005d belong to Phase 9 and are not in this gate, because multi-route
descriptors and probing resistance are not implemented until then.

### Phase 6 — Independent deployment and review

- Recruit and document at least two independent replica operators.
- Stage the exact reviewed artifacts, publish operator keys/profile
  commitments, and rehearse failure/rotation procedures.
- Complete an external cryptographic audit and implementation security review.
- Enable L2 for explicit experimental rooms, then graduate only after public
  measurements and incident-free operation.

**Gate:** stable UI may label rooms `L2a`; `L2b` remains unavailable until its
network trust and trace requirements are separately met. AC-012 is the Phase-6
release gate.

### Phase 7 — Scheduled data-plane cover and sparse PQ healing

- Integrate the existing sparse-PQ state machine with canonical ACK encoding,
  crash-safe encrypted checkpoint/restore, exact sealed-record retransmission,
  message-key combination, and the WebRTC scheduler.
- Implement room-wide scheduled real-or-cover lanes, authenticated
  future-boundary policy changes, encrypted cancellation semantics, and fixed
  large-transfer classes.
- Preserve immediate/no-cover as the product default. Do not enable
  `scheduled-future` merely because its policy value is encoded.
- Measure bandwidth, latency, battery, DataChannel churn, direct/TURN packet
  traces, cancellation leakage, and large-file class leakage.

**Gate:** AC-009 and the separate PQ-healing crash/replay/fork gates pass for
the exact deployed artifacts.

### Phase 8 — L2b network unlinkability

- Split client ingress from board processing and TURN observation across
  independent operators, or integrate a reviewed mix/onion transport.
- Define batching, delay, source-IP retention, collusion, and direct-WebRTC
  residuals.
- Repeat the preregistered classifier evaluation with ingress and TURN traces.

**Gate:** only a separately reviewed and measured deployment may display an
`L2b` label.

### Phase 9 — Blocking resistance

- Implement multi-route replica descriptors per SEC-019a so one board is
  reachable directly, through an OHTTP relay, and through at least one
  fronted or proxied route, with identical record bytes on every route.
- Add probing resistance per SEC-019b and obtain review of it as a formal
  property rather than as an absence of banners.
- Record jurisdictional, CDN, and autonomous-system diversity per board group,
  and measure reachability from censored vantage points rather than from the
  maintainers' network.
- Quantify the tension in SEC-019c: report what the fixed-size, fixed-cadence
  traffic shape looks like to a flow classifier trained to find it, and state
  the settings at which the anonymity claim and the blocking claim disagree.
- Decide and document the registry-versus-embedded trade-off of SEC-019e for
  the reference deployment.

**Gate:** AC-005c and AC-005d pass. A blocking-resistance claim additionally
requires reachability measurements from real censored networks, a reviewed
probing-resistance argument as the AC-005d artifact, and a published statement
of which transports, if blocked wholesale, take p2party with them. No such
claim may rest on replica count alone.

## 12. Related Specifications / Further Reading

- [Protocol evolution decision log](../docs/protocol-evolution-decision-log.md)
- [Prior art and related work](../docs/paper-prior-art-and-related-work.md)
- [Rendezvous and federation prior art](../docs/rendezvous-prior-art.md) — the
  link-verified annotated bibliography for this specification, including the
  private-write/private-read literature, the deployed federation systems and
  their documented metadata failures, the traffic-analysis evaluation bar, and
  the blind-signature payment lineage behind SEC-012a
- [Protocol-v3 security boundary](../docs/protocol-v3-security.md)
- [Riposte: Anonymous Messaging at Scale](https://eprint.iacr.org/2015/824)
- [Talek: Private Group Messaging with Hidden Access Patterns](https://eprint.iacr.org/2020/066)
- [2PPS: Publish/Subscribe with Provable Privacy](https://arxiv.org/abs/2108.08624)
- [Pung: Unobservable Communication over Fully Untrusted Infrastructure](https://www.usenix.org/conference/osdi16/technical-sessions/presentation/angel)
- [Distributed PIR: Scaling Private Messaging via the Users' Devices](https://eprint.iacr.org/2024/978)
- [Myco: Unlocking Polylogarithmic Accesses in Metadata-Private Messaging](https://eprint.iacr.org/2025/687)
- [Peer2PIR: Private Queries for IPFS](https://doi.org/10.1109/SP61157.2025.00231)
- [Private Signaling](https://www.usenix.org/conference/usenixsecurity22/presentation/madathil)
- [DP5: A Private Presence Service](https://discovery.ucl.ac.uk/id/eprint/1469539/1/popets-2015-0008.pdf)
- [Signal Private Groups](https://eprint.iacr.org/2019/1416)
- [No Safety in Numbers: Traffic Analysis of Sealed-Sender Groups](https://arxiv.org/abs/2305.09799)
- [Alpenhorn: Bootstrapping Secure Communication without Leaking Metadata](https://www.usenix.org/conference/osdi16/technical-sessions/presentation/lazar)
- [Tor onion-service rendezvous protocol](https://spec.torproject.org/rend-spec/protocol-overview.html)
- [RFC 9458: Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458)
- [RFC 9576: Privacy Pass Architecture](https://www.rfc-editor.org/rfc/rfc9576)
