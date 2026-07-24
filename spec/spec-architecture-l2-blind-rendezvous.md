---
title: L2 Server-Blind N-Party Rendezvous Architecture
version: 0.1-proposed
date_created: 2026-07-24
last_updated: 2026-07-24
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

## 1. Purpose & Scope

### 1.1 Purpose

The implementation shall replace explicit room registration, roster lookup,
and addressed SDP/ICE forwarding with private writes and private reads over an
anytrust replica set. Once two peers discover each other and establish a
WebRTC edge, application payloads remain peer-to-peer.

### 1.2 Scope

This specification covers:

- fragment-only room invitations;
- an authenticated, versioned room policy;
- an epoch-based private presence board;
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
  demand-shaped tail.
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
  shall not become the rendezvous address.
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

type ReplicaDescriptorV1 = {
  origin: string; // canonical HTTPS origin
  role: "private-board";
  signatureAlgorithm: "Ed25519";
  publicKey: Uint8Array;
};

type RoomPolicyV2 = {
  policyVersion: 2;
  wireProtocolVersion: 4;
  revision: 0;
  rendezvousMode: "blind-meeting-point";
  rendezvousProfileId: number;
  rendezvousProfileHash: Uint8Array;
  replicaSetProfileId: number;
  replicaSetProfileHash: Uint8Array;
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

type ReplicaSetProfileV1 = {
  profileVersion: 1;
  profileId: number;
  revision: number;
  replicas: readonly ReplicaDescriptorV1[];
  contactAllReplicasEveryLane: true;
  requiredWriteShares: number;
  requiredReadShares: number;
  maxColludingReplicas: number;
};
```

The encoded access object lives only after `#`. The canonical policy bytes and
replica-set commitment are authenticated by every pairwise handshake.
`encodeRoomPolicyV2` and the two profile encoders shall map every enum to a
fixed numeric identifier, length-prefix variable fields, sort replica
descriptors by canonical encoded bytes, reject unknown/duplicate fields, and
produce one byte representation per object. The policy/profile hashes are
included in the existing room channel context. Free-form profile or algorithm
strings are not permitted on the wire.

The room policy references rendezvous and replica-set profiles by registered ID
and content hash; it cannot embed an arbitrary room-specific replica list. The
initial full-anytrust profile contacts every replica on every scheduled lane,
sets both required share counts to `replicas.length`, and states
`maxColludingReplicas = replicas.length - 1`. Any threshold construction with
different privacy or availability semantics requires a new reviewed profile.

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

The client derives a fixed candidate set of bucket/subslot indexes from the
room capability, epoch, and profile. It privately writes one candidate and
privately reads the entire candidate set. Candidate selection, collision
recovery, and capacity are profile parameters, not hidden implementation
defaults.

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
- **AC-005**: Given one unavailable replica, when a room requires the full
  anytrust profile, then the client reports an explicit L2 availability failure
  and does not reveal the target to the remaining replica through a fallback.
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
  on-demand expansion.
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
- **Integration**: two- and three-replica in-memory deployments with honest,
  unavailable, stale, equivocating, and selectively failing replicas.
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
- behavior under one malicious, one unavailable, and colluding replicas.

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
- Self-hosting a strong L2 room requires a federation, not one p2party server.
- Browsers pay scheduled dummy access, private-query CPU, and response egress.
- Collision handling and board capacity become explicit protocol concerns.
- Abuse resistance cannot rely on stable authenticated accounts.
- The result is publishable only if measurements show a useful point on the
  privacy/performance frontier.

## 8. Dependencies & External Integrations

### External systems

- **EXT-001**: Independent rendezvous replica operators — at least two
  administrative and infrastructure trust domains.
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

### 9.2 Presence collision

Two writers choose the same subslot and the combined record cannot authenticate.
Both clients continue their unchanged schedule and use the next
profile-defined candidate in the next allowed epoch. They do not send an
immediate retry that would reveal a real collision.

### 9.3 Oversized SDP

If SDP/ICE exceeds the selected signaling class, the sender either uses a
larger class already authenticated in `RoomPolicyV2` or fails. It does not emit
an unpadded variable tail or silently switch to legacy forwarding.

### 9.4 Replica failure

If the required replica set cannot answer, the client presents an L2
availability error. It may retry on the public schedule. It does not send the
room token to the available server.

### 9.5 PIN room

The high-entropy capability selects and decrypts private board records. The
human PIN is supplied only to CPace during the pairwise handshake. A board
snapshot cannot be used to test PIN guesses offline. A capability holder may
still discover the roster and, under the post-DTLS CPace ordering, receive
peer endpoints and provisional stable identity bundles; the PIN authenticates
peers rather than hiding presence.

## 10. Validation Criteria

Implementation is conformant only when:

1. all `SEC-*` requirements have automated tests or a documented external
   review artifact;
2. the exact production artifacts pass unit, integration, `n >= 3` browser E2E,
   fault-injection, and privacy-trace suites;
3. the deployed replicas are controlled by independent operators;
4. no legacy fallback is reachable from `blind-meeting-point`;
5. the room policy and replica set are handshake authenticated;
6. the public documentation labels the deployment L2a or L2b and states the
   remaining leakage;
7. an external cryptographic review approves the selected DPF/PIR composition
   and wire format;
8. the paper reports negative and positive results, including cost, collisions,
   failures, inference attacks, and comparison baselines;
9. `blind-meeting-point` remains disabled in stable releases until every item
   above is satisfied.

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
- Produce independently deployable Apache-licensed server artifacts.

**Gate:** malicious-replica and load tests pass without target-bearing logs.

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

**Gate:** AC-001 through AC-008, AC-010 through AC-011, and AC-013 through
AC-014 pass; the evaluated privacy/cost result passes the preregistered L2a
thresholds.

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

## 12. Related Specifications / Further Reading

- [Protocol evolution decision log](../docs/protocol-evolution-decision-log.md)
- [Prior art and related work](../docs/paper-prior-art-and-related-work.md)
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
