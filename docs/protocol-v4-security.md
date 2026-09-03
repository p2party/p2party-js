# Protocol-v4 security boundary

This document states what p2party 0.14's code path does, what observers still
learn, and which adjacent mechanisms are not production properties. It is a
developer threat-model summary, not an independent audit or a formal proof.

Protocol v4 is a clean wire break. Missing, malformed, older, and mismatched
wire versions fail closed; there is no legacy cryptographic fallback.

## What establishes a peer edge

There are three different acknowledgements in the system:

1. An `RTCDataChannel` becoming `open` means the DTLS/SCTP transport and that
   channel are ready. An in-band channel may have completed its DCEP OPEN/ACK,
   but this is not p2party identity or key confirmation.
2. The protocol-v4 handshake runs over the open main channel. After HELLO,
   responder CONFIRM, initiator CONFIRM, and responder FINISH, the peers have
   authenticated the same hybrid root and initial ratchet keys.
3. Authenticated 65-byte receipt frames acknowledge message chunks and final
   transfer completion. They are delivery/reconciliation signals, not handshake
   establishment.

An open data channel therefore is necessary transport readiness, not an
established p2party crypto session.

The handshake combines:

- interactive 3DH proving possession of fresh ephemeral X25519 keys and
  dedicated long-term X25519 identity keys;
- Ed25519-pinned identities cross-signing those X25519 identity keys with a
  domain-separated transcript;
- one room-fixed ML-KEM-512, ML-KEM-768, or ML-KEM-1024 shared secret;
- draft-21 CPace in PIN rooms; and
- HKDF/HMAC transcript binding and three chained key-confirmation flights.

The authenticated channel input binds the channel identifier, initiator and
responder Ed25519 identities, ordered endpoint fingerprints, and exact ML-KEM
suite tag. The room policy is fixed before traffic; a suite/mode mismatch
poisons the transcript instead of negotiating or falling back.

The initiator returns established only after receiving and verifying FINISH.
The responder returns after successfully sending FINISH. Losing that final
flight can leave the responder complete while the initiator waits and
eventually fails. That is an availability/common-knowledge limit of the final
message, not evidence that an attacker learned the root key.

## Post-handshake message protection

Every authenticated peer edge owns independent Double Ratchet state. Either
role may send first, and simultaneous first sends are tested. Each logical
message consumes one message-key step; its chunks share the authenticated
ratchet header and use fresh nonces. Failed authentication rolls back the
candidate receive state, and skipped-key storage is bounded.

Each chunk frame is exactly 65,490 bytes:

```text
type(1) || DH public key(32) || N(8) || PN(8) || PQ epoch(8) ||
nonce(12) || encrypted fixed plaintext cell(65,405) || AEAD tag(16)
```

The 69-byte clear header is authenticated as AAD, excluding the fresh random
nonce. The PQ epoch is an unsigned 64-bit counter — widened from v3's single
byte so the sparse post-quantum healing epoch cannot wrap.

The fixed frame geometry absorbs the ratchet and AEAD overhead into the cell
budget. Random padding and decoy slots can hide the exact payload length within
one transfer's chosen number of frames. Receipts have a distinct fixed 65-byte
geometry. Handshake flights are suite- and step-dependent rather than
65,490-byte cells.

Per-message channels give each transfer an independent lifecycle for
cancellation, bounded channel accounting, receipts, selective retransmission,
and reconnect resume. Channel isolation is a UX and reliability property; it
does not make timing or channel count invisible.

## Guarantees, assuming authenticated peer keys

With a correctly pinned peer Ed25519 identity, uncompromised endpoints, matching
room configuration, and successful confirmation, the implementation is
designed to provide:

- mutual possession authentication for the cross-signed X25519 identities;
- optional shared-PIN authentication in addition to identity authentication;
- a hybrid initial root dependent on both classical 3DH and the selected
  ML-KEM exchange;
- transcript binding to roles, identities, endpoint fingerprints, policy
  suite, KEM fields, and initial ratchet public keys;
- confidentiality and integrity for message cells;
- forward evolution and post-compromise recovery from later uncompromised
  classical DH ratchet turns;
- replay/tamper rejection within the ratchet and transfer protocols; and
- bounded out-of-order key retention and bounded per-edge transfer resources.

These are implementation claims, not a claim of equivalence to Signal's PQXDH
proofs or to a standardized X-Wing combiner. p2party's handshake is interactive,
includes transport and optional CPace binding, and uses its own explicitly
domain-separated combiner. The code has not completed an independent
third-party cryptographic audit or a ProVerif/CryptoVerif analysis.

## Observable metadata

Encryption does not hide all communication metadata.

The current legacy signaling operator can observe:

- the normalized room capability and room membership;
- peer identifiers and presented public identity keys;
- signaling timing, SDP, ICE candidates, IP/network information, and TURN use;
- room joins, leaves, and connection attempts; and
- any fallback/relay metadata explicitly sent through server-controlled paths.

A network observer can still estimate connection timing, endpoints where
WebRTC exposes them, packet volume, transfer duration, and traffic bursts. An
endpoint peer necessarily learns plaintexts it decrypts, peer identity, message
ordering, and transfer activity.

Fixed chunk cells hide exact plaintext length only within the frame-count
bucket and chosen decoy allocation. With immediate delivery, observers still
see when a message starts, how many cells/channels are active, when receipts
flow, and when a transfer ends. Fixed cells without a room-wide schedule are
not continuous cover traffic.

Putting the capability in a URL fragment keeps it out of ordinary HTTP
requests and common access logs, but the shipped legacy signaling path still
receives its normalized value. A fragment is not a server-blind meeting point.

## Signaling and TURN correctness boundary

SDK 0.14.6 makes legacy signaling state transitions correlated and bounded; it
does not make that signaling path blind.

- A room response is accepted only for the exact current socket, room
  capability, and UUIDv4 request. A delayed response cannot configure another
  room.
- Caller ICE configuration and signaling-managed TURN credentials are separate
  inputs. Managed credentials carry an absolute expiry, are applied to every
  live room edge before an ICE restart, refresh proactively, and are removed or
  failed closed when they expire.
- `purgeRoom()` tears down local transports and durable state before waiting
  for a correlated server acknowledgement. The leave is keyed by the stable
  room capability rather than the server-assigned room UUID, so a purge racing
  an in-flight join still revokes that membership. Matching `p2party-server`
  0.1.1 unlinks the authenticated peer from the room before acknowledging. An
  offline or non-acknowledging server produces
  `RemoteRoomRevocationUnconfirmedError`; it is never reported as confirmed.
- Signaling ingress, room rosters, live mesh edges, pending ICE, and channel
  registries have explicit client-side bounds. Those bounds limit one client's
  exposure; they are not server-side Sybil resistance or a global availability
  proof.

TURN is a transport relay, not a privacy proxy. The legacy REST username is
expiry-bound but contains the client's Ed25519 public key, and the TURN
operator can observe source addresses, allocations, timing, and byte volume.
Neither relay use nor TLS makes the signaling operator unable to read SDP, ICE,
room capabilities, or membership.

The current challenge proves possession of the presented Ed25519 key to the
server by signing a fresh nonce. Its transcript is not bound to a server
identity or origin, so it does not resist a malicious server relaying another
server's nonce as a signing oracle. The legacy service also has no
cross-instance session-generation fence or Byzantine quorum. Consequently none
of malicious-rendezvous blindness, two-server BFT, social-graph hiding,
server-bound authentication, shutdown survival, or post-quantum signaling
authentication is a property of this path. Those remain requirements of the
versioned blind-rendezvous design.

## Shipped, implemented core, and research

| Status                    | Exact boundary in 0.14                                                                                                                                                                                                                                                                                                                                                                                                  |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Shipped public path       | Full WebRTC room mesh; protocol-v4 hybrid 3DH + exact room-fixed ML-KEM-512/768/1024 bootstrap; optional CPace PIN rooms; chained triple confirmation; per-edge Double Ratchet; fixed message cells and in-transfer decoys; per-message channels; authenticated receipts, cancellation, selective retransmission, reconnect resume; compact/fragment/word invites; store-free `createSession()`/`restoreSession()` API. |
| Shipped, newer            | Sparse post-quantum healing (OFFER/ADVANCE/ACK epoch exchange) with persist-before-dispatch and application traffic blocked while an epoch is in flight. Room-wide scheduled timing cover: policy-pinned cadence, lanes, and frames per cell, emitted whether or not data is queued.                                                                                                                                    |
| Research/design direction | Opaque/server-blind rendezvous and blind meeting points; a private BitTorrent-compatible swarm extension; multi-device/group-state designs beyond independent pairwise mesh edges; and machine-checked formal analysis comparable in scope to PQXDH work.                                                                                                                                                               |

Scheduled cover is a room-wide property: it hides _when_ a peer has something
to say only for as long as every edge in the room keeps emitting on the
schedule. It does not hide room membership from the signaling operator, and it
does not apply to rooms whose policy selects immediate delivery.

## Deployment obligations

Applications using `p2party/session` own several security-critical jobs:

- authenticate or explicitly TOFU-pin peer Ed25519 keys;
- bind the session to a real transport context and route handshake frames
  without cross-session confusion;
- keep long-term Ed25519/X25519 secrets in protected storage;
- encrypt snapshots at rest and enforce rollback protection;
- wipe caller-owned PIN, identity-secret, WASM scratch, and snapshot buffers
  when their lifecycle ends;
- enforce timeouts, message-size/resource limits, and abuse controls; and
- update JavaScript and its exact release-matched WASM together.

For browser-mesh setup and artifact behavior, see
[Getting started](getting-started.md). For the standalone transport and
snapshot contract, see [Store-free session API](session-api.md).
