# Protocol-v3 security boundary

This document states what p2party 0.12's code path does, what observers still
learn, and which adjacent mechanisms are not production properties. It is a
developer threat-model summary, not an independent audit or a formal proof.

Protocol v3 is a clean wire break. Missing, malformed, older, and mismatched
wire versions fail closed; there is no legacy cryptographic fallback.

## What establishes a peer edge

There are three different acknowledgements in the system:

1. An `RTCDataChannel` becoming `open` means the DTLS/SCTP transport and that
   channel are ready. An in-band channel may have completed its DCEP OPEN/ACK,
   but this is not p2party identity or key confirmation.
2. The protocol-v3 handshake runs over the open main channel. After HELLO,
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
type(1) || DH public key(32) || N(8) || PN(8) || PQ epoch(1) ||
nonce(12) || encrypted fixed plaintext cell(65,412) || AEAD tag(16)
```

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

## Shipped, implemented core, and research

| Status                                        | Exact boundary in 0.12                                                                                                                                                                                                                                                                                                                                                                                                  |
| --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Shipped public path                           | Full WebRTC room mesh; protocol-v3 hybrid 3DH + exact room-fixed ML-KEM-512/768/1024 bootstrap; optional CPace PIN rooms; chained triple confirmation; per-edge Double Ratchet; fixed message cells and in-transfer decoys; per-message channels; authenticated receipts, cancellation, selective retransmission, reconnect resume; compact/fragment/word invites; store-free `createSession()`/`restoreSession()` API. |
| Implemented/tested core, not production-wired | Sparse post-quantum healing state machine. Production still needs crash-safe persistence, authenticated control-frame routing, message-key integration, nonzero epoch emission/acceptance, and scheduling. The room-policy codec also represents scheduled cover and private rendezvous modes, but public `connect()` rejects them.                                                                                     |
| Research/design direction                     | Room-wide scheduled timing cover; opaque/server-blind rendezvous and blind meeting points; a private BitTorrent-compatible swarm extension; multi-device/group-state designs beyond independent pairwise mesh edges; and machine-checked formal analysis comparable in scope to PQXDH work.                                                                                                                             |

Do not advertise an implemented-core row as a deployed guarantee. In
particular, all shipped chunk headers currently identify the bootstrap PQ epoch;
sparse PQ healing does not yet refresh live production message roots.

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
