# Security policy

## Reporting a vulnerability

Please do not open a public issue for an undisclosed vulnerability.

Email `security@p2party.com` with:

- the affected commit, package version, runtime, or deployed endpoint;
- reproduction steps or a proof of concept;
- the expected security impact; and
- whether you want attribution.

Use synthetic identities, room capabilities, PINs, snapshots, and files in
reproductions. Do not attach a live identity secret, room PIN, `.env` file,
TURN secret, production database, or user capture. Ask
`security@p2party.com` for the current encryption key before sending sensitive
artifacts.

Maintainers will acknowledge receipt, coordinate validation and remediation,
and agree on a disclosure timeline with the reporter. Please allow time for a
fix to reach supported clients before publishing details.

## Supported version

Protocol v3 on the default branch and the newest published protocol-v3 npm
release are supported. Older wire protocols are rejected rather than
negotiated.

## Cryptographic scope

This repository implements the browser room mesh, the store-free session API,
the authenticated handshake, message ratchet, chunk protocol, and persistent
client state. It has not completed an independent third-party security audit;
avoid claims to the contrary.

The currently shipped connection path uses immediate delivery and the legacy
signaling rendezvous. Its operator can observe room membership, identity public
keys, peer IDs, IP/network metadata, timing, and TURN use. Scheduled timing
cover, server-blind rendezvous, and the private BitTorrent extension are not
currently wired public guarantees. A sparse post-quantum healing state-machine
core is implemented and tested, but its production persistence, authenticated
control routing, message-key integration, and scheduler wiring remain gated.

An `RTCDataChannel` becoming open proves transport readiness, not completion of
the protocol-v3 identity and key-confirmation transcript.
