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

Protocol v4 on the default branch, and the newest published protocol-v4 release.
Older wire protocols are rejected rather than negotiated: v4 does not resume v3
peers or persisted v3 crypto rows.

## Cryptographic scope

This repository implements the browser room mesh, the store-free session API,
the authenticated handshake, message ratchet, chunk protocol, and persistent
client state. It has not completed an independent third-party security audit;
avoid claims to the contrary.

What is and is not a shipped guarantee is stated in one place —
[docs/protocol-v4-security.md](docs/protocol-v4-security.md) — and deliberately
not repeated here, because two copies of that boundary drift and the stale one
is the one somebody reads. Read it before treating any property as deployed.

Two limits are worth restating because they are the ones most often assumed
away: the legacy signaling operator can observe room membership, identity
public keys, peer IDs, network metadata and timing; and an `RTCDataChannel`
becoming open proves transport readiness, not completion of the protocol-v4
identity and key-confirmation transcript.
