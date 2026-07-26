# Roadmap

Direction, not a schedule. Nothing here carries a date, and anything in
"Research directions" may turn out to be a bad idea once it is studied
properly. What is already shipped is described in the
[README](README.md) and bounded honestly in the
[protocol-v4 security boundary](docs/protocol-v4-security.md).

Citation numbers refer to [docs/references.md](docs/references.md).

## Where things stand

Shipped and running in the browser mesh as of 0.14.1:

- protocol v4 — hybrid interactive 3DH ⊕ ML-KEM bootstrap, Ed25519-pinned
  identities, three chained confirmation flights, per-edge Double Ratchet;
- sparse post-quantum healing — the OFFER/ADVANCE/ACK epoch exchange, with
  persist-before-dispatch and application traffic blocked mid-exchange;
- room-wide scheduled timing cover — policy-pinned cadence, lanes, and frames
  per cell, emitted whether or not there is data to send;
- reliable transfer — per-message channels, authenticated receipts, selective
  retransmission, reconnect resume, files to 10 GiB;
- a store-free `p2party/session` API for non-browser transports.

## Near term

**Close the verification gaps.** Three properties are implemented and believed
correct but not yet demonstrated end to end: PIN backoff escalation under
repeated wrong PINs, packet-trace indistinguishability at n > 2, and cover
behaviour across a real network rather than loopback. Claims stay out of the
README until a harness demonstrates them.

**Independent security audit.** The protocol has had no third-party review.
This is the single most valuable thing that could happen to the project, and
no amount of internal testing substitutes for it.

**Untangle the module graph.** Roughly eleven import cycles remain between the
store, the RTK Query layer, and the handlers. They are latent initialization-
order hazards, not current bugs.

**Identity backup and restore.** Long-term Ed25519/X25519 identities currently
live only in browser storage. Losing the profile loses the identity. A
mnemonic backup and restore flow is the missing piece.

## Research directions

Each of these is a real open problem, paired with the prior work that would
have to be answered.

None of them is a known vulnerability. They are properties p2party does not
claim, and research it would have to do before claiming them. The metadata the
shipped design does expose to the signaling operator is stated plainly in the
[security boundary](docs/protocol-v4-security.md) rather than listed here as
though it were a defect.

**Server-blind rendezvous.** The largest remaining metadata leak: today's
signaling operator sees the normalized room capability, membership, and
timing, so the `opaque` and `blind` rendezvous modes exist in the policy codec
but are rejected by `connect()`. Making them real means answering DP5's
private-presence design, _Private Signaling_ (USENIX Security 2022), and Tor's
onion rendezvous protocol, plus deciding whether Oblivious HTTP (RFC 9458) and
Privacy Pass (RFC 9576) can carry the introduction without reintroducing a
trusted observer.

**Byte-uniform KEM encodings, if a wire layer ever exposes them.** ML-KEM
public keys and ciphertexts are not uniform random bytes, and a distinguisher
that can read the raw encoding separates KEM material from padding.
[Kemeleon](https://eprint.iacr.org/2024/1086), introduced in Günther, Stebila
and Veitch's _Obfuscated Key Exchange_, is the mapping that fixes it.

This entry previously overstated it. Kemeleon is prior art we have to cite,
not a bug we currently have. Every KEM record p2party sends today travels inside
an authenticated fixed-size application cell and then inside DTLS, so an
observer at or before DTLS/TURN — the adversary this project actually claims —
sees AEAD ciphertext, not ML-KEM coefficients. Applying a raw-byte uniformity
test at that position is a layer error; see the adjudication in
[docs/paper-prior-art-and-related-work.md](docs/paper-prior-art-and-related-work.md).

It starts to matter the moment a wire layer carries KEM material outside the
encrypted envelope, which server-blind rendezvous needs almost by definition:
an introduction has to be readable before a session exists to encrypt it.
Packet traces confirming that no KEM bytes appear outside the envelope are the
check that keeps this entry closed.

**Cover traffic that survives analysis.** Fixed cells and a fixed cadence are
the easy half. _The Last Hop Attack_ (PoPETs 2025) shows how loop cover over
fixed cascades fails, and Maybenot and Tamaraw give a framework for evaluating
a defence rather than asserting one. p2party should be measured against these
before scheduled cover is described as traffic-analysis resistance rather than
as timing cover.

**Group state beyond a pairwise mesh.** An n-party room is currently n(n−1)/2
independent pairwise sessions, which is simple and hard to break but scales
quadratically and gives no group-level forward secrecy. MLS (RFC 9420, and
`ts-mls` for a browser implementation) is the obvious comparison; Signal's
_Call to Action_ on quantum-safe private groups is the post-quantum framing.

**Formal analysis.** The handshake is interactive, adds CPace and transport
binding, and uses its own domain-separated combiner — so none of the existing
PQXDH or Double Ratchet proofs transfer to it directly. A ProVerif or
CryptoVerif model in the style of Bhargavan et al.'s PQXDH verification would
turn the current implementation claims into analysed ones.

**Private swarm transfer.** A fail-closed BitTorrent extension carrying
p2party sessions over fixed cells — BEP 3/10/27 for the base protocol and
private-torrent semantics, with I2P's ECIES-X25519-AEAD-Ratchet and OneSwarm
as the prior art for what does and does not work.

## Non-goals

- **A hosted service that can read messages.** The signaling server coordinates
  discovery. It is never the message hub, and no feature is worth changing
  that.
- **Backward compatibility across wire breaks.** v4 does not resume v3 peers or
  v3 crypto rows, deliberately. A cryptographic fallback path is a downgrade
  attack surface.
- **Claiming properties that have not been demonstrated.** If a guarantee is
  not tested, it does not go in the README.

## Contributing

The near-term list is where help is most useful, particularly the verification
harnesses and the module-graph cleanup. See
[CONTRIBUTING.md](CONTRIBUTING.md); report security issues privately via
[SECURITY.md](SECURITY.md).
