# Roadmap

Direction, not a schedule. Nothing here is promised by a date — the only dates
below say when a measurement or an observation was taken — and anything in
"Research directions" may turn out to be a bad idea once it is studied
properly. What the current source release contains is described in the
[README](README.md) and bounded honestly in the
[protocol-v4 security boundary](docs/protocol-v4-security.md).

Citation numbers refer to [docs/references.md](docs/references.md).

## Where things stand

The SDK `0.14.10` includes durable sender recovery, selective scheduled receipts,
sparse-PQ overlap handling, and disabled secret-bearing DevTools integration.
Signaling server `0.1.3` or newer provides membership snapshots and targeted mesh
repair. Local verification results and remaining limits are recorded in
[the browser harness report](docs/e2e/README.md).

This remediation does not publish, deploy, or push any repository. A site must
vendor the tested SDK tarball and the deployed signaling server must be upgraded
before the new recovery behavior can be claimed for that deployment.

- protocol v4 — hybrid interactive 3DH plus ML-KEM bootstrap. The two secrets
  are combined by `HKDF-Extract` over a fixed-order concatenation —
  `3DH ‖ ML-KEM`, or `CPace-ISK ‖ 3DH ‖ ML-KEM` in a PIN room — expanded under
  a domain separator that names the mode and the ML-KEM parameter set. It is
  not an XOR, and it is deliberately not X-Wing: see the comment and
  `hybridKdfDomain` in `src/handlers/handshakeCore.ts`. Three chained
  confirmation flights and a per-edge Double Ratchet follow;
- session-scoped Ed25519 identity anchoring — an edge authenticates against
  the Ed25519 key the signaling roster supplied for that session
  (`handleWebSocketMessage.ts` copies `message.peers[i].publicKey` into
  `peerPublicKey`, and the handshake reads it back as
  `epc.withPeerPublicKey`). The SDK has no automatic trust-on-first-use store.
  The one durable pin is the opt-in address book —
  `addPeerToAddressBook` plus `onlyAllowConnectionsFromAddressBook`, which the
  application must switch on per room — and it filters who a room stays
  connected to rather than being checked inside the handshake;
- sparse post-quantum healing — the OFFER/ADVANCE/ACK epoch exchange, with
  persist-before-dispatch and application traffic blocked mid-exchange;
- room-wide scheduled timing cover — policy-pinned cadence, lanes, and frames
  per cell, emitted whether or not there is data to send;
- reliable transfer — authenticated receipts, selective retries and a bounded
  durable sender outbox. Prepared sends survive page reloads in the same browser
  storage and identity; abandoned preparation does not. Per-recipient outcomes,
  fenced ownership and explicit pause/cancel semantics preserve recovery while
  limiting storage and retries. `MAX_MESSAGE_SIZE` enforces a 10 GiB ceiling,
  an enforced limit rather than a demonstrated transfer size;
- a store-free `p2party/session` API for non-browser transports.

One caveat belongs here rather than in a footnote. The post-connect DTLS
fingerprint tripwire — comparing the live certificate from `getStats()` against
the fingerprint in the SDP — is **skipped** on engines that report no
`transport` or `certificate` statistics, which today means Firefox
(`src/handlers/handleHandshake.ts`). The library warns once per session and
continues. What survives there is the transcript binding: both SDP fingerprints
are authenticated inside the handshake, so a rewritten SDP still produces a
transcript both peers reject. What is lost is the narrower check that the DTLS
transport terminates on the certificate the SDP advertised.

## Near term

### Known open, in priority order

1. **Compatibility with older signaling servers.** Socket-generation recovery
   needs server `0.1.2` or newer; correlated membership and targeted per-member
   repair need `0.1.3`. Older servers cannot supply those missing facts. Retry
   ceilings bound failures without guaranteeing convergence.
2. **Existing limits.** Import cycles, unexecuted ProVerif verification and
   Firefox's missing post-connect certificate statistics remain. Recovery
   latency outside the measured loopback scenarios is not established.

C6, C9/C11, C10 and selective scheduled receipts are implemented in the current SDK.
Their acceptance tests and explicit limits are tracked in the
[browser report](docs/e2e/README.md). No general sublinear system cost is claimed:
ACK membership checks are constant-time, but snapshot size, staged-index scans
and fixed cover traffic still scale with their respective inputs.

**Close the verification gaps.** Three properties are implemented and believed
correct but still not demonstrated end to end: PIN backoff escalation under
repeated wrong PINs, packet-trace indistinguishability at n > 2, and cover
behaviour across a real network rather than loopback. Claims stay out of the
README until a harness demonstrates them.

The recovery harness is committed at `docs/e2e/desync/`. It uses separate
Chromium processes and floods the frozen peer's UDP receive buffers, so a
process freeze also exercises the lost network traffic that made the original
split reproducible. Current results, including in-flight immediate and scheduled
transfers, are recorded in [the E2E report](docs/e2e/README.md).

The historical responder-transfer case took roughly 37 seconds to reconverge.
The rebind authentication deadline now rebuilds an association that cannot
complete its new handshake. In the current responder-freeze 8 MiB arm,
mutual authentication returned at 12.023 seconds and bidirectional delivery
verification completed at 15.497 seconds; the transfer was byte-exact and the
sender reported delivery. These are measurements, not a general network bound.
The new mesh scenario covers three browser peers on loopback. It does not
establish traffic-analysis resistance or recovery bounds on real networks.

**Independent security audit.** The protocol has had no third-party review.
This is the single most valuable thing that could happen to the project, and
no amount of internal testing substitutes for it.

**Untangle the module graph.** 15 elementary import cycles remain, all of them
in the same runtime cluster: `store.ts`, the RTK Query layer
(`api/signalingServerApi.ts`, `api/webrtc/*`), and the handlers. Re-measured on
2026-09-02 with `npx --yes madge --circular --extensions ts src/index.ts`; an
earlier count of 62 was taken on 2026-07-27, and an earlier estimate of
"roughly eleven" counted clusters rather than cycles. The number moves; the
cluster does not. They are latent initialization-order hazards, not current bugs —
but they are also what stands between the SDK and a second rendezvous
transport, since no board client can reuse the peer-connection handlers without
importing the WebSocket API.

**Identity backup and restore.** The SDK flow now exists:
`createRecoverableIdentity()`, `restoreIdentityFromMnemonic()` and
`getIdentityBackupStatus()` create, adopt and describe an identity derived from
a recovery phrase, with tests over the ordering the swap depends on. See
[Back up and restore your identity](README.md#back-up-and-restore-your-identity).
The derivation is one way, which is the residue: an identity generated randomly —
every identity that existed before these calls — cannot be exported, only
replaced, and replacing it is an identity-key change every contact sees. There
is no migration for those users beyond that trade. The p2party.com application
provides the create/restore flow and explains that replacing a random identity
changes the key seen by contacts.

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

This one has a written architecture ahead of the others:
[the L2 blind-rendezvous spec](spec/spec-architecture-l2-blind-rendezvous.md)
covers the presence board, pairwise inboxes, tiers, and release gates. An
annotated bibliography of the verified prior art behind it is maintained
alongside the spec but is not published in this repository.

It also has code. `src/blindRendezvous/` holds 31 modules and roughly 21,000
lines with 29 test files behind them — the operation codec, admission policy,
presence projection, carrier envelope and derivations. None of it is exported
from `src/index.ts`, nothing outside that directory imports it, and
`src/utils/roomConnectAdmission.ts` still throws
`"Private rendezvous room connections are not wired yet"` for any
`rendezvousMode` other than `legacy-signaling`. So: implemented components,
unwired, held behind the spec's own release gates rather than behind missing
code.

Since September 2026 those components have also been shown to fit together. A
flagged prototype in a further directory, `src/blindRendezvous/prototype/`, runs
two headless browsers that share nothing but a 32-byte room capability against
two store processes with no signaling server anywhere in the test: presence and
the four pair flights are carried blind, a WebRTC edge opens from the exchanged
SDP with DTLS verified on both sides, the existing protocol-v4 session runs over
it, and messages round-trip byte-exact — including with one store killed, one
store lying, and one browser able to reach only one of the two. It changes
nothing above: the prototype is not exported either, its stores refuse to start
without two environment flags, its bytes say `prototype-v0` rather than any
release version, its admission and allocation are open, and two store processes
on one laptop are one fault domain. It demonstrates a shape rather than
establishing a property, and
[`docs/blind-rendezvous-two-store-prototype.md`](docs/blind-rendezvous-two-store-prototype.md)
opens by saying at length what it does not claim.

**Finding peers across independently operated servers.** A room today lives on
exactly one signaling service. Federating discovery is what makes self-hosting
useful to anyone but the host, and it is also the precondition for the
strongest privacy tier: read privacy against a single malicious server is
achievable, write privacy against one is not, so trust-splitting needs a second
operator who is not us. The prior art here is mostly cautionary — Matrix
replicates full room state to every participating homeserver, Nostr relays
receive each client's interest graph in plaintext, and libp2p's rendezvous
protocol registers under plaintext namespaces — so the open question is how to
cross a server boundary without turning each additional server into another
observer. Binding rooms to boards rather than users to home servers appears to
avoid a server-to-server protocol entirely — unless robust private writes are
audited in the manner of Express, which needs a replica-to-replica channel
inside a board group. Whether that avoidance survives contact with abuse
control and availability is unproven.

**Censorship resistance for the rendezvous path.** Distinct from blindness: an
adversary who cannot read the board can still stop clients from reaching it,
and a design that requires contacting several servers fails closed when they
are blocked. The work is multi-route board access, resistance to active
probing, and enough board diversity that no single jurisdiction or CDN is the
blocking target. Snowflake (USENIX Security 2024) is the deployed precedent
worth studying closely, since it already does broker-mediated WebRTC
circumvention at scale.

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
`ts-mls` for a browser implementation) is the obvious comparison; the
post-quantum framing is Connell et al., _A Quantum-Safe Private Group System
for Signal from Key Re-Randomizable Signatures_
([ePrint 2026/453](https://eprint.iacr.org/2026/453), preprint, presented at
Real World Crypto 2026), which rebuilds the Signal Private Group System on
ML-DSA-based re-randomizable signatures.

**Formal analysis.** The handshake is interactive, adds CPace and transport
binding, and uses its own domain-separated combiner — so none of the existing
PQXDH or Double Ratchet proofs transfer to it directly. A ProVerif or
CryptoVerif model in the style of Bhargavan et al.'s PQXDH verification would
turn the current implementation claims into analysed ones.

A first step exists and is explicitly not a proof. `formal/proverif/` holds an
838-line symbolic model of the no-PIN pairwise bootstrap after triple
confirmation, with `PROFILE_BASELINE` and `PROFILE_THREAT` query profiles in
the C-preprocessor style of the PQXDH artifact. Both profiles preprocess
cleanly with `cpp -P -traditional-cpp`. **Neither has ever been run**: ProVerif
is not installed, so no parser or solver result has been recorded, and nothing
in it may be cited as a verified property. `formal/proverif/README.md` states
its own limits — the Ed25519 anchor is assumed pre-authenticated, and the
symbolic `hybrid_extract` cannot say anything about whether the real combiner
is robust. Installing ProVerif and getting both profiles through it, traces
reviewed, is the next milestone.

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
