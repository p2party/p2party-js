# Server-blind rendezvous and federated discovery: prior art

Annotated bibliography for the two roadmap items this document precedes:
**server-blind rendezvous** (rooms whose meeting point teaches the operator
nothing about the social graph) and **cross-server peer discovery**
(finding room members across independently operated servers).

Collected and link-verified 2026-07-26. Every entry states its verification
status honestly: VERIFIED means the linked primary source was fetched this
session and its title/authors checked; where a canonical page blocked
automated fetching (usenix.org and ACM DL return 403 to non-browser
clients), the entry says so and cites the mirror that was actually checked.
Entries feed [references.md](references.md) and the README only when the
feature they support ships — reserving a citation is not claiming a
property. Novelty adjudication belongs to
[paper-prior-art-and-related-work.md](paper-prior-art-and-related-work.md);
this file is the raw shelf.

## A. Private presence and private signaling systems

The systems that already solve "meet without the server learning who meets."

- N. Borisov, G. Danezis, I. Goldberg. _DP5: A Private Presence Service._
  PoPETs 2015(2). https://petsymposium.org/popets/2015/popets-2015-0008.pdf
  — VERIFIED. Anytrust multi-server IT-PIR presence (≥1 honest server);
  two-tier epochs (daily registration, minutes-scale presence) carrying
  small authenticated payloads explicitly meant to bootstrap direct P2P.
  Assumes every friend pair already shares a secret; server work is linear
  in the online-user database per query. Preempts "PIR-based blind
  presence" as a novelty claim.
- V. Madathil, A. Scafuro, I. A. Seres, O. Shlomovits, D. Varlakov.
  _Private Signaling._ USENIX Security 2022.
  https://eprint.iacr.org/2021/853 — VERIFIED via eprint (usenix.org
  blocked automated fetch). UC-formalizes the private-notification
  primitive: post to a board so only the intended recipient detects it.
  Two constructions: single server with a TEE, or two non-colluding
  servers running garbled circuits; O(1) client work, server cost linear
  in registered recipients. The definitional cite for "private signaling."
- D. Kaviani, D. Rathee, B. Annem, R. A. Popa. _Myco: Unlocking
  Polylogarithmic Accesses in Metadata-Private Messaging._ IEEE S&P 2025.
  https://eprint.iacr.org/2025/687 — VERIFIED. Asymmetric two-server
  oblivious tree: O(N log² N) server work per epoch, 302x over
  multi-server PIR baselines. The mandated efficiency comparator
  (decision log) for any asynchronous blind drop; epoch-batched, so not
  interactive. Collusion of both servers breaks unlinkability.
- R. Cheng, W. Scott, E. Masserova, I. Zhang, V. Goyal, T. Anderson,
  A. Krishnamurthy, B. Parno. _Talek: Private Group Messaging with Hidden
  Access Patterns._ ACSAC 2020. https://eprint.iacr.org/2020/066 —
  VERIFIED. The closest structural analog to a p2party room: an oblivious
  log per topic, write locations derived from a shared topic secret,
  3-server anytrust IT-PIR reads, fixed-rate polling as cover. 9,433 msg/s
  at 32k users, 1.7 s latency. Topic secrets bootstrap out-of-band —
  exactly the role p2party's room capability already plays.
- S. Angel, S. Setty. _Unobservable Communication over Fully Untrusted
  Infrastructure_ (Pung). OSDI 2016.
  https://www.usenix.org/conference/osdi16/technical-sessions/presentation/angel
  — VERIFIED via the Microsoft Research mirror (usenix.org blocked
  automated fetch). The zero-trust extreme: single fully untrusted server,
  computational PIR (XPIR) with batch codes. Establishes what refusing any
  two-server assumption costs: orders of magnitude more server CPU,
  epoch-synchronized rounds, and rendezvous still assumed out-of-band.
- D. Lazar, N. Zeldovich. _Alpenhorn: Bootstrapping Secure Communication
  without Leaking Metadata._ OSDI 2016.
  https://people.csail.mit.edu/nickolai/papers/lazar-alpenhorn-2016-10-05.pdf
  — VERIFIED (PDF read). Solves stranger introduction (username only, no
  pre-shared secret) via anytrust IBE plus a DP-noised mixnet and per-epoch
  "keywheel" secrets. ~150 s dial latency rules it out for live WebRTC;
  p2party's capability-invite model deliberately stays out of this harder
  problem.
- S. A. Gaballah, C. Coijanovic, T. Strufe, M. Mühlhäuser. _2PPS —
  Publish/Subscribe with Provable Privacy._ SRDS 2021.
  https://arxiv.org/abs/2108.08624 — VERIFIED. Anytrust pub/sub:
  DPF/Riposte-style secret-shared publishes, PIR subscribes, fixed global
  rounds (~5 s, 100k clients). The design point for "room announcements
  without membership leakage," at round-synchronous cost.
- M. Mazmudar, S. Veitch, R. Akhavan Mahdavi. _Peer2PIR: Private Queries
  for IPFS._ IEEE S&P 2025. https://arxiv.org/abs/2405.17307 — VERIFIED.
  Single-server computational PIR against each DHT hop; makes routing,
  provider ads, and retrieval private in a real P2P network, handling
  churn and heterogeneous DBs. Preempts generic "private P2P discovery"
  claims; protects query privacy only.

**Cluster note.** Trust spectrum, cheapest to strongest: anytrust k-of-n
IT-PIR (DP5, Talek, 2PPS) → two-server non-colluding (Private Signaling
GC, Myco) → TEE (Private Signaling variant) → single untrusted server via
computational PIR (Pung, Peer2PIR). All are epoch/round-batched
(seconds to minutes). Sub-second blind WebRTC signaling among
capability-holders is an unclaimed latency point — and p2party already has
the shared secret that DP5/Talek/Pung assume arrives out-of-band.

## B. PIR and distributed point functions

The machinery for private reads and private writes.

- N. Gilboa, Y. Ishai. _Distributed Point Functions and their
  Applications._ EUROCRYPT 2014.
  https://www.iacr.org/archive/eurocrypt2014/84410245/84410245.pdf —
  VERIFIED. The DPF: two keys whose XOR evaluates a point function,
  neither key revealing the point. Foundational for 2-server PIR reads
  AND "PIR writing." Strictly two-server non-colluding.
- E. Boyle, N. Gilboa, Y. Ishai. _Function Secret Sharing: Improvements
  and Extensions._ CCS 2016. https://eprint.iacr.org/2018/707 — VERIFIED.
  The concretely efficient DPF everyone implements: ~λ·log n key size, one
  AES call per tree level — microseconds in WASM, KB-scale keys. The
  workhorse cite for browser-side costs.
- H. Corrigan-Gibbs, D. Boneh, D. Mazières. _Riposte: An Anonymous
  Messaging System Handling Millions of Users._ IEEE S&P 2015.
  https://arxiv.org/abs/1503.06115 — VERIFIED. The canonical private-write
  system: DPF writes into a secret-shared table, plus a third
  non-colluding audit server that zero-knowledge-rejects malformed writes.
  Preempts designs that ignore write-side disruption attacks.
- A. Henzinger, M. M. Hong, H. Corrigan-Gibbs, S. Meiklejohn,
  V. Vaikuntanathan. _One Server for the Price of Two: Simple and Fast
  Single-Server PIR_ (SimplePIR). USENIX Security 2023.
  https://eprint.iacr.org/2022/949 — VERIFIED. LWE-based single-server
  reads at ~10 GB/s/core, but a per-database hint download (121 MB for a
  1 GB DB) that re-downloads on DB change — painful for a churning board.
- M. Zhou, A. Park, E. Shi, W. Zheng. _Piano: Extremely Simple,
  Single-Server PIR with Sublinear Server Computation._ IEEE S&P 2024.
  https://eprint.iacr.org/2023/452 — VERIFIED. PRF-only, sublinear online
  cost — but the client streams the whole DB during preprocessing; only
  browser-realistic where the DB doubles as gossip state.
- S. J. Menon, D. J. Wu. _YPIR: High-Throughput Single-Server PIR with
  Silent Preprocessing._ USENIX Security 2024.
  https://eprint.iacr.org/2024/270 — VERIFIED. No offline hint at all,
  ~2.5 MB total per query: the best cold-start browser fit for a
  join-from-a-link flow against a single server. Reads only.
- S. Angel, H. Chen, K. Laine, S. Setty. _PIR with Compressed Queries and
  Amortized Query Processing_ (SealPIR). IEEE S&P 2018.
  https://eprint.iacr.org/2017/1142 — VERIFIED. Batch PIR via
  probabilistic batch codes: one client fetches k records with ~40x
  amortized speedup — the cite for refreshing many mailboxes in one round.
- B. Chor, N. Gilboa, M. Naor. _Private Information Retrieval by
  Keywords._ ePrint 1998/003. https://eprint.iacr.org/1998/003 —
  VERIFIED. The keyword-PIR bridge: rendezvous lookups are keyed by tag,
  not array offset, so every index-PIR scheme above needs this (or a
  cuckoo-hash descendant) composed on top.

**Cluster note.** The asymmetry that shapes the whole design: single-server
deployments can get *read* privacy (YPIR-class, or trivially by
downloading the board), but *write* privacy fundamentally requires ≥2
non-colluding servers (DPF/Riposte) short of FHE or TEEs. Federated
discovery is therefore not a scaling feature — it is the enabler of
server-blind writes.

## C. Metadata-hiding messaging at scale, and the evaluation bar

- J. van den Hooff, D. Lazar, M. Zaharia, N. Zeldovich. _Vuvuzela:
  Scalable Private Messaging Resistant to Traffic Analysis._ SOSP 2015.
  https://pdos.csail.mit.edu/papers/vuvuzela:sosp15.pdf — VERIFIED.
  Anytrust server chain adding Laplace noise to dead-drop access counts
  ((ε,δ)-DP); every client transmits every round. The origin of the
  synchronized-rounds cover model, and of the dead-drop rendezvous
  template. 37 s latency; DP budget depletes under active attack.
- N. Tyagi, Y. Gilad, D. Leung, M. Zaharia, N. Zeldovich. _Stadium: A
  Distributed Metadata-Private Messaging System._ SOSP 2017.
  https://eprint.iacr.org/2016/943 — VERIFIED. Federates Vuvuzela across
  hundreds of small operators; the lesson for any federated anytrust
  design: honest noise/cover generation must be *verifiable* (ZK
  shuffles), and that verification dominates cost.
- D. Lazar, Y. Gilad, N. Zeldovich. _Karaoke: Distributed Private
  Messaging Immune to Passive Traffic Analysis._ OSDI 2018.
  https://www.usenix.org/system/files/osdi18-lazar.pdf — VERIFIED
  (official PDF). "Optimistic indistinguishability": leak nothing against
  passive adversaries, detect the rounds where active attacks might have
  leaked, and spend noise only then — 5–10x cheaper than paying for active
  adversaries every round. The right budget frame for p2party's cover.
- A. M. Piotrowska, J. Hayes, T. Elahi, S. Meiser, G. Danezis. _The
  Loopix Anonymity System._ USENIX Security 2017.
  https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-piotrowska.pdf
  — VERIFIED (official PDF). Continuous-time Poisson mixing and cover — a
  better fit for asynchronous WebRTC traffic than global rounds — but the
  user's provider sees participation patterns, and see Last Hop below.
- C. Diaz, H. Halpin, A. Kiayias. _The Nym Network._ Whitepaper v1.0,
  2021. https://nym.com/nym-whitepaper.pdf — VERIFIED (whitepaper, not
  peer-reviewed). Deployed Loopix descendant with stake-incentivized
  nodes and Coconut anonymous credentials for paid, private access — the
  make-vs-buy benchmark for outsourcing cover/federation, at seconds-scale
  latency and a token dependency.
- M. Weisenseel, C. Döpmann, F. Tschorsch. _The Last Hop Attack: Why Loop
  Cover Traffic over Fixed Cascades Threatens Anonymity._ PoPETs 2025(2).
  https://petsymposium.org/popets/2025/popets-2025-0067.pdf — VERIFIED.
  Proves loop cover over fixed cascades breaks sender–receiver
  unlinkability. Kills the cheapest tempting design: self-loop heartbeats
  through a fixed signaling path are formally insufficient as cover.
- T. Pulls, E. Witwer. _Maybenot: A Framework for Traffic Analysis
  Defenses._ WPES 2023. https://arxiv.org/abs/2304.09510 — VERIFIED via
  arXiv (ACM DL blocked automated fetch). Defenses as probabilistic state
  machines + simulator (production use: Mullvad DAITA). The substrate the
  cover schedule should be expressed and evaluated in.
- X. Cai, R. Nithyanand, T. Wang, R. Johnson, I. Goldberg. _A Systematic
  Approach to Developing and Evaluating Website Fingerprinting Defenses_
  (Tamaraw). CCS 2014. https://www.cs.sfu.ca/~taowang/wf/Ca-Tamaraw.pdf —
  VERIFIED (author-hosted PDF; DOI 10.1145/2660267.2660362). Provable
  overhead lower bounds and the open-world evaluation frame. A single
  trace ratio (the verified loopback 0.998x) is necessary, not sufficient.

## D. Introduction transports, anonymous tokens, byte-uniform encodings

- M. Thomson, C. A. Wood. _Oblivious HTTP._ RFC 9458, 2024.
  https://www.rfc-editor.org/rfc/rfc9458 — VERIFIED. Relay sees client IP
  but only HPKE ciphertext; gateway sees plaintext but no IP; void if the
  two collude or share an operator. The natural transport for IP-blind
  board writes and token issuance; not a session transport, and it does
  not hide timing.
- A. Davidson, J. Iyengar, C. A. Wood. _The Privacy Pass Architecture._
  RFC 9576, 2024. https://www.rfc-editor.org/rfc/rfc9576 — VERIFIED. The
  Client/Attester/Issuer/Origin taxonomy with per-deployment-model
  unlinkability analysis — the checklist for which p2party server
  pairings would re-enable social-graph recovery.
- T. Pauly, S. Valdez, C. A. Wood. _The Privacy Pass HTTP Authentication
  Scheme._ RFC 9577, 2024. https://www.rfc-editor.org/rfc/rfc9577 —
  VERIFIED. The PrivateToken challenge/response wire format — a
  ready-made frame for presenting anonymous quota tokens instead of
  inventing one.
- S. Celi, A. Davidson, S. Valdez, C. A. Wood. _Privacy Pass Issuance
  Protocols._ RFC 9578, 2024. https://www.rfc-editor.org/rfc/rfc9578 —
  VERIFIED. Type 0x0001 VOPRF (48-byte token, issuer must verify) vs type
  0x0002 Blind RSA (256-byte, *publicly verifiable* — server B can verify
  tokens issued by server A without contacting it). The decisive split
  for cross-server quota.
- A. Davidson, A. Faz-Hernandez, N. Sullivan, C. A. Wood. _Oblivious
  Pseudorandom Functions (OPRFs) Using Prime-Order Groups._ RFC 9497,
  2023. https://www.rfc-editor.org/rfc/rfc9497 — VERIFIED. Blind
  evaluation of PRF(k_server, input) — the primitive for deriving a
  server-specific rendezvous tag without revealing the room secret;
  POPRF's public input is the natural epoch slot.
- S. Hendrickson, J. Iyengar, T. Pauly, S. Valdez, C. A. Wood.
  _Rate-Limited Token Issuance Protocol._
  draft-ietf-privacypass-rate-limit-tokens-06, 2024 — EXPIRED draft.
  https://datatracker.ietf.org/doc/html/draft-ietf-privacypass-rate-limit-tokens-06
  — VERIFIED (text fetched; never became an RFC). Two-party split
  (Attester counts per client-alias, Issuer sees origin, neither sees
  both); collapses under collusion. Blueprint only.
- C. Yun, C. A. Wood, A. Faz-Hernandez. _Anonymous Rate-Limited
  Credentials Cryptography._ draft-ietf-privacypass-arc-crypto-01, 2026 —
  ACTIVE draft. https://datatracker.ietf.org/doc/draft-ietf-privacypass-arc-crypto/
  — VERIFIED. One issuance yields N mutually unlinkable presentations
  with keyed verification: rate-limited anonymous access against a
  SINGLE server, no attester/issuer split — the right tool for the k=1
  deployment. Keyed verification means no cross-server portability; pair
  with Blind RSA for federation.
- The Tor Project. _Tor Rendezvous Specification, Version 3._
  https://spec.torproject.org/rend-spec/ — VERIFIED. The deployed
  standard for blind meeting points: per-epoch key blinding, descriptors
  encrypted under keys derived from the blinded identity, HSDir positions
  unpredictable without the address. The transplantable pattern:
  epoch-rotated derived tags + encrypted descriptors, minus Tor's
  IP-hiding (which comes from circuits, not the rendezvous design).
- F. Günther, D. Stebila, S. Veitch. _Obfuscated Key Exchange._ CCS 2024.
  https://eprint.iacr.org/2024/1086 — VERIFIED. Formalizes
  byte-uniform handshakes; introduces Kemeleon encodings mapping ML-KEM
  keys/ciphertexts to uniform bytes. Load-bearing the moment KEM material
  sits outside an AEAD envelope on a public board; already adjudicated in
  the decision log as "adopt, do not improvise."
- D. J. Bernstein, M. Hamburg, A. Krasnova, T. Lange. _Elligator:
  Elliptic-curve points indistinguishable from uniform random strings._
  CCS 2013. https://eprint.iacr.org/2013/325 — VERIFIED. The classical
  counterpart: X25519 ephemerals as uniform bytes (expected ~2 keygen
  attempts). Any pre-session key material in a server-stored blob should
  be Elligator/Kemeleon-encoded.

## E. Federation and cross-server discovery: deployed systems and their failures

- The Matrix.org Foundation. _Matrix Specification: Server-Server API
  (v1.19)._ https://spec.matrix.org/latest/server-server-api/ — VERIFIED.
  Federation by full state replication: every homeserver in a room
  receives the complete membership list and presence/device EDUs as
  signed plaintext. The anti-pattern baseline: one malicious homeserver
  in a room defeats blind rendezvous entirely.
- M. R. Albrecht, S. Celi, B. Dowling, D. Jones. _Practically-exploitable
  Cryptographic Vulnerabilities in Matrix._ IEEE S&P 2023.
  https://eprint.iacr.org/2023/485 — VERIFIED (note: IEEE S&P 2023, a
  common miscite is USENIX). A single malicious homeserver could add its
  own devices to E2EE rooms because membership is server-managed —
  direct support for p2party's rule that membership must be authenticated
  end-to-end, never delegated to the rendezvous layer.
- P. Saint-Andre. _XMPP: Core_ / _XMPP: IM and Presence._ RFC 6120 /
  RFC 6121, 2011. https://www.rfc-editor.org/rfc/rfc6120 ·
  https://www.rfc-editor.org/rfc/rfc6121 — VERIFIED. Pairwise-edge
  federation: each cross-domain edge is visible to exactly the two home
  servers (plus DNS) — the minimum-leak shape of *addressed* routing,
  still fully non-blind.
- vyzo et al. _libp2p Rendezvous Protocol_ (working draft, rev 1A, 2021).
  https://github.com/libp2p/specs/blob/master/rendezvous/README.md —
  VERIFIED. Register/discover under plaintext namespaces with zero
  privacy machinery — the closest structural analog to today's signaling
  server and precisely the design to beat. The pagination-cookie delta
  polling is worth keeping; the plaintext namespace is not.
- P. Maymounkov, D. Mazières. _Kademlia: A Peer-to-peer Information
  System Based on the XOR Metric._ IPTPS 2002.
  https://pdos.csail.mit.edu/~petar/papers/maymounkov-kademlia-lncs.pdf —
  VERIFIED. Serverless O(log n) lookup at the cost of every path node
  learning (querier, target key), with sybil positioning near any target.
  DHT discovery swaps one omniscient server for many partial observers.
- A. Loewenstern, A. Norberg. _BEP 5: DHT Protocol_ (2008) and
  A. Norberg, S. Siloti. _BEP 44: Storing arbitrary data in the DHT_
  (2014). https://www.bittorrent.org/beps/bep_0005.html ·
  https://www.bittorrent.org/beps/bep_0044.html — VERIFIED. BEP 44's
  ed25519-addressed mutable items (salt slots, sequence numbers, ~2 h
  expiry) are a deployed serverless mutable-mailbox pattern; readers and
  writers still expose IPs and keys to storing nodes.
- The I2P Project. _The Network Database._
  https://i2p.net/en/docs/overview/network-database — VERIFIED (canonical
  geti2p.net URL now 301-redirects here). The most privacy-hardened
  deployed discovery layer: lookups through the client's own tunnels,
  encrypted LeaseSets, daily keyspace rotation — and the documented
  concession that rotation barely slows keyspace-clustering sybils.
  Lesson: blinding by indirection works; target-key clustering remains
  the attack.
- fiatjaf et al. _NIP-01: Basic protocol flow description._
  https://github.com/nostr-protocol/nips/blob/master/01.md — VERIFIED.
  Client-driven multi-homing with no s2s protocol: elegant availability,
  total per-relay leakage (plaintext filters reveal the client's entire
  interest graph). Evidence that multi-server without blinding
  *multiplies* observers instead of splitting trust.
- C. Bocovich, A. Breault, D. Fifield, Serene, X. Wang. _Snowflake, a
  censorship circumvention system using temporary WebRTC proxies._
  USENIX Security 2024.
  https://www.usenix.org/conference/usenixsecurity24/presentation/bocovich
  — VERIFIED via https://www.bamsoftware.com/papers/snowflake/
  (usenix.org blocked automated fetch). The deployed existence proof for
  broker-mediated WebRTC rendezvous at ~100k proxies; structurally
  identical to p2party signaling, and its broker deliberately records no
  IPs — but matching is not blinded, so roommates remain linkable at the
  broker. That last gap is exactly this project's target.

## F. Anytrust, anonymous membership, and abuse control

- D. I. Wolinsky, H. Corrigan-Gibbs, B. Ford, A. Johnson. _Dissent in
  Numbers: Making Strong Anonymity Scale._ OSDI 2012.
  https://dedis.cs.yale.edu/dissent/papers/osdi12.pdf — VERIFIED
  (usenix.org blocked automated fetch; DEDIS PDF checked). The origin of
  the anytrust model: clients trust only that ≥1 of a small set of
  independent servers is honest, without knowing which. Borrow the trust
  model, not the DC-net transport.
- M. Chase, T. Perrin, G. Zaverucha. _The Signal Private Group System and
  Anonymous Credentials Supporting Efficient Verifiable Encryption._
  CCS 2020. https://eprint.iacr.org/2019/1416 — VERIFIED. A single
  untrusted server enforces group access control over an *encrypted*
  membership list (KVACs over encrypted UIDs, ristretto-friendly).
  The strongest single-server membership-hiding design; server still
  trusted for liveness/consistency, and keyed verification does not
  federate — exactly the gap cross-server discovery must fill.
- M. Chase, S. Meiklejohn, G. Zaverucha. _Algebraic MACs and
  Keyed-Verification Anonymous Credentials._ CCS 2014.
  https://eprint.iacr.org/2013/516 — VERIFIED. The primitive underneath:
  issuer-equals-verifier credentials from algebraic MACs, no pairings —
  browser/WASM-practical. Inherently single-verifier.
- P. P. Tsang, M. H. Au, A. Kapadia, S. W. Smith. _Blacklistable
  Anonymous Credentials: Blocking Misbehaving Users without TTPs._
  CCS 2007. https://www.cs.dartmouth.edu/~sws/pubs/akts07.pdf — VERIFIED.
  Ban a flooding client without ever holding a linkable identity: users
  prove in ZK they are not on the ticket blacklist. Cost linear in
  blacklist size; needs windowing or a k-times rate limit at scale.
- G. Connell, S. Faller, F. Günther, J. Hesse, V. Lyubashevsky,
  R. Schmidt. _A Quantum-Safe Private Group System for Signal from Key
  Re-Randomizable Signatures._ ePrint 2026/453 (preprint; RWC 2026).
  https://eprint.iacr.org/2026/453 — VERIFIED. PQ redesign of the Signal
  group system (ML-DSA-based re-randomizable signatures) by Signal + IBM
  Zurich engineers. The argument for keeping any credential layer modular
  from day one. NOTE for ROADMAP.md: the "Signal _Call to Action_ on
  quantum-safe private groups" phrasing there needs a source check — no
  such signal.org page was found; the verifiable anchors are this eprint
  and IBM Research's announcement
  (https://research.ibm.com/blog/signal-threema-quantum-safe, VERIFIED).
- S. Sasy, A. Johnson, I. Goldberg. _TEEMS: A Trusted Execution
  Environment based Metadata-protected Messaging System._ PoPETs 2025(4).
  https://petsymposium.org/popets/2025/popets-2025-0119.php — VERIFIED.
  The TEE counter-design to cite and decline: strictly stronger hiding,
  at the price of putting the hardware vendor in the TCB and having no
  browser story.

## G. Paying for tokens without linking identity

Supporting the idea that quota tokens may be *purchased* (including with
cryptocurrency) rather than granted per identity, without the purchase
linking to token spending.

- D. Chaum. _Blind Signatures for Untraceable Payments._ CRYPTO 1982
  (proceedings pp. 199–203).
  https://chaum.com/wp-content/uploads/2022/01/Chaum-blind-signatures.pdf
  — VERIFIED (PDF title page read). The origin of the whole unlinkable
  token lineage: the issuer signs what it cannot see, so issuance and
  spending cannot be linked. Everything in cluster D descends from this.
- F. Dold. _The GNU Taler System: Practical and Provably Secure
  Electronic Payments._ PhD thesis, Université de Rennes 1, 2019.
  https://taler.net/papers/thesis-dold-phd-2019.pdf — VERIFIED (title
  page read; advisor C. Grothoff). The worked system for
  blind-signature payments with income transparency — the reference
  design if p2party servers ever sell token batches for crypto or fiat
  without learning where tokens are spent.
- See also the Nym whitepaper (cluster C): Coconut credentials are the
  deployed precedent for *paid*, unlinkable access to privacy
  infrastructure.

## What the shelf says, in one paragraph

Reads can be private against a single malicious server; writes cannot —
private writes need ≥2 non-colluding servers, so the federation feature
and the blindness feature are one design, not two. The room capability is
already the pre-shared secret that DP5, Talek, and Pung assume arrives
out-of-band, which lets p2party skip the hardest problem (stranger
introduction, Alpenhorn's) and target an unclaimed point: sub-second,
browser-native, capability-scoped blind rendezvous with k=1 read privacy
degrading gracefully from k≥2 full blindness. Abuse control without
identity is solved per-server by ARC-style rate-limited credentials and
across servers by publicly verifiable Blind RSA tokens, with purchase
(Chaum/Taler lineage) as one pluggable issuance gate. Tor's rend-spec
supplies the tag-blinding and encrypted-descriptor pattern; Riposte the
write-audit pattern; Karaoke the passive/active budget frame; Matrix and
Nostr the federation anti-patterns; and Tamaraw/Maybenot/Last-Hop set the
evaluation bar any cover or unlinkability claim must clear before it may
appear in the README.
