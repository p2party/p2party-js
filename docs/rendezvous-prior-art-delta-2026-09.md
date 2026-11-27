# Literature delta for the two-store server-blind rendezvous prototype

Synthesized 2026-09-07 from eight angle sweeps (private writes, OMR/detection,
presence/PIR, replicated logs/BEC, transports/tokens, deployed systems,
attacks/evaluation, browser feasibility) against the 2026-07-26 shelf
(`docs/rendezvous-prior-art.md`) and the adjudication file
(`docs/paper-prior-art-and-related-work.md`). It serves one decision: how to
build a MINIMUM two-store prototype (two independently operated public-store
processes) that is fault tolerant (f=1: either store may fail, omit, or be
blocked) and "sufficiently private" (each store alone learns no more than the
spec's S1 baseline), behind an internal flag, without inventing v0.4 bytes
(spec line 3392).

Verification discipline. Every sweep ran without WebSearch; discovery went
through ePrint/arXiv/Crossref/OpenAlex/npm/datatracker APIs and a handful of
page fetches. VERIFIED below means the named sweep fetched the primary record
(ePrint/arXiv page, RFC/draft page, vendor README or docs) and checked title
and authors; the venue is quoted from that record unless flagged. Entries
that one sweep listed from memory and no second sweep independently
confirmed were DROPPED (list in section 2.4) rather than carried as
"UNVERIFIED"; the single UNVERIFIED entry retained is one two sweeps agreed on
independently. Numbers are from abstracts or PDFs the sweeps extracted; the
browser DPF figures in cluster B are a sweep's own Node micro-benchmark and
are labelled so. Nothing below is a citation reserved for a shipped feature;
this file feeds `docs/rendezvous-prior-art.md` only after adjudication.

Vocabulary: S1 = the spec's single-carrier safety baseline (a Byzantine store
gets end-to-end confidentiality/authenticity, room isolation, no room id, no
room-equality tag, no membership edge, no stable identity, no SDP/ICE; it does
NOT get availability, completeness, source anonymity, or omission tolerance).
R2-BEC = the spec's client-additive authenticated-union conformance package.
SP1 = the spec's measured source-unlinkability package, which spec line 4206
says OHTTP, Tor, or "two ordinary stores" do not satisfy by name.

---

## 1. New entries, by shelf cluster

### A. Private presence and private signaling systems

- Z. Liu, E. Tromer. _Oblivious Message Retrieval._ ePrint 2021/1256 (2021;
  the USENIX Security 2022 venue was not fetched this sweep).
  https://eprint.iacr.org/2021/1256 — VERIFIED (ePrint listing: id, title,
  authors; OMR sweep). Senders post messages carrying a PVW/LWE "clue"; an
  untrusted server holding a recipient's FHE-encrypted detection key
  homomorphically tests every board message and returns a digest from which
  the recipient recovers exactly its pertinent messages, so the server learns
  nothing about pertinency — strictly stronger than S1 on the read path.
  Detection keys are large (tens to hundreds of MB in the original), server
  work is linear in board size, and a fixed pertinency bound k loses messages
  when exceeded. Group OMR (Liu, Tromer, Wang, ePrint 2023/534, VERIFIED
  listing) extends one post to a group of recipients without the server
  seeing membership. Preempts "server-blind detection over a public board"
  and "group-addressed server-blind posts"; a two-member room can derive one
  clue keypair from the capability and hand each store an unlinkable
  detection key, but browser FHE keygen and MB-scale keys make this a
  phase-2 upgrade, not a minimum.
- Z. Liu, E. Tromer, Y. Wang. _PerfOMR: Oblivious Message Retrieval with
  Reduced Communication and Computation._ USENIX Security 2024 (ePrint
  2024/204). https://eprint.iacr.org/2024/204 — VERIFIED (ePrint page;
  presence/PIR and OMR sweeps agree). Re-engineers OMR: 13.8x faster
  detection circuit and 235x smaller public key than the original, at about
  0.1 s and about 1 KB per message of overhead in the prior work's terms.
  The first OMR point whose per-epoch detection-key upload looks tolerable
  from a browser; the bar any "cheap server-blind read" must beat.
- Y. Jia, V. Madathil, A. Kate. _HomeRun: High-efficiency Oblivious Message
  Retrieval, Unrestricted._ ACM CCS 2024 (ePrint 2024/188).
  https://eprint.iacr.org/2024/188 — VERIFIED (ePrint page; two sweeps).
  Two semi-honest non-colluding servers; removes OMR's pertinency cap (no
  message loss under bursty recipients), gives unlinkable repeated
  retrievals, and lets servers delete retrieved messages. A rendezvous peer
  that re-posts trickle-ICE and reconnect records is exactly the "more
  pertinent messages than the bound" case; HomeRun is the correct citation
  for unbounded per-recipient retrieval, and it needs both servers online.
- K. Lee, Y. Yeo. _SophOMR: Improved Oblivious Message Retrieval from
  SIMD-Aware Homomorphic Compression._ USENIX Security 2026 (ePrint
  2024/1814); H. Liang, Z. Liu, E. Tromer, X. Xie, Y. Yu. _InstantOMR:
  Oblivious Message Retrieval with Low Latency and Optimal
  Parallelizability._ USENIX Security 2026 (ePrint 2025/2317); B. Fisch,
  Z. Liu, E. Tromer, Y. Wang. _UnifOMR: Oblivious Message Retrieval with
  Near-optimal Concrete Efficiency._ ACM CCS 2026 (ePrint 2026/910).
  https://eprint.iacr.org/2026/910 — VERIFIED (ePrint pages; venues from the
  "Publication info" lines; two sweeps). SophOMR is 3.4x faster than PerfOMR
  at 65,536 payloads of 612 B; InstantOMR cuts latency about 860x via TFHE
  functional bootstrapping so detection runs per message as it arrives;
  UnifOMR is 20-1080x faster on the server than SophOMR (2^19 messages of
  612 B in about 25 s with 4 MB communication) and proves OMR with strong
  detection-key unlinkability is at least as hard as PIR. The OMR-not-cheaper-
  than-PIR reduction is the citable reason to stop searching for a clever
  presence beacon that avoids oblivious reads; InstantOMR is the one to read
  if OMR is ever needed, because rendezvous is latency-bound.
- Z. Liu, K. Sotiraki, E. Tromer, Y. Wang. _Snake-eye Resistant PKE from LWE
  for Oblivious Message Retrieval and Robust Encryption._ ePrint 2024/510
  (preprint). https://eprint.iacr.org/2024/510 — VERIFIED (ePrint listing).
  A malicious sender can craft a clue pertinent under two different
  recipients' keys, letting whoever controls posts test whether two detection
  keys belong to related secrets; the paper builds an LWE PKE where no
  ciphertext decrypts validly under two independent keys. In p2party terms
  this is a store-driven co-membership probe; any design that lets clients
  test store-chosen records must MAC records under the room key so crafted
  posts cannot flag.
- G. Beck, J. Len, I. Miers, M. Green. _Fuzzy Message Detection._ ACM CCS
  2021 (ePrint 2021/089), with I. A. Seres, B. Pejo, P. Burcsi. _The Effect
  of False Positives: Why Fuzzy Message Detection Leads to Fuzzy Privacy
  Guarantees?_ ePrint 2021/1180 (preprint; workshop venue not fetched).
  https://eprint.iacr.org/2021/089 · https://eprint.iacr.org/2021/1180 —
  VERIFIED (ePrint listing; FMD's CCS 2021 venue as stated on the 2025/2072
  abstract). FMD gives the server a detection key that matches a recipient's
  posts with probability 1 and everyone else's with tunable rate p, at O(1)
  per message with no FHE; Seres et al. show the resulting cover set shrinks
  fast under intersection over many posts, especially for low-traffic
  recipients. For a two-member room a store that sees whose key flags which
  posts over a few epochs de-anonymises the pair exactly along those lines;
  cite FMD as the rejected cheap option and Seres et al. as the reason.
- C. Goes, Y. Khalniyazova, E. Larraia, X. Song. _Multi-server Fuzzy Message
  Detection._ ePrint 2025/2072 (preprint, revised 2025-11-13).
  https://eprint.iacr.org/2025/2072 — VERIFIED (ePrint page: title, authors,
  abstract). Several servers get different detection keys extracted from one
  secret; the receiver combines their tests locally, so servers can run at
  high false-positive rates while the client ends at a low one; also
  formalises stealth public keys in the FMD setting. The closest published
  object to "two stores each run a coarse test, client intersects" — but it
  degrades to single-server FMD when one store is down and colluding stores
  intersect, so it adds efficiency, not single-store privacy.
- S. Jakkamsetti, Z. Liu, V. Madathil. _Scalable Private Signaling._ ePrint
  2023/572 (preprint). https://eprint.iacr.org/2023/572 — VERIFIED (ePrint
  listing; two sweeps). Successor to the shelf's Private Signaling: one
  TEE-equipped server with oblivious data structures gives polylog(N)
  per-recipient retrieval; under 60 ms per sent message and under 6 s
  retrieval at 1M recipients / 10M messages. The "what you give up without a
  TEE" reference; p2party has no TEE, so this bounds the passive-server
  cost floor rather than offering a design.
- H. Chu, X. Wang, Y. Jia. _Private Signaling Secure Against Actively
  Corrupted Servers._ ePrint 2025/1056 (preprint, 2025-06-06).
  https://eprint.iacr.org/2025/1056 — VERIFIED (ePrint page: title, authors,
  abstract). First TEE-free simulation-secure private signaling with two
  non-colluding servers either of which may be actively corrupt; retrieval
  becomes a PSI-like problem with custom ZK proofs of consistency against
  the public bulletin board; for a 2^19-message board the digest is
  33.57 KB and retrieval takes about 2 minutes on 16 LAN threads. Preempts
  "two independent servers, one may be malicious" and the checkpoint-
  witnessing idea as a technique (its consistency proofs are omission
  detection); its servers must both be online and talk to each other, and
  2 minutes at 2^19 is far too slow for WebRTC rendezvous.
- Y. Jia, D. Das, W. Zhang, A. Kate. _Kerblam: Anonymous Messaging System
  Protecting Both Senders and Recipients._ ePrint 2025/997 (preprint).
  https://eprint.iacr.org/2025/997 — VERIFIED (ePrint listing; two sweeps;
  content read only from the abstract by one). HomeRun plus an oblivious
  shuffle and two-server distributed ORAM so that sender AND recipient are
  hidden. The title alone matters: the whole OMR/FMD/private-signaling line
  protects the recipient only, leaving the writer's source address and
  timing visible to the store — the gap an OHTTP-style role split exists to
  close.
- C. Kocaogullar, D. Hugenroth, M. Kleppmann, A. R. Beresford. _Pudding:
  Private User Discovery in Anonymity Networks._ IEEE S&P 2024 (arXiv
  2311.10825; DOI 10.1109/sp54263.2024.00167).
  https://arxiv.org/abs/2311.10825 — VERIFIED (arXiv record and abstract;
  two sweeps). Private user discovery layered on Loopix/Nym: contact by
  email address only, hidden contact relationships, no impersonation,
  registered usernames concealed; Byzantine fault tolerant as long as fewer
  than one third of discovery servers are crashed or malicious, so n >= 3f+1
  (four servers to tolerate one). The post-DP5 reference for "discovery with
  fault tolerance": tolerating one faulty server while keeping a
  server-blind guarantee via BFT costs four servers, so a two-store prototype
  may claim crash/omission tolerance with detection, never BFT.
- N. Mohnblatt, A. Sonnino, K. Gurkan, P. Jovanovic. _Arke: Scalable and
  Byzantine Fault Tolerant Privacy-Preserving Contact Discovery._ ACM CCS
  2024 (DOI 10.1145/3658644.3670289). https://doi.org/10.1145/3658644.3670289
  — VERIFIED-INDEX (DOI record and abstract; browser sweep). Identity-based
  non-interactive key exchange plus an "unlinkable handshake" on a custom
  consensus-free BFT store: unlinkability, enumeration resistance, no single
  point of trust or failure, per-request cost independent of user count,
  over 1,500 requests/s at under 0.5 s geo-distributed. Its shape — derive a
  shared secret from what both parties already know, then meet at an
  unlinkable location on a replicated store — is architecture A with an IBE
  identity where p2party has a 32-byte capability; it too uses >= 4 servers.
- P. Jiang, Y. Wu, L. Xu, W. Dong, P. Chen, Y. Ming, C. Wang, X. Jia,
  Q. Wang. _Anonymous Messaging Made More Flexible With PingPong._ IEEE/ACM
  Transactions on Networking 2026 (DOI 10.1109/TON.2026.3672821; arXiv
  2504.19566, "Metadata-private Messaging without Coordination").
  https://arxiv.org/abs/2504.19566 — VERIFIED (arXiv record; Crossref DOI;
  two sweeps). Replaces "dial-before-converse" (Vuvuzela/Alpenhorn/Private
  Signaling) with "notify-before-retrieval": a metadata-private notification
  store (Ping) plus a message store (Pong) under uniform traffic, so users
  run many conversations without a coordinated round; TEE-dependent. Already
  in the adjudication file as a preprint; now a journal paper. Its framing —
  a notification store plus a message store — is the rendezvous problem
  restated, and it preempts "notify-then-retrieve without a dialing round".
- Y. Chen, D. Heath, R. Chatterjee, E. Fernandes. _Scalable Metadata-Hiding
  for Privacy-Preserving IoT Systems_ (Mohito). PoPETs 2024(4) (DOI
  10.56553/popets-2024-0135). https://petsymposium.org/popets/2024/popets-2024-0135.php
  — VERIFIED (Crossref; PoPETs PDF text; private-writes sweep). Hides which
  user talks to which device from both an integrator and vendor servers
  using an oblivious key-value store and a fixed user-to-device graph;
  about 24,000 commands/s versus about 40 messages/s for Express in a
  comparable setting. The closest "two-party rendezvous through blind
  servers" in the DPF lineage and evidence that OKVS batching beats
  per-write DPF expansion when the access graph is fixed.

### B. PIR and distributed point functions

Private writes (the Express lineage the shelf stops short of):

- S. Eskandarian, H. Corrigan-Gibbs, M. Zaharia, D. Boneh. _Express: Lowering
  the Cost of Metadata-hiding Communication with Cryptographic Privacy._
  USENIX Security 2021 (arXiv 1911.09215).
  https://www.usenix.org/conference/usenixsecurity21/presentation/eskandarian
  — VERIFIED (arXiv record; USENIX PDF fetched and text-extracted by the
  private-writes sweep; USENIX page title matched by the browser sweep).
  Two-server mailbox system: mailboxes are additively secret-shared, a
  client writes with a 2-party DPF so neither server learns which mailbox,
  secure against any number of malicious clients and ONE malicious
  (non-colluding) server. Mailboxes are addressed by a 128-bit virtual
  address chosen at registration, and the audit enforces that only a holder
  of the address can write there with O(lambda) server-to-server
  communication and O(1) client work; about 20 ms client compute and about
  5 KB per message, over 100x less bandwidth than Pung/Riposte; every write
  costs each server a full-domain DPF expansion over the whole table (about
  40 messages/s in Mohito's comparison). Preempts "two-server DPF writes into
  capability-addressed mailboxes with a two-party audit"; both servers are
  needed for every read, so there is no f=1 availability.
- A. Vadapalli, K. Storrier, R. Henry. _Sabre: Sender-Anonymous Messaging
  with Fast Audits._ IEEE S&P 2022 (DOI 10.1109/SP46214.2022.9833601).
  https://doi.org/10.1109/SP46214.2022.9833601 — VERIFIED (Crossref and
  OpenAlex title/authors/venue; two sweeps agree on the author list; the
  task brief's "Goldberg" was wrong). Replaces Riposte/Express's linear-cost
  write audits with logarithmic-cost ones from verifiable DPFs and
  MPC-in-the-head checks, claiming anonymity sets in the tens of millions
  and an order-of-magnitude concrete speedup; PACL later reports Sabre's
  proofs are about 1,000x larger than DL-based ones. The audit-cost
  baseline for any DPF write that is audited at all; still two servers,
  both online.
- Z. Newman, S. Servan-Schreiber, S. Devadas. _Spectrum: High-Bandwidth
  Anonymous Broadcast._ USENIX NSDI 2022 (ePrint 2021/325).
  https://eprint.iacr.org/2021/325 — VERIFIED (ePrint page states NSDI 22;
  PDF text-extracted; four sweeps). Two-or-more-server DC-net where a few
  broadcasters write and many subscribers send zero-shares as cover; "blind
  access control" lets servers reject a request unless the client proves in
  secret-shared form that it knows the channel key or is sending zero; a
  BlameGame identifies a deviating server; 1 GB to 10,000 subscribers in
  13 h 20 m for about $6.84 on two commodity servers, and more than two
  servers need a seed-homomorphic PRG and are concretely slower. Its audit
  predicate — prove you hold the channel capability without revealing which
  channel — is exactly write authorisation on a room capability, and its
  >2-server mode is the only DPF-lineage design offering a threshold.
- C. Li, H. Wang, X. Mi. _Pepper: High-bandwidth and Scalable Anonymous
  Broadcast with Cryptographic Privacy._ arXiv 2606.04411 (3 June 2026,
  preprint). https://arxiv.org/abs/2606.04411 — VERIFIED (arXiv record; PDF
  text-extracted; two sweeps). Two-server DC-net in the Express/Spectrum
  mould with anonymous channel registration verified jointly via VDPFs (no
  external dialing service), batch writes via distributed multi-point
  functions, and PACL-style secret-shared access proofs; registration
  audits in milliseconds at 16K channels, 1.2-5x PACL's and 13.6-20x
  Spectrum's rate at batch size 8; designed for Tor and Mastodon
  co-deployment. Supersedes Express/Spectrum as the reference two-server
  design as of 2026 and is the closest published analogue of "join a room
  without the servers learning which room"; still two servers, both
  required, with server-to-server audit traffic.
- L. de Castro, A. Polychroniadou. _Lightweight, Maliciously Secure
  Verifiable Function Secret Sharing._ EUROCRYPT 2022 (ePrint 2021/580).
  https://eprint.iacr.org/2021/580 — VERIFIED (Crossref LNCS 2022; ePrint
  page; two sweeps). A 2-party verifiable DPF whose check uses only
  symmetric-key operations, costs about the same as an unverified DPF,
  proves the shares encode SOME point function whatever the payload, stays
  secure with one malicious server, and batches so that verifying many
  pairs costs one exchange. The cheapest known malformed-write audit, and
  the primitive Pepper's anonymous registration is built on; the one
  exchange still requires both stores reachable.
- S. Servan-Schreiber, S. Beyzerov, E. Yablon, H. Park. _Private Access
  Control for Function Secret Sharing._ IEEE S&P 2023 (ePrint 2022/1707),
  with K. Ji, B. Zhang, K. Ren. _Fine-grained Policy Constraints for
  Distributed Point Function._ ePrint 2023/1672 (preprint).
  https://eprint.iacr.org/2022/1707 · https://eprint.iacr.org/2023/1672 —
  VERIFIED (Crossref/OpenAlex; ePrint PDF text; two sweeps). Given only the
  shares of a point function, evaluators check the dealer knows the access
  key for that point without learning which point, via a discrete-log ZK
  proof over secret-shared elements: 50-70x cheaper than Express/Spectrum's
  ad-hoc checks and about 1,000x smaller proofs than Sabre. Ji-Zhang-Ren
  show the S&P 2023 scheme never constrains the payload, so an authorised
  writer can still write junk, and fix it with policy templates over both
  the point and the payload. PACL is "prove you hold the capability for
  this slot" on secret-shared writes; the 2023 break is the warning that slot
  authorisation without payload validation does not stop clobbering.
- H. Corrigan-Gibbs, D. Boneh. _Prio: Private, Robust, and Scalable
  Computation of Aggregate Statistics._ NSDI 2017 (arXiv 1703.06255);
  D. Boneh, E. Boyle, H. Corrigan-Gibbs, N. Gilboa, Y. Ishai. _Lightweight
  Techniques for Private Heavy Hitters_ (Poplar). IEEE S&P 2021 (DOI
  10.1109/SP40001.2021.00048); D. Mouris, C. Patton, H. Davis, P. Sarkar,
  N. G. Tsoutsos. _Mastic: Private Weighted Heavy-Hitters and
  Attribute-Based Metrics._ PoPETs 2025(1) (DOI 10.56553/popets-2025-0017);
  IETF/IRTF _draft-irtf-cfrg-vdaf_ and _draft-ietf-ppm-dap-19_ (2026-07-06,
  "WG Consensus: Waiting for Write-Up"). https://datatracker.ietf.org/doc/draft-ietf-ppm-dap/
  — VERIFIED (Crossref/S2 records; PoPETs PDF; datatracker fetched by two
  sweeps, which read the VDAF revision as -20 and -22 respectively —
  reconcile before quoting). SNIPs let two servers check from shares that a
  contribution is well-formed about 100x cheaper than generic ZK; Poplar
  adds incremental DPFs with per-level sketching; Mastic cuts validation to
  one round between two aggregators. DAP fixes the client -> leader/helper
  transport with per-report HPKE sealing of each share. This is the
  standardised, browser-shipped two-independent-server private-write
  pattern (Firefox/Divvi Up), so "two-server verified secret-shared uploads
  from browsers" is entirely preempted; every audit still needs the two
  servers to exchange verifier shares.
- Divvi Up / ISRG. _divviup-ts_ (@divviup/dap 0.9.1, @divviup/vdaf 0.8.0;
  targets DAP draft-09 / VDAF draft-08; browser bundle via script tag).
  https://github.com/divviup/divviup-ts — VERIFIED (README and package tree
  fetched by two sweeps; npm records). Pure-TypeScript Prio3 sharding and
  FLP proof generation in browsers is shipping code, but the tree contains
  NO Poplar1/IDPF; the Rust `prio` crate (0.18.1-alpha.3, 2026-03-16) has
  IDPF/Poplar1 and is the natural wasm-bindgen source, and npm has no
  DPF/FSS package at all. A DPF write client for the browser must be
  ported or written; the client side is cheap (see next entry) but not
  off-the-shelf.
- E. Boyle, N. Gilboa, Y. Ishai, P. Scholl. _Distributed Point Functions and
  Function Secret Sharing_ (survey). Proceedings of the IEEE 2026 (DOI
  10.1109/JPROC.2026.3719236; arXiv 2607.27696).
  https://arxiv.org/abs/2607.27696 — VERIFIED (Crossref; arXiv record; two
  sweeps). One consolidated reference for DPF/FSS definitions,
  constructions, and the anonymous-messaging application. Supersedes reading
  the shelf's GI14 and BGI16 separately as an implementer's entry point.
  Browser cost anchor (private-writes sweep's own Node v24 micro-benchmark,
  NOT a browser measurement): BGI16 two-party DPF keygen 0.08-0.18 ms for
  domains 2^16-2^32, about 0.4-0.7 KB per key share, single-point eval
  0.04-0.06 ms; naive full-domain evaluation — what a STORE pays per write —
  141 ms at 2^16 slots and 2.4 s at 2^20 in pure JS versus milliseconds in
  Express's Go/C. The client side of DPF writes is negligible; the cost
  lands on the stores linearly in table size and on the store-to-store
  audit round.
- G. Zyskind, A. Yanai, A. Pentland. _High-Throughput Three-Party DPFs with
  Applications to ORAM and Digital Currencies._ ACM CCS 2024 (DOI
  10.1145/3658644.3670292; ePrint 2024/1658), and M. Damie, F. Hahn,
  A. Peter, J. Ramon. _Eliminating Exponential Key Growth in PRG-Based
  Distributed Point Functions._ arXiv 2509.22022 (preprint).
  https://eprint.iacr.org/2024/1658 · https://arxiv.org/abs/2509.22022 —
  VERIFIED (Crossref; arXiv record; private-writes sweep). The first 3-party
  DPF at 2-party cost, secure against a malicious dealer plus one malicious
  evaluator, 40-120x smaller shares than prior 3-party DPFs; Damie et al.
  give practical-key multi-party DPFs under honest majority. Relevant only
  to a later 3-store variant: Zyskind et al. is (3,3)-sharing, not a 2-of-3
  threshold, so it does not by itself give availability.

Private reads (single-server PIR that fits a churning board):

- A. Burton, S. J. Menon, D. J. Wu. _Respire: High-Rate PIR for Databases
  with Small Records._ ACM CCS 2024 (ePrint 2024/1165).
  https://eprint.iacr.org/2024/1165 — VERIFIED (ePrint page). Single-server
  lattice PIR tuned for small records: one record from over 1M 256-byte rows
  costs 6.1 KB online (5.9x less than prior lattice PIR); batch variant
  3.4-7.1x less communication at 200-400 MB/s server throughput. A presence
  slot is a small record, so Respire is the reference cost for an oblivious
  read against ONE store, which keeps fault tolerance because each store is
  queried independently; browser cost unpublished.
- B. Li, D. Micciancio, M. Raykova, M. Schultz-Wu. _Hintless Single-Server
  Private Information Retrieval._ CRYPTO 2024 (ePrint 2023/1733), with
  L. de Castro, K. Lewi, E. Suh. _WhisPIR._ ePrint 2024/266 (preprint).
  https://eprint.iacr.org/2023/1733 — VERIFIED (ePrint pages; two sweeps).
  Removes SimplePIR's client hint by outsourcing hint computation to the
  server with composable-preprocessing HE; about 6.37 GB/s on an 8 GB
  database with no client- or server-side per-client state; WhisPIR is the
  fully stateless variant for ephemeral clients. A rendezvous store churns
  every few seconds, so hint-based PIR (SimplePIR/DoublePIR, Piano, Plinko)
  is the wrong family; hintless/stateless PIR is the right one, and each
  store can be read independently.
- R. Akhavan Mahdavi, S. Patel, J. Y. Seo, K. Yeo. _InsPIRe:
  Communication-Efficient PIR with Server-side Preprocessing._ IEEE S&P 2026
  (ePrint 2025/1352). https://eprint.iacr.org/2025/1352 — VERIFIED (ePrint
  page). First PIR with high throughput, low query communication, and
  silent preprocessing: 5x smaller keys than YPIR, up to 50% less online
  query communication, up to 25% higher throughput, via an LWE-to-RLWE
  ring-packing algorithm; evaluated on IPFS and device enrollment.
  Supersedes YPIR on the shelf for the no-offline-phase single-server
  setting; still MB-class uploads per query.
- M. Hao, W. Liu, L. Peng, C. Zhang, P. Wu, L. Zhang, H. Li, R. H. Deng.
  _Practical Keyword Private Information Retrieval from Key-to-Index
  Mappings._ USENIX Security 2025 (ePrint 2025/210), with S. Celi,
  A. Davidson. _Call Me By My Name: Simple, Practical Private Information
  Retrieval for Keyword Queries_ (ChalametPIR). ACM CCS 2024 (ePrint
  2024/092; DOI 10.1145/3658644.3670271).
  https://eprint.iacr.org/2025/210 · https://eprint.iacr.org/2024/092 —
  VERIFIED (ePrint pages; DOI record; two sweeps). ChalametPIR converts any
  LWE index PIR into keyword PIR through Binary Fuse filters at <= 1.08x
  overhead, 6-11x faster than prior keyword PIR; KPIR reduces keyword to
  index PIR through compact key-to-index mappings, 15-178x less
  communication than ChalametPIR and 47 ms per query on 1M 32-byte entries
  natively. p2party clients know the capability, so a read is a keyword
  lookup; keyword PIR lets a client fetch by tag without the store seeing an
  equality tag, and it supersedes the shelf's Chor-Gilboa-Naor as the
  practical reference.
- B. Li, K. Yang, Q. Liu, B. Xiang, X. Zhou, X. Xie, Y. Yu. _LetoPIR: Fast
  Keyword PIR with Logarithmic Communication._ ePrint 2026/1814 (preprint,
  2026-08-28). https://eprint.iacr.org/2026/1814 — VERIFIED (ePrint page).
  Hintless single-server keyword PIR from HE-encoded k-hot vectors with
  bucket merging; 12.4-17x less communication than SparsePIR on 256 MB-4 GB
  of 256-byte records, 51-185x less than KPIR's client-hint variant. Two
  weeks old and unreviewed: a bound, not a dependency.
- M. Rathee, K. Lee, R. A. Popa. _Verifiable PIR with Small Client Storage._
  IEEE S&P 2026 (ePrint 2025/1714), with L. de Castro, K. Lee.
  _VeriSimplePIR._ USENIX Security 2024 (ePrint 2024/341), and
  Guskind, Hamlin, Little, Roche, Varia. _Single-Server Verifiable PIR with
  Updates and Universally Composable Security._ ePrint 2026/1651 (preprint).
  https://eprint.iacr.org/2025/1714 — VERIFIED (ePrint pages). Verifiable
  PIR binds a possibly malicious server to one well-formed database so it
  cannot answer inconsistently or selectively; client state drops from over
  1 GiB (VeriSimplePIR) to 512 KiB at a 2.5x server cost; the UC paper shows
  game-based VPIR breaks under composition. "Either store may omit" is the
  malicious-server case vPIR addresses, and VeriSimplePIR's principle — any
  digest, even a malicious one, commits to SOME database — is the formal
  version of cross-store checkpoint witnessing; the UC warning applies to
  composing any of this inside a rendezvous protocol.
- A. Davidson, G. Pestana, S. Celi. _FrodoPIR: Simple, Scalable,
  Single-Server Private Information Retrieval._ PoPETs 2023(1) (ePrint
  2022/981); A. Henzinger, E. Dauterman, H. Corrigan-Gibbs, N. Zeldovich.
  _Private Web Search with Tiptoe._ SOSP 2023 (ePrint 2023/1438).
  https://eprint.iacr.org/2022/981 · https://eprint.iacr.org/2023/1438 —
  VERIFIED (ePrint abstracts and DOIs; two sweeps for Tiptoe). FrodoPIR on
  1M x 1 KB rows answers in under 1 s with a client-independent hint;
  Tiptoe searches 360M documents with 145 core-seconds, 56.9 MiB per query
  (74% before the query is typed), 2.7 s, no non-colluding servers. The
  product-scale evidence that single-server PIR is affordable; both are
  hint/offline-heavy, so cite them for feasibility, not as the scheme.
- S. Arunachalaramanan, H. Chen, L. Ren. _PIR: A Tutorial and Survey._
  Proceedings of the IEEE (ePrint 2026/1135, revised 2026-09-06).
  https://eprint.iacr.org/2026/1135 — VERIFIED (ePrint page). Paradigm
  selection and concrete-efficiency comparison across single-server,
  multi-server, preprocessing, keyword, and batch PIR. Read before picking a
  scheme; supersedes piecemeal reading of the PIR shelf.
- A. Hoover, S. Patel, G. Persiano, K. Yeo. _Plinko: Single-Server PIR with
  Efficient Updates via Invertible PRFs._ EUROCRYPT 2025 (ePrint 2024/318).
  https://eprint.iacr.org/2024/318 — VERIFIED (ePrint page). First
  client-preprocessing PIR with worst-case O~(1) updates per entry and an
  optimal r*t = Omega(n) trade-off. Only relevant if a hint-based design is
  chosen despite churn.
- E. Tovey, J. Weiss, Y. Gilad. _Distributed PIR: Scaling Private Messaging
  via the Users' Devices._ ACM CCS 2024 (ePrint 2024/978), and X. Liu et
  al. _Pencil._ NDSS 2024 (arXiv 2403.11166).
  https://eprint.iacr.org/2024/978 — VERIFIED (ePrint/arXiv records; attacks
  sweep; DPIR is already in the adjudication file as a preprint). DPIR
  delegates PIR work to clients and removes misbehaving delegates rather
  than trusting a second server (3.25-4.31x over prior work); Pencil is
  explicitly motivated by "relaxing the non-colluding assumption is still an
  open problem". Cite both as designers abandoning the two-server
  non-collusion assumption rather than defending it.
- Y. Ishai, M. Kelkar, D. Lee, Y. Ma. _Information-Theoretic Single-Server
  PIR in the Shuffle Model._ ITC 2024 (DOI 10.4230/lipics.itc.2024.6).
  https://doi.org/10.4230/LIPIcs.ITC.2024.6 — VERIFIED-INDEX (DOI record;
  browser sweep). A shuffler in front of a single server yields PIR-style
  guarantees information-theoretically. Theoretical backing for why a relay
  in architecture B is more than an IP-hider — and for why it is not one
  either unless it actually mixes, which spec line 4206 already says.

### C. Metadata-hiding messaging at scale, and the evaluation bar

Robust (fault-tolerant) private broadcast — what "survives a bad server"
costs when done properly:

- I. Abraham, B. Pinkas, A. Yanai. _Blinder — Scalable, Robust Anonymous
  Committed Broadcast._ ACM CCS 2020 (DOI 10.1145/3372297.3417261; ePrint
  2020/248), and S. Eskandarian, D. Boneh. _Clarion: Anonymous Communication
  from Multiparty Shuffling Protocols._ NDSS 2022 (DOI
  10.14722/ndss.2022.24141; ePrint 2021/1514).
  https://eprint.iacr.org/2020/248 · https://eprint.iacr.org/2021/1514 —
  VERIFIED (Crossref; ePrint abstracts; two sweeps for Blinder; the brief's
  "CCS 2021" and "PoPETs" were wrong). Blinder: clients commit Shamir-shared
  messages to n servers which open them in random order; fully robust
  (guaranteed output delivery) and censorship-resistant against a global
  active adversary, but needs an honest majority (t < n/4 per Pepper's
  reading); 1M clients on 5 GPU servers in under 8 min. Clarion replaces
  DPF/DC-net writes with a secret-shared multiparty shuffle. This lineage is
  where fault tolerance lives in the private-write literature: robustness
  against a failed or malicious server is bought with 3-4+ servers and an
  honest majority, never with two.
- W. Dong, P. Jiang, H. Duan, C. Wang, L. Zhao, Q. Wang. _Ring of Gyges:
  Accountable Anonymous Broadcast via Secret-Shared Shuffle._ NDSS 2025
  (DOI 10.14722/ndss.2025.240268), and W. Tang, H. Feng, J. Li, Y. Lu,
  Q. Tang. _DumboMix: Robust Asynchronous Anonymous Broadcast Made
  Practical._ ePrint 2026/1699 (preprint, 2026-08-21).
  https://eprint.iacr.org/2026/1699 — VERIFIED (Crossref; NDSS PDF text;
  ePrint page; two sweeps for DumboMix). Gyges: honest-majority four-party
  secret-shared relay with a "silent shuffle" (no online inter-server
  traffic) plus tracing of abusive messages, 1.41-2.32x faster than Clarion
  at 10^5 messages of 32 B-1 KB. DumboMix: asynchronous guaranteed output
  delivery with n servers tolerating floor((n-1)/3) Byzantine ones, and a
  critique that Blinder may reveal a non-negligible fraction of inputs
  unshuffled. State of the art for "writes survive a malicious or absent
  server" is four servers or n >= 3f+1 with BFT-style MPC; both define what
  fault-tolerant AND server-blind costs and both are far above a two-store
  budget.
- M. Rosenberg, M. Shih, Z. Zhao, R. Wang, I. Miers, F. Zhang. _ZIPNet:
  Low-bandwidth anonymous broadcast from (dis)Trusted Execution
  Environments._ PoPETs 2025(1) (DOI 10.56553/popets-2025-0058; ePrint
  2024/1227). https://petsymposium.org/popets/2025/popets-2025-0058.pdf —
  VERIFIED (Crossref; ePrint abstract; PoPETs PDF text). Dissent-style
  any-trust DC-net scaled to hundreds of servers by pushing almost all
  inbound traffic and about 80% of compute to AGGREGATORS that are untrusted
  for privacy; 84 bytes per server per extra cover message; notes Riposte
  "does not practically" and Express "does not at all" support more than two
  servers; uses SGX for performance while anonymity stays any-trust. The
  clean precedent for the role split in architecture B — a party that sees
  sources is untrusted for privacy, a party holding shares never sees
  sources — and the only DC-net in which losing a server is survivable (a
  round is re-run without it), at the price of TEEs.
- S. Langowski, S. Servan-Schreiber, S. Devadas. _Trellis: Robust and
  Scalable Metadata-private Anonymous Broadcast._ NDSS 2023 (DOI
  10.14722/ndss.2023.23088; ePrint 2022/1548).
  https://eprint.iacr.org/2022/1548 — VERIFIED (Crossref; ePrint). A
  mixnet-based robust broadcast with blame protocols: 128 servers deliver
  about 320 bit/s per user. What "robust" costs in the mixnet branch;
  another blame-the-server precedent for checkpoint witnessing.
- Y. Ming, M. Wang, C. Wang, W. Li, X. Jia. _MHcast: Metadata-Hiding
  Multicast With Resilience Against Malicious Clients and Servers._ IEEE
  TIFS 2026 (DOI 10.1109/TIFS.2026.3711782).
  https://doi.org/10.1109/TIFS.2026.3711782 — VERIFIED (Crossref; S2
  abstract; PDF not open). Metadata-hiding multicast from two distributed
  comparison functions with a public mapping, mailbox access control
  against junk writes, and an identification scheme by which honest clients
  help an honest server identify the malicious server; 2-10x the throughput
  of repeated unicast at group size 16. The first Express-style system with
  an explicit "blame the bad server" mechanism — what any cross-store
  witnessing must provide if it is to attribute, not just detect.

Evaluation methodology and attacks the prototype must be measured against:

- S. Sasy, I. Goldberg. _SoK: Metadata-Protecting Communication Systems._
  PoPETs 2024 (article popets-2024-0030; ePrint 2023/313).
  https://petsymposium.org/popets/2024/popets-2024-0030.php — VERIFIED
  (PoPETs index; ePrint number; attacks sweep). Systematises the
  dead-drop/PIR/DPF/mixnet/DC-net space along threat model (global passive
  vs active, fraction of malicious servers, non-collusion), leakage classes
  (presence, round participation, volume, contact graph), and cost model,
  and calls out that round participation and presence remain leaked by most
  "metadata-private" systems. The vocabulary and axes the prototype's
  leakage statement must be written in; preempts calling a dead drop with
  visible polling "metadata-private".
- C. Döpmann, M. Weisenseel, F. Tschorsch. _Progressive Pruning: Analyzing
  the Impact of Intersection Attacks._ arXiv 2410.08700 (preprint, 2024),
  with F. Pérez-González, C. Troncoso, S. Oya. _A Least Squares Approach to
  the Static Traffic Analysis of High-Latency Anonymous Communication
  Systems_ (LSDA). arXiv 1910.07903; S. A. Gaballah et al. _Mitigating
  Intersection Attacks in Anonymous Microblogging._ arXiv 2307.09069; and
  D. I. Wolinsky, E. Syta, B. Ford. _Hang With Your Buddies to Resist
  Intersection Attacks._ arXiv 1305.5236 (CCS 2013 venue not fetched).
  https://arxiv.org/abs/2410.08700 — VERIFIED (arXiv API records; attacks
  sweep). Progressive Pruning is a metric: the size of each party's
  candidate set as an observer intersects "who was online" across
  observations, reported against stream length, population, and
  distribution (large Tor simulations); LSDA gives closed-form profiling
  error versus rounds and volume; buddy sets are the canonical defence.
  Two stores plus one observer is an intersection oracle over (client,
  epoch) pairs seen at both; report the Progressive-Pruning curve and an
  LSDA profiling error for a synthetic population or the "no leak" claim
  will not survive review.
- N. Constantinides. _A traffic analysis attack against Introduction
  Protocol and Onion Services._ arXiv 2602.23560 (preprint, v2 Feb 2026).
  https://arxiv.org/abs/2602.23560 — VERIFIED (arXiv record). A practical
  intersection attack on Tor's rendezvous substrate: because introduction
  circuits are long-lived and deterministically structured, an attacker
  repeatedly probing a target service and intersecting next-hop sets seen
  in narrow INTRODUCE1-to-RENDEZVOUS2 windows identifies each successive
  relay toward the service from a single vantage point per stage; evaluated
  on the live network. The request-to-answer timing window is the join key
  and one vantage point suffices; the p2party analogue is a POST at store X
  followed by a GET at store Y inside a bounded window, so the shelf's
  rend-spec v3 is no longer a "safe" timing reference.
- N. Constantinides, M. Rahimi, S. Nonis. _Hidden Services Protocol for
  Mixnets_ (NymHS). arXiv 2609.01326 (preprint, 1 Sep 2026).
  https://arxiv.org/abs/2609.01326 — VERIFIED (arXiv record). First
  practical receiver-anonymous hidden-service protocol for Loopix-style
  mixnets from single-use reply blocks; shows two attacks that break sender
  or receiver anonymity when the opposing party controls only ONE mixnode,
  adds defences, and evaluates on the Nym code. Reply-path material (the
  SDP answer path) is the weak point and a one-node adversary suffices: the
  answer object must not encode anything derivable from the offer's storage
  location or timing.
- D. Schadt, C. Coijanovic, T. Strufe. _Breaking and (Partially) Fixing
  Onion Routing with Fragmentation._ PoPETs 2026(2) (popets-2026-0120).
  https://petsymposium.org/popets/2026/popets-2026-0120.php — VERIFIED
  (abstract page fetched). Fragmentation, present in every deployed mixnet,
  lets an adversary tag a message by suppressing one fragment and watching
  where the gap reappears; demonstrated on live Nym; a lightweight
  mitigation is proven in a formal fragmentation model. SDP plus ICE exceeds
  one fixed chunk, so an active store can drop a fragment and watch which
  reader retries at the OTHER store: the prototype's retry-on-survivor logic
  is itself the tagging oracle unless retries happen only at epoch
  boundaries and objects are padded to one slot.
- S. Angel, D. Lazar, I. Tzialla. _What's a little leakage between friends?_
  WPES 2018 (arXiv 1809.00111). https://arxiv.org/abs/1809.00111 — VERIFIED
  (arXiv record with venue in the comment field). The "exclusive call
  centre" result: if one of your peers is compromised, it learns whether you
  are talking to someone ELSE this round, re-opening intersection attacks
  against any round-based system; the only fix is a private answering
  machine with a bound on friend count. A compromised co-member, or a store
  seeing a tag read shortly after it was written, leaks presence; polling
  must be constant and independent of hits.
- I. Martiny, G. Kaptchuk, A. Aviv, D. Roche, E. Wustrow. _Improving
  Signal's Sealed Sender._ NDSS 2021.
  https://www.ndss-symposium.org/ndss-paper/improving-signals-sealed-sender/
  — UNVERIFIED (not fetched; two sweeps — deployed-systems and attacks —
  independently cite the same venue, authors, and result, so it is retained
  as a lead; confirm before quoting). Even with sealed sender, delivery
  receipts flow back within a short window, so a statistical disclosure
  attack over a handful of message/receipt rounds recovers the conversation
  edge; proposes ephemeral per-conversation delivery keys. Companion:
  E. Brigham, N. Hopper. _No Safety in Numbers: Traffic Analysis of
  Sealed-Sender Groups in Signal._ arXiv 2305.09799 (S&P 2023 poster;
  VERIFIED via arXiv; already in the adjudication file). A single store
  recovers an (IP a, IP b) edge from write-then-read/ack pairings in a few
  rounds with no identifiers at all: "no identifiers => no edge" is false,
  and only cadence decoupling or IP separation helps.
- A. M. Piotrowska. _Studying the anonymity trilemma with a discrete-event
  mixnet simulator._ arXiv 2107.12172. https://arxiv.org/abs/2107.12172 —
  VERIFIED (arXiv record). The tool for the timing-join experiments the
  memo below asks for.

### D. Introduction transports, anonymous tokens, byte-uniform encodings

- IETF PRIVACYPASS WG. _Batched Token Issuance Protocol._
  draft-ietf-privacypass-batched-tokens-08 (2026-05-04; "AD Evaluation /
  Submitted to IESG for Publication").
  https://datatracker.ietf.org/doc/draft-ietf-privacypass-batched-tokens/ —
  VERIFIED (status, version, and date from the WG document list fetched
  2026-09-07; content from the transports sweep's prior reading). One
  issuance round yields N tokens (arbitrary-batch VOPRF over P-384 /
  ristretto255, or amortised Blind RSA); a P-384 VOPRF token is 146 B on the
  wire, an RSA-2048 token 354 B. Lets a client hold 2 x K tokens (one bundle
  per store) and spend one per write; redemptions at the two stores are
  unlinkable to each other PROVIDED the stores never share a double-spend
  database — sharing one would create the cross-store edge S1 forbids.
- IETF PRIVACYPASS WG. _Privacy Pass Issuance Protocols with Public
  Metadata._ draft-ietf-privacypass-public-metadata-issuance-03 (2026-05-13),
  with _draft-ietf-privacypass-expiration-extension-00_ (WGLC, 2026-05-15)
  and _draft-ietf-privacypass-auth-scheme-extensions-03_.
  https://datatracker.ietf.org/wg/privacypass/documents/ — VERIFIED
  (existence, versions, dates, statuses from the WG page). Binds an
  issuer-visible metadata string (epoch, policy id, tier) into the token via
  a POPRF (RFC 9497) or partially-blind RSA; the origin can require the
  value without learning anything else, and the expiration extension makes
  stale tokens useless after an epoch rolls. Gives "at most R writes per
  epoch per credential" at each store with no cross-store state and no
  stable identity, matching the epoch semantics of architecture A.
- IETF OHAI WG (concluded). _Chunked Oblivious HTTP Messages._
  draft-ietf-ohai-chunked-ohttp-08 (2026-02-18; RFC Editor queue), and
  T. Pauly, T. Reddy. _Discovery of Oblivious Services via Service Binding
  Records._ RFC 9540 (2024-02).
  https://datatracker.ietf.org/wg/ohai/documents/ — VERIFIED (statuses and
  dates; WG concluded). Chunked OHTTP streams encapsulated request and
  response bodies under one HPKE context, which a long-poll "wait for the
  other side's SDP" behind a relay needs (base RFC 9458 is strictly one
  request, one response); RFC 9540 moves gateway key discovery into
  SVCB/HTTPS records. Per-exchange overhead with X25519/HKDF-SHA256/
  AES-128-GCM is under 110 B. Architecture B is implementable with fetch()
  plus a JS HPKE library, but only as request/response or chunked streaming
  — no WebSocket through a relay, and no further transport-privacy features
  are coming from OHAI.
- IETF PRIVACYPASS WG. _draft-ietf-privacypass-key-consistency-01_
  (2023-07-10) and _draft-ietf-privacypass-consistency-mirror-00_
  (2024-01-30) — both EXPIRED.
  https://datatracker.ietf.org/wg/privacypass/documents/ — VERIFIED (expired
  status). An OHTTP gateway or token issuer that serves different keys to
  different clients partitions its anonymity set (split-view); the drafts
  surveyed transparency logs, mirrors, and shared caches and did not
  converge; RFC 9540 relocates discovery, it does not solve consistency. A
  two-store prototype inherits this hole twice (each store's HPKE key and
  each store's issuer key); the cheap fix is to have each store witness a
  signed digest of the other's current key set alongside its checkpoints.
- IETF MOQ WG. _Privacy Pass Authentication for Media over QUIC._
  draft-ietf-moq-privacy-pass-auth-03 (2026-07-06; WG document).
  https://datatracker.ietf.org/doc/draft-ietf-moq-privacy-pass-auth/ —
  VERIFIED (existence, version, date, status). MoQ relays accept an RFC
  9577 PrivateToken as authorisation for subscribe/publish on a track
  namespace, so a relay admits and rate-limits clients without learning
  who they are. The nearest standardised analogue of token-gated
  writes/reads on a pub/sub relay, i.e. a p2party public store; copy its
  per-namespace challenge and one-token-per-operation flow, but note it
  does not hide the namespace from the relay.
- Google Chrome. _IP Protection_ (two-hop MASQUE proxy for third-party
  traffic in Incognito; proxy A by Google, proxy B by a partner CDN;
  token-gated with approximate expiration; launch no sooner than July
  2025). https://github.com/GoogleChrome/ip-protection — VERIFIED (README
  fetched by the browser sweep; the transports sweep cites it from memory).
  No single party sees both the user's IP and the destination; access is
  gated by blind-signed tokens with per-user quotas; fail-closed by policy.
  The role split of architecture B deployed at scale by a browser vendor,
  always with two organisationally independent operators and a token gate;
  its fail-closed default is the opposite of "either store may fail".
- Apple Machine Learning Research. _Combining Machine Learning and
  Homomorphic Encryption in the Apple Ecosystem_ (2024-10-24) and
  _swift-homomorphic-encryption_ (BFV keyword PIR for Live Caller ID Lookup
  and Network Extension URL filters).
  https://machinelearning.apple.com/research/homomorphic-encryption ·
  https://github.com/apple/swift-homomorphic-encryption — VERIFIED (post
  and README fetched by two sweeps; no performance numbers on either page).
  The client encrypts its keyword under BFV; Apple's server evaluates
  keyword PIR without learning the query; requests travel through a
  third-party OHTTP relay so the PIR server never sees the source IP and
  the relay never sees the query. Architecture B plus single-server keyword
  PIR in production: "server learns no query, relay learns no content" is an
  established guarantee, and the chain is serial — a down relay or PIR
  server breaks the lookup, remedied operationally, not by protocol.
- P. Sattler, J. Aulbach, J. Zirngibl, G. Carle. _Towards a Tectonic Traffic
  Shift? Investigating Apple's New Relay Network._ arXiv 2207.02112 (PAM
  2022 venue not fetched), and M. Flynn, F. Bronzino, P. Schmitt. arXiv
  2307.04009 (egress-IP geolocation friction).
  https://arxiv.org/abs/2207.02112 — VERIFIED (arXiv records; attacks
  sweep). iCloud Private Relay's ingress and egress are operated by disjoint
  providers, yet ingress addresses are enumerable (1,586 IPv4 / 1,575 IPv6
  via EDNS0 and RIPE Atlas), so relay users are passively detectable, and
  both hops are contractually chosen by one party. For architecture B:
  "independent" is a business fact, not a cryptographic one, and the split
  itself is observable.
- R. Chairattana-Apirom, N. Döttling, A. Lysyanskaya, S. Tessaro.
  _Everlasting Anonymous Rate-Limited Tokens._ ePrint 2025/1030 (Springer
  chapter DOI 10.1007/978-981-95-5119-4_14; proceedings volume not
  fetched). https://eprint.iacr.org/2025/1030 — VERIFIED (ePrint listing).
  A user obtains a token dispenser once and derives up to k unlinkable,
  publicly verifiable tokens per period; "everlasting" means unlinkability
  holds even against an issuer that later becomes computationally
  unbounded. Follow-ons, all VERIFIED as ePrint listings with venues not
  fetched: SMA2RT (Lysyanskaya, Nolan, ePrint 2026/518), Atlantis (Baldimtsi,
  Yadav, ePrint 2026/1248, lattice-based with private metadata bit),
  Kemmoe-Lysyanskaya-Nguyen (ePrint 2026/1649), Kretzler-Li-Ogreanu (ePrint
  2025/2263, AsiaCCS 2026 per DOI 10.1145/3779208.3785269),
  Baldimtsi-Hanzlik-Nguyen-Yadav (ePrint 2025/430), and the analysis
  H. Chu, K. Do, L. Hanzlik. _On the Security of Rate-limited Privacy
  Pass._ ePrint 2023/1805 (CCS 2023 venue not fetched), which finds design
  flaws in the shelf's expired rate-limit-tokens draft as specified. The
  concrete abuse-control primitive for two stores: one dispenser issued at
  invite time, k tokens per epoch, publicly verifiable at either store,
  unlinkable across them, with the "k total vs k per store" choice made
  explicit because k per store doubles flood capacity when one store is
  blocked.
- T. Meunier. _ohttp-ts_ 0.5.2 (2026-08-26; RFC 9458 with the chunked
  extension; deps bhttp-ts, hpke, quicvarint); Cloudflare.
  _@cloudflare/privacypass-ts_ 0.9.0 (2026-06-05), _blindrsa-ts_ 0.4.6,
  _voprf-ts_ 1.0.0; A. Daisuke. _hpke-js_ / @hpke/core 1.9.0 (2026-03-08;
  RFC 9180 over WebCrypto, passes the CFRG vectors; @hpke/ml-kem 0.3.0 and
  @hpke/hybridkem-x-wing 0.7.0 marked experimental); P. Miller.
  _noble-post-quantum_ 0.7.1 (2026-08-27).
  https://github.com/dajiaji/hpke-js · https://github.com/paulmillr/noble-post-quantum
  — VERIFIED (npm records and READMEs fetched by the browser sweep).
  hpke-js runs the same code in browsers and Bun; noble-post-quantum's own
  Apple M4 pure-JS figures are ML-KEM-768 keygen 4,661 ops/s and
  encaps+decaps 4,089 ops/s (pk 1,184 B, ct 1,088 B), ML-DSA-65 sign 294
  and verify 610 ops/s (sig 3,309 B), x/ed25519 sign 6,157 and verify 1,255
  ops/s. Every sealing, relaying, and token primitive the three
  architectures need exists as maintained TypeScript as of Aug 2026; PQ
  sealing is a bandwidth line item (about 1.1 KB per object), not a
  feasibility question, and "HPKE/PQ in the browser" is not claimable.
- D. Huigens, F. Skokan (eds). _Modern Algorithms in the Web Cryptography
  API._ WICG Draft Community Group Report (2026-09-03), with Chrome
  "Algorithm Updates in WebCrypto" (chromestatus 5198951632470016: status
  Proposed; prototype M150, origin trial M151, ship M154; WebKit position
  "neutral", issue 641 closed 2026-04-28).
  https://github.com/WICG/webcrypto-modern-algos — VERIFIED (draft fetched;
  chromestatus API; MDN BCD 8.1.0 dump parsed; WebKit issue via GitHub API).
  Adds ML-KEM, hybrid KEMs, ML-DSA, SLH-DSA, ChaCha20-Poly1305, SHA-3,
  Argon2 and more to SubtleCrypto, none mandatory and not a W3C Standard;
  MDN BCD has zero ML-KEM/ML-DSA entries in any browser, while X25519
  (Chrome 133 / Firefox 130 / Safari 17) and Ed25519 (Chrome 137 /
  Firefox 129 / Safari 17) are native. The platform floor: HPKE(DHKEM-X25519)
  and Ed25519 checkpoint signatures cost nothing extra; PQ must come from
  JS/WASM until at least Chrome 154.

### E. Federation and cross-server discovery: deployed systems and their failures

- M. Buus and Holepunch Inc. _HyperDHT / Hyperswarm_ (substrate of Keet).
  https://docs.pears.com/building-blocks/hyperdht — VERIFIED (docs page
  fetched; it documents the API, not a privacy model). Topics are 32-byte
  buffers, typically hashes; `announce(topic, keyPair)` registers a keypair
  under the topic on the closest DHT nodes, `lookup(topic)` returns
  announcers, connections are Noise-encrypted and hole-punched with DHT
  nodes as introducers. A storing node learns the exact topic (in Keet's
  usage a hash of the room secret, a room-equality tag), the announcer's
  stable public key and IP, and every querier's IP plus topic. The "not
  blind" reference point on every S1 axis except content; browsers cannot
  join a UDP DHT, so any DHT design needs a bridge that becomes the store
  one is trying to blind. Redundancy pattern (any k-closest node suffices)
  is what architecture A reproduces with k = 2.

### F. Anytrust, anonymous membership, and abuse control

- M. Kleinstein, R. Wahby, Y. Gilad. _Sybil-Resistant Parallel Mixing_
  (BalancedMixnet). PoPETs 2025(2) (popets-2025-0149).
  https://petsymposium.org/popets/2025/popets-2025-0149.php — VERIFIED
  (abstract page fetched). In stratified parallel mixnets Sybil clients can
  steer already-mixed messages onto one victim server and stall delivery
  for everyone; the fix is an anonymous credential proving the message
  comes from a valid client, was routed along a protocol-chosen uniformly
  random route, and is not a replay, with issuance cost amortised. The
  abuse-control pattern for two independent stores: bind the token to a
  server-verifiable random choice so a Sybil cannot concentrate load on one
  store or bucket while staying unlinkable.
- Z. Lu, Y. Cui, S. Lu. _WhiteCloak: How to Hold Anonymous Malicious
  Clients Accountable in Secure Aggregation?_ NDSS 2026 (DOI
  10.14722/ndss.2026.230142). https://doi.org/10.14722/ndss.2026.230142 —
  VERIFIED (Crossref; NDSS PDF). Blacklisting of anonymous-credential
  clients that submit malformed shares, under 2 s and 0.03-0.1 KB per client
  at 500 clients / 25 blacklisted. The 2026 cost anchor for holding
  anonymous writers accountable without identity; only needed if writes are
  secret-shared (architecture C).
- Y. Zhang, A. Cheu, A. Gascon, D. Moghimi, P. Schoppmann, M. Schwarz.
  _SNPeek: Side-Channel Analysis for Privacy Applications on Confidential
  VMs._ NDSS 2026 (DOI 10.14722/ndss.2026.240699).
  https://doi.org/10.14722/ndss.2026.240699 — VERIFIED-INDEX (DOI record;
  abstract not read). Side-channel analysis of privacy applications on
  confidential VMs. Undercuts the shelf's TEE counter-design (TEEMS,
  Scalable Private Signaling) for a small operator and supports choosing a
  cryptographic split over an enclave split.

### G. Paying for tokens without linking identity

No new entries. None of the eight sweeps surfaced anything that changes the
Chaum / Taler / Coconut line on the shelf; the token developments above
(batched issuance, public metadata, everlasting rate-limited tokens) are
issuance mechanics, not payment.

### H. Replicated logs and Byzantine eventual consistency (new cluster)

What a client with two untrusted stores can and cannot detect; none of this
lineage was on the shelf even where the work is old.

- M. Kleppmann, H. Howard. _Byzantine Eventual Consistency and the
  Fundamental Limits of Peer-to-Peer Databases._ arXiv 2012.00472 (2020).
  https://arxiv.org/abs/2012.00472 — VERIFIED (Kleppmann publications list
  fetched). Defines BEC for replicated databases with an ARBITRARY number of
  Byzantine nodes: achievable iff honest nodes form a connected graph (no
  f < n/3 bound, Sybils harmless to safety), and impossible to preserve
  global invariants such as uniqueness without consensus; mechanism is a
  content-addressed hash-DAG reconciled by exchanging hashes/Bloom filters.
  The exact model for two stores: the client is the honest node, both
  stores are possibly-Byzantine replicas of a grow-only set of
  capability-AEAD'd content-hashed entries, safety needs no quorum,
  liveness needs one honest reachable store; and "one offer per room per
  epoch" cannot be enforced, so concurrent offers must be tie-broken
  deterministically. Preempts "union over two untrusted stores is safe with
  f = 1 of 2" as a claim — it is a corollary of BEC and of the spec's own
  R2-BEC package.
- M. Kleppmann. _Making CRDTs Byzantine Fault Tolerant._ PaPoC 2022, with
  F. Jacob, S. Bayreuther, H. Hartenstein. _On CRDTs and Equivocation in
  Byzantine Setups._ arXiv 2109.10554, and F. Jacob, H. Hartenstein.
  _Extend-Only Directed Posets and Derived Byzantine-Tolerant Replicated
  Data Types._ arXiv 2304.04318.
  https://martin.kleppmann.com/papers/bft-crdt-papoc22.pdf ·
  https://arxiv.org/abs/2109.10554 — VERIFIED (publications list; arXiv
  listing). Any op-based CRDT becomes BFT against unbounded Byzantine nodes
  if ops are identified by hashes that include predecessor hashes, so
  equivocation degenerates into two concurrent ops; Jacob et al. isolate the
  subclass that is equivocation-tolerant by construction (grow-only sets,
  hash-DAGs; Matrix room DAGs as the running example). A rendezvous mailbox
  as a grow-only set of content-addressed ciphertexts is in that subclass:
  store replays are idempotent, stores cannot forge, and an equivocating
  co-member just posts two entries. What remains p2party's is the S1
  privacy envelope, not the consistency semantics.
- P. S. Almeida, E. Shapiro. _The Blocklace: A Byzantine-repelling and
  Universal CRDT._ arXiv 2402.08068 (2024), with D. Frey, L. Guillou,
  M. Raynal, F. Taïani. _Process-Commutative Distributed Objects: From
  Cryptocurrencies to Byzantine-Fault-Tolerant CRDTs._ arXiv 2311.13936.
  https://arxiv.org/abs/2402.08068 — VERIFIED (arXiv listing; the 2026
  arXiv wave it cites — Gillespie 2607.10305, Brocco 2606.18966,
  O'Connor-Barnes did:crdt 2606.16223, Jacob-Stuber-Hartenstein 2604.23560,
  Dougal ERA 2601.22963 — is VERIFIED as listings only). A signed hash-DAG
  in which equivocation is detectable and excludable by evidence (two blocks
  by one signer with the same predecessor set) while remaining a universal
  CRDT; Frey et al. show FIFO-ordered per-process operations give BFT CRDTs
  without consensus. Blocklace-style ids are the cheap way to make store
  replays and duplicate offers idempotent; the field is active through
  mid-2026 and none of it targets server-blind rendezvous, so the mechanism
  is preempted and only the composition is open.
- L. Chuat, P. Szalachowski, A. Perrig. _Efficient Gossip Protocols for
  Verifying the Consistency of Certificate Logs._ arXiv 1511.01514 (2015),
  and R. Dahlberg, T. Pulls, J. Vestin, T. Høiland-Jørgensen, A. Kassler.
  _Aggregation-Based Certificate Transparency Gossip._ arXiv 1806.08817
  (2018); context RFC 9162 (CT v2, 2021; RFC text not fetched this sweep).
  https://arxiv.org/abs/1511.01514 · https://arxiv.org/abs/1806.08817 —
  VERIFIED (arXiv listings). RFC 9162 specifies signed tree heads and
  log2(n)-hash inclusion/consistency proofs but leaves split-view detection
  to "gossip" that never shipped as a standard; Chuat et al. proposed STH
  pollination through web servers, Dahlberg et al. do it in the network
  (P4 at 10 Gbps). What deployed instead is log-operator diversity (Chrome's
  two-operator policy) and auditing through a trusted party or witnesses.
  Ten years of CT practice concluded a client ALONE cannot detect a split
  view; read-both gives diversity, detection needs cross-observer
  comparison — which p2party gets for free after rendezvous over the
  WebRTC channel.
- S. Meiklejohn, P. Kalinnikov, C. S. Lin, M. Hutchinson, G. Belvin,
  M. Raykova, A. Cutter. _Think Global, Act Local: Gossip and Client Audits
  in Verifiable Data Structures._ arXiv 2011.04551 (2020).
  https://arxiv.org/abs/2011.04551 — VERIFIED (arXiv listing). Google/
  Trillian's formalisation of what clients can audit locally (inclusion,
  consistency, own history) versus what requires gossip; the gossip and
  audit parties explicitly need an anonymous channel so the log cannot
  serve a per-client fork. Directly answers "what a client with two stores
  can detect": omission evidence and inconsistent consistency proofs
  locally, targeted forks only via another observer; preempts "client-side
  audit of two logs".
- C2SP. _tlog-witness_ specification, with Sigsum (https://www.sigsum.org/).
  https://github.com/C2SP/C2SP/blob/main/tlog-witness.md — VERIFIED (spec
  page fetched; Sigsum home page fetched, its threat-model page 404'd; the
  fetched spec summary mentioned ML-DSA-44 cosignature lines of about
  2.4 KB — re-check whether that is a 2026 PQ update, classic cosignature/v1
  being Ed25519). A witness keeps, per log origin, only the latest
  checkpoint (origin, size, root hash, signatures); before cosigning it
  verifies the log signature, that the old size matches its stored
  checkpoint, and an RFC 6962 consistency proof; k-of-n policy is left to
  verifiers, and monitors "must not be possible to partition" from
  witnesses. Sigsum's home page: the design resists an attacker controlling
  the signer's key and distribution plus the log and its hosting. Cross-
  store checkpoint witnessing is literally tlog-witness with n = 2, each
  store witnessing the other, at one checkpoint plus log2(n) hashes per
  interval — but Sigsum's "only cosigned heads are valid" stance would make
  availability depend on both stores, so the prototype must treat a
  cosignature as evidence, never as validity.
- IETF KEYTRANS WG. _Key Transparency Architecture._
  draft-ietf-keytrans-architecture-09 (2026-06-29; submitted to IESG as
  Informational). https://datatracker.ietf.org/doc/draft-ietf-keytrans-architecture/
  — VERIFIED (datatracker fetched). Three deployment modes — Contact
  Monitoring (clients "MUST regularly attempt to detect forks through
  anonymous communication" with the log or peer-to-peer), Third-Party
  Auditing, Third-Party Management (non-collusion assumed) — and an explicit
  statement that a client alone cannot detect split views without an
  auditor, an anonymous channel, or peer gossip. Confirms the architecture-B
  insight that an unlinkable channel is what stops a store keying a split
  view on source IP, and sets the ceiling for two stores without external
  auditors: detection = post-rendezvous peer gossip or mutual witnessing.
  "Anonymous audit channel" is normative WG text, not a novelty.

### I. Deployed identifier-free multi-server messengers (new cluster)

What each server learns, per server, in systems people actually run.

- V. Pamplona et al. _NIP-17: Private Direct Messages_ with _NIP-59: Gift
  Wrap_ (Nostr Implementation Possibilities, 2024, living documents).
  https://github.com/nostr-protocol/nips/blob/master/17.md — VERIFIED
  (NIP-17 fetched 2026-09-07; NIP-59 not fetched; author attribution from
  the repository). A recipient publishes a kind:10050 inbox-relay list of
  1-3 relays; a sender MUST publish only to those relays (one copy each,
  plus one to its own inbox); the message is an unsigned rumor inside a
  sender-signed seal inside a gift wrap signed by a fresh random keypair,
  `p`-tagged to the recipient, with `created_at` randomised up to two days
  back; relays SHOULD serve kind:1059 only to the tagged user under NIP-42
  AUTH. Each relay learns the recipient's long-term pubkey (a stable
  identity and membership anchor), sender IP and arrival time, ciphertext
  size, and which pubkey polls. Architecture A in production — write to
  every store the peer lists, read from any, dedup client-side — so
  multi-relay replication with client union is not claimable; it fails S1
  only because records are addressed by a stable recipient key and reads
  are AUTH-gated. SUPERSEDES the shelf's NIP-01 as the description of Nostr
  private messaging (NIP-04 is deprecated).
- J. Lund / Signal Messenger. _Sealed Sender._ Signal blog, October 2018.
  https://signal.org/blog/sealed-sender/ — VERIFIED (fetched 2026-09-07).
  The server no longer sees the sender identity; it still needs the
  recipient identity to deliver; sending requires a 96-bit delivery token
  derived from the recipient's profile key unless the recipient opts into
  "from anyone"; the post states that resistance to timing and IP
  correlation "are areas of ongoing development". The server learns
  recipient identity, sender IP, time, size, and the delivery-token check.
  The 2018 baseline: hiding the writer's identity from the store is old
  news; the delivery-token idea (prove knowledge of a shared secret to be
  allowed to write) is a cheap anti-spam gate that does not create an
  equality tag if the proof is per-epoch and unlinkable.
- S. J. Lewis and Open Privacy contributors. _Cwtch Security Handbook:
  Server._ docs.cwtch.im (2021-2024).
  https://docs.cwtch.im/security/components/cwtch/server — VERIFIED (server
  page fetched 2026-09-07). The server is assumed malicious; group messages
  are encrypted to a key shared out-of-band; the server is an append-only
  untrusted store reached over Tor onion services, so it sees no IPs and no
  identities; peers joining a group "download all messages from the
  server, and from then on download only new messages". The handbook
  concedes the only known protocol achieving the desired privacy is "the
  server sends everything, and the peers sift through it", that this is
  bandwidth-heavy, and that the server "can track new messages for each
  suspected unique profile" via session patterns. The closest deployed match
  to S1 per server, in production since 2021, so "opaque-blob store with
  client sifting" is not claimable; its two admitted problems — full-scan
  bandwidth and session-level profile clustering — are exactly the
  prototype's, and it never solved multi-server redundancy, so a working
  two-store failover on the Cwtch model is a legitimate engineering
  contribution.
- T. Yu, T. Haines. _Practical Attacks on Session Messenger and Oxen
  Blockchain._ EuroS&P 2026 (ePrint 2026/773; "Published elsewhere —
  EuroS&P"). https://eprint.iacr.org/2026/773 — VERIFIED (ePrint page
  fetched; Session's own whitepaper, arXiv 2002.04609, was cited by the
  deployed-systems sweep from memory and not fetched). First comprehensive
  analysis of Session, whose swarm of service nodes is a REPLICATED
  dead-drop store addressed by a public key behind onion requests: seven
  vulnerabilities, including Oxen consensus flaws allowing network takeover
  "in a realistic setting" (so the non-collusion assumption over the
  storage swarm collapses to whoever wins consensus) and serious flaws in
  group-chat v1, with simulations and mitigations. The one 2026 post-mortem
  of a shipped multi-server dead-drop whose "many independent operators"
  assumption proved capturable: the independence of two stores must be a
  stated, auditable property (operators, ASNs, jurisdictions), not an
  emergent one; and Session's replicated any-of-swarm reads plus
  identity-addressed storage is architecture A minus S1.

What each server learns (per single server; VERIFIED rows only):

| System | Servers per conversation | Client IP | Stable identity / addressable key | Room-equality tag | Edge visible | Content |
|---|---|---|---|---|---|---|
| Nostr NIP-17 | 1-3 inbox relays, replicated | yes (sender and reader, unless Tor) | recipient pubkey (`p` tag, AUTH) | via recipient pubkey | recipient side; sender hidden | no |
| Signal sealed sender | 1 | yes | recipient | via recipient | recipient; sender via receipt timing | no |
| HyperDHT / Keet | k-closest DHT nodes | yes | announcer pubkey | yes (topic hash) | yes (announce + lookup on one topic) | no |
| Cwtch server | 1 per group | no (Tor) | no (session clustering only) | no | no | no |
| Session swarm | swarm, replicated | no (onion requests) | recipient Session ID | via Session ID | recipient side | no |

Only Cwtch reaches S1 per server, and it pays with Tor for the IP column and
with full-store scans for the read path. Nothing verified here is
browser-native and server-blind at once; that combination — S1 per store,
two stores, browser only, no Tor — is a systems gap, not a cryptographic one.

---

## 2. Superseded or corrected shelf entries

### 2.1 Entries whose reading changes

- **Cluster B note ("write privacy fundamentally requires >= 2 non-colluding
  servers ... federation is the enabler of server-blind writes") and the
  one-paragraph summary ("k >= 2 full blindness").** Corrected, not
  retracted: with exactly two servers the DPF route (Riposte, _Express_,
  _Sabre_, _Spectrum_, _Pepper_) buys a hidden write slot only while BOTH
  servers are up — a 2-of-2 additive share is noise without its partner —
  and every robust private-write system (_Blinder_, _Ring of Gyges_,
  _DumboMix_, _Trellis_, Spectrum's >2-server mode) pays for survivability
  with 3-4+ servers and honest majority. Two servers therefore buy EITHER
  slot-hiding OR f = 1 availability, never both. The spec's own model
  (targetless public buckets, fixed-scan reads) removes the room-linked slot
  the DPF would hide, so at two stores the DPF adds cost without adding
  single-store privacy.
- **Riposte (shelf B) as the write-audit reference.** Superseded as the
  reference two-server design by _Express_ (2021) -> _Sabre_ (2022) ->
  _Spectrum_ (2022) -> _Pepper_ (2026); as the audit primitive by
  _Lightweight, Maliciously Secure Verifiable Function Secret Sharing_
  (VDPF) and _Private Access Control for Function Secret Sharing_ (with the
  Ji-Zhang-Ren payload fix); and as the standardised packaging by
  Prio/Poplar/Mastic + DAP/VDAF. Riposte's third audit server is no longer
  needed; the two-party audit round is.
- **Gilboa-Ishai 2014 and BGI 2016 (shelf B).** Superseded as an
  implementer's entry point by _Distributed Point Functions and Function
  Secret Sharing_ (Proc. IEEE 2026 survey). The BGI16 cost line ("microseconds
  in WASM, KB-scale keys") stands for the client; add that the STORE pays a
  full-domain evaluation per write (141 ms at 2^16 slots in naive JS).
- **Private Signaling (shelf A).** Superseded for the passive model by
  _Scalable Private Signaling_ (TEE + ORAM, polylog) and for the active
  model by _Private Signaling Secure Against Actively Corrupted Servers_
  (two non-colluding servers, either actively corrupt, TEE-free, 33.57 KB
  digest at 2^19 messages, about 2 minutes). Both still need both servers
  online.
- **Myco (shelf A).** Not superseded: no successor to the two-server
  polylog mailbox line surfaced in any sweep. Still the mandated efficiency
  comparator; still needs both servers.
- **Talek / DP5 / Pung read model.** Add the _UnifOMR_ result that OMR with
  detection-key unlinkability is at least as hard as PIR: no "presence
  beacon" can be cheaper than an oblivious read, whatever it is called.
  Since p2party clients know the capability, keyword PIR (or a bucket
  download) is the floor and OMR is unnecessary at rendezvous scale.
- **SimplePIR / Piano (shelf B).** Superseded for a churning board by
  hintless and stateless single-server PIR: _Hintless Single-Server PIR_ /
  WhisPIR, _Respire_ (6.1 KB per query on 1M x 256 B), _InsPIRe_.
  **YPIR (shelf B)** is superseded by _InsPIRe_ (5x smaller keys, up to 50%
  less online communication) in the no-offline-phase setting.
  **Chor-Gilboa-Naor keyword PIR (shelf B)** is superseded as the practical
  reference by _ChalametPIR_ and _KPIR_ (47 ms on 1M x 32 B natively) and,
  as a bound, _LetoPIR_.
- **RFC 9458 OHTTP (shelf D).** Add: the OHAI WG has concluded; chunked
  OHTTP (-08, RFC Editor queue) is the streaming variant a relayed long-poll
  needs; RFC 9540 provides SVCB key discovery; and the split-view key
  problem is UNSOLVED at the IETF (key-consistency-01 and
  consistency-mirror-00 both expired). Deployed at scale by Chrome IP
  Protection and Apple Live Caller ID Lookup, always with two independent
  operators and a token gate, and always fail-closed.
- **Rate-Limited Token Issuance draft (shelf D).** The shelf already marks
  it EXPIRED; add that _On the Security of Rate-limited Privacy Pass_
  (ePrint 2023/1805) finds design flaws in the draft as specified, and that
  the rate-limit role is now covered by batched issuance + public metadata
  at the IETF and by _Everlasting Anonymous Rate-Limited Tokens_ and its
  2026 follow-ons in the literature.
- **ARC draft (shelf D, listed as draft-ietf-privacypass-arc-crypto-01,
  ACTIVE, VERIFIED 2026-07-26).** CONFLICT TO RESOLVE, not a correction: the
  transports sweep fetched the PRIVACYPASS WG document list on 2026-09-07
  and found NO ARC draft among active, expired, or related documents, and
  its guessed URL 404'd. Either the WG listing omits it, or the draft was
  renamed or expired between July and September. Re-fetch the shelf's URL
  before citing ARC as adopted; do not build the prototype's quota on it
  either way (batched RFC 9578 tokens carry no such risk).
- **Tor rend-spec v3 (shelf D).** No longer a "safe" timing reference:
  _A traffic analysis attack against Introduction Protocol and Onion
  Services_ (2026) intersects INTRODUCE1-to-RENDEZVOUS2 windows from a
  single vantage point per stage. Keep it for the blinding/encrypted-
  descriptor pattern and for HSDir replication (upload to 8, fetch from any
  of 6, keyed by a per-period blinded key — the canonical precedent for
  write-all/read-any), but note the blinded key is a within-period equality
  tag S1 forbids.
- **NIP-01 (shelf E).** Superseded for private messaging by _NIP-17_ /
  NIP-59 (gift wrap, 1-3 inbox relays, AUTH-gated reads); the shelf's
  "plaintext filters reveal the interest graph" lesson still holds for the
  public-event path.
- **Snowflake (shelf E).** Unchanged: the sweep could not verify the 2024-26
  rendezvous-channel changes (AMP cache, SQS, Azure fronting shutdown), so
  the shelf entry stands as written.
- **TEEMS (shelf F).** Add _SNPeek_ (NDSS 2026) as the side-channel reason
  a small operator should prefer a cryptographic split to an enclave split.
- **Loopix / Last Hop / Maybenot / Tamaraw (shelf C).** Unchanged as the
  evaluation bar; add the concrete harness the prototype needs on top:
  _Progressive Pruning_ candidate-set curves, LSDA profiling error, the
  _Breaking and (Partially) Fixing Onion Routing with Fragmentation_
  retry-oracle test, and _SoK: Metadata-Protecting Communication Systems_
  as the leakage vocabulary.
- **Adjudication file, section H "SOTA conclusion" ("DPF/Riposte-style
  private point writes plus batched IT-PIR reads for the dynamic
  multi-writer presence board").** That working point is not fault
  tolerant at two stores and is contradicted by the spec's own targetless
  bucket model; rewrite it as "client-additive replicated targetless
  stores with fixed-scan reads, Myco/Pepper/Chu-Wang-Jia as the
  two-server comparators, DPF writes deferred to a >= 3-store stage". The
  section's Express gloss ("leaks which mailbox is read") stands.

### 2.2 Factual corrections carried from the sweeps

- Sabre's authors are Vadapalli, Storrier, Henry (not Goldberg).
- Blinder is CCS 2020 (not 2021); Clarion is NDSS 2022 (not PoPETs).
- Spectrum is NSDI 2022 by Newman, Servan-Schreiber, Devadas.
- Express is USENIX Security 2021 (usenix.org returns 403 to fetchers;
  verified via arXiv 1911.09215 and the USENIX PDF).
- HomeRun uses two semi-honest non-colluding servers (the OMR sweep's
  "single server" reading was from memory; the ePrint page says two).
- The VDAF draft revision was read as -20 by one sweep and -22 by another on
  the same day; reconcile before quoting a number.
- PingPong is now IEEE/ACM ToN 2026, not only an arXiv preprint.

### 2.3 Claims the prototype write-up must not make (consolidated)

Two-server DPF writes into capability-addressed mailboxes with a two-party
audit (_Express_); fast audits of secret-shared writes (_Sabre_, VDPF);
capability-gated private writes in ZK over shares (_Spectrum_, PACL);
anonymous channel registration via VDPF (_Pepper_); blame-the-server
(_Spectrum_, _MHcast_, _Trellis_); untrusted front-end before an any-trust
store (_ZIPNet_); robust private writes (_Blinder_, _Ring of Gyges_,
_DumboMix_); two non-colluding servers with one actively corrupt
(_Private Signaling Secure Against Actively Corrupted Servers_); split
detection across servers combined locally (_Multi-server FMD_); polylog
two-server mailbox (Myco); server-blind detection over a public board and
group-addressed posts (OMR, GOMR); unbounded per-recipient retrieval
(_HomeRun_); fault-tolerant private discovery (_Pudding_, _Arke_);
BFT/equivocation-tolerant grow-only sets (BEC, BFT CRDTs, _Blocklace_);
mutual log witnessing (tlog-witness, Sigsum); anonymous audit channel
(keytrans-architecture); two logs for robustness (CT two-operator policy);
relay/gateway split hiding IP from the store (RFC 9458, Chrome IP
Protection, Apple Live Caller ID); batch-issued unlinkable write credits and
epoch-scoped tokens (batched-tokens, public-metadata drafts); per-epoch
anonymous quota across independent servers (_Everlasting ARLT_); Sybil-
resistant anonymous load balancing (_BalancedMixnet_); multi-store
replication with client union (_NIP-17_, Session, Tor HSDirs); opaque-blob
store with client sifting (Cwtch); capability-derived epoch-bucketed
rendezvous addresses (Tor v3 blinding); HPKE/PQ in the browser (hpke-js,
noble-post-quantum); two-server HPKE-sealed secret-shared submission from a
browser (DAP/divviup-ts); notify-then-retrieve without a dialing round
(_PingPong_).

### 2.4 Dropped pending verification (one sweep, from memory, no independent
confirmation — re-verify before any use)

SUNDR / Mazières-Shasha fork consistency; Depot (OSDI 2010); Verena
(S&P 2016); TrInc (NSDI 2009); CoSi witness cosigning (S&P 2016); Ghostor
(NSDI 2020); Guerraoui et al. consensus number (PODC 2019), Auvolat et al.
Byzantine causal broadcast, Cholvi et al. Byzantine grow-only sets; the SDA
canon (Danezis 2003/2004, Troncoso 2008/2009, Oya 2014) beyond the arXiv-
verified LSDA; Parakeet and Apple Contact Key Verification; Chrome SCT
auditing and the two-operator CT policy as a written policy; Tor proposal
327 PoW and Arti onion-service status; Snowflake 2024-26 rendezvous-channel
changes; Apple Private Cloud Compute's OHTTP relay; Kagi's Privacy Pass
deployment; Fastly/Mozilla OHTTP relays; SimpleX private message routing,
queue rotation, XFTP, and server-stored links (the deployed
architecture-B precedent at consumer scale — worth verifying first);
Session's whitepaper and swarm sizing; Veilid private/safety routes; Delta
Chat chatmail retention and iroh channels; Briar BRP and Mailbox; the
Constantinides/NymHS papers' venues; Wolinsky et al.'s CCS 2013 venue; the
Willow protocol's Private Area Intersection; BeeKEM (ePrint 2026/1434,
listed only). Of these, SUNDR/Depot/Verena and SimpleX/Briar matter most to
the memo below and were argued from BEC, Meiklejohn et al., Cwtch, and
NIP-17 instead.

---

## 3. Design memo: what the literature says a MINIMUM two-store rendezvous should be

### 3.1 The one fact that decides it

Every sweep converged on the same structural point, from different
directions. Two stores cannot buy fault tolerance AND privacy beyond S1
from any cryptographic family in the literature:

- In the DPF/DC-net family (_Express_, _Sabre_, _Spectrum_, _Pepper_, VDPF,
  PACL, DAP/VDAF) each store's table is the sum of all writers' masked
  shares and only the partner table cancels the masks; if either store is
  down, blocked, or omitting, the survivor holds pseudorandom noise. Every
  audit in that family also needs a store-to-store round.
- In the robust family (_Blinder_, _Ring of Gyges_, _DumboMix_, _Trellis_,
  _Pudding_, _Arke_) survivability costs 3-4+ servers with honest majority
  or n >= 3f+1.
- In the two-server private-read/detection family (Myco, _HomeRun_,
  _Private Signaling Secure Against Actively Corrupted Servers_,
  _Multi-server FMD_) both servers must be online and usually must talk.
- In the replicated-log family (BEC, BFT CRDTs, tlog-witness, keytrans)
  safety against any number of Byzantine replicas is free when entries are
  self-authenticating and the client validates; liveness needs one honest
  reachable replica; and a client alone cannot detect a targeted fork
  without another observer.

So with n = 2 the honest choices are: replicate S1 objects and accept
per-store S1 (A); or use a stronger two-server primitive that DEGRADES to
S1 when one store is missing (B, and C only with a plaintext fallback that
gives up the very thing C bought). The spec already says this in its own
words: R2-BEC gives f = 1 delivery resilience from "two proactively used,
independently operated honest stores", servers "do not vote, agree on a
log, or prove absence", and clients "authenticate and union everything
delivered".

### 3.2 Scoring

Scale for the two privacy rows: 1 = below S1, 3 = exactly S1, 4 = S1 plus a
named extra under a named assumption, 5 = provably beyond S1 with no extra
assumption. Other rows: 1 = fails the requirement, 3 = meets it with
caveats, 5 = meets it by construction. Scores are for the MINIMUM two-store
build; variants are noted in the justification.

| Criterion | (A) two replicated additive S1 stores + client union + cross-store checkpoint witnessing | (B) OHTTP-style relay/gateway role split | (C) DPF secret-shared writes |
|---|---|---|---|
| Privacy vs one malicious store | **3** | **4** | **4** |
| Privacy vs two colluding stores | **3** | **3** | **3** |
| f = 1 fault tolerance | **5** | **3** | **1** |
| Browser cost | **5** | **4** | **3** |
| Server cost | **5** | **4** | **2** |
| Fit with the spec's immutable operation-set model | **5** | **3** | **1** |
| Abuse control | **3** | **4** | **2** |
| Honesty of claims | **5** | **3** | **2** |
| Total (of 40) | **34** | **28** | **18** |

Justifications, citing entries by title:

- **Privacy vs one malicious store.** (A) is S1 exactly: the store sees an
  opaque fixed-size object, a targetless bucket, a source IP, and a time;
  that is what Cwtch's server sees (_Cwtch Security Handbook: Server_) and
  what the spec defines S1 to be. It is 3, not less, only if records carry
  no deterministic room tag and reads are whole-bucket (the Talek/DP5
  fixed-scan discipline; _Snake-eye Resistant PKE_ and _The Effect of False
  Positives_ show what a per-room tag or a fuzzy test leaks). (B) adds "no
  single store sees IP and object together" under relay/gateway
  non-collusion — the guarantee Apple's Live Caller ID Lookup and Chrome IP
  Protection ship, and the gap _Kerblam_'s title names in the whole
  recipient-privacy line — hence 4, but spec line 4206 says this is not
  SP1 by name. (C) adds a hidden write slot under non-collusion (_Express_,
  _Pepper_), hence 4; in the spec's targetless-bucket model there is no
  room-linked slot to hide, so the extra is nominal, and without an audit a
  malicious client (not store) can clobber the table (_Private Access
  Control for FSS_ and its 2023 break).
- **Privacy vs two colluding stores.** Collusion flattens all three to S1:
  (A) promised nothing more; (B)'s split is "void if the two collude or
  share an operator" (the shelf's own RFC 9458 gloss, and _Towards a
  Tectonic Traffic Shift?_ shows independence is contractual); (C)'s two
  keys reveal the slot, and the AEAD under the capability is what keeps
  the content at S1. The Session post-mortem (_Practical Attacks on Session
  Messenger and Oxen Blockchain_) is the reason to state operator
  independence as an auditable fact rather than an emergent one.
- **f = 1 fault tolerance.** (A) by construction: write-both/read-both,
  authenticated union, no quorum — a corollary of _Byzantine Eventual
  Consistency_ and _Making CRDTs Byzantine Fault Tolerant_, deployed as
  _NIP-17_ inbox relays, Session swarms, and Tor HSDirs; cross-store
  checkpoint cosignatures must be evidence, not validity, or Sigsum's
  cosigned-only rule reintroduces a both-stores dependency. (B) standalone
  is a serial chain (relay down = path down; Chrome IP Protection fails
  closed): 2. Symmetric B — each store relays for the other's gateway, the
  client writes via both orderings, direct-to-survivor fallback — restores
  f = 1 at the price of each store seeing IPs in its relay role: 4. Scored
  3 as the average of what the minimum build gets. (C) is 2-of-2: a lost
  share is a lost write, the surviving table is noise, and corruption is
  unattributable (_Express_; ZIPNet's remark that Express "does not at all"
  support more than two servers). The only escapes are three stores with
  pairwise DPFs or a 2-of-3 threshold DPF (_High-Throughput Three-Party
  DPFs_, _Eliminating Exponential Key Growth_), or a plaintext-S1 fallback
  copy that surrenders the slot privacy — neither is a two-store minimum.
- **Browser cost.** (A) needs AEAD, Ed25519, HPKE(DHKEM-X25519), all native
  per _Modern Algorithms in the Web Cryptography API_ and hpke-js; the read
  is a bucket download (a few MB per epoch at rendezvous scale, per the
  Cwtch model) with local trial decryption in microseconds. (B) adds one
  HPKE seal (about 0.1 ms) and about 110 B per exchange via ohttp-ts, and
  needs chunked OHTTP for a long-poll: 4. (C)'s client side is cheap
  (sub-millisecond keygen, about 0.5 KB per share in the private-writes
  sweep's Node micro-benchmark; about 20 ms and 5 KB with an Express-style
  audit proof), but no DPF/FSS package exists on npm and divviup-ts has no
  IDPF, so it means a WASM port of the Rust `prio` crate or a hand-written
  BGI16 tree; reads still need single-server PIR (_Respire_, _KPIR_) on top:
  3.
- **Server cost.** (A) is a hash-map insert per write and a bucket serve
  per read (Bun routes): 5. (B) doubles requests and adds an HPKE unseal
  per relayed message: 4. (C) pays a full-domain DPF evaluation per write,
  linear in table size (141 ms at 2^16 and 2.4 s at 2^20 slots in naive JS,
  milliseconds native per _Express_/_Spectrum_), plus one audit round
  between stores per batch (VDPF, _Mastic_), plus O(N) PIR work per read:
  2.
- **Fit with the spec's immutable operation-set model.** (A) IS the model:
  REQ-004 client-additive carriers, Phase 4 "additive stores and censorship
  paths", R2-BEC authenticated union, targetless public cohort log, fixed
  public buckets — and the equivocation-tolerant grow-only-set subclass of
  _On CRDTs and Equivocation in Byzantine Setups_ is the formal name for it:
  5. (B) is a transport wrapper over A's operations and composes cleanly,
  but the spec reserves source-privacy claims for a measured SP1 profile
  with mixing evidence (line 4206): 3. (C) contradicts the model: DPF writes
  are additive updates into a fixed-size table, not immutable
  content-addressed operations, so there is no self-authenticating log to
  checkpoint, replay is not idempotent, and none of the BEC/witness/
  evidence machinery applies: 1.
- **Abuse control.** (A) gates writes with RFC 9578 tokens from an issuer
  that is neither store, batched (_Batched Token Issuance_) and epoch-bound
  (_Public Metadata_), one bundle per store with NO shared double-spend
  database; records are self-authenticating so junk cannot forge, but it
  can flood a bucket, and the prototype's declared open policy means abuse
  control is stubbed: 3. (B) adds a second, independent gate — the relay can
  rate-limit by source without seeing content while the gateway checks
  tokens without seeing sources — the _MoQ Privacy Pass Authentication_
  pattern: 4. (C) needs a malformed-write audit or a malicious client zeroes
  every slot; every audit (_Express_, _Sabre_, VDPF, PACL, _Mastic_) requires
  the two stores to exchange verifier data, which "either store may be
  blocked" forbids, and the PACL payload break shows slot authorisation
  alone is insufficient: 2.
- **Honesty of claims.** (A) claims nothing novel — it is _NIP-17_ plus
  Cwtch plus HSDir replication plus tlog-witness with n = 2 — and its
  per-store leakage can be stated in _SoK: Metadata-Protecting Communication
  Systems_ terms as exactly "IP, time, size, count"; it cannot be mistaken
  for v0.4 bytes: 5. (B) invites "anonymous" and SP1 language the spec
  forbids and that _Towards a Tectonic Traffic Shift?_ shows is contractual;
  it must be described as a degradation ladder (split -> direct) with a
  logged privacy state: 3. (C) invites "server-blind writes" while being
  non-fault-tolerant at two stores; every component is preempted (_Express_
  through _Pepper_); and the one unpublished combination (OHTTP-relayed DPF
  shares) inherits the same availability failure: 2.

### 3.3 Recommendation

Build **A** as the minimum, behind the internal flag, exactly as the spec's
Phase 1 + Phase 4 client-additive model describes, with the literature's
four hygiene rules built in from day one; add **B** as a second flag only
after A's end-to-end run (two stores, one killed, one withholding) passes;
keep **C** as a documented, measured option for a >= 3-store stage.

Concretely, A means:

1. Two independently run store processes with the same targetless
   append-only bucket API; the client writes every retained operation to
   both and unions everything it authenticates (REQ-004; _Byzantine
   Eventual Consistency_).
2. Records padded to one fixed slot, sealed under the capability, carrying
   no deterministic room tag; reads are whole-bucket downloads from
   whichever store answers, trial-decrypted locally (Cwtch model; _Snake-eye
   Resistant PKE_ for why crafted records must fail the MAC).
3. Content-addressed operation ids so replays and duplicate offers are
   idempotent (_Blocklace_), and a deterministic tie-break for concurrent
   offers because uniqueness cannot be enforced (BEC impossibility).
4. Each store signs a per-interval checkpoint (origin, size, root) and
   witnesses the other's, on a schedule independent of client traffic;
   the client compares; a missing cosignature is "degraded", never
   "invalid" (tlog-witness; _Verifiable PIR with Small Client Storage_ for
   the any-digest-commits principle). Include each store's HPKE and token
   key digests in what is witnessed, since key consistency is unsolved at
   the IETF.
5. Post-rendezvous checkpoint gossip: once the WebRTC channel is up, peers
   exchange the checkpoint tuples they saw from each store; a mismatch
   without a consistency proof is transferable evidence (_Think Global, Act
   Local_; keytrans-architecture). This is the one modest twist not already
   in CT/KT practice; it catches forks retroactively, for peers who did
   connect.
6. Write tokens: batched RFC 9578 tokens with (epoch, store-id) public
   metadata, k per epoch TOTAL split across stores, separate double-spend
   state per store; stubbed open in the prototype and labelled so.
7. Evaluation instrumented from the first run: a timing-join experiment
   (fraction of replicated write pairs a global observer links vs delay
   scale and population), a _Progressive Pruning_ candidate-set curve, an
   LSDA profiling error over many rendezvous, and the fragmentation
   retry-oracle test, using Piotrowska's discrete-event simulator where a
   live run is too small.

B, when added, is the symmetric variant: each store also runs an RFC 9458
relay pointed at the other's gateway; the client writes via both
orderings; loss of either hop degrades to a direct write on the survivor
with the privacy state surfaced in the flag's diagnostics. Its whole
security argument then rests on the timing decorrelation in 3.4, because
one server is simultaneously relay for replica 1 and gateway for replica 2.

C, if ever built, belongs on top of A's two stores plus a third as an
optional write mode with three pairwise DPFs, VDPF + PACL-with-payload-fix
audits, and _Pepper_ as the comparison implementation; the browser-native
WASM DPF client with published measurements is the only genuinely
unclaimed artefact in that space.

The defensible statement for the flag's README is narrow and matches the
existing design doc: a browser-native, two-operator, crash/omission-
tolerant rendezvous for WebRTC signaling in which each store alone learns
no more than S1, with a documented degradation ladder, measured browser
costs, and NO S1/R2-BEC/SP1/L2/"anonymous"/"BFT" label (spec line 3392 and
the design doc's "What this is not").

### 3.4 Residual leaks that must be disclosed

These survive A (and B) and must appear in the flag's README in _SoK:
Metadata-Protecting Communication Systems_ vocabulary. None is hidden by
S1, which excludes source anonymity and traffic patterns by definition.

1. **Replicated-write timing linkability (the prototype's own worst leak).**
   The client writes the same object to both stores within milliseconds.
   Any party seeing both stores' request logs — a global or on-path
   observer, a shared upstream, colluding operators, or in symmetric B a
   single server acting as relay for one replica and gateway for the other
   — joins the two writes into one client with no identifiers at all
   (_Progressive Pruning_; _A traffic analysis attack against Introduction
   Protocol and Onion Services_ shows one vantage point suffices). The
   second replica must be written after an independent random delay drawn
   wide relative to the epoch (Loopix-style), objects must be one fixed
   size, and the linkage fraction must be measured and published; the delay
   trades directly against rendezvous latency, and that trade must be
   stated, not hidden.
2. **Source addresses.** Without B or Tor, both stores see the client IP on
   every write and every poll. A single store can recover the (IP a, IP b)
   edge from write-then-read pairings in a handful of rounds (_Improving
   Signal's Sealed Sender_ — UNVERIFIED but independently cited by two
   sweeps; _What's a little leakage between friends?_), and two stores'
   combined logs make co-presence trivially linkable. S1 explicitly does
   not promise source anonymity; the README must say the co-membership
   edge is hidden at the identifier level only, not at the IP level.
3. **Size and count.** Object lengths and per-epoch write counts are
   visible; pad to one slot, keep per-epoch cadence constant.
4. **Presence and polling shape.** Polling must be schedule-shaped, not
   event-shaped: constant cadence regardless of hits, no burst after an
   answer, randomised offer-to-answer interval, no coordinated dial phase
   between stores (_PingPong_; _What's a little leakage between friends?_).
   Any behaviour change on failure (extra writes, faster polls) is
   observable, so the fallback must not change the client's traffic shape.
5. **Retry oracle.** Retrying at the surviving store after one store drops
   an object or fragment is an active cross-store tagging channel
   (_Breaking and (Partially) Fixing Onion Routing with Fragmentation_);
   retry only at epoch boundaries and treat "store omitted my object" as
   indistinguishable from "no answer yet".
6. **The witness channel as a beacon.** Cross-store checkpoint writes are
   themselves replicated writes; schedule them independently of user
   traffic or they time-stamp every rendezvous.
7. **Detection, not prevention, and its blind spots.** A client detects
   forged/altered entries, replays, and set disagreement locally; omission
   evidence needs signed checkpoints; targeted split views need
   cross-observer comparison. It cannot detect collusion of both stores on
   omission, a first-write omission window before any checkpoint, stale-
   but-consistent views inside an epoch, or attribution when the writer
   itself failed to write to both (_Think Global, Act Local_;
   keytrans-architecture).
8. **Non-collusion and independence are business facts.** Operator, ASN,
   hosting, jurisdiction, and funding independence of the two stores must
   be stated and auditable (_Towards a Tectonic Traffic Shift?_; _Practical
   Attacks on Session Messenger and Oxen Blockchain_). For B, the split is
   also passively detectable (enumerable relay ingress).
9. **Key split-view.** Each store's HPKE key config and the token issuer's
   key can be served per-client to partition the anonymity set
   (key-consistency drafts, expired); witnessing key digests mitigates but
   does not solve this.
10. **No uniqueness.** Two concurrent offers for one room in one epoch
    cannot be prevented (BEC); the tie-break rule is part of the protocol,
    and a Byzantine co-member can always post two.
11. **Token double-spend state and quota shape.** If the stores ever share a
    double-spend database, redemptions at the two stores become linkable —
    a cross-store membership edge; if quotas are per store rather than
    total, flood capacity doubles when one store is blocked.
12. **Local forensics.** Persisted seen-sets, pending objects, and
    checkpoints must be keyed by per-store opaque ids, never by
    room-derived tags, or a disk read reveals membership.
13. **No labels.** The prototype earns no S1, R2-BEC, SP1, L2, "anonymous",
    "censorship-resistant", or "BFT" label; two stores give crash/omission
    tolerance with detection, not Byzantine tolerance (_Pudding_, _Arke_).

### 3.5 What is left to claim, honestly

Every component above is preempted (section 2.3). The composition —
capability-authenticated Byzantine grow-only set, S1 fixed-scan reads,
mutual tlog-style witnessing treated as evidence, post-rendezvous peer
gossip of checkpoints over the established WebRTC channel, a symmetric
relay ladder with logged degradation, decorrelated replicated writes, and
a measured timing-join / intersection evaluation in a real browser — is
what no sweep found published together, and the WASM-side cost numbers
are genuinely missing from the literature. That is a systems contribution
for a flagged prototype and a possible workshop paper (WPES/PoPETs per the
adjudication file), not a cryptographic result, and not v0.4.
