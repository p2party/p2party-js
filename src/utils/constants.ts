import {
  crypto_aead_chacha20poly1305_ietf_ABYTES,
  crypto_hash_sha512_BYTES,
} from "../cryptography/interfaces";

/** One bound shared by room admission and all signaling lifecycle registries. */
export const MAX_ACTIVE_SIGNALING_ROOMS = 256;

export const MESSAGE_LEN = 64 * 1024;
// Protocol-wide application payload ceiling. This is enforced before outbound
// chunk planning and again after authenticated metadata is decrypted / inside
// the DB worker, before OPFS can pre-size a receive file.
export const MAX_MESSAGE_SIZE = 10 * 1024 * 1024 * 1024; // 10 GiB
// High watermark for the data-channel send buffer (16 frames = 1 MiB). The old
// value of 2 frames meant ordinary congestion immediately spilled full 64KiB
// frames through the signaling server (which then sees sender/receiver, size,
// timing and the plaintext root label) — the exact metadata the chunking scheme
// tries to hide. Browsers buffer ~16 MiB, so 1 MiB keeps normal transfers on
// the peer-to-peer data channel and reserves server relay for a genuinely
// unavailable channel.
export const MAX_BUFFERED_AMOUNT = 16 * MESSAGE_LEN;

// ── Blind-rendezvous prototype data channel (prototype/webrtcProvider.ts) ────
// Inbound bounds, one pair per lane. A remote endpoint may speak before local
// certificate verification or session startup completes, and a reader may fall
// behind its peer, so what arrives with no reader waiting is queued, up to these
// bounds and no further. The control lane carries the protocol-v4 handshake
// alone: at most three frames from the peer, the largest 3,329 bytes (an
// ML-KEM-1024 HELLO). The app lane carries the message header and the uniform
// chunk frames; 16 MiB is 256 of them. The frame counts bound the per-frame
// overhead of tiny frames. The send side waits at MAX_BUFFERED_AMOUNT and
// resumes at SEND_BUFFER_LOW_THRESHOLD, as the main app's sender does.
export const PROTOTYPE_CONTROL_LANE_HIGH_WATER_BYTES = 64 * 1024;
export const PROTOTYPE_CONTROL_LANE_MAX_FRAMES = 16;
export const PROTOTYPE_APP_LANE_HIGH_WATER_BYTES = 16 * 1024 * 1024;
export const PROTOTYPE_APP_LANE_MAX_FRAMES = 1024;
// How long a graceful `stop()` of a prototype run waits for the data channel's
// send buffer to drain before it closes the channel anyway. The same 5 s as the
// default of `src/utils/drainAndClose.ts`.
export const PROTOTYPE_STOP_DRAIN_TIMEOUT_MS = 5_000;

export const NAME_LEN = 256;
export const METADATA_LEN =
  8 + // schemaVersion (8 bytes)
  1 + // messageType (1 byte)
  crypto_hash_sha512_BYTES + // hash
  8 + // totalSize (8 bytes)
  8 + // date (8 bytes)
  NAME_LEN + // name (256 bytes)
  8 + // chunkStartIndex (8 bytes)
  8 + // chunkEndIndex (8 bytes)
  8; // chunkIndex (8 bytes)
// Merkle internal-node domain byte: a node is SHA-512(0x01 ‖ left ‖ right),
// byte-matched with MERKLE_NODE_DOMAIN in src/cryptography/merkle.c. Leaves use
// 0x00 (src/utils/leafHash.ts).
export const MERKLE_NODE_DOMAIN = 0x01;
// The longest one slice of an outgoing message's proof-level build holds the
// thread, in ms (src/cryptography/merkle.ts). The build is about 2.5 µs a leaf
// in Chromium (3.9 s for 1,600,000 leaves in one call, docs/e2e/cover-timers/),
// so it runs in slices, handing the page back between them; a cover wake-up
// that falls due during the build then waits for at most the slice it fell
// in. Below MIN_COVER_SLOT_MS (25 ms, src/roomPolicy.ts), the shortest slot
// spacing a schedule may have, so no slot passes whole inside one slice; and
// in Chromium 1 ms slices cost the build 5 to 8 % more time than 4 ms ones.
export const PROOF_LEVEL_BUILD_SLICE_MS = 1;
export const PROOF_LEN =
  4 + // length of the proof
  48 * (crypto_hash_sha512_BYTES + 1); // ceil(log2(tree)) <= 48 * (hash + position)
export const CHUNK_START =
  METADATA_LEN + // fixed
  PROOF_LEN; // Merkle proof max len of 3kb
// The v4 profile keeps the complete wire cell fixed at 65,490 bytes. Expanding
// the PQ epoch from one byte to a u64 adds seven clear-header bytes, so those
// bytes are paid for by padding: 65,405 bytes of authenticated plaintext after
// the 69-byte clear header and before the 16-byte AEAD tag.
export const CHUNK_PLAINTEXT_LEN = 65_405;
export const CHUNK_LEN = CHUNK_PLAINTEXT_LEN - CHUNK_START;
// Historical public send options require the configurable chunk payload to be
// larger than the non-payload budget. Keep that product bound explicitly named;
// it is not an on-wire box header.
export const CHUNK_SIZE_FLOOR = MESSAGE_LEN - CHUNK_LEN;
export const DECRYPTED_LEN = CHUNK_PLAINTEXT_LEN;

// ── protocol-v4 wire framing (SSOT; byte-matched in cryptography/utils.h) ─────
// Clean v4 break: every data-channel frame begins with a 1-byte type tag so
// the inbound classifier is unambiguous (replaces the old length-only 64B /
// MESSAGE_LEN test). A mismatch here mis-routes frames silently, so the values
// are asserted equal to the C #defines by src/utils/constants.test.ts.
export const PROTOCOL_VERSION = 4;
export const FRAME_TYPE_LEN = 1;
export const FRAME_TYPE_HANDSHAKE = 1;
export const FRAME_TYPE_CHUNK = 2;
export const FRAME_TYPE_RECEIPT = 3;
// Both cover and sparse-PQ control records use the same 65,490-byte cell
// geometry as application chunks. CANCEL is an encrypted cover-cell kind, not
// a separately observable outer frame type.
export const FRAME_TYPE_COVER = 4;
export const FRAME_TYPE_PQ_CONTROL = 5;
// Receipts are protocol frames, not bare SHA-512 values. Both ordinary
// chunk acknowledgements and the terminal content-hash acknowledgement use
// this exact tagged geometry.
export const RECEIPT_TOKEN_LEN = crypto_hash_sha512_BYTES;
export const WIRE_RECEIPT_FRAME_LEN = FRAME_TYPE_LEN + RECEIPT_TOKEN_LEN; // 65
// CPace/channel-input suite marker. 0x01 means the mandatory protocol-v4
// classical-or-CPace + ML-KEM-768 hybrid bootstrap. It is transcript/KDF
// context, not the KEM ciphertext and not a negotiation/fallback bit.
export const PQ_TAG_LEN = 1;
export const PQ_TAG = new Uint8Array([0x01]);

// ── protocol-v4 CHUNK frame header (SSOT; byte-matched in utils.h) ────────────
// A v4 message-chunk frame is:
//   FRAME_TYPE_CHUNK(1) ‖ dhPub(32) ‖ N(8 BE) ‖ PN(8 BE) ‖
//   pqEpoch(8 BE) ‖ nonce(12) ‖ ciphertext
// The ratchet header (dhPub, N, PN) is SHARED by every chunk of a message (one ratchet
// step per message); the 12-byte nonce is fresh + random per chunk. The epoch is
// an unsigned u64, represented as bigint in TypeScript, so it cannot silently
// lose precision. N/PN remain safe-integer JS numbers encoded as u64 BE.
export const RATCHET_DHPUB_LEN = 32;
export const RATCHET_N_LEN = 8;
export const RATCHET_PN_LEN = 8;
export const PQ_EPOCH_LEN = 8;
export const RATCHET_NONCE_LEN = 12;
// Complete clear header authenticated as application AAD, excluding the random
// nonce. The expected Merkle root is prepended by messageChunkCrypto.
export const CHUNK_AAD_HEADER_LEN =
  FRAME_TYPE_LEN +
  RATCHET_DHPUB_LEN +
  RATCHET_N_LEN +
  RATCHET_PN_LEN +
  PQ_EPOCH_LEN; // 57
// Where the ratchet header (dhPub ‖ N ‖ PN) ends in a chunk frame. Every chunk
// of one message carries the same bytes before this offset. Derived here for
// the TypeScript side; there is no matching C #define.
export const CHUNK_RATCHET_HEADER_END =
  FRAME_TYPE_LEN + RATCHET_DHPUB_LEN + RATCHET_N_LEN + RATCHET_PN_LEN; // 49
export const CHUNK_HEADER_LEN =
  RATCHET_DHPUB_LEN +
  RATCHET_N_LEN +
  RATCHET_PN_LEN +
  PQ_EPOCH_LEN +
  RATCHET_NONCE_LEN; // 68

// Complete v4 clear header, including nonce; ciphertext begins at byte 69.
export const MESSAGE_START = FRAME_TYPE_LEN + CHUNK_HEADER_LEN; // 69
// Full v4 chunk frame length remains exactly 65,490 bytes:
// 69-byte header ‖ 65,405-byte ciphertext ‖ 16-byte tag.
export const WIRE_CHUNK_FRAME_LEN =
  MESSAGE_START + DECRYPTED_LEN + crypto_aead_chacha20poly1305_ietf_ABYTES; // 65490

// D2=B / SECURITY-1: domain separator for the Ed25519 cross-signature over the
// dedicated X25519 identity pub. The cross-sig signs
// (IDENTITY_CROSS_SIGN_DOMAIN_BYTES ‖ X25519_pub), NOT the bare pub, so it cannot
// collide with the login-challenge signing oracle (handleChallenge signs a raw
// 32-byte server-supplied nonce with the same Ed25519 identity key; a bare cross-sig
// would be forgeable by sending a chosen X25519 pub as that challenge). Same
// convention as the other p2party domain labels; TS-only (the cross-sig is
// produced/verified entirely in TS via ed25519 sign/verify — no C-side use).
export const IDENTITY_CROSS_SIGN_DOMAIN_BYTES = new TextEncoder().encode(
  "p2party-x25519-idsig-v1",
); // 23 bytes

// Exact group DSIs for the draft-21 CPACE-RISTR255-SHA512 cipher suite. These
// are standards constants, not p2party-local labels: changing either changes
// the PAKE and forfeits the draft's test vectors/security analysis.
export const CPACE_RISTRETTO255_DSI = "CPaceRistretto255";
export const CPACE_RISTRETTO255_ISK_DSI = "CPaceRistretto255_ISK";

// Persisted/snapshot provenance for the authenticated, room-policy-selected
// protocol-v4 bootstrap suite. "3dh" is deliberate: this is interactive
// triple-DH, not Signal's asynchronous X3DH prekey protocol. PIN policy adds
// exact draft-21 CPace. The room policy fixes one suite before the handshake;
// there is no in-band negotiation, downgrade, or classical fallback.
export const RATCHET_ROOT_SUITE_MLKEM512 =
  "hybrid-3dh-mlkem512-cpace21-v4" as const;
export const RATCHET_ROOT_SUITE_MLKEM768 =
  "hybrid-3dh-mlkem768-cpace21-v4" as const;
export const RATCHET_ROOT_SUITE_MLKEM1024 =
  "hybrid-3dh-mlkem1024-cpace21-v4" as const;
export const RATCHET_ROOT_SUITES = [
  RATCHET_ROOT_SUITE_MLKEM512,
  RATCHET_ROOT_SUITE_MLKEM768,
  RATCHET_ROOT_SUITE_MLKEM1024,
] as const;
export type RatchetRootSuite = (typeof RATCHET_ROOT_SUITES)[number];

/** Backward source alias for the 0.10 default suite. */
export const RATCHET_ROOT_SUITE = RATCHET_ROOT_SUITE_MLKEM768;

export const isRatchetRootSuite = (value: unknown): value is RatchetRootSuite =>
  typeof value === "string" &&
  (RATCHET_ROOT_SUITES as readonly string[]).includes(value);

// Double Ratchet KDF domain-separation labels (protocol-v4). These are the
// `info` strings for the two HKDF-SHA512 chains of the ratchet, and are SSOT
// constants that MUST byte-match any C-side kdf_rk/kdf_ck should one be added
// (the ratchet state machine currently derives them in TS on the compiled
// crypto_auth_hmacsha512 via hkdf.ts). Same "p2party-*-v1" convention as
// CPace DSIs above.
//   kdf_rk: (rootKey, DH(...)) -> (newRootKey ‖ chainKey)   [HKDF extract+expand]
//   kdf_ck: chainKey           -> (nextChainKey, messageKey) [two labelled HMACs]
export const KDF_RK_LABEL = "p2party-rk-v1";
export const KDF_CK_LABEL = "p2party-ck-v1";
export const KDF_MK_LABEL = "p2party-mk-v1";

// Anti-DoS bound on the Double Ratchet's out-of-order skipped-message-key map.
// A single DH-ratchet step (or a header with a large N) may derive at most
// MAX_SKIP message keys before the requested one; a jump beyond this MUST throw
// rather than loop unboundedly. The skipped-key map lives in JS (the WASM heap
// is fixed at 2 MB with growth off), so this bounds JS-side derivations, not the
// WASM heap. Measured conservatively against the 2 MB heap (~500).
export const MAX_SKIP = 512;

// Anti-DoS bound on the Double Ratchet's out-of-order skipped-message-key map,
// TOTAL across the whole session (not just one `ratchetDecrypt` call). MAX_SKIP
// above only bounds derivations within a single call; nothing stopped a peer
// from repeatedly forcing DH-steps (or gaps) across many calls to grow
// `state.skipped` — and thus RAM and the persisted IndexedDB row — without
// ceiling. 2000 is a few chains' worth of legitimate reordering headroom
// (MAX_SKIP=512 * ~4), bounded so an adversarial peer can't grow the map
// unboundedly; the oldest entries are evicted first when this is exceeded.
export const MAX_SKIP_SESSION = 2000;

// Selective-retransmit / reconcile tuning: after the initial send, resend only
// the un-acked real chunks until the receiver confirms completion, up to
// MAX_RETRANSMITS attempts with a base timeout that backs off linearly.
export const MAX_RETRANSMITS = 5;
export const RETRANSMIT_TIMEOUT_MS = 2000;

// The receive handler reports each (transfer, failure) pair to the app once
// until that transfer stores again; this caps the set it remembers them in.
// Forgetting one only means its next failure is reported again.
export const MAX_REPORTED_RECEIVE_STORAGE_ERRORS = 1_024;

// Whole-file verification of a received file reads this many chunks (about
// 1 MiB of real bytes at full chunks) per batch, then yields, so the database
// worker keeps answering other requests while it hashes a large file.
export const RECEIVE_VERIFY_BATCH_CHUNKS = 16;
// ...and renews its receive lease this often, so another tab cannot take the
// transfer over while it runs.
export const RECEIVE_VERIFY_LEASE_RENEW_MS = 30_000;
// ...and remembers the outcome of this many recently committed attempts, so a
// second caller holding the same attempt gets the same answer.
export const RECEIVE_VERIFY_SETTLED_MEMORY = 256;
// While a received file is verified the worker reports progress, as each batch
// ends, once this many bytes were hashed since its last report or once
// RECEIVE_VERIFY_RECEIPT_INTERVAL_MS passed, whichever comes first. A report
// costs one message to the page; the page decides what goes on the wire.
export const RECEIVE_VERIFY_PROGRESS_BYTES = 8 * 1024 * 1024;

// Wait this long for a per-message data channel to reach "open" before sending,
// so its first frames aren't spilled to the WS relay while it is still
// "connecting" (anything that still slips is recovered by reconcile()).
export const CHANNEL_OPEN_TIMEOUT_MS = 3000;
export const CHANNEL_OPEN_POLL_MS = 25;

// ── Sender waits (handleSendMessage.ts, reconcile.ts) ───────────────────────
// Every wait below is woken by the event it waits for. Its timer is the
// fallback for a wake-up that never comes, not a polling cadence.
//
// A sender held at MAX_BUFFERED_AMOUNT resumes once its data channel's buffer
// drains to this (`bufferedAmountLowThreshold`): one wake-up refills about
// eight 64 KiB frames instead of one.
export const SEND_BUFFER_LOW_THRESHOLD = MAX_BUFFERED_AMOUNT / 2;
// A full send buffer is re-checked this often in case `bufferedamountlow` is
// never delivered.
export const SEND_BUFFER_FALLBACK_MS = 250;
// A full receipt window is re-checked this often if no receipt or close wakes
// it, so a lost wake-up costs at most this much per wait.
export const RECEIPT_WINDOW_FALLBACK_MS = 500;
// A completion wait is re-checked this often if no final receipt, refusal or
// abort wakes it.
export const COMPLETION_WAIT_FALLBACK_MS = 1_000;
// Once every chunk of a transfer is acknowledged the receiver is verifying the
// whole file before its final receipt, and re-sends that transfer's receipt at
// least every 10 s while it does. The sender gives up after this long without
// any frame for the transfer: the same 30 s its retransmit rounds took before
// giving up (RETRANSMIT_TIMEOUT_MS × (1 + 2 + … + MAX_RETRANSMITS)).
export const RECEIVER_SILENCE_LIMIT_MS =
  (RETRANSMIT_TIMEOUT_MS * MAX_RETRANSMITS * (MAX_RETRANSMITS + 1)) / 2;
// The slowest whole-file verification a sender waits for. A receiver that keeps
// reporting is given at most
//   totalSize / MIN_RECEIVER_VERIFY_BYTES_PER_SECOND + the silence bound,
// that is 1,280 s + 30 s ≈ 21.8 min at the 10 GiB MAX_MESSAGE_SIZE. (This
// machine verifies at about 15 s/GiB, roughly 70 MiB/s.)
export const MIN_RECEIVER_VERIFY_BYTES_PER_SECOND = 8 * 1024 * 1024;
// That wait re-checks this often, so a page that was frozen, asleep or offline
// (a check later than this past its due time) is seen, and the time it lost is
// not counted as the receiver's silence.
export const REPORTED_COMPLETION_CHECK_MS = 5_000;
// While a received file is verified the receiver re-sends that transfer's
// ordinary receipt at most once per this interval, and only when the worker's
// hashed byte count advanced since the receipt it last sent, so a stuck
// verification goes silent and the sender's silence bound ends its wait. A
// third of that bound leaves room for one late report. The worker reports at
// least this often while its reads finish.
export const RECEIVE_VERIFY_RECEIPT_INTERVAL_MS = RECEIVER_SILENCE_LIMIT_MS / 3;
// A held file that another context (another tab) is verifying when this
// worker would verify it at a room load is retried when that context's
// receive lease ends, and re-armed while the lease keeps being renewed, for at
// most this long from the first try; after that it is left for the next
// start. It is the longest a sender waits for a verification at the
// MAX_MESSAGE_SIZE: about 21.8 min.
export const RECEIVE_VERIFY_START_RETRY_WINDOW_MS =
  Math.ceil((MAX_MESSAGE_SIZE / MIN_RECEIVER_VERIFY_BYTES_PER_SECOND) * 1000) +
  RECEIVER_SILENCE_LIMIT_MS;
// When the database worker starts it lists the SDK's directory in the origin
// private file system and removes every file no record owns. It looks the
// listed files up this many per read transaction, so a directory of any size
// costs a bounded transaction each time.
export const RECEIVE_RECONCILE_BATCH_FILES = 64;
// Requests that create, read or remove a file wait for that pass, for at most
// this long. A pass that takes longer (a file system call that never
// settles, or a very large directory) goes on while the requests are served.
export const RECEIVE_RECONCILE_GATE_MS = 5_000;

// Resume-on-reconnect: a FULL peer reconnect (new RTCPeerConnection) destroys the
// per-message data channel — only "main" is auto-reopened — so an in-flight send
// must re-establish its own channel and continue. sendWithReconcile waits up to
// RECONNECT_RESUME_TIMEOUT_MS (polling every RECONNECT_RESUME_POLL_MS) for the
// peer's fresh connection to re-open the channel, and gives up after
// MAX_RESUME_ATTEMPTS reconnects so a flapping peer can't loop forever. The
// receiver re-emits its stored leaf-hash receipts on the new channel's onopen,
// so the sender rebuilds its acked-set and resends ONLY the still-missing reals.
// A "disconnected" edge is not abandoned immediately: handleConnectToPeer
// attempts an ICE restart and defers teardown by 8000 ms. Send admission waits
// longer than that, so a send issued during the repair is not failed while the
// peer is still in the roster and the UI still — correctly — shows it present.
export const PEER_ADMISSION_WAIT_MS = 12000;
export const RECONNECT_RESUME_TIMEOUT_MS = 30000;
export const RECONNECT_RESUME_POLL_MS = 500;
export const MAX_RESUME_ATTEMPTS = 3;

// Bound the send path's wait on the per-peer ratchet gate. A peer whose edge
// re-dialled onto a fresh transport may never finish the handshake (the other
// side still thinks it is authenticated, or the `main` channel never opens);
// without a bound every send to that peer hangs forever on the gate. The
// budget must be >= HANDSHAKE_STEP_TIMEOUT_MS (30 s, handleHandshake.ts) so a
// handshake that fails on its own rejects the gate first, plus a margin for the
// channel open + first step to start.
export const RATCHET_GATE_WAIT_TIMEOUT_MS = 45_000;

// A per-message frame can legitimately arrive before THIS side's ratchet gate
// has finished settling: gates open inside an async IndexedDB persist, and the
// identity responder completes the handshake on SENDING finish (and replays its
// receipts at once) while the initiator completes on RECEIVING it. Park such a
// frame for this long rather than closing its channel — a self-inflicted close
// was read back as a peer CANCEL and destroyed BOTH sides' partial transfer
// (C7). Far longer than any persist, far shorter than
// RATCHET_GATE_WAIT_TIMEOUT_MS, so a genuinely dead edge is still failed by the
// send path's own budget rather than by this guard.
export const PRE_AUTH_FRAME_PARK_MS = 10_000;
// Parking is bounded in BYTES as well as in time. The guard it replaces closed
// the channel on the FIRST unauthenticated frame, so an unauthenticated peer
// could pin at most one frame's memory; without a bound it could pin an
// unbounded amount for the whole park window.
//
// Bytes, not frames, because the two things that arrive early differ in size by
// three orders of magnitude. A reconnect receipt replay is 65-byte frames, one
// per stored chunk, unbounded and paced 32 every 10 ms — a partial of only a few
// megabytes crosses a 64-FRAME ceiling in about 20 ms, and every frame past it
// is lost work: the sender never learns that chunk is held and resends it, so a
// 100 MiB resume would re-send essentially the whole file. The DoS case is the
// opposite shape: full 65,490-byte cells, where 64 is already 4 MiB of pinned
// memory. Bounding the resource itself keeps the flooder to exactly the 64 cells
// the frame count allowed — the memory ceiling is unchanged by construction —
// while giving the receipt replay orders of magnitude more room (see the
// per-frame overhead charge below for the number it actually gets).
export const MAX_PARKED_PRE_AUTH_FRAMES = 64;
export const MAX_PARKED_PRE_AUTH_BYTES =
  MAX_PARKED_PRE_AUTH_FRAMES * WIRE_CHUNK_FRAME_LEN; // 4,191,360 (~4 MiB)
// A parked frame pins more than its own bytes: the suspended handler, the
// promise chain it awaits on and one park timer. For a 65,490-byte cell that
// overhead is noise, but for a 65-byte receipt it is all of the cost, and
// charging only the payload would let a flood of tiny frames pin a thousand
// times more parked continuations than the frame count it replaces ever
// allowed. Every parked frame is therefore charged at least this much, which
// leaves the flooder the same ~4 MiB ceiling in either frame size while still
// giving a legitimate receipt replay ~4,000 slots — a partial of ~256 MiB,
// against the ~4 MiB a 64-frame ceiling allowed. Conservatively rounded up
// from the engine's real per-suspension cost.
export const PARKED_PRE_AUTH_FRAME_OVERHEAD_BYTES = 1024;

// Head-room over the arithmetic floor of a scheduled confirmation: the sealer
// runs on the main thread, a boundary can be degraded, and the receipt job
// itself competes for a lane. Only head-room — the floor is derived from the
// schedule by coverTransfer.scheduledDeliveryTimeoutMs, never guessed. The
// fixed 120 s bound this replaces was unrelated to the room's cadence and
// rejected 100% of sends in the shipped "5 min cycles" preset, whose minimum
// possible confirmation is 301.2 s (C3).
export const SCHEDULED_DELIVERY_MARGIN_MS = 20_000;

// Every recovery path destroys the edge's cover runtime, which settles and
// deletes every job it held; the replacement runtime starts empty, so an
// in-flight scheduled send used to die with no resume and no notification (C8).
// The sender re-derives on the replacement generation and re-offers the
// message, but scheduled mode emits no per-chunk receipts — getAckedChunks is
// always empty there — so a resumed job re-offers EVERY chunk. The receiver
// dedups by leaf hash, so that is correct, but it is a full re-send: a flapping
// edge must not do it indefinitely. Matches MAX_RESUME_ATTEMPTS' role on the
// immediate-mode path, one lower because each scheduled attempt already costs a
// whole schedule-derived idle budget.
export const MAX_SCHEDULED_SEND_RESUMES = 2;

// Signaling liveness. The server pings every 10 s (p2party-server
// src/utils/handleInterval.ts PING_INTERVAL). When a mobile browser freezes
// the page with its radio off, the WebSocket can come back half-open: the
// server has long since closed its end, but no onclose fires locally until
// the TCP stack gives up, so Redux keeps reporting a live, verified socket
// and no reconnect (and no peer re-dial) ever starts. The SDK therefore
// stamps the wall clock on every answered server heartbeat and, on an
// interval and on each wake event, marks the socket dead itself once no
// heartbeat arrived for the timeout: 25 s tolerates two lost pings plus
// jitter without reacting to ordinary delay.
export const SIGNALING_HEARTBEAT_TIMEOUT_MS = 25_000;
export const SIGNALING_HEARTBEAT_CHECK_MS = 5_000;

// Bound an IN-PLACE re-bind of an existing RTCPeerConnection onto a new remote
// DTLS certificate (see remoteTransportChange). The surviving SCTP association
// keeps accepting OUR new outbound streams while never delivering the peer's,
// so the re-bound transport looks alive from here but the peer's fresh `main`
// never arrives and the edge never re-authenticates. Nothing else ends that
// state quickly: a PC whose ICE stays connected never fails, so the only exit
// is the PEER's HANDSHAKE_STEP_TIMEOUT_MS (30 s, handleHandshake.ts) tearing
// its own side down — measured on the process-freeze harness as a ~37 s
// convergence instead of ~7 s. Shorter than that 30 s so the edge is REBUILT
// rather than waited out, and comfortably longer than a healthy re-bind, which
// the same harness measures at about 2 s.
export const REBIND_AUTHENTICATION_DEADLINE_MS = 10_000;

// Bound every RTCPeerConnection operation awaited inside a room/peer
// negotiation critical section. close() aborts an in-flight addIceCandidate /
// setLocalDescription / setRemoteDescription WITHOUT settling its promise and
// fires no event, so an await on one can hang forever — holding the (room,
// peer) mutex and, because the socket ingress queue is strictly serial, every
// later signaling frame behind it. The poll interval is what "as soon as the
// PC closes" costs; the budget only has to outlive a legitimately slow
// operation on a live transport (a candidate add or SDP apply is milliseconds
// of local work, so seconds are already generous).
export const PC_OPERATION_POLL_MS = 100;
export const PC_OPERATION_TIMEOUT_MS = 8_000;

// Streaming send-side hash: read the file from disk one HASH_WINDOW_BYTES slice
// at a time (O(1) memory — never the whole file) and feed it to the WASM
// incremental SHA-512 in HASH_WASM_CHUNK_BYTES sub-chunks (the WASM heap buffer
// is tiny and fixed; the merkle module's memory can't grow). SSOT.
export const HASH_WINDOW_BYTES = 1024 * 1024; // 1 MiB disk read window
export const HASH_WASM_CHUNK_BYTES = 64 * 1024; // 64 KiB WASM update buffer

// Big-file storage in the Origin Private File System (OPFS), inside the DB
// worker (createSyncAccessHandle is worker-only / Safari-safe), so the whole
// file is never built in RAM. Two producers write here, keyed by merkleRoot:
//   - RECEIVE: each real chunk is written at its offset into a pre-sized file as
//     it arrives (receive-time write); IndexedDB keeps only the leaf-hash.
//   - SEND: a sent copy's IndexedDB chunks are streamed here on read.
// Falls back to an in-memory Blob where OPFS is unavailable.
export const OPFS_REASSEMBLE_DIR = "p2party-reassembled";

// Bounded reconciliation of a room that has nobody in it (roomRosterReconciler,
// wired in roomListenerMiddleware). Every other roster request in the SDK is
// caused by an event — a join, a server introduction, an edge teardown that
// re-dials — so a room whose last peer went away without producing one of those
// stays empty on a healthy, verified socket until the page is reloaded. These
// delays are the "ask again" schedule for exactly that state: 5 s is well past
// the join and re-dial debounce windows, the cap keeps a genuinely empty room
// (the common case: the user is first in) down to one request a minute, and the
// attempt cap stops it entirely after ~5 minutes of nothing changing.
export const ROOM_ROSTER_RECONCILE_DELAYS_MS = [
  5_000, 10_000, 20_000, 40_000, 60_000,
];
export const ROOM_ROSTER_RECONCILE_MAX_ATTEMPTS = 8;
// The reconciler's own debounce budget, under its own key so it can neither be
// swallowed by nor swallow a join or a re-dial. Shorter than the first backoff
// delay, so it never suppresses a scheduled attempt — it only bounds a room
// observed as stranded by two different code paths in the same instant.
export const ROOM_ROSTER_RECONCILE_DEBOUNCE_MS = 4_000;

// A signaling socket that closes without a browser wake event is otherwise
// terminal: settleClosedSocket dispatches disconnect() and nothing schedules
// another attempt, while the site's auto-connect is one-shot per room URL. A
// focused desktop tab therefore never reconnects, and every introduction the
// server routes toward that peer is dropped (its membership row keeps
// serverId=null). These are the retry delays for exactly that state. The last
// rung repeats: a server that is down for an hour must still be found when it
// returns, and a 30 s poll is cheap enough to run indefinitely.
export const SIGNALING_RECONNECT_DELAYS_MS = [
  1_000, 2_000, 4_000, 8_000, 15_000, 30_000,
];

// ── Blind-rendezvous prototype store, client and carrier runtime ────────────
// (prototype/store/*, prototype/storeClient.ts, prototype/carrierRuntime.ts)
//
// How far behind the clock a carrier runtime's schedule catches up, in windows.
// A page suspended for longer gives the older windows up whole and reports
// them missed, rather than coming back as a burst of every window it slept.
export const PROTOTYPE_MAX_READ_WINDOWS = 64;
// The furthest back, in windows, any request of an honest client lands at a
// store: a catch-up read reaches MAX_READ_WINDOWS + 1 back (reads lag the
// schedule by `publicReadLagWindows`), its answer may take up to one window
// (the client's request deadline), and a store clock ahead by under a window
// may already count one window more.
export const PROTOTYPE_READ_BACK_WINDOWS = PROTOTYPE_MAX_READ_WINDOWS + 3;
// A store's retention (inclusive, as `bucketIsReadable` defines it), stated in
// its signed descriptor. A store refuses to start below the minimum and a
// client refuses to use a store that states less, so no honest read ever
// meets an expired window. The default is about 17 minutes at the pinned
// 4,000 ms window and about 0.7 GB of idle rows per store.
export const PROTOTYPE_STORE_MIN_RETENTION_WINDOWS =
  PROTOTYPE_READ_BACK_WINDOWS;
export const PROTOTYPE_STORE_DEFAULT_RETENTION_WINDOWS = 256;
// One retention sweep deletes at most this many window rows, and as many
// witness windows; the entrypoint runs one per interval.
export const PROTOTYPE_STORE_SWEEP_BATCH_WINDOWS = 16;
export const PROTOTYPE_STORE_SWEEP_INTERVAL_MS = 1_000;
// Witness records one window holds from every caller together (the canonical
// cap of the records array), and new records one admission quota key may add.
export const PROTOTYPE_STORE_MAX_WITNESS_RECORDS_PER_WINDOW = 4_096;
export const PROTOTYPE_STORE_MAX_WITNESS_RECORDS_PER_QUOTA_KEY = 8;
// Units of work the store's mutation queue holds, queued and running. One
// window's honest work at the pinned profile is 8 allocations and 40 slot
// bindings; past the bound a request is answered 503 before it is queued.
export const PROTOTYPE_STORE_MAX_MUTATION_QUEUE_DEPTH = 64;
// Bytes of an admission token: the allocation body's `privacyPassToken`, and
// the `authorization: Bearer <hex>` value on append and witness.
export const PROTOTYPE_STORE_ADMISSION_TOKEN_BYTES = 32;
// `PRAGMA user_version` of the store's SQLite schema. 2 added the precomputed
// chunk and checkpoint response tables.
export const PROTOTYPE_STORE_SQLITE_SCHEMA_VERSION = 2;
// A store client tracks at most this many appends awaiting their answer, and
// keeps slot hashes for this many scanned windows for receipts that arrive
// after the scan.
export const PROTOTYPE_STORE_CLIENT_MAX_IN_FLIGHT_APPENDS = 1_024;
export const PROTOTYPE_STORE_CLIENT_MAX_SCANNED_WINDOWS = 16;

// The largest delay a platform timer honours (2^31 - 1 ms): a longer one fires
// at once.
export const MAX_TIMER_DELAY_MS = 0x7fffffff;
// Scheduled cover's shared timer worker (src/handlers/coverTimerWorker.ts).
// A wake-up this far past its deadline on the page's clock makes the page ask
// the worker to answer a ping; it is not taken as proof the worker is dead (a
// freeze, a system sleep or a long task makes every wake-up late too).
export const COVER_TIMER_WORKER_STALL_MS = 5_000;
// A worker that has not answered a ping by then is dropped for page timers.
export const COVER_TIMER_WORKER_PING_TIMEOUT_MS = 10_000;
// A ping timeout that runs this much past its own deadline ran after a page
// pause, perhaps ahead of the worker's queued answer: it waits one timeout more
// before the worker is dropped.
export const COVER_TIMER_WORKER_PING_LATE_MS = 1_000;
// How many replacements in a row a lost timer worker gets (each at a cycle
// boundary, the first no sooner than the backoff after the loss, each later
// one twice as long) before the page stays on page timers for good.
export const COVER_TIMER_WORKER_MAX_RESTARTS = 3;
export const COVER_TIMER_WORKER_RESTART_BACKOFF_MS = 1_000;
// A replacement that has delivered this many wake-ups has proved healthy: the
// count of replacements starts again, so only losses in quick succession
// exhaust it.
export const COVER_TIMER_WORKER_HEALTHY_WAKE_UPS = 100;
