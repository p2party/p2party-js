import {
  crypto_aead_chacha20poly1305_ietf_ABYTES,
  crypto_hash_sha512_BYTES,
} from "../cryptography/interfaces";

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
export const PROOF_LEN =
  4 + // length of the proof
  48 * (crypto_hash_sha512_BYTES + 1); // ceil(log2(tree)) <= 48 * (hash + position)
export const CHUNK_START =
  METADATA_LEN + // fixed
  PROOF_LEN; // Merkle proof max len of 3kb
// The v3 profile freezes the authenticated plaintext cell at 65,412 bytes.
// This retains the deployed v3 Merkle/OPFS geometry and yields a uniform 65,490
// byte wire cell after the 62-byte ratchet header and 16-byte AEAD tag. Crypto
// overhead consumes the cell budget rather than changing observer-visible size.
export const CHUNK_PLAINTEXT_LEN = 65_412;
export const CHUNK_LEN = CHUNK_PLAINTEXT_LEN - CHUNK_START;
// Historical public send options require the configurable chunk payload to be
// larger than the non-payload budget. Keep that product bound explicitly named;
// it is not an on-wire box header.
export const CHUNK_SIZE_FLOOR = MESSAGE_LEN - CHUNK_LEN;
export const DECRYPTED_LEN = CHUNK_PLAINTEXT_LEN;

// ── protocol-v3 wire framing (SSOT; byte-matched in cryptography/utils.h) ─────
// Clean v3 break: every data-channel frame now begins with a 1-byte type tag so
// the inbound classifier is unambiguous (replaces the old length-only 64B /
// MESSAGE_LEN test). A mismatch here mis-routes frames silently, so the values
// are asserted equal to the C #defines by src/utils/constants.test.ts.
export const PROTOCOL_VERSION = 3;
export const FRAME_TYPE_LEN = 1;
export const FRAME_TYPE_HANDSHAKE = 1;
export const FRAME_TYPE_CHUNK = 2;
export const FRAME_TYPE_RECEIPT = 3;
// Receipts are protocol frames, not bare SHA-512 values. Both ordinary
// chunk acknowledgements and the terminal content-hash acknowledgement use
// this exact tagged geometry.
export const RECEIPT_TOKEN_LEN = crypto_hash_sha512_BYTES;
export const WIRE_RECEIPT_FRAME_LEN =
  FRAME_TYPE_LEN + RECEIPT_TOKEN_LEN; // 65
// CPace/channel-input suite marker. 0x01 means the mandatory protocol-v3
// classical-or-CPace + ML-KEM-768 hybrid bootstrap. It is transcript/KDF
// context, not the KEM ciphertext and not a negotiation/fallback bit.
export const PQ_TAG_LEN = 1;
export const PQ_TAG = new Uint8Array([0x01]);

// ── protocol-v3 CHUNK frame header (SSOT; byte-match in cryptography/utils.h when the
// C receive path is cut over in Stage-5 task 2) ─────────────────────────────────────
// A v3 message-chunk frame is:
//   FRAME_TYPE_CHUNK(1) ‖ dhPub(32) ‖ N(8 BE) ‖ PN(8 BE) ‖ PQ_EPOCH(1) ‖ nonce(12) ‖ ciphertext
// The ratchet header (dhPub, N, PN) is SHARED by every chunk of a message (one ratchet
// step per message); the 12-byte nonce is fresh + random per chunk. PQ_EPOCH=0
// truthfully names the bootstrap epoch established by the mandatory ML-KEM
// handshake; periodic/sparse KEM epoch advancement is not implemented here.
// Ciphertext begins at FRAME_TYPE_LEN + CHUNK_HEADER_LEN = 62 — the v3
// replacement for the box scheme's MESSAGE_START=96 (the send/receive swap that relocates
// MESSAGE_START is Stage-5 task 3; these constants are additive foundation). N/PN are the
// ratchet counters, serialized 8-byte big-endian, guarded < 2^53.
export const RATCHET_DHPUB_LEN = 32;
export const RATCHET_N_LEN = 8;
export const RATCHET_PN_LEN = 8;
export const PQ_EPOCH_LEN = 1;
export const RATCHET_NONCE_LEN = 12;
export const CHUNK_HEADER_LEN =
  RATCHET_DHPUB_LEN +
  RATCHET_N_LEN +
  RATCHET_PN_LEN +
  PQ_EPOCH_LEN +
  RATCHET_NONCE_LEN; // 61

// v3 message-chunk ON-WIRE header length (ciphertext begins here) = the byte the
// send path relocates to and the receive path parses from. REPLACES the box
// scheme's BOX_MESSAGE_HEADER_LEN (96) on the wire; byte-matches
// pake_ratchet.h MESSAGE_START and chunkFrame.ts CHUNK_FRAME_HEADER_LEN. It is
// intentionally decoupled from the DECRYPTED_LEN sizing above (Stage-5 task 3).
export const MESSAGE_START = FRAME_TYPE_LEN + CHUNK_HEADER_LEN; // 62
// Full v3 chunk frame length on the wire = header(62) ‖ ciphertext(DECRYPTED_LEN)
// ‖ AEAD tag(16) = 62 + 65412 + 16 = 65490. The receive-side frame classifier
// keys on this exact length + the leading FRAME_TYPE_CHUNK tag (the box frame was
// the full MESSAGE_LEN = 65536; the v3 frame is 46 bytes shorter because the
// ratchet header replaces the larger box header).
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

// Persisted/snapshot provenance for the one protocol-v3 bootstrap suite. The
// "3dh" name is deliberate: this is interactive triple-DH, not Signal's
// asynchronous X3DH prekey protocol. PIN policy adds exact draft-21 CPace.
export const RATCHET_ROOT_SUITE =
  "hybrid-3dh-mlkem768-cpace21-v3" as const;

// Double Ratchet KDF domain-separation labels (protocol-v3). These are the
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

// Wait this long for a per-message data channel to reach "open" before sending,
// so its first frames aren't spilled to the WS relay while it is still
// "connecting" (anything that still slips is recovered by reconcile()).
export const CHANNEL_OPEN_TIMEOUT_MS = 3000;
export const CHANNEL_OPEN_POLL_MS = 25;

// Resume-on-reconnect: a FULL peer reconnect (new RTCPeerConnection) destroys the
// per-message data channel — only "main" is auto-reopened — so an in-flight send
// must re-establish its own channel and continue. sendWithReconcile waits up to
// RECONNECT_RESUME_TIMEOUT_MS (polling every RECONNECT_RESUME_POLL_MS) for the
// peer's fresh connection to re-open the channel, and gives up after
// MAX_RESUME_ATTEMPTS reconnects so a flapping peer can't loop forever. The
// receiver re-emits its stored leaf-hash receipts on the new channel's onopen,
// so the sender rebuilds its acked-set and resends ONLY the still-missing reals.
export const RECONNECT_RESUME_TIMEOUT_MS = 30000;
export const RECONNECT_RESUME_POLL_MS = 500;
export const MAX_RESUME_ATTEMPTS = 3;

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
