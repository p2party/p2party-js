import {
  getEncryptedLen,
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
  crypto_box_poly1305_AUTHTAGBYTES,
  crypto_hash_sha512_BYTES,
  crypto_sign_ed25519_BYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
} from "../cryptography/interfaces";

export const MESSAGE_LEN = 64 * 1024;
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
export const MESSAGE_START =
  crypto_sign_ed25519_PUBLICKEYBYTES + // ephemeral pk
  crypto_sign_ed25519_BYTES; // pk signed with identity sk
export const CHUNK_START =
  METADATA_LEN + // fixed
  PROOF_LEN; // Merkle proof max len of 3kb
export const MESSAGE_DATA_BEFORE_START_INDEX =
  MESSAGE_START + CHUNK_START + crypto_aead_chacha20poly1305_ietf_NPUBBYTES; // Encrypted message nonce
export const IMPORTANT_DATA_LEN =
  MESSAGE_DATA_BEFORE_START_INDEX + crypto_box_poly1305_AUTHTAGBYTES; // Encrypted message auth tag
export const CHUNK_LEN =
  MESSAGE_LEN - // 64kb max message size on RTCDataChannel
  // crypto_hash_sha512_BYTES - // merkle root of message
  IMPORTANT_DATA_LEN;
export const DECRYPTED_LEN = METADATA_LEN + PROOF_LEN + CHUNK_LEN;
export const ENCRYPTED_LEN = getEncryptedLen(DECRYPTED_LEN);

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
// CPace channel-input transcript marker (algorithm/epoch; value 0 in v3). It
// reserves transcript structure so a future hybrid KEM binds without a v4 wire
// break — it is NOT the KEM ciphertext. See spec §5/§10.
export const PQ_TAG_LEN = 1;
export const PQ_TAG = new Uint8Array(PQ_TAG_LEN); // [0]

// ── protocol-v3 CHUNK frame header (SSOT; byte-match in cryptography/utils.h when the
// C receive path is cut over in Stage-5 task 2) ─────────────────────────────────────
// A v3 message-chunk frame is:
//   FRAME_TYPE_CHUNK(1) ‖ dhPub(32) ‖ N(8 BE) ‖ PN(8 BE) ‖ PQ_EPOCH(1) ‖ nonce(12) ‖ ciphertext
// The ratchet header (dhPub, N, PN) is SHARED by every chunk of a message (one ratchet
// step per message); the 12-byte nonce is fresh + random per chunk. PQ_EPOCH is 0 in v3
// (reserved). Ciphertext begins at FRAME_TYPE_LEN + CHUNK_HEADER_LEN = 62 — the v3
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

// Per-chunk sender authentication signs a domain-separated transcript
// (DOMAIN || merkle_root || ephemeral_pk) rather than the bare ephemeral public
// key, so a signature harvested from the raw-nonce server-challenge oracle
// cannot be replayed as chunk auth. Must byte-match the C side
// (CHUNK_AUTH_* in cryptography/utils.h).
export const CHUNK_AUTH_DOMAIN_BYTES = new TextEncoder().encode(
  "p2party-chunk-auth-v1",
); // 21 bytes

// D2=B / SECURITY-1: domain separator for the Ed25519 cross-signature over the
// dedicated X25519 identity pub. The cross-sig signs
// (IDENTITY_CROSS_SIGN_DOMAIN_BYTES ‖ X25519_pub), NOT the bare pub, so it cannot
// collide with the login-challenge signing oracle (handleChallenge signs a raw
// 32-byte server-supplied nonce with the same Ed25519 identity key; a bare cross-sig
// would be forgeable by sending a chosen X25519 pub as that challenge). Same
// convention as CHUNK_AUTH_DOMAIN_BYTES above; TS-only (the cross-sig is
// produced/verified entirely in TS via ed25519 sign/verify — no C-side use).
export const IDENTITY_CROSS_SIGN_DOMAIN_BYTES = new TextEncoder().encode(
  "p2party-x25519-idsig-v1",
); // 23 bytes
export const CHUNK_AUTH_TRANSCRIPT_LEN =
  CHUNK_AUTH_DOMAIN_BYTES.length +
  crypto_hash_sha512_BYTES + // merkle root
  crypto_sign_ed25519_PUBLICKEYBYTES; // ephemeral pk

// CPace (PAKE, protocol-v3) generator-derivation domain separator. The TS CPace
// layer derives the session generator as
//   G = ristretto255_from_hash( SHA512(lv_cat(CPACE_DOMAIN, PRS, sid, CI)) )
// where lv_cat length-prefixes each field (IRTF draft-irtf-cfrg-cpace) so the
// transcript encoding is injective. This label domain-separates the CPace
// transcript from every other SHA-512 use in the codebase (the C-side
// cpace_ristretto255_from_hash is a bare wrapper with no built-in DSI, so the
// separation must live here). Same naming convention as CHUNK_AUTH_DOMAIN_BYTES
// above.
export const CPACE_DOMAIN = "p2party-cpace-v1";

// Double Ratchet KDF domain-separation labels (protocol-v3). These are the
// `info` strings for the two HKDF-SHA512 chains of the ratchet, and are SSOT
// constants that MUST byte-match any C-side kdf_rk/kdf_ck should one be added
// (the ratchet state machine currently derives them in TS on the compiled
// crypto_auth_hmacsha512 via hkdf.ts). Same "p2party-*-v1" convention as
// CPACE_DOMAIN above.
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
