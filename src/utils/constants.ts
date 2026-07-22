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

// Per-chunk sender authentication signs a domain-separated transcript
// (DOMAIN || merkle_root || ephemeral_pk) rather than the bare ephemeral public
// key, so a signature harvested from the raw-nonce server-challenge oracle
// cannot be replayed as chunk auth. Must byte-match the C side
// (CHUNK_AUTH_* in cryptography/utils.h).
export const CHUNK_AUTH_DOMAIN_BYTES = new TextEncoder().encode(
  "p2party-chunk-auth-v1",
); // 21 bytes
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
