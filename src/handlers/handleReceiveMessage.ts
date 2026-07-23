import { deserializeMetadata } from "../utils/metadata";
import { getMimeType, MessageType } from "../utils/messageTypes";
import { uint8ArrayToHex } from "../utils/uint8array";
import { isStorableChunkRange } from "../utils/chunkBounds";
import { MESSAGE_LEN, METADATA_LEN, PROOF_LEN } from "../utils/constants";
import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";
import { verifyMerkleProof } from "../cryptography/merkle";
import { hashMerkleLeafWasm } from "../utils/leafHash";

import { decryptMessageChunk, messageCacheKey } from "./messageChunkCrypto";
import { parseChunkFrameHeader } from "./chunkFrame";
import { persistRatchetSession } from "./ratchetPersist";

import { getDBMessageData, setDBChunk, storeReceiveChunk } from "../db/api";

import type { LibCrypto } from "../cryptography/libcrypto";
import type { IRTCPeerConnection } from "../api/webrtc/interfaces";

export interface ReceiveMessageResult {
  date: Date;
  chunkSize: number;
  chunkIndex: number;
  receivedFullSize: boolean;
  chunkAlreadyExists: boolean;
  totalSize: number;
  messageType: number;
  filename: string;
  chunkHash: Uint8Array;
  messageHash: Uint8Array;
}

// Uniform "not stored / crypto-failed" result — the queueing layer reacts to it
// by emitting a decoy receipt (so the reverse count still matches the forward
// frame count) and skipping storage. Mirrors the box path's error returns.
const dropped = (): ReceiveMessageResult => ({
  date: new Date(),
  chunkIndex: -1,
  chunkSize: 0,
  receivedFullSize: false,
  chunkAlreadyExists: false,
  totalSize: 0,
  messageType: MessageType.Text,
  filename: "",
  chunkHash: new Uint8Array(),
  messageHash: new Uint8Array(),
});

// ── protocol-v3 receive (Stage-5 task 3) ─────────────────────────────────────────
// Decrypt one inbound v3 CHUNK frame off the seeded Double Ratchet (replacing the
// box `_receive_message` path), verify its Merkle proof, and store the real bytes.
//
// Crypto: `decryptMessageChunk` derives/uses the per-MESSAGE key (one ratchet step
// per message, cached per `(dhPub, N)` on the edge; clone-rollback so a replayed
// header can't desync the session) and AEAD-opens the chunk to the DECRYPTED_LEN
// plaintext `metadata ‖ merkle-proof ‖ chunk`. When the ratchet advanced we persist
// it. Every crypto primitive on this path runs in libsodium/C: the AEAD open
// (`_decrypt_chachapoly_symmetric`), the Merkle proof walk (`_verify_merkle_proof`),
// and the domain-separated leaf/receipt hash (`hashMerkleLeafWasm` → `_sha512_*`) —
// byte-identical to what the C `receive_message` did over the same plaintext. Only
// the frame parsing, ratchet-state bookkeeping, and storage are TS. The
// verify-store-receipt tail below is verbatim from the box path.
export const handleReceiveMessage = async (
  frame: Uint8Array,
  roomId: string,
  epc: IRTCPeerConnection,
  merkleRoot: Uint8Array,
  module: LibCrypto,
): Promise<ReceiveMessageResult> => {
  if (!epc.ratchetState) {
    // Ratchet not established yet (should not happen: the queue awaits the gate
    // before draining) — drop rather than mis-decrypt.
    console.error("v3 receive: no ratchet state for peer");
    return dropped();
  }
  if (!epc.messageKeyCache) epc.messageKeyCache = new Map<string, Uint8Array>();
  const cache = epc.messageKeyCache;

  // The per-message cache key (dhPub, N) — used to evict the key when the message
  // completes so a peer can't pin keys with never-completing messages.
  let cacheKey: string | undefined;
  try {
    const { header } = parseChunkFrameHeader(frame);
    cacheKey = messageCacheKey(header.dhPub, header.N);
  } catch {
    return dropped();
  }

  // 1) Ratchet + AEAD. Throws on auth failure (clone-rollback already left the
  //    live state untouched) — treat exactly like the box "could not decrypt".
  let plaintext: Uint8Array;
  let stateAdvanced: boolean;
  try {
    const d = decryptMessageChunk(epc.ratchetState, frame, cache, merkleRoot, module);
    plaintext = d.plaintext;
    stateAdvanced = d.stateAdvanced;
  } catch {
    console.error("Could not decrypt message");
    return dropped();
  }

  // 2) Persist the ratchet as soon as it advances (the first-arriving chunk of a
  //    message), so a crash after receipt can't replay the DH step.
  if (stateAdvanced) {
    try {
      await persistRatchetSession(epc, roomId);
    } catch (error) {
      console.error(error);
    }
  }

  // Anti-DoS backstop: a completing message evicts its own key below, but a peer
  // could pin keys with never-completing messages. Bound the per-edge cache,
  // evicting oldest first (a Map preserves insertion order).
  const MESSAGE_KEY_CACHE_MAX = 256;
  if (cache.size > MESSAGE_KEY_CACHE_MAX) {
    for (const k of cache.keys()) {
      if (cache.size <= MESSAGE_KEY_CACHE_MAX) break;
      cache.get(k)?.fill(0);
      cache.delete(k);
    }
  }

  // 3) Split the plaintext: metadata ‖ merkle-proof(4B len ‖ artifacts) ‖ chunk.
  const metadataArray = plaintext.slice(0, METADATA_LEN);
  const proofRegion = plaintext.slice(METADATA_LEN, METADATA_LEN + PROOF_LEN);
  const chunk = plaintext.slice(METADATA_LEN + PROOF_LEN);
  const metadata = deserializeMetadata(metadataArray);

  // 4) Verify the Merkle proof over the domain-separated leaf SHA-512(0x00 ‖ chunk)
  //    against the message root. proofLen is a big-endian u32 prefix; reject a
  //    malformed length (box path return -3) or a proof that doesn't fold to the
  //    root (return -6).
  const proofLen =
    (proofRegion[0] << 24) |
    (proofRegion[1] << 16) |
    (proofRegion[2] << 8) |
    proofRegion[3];
  if (
    proofLen % (crypto_hash_sha512_BYTES + 1) !== 0 ||
    proofLen > PROOF_LEN - 4 ||
    proofLen <= 0
  ) {
    console.error("Merkle proof length is wrong");
    return dropped();
  }
  const proof = proofRegion.slice(4, 4 + proofLen);
  try {
    const ok = await verifyMerkleProof(chunk, merkleRoot, proof, module);
    if (!ok) {
      console.error("Could not verify Merkle proof");
      return dropped();
    }
  } catch (error) {
    console.error(error);
    return dropped();
  }

  // The read-receipt token is the leaf hash (SHA-512(0x00 ‖ chunk)) — the same
  // value the sender used as the Merkle leaf (splitToChunks). Computed in
  // libsodium (C), matching the C `receive_message_with_key` receipt.
  const chunkHash = hashMerkleLeafWasm(chunk, module);

  const realChunk = chunk.slice(
    metadata.chunkStartIndex,
    metadata.chunkEndIndex,
  );

  const chunkSize =
    metadata.chunkEndIndex - metadata.chunkStartIndex > metadata.totalSize
      ? 0
      : metadata.chunkEndIndex - metadata.chunkStartIndex > MESSAGE_LEN
        ? 0
        : metadata.chunkEndIndex - metadata.chunkStartIndex;

  const evict = () => {
    if (cacheKey) {
      cache.get(cacheKey)?.fill(0);
      cache.delete(cacheKey);
    }
  };

  if (chunkSize === 0)
    return {
      date: metadata.date,
      chunkIndex: -1,
      chunkSize: 0,
      receivedFullSize: false,
      chunkAlreadyExists: true,
      totalSize: metadata.totalSize,
      messageType: metadata.messageType,
      filename: metadata.name,
      chunkHash,
      messageHash: metadata.hash,
    };

  // The real-data offsets come from attacker-controllable metadata; reject any
  // that would slice outside the chunk or are inverted, so a malicious sender
  // cannot store the wrong bytes and corrupt reassembly.
  if (
    !isStorableChunkRange(
      metadata.chunkStartIndex,
      metadata.chunkEndIndex,
      chunk.length,
    )
  )
    return {
      date: metadata.date,
      chunkIndex: -1,
      chunkSize: 0,
      receivedFullSize: false,
      chunkAlreadyExists: true,
      totalSize: metadata.totalSize,
      messageType: metadata.messageType,
      filename: metadata.name,
      chunkHash,
      messageHash: metadata.hash,
    };

  const merkleRootHex = uint8ArrayToHex(merkleRoot);
  const messageExists = await getDBMessageData(merkleRootHex);

  const alreadyHasEverything =
    messageExists != undefined &&
    messageExists.savedSize === messageExists.totalSize;

  const messageRelevant =
    !messageExists ||
    messageExists.savedSize + chunkSize <= messageExists.totalSize;

  const receivedFullSize =
    alreadyHasEverything ||
    chunkSize === metadata.totalSize ||
    (messageExists?.savedSize !== undefined &&
      messageExists.savedSize + chunkSize === messageExists.totalSize);

  if (receivedFullSize) evict();

  if (!messageRelevant)
    return {
      date: metadata.date,
      chunkIndex: -1,
      chunkSize,
      receivedFullSize,
      chunkAlreadyExists: true,
      totalSize: metadata.totalSize,
      messageType: metadata.messageType,
      filename: metadata.name,
      chunkHash,
      messageHash: metadata.hash,
    };

  const mimeType = getMimeType(metadata.messageType);

  try {
    let stored: boolean;
    if (metadata.messageType === MessageType.Text) {
      // Text is small and read back via Blob.text(), so keep its bytes in
      // IndexedDB (no OPFS file). setDBChunk throws on a duplicate key.
      await setDBChunk({
        merkleRoot: merkleRootHex,
        hash: uint8ArrayToHex(metadata.hash),
        chunkIndex: metadata.chunkIndex,
        data: realChunk.buffer,
        mimeType,
        realLen: chunkSize,
        // Persist the exact receipt token so it can be re-emitted verbatim on
        // reconnect (the padded chunk it was hashed over is discarded).
        leafHash: uint8ArrayToHex(chunkHash),
      });
      stored = true;
    } else {
      // FILE: write the real bytes straight into the message's pre-sized OPFS
      // file at chunkIndex*uniformSize; IndexedDB keeps only the leaf-hash
      // have-set (bytesless). Returns false if already stored.
      stored = await storeReceiveChunk({
        merkleRoot: merkleRootHex,
        hash: uint8ArrayToHex(metadata.hash),
        chunkIndex: metadata.chunkIndex,
        mimeType,
        leafHash: uint8ArrayToHex(chunkHash),
        realLen: chunkSize,
        totalSize: metadata.totalSize,
        data: realChunk.buffer,
      });
    }

    return {
      date: metadata.date,
      chunkIndex: metadata.chunkIndex,
      chunkSize,
      receivedFullSize,
      chunkAlreadyExists: !stored,
      totalSize: metadata.totalSize,
      messageType: metadata.messageType,
      filename: metadata.name,
      chunkHash,
      messageHash: metadata.hash,
    };
  } catch {
    return {
      date: metadata.date,
      chunkIndex: metadata.chunkIndex,
      chunkSize,
      receivedFullSize,
      chunkAlreadyExists: true,
      totalSize: metadata.totalSize,
      messageType: metadata.messageType,
      filename: metadata.name,
      chunkHash,
      messageHash: metadata.hash,
    };
  }
};
