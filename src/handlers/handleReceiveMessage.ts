import { deserializeMetadata } from "../utils/metadata";
import { getMimeType, MessageType } from "../utils/messageTypes";
import { uint8ArrayToHex } from "../utils/uint8array";
import { isStorableChunkRange } from "../utils/chunkBounds";
import { MESSAGE_LEN, METADATA_LEN, PROOF_LEN } from "../utils/constants";
import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";

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
// Crypto: `decryptMessageChunk` derives the per-MESSAGE key off the ratchet (one
// step per message, cached per `(dhPub, N)`; clone-rollback so a replayed header
// can't desync the session), then hands the raw frame + key + expected root to the
// C `_receive_message_with_key`, which decrypts, hashes the leaf, verifies the
// Merkle proof, and writes the receipt leaf — the ENTIRE receive crypto in ONE
// libsodium call, in place, no TS↔WASM back-and-forth. On success it returns the
// DECRYPTED_LEN plaintext `metadata ‖ receiptLeaf ‖ chunk`; only frame parsing,
// ratchet bookkeeping, and storage remain in TS. The store-receipt tail below is
// verbatim from the box path.
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

  // 1) The ENTIRE receive crypto in one C call: derive the per-message key off the
  //    ratchet (clone-rollback), then `_receive_message_with_key` decrypts, hashes
  //    the leaf, verifies the Merkle proof, and writes the receipt — all libsodium.
  let decrypted: Uint8Array | null;
  let ok: boolean;
  let stateAdvanced: boolean;
  try {
    const d = decryptMessageChunk(epc.ratchetState, frame, cache, merkleRoot, module);
    decrypted = d.decrypted;
    ok = d.ok;
    stateAdvanced = d.stateAdvanced;
  } catch {
    console.error("Could not decrypt message");
    return dropped();
  }

  // 2) Persist the ratchet as soon as it advances (first-arriving chunk whose AEAD
  //    authenticated), so a crash after receipt can't replay the DH step — even if
  //    the chunk is then dropped for a bad Merkle proof.
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

  // 3) A drop (AEAD auth OR Merkle proof failed inside the C call, or a stale-chain
  //    replay) → emit a decoy receipt, don't store.
  if (!ok || !decrypted) {
    console.error("Could not decrypt or verify message");
    return dropped();
  }

  // 4) Split the C output: metadata ‖ receiptLeaf ‖ chunk. The C wrote the leaf
  //    hash SHA-512(0x00 ‖ chunk) over the (now-consumed) proof region — that IS
  //    the read-receipt token, so no second hash is computed here.
  const metadataArray = decrypted.slice(0, METADATA_LEN);
  const chunkHash = decrypted.slice(
    METADATA_LEN,
    METADATA_LEN + crypto_hash_sha512_BYTES,
  );
  const chunk = decrypted.slice(METADATA_LEN + PROOF_LEN);
  const metadata = deserializeMetadata(metadataArray);

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
