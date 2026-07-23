import { assertMetadataV1, deserializeMetadata } from "../utils/metadata";
import { getMimeType, MessageType } from "../utils/messageTypes";
import { uint8ArrayToHex } from "../utils/uint8array";
import { isStorableChunkRange } from "../utils/chunkBounds";
import { createChunkReceiptToken } from "../utils/receiptToken";
import { MESSAGE_LEN, METADATA_LEN, PROOF_LEN } from "../utils/constants";
import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";

import { messageCacheKey } from "./messageChunkCrypto";
import { parseChunkFrameHeader } from "./chunkFrame";
import {
  decryptMessageChunkDurably,
  forgetReceiveMessageKeyDurably,
} from "./ratchetPersist";

import { storeReceiveChunk as persistReceiveChunk } from "../db/api";

import type { LibCrypto } from "../cryptography/libcrypto";
import type { IRTCPeerConnection } from "../api/webrtc/interfaces";
import type {
  ReceiveChunk,
  ReceiveChunkStoreResult,
} from "../db/types";

export interface ReceiveMessageResult {
  date: Date;
  chunkSize: number;
  chunkIndex: number;
  receivedFullSize: boolean;
  chunkAlreadyExists: boolean;
  totalSize: number;
  messageType: number;
  filename: string;
  /** 64-byte root/index/leaf-bound receipt token (legacy field name). */
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

type ReceiveChunkStore = (
  chunk: ReceiveChunk,
) => Promise<ReceiveChunkStoreResult>;

/**
 * Worker storage is the durability boundary for a receipt. A failed write must
 * look exactly like a decoy/drop to the caller, and the owned real-byte copy is
 * erased after postMessage has cloned it (or after an injected failure).
 */
export const storeReceiveChunkFailClosed = async (
  chunk: Omit<ReceiveChunk, "data">,
  realChunk: Uint8Array,
  store: ReceiveChunkStore = persistReceiveChunk,
): Promise<ReceiveChunkStoreResult | null> => {
  try {
    return await store({ ...chunk, data: realChunk.buffer as ArrayBuffer });
  } catch (error) {
    console.error("Could not durably store received chunk", error);
    return null;
  } finally {
    realChunk.fill(0);
  }
};

// ── protocol-v3 receive (Stage-5 task 3) ─────────────────────────────────────────
// Decrypt one inbound v3 CHUNK frame off the seeded Double Ratchet (replacing the
// authenticated v3 receive path), verify its Merkle proof, and store real bytes.
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
  channelLabel: string,
  epc: IRTCPeerConnection,
  merkleRoot: Uint8Array,
  module: LibCrypto,
  signal?: AbortSignal,
): Promise<ReceiveMessageResult> => {
  if (signal?.aborted) return dropped();
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

  // 1) Derive/decrypt against a staged clone, then persist and adopt the
  //    authenticated successor before exposing any plaintext. The per-edge lock
  //    also serializes concurrent send/receive ratchet transitions.
  let decrypted: Uint8Array | null;
  let ok: boolean;
  try {
    const d = await decryptMessageChunkDurably(
      epc,
      roomId,
      frame,
      cache,
      merkleRoot,
      module,
    );
    decrypted = d.decrypted;
    ok = d.ok;
  } catch (error) {
    console.error("Could not durably decrypt message", error);
    return dropped();
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
      if (epc.messageKeyByMerkleRoot) {
        for (const [root, mappedKey] of epc.messageKeyByMerkleRoot) {
          if (mappedKey === k) epc.messageKeyByMerkleRoot.delete(root);
        }
      }
    }
  }

  // 2) A drop (AEAD auth OR Merkle proof failed inside the C call, or a stale-chain
  //    replay) → emit a decoy receipt, don't store.
  if (!ok || !decrypted) {
    console.error("Could not decrypt or verify message");
    return dropped();
  }

  const merkleRootHex = uint8ArrayToHex(merkleRoot);
  epc.messageKeyByMerkleRoot ??= new Map<string, string>();
  epc.messageKeyByMerkleRoot.set(merkleRootHex, cacheKey);

  try {
    // Cancellation waits for this handler to quiesce before retiring the
    // mapped receive key. Stop before any plaintext reaches storage.
    if (signal?.aborted) return dropped();

    // 3) Split the C output: metadata ‖ receiptLeaf ‖ chunk. The C wrote the
    //    leaf hash SHA-512(0x00 ‖ chunk) over the proof region; that is the
    //    receipt token, so no second hash is computed here.
    const metadataArray = decrypted.subarray(0, METADATA_LEN);
    const leafHash = decrypted.slice(
      METADATA_LEN,
      METADATA_LEN + crypto_hash_sha512_BYTES,
    );
    const chunk = decrypted.subarray(METADATA_LEN + PROOF_LEN);
    const metadata = deserializeMetadata(metadataArray);
    assertMetadataV1(metadata);

    const chunkSize =
      metadata.chunkEndIndex - metadata.chunkStartIndex > metadata.totalSize
        ? 0
        : metadata.chunkEndIndex - metadata.chunkStartIndex > MESSAGE_LEN
          ? 0
          : metadata.chunkEndIndex - metadata.chunkStartIndex;

    const rejectedResult = (): ReceiveMessageResult => ({
      date: metadata.date,
      chunkIndex: -1,
      chunkSize: 0,
      receivedFullSize: false,
      chunkAlreadyExists: true,
      totalSize: metadata.totalSize,
      messageType: metadata.messageType,
      filename: metadata.name,
      chunkHash: leafHash,
      messageHash: metadata.hash,
    });

    if (chunkSize === 0) return rejectedResult();

    // The real-data offsets come from attacker-controllable metadata; reject
    // anything outside the padded chunk or inverted.
    if (
      !isStorableChunkRange(
        metadata.chunkStartIndex,
        metadata.chunkEndIndex,
        chunk.length,
      )
    )
      return rejectedResult();

    const receiptToken = await createChunkReceiptToken(
      merkleRoot,
      metadata.chunkIndex,
      leafHash,
    );
    if (signal?.aborted) {
      receiptToken.fill(0);
      return dropped();
    }
    const mimeType = getMimeType(metadata.messageType);
    // Create this owned plaintext copy only once all fallible preprocessing is
    // done; storeReceiveChunkFailClosed assumes ownership and always wipes it.
    const realChunk = chunk.slice(
      metadata.chunkStartIndex,
      metadata.chunkEndIndex,
    );

    const progress = await storeReceiveChunkFailClosed(
      {
        schemaVersion: metadata.schemaVersion,
        roomId,
        fromPeerId: epc.withPeerId,
        channelLabel,
        timestamp: metadata.date.getTime(),
        merkleRoot: merkleRootHex,
        hash: uint8ArrayToHex(metadata.hash),
        filename: metadata.name,
        messageType: metadata.messageType,
        chunkIndex: metadata.chunkIndex,
        mimeType,
        // Keep the leaf on the receiver so reconnect can derive the same scoped
        // token without retaining the padded body.
        leafHash: uint8ArrayToHex(leafHash),
        realLen: chunkSize,
        totalSize: metadata.totalSize,
        storage:
          metadata.messageType === MessageType.Text ? "indexeddb" : "opfs",
      },
      realChunk,
    );
    if (!progress) {
      receiptToken.fill(0);
      return dropped();
    }
    if (signal?.aborted) {
      // The worker write may already have crossed its durability boundary.
      // cancelReceiveTransfer queues a locked delete after this handler exits.
      receiptToken.fill(0);
      return dropped();
    }

    // `complete` comes from the same transaction that inserted/deduplicated
    // the chunk and updated messageData. A duplicate of an incomplete message
    // remains incomplete; a duplicate after a crash may safely re-emit the
    // idempotent terminal receipt for an already-durable complete message.
    const receivedFullSize = progress.complete;
    if (receivedFullSize && cacheKey) {
      await forgetReceiveMessageKeyDurably(
        epc,
        roomId,
        cache,
        cacheKey,
      );
      epc.messageKeyByMerkleRoot.delete(merkleRootHex);
    }

    return {
      date: metadata.date,
      chunkIndex: metadata.chunkIndex,
      chunkSize,
      receivedFullSize,
      chunkAlreadyExists: !progress.stored,
      totalSize: metadata.totalSize,
      messageType: metadata.messageType,
      filename: metadata.name,
      chunkHash: receiptToken,
      messageHash: metadata.hash,
    };
  } catch (error) {
    console.error("Could not parse or store decrypted message", error);
    return dropped();
  } finally {
    // `receiveWithKey` returned an owned plaintext copy. All returned metadata
    // and receipt fields are independent slices, so erase the padded body now.
    decrypted.fill(0);
  }
};
