import { getMessageType, getMimeType, MessageType } from "./messageTypes";
import { uint8ArrayToHex } from "./uint8array";
import { hashMerkleLeaf } from "./leafHash";
import { deserializeMetadata, serializeMetadata } from "./metadata";
import {
  CHUNK_LEN,
  CHUNK_SIZE_FLOOR,
  MAX_MESSAGE_SIZE,
  METADATA_LEN,
  PROOF_LEN,
} from "./constants";

import {
  setDBNewChunk,
  deleteDBNewChunk,
  deleteReceiveTransfer,
  getDBNewChunk,
  setDBChunk,
  setDBRoomMessageData,
} from "../db/api";

import { setMessage, deleteMessage } from "../reducers/roomSlice";

import { getMerkleRoot } from "../cryptography/merkle";
import { hashFileStreaming } from "../cryptography/hashStream";
import {
  generateRandomRoomUrl,
  randomNumberInRange,
} from "../cryptography/utils";
import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";
import type { Room } from "../reducers/roomSlice";
import type { LibCrypto } from "../cryptography/libcrypto";
import type { TransferAbortHandle } from "../handlers/transferAbort";

export const metadataSchemaVersions = [1];

export const planMessageChunkCount = (
  totalSize: number,
  minChunks = 1,
  chunkSize = CHUNK_LEN,
  percentageFilledChunk = 0.9,
): number => {
  if (minChunks < 1) throw new Error("Need at least one chunk.");
  if (percentageFilledChunk < 0.0001 || percentageFilledChunk > 0.99)
    throw new Error(
      "Percentage of useful data in chunk should be in (0, 0.99].",
    );
  if (chunkSize > CHUNK_LEN || chunkSize <= CHUNK_SIZE_FLOOR)
    throw new Error(
      `Chunk length needs to be between ${String(CHUNK_SIZE_FLOOR)} and ${String(CHUNK_LEN)}`,
    );
  if (!Number.isSafeInteger(totalSize) || totalSize < 1)
    throw new Error("No data to split in chunks");
  if (totalSize > MAX_MESSAGE_SIZE)
    throw new Error(
      `Message exceeds the ${String(MAX_MESSAGE_SIZE)} byte protocol limit`,
    );

  const maxRealBytesPerChunk = Math.ceil(
    chunkSize * percentageFilledChunk,
  );
  const realChunks = Math.ceil(totalSize / maxRealBytesPerChunk);

  return Math.max(minChunks, realChunks);
};

// IndexedDB accounts more than the source bytes: every outbound cell keeps its
// full padded body, metadata, eventual Merkle proof and record/index keys, while
// the sender's local message copy stores the real bytes once more. The fixed
// overhead is deliberately conservative; the real quota error is still allowed
// to propagate because browser accounting varies by implementation.
export const OUTBOUND_CHUNK_RECORD_OVERHEAD = 2048;
export const estimateOutboundStagingBytes = (
  totalSize: number,
  totalChunks: number,
  chunkSize: number,
): number => {
  if (
    !Number.isSafeInteger(totalSize) ||
    totalSize < 0 ||
    !Number.isSafeInteger(totalChunks) ||
    totalChunks < 1 ||
    !Number.isSafeInteger(chunkSize) ||
    chunkSize < 1
  )
    throw new Error("Invalid outbound staging geometry");
  const estimate =
    totalSize +
    totalChunks *
      (chunkSize +
        METADATA_LEN +
        PROOF_LEN +
        OUTBOUND_CHUNK_RECORD_OVERHEAD);
  return Number.isSafeInteger(estimate) ? estimate : Number.POSITIVE_INFINITY;
};

/**
 * Splits a Uint8Array into chunks of a specified size, padding with noise if necessary.
 * Ensures a minimum number of chunks are created.
 * Returns the chunks and the last valid byte index in the last chunk before padding.
 *
 * @param data - The Uint8Array to be split.
 * @param minChunks - The minimum number of chunks to produce.
 * @param chunkSize - The desired size of each chunk.
 * @param percentageFilledChunk - Useful-data fraction, range (0, 0.99]. The
 * remaining RNG padding gives each send a fresh Merkle-root namespace.
 * @returns An object containing the chunks, their merkle proofs and the last valid byte index.
 */
export const splitToChunks = async (
  message: string | File,
  api: BaseQueryApi,
  label: string,
  room: Room,
  merkleModule: LibCrypto,
  transfer: Pick<
    TransferAbortHandle,
    "transferId" | "signal" | "bindHash"
  >,
  minChunks = 1,
  chunkSize = CHUNK_LEN,
  percentageFilledChunk = 0.9,
  metadataSchemaVersion = 1,
): Promise<{
  merkleRoot: Uint8Array;
  merkleRootHex: string;
  hash: Uint8Array;
  hashHex: string;
  totalChunks: number;
  totalSize: number;
  messageType: number;
  chunkHashes: Uint8Array;
}> => {
  const { keyPair } = api.getState() as State;

  if (!metadataSchemaVersions.includes(metadataSchemaVersion))
    throw new Error("Unknown metadata version schema.");

  const messageType = getMessageType(message);
  const name =
    messageType === MessageType.Text
      ? await generateRandomRoomUrl(256)
      : (message as File).name.substring(0, 255);

  const file =
    typeof message === "string" ? new TextEncoder().encode(message) : message;

  const totalSize =
    // room.peers.length *
    typeof message === "string"
      ? (file as Uint8Array).length
      : (file as File).size;
  const totalChunks = planMessageChunkCount(
    totalSize,
    minChunks,
    chunkSize,
    percentageFilledChunk,
  );
  const storage = await navigator.storage.estimate();
  const quota = storage.quota ?? 10 * 1024 * 1024 * 1024;
  const usage = storage.usage ?? 64 * 1024;
  const availableSpace = Math.max(0, quota - usage);
  const stagingBytes = estimateOutboundStagingBytes(
    totalSize,
    totalChunks,
    chunkSize,
  );
  if (stagingBytes > availableSpace)
    throw new Error(
      "Not enough space to stage the padded encrypted transfer in the browser.",
    );

  const date = new Date();

  // Hash the full content. A string is already in memory (crypto.subtle). A File
  // is streamed from disk through the WASM incremental SHA-512 (hashFileStreaming)
  // so the whole file is never resident — this is what makes arbitrarily large
  // files sendable. Both produce plain SHA-512, so the value is unchanged.
  let sha512: Uint8Array;
  if (transfer.signal.aborted)
    throw transfer.signal.reason instanceof Error
      ? transfer.signal.reason
      : new Error("Message transfer cancelled");
  if (typeof message === "string") {
    const hashArrayBuffer = await window.crypto.subtle.digest(
      "SHA-512",
      (file as Uint8Array).buffer as ArrayBuffer,
    );
    sha512 = new Uint8Array(hashArrayBuffer);
  } else {
    sha512 = await hashFileStreaming(
      file as File,
      merkleModule,
      transfer.signal,
    );
  }
  if (transfer.signal.aborted)
    throw transfer.signal.reason instanceof Error
      ? transfer.signal.reason
      : new Error("Message transfer cancelled");
  const sha512Hex = uint8ArrayToHex(sha512);
  transfer.bindHash(sha512Hex);

  const m = {
    schemaVersion: metadataSchemaVersion,
    messageType,
    hash: sha512,
    name,
    totalSize,
    date,
  };

  let offset = 0;

  const chunk = new Uint8Array(chunkSize);
  const chunkHashes = new Uint8Array(totalChunks * crypto_hash_sha512_BYTES);
  const maxChunkStartIndex = Math.floor(
    chunkSize * (1 - percentageFilledChunk),
  );
  const maxBytesToCopy = Math.ceil(chunkSize * percentageFilledChunk);
  for (let i = 0; i < totalChunks; i++) {
    if (transfer.signal.aborted) break;

    window.crypto.getRandomValues(chunk);
    const chunkStartIndex = await randomNumberInRange(0, maxChunkStartIndex);
    const remainingBytes = totalSize - offset;
    const bytesToCopy = Math.min(Math.max(remainingBytes, 0), maxBytesToCopy);

    let chunkEndIndex = chunkStartIndex + bytesToCopy;

    if (remainingBytes > 0) {
      const blob = file.slice(offset, offset + bytesToCopy);
      if (typeof message === "string") {
        chunk.set(blob as Uint8Array, chunkStartIndex);
      } else {
        const buffer = await (blob as Blob).arrayBuffer();
        if (transfer.signal.aborted) break;
        chunk.set(new Uint8Array(buffer), chunkStartIndex);
      }

      offset += bytesToCopy;
    } else {
      const start = chunkEndIndex + totalSize + 1;
      const end = Number.MAX_SAFE_INTEGER - start;
      const r = await randomNumberInRange(start, end);
      chunkEndIndex += r;
    }

    const hash = await hashMerkleLeaf(chunk);
    const leafHash = uint8ArrayToHex(hash);
    chunkHashes.set(hash, i * crypto_hash_sha512_BYTES);

    const mSerialized = serializeMetadata({
      ...m,
      chunkStartIndex,
      chunkEndIndex,
      chunkIndex: i,
    });

    // A failed staging write is fatal. Sending a partial tree would make the
    // transfer unrecoverable while presenting misleading progress to the UI.
    await setDBNewChunk({
      transferId: transfer.transferId,
      hash: sha512Hex,
      merkleRoot: "",
      chunkIndex: i,
      leafHash,
      receiptToken: "",
      data: chunk.slice().buffer,
      metadata: mSerialized.buffer as ArrayBuffer,
      merkleProof: new Uint8Array().buffer,
    });

    api.dispatch(
      setMessage({
        roomId: room.id,
        transferId: transfer.transferId,
        merkleRootHex: "",
        sha512Hex,
        fromPeerId: keyPair.peerId,
        chunkSize: 0,
        totalSize,
        chunksCreated: i + 1,
        totalChunks,
        messageType,
        filename: name,
        channelLabel: label,
        timestamp: date.getTime(),
      }),
    );
  }

  if (transfer.signal.aborted) {
    await deleteDBNewChunk({ transferId: transfer.transferId });
    api.dispatch(
      deleteMessage({ roomId: room.id, transferId: transfer.transferId }),
    );

    return {
      merkleRoot: new Uint8Array(),
      merkleRootHex: "",
      hash: new Uint8Array(),
      hashHex: "",
      totalChunks: 0,
      totalSize: 0,
      messageType: 0,
      chunkHashes: new Uint8Array(),
    };
  }

  const merkleRoot = await getMerkleRoot(chunkHashes, merkleModule);
  const merkleRootHex = uint8ArrayToHex(merkleRoot);

  try {
    // Persist the sender's real-byte copy exactly once, independent of peer
    // count. The old per-peer send loop rewrote N copies and stored none at all
    // for an offline room while metadata falsely claimed 100% durability.
    const mimeType = getMimeType(messageType);
    for (let i = 0; i < totalChunks; i++) {
      if (transfer.signal.aborted) break;
      const staged = await getDBNewChunk(transfer.transferId, i);
      if (!staged)
        throw new Error(`Missing staged outbound chunk ${String(i)}`);
      const metadata = deserializeMetadata(new Uint8Array(staged.metadata));
      const realLen = metadata.chunkEndIndex - metadata.chunkStartIndex;
      if (realLen <= 0 || realLen > metadata.totalSize) continue;
      await setDBChunk({
        merkleRoot: merkleRootHex,
        hash: sha512Hex,
        chunkIndex: metadata.chunkIndex,
        data: staged.data.slice(
          metadata.chunkStartIndex,
          metadata.chunkEndIndex,
        ),
        mimeType,
      });
    }
  } catch (error) {
    await deleteReceiveTransfer(merkleRootHex);
    throw error;
  }
  if (transfer.signal.aborted) {
    await deleteDBNewChunk({ transferId: transfer.transferId });
    await deleteReceiveTransfer(merkleRootHex);
    api.dispatch(
      deleteMessage({ roomId: room.id, transferId: transfer.transferId }),
    );
    return {
      merkleRoot: new Uint8Array(),
      merkleRootHex: "",
      hash: new Uint8Array(),
      hashHex: "",
      totalChunks: 0,
      totalSize: 0,
      messageType: 0,
      chunkHashes: new Uint8Array(),
    };
  }

  // Do not claim a fully durable local message until every self-copy write
  // above succeeded. IndexedDB quota/write failures propagate to the caller.
  try {
    await setDBRoomMessageData(
      room.id,
      merkleRootHex,
      sha512Hex,
      keyPair.peerId,
      totalSize,
      totalSize,
      messageType,
      name,
      label,
      date.getTime(),
      transfer.transferId,
    );
  } catch (error) {
    await deleteReceiveTransfer(merkleRootHex);
    throw error;
  }

  api.dispatch(
    setMessage({
      roomId: room.id,
      transferId: transfer.transferId,
      merkleRootHex,
      sha512Hex,
      fromPeerId: keyPair.peerId,
      chunkSize: 0,
      totalSize,
      chunksCreated: totalChunks,
      totalChunks,
      messageType,
      filename: name,
      channelLabel: label,
      timestamp: date.getTime(),
    }),
  );

  return {
    merkleRoot,
    merkleRootHex,
    hash: sha512,
    hashHex: sha512Hex,
    totalSize,
    totalChunks,
    messageType,
    chunkHashes,
  };
};
