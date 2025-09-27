import { getMessageType, MessageType } from "./messageTypes";
import { uint8ArrayToHex } from "./uint8array";
import { serializeMetadata } from "./metadata";
import { CHUNK_LEN, IMPORTANT_DATA_LEN } from "./constants";

import {
  setDBNewChunk,
  deleteDBNewChunk,
  setDBRoomMessageData,
} from "../db/api";

import { setMessage, deleteMessage } from "../reducers/roomSlice";

import { getMerkleRoot } from "../cryptography/merkle";
import {
  generateRandomRoomUrl,
  randomNumberInRange,
} from "../cryptography/utils";
import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";
import type { Room } from "../reducers/roomSlice";
import type { LibCrypto } from "../cryptography/libcrypto";

export const metadataSchemaVersions = [1];

export const CANCEL_SEND = "CANCEL_SEND";

/**
 * Splits a Uint8Array into chunks of a specified size, padding with noise if necessary.
 * Ensures a minimum number of chunks are created.
 * Returns the chunks and the last valid byte index in the last chunk before padding.
 *
 * @param data - The Uint8Array to be split.
 * @param minChunks - The minimum number of chunks to produce.
 * @param chunkSize - The desired size of each chunk.
 * @param percentageFilledChunk - If = 1 then all chunk is filled with useful data. Range (0, 1].
 * @returns An object containing the chunks, their merkle proofs and the last valid byte index.
 */
export const splitToChunks = async (
  message: string | File,
  api: BaseQueryApi,
  label: string,
  room: Room,
  merkleModule: LibCrypto,
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

  if (minChunks < 1) throw new Error("Need at least one chunk.");
  if (percentageFilledChunk < 0.0001 || percentageFilledChunk > 1)
    throw new Error("Percentage of useful data in chunk should be in (0, 1].");
  if (!metadataSchemaVersions.includes(metadataSchemaVersion))
    throw new Error("Unknown metadata version schema.");
  if (chunkSize > CHUNK_LEN || chunkSize <= IMPORTANT_DATA_LEN)
    throw new Error(
      `Chunk length needs to be between ${String(IMPORTANT_DATA_LEN)} and ${String(CHUNK_LEN)}`,
    );

  let shouldStop = false;
  const onCancel = () => {
    shouldStop = true;
  };
  window.addEventListener(CANCEL_SEND, onCancel);

  const messageType = getMessageType(message);
  const name =
    messageType === MessageType.Text
      ? await generateRandomRoomUrl(256)
      : (message as File).name.substring(0, 255);

  const file =
    typeof message === "string" ? new TextEncoder().encode(message) : message;

  const storage = await navigator.storage.estimate();
  const quota = storage.quota ?? 10 * 1024 * 1024 * 1024;
  const usage = storage.usage ?? 64 * 1024;
  const availableSpace = quota - usage;

  const totalSize =
    // room.peers.length *
    typeof message === "string"
      ? (file as Uint8Array).length
      : (file as File).size;
  if (totalSize > availableSpace)
    throw new Error("Not enough space to save the file in the browser.");
  if (totalSize < 1) throw new Error("No data to split in chunks");

  const date = new Date();

  // TODO fix hasher
  const hashArrayBuffer = await window.crypto.subtle.digest(
    "SHA-512",
    totalSize < 10 * 1024 * 1024
      ? typeof message === "string"
        ? ((file as Uint8Array).buffer as ArrayBuffer)
        : await (file as File).arrayBuffer()
      : typeof message === "string"
        ? ((file as Uint8Array).subarray(0, 10 * 1024 * 1024)
            .buffer as ArrayBuffer)
        : await (file as File).slice(0, 10 * 1024 * 1024).arrayBuffer(),
  );
  const sha512 = new Uint8Array(hashArrayBuffer);
  const sha512Hex = uint8ArrayToHex(sha512);

  const m = {
    schemaVersion: metadataSchemaVersion,
    messageType,
    hash: sha512,
    name,
    totalSize,
    date,
  };

  let offset = 0;

  const totalChunks = Math.max(
    minChunks,
    Math.ceil(totalSize / (chunkSize * percentageFilledChunk)),
  );

  const chunk = new Uint8Array(chunkSize);
  const chunkHashes = new Uint8Array(totalChunks * crypto_hash_sha512_BYTES);
  const maxChunkStartIndex = Math.floor(
    chunkSize * (1 - percentageFilledChunk),
  );
  const maxBytesToCopy = Math.ceil(chunkSize * percentageFilledChunk);
  for (let i = 0; i < totalChunks; i++) {
    // Cancel event fired
    if (shouldStop) break;

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
        chunk.set(new Uint8Array(buffer), chunkStartIndex);
      }

      offset += bytesToCopy;
    } else {
      const start = chunkEndIndex + totalSize + 1;
      const end = Number.MAX_SAFE_INTEGER - start;
      const r = await randomNumberInRange(start, end);
      chunkEndIndex += r;
    }

    const h = await window.crypto.subtle.digest("SHA-512", chunk);
    const hash = new Uint8Array(h);
    const realChunkHash = uint8ArrayToHex(hash);
    chunkHashes.set(hash, i * crypto_hash_sha512_BYTES);

    const mSerialized = serializeMetadata({
      ...m,
      chunkStartIndex,
      chunkEndIndex,
      chunkIndex: i,
    });

    try {
      await setDBNewChunk({
        hash: sha512Hex,
        merkleRoot: "",
        chunkIndex: i,
        realChunkHash,
        data: chunk.buffer,
        metadata: mSerialized.buffer as ArrayBuffer,
        merkleProof: new Uint8Array().buffer,
      });
    } catch {
      /* ignore */
    } // (error) {
    //   console.error(error);
    // }

    api.dispatch(
      setMessage({
        roomId: room.id,
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

  if (shouldStop) {
    window.removeEventListener(CANCEL_SEND, onCancel);
    await deleteDBNewChunk(undefined, undefined, sha512Hex);
    api.dispatch(deleteMessage({ hashHex: sha512Hex }));

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
    );
  } catch (error) {
    console.error(error);
  }

  api.dispatch(
    setMessage({
      roomId: room.id,
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

  window.removeEventListener(CANCEL_SEND, onCancel);

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
