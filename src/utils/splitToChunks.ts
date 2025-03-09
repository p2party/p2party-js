import { getMessageType, MessageType } from "./messageTypes";
import { uint8ArrayToHex } from "./uint8array";
import { serializeMetadata, METADATA_LEN } from "./metadata";

import { setDBNewChunk, setDBRoomMessageData } from "../db/api";

// import { setMessage } from "../reducers/roomSlice";

import cryptoMemory from "../cryptography/memory";
import libcrypto from "../cryptography/libcrypto";
import { getMerkleRoot } from "../cryptography/merkle";
import {
  generateRandomRoomUrl,
  randomNumberInRange,
} from "../cryptography/utils";
import {
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
  crypto_box_poly1305_AUTHTAGBYTES,
  crypto_hash_sha512_BYTES,
  crypto_sign_ed25519_BYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
} from "../cryptography/interfaces";

import type { Metadata } from "./metadata";
import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";

export const PROOF_LEN =
  4 + // length of the proof
  48 * (crypto_hash_sha512_BYTES + 1); // ceil(log2(tree)) <= 48 * (hash + position)
export const IMPORTANT_DATA_LEN =
  crypto_sign_ed25519_PUBLICKEYBYTES + // ephemeral pk
  crypto_sign_ed25519_BYTES + // pk signed with identity sk
  METADATA_LEN + // fixed
  PROOF_LEN + // Merkle proof max len of 3kb
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES + // Encrypted message nonce
  crypto_box_poly1305_AUTHTAGBYTES; // Encrypted message auth tag
export const CHUNK_LEN =
  64 * 1024 - // 64kb max message size on RTCDataChannel
  // crypto_hash_sha512_BYTES - // merkle root of message
  IMPORTANT_DATA_LEN;

export const metadataSchemaVersions = [1];

/**
 * Splits a Uint8Array into chunks of a specified size, padding with zeros if necessary.
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
  roomId: string,
  // db: IDBPDatabase<RepoSchema>,
  minChunks = 5, // TODO errors when =2 due to merkle
  chunkSize = CHUNK_LEN,
  percentageFilledChunk = 0.8,
  metadataSchemaVersion = 1,
): Promise<{
  merkleRoot: Uint8Array;
  merkleRootHex: string;
  hash: Uint8Array;
  hashHex: string;
  totalChunks: number;
  totalSize: number;
  messageType: MessageType;
  chunkHashes: Uint8Array;
}> => {
  // if (minChunks < 3) throw new Error("We need at least 3 chunks");
  if (percentageFilledChunk <= 0 || percentageFilledChunk > 1)
    throw new Error("Percentage of useful data in chunk should be in (0, 1].");
  if (!metadataSchemaVersions.includes(metadataSchemaVersion))
    throw new Error("Unknown metadata version schema.");
  if (chunkSize > CHUNK_LEN || chunkSize <= IMPORTANT_DATA_LEN)
    throw new Error(
      `Chunk length needs to be between ${IMPORTANT_DATA_LEN} and ${CHUNK_LEN}`,
    );

  const messageType = getMessageType(message);
  const name =
    messageType === MessageType.Text
      ? await generateRandomRoomUrl(256)
      : (message as File).name.slice(0, 255);

  const file =
    typeof message === "string" ? new TextEncoder().encode(message) : message;

  const storage = await navigator.storage.estimate();
  const quota = storage.quota ?? 10 * 1024 * 1024 * 1024;
  const usage = storage.usage ?? 64 * 1024;
  const availableSpace = quota - usage;

  const totalSize =
    typeof message === "string"
      ? (file as Uint8Array).length
      : (file as File).size;
  if (totalSize > availableSpace)
    throw new Error("Not enough space to save the file in the browser.");
  if (totalSize < 1) throw new Error("No data to split in chunks");

  const totalChunks = Math.max(
    minChunks,
    Math.ceil(totalSize / (chunkSize * percentageFilledChunk)),
  );

  const date = new Date();

  // TODO fix hasher
  const hashArrayBuffer = await window.crypto.subtle.digest(
    "SHA-512",
    totalSize < 10 * 1024 * 1024
      ? typeof message === "string"
        ? ((file as Uint8Array).buffer as ArrayBuffer)
        : await (file as File).arrayBuffer()
      : typeof message === "string"
        ? (file as Uint8Array).slice(0, 10 * 1024 * 1024).buffer
        : await (file as File).slice(0, 10 * 1024 * 1024).arrayBuffer(),
  );
  const hash = new Uint8Array(hashArrayBuffer);
  const sha512Hex = uint8ArrayToHex(hash);

  const chunkHashes = new Uint8Array(totalChunks * crypto_hash_sha512_BYTES);
  let offset = 0;
  for (let i = 0; i < totalChunks; i++) {
    const chunk = window.crypto.getRandomValues(new Uint8Array(chunkSize));

    const remainingBytes = totalSize - offset;
    const bytesToCopy =
      remainingBytes > 0
        ? Math.min(remainingBytes, Math.ceil(chunkSize * percentageFilledChunk))
        : 0;

    const chunkStartIndex = await randomNumberInRange(
      0,
      Math.floor(chunkSize * (1 - percentageFilledChunk)),
    );
    let chunkEndIndex = chunkStartIndex + bytesToCopy;

    if (remainingBytes > 0) {
      // new file read
      const blob = file.slice(offset, offset + bytesToCopy);
      if (typeof message === "string") {
        chunk.set(blob as Uint8Array, chunkStartIndex);

        const hash = await window.crypto.subtle.digest(
          "SHA-512",
          (blob as Uint8Array).buffer as ArrayBuffer,
        );
        chunkHashes.set(new Uint8Array(hash), i * crypto_hash_sha512_BYTES);
      } else {
        const buffer = await (blob as Blob).arrayBuffer();
        chunk.set(new Uint8Array(buffer), chunkStartIndex);

        const hash = await window.crypto.subtle.digest("SHA-512", buffer);
        chunkHashes.set(new Uint8Array(hash), i * crypto_hash_sha512_BYTES);
      }

      offset += bytesToCopy;
    } else {
      const start = chunkEndIndex + totalSize + 1;
      const end = Number.MAX_SAFE_INTEGER - start;
      const r = await randomNumberInRange(start, end);
      chunkEndIndex += r;

      const hash = await window.crypto.subtle.digest("SHA-512", chunk);
      chunkHashes.set(new Uint8Array(hash), i * crypto_hash_sha512_BYTES);
    }

    const m: Metadata = {
      schemaVersion: metadataSchemaVersion,
      messageType,
      name,
      chunkStartIndex,
      chunkEndIndex,
      chunkIndex: i,
      totalSize,
      date,
    };
    const mSerialized = serializeMetadata(m);

    await setDBNewChunk({
      hash: sha512Hex,
      merkleRoot: "",
      chunkIndex: i,
      realChunkHash: chunkHashes.slice(
        i * crypto_hash_sha512_BYTES,
        (i + 1) * crypto_hash_sha512_BYTES,
      ).buffer,
      data: chunk.buffer,
      metadata: mSerialized.buffer as ArrayBuffer,
      merkleProof: new Uint8Array().buffer,
    });
  }

  const merkleWasmMemory = cryptoMemory.getMerkleProofMemory(totalChunks);
  const merkleCryptoModule = await libcrypto({
    wasmMemory: merkleWasmMemory,
  });

  const merkleRoot = await getMerkleRoot(chunkHashes, merkleCryptoModule);
  const merkleRootHex = uint8ArrayToHex(merkleRoot);

  const { keyPair } = api.getState() as State;

  // api.dispatch(setMessageAllChunks(messageData));
  // api.dispatch(
  //   setMessage({
  //     roomId,
  //     merkleRootHex,
  //     sha512Hex,
  //     fromPeerId: keyPair.peerId,
  //     chunkSize: 0,
  //     totalSize,
  //     messageType,
  //     filename: name,
  //     channelLabel: label,
  //   }),
  // );

  await setDBRoomMessageData(
    roomId,
    merkleRootHex,
    sha512Hex,
    keyPair.peerId,
    totalSize,
    totalSize,
    messageType,
    name,
    label,
    Date.now(),
  );

  return {
    merkleRoot,
    merkleRootHex,
    hash,
    hashHex: sha512Hex,
    totalSize,
    totalChunks,
    messageType,
    chunkHashes,
  };
};
