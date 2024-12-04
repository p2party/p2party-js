import { getMessageType, getMimeType } from "./messageTypes";
import { serializer, uint8ArrayToHex, concatUint8Arrays } from "./uint8array";
import { serializeMetadata, METADATA_LEN } from "./metadata";
import { setDBChunk } from "./db";

import { setMessageAllChunks } from "../reducers/roomSlice";

import { rtcDataChannelMessageLimit } from "../api/webrtc";

import cryptoMemory from "../cryptography/memory";
import libcrypto from "../cryptography/libcrypto";
import { getMerkleProof, getMerkleRoot } from "../cryptography/merkle";
import {
  generateRandomRoomUrl,
  randomNumberInRange,
} from "../cryptography/utils";

import {
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
  crypto_box_poly1305_AUTHTAGBYTES,
  crypto_hash_sha512_BYTES,
} from "../cryptography/interfaces";
import type { Metadata } from "./metadata";
import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";
import type { IDBPDatabase } from "idb";
import type { RepoSchema } from "./db";

export const PROOF_LEN =
  4 + // length of the proof
  48 * (crypto_hash_sha512_BYTES + 1); // ceil(log2(tree)) <= 48 * (hash + position)
export const CHUNK_LEN =
  rtcDataChannelMessageLimit - // 64kb max message size on RTCDataChannel
  crypto_hash_sha512_BYTES - // merkle root of message
  METADATA_LEN - // fixed
  PROOF_LEN - // Merkle proof max len of 3kb
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES - // Encrypted message nonce
  crypto_box_poly1305_AUTHTAGBYTES; // Encrypted message auth tag

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
  db: IDBPDatabase<RepoSchema>,
  minChunks = 5, // TODO errors when =2 due to merkle
  chunkSize = CHUNK_LEN,
  percentageFilledChunk = 0.9,
): Promise<{
  merkleRoot: Uint8Array;
  unencryptedChunks: Uint8Array[];
}> => {
  if (percentageFilledChunk <= 0 || percentageFilledChunk > 1)
    throw new Error("Percentage of useful data in chunk should be in (0, 1].");

  const data = await serializer(message);

  const hashArrayBuffer = await window.crypto.subtle.digest("SHA-512", data);
  const dataHash = new Uint8Array(hashArrayBuffer);

  const messageType = getMessageType(message);
  const size = data.length;
  const name =
    typeof message === "string"
      ? await generateRandomRoomUrl(256)
      : message.name.slice(0, 255);
  const lastModified = new Date(
    typeof message === "string" ? Date.now() : message.lastModified,
  );

  const totalChunks = Math.max(
    minChunks,
    Math.ceil(size / (chunkSize * percentageFilledChunk)),
  );

  const merkleWasmMemory = cryptoMemory.getMerkleProofMemory(totalChunks);
  const merkleCryptoModule = await libcrypto({
    wasmMemory: merkleWasmMemory,
  });

  const chunks: Uint8Array[] = [];
  const chunkHashes = new Uint8Array(totalChunks * crypto_hash_sha512_BYTES);
  const metadata: Metadata[] = [];
  let offset = 0;
  for (let i = 0; i < totalChunks; i++) {
    const chunk = window.crypto.getRandomValues(new Uint8Array(chunkSize));

    const remainingBytes = data.length - offset;
    const bytesToCopy =
      remainingBytes > 0
        ? Math.min(remainingBytes, Math.ceil(chunkSize * percentageFilledChunk))
        : 0;

    const chunkStartIndex = await randomNumberInRange(
      0,
      Math.floor(chunkSize * (1 - percentageFilledChunk)),
    );
    const chunkEndIndex = chunkStartIndex + bytesToCopy;

    if (remainingBytes > 0) {
      chunk.set(data.slice(offset, offset + bytesToCopy), chunkStartIndex);
      offset += bytesToCopy;
    }

    chunks.push(chunk);
    metadata.push({
      messageType,
      size,
      name,
      hash: dataHash,
      lastModified,
      chunkStartIndex,
      chunkEndIndex,
      chunkIndex: i,
      totalChunks,
    });

    const hash = await window.crypto.subtle.digest("SHA-512", chunk);
    chunkHashes.set(new Uint8Array(hash), i * crypto_hash_sha512_BYTES);
  }

  const merkleRoot = await getMerkleRoot(chunkHashes, merkleCryptoModule);
  const merkleRootHex = uint8ArrayToHex(merkleRoot);

  // const merkleProofs: Uint8Array[] = [];
  const unencryptedChunks: Uint8Array[] = [];
  for (let i = 0; i < totalChunks; i++) {
    const proof = await getMerkleProof(
      chunkHashes,
      chunks[i],
      merkleCryptoModule,
      PROOF_LEN,
    );

    const realChunk = chunks[i].slice(
      metadata[i].chunkStartIndex,
      metadata[i].chunkEndIndex,
    );
    const mimeType = getMimeType(metadata[i].messageType);

    await setDBChunk(
      {
        merkleRoot: merkleRootHex,
        chunkIndex: metadata[i].chunkIndex,
        totalSize: metadata[i].size,
        data: new Blob([realChunk]), // uint8ArrayToHex(realChunk),
        mimeType,
      },
      db,
    );

    const m = serializeMetadata(metadata[i]);

    delete metadata[i];

    const unencrypted = await concatUint8Arrays([m, proof, chunks[i]]);

    delete chunks[i];

    unencryptedChunks.push(unencrypted);
  }

  const { keyPair } = api.getState() as State;

  api.dispatch(
    setMessageAllChunks({
      merkleRootHex,
      sha512Hex: uint8ArrayToHex(dataHash),
      fromPeerId: keyPair.peerId,
      totalSize: size,
      messageType,
      filename: name,
      channelLabel: label,
    }),
  );

  return { merkleRoot, unencryptedChunks };
};
