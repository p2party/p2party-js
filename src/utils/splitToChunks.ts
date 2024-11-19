import { getMessageType } from "./messageTypes";
import { serializer } from "./uint8array";
import { serializeMetadata, METADATA_LEN } from "./metadata";

import cryptoMemory from "../cryptography/memory";
import libcrypto from "../cryptography/libcrypto";
import { getMerkleProof, getMerkleRootFromProof } from "../cryptography/merkle";
import {
  generateRandomRoomUrl,
  randomNumberInRange,
} from "../cryptography/utils";
import {
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
  crypto_box_poly1305_AUTHTAGBYTES,
  crypto_hash_sha512_BYTES,
} from "../cryptography/interfaces";

export const PROOF_LEN =
  4 + // length of the proof
  48 * // let's say ceil(log2(tree)) <= 48
    (crypto_hash_sha512_BYTES + 1); // hash + position
export const CHUNK_LEN =
  64 * 1024 - // 64kb max message size on RTCDataChannel
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
 * @param chunkSize - The desired size of each chunk.
 * @param minChunks - The minimum number of chunks to produce.
 * @returns An object containing the chunks, their merkle proofs and the last valid byte index.
 */
export const splitToChunks = async (
  message: string | File,
  minChunks = 5, // TODO errors when =2 due to merkle
  chunkSize = CHUNK_LEN,
): Promise<{
  merkleRoot: Uint8Array;
  metadata: Uint8Array[];
  chunks: Uint8Array[];
  merkleProofs: Uint8Array[];
}> => {
  const data = await serializer(message);

  const messageType = getMessageType(message);
  const size = data.length;
  const name =
    typeof message === "string"
      ? await generateRandomRoomUrl(256)
      : message.name.slice(0, 255);
  const lastModified = new Date(
    typeof message === "string" ? Date.now() : message.lastModified,
  );
  // Every chunk is half data and half random bytes
  const totalChunks = Math.max(
    minChunks,
    2 * Math.ceil(data.length / chunkSize),
  );

  const merkleWasmMemory = cryptoMemory.getMerkleProofMemory(totalChunks);
  const merkleCryptoModule = await libcrypto({
    wasmMemory: merkleWasmMemory,
  });

  const chunks: Uint8Array[] = [];
  const metadata: Uint8Array[] = [];
  let offset = 0;
  for (let i = 0; i < totalChunks; i++) {
    const chunk = window.crypto.getRandomValues(new Uint8Array(chunkSize));

    const remainingBytes = data.length - offset;
    const bytesToCopy =
      remainingBytes > 0
        ? Math.min(remainingBytes, Math.ceil(chunkSize / 2))
        : 0;

    const chunkStartIndex = await randomNumberInRange(
      0,
      Math.floor(chunkSize / 2),
    );
    const chunkEndIndex = chunkStartIndex + bytesToCopy;

    if (remainingBytes > 0) {
      chunk.set(data.subarray(offset, offset + bytesToCopy), chunkStartIndex);
      offset += bytesToCopy;
    }

    const serializedMetadata = serializeMetadata({
      messageType,
      size,
      name,
      lastModified,
      chunkStartIndex,
      chunkEndIndex,
      // lastChunkSize: bytesToCopy,
      chunkIndex: i,
      totalChunks,
    });

    chunks.push(chunk);
    metadata.push(serializedMetadata);
  }

  // // Determine the last valid byte index in the last chunk before padding
  // let lastValidByteIndex = 0;
  // if (data.length === 0) {
  //   lastValidByteIndex = 0;
  // } else {
  //   const remainder = data.length % chunkSize;
  //   lastValidByteIndex = remainder === 0 ? chunkSize : remainder;
  // }

  const merkleProofs: Uint8Array[] = [];
  for (let i = 0; i < totalChunks; i++) {
    const proof = await getMerkleProof(
      chunks,
      chunks[i],
      merkleCryptoModule,
      PROOF_LEN,
    );
    merkleProofs.push(proof);
  }

  // chunkIndex (4 bytes)
  const proofLenView = new DataView(
    merkleProofs[0].buffer,
    merkleProofs[0].byteOffset,
    4,
  );
  const proofLen = proofLenView.getUint32(0, false); // Big-endian
  const merkleRoot = await getMerkleRootFromProof(
    chunks[0],
    merkleProofs[0].slice(4, proofLen + 4),
  );

  // const verify = await verifyMerkleProof(chunks[0], merkleRoot, merkleProofs[0].slice(4, 4 + proofLen))

  return { merkleRoot, metadata, chunks, merkleProofs };
};
