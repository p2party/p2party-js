import { decryptAsymmetric } from "../cryptography/chacha20poly1305";
import { verifyMerkleProof } from "../cryptography/merkle";
import { verify } from "../cryptography/ed25519";
import {
  crypto_sign_ed25519_BYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
} from "../cryptography/interfaces";

import {
  // existsDBChunk,
  getDBChunk,
  setDBChunk,
} from "../db/api";
import { deserializeMetadata, METADATA_LEN } from "../utils/metadata";
import { PROOF_LEN } from "../utils/splitToChunks";
import { uint8ArrayToHex } from "../utils/uint8array";
import { getMimeType, MessageType } from "../utils/messageTypes";

import type { LibCrypto } from "../cryptography/libcrypto";
import type { Room } from "../reducers/roomSlice";

export const handleReceiveMessage = async (
  data: ArrayBuffer,
  merkleRoot: Uint8Array,
  senderPublicKey: Uint8Array,
  receiverSecretKey: Uint8Array,
  room: Room,
  decryptionModule: LibCrypto,
  merkleModule: LibCrypto,
): Promise<{
  date: Date;
  chunkSize: number;
  totalSize: number;
  chunkIndex: number;
  chunkHash: ArrayBuffer;
  receivedFullSize: boolean;
  messageType: MessageType;
  filename: string;
}> => {
  try {
    // const messageBuffer = await data.arrayBuffer();
    const message = new Uint8Array(data);
    const senderEphemeralPublicKey = message.slice(
      0,
      crypto_sign_ed25519_PUBLICKEYBYTES,
    );
    const sig = message.slice(
      crypto_sign_ed25519_PUBLICKEYBYTES,
      crypto_sign_ed25519_PUBLICKEYBYTES + crypto_sign_ed25519_BYTES,
    );

    const verifySig = await verify(
      senderEphemeralPublicKey,
      sig,
      senderPublicKey,
      decryptionModule,
    );

    if (!verifySig)
      return {
        date: new Date(),
        chunkIndex: -1,
        chunkSize: 0,
        receivedFullSize: false,
        totalSize: 0,
        messageType: MessageType.Text,
        filename: "",
        chunkHash: new Uint8Array().buffer,
      };

    const encryptedMessage = message.slice(
      crypto_sign_ed25519_PUBLICKEYBYTES + crypto_sign_ed25519_BYTES,
    );
    const decryptedMessage = await decryptAsymmetric(
      encryptedMessage,
      senderEphemeralPublicKey, // senderPublicKey,
      receiverSecretKey,
      merkleRoot,
      decryptionModule,
    );

    const metadata = deserializeMetadata(
      decryptedMessage.slice(0, METADATA_LEN),
    );

    const chunkSize =
      metadata.chunkEndIndex - metadata.chunkStartIndex > metadata.totalSize
        ? 0
        : metadata.chunkEndIndex - metadata.chunkStartIndex;

    const realChunk =
      chunkSize > 0
        ? decryptedMessage.slice(
            METADATA_LEN + PROOF_LEN + metadata.chunkStartIndex,
            METADATA_LEN + PROOF_LEN + metadata.chunkEndIndex,
          )
        : decryptedMessage.slice(METADATA_LEN + PROOF_LEN);

    const realChunkHash = await window.crypto.subtle.digest(
      "SHA-512",
      realChunk,
    );

    if (chunkSize === 0)
      return {
        date: metadata.date,
        chunkIndex: -1,
        chunkSize: 0,
        receivedFullSize: false,
        totalSize: metadata.totalSize,
        messageType: metadata.messageType,
        filename: metadata.name,
        chunkHash: realChunkHash,
      };

    const merkleRootHex = uint8ArrayToHex(merkleRoot);
    const incomingMessageIndex = room.messages.findIndex(
      (m) => m.merkleRootHex === merkleRootHex,
    );

    // const exists = await existsDBChunk(merkleRootHex, metadata.chunkIndex); //, db);
    const exists = await getDBChunk(merkleRootHex, metadata.chunkIndex);

    const messageRelevant =
      incomingMessageIndex === -1 ||
      (room.messages[incomingMessageIndex].totalSize >=
        room.messages[incomingMessageIndex].savedSize + chunkSize &&
        !exists);

    const receivedFullSize =
      incomingMessageIndex > -1
        ? room.messages[incomingMessageIndex].totalSize ===
          room.messages[incomingMessageIndex].savedSize + chunkSize
        : false;

    if (!messageRelevant)
      return {
        date: metadata.date,
        chunkIndex: -1,
        chunkSize: chunkSize === 0 ? 0 : incomingMessageIndex === -1 ? -1 : -2,
        receivedFullSize,
        totalSize: metadata.totalSize,
        messageType: metadata.messageType,
        filename: metadata.name,
        chunkHash: realChunkHash,
      };

    const merkleProofArray = decryptedMessage.slice(
      METADATA_LEN,
      METADATA_LEN + PROOF_LEN,
    );
    const proofLenView = new DataView(
      merkleProofArray.buffer,
      merkleProofArray.byteOffset,
      4,
    );
    const proofLen = proofLenView.getUint32(0, false); // Big-endian
    if (proofLen > PROOF_LEN)
      return {
        date: metadata.date,
        chunkIndex: -1,
        chunkSize: -3,
        receivedFullSize,
        totalSize: metadata.totalSize,
        messageType: metadata.messageType,
        filename: metadata.name,
        chunkHash: realChunkHash,
      };

    const merkleProof = merkleProofArray.slice(4, 4 + proofLen);
    const chunk = decryptedMessage.slice(
      METADATA_LEN + PROOF_LEN + metadata.chunkStartIndex,
      METADATA_LEN + PROOF_LEN + metadata.chunkEndIndex,
    );

    const verifyProof = await verifyMerkleProof(
      chunk,
      merkleRoot,
      merkleProof,
      merkleModule,
    );

    if (!verifyProof)
      return {
        date: metadata.date,
        chunkIndex: -1,
        chunkSize: -4,
        receivedFullSize,
        totalSize: metadata.totalSize,
        messageType: metadata.messageType,
        filename: metadata.name,
        chunkHash: realChunkHash,
      };

    const mimeType = getMimeType(metadata.messageType);

    await setDBChunk({
      merkleRoot: merkleRootHex,
      chunkIndex: metadata.chunkIndex,
      data: realChunk.buffer, // new Blob([realChunk]),
      mimeType,
    });

    return {
      date: metadata.date,
      chunkIndex: metadata.chunkIndex,
      chunkSize,
      receivedFullSize,
      totalSize: metadata.totalSize,
      messageType: metadata.messageType,
      filename: metadata.name,
      chunkHash: realChunkHash,
    };
  } catch (error) {
    console.error(error);
    throw error;
  }
};
