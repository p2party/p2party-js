import { decryptAsymmetric } from "../cryptography/chacha20poly1305";
import { verifyMerkleProof } from "../cryptography/merkle";

import { existsDBChunk, getDB, setDBChunk } from "../utils/db";
import { deserializeMetadata, METADATA_LEN } from "../utils/metadata";
import { PROOF_LEN } from "../utils/splitToChunks";
import { uint8ArrayToHex } from "../utils/uint8array";
import { getMimeType, MessageType } from "../utils/messageTypes";

import type { LibCrypto } from "../cryptography/libcrypto";
import type { Room } from "../reducers/roomSlice";

export const handleReceiveMessage = async (
  data: Blob, // Uint8Array,
  merkleRoot: Uint8Array,
  senderPublicKey: Uint8Array,
  receiverSecretKey: Uint8Array,
  room: Room,
  decryptionModule: LibCrypto,
  merkleModule: LibCrypto,
): Promise<{
  chunkIndex: number;
  chunkSize: number;
  totalSize: number;
  messageType: MessageType;
  filename: string;
}> => {
  try {
    const messageBuffer = await data.arrayBuffer();
    const encryptedMessage = new Uint8Array(messageBuffer);
    const decryptedMessage = await decryptAsymmetric(
      encryptedMessage,
      senderPublicKey,
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

    const merkleRootHex = uint8ArrayToHex(merkleRoot);
    const incomingMessageIndex = room.messages.findIndex(
      (m) => m.merkleRootHex === merkleRootHex,
    );

    const db = await getDB();

    const exists = await existsDBChunk(merkleRootHex, metadata.chunkIndex, db);

    const messageRelevant =
      chunkSize > 0 &&
      (incomingMessageIndex === -1 ||
        (room.messages[incomingMessageIndex].totalSize >=
          room.messages[incomingMessageIndex].savedSize + chunkSize &&
          !exists));

    if (!messageRelevant) {
      db.close();

      return {
        chunkIndex: -1,
        chunkSize: chunkSize === 0 ? 0 : incomingMessageIndex === -1 ? -1 : -2,
        totalSize: metadata.totalSize,
        messageType: metadata.messageType,
        filename: metadata.name,
      };
    }

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
        chunkIndex: -1,
        chunkSize: -3,
        totalSize: metadata.totalSize,
        messageType: metadata.messageType,
        filename: metadata.name,
      };

    const merkleProof = merkleProofArray.slice(4, 4 + proofLen);
    const chunk = decryptedMessage.slice(METADATA_LEN + PROOF_LEN);

    const verifyProof = await verifyMerkleProof(
      chunk,
      merkleRoot,
      merkleProof,
      merkleModule,
    );

    if (!verifyProof)
      return {
        chunkIndex: -1,
        chunkSize: -4,
        totalSize: metadata.totalSize,
        messageType: metadata.messageType,
        filename: metadata.name,
      };

    const realChunk = decryptedMessage.slice(
      METADATA_LEN + PROOF_LEN + metadata.chunkStartIndex,
      METADATA_LEN + PROOF_LEN + metadata.chunkEndIndex,
    );

    const mimeType = getMimeType(metadata.messageType);

    await setDBChunk(
      {
        merkleRoot: merkleRootHex,
        chunkIndex: metadata.chunkIndex,
        data: new Blob([realChunk]),
        mimeType,
      },
      db,
    );

    db.close();

    return {
      chunkIndex: metadata.chunkIndex,
      chunkSize,
      totalSize: metadata.totalSize,
      messageType: metadata.messageType,
      filename: metadata.name,
    };
  } catch (error) {
    throw error;
  }
};
