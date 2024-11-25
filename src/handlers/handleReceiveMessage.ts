import { decryptAsymmetric } from "../cryptography/chacha20poly1305";
import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";
import { verifyMerkleProof } from "../cryptography/merkle";

import { setMessage } from "../reducers/roomSlice";

import { getDB, getDBChunk, setDBChunk } from "../utils/db";
import { deserializeMetadata, METADATA_LEN } from "../utils/metadata";
import { PROOF_LEN } from "../utils/splitToChunks";
import { uint8ArrayToHex } from "../utils/uint8array";
import { getMimeType } from "../utils/messageTypes";

import type { LibCrypto } from "../cryptography/libcrypto";
import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";

export const handleReceiveMessage = async (
  data: Blob, // Uint8Array,
  senderPublicKey: Uint8Array,
  receiverSecretKey: Uint8Array,
  decryptionModule: LibCrypto,
  channelLabel: string,
  fromPeerId: string,
  api: BaseQueryApi,
) => {
  try {
    const { room } = api.getState() as State;
    const incomingMessages = room.messages;

    const messageBuffer = await data.arrayBuffer();
    const message = new Uint8Array(messageBuffer);

    const merkleRoot = message.slice(0, crypto_hash_sha512_BYTES); // data.slice(0, crypto_hash_sha512_BYTES);
    const merkleRootHex = uint8ArrayToHex(merkleRoot);

    const encryptedMessage = message.slice(crypto_hash_sha512_BYTES); // data.slice(crypto_hash_sha512_BYTES);
    const decryptedMessage = await decryptAsymmetric(
      encryptedMessage,
      senderPublicKey,
      receiverSecretKey,
      merkleRoot,
      decryptionModule,
    );

    const metadataSerialized = decryptedMessage.slice(0, METADATA_LEN);
    const metadata = deserializeMetadata(metadataSerialized);

    const chunkLen = metadata.chunkEndIndex - metadata.chunkStartIndex;

    const incomingMessageIndex = incomingMessages.findIndex(
      (m) => m.merkleRootHex === merkleRootHex,
    );
    const messageRelevant =
      chunkLen > 0 &&
      (incomingMessageIndex === -1 ||
        (!incomingMessages[incomingMessageIndex].chunkIndexes.includes(
          metadata.chunkIndex,
        ) &&
          incomingMessages[incomingMessageIndex].totalSize >=
            incomingMessages[incomingMessageIndex].savedSize + chunkLen));

    if (messageRelevant) {
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
      const merkleProof = merkleProofArray.subarray(4, 4 + proofLen);
      const chunk = decryptedMessage.slice(METADATA_LEN + PROOF_LEN);
      const verifyProof = await verifyMerkleProof(
        chunk,
        merkleRoot,
        merkleProof,
      );

      if (verifyProof) {
        api.dispatch(
          setMessage({
            merkleRootHex: uint8ArrayToHex(merkleRoot),
            fromPeerId,
            chunkIndex: metadata.chunkIndex,
            chunkSize: metadata.chunkEndIndex - metadata.chunkStartIndex,
            totalSize: metadata.size,
            messageType: metadata.messageType,
            filename: metadata.name,
            channelLabel,
          }),
        );

        const realChunk = decryptedMessage.slice(
          METADATA_LEN + PROOF_LEN + metadata.chunkStartIndex,
          METADATA_LEN +
            PROOF_LEN +
            // metadata.chunkStartIndex +
            metadata.chunkEndIndex,
        );

        const db = await getDB();
        const storedChunk = await getDBChunk(
          merkleRootHex,
          metadata.chunkIndex,
          db,
        );
        if (!storedChunk) {
          const mimeType = getMimeType(metadata.messageType);

          await setDBChunk(
            {
              merkleRoot: merkleRootHex,
              chunkIndex: metadata.chunkIndex,
              totalSize: metadata.size,
              data: new Blob([realChunk]), // uint8ArrayToHex(realChunk),
              mimeType,
            },
            db,
          );
        }

        db.close();
      }
    }
  } catch (error) {
    throw error;
  }
};
