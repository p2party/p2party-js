import { decryptAsymmetric } from "../cryptography/chacha20poly1305";
import { verifyMerkleProof } from "../cryptography/merkle";
import { verify } from "../cryptography/ed25519";
import {
  crypto_sign_ed25519_BYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
} from "../cryptography/interfaces";

import { existsDBChunk, getDBMessageData, setDBChunk } from "../db/api";

import { deserializeMetadata, METADATA_LEN } from "../utils/metadata";
import { PROOF_LEN } from "../utils/splitToChunks";
import { uint8ArrayToHex } from "../utils/uint8array";
import { getMimeType, MessageType } from "../utils/messageTypes";

import type { LibCrypto } from "../cryptography/libcrypto";
import { KB64 } from "./handleOpenChannel";
// import type { Room } from "../reducers/roomSlice";

export const handleReceiveMessage = async (
  data: ArrayBuffer,
  merkleRoot: Uint8Array,
  // hashHex: string,
  // fromPeerId: string,
  senderPublicKey: Uint8Array,
  receiverSecretKey: Uint8Array,
  // room: Room,
  // channelLabel: string,
  // api: BaseQueryApi,
  decryptionModule: LibCrypto,
  merkleModule: LibCrypto,
): Promise<{
  date: Date;
  chunkSize: number;
  savedSize: number;
  totalSize: number;
  chunkIndex: number;
  chunkHash: Uint8Array;
  messageHash: Uint8Array;
  receivedFullSize: boolean;
  messageAlreadyExists: boolean;
  chunkAlreadyExists: boolean;
  messageType: number; // MessageType;
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
        messageAlreadyExists: false,
        chunkAlreadyExists: false,
        savedSize: 0,
        totalSize: 0,
        messageType: MessageType.Text,
        filename: "",
        chunkHash: new Uint8Array(),
        messageHash: new Uint8Array(),
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
        : metadata.chunkEndIndex - metadata.chunkStartIndex > KB64
          ? 0
          : metadata.chunkEndIndex - metadata.chunkStartIndex;

    const realChunk =
      chunkSize > 0
        ? decryptedMessage.slice(
            METADATA_LEN + PROOF_LEN + metadata.chunkStartIndex,
            METADATA_LEN + PROOF_LEN + metadata.chunkEndIndex,
          )
        : decryptedMessage.slice(METADATA_LEN + PROOF_LEN);

    const chunkHashBuffer = await window.crypto.subtle.digest(
      "SHA-512",
      decryptedMessage.slice(METADATA_LEN + PROOF_LEN),
    );
    const chunkHash = new Uint8Array(chunkHashBuffer);

    if (chunkSize === 0)
      return {
        date: metadata.date,
        chunkIndex: -1,
        chunkSize: 0,
        receivedFullSize: false,
        messageAlreadyExists: false,
        chunkAlreadyExists: false,
        savedSize: 0,
        totalSize: metadata.totalSize,
        messageType: metadata.messageType,
        filename: metadata.name,
        chunkHash,
        messageHash: metadata.hash,
      };

    const merkleRootHex = uint8ArrayToHex(merkleRoot);
    // const incomingMessageIndex = room.messages.findLastIndex(
    //   (m) => m.merkleRootHex === merkleRootHex, // || m.sha512Hex === hashHex,
    // );

    const chunkAlreadyExists = await existsDBChunk(
      merkleRootHex,
      metadata.chunkIndex,
    );

    const messageExists = await getDBMessageData(merkleRootHex); //, hashHex);

    const alreadyHasEverything =
      messageExists != undefined &&
      messageExists.savedSize === messageExists.totalSize; // ||
    // (incomingMessageIndex > -1 &&
    //   room.messages[incomingMessageIndex].totalSize ===
    //     room.messages[incomingMessageIndex].savedSize);

    const messageRelevant =
      // incomingMessageIndex === -1 ||
      !messageExists ||
      (messageExists.savedSize + chunkSize <= messageExists.totalSize &&
        // (room.messages[incomingMessageIndex].totalSize >=
        //   room.messages[incomingMessageIndex].savedSize + chunkSize &&
        !chunkAlreadyExists);

    const receivedFullSize =
      alreadyHasEverything ||
      // (incomingMessageIndex > -1 &&
      //   !chunkAlreadyExists &&
      //   room.messages[incomingMessageIndex].totalSize ===
      //     room.messages[incomingMessageIndex].savedSize + chunkSize) ||
      // (incomingMessageIndex === -1 &&
      chunkSize === metadata.totalSize || //)
      (messageExists != undefined &&
        !chunkAlreadyExists &&
        messageExists.savedSize + chunkSize === messageExists.totalSize);

    if (!messageRelevant) {
      return {
        date: metadata.date,
        chunkIndex: -1,
        chunkSize, // incomingMessageIndex === -1 ? -1 : -2,
        receivedFullSize,
        messageAlreadyExists: messageExists != undefined,
        chunkAlreadyExists,
        savedSize: messageExists?.savedSize ?? 0,
        // incomingMessageIndex > -1
        //   ? room.messages[incomingMessageIndex].savedSize
        // :
        // messageExists ? messageExists.savedSize : 0,
        totalSize: metadata.totalSize,
        messageType: metadata.messageType,
        filename: metadata.name,
        chunkHash,
        messageHash: metadata.hash,
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
        date: metadata.date,
        chunkIndex: -1,
        chunkSize: -3,
        receivedFullSize,
        messageAlreadyExists: messageExists != undefined,
        chunkAlreadyExists,
        savedSize: messageExists?.savedSize ?? 0,
        // savedSize:
        // incomingMessageIndex > -1
        //   ? room.messages[incomingMessageIndex].savedSize
        // :
        // messageExists ? messageExists.savedSize : 0,
        totalSize: metadata.totalSize,
        messageType: metadata.messageType,
        filename: metadata.name,
        chunkHash,
        messageHash: metadata.hash,
      };

    const merkleProof = merkleProofArray.slice(4, 4 + proofLen);
    const chunk = decryptedMessage.slice(
      METADATA_LEN + PROOF_LEN,
      // METADATA_LEN + PROOF_LEN + metadata.chunkEndIndex,
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
        messageAlreadyExists: messageExists != undefined,
        chunkAlreadyExists,
        savedSize: messageExists?.savedSize ?? 0,
        // savedSize:
        // incomingMessageIndex > -1
        //   ? room.messages[incomingMessageIndex].savedSize
        // :
        // messageExists ? messageExists.savedSize : 0,
        totalSize: metadata.totalSize,
        messageType: metadata.messageType,
        filename: metadata.name,
        chunkHash,
        messageHash: metadata.hash,
      };

    const mimeType = getMimeType(metadata.messageType);

    try {
      if (!chunkAlreadyExists) {
        await setDBChunk({
          merkleRoot: merkleRootHex,
          hash: uint8ArrayToHex(metadata.hash),
          chunkIndex: metadata.chunkIndex,
          data: realChunk.buffer,
          mimeType,
        });
      }

      return {
        date: metadata.date,
        chunkIndex: metadata.chunkIndex,
        chunkSize,
        receivedFullSize,
        messageAlreadyExists: messageExists != undefined,
        chunkAlreadyExists,
        savedSize: messageExists?.savedSize ?? 0,
        // savedSize:
        // incomingMessageIndex > -1
        //   ? room.messages[incomingMessageIndex].savedSize
        // :
        // messageExists ? messageExists.savedSize : 0,
        totalSize: metadata.totalSize,
        messageType: metadata.messageType,
        filename: metadata.name,
        chunkHash,
        messageHash: metadata.hash,
      };
    } catch (error) {
      return {
        date: metadata.date,
        chunkIndex: metadata.chunkIndex,
        chunkSize: 0,
        receivedFullSize: messageExists != undefined ? receivedFullSize : false,
        messageAlreadyExists: messageExists != undefined,
        chunkAlreadyExists,
        savedSize: messageExists?.savedSize ?? 0,
        // savedSize:
        // incomingMessageIndex > -1
        //   ? room.messages[incomingMessageIndex].savedSize
        // :
        // messageExists ? messageExists.savedSize : 0,
        totalSize: 0,
        messageType: metadata.messageType,
        filename: metadata.name,
        chunkHash,
        messageHash: metadata.hash,
      };
    }
  } catch (error) {
    console.error(error);
    throw error;
  }
};
