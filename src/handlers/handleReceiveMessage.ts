import { deserializeMetadata } from "../utils/metadata";
import { getMimeType, MessageType } from "../utils/messageTypes";
import { uint8ArrayToHex } from "../utils/uint8array";
import { MESSAGE_LEN, METADATA_LEN, PROOF_LEN } from "../utils/constants";

import { existsDBChunk, getDBMessageData, setDBChunk } from "../db/api";

import type { LibCrypto } from "../cryptography/libcrypto";

export const handleReceiveMessage = async (
  decrypted: Uint8Array,
  messageArray: Uint8Array,
  merkleRootArray: Uint8Array,
  senderPublicKeyArray: Uint8Array,
  receiverSecretKeyArray: Uint8Array,
  module: LibCrypto,
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
  const result = module._receive_message(
    decrypted.byteOffset,
    messageArray.byteOffset,
    merkleRootArray.byteOffset,
    senderPublicKeyArray.byteOffset,
    receiverSecretKeyArray.byteOffset,
  );

  switch (result) {
    case 0: {
      const metadata = deserializeMetadata(decrypted.subarray(0, METADATA_LEN));

      const chunkSize =
        metadata.chunkEndIndex - metadata.chunkStartIndex > metadata.totalSize
          ? 0
          : metadata.chunkEndIndex - metadata.chunkStartIndex > MESSAGE_LEN
            ? 0
            : metadata.chunkEndIndex - metadata.chunkStartIndex;

      const chunkHashBuffer = await window.crypto.subtle.digest(
        "SHA-512",
        decrypted.subarray(METADATA_LEN + PROOF_LEN) as Uint8Array<ArrayBuffer>,
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

      // const merkleRootHex = uint8ArrayToHex(merkleRoot);
      const merkleRootHex = uint8ArrayToHex(
        // Uint8Array.from([...merkleRootArray]),
        merkleRootArray,
      );

      const chunkAlreadyExists = await existsDBChunk(
        merkleRootHex,
        metadata.chunkIndex,
      );

      const messageExists = await getDBMessageData(merkleRootHex);

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
        // cryptoModule._free(ptr1);

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

      const mimeType = getMimeType(metadata.messageType);

      try {
        if (!chunkAlreadyExists) {
          await setDBChunk({
            merkleRoot: merkleRootHex,
            hash: uint8ArrayToHex(metadata.hash),
            chunkIndex: metadata.chunkIndex,
            data: decrypted.slice(
              METADATA_LEN + PROOF_LEN + metadata.chunkStartIndex,
              METADATA_LEN + PROOF_LEN + metadata.chunkEndIndex,
            ).buffer as ArrayBuffer,
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
          receivedFullSize:
            messageExists != undefined ? receivedFullSize : false,
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
    }

    case -1: {
      console.error("Message signature is wrong");

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
    }

    case -2: {
      console.error("Could not decrypt message");

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
    }

    case -3: {
      console.error("Merkle proof length is wrong");

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
    }

    case -4: {
      console.error("Could not allocate memory for hash");

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
    }

    case -5: {
      console.error("Could not hash chunk");

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
    }

    case -6: {
      console.error("Could not verify Merkle proof");

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
    }

    default: {
      console.error("Unexpected error occured.");

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
    }
  }
};
