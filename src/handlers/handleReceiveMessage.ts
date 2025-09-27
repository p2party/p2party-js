import { deserializeMetadata } from "../utils/metadata";
import { getMimeType, MessageType } from "../utils/messageTypes";
import { uint8ArrayToHex } from "../utils/uint8array";
import { MESSAGE_LEN, METADATA_LEN, PROOF_LEN } from "../utils/constants";

import { getDBMessageData, setDBChunk } from "../db/api";

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
  chunkIndex: number;
  receivedFullSize: boolean;
  chunkAlreadyExists: boolean;
  totalSize: number;
  messageType: number;
  filename: string;
  chunkHash: Uint8Array;
  messageHash: Uint8Array;
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
      const metadataArray = decrypted.slice(0, METADATA_LEN);
      const chunk = decrypted.slice(METADATA_LEN + PROOF_LEN);
      const metadata = deserializeMetadata(metadataArray);
      const realChunk = chunk.slice(
        metadata.chunkStartIndex,
        metadata.chunkEndIndex,
      );
      const chunkHashBuffer = await window.crypto.subtle.digest(
        "SHA-512",
        chunk,
      );
      const chunkHash = new Uint8Array(chunkHashBuffer);

      const chunkSize =
        metadata.chunkEndIndex - metadata.chunkStartIndex > metadata.totalSize
          ? 0
          : metadata.chunkEndIndex - metadata.chunkStartIndex > MESSAGE_LEN
            ? 0
            : metadata.chunkEndIndex - metadata.chunkStartIndex;

      if (chunkSize === 0)
        return {
          date: metadata.date,
          chunkIndex: -1,
          chunkSize: 0,
          receivedFullSize: false,
          chunkAlreadyExists: true,
          totalSize: metadata.totalSize,
          messageType: metadata.messageType,
          filename: metadata.name,
          chunkHash,
          messageHash: metadata.hash,
        };

      const merkleRootHex = uint8ArrayToHex(merkleRootArray);
      const messageExists = await getDBMessageData(merkleRootHex);

      const alreadyHasEverything =
        messageExists != undefined &&
        messageExists.savedSize === messageExists.totalSize;

      const messageRelevant =
        !messageExists ||
        messageExists.savedSize + chunkSize <= messageExists.totalSize;

      const receivedFullSize =
        alreadyHasEverything ||
        chunkSize === metadata.totalSize ||
        (messageExists != undefined &&
          messageExists.savedSize + chunkSize === messageExists.totalSize);

      if (!messageRelevant) 
        return {
          date: metadata.date,
          chunkIndex: -1,
          chunkSize,
          receivedFullSize,
          chunkAlreadyExists: true,
          totalSize: metadata.totalSize,
          messageType: metadata.messageType,
          filename: metadata.name,
          chunkHash,
          messageHash: metadata.hash,
        };

      const mimeType = getMimeType(metadata.messageType);

      try {
        await setDBChunk({
          merkleRoot: merkleRootHex,
          hash: uint8ArrayToHex(metadata.hash),
          chunkIndex: metadata.chunkIndex,
          data: realChunk.buffer,
          mimeType,
        });

        return {
          date: metadata.date,
          chunkIndex: metadata.chunkIndex,
          chunkSize,
          receivedFullSize,
          chunkAlreadyExists: false,
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
          chunkAlreadyExists: true,
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
        chunkAlreadyExists: false,
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
        chunkAlreadyExists: false,
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
        chunkAlreadyExists: false,
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
        chunkAlreadyExists: false,
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
        chunkAlreadyExists: false,
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
        chunkAlreadyExists: false,
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
        chunkAlreadyExists: false,
        totalSize: 0,
        messageType: MessageType.Text,
        filename: "",
        chunkHash: new Uint8Array(),
        messageHash: new Uint8Array(),
      };
    }
  }
};
