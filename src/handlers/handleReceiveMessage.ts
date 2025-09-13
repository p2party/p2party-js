import cryptoMemory from "../cryptography/memory";
import libcrypto from "../cryptography/libcrypto";
import {
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
  crypto_box_poly1305_AUTHTAGBYTES,
  crypto_hash_sha512_BYTES,
  crypto_sign_ed25519_BYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
} from "../cryptography/interfaces";

import { KB64 } from "./handleOpenChannel";

import { deserializeMetadata, METADATA_LEN } from "../utils/metadata";
import { getMimeType, MessageType } from "../utils/messageTypes";
import { PROOF_LEN } from "../utils/splitToChunks";
import { uint8ArrayToHex } from "../utils/uint8array";

import { existsDBChunk, getDBMessageData, setDBChunk } from "../db/api";

import type { LibCrypto } from "../cryptography/libcrypto";

export const handleReceiveMessage = async (
  data: ArrayBuffer,
  merkleRoot: Uint8Array,
  senderPublicKey: Uint8Array,
  receiverSecretKey: Uint8Array,
  module?: LibCrypto,
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
  const message = new Uint8Array(data);
  if (message.length !== KB64)
    throw new Error(`Message size should be ${String(KB64)} bytes`);
  if (merkleRoot.length !== crypto_hash_sha512_BYTES)
    throw new Error(
      `Merkle root size should be ${String(crypto_hash_sha512_BYTES)} bytes`,
    );
  if (senderPublicKey.length !== crypto_sign_ed25519_PUBLICKEYBYTES)
    throw new Error(
      `Sender public key size should be ${String(crypto_sign_ed25519_PUBLICKEYBYTES)} bytes`,
    );
  if (receiverSecretKey.length !== crypto_sign_ed25519_SECRETKEYBYTES)
    throw new Error(
      `Receiver secret key size should be ${String(crypto_sign_ed25519_SECRETKEYBYTES)} bytes`,
    );

  const wasmMemory =
    module?.wasmMemory ?? cryptoMemory.getReceiveMessageMemory();
  const cryptoModule =
    module ??
    (await libcrypto({
      wasmMemory,
    }));

  const ENCRYPTED_LEN =
    KB64 - crypto_sign_ed25519_PUBLICKEYBYTES - crypto_sign_ed25519_BYTES;
  const DECRYPTED_LEN =
    ENCRYPTED_LEN -
    crypto_aead_chacha20poly1305_ietf_NPUBBYTES -
    crypto_box_poly1305_AUTHTAGBYTES;

  const ptr1 = cryptoModule._malloc(DECRYPTED_LEN);
  const decrypted = new Uint8Array(wasmMemory.buffer, ptr1, DECRYPTED_LEN);

  const ptr2 = cryptoModule._malloc(KB64);
  const messageArray = new Uint8Array(wasmMemory.buffer, ptr2, KB64);
  messageArray.set(message);

  const ptr3 = cryptoModule._malloc(crypto_hash_sha512_BYTES);
  const merkleRootArray = new Uint8Array(
    wasmMemory.buffer,
    ptr3,
    crypto_hash_sha512_BYTES,
  );
  merkleRootArray.set(merkleRoot);

  const ptr4 = cryptoModule._malloc(crypto_sign_ed25519_PUBLICKEYBYTES);
  const senderPublicKeyArray = new Uint8Array(
    wasmMemory.buffer,
    ptr4,
    crypto_sign_ed25519_PUBLICKEYBYTES,
  );
  senderPublicKeyArray.set(senderPublicKey);

  const ptr5 = cryptoModule._malloc(crypto_sign_ed25519_SECRETKEYBYTES);
  const receiverSecretKeyArray = new Uint8Array(
    wasmMemory.buffer,
    ptr5,
    crypto_sign_ed25519_SECRETKEYBYTES,
  );
  receiverSecretKeyArray.set(receiverSecretKey);

  const result = cryptoModule._receive_message(
    decrypted.byteOffset,
    messageArray.byteOffset,
    merkleRootArray.byteOffset,
    senderPublicKeyArray.byteOffset,
    receiverSecretKeyArray.byteOffset,
  );

  cryptoModule._free(ptr2);
  cryptoModule._free(ptr3);
  cryptoModule._free(ptr4);
  cryptoModule._free(ptr5);

  switch (result) {
    case 0: {
      const metadata = deserializeMetadata(decrypted.subarray(0, METADATA_LEN));

      const chunkSize =
        metadata.chunkEndIndex - metadata.chunkStartIndex > metadata.totalSize
          ? 0
          : metadata.chunkEndIndex - metadata.chunkStartIndex > KB64
            ? 0
            : metadata.chunkEndIndex - metadata.chunkStartIndex;

      const chunkHashBuffer = await window.crypto.subtle.digest(
        "SHA-512",
        decrypted.subarray(METADATA_LEN + PROOF_LEN),
      );
      const chunkHash = new Uint8Array(chunkHashBuffer);

      if (chunkSize === 0) {
        cryptoModule._free(ptr1);

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
      }

      const merkleRootHex = uint8ArrayToHex(merkleRoot);

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
        cryptoModule._free(ptr1);

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
          const realChunk = new Uint8Array(
            metadata.chunkEndIndex - metadata.chunkStartIndex,
          );
          realChunk.set([
            ...decrypted.slice(
              METADATA_LEN + PROOF_LEN + metadata.chunkStartIndex,
              METADATA_LEN + PROOF_LEN + metadata.chunkEndIndex,
            ),
          ]);
          // const realChunk = decrypted.subarray(
          //   METADATA_LEN + PROOF_LEN + metadata.chunkStartIndex,
          //   METADATA_LEN + PROOF_LEN + metadata.chunkEndIndex,
          // );

          await setDBChunk({
            merkleRoot: merkleRootHex,
            hash: uint8ArrayToHex(metadata.hash),
            chunkIndex: metadata.chunkIndex,
            data: realChunk.buffer as ArrayBuffer,
            mimeType,
          });
        }

        cryptoModule._free(ptr1);

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
        cryptoModule._free(ptr1);
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
      cryptoModule._free(ptr1);
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
      cryptoModule._free(ptr1);
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
      cryptoModule._free(ptr1);
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
      cryptoModule._free(ptr1);
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
      cryptoModule._free(ptr1);
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
      cryptoModule._free(ptr1);
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
      cryptoModule._free(ptr1);
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
