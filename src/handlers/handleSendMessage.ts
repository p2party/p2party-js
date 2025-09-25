import { handleOpenChannel } from "./handleOpenChannel";

// import { encryptAsymmetric } from "../cryptography/chacha20poly1305";
import { fisherYatesShuffle, randomNumberInRange } from "../cryptography/utils";
// import { newKeyPair, sign } from "../cryptography/ed25519";
import { getMerkleProof } from "../cryptography/merkle";
import {
  crypto_hash_sha512_BYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
} from "../cryptography/interfaces";

import { concatUint8Arrays, hexToUint8Array } from "../utils/uint8array";
import { splitToChunks } from "../utils/splitToChunks";
import { deserializeMetadata } from "../utils/metadata";
import { getMimeType } from "../utils/messageTypes";
import {
  compileChannelMessageLabel,
  decompileChannelMessageLabel,
} from "../utils/channelLabel";
import { allocateSendMessage } from "../utils/allocators";
import {
  CHUNK_LEN,
  DECRYPTED_LEN,
  MAX_BUFFERED_AMOUNT,
  PROOF_LEN,
} from "../utils/constants";

import {
  deleteDBSendQueue,
  getDBNewChunk,
  getDBSendQueue,
  setDBChunk,
  setDBNewChunk,
  setDBSendQueue,
} from "../db/api";

import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../api/webrtc/interfaces";
import type { LibCrypto } from "../cryptography/libcrypto";
import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";

// export const wait = (milliseconds: number) => {
//   return new Promise((resolve) => {
//     setTimeout(resolve, milliseconds);
//   });
// };

const sendChunks = async (
  channel: IRTCDataChannel,
  senderSecretKey: Uint8Array,
  chunksLen: number,
  chunkHashes: Uint8Array,
  merkleRoot: Uint8Array,
  hashHex: string,
  epc: IRTCPeerConnection,
  encryptionModule: LibCrypto,
  merkleModule: LibCrypto,
) => {
  let putItemInDBSendQueue = false;

  const { merkleRootHex } = await decompileChannelMessageLabel(channel.label);

  const indexes = Array.from({ length: chunksLen }, (_, i) => i);
  const indexesRandomized = fisherYatesShuffle(indexes);

  const {
    ptr1,
    ptr2,
    ptr3,
    ptr5,
    ptr6,
    ptr7,
    ptr9,
    ptr10,
    senderEphemeralPublicKey,
    senderEphemeralSecretKey,
    seedBytes,
    senderEphemeralSignature,
    chunkArray,
    receiverPublicKeyArray,
    nonceArray,
    encryptedArray,
  } = allocateSendMessage(encryptionModule);

  const peerPublicKeyHex = epc.withPeerPublicKey;
  // const receiverPublicKey = hexToUint8Array(peerPublicKeyHex);
  receiverPublicKeyArray.set(hexToUint8Array(peerPublicKeyHex));

  for (let i = 0; i < chunksLen; i++) {
    const iRandom = indexesRandomized[i];

    window.crypto.getRandomValues(seedBytes);

    const newKeyPairResult = encryptionModule._keypair_from_seed(
      senderEphemeralPublicKey.byteOffset,
      senderEphemeralSecretKey.byteOffset,
      seedBytes.byteOffset,
    );

    if (newKeyPairResult !== 0) continue;

    const sigResult = encryptionModule._sign(
      crypto_sign_ed25519_PUBLICKEYBYTES,
      senderEphemeralPublicKey.byteOffset,
      senderSecretKey.byteOffset,
      senderEphemeralSignature.byteOffset,
    );

    if (sigResult !== 0) continue;

    // const senderEphemeralKey = await newKeyPair(encryptionModule);
    // const ephemeralSignature = await sign(
    //   senderEphemeralKey.publicKey,
    //   senderSecretKey,
    //   encryptionModule,
    // );

    const unencryptedChunk = await getDBNewChunk(hashHex, iRandom);
    if (!unencryptedChunk) continue;

    const metadataArray = new Uint8Array(unencryptedChunk.metadata);
    const metadata = deserializeMetadata(metadataArray);

    if (
      metadata.chunkStartIndex >= 0 &&
      metadata.chunkEndIndex > metadata.chunkStartIndex &&
      metadata.chunkEndIndex - metadata.chunkStartIndex <= metadata.totalSize
    ) {
      const mimeType = getMimeType(metadata.messageType);
      const realChunk = unencryptedChunk.data.slice(
        metadata.chunkStartIndex,
        metadata.chunkEndIndex,
      );
      await setDBChunk({
        merkleRoot: merkleRootHex,
        hash: hashHex,
        chunkIndex: metadata.chunkIndex,
        data: realChunk,
        mimeType,
      });
    }

    const merkleProof = new Uint8Array(PROOF_LEN);
    if (unencryptedChunk.merkleProof.byteLength === 0) {
      const m = await getMerkleProof(
        chunkHashes,
        hexToUint8Array(unencryptedChunk.realChunkHash),
        merkleModule,
        PROOF_LEN,
      );

      merkleProof.set(m);

      try {
        await setDBNewChunk({
          hash: hashHex,
          merkleRoot: merkleRootHex,
          realChunkHash: unencryptedChunk.realChunkHash,
          chunkIndex: iRandom,
          data: unencryptedChunk.data,
          metadata: unencryptedChunk.metadata,
          merkleProof: merkleProof.buffer,
        });
      } catch (error) {
        console.warn(error);
      }
    } else {
      merkleProof.set(new Uint8Array(unencryptedChunk.merkleProof));

      if (unencryptedChunk.merkleRoot.length === 0) {
        try {
          await setDBNewChunk({
            hash: hashHex,
            merkleRoot: merkleRootHex,
            realChunkHash: unencryptedChunk.realChunkHash,
            chunkIndex: iRandom,
            data: unencryptedChunk.data,
            metadata: unencryptedChunk.metadata,
            merkleProof: unencryptedChunk.merkleProof,
          });
        } catch (error) {
          console.warn(error);
        }
      }
    }

    if (
      DECRYPTED_LEN !==
      metadataArray.length +
        merkleProof.length +
        new Uint8Array(unencryptedChunk.data).length
    )
      continue;

    const chunk = await concatUint8Arrays([
      metadataArray,
      merkleProof,
      new Uint8Array(unencryptedChunk.data),
    ]);
    chunkArray.set(chunk);

    window.crypto.getRandomValues(nonceArray);

    const encResult = encryptionModule._encrypt_chachapoly_asymmetric(
      DECRYPTED_LEN,
      chunkArray.byteOffset,
      receiverPublicKeyArray.byteOffset,
      senderEphemeralSecretKey.byteOffset,
      nonceArray.byteOffset,
      crypto_hash_sha512_BYTES,
      merkleRoot.byteOffset,
      encryptedArray.byteOffset,
    );

    if (encResult !== 0) continue;

    // const encryptedMessage = await encryptAsymmetric(
    //   chunk,
    //   // unencryptedChunks[jRandom],
    //   receiverPublicKey,
    //   senderEphemeralKey.secretKey, // senderSecretKey,
    //   merkleRoot,
    //   encryptionModule,
    // );

    const message = await concatUint8Arrays([
      senderEphemeralPublicKey,
      senderEphemeralSignature,
      encryptedArray,
    ]);

    if (
      channel.readyState === "open" &&
      channel.bufferedAmount < MAX_BUFFERED_AMOUNT
    ) {
      // const timeoutMilliseconds = randomNumberInRange(1, 10);
      // await wait(timeoutMilliseconds);

      channel.send(message.buffer as ArrayBuffer);
    } else if (
      // channel.readyState !== "closing" &&
      channel.readyState !== "closed"
    ) {
      putItemInDBSendQueue = true;

      try {
        await setDBSendQueue({
          position: iRandom,
          label: channel.label,
          toPeerId: channel.withPeerId,
          encryptedData: message.buffer as ArrayBuffer, // new Blob([message]),
        });
      } catch (error) {
        console.error(error);
      }
    } else {
      console.log(
        "Cannot send message because channel is " +
          channel.readyState +
          " and bufferedAmount is " +
          String(channel.bufferedAmount),
      );

      break;
    }
  }

  if (putItemInDBSendQueue) {
    while (
      channel.readyState === "open" &&
      channel.bufferedAmount < MAX_BUFFERED_AMOUNT
    ) {
      const sendQueue = await getDBSendQueue(channel.label, epc.withPeerId);
      while (
        sendQueue.length > 0 &&
        channel.bufferedAmount < MAX_BUFFERED_AMOUNT &&
        channel.readyState === "open"
      ) {
        // const timeoutMilliseconds = await randomNumberInRange(1, 10);
        // await wait(timeoutMilliseconds);

        let pos = await randomNumberInRange(0, sendQueue.length);
        if (pos === sendQueue.length) pos = 0;

        const [item] = sendQueue.splice(pos, 1);
        if (channel.readyState === "open") {
          channel.send(item.encryptedData);

          try {
            await deleteDBSendQueue(
              channel.label,
              epc.withPeerId,
              item.position,
            );
          } catch (error) {
            console.error(error);
          }
        }
      }
    }
  }

  encryptionModule._free(ptr1);
  encryptionModule._free(ptr2);
  encryptionModule._free(ptr3);
  encryptionModule._free(ptr5);
  encryptionModule._free(ptr6);
  encryptionModule._free(ptr7);
  encryptionModule._free(ptr9);
  encryptionModule._free(ptr10);
};

export const handleSendMessage = async (
  data: string | File,
  api: BaseQueryApi,
  label: string,
  roomId: string,
  peerConnections: IRTCPeerConnection[],
  dataChannels: IRTCDataChannel[],
  // receiveMessageModule: LibCrypto,
  encryptionModule: LibCrypto,
  // decryptionModule: LibCrypto,
  merkleModule: LibCrypto,
  minChunks = 1,
  chunkSize = CHUNK_LEN,
  percentageFilledChunk = 0.9,
  metadataSchemaVersion = 1,
) => {
  try {
    const { rooms, keyPair } = api.getState() as State;

    const roomIndex = rooms.findIndex((r) => r.id === roomId);

    if (roomIndex > -1) {
      const channelIndex = rooms[roomIndex].channels.findIndex(
        (c) => c.label === label,
      );
      if (channelIndex === -1)
        throw new Error("No channel with label " + label);

      const { merkleRoot, merkleRootHex, hashHex, totalChunks, chunkHashes } =
        await splitToChunks(
          data,
          api,
          label,
          rooms[roomIndex], // roomId,
          merkleModule,
          minChunks,
          chunkSize,
          percentageFilledChunk,
          metadataSchemaVersion,
        );

      if (
        merkleRoot.length === 0 ||
        hashHex.length === 0 ||
        totalChunks === 0 ||
        chunkHashes.length === 0
      )
        return;

      const channelMessageLabel = await compileChannelMessageLabel(
        label,
        merkleRootHex,
      );

      const ptr4 = encryptionModule._malloc(crypto_sign_ed25519_SECRETKEYBYTES);
      const senderSecretKey = new Uint8Array(
        encryptionModule.wasmMemory.buffer,
        ptr4,
        crypto_sign_ed25519_SECRETKEYBYTES,
      );
      senderSecretKey.set(hexToUint8Array(keyPair.secretKey));

      const ptr8 = encryptionModule._malloc(crypto_hash_sha512_BYTES);
      const additionalData = new Uint8Array(
        encryptionModule.wasmMemory.buffer,
        ptr8,
        crypto_hash_sha512_BYTES,
      );
      additionalData.set(merkleRoot);

      const PEERS_LEN = rooms[roomIndex].channels[channelIndex].peerIds.length;
      const promises: Promise<void>[] = [];
      for (let i = 0; i < PEERS_LEN; i++) {
        const peerIndex = peerConnections.findIndex(
          (p) =>
            p.withPeerId === rooms[roomIndex].channels[channelIndex].peerIds[i],
        );
        if (peerIndex === -1) continue;

        const channel = await handleOpenChannel(
          {
            channel: channelMessageLabel,
            epc: peerConnections[peerIndex],
            roomId,
            dataChannels,
            // receiveMessageModule,
            // decryptionModule,
            // merkleModule,
          },
          api,
        );

        promises.push(
          sendChunks(
            channel,
            senderSecretKey,
            totalChunks,
            chunkHashes,
            additionalData, // merkleRoot,
            hashHex,
            peerConnections[peerIndex],
            encryptionModule,
            merkleModule,
          ),
        );
      }

      await Promise.allSettled(promises);

      encryptionModule._free(ptr4);
      encryptionModule._free(ptr8);
    }
  } catch (error) {
    console.trace(error);
  }
};
