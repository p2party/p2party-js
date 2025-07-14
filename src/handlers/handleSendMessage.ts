import { encryptAsymmetric } from "../cryptography/chacha20poly1305";
import { fisherYatesShuffle, randomNumberInRange } from "../cryptography/utils";
import { newKeyPair, sign } from "../cryptography/ed25519";
import { getMerkleProof } from "../cryptography/merkle";

// import { setMessage } from "../reducers/roomSlice";

import { concatUint8Arrays, hexToUint8Array } from "../utils/uint8array";
import { splitToChunks } from "../utils/splitToChunks";
import { deserializeMetadata } from "../utils/metadata";
import { getMimeType } from "../utils/messageTypes";
import {
  compileChannelMessageLabel,
  decompileChannelMessageLabel,
} from "../utils/channelLabel";

import {
  deleteDBSendQueue,
  getDBNewChunk,
  getDBSendQueue,
  setDBChunk,
  setDBNewChunk,
  setDBSendQueue,
} from "../db/api";

import { handleOpenChannel, MAX_BUFFERED_AMOUNT } from "./handleOpenChannel";

// import { deleteMessage } from "../reducers/roomSlice";

import { CHUNK_LEN, PROOF_LEN } from "../utils/splitToChunks";

import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../api/webrtc/interfaces";
import type { LibCrypto } from "../cryptography/libcrypto";
import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";

export const wait = (milliseconds: number) => {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
};

const sendChunks = async (
  channel: IRTCDataChannel,
  // roomId: string,
  // fromPeerId: string,
  senderSecretKey: Uint8Array,
  chunksLen: number,
  chunkHashes: Uint8Array,
  merkleRoot: Uint8Array,
  epc: IRTCPeerConnection,
  // api: BaseQueryApi,
  encryptionModule: LibCrypto,
  merkleModule: LibCrypto,
) => {
  try {
    let putItemInDBSendQueue = false;
    // const merkleRootHex = uint8ArrayToHex(merkleRoot);

    const peerPublicKeyHex = epc.withPeerPublicKey;
    const receiverPublicKey = hexToUint8Array(peerPublicKeyHex);

    const {
      // channelLabel,
      hashHex,
      merkleRootHex,
    } = await decompileChannelMessageLabel(channel.label);

    const indexes = Array.from({ length: chunksLen }, (_, i) => i);
    const indexesRandomized = await fisherYatesShuffle(indexes);
    for (let i = 0; i < chunksLen; i++) {
      const iRandom = indexesRandomized[i];

      const senderEphemeralKey = await newKeyPair(encryptionModule);
      const ephemeralSignature = await sign(
        senderEphemeralKey.publicKey,
        senderSecretKey,
        encryptionModule,
      );

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

        try {
          await setDBChunk({
            merkleRoot: merkleRootHex,
            hash: hashHex,
            chunkIndex: metadata.chunkIndex,
            data: unencryptedChunk.data.slice(
              metadata.chunkStartIndex,
              metadata.chunkEndIndex,
            ), // new Blob([realChunk]),
            mimeType,
          });
        } catch {}
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
            merkleProof: merkleProof.buffer as ArrayBuffer,
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

      const chunk = await concatUint8Arrays([
        metadataArray,
        merkleProof,
        new Uint8Array(unencryptedChunk.data),
      ]);

      const encryptedMessage = await encryptAsymmetric(
        chunk,
        // unencryptedChunks[jRandom],
        receiverPublicKey,
        senderEphemeralKey.secretKey, // senderSecretKey,
        merkleRoot,
        encryptionModule,
      );

      const message = (await concatUint8Arrays([
        senderEphemeralKey.publicKey,
        ephemeralSignature,
        encryptedMessage,
      ])) as Uint8Array;

      const timeoutMilliseconds = await randomNumberInRange(1, 10);
      await wait(timeoutMilliseconds);
      if (
        channel.readyState === "open" &&
        channel.bufferedAmount < MAX_BUFFERED_AMOUNT
      ) {
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
            channel.bufferedAmount,
        );

        break;
      }
    }

    // if (!putItemInDBSendQueue) {
    //   channel.close();
    // } else {
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
          const timeoutMilliseconds = await randomNumberInRange(1, 10);
          await wait(timeoutMilliseconds);

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
  } catch (error) {
    console.error(error);
    throw error;
  }
};

export const handleSendMessage = async (
  data: string | File,
  api: BaseQueryApi,
  label: string,
  roomId: string,
  peerConnections: IRTCPeerConnection[],
  dataChannels: IRTCDataChannel[],
  encryptionModule: LibCrypto,
  decryptionModule: LibCrypto,
  merkleModule: LibCrypto,
  minChunks = 1,
  chunkSize = CHUNK_LEN,
  percentageFilledChunk = 0.9,
  metadataSchemaVersion = 1,
) => {
  try {
    const { rooms, keyPair } = api.getState() as State;
    const senderSecretKey = hexToUint8Array(keyPair.secretKey);

    const roomIndex = rooms.findIndex((r) => r.id === roomId);

    if (roomIndex > -1) {
      const channelIndex = rooms[roomIndex].channels.findIndex(
        (c) => c.label === label,
      );
      if (channelIndex === -1)
        throw new Error("No channel with label " + label);

      const {
        merkleRoot,
        merkleRootHex,
        hashHex,
        totalChunks,
        chunkHashes,
      } = //, unencryptedChunks } =
        await splitToChunks(
          data,
          api,
          label,
          rooms[roomIndex], // roomId,
          minChunks,
          chunkSize,
          percentageFilledChunk,
          metadataSchemaVersion,
        );

      const channelMessageLabel = await compileChannelMessageLabel(
        label,
        merkleRootHex,
        hashHex,
      );

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
            decryptionModule,
            merkleModule,
          },
          api,
        );

        promises.push(
          sendChunks(
            channel,
            // roomId,
            // keyPair.peerId,
            senderSecretKey,
            totalChunks,
            chunkHashes,
            merkleRoot,
            peerConnections[peerIndex],
            // api,
            encryptionModule,
            merkleModule,
          ),
        );
      }

      await Promise.allSettled(promises);
    }
  } catch (error) {
    console.trace(error);
  }
};
