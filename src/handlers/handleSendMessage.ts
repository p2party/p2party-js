import { encryptAsymmetric } from "../cryptography/chacha20poly1305";
import { fisherYatesShuffle, randomNumberInRange } from "../cryptography/utils";

import { hexToUint8Array } from "../utils/uint8array";
import { splitToChunks } from "../utils/splitToChunks";
import { deserializeMetadata, METADATA_LEN } from "../utils/metadata";
import { deleteDBChunk, getDB, setDBSendQueue } from "../utils/db";
// import {
//   getMessageCategory,
//   getMessageType,
//   MessageCategory,
// } from "../utils/messageTypes";

import { handleOpenChannel, MAX_BUFFERED_AMOUNT } from "./handleOpenChannel";
import { compileChannelMessageLabel } from "../utils/channelLabel";

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

export const handleSendMessage = async (
  data: string | File,
  peerConnections: IRTCPeerConnection[],
  dataChannels: IRTCDataChannel[],
  encryptionModule: LibCrypto,
  decryptionModule: LibCrypto,
  merkleModule: LibCrypto,
  api: BaseQueryApi,
  label: string,
) => {
  const { room, keyPair } = api.getState() as State;
  const senderSecretKey = hexToUint8Array(keyPair.secretKey);

  const channelIndex = room.channels.findIndex((c) => c.label === label);
  if (channelIndex === -1) throw new Error("No channel with label " + label);

  const db = await getDB();

  const { merkleRoot, merkleRootHex, hashHex, totalSize, unencryptedChunks } =
    await splitToChunks(data, api, label, db);

  const channelMessageLabel = await compileChannelMessageLabel(
    label,
    merkleRootHex,
    hashHex,
  );
  const chunksLen = unencryptedChunks.length;
  const PEERS_LEN = room.channels[channelIndex].peerIds.length;
  for (let i = 0; i < PEERS_LEN; i++) {
    const peerIndex = peerConnections.findIndex(
      (p) => p.withPeerId === room.channels[channelIndex].peerIds[i],
    );
    if (peerIndex === -1) continue;

    const channel = await handleOpenChannel(
      {
        channel: channelMessageLabel,
        epc: peerConnections[peerIndex],
        dataChannels,
        decryptionModule,
        merkleModule,
      },
      api,
    );

    const peerPublicKeyHex = peerConnections[peerIndex].withPeerPublicKey;
    const receiverPublicKey = hexToUint8Array(peerPublicKeyHex);

    const indexes = Array.from({ length: chunksLen }, (_, i) => i);
    const indexesRandomized = await fisherYatesShuffle(indexes);
    for (let j = 0; j < chunksLen; j++) {
      // If audio or video then sequential data, else random order
      const jRandom = indexesRandomized[j];
      // messageCategory === MessageCategory.Audio || MessageCategory.Video
      //   ? j
      //   : indexesRandomized[j];

      const encryptedMessage = await encryptAsymmetric(
        unencryptedChunks[jRandom],
        receiverPublicKey,
        senderSecretKey,
        merkleRoot,
        encryptionModule,
      );

      const timeoutMilliseconds = await randomNumberInRange(2, 20);
      if (channel.bufferedAmount < MAX_BUFFERED_AMOUNT) {
        await wait(timeoutMilliseconds);
        channel.send(encryptedMessage);
      } else {
        await setDBSendQueue(
          {
            position: jRandom,
            label: channel.label,
            toPeerId: channel.withPeerId,
            encryptedData: new Blob([encryptedMessage]),
          },
          db,
        );
      }

      const m = deserializeMetadata(
        unencryptedChunks[jRandom].slice(0, METADATA_LEN),
      );

      if (m.chunkEndIndex - m.chunkStartIndex > totalSize)
        await deleteDBChunk(merkleRootHex, m.chunkIndex, db);

      delete unencryptedChunks[jRandom];
    }

    channel.close();
  }

  // const CHANNELS_LEN = dataChannels.length;
  // for (let i = channelIndex; i < CHANNELS_LEN; i++) {
  //   if (dataChannels[i].label !== label) continue;

  //   const peerId = dataChannels[i].withPeerId;
  //   const peerIndex = peerConnections.findIndex((p) => p.withPeerId === peerId);
  //   if (peerIndex === -1) continue;

  //   const peerPublicKeyHex = peerConnections[peerIndex].withPeerPublicKey;
  //   const receiverPublicKey = hexToUint8Array(peerPublicKeyHex);

  //   const indexes = Array.from({ length: chunksLen }, (_, i) => i);
  //   const indexesRandomized = await fisherYatesShuffle(indexes);
  //   for (let j = 0; j < chunksLen; j++) {
  //     // If audio or video then sequential data, else random order
  //     const jRandom = indexesRandomized[j];
  //     // messageCategory === MessageCategory.Audio || MessageCategory.Video
  //     //   ? j
  //     //   : indexesRandomized[j];

  //     const encryptedMessage = await encryptAsymmetric(
  //       unencryptedChunks[jRandom],
  //       receiverPublicKey,
  //       senderSecretKey,
  //       merkleRoot,
  //       encryptionModule,
  //     );

  //     const concatedEncrypted = await concatUint8Arrays([
  //       merkleRoot,
  //       encryptedMessage,
  //     ]);

  //     const timeoutMilliseconds = await randomNumberInRange(2, 20);
  //     if (dataChannels[i].bufferedAmount < MAX_BUFFERED_AMOUNT) {
  //       await wait(timeoutMilliseconds);
  //       dataChannels[i].send(concatedEncrypted);
  //     } else {
  //       await setDBSendQueue(
  //         {
  //           position: jRandom,
  //           label: dataChannels[i].label,
  //           toPeerId: dataChannels[i].withPeerId,
  //           encryptedData: new Blob([concatedEncrypted]),
  //         },
  //         db,
  //       );
  //     }

  //     const m = deserializeMetadata(
  //       unencryptedChunks[jRandom].slice(0, METADATA_LEN),
  //     );

  //     if (m.chunkEndIndex - m.chunkStartIndex > totalSize)
  //       await deleteDBChunk(merkleRootHex, m.chunkIndex, db);

  //     delete unencryptedChunks[jRandom];
  //   }
  // }

  db.close();
};
