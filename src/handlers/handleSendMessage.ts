import { encryptAsymmetric } from "../cryptography/chacha20poly1305";
import { fisherYatesShuffle, randomNumberInRange } from "../cryptography/utils";

import { hexToUint8Array } from "../utils/uint8array";
import { splitToChunks } from "../utils/splitToChunks";
import { deserializeMetadata, METADATA_LEN } from "../utils/metadata";
import { deleteDBChunk, setDBSendQueue } from "../db/api";

import { handleOpenChannel, MAX_BUFFERED_AMOUNT } from "./handleOpenChannel";
import { compileChannelMessageLabel } from "../utils/channelLabel";

import { deleteMessage } from "../reducers/roomSlice";

import { CHUNK_LEN } from "../utils/splitToChunks";

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
  api: BaseQueryApi,
  label: string,
  peerConnections: IRTCPeerConnection[],
  dataChannels: IRTCDataChannel[],
  encryptionModule: LibCrypto,
  decryptionModule: LibCrypto,
  merkleModule: LibCrypto,
  minChunks = 5, // TODO errors when =2 due to merkle
  chunkSize = CHUNK_LEN,
  percentageFilledChunk = 0.8,
  metadataSchemaVersion = 1,
) => {
  try {
    const { room, keyPair } = api.getState() as State;
    const senderSecretKey = hexToUint8Array(keyPair.secretKey);

    const channelIndex = room.channels.findIndex((c) => c.label === label);
    if (channelIndex === -1) throw new Error("No channel with label " + label);

    const { merkleRoot, merkleRootHex, hashHex, totalSize, unencryptedChunks } =
      await splitToChunks(
        data,
        api,
        label,
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
    const chunksLen = unencryptedChunks.length;
    const PEERS_LEN = room.channels[channelIndex].peerIds.length;
    for (let i = 0; i < PEERS_LEN; i++) {
      let putItemInDBSendQueue = false;
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

        const m = deserializeMetadata(
          unencryptedChunks[jRandom].slice(0, METADATA_LEN),
        );

        const encryptedMessage = await encryptAsymmetric(
          unencryptedChunks[jRandom],
          receiverPublicKey,
          senderSecretKey,
          merkleRoot,
          encryptionModule,
        );

        const timeoutMilliseconds = await randomNumberInRange(2, 20);
        await wait(timeoutMilliseconds);
        if (
          channel.bufferedAmount < MAX_BUFFERED_AMOUNT &&
          channel.readyState === "open"
        ) {
          channel.send(encryptedMessage);
        } else if (
          channel.readyState === "closing" ||
          channel.readyState === "closed"
        ) {
          api.dispatch(deleteMessage({ merkleRootHex }));

          channel.close();
        } else {
          putItemInDBSendQueue = true;
          await setDBSendQueue({
            position: jRandom,
            label: channel.label,
            toPeerId: channel.withPeerId,
            encryptedData: new Blob([encryptedMessage]),
          });
        }

        if (m.chunkEndIndex - m.chunkStartIndex > totalSize)
          await deleteDBChunk(merkleRootHex, m.chunkIndex);

        // delete unencryptedChunks[jRandom];
      }

      if (!putItemInDBSendQueue) channel.close();
    }
  } catch (error) {
    console.error(error);
  }
};
