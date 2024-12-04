import { encryptAsymmetric } from "../cryptography/chacha20poly1305";
import { fisherYatesShuffle, randomNumberInRange } from "../cryptography/utils";

import {
  hexToUint8Array,
  uint8ArrayToHex,
  concatUint8Arrays,
} from "../utils/uint8array";
import { splitToChunks } from "../utils/splitToChunks";
import { deserializeMetadata, METADATA_LEN } from "../utils/metadata";
import { deleteDBChunk, getDB, setDBSendQueue } from "../utils/db";
// import {
//   getMessageCategory,
//   getMessageType,
//   MessageCategory,
// } from "../utils/messageTypes";

import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../api/webrtc/interfaces";
import type { LibCrypto } from "../cryptography/libcrypto";
import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";
import { MAX_BUFFERED_AMOUNT } from "./handleOpenChannel";

export const handleSendMessage = async (
  data: string | File,
  peerConnections: IRTCPeerConnection[],
  dataChannels: IRTCDataChannel[],
  encryptionModule: LibCrypto,
  api: BaseQueryApi,
  label: string,
) => {
  const { keyPair } = api.getState() as State;
  const senderSecretKey = hexToUint8Array(keyPair.secretKey);

  const channelIndex = dataChannels.findIndex((c) => c.label === label);
  if (channelIndex === -1) throw new Error("No channel with label " + label);

  const db = await getDB();

  const { merkleRoot, unencryptedChunks } = await splitToChunks(
    data,
    api,
    label,
    db,
  );

  const merkleRootHex = uint8ArrayToHex(merkleRoot);

  // const messageType = getMessageType(data);
  // const messageCategory = getMessageCategory(messageType);

  const chunksLen = unencryptedChunks.length;
  const CHANNELS_LEN = dataChannels.length;
  for (let i = channelIndex; i < CHANNELS_LEN; i++) {
    if (dataChannels[i].label !== label) continue;

    const peerId = dataChannels[i].withPeerId;
    const peerIndex = peerConnections.findIndex((p) => p.withPeerId === peerId);
    if (peerIndex === -1) continue;

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

      const concatedEncrypted = await concatUint8Arrays([
        merkleRoot,
        encryptedMessage,
      ]);

      const timeoutSeconds = await randomNumberInRange(1, 50);

      if (
        dataChannels[i].bufferedAmount < MAX_BUFFERED_AMOUNT
      ) {
        setTimeout(() => {
          dataChannels[i].send(concatedEncrypted);
        }, timeoutSeconds);
      } else {
        await setDBSendQueue(
          {
            position: jRandom,
            label: dataChannels[i].label,
            toPeerId: dataChannels[i].withPeerId,
            encryptedData: new Blob([concatedEncrypted]),
          },
          db,
        );
      }

      const m = deserializeMetadata(
        unencryptedChunks[jRandom].slice(0, METADATA_LEN),
      );

      if (m.chunkStartIndex === m.chunkEndIndex)
        await deleteDBChunk(merkleRootHex, m.chunkIndex, db);

      delete unencryptedChunks[jRandom];
    }
  }

  db.close();
};
