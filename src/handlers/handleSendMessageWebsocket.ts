import signalingServerApi from "../api/signalingServerApi";

import { setMessage } from "../reducers/roomSlice";
import { deleteDBChunk, getDBNewChunk } from "../db/api";

import { splitToChunks } from "../utils/splitToChunks";
import { deserializeMetadata } from "../utils/metadata";
import {
  uint8ArrayToHex,
  hexToUint8Array,
  concatUint8Arrays,
} from "../utils/uint8array";
import { METADATA_LEN } from "../utils/constants";

import { fisherYatesShuffle } from "../cryptography/utils";
import { encryptAsymmetric } from "../cryptography/chacha20poly1305";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { LibCrypto } from "../cryptography/libcrypto";
import type { State } from "../store";
import type { WebSocketMessageMessageSendRequest } from "../utils/interfaces";

export const handleSendMessageWebsocket = async (
  data: string | File,
  roomId: string,
  encryptionModule: LibCrypto,
  api: BaseQueryApi,
  label: string,
) => {
  const { keyPair, rooms } = api.getState() as State;
  const senderSecretKey = hexToUint8Array(keyPair.secretKey);

  const roomIndex = rooms.findIndex((r) => r.id === roomId);

  if (roomIndex > -1) {
    const peerConnections = rooms[roomIndex].peers;
    const dataChannels = rooms[roomIndex].channels;

    const channelIndex = label
      ? dataChannels.findIndex((c) => c.label === label)
      : 0;
    if (channelIndex === -1) throw new Error("No channel with label " + label);

    const {
      merkleRoot,
      merkleRootHex,
      hashHex,
      totalSize,
      totalChunks,
    } = // , unencryptedChunks } =
      await splitToChunks(data, api, label, rooms[roomIndex], encryptionModule); // db);

    const PEERS_LEN = dataChannels[channelIndex].peerIds.length;
    for (let i = 0; i < PEERS_LEN; i++) {
      const peerId = dataChannels[channelIndex].peerIds[i];
      const peerIndex = peerConnections.findIndex((p) => p.peerId === peerId);
      if (peerIndex === -1) continue;

      const peerPublicKeyHex = peerConnections[peerIndex].peerPublicKey;
      const receiverPublicKey = hexToUint8Array(peerPublicKeyHex);

      const indexes = Array.from({ length: totalChunks }, (_, i) => i);
      const indexesRandomized = await fisherYatesShuffle(indexes);
      for (let j = 0; j < totalChunks; j++) {
        const jRandom = indexesRandomized[j];

        const unencryptedChunk = await getDBNewChunk(hashHex, jRandom);
        if (!unencryptedChunk) continue;

        const m = deserializeMetadata(
          new Uint8Array(unencryptedChunk.data).slice(0, METADATA_LEN),
        );
        if (m.chunkStartIndex < m.chunkEndIndex) {
          api.dispatch(
            setMessage({
              roomId,
              merkleRootHex,
              sha512Hex: hashHex,
              fromPeerId: keyPair.peerId,
              chunkSize: m.chunkEndIndex - m.chunkStartIndex,
              totalSize,
              messageType: m.messageType,
              filename: m.name,
              channelLabel: label ?? dataChannels[channelIndex].label,
            }),
          );
        } else {
          await deleteDBChunk(merkleRootHex, m.chunkIndex);
        }

        const encryptedMessage = await encryptAsymmetric(
          new Uint8Array(unencryptedChunk.data),
          receiverPublicKey,
          senderSecretKey,
          merkleRoot,
          encryptionModule,
        );

        const concatedEncrypted = await concatUint8Arrays([
          merkleRoot,
          encryptedMessage,
        ]);

        api.dispatch(
          signalingServerApi.endpoints.sendMessage.initiate({
            content: {
              type: "message",
              message: uint8ArrayToHex(concatedEncrypted),
              roomId,
              fromPeerId: keyPair.peerId,
              toPeerId: peerId,
              label,
            } as WebSocketMessageMessageSendRequest,
          }),
        );
      }
    }
  }
};
