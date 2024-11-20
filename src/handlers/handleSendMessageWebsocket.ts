import signalingServerApi from "../api/signalingServerApi";

import { setMessage } from "../reducers/roomSlice";
import { getDB, getDBChunk, setDBChunk } from "../utils/db";

import { splitToChunks } from "../utils/splitToChunks";
import { deserializeMetadata } from "../utils/metadata";
import {
  uint8ArrayToHex,
  hexToUint8Array,
  concatUint8Arrays,
} from "../utils/uint8array";
import { fisherYatesShuffle } from "../cryptography/utils";
import { encryptAsymmetric } from "../cryptography/chacha20poly1305";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { LibCrypto } from "../cryptography/libcrypto";
import type { State } from "../store";
import type { WebSocketMessageMessageSendRequest } from "../utils/interfaces";

export const handleSendMessageWebsocket = async (
  data: string | File,
  encryptionModule: LibCrypto,
  api: BaseQueryApi,
  label?: string,
) => {
  const { keyPair, room } = api.getState() as State;
  const senderSecretKey = hexToUint8Array(keyPair.secretKey);

  const peerConnections = room.peers;
  const dataChannels = room.channels;

  const channelIndex = label
    ? dataChannels.findIndex((c) => c.label === label)
    : 0;
  if (channelIndex === -1) throw new Error("No channel with label " + label);

  const { merkleRoot, chunks, metadata, merkleProofs } =
    await splitToChunks(data);

  const merkleRootHex = uint8ArrayToHex(merkleRoot);

  const chunksLen = chunks.length;
  // const channels: string[] = [];
  const PEERS_LEN = dataChannels[channelIndex].peerIds.length;
  for (let i = 0; i < PEERS_LEN; i++) {
    const peerId = dataChannels[channelIndex].peerIds[i];
    const peerIndex = peerConnections.findIndex((p) => p.peerId === peerId);
    if (peerIndex === -1) continue;

    const peerPublicKeyHex = peerConnections[peerIndex].peerPublicKey;
    const receiverPublicKey = hexToUint8Array(peerPublicKeyHex);

    const indexes = Array.from({ length: chunksLen }, (_, i) => i);
    const indexesRandomized = await fisherYatesShuffle(indexes);
    for (let j = 0; j < chunksLen; j++) {
      const jRandom = indexesRandomized[j];

      const m = deserializeMetadata(metadata[jRandom]);
      if (m.chunkStartIndex < m.chunkEndIndex) {
        api.dispatch(
          setMessage({
            merkleRootHex,
            fromPeerId: keyPair.peerId,
            chunkIndex: m.chunkIndex,
            chunkSize: m.chunkEndIndex - m.chunkStartIndex,
            totalSize: m.size,
            messageType: m.messageType,
            channelLabel: label ?? dataChannels[channelIndex].label,
          }),
        );

        const db = await getDB();
        const storedChunk = await getDBChunk(merkleRootHex, m.chunkIndex, db);
        if (!storedChunk) {
          const realChunk = chunks[jRandom].slice(
            m.chunkStartIndex,
            m.chunkEndIndex,
          );
          await setDBChunk(
            {
              merkleRoot: merkleRootHex,
              chunkIndex: m.chunkIndex,
              totalSize: m.size,
              data: uint8ArrayToHex(realChunk),
            },
            db,
          );
        }

        db.close();
      }

      const concatedUnencrypted = await concatUint8Arrays([
        metadata[jRandom],
        merkleProofs[jRandom],
        chunks[jRandom],
      ]);

      const encryptedMessage = await encryptAsymmetric(
        concatedUnencrypted,
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
            roomId: room.id,
            fromPeerId: keyPair.peerId,
            toPeerId: peerId,
            label,
          } as WebSocketMessageMessageSendRequest,
        }),
      );
    }
  }
};
