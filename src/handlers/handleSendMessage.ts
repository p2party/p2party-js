import { encryptAsymmetric } from "../cryptography/chacha20poly1305";
import { fisherYatesShuffle } from "../cryptography/utils";

import { setMessage } from "../reducers/roomSlice";

import {
  hexToUint8Array,
  uint8ArrayToHex,
  concatUint8Arrays,
} from "../utils/uint8array";
import { splitToChunks } from "../utils/splitToChunks";
import { deserializeMetadata } from "../utils/metadata";
import { getDB, getDBChunk, setDBChunk } from "../utils/db";
import { getMimeType } from "../utils/messageTypes";

import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../api/webrtc/interfaces";
import type { LibCrypto } from "../cryptography/libcrypto";
import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";

export const handleSendMessage = async (
  data: string | File,
  // senderSecretKey: Uint8Array,
  peerConnections: IRTCPeerConnection[],
  dataChannels: IRTCDataChannel[],
  encryptionModule: LibCrypto,
  api: BaseQueryApi,
  label?: string,
) => {
  const { keyPair } = api.getState() as State;
  const senderSecretKey = hexToUint8Array(keyPair.secretKey);

  const channelIndex = label
    ? dataChannels.findIndex((c) => c.label === label)
    : 0;
  if (channelIndex === -1) throw new Error("No channel with label " + label);

  const { merkleRoot, chunks, metadata, merkleProofs } =
    await splitToChunks(data);

  const merkleRootHex = uint8ArrayToHex(merkleRoot);

  const chunksLen = chunks.length;
  // const channels: string[] = [];
  const CHANNELS_LEN = dataChannels.length;
  for (let i = channelIndex; i < CHANNELS_LEN; i++) {
    if (label && dataChannels[i].label !== label) continue;

    const peerId = dataChannels[i].withPeerId;
    const peerIndex = peerConnections.findIndex((p) => p.withPeerId === peerId);
    if (peerIndex === -1) continue;

    const peerPublicKeyHex = peerConnections[peerIndex].withPeerPublicKey;
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
            filename: m.name,
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
          const mimeType = getMimeType(m.messageType);

          await setDBChunk(
            {
              merkleRoot: merkleRootHex,
              chunkIndex: m.chunkIndex,
              totalSize: m.size,
              data: new Blob([realChunk]), // uint8ArrayToHex(realChunk),
              mimeType,
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

      dataChannels[i].send(concatedEncrypted);
    }

    // // const messageEncoded = new TextEncoder().encode(message);
    // const encryptedMessage = await encryptAsymmetric(
    //   serialized, // messageEncoded,
    //   receiverPublicKey,
    //   senderSecretKey,
    //   additionalData,
    //   encryptionModule,
    // );
    //
    // const encryptedMessageHex =
    //   uint8ToHex(encryptedMessage) + "-" + uint8ToHex(additionalData);
    //
    // dataChannels[i].send(encryptedMessageHex);

    // if (label && channels.length === 0) channels.push(label);
    // if (!label && !channels.includes(dataChannels[i].label))
    //   channels.push(dataChannels[i].label);
  }
};
