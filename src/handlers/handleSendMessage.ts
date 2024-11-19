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
      // const messageEncoded = new TextEncoder().encode(message);

      const m = deserializeMetadata(metadata[j]);
      if (m.chunkStartIndex < m.chunkEndIndex) {
        api.dispatch(
          setMessage({
            merkleRootHex: uint8ArrayToHex(merkleRoot),
            fromPeerId: keyPair.peerId,
            chunkIndex: m.chunkIndex,
            chunkSize: m.chunkEndIndex - m.chunkStartIndex,
            totalSize: m.size,
            messageType: m.messageType,
            channelLabel: label ?? dataChannels[channelIndex].label,
          }),
        );
      }

      const jRandom = indexesRandomized[j];
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

      dataChannels[i].send(concatedEncrypted.buffer);
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
