import { isUUID } from "class-validator";

import { setMessage } from "../../reducers/roomSlice";

import libcrypto from "../../cryptography/libcrypto";
import {
  encryptAsymmetric,
  decryptAsymmetric,
} from "../../cryptography/chacha20poly1305";

import { hexToUint8, uint8ToHex } from "../../utils/hexString";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type { State } from "../../store";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
  RTCChannelMessageParams,
} from "./interfaces";

export interface RTCChannelMessageParamsExtension
  extends RTCChannelMessageParams {
  peerConnections: IRTCPeerConnection[];
  dataChannels: IRTCDataChannel[];
  encryptionWasmMemory: WebAssembly.Memory;
  decryptionWasmMemory: WebAssembly.Memory;
}

const webrtcMessageQuery: BaseQueryFn<
  RTCChannelMessageParamsExtension,
  void,
  unknown
> = async (
  {
    message,
    fromPeerId,
    label,
    peerConnections,
    dataChannels,
    encryptionWasmMemory,
    decryptionWasmMemory,
  },
  api,
) => {
  try {
    if (!isUUID(fromPeerId)) throw new Error("FromPeerId not a uuidv4");

    const { keyPair } = api.getState() as State;
    if (keyPair.peerId === fromPeerId) {
      const encryptionModule = await libcrypto({
        wasmMemory: encryptionWasmMemory,
      });

      if (label) {
        const channelIndex = dataChannels.findIndex((c) => c.label === label);

        if (channelIndex === -1) throw new Error("No channel with this label");

        const CHANNELS_LEN = dataChannels.length;
        for (let i = channelIndex; i < CHANNELS_LEN; i++) {
          if (label && dataChannels[i].label !== label) continue;

          const peerId = dataChannels[i].withPeerId;
          const peerIndex = peerConnections.findIndex(
            (p) => p.withPeerId === peerId,
          );
          if (peerIndex === -1) continue;

          const peerPublicKeyHex = peerConnections[peerIndex].withPeerPublicKey;

          const receiverPublicKey = hexToUint8(peerPublicKeyHex);
          const senderSecretKey = hexToUint8(keyPair.secretKey);

          const randomData = window.crypto.getRandomValues(new Uint8Array(16));
          const messageEncoded = new TextEncoder().encode(message);
          const encryptedMessage = await encryptAsymmetric(
            messageEncoded,
            receiverPublicKey,
            senderSecretKey,
            randomData,
            encryptionModule,
          );

          const encryptedMessageHex =
            uint8ToHex(encryptedMessage) + "-" + uint8ToHex(randomData);

          dataChannels[i].send(encryptedMessageHex);

          api.dispatch(
            setMessage({
              id: window.crypto.randomUUID(),
              message,
              fromPeerId,
              // toPeerId: dataChannels[i].withPeerId,
              channelLabel: dataChannels[i].label,
              timestamp: Date.now(),
            }),
          );
        }
      } else {
        const CHANNELS_LEN = dataChannels.length;
        for (let i = 0; i < CHANNELS_LEN; i++) {
          const peerId = dataChannels[i].withPeerId;
          const peerIndex = peerConnections.findIndex(
            (p) => p.withPeerId === peerId,
          );
          if (peerIndex === -1) continue;

          const peerPublicKeyHex = peerConnections[peerIndex].withPeerPublicKey;

          const receiverPublicKey = hexToUint8(peerPublicKeyHex);
          const senderSecretKey = hexToUint8(keyPair.secretKey);

          const randomData = window.crypto.getRandomValues(new Uint8Array(16));
          const messageEncoded = new TextEncoder().encode(message);
          const encryptedMessage = await encryptAsymmetric(
            messageEncoded,
            receiverPublicKey,
            senderSecretKey,
            randomData,
            encryptionModule,
          );

          const encryptedMessageHex =
            uint8ToHex(encryptedMessage) + "-" + uint8ToHex(randomData);

          dataChannels[i].send(encryptedMessageHex);

          api.dispatch(
            setMessage({
              id: window.crypto.randomUUID(),
              message,
              fromPeerId,
              channelLabel: dataChannels[i].label,
              timestamp: Date.now(),
            }),
          );
        }
      }
    } else {
      const decryptionModule = await libcrypto({
        wasmMemory: decryptionWasmMemory,
      });

      if (!label) throw new Error("Received a message without a label");

      const peerIndex = peerConnections.findIndex(
        (p) => p.withPeerId === fromPeerId,
      );
      if (peerIndex === -1)
        throw new Error("Received a message from unknown peer");

      const peerPublicKeyHex = peerConnections[peerIndex].withPeerPublicKey;

      const senderPublicKey = hexToUint8(peerPublicKeyHex);
      const receiverSecretKey = hexToUint8(keyPair.secretKey);

      const splitIndex = message.length - 32;
      const encryptedMessage = hexToUint8(message.slice(0, splitIndex - 1));
      const randomData = hexToUint8(message.slice(splitIndex));

      const decryptedMessage = await decryptAsymmetric(
        encryptedMessage,
        senderPublicKey,
        receiverSecretKey,
        randomData,
        decryptionModule,
      );

      api.dispatch(
        setMessage({
          id: window.crypto.randomUUID(),
          message: new TextDecoder().decode(decryptedMessage),
          fromPeerId,
          // toPeerId: keyPair.peerId,
          channelLabel: label ?? "",
          timestamp: Date.now(),
        }),
      );
    }

    return { data: undefined };
  } catch (error) {
    throw error;
  }
};

export default webrtcMessageQuery;
