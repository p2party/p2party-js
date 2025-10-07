import { handleReceiveMessage } from "./handleReceiveMessage";

import { setDBRoomMessageData } from "../db/api";

import { uint8ArrayToHex } from "../utils/uint8array";
import { compileChannelMessageLabel } from "../utils/channelLabel";

import { setMessage, setMessageAllChunks } from "../reducers/roomSlice";

import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";

import signalingServerApi from "../api/signalingServerApi";

import type { LibCrypto } from "../cryptography/libcrypto";
import type { BaseQueryApi } from "@reduxjs/toolkit/dist/query";
import type { IRTCDataChannel } from "../api/webrtc/interfaces";
import type { WebSocketMessageMessageSendRequest } from "../utils/interfaces";
import type { State } from "../store";

const k16 = (u8: Uint8Array) => {
  const v = new DataView(u8.buffer, u8.byteOffset, 16);
  const a = v.getBigUint64(0, false).toString(16).padStart(16, "0");
  const b = v.getBigUint64(8, false).toString(16).padStart(16, "0");
  return a + b; // 128-bit prefi key
};

const processMessage = async (
  data: Uint8Array,
  api: BaseQueryApi,
  roomId: string,
  peerId: string,
  channelLabel: string,
  merkleRootHex: string,
  extChannel: IRTCDataChannel | undefined,
  decrypted: Uint8Array | undefined,
  messageArray: Uint8Array | undefined,
  merkleRootArray: Uint8Array | undefined,
  senderPublicKeyArray: Uint8Array | undefined,
  receiverSecretKeyArray: Uint8Array | undefined,
  receiveMessageModule: LibCrypto,
): Promise<{ receivedFullSize: boolean }> => {
  if (
    decrypted &&
    messageArray &&
    merkleRootArray &&
    senderPublicKeyArray &&
    receiverSecretKeyArray
  ) {
    try {
      messageArray.set(data);

      const {
        date,
        chunkSize,
        chunkIndex,
        receivedFullSize,
        chunkAlreadyExists,
        totalSize,
        messageType,
        filename,
        chunkHash,
        messageHash,
      } = await handleReceiveMessage(
        decrypted,
        messageArray,
        merkleRootArray,
        senderPublicKeyArray,
        receiverSecretKeyArray,
        receiveMessageModule,
      );

      const { signalingServer, keyPair } = api.getState() as State;

      if (
        totalSize > 0 &&
        chunkHash.length === crypto_hash_sha512_BYTES &&
        !chunkAlreadyExists
      ) {
        if (extChannel && extChannel.readyState === "open") {
          extChannel.send(chunkHash.buffer as ArrayBuffer);
        } else {
          const channel = await compileChannelMessageLabel(
            channelLabel,
            merkleRootHex,
          );

          if (signalingServer.isConnected) {
            await api.dispatch(
              signalingServerApi.endpoints.sendMessage.initiate({
                content: {
                  type: "message",
                  message: uint8ArrayToHex(chunkHash),
                  roomId,
                  fromPeerId: keyPair.peerId,
                  toPeerId: peerId,
                  label: channel,
                } as WebSocketMessageMessageSendRequest,
              }),
            );
          }
        }
      }

      const hashHex = uint8ArrayToHex(messageHash);

      if (receivedFullSize) {
        await setDBRoomMessageData(
          roomId,
          merkleRootHex,
          hashHex,
          peerId,
          totalSize,
          totalSize,
          messageType,
          filename,
          channelLabel,
          date.getTime(),
        );

        api.dispatch(
          setMessageAllChunks({
            roomId,
            merkleRootHex,
            sha512Hex: hashHex,
            fromPeerId: peerId,
            totalSize,
            messageType,
            filename,
            channelLabel,
            timestamp: date.getTime(),
            alsoSendFinishedMessage: true,
          }),
        );

        if (extChannel && extChannel.readyState === "open") {
          extChannel.send(messageHash.buffer as ArrayBuffer);
        } else {
          const channel = await compileChannelMessageLabel(
            channelLabel,
            merkleRootHex,
          );

          if (signalingServer.isConnected) {
            await api.dispatch(
              signalingServerApi.endpoints.sendMessage.initiate({
                content: {
                  type: "message",
                  message: uint8ArrayToHex(messageHash),
                  roomId,
                  fromPeerId: keyPair.peerId,
                  toPeerId: peerId,
                  label: channel,
                } as WebSocketMessageMessageSendRequest,
              }),
            );
          }
        }
      } else if (chunkSize > 0 && chunkIndex > -1 && !chunkAlreadyExists) {
        await setDBRoomMessageData(
          roomId,
          merkleRootHex,
          hashHex,
          peerId,
          chunkSize,
          totalSize,
          messageType,
          filename,
          channelLabel,
          date.getTime(),
        );

        api.dispatch(
          setMessage({
            roomId,
            merkleRootHex,
            sha512Hex: hashHex,
            fromPeerId: peerId,
            chunkSize,
            totalSize,
            messageType,
            filename,
            channelLabel,
            timestamp: date.getTime(),
          }),
        );
      }

      return { receivedFullSize };
    } catch (error) {
      console.error(error);

      return { receivedFullSize: false };
    }
  }

  return { receivedFullSize: false };
};

const drain = async (
  queue: Uint8Array[],
  seen: Set<string>,
  draining: boolean,
  api: BaseQueryApi,
  roomId: string,
  peerId: string,
  channelLabel: string,
  merkleRootHex: string,
  extChannel: IRTCDataChannel | undefined,
  decrypted: Uint8Array | undefined,
  messageArray: Uint8Array | undefined,
  merkleRootArray: Uint8Array | undefined,
  senderPublicKeyArray: Uint8Array | undefined,
  receiverSecretKeyArray: Uint8Array | undefined,
  receiveMessageModule: LibCrypto,
) => {
  if (draining) return;
  draining = true;
  try {
    for (;;) {
      const chunk = queue.pop();
      if (!chunk) break;

      // const { receivedFullSize } =
      await processMessage(
        chunk,
        api,
        roomId,
        peerId,
        channelLabel,
        merkleRootHex,
        extChannel,
        decrypted,
        messageArray,
        merkleRootArray,
        senderPublicKeyArray,
        receiverSecretKeyArray,
        receiveMessageModule,
      );

      // if (receivedFullSize) {
      //   queue = [];
      //   seen = new Set<string>();
      //
      //   break;
      // }
    }
  } finally {
    draining = false;
    if (queue.length > 0)
      void drain(
        queue,
        seen,
        draining,
        api,
        roomId,
        peerId,
        channelLabel,
        merkleRootHex,
        extChannel,
        decrypted,
        messageArray,
        merkleRootArray,
        senderPublicKeyArray,
        receiverSecretKeyArray,
        receiveMessageModule,
      );
  }
};

export const enqueue = (
  data: Uint8Array,
  queue: Uint8Array[],
  seen: Set<string>,
  draining: boolean,
  api: BaseQueryApi,
  roomId: string,
  peerId: string,
  channelLabel: string,
  merkleRootHex: string,
  extChannel: IRTCDataChannel | undefined,
  decrypted: Uint8Array | undefined,
  messageArray: Uint8Array | undefined,
  merkleRootArray: Uint8Array | undefined,
  senderPublicKeyArray: Uint8Array | undefined,
  receiverSecretKeyArray: Uint8Array | undefined,
  receiveMessageModule: LibCrypto,
) => {
  const k = k16(data);
  if (seen.has(k)) return; // drop duplicate-in-queue
  seen.add(k);

  queue.push(data);

  if (!draining)
    void drain(
      queue,
      seen,
      draining,
      api,
      roomId,
      peerId,
      channelLabel,
      merkleRootHex,
      extChannel,
      decrypted,
      messageArray,
      merkleRootArray,
      senderPublicKeyArray,
      receiverSecretKeyArray,
      receiveMessageModule,
    );
};
