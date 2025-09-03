// import { wait } from "./handleSendMessage";
import { handleReadReceipt } from "./handleReadReceipt";
import { handleReceiveMessage } from "./handleReceiveMessage";

import webrtcApi from "../api/webrtc";

import {
  setChannel,
  setConnectingToPeers,
  setMessage,
  setMessageAllChunks,
} from "../reducers/roomSlice";

import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";
import { randomNumberInRange } from "../cryptography/utils";

import {
  // countDBSendQueue,
  deleteDBSendQueue,
  getDBSendQueue,
  setDBRoomMessageData,
} from "../db/api";

import { hexToUint8Array, uint8ArrayToHex } from "../utils/uint8array";
import { decompileChannelMessageLabel } from "../utils/channelLabel";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";
import type {
  IRTCPeerConnection,
  IRTCDataChannel,
} from "../api/webrtc/interfaces";
import type { LibCrypto } from "../cryptography/libcrypto";

export interface OpenChannelHelperParams {
  channel: string | RTCDataChannel;
  epc: IRTCPeerConnection;
  roomId: string;
  dataChannels: IRTCDataChannel[];
  decryptionModule: LibCrypto;
  merkleModule: LibCrypto;
}

export const KB64 = 64 * 1024;

export const MAX_BUFFERED_AMOUNT = 2 * KB64;

export const handleOpenChannel = (
  {
    channel,
    epc,
    roomId,
    dataChannels,
    decryptionModule,
    merkleModule,
  }: OpenChannelHelperParams,
  api: BaseQueryApi,
): Promise<IRTCDataChannel> => {
  return new Promise((resolve) => {
    const { keyPair } = api.getState() as State;

    if (typeof channel === "string") {
      const channelIndex = dataChannels.findIndex(
        (dc) => dc.label === channel && dc.withPeerId === epc.withPeerId,
      );

      if (channelIndex > -1 && dataChannels[channelIndex].readyState === "open")
        resolve(dataChannels[channelIndex]);
    }

    const label = typeof channel === "string" ? channel : channel.label;
    const dataChannel =
      typeof channel === "string"
        ? epc.createDataChannel(channel, {
            ordered: false,
            protocol: "raw",
            // negotiated: true,
            // id: dataChannelsWithPeer.length + 1,
            // maxRetransmits: 3,
          })
        : channel;
    dataChannel.binaryType = "arraybuffer";
    dataChannel.bufferedAmountLowThreshold = KB64;
    dataChannel.onbufferedamountlow = async () => {
      while (dataChannel.readyState === "open") {
        const sendQueue = await getDBSendQueue(label, epc.withPeerId);
        if (sendQueue.length === 0) break;

        while (
          sendQueue.length > 0 &&
          dataChannel.bufferedAmount < MAX_BUFFERED_AMOUNT &&
          dataChannel.readyState === "open"
        ) {
          // const timeoutMilliseconds = await randomNumberInRange(1, 10);
          // await wait(timeoutMilliseconds);

          let pos = await randomNumberInRange(0, sendQueue.length);
          if (pos === sendQueue.length) pos = 0;

          const [item] = sendQueue.splice(pos, 1);
          if (dataChannel.readyState === "open") {
            dataChannel.send(item.encryptedData);
            await deleteDBSendQueue(label, epc.withPeerId, item.position);
          }
        }
      }
    };

    const extChannel = dataChannel as IRTCDataChannel;
    extChannel.withPeerId = epc.withPeerId;
    extChannel.roomIds = [roomId];

    // extChannel.onclosing = () => {
    //   console.log(`Channel with label ${extChannel.label} is closing.`);
    // };

    extChannel.onclose = async () => {
      console.log(`Channel with label ${extChannel.label} has closed.`);

      await api.dispatch(
        webrtcApi.endpoints.disconnectFromPeerChannelLabel.initiate({
          peerId: epc.withPeerId,
          label: extChannel.label,
        }),
      );

      if (extChannel.label === "main") {
        api.dispatch(setConnectingToPeers({ roomId, connectingToPeers: true }));
      }
    };

    extChannel.onerror = async (e) => {
      console.error(e);

      await api.dispatch(
        webrtcApi.endpoints.disconnectFromPeerChannelLabel.initiate({
          peerId: epc.withPeerId,
          label: extChannel.label,
        }),
      );

      api.dispatch(setConnectingToPeers({ roomId, connectingToPeers: true }));
    };

    extChannel.onmessage = async (e) => {
      try {
        const { channelLabel, merkleRoot, merkleRootHex } =
          await decompileChannelMessageLabel(label); // , hash, hashHex } =

        const peerPublicKeyHex = epc.withPeerPublicKey;
        const senderPublicKey = hexToUint8Array(peerPublicKeyHex);
        const receiverSecretKey = hexToUint8Array(keyPair.secretKey);

        const { rooms } = api.getState() as State;
        const roomIndex = rooms.findIndex((r) => r.id === roomId);

        if (roomIndex > -1) {
          const data = e.data as ArrayBuffer;
          if (data.byteLength === crypto_hash_sha512_BYTES) {
            await handleReadReceipt(
              new Uint8Array(data),
              extChannel,
              rooms[roomIndex],
              api,
              dataChannels,
            );
          } else if (data.byteLength === KB64) {
            const {
              date,
              chunkSize,
              chunkIndex,
              receivedFullSize,
              // messageAlreadyExists,
              chunkAlreadyExists,
              // savedSize,
              totalSize,
              messageType,
              filename,
              chunkHash,
              messageHash,
            } = await handleReceiveMessage(
              data,
              merkleRoot,
              // hashHex,
              senderPublicKey,
              receiverSecretKey,
              // rooms[roomIndex],
              decryptionModule,
              merkleModule,
            );

            if (
              totalSize > 0 &&
              chunkHash.length === crypto_hash_sha512_BYTES &&
              extChannel.readyState === "open" &&
              !chunkAlreadyExists // &&
              // !receivedFullSize
            ) {
              extChannel.send(chunkHash.buffer as ArrayBuffer);
              // await wait(10);
            }

            const hashHex = uint8ArrayToHex(messageHash);

            if (receivedFullSize) {
              await setDBRoomMessageData(
                roomId,
                merkleRootHex,
                hashHex,
                epc.withPeerId,
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
                  fromPeerId: epc.withPeerId,
                  totalSize,
                  messageType,
                  filename,
                  channelLabel,
                  timestamp: date.getTime(),
                  alsoSendFinishedMessage: true,
                }),
              );
            } else if (
              chunkSize > 0 &&
              chunkIndex > -1 &&
              !chunkAlreadyExists
            ) {
              await setDBRoomMessageData(
                roomId,
                merkleRootHex,
                hashHex,
                epc.withPeerId,
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
                  fromPeerId: epc.withPeerId,
                  chunkSize,
                  totalSize,
                  messageType,
                  filename,
                  channelLabel,
                  timestamp: date.getTime(),
                }),
              );
            }
          } else {
            console.error("Unrecognized data size");
          }
        }
      } catch (error) {
        console.error(error);
      }
    };

    extChannel.onopen = async () => {
      try {
        console.log(
          `Channel with label "${extChannel.label}" and client ${epc.withPeerId} is open.`,
        );

        dataChannels.push(extChannel);

        const decompiledLabel = await decompileChannelMessageLabel(label);

        if (
          decompiledLabel.merkleRootHex === "" &&
          decompiledLabel.channelLabel.length > 0
        ) {
          api.dispatch(
            setChannel({ roomId, label, peerId: extChannel.withPeerId }),
          );
        }
      } catch (error) {
        console.error(error);
      }
    };

    resolve(extChannel);
  });
};
