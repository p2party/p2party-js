import { handleReceiveMessage } from "./handleReceiveMessage";

import webrtcApi from "../api/webrtc";

import { setChannel, setMessage } from "../reducers/roomSlice";

import { randomNumberInRange } from "../cryptography/utils";

import {
  // countDBSendQueue,
  deleteDBSendQueue,
  getDBSendQueue,
  setDBRoomMessageData,
} from "../db/api";
import { hexToUint8Array } from "../utils/uint8array";
import { decompileChannelMessageLabel } from "../utils/channelLabel";

import { wait } from "./handleSendMessage";

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

export const MAX_BUFFERED_AMOUNT = 2 * 64 * 1024;

export const handleOpenChannel = async (
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
  try {
    const { keyPair } = api.getState() as State;

    // const dataChannelsWithPeer = dataChannels.filter((d) => d.withPeerId === epc.withPeerId);

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
    dataChannel.bufferedAmountLowThreshold = 64 * 1024;
    dataChannel.onbufferedamountlow = async () => {
      while (dataChannel.readyState === "open") {
        const sendQueue = await getDBSendQueue(label, epc.withPeerId);
        if (sendQueue.length === 0) break;

        while (
          sendQueue.length > 0 &&
          dataChannel.bufferedAmount < MAX_BUFFERED_AMOUNT &&
          dataChannel.readyState === "open"
        ) {
          const timeoutMilliseconds = await randomNumberInRange(1, 10);
          await wait(timeoutMilliseconds);

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

    extChannel.onclose = () => {
      console.log(`Channel with label ${extChannel.label} has closed.`);

      api.dispatch(
        webrtcApi.endpoints.disconnectFromPeerChannelLabel.initiate({
          peerId: epc.withPeerId,
          label: extChannel.label,
        }),
      );
    };

    extChannel.onerror = (e) => {
      console.error(e);

      api.dispatch(
        webrtcApi.endpoints.disconnectFromPeerChannelLabel.initiate({
          peerId: epc.withPeerId,
          label: extChannel.label,
        }),
      );
    };

    extChannel.onmessage = async (e) => {
      try {
        const { channelLabel, merkleRoot, merkleRootHex, hashHex } =
          await decompileChannelMessageLabel(label);

        const peerPublicKeyHex = epc.withPeerPublicKey;
        const senderPublicKey = hexToUint8Array(peerPublicKeyHex);
        const receiverSecretKey = hexToUint8Array(keyPair.secretKey);

        const { rooms } = api.getState() as State;
        const roomIndex = rooms.findIndex((r) => r.id === roomId);

        if (roomIndex > -1) {
          const {
            chunkSize,
            chunkIndex,
            // relevant,
            receivedFullSize,
            totalSize,
            messageType,
            filename,
          } = await handleReceiveMessage(
            e.data as ArrayBuffer,
            merkleRoot,
            senderPublicKey,
            receiverSecretKey,
            rooms[roomIndex],
            decryptionModule,
            merkleModule,
          );

          await setDBRoomMessageData(roomId, {
            roomId,
            merkleRootHex,
            sha512Hex: hashHex,
            fromPeerId: epc.withPeerId,
            totalSize,
            messageType,
            filename,
            channelLabel,
            timestamp: Date.now(),
          });

          if (chunkSize > 0) {
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
              }),
            );
          }

          if (chunkIndex > -1 && chunkSize > 0 && receivedFullSize)
            extChannel.close();
        }
      } catch (error) {
        console.error(error);
      }
    };

    extChannel.onopen = async () => {
      try {
        console.log(
          `Channel with label \"${extChannel.label}\" and client ${epc.withPeerId} is open.`,
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

    return extChannel;
  } catch (error) {
    throw error;
  }
};
