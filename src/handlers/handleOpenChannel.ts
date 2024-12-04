import { handleSendMessage } from "./handleSendMessage";
import { handleReceiveMessage } from "./handleReceiveMessage";

import webrtcApi from "../api/webrtc";

import { setChannel, setMessage } from "../reducers/roomSlice";

import { randomNumberInRange } from "../cryptography/utils";

import { deleteDBSendQueueItem, getDB, getDBSendQueue } from "../utils/db";
import { hexToUint8Array } from "../utils/uint8array";

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
  dataChannels: IRTCDataChannel[];
  encryptionModule: LibCrypto;
  decryptionModule: LibCrypto;
  merkleModule: LibCrypto;
}

export const MAX_BUFFERED_AMOUNT = 128 * 1024;

export const handleOpenChannel = async (
  {
    channel,
    epc,
    dataChannels,
    encryptionModule,
    decryptionModule,
    merkleModule,
  }: OpenChannelHelperParams,
  api: BaseQueryApi,
): Promise<IRTCDataChannel> => {
  try {
    const { keyPair } = api.getState() as State;

    const label = typeof channel === "string" ? channel : channel.label;

    const dataChannel =
      typeof channel === "string"
        ? epc.createDataChannel(channel, {
            ordered: false,
            maxRetransmits: 10,
          })
        : channel;
    dataChannel.binaryType = "blob";
    dataChannel.bufferedAmountLowThreshold = 64 * 1024;
    dataChannel.onbufferedamountlow = async () => {
      const db = await getDB();
      const sendQueue = await getDBSendQueue(label, epc.withPeerId, db);
      const sendQueueLen = sendQueue.length;

      while (dataChannel.bufferedAmount < MAX_BUFFERED_AMOUNT && sendQueueLen > 0) {
        for (let i = 0; i < sendQueueLen; i++) {
          const timeoutSeconds = await randomNumberInRange(1, 50);
          setTimeout(() => {
            dataChannel.send(sendQueue[i].encryptedData);
          }, timeoutSeconds);

          await deleteDBSendQueueItem(
            sendQueue[i].position,
            label,
            epc.withPeerId,
            db,
          );

          delete(sendQueue[i]);
        }
      }

      db.close();
    };

    const extChannel = dataChannel as IRTCDataChannel;
    extChannel.withPeerId = epc.withPeerId;

    extChannel.onclosing = () => {
      console.log(`Channel with label ${extChannel.label} is closing.`);
    };

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
      console.log("Received message");
      try {
        const { room } = api.getState() as State;

        const peerPublicKeyHex = epc.withPeerPublicKey;
        const senderPublicKey = hexToUint8Array(peerPublicKeyHex);
        const receiverSecretKey = hexToUint8Array(keyPair.secretKey);

        const {
          merkleRootHex,
          sha512Hex,
          chunkSize,
          totalSize,
          messageType,
          filename,
        } = await handleReceiveMessage(
          e.data as Blob,
          senderPublicKey,
          receiverSecretKey,
          room,
          decryptionModule,
          merkleModule,
        );

        if (chunkSize > 0) {
          api.dispatch(
            setMessage({
              merkleRootHex,
              sha512Hex,
              fromPeerId: epc.withPeerId,
              chunkSize,
              totalSize,
              messageType,
              filename,
              channelLabel: label,
            }),
          );
        }
      } catch (error) {
        console.error(error);
      }
    };

    extChannel.onopen = async () => {
      console.log(
        `Channel with label \"${extChannel.label}\" and client ${epc.withPeerId} is open.`,
      );

      dataChannels.push(extChannel);

      api.dispatch(setChannel({ label, peerId: extChannel.withPeerId }));

      const msg = `Connected with ${keyPair.peerId} on channel ${extChannel.label}`;

      await handleSendMessage(
        msg,
        [epc],
        [extChannel],
        encryptionModule,
        api,
        label,
      );
    };

    return extChannel;
  } catch (error) {
    throw error;
  }
};
