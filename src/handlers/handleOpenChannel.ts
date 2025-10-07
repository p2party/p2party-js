import { handleReadReceipt } from "./handleReadReceipt";
import { enqueue } from "./handleMessageQueueing";

import webrtcApi from "../api/webrtc";

import { setChannel, setConnectingToPeers } from "../reducers/roomSlice";

import {
  crypto_hash_sha512_BYTES,
  crypto_sign_ed25519_PUBLICKEYBYTES,
  crypto_sign_ed25519_SECRETKEYBYTES,
} from "../cryptography/interfaces";
import { randomNumberInRange } from "../cryptography/utils";
import cryptoMemory from "../cryptography/memory";
import { wasmLoader } from "../cryptography/wasmLoader";

import { deleteDBSendQueue, getDBSendQueue } from "../db/api";

import { hexToUint8Array } from "../utils/uint8array";
import { decompileChannelMessageLabel } from "../utils/channelLabel";
import {
  DECRYPTED_LEN,
  MAX_BUFFERED_AMOUNT,
  MESSAGE_LEN,
} from "../utils/constants";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";
import type {
  IRTCPeerConnection,
  IRTCDataChannel,
} from "../api/webrtc/interfaces";

export interface OpenChannelHelperParams {
  channel: string | RTCDataChannel;
  epc: IRTCPeerConnection;
  roomId: string;
  dataChannels: IRTCDataChannel[];
}

export const handleOpenChannel = async (
  { channel, epc, roomId, dataChannels }: OpenChannelHelperParams,
  api: BaseQueryApi,
): Promise<IRTCDataChannel> => {
  const { keyPair, rooms } = api.getState() as State;

  const senderPublicKey = hexToUint8Array(epc.withPeerPublicKey);
  const receiverSecretKey = hexToUint8Array(keyPair.secretKey);
  const roomIndex = rooms.findIndex((r) => r.id === roomId);
  let peerRoomIndex = epc.rooms.findLastIndex((r) => r.roomId === roomId);
  if (peerRoomIndex === -1) {
    const wasmMemory = cryptoMemory.getReceiveMessageMemory();
    const receiveMessageModule = await wasmLoader(wasmMemory);
    // const receiveMessageModule = await libcrypto({
    //   wasmMemory,
    // });

    peerRoomIndex = epc.rooms.length;
    epc.rooms.push({
      roomId,
      receiveMessageModule,
    });
  }

  const queue: Uint8Array[] = [];
  const seen = new Set<string>();
  let draining = false;

  if (typeof channel === "string") {
    const channelIndex = dataChannels.findIndex(
      (dc) => dc.label === channel && dc.withPeerId === epc.withPeerId,
    );

    if (channelIndex > -1 && dataChannels[channelIndex].readyState === "open")
      return dataChannels[channelIndex];
  }

  const label = typeof channel === "string" ? channel : channel.label;
  const { channelLabel, merkleRoot, merkleRootHex } =
    await decompileChannelMessageLabel(label);

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
  dataChannel.bufferedAmountLowThreshold = MESSAGE_LEN;
  dataChannel.onbufferedamountlow = async () => {
    while (dataChannel.readyState === "open") {
      const sendQueue = await getDBSendQueue(label, epc.withPeerId);
      if (sendQueue.length === 0) break;

      while (
        sendQueue.length > 0 &&
        dataChannel.bufferedAmount < MAX_BUFFERED_AMOUNT &&
        dataChannel.readyState === "open"
      ) {
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

  let ptr1: number | undefined;
  let decrypted: Uint8Array | undefined;
  let ptr2: number | undefined;
  let messageArray: Uint8Array | undefined;
  let ptr3: number | undefined;
  let merkleRootArray: Uint8Array | undefined;
  let ptr4: number | undefined;
  let senderPublicKeyArray: Uint8Array | undefined;
  let ptr5: number | undefined;
  let receiverSecretKeyArray: Uint8Array | undefined;

  // extChannel.onclosing = () => {
  //   console.log(`Channel with label ${extChannel.label} is closing.`);
  // };

  extChannel.onclose = async () => {
    console.log(`Channel with label ${extChannel.label} has closed.`);

    if (peerRoomIndex && epc.rooms[peerRoomIndex]) {
      if (ptr1) epc.rooms[peerRoomIndex].receiveMessageModule._free(ptr1);
      if (ptr2) epc.rooms[peerRoomIndex].receiveMessageModule._free(ptr2);
      if (ptr3) epc.rooms[peerRoomIndex].receiveMessageModule._free(ptr3);
      if (ptr4) epc.rooms[peerRoomIndex].receiveMessageModule._free(ptr4);
      if (ptr5) epc.rooms[peerRoomIndex].receiveMessageModule._free(ptr5);
    }

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
    const data = new Uint8Array(e.data as ArrayBuffer);

    if (roomIndex > -1 && data.length === crypto_hash_sha512_BYTES) {
      try {
        await handleReadReceipt(
          data,
          extChannel.label,
          extChannel.withPeerId,
          // extChannel,
          rooms[roomIndex],
          api,
          // dataChannels,
        );
      } catch (error) {
        console.error(error);
      }

      return;
    }

    if (data.length === MESSAGE_LEN) {
      void enqueue(
        data,
        queue,
        seen,
        draining,
        api,
        roomId,
        extChannel.withPeerId,
        channelLabel,
        merkleRootHex,
        extChannel,
        decrypted,
        messageArray,
        merkleRootArray,
        senderPublicKeyArray,
        receiverSecretKeyArray,
        epc.rooms[peerRoomIndex].receiveMessageModule,
      );

      return;
    }

    console.error(new Error("Wrong data length received"));
  };

  extChannel.onopen = () => {
    console.log(
      `Channel with label "${extChannel.label}" and client ${epc.withPeerId} is open.`,
    );

    dataChannels.push(extChannel);

    if (merkleRootHex === "" && channelLabel.length > 0) {
      api.dispatch(
        setChannel({ roomId, label, peerId: extChannel.withPeerId }),
      );
    }

    try {
      ptr1 =
        epc.rooms[peerRoomIndex].receiveMessageModule._malloc(DECRYPTED_LEN);
      decrypted = new Uint8Array(
        epc.rooms[peerRoomIndex].receiveMessageModule.wasmMemory.buffer,
        ptr1,
        DECRYPTED_LEN,
      );

      ptr2 = epc.rooms[peerRoomIndex].receiveMessageModule._malloc(MESSAGE_LEN);
      messageArray = new Uint8Array(
        epc.rooms[peerRoomIndex].receiveMessageModule.wasmMemory.buffer,
        ptr2,
        MESSAGE_LEN,
      );

      ptr3 = epc.rooms[peerRoomIndex].receiveMessageModule._malloc(
        crypto_hash_sha512_BYTES,
      );
      merkleRootArray = new Uint8Array(
        epc.rooms[peerRoomIndex].receiveMessageModule.wasmMemory.buffer,
        ptr3,
        crypto_hash_sha512_BYTES,
      );
      merkleRootArray.set(merkleRoot);

      ptr4 = epc.rooms[peerRoomIndex].receiveMessageModule._malloc(
        crypto_sign_ed25519_PUBLICKEYBYTES,
      );
      senderPublicKeyArray = new Uint8Array(
        epc.rooms[peerRoomIndex].receiveMessageModule.wasmMemory.buffer,
        ptr4,
        crypto_sign_ed25519_PUBLICKEYBYTES,
      );
      senderPublicKeyArray.set(senderPublicKey);

      ptr5 = epc.rooms[peerRoomIndex].receiveMessageModule._malloc(
        crypto_sign_ed25519_SECRETKEYBYTES,
      );
      receiverSecretKeyArray = new Uint8Array(
        epc.rooms[peerRoomIndex].receiveMessageModule.wasmMemory.buffer,
        ptr5,
        crypto_sign_ed25519_SECRETKEYBYTES,
      );
      receiverSecretKeyArray.set(receiverSecretKey);
    } catch (error) {
      console.error(error);
    }
  };

  return extChannel;
};
