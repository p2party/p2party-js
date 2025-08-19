import {
  deleteChannel,
  deletePeer,
  // setMessageAllChunks
} from "../../reducers/roomSlice";

import {
  deleteDBNewChunk,
  deleteDBSendQueue,
  setDBRoomMessageData,
} from "../../db/api";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type { State } from "../../store";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
  RTCDisconnectFromPeerChannelLabelParams,
} from "./interfaces";
import { decompileChannelMessageLabel } from "../../utils/channelLabel";

export interface RTCDisconnectFromPeerChannelLabelParamsExtension
  extends RTCDisconnectFromPeerChannelLabelParams {
  peerConnections: IRTCPeerConnection[];
  dataChannels: IRTCDataChannel[];
}

const webrtcDisconnectFromPeerChannelLabelQuery: BaseQueryFn<
  RTCDisconnectFromPeerChannelLabelParamsExtension,
  void,
  unknown
> = async ({ peerId, label, peerConnections, dataChannels }, api) => {
  try {
    const channelIndex = dataChannels.findIndex(
      (c) => c.label === label && c.withPeerId === peerId,
    );

    if (channelIndex > -1) {
      if (dataChannels[channelIndex]) {
        api.dispatch(
          deleteChannel({
            peerId,
            label,
          }),
        );

        await deleteDBSendQueue(label, peerId);

        if (
          dataChannels[channelIndex] // &&
        ) {
          dataChannels[channelIndex].onopen = null;
          dataChannels[channelIndex].onclose = null;
          dataChannels[channelIndex].onerror = null;
          dataChannels[channelIndex].onclosing = null;
          dataChannels[channelIndex].onmessage = null;
          dataChannels[channelIndex].onbufferedamountlow = null;

          if (dataChannels[channelIndex].readyState === "open")
            dataChannels[channelIndex].close();

          delete dataChannels[channelIndex];
        }

        dataChannels.splice(channelIndex, 1);
      }
    }

    const { channelLabel, merkleRootHex } =
      await decompileChannelMessageLabel(label);
    const hasLen = merkleRootHex.length > 0;

    if (hasLen) {
      const c = dataChannels.findIndex(async (c) => {
        const m = await decompileChannelMessageLabel(c.label);

        return m.merkleRootHex === merkleRootHex;
      });

      if (c < 0) await deleteDBNewChunk(merkleRootHex);
    }

    const { rooms, keyPair } = api.getState() as State;
    const roomsLen = rooms.length;
    let peerHasChannel = false;
    for (let i = 0; i < roomsLen; i++) {
      if (hasLen) {
        const messageIndex = rooms[i].messages.findLastIndex(
          (m) => m.merkleRootHex === merkleRootHex,
        );
        if (
          messageIndex > -1 &&
          rooms[i].messages[messageIndex].fromPeerId === keyPair.peerId
        ) {
          const hashHex = rooms[i].messages[messageIndex].sha512Hex;
          const roomId = rooms[i].id;
          const savedSize = rooms[i].messages[messageIndex].savedSize;
          const totalSize = rooms[i].messages[messageIndex].totalSize;
          const messageType = rooms[i].messages[messageIndex].messageType;
          const filename = rooms[i].messages[messageIndex].filename;
          const date = rooms[i].messages[messageIndex].timestamp;

          await setDBRoomMessageData(
            roomId,
            merkleRootHex,
            hashHex,
            keyPair.peerId,
            savedSize,
            totalSize,
            messageType,
            filename,
            channelLabel,
            date,
          );

          // api.dispatch(
          //   setMessageAllChunks({
          //     roomId,
          //     merkleRootHex,
          //     sha512Hex: hashHex,
          //     fromPeerId: keyPair.peerId,
          //     totalSize,
          //     messageType,
          //     filename,
          //     channelLabel,
          //     timestamp: date,
          //   }),
          // );
        }
      }

      const channelsLen = rooms[i].channels.length;
      for (let j = 0; j < channelsLen; j++) {
        if (rooms[i].channels[j].peerIds.includes(peerId)) {
          peerHasChannel = true;

          break;
        }
      }

      if (peerHasChannel) break;
    }

    if (!peerHasChannel) {
      api.dispatch(deletePeer({ peerId }));

      const peerIndex = peerConnections.findIndex(
        (peer) => peer.withPeerId === peerId,
      );

      if (peerIndex > -1) {
        peerConnections[peerIndex].ontrack = null;
        peerConnections[peerIndex].ondatachannel = null;
        peerConnections[peerIndex].onicecandidate = null;
        peerConnections[peerIndex].onicecandidateerror = null;
        peerConnections[peerIndex].onnegotiationneeded = null;
        peerConnections[peerIndex].onsignalingstatechange = null;
        peerConnections[peerIndex].onconnectionstatechange = null;
        peerConnections[peerIndex].onicegatheringstatechange = null;
        peerConnections[peerIndex].oniceconnectionstatechange = null;

        if (peerConnections[peerIndex].connectionState !== "closed")
          peerConnections[peerIndex].close();

        delete peerConnections[peerIndex];
        peerConnections.splice(peerIndex, 1);
      }
    }

    return { data: undefined };
  } catch (error) {
    throw error;
  }
};

export default webrtcDisconnectFromPeerChannelLabelQuery;
