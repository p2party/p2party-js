import { deleteChannel, deletePeer } from "../../reducers/roomSlice";

import { deleteDBSendQueue } from "../../db/api";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type { State } from "../../store";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
  RTCDisconnectFromPeerChannelLabelParams,
} from "./interfaces";

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
            peerId: dataChannels[channelIndex].withPeerId,
            label,
          }),
        );

        await deleteDBSendQueue(label, dataChannels[channelIndex].withPeerId);

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

    const { room } = api.getState() as State;

    let peerHasChannel = false;
    const channelsLen = room.channels.length;
    for (let i = 0; i < channelsLen; i++) {
      if (room.channels[i].peerIds.includes(peerId)) {
        peerHasChannel = true;

        break;
      }
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
