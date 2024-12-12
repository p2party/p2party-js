import { deleteChannel } from "../../reducers/roomSlice";

import { deleteDBSendQueue } from "../../db/api";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  RTCDisconnectFromPeerChannelLabelParams,
} from "./interfaces";

export interface RTCDisconnectFromPeerChannelLabelParamsExtension
  extends RTCDisconnectFromPeerChannelLabelParams {
  dataChannels: IRTCDataChannel[];
}

const webrtcDisconnectFromPeerChannelLabelQuery: BaseQueryFn<
  RTCDisconnectFromPeerChannelLabelParamsExtension,
  void,
  unknown
> = async ({ peerId, label, dataChannels }, api) => {
  try {
    const channelIndex = dataChannels.findIndex(
      (c) => c.label === label && c.withPeerId === peerId,
    );

    if (channelIndex > -1) {
      if (dataChannels[channelIndex].readyState === "open") {
        dataChannels[channelIndex].onopen = null;
        dataChannels[channelIndex].onclose = null;
        dataChannels[channelIndex].onerror = null;
        dataChannels[channelIndex].onclosing = null;
        dataChannels[channelIndex].onmessage = null;
        dataChannels[channelIndex].onbufferedamountlow = null;
        dataChannels[channelIndex].close();
      }

      await deleteDBSendQueue(label, peerId);

      api.dispatch(
        deleteChannel({
          peerId: dataChannels[channelIndex].withPeerId,
          label,
        }),
      );

      dataChannels.splice(channelIndex, 1);
    }

    return { data: undefined };
  } catch (error) {
    throw error;
  }
};

export default webrtcDisconnectFromPeerChannelLabelQuery;
