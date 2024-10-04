import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  RTCDisconnectFromPeerChannelLabelParams,
} from "./interfaces";
import { deleteChannel } from "../../reducers/roomSlice";

export interface RTCDisconnectFromPeerChannelLabelParamsExtension
  extends RTCDisconnectFromPeerChannelLabelParams {
  dataChannels: IRTCDataChannel[];
}

const webrtcDisconnectFromPeerChannelLabelQuery: BaseQueryFn<
  RTCDisconnectFromPeerChannelLabelParamsExtension,
  void,
  unknown
> = async ({ peerId, label, dataChannels }, api) => {
  return new Promise((resolve, reject) => {
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

        api.dispatch(
          deleteChannel({
            peerId: dataChannels[channelIndex].withPeerId,
            label,
          }),
        );

        dataChannels.splice(channelIndex, 1);
      }

      resolve({ data: undefined });
    } catch (error) {
      reject(error);
    }
  });
};

export default webrtcDisconnectFromPeerChannelLabelQuery;
