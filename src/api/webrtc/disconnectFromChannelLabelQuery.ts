import { deleteChannel } from "../../reducers/roomSlice";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  RTCDisconnectFromChannelLabelParams,
} from "./interfaces";

export interface RTCDisconnectFromChannelLabelParamsExtension
  extends RTCDisconnectFromChannelLabelParams {
  dataChannels: IRTCDataChannel[];
}

const webrtcDisconnectFromChannelLabelQuery: BaseQueryFn<
  RTCDisconnectFromChannelLabelParamsExtension,
  void,
  unknown
> = async ({ label, dataChannels }, api) => {
  return new Promise((resolve, reject) => {
    try {
      const CHANNELS_LEN = dataChannels.length;
      const channelsClosedIndexes: number[] = [];

      for (let i = 0; i < CHANNELS_LEN; i++) {
        if (
          dataChannels[i].label !== label ||
          dataChannels[i].readyState !== "open"
        )
          continue;

        dataChannels[i].onopen = null;
        dataChannels[i].onclose = null;
        dataChannels[i].onerror = null;
        dataChannels[i].onclosing = null;
        dataChannels[i].onmessage = null;
        dataChannels[i].onbufferedamountlow = null;
        dataChannels[i].close();

        channelsClosedIndexes.push(i);

        api.dispatch(
          deleteChannel({ label, peerId: dataChannels[i].withPeerId }),
        );
      }

      const INDEXES_LEN = channelsClosedIndexes.length;
      for (let i = 0; i < INDEXES_LEN; i++) {
        dataChannels.splice(channelsClosedIndexes[i], 1);
      }

      resolve({ data: undefined });
    } catch (error) {
      reject(error);
    }
  });
};

export default webrtcDisconnectFromChannelLabelQuery;
