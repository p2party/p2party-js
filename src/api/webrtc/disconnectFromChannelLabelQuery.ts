import {
  // deleteChannel,
  deleteMessage,
} from "../../reducers/roomSlice";

// import { deleteDBSendQueue } from "../../db/api";
import { decompileChannelMessageLabel } from "../../utils/channelLabel";

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
> = async ({ label, alsoDeleteData, dataChannels }, api) => {
  const CHANNELS_LEN = dataChannels.length;
  if (CHANNELS_LEN === 0) return { data: undefined };

  for (let i = 0; i < CHANNELS_LEN; i++) {
    if (
      !dataChannels[i] ||
      dataChannels[i].label !== label ||
      dataChannels[i].readyState !== "open"
    )
      continue;

    if (alsoDeleteData) {
      const { merkleRootHex } = await decompileChannelMessageLabel(label);

      if (alsoDeleteData) {
        api.dispatch(deleteMessage({ merkleRootHex }));
      }
    }

    dataChannels[i].close();
  }

  return { data: undefined };
};

export default webrtcDisconnectFromChannelLabelQuery;
