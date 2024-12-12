import { deleteChannel, deleteMessage } from "../../reducers/roomSlice";

import { deleteDBSendQueue } from "../../db/api";
import { decompileChannelMessageLabel } from "../../utils/channelLabel";
import { crypto_hash_sha512_BYTES } from "../../cryptography/interfaces";

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
  try {
    const CHANNELS_LEN = dataChannels.length;
    for (let i = 0; i < CHANNELS_LEN; i++) {
      if (
        dataChannels[i].label !== label ||
        dataChannels[i].readyState !== "open"
      )
        continue;

      await deleteDBSendQueue(label, dataChannels[i].withPeerId);

      api.dispatch(
        deleteChannel({ label, peerId: dataChannels[i].withPeerId }),
      );

      dataChannels[i].onopen = null;
      dataChannels[i].onclose = null;
      dataChannels[i].onerror = null;
      dataChannels[i].onclosing = null;
      dataChannels[i].onmessage = null;
      dataChannels[i].onbufferedamountlow = null;
      dataChannels[i].close();

      if (alsoDeleteData) {
        const { merkleRootHex } = await decompileChannelMessageLabel(label);
        if (merkleRootHex.length === crypto_hash_sha512_BYTES * 2) {
          api.dispatch(deleteMessage({ merkleRootHex }));
        }
      }

      delete dataChannels[i];
    }

    return { data: undefined };
  } catch (error) {
    throw error;
  }
};

export default webrtcDisconnectFromChannelLabelQuery;
