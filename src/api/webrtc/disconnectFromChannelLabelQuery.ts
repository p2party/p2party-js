import {
  // deleteChannel,
  deleteMessage,
} from "../../reducers/roomSlice";

// import { deleteDBSendQueue } from "../../db/api";
import { decompileChannelMessageLabel } from "../../utils/channelLabel";
import { drainAndClose } from "../../utils/drainAndClose";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  RTCDisconnectFromChannelLabelParams,
} from "./interfaces";
import { crypto_hash_sha512_BYTES } from "../../cryptography/interfaces";

export interface RTCDisconnectFromChannelLabelParamsExtension extends RTCDisconnectFromChannelLabelParams {
  dataChannels: IRTCDataChannel[];
}

const webrtcDisconnectFromChannelLabelQuery: BaseQueryFn<
  RTCDisconnectFromChannelLabelParamsExtension,
  undefined
> = async (
  { label, messageHash, alsoDeleteData, alsoSendFinishedMessage, dataChannels },
  api,
) => {
  const CHANNELS_LEN = dataChannels.length;
  if (CHANNELS_LEN === 0) return { data: undefined };

  for (let i = 0; i < CHANNELS_LEN; i++) {
    if (
      dataChannels[i]?.label !== label ||
      dataChannels[i].readyState !== "open"
    )
      continue;

    if (
      messageHash &&
      alsoSendFinishedMessage &&
      messageHash.length === crypto_hash_sha512_BYTES
    )
      dataChannels[i].send(messageHash.buffer as ArrayBuffer);

    // Drain the send buffer before closing so the just-queued finished-message
    // (and any still-buffered chunks) are not wiped by close().
    await drainAndClose(dataChannels[i]);

    if (alsoDeleteData) {
      const { merkleRootHex } = await decompileChannelMessageLabel(label);
      api.dispatch(deleteMessage({ merkleRootHex }));
    }
  }

  return { data: undefined };
};

export default webrtcDisconnectFromChannelLabelQuery;
