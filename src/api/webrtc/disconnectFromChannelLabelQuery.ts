import { sendImmediateCancel } from "../../handlers/immediateDisposition";
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
import { sendReceiptFrame } from "../../handlers/receiptFrame";

export interface RTCDisconnectFromChannelLabelParamsExtension extends RTCDisconnectFromChannelLabelParams {
  dataChannels: IRTCDataChannel[];
}

const webrtcDisconnectFromChannelLabelQuery: BaseQueryFn<
  RTCDisconnectFromChannelLabelParamsExtension,
  undefined
> = async (
  {
    roomId,
    label,
    messageHash,
    alsoDeleteData,
    alsoSendFinishedMessage,
    dataChannels,
  },
  api,
) => {
  const targets = dataChannels.filter(
    (channel) =>
      channel.label === label &&
      channel.roomIds.includes(roomId) &&
      channel.readyState === "open",
  );
  for (const targetChannel of targets) {
    if (alsoDeleteData) await sendImmediateCancel(targetChannel);
    if (alsoDeleteData && targetChannel.cancelReceiveTransfer)
      await targetChannel.cancelReceiveTransfer();
    else targetChannel.releaseProtocolResources?.();
    if (
      messageHash &&
      alsoSendFinishedMessage &&
      messageHash.length === crypto_hash_sha512_BYTES
    )
      sendReceiptFrame(targetChannel, messageHash);

    // Drain the send buffer before closing so the just-queued finished-message
    // (and any still-buffered chunks) are not wiped by close().
    await drainAndClose(targetChannel);

    if (alsoDeleteData) {
      const { merkleRootHex } = await decompileChannelMessageLabel(label);
      api.dispatch(deleteMessage({ roomId, merkleRootHex }));
    }
  }

  return { data: undefined };
};

export default webrtcDisconnectFromChannelLabelQuery;
