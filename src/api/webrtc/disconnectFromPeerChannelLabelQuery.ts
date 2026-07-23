import webrtcApi from ".";

import { deleteChannel, deleteMessage } from "../../reducers/roomSlice";

import { deleteDBSendQueue } from "../../db/api";

import { decompileChannelMessageLabel } from "../../utils/channelLabel";
import { drainAndClose } from "../../utils/drainAndClose";

import { crypto_hash_sha512_BYTES } from "../../cryptography/interfaces";
import { sendReceiptFrame } from "../../handlers/receiptFrame";
import { findRoomPeerConnectionIndex } from "./roomPeer";
import { roomSendQueueLabel } from "../../utils/sendQueueKey";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type { State } from "../../store";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
  RTCDisconnectFromPeerChannelLabelParams,
} from "./interfaces";

export interface RTCDisconnectFromPeerChannelLabelParamsExtension extends RTCDisconnectFromPeerChannelLabelParams {
  peerConnections: IRTCPeerConnection[];
  dataChannels: IRTCDataChannel[];
}

const webrtcDisconnectFromPeerChannelLabelQuery: BaseQueryFn<
  RTCDisconnectFromPeerChannelLabelParamsExtension,
  undefined
> = async (
  {
    roomId,
    peerId,
    label,
    messageHash,
    alsoDeleteData,
    alsoSendFinishedMessage,
    channel,
    peerConnections,
    dataChannels,
  },
  api,
) => {
  const { rooms, signalingServer } = api.getState() as State;

  const channelIndex = dataChannels.findIndex(
    (c) =>
      (channel
        ? c === channel
        : c.label === label &&
          c.withPeerId === peerId &&
          c.roomIds.includes(roomId)),
  );

  if (channelIndex > -1 && dataChannels[channelIndex]) {
    if (
      alsoDeleteData &&
      dataChannels[channelIndex].cancelReceiveTransfer
    )
      await dataChannels[channelIndex].cancelReceiveTransfer();
    else dataChannels[channelIndex].releaseProtocolResources?.();
    if (
      messageHash &&
      alsoSendFinishedMessage &&
      messageHash.length === crypto_hash_sha512_BYTES
    ) {
      sendReceiptFrame(dataChannels[channelIndex], messageHash);
    }

    dataChannels[channelIndex].onopen = null;
    dataChannels[channelIndex].onclose = null;
    dataChannels[channelIndex].onerror = null;
    dataChannels[channelIndex].onclosing = null;
    dataChannels[channelIndex].onmessage = null;
    dataChannels[channelIndex].onbufferedamountlow = null;
    // Drain the send buffer before closing so any still-buffered frames are not
    // wiped by close() (objective 3) — mirrors disconnectFromChannelLabelQuery.
    if (dataChannels[channelIndex].readyState === "open")
      await drainAndClose(dataChannels[channelIndex]);

    dataChannels.splice(channelIndex, 1);

    await deleteDBSendQueue(roomSendQueueLabel(roomId, label), peerId);
  }

  // Check whether channel is a name or a message channel
  const { merkleRootHex } = await decompileChannelMessageLabel(label);
  if (merkleRootHex.length > 0) {
    if (alsoDeleteData)
      api.dispatch(deleteMessage({ roomId, merkleRootHex }));

    // `newChunks` is shared by every peer edge of one logical room send.
    // Never free it from a per-peer close/completion path: a fast peer may
    // finish before another peer's same-label channel has even reached onopen
    // (and therefore before it appears in dataChannels). The outer
    // handleSendMessage job owns final cleanup after all peer sends settle.
  } else if (!signalingServer.isConnected || alsoDeleteData) {
    api.dispatch(
      deleteChannel({
        roomId,
        peerId,
        label,
      }),
    );
  }

  // Find out if the two peers have at least one channel together
  const room = rooms.find((candidate) => candidate.id === roomId);
  const peerHasChannel =
    room?.channels.some((channel) => channel.peerIds.includes(peerId)) ?? false;

  if (!peerHasChannel) {
    const peerIndex = findRoomPeerConnectionIndex(
      peerConnections,
      roomId,
      peerId,
    );

    if (peerIndex > -1) {
      await api.dispatch(
        webrtcApi.endpoints.disconnectFromPeer.initiate({
          peerId: peerConnections[peerIndex].withPeerId,
          roomId,
        }),
      );
    }
  }

  return { data: undefined };
};

export default webrtcDisconnectFromPeerChannelLabelQuery;
