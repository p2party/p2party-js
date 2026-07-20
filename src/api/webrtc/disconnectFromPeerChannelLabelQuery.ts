import webrtcApi from ".";

import { deleteChannel, deleteMessage } from "../../reducers/roomSlice";

import { deleteDBNewChunk, deleteDBSendQueue } from "../../db/api";

import { decompileChannelMessageLabel } from "../../utils/channelLabel";
import { drainAndClose } from "../../utils/drainAndClose";

import { crypto_hash_sha512_BYTES } from "../../cryptography/interfaces";

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
    peerId,
    label,
    messageHash,
    alsoDeleteData,
    alsoSendFinishedMessage,
    transferComplete,
    peerConnections,
    dataChannels,
  },
  api,
) => {
  const { rooms, signalingServer } = api.getState() as State;

  const channelIndex = dataChannels.findIndex(
    (c) => c.label === label && c.withPeerId === peerId,
  );

  if (channelIndex > -1 && dataChannels[channelIndex]) {
    if (
      messageHash &&
      alsoSendFinishedMessage &&
      messageHash.length === crypto_hash_sha512_BYTES
    ) {
      dataChannels[channelIndex].send(messageHash.buffer as ArrayBuffer);
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

    await deleteDBSendQueue(label, peerId);
  }

  // Check whether channel is a name or a message channel
  const { merkleRootHex } = await decompileChannelMessageLabel(label);
  if (merkleRootHex.length > 0) {
    if (alsoDeleteData) api.dispatch(deleteMessage({ merkleRootHex }));

    // Find out if the message is sent to others
    const c = dataChannels.findIndex((c) => c.label === label);

    // If the message is not sent to anyone then delete it from sending memory —
    // BUT only once the transfer completed (transferComplete, set by the
    // completion path) or the caller asked to drop the data. On an UNEXPECTED
    // mid-transfer disconnect the channel also closes here with no such flag;
    // deleting newChunks then would destroy the resend source and make
    // resume-on-reconnect impossible, so we keep them for the resume path.
    // (transferComplete is an explicit param, not volatile reconcile state, so
    // it can't be raced by sendWithReconcile's clearTransfer.)
    if (c < 0 && (alsoDeleteData || transferComplete))
      await deleteDBNewChunk(merkleRootHex);
  } else if (!signalingServer.isConnected || alsoDeleteData) {
    api.dispatch(
      deleteChannel({
        peerId,
        label,
      }),
    );
  }

  // Find out if the two peers have at least one channel together
  const roomsLen = rooms.length;
  let peerHasChannel = false;
  for (let i = 0; i < roomsLen; i++) {
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
    const peerIndex = peerConnections.findIndex(
      (peer) => peer.withPeerId === peerId,
    );

    if (
      peerIndex > -1 &&
      (peerConnections[peerIndex].connectionState === "failed" ||
        peerConnections[peerIndex].connectionState === "connected")
    ) {
      await api.dispatch(
        webrtcApi.endpoints.disconnectFromPeer.initiate({
          peerId: peerConnections[peerIndex].withPeerId,
        }),
      );
    }
  }

  return { data: undefined };
};

export default webrtcDisconnectFromPeerChannelLabelQuery;
