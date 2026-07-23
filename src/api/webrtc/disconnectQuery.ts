import webrtcApi from ".";

import { deleteDB } from "../../db/api";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
  RTCDisconnectParams,
} from "./interfaces";

export interface RTCDisconnectParamsExtension extends RTCDisconnectParams {
  peerConnections: IRTCPeerConnection[];
  dataChannels: IRTCDataChannel[];
}

const webrtcDisconnectQuery: BaseQueryFn<
  RTCDisconnectParamsExtension,
  undefined
> = async ({ alsoDeleteDB, peerConnections, dataChannels }, api) => {
  for (let i = dataChannels.length - 1; i >= 0; i--) {
    const channel = dataChannels[i];
    channel.releaseProtocolResources?.();
    channel.onopen = null;
    channel.onclose = null;
    channel.onerror = null;
    channel.onclosing = null;
    channel.onmessage = null;
    channel.onbufferedamountlow = null;
    if (channel.readyState !== "closed") channel.close();
    dataChannels.splice(i, 1);
  }

  const peerIds = [
    ...new Set(peerConnections.map((connection) => connection.withPeerId)),
  ];
  for (const peerId of peerIds) {
    await api.dispatch(
      webrtcApi.endpoints.disconnectFromPeer.initiate({
        peerId,
      }),
    );
  }

  if (alsoDeleteDB) await deleteDB();

  return { data: undefined };
};

export default webrtcDisconnectQuery;
