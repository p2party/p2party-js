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
  void,
  unknown
> = async ({ alsoDeleteDB, peerConnections, dataChannels }, api) => {
  const CHANNELS_LEN = dataChannels.length;
  for (let i = 0; i < CHANNELS_LEN; i++) {
    if (dataChannels[i].readyState !== "open") continue;

    dataChannels[i].close();
  }

  const PEERS_LEN = peerConnections.length;
  for (let i = 0; i < PEERS_LEN; i++) {
    await api.dispatch(
      webrtcApi.endpoints.disconnectFromPeer.initiate({
        peerId: peerConnections[i].withPeerId,
      }),
    );
  }

  if (alsoDeleteDB) await deleteDB();

  return { data: undefined };
};

export default webrtcDisconnectQuery;
