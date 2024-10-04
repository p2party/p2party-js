import { createApi } from "@reduxjs/toolkit/query";

import webrtcBaseQuery from "./baseQuery";
import webrtcSetDescriptionQuery from "./setDescriptionQuery";
import webrtcSetIceCandidateQuery from "./setCandidateQuery";
import webrtcOpenChannelQuery from "./openChannelQuery";
import webrtcMessageQuery from "./messageQuery";
import webrtcGetInfoQuery from "./getInfoQuery";
import webrtcDisconnectQuery from "./disconnectQuery";
import webrtcDisconnectRoomQuery from "./disconnectFromRoomQuery";
import webrtcDisconnectPeerQuery from "./disconnectFromPeerQuery";
import webrtcDisconnectFromChannelLabelQuery from "./disconnectFromChannelLabelQuery";
import webrtcDisconnectFromPeerChannelLabelQuery from "./disconnectFromPeerChannelLabelQuery";

import type {
  IRTCPeerConnection,
  IRTCIceCandidate,
  IRTCDataChannel,
  IRTCMessage,
  RTCPeerConnectionParams,
  RTCChannelMessageParams,
  RTCSetDescriptionParams,
  RTCSetCandidateParams,
  RTCOpenChannelParams,
  RoomData,
  RTCRoomInfoParams,
  RTCDisconnectFromRoomParams,
  RTCDisconnectFromPeerParams,
  RTCDisconnectFromChannelLabelParams,
  RTCDisconnectFromPeerChannelLabelParams,
} from "./interfaces";

const peerConnections: IRTCPeerConnection[] = [];
const iceCandidates: IRTCIceCandidate[] = [];
const dataChannels: IRTCDataChannel[] = [];
const messages: IRTCMessage[] = [];

const webrtcApi = createApi({
  reducerPath: "webrtcApi",
  baseQuery: webrtcBaseQuery,
  endpoints: (builder) => ({
    connectWithPeer: builder.query<void, RTCPeerConnectionParams>({
      query: ({
        peerId,
        peerPublicKey,
        roomId,
        initiator = true,
        rtcConfig = {
          iceServers: [
            {
              urls: [
                "stun:stun.l.google.com:19302",
                "stun:stun1.l.google.com:19302",
              ],
            },
          ],
        },
      }) => ({
        peerId,
        peerPublicKey,
        roomId,
        initiator,
        rtcConfig,
        peerConnections,
        dataChannels,
        messages,
      }),
    }),

    setDescription: builder.query<void, RTCSetDescriptionParams>({
      queryFn: (args, api, extraOptions) =>
        webrtcSetDescriptionQuery(
          { ...args, peerConnections, iceCandidates, dataChannels, messages },
          api,
          extraOptions,
        ),
    }),

    setCandidate: builder.query<void, RTCSetCandidateParams>({
      queryFn: (args, api, extraOptions) =>
        webrtcSetIceCandidateQuery(
          { ...args, peerConnections, iceCandidates },
          api,
          extraOptions,
        ),
    }),

    openChannel: builder.query<void, RTCOpenChannelParams>({
      queryFn: (args, api, extraOptions) =>
        webrtcOpenChannelQuery(
          { ...args, peerConnections, dataChannels, messages },
          api,
          extraOptions,
        ),
    }),

    message: builder.mutation<void, RTCChannelMessageParams>({
      queryFn: (args, api, extraOptions) =>
        webrtcMessageQuery(
          { ...args, dataChannels, messages },
          api,
          extraOptions,
        ),
    }),

    getRoomInfo: builder.mutation<RoomData, RTCRoomInfoParams>({
      queryFn: (args, api, extraOptions) =>
        webrtcGetInfoQuery(
          { ...args, peerConnections, dataChannels, messages },
          api,
          extraOptions,
        ),
    }),

    disconnect: builder.query<void, void>({
      queryFn: (_, api, extraOptions) =>
        webrtcDisconnectQuery(
          { peerConnections, dataChannels },
          api,
          extraOptions,
        ),
    }),

    disconnectFromRoom: builder.query<void, RTCDisconnectFromRoomParams>({
      queryFn: (args, api, extraOptions) =>
        webrtcDisconnectRoomQuery(
          { ...args, peerConnections, dataChannels },
          api,
          extraOptions,
        ),
    }),

    disconnectFromPeer: builder.query<void, RTCDisconnectFromPeerParams>({
      queryFn: (args, api, extraOptions) =>
        webrtcDisconnectPeerQuery(
          { ...args, peerConnections, dataChannels },
          api,
          extraOptions,
        ),
    }),

    disconnectFromChannelLabel: builder.query<
      void,
      RTCDisconnectFromChannelLabelParams
    >({
      queryFn: (args, api, extraOptions) =>
        webrtcDisconnectFromChannelLabelQuery(
          { ...args, dataChannels },
          api,
          extraOptions,
        ),
    }),

    disconnectFromPeerChannelLabel: builder.query<
      void,
      RTCDisconnectFromPeerChannelLabelParams
    >({
      queryFn: (args, api, extraOptions) =>
        webrtcDisconnectFromPeerChannelLabelQuery(
          { ...args, dataChannels },
          api,
          extraOptions,
        ),
    }),
  }),
});

export default webrtcApi;
