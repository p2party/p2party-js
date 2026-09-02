import { createApi } from "@reduxjs/toolkit/query";

import webrtcBaseQuery from "./baseQuery";
import webrtcSetDescriptionQuery from "./setDescriptionQuery";
import webrtcSetIceCandidateQuery from "./setCandidateQuery";
import webrtcOpenChannelQuery from "./openChannelQuery";
import webrtcMessageQuery from "./sendMessageQuery";
import webrtcDisconnectQuery from "./disconnectQuery";
import webrtcDisconnectRoomQuery from "./disconnectFromRoomQuery";
import webrtcDisconnectAllRoomsQuery from "./disconnectFromAllRoomsQuery";
import webrtcDisconnectPeerQuery from "./disconnectFromPeerQuery";
import webrtcDisconnectFromChannelLabelQuery from "./disconnectFromChannelLabelQuery";
import webrtcDisconnectFromPeerChannelLabelQuery from "./disconnectFromPeerChannelLabelQuery";
import { applyRoomIceConfiguration } from "./applyIceConfiguration";

import type {
  IRTCPeerConnection,
  IRTCIceCandidate,
  IRTCDataChannel,
  RTCPeerConnectionParams,
  RTCSendMessageParams,
  RTCSetDescriptionParams,
  RTCSetCandidateParams,
  RTCOpenChannelParams,
  RTCDisconnectFromRoomParams,
  RTCDisconnectFromAllRoomsParams,
  RTCDisconnectFromPeerParams,
  RTCDisconnectFromChannelLabelParams,
  RTCDisconnectFromPeerChannelLabelParams,
  RTCDisconnectParams,
  RTCApplyRoomConfigurationParams,
  DisconnectPeerTransport,
} from "./interfaces";
import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { SendMessageResult } from "../../handlers/handleSendMessage";

const peerConnections: IRTCPeerConnection[] = [];
const iceCandidates: IRTCIceCandidate[] = [];
const dataChannels: IRTCDataChannel[] = [];

const disconnectPeerThroughApi = (
  api: Pick<BaseQueryApi, "dispatch">,
): DisconnectPeerTransport => {
  return async (params) => {
    await api
      .dispatch(webrtcApi.endpoints.disconnectFromPeer.initiate(params))
      .unwrap();
  };
};

const webrtcApi = createApi({
  reducerPath: "webrtcApi",
  baseQuery: webrtcBaseQuery,
  endpoints: (builder) => ({
    connectWithPeer: builder.mutation<undefined, RTCPeerConnectionParams>({
      query: ({
        peerId,
        peerPublicKey,
        roomId,
        rtcConfig = {
          iceServers: [
            {
              // Use single STUN URL - multiple STUN servers slow down ICE gathering
              urls: "stun:stun.p2party.com:3478",
            },
          ],
          // Pre-allocate ICE candidates for faster connection setup
          iceCandidatePoolSize: 2,
        },
      }) => ({
        peerId,
        peerPublicKey,
        roomId,
        rtcConfig,
        peerConnections,
        dataChannels,
      }),
    }),

    setDescription: builder.mutation<undefined, RTCSetDescriptionParams>({
      queryFn: (args, api, extraOptions) =>
        webrtcSetDescriptionQuery(
          {
            ...args,
            peerConnections,
            iceCandidates,
            dataChannels,
            disconnectPeer: disconnectPeerThroughApi(api),
          },
          api,
          extraOptions,
        ),
    }),

    setCandidate: builder.mutation<undefined, RTCSetCandidateParams>({
      queryFn: (args, api, extraOptions) =>
        webrtcSetIceCandidateQuery(
          { ...args, peerConnections, iceCandidates },
          api,
          extraOptions,
        ),
    }),

    applyRoomConfiguration: builder.mutation<
      undefined,
      RTCApplyRoomConfigurationParams
    >({
      queryFn: ({
        roomId,
        rtcConfig,
        restartIce = false,
        failurePolicy = "rollback",
      }) => {
        applyRoomIceConfiguration(
          peerConnections,
          roomId,
          rtcConfig,
          restartIce,
          failurePolicy,
        );
        return { data: undefined };
      },
    }),

    openChannel: builder.mutation<undefined, RTCOpenChannelParams>({
      queryFn: (args, api, extraOptions) =>
        webrtcOpenChannelQuery(
          {
            ...args,
            peerConnections,
            dataChannels,
          },
          api,
          extraOptions,
        ),
    }),

    sendMessage: builder.mutation<
      SendMessageResult | undefined,
      RTCSendMessageParams
    >({
      queryFn: (args, api, extraOptions) =>
        webrtcMessageQuery(
          {
            ...args,
            peerConnections,
            dataChannels,
          },
          api,
          extraOptions,
        ),
    }),

    disconnect: builder.mutation<undefined, RTCDisconnectParams>({
      queryFn: (args, api, extraOptions) =>
        webrtcDisconnectQuery(
          {
            ...args,
            peerConnections,
            dataChannels,
            disconnectPeer: disconnectPeerThroughApi(api),
          },
          api,
          extraOptions,
        ),
    }),

    disconnectFromRoom: builder.mutation<
      undefined,
      RTCDisconnectFromRoomParams
    >({
      queryFn: (args, api, extraOptions) =>
        webrtcDisconnectRoomQuery(
          {
            ...args,
            peerConnections,
            dataChannels,
            disconnectPeer: disconnectPeerThroughApi(api),
          },
          api,
          extraOptions,
        ),
    }),

    disconnectFromAllRooms: builder.mutation<
      undefined,
      RTCDisconnectFromAllRoomsParams
    >({
      queryFn: (args, api, extraOptions) =>
        webrtcDisconnectAllRoomsQuery(
          {
            ...args,
            peerConnections,
            dataChannels,
            disconnectPeer: disconnectPeerThroughApi(api),
          },
          api,
          extraOptions,
        ),
    }),

    disconnectFromPeer: builder.mutation<
      undefined,
      RTCDisconnectFromPeerParams
    >({
      queryFn: (args, api, extraOptions) =>
        webrtcDisconnectPeerQuery(
          { ...args, peerConnections, dataChannels, iceCandidates },
          api,
          extraOptions,
        ),
    }),

    disconnectFromChannelLabel: builder.mutation<
      undefined,
      RTCDisconnectFromChannelLabelParams
    >({
      queryFn: (args, api, extraOptions) =>
        webrtcDisconnectFromChannelLabelQuery(
          { ...args, dataChannels },
          api,
          extraOptions,
        ),
    }),

    disconnectFromPeerChannelLabel: builder.mutation<
      undefined,
      RTCDisconnectFromPeerChannelLabelParams
    >({
      queryFn: (args, api, extraOptions) =>
        webrtcDisconnectFromPeerChannelLabelQuery(
          { ...args, peerConnections, dataChannels },
          api,
          extraOptions,
        ),
    }),
  }),
});

export default webrtcApi;
