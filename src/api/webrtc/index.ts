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

import { CHUNK_LEN, PROOF_LEN } from "../../utils/constants";

import cryptoMemory from "../../cryptography/memory";
import { crypto_hash_sha512_BYTES } from "../../cryptography/interfaces";

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
} from "./interfaces";

const peerConnections: IRTCPeerConnection[] = [];
const iceCandidates: IRTCIceCandidate[] = [];
const dataChannels: IRTCDataChannel[] = [];

const encryptionWasmMemory = cryptoMemory.encryptAsymmetricMemory(
  CHUNK_LEN,
  crypto_hash_sha512_BYTES, // additional data is the merkle root
);

const merkleWasmMemory = cryptoMemory.verifyMerkleProofMemory(PROOF_LEN);

const webrtcApi = createApi({
  reducerPath: "webrtcApi",
  baseQuery: webrtcBaseQuery,
  endpoints: (builder) => ({
    connectWithPeer: builder.mutation<void, RTCPeerConnectionParams>({
      query: ({
        peerId,
        peerPublicKey,
        roomId,
        initiator = false,
        rtcConfig = {
          iceServers: [
            {
              urls: ["stun:stun.p2party.com:3478"],
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
      }),
    }),

    setDescription: builder.mutation<void, RTCSetDescriptionParams>({
      queryFn: (args, api, extraOptions) =>
        webrtcSetDescriptionQuery(
          {
            ...args,
            peerConnections,
            iceCandidates,
            dataChannels,
          },
          api,
          extraOptions,
        ),
    }),

    setCandidate: builder.mutation<void, RTCSetCandidateParams>({
      queryFn: (args, api, extraOptions) =>
        webrtcSetIceCandidateQuery(
          { ...args, peerConnections, iceCandidates },
          api,
          extraOptions,
        ),
    }),

    openChannel: builder.mutation<void, RTCOpenChannelParams>({
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

    sendMessage: builder.mutation<void, RTCSendMessageParams>({
      queryFn: (args, api, extraOptions) =>
        webrtcMessageQuery(
          {
            ...args,
            peerConnections,
            dataChannels,
            encryptionWasmMemory,
            merkleWasmMemory,
          },
          api,
          extraOptions,
        ),
    }),

    disconnect: builder.mutation<void, RTCDisconnectParams>({
      queryFn: (args, api, extraOptions) =>
        webrtcDisconnectQuery(
          { ...args, peerConnections, dataChannels },
          api,
          extraOptions,
        ),
    }),

    disconnectFromRoom: builder.mutation<void, RTCDisconnectFromRoomParams>({
      queryFn: (args, api, extraOptions) =>
        webrtcDisconnectRoomQuery(
          { ...args, peerConnections, dataChannels },
          api,
          extraOptions,
        ),
    }),

    disconnectFromAllRooms: builder.mutation<
      void,
      RTCDisconnectFromAllRoomsParams
    >({
      queryFn: (args, api, extraOptions) =>
        webrtcDisconnectAllRoomsQuery(
          { ...args, peerConnections, dataChannels },
          api,
          extraOptions,
        ),
    }),

    disconnectFromPeer: builder.mutation<void, RTCDisconnectFromPeerParams>({
      queryFn: (args, api, extraOptions) =>
        webrtcDisconnectPeerQuery(
          { ...args, peerConnections, dataChannels },
          api,
          extraOptions,
        ),
    }),

    disconnectFromChannelLabel: builder.mutation<
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

    disconnectFromPeerChannelLabel: builder.mutation<
      void,
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
