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

import cryptoMemory from "../../cryptography/memory";
import {
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
  crypto_box_poly1305_AUTHTAGBYTES,
  crypto_hash_sha512_BYTES,
} from "../../cryptography/interfaces";

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

export const rtcDataChannelMessageLimit = 64 * 1024;
export const messageLen =
  rtcDataChannelMessageLimit -
  crypto_hash_sha512_BYTES - // merkle root
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES - // nonce
  crypto_box_poly1305_AUTHTAGBYTES; // auth tag
export const encryptedLen =
  rtcDataChannelMessageLimit - crypto_hash_sha512_BYTES; // merkle root

const encryptionWasmMemory = cryptoMemory.encryptAsymmetricMemory(
  messageLen,
  crypto_hash_sha512_BYTES, // additional data is the merkle root
);

const PROOF_LEN = 4 * 48 * (crypto_hash_sha512_BYTES + 1);
const merkleWasmMemory = cryptoMemory.verifyMerkleProofMemory(PROOF_LEN);

const receiveMessageWasmMemory = cryptoMemory.getReceiveMessageMemory();

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
              urls: [
                "stun:stun.p2party.com:3478",
                // "stun:stun.l.google.com:19302",
                // "stun:stun1.l.google.com:19302",
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
        receiveMessageWasmMemory,
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
            receiveMessageWasmMemory,
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
            receiveMessageWasmMemory,
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
            receiveMessageWasmMemory,
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
