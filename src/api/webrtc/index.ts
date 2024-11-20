import { createApi } from "@reduxjs/toolkit/query";

import webrtcBaseQuery from "./baseQuery";
import webrtcSetDescriptionQuery from "./setDescriptionQuery";
import webrtcSetIceCandidateQuery from "./setCandidateQuery";
import webrtcOpenChannelQuery from "./openChannelQuery";
import webrtcMessageQuery from "./messageQuery";
import webrtcDisconnectQuery from "./disconnectQuery";
import webrtcDisconnectRoomQuery from "./disconnectFromRoomQuery";
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
  RTCChannelMessageParams,
  RTCSetDescriptionParams,
  RTCSetCandidateParams,
  RTCOpenChannelParams,
  RTCDisconnectFromRoomParams,
  RTCDisconnectFromPeerParams,
  RTCDisconnectFromChannelLabelParams,
  RTCDisconnectFromPeerChannelLabelParams,
} from "./interfaces";

const peerConnections: IRTCPeerConnection[] = [];
const iceCandidates: IRTCIceCandidate[] = [];
const dataChannels: IRTCDataChannel[] = [];

export const rtcDataChannelMessageLimit = 64 * 1024; // limit from RTCDataChannel is 64kb
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

const decryptionWasmMemory = cryptoMemory.decryptAsymmetricMemory(
  100 * 64 * 1024,
  crypto_hash_sha512_BYTES, // additional data is the merkle root
);

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
        encryptionWasmMemory,
      }),
    }),

    setDescription: builder.query<void, RTCSetDescriptionParams>({
      queryFn: (args, api, extraOptions) =>
        webrtcSetDescriptionQuery(
          {
            ...args,
            peerConnections,
            iceCandidates,
            dataChannels,
            encryptionWasmMemory,
          },
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
          { ...args, peerConnections, dataChannels, encryptionWasmMemory },
          api,
          extraOptions,
        ),
    }),

    message: builder.mutation<void, RTCChannelMessageParams>({
      queryFn: (args, api, extraOptions) =>
        webrtcMessageQuery(
          {
            ...args,
            peerConnections,
            dataChannels,
            encryptionWasmMemory,
            decryptionWasmMemory,
          },
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
