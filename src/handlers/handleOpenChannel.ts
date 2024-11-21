import { handleSendMessage } from "./handleSendMessage";

import webrtcApi from "../api/webrtc";

import { setChannel } from "../reducers/roomSlice";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";
import type {
  IRTCPeerConnection,
  IRTCDataChannel,
} from "../api/webrtc/interfaces";
import type { LibCrypto } from "../cryptography/libcrypto";

export interface OpenChannelHelperParams {
  channel: string | RTCDataChannel;
  epc: IRTCPeerConnection;
  dataChannels: IRTCDataChannel[];
  encryptionModule: LibCrypto;
}

export const handleOpenChannel = async (
  { channel, epc, dataChannels, encryptionModule }: OpenChannelHelperParams,
  api: BaseQueryApi,
): Promise<IRTCDataChannel> => {
  return new Promise((resolve, reject) => {
    try {
      const { keyPair } = api.getState() as State;

      const dataChannel =
        typeof channel === "string"
          ? epc.createDataChannel(channel) // , {
          : //   ordered: true,
            //   maxRetransmits: 0,
            // })
            channel;
      dataChannel.bufferedAmountLowThreshold = 64 * 1024; // 64kb
      dataChannel.binaryType = "arraybuffer";
      const label = typeof channel === "string" ? channel : channel.label;
      const extChannel = dataChannel as IRTCDataChannel;
      extChannel.withPeerId = epc.withPeerId;

      extChannel.onclosing = () => {
        console.log(`Channel with label ${extChannel.label} is closing.`);
      };

      extChannel.onclose = () => {
        console.log(`Channel with label ${extChannel.label} has closed.`);

        api.dispatch(
          webrtcApi.endpoints.disconnectFromPeerChannelLabel.initiate({
            peerId: epc.withPeerId,
            label: extChannel.label,
          }),
        );
      };

      extChannel.onerror = (e) => {
        console.error(e);

        api.dispatch(
          webrtcApi.endpoints.disconnectFromPeerChannelLabel.initiate({
            peerId: epc.withPeerId,
            label: extChannel.label,
          }),
        );
      };

      extChannel.onmessage = (e) => {
        api.dispatch(
          webrtcApi.endpoints.message.initiate({
            data: e.data,
            fromPeerId: epc.withPeerId,
            label: extChannel.label,
          }),
        );
      };

      extChannel.onopen = async () => {
        console.log(
          `Channel with label \"${extChannel.label}\" and client ${epc.withPeerId} is open.`,
        );

        dataChannels.push(extChannel);

        api.dispatch(setChannel({ label, peerId: extChannel.withPeerId }));

        const msg = `Connected with ${keyPair.peerId} on channel ${extChannel.label}`;

        await handleSendMessage(
          msg,
          [epc],
          [extChannel],
          encryptionModule,
          api,
          label,
        );
      };

      resolve(extChannel);
    } catch (error) {
      reject(error);
    }
  });
};
