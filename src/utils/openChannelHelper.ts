import webrtcApi from "../api/webrtc";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";
import type {
  IRTCPeerConnection,
  IRTCDataChannel,
  IRTCMessage,
} from "../api/webrtc/interfaces";

export interface OpenChannelHelperParams {
  channel: string | RTCDataChannel;
  epc: IRTCPeerConnection;
  dataChannels: IRTCDataChannel[];
  messages: IRTCMessage[];
}

const openChannelHelper = async (
  { channel, epc, dataChannels, messages }: OpenChannelHelperParams,
  api: BaseQueryApi,
): Promise<IRTCDataChannel> => {
  return new Promise((resolve, reject) => {
    try {
      const { keyPair } = api.getState() as State;

      const dataChannel =
        typeof channel === "string" ? epc.createDataChannel(channel) : channel;
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
        if (typeof e.data === "string" && e.data.length > 0) {
          console.log(e.data);
          api.dispatch(
            webrtcApi.endpoints.message.initiate({
              message: e.data,
              fromPeerId: epc.withPeerId,
              toPeerId: keyPair.peerId,
              label: extChannel.label,
            }),
          );
        }
      };

      extChannel.onopen = () => {
        console.log(
          `Channel with label \"${extChannel.label}\" and client ${epc.withPeerId} is open.`,
        );

        dataChannels.push(extChannel);

        const message = `Connected with ${keyPair.peerId} on channel ${extChannel.label}`;

        extChannel.send(message);

        messages.push({
          id: window.crypto.randomUUID(),
          message,
          fromPeerId: keyPair.peerId,
          toPeerId: extChannel.withPeerId,
          channelLabel: label,
          timestamp: new Date(),
        });
      };

      resolve(extChannel);
    } catch (error) {
      reject(error);
    }
  });
};

export default openChannelHelper;
