import { isUUID } from "class-validator";

import { setMessage } from "../../reducers/roomSlice";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type { State } from "../../store";
import type { IRTCDataChannel, RTCChannelMessageParams } from "./interfaces";

export interface RTCChannelMessageParamsExtension
  extends RTCChannelMessageParams {
  dataChannels: IRTCDataChannel[];
}

const webrtcMessageQuery: BaseQueryFn<
  RTCChannelMessageParamsExtension,
  void,
  unknown
> = async ({ message, fromPeerId, label, dataChannels }, api) => {
  return new Promise((resolve, reject) => {
    try {
      if (!isUUID(fromPeerId)) reject({ message: "FromPeerId not a uuidv4" });

      const { keyPair } = api.getState() as State;
      if (keyPair.peerId === fromPeerId) {
        if (label) {
          const channelIndex = dataChannels.findIndex((c) => c.label === label);

          if (channelIndex === -1)
            reject(new Error("No channel with this label"));

          const CHANNELS_LEN = dataChannels.length;
          for (let i = channelIndex; i < CHANNELS_LEN; i++) {
            if (label && dataChannels[i].label !== label) continue;

            dataChannels[i].send(message);

            api.dispatch(
              setMessage({
                id: window.crypto.randomUUID(),
                message,
                fromPeerId,
                // toPeerId: dataChannels[i].withPeerId,
                channelLabel: dataChannels[i].label,
                timestamp: Date.now(),
              }),
            );
          }
        } else {
          const CHANNELS_LEN = dataChannels.length;
          for (let i = 0; i < CHANNELS_LEN; i++) {
            dataChannels[i].send(message);

            api.dispatch(
              setMessage({
                id: window.crypto.randomUUID(),
                message,
                fromPeerId,
                // toPeerId: dataChannels[i].withPeerId,
                channelLabel: dataChannels[i].label,
                timestamp: Date.now(),
              }),
            );
          }
        }
      } else {
        if (!label) reject(new Error("Received a message without a label"));

        api.dispatch(
          setMessage({
            id: window.crypto.randomUUID(),
            message,
            fromPeerId,
            // toPeerId: keyPair.peerId,
            channelLabel: label ?? "",
            timestamp: Date.now(),
          }),
        );
      }

      resolve({ data: undefined });
    } catch (error) {
      reject(error);
    }
  });
};

export default webrtcMessageQuery;
