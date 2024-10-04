import { isUUID } from "class-validator";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type { State } from "../../store";
import type {
  IRTCDataChannel,
  IRTCMessage,
  RTCChannelMessageParams,
} from "./interfaces";

export interface RTCChannelMessageParamsExtension
  extends RTCChannelMessageParams {
  dataChannels: IRTCDataChannel[];
  messages: IRTCMessage[];
}

const webrtcMessageQuery: BaseQueryFn<
  RTCChannelMessageParamsExtension,
  void,
  unknown
> = async (
  { message, fromPeerId, toPeerId, label, dataChannels, messages },
  api,
) => {
  return new Promise((resolve, reject) => {
    try {
      if (!isUUID(fromPeerId) || !isUUID(toPeerId))
        reject({ message: "FromPeerId or ToPeerId not a uuidv4" });

      const { keyPair } = api.getState() as State;
      if (keyPair.peerId === fromPeerId) {
        if (label && toPeerId) {
          const channelIndex = dataChannels.findIndex(
            (c) => c.label === label && c.withPeerId === toPeerId,
          );

          if (channelIndex === -1)
            reject(new Error("No channel with this label and peer"));

          dataChannels[channelIndex].send(message);

          messages.push({
            id: window.crypto.randomUUID(),
            message,
            fromPeerId,
            toPeerId,
            channelLabel: label,
            timestamp: new Date(),
          });
        } else if (label || toPeerId) {
          const channelIndex = dataChannels.findIndex(
            (c) => c.label === label || c.withPeerId === toPeerId,
          );

          if (channelIndex === -1)
            reject(new Error("No channel with this label or peer"));

          const CHANNELS_LEN = dataChannels.length;
          for (let i = channelIndex; i < CHANNELS_LEN; i++) {
            if (
              (toPeerId && dataChannels[i].withPeerId !== toPeerId) ||
              (label && dataChannels[i].label !== label)
            )
              continue;

            dataChannels[i].send(message);
            messages.push({
              id: window.crypto.randomUUID(),
              message,
              fromPeerId,
              toPeerId: dataChannels[i].withPeerId,
              channelLabel: dataChannels[i].label,
              timestamp: new Date(),
            });
          }
        } else {
          const CHANNELS_LEN = dataChannels.length;
          for (let i = 0; i < CHANNELS_LEN; i++) {
            dataChannels[i].send(message);
            messages.push({
              id: window.crypto.randomUUID(),
              message,
              fromPeerId,
              toPeerId: dataChannels[i].withPeerId,
              channelLabel: dataChannels[i].label,
              timestamp: new Date(),
            });
          }
        }
      } else if (toPeerId && toPeerId !== keyPair.peerId) {
        reject(new Error("Neither receiver not sender is us"));
      } else {
        if (!label) reject(new Error("Received a message without a label"));

        messages.push({
          id: window.crypto.randomUUID(),
          message,
          fromPeerId,
          toPeerId: keyPair.peerId,
          channelLabel: label ?? "",
          timestamp: new Date(),
        });
      }

      resolve({ data: undefined });
    } catch (error) {
      reject(error);
    }
  });
};

export default webrtcMessageQuery;
