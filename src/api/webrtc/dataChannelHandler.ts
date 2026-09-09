import { handleOpenChannel } from "../../handlers/handleOpenChannel";

import type { IRTCDataChannel, IRTCPeerConnection } from "./interfaces";

/**
 * Wires a transport's `ondatachannel` to handleOpenChannel: every inbound
 * channel goes through the same admission as a locally created one, and an
 * inbound `main` becomes the transport's main channel. Shared by the fresh
 * transports built from a roster introduction (connectWithPeer) and from an
 * inbound offer (setDescription), so the two never drift.
 */
export const attachDataChannelHandler = (
  epc: IRTCPeerConnection,
  dataChannels: IRTCDataChannel[],
  api: Parameters<typeof handleOpenChannel>[1],
): void => {
  epc.ondatachannel = async (event: RTCDataChannelEvent) => {
    try {
      const channel = await handleOpenChannel(
        {
          channel: event.channel,
          epc,
          roomId: epc.roomId,
          dataChannels,
          incoming: true,
        },
        api,
      );
      if (channel.label === "main") epc.mainChannel = channel;
    } catch (error) {
      console.error("Rejected incoming DataChannel:", error);
    }
  };
};
