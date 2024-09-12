import {
  setChannel,
  setMessage,
  sendMessageToChannel,
  deleteChannel,
  deletePeerChannels,
  deleteLabelChannels,
  deleteAllChannels,
} from "../reducers/channelsSlice";
import { deletePeer, type IRTCPeerConnection } from "../reducers/peersSlice";

import type { Middleware } from "redux";
import type { IRTCDataChannel } from "../reducers/channelsSlice";

const channelsMiddleware: Middleware = (store) => {
  const dataChannels: IRTCDataChannel[] = [];

  const openDataChannel = async (
    channel: string | RTCDataChannel,
    epc: IRTCPeerConnection,
  ) => {
    const label = typeof channel === "string" ? channel : channel.label;
    const dataChannel =
      typeof channel === "string" ? epc.createDataChannel(channel) : channel;
    const extChannel = dataChannel as IRTCDataChannel;
    extChannel.withPeerId = epc.withPeerId;

    extChannel.onopen = () => {
      console.log(
        `Channel with label \"${extChannel.label}\" and client ${epc.withPeerId} is open.`,
      );

      const message = `Connected with ${epc.withPeerId} on channel ${extChannel.label}`;
      extChannel.send(message);

      const { keyPair } = store.getState();

      store.dispatch(
        setMessage({
          message,
          fromPeerId: keyPair.peerId,
          toPeerId: extChannel.withPeerId,
          channel: label,
        }),
      );
    };

    extChannel.onclosing = () => {
      console.log(`Channel with label ${channel} is closing.`);
    };

    extChannel.onclose = async () => {
      console.log(`Channel with label ${channel} has closed.`);

      store.dispatch(
        deleteChannel({
          channel: label,
          peerId: epc.withPeerId,
        }),
      );

      if (channel === "signaling") {
        store.dispatch(deletePeerChannels({ peerId: epc.withPeerId }));
        store.dispatch(deletePeer({ peerId: epc.withPeerId }));
      }
    };

    extChannel.onerror = async (e) => {
      console.error(e);

      store.dispatch(
        deleteChannel({
          channel: label,
          peerId: epc.withPeerId,
        }),
      );
    };

    extChannel.onmessage = (e) => {
      if (typeof e.data === "string" && e.data.length > 0) {
        const { keyPair } = store.getState();
        store.dispatch(
          setMessage({
            message: e.data,
            fromPeerId: epc.withPeerId,
            toPeerId: keyPair.peerId,
            channel: extChannel.label,
          }),
        );
      }
    };

    return extChannel;
  };

  return (next) => async (action) => {
    if (deleteChannel.match(action)) {
      const { peerId, channel } = action.payload;

      const channelIndex = dataChannels.findIndex(
        (c) => c.label === channel && c.withPeerId === peerId,
      );

      if (channelIndex > -1) {
        if (dataChannels[channelIndex].readyState === "open") {
          dataChannels[channelIndex].onopen = null;
          dataChannels[channelIndex].onclose = null;
          dataChannels[channelIndex].onerror = null;
          dataChannels[channelIndex].onclosing = null;
          dataChannels[channelIndex].onmessage = null;
          dataChannels[channelIndex].onbufferedamountlow = null;
          dataChannels[channelIndex].close();
        }
        dataChannels.splice(channelIndex, 1);
      }

      return next(action);
    }

    if (deleteAllChannels.match(action)) {
      const CHANNELS_LEN = dataChannels.length;
      for (let i = 0; i < CHANNELS_LEN; i++) {
        if (dataChannels[i].readyState === "open") {
          dataChannels[i].onopen = null;
          dataChannels[i].onclose = null;
          dataChannels[i].onerror = null;
          dataChannels[i].onclosing = null;
          dataChannels[i].onmessage = null;
          dataChannels[i].onbufferedamountlow = null;
          dataChannels[i].close();
        }

        dataChannels.splice(i, 1);
      }

      return next(action);
    }

    if (deletePeerChannels.match(action)) {
      const { peerId } = action.payload;
      const CHANNELS_LEN = dataChannels.length;
      const channelsClosedIndexes: number[] = [];
      for (let i = 0; i < CHANNELS_LEN; i++) {
        if (dataChannels[i].withPeerId !== peerId) continue;

        dataChannels[i].onopen = null;
        dataChannels[i].onclose = null;
        dataChannels[i].onerror = null;
        dataChannels[i].onclosing = null;
        dataChannels[i].onmessage = null;
        dataChannels[i].onbufferedamountlow = null;
        dataChannels[i].close();

        channelsClosedIndexes.push(i);
      }

      const INDEXES_LEN = channelsClosedIndexes.length;
      for (let i = 0; i < INDEXES_LEN; i++) {
        dataChannels.splice(channelsClosedIndexes[i], 1);
      }

      return next(action);
    }

    if (deleteLabelChannels.match(action)) {
      const { channel } = action.payload;
      const CHANNELS_LEN = dataChannels.length;
      const channelsClosedIndexes: number[] = [];
      for (let i = 0; i < CHANNELS_LEN; i++) {
        if (
          dataChannels[i].label !== channel ||
          dataChannels[i].readyState !== "open"
        )
          continue;

        dataChannels[i].onopen = null;
        dataChannels[i].onclose = null;
        dataChannels[i].onerror = null;
        dataChannels[i].onclosing = null;
        dataChannels[i].onmessage = null;
        dataChannels[i].onbufferedamountlow = null;
        dataChannels[i].close();

        channelsClosedIndexes.push(i);
      }

      const INDEXES_LEN = channelsClosedIndexes.length;
      for (let i = 0; i < INDEXES_LEN; i++) {
        dataChannels.splice(channelsClosedIndexes[i], 1);
      }

      return next(action);
    }

    if (setChannel.match(action)) {
      const { channel, label, epc } = action.payload;

      const channelIndex = dataChannels.findIndex((c) => {
        c.label === label && c.withPeerId === epc.withPeerId;
      });

      if (channelIndex > -1) return next(action);

      const dataChannel = await openDataChannel(channel, epc);

      dataChannels.push(dataChannel);

      return next(action);
    }

    if (setMessage.match(action)) {
      const { channel, toPeerId, message } = action.payload;

      const channelIndex = dataChannels.findIndex(
        (c) => c.label === channel && c.withPeerId === toPeerId,
      );

      if (channelIndex > -1) {
        dataChannels[channelIndex].send(message);
      }

      return next(action);
    }

    if (sendMessageToChannel.match(action)) {
      const { message, channel } = action.payload;

      let channelIndex = dataChannels.findIndex((c) => c.label === channel);
      if (channelIndex === -1) return next(action); // TODO open channel and send

      while (channelIndex > -1) {
        dataChannels[channelIndex].send(message);
        dataChannels.splice(channelIndex, 1);
        channelIndex = dataChannels.findIndex((c) => {
          c.label === channel;
        });
      }

      return next(action);
    }

    return next(action);
  };
};

export default channelsMiddleware;
