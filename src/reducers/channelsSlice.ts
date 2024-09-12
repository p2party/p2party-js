import { createSlice } from "@reduxjs/toolkit";

import type { PayloadAction } from "@reduxjs/toolkit";
import type { RoomState } from "../store/room";
import type { IRTCPeerConnection } from "./peersSlice";

export interface IRTCDataChannel extends RTCDataChannel {
  withPeerId: string;
  roomId: string;
}

export interface SetChannelArgs {
  label: string;
  channel: string | RTCDataChannel;
  roomId: string;
  // withPeerId: string;
  epc: IRTCPeerConnection;
}

export interface DeleteLabelChannelArgs {
  channel: string;
}

export interface DeleteChannelArgs extends DeleteLabelChannelArgs {
  peerId: string;
}

export interface DeletePeerChannelArgs {
  peerId: string;
}

export interface SetMessageArgs {
  message: string;
  fromPeerId: string;
  toPeerId: string;
  channel: string;
}

export interface SendMessageToChannelArgs {
  message: string;
  fromPeerId: string; // our
  channel: string;
}

export interface DeleteChannelMessagesArgs {
  channel: string;
}

export interface DeletePeerMessagesArgs {
  peerId: string;
}

export interface DeleteMessageArgs {
  messageId: string;
  peerId: string;
  channel: string;
}

export interface Message {
  id: string;
  message: string;
  fromPeerId: string;
  toPeerId: string;
  timestamp: Date;
}

export interface Channel {
  roomId: string;
  label: string;
  withPeerId: string;
  messages: Message[];
}

const initialState: Channel[] = [];

const channelsSlice = createSlice({
  name: "channels",
  initialState,
  reducers: {
    setChannel: (state, action: PayloadAction<SetChannelArgs>) => {
      const { label, roomId, epc } = action.payload;
      const channelIndex = state.findIndex(
        (c) => c.withPeerId === epc.withPeerId && c.label === label,
      );

      if (channelIndex === -1) {
        state.push({
          // extChannel
          roomId,
          label,
          withPeerId: epc.withPeerId,
          messages: [] as Message[],
        });
      } else {
        state.splice(
          channelIndex,
          1,
          Object.assign(state[channelIndex], {
            roomId,
            label,
            withPeerId: epc.withPeerId,
          }),
        );
      }

      return state;
    },

    setMessage: (state, action: PayloadAction<SetMessageArgs>) => {
      const { message, fromPeerId, toPeerId, channel } = action.payload;
      const channelIndex = state.findIndex(
        (c) =>
          c.label === channel &&
          (c.withPeerId === fromPeerId || c.withPeerId === toPeerId),
      );
      if (channelIndex === -1) return state;

      const messageIndex = state[channelIndex].messages.findIndex(
        (msg) =>
          msg.message === message &&
          msg.fromPeerId === fromPeerId &&
          msg.toPeerId === toPeerId,
      );

      const newMessage: Message =
        messageIndex === -1
          ? {
              id: window.crypto.randomUUID(),
              fromPeerId,
              toPeerId,
              timestamp: new Date(),
              message,
            }
          : Object.assign(state[channelIndex].messages[messageIndex], {
              timestamp: new Date(),
            });

      if (messageIndex === -1) {
        state[channelIndex].messages.push(newMessage);
      } else {
        state[channelIndex].messages[messageIndex] = Object.assign(
          state[channelIndex].messages[messageIndex],
          newMessage,
        );
      }

      return state;
    },

    sendMessageToChannel: (
      state,
      action: PayloadAction<SendMessageToChannelArgs>,
    ) => {
      const { message, fromPeerId, channel } = action.payload;
      let channelIndex = state.findIndex((c) => c.label === channel);
      if (channelIndex === -1) return state;

      while (channelIndex > -1) {
        state[channelIndex].messages.push({
          id: window.crypto.randomUUID(),
          fromPeerId: fromPeerId,
          toPeerId: state[channelIndex].withPeerId,
          timestamp: new Date(),
          message,
        });

        channelIndex = state.findIndex((c) => {
          c.label === channel;
        });
      }

      return state;
    },

    deletePeerChannels: (
      state,
      action: PayloadAction<DeletePeerChannelArgs>,
    ) => {
      const { peerId } = action.payload;
      const CHANNELS_LEN = state.length;
      const channelsClosedIndexes: number[] = [];
      for (let i = 0; i < CHANNELS_LEN; i++) {
        if (state[i].withPeerId !== peerId) continue;

        channelsClosedIndexes.push(i);
      }

      const INDEXES_LEN = channelsClosedIndexes.length;
      for (let i = 0; i < INDEXES_LEN; i++) {
        state.splice(channelsClosedIndexes[i], 1);
      }

      return state;
    },

    deleteLabelChannels: (
      state,
      action: PayloadAction<DeleteLabelChannelArgs>,
    ) => {
      const { channel } = action.payload;
      const CHANNELS_LEN = state.length;
      const channelsClosedIndexes: number[] = [];
      for (let i = 0; i < CHANNELS_LEN; i++) {
        if (state[i].label !== channel) continue;

        channelsClosedIndexes.push(i);
      }

      const INDEXES_LEN = channelsClosedIndexes.length;
      for (let i = 0; i < INDEXES_LEN; i++) {
        state.splice(channelsClosedIndexes[i], 1);
      }

      return state;
    },

    deleteChannel: (state, action: PayloadAction<DeleteChannelArgs>) => {
      const { channel, peerId } = action.payload;

      const channelIndex = state.findIndex(
        (c) => c.label === channel && c.withPeerId === peerId,
      );
      if (channelIndex > -1) {
        state.splice(channelIndex, 1);
      }

      return state;
    },

    deleteAllChannels: (_state) => {
      return [];
    },

    deleteMessage: (state, action: PayloadAction<DeleteMessageArgs>) => {
      const { channel, peerId, messageId } = action.payload;

      const channelIndex = state.findIndex(
        (c) => c.label === channel && c.withPeerId === peerId,
      );
      const messageIndex = state[channelIndex].messages.findIndex(
        (msg) => msg.id === messageId,
      );
      if (messageIndex > -1) {
        state[channelIndex].messages.splice(messageIndex, 1);
      }

      return state;
    },

    deleteChannelMessages: (
      state,
      action: PayloadAction<DeleteChannelMessagesArgs>,
    ) => {
      const { channel } = action.payload;

      const channelIndex = state.findIndex((c) => c.label === channel);
      if (channelIndex > -1) {
        state[channelIndex].messages = [];
      }

      return state;
    },

    deletePeerMessages: (
      state,
      action: PayloadAction<DeletePeerMessagesArgs>,
    ) => {
      const { peerId } = action.payload;

      let channelIndex = state.findIndex((c) => {
        c.withPeerId === peerId;
      });
      while (channelIndex > -1) {
        state.splice(channelIndex, 1);

        channelIndex = state.findIndex((c) => {
          c.withPeerId === peerId;
        });
      }

      return state;
    },

    deleteAllMessages: () => {
      return [];
    },
  },
});

export const {
  setChannel,
  setMessage,
  sendMessageToChannel,
  deleteChannel,
  deletePeerChannels,
  deleteLabelChannels,
  deleteAllChannels,
} = channelsSlice.actions;
export const channelsSelector = (state: RoomState) => state.channels;
export default channelsSlice.reducer;
