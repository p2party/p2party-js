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
export declare const setChannel: import("@reduxjs/toolkit").ActionCreatorWithPayload<
    SetChannelArgs,
    "channels2/setChannel"
  >,
  setMessage: import("@reduxjs/toolkit").ActionCreatorWithPayload<
    SetMessageArgs,
    "channels2/setMessage"
  >,
  deleteChannel: import("@reduxjs/toolkit").ActionCreatorWithPayload<
    DeleteChannelArgs,
    "channels2/deleteChannel"
  >,
  deletePeerChannels: import("@reduxjs/toolkit").ActionCreatorWithPayload<
    DeletePeerChannelArgs,
    "channels2/deletePeerChannels"
  >,
  deleteLabelChannels: import("@reduxjs/toolkit").ActionCreatorWithPayload<
    DeleteLabelChannelArgs,
    "channels2/deleteLabelChannels"
  >,
  deleteAllChannels: import("@reduxjs/toolkit").ActionCreatorWithoutPayload<"channels2/deleteAllChannels">;
export declare const peer2Selector: (
  state: RoomState,
) => import("./peers2Slice").Peer[];
declare const _default: import("redux").Reducer<Channel[]>;
export default _default;
//# sourceMappingURL=channels2Slice.d.ts.map
