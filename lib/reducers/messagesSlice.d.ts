import type { RoomState } from "../store/room";
export interface Message {
  message: string;
  channel: string;
  fromPeerId: string;
  toPeerId: string;
  timestamp: Date;
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
  peerId: string;
  channel: string;
}
export declare const setMessage: import("@reduxjs/toolkit").ActionCreatorWithPayload<
    SetMessageArgs,
    "messages/setMessage"
  >,
  deleteMessage: import("@reduxjs/toolkit").ActionCreatorWithPayload<
    DeleteMessageArgs,
    "messages/deleteMessage"
  >,
  deletePeerMessages: import("@reduxjs/toolkit").ActionCreatorWithPayload<
    DeletePeerMessagesArgs,
    "messages/deletePeerMessages"
  >,
  deleteChannelMessages: import("@reduxjs/toolkit").ActionCreatorWithPayload<
    DeleteChannelMessagesArgs,
    "messages/deleteChannelMessages"
  >,
  deleteAllMessages: import("@reduxjs/toolkit").ActionCreatorWithoutPayload<"messages/deleteAllMessages">;
export declare const messagesSelector: (state: RoomState) => any;
declare const _default: import("redux").Reducer<Message[]>;
export default _default;
//# sourceMappingURL=messagesSlice.d.ts.map
