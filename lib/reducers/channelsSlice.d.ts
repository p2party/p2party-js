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
export interface SendMessageToChannelArgs {
    message: string;
    fromPeerId: string;
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
export declare const setChannel: import("@reduxjs/toolkit").ActionCreatorWithPayload<SetChannelArgs, "channels/setChannel">, setMessage: import("@reduxjs/toolkit").ActionCreatorWithPayload<SetMessageArgs, "channels/setMessage">, sendMessageToChannel: import("@reduxjs/toolkit").ActionCreatorWithPayload<SendMessageToChannelArgs, "channels/sendMessageToChannel">, deleteChannel: import("@reduxjs/toolkit").ActionCreatorWithPayload<DeleteChannelArgs, "channels/deleteChannel">, deletePeerChannels: import("@reduxjs/toolkit").ActionCreatorWithPayload<DeletePeerChannelArgs, "channels/deletePeerChannels">, deleteLabelChannels: import("@reduxjs/toolkit").ActionCreatorWithPayload<DeleteLabelChannelArgs, "channels/deleteLabelChannels">, deleteAllChannels: import("@reduxjs/toolkit").ActionCreatorWithoutPayload<"channels/deleteAllChannels">;
export declare const channelsSelector: (state: RoomState) => Channel[];
declare const _default: import("redux").Reducer<Channel[]>;
export default _default;
//# sourceMappingURL=channelsSlice.d.ts.map