import type { RoomState } from "./store/room";
import type { DescriptionSendArgs, CandidateSendArgs } from "./utils/interfaces";
import type { Room } from "./reducers/roomsSlice";
import type { Peer } from "./reducers/peersSlice";
import type { Channel } from "./reducers/channelsSlice";
import type { Message } from "./reducers/channelsSlice";
declare const _default: {
    room: import("@reduxjs/toolkit").EnhancedStore<{
        keyPair: import("./reducers/keyPairSlice").KeyPair;
        rooms: Room[];
        peers: Peer[];
        isSettingRemoteAnswerPending: boolean;
        channels: Channel[];
        signalingServer: import("./reducers/signalingServerSlice").SignalingState;
    }, import("redux").UnknownAction, import("@reduxjs/toolkit").Tuple<[import("redux").StoreEnhancer<{
        dispatch: {};
    }>, import("redux").StoreEnhancer]>>;
    signalingServerSelector: (state: RoomState) => import("./reducers/signalingServerSlice").SignalingState;
    peersSelector: (state: RoomState) => Peer[];
    roomsSelector: (state: RoomState) => Room[];
    keyPairSelector: (state: RoomState) => import("./reducers/keyPairSlice").KeyPair;
    channelsSelector: (state: RoomState) => Channel[];
    connectToSignalingServer: (signalingServerUrl?: string) => Promise<void>;
    connectToRoom: (roomUrl: string) => void;
    connectToRoomPeers: (roomUrl: string, httpServerUrl?: string, rtcConfig?: RTCConfiguration) => Promise<void>;
    disconnectFromSignalingServer: () => Promise<void>;
    disconnectFromRoom: (roomId: string, _deleteMessages?: boolean) => Promise<void>;
    openChannel: (label: string, roomId: string, withPeerIds?: string[]) => Promise<void>;
    sendMessage: (message: string, toChannel: string) => Promise<void>;
};
export default _default;
export type { DescriptionSendArgs, CandidateSendArgs, RoomState, Room, Channel, Peer, Message, };
//# sourceMappingURL=index.d.ts.map