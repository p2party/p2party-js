export declare const room: import("@reduxjs/toolkit").EnhancedStore<{
    keyPair: import("../reducers/keyPairSlice").KeyPair;
    rooms: import("../reducers/roomsSlice").Room[];
    peers: import("../reducers/peersSlice").Peer[];
    isSettingRemoteAnswerPending: boolean;
    channels: import("../reducers/channelsSlice").Channel[];
    signalingServer: import("../reducers/signalingServerSlice").SignalingState;
}, import("redux").UnknownAction, import("@reduxjs/toolkit").Tuple<[import("redux").StoreEnhancer<{
    dispatch: {};
}>, import("redux").StoreEnhancer]>>;
export type AppDispatch = typeof room.dispatch;
export type RoomState = ReturnType<typeof room.getState>;
//# sourceMappingURL=room.d.ts.map