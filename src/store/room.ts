import { configureStore } from "@reduxjs/toolkit";

import keyPairReducer from "../reducers/keyPairSlice";
import roomsReducer from "../reducers/roomsSlice";
import isSettingRemoteAnswerPendingReducer from "../reducers/isSettingRemoteAnswerPendingSlice";
import peers2Reducer from "../reducers/peersSlice";
import channels2Reducer from "../reducers/channelsSlice";
import signalingServerReducer from "../reducers/signalingServerSlice";

import signalingServerMiddleware from "../middleware/signalingServerMiddleware";
import channelsMiddleware from "../middleware/channelsMiddleware";
import peersMiddleware from "../middleware/peersMiddleware";
import roomsMiddleware from "../middleware/roomsMiddleware";

export const room = configureStore({
  reducer: {
    keyPair: keyPairReducer,
    rooms: roomsReducer,
    peers: peers2Reducer,
    isSettingRemoteAnswerPending: isSettingRemoteAnswerPendingReducer,
    channels: channels2Reducer,
    signalingServer: signalingServerReducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware().prepend([
      signalingServerMiddleware,
      channelsMiddleware,
      peersMiddleware,
      roomsMiddleware,
    ]),
});

export type AppDispatch = typeof room.dispatch;
export type RoomState = ReturnType<typeof room.getState>;
