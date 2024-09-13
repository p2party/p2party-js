import { configureStore } from "@reduxjs/toolkit";

import keyPairReducer from "../reducers/keyPairSlice";
import roomsReducer from "../reducers/roomsSlice";
import isSettingRemoteAnswerPendingReducer from "../reducers/isSettingRemoteAnswerPendingSlice";
import peers2Reducer, {
  setCandidate,
  setDescription,
} from "../reducers/peersSlice";
import channels2Reducer, { setChannel } from "../reducers/channelsSlice";
import signalingServerReducer, {
  signalingServerActions,
} from "../reducers/signalingServerSlice";

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
    getDefaultMiddleware({
      serializableCheck: {
        ignoredActions: [
          signalingServerActions.sendMessage.toString(),
          setCandidate.toString(),
          setDescription.toString(),
          setChannel.toString(),
        ],
      },
    }).prepend([
      signalingServerMiddleware,
      channelsMiddleware,
      peersMiddleware,
      roomsMiddleware,
    ]),
});

export type AppDispatch = typeof room.dispatch;
export type RoomState = ReturnType<typeof room.getState>;
