import { configureStore } from "@reduxjs/toolkit";

import keyPairReducer from "./reducers/keyPairSlice";
import roomReducer from "./reducers/roomSlice";
import isSettingRemoteAnswerPendingReducer from "./reducers/isSettingRemoteAnswerPendingSlice";
import peers2Reducer, {
  setCandidate,
  setDescription,
} from "./reducers/peersSlice";
import channels2Reducer, { setChannel } from "./reducers/channelsSlice";
import signalingServerReducer from "./reducers/signalingServerSlice"; // } // signalingServerActions, //, {

import signalingServerApi from "./api/signalingServerApi";

// import signalingServerMiddleware from "../middleware/signalingServerMiddleware";
import roomListenerMiddleware from "./middleware/roomListenerMiddleware";
import channelsMiddleware from "./middleware/channelsMiddleware";
import peersMiddleware from "./middleware/peersMiddleware";
import keyPairListenerMiddleware from "./middleware/keyPairListenerMiddleware";

export const store = configureStore({
  reducer: {
    keyPair: keyPairReducer,
    room: roomReducer,
    peers: peers2Reducer,
    isSettingRemoteAnswerPending: isSettingRemoteAnswerPendingReducer,
    channels: channels2Reducer,
    signalingServer: signalingServerReducer,
    [signalingServerApi.reducerPath]: signalingServerApi.reducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        ignoredActions: [
          // signalingServerActions.sendMessage.toString(),
          setCandidate.toString(),
          setDescription.toString(),
          setChannel.toString(),
        ],
      },
    })
      .concat([
        signalingServerApi.middleware,
        // signalingServerMiddleware,
        roomListenerMiddleware.middleware,
        keyPairListenerMiddleware.middleware,
        channelsMiddleware,
        peersMiddleware,
      ])
      .concat([]),
});

export type AppDispatch = typeof store.dispatch;
export type RootState = ReturnType<typeof store.getState>;

export const dispatch: AppDispatch = store.dispatch;
