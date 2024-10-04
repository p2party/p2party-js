import { configureStore } from "@reduxjs/toolkit";

import keyPairReducer from "./reducers/keyPairSlice";
import roomReducer from "./reducers/roomSlice";
import makingOfferReducer from "./reducers/makingOfferSlice";
import peerRoomsReducer from "./reducers/peerRoomsSlice";
import isSettingRemoteAnswerPendingReducer from "./reducers/isSettingRemoteAnswerPendingSlice";
// import peers2Reducer from "./reducers/peersSlice"; // setDescription, // setCandidate,
// import channels2Reducer from "./reducers/channelsSlice"; // setChannel
import signalingServerReducer from "./reducers/signalingServerSlice"; // } // signalingServerActions, //, {

import signalingServerApi from "./api/signalingServerApi";
import webrtcApi from "./api/webrtc";

import roomListenerMiddleware from "./middleware/roomListenerMiddleware";
import keyPairListenerMiddleware from "./middleware/keyPairListenerMiddleware";

export const store = configureStore({
  reducer: {
    keyPair: keyPairReducer,
    room: roomReducer,
    makingOffer: makingOfferReducer,
    peerRooms: peerRoomsReducer,
    // peers: peers2Reducer,
    isSettingRemoteAnswerPending: isSettingRemoteAnswerPendingReducer,
    // channels: channels2Reducer,
    signalingServer: signalingServerReducer,
    [signalingServerApi.reducerPath]: signalingServerApi.reducer,
    [webrtcApi.reducerPath]: webrtcApi.reducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware().concat([
      signalingServerApi.middleware,
      webrtcApi.middleware,
      roomListenerMiddleware.middleware,
      keyPairListenerMiddleware.middleware,
    ]),
});

export type AppDispatch = typeof store.dispatch;
export type State = ReturnType<typeof store.getState>;

export const dispatch: AppDispatch = store.dispatch;
