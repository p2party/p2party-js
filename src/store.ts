import { configureStore } from "@reduxjs/toolkit";

import keyPairReducer from "./reducers/keyPairSlice";
import roomReducer from "./reducers/roomSlice";
import makingOfferReducer from "./reducers/makingOfferSlice";
import signalingServerReducer from "./reducers/signalingServerSlice";

import signalingServerApi from "./api/signalingServerApi";
import webrtcApi from "./api/webrtc";

import roomListenerMiddleware from "./middleware/roomListenerMiddleware";
import keyPairListenerMiddleware from "./middleware/keyPairListenerMiddleware";

export const store = configureStore({
  reducer: {
    keyPair: keyPairReducer,
    room: roomReducer,
    makingOffer: makingOfferReducer,
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
