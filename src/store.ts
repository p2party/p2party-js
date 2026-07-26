import { configureStore } from "@reduxjs/toolkit";

import commonStateReducer from "./reducers/commonSlice";
import keyPairReducer from "./reducers/keyPairSlice";
import roomReducer from "./reducers/roomSlice";
import signalingServerReducer from "./reducers/signalingServerSlice";

import signalingServerApi from "./api/signalingServerApi";
import webrtcApi from "./api/webrtc";

import roomListenerMiddleware from "./middleware/roomListenerMiddleware";
import keyPairListenerMiddleware from "./middleware/keyPairListenerMiddleware";

export const store = configureStore({
  reducer: {
    commonState: commonStateReducer,
    keyPair: keyPairReducer,
    rooms: roomReducer,
    signalingServer: signalingServerReducer,
    [signalingServerApi.reducerPath]: signalingServerApi.reducer,
    [webrtcApi.reducerPath]: webrtcApi.reducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      // sendMessage returns its MessageDeliveryError rather than throwing it,
      // because a thrown queryFn error is serialized to a plain object and the
      // documented `error instanceof MessageDeliveryError` check can never be
      // true. Keeping the instance is the point, and an Error instance is by
      // definition not serializable, so RTK Query's own cache entries for
      // these endpoints are exempt from the check.
      //
      // Scoped to the two API slices: application state stays checked, so a
      // genuine non-serializable value in a room or key-pair reducer is still
      // reported.
      serializableCheck: {
        ignoredPaths: [
          `${webrtcApi.reducerPath}.mutations`,
          `${webrtcApi.reducerPath}.queries`,
          `${signalingServerApi.reducerPath}.mutations`,
          `${signalingServerApi.reducerPath}.queries`,
        ],
        // RTK Query echoes the mutation's arguments back on every
        // pending/fulfilled action, and those arguments are live WebRTC
        // objects: an RTCDataChannel for a send, an RTCIceCandidate for a
        // signal. They are handles, not data, and there is nothing to
        // serialize about them.
        ignoredActionPaths: [
          "payload",
          "error",
          "meta.arg.originalArgs",
          "meta.baseQueryMeta",
        ],
      },
    }).concat([
      signalingServerApi.middleware,
      webrtcApi.middleware,
      roomListenerMiddleware.middleware,
      keyPairListenerMiddleware.middleware,
    ]),
});

export type AppDispatch = typeof store.dispatch;
export type State = ReturnType<typeof store.getState>;

export const dispatch: AppDispatch = store.dispatch;
