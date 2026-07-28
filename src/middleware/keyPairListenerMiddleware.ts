import { createListenerMiddleware, isAnyOf } from "@reduxjs/toolkit";
import { isUUID, isHexadecimal } from "class-validator";

import {
  setKeyPair,
  setChallengeId,
  setPeerData,
  resetIdentity,
} from "../reducers/keyPairSlice";
import { signalingServerActions } from "../reducers/signalingServerSlice";

import { sendRoomRequestMessage } from "../api/signalingServerApi";
import { requestAllActiveRooms } from "../handlers/requestRoom";
import {
  markFreshSocketProof,
  resetRoomRequestLifecycle,
} from "../utils/roomRequestCoordinator";

const keyPairListenerMiddleware = createListenerMiddleware();
keyPairListenerMiddleware.startListening({
  matcher: isAnyOf(
    setKeyPair,
    setPeerData,
    setChallengeId,
    resetIdentity,
    signalingServerActions.disconnect,
  ),
  effect: async (action, listenerApi) => {
    const refreshActiveRooms = async (): Promise<void> => {
      try {
        await requestAllActiveRooms(listenerApi, (request) =>
          sendRoomRequestMessage(listenerApi, request),
        );
      } catch (error) {
        console.warn(
          "p2party: failed to refresh one or more active rooms",
          error instanceof Error ? error.message : String(error),
        );
      }
    };

    if (setKeyPair.match(action)) {
      const { publicKey, secretKey } = action.payload;

      if (publicKey.length === 64 && secretKey.length === 128) {
        localStorage.setItem("publicKey", action.payload.publicKey);
        // Clean v3 migration: the secret is wrapped in IndexedDB by the
        // signaling bootstrap and remains memory-only in Redux.
        localStorage.removeItem("secretKey");
      }
    } else if (setPeerData.match(action)) {
      const { peerId, challenge, signature } = action.payload;

      if (
        isUUID(peerId) &&
        isHexadecimal(challenge) &&
        isHexadecimal(signature) &&
        challenge.length === 64 &&
        signature.length === 128
      ) {
        localStorage.setItem("peerId", peerId);
        localStorage.setItem("challenge", challenge);
        localStorage.setItem("signature", signature);
      }
    } else if (setChallengeId.match(action)) {
      const { challengeId } = action.payload;
      if (isUUID(challengeId)) {
        listenerApi.dispatch(signalingServerActions.connectionVerified());
        markFreshSocketProof();

        localStorage.setItem("challengeId", challengeId);

        await refreshActiveRooms();
      }
    } else if (resetIdentity.match(action)) {
      resetRoomRequestLifecycle("identity reset");
      console.trace("[keyPairListenerMiddleware] resetIdentity dispatched");
      localStorage.setItem("peerId", "");
      localStorage.setItem("challengeId", "");
      localStorage.setItem("publicKey", "");
      localStorage.removeItem("secretKey");
      localStorage.setItem("challenge", "");
      localStorage.setItem("signature", "");
    } else if (signalingServerActions.disconnect.match(action)) {
      resetRoomRequestLifecycle();
    }
  },
});

export default keyPairListenerMiddleware;
