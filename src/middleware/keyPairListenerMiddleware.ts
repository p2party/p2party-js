import { createListenerMiddleware, isAnyOf } from "@reduxjs/toolkit";
import { isUUID, isHexadecimal } from "class-validator";

import { setChallengeId, setPeerData } from "../reducers/keyPairSlice";
import { setConnectingToPeers } from "../reducers/roomSlice";

import signalingServerApi from "../api/signalingServerApi";

import type { State } from "../store";
import type {
  WebSocketMessageChallengeResponse,
  WebSocketMessageRoomIdRequest,
} from "../utils/interfaces";

const keyPairListenerMiddleware = createListenerMiddleware();
keyPairListenerMiddleware.startListening({
  matcher: isAnyOf(setPeerData, setChallengeId),
  effect: (action, listenerApi) => {
    if (setPeerData.match(action)) {
      const { peerId, challenge, signature } = action.payload;

      if (
        isUUID(peerId) &&
        isHexadecimal(challenge) &&
        isHexadecimal(signature) &&
        challenge.length === 64 &&
        // signature.length === 1024
        signature.length === 128
      ) {
        listenerApi.dispatch(
          signalingServerApi.endpoints.sendMessage.initiate({
            content: {
              type: "challenge",
              fromPeerId: peerId,
              challenge,
              signature,
            } as WebSocketMessageChallengeResponse,
          }),
        );
      }
    } else if (setChallengeId.match(action)) {
      const { keyPair, room } = listenerApi.getState() as State;

      if (isUUID(room.id)) {
        listenerApi.dispatch(setConnectingToPeers(true));
      } else {
        listenerApi.dispatch(
          signalingServerApi.endpoints.sendMessage.initiate({
            content: {
              type: "room",
              fromPeerId: keyPair.peerId,
              roomUrl: room.url,
            } as WebSocketMessageRoomIdRequest,
          }),
        );
      }
    }
  },
});

export default keyPairListenerMiddleware;
