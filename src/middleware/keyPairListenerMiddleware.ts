import { createListenerMiddleware, isAnyOf } from "@reduxjs/toolkit";
import { isUUID, isHexadecimal } from "class-validator";

import { setChallengeId, setPeerData } from "../reducers/keyPairSlice";
import { setConnectingToPeers, setIceServers } from "../reducers/roomSlice";

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

      if (action.payload.username && action.payload.credential) {
        listenerApi.dispatch(
          setIceServers({
            iceServers: [
              {
                urls: [
                  "turn:turn.p2party.com:3478?transport=udp",
                  // "turn:turn.p2party.com:5349?transport=tcp",
                  "turns:turn.p2party.com:443?transport=tcp",
                ],
                username: action.payload.username,
                credential: action.payload.credential,
              } as RTCIceServer,
            ],
          }),
        );
      }

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
