import { createListenerMiddleware, isAnyOf } from "@reduxjs/toolkit";
import { isUUID, isHexadecimal } from "class-validator";

import {
  setKeyPair,
  setReconnectData,
  setChallengeId,
  setPeerData,
  resetIdentity,
} from "../reducers/keyPairSlice";
import { setConnectingToPeers, setIceServers } from "../reducers/roomSlice";

import signalingServerApi from "../api/signalingServerApi";

import type { State } from "../store";
import type {
  WebSocketMessageChallengeResponse,
  WebSocketMessageRoomIdRequest,
} from "../utils/interfaces";

const keyPairListenerMiddleware = createListenerMiddleware();
keyPairListenerMiddleware.startListening({
  matcher: isAnyOf(
    setKeyPair,
    setReconnectData,
    setPeerData,
    setChallengeId,
    resetIdentity,
  ),
  effect: (action, listenerApi) => {
    if (setKeyPair.match(action)) {
      const { publicKey, secretKey } = action.payload;

      if (publicKey.length === 64 && secretKey.length === 128) {
        localStorage.setItem("publicKey", action.payload.publicKey);
        localStorage.setItem("secretKey", action.payload.secretKey);
      }
    } else if (setReconnectData.match(action)) {
      const {
        peerId,
        challenge,
        signature,
        challengeId,
        username,
        credential,
      } = action.payload;

      if (
        isUUID(peerId) &&
        isUUID(challengeId) &&
        isHexadecimal(challenge) &&
        isHexadecimal(signature) &&
        challenge.length === 64 &&
        // signature.length === 1024
        signature.length === 128
      ) {
        localStorage.setItem("peerId", peerId);
        localStorage.setItem("challenge", challenge);
        localStorage.setItem("signature", signature);
        localStorage.setItem("challengeId", challengeId);

        const { keyPair, room } = listenerApi.getState() as State;

        if (action.payload.username && action.payload.credential) {
          listenerApi.dispatch(
            setIceServers({
              iceServers: [
                {
                  urls: [
                    "turn:turn.p2party.com:3478?transport=udp",
                    "turn:turn.p2party.com:3478?transport=tcp",
                    "turns:turn.p2party.com:443?transport=tcp",
                  ],
                  username,
                  credential,
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
      const { challengeId } = action.payload;
      if (isUUID(challengeId)) {
        localStorage.setItem("challengeId", challengeId);

        if (action.payload.username && action.payload.credential) {
          listenerApi.dispatch(
            setIceServers({
              iceServers: [
                {
                  urls: [
                    "turn:turn.p2party.com:3478?transport=udp",
                    "turn:turn.p2party.com:3478?transport=tcp",
                    "turns:turn.p2party.com:443?transport=tcp",
                  ],
                  username: action.payload.username,
                  credential: action.payload.credential,
                } as RTCIceServer,
              ],
            }),
          );
        }

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
    } else if (resetIdentity.match(action)) {
      localStorage.setItem("peerId", "");
      localStorage.setItem("challengeId", "");
      localStorage.setItem("publicKey", "");
      localStorage.setItem("secretKey", "");
      localStorage.setItem("challenge", "");
      localStorage.setItem("signature", "");
    }
  },
});

export default keyPairListenerMiddleware;
