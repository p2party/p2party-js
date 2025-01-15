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

        const { keyPair, rooms, commonState } = listenerApi.getState() as State;

        const roomIndex =
          commonState.currentRoomUrl.length === 64
            ? rooms.findIndex((r) => r.url === commonState.currentRoomUrl)
            : -1;

        if (roomIndex > -1) {
          if (action.payload.username && action.payload.credential) {
            listenerApi.dispatch(
              setIceServers({
                roomId: rooms[roomIndex].id,
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

          if (isUUID(rooms[roomIndex].id)) {
            listenerApi.dispatch(
              setConnectingToPeers({
                roomId: rooms[roomIndex].id,
                connectingToPeers: true,
              }),
            );
          }
        } else if (
          isUUID(keyPair.peerId) &&
          commonState.currentRoomUrl.length === 64
        ) {
          listenerApi.dispatch(
            signalingServerApi.endpoints.sendMessage.initiate({
              content: {
                type: "room",
                fromPeerId: keyPair.peerId,
                roomUrl: commonState.currentRoomUrl,
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

        const { keyPair, rooms, commonState } = listenerApi.getState() as State;

        const roomIndex =
          commonState.currentRoomUrl.length === 64
            ? rooms.findIndex((r) => r.url === commonState.currentRoomUrl)
            : -1;

        if (roomIndex > -1) {
          if (action.payload.username && action.payload.credential) {
            listenerApi.dispatch(
              setIceServers({
                roomId: rooms[roomIndex].id,
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

            if (isUUID(rooms[roomIndex].id)) {
              listenerApi.dispatch(
                setConnectingToPeers({
                  roomId: rooms[roomIndex].id,
                  connectingToPeers: true,
                }),
              );
            } else if (
              isUUID(keyPair.peerId) &&
              commonState.currentRoomUrl.length === 64
            ) {
              listenerApi.dispatch(
                signalingServerApi.endpoints.sendMessage.initiate({
                  content: {
                    type: "room",
                    fromPeerId: keyPair.peerId,
                    roomUrl: commonState.currentRoomUrl,
                  } as WebSocketMessageRoomIdRequest,
                }),
              );
            }
          }
        } else if (
          isUUID(keyPair.peerId) &&
          commonState.currentRoomUrl.length === 64
        ) {
          listenerApi.dispatch(
            signalingServerApi.endpoints.sendMessage.initiate({
              content: {
                type: "room",
                fromPeerId: keyPair.peerId,
                roomUrl: commonState.currentRoomUrl,
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
