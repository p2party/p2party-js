import { isUUID, isHexadecimal } from "class-validator";

import handleChallenge from "./handleChallenge";

import webrtcApi from "../api/webrtc";

// import { exportPublicKeyToHex } from "../utils/exportPEMKeys";
// import { importPublicKey } from "../utils/importPEMKeys";

import { setRoom } from "../reducers/roomSlice";
import { setChallengeId } from "../reducers/keyPairSlice";
// import {
//   setDescription,
//   setCandidate,
//   // setPeer
// } from "../reducers/peersSlice";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";
import type {
  WebSocketMessageChallengeRequest,
  WebSocketMessageRoomIdResponse,
  WebSocketMessageDescriptionReceive,
  WebSocketMessageCandidateReceive,
  WebSocketMessagePeersResponse,
  WebSocketMessageSuccessfulChallenge,
  WebSocketMessageError,
} from "../utils/interfaces";

const handleWebSocketMessage = async (
  event: MessageEvent,
  ws: WebSocket,
  api: BaseQueryApi,
) => {
  console.log("Message from server:", JSON.parse(event.data));

  if (event.data === "PING") return ws.send("PONG");

  const message:
    | WebSocketMessageChallengeRequest
    | WebSocketMessageRoomIdResponse
    | WebSocketMessageDescriptionReceive
    | WebSocketMessageCandidateReceive
    | WebSocketMessagePeersResponse
    | WebSocketMessageSuccessfulChallenge
    | WebSocketMessageError = JSON.parse(event.data);

  const { keyPair, room } = api.getState() as State;

  switch (message.type) {
    case "peerId": {
      const peerId = message.peerId ?? "";
      const challenge = message.challenge ?? "";

      const isNewPeerId =
        isUUID(peerId) &&
        isHexadecimal(challenge) &&
        challenge.length === 64 &&
        keyPair.challenge.length === 0 &&
        keyPair.signature.length === 0;

      const isNewDbEntry =
        isUUID(peerId) &&
        isUUID(keyPair.peerId) &&
        keyPair.peerId !== peerId &&
        isHexadecimal(challenge) &&
        challenge.length === 64;

      if (isNewPeerId || isNewDbEntry)
        await handleChallenge(keyPair, peerId, challenge, api);

      break;
    }

    case "roomId": {
      api.dispatch(
        setRoom({
          id: message.roomId,
          url: message.roomUrl,
        }),
      );

      break;
    }

    case "challenge": {
      api.dispatch(setChallengeId(message.challengeId));

      break;
    }

    case "peers": {
      if (
        message.roomId !== room.id ||
        !isUUID(message.roomId) ||
        keyPair.publicKey.length === 0
      )
        break;

      const len = message.peers.length;
      if (len === 1) break;

      // const pk = await importPublicKey(keyPair.publicKey);
      // const pkHex = await exportPublicKeyToHex(pk);
      for (let i = 0; i < len; i++) {
        if (
          message.peers[i].publicKey === keyPair.publicKey ||
          message.peers[i].id === keyPair.peerId ||
          !isUUID(message.peers[i].id) ||
          message.peers[i].publicKey.length !== 1100
        )
          continue;

        api.dispatch(
          webrtcApi.endpoints.connectWithPeer.initiate({
            roomId: message.roomId,
            peerId: message.peers[i].id,
            peerPublicKey: message.peers[i].publicKey,
            initiator: true,
            rtcConfig: room.rtcConfig,
          }),
        );
      }

      break;
    }

    case "description": {
      api.dispatch(
        webrtcApi.endpoints.setDescription.initiate({
          peerId: message.fromPeerId,
          peerPublicKey: message.fromPeerPublicKey,
          roomId: message.roomId,
          description: message.description,
        }),
      );

      // api.dispatch(
      //   setDescription({
      //     peerId: message.fromPeerId,
      //     peerPublicKey: message.fromPeerPublicKey,
      //     roomId: message.roomId,
      //     description: message.description,
      //   }),
      // );

      break;
    }

    case "candidate": {
      api.dispatch(
        webrtcApi.endpoints.setCandidate.initiate({
          peerId: message.fromPeerId,
          // peerPublicKey: message.fromPeerPublicKey,
          // roomId: message.roomId,
          candidate: message.candidate,
        }),
      );
      // api.dispatch(
      //   setCandidate({
      //     peerId: message.fromPeerId,
      //     roomId: message.roomId,
      //     candidate: message.candidate,
      //   }),
      // );

      break;
    }

    case "error": {
      console.error(message);

      break;
    }

    default: {
      console.error("Unknown message type " + message);

      break;
    }
  }
};

export default handleWebSocketMessage;
