import { isUUID, isHexadecimal } from "class-validator";

import handleChallenge from "./handleChallenge";

import { setRoom } from "../reducers/roomsSlice";
import { setDescription, setCandidate } from "../reducers/peersSlice";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { RoomState } from "../store/room";
import type {
  WebSocketMessageChallengeRequest,
  WebSocketMessageRoomIdResponse,
  WebSocketMessageDescriptionReceive,
  WebSocketMessageCandidateReceive,
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
    | WebSocketMessageError = JSON.parse(event.data);

  const { keyPair } = api.getState() as RoomState;

  switch (message.type) {
    case "peerId": {
      const peerId = message.peerId ?? "";
      const challenge = message.challenge ?? "";

      console.log(peerId);

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

      if (isNewPeerId || isNewDbEntry) {
        await handleChallenge(keyPair, peerId, challenge, api);
      }

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

    case "description": {
      api.dispatch(
        setDescription({
          peerId: message.fromPeerId,
          peerPublicKey: message.fromPeerPublicKey,
          roomId: message.roomId,
          description: message.description,
        }),
      );

      break;
    }

    case "candidate": {
      api.dispatch(
        setCandidate({
          peerId: message.fromPeerId,
          roomId: message.roomId,
          candidate: message.candidate,
        }),
      );

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
