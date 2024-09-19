// import { Mutex } from "async-mutex";
import { isHexadecimal, isUUID } from "class-validator";

import handleChallenge from "../handlers/handleChallenge";

import { setCandidate, setDescription } from "../reducers/peersSlice";
import { signalingServerActions } from "../reducers/signalingServerSlice";
import { setKeyPair } from "../reducers/keyPairSlice";
import { setRoom } from "../reducers/roomsSlice";

import { exportPublicKeyToHex, exportPemKeys } from "../utils/exportPEMKeys";
import { importPublicKey } from "../utils/importPEMKeys";

import type { Middleware } from "redux";
import type { RoomState } from "../store/room";
import type {
  WebSocketMessageChallengeRequest,
  WebSocketMessageRoomIdResponse,
  WebSocketMessageDescriptionReceive,
  WebSocketMessageCandidateReceive,
  WebSocketMessageError,
} from "../utils/interfaces";

const waitForSocketConnection = (ws: WebSocket, callback: () => any) => {
  setTimeout(function () {
    if (ws.readyState === 1) {
      console.log("Connection is made");
      if (callback != null) {
        callback();
      }
    } else {
      console.log("wait for connection...");
      waitForSocketConnection(ws, callback);
    }
  }, 10); // wait 10 milisecond for the connection...
};

// Mutex to control WebSocket connection (optional)
// const socketMutex = new Mutex();

const signalingServerMiddleware: Middleware = (store) => {
  let ws: WebSocket;

  return (next) => async (action) => {
    const { signalingServer } = store.getState() as RoomState;
    const isConnectionEstablished =
      ws != undefined &&
      ws.readyState === 1 &&
      // ws.readyState !== WebSocket.CONNECTING &&
      // ws.readyState !== WebSocket.CLOSED &&
      // ws.readyState !== WebSocket.CLOSING &&
      signalingServer.isConnected;

    if (
      signalingServerActions.startConnecting.match(action) &&
      !isConnectionEstablished
    ) {
      const { keyPair } = store.getState() as RoomState;
      // await socketMutex.runExclusive(async () => {
      let publicKey = "";
      if (keyPair.secretKey.length === 0) {
        const newKeyPair = await crypto.subtle.generateKey(
          {
            name: "RSA-PSS",
            hash: "SHA-256",
            modulusLength: 4096,
            publicExponent: new Uint8Array([1, 0, 1]),
          },
          true,
          ["sign", "verify"],
        );

        const pair = await exportPemKeys(newKeyPair);

        store.dispatch(setKeyPair(pair));

        publicKey = await exportPublicKeyToHex(newKeyPair.publicKey);
      } else {
        const publicKeyPem = await importPublicKey(keyPair.publicKey);
        publicKey = await exportPublicKeyToHex(publicKeyPem);
      }

      ws = new WebSocket(signalingServer.serverUrl + "?publickey=" + publicKey);

      ws.onopen = () => {
        console.log("WebSocket connected");
        store.dispatch(signalingServerActions.connectionEstablished());
      };

      ws.onerror = (error) => {
        console.error("WebSocket error:", error);
        ws.removeEventListener("message", () => {});
        ws.removeEventListener("open", () => {});
        ws.removeEventListener("close", () => {});
        ws.close();
      };

      ws.onclose = () => {
        console.log("WebSocket closed");
      };

      ws.onmessage = async (event) => {
        console.log("Message from server:", JSON.parse(event.data));

        if (event.data === "PING") return ws.send("PONG");

        const message:
          | WebSocketMessageChallengeRequest
          | WebSocketMessageRoomIdResponse
          | WebSocketMessageDescriptionReceive
          | WebSocketMessageCandidateReceive
          | WebSocketMessageError = JSON.parse(event.data);

        const { keyPair } = store.getState() as RoomState;

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
              await handleChallenge(keyPair, peerId, challenge, store);
            }

            break;
          }

          case "roomId": {
            store.dispatch(
              setRoom({
                id: message.roomId,
                url: message.roomUrl,
              }),
            );

            break;
          }

          case "description": {
            store.dispatch(
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
            store.dispatch(
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
      // });

      return next(action);
    }

    if (
      signalingServerActions.disconnect.match(action) &&
      isConnectionEstablished
    ) {
      ws.removeEventListener("message", () => {});
      ws.removeEventListener("open", () => {});
      ws.removeEventListener("close", () => {});
      ws.close();

      return next(action);
    }

    if (
      signalingServerActions.sendMessage.match(action) &&
      isConnectionEstablished
    ) {
      const { keyPair } = store.getState();

      console.log(action.payload.content);
      if (
        isUUID(keyPair.peerId, 4) &&
        isHexadecimal(keyPair.challenge) &&
        isHexadecimal(keyPair.signature) &&
        keyPair.signature.length === 1024 &&
        keyPair.challenge.length === 64
      ) {
        waitForSocketConnection(ws, function () {
          console.log("message sent!!!");
          ws.send(JSON.stringify(action.payload.content));
        });
        // ws.send(JSON.stringify(action.payload.content));
      }

      return next(action);
    }

    return next(action);
  };
};

export default signalingServerMiddleware;
