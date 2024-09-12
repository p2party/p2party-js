import { Mutex } from "async-mutex";

import { setCandidate, setDescription } from "../reducers/peersSlice";
import { signalingServerActions } from "../reducers/signalingServerSlice";
import { setKeyPair, setPeerId } from "../reducers/keyPairSlice";
import { setRoom } from "../reducers/roomsSlice";

import { exportPublicKeyToHex, exportPemKeys } from "../utils/exportPEMKeys";
import { importPrivateKey, importPublicKey } from "../utils/importPEMKeys";

import type { Middleware } from "redux";
import type { RoomState } from "../store/room";
import type {
  PeerId,
  RoomId,
  Description,
  Candidate,
} from "../utils/interfaces";

// Mutex to control WebSocket connection (optional)
const socketMutex = new Mutex();

const signalingServerMiddleware: Middleware = (store) => {
  let ws: WebSocket;

  return (next) => async (action) => {
    const { signalingServer } = store.getState() as RoomState;
    const isConnectionEstablished =
      ws != undefined &&
      ws.readyState !== WebSocket.CLOSED &&
      ws.readyState !== WebSocket.CLOSING &&
      signalingServer.isConnected;

    if (
      signalingServerActions.startConnecting.match(action) &&
      !isConnectionEstablished
    ) {
      const { keyPair } = store.getState();
      await socketMutex.runExclusive(async () => {
        let publicKey = "";
        if (!isConnectionEstablished && keyPair.secretKey.length === 0) {
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
        } else if (!isConnectionEstablished) {
          const publicKeyPem = await importPublicKey(keyPair.publicKey);
          publicKey = await exportPublicKeyToHex(publicKeyPem);
        }

        ws = new WebSocket(
          signalingServer.serverUrl + "?publickey=" + publicKey,
        );

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

          const message: PeerId | RoomId | Description | Candidate = JSON.parse(
            event.data,
          );

          switch (message.type) {
            case "peerId": {
              const { keyPair } = store.getState();
              const peerId = message.peerId ?? "";
              const challenge = message.challenge ?? "";

              store.dispatch(
                setPeerId({
                  peerId,
                }),
              );

              try {
                const secretKey = await importPrivateKey(keyPair.secretKey);

                const nonce = Uint8Array.from(
                  challenge
                    .match(/.{1,2}/g)!
                    .map((byte: string) => parseInt(byte, 16)),
                );

                const signature = await window.crypto.subtle.sign(
                  {
                    name: "RSA-PSS",
                    saltLength: 32,
                  },
                  secretKey,
                  nonce,
                );

                store.dispatch(
                  signalingServerActions.sendMessage({
                    content: {
                      type: "challenge",
                      fromPeerId: peerId,
                      challenge,
                      signature:
                        "0x" +
                        [...new Uint8Array(signature)]
                          .map((x) => x.toString(16).padStart(2, "0"))
                          .join(""),
                    },
                  }),
                );
                // ws.send(
                //   JSON.stringify({
                //     type: "challenge",
                //     fromPeerId: peerId,
                //     challenge,
                //     signature:
                //       "0x" +
                //       [...new Uint8Array(signature)]
                //         .map((x) => x.toString(16).padStart(2, "0"))
                //         .join(""),
                //   }),
                // );
              } catch (error) {
                throw error;
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

            default: {
              console.error("Unknown message type");

              break;
            }
          }
        };
      });

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
      ws.send(JSON.stringify(action.payload.content));

      console.log(JSON.stringify(action.payload.content));

      return next(action);
    }

    return next(action);
  };
};

export default signalingServerMiddleware;
