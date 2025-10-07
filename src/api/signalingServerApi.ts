import { createApi } from "@reduxjs/toolkit/query";
import { isUUID, isHexadecimal } from "class-validator";

import { setKeyPair } from "../reducers/keyPairSlice";
import {
  setPeer,
  setChannel,
  setConnectingToPeers,
} from "../reducers/roomSlice";
import { signalingServerActions } from "../reducers/signalingServerSlice";

import handleWebSocketMessage from "../handlers/handleWebSocketMessage";

import { uint8ArrayToHex } from "../utils/uint8array";

import { newKeyPair } from "../cryptography/ed25519";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type { State } from "../store";
import type {
  WSPeerConnection,
  WebSocketMessageCandidateSend,
  WebSocketMessageDescriptionSend,
  WebSocketMessageChallengeResponse,
  WebSocketMessageRoomIdRequest,
  WebSocketMessagePeersRequest,
  WebSocketMessageConnectionResponse,
  WebSocketMessagePongResponse,
  WebSocketMessageMessageSendRequest,
  WebSocketPeerConnectionParams,
  // WebSocketSendMessageToPeerParams,
  WebSocketMessagePeerConnectionRequest,
} from "../utils/interfaces";

export interface WebSocketParams {
  signalingServerUrl: string;
}

export interface WebSocketMessage {
  content:
    | WebSocketMessagePongResponse
    | WebSocketMessageCandidateSend
    | WebSocketMessageDescriptionSend
    | WebSocketMessageChallengeResponse
    | WebSocketMessageRoomIdRequest
    | WebSocketMessagePeersRequest
    | WebSocketMessageConnectionResponse
    | WebSocketMessageMessageSendRequest;
}

const waitForSocketConnection = (
  ws: WebSocket,
  callback: () => void,
  maxAttempts = 10,
  interval = 20,
) => {
  let attempts = 0;

  const checkConnection = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) {
      clearInterval(checkConnection);
      callback();
    } else {
      attempts += 1;
      console.log(`Waiting for connection... Attempt ${String(attempts)}`);

      if (attempts >= maxAttempts) {
        clearInterval(checkConnection);
        console.log(
          "WebSocket failed to connect after multiple attempts, closing...",
        );

        ws.removeEventListener("message", () => {});
        ws.removeEventListener("open", () => {});
        ws.removeEventListener("close", () => {});
        ws.close();
      }
    }
  }, interval);
};

let ws: WebSocket | null = null;
const peerConnections: WSPeerConnection[] = [];

const websocketBaseQuery: BaseQueryFn<WebSocketParams, undefined> = async (
  { signalingServerUrl },
  api,
) => {
  const { keyPair, signalingServer } = api.getState() as State;
  if (
    ws ||
    signalingServer.isConnected ||
    signalingServer.isEstablishingConnection
  ) {
    console.log("WebSocket already connected");

    return { data: undefined };
  } else {
    api.dispatch(signalingServerActions.startConnecting(signalingServerUrl));
  }

  try {
    let publicKey = localStorage.getItem("publicKey") ?? "";
    let secretKey = localStorage.getItem("secretKey") ?? "";
    if (keyPair.secretKey.length === 0 && secretKey.length === 0) {
      const k = await newKeyPair();
      publicKey = uint8ArrayToHex(k.publicKey);
      secretKey = uint8ArrayToHex(k.secretKey);

      api.dispatch(setKeyPair({ publicKey, secretKey }));
    } else if (keyPair.secretKey.length === 0) {
      if (secretKey.length === 128 && publicKey.length === 64) {
        api.dispatch(setKeyPair({ publicKey, secretKey }));
      } else {
        const k = await newKeyPair();
        publicKey = uint8ArrayToHex(k.publicKey);
        secretKey = uint8ArrayToHex(k.secretKey);

        api.dispatch(setKeyPair({ publicKey, secretKey }));
      }
    } else {
      publicKey = keyPair.publicKey;
    }

    const fullUrl = signalingServerUrl + "?publickey=" + publicKey;

    ws = new WebSocket(fullUrl);
    ws.binaryType = "arraybuffer";

    return await new Promise((resolve, reject) => {
      try {
        ws!.onopen = () => {
          console.log("WebSocket connected to:", fullUrl);
          api.dispatch(signalingServerActions.connectionEstablished());

          const { rooms, commonState } = api.getState() as State;

          const roomIndex =
            commonState.currentRoomUrl.length === 64
              ? rooms.findIndex((r) => r.url === commonState.currentRoomUrl)
              : -1;

          if (
            roomIndex > -1 &&
            isUUID(keyPair.peerId) &&
            isUUID(rooms[roomIndex].id)
          ) {
            api.dispatch(
              setConnectingToPeers({
                roomId: rooms[roomIndex].id,
                connectingToPeers: true,
              }),
            );
          } else if (
            isUUID(keyPair.peerId) &&
            commonState.currentRoomUrl.length === 64
          ) {
            waitForSocketConnection(ws!, () => {
              ws!.send(
                JSON.stringify({
                  type: "room",
                  fromPeerId: keyPair.peerId,
                  roomUrl: commonState.currentRoomUrl,
                } as WebSocketMessageRoomIdRequest),
              );
            });
          }

          resolve({ data: undefined });
        };

        ws!.onerror = (error) => {
          console.error("WebSocket error:", error);
          if (ws) {
            ws.removeEventListener("message", () => {});
            ws.removeEventListener("open", () => {});
            ws.removeEventListener("close", () => {});
            ws.close();
            ws = null;
          }

          api.dispatch(signalingServerActions.disconnect());

          reject({ error: "WebSocket connection failed" });
        };

        ws!.onmessage = async (message) => {
          await handleWebSocketMessage(message, ws!, api, peerConnections);
        };

        ws!.onclose = () => {
          if (ws) {
            ws.removeEventListener("message", () => {});
            ws.removeEventListener("open", () => {});
            ws.removeEventListener("close", () => {});
            ws.close();
            ws = null;
          }

          api.dispatch(signalingServerActions.disconnect());
          console.log("WebSocket disconnected");
          resolve({ data: undefined });
        };
      } catch (error) {
        reject(error);
      }

      // Cleanup function to close the WebSocket when the query is unsubscribed
      return () => {
        if (ws) {
          console.log("Cleaning up WebSocket connection...");
          ws.removeEventListener("message", () => {});
          ws.removeEventListener("open", () => {});
          ws.removeEventListener("close", () => {});
          ws.close();
          ws = null;
        }
      };
    });
  } catch (error) {
    if (ws) {
      ws.removeEventListener("message", () => {});
      ws.removeEventListener("open", () => {});
      ws.removeEventListener("close", () => {});
      ws.close();
      ws = null;
    }

    api.dispatch(signalingServerActions.disconnect());
    console.error("Error during WebSocket setup:", error);

    return { error: "WebSocket connection failed" };
  }
};

const websocketDisconnectQuery: BaseQueryFn<void, undefined, unknown> = (
  _: void,
  api,
) => {
  if (ws) {
    ws.removeEventListener("message", () => {});
    ws.removeEventListener("open", () => {});
    ws.removeEventListener("close", () => {});
    ws.close();

    ws = null;

    console.log("WebSocket manually disconnected");
  }

  api.dispatch(signalingServerActions.disconnect());

  return { data: undefined };
};

// BaseQuery for sending messages over WebSocket
const websocketSendMessageQuery: BaseQueryFn<
  WebSocketMessage,
  void,
  unknown
> = (message, api) => {
  if (ws && ws.readyState === WebSocket.OPEN) {
    const { keyPair } = api.getState() as State;

    if (
      isUUID(keyPair.peerId) &&
      isHexadecimal(keyPair.challenge) &&
      isHexadecimal(keyPair.signature) &&
      // keyPair.signature.length === 1024 &&
      keyPair.signature.length === 128 &&
      keyPair.challenge.length === 64
    ) {
      waitForSocketConnection(ws, () => {
        ws!.send(JSON.stringify(message.content));
      });
    }

    return { data: undefined };
  } else {
    console.warn("WebSocket is not open");

    return { data: undefined };
  }
};

const websocketConnectWithPeerQuery: BaseQueryFn<
  WebSocketPeerConnectionParams,
  void,
  unknown
> = async ({ peerId, peerPublicKey, roomId }, api) => {
  if (ws && ws.readyState === WebSocket.OPEN) {
    const { keyPair } = api.getState() as State;

    if (
      isUUID(keyPair.peerId) &&
      isHexadecimal(keyPair.challenge) &&
      isHexadecimal(keyPair.signature) &&
      keyPair.signature.length === 128 &&
      keyPair.challenge.length === 64 &&
      peerPublicKey.length === 64
    ) {
      api.dispatch(setPeer({ roomId, peerId, peerPublicKey }));
      api.dispatch(setChannel({ roomId, label: "main", peerId }));
      console.log(`Connected with ${keyPair.peerId} on channel main`);

      waitForSocketConnection(ws, () => {
        ws!.send(
          JSON.stringify({
            type: "connection",
            roomId,
            fromPeerId: keyPair.peerId,
            toPeerId: peerId,
            labels: ["main"],
          } as WebSocketMessagePeerConnectionRequest),
        );
      });
    }

    return { data: undefined };
  } else {
    console.warn("WebSocket is not open");

    return { data: undefined };
  }
};

// const websocketSendMessageToPeerQuery: BaseQueryFn<
//   WebSocketSendMessageToPeerParams,
//   void,
//   unknown
// > = async ({ data, toChannel }, api) => {
//   if (ws && ws.readyState === WebSocket.OPEN) {
//     const { keyPair } = api.getState() as State;
//
//     if (
//       isUUID(keyPair.peerId) &&
//       isHexadecimal(keyPair.challenge) &&
//       isHexadecimal(keyPair.signature) &&
//       // keyPair.signature.length === 1024 &&
//       keyPair.signature.length === 128 &&
//       keyPair.challenge.length === 64
//     ) {
//       const encryptionModule = await libcrypto({
//         wasmMemory: encryptionWasmMemory,
//       });
//
//       await handleSendMessageWebsocket(
//         data as string | File,
//         encryptionModule,
//         api,
//         toChannel,
//       );
//     }
//
//     return { data: undefined };
//   } else {
//     console.warn("WebSocket is not open");
//
//     return { data: undefined };
//   }
// };

const signalingServerApi = createApi({
  reducerPath: "signalingServerApi",
  baseQuery: websocketBaseQuery,
  endpoints: (builder) => ({
    connectWebSocket: builder.mutation<void, string>({
      query: (signalingServerUrl = "wss://signaling.p2party.com/ws") => ({
        signalingServerUrl,
      }),
    }),
    disconnectWebSocket: builder.mutation<void, void>({
      queryFn: websocketDisconnectQuery,
    }),
    sendMessage: builder.mutation<void, WebSocketMessage>({
      queryFn: websocketSendMessageQuery,
    }),
    connectWithPeer: builder.mutation<void, WebSocketPeerConnectionParams>({
      queryFn: websocketConnectWithPeerQuery,
    }),
    // sendMessageToPeer: builder.mutation<void, WebSocketSendMessageToPeerParams>(
    //   {
    //     queryFn: websocketSendMessageToPeerQuery,
    //   },
    // ),
  }),
});

export default signalingServerApi;
