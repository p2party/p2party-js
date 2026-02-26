import { createApi } from "@reduxjs/toolkit/query";
import { isUUID, isHexadecimal } from "class-validator";

import { setKeyPair } from "../reducers/keyPairSlice";
import { setPeer, setChannel } from "../reducers/roomSlice";
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
      if (!ws) {
        reject(new Error("WebSocket is null"));
        return;
      }
      const socket = ws;
      try {
        socket.onopen = () => {
          console.log("WebSocket connected to:", fullUrl);
          api.dispatch(signalingServerActions.connectionEstablished());

          resolve({ data: undefined });
        };

        socket.onerror = (error) => {
          console.error("WebSocket error:", error);
          if (ws) {
            ws.removeEventListener("message", () => {});
            ws.removeEventListener("open", () => {});
            ws.removeEventListener("close", () => {});
            ws.close();
            ws = null;
          }

          api.dispatch(signalingServerActions.disconnect());

          reject(new Error("WebSocket connection failed"));
        };

        socket.onmessage = async (message) => {
          await handleWebSocketMessage(message, socket, api, peerConnections);
        };

        socket.onclose = () => {
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
        reject(error instanceof Error ? error : new Error(String(error)));
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

const websocketDisconnectQuery: BaseQueryFn<undefined, undefined> = (
  _: undefined,
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
const websocketSendMessageQuery: BaseQueryFn<WebSocketMessage, undefined> = (
  message,
  api,
) => {
  if (ws?.readyState === WebSocket.OPEN) {
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
        ws?.send(JSON.stringify(message.content));
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
  undefined
> = ({ peerId, peerPublicKey, roomId }, api) => {
  if (ws?.readyState === WebSocket.OPEN) {
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
        ws?.send(
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
    connectWebSocket: builder.mutation<undefined, string>({
      query: (signalingServerUrl) => ({
        signalingServerUrl,
      }),
    }),
    disconnectWebSocket: builder.mutation<undefined, undefined>({
      queryFn: websocketDisconnectQuery,
    }),
    sendMessage: builder.mutation<undefined, WebSocketMessage>({
      queryFn: websocketSendMessageQuery,
    }),
    connectWithPeer: builder.mutation<undefined, WebSocketPeerConnectionParams>(
      {
        queryFn: websocketConnectWithPeerQuery,
      },
    ),
    // sendMessageToPeer: builder.mutation<void, WebSocketSendMessageToPeerParams>(
    //   {
    //     queryFn: websocketSendMessageToPeerQuery,
    //   },
    // ),
  }),
});

export default signalingServerApi;
