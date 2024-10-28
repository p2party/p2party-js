import { createApi } from "@reduxjs/toolkit/query";
import { isUUID, isHexadecimal } from "class-validator";

import { setKeyPair } from "../reducers/keyPairSlice";
import { signalingServerActions } from "../reducers/signalingServerSlice";
import { setConnectingToPeers } from "../reducers/roomSlice";

import handleWebSocketMessage from "../handlers/handleWebSocketMessage";

import { uint8ToHex } from "../utils/hexString";

import { newKeyPair } from "../cryptography/ed25519";

// import { exportPublicKeyToHex, exportPemKeys } from "../utils/exportPEMKeys";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type { State } from "../store";
import type {
  WebSocketMessageCandidateSend,
  WebSocketMessageDescriptionSend,
  WebSocketMessageChallengeResponse,
  WebSocketMessageRoomIdRequest,
  WebSocketMessagePeersRequest,
  WebSocketMessagePongResponse,
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
    | WebSocketMessagePeersRequest;
}

const waitForSocketConnection = (ws: WebSocket, callback: () => any) => {
  setTimeout(() => {
    if (ws.readyState === 1) {
      if (callback != null) {
        callback();
      }
    } else {
      console.log("wait for connection...");
      waitForSocketConnection(ws, callback);
    }
  }, 10); // wait 10 milisecond for the connection...
};

let ws: WebSocket | null = null;

const websocketBaseQuery: BaseQueryFn<
  WebSocketParams,
  string,
  unknown
> = async ({ signalingServerUrl }, api) => {
  if (ws) {
    const { keyPair } = api.getState() as State;

    console.warn("WebSocket already connected");

    return { data: keyPair.publicKey };
  }

  try {
    const { keyPair } = api.getState() as State;

    let publicKey = "";
    if (keyPair.secretKey.length === 0) {
      // const newKeyPair = await crypto.subtle.generateKey(
      //   {
      //     name: "RSA-PSS",
      //     hash: "SHA-256",
      //     modulusLength: 4096,
      //     publicExponent: new Uint8Array([1, 0, 1]),
      //   },
      //   true,
      //   ["sign", "verify"],
      // );
      //
      // const pair = await exportPemKeys(newKeyPair);
      // publicKey = await exportPublicKeyToHex(newKeyPair.publicKey);
      //
      // api.dispatch(setKeyPair({ publicKey, secretKey: pair.secretKey }));

      const k = await newKeyPair();
      publicKey = uint8ToHex(k.publicKey);
      const secretKey = uint8ToHex(k.secretKey);

      api.dispatch(setKeyPair({ publicKey, secretKey }));
    } else {
      publicKey = keyPair.publicKey;
    }

    const fullUrl = signalingServerUrl + "?publickey=" + publicKey;
    api.dispatch(signalingServerActions.startConnecting(fullUrl));

    ws = new WebSocket(fullUrl);

    return new Promise((resolve, reject) => {
      try {
        ws!.onopen = () => {
          console.log("WebSocket connected to:", fullUrl);
          api.dispatch(signalingServerActions.connectionEstablished());

          const { keyPair, room } = api.getState() as State;

          if (isUUID(keyPair.peerId) && isUUID(room.id)) {
            api.dispatch(setConnectingToPeers(true));
          }

          resolve({ data: publicKey });
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
          await handleWebSocketMessage(message, ws!, api);
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
          resolve({ data: publicKey });
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

const websocketDisconnectQuery: BaseQueryFn<void, string, unknown> = async (
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

  const { keyPair } = api.getState() as State;

  api.dispatch(signalingServerActions.disconnect());

  return { data: keyPair.publicKey };
};

// BaseQuery for sending messages over WebSocket
const websocketSendMessageQuery: BaseQueryFn<
  WebSocketMessage,
  void,
  unknown
> = async (message, api) => {
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
        console.log(message.content);
      });
    }

    return { data: undefined };
  } else {
    console.warn("WebSocket is not open");

    return { data: undefined };
  }
};

const signalingServerApi = createApi({
  reducerPath: "signalingServerApi",
  baseQuery: websocketBaseQuery,
  endpoints: (builder) => ({
    connectWebSocket: builder.mutation<void, string>({
      query: (signalingServerUrl = "ws://localhost:3001/ws") => ({
        signalingServerUrl,
      }),
    }),
    disconnectWebSocket: builder.mutation<string, void>({
      queryFn: websocketDisconnectQuery,
    }),
    sendMessage: builder.mutation<void, WebSocketMessage>({
      queryFn: websocketSendMessageQuery,
    }),
  }),
});

export default signalingServerApi;
