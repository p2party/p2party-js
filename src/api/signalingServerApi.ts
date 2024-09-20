import { createApi } from "@reduxjs/toolkit/query";
import { isUUID, isHexadecimal } from "class-validator";

import { setKeyPair } from "../reducers/keyPairSlice";
import { signalingServerActions } from "../reducers/signalingServerSlice";

import handleWebSocketMessage from "../handlers/handleWebSocketMessage";

import { importPublicKey } from "../utils/importPEMKeys";
import { exportPublicKeyToHex, exportPemKeys } from "../utils/exportPEMKeys";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type { RootState } from "../store";
import type {
  WebSocketMessageCandidateSend,
  WebSocketMessageDescriptionSend,
  WebSocketMessageChallengeResponse,
  WebSocketMessageRoomIdRequest,
  WebSocketMessagePeersRequest,
} from "../utils/interfaces";

export interface WebSocketParams {
  signalingServerUrl: string;
}

export interface WebSocketMessage {
  content:
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
    console.warn("WebSocket already connected");
    return { data: "already connected" };
  }

  try {
    const { keyPair } = api.getState() as RootState;

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

      api.dispatch(setKeyPair(pair));

      publicKey = await exportPublicKeyToHex(newKeyPair.publicKey);
    } else {
      const publicKeyPem = await importPublicKey(keyPair.publicKey);
      publicKey = await exportPublicKeyToHex(publicKeyPem);
    }

    const fullUrl = signalingServerUrl + "?publickey=" + publicKey;
    ws = new WebSocket(fullUrl);

    return new Promise((resolve, reject) => {
      ws!.onopen = () => {
        console.log("WebSocket connected to:", fullUrl);
        resolve({ data: "connected" });
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

const websocketDisconnectQuery: BaseQueryFn<void, void, unknown> = async (
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
> = async (message, api) => {
  if (ws && ws.readyState === WebSocket.OPEN) {
    const { keyPair } = api.getState() as RootState;

    if (
      isUUID(keyPair.peerId) &&
      isHexadecimal(keyPair.challenge) &&
      isHexadecimal(keyPair.signature) &&
      keyPair.signature.length === 1024 &&
      keyPair.challenge.length === 64
    ) {
      waitForSocketConnection(ws, () => {
        console.log("message sent!!!");
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
  baseQuery: websocketBaseQuery,
  endpoints: (builder) => ({
    connectWebSocket: builder.query<void, string>({
      query: (signalingServerUrl = "ws://localhost:3001/ws") => ({
        signalingServerUrl,
      }),
    }),
    disconnectWebSocket: builder.query<void, void>({
      queryFn: websocketDisconnectQuery,
    }),
    sendMessage: builder.mutation<void, WebSocketMessage>({
      queryFn: websocketSendMessageQuery,
    }),
  }),
});

export default signalingServerApi;
