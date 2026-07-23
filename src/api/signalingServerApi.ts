import { createApi } from "@reduxjs/toolkit/query";
import { isUUID, isHexadecimal } from "class-validator";

import { setKeyPair } from "../reducers/keyPairSlice";
import { setPeer, setChannel } from "../reducers/roomSlice";
import { signalingServerActions } from "../reducers/signalingServerSlice";

import handleWebSocketMessage from "../handlers/handleWebSocketMessage";

import { uint8ArrayToHex, hexToUint8Array } from "../utils/uint8array";
import {
  assertCanonicalEd25519Identity,
  isCanonicalEd25519Identity,
} from "../utils/identityRole";
import { PROTOCOL_VERSION } from "../utils/constants";

import { newKeyPair } from "../cryptography/ed25519";
import { newX25519KeyPair } from "../cryptography/x25519";
import {
  crossSignIdentityX25519,
  verifyIdentityCrossSig,
} from "../cryptography/identityCrossSig";

import {
  getIdentityEd25519,
  getIdentityX25519,
  setIdentityEd25519,
  setIdentityX25519,
} from "../db/api";

import type { BaseQueryFn } from "@reduxjs/toolkit/query";
import type { State } from "../store";
import type {
  WebSocketMessageCandidateSend,
  WebSocketMessageDescriptionSend,
  WebSocketMessageChallengeResponse,
  WebSocketMessageRoomIdRequest,
  WebSocketMessagePeersRequest,
  WebSocketMessageConnectionResponse,
  WebSocketMessagePongResponse,
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
    | WebSocketMessageConnectionResponse;
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
    const toBuf = (u: Uint8Array): ArrayBuffer => {
      const b = new ArrayBuffer(u.byteLength);
      new Uint8Array(b).set(u);
      return b;
    };

    let publicKey = keyPair.publicKey;
    let secretKey = keyPair.secretKey;
    const storedEd = await getIdentityEd25519();
    const storedEdPublicKey = storedEd
      ? uint8ArrayToHex(new Uint8Array(storedEd.pub))
      : "";
    const storedEdSecret = storedEd
      ? new Uint8Array(storedEd.secret)
      : undefined;
    const storedEdSecretKey = storedEdSecret
      ? uint8ArrayToHex(storedEdSecret)
      : "";
    storedEdSecret?.fill(0);

    const canonicalSecretKey = /^[0-9a-f]{128}$/;
    if (
      !isCanonicalEd25519Identity(publicKey) ||
      !canonicalSecretKey.test(secretKey)
    ) {
      if (storedEd) {
        publicKey = storedEdPublicKey;
        secretKey = storedEdSecretKey;
      } else {
        // One-way clean-v3 migration from the old plaintext localStorage row.
        const legacyPublic = localStorage.getItem("publicKey") ?? "";
        const legacySecret = localStorage.getItem("secretKey") ?? "";
        if (
          isCanonicalEd25519Identity(legacyPublic) &&
          canonicalSecretKey.test(legacySecret)
        ) {
          publicKey = legacyPublic;
          secretKey = legacySecret;
          const secretBytes = hexToUint8Array(secretKey);
          await setIdentityEd25519({
            pub: toBuf(hexToUint8Array(publicKey)),
            secret: toBuf(secretBytes),
          });
          secretBytes.fill(0);
        } else {
          const generated = await newKeyPair();
          publicKey = uint8ArrayToHex(generated.publicKey);
          secretKey = uint8ArrayToHex(generated.secretKey);
          await setIdentityEd25519({
            pub: toBuf(generated.publicKey),
            secret: toBuf(generated.secretKey),
          });
          generated.secretKey.fill(0);
        }
      }
      api.dispatch(setKeyPair({ publicKey, secretKey }));
    } else if (
      !storedEd ||
      storedEdPublicKey !== publicKey ||
      storedEdSecretKey !== secretKey
    ) {
      const secretBytes = hexToUint8Array(secretKey);
      await setIdentityEd25519({
        pub: toBuf(hexToUint8Array(publicKey)),
        secret: toBuf(secretBytes),
      });
      secretBytes.fill(0);
    }
    assertCanonicalEd25519Identity(publicKey, "Self Ed25519 identity");
    localStorage.removeItem("secretKey");

    // D2=B: ensure the dedicated X25519 identity exists — generated once, wrapped in
    // IndexedDB, cross-signed by the Ed25519 identity under a domain separator so
    // peers trust it transitively. Self-healing: if the stored record's cross-sig no
    // longer verifies against the current Ed25519 identity (e.g. the Ed25519 key was
    // rotated/regenerated), it is regenerated so no orphaned cross-sig survives.
    const edSecretHex = secretKey.length > 0 ? secretKey : keyPair.secretKey;
    const edPubHex = publicKey.length > 0 ? publicKey : keyPair.publicKey;
    if (edSecretHex.length > 0 && edPubHex.length > 0) {
      const existing = await getIdentityX25519();
      const valid =
        existing != null &&
        (await verifyIdentityCrossSig(
          new Uint8Array(existing.pub),
          new Uint8Array(existing.crossSig),
          hexToUint8Array(edPubHex),
        ));
      if (!valid) {
        const x = await newX25519KeyPair();
        const crossSig = await crossSignIdentityX25519(
          x.publicKey,
          hexToUint8Array(edSecretHex),
        );
        await setIdentityX25519({
          pub: toBuf(x.publicKey),
          secret: toBuf(x.secretKey),
          crossSig: toBuf(crossSig),
        });
      }
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
          await handleWebSocketMessage(message, socket, api);
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
      isCanonicalEd25519Identity(peerPublicKey)
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
            protocolVersion: PROTOCOL_VERSION,
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
