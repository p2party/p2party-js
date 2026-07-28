import { debugLog } from "../utils/debug";
import { createApi } from "@reduxjs/toolkit/query";

import { setKeyPair } from "../reducers/keyPairSlice";
import { signalingServerActions } from "../reducers/signalingServerSlice";

import handleWebSocketMessage from "../handlers/handleWebSocketMessage";

import { uint8ArrayToHex, hexToUint8Array } from "../utils/uint8array";
import {
  assertCanonicalEd25519Identity,
  isCanonicalEd25519Identity,
} from "../utils/identityRole";
import {
  signalingAttemptLifecycle,
  type SignalingAttempt,
} from "../utils/signalingAttemptLifecycle";
import {
  buildSignalingWebSocketUrl,
  canonicalSignalingServerUrl,
} from "../utils/signalingServerBoundary";
import {
  sendAuthenticatedSignalingFrame,
  sendPeerConnectionRequest,
  type WebSocketBaseResult,
} from "../utils/signalingFrame";
import {
  answerImmediateSignalingHeartbeat,
  SignalingIngressQueue,
  SignalingSocketIngressLease,
} from "../utils/signalingIngressQueue";
import { MAX_SIGNALING_MESSAGE_CHARS } from "../utils/signalingBounds";
import {
  acknowledgeRoomLeft,
  cancelRoomLeavesForSocket,
  parseRoomLeftAcknowledgement,
  RemoteRoomRevocationUnconfirmedError,
  requestRoomLeaveAcknowledgement,
  type RequestRoomLeaveOptions,
} from "../utils/roomLeaveCoordinator";
import { randomUuidV4 } from "../utils/correlationId";

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
  WebSocketMessageLeaveRoomRequest,
  WebSocketPeerConnectionParams,
  // WebSocketSendMessageToPeerParams,
  WebSocketMessagePeerConnectionRequest,
} from "../utils/interfaces";
import type { BaseQueryApi } from "@reduxjs/toolkit/query";

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
    | WebSocketMessageLeaveRoomRequest
    | WebSocketMessagePeersRequest
    | WebSocketMessageConnectionResponse
    | WebSocketMessagePeerConnectionRequest;
}

let ws: WebSocket | null = null;
let wsIngressLease: SignalingSocketIngressLease | null = null;
const websocketBaseQuery: BaseQueryFn<WebSocketParams, undefined> = async (
  { signalingServerUrl },
  api,
) => {
  let normalizedSignalingServerUrl: string;
  try {
    normalizedSignalingServerUrl =
      canonicalSignalingServerUrl(signalingServerUrl);
  } catch (error) {
    return {
      error: error instanceof Error ? error.message : "Invalid signaling URL",
    };
  }

  if (signalingAttemptLifecycle.isIdentityPurgeActive())
    return { error: "Identity purge is in progress" };

  const { keyPair, signalingServer } = api.getState() as State;
  if (
    ws ||
    signalingServer.isConnected ||
    (signalingServer.isEstablishingConnection &&
      signalingAttemptLifecycle.hasActiveAttempt())
  ) {
    if (
      canonicalSignalingServerUrl(signalingServer.serverUrl) !==
      normalizedSignalingServerUrl
    )
      return {
        error: "A different signaling server is already active",
      };
    debugLog("WebSocket already connected");

    return { data: undefined };
  }
  let lifecycleAttempt: SignalingAttempt;
  try {
    lifecycleAttempt = signalingAttemptLifecycle.begin(
      normalizedSignalingServerUrl,
    );
  } catch (error) {
    return {
      error:
        error instanceof Error
          ? error.message
          : "WebSocket connection attempt was rejected",
    };
  }
  api.dispatch(
    signalingServerActions.startConnecting(normalizedSignalingServerUrl),
  );
  const { token: attempt, cancelled } = lifecycleAttempt;
  const attemptCancelled = cancelled.then((): WebSocketBaseResult => ({
    error: "WebSocket connection attempt was cancelled",
  }));

  const runAttempt = async (): Promise<WebSocketBaseResult> => {
    let socketForAttempt: WebSocket | null = null;
    let releaseIdentityBootstrap: (() => void) | null = null;
    const requireCurrentAttempt = (): void =>
      signalingAttemptLifecycle.assertCurrent(attempt);

    try {
      releaseIdentityBootstrap =
        await signalingAttemptLifecycle.acquireBootstrap(attempt);
      const toBuf = (u: Uint8Array): ArrayBuffer => {
        const b = new ArrayBuffer(u.byteLength);
        new Uint8Array(b).set(u);
        return b;
      };

      let publicKey = keyPair.publicKey;
      let secretKey = keyPair.secretKey;
      const storedEd = await getIdentityEd25519();
      requireCurrentAttempt();
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
            try {
              await setIdentityEd25519({
                pub: toBuf(hexToUint8Array(publicKey)),
                secret: toBuf(secretBytes),
              });
            } finally {
              secretBytes.fill(0);
            }
            requireCurrentAttempt();
          } else {
            const generated = await newKeyPair();
            try {
              requireCurrentAttempt();
              publicKey = uint8ArrayToHex(generated.publicKey);
              secretKey = uint8ArrayToHex(generated.secretKey);
              await setIdentityEd25519({
                pub: toBuf(generated.publicKey),
                secret: toBuf(generated.secretKey),
              });
              requireCurrentAttempt();
            } finally {
              generated.secretKey.fill(0);
            }
          }
        }
        api.dispatch(setKeyPair({ publicKey, secretKey }));
      } else if (
        !storedEd ||
        storedEdPublicKey !== publicKey ||
        storedEdSecretKey !== secretKey
      ) {
        const secretBytes = hexToUint8Array(secretKey);
        try {
          await setIdentityEd25519({
            pub: toBuf(hexToUint8Array(publicKey)),
            secret: toBuf(secretBytes),
          });
        } finally {
          secretBytes.fill(0);
        }
        requireCurrentAttempt();
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
        requireCurrentAttempt();
        const valid =
          existing != null &&
          (await verifyIdentityCrossSig(
            new Uint8Array(existing.pub),
            new Uint8Array(existing.crossSig),
            hexToUint8Array(edPubHex),
          ));
        requireCurrentAttempt();
        if (!valid) {
          const x = await newX25519KeyPair();
          try {
            requireCurrentAttempt();
            const crossSig = await crossSignIdentityX25519(
              x.publicKey,
              hexToUint8Array(edSecretHex),
            );
            requireCurrentAttempt();
            await setIdentityX25519({
              pub: toBuf(x.publicKey),
              secret: toBuf(x.secretKey),
              crossSig: toBuf(crossSig),
            });
            requireCurrentAttempt();
          } finally {
            x.secretKey.fill(0);
          }
        }
      }

      const fullUrl = buildSignalingWebSocketUrl(
        normalizedSignalingServerUrl,
        publicKey,
      );

      // Identity bootstrap may await IndexedDB and crypto. A manual disconnect
      // or replacement during those awaits owns the newer lifecycle.
      requireCurrentAttempt();
      releaseIdentityBootstrap();
      releaseIdentityBootstrap = null;
      socketForAttempt = new WebSocket(fullUrl);
      ws = socketForAttempt;
      socketForAttempt.binaryType = "arraybuffer";

      return await new Promise<WebSocketBaseResult>((resolve, reject) => {
        if (!socketForAttempt) {
          reject(new Error("WebSocket is null"));
          return;
        }
        const socket = socketForAttempt;
        const ownsSocketAttempt = (): boolean =>
          ws === socket && signalingAttemptLifecycle.isCurrent(attempt);
        const ingressLease = new SignalingSocketIngressLease();
        wsIngressLease = ingressLease;
        const isCurrentSocket = (): boolean =>
          wsIngressLease === ingressLease &&
          ingressLease.isCurrent(ownsSocketAttempt);
        const invalidateSocketIngress = (
          reason: "socket-closed" | "socket-replaced" | "ingress-rejected",
        ): void => {
          ingressLease.invalidate();
          cancelRoomLeavesForSocket(socket, reason);
          if (wsIngressLease === ingressLease) wsIngressLease = null;
        };
        const ingressQueue = new SignalingIngressQueue({
          onOverflow: () => {
            invalidateSocketIngress("ingress-rejected");
            if (!ownsSocketAttempt()) return;
            socket.onmessage = null;
            socket.close(1008, "signaling ingress backlog exceeded");
          },
          onTaskError: (error) => {
            console.error("Signaling ingress task failed", error);
          },
        });
        let settled = false;
        const resolveOnce = (
          result: { data: undefined } | { error: string },
        ) => {
          if (settled) return;
          settled = true;
          resolve(result);
        };
        const rejectOnce = (error: Error) => {
          if (settled) return;
          settled = true;
          reject(error);
        };
        const cancelAttempt = (): void => {
          resolveOnce({ error: "WebSocket connection attempt was cancelled" });
          if (ws !== socket) return;
          invalidateSocketIngress("socket-replaced");
          ingressQueue.close();
          socket.onmessage = null;
          socket.onopen = null;
          socket.onclose = null;
          socket.onerror = null;
          socket.close();
          ws = null;
        };
        if (isCurrentSocket())
          signalingAttemptLifecycle.addCancellationEffect(
            attempt,
            cancelAttempt,
          );
        try {
          socket.onopen = () => {
            if (!isCurrentSocket()) return;
            debugLog("WebSocket connected to:", fullUrl);
            api.dispatch(signalingServerActions.connectionEstablished());
            signalingAttemptLifecycle.disarmCancellation(attempt);
            resolveOnce({ data: undefined });
          };

          socket.onerror = (error) => {
            if (!ownsSocketAttempt()) return;
            console.error("WebSocket error:", error);
            invalidateSocketIngress("socket-closed");
            ingressQueue.close();
            socket.onmessage = null;
            socket.onopen = null;
            socket.onclose = null;
            socket.onerror = null;
            socket.close();
            ws = null;
            signalingAttemptLifecycle.clear(attempt);

            api.dispatch(signalingServerActions.disconnect());

            rejectOnce(new Error("WebSocket connection failed"));
          };

          socket.onmessage = (message) => {
            if (!isCurrentSocket()) return;
            const payloadSize =
              typeof message.data === "string"
                ? message.data.length
                : message.data instanceof ArrayBuffer
                  ? message.data.byteLength
                  : message.data instanceof Blob
                    ? message.data.size
                    : MAX_SIGNALING_MESSAGE_CHARS + 1;
            if (payloadSize > MAX_SIGNALING_MESSAGE_CHARS) {
              invalidateSocketIngress("ingress-rejected");
              ingressQueue.close();
              socket.onmessage = null;
              socket.close(1009, "signaling frame too large");
              return;
            }
            const roomLeft = parseRoomLeftAcknowledgement(message.data);
            if (roomLeft) {
              if (!acknowledgeRoomLeft(roomLeft, socket))
                console.error(
                  "Rejecting unsolicited or stale room leave acknowledgement",
                );
              return;
            }
            try {
              if (
                answerImmediateSignalingHeartbeat(message.data, {
                  raw: () => socket.send("PONG"),
                  json: () => {
                    const { keyPair } = api.getState() as State;
                    const result = sendAuthenticatedSignalingFrame(
                      socket,
                      {
                        content: {
                          type: "pong",
                          fromPeerId: keyPair.peerId,
                        },
                      },
                      api,
                      isCurrentSocket,
                    );
                    if ("error" in result) throw new Error(result.error);
                  },
                })
              )
                return;
            } catch (error) {
              console.error("Could not answer signaling heartbeat", error);
              invalidateSocketIngress("ingress-rejected");
              ingressQueue.close();
              socket.onmessage = null;
              socket.close(1011, "signaling heartbeat failed");
              return;
            }
            ingressQueue.enqueue(
              async () =>
                await handleWebSocketMessage(
                  message,
                  socket,
                  api,
                  isCurrentSocket,
                ),
              payloadSize,
            );
          };

          socket.onclose = () => {
            if (!ownsSocketAttempt()) return;
            invalidateSocketIngress("socket-closed");
            ingressQueue.close();
            socket.onmessage = null;
            socket.onopen = null;
            socket.onclose = null;
            socket.onerror = null;
            ws = null;
            signalingAttemptLifecycle.clear(attempt);

            api.dispatch(signalingServerActions.disconnect());
            debugLog("WebSocket disconnected");
            resolveOnce({ data: undefined });
          };
        } catch (error) {
          signalingAttemptLifecycle.disarmCancellation(attempt);
          rejectOnce(error instanceof Error ? error : new Error(String(error)));
        }

        // Cleanup function to close the WebSocket when the query is unsubscribed
        return () => {
          if (ownsSocketAttempt()) {
            debugLog("Cleaning up WebSocket connection...");
            signalingAttemptLifecycle.cancelActive();
            invalidateSocketIngress("socket-closed");
            ingressQueue.close();
            socket.onmessage = null;
            socket.onopen = null;
            socket.onclose = null;
            socket.onerror = null;
            socket.close();
            ws = null;
          }
        };
      });
    } catch (error) {
      releaseIdentityBootstrap?.();
      const ownsAttempt = signalingAttemptLifecycle.isCurrent(attempt);
      if (ownsAttempt && socketForAttempt && ws === socketForAttempt) {
        wsIngressLease?.invalidate();
        wsIngressLease = null;
        cancelRoomLeavesForSocket(socketForAttempt, "socket-closed");
        socketForAttempt.onmessage = null;
        socketForAttempt.onopen = null;
        socketForAttempt.onclose = null;
        socketForAttempt.onerror = null;
        socketForAttempt.close();
        ws = null;
      }

      if (ownsAttempt) {
        signalingAttemptLifecycle.clear(attempt);
        api.dispatch(signalingServerActions.disconnect());
      }
      if (
        !(error instanceof Error) ||
        error.message !== "WebSocket connection attempt was cancelled"
      )
        console.error("Error during WebSocket setup:", error);

      return { error: "WebSocket connection failed" };
    }
  };

  return await Promise.race([runAttempt(), attemptCancelled]);
};

const websocketDisconnectQuery: BaseQueryFn<undefined, undefined> = (
  _: undefined,
  api,
) => {
  const socket = ws;
  const ingressLease = wsIngressLease;
  ws = null;
  wsIngressLease = null;
  // Also cancels an attempt still awaiting identity bootstrap, where no
  // WebSocket object exists yet.
  signalingAttemptLifecycle.cancelActive();
  if (socket) {
    ingressLease?.invalidate();
    cancelRoomLeavesForSocket(socket, "socket-closed");
    socket.onmessage = null;
    socket.onopen = null;
    socket.onclose = null;
    socket.onerror = null;
    socket.close();

    debugLog("WebSocket manually disconnected");
  }

  api.dispatch(signalingServerActions.disconnect());

  return { data: undefined };
};

// BaseQuery for sending messages over WebSocket
const websocketSendMessageQuery: BaseQueryFn<WebSocketMessage, undefined> = (
  message,
  api,
) => {
  const socket = ws;
  const ingressLease = wsIngressLease;
  if (!socket || !ingressLease) return { error: "WebSocket is not open" };
  return sendAuthenticatedSignalingFrame(
    socket,
    message,
    api,
    () =>
      ws === socket &&
      wsIngressLease === ingressLease &&
      ingressLease.isCurrent(() => true),
  );
};

const websocketConnectWithPeerQuery: BaseQueryFn<
  WebSocketPeerConnectionParams,
  undefined
> = (params, api) => {
  const socket = ws;
  const ingressLease = wsIngressLease;
  if (!socket || !ingressLease) return { error: "WebSocket is not open" };
  return sendPeerConnectionRequest(socket, params, api, () =>
    Boolean(
      ws === socket &&
      wsIngressLease === ingressLease &&
      ingressLease.isCurrent(() => true),
    ),
  );
};

type CurrentSocketApi = Pick<BaseQueryApi, "dispatch" | "getState">;

/**
 * Send a correlated leave on the exact authenticated socket and wait for its
 * exact acknowledgement. The caller must make local room transport terminal
 * before invoking this network-only boundary.
 */
export const requestCurrentSocketRoomLeave = (
  api: CurrentSocketApi,
  roomUrl: string,
  options: RequestRoomLeaveOptions = {},
): Promise<void> => {
  const socket = ws;
  const ingressLease = wsIngressLease;
  const roomLeaveId = options.roomLeaveId ?? randomUuidV4();
  if (!socket || !ingressLease)
    return Promise.reject(
      new RemoteRoomRevocationUnconfirmedError(
        roomUrl,
        roomLeaveId,
        "no-current-socket",
      ),
    );
  const isCurrentSocket = (): boolean =>
    ws === socket &&
    wsIngressLease === ingressLease &&
    ingressLease.isCurrent(() => true);
  const { keyPair } = api.getState() as State;
  return requestRoomLeaveAcknowledgement(
    keyPair.peerId,
    roomUrl,
    socket,
    (request) => {
      const result = sendAuthenticatedSignalingFrame(
        socket,
        { content: request },
        api,
        isCurrentSocket,
      );
      if ("error" in result) throw new Error(result.error);
    },
    { ...options, roomLeaveId },
  );
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

/** Queue one room request or reject immediately when RTK reports no send. */
export const sendRoomRequestMessage = async (
  api: Pick<BaseQueryApi, "dispatch">,
  request: WebSocketMessageRoomIdRequest,
): Promise<void> => {
  await api
    .dispatch(
      signalingServerApi.endpoints.sendMessage.initiate({
        content: request,
      }),
    )
    .unwrap();
};

export default signalingServerApi;
