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
  createSignalingHeartbeatWatchdog,
  type SignalingHeartbeatWatchdog,
  type SignalingHeartbeatWatchdogEnv,
  type SignalingWakeEventName,
} from "../utils/signalingHeartbeatWatchdog";
import {
  SIGNALING_HEARTBEAT_CHECK_MS,
  SIGNALING_HEARTBEAT_TIMEOUT_MS,
} from "../utils/constants";
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
  setIdentityDerivation,
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
// Liveness watchdog of the open socket in `ws`. Invariant: null, or owned by
// exactly that socket — every path that replaces `ws` stops it first.
let wsHeartbeatWatchdog: SignalingHeartbeatWatchdog | null = null;
const stopCurrentHeartbeatWatchdog = (): void => {
  wsHeartbeatWatchdog?.stop();
  wsHeartbeatWatchdog = null;
};

/** Wake events the browser fires when a frozen/backgrounded page resumes. */
const browserWakeEnv = (): SignalingHeartbeatWatchdogEnv | undefined => {
  if (typeof window === "undefined" || typeof document === "undefined")
    return undefined;
  const targetOf = (name: SignalingWakeEventName): EventTarget =>
    name === "visibilitychange" ? document : window;
  return {
    addListener: (name, listener) =>
      targetOf(name).addEventListener(name, listener),
    removeListener: (name, listener) =>
      targetOf(name).removeEventListener(name, listener),
    isVisible: () => document.visibilityState === "visible",
  };
};

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
            // The adopted legacy key was generated from a random seed, so no
            // recovery phrase can ever reproduce it. Record that before the
            // user is ever offered a backup.
            await setIdentityDerivation("random");
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
              // Randomly seeded: unrecoverable by design. Persisting this is
              // what lets the app tell the user their identity cannot be
              // backed up, instead of silently offering an unusable phrase.
              await setIdentityDerivation("random");
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
          stopCurrentHeartbeatWatchdog();
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
        // One settlement for every way this socket stops being ours after
        // open: the browser's close event, or the heartbeat watchdog deciding
        // the socket is half-open. The watchdog path must not wait for the
        // browser: a socket the platform silently dropped fires no close
        // event until TCP gives up, so the bookkeeping runs synchronously
        // here and the close handshake is merely started.
        let socketSettled = false;
        const settleClosedSocket = (
          close?: Readonly<{ code: number; reason: string }>,
        ): void => {
          if (socketSettled) return;
          socketSettled = true;
          stopCurrentHeartbeatWatchdog();
          invalidateSocketIngress("socket-closed");
          ingressQueue.close();
          socket.onmessage = null;
          socket.onopen = null;
          socket.onclose = null;
          socket.onerror = null;
          if (close) socket.close(close.code, close.reason);
          ws = null;
          signalingAttemptLifecycle.clear(attempt);

          api.dispatch(signalingServerActions.disconnect());
          resolveOnce({ data: undefined });
        };
        // This socket's own instance: a beat that lands after the socket was
        // replaced hits a stopped watchdog (a no-op), never the successor's.
        let heartbeatWatchdog: SignalingHeartbeatWatchdog | null = null;
        const noteHeartbeat = (): void => heartbeatWatchdog?.beat();
        try {
          socket.onopen = () => {
            if (!isCurrentSocket()) return;
            debugLog("WebSocket connected to:", fullUrl);
            const watchdog = createSignalingHeartbeatWatchdog({
              now: () => Date.now(),
              timeoutMs: SIGNALING_HEARTBEAT_TIMEOUT_MS,
              checkEveryMs: SIGNALING_HEARTBEAT_CHECK_MS,
              schedule: {
                setInterval: (callback, ms) => setInterval(callback, ms),
                clearInterval: (handle) => clearInterval(handle),
              },
              env: browserWakeEnv(),
              onDead: () => {
                if (!ownsSocketAttempt()) return;
                console.warn(
                  "p2party: no signaling heartbeat for " +
                    `${SIGNALING_HEARTBEAT_TIMEOUT_MS} ms; marking the socket disconnected`,
                );
                settleClosedSocket({
                  code: 4000,
                  reason: "signaling heartbeat lost",
                });
              },
            });
            heartbeatWatchdog = watchdog;
            wsHeartbeatWatchdog = watchdog;
            api.dispatch(signalingServerActions.connectionEstablished());
            signalingAttemptLifecycle.disarmCancellation(attempt);
            resolveOnce({ data: undefined });
          };

          socket.onerror = (error) => {
            if (!ownsSocketAttempt()) return;
            console.error("WebSocket error:", error);
            stopCurrentHeartbeatWatchdog();
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
              ) {
                noteHeartbeat();
                return;
              }
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
                  noteHeartbeat,
                ),
              payloadSize,
            );
          };

          socket.onclose = () => {
            if (!ownsSocketAttempt()) return;
            settleClosedSocket();
            debugLog("WebSocket disconnected");
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
            stopCurrentHeartbeatWatchdog();
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
        stopCurrentHeartbeatWatchdog();
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
  stopCurrentHeartbeatWatchdog();
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
