import { isUUID } from "./formatValidation";

import { setChannel, setPeer } from "../reducers/roomSlice";
import { isCanonicalEd25519Identity } from "./identityRole";
import { hasCurrentSocketProof } from "./signalingAuth";
import { debugLog } from "./debug";
import { PROTOCOL_VERSION } from "./constants";

import type { BaseQueryApi } from "@reduxjs/toolkit/query";
import type { State } from "../store";
import type {
  WebSocketMessagePeerConnectionRequest,
  WebSocketPeerConnectionParams,
} from "./interfaces";

export type WebSocketBaseResult = { data: undefined } | { error: string };
type SignalingQueryApi = Pick<BaseQueryApi, "dispatch" | "getState">;
type SignalingSocket = Pick<WebSocket, "readyState" | "send">;

export interface AuthenticatedSignalingFrame<
  Content extends { fromPeerId: string } = { fromPeerId: string },
> {
  content: Content;
}

export const sendAuthenticatedSignalingFrame = <
  Content extends { fromPeerId: string },
>(
  socket: SignalingSocket,
  message: AuthenticatedSignalingFrame<Content>,
  api: SignalingQueryApi,
  isCurrentSocket: () => boolean,
): WebSocketBaseResult => {
  if (socket.readyState !== 1 || !isCurrentSocket())
    return { error: "WebSocket is not open" };

  const { keyPair, signalingServer } = api.getState() as State;
  if (!hasCurrentSocketProof(keyPair, signalingServer))
    return { error: "WebSocket identity is not authenticated" };
  if (message.content.fromPeerId !== keyPair.peerId)
    return { error: "Signaling frame identity is stale" };
  if (!isCurrentSocket()) return { error: "WebSocket connection was replaced" };

  try {
    socket.send(JSON.stringify(message.content));
    return { data: undefined };
  } catch (error) {
    return {
      error:
        error instanceof Error
          ? error.message
          : "WebSocket rejected the signaling frame",
    };
  }
};

export const sendPeerConnectionRequest = (
  socket: SignalingSocket,
  { peerId, peerPublicKey, roomId }: WebSocketPeerConnectionParams,
  api: SignalingQueryApi,
  isCurrentSocket: () => boolean,
): WebSocketBaseResult => {
  if (!isUUID(peerId, 4))
    return { error: "Peer connection target must be a UUIDv4" };
  if (!isCanonicalEd25519Identity(peerPublicKey))
    return { error: "Peer connection target identity is invalid" };

  const { keyPair } = api.getState() as State;
  const result = sendAuthenticatedSignalingFrame(
    socket,
    {
      content: {
        type: "connection",
        roomId,
        fromPeerId: keyPair.peerId,
        toPeerId: peerId,
        labels: ["main"],
        protocolVersion: PROTOCOL_VERSION,
      } satisfies WebSocketMessagePeerConnectionRequest,
    },
    api,
    isCurrentSocket,
  );
  if ("error" in result) return result;
  if (!isCurrentSocket())
    return { error: "WebSocket connection was replaced during send" };

  api.dispatch(setPeer({ roomId, peerId, peerPublicKey }));
  api.dispatch(setChannel({ roomId, label: "main", peerId }));
  debugLog(`Connected with ${keyPair.peerId} on channel main`);
  return result;
};
