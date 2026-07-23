export interface WebSocketMessagePingRequest {
  type: "ping";
}

export interface WebSocketMessagePongResponse {
  type: "pong";
  fromPeerId: string;
}

export interface WebSocketMessageChallengeRequest {
  type: "peerId";
  peerId: string;
  challenge: string;
  protocolVersion: number;
  message: string;
}

export interface WebSocketMessageChallengeResponse {
  type: "challenge";
  challenge: string;
  signature: string;
  fromPeerId: string;
  protocolVersion: number;
}

export interface WebSocketMessageSuccessfulChallenge {
  type: "challenge";
  challengeId: string;
  protocolVersion: number;
  username?: string;
  credential?: string;
}

export interface WebSocketMessageRoomIdRequest {
  type: "room";
  fromPeerId: string;
  roomUrl: string;
  protocolVersion: number;
}

export interface TurnCredentials {
  urls: string[];
  username: string;
  credential: string;
  ttl: number;
}

export interface WebSocketMessageRoomIdResponse {
  type: "roomId";
  roomId: string;
  roomUrl: string;
  turnCredentials?: TurnCredentials;
  /** Optional only so missing/pre-v3 server responses fail closed at runtime. */
  protocolVersion?: number;
}

export interface WebSocketMessageDescriptionSend {
  type: "description";
  description: RTCSessionDescription;
  fromPeerId: string;
  fromPeerPublicKey: string;
  toPeerId: string;
  roomId: string;
  protocolVersion: number;
}

export interface WebSocketMessageDescriptionReceive {
  type: "description";
  description: RTCSessionDescription;
  fromPeerId: string;
  fromPeerPublicKey: string;
  roomId: string;
  /** Optional only so missing/pre-v3 messages can be rejected at runtime. */
  protocolVersion?: number;
}

export interface WebSocketMessageCandidateSend {
  type: "candidate";
  candidate: RTCIceCandidateInit | RTCIceCandidate;
  fromPeerId: string;
  toPeerId: string;
  roomId: string;
  protocolVersion: number;
}

export interface WebSocketMessageCandidateReceive {
  type: "candidate";
  candidate: RTCIceCandidateInit | RTCIceCandidate;
  fromPeerId: string;
  roomId: string;
  /** Optional only so missing/pre-v3 messages can be rejected at runtime. */
  protocolVersion?: number;
}

export interface WebSocketMessagePeersRequest {
  type: "peers";
  fromPeerId: string;
  roomId: string;
  protocolVersion: number;
}

export interface RoomPeer {
  id: string;
  publicKey: string;
}

export interface WebSocketMessagePeersResponse {
  type: "peers";
  roomId: string;
  peers: RoomPeer[];
  /** Optional only so missing/pre-v3 server responses fail closed at runtime. */
  protocolVersion?: number;
}

export interface WebSocketMessageConnectionRequest {
  type: "peerConnection";
  roomId: string;
  peer: RoomPeer;
  /** Optional only so missing/pre-v3 messages can be rejected at runtime. */
  protocolVersion?: number;
}

export interface WebSocketMessageConnectionResponse {
  type: "peerConnection";
  roomId: string;
  fromPeerId: string;
  toPeerId: string;
  protocolVersion: number;
}

export interface WebSocketMessagePeerConnectionRequest {
  type: "connection";
  roomId: string;
  fromPeerId: string;
  toPeerId: string;
  labels: string[];
  protocolVersion: number;
}

export interface WebSocketMessagePeerConnectionResponse {
  type: "connection";
  roomId: string;
  fromPeerId: string;
  fromPeerPublicKey: string;
  labels: string[];
  /** Optional only so a pre-v3/malformed server response can be rejected. */
  protocolVersion?: number;
}

export interface WebSocketPeerConnectionParams {
  peerId: string;
  peerPublicKey: string;
  roomId: string;
}

export interface WebSocketSendMessageToPeerParams {
  data: string | File;
  toChannel: string;
}

export interface WebSocketMessageError {
  type: "error";
  fromAction:
    | "ping"
    | "sendCandidate"
    | "receiveCandidate"
    | "sendDescription"
    | "receiveDescription"
    | "requestRoomId"
    | "requestPeerId"
    | "sendChallengeResponse";
  error:
    | Error
    | {
        message: string;
        [key: string]: unknown;
      };
}
