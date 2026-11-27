export interface WebSocketMessagePingRequest {
  type: "ping";
}

export interface WebSocketMessagePongResponse {
  type: "pong";
  fromPeerId: string;
}

export interface WebSocketMessageLeaveRoomRequest {
  type: "leaveRoom";
  protocolVersion: 5;
  fromPeerId: string;
  roomLocator: string;
  roomLeaveId: string;
}

export interface WebSocketMessageRoomLeftResponse {
  type: "roomLeft";
  protocolVersion: 5;
  roomLocator: string;
  roomLeaveId: string;
}

export interface WebSocketMessageChallengeRequest {
  type: "authChallenge";
  challenge: string;
  protocolVersion: number;
}

export interface WebSocketMessageChallengeResponse {
  type: "challenge";
  challenge: string;
  signature: string;
  publicKey: string;
  protocolVersion: number;
}

export interface WebSocketMessageSuccessfulChallenge {
  type: "challenge";
  peerId: string;
  challengeId: string;
  protocolVersion: number;
}

export interface WebSocketMessageRoomIdRequest {
  type: "room";
  fromPeerId: string;
  roomLocator: string;
  /** Fresh request/response correlation nonce. Never reused across requests. */
  roomRequestId: string;
  protocolVersion: 5;
}

export interface TurnCredentials {
  urls: string[];
  username: string;
  credential: string;
  /**
   * Absolute TURN REST expiry. It must equal the timestamp prefix authenticated
   * inside `username`; carrying it explicitly lets clients schedule refresh
   * without interpreting an undocumented deployment convention.
   */
  expiresAtUnixSeconds: number;
}

export interface WebSocketMessageRoomIdResponse {
  type: "roomId";
  roomId: string;
  roomLocator: string;
  /** Exact echo of the request's fresh `roomRequestId`. */
  roomRequestId: string;
  turnCredentials?: TurnCredentials;
  protocolVersion: 5;
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
  rosterRequestId?: string;
  targetPeerIds?: string[];
}

export interface RoomPeer {
  id: string;
  publicKey: string;
  /** Per-socket generation from a generation-aware server; absent on 0.1.1. */
  socketGeneration?: string;
}

export interface WebSocketMessagePeersResponse {
  type: "peers";
  roomId: string;
  peers: RoomPeer[];
  /** Missing kind is the legacy accepted-peer delta. Snapshots are discovery only. */
  rosterKind?: "snapshot" | "delta";
  rosterRequestId?: string;
  /** Optional only so missing/pre-v3 server responses fail closed at runtime. */
  protocolVersion?: number;
}

export interface WebSocketMessageConnectionRequest {
  type: "peerConnection";
  roomId: string;
  /** The requester; `socketGeneration` names the socket that asked. */
  peer: RoomPeer;
  /** Optional only so missing/pre-v3 messages can be rejected at runtime. */
  protocolVersion?: number;
}

/** "left": the member sent leaveRoom. "offline": its last socket closed. */
export type PeerDepartureReason = "left" | "offline";

/**
 * The server's report that another member of a room left it or went offline.
 * Unauthenticated: the signaling server can send it about anyone, so it is a
 * hint that never closes a connected edge (handleWebSocketMessage).
 */
export interface WebSocketMessagePeerLeft {
  type: "peerLeft";
  roomId: string;
  peerId: string;
  reason: PeerDepartureReason;
  /**
   * The generation of the member's socket that left or closed. A departure
   * naming another generation than the one the server last named for that
   * member is about an earlier session and is ignored.
   */
  socketGeneration: string;
  /** Optional only so a missing version can be rejected at runtime. */
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
  /** The dialling peer's per-socket generation; absent on a 0.1.1 server. */
  fromPeerSocketGeneration?: string;
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
