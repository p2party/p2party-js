export interface WebSocketMessageChallengeRequest {
  type: "peerId";
  peerId: string;
  challenge: string;
  message: string;
}

export interface WebSocketMessageChallengeResponse {
  type: "challenge";
  challenge: string;
  signature: string;
  fromPeerId: string;
}

export interface WebSocketMessageSuccessfulChallenge {
  type: "challenge";
  challengeId: string;
}

export interface WebSocketMessageRoomIdRequest {
  type: "room";
  fromPeerId: string;
  roomUrl: string;
}

export interface WebSocketMessageRoomIdResponse {
  type: "roomId";
  roomId: string;
  roomUrl: string;
}

export interface WebSocketMessageDescriptionSend {
  type: "description";
  description: RTCSessionDescription;
  fromPeerId: string;
  fromPeerPublicKey: string;
  toPeerId: string;
  roomId: string;
}

export interface WebSocketMessageDescriptionReceive {
  type: "description";
  description: RTCSessionDescription;
  fromPeerId: string;
  fromPeerPublicKey: string;
  roomId: string;
}

export interface WebSocketMessageCandidateSend {
  type: "candidate";
  candidate: RTCIceCandidate;
  fromPeerId: string;
  toPeerId: string;
  roomId: string;
}

export interface WebSocketMessageCandidateReceive {
  type: "candidate";
  candidate: RTCIceCandidate;
  fromPeerId: string;
  // fromPeerPublicKey: string;
  // roomId: string;
}

export interface WebSocketMessagePeersRequest {
  type: "peers";
  fromPeerId: string;
  roomId: string;
}

export interface RoomPeer {
  id: string;
  publicKey: string;
}

export interface WebSocketMessagePeersResponse {
  type: "peers";
  roomId: string;
  peers: RoomPeer[];
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
