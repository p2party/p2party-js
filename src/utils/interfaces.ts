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
  roomId: string;
}
