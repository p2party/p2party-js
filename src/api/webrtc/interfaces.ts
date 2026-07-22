import type { LibCrypto } from "../../cryptography/libcrypto";
import type { RatchetState } from "../../cryptography/ratchet";
import type { RatchetSession } from "../../db/types";

export interface IRTCPeerConnectionRoomId {
  roomId: string;
  receiveMessageModule: LibCrypto;
}

export interface IRTCPeerConnection extends RTCPeerConnection {
  withPeerId: string;
  withPeerPublicKey: string;
  makingOffer: boolean;
  ignoreOffer: boolean;
  rooms: IRTCPeerConnectionRoomId[];
  iceCandidates: RTCIceCandidateInit[];
  // protocol-v3: live Double-Ratchet handle (never Redux; secrets stay off the
  // store). `session` is the last-persisted (wrapped) record; `ratchetEstablished`
  // is the per-peer gate promise (ratchetGate.ts) the `main` channel resolves.
  ratchetState?: RatchetState;
  session?: RatchetSession;
  ratchetEstablished?: Promise<void>;
}

export interface IRTCDataChannel extends RTCDataChannel {
  withPeerId: string;
  roomIds: string[];
}

export interface IRTCMessage {
  id: string;
  message: string;
  fromPeerId: string;
  toPeerId: string;
  channelLabel: string;
  timestamp: Date;
}

export interface IRTCIceCandidate extends RTCIceCandidateInit {
  withPeerId: string;
}

export interface RTCPeerConnectionParams {
  peerId: string;
  peerPublicKey: string;
  roomId: string;
  initiator?: boolean;
  rtcConfig?: RTCConfiguration;
}

export interface RTCSetDescriptionParams {
  peerId: string;
  peerPublicKey: string;
  roomId: string;
  description: RTCSessionDescription;
  rtcConfig?: RTCConfiguration;
}

export interface RTCSetCandidateParams {
  peerId: string;
  candidate: RTCIceCandidateInit | RTCIceCandidate;
}

export interface RTCOpenChannelParams {
  roomId: string;
  channel: string | RTCDataChannel;
  withPeers?: { peerId: string; peerPublicKey: string }[];
}

export interface RTCSendMessageParams {
  data: string | File;
  label: string;
  roomId: string;
  minChunks?: number;
  chunkSize?: number;
  percentageFilledChunk?: number;
  metadataSchemaVersion?: number;
}

export interface RTCRoomInfoParams {
  roomId: string;
}

export interface ChannelData {
  label: string;
  peerId: string;
}

export interface PeerData {
  peerId: string;
  peerPublicKey: string;
}

export interface MessageData extends IRTCMessage {
  channel: string;
}

export interface RoomData {
  roomId: string;
  peers: PeerData[];
  channels: ChannelData[];
  messages: MessageData[];
}

export interface RTCDisconnectParams {
  alsoDeleteDB: boolean;
}

export interface RTCDisconnectFromRoomParams {
  roomId: string;
  deleteMessages?: boolean;
}

export interface RTCDisconnectFromAllRoomsParams {
  deleteMessages?: boolean;
  exceptionRoomIds?: string[];
}

export interface RTCDisconnectFromPeerParams {
  peerId: string;
  alsoDeleteData?: boolean;
}

export interface RTCDisconnectFromChannelLabelParams {
  label: string;
  messageHash?: Uint8Array;
  alsoDeleteData?: boolean;
  alsoSendFinishedMessage?: boolean;
}

export interface RTCDisconnectFromPeerChannelLabelParams {
  peerId: string;
  label: string;
  messageHash?: Uint8Array;
  alsoDeleteData?: boolean;
  alsoSendFinishedMessage?: boolean;
  // Set by the completion path (handleReadReceipt got the final message-hash
  // receipt): the sender may free its newChunks. On a mid-transfer disconnect
  // this is absent, so newChunks are kept for resume-on-reconnect.
  transferComplete?: boolean;
}
