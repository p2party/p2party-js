import type { LibCrypto } from "../../cryptography/libcrypto";
import type { RatchetState } from "../../cryptography/ratchet";
import type { RatchetGateLease } from "../../handlers/ratchetGate";
import type { CoverRuntime } from "../../handlers/coverRuntime";
import type { SparsePqHealingState } from "../../handlers/pqHealingRuntime";

export interface IRTCPeerConnection extends RTCPeerConnection {
  /** The room this transport belongs to. A room/peer pair owns one PC. */
  roomId: string;
  withPeerId: string;
  withPeerPublicKey: string;
  makingOffer: boolean;
  ignoreOffer: boolean;
  receiveMessageModule: LibCrypto;
  iceCandidates: RTCIceCandidateInit[];
  /** Persistent control channel for this room/peer transport. */
  mainChannel?: IRTCDataChannel;
  /** Gate ownership captured when this concrete transport is created. */
  ratchetGateLease: RatchetGateLease;
  /** Resolves once the per-transport WASM dependency is ready. */
  initialization?: Promise<void>;
  // protocol-v3: live Double-Ratchet handle (never Redux; secrets stay off the
  // store). `ratchetEstablished` is the gate the `main` channel resolves.
  ratchetState?: RatchetState;
  ratchetEstablished?: Promise<void>;
  // protocol-v3 receive: per-EDGE per-message key cache (Stage-5 task 3). Keyed by
  // messageCacheKey(dhPub, N); the first-arriving chunk of a message derives +
  // caches its key (one ratchet step), every later chunk of that message reuses
  // it, and the entry is evicted after a complete channel's queued frames drain
  // (or immediately on cancel). Lives on the edge (not per-message channel)
  // because the ratchet it derives from is per-edge.
  messageKeyCache?: Map<string, Uint8Array>;
  /** Maps a live transfer root to its `(dhPub,N)` receive-cache key for cancel cleanup. */
  messageKeyByMerkleRoot?: Map<string, string>;
  /** All configured non-main channels, including connecting channels. */
  messageChannels?: Set<IRTCDataChannel>;
  /**
   * Protocol-v4 atomic edge checkpoint hook. The PQ runtime installs this
   * store-free serializer before the initial ratchet row is committed.
   */
  serializeEdgeCryptoState?: () => Uint8Array;
  /**
   * Protocol-v4 live sparse-PQ runtime for this authenticated edge. Installed
   * synchronously with `ratchetState` after the initial row (ratchet + PQ
   * checkpoint) is durable; destroyed with it on teardown/replacement.
   */
  pqHealingState?: SparsePqHealingState;
  /**
   * Protocol-v4 scheduled-cover runtime, present ONLY on edges of rooms whose
   * authenticated policy selects `coverMode: "scheduled"`. Its presence is the
   * scheduled-mode signal for the send/receive/receipt/cancel paths.
   */
  coverRuntime?: CoverRuntime;
}

export interface IRTCDataChannel extends RTCDataChannel {
  withPeerId: string;
  /** A data channel belongs to exactly one room. */
  roomIds: [string];
  /** Releases queue/channel accounting even when teardown nulls onclose. */
  releaseProtocolResources?: () => void;
  /**
   * Abort an inbound message pipeline, retire its persisted receive key, and
   * delete its storage artifacts after the active handler reaches quiescence.
   */
  cancelReceiveTransfer?: () => Promise<void>;
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
  roomId: string;
  withPeerId: string;
}

export interface RTCPeerConnectionParams {
  peerId: string;
  peerPublicKey: string;
  roomId: string;
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
  roomId: string;
  candidate: RTCIceCandidateInit | RTCIceCandidate;
}

export interface RTCOpenChannelParams {
  roomId: string;
  channel: string | RTCDataChannel;
  withPeers?: { peerId: string; peerPublicKey: string }[];
}

export interface RTCSendMessageParams {
  /** Random 32-byte lowercase-hex identity allocated by the public API. */
  transferId: string;
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
  /** When present, tear down only this room/peer transport. */
  roomId?: string;
  alsoDeleteData?: boolean;
}

export interface RTCDisconnectFromChannelLabelParams {
  roomId: string;
  label: string;
  messageHash?: Uint8Array;
  alsoDeleteData?: boolean;
  alsoSendFinishedMessage?: boolean;
}

export interface RTCDisconnectFromPeerChannelLabelParams {
  roomId: string;
  peerId: string;
  label: string;
  messageHash?: Uint8Array;
  alsoDeleteData?: boolean;
  alsoSendFinishedMessage?: boolean;
  /** Internal exact-object selector; prevents a stale callback closing a replacement. */
  channel?: IRTCDataChannel;
}
