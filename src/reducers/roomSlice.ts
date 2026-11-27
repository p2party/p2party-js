import { createSlice } from "@reduxjs/toolkit";
import { isUUID } from "../utils/formatValidation";

import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";
import {
  DEFAULT_ROOM_POLICY_V1,
  canonicalizeRoomPolicyV1,
  roomPoliciesEqualV1,
} from "../roomPolicy";
import { MAX_ACTIVE_SIGNALING_ROOMS } from "../utils/constants";
import {
  MAX_DATA_CHANNEL_LABEL_CHARS,
  MAX_SIGNALING_ROOM_CHANNELS,
  MAX_SIGNALING_ROOM_PEERS,
} from "../utils/signalingBounds";

import {
  isRoomMember,
  notedPeerPresence,
  planPeerDeparture,
} from "../handlers/peerRosterDelta";

import type { PayloadAction } from "@reduxjs/toolkit";
import type { RoomPolicyV1 } from "../roomPolicy";
import type { CoverSchedulerStatus } from "../handlers/coverScheduler";
import type { PeerPresenceEvidence } from "../handlers/peerRosterDelta";
import type { PeerDepartureReason, TurnCredentials } from "../utils/interfaces";
// import type { MessageType } from "../utils/messageTypes";

export interface Channel {
  label: string;
  peerIds: string[];
}

export interface Peer {
  peerId: string;
  peerPublicKey: string;
}

export interface Message {
  /** Sender-only random identity for one logical outbound transfer. */
  transferId?: string;
  merkleRootHex: string;
  sha512Hex: string;
  fromPeerId: string;
  /** Identity recorded at receipt or local send. Absent on older history. */
  fromPeerPublicKey?: string;
  filename: string;
  messageType: number;
  savedSize: number;
  totalSize: number;
  chunksCreated: number;
  totalChunks: number;
  channelLabel: string;
  timestamp: number;
  // Telemetry (optional; let humans see the obfuscation + reliability):
  // frames processed incl. decoys, real chunks stored, sender retransmit rounds.
  // Progress % stays over the REAL message (savedSize / totalSize).
  chunksReceivedTotal?: number;
  chunksReceivedReal?: number;
  retransmits?: number;
}

export interface IncrementMessageStatsArgs {
  roomId: string;
  merkleRootHex?: string; // receiver matches by root
  sha512Hex?: string; // sender matches by message hash (root not known there)
  real?: boolean; // receiver: a real chunk was stored (else a decoy/other frame)
  retransmit?: boolean; // sender: a reconcile retransmit round happened
}

export interface SetRoomArgs {
  url: string;
  id: string;
  canBeConnectionRelay?: boolean;
  onlyConnectWithKnownPeers?: boolean;
  rtcConfig?: RTCConfiguration;
  /** Public/authenticated room settings only. PIN bytes never enter Redux. */
  policy?: RoomPolicyV1;
}

export interface SetRoomPolicyArgs {
  roomContext: string;
  policy: RoomPolicyV1;
}

export interface SetPeerArgs extends Peer {
  roomId: string;
}

export interface SetIceServersArgs {
  roomId: string;
  iceServers: RTCIceServer[];
}

export interface ApplyRoomResponseArgs {
  roomUrl: string;
  roomId: string;
  roomRequestId: string;
  requestGeneration: number;
  turnCredentials: TurnCredentials | null;
}

export interface ExpireRoomTurnCredentialsArgs {
  roomUrl: string;
  expiresAtUnixSeconds: number;
  requestGeneration: number;
}

export interface RollbackRoomResponseArgs {
  roomUrl: string;
  failedRoomId: string;
  failedRequestGeneration: number;
  previousRoomId: string;
  previousRequestGeneration: number;
  previousTurnCredentials: TurnCredentials | null;
  previousSignalingActive: boolean;
}

export interface SetMessageArgs {
  roomId: string;
  transferId?: string;
  merkleRootHex: string;
  sha512Hex: string;
  chunkSize: number;
  totalSize: number;
  chunksCreated?: number;
  totalChunks?: number;
  timestamp?: number;
  fromPeerId: string;
  /** Identity recorded at receipt or local send. Absent on older history. */
  fromPeerPublicKey?: string;
  filename: string;
  messageType: number;
  channelLabel: string;
}

export interface SetMessageAllChunksArgs {
  roomId: string;
  transferId?: string;
  merkleRootHex: string;
  sha512Hex: string;
  fromPeerId: string;
  /** Identity recorded at receipt or local send. Absent on older history. */
  fromPeerPublicKey?: string;
  filename: string;
  messageType: number;
  totalSize: number;
  channelLabel: string;
  timestamp: number;
  alsoSendFinishedMessage?: boolean;
}

export interface SetMessageDeliveredSizeArgs {
  roomId: string;
  merkleRootHex: string;
  sha512Hex: string;
  fromPeerId: string;
  deliveredSize: number;
}

export interface SetChannelArgs {
  roomId: string;
  peerId: string;
  label: string;
}

export interface ResetMessageReceiveProgressArgs {
  roomId: string;
  merkleRootHex: string;
}

export interface DeleteMessageArgs {
  roomId: string;
  transferId?: string;
  merkleRootHex?: string;
  hashHex?: string;
}

export interface DeleteChannelArgs {
  roomId?: string;
  peerId?: string;
  label?: string;
}

export interface SetCanOnlyConnectWithKnownPeers {
  roomId: string;
  roomUrl?: string;
  onlyConnectWithKnownPeers: boolean;
}

export interface SetPeerCoverStatusArgs {
  roomId: string;
  peerId: string;
  status: CoverSchedulerStatus;
}

/**
 * Why the authenticated edge is not (yet) up. "pin-mismatch" also covers a
 * differing room policy on a PIN room — the confirmation transcript cannot
 * distinguish them; "policy" is a nopin-room confirmation failure, which can
 * only be a policy/transcript mismatch.
 */
export type PeerHandshakeFailureReason =
  "pin-mismatch" | "pin-throttled" | "policy" | "transport";

export interface PeerHandshakeStatus {
  status: "authenticating" | "authenticated" | "failed";
  reason?: PeerHandshakeFailureReason;
  /** Absolute epoch ms after which a throttled PIN retry may succeed. */
  retryAfter?: number;
  /**
   * The stable identity this status describes, in the same hex spelling as
   * `Peer.peerPublicKey`. A peerId is a per-session signaling handle: a peer
   * that fails and reconnects arrives under a new one, and a joiner that fails
   * is dropped from `peers` altogether — so a UI that keys a failure on the
   * peerId either loses it or leaves a stale one on top of a working room.
   * The identity is what stays the same across both.
   *
   * Optional only because a status persisted by an older build has none.
   */
  peerPublicKey?: string;
}

/**
 * `peerPublicKey` is inherited as optional so a caller that only has a peerId
 * still compiles, but every in-library dispatch supplies it: the edge always
 * knows the identity it is authenticating against (`epc.withPeerPublicKey`).
 */
export interface SetPeerHandshakeStatusArgs extends PeerHandshakeStatus {
  roomId: string;
  peerId: string;
}

/**
 * What the signaling server last said about one room member's session. An
 * unauthenticated hint: it decides which members this client asks the server
 * to reintroduce, and never closes an edge.
 */
export interface PeerSignalingPresence {
  /** The member's socket generation the server last named in this room. */
  socketGeneration?: string;
  /**
   * A departure the server reported (`peerLeft`) that no later frame naming
   * the member has withdrawn. A departed member is not re-dialled.
   */
  departure?: PeerDepartureReason;
}

export interface NotePeerPresenceArgs {
  roomId: string;
  peerId: string;
  /** As the frame carried it; only a UUIDv4 is recorded. */
  socketGeneration?: unknown;
  evidence: PeerPresenceEvidence;
}

export interface PeerDepartedArgs {
  roomId: string;
  peerId: string;
  reason: PeerDepartureReason;
  socketGeneration: string;
  /** Whether this client holds a connected edge to the peer in this room. */
  edgeConnected: boolean;
}

/**
 * Forget a member: roster entry, snapshot entry, presence, cover status and
 * any non-failed handshake status (a failed one is kept, as deletePeer keeps
 * it). Channels belong to the transport and go with its teardown.
 */
const removeRoomMember = (room: Room, peerId: string): void => {
  const peerIndex = room.peers.findIndex((peer) => peer.peerId === peerId);
  if (peerIndex > -1) room.peers.splice(peerIndex, 1);
  const knownIndex =
    room.knownPeers?.findIndex((peer) => peer.peerId === peerId) ?? -1;
  if (knownIndex > -1) room.knownPeers!.splice(knownIndex, 1);
  if (room.peerPresence) delete room.peerPresence[peerId];
  if (room.coverStatusByPeer) delete room.coverStatusByPeer[peerId];
  if (
    room.handshakeStatusByPeer &&
    room.handshakeStatusByPeer[peerId]?.status !== "failed"
  )
    delete room.handshakeStatusByPeer[peerId];
};

/** Presence is kept only for tracked members, so it is bounded with them. */
const prunePeerPresence = (room: Room): void => {
  if (!room.peerPresence) return;
  for (const peerId of Object.keys(room.peerPresence))
    if (!isRoomMember(room, peerId)) delete room.peerPresence[peerId];
};

export interface Room extends SetRoomArgs {
  policy: RoomPolicyV1;
  connectingToPeers: boolean;
  connectedToPeers: boolean;
  canBeConnectionRelay: boolean;
  onlyConnectWithKnownAddresses: boolean;
  /** Caller-owned configuration. Signaling credentials never mutate it. */
  callerRtcConfig?: RTCConfiguration;
  /** Current signaling-owned TURN bundle, replaced atomically per response. */
  signalingTurnCredentials?: TurnCredentials | null;
  /** Compatibility projection derived from the two authoritative inputs. */
  rtcConfig: RTCConfiguration;
  /** Last accepted wire-correlated response generation for this room URL. */
  roomResponseGeneration?: number;
  /** False after deleteRoom so retained room metadata is not auto-rejoined. */
  signalingActive?: boolean;
  peers: Peer[];
  /** Eligible signaling membership, independent of currently retained transports. */
  knownPeers?: Peer[];
  /**
   * Per tracked member (peerId): the socket generation the server last named
   * and a departure it reported (`peerLeft`). Only members on `peers` or
   * `knownPeers` have an entry.
   */
  peerPresence?: Record<string, PeerSignalingPresence>;
  channels: Channel[];
  messages: Message[];
  /**
   * protocol-v4: live scheduled-cover status per authenticated peer edge
   * (peerId → status). Absent means no cover claim may ever be made for that
   * edge — only an explicit "active" from the runtime is a cover claim, so a
   * browser gap ("suspended") or teardown ("stopped") is always visible.
   */
  coverStatusByPeer?: Record<string, CoverSchedulerStatus>;
  /**
   * Live authenticated-handshake state per peer edge (peerId → status), so a
   * UI can distinguish "still authenticating" from "PIN did not match" from
   * "PIN retries throttled until T" instead of showing an eternal
   * waiting-for-peers state.
   */
  handshakeStatusByPeer?: Record<string, PeerHandshakeStatus>;
}

/** Fully normalized reducer state; public Room keeps new fields optional. */
export interface ManagedRoom extends Room {
  callerRtcConfig: RTCConfiguration;
  signalingTurnCredentials: TurnCredentials | null;
  roomResponseGeneration: number;
  signalingActive: boolean;
}

export const defaultRTCConfig = {
  iceServers: [
    {
      // Use single STUN URL - multiple STUN servers slow down ICE gathering
      urls: "stun:stun.p2party.com:3478",
    },
    // No TURN entry here on purpose: relay credentials are short-lived and
    // bound to this client's identity, so they cannot be a static default.
    // The signaling server issues them with the room response and
    // handleWebSocketMessage merges them into this config. Without a
    // configured relay the client stays STUN-only, which cannot traverse
    // symmetric or carrier-grade NAT.
  ],
  iceTransportPolicy: "all",
  // Pre-allocate ICE candidates for faster connection setup
  iceCandidatePoolSize: 2,
} as RTCConfiguration;

const iceServerUrls = (server: RTCIceServer): string[] =>
  Array.isArray(server.urls) ? [...server.urls] : [server.urls];

const cloneIceServer = (server: RTCIceServer): RTCIceServer => ({
  ...server,
  urls: Array.isArray(server.urls) ? [...server.urls] : server.urls,
});

export const cloneRTCConfiguration = (
  configuration: RTCConfiguration,
): RTCConfiguration => ({
  ...configuration,
  iceServers: configuration.iceServers?.map(cloneIceServer),
  certificates: configuration.certificates
    ? [...configuration.certificates]
    : configuration.certificates,
});

const stringArraysEqual = (
  left: readonly string[],
  right: readonly string[],
): boolean =>
  left.length === right.length &&
  left.every((value, index) => value === right[index]);

export const rtcConfigurationsEqual = (
  left: RTCConfiguration,
  right: RTCConfiguration,
): boolean => {
  if (
    left.bundlePolicy !== right.bundlePolicy ||
    left.iceCandidatePoolSize !== right.iceCandidatePoolSize ||
    left.iceTransportPolicy !== right.iceTransportPolicy ||
    left.rtcpMuxPolicy !== right.rtcpMuxPolicy
  )
    return false;
  const leftCertificates = left.certificates ?? [];
  const rightCertificates = right.certificates ?? [];
  if (
    leftCertificates.length !== rightCertificates.length ||
    leftCertificates.some(
      (certificate, index) => certificate !== rightCertificates[index],
    )
  )
    return false;
  const leftServers = left.iceServers ?? [];
  const rightServers = right.iceServers ?? [];
  if (leftServers.length !== rightServers.length) return false;
  return leftServers.every((server, index) => {
    const other = rightServers[index];
    if (
      server.username !== other.username ||
      server.credential !== other.credential
    )
      return false;
    const urls = iceServerUrls(server);
    const otherUrls = iceServerUrls(other);
    return stringArraysEqual(urls, otherUrls);
  });
};

/**
 * Replace credentials only for endpoints present in an incoming ICE server.
 *
 * This preserves every unrelated caller-supplied STUN/TURN entry and every
 * non-ICE RTCConfiguration option. Replacing overlapping URLs is required:
 * TURN REST credentials expire, so retaining the first credential for a URL
 * would make a later authenticated room join silently keep stale access.
 */
export const mergeIceServers = (
  existing: readonly RTCIceServer[] | undefined,
  incoming: readonly RTCIceServer[],
): RTCIceServer[] => {
  let merged = (existing ?? []).map(cloneIceServer);

  for (const replacement of incoming) {
    const replacementUrls = new Set(iceServerUrls(replacement));
    const retained: RTCIceServer[] = [];

    for (const current of merged) {
      const currentUrls = iceServerUrls(current);
      const remainingUrls = currentUrls.filter(
        (url) => !replacementUrls.has(url),
      );
      if (remainingUrls.length === 0) continue;
      retained.push({
        ...current,
        urls: Array.isArray(current.urls) ? remainingUrls : remainingUrls[0],
      });
    }

    retained.push(cloneIceServer(replacement));
    merged = retained;
  }

  return merged;
};

/**
 * Derive the browser configuration from two single-source inputs.
 *
 * A managed URL replaces an overlapping caller URL only in this projection.
 * Clearing the managed bundle therefore restores the caller's exact input,
 * while rotation cannot accidentally retain an older signaling credential.
 */
export const deriveEffectiveRTCConfig = (
  callerRtcConfig: RTCConfiguration,
  signalingTurnCredentials: TurnCredentials | null,
): RTCConfiguration => {
  const effective = cloneRTCConfiguration(callerRtcConfig);
  if (!signalingTurnCredentials) return effective;

  const managed: RTCIceServer = {
    urls: Array.isArray(signalingTurnCredentials.urls)
      ? [...signalingTurnCredentials.urls]
      : signalingTurnCredentials.urls,
    username: signalingTurnCredentials.username,
    credential: signalingTurnCredentials.credential,
  };
  effective.iceServers = mergeIceServers(effective.iceServers, [managed]);
  return effective;
};

const freshCallerRTCConfig = (
  rtcConfig: RTCConfiguration | undefined,
): RTCConfiguration => cloneRTCConfiguration(rtcConfig ?? defaultRTCConfig);

const updateCallerRTCConfig = (
  room: ManagedRoom,
  rtcConfig: RTCConfiguration,
): void => {
  room.callerRtcConfig = cloneRTCConfiguration(rtcConfig);
  room.rtcConfig = deriveEffectiveRTCConfig(
    room.callerRtcConfig,
    room.signalingTurnCredentials,
  );
};

const initialState: ManagedRoom[] = [];

const assertRoomPolicyUnchanged = (
  current: RoomPolicyV1,
  requested: RoomPolicyV1,
): void => {
  const candidate = canonicalizeRoomPolicyV1(requested);
  if (!roomPoliciesEqualV1(current, candidate))
    throw new Error("roomSlice: room policy is immutable after creation");
};

const assertRoomActivationCapacity = (
  rooms: readonly { signalingActive?: boolean }[],
  roomIndex: number,
): void => {
  const transitionsToActive =
    roomIndex === -1 || rooms[roomIndex].signalingActive === false;
  if (
    transitionsToActive &&
    rooms.filter((room) => room.signalingActive !== false).length >=
      MAX_ACTIVE_SIGNALING_ROOMS
  )
    throw new Error(
      `roomSlice: cannot activate more than ${String(MAX_ACTIVE_SIGNALING_ROOMS)} rooms`,
    );
};

const deleteMessageFromState = <T extends { id: string; messages: Message[] }>(
  state: T[],
  { roomId, transferId, merkleRootHex, hashHex }: DeleteMessageArgs,
): void => {
  if (!transferId && !merkleRootHex && !hashHex) return;
  if (transferId && !/^[0-9a-f]{64}$/.test(transferId)) return;
  if (merkleRootHex && merkleRootHex.length !== crypto_hash_sha512_BYTES * 2)
    return;
  if (hashHex && hashHex.length !== crypto_hash_sha512_BYTES * 2) return;

  const roomIndex = state.findIndex((room) => room.id === roomId);
  if (roomIndex === -1) return;

  if (transferId) {
    const messageIndex = state[roomIndex].messages.findIndex(
      (message) => message.transferId === transferId,
    );
    if (messageIndex > -1) state[roomIndex].messages.splice(messageIndex, 1);
  } else if (merkleRootHex) {
    const messageIndex = state[roomIndex].messages.findIndex(
      (message) => message.merkleRootHex === merkleRootHex,
    );
    if (messageIndex > -1) state[roomIndex].messages.splice(messageIndex, 1);
  } else if (hashHex) {
    const messageIndex = state[roomIndex].messages.findLastIndex(
      (message) => message.sha512Hex === hashHex,
    );
    if (messageIndex > -1) state[roomIndex].messages.splice(messageIndex, 1);
  }
};

const roomSlice = createSlice({
  name: "rooms",
  initialState,
  reducers: {
    setRoom: (state, action: PayloadAction<SetRoomArgs>) => {
      const {
        url,
        id,
        canBeConnectionRelay,
        rtcConfig,
        onlyConnectWithKnownPeers,
        policy,
      } = action.payload;

      if (/^[0-9a-f]{64}$/.test(url) && isUUID(id)) {
        const roomIndex = state.findIndex((r) => r.url === url);
        const collidingRoom = state.findIndex(
          (room) => room.url !== url && room.id === id,
        );
        if (collidingRoom > -1) return;
        assertRoomActivationCapacity(state, roomIndex);

        if (roomIndex > -1) {
          state[roomIndex].callerRtcConfig ??= cloneRTCConfiguration(
            state[roomIndex].rtcConfig ?? defaultRTCConfig,
          );
          state[roomIndex].signalingTurnCredentials ??= null;
          state[roomIndex].roomResponseGeneration ??= 0;
          if (policy)
            assertRoomPolicyUnchanged(state[roomIndex].policy, policy);
          state[roomIndex].url = url;
          state[roomIndex].id = id;
          state[roomIndex].signalingActive = true;
          if (canBeConnectionRelay != undefined)
            state[roomIndex].canBeConnectionRelay = canBeConnectionRelay;
          if (rtcConfig) updateCallerRTCConfig(state[roomIndex], rtcConfig);
          if (onlyConnectWithKnownPeers != undefined) {
            state[roomIndex].onlyConnectWithKnownAddresses =
              onlyConnectWithKnownPeers;
          } else {
            state[roomIndex].onlyConnectWithKnownAddresses =
              localStorage.getItem(url + "-onlyConnectWithKnownPeers") ===
              "true";
          }
        } else {
          const callerRtcConfig = freshCallerRTCConfig(rtcConfig);
          state.push({
            url,
            id,
            connectingToPeers: false,
            connectedToPeers: false,
            canBeConnectionRelay: canBeConnectionRelay ?? true,
            onlyConnectWithKnownAddresses:
              onlyConnectWithKnownPeers ??
              localStorage.getItem(url + "-onlyConnectWithKnownPeers") ===
                "true",
            callerRtcConfig,
            signalingTurnCredentials: null,
            rtcConfig: deriveEffectiveRTCConfig(callerRtcConfig, null),
            roomResponseGeneration: 0,
            signalingActive: true,
            policy: canonicalizeRoomPolicyV1(policy ?? DEFAULT_ROOM_POLICY_V1),
            peers: [],
            channels: [],
            messages: [],
          });
        }
      } else if (/^[0-9a-f]{64}$/.test(url)) {
        const roomIndex = state.findIndex((r) => r.url === url);
        assertRoomActivationCapacity(state, roomIndex);

        if (roomIndex > -1) {
          state[roomIndex].callerRtcConfig ??= cloneRTCConfiguration(
            state[roomIndex].rtcConfig ?? defaultRTCConfig,
          );
          state[roomIndex].signalingTurnCredentials ??= null;
          state[roomIndex].roomResponseGeneration ??= 0;
          if (policy)
            assertRoomPolicyUnchanged(state[roomIndex].policy, policy);
          state[roomIndex].url = url;
          state[roomIndex].id = "";
          state[roomIndex].signalingActive = true;
          if (canBeConnectionRelay != undefined)
            state[roomIndex].canBeConnectionRelay = canBeConnectionRelay;
          if (rtcConfig) updateCallerRTCConfig(state[roomIndex], rtcConfig);
          if (onlyConnectWithKnownPeers != undefined) {
            state[roomIndex].onlyConnectWithKnownAddresses =
              onlyConnectWithKnownPeers;
          } else {
            state[roomIndex].onlyConnectWithKnownAddresses =
              localStorage.getItem(url + "-onlyConnectWithKnownPeers") ===
              "true";
          }
        } else {
          const callerRtcConfig = freshCallerRTCConfig(rtcConfig);
          state.push({
            url,
            id: "",
            connectingToPeers: false,
            connectedToPeers: false,
            canBeConnectionRelay: canBeConnectionRelay ?? true,
            onlyConnectWithKnownAddresses:
              onlyConnectWithKnownPeers ??
              localStorage.getItem(url + "-onlyConnectWithKnownPeers") ===
                "true",
            callerRtcConfig,
            signalingTurnCredentials: null,
            rtcConfig: deriveEffectiveRTCConfig(callerRtcConfig, null),
            roomResponseGeneration: 0,
            signalingActive: true,
            policy: canonicalizeRoomPolicyV1(policy ?? DEFAULT_ROOM_POLICY_V1),
            peers: [],
            channels: [],
            messages: [],
          });
        }
      }
    },

    applyRoomResponse: (
      state,
      action: PayloadAction<ApplyRoomResponseArgs>,
    ) => {
      const {
        roomUrl,
        roomId,
        roomRequestId,
        requestGeneration,
        turnCredentials,
      } = action.payload;
      if (
        !/^[0-9a-f]{64}$/.test(roomUrl) ||
        !isUUID(roomId) ||
        !isUUID(roomRequestId, 4) ||
        !Number.isSafeInteger(requestGeneration) ||
        requestGeneration <= 0
      )
        return;

      const roomIndex = state.findIndex((room) => room.url === roomUrl);
      if (roomIndex === -1) return;
      const room = state[roomIndex];
      if (
        room.signalingActive === false ||
        requestGeneration <= (room.roomResponseGeneration ?? 0) ||
        (isUUID(room.id) && room.id !== roomId) ||
        state.some(
          (candidate, index) => index !== roomIndex && candidate.id === roomId,
        )
      )
        return;

      room.id = roomId;
      room.signalingTurnCredentials = turnCredentials
        ? {
            ...turnCredentials,
            urls: Array.isArray(turnCredentials.urls)
              ? [...turnCredentials.urls]
              : turnCredentials.urls,
          }
        : null;
      room.rtcConfig = deriveEffectiveRTCConfig(
        room.callerRtcConfig,
        room.signalingTurnCredentials,
      );
      room.roomResponseGeneration = requestGeneration;
    },

    rollbackRoomResponse: (
      state,
      action: PayloadAction<RollbackRoomResponseArgs>,
    ) => {
      const room = state.find(
        (candidate) => candidate.url === action.payload.roomUrl,
      );
      if (
        !room ||
        room.id !== action.payload.failedRoomId ||
        room.roomResponseGeneration !== action.payload.failedRequestGeneration
      )
        return;
      room.id = action.payload.previousRoomId;
      room.roomResponseGeneration = action.payload.previousRequestGeneration;
      room.signalingActive = action.payload.previousSignalingActive;
      const previous = action.payload.previousTurnCredentials;
      room.signalingTurnCredentials = previous
        ? {
            ...previous,
            urls: [...previous.urls],
          }
        : null;
      room.rtcConfig = deriveEffectiveRTCConfig(
        room.callerRtcConfig,
        room.signalingTurnCredentials,
      );
    },

    expireRoomTurnCredentials: (
      state,
      action: PayloadAction<ExpireRoomTurnCredentialsArgs>,
    ) => {
      const room = state.find(
        (candidate) => candidate.url === action.payload.roomUrl,
      );
      if (
        !room ||
        room.roomResponseGeneration !== action.payload.requestGeneration ||
        room.signalingTurnCredentials?.expiresAtUnixSeconds !==
          action.payload.expiresAtUnixSeconds
      )
        return;
      room.signalingTurnCredentials = null;
      room.rtcConfig = deriveEffectiveRTCConfig(room.callerRtcConfig, null);
    },

    setRoomPolicy: (state, action: PayloadAction<SetRoomPolicyArgs>) => {
      const roomIndex = state.findIndex(
        (room) =>
          room.url === action.payload.roomContext ||
          room.id === action.payload.roomContext,
      );
      if (roomIndex > -1)
        assertRoomPolicyUnchanged(
          state[roomIndex].policy,
          action.payload.policy,
        );
    },

    setConnectingToPeers: (
      state,
      action: PayloadAction<{
        roomId: string;
        connectingToPeers: boolean;
        // Read by roomListenerMiddleware only, to pick the debounce budget: a
        // "redial" after an edge teardown and a "reconcile" of a room that has
        // nobody in it each have their own, independent of a room join.
        reason?: "redial" | "reconcile";
        /** A per-member retry; the listener batches concurrent targets. */
        peerId?: string;
      }>,
    ) => {
      const { roomId, connectingToPeers } = action.payload;

      const roomIndex = state.findIndex((r) => r.id === roomId);

      if (roomIndex > -1)
        state[roomIndex].connectingToPeers = connectingToPeers;
    },

    setConnectedToPeers: (
      state,
      action: PayloadAction<{ roomId: string; connectedToPeers: boolean }>,
    ) => {
      const { roomId, connectedToPeers } = action.payload;

      const roomIndex = state.findIndex((r) => r.id === roomId);

      if (roomIndex > -1) {
        state[roomIndex].connectingToPeers = false;
        state[roomIndex].connectedToPeers = connectedToPeers;
      }
    },

    setConnectionRelay: (
      state,
      action: PayloadAction<{ roomId: string; canBeConnectionRelay: boolean }>,
    ) => {
      const { roomId, canBeConnectionRelay } = action.payload;

      const roomIndex = state.findIndex((r) => r.id === roomId);

      if (roomIndex > -1)
        state[roomIndex].canBeConnectionRelay = canBeConnectionRelay;
    },

    setKnownRoomPeers: (
      state,
      action: PayloadAction<{ roomId: string; peers: Peer[] }>,
    ) => {
      const room = state.find(
        (r) => r.id === action.payload.roomId && r.signalingActive !== false,
      );
      if (room && action.payload.peers.length <= MAX_SIGNALING_ROOM_PEERS) {
        room.knownPeers = action.payload.peers.map((peer) => ({ ...peer }));
        prunePeerPresence(room);
      }
    },

    /**
     * A server frame named a member (handleWebSocketMessage): record the
     * socket generation it carried and withdraw a departure it answers
     * (notedPeerPresence). Untracked peers get no entry.
     */
    notePeerPresence: (state, action: PayloadAction<NotePeerPresenceArgs>) => {
      const { roomId, peerId, socketGeneration, evidence } = action.payload;
      const room = state.find(
        (r) => r.id === roomId && r.signalingActive !== false,
      );
      if (!room || !isRoomMember(room, peerId)) return;
      room.peerPresence ??= {};
      room.peerPresence[peerId] = notedPeerPresence(
        room.peerPresence[peerId],
        socketGeneration,
        evidence,
      );
    },

    /**
     * The server reported that a member left the room or went offline
     * (`peerLeft`). Applies planPeerDeparture: a report about an earlier
     * session or an untracked peer changes nothing; "left" without a
     * connected edge drops the member; anything else only marks it, and
     * never touches its edge.
     */
    peerDeparted: (state, action: PayloadAction<PeerDepartedArgs>) => {
      const { roomId, peerId, reason, socketGeneration, edgeConnected } =
        action.payload;
      const room = state.find(
        (r) => r.id === roomId && r.signalingActive !== false,
      );
      if (!room) return;
      // Self never appears among a room's members, so no self id is needed.
      const verdict = planPeerDeparture(
        room,
        { peerId, reason, socketGeneration },
        "",
        edgeConnected,
      );
      if (verdict === "ignore") return;
      if (verdict === "remove") {
        removeRoomMember(room, peerId);
        return;
      }
      room.peerPresence ??= {};
      room.peerPresence[peerId] = { socketGeneration, departure: reason };
    },

    setPeer: (state, action: PayloadAction<SetPeerArgs>) => {
      const { roomId, peerId, peerPublicKey } = action.payload;

      const roomIndex = state.findIndex((r) => r.id === roomId);

      if (roomIndex > -1) {
        const peerIndex = state[roomIndex].peers.findIndex(
          (peer) =>
            peer.peerId === peerId || peer.peerPublicKey === peerPublicKey,
        );

        if (
          peerIndex === -1 &&
          state[roomIndex].peers.length < MAX_SIGNALING_ROOM_PEERS
        )
          state[roomIndex].peers.push({ peerId, peerPublicKey });
        // Once a snapshot established membership, an accepted introduction is
        // a new member too. Removing a transport must not erase this knowledge.
        const known = state[roomIndex].knownPeers;
        if (
          known &&
          known.length < MAX_SIGNALING_ROOM_PEERS &&
          !known.some(
            (peer) =>
              peer.peerId === peerId || peer.peerPublicKey === peerPublicKey,
          )
        )
          known.push({ peerId, peerPublicKey });
      }
    },

    deletePeer: (
      state,
      action: PayloadAction<{ peerId: string; roomId?: string }>,
    ) => {
      const roomsLen = state.length;
      for (let i = 0; i < roomsLen; i++) {
        if (
          action.payload.roomId !== undefined &&
          state[i].id !== action.payload.roomId
        )
          continue;
        const peerIndex = state[i].peers.findIndex(
          (p) => p.peerId === action.payload.peerId,
        );

        if (peerIndex > -1) state[i].peers.splice(peerIndex, 1);
        // The edge of a member the server reported as left is gone: the
        // member goes too, so nothing re-dials it. An "offline" member stays
        // in the snapshot with its mark, and is not re-dialled either until
        // a server frame names it again.
        if (
          state[i].peerPresence?.[action.payload.peerId]?.departure === "left"
        ) {
          const knownIndex =
            state[i].knownPeers?.findIndex(
              (p) => p.peerId === action.payload.peerId,
            ) ?? -1;
          if (knownIndex > -1) state[i].knownPeers!.splice(knownIndex, 1);
        }
        prunePeerPresence(state[i]);
        const coverStatusByPeer = state[i].coverStatusByPeer;
        if (coverStatusByPeer) delete coverStatusByPeer[action.payload.peerId];
        // A FAILED handshake must outlive the peer it describes: the edge is
        // torn down immediately after the failure, and dropping the reason
        // here would leave a UI with a vanished peer and no explanation —
        // exactly the silent-failure case this state exists to remove. A
        // later authenticating/authenticated report overwrites it.
        const handshakeStatusByPeer = state[i].handshakeStatusByPeer;
        if (
          handshakeStatusByPeer &&
          handshakeStatusByPeer[action.payload.peerId]?.status !== "failed"
        )
          delete handshakeStatusByPeer[action.payload.peerId];
      }
    },

    setPeerCoverStatus: (
      state,
      action: PayloadAction<SetPeerCoverStatusArgs>,
    ) => {
      const { roomId, peerId, status } = action.payload;

      const roomIndex = state.findIndex((r) => r.id === roomId);

      if (roomIndex > -1) {
        const room = state[roomIndex];
        room.callerRtcConfig ??= cloneRTCConfiguration(
          room.rtcConfig ?? defaultRTCConfig,
        );
        room.coverStatusByPeer ??= {};
        room.coverStatusByPeer[peerId] = status;
      }
    },

    /** Explicit connect() retry; ordinary signaling refreshes never clear failures. */
    clearPeerHandshakeFailures: (state, action: PayloadAction<string>) => {
      const room = state.find((candidate) => candidate.url === action.payload);
      if (!room?.handshakeStatusByPeer) return;
      for (const [peerId, status] of Object.entries(room.handshakeStatusByPeer))
        if (status.status === "failed")
          delete room.handshakeStatusByPeer[peerId];
    },

    /**
     * A transport generation of this edge was torn down: an "authenticating"
     * or "authenticated" status described a transport that no longer exists,
     * so a peer whose replacement never authenticates is not shown as
     * authenticated. A failed status stays, exactly as deletePeer keeps it,
     * and the roster entry is left alone.
     */
    clearPeerHandshakeStatus: (
      state,
      action: PayloadAction<{ roomId: string; peerId: string }>,
    ) => {
      const { roomId, peerId } = action.payload;
      const statuses = state.find(
        (room) => room.id === roomId,
      )?.handshakeStatusByPeer;
      if (statuses && statuses[peerId]?.status !== "failed")
        delete statuses[peerId];
    },

    allowPeerHandshakeRetry: (state, action: PayloadAction<SetPeerArgs>) => {
      const { roomId, peerId, peerPublicKey } = action.payload;
      const room = state.find((candidate) => candidate.id === roomId);
      if (!room?.handshakeStatusByPeer) return;
      for (const [failedPeerId, status] of Object.entries(
        room.handshakeStatusByPeer,
      ))
        if (
          status.status === "failed" &&
          (status.peerPublicKey === peerPublicKey ||
            (status.peerPublicKey === undefined && failedPeerId === peerId))
        )
          delete room.handshakeStatusByPeer[failedPeerId];
    },

    setPeerHandshakeStatus: (
      state,
      action: PayloadAction<SetPeerHandshakeStatusArgs>,
    ) => {
      const { roomId, peerId, status, reason, retryAfter, peerPublicKey } =
        action.payload;

      const roomIndex = state.findIndex((r) => r.id === roomId);

      if (roomIndex > -1) {
        const room = state[roomIndex];
        room.handshakeStatusByPeer ??= {};
        room.handshakeStatusByPeer[peerId] = {
          status,
          reason,
          retryAfter,
          peerPublicKey,
        };
      }
    },

    setChannel: (state, action: PayloadAction<SetChannelArgs>) => {
      const { roomId, label, peerId } = action.payload;
      if (label.length === 0 || label.length > MAX_DATA_CHANNEL_LABEL_CHARS)
        return;

      const roomIndex = state.findIndex((r) => r.id === roomId);

      if (roomIndex > -1) {
        const channelIndex = state[roomIndex].channels.findIndex(
          (c) => c.label === label,
        );

        if (channelIndex > -1) {
          const peerIndex = state[roomIndex].channels[
            channelIndex
          ].peerIds.findIndex((p) => p === peerId);

          if (
            peerIndex === -1 &&
            state[roomIndex].channels[channelIndex].peerIds.length <
              MAX_SIGNALING_ROOM_PEERS
          ) {
            state[roomIndex].channels[channelIndex].peerIds.push(peerId);
          }
        } else if (
          state[roomIndex].channels.length < MAX_SIGNALING_ROOM_CHANNELS
        ) {
          state[roomIndex].channels.push({
            label: label,
            peerIds: [peerId],
          });
        }
      }
    },

    deleteChannel: (state, action: PayloadAction<DeleteChannelArgs>) => {
      const { roomId, peerId, label } = action.payload;

      const roomsLen = state.length;
      for (let i = 0; i < roomsLen; i++) {
        if (roomId !== undefined && state[i].id !== roomId) continue;
        if (label && !peerId) {
          const channelIndex = state[i].channels.findIndex(
            (c) => c.label === label,
          );

          if (channelIndex > -1) state[i].channels.splice(channelIndex, 1);
        } else if (!label && peerId) {
          for (let j = state[i].channels.length - 1; j >= 0; j--) {
            const peerIndex = state[i].channels[j].peerIds.findIndex(
              (p) => p === peerId,
            );

            if (peerIndex > -1) {
              state[i].channels[j].peerIds.splice(peerIndex, 1);

              if (state[i].channels[j].peerIds.length === 0) {
                state[i].channels.splice(j, 1);
              }
            }
          }
        } else if (peerId && label) {
          const channelIndex = state[i].channels.findIndex(
            (c) => c.label === label && c.peerIds.includes(peerId),
          );

          if (channelIndex > -1) {
            const peerIndex = state[i].channels[channelIndex].peerIds.findIndex(
              (p) => p === peerId,
            );

            state[i].channels[channelIndex].peerIds.splice(peerIndex, 1);

            if (state[i].channels[channelIndex].peerIds.length === 0) {
              state[i].channels.splice(channelIndex, 1);
            }
          }
        }
      }
    },

    setIceServers: (state, action: PayloadAction<SetIceServersArgs>) => {
      const { roomId, iceServers } = action.payload;

      const roomIndex = state.findIndex((r) => r.id === roomId);

      if (roomIndex > -1) {
        const room = state[roomIndex];
        room.callerRtcConfig.iceServers = mergeIceServers(
          room.callerRtcConfig.iceServers,
          iceServers,
        );
        room.rtcConfig = deriveEffectiveRTCConfig(
          room.callerRtcConfig,
          room.signalingTurnCredentials,
        );
      }
    },

    setMessage: (state, action: PayloadAction<SetMessageArgs>) => {
      const {
        roomId,
        transferId,
        merkleRootHex,
        sha512Hex,
        filename,
        channelLabel,
        fromPeerId,
        fromPeerPublicKey,
        messageType,
        chunkSize,
        totalSize,
        chunksCreated,
        totalChunks,
        timestamp,
      } = action.payload;

      const roomIndex = state.findIndex((r) => r.id === roomId);

      if (roomIndex > -1) {
        const messageIndex = state[roomIndex].messages.findLastIndex(
          (m) =>
            (transferId !== undefined
              ? m.transferId === transferId
              : m.merkleRootHex === merkleRootHex) ||
            (transferId === undefined &&
              m.sha512Hex === sha512Hex &&
              m.merkleRootHex.length === 0),
        );

        if (messageIndex === -1) {
          if (
            channelLabel &&
            fromPeerId &&
            isUUID(fromPeerId) &&
            messageType &&
            // chunkSize > 0 &&
            totalSize
          ) {
            state[roomIndex].messages.push({
              transferId,
              merkleRootHex,
              sha512Hex,
              channelLabel,
              filename: filename.length > 0 ? filename : "txt",
              messageType,
              fromPeerId,
              fromPeerPublicKey,
              timestamp: timestamp ?? Date.now(),
              savedSize: chunkSize > 0 ? chunkSize : 0,
              totalSize,
              chunksCreated: chunksCreated ?? 0,
              totalChunks: totalChunks ?? 0,
            });
          }
        } else if (
          // state[roomIndex].messages[messageIndex].merkleRootHex.length === 0 &&
          state[roomIndex].messages[messageIndex].timestamp !== timestamp &&
          // Same message at different time
          // state[roomIndex].messages[messageIndex].merkleRootHex !==
          //   merkleRootHex &&
          state[roomIndex].messages[messageIndex].sha512Hex === sha512Hex &&
          state[roomIndex].messages[messageIndex].savedSize ===
            state[roomIndex].messages[messageIndex].totalSize
        ) {
          state[roomIndex].messages.push({
            transferId,
            merkleRootHex,
            sha512Hex,
            channelLabel,
            filename: filename.length > 0 ? filename : "txt",
            messageType,
            fromPeerId,
            fromPeerPublicKey,
            timestamp: timestamp ?? Date.now(),
            savedSize: chunkSize,
            totalSize,
            chunksCreated: chunksCreated ?? 0,
            totalChunks: totalChunks ?? 0,
          });
        } else {
          if (
            merkleRootHex.length === crypto_hash_sha512_BYTES * 2 &&
            state[roomIndex].messages[messageIndex].merkleRootHex === ""
          ) {
            state[roomIndex].messages[messageIndex].merkleRootHex =
              merkleRootHex;
          }

          if (
            totalSize > 0 &&
            state[roomIndex].messages[messageIndex].totalSize !== totalSize
          ) {
            state[roomIndex].messages[messageIndex].totalSize = totalSize;
          }

          if (
            chunkSize > 0 &&
            state[roomIndex].messages[messageIndex].totalSize >=
              state[roomIndex].messages[messageIndex].savedSize + chunkSize
          ) {
            state[roomIndex].messages[messageIndex].savedSize += chunkSize;
          }

          if (
            chunksCreated &&
            chunksCreated <= state[roomIndex].messages[messageIndex].totalChunks
          ) {
            state[roomIndex].messages[messageIndex].chunksCreated =
              chunksCreated + 1;
          }
        }
      }
    },

    setMessageAllChunks: (
      state,
      action: PayloadAction<SetMessageAllChunksArgs>,
    ) => {
      const {
        roomId,
        transferId,
        merkleRootHex,
        sha512Hex,
        channelLabel,
        filename,
        messageType,
        fromPeerId,
        fromPeerPublicKey,
        timestamp,
        totalSize,
      } = action.payload;

      const roomIndex = state.findIndex((r) => r.id === roomId);

      if (roomIndex > -1) {
        const messageIndex = state[roomIndex].messages.findLastIndex(
          (m) => m.merkleRootHex === merkleRootHex, // || m.sha512Hex === sha512Hex,
        );

        if (
          messageIndex === -1 &&
          channelLabel &&
          fromPeerId &&
          isUUID(fromPeerId) &&
          messageType &&
          totalSize
        ) {
          state[roomIndex].messages.push({
            transferId,
            merkleRootHex,
            sha512Hex,
            channelLabel,
            filename: filename.length > 0 ? filename : "txt",
            messageType,
            fromPeerId,
            fromPeerPublicKey,
            timestamp,
            savedSize: totalSize,
            totalSize,
            chunksCreated: 0,
            totalChunks: 0,
          });
        } else if (
          messageIndex > -1 &&
          state[roomIndex].messages[messageIndex].timestamp < timestamp
        ) {
          state[roomIndex].messages.push({
            transferId,
            merkleRootHex,
            sha512Hex,
            channelLabel,
            filename: filename.length > 0 ? filename : "txt",
            messageType,
            fromPeerId,
            fromPeerPublicKey,
            timestamp,
            savedSize: totalSize,
            totalSize,
            chunksCreated: 0,
            totalChunks: 0,
          });
        } else if (
          messageIndex > -1 &&
          state[roomIndex].messages[messageIndex].savedSize !== totalSize
        ) {
          state[roomIndex].messages[messageIndex].savedSize = totalSize;
        }
        // else {
        //   debugLog("HEre");
        // }
      }
    },

    /**
     * A received file whose stored bytes failed verification had its chunks
     * dropped: show its progress as 0 again, in place, so it keeps its
     * position in the room's list.
     */
    resetMessageReceiveProgress: (
      state,
      action: PayloadAction<ResetMessageReceiveProgressArgs>,
    ) => {
      const { roomId, merkleRootHex } = action.payload;
      const roomIndex = state.findIndex((r) => r.id === roomId);
      if (roomIndex === -1) return;
      // The same entry setMessage and setMessageAllChunks update: the last one
      // for this root.
      const messageIndex = state[roomIndex].messages.findLastIndex(
        (m) => m.merkleRootHex === merkleRootHex,
      );
      if (messageIndex > -1)
        state[roomIndex].messages[messageIndex].savedSize = 0;
    },

    deleteMessage: (state, action: PayloadAction<DeleteMessageArgs>) => {
      deleteMessageFromState(state, action.payload);
    },

    /** Reducer-only twin for callers that already awaited durable deletion. */
    deleteMessageStateOnly: (
      state,
      action: PayloadAction<DeleteMessageArgs>,
    ) => {
      deleteMessageFromState(state, action.payload);
    },

    setOnlyConnectWithKnownPeers: (
      state,
      action: PayloadAction<SetCanOnlyConnectWithKnownPeers>,
    ) => {
      const { roomId, roomUrl, onlyConnectWithKnownPeers } = action.payload;

      const roomIndex = state.findIndex(
        (room) =>
          (roomUrl !== undefined && room.url === roomUrl) ||
          (roomUrl === undefined && room.id === roomId),
      );

      if (roomIndex > -1) {
        state[roomIndex].onlyConnectWithKnownAddresses =
          onlyConnectWithKnownPeers;
      }
    },

    deleteRoom: (state, action: PayloadAction<string>) => {
      const roomIndex = state.findIndex(
        (r) => r.url === action.payload || r.id === action.payload,
      );
      if (roomIndex > -1) {
        const url = state[roomIndex].url;
        const policy = state[roomIndex].policy;
        const callerRtcConfig = freshCallerRTCConfig(undefined);

        state[roomIndex] = {
          url,
          id: "",
          connectingToPeers: false,
          connectedToPeers: false,
          canBeConnectionRelay: true,
          onlyConnectWithKnownAddresses: false,
          callerRtcConfig,
          signalingTurnCredentials: null,
          rtcConfig: deriveEffectiveRTCConfig(callerRtcConfig, null),
          roomResponseGeneration: 0,
          signalingActive: false,
          // The descriptor is public room identity, not ephemeral connection
          // state. Retaining the URL while silently resetting a PIN room to
          // no-PIN would create a local downgrade on reconnect.
          policy: canonicalizeRoomPolicyV1(policy),
          peers: [],
          channels: [],
          messages: [],
        };
      }
    },

    /** Full-device purge only; ordinary room deletion keeps a safe tombstone. */
    purgeAllRooms: () => [] as ManagedRoom[],

    incrementMessageStats: (
      state,
      action: PayloadAction<IncrementMessageStatsArgs>,
    ) => {
      const { roomId, merkleRootHex, sha512Hex, real, retransmit } =
        action.payload;
      const roomIndex = state.findIndex((r) => r.id === roomId);
      if (roomIndex < 0) return;
      const messageIndex = state[roomIndex].messages.findLastIndex(
        (m) =>
          (merkleRootHex !== undefined && m.merkleRootHex === merkleRootHex) ||
          (sha512Hex !== undefined && m.sha512Hex === sha512Hex),
      );
      if (messageIndex < 0) return;
      const m = state[roomIndex].messages[messageIndex];
      if (retransmit) {
        m.retransmits = (m.retransmits ?? 0) + 1;
      } else {
        m.chunksReceivedTotal = (m.chunksReceivedTotal ?? 0) + 1;
        if (real) m.chunksReceivedReal = (m.chunksReceivedReal ?? 0) + 1;
      }
    },
  },
});

export const {
  setRoom,
  applyRoomResponse,
  rollbackRoomResponse,
  expireRoomTurnCredentials,
  setRoomPolicy,
  setConnectingToPeers,
  setConnectedToPeers,
  setConnectionRelay,
  setOnlyConnectWithKnownPeers,
  setPeer,
  setPeerCoverStatus,
  setPeerHandshakeStatus,
  clearPeerHandshakeFailures,
  clearPeerHandshakeStatus,
  allowPeerHandshakeRetry,
  setChannel,
  setIceServers,
  setMessage,
  setMessageAllChunks,
  resetMessageReceiveProgress,
  incrementMessageStats,
  deletePeer,
  deleteChannel,
  deleteMessage,
  deleteMessageStateOnly,
  deleteRoom,
  purgeAllRooms,
  setKnownRoomPeers,
  notePeerPresence,
  peerDeparted,
} = roomSlice.actions;
export const roomSelector = <TRoom extends Room>(state: {
  readonly rooms: TRoom[];
}): TRoom[] => state.rooms;
export default roomSlice.reducer;
