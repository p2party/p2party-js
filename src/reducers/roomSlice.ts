import { createSlice } from "@reduxjs/toolkit";
import { isUUID } from "class-validator";

import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";
import {
  DEFAULT_ROOM_POLICY_V1,
  canonicalizeRoomPolicyV1,
  roomPoliciesEqualV1,
} from "../roomPolicy";

import type { PayloadAction } from "@reduxjs/toolkit";
import type { State } from "../store";
import type { RoomPolicyV1 } from "../roomPolicy";
import type { CoverSchedulerStatus } from "../handlers/coverScheduler";
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
  onlyConnectWithKnownPeers: boolean;
}

export interface SetPeerCoverStatusArgs {
  roomId: string;
  peerId: string;
  status: CoverSchedulerStatus;
}

export interface Room extends SetRoomArgs {
  policy: RoomPolicyV1;
  connectingToPeers: boolean;
  connectedToPeers: boolean;
  canBeConnectionRelay: boolean;
  onlyConnectWithKnownAddresses: boolean;
  rtcConfig: RTCConfiguration;
  peers: Peer[];
  channels: Channel[];
  messages: Message[];
  /**
   * protocol-v4: live scheduled-cover status per authenticated peer edge
   * (peerId → status). Absent means no cover claim may ever be made for that
   * edge — only an explicit "active" from the runtime is a cover claim, so a
   * browser gap ("suspended") or teardown ("stopped") is always visible.
   */
  coverStatusByPeer?: Record<string, CoverSchedulerStatus>;
}

export const defaultRTCConfig = {
  iceServers: [
    {
      // Use single STUN URL - multiple STUN servers slow down ICE gathering
      urls: "stun:stun.p2party.com:3478",
    },
    // TURN server requires credentials from signaling server via TURN REST API
    // Add TURN server entry with valid credentials when available:
    // {
    //   urls: ["turn:turn.p2party.com:3478", "turns:turn.p2party.com:443?transport=tcp"],
    //   username: "<from-signaling-server>",
    //   credential: "<from-signaling-server>",
    // },
  ],
  iceTransportPolicy: "all",
  // Pre-allocate ICE candidates for faster connection setup
  iceCandidatePoolSize: 2,
} as RTCConfiguration;

const initialState: Room[] = [];

const assertRoomPolicyUnchanged = (
  current: RoomPolicyV1,
  requested: RoomPolicyV1,
): void => {
  const candidate = canonicalizeRoomPolicyV1(requested);
  if (!roomPoliciesEqualV1(current, candidate))
    throw new Error("roomSlice: room policy is immutable after creation");
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

      if (url.length === 64 && isUUID(id)) {
        const roomIndex = state.findIndex((r) => r.url === url || r.id === id);

        if (roomIndex > -1) {
          if (policy)
            assertRoomPolicyUnchanged(state[roomIndex].policy, policy);
          state[roomIndex].url = url;
          state[roomIndex].id = id;
          if (canBeConnectionRelay != undefined)
            state[roomIndex].canBeConnectionRelay = canBeConnectionRelay;
          if (rtcConfig) state[roomIndex].rtcConfig = rtcConfig;
          if (onlyConnectWithKnownPeers != undefined) {
            state[roomIndex].onlyConnectWithKnownAddresses =
              onlyConnectWithKnownPeers;
          } else {
            state[roomIndex].onlyConnectWithKnownAddresses =
              localStorage.getItem(url + "-onlyConnectWithKnownPeers") ===
              "true";
          }
        } else {
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
            rtcConfig: rtcConfig ?? defaultRTCConfig,
            policy: canonicalizeRoomPolicyV1(policy ?? DEFAULT_ROOM_POLICY_V1),
            peers: [],
            channels: [],
            messages: [],
          });
        }
      } else if (url.length === 64) {
        const roomIndex = state.findIndex((r) => r.url === url);

        if (roomIndex > -1) {
          if (policy)
            assertRoomPolicyUnchanged(state[roomIndex].policy, policy);
          state[roomIndex].url = url;
          state[roomIndex].id = "";
          if (canBeConnectionRelay != undefined)
            state[roomIndex].canBeConnectionRelay = canBeConnectionRelay;
          if (rtcConfig) state[roomIndex].rtcConfig = rtcConfig;
          if (onlyConnectWithKnownPeers != undefined) {
            state[roomIndex].onlyConnectWithKnownAddresses =
              onlyConnectWithKnownPeers;
          } else {
            state[roomIndex].onlyConnectWithKnownAddresses =
              localStorage.getItem(url + "-onlyConnectWithKnownPeers") ===
              "true";
          }
        } else {
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
            rtcConfig: rtcConfig ?? defaultRTCConfig,
            policy: canonicalizeRoomPolicyV1(policy ?? DEFAULT_ROOM_POLICY_V1),
            peers: [],
            channels: [],
            messages: [],
          });
        }
      }
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
      action: PayloadAction<{ roomId: string; connectingToPeers: boolean }>,
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

    setPeer: (state, action: PayloadAction<SetPeerArgs>) => {
      const { roomId, peerId, peerPublicKey } = action.payload;

      const roomIndex = state.findIndex((r) => r.id === roomId);

      if (roomIndex > -1) {
        const peerIndex = state[roomIndex].peers.findIndex(
          (p) => p.peerId === peerId,
        );

        if (peerIndex === -1)
          state[roomIndex].peers.push({ peerId, peerPublicKey });
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
        const coverStatusByPeer = state[i].coverStatusByPeer;
        if (coverStatusByPeer) delete coverStatusByPeer[action.payload.peerId];
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
        room.coverStatusByPeer ??= {};
        room.coverStatusByPeer[peerId] = status;
      }
    },

    setChannel: (state, action: PayloadAction<SetChannelArgs>) => {
      const { roomId, label, peerId } = action.payload;

      const roomIndex = state.findIndex((r) => r.id === roomId);

      if (roomIndex > -1) {
        const channelIndex = state[roomIndex].channels.findIndex(
          (c) => c.label === label,
        );

        if (channelIndex > -1) {
          const peerIndex = state[roomIndex].channels[
            channelIndex
          ].peerIds.findIndex((p) => p === peerId);

          if (peerIndex === -1) {
            state[roomIndex].channels[channelIndex].peerIds.push(peerId);
          }
        } else {
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
        const iceServersLen = iceServers.length;
        const existingIceServers =
          state[roomIndex].rtcConfig.iceServers?.flatMap((server) =>
            Array.isArray(server.urls) ? server.urls : [server.urls],
          ) ?? [];
        for (let i = 0; i < iceServersLen; i++) {
          const urlsLen = iceServers[i].urls.length;
          let shouldPush = false;
          for (let j = 0; j < urlsLen; j++) {
            if (!existingIceServers.includes(iceServers[i].urls[j])) {
              shouldPush = true;

              break;
            }
          }

          if (shouldPush) {
            state[roomIndex].rtcConfig.iceServers?.push(iceServers[i]);
          }
        }
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
        //   console.log("HEre");
        // }
      }
    },

    deleteMessage: (state, action: PayloadAction<DeleteMessageArgs>) => {
      const { roomId, transferId, merkleRootHex, hashHex } = action.payload;

      if (!transferId && !merkleRootHex && !hashHex) return;
      if (transferId && !/^[0-9a-f]{64}$/.test(transferId)) return;
      if (
        merkleRootHex &&
        merkleRootHex.length !== crypto_hash_sha512_BYTES * 2
      )
        return;
      if (hashHex && hashHex.length !== crypto_hash_sha512_BYTES * 2) return;

      const roomIndex = state.findIndex((room) => room.id === roomId);
      if (roomIndex === -1) return;

      if (transferId) {
        const messageIndex = state[roomIndex].messages.findIndex(
          (m) => m.transferId === transferId,
        );

        if (messageIndex > -1)
          state[roomIndex].messages.splice(messageIndex, 1);
      } else if (merkleRootHex) {
        const messageIndex = state[roomIndex].messages.findIndex(
          (m) => m.merkleRootHex === merkleRootHex,
        );

        if (messageIndex > -1)
          state[roomIndex].messages.splice(messageIndex, 1);
      } else if (hashHex) {
        const messageIndex = state[roomIndex].messages.findLastIndex(
          (m) => m.sha512Hex === hashHex,
        );

        if (messageIndex > -1)
          state[roomIndex].messages.splice(messageIndex, 1);
      }
    },

    setOnlyConnectWithKnownPeers: (
      state,
      action: PayloadAction<SetCanOnlyConnectWithKnownPeers>,
    ) => {
      const { roomId, onlyConnectWithKnownPeers } = action.payload;

      const roomIndex = state.findIndex((r) => r.id === roomId);

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

        state[roomIndex] = {
          url,
          id: "",
          connectingToPeers: false,
          connectedToPeers: false,
          canBeConnectionRelay: true,
          onlyConnectWithKnownAddresses: false,
          rtcConfig: defaultRTCConfig,
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
  setRoomPolicy,
  setConnectingToPeers,
  setConnectedToPeers,
  setConnectionRelay,
  setOnlyConnectWithKnownPeers,
  setPeer,
  setPeerCoverStatus,
  setChannel,
  setIceServers,
  setMessage,
  setMessageAllChunks,
  incrementMessageStats,
  deletePeer,
  deleteChannel,
  deleteMessage,
  deleteRoom,
} = roomSlice.actions;
export const roomSelector = (state: State) => state.rooms;
export default roomSlice.reducer;
