// Full app-stack browser entry: the REAL p2party API (Redux store + IndexedDB
// DB worker + WebRTC) driven end to end. No store-free shortcuts.
import {
  p2party,
  setWasmSourceUrl,
  DEFAULT_ROOM_POLICY_V1,
  canonicalizeRoomPolicyV1,
} from "/Users/deliberative/Desktop/@p2party/p2party-js/src/index";
import { setChannel } from "/Users/deliberative/Desktop/@p2party/p2party-js/src/reducers/roomSlice";
import type { RoomPolicyV1 } from "/Users/deliberative/Desktop/@p2party/p2party-js/src/roomPolicy";

// Loopback WebRTC: host candidates suffice, no STUN/TURN reachability needed.
const LOOPBACK_RTC: RTCConfiguration = { iceServers: [], iceCandidatePoolSize: 2 };

declare global {
  interface Window {
    __app: typeof api;
  }
}

const store = p2party.store;

const roomIdFor = (roomUrlHex: string): string => {
  const st = store.getState();
  const room = st.rooms.find((r) => r.url === roomUrlHex);
  return room?.id ?? "";
};

const api = {
  boot(wasmUrl: string): void {
    setWasmSourceUrl(wasmUrl);
  },

  async connect(
    roomUrlHex: string,
    wsUrl: string,
    opts: { mode?: "immediate" | "scheduled" | "pin"; pinHex?: string } = {},
  ): Promise<void> {
    let policy: RoomPolicyV1 = canonicalizeRoomPolicyV1(DEFAULT_ROOM_POLICY_V1);
    if (opts.mode === "scheduled") {
      policy = canonicalizeRoomPolicyV1({
        ...DEFAULT_ROOM_POLICY_V1,
        coverMode: "scheduled",
        coverCadenceMs: 2000,
        coverLanes: 2,
        coverFramesPerCell: 16,
        coverDurationEpochs: 1,
      });
    } else if (opts.mode === "pin") {
      policy = canonicalizeRoomPolicyV1({
        ...DEFAULT_ROOM_POLICY_V1,
        authMode: "pin",
      });
    }
    const pin =
      opts.mode === "pin" && opts.pinHex
        ? Uint8Array.from(
            opts.pinHex.match(/.{2}/g)!.map((h) => parseInt(h, 16)),
          )
        : undefined;
    await p2party.connect(roomUrlHex, wsUrl, LOOPBACK_RTC, { policy, pin });
  },

  myPeerId(): string {
    return store.getState().keyPair.peerId;
  },
  myPublicKey(): string {
    return store.getState().keyPair.publicKey;
  },
  roomId(roomUrlHex: string): string {
    return roomIdFor(roomUrlHex);
  },
  isVerified(): boolean {
    return store.getState().signalingServer.isVerified;
  },
  peerCount(roomUrlHex: string): number {
    const st = store.getState();
    const room = st.rooms.find((r) => r.url === roomUrlHex);
    return room?.peers.length ?? 0;
  },
  peerIds(roomUrlHex: string): string[] {
    const st = store.getState();
    const room = st.rooms.find((r) => r.url === roomUrlHex);
    return (room?.peers ?? []).map((p) => p.peerId);
  },

  // Send a message on a logical channel to every peer on it, awaiting delivery.
  async send(
    roomUrlHex: string,
    channel: string,
    text: string,
  ): Promise<{ transferId: string; merkleRootHex: string; delivered: number }> {
    const roomId = roomIdFor(roomUrlHex);
    const handle = p2party.sendMessage(text, channel, roomId);
    const result = await handle.done;
    const delivered = (result?.outcomes ?? []).filter(
      (o: { status: string }) => o.status === "delivered",
    ).length;
    return {
      transferId: handle.transferId,
      merkleRootHex: result?.merkleRootHex ?? "",
      delivered,
    };
  },

  // Add both self + peers to a channel so a send has targets (mirrors the app
  // opening a chat channel). Uses the exposed store dispatch.
  joinChannel(roomUrlHex: string, channel: string): void {
    const roomId = roomIdFor(roomUrlHex);
    const st = store.getState();
    const room = st.rooms.find((r) => r.id === roomId);
    if (!room) return;
    for (const peer of room.peers)
      store.dispatch(setChannel({ roomId, label: channel, peerId: peer.peerId }));
  },

  // The most recent message in the room authored by another peer.
  latestIncoming(roomUrlHex: string): { merkleRootHex: string; from: string } | null {
    const st = store.getState();
    const me = st.keyPair.peerId;
    const room = st.rooms.find((r) => r.url === roomUrlHex);
    if (!room) return null;
    for (let i = room.messages.length - 1; i >= 0; i--) {
      const m = room.messages[i];
      if (m.fromPeerId !== me && m.merkleRootHex)
        return { merkleRootHex: m.merkleRootHex, from: m.fromPeerId };
    }
    return null;
  },

  async read(merkleRootHex: string): Promise<string> {
    const res = await p2party.readMessage(merkleRootHex);
    return typeof res.message === "string" ? res.message : "[blob]";
  },

  async disconnectAll(): Promise<void> {
    await p2party.disconnectFromAllRooms({});
  },
};

window.__app = api;
