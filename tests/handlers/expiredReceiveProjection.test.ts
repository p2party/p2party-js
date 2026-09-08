import { describe, expect, test } from "bun:test";
import {
  sweepExpiredReceiveState,
  createExpiredReceiveMaintenance,
} from "../../src/handlers/expiredReceiveProjection";
import {
  bindReceiveMessageKey,
  captureReceiveMessageKey,
  forgetExpiredReceiveMessageKey,
} from "../../src/handlers/receiveMessageKeyLifetime";
import {
  forgetReceiveMessageKeyIfCurrentDurably,
  withEdgeCryptoMutationLock,
} from "../../src/handlers/ratchetPersist";
import {
  claimRatchetGate,
  openRatchetGate,
  resetRatchetGate,
} from "../../src/handlers/ratchetGate";
import type { IRTCPeerConnection } from "../../src/api/webrtc/interfaces";
import type { Message } from "../../src/reducers/roomSlice";
import type { MessageData } from "../../src/db/types";
import type { RatchetState } from "../../src/cryptography/ratchet";

const ROOT = "ab".repeat(64);
let sequence = 0;
const message = (overrides: Partial<Message> = {}): Message => ({
  merkleRootHex: ROOT,
  sha512Hex: "cd".repeat(64),
  fromPeerId: "peer",
  filename: "partial.bin",
  messageType: 1,
  savedSize: 5,
  totalSize: 10,
  chunksCreated: 0,
  totalChunks: 0,
  channelLabel: "chat",
  timestamp: 1,
  ...overrides,
});
const edge = (roomId: string, peerId = "peer") => {
  const key = new Uint8Array(32).fill(7);
  const cacheKey = `${"22".repeat(32)}:0`;
  const ratchet: RatchetState = {
    rootSuite: "hybrid-3dh-mlkem768-cpace21-v4",
    rootKey: new Uint8Array(32),
    sendingChainKey: null,
    receivingChainKey: null,
    dhSelfPub: new Uint8Array(32),
    dhSelfSec: new Uint8Array(32),
    dhRemotePub: null,
    Ns: 0,
    Nr: 0,
    PN: 0,
    skipped: new Map([[cacheKey, key.slice()]]),
  };
  const gate = claimRatchetGate(roomId, peerId);
  openRatchetGate(roomId, peerId, gate);
  const peer = {
    roomId,
    withPeerId: peerId,
    withPeerPublicKey: "11".repeat(32),
    ratchetGateLease: gate,
    ratchetState: ratchet,
    messageKeyCache: new Map([[cacheKey, key]]),
  } as unknown as IRTCPeerConnection;
  bindReceiveMessageKey(peer, ROOT, cacheKey);
  return { peer, key, cacheKey };
};
const realRetirement: typeof forgetExpiredReceiveMessageKey = (
  snapshot,
  absent,
) =>
  forgetExpiredReceiveMessageKey(
    snapshot,
    absent,
    (peer, room, cache, key, check) =>
      forgetReceiveMessageKeyIfCurrentDurably(
        peer,
        room,
        cache,
        key,
        check,
        async () => {},
      ),
  );

describe("expired receive projection", () => {
  test("frequent metadata polling coalesces maintenance and avoids repeated key scans", async () => {
    let now = 100;
    let snapshots = 0;
    let sweeps = 0;
    const maintain = createExpiredReceiveMaintenance(
      {
        getRooms: () => [],
        getPeers: () => {
          snapshots++;
          return [];
        },
        sweep: async () => {
          sweeps++;
          return [];
        },
        dropMessage: () => {
          throw new Error("No stale rows");
        },
      },
      () => now,
    );
    await Promise.all(Array.from({ length: 100 }, () => maintain()));
    now += 29_999;
    for (let index = 0; index < 100; index++) await maintain();
    expect(snapshots).toBe(2);
    expect(sweeps).toBe(1);
    now++;
    await maintain();
    expect(snapshots).toBe(4);
    expect(sweeps).toBe(2);
  });

  test("atomic deletion removes only its partial room row and durably mapped key", async () => {
    const roomId = `expiry-${++sequence}`;
    const retired = edge(roomId);
    const other = edge(`${roomId}-other`);
    const completed = message({
      merkleRootHex: "12".repeat(64),
      savedSize: 10,
    });
    const active = message({ merkleRootHex: "13".repeat(64) });
    const self = message({
      merkleRootHex: "14".repeat(64),
      transferId: "sender",
    });
    let rooms = [
      { id: roomId, messages: [message(), completed, active, self] },
      { id: other.peer.roomId, messages: [message()] },
    ];
    const dropped: string[] = [];
    await sweepExpiredReceiveState({
      getRooms: () => rooms,
      getPeers: () => [retired.peer, other.peer],
      sweep: async () => [{ merkleRoot: ROOT, roomId, fromPeerId: "peer" }],
      readProgress: async () => undefined,
      forgetKey: realRetirement,
      dropMessage: (room, root) => {
        dropped.push(`${room}:${root}`);
        rooms = rooms.map((r) =>
          r.id === room
            ? {
                ...r,
                messages: r.messages.filter((m) => m.merkleRootHex !== root),
              }
            : r,
        );
      },
    });
    expect(dropped).toEqual([`${roomId}:${ROOT}`]);
    expect(rooms[0]!.messages).toEqual([completed, active, self]);
    expect(rooms[1]!.messages).toHaveLength(1);
    expect(retired.key.every((byte) => byte === 0)).toBe(true);
    expect(retired.peer.ratchetState!.skipped.has(retired.cacheKey)).toBe(
      false,
    );
    expect(retired.peer.messageKeyByMerkleRoot!.has(ROOT)).toBe(false);
    expect(other.key[0]).toBe(7);
    expect(other.peer.messageKeyByMerkleRoot!.has(ROOT)).toBe(true);
  });

  test("active/completed rows omitted by the atomic worker result remain untouched", async () => {
    const roomId = `expiry-${++sequence}`;
    const current = edge(roomId);
    const rooms = [{ id: roomId, messages: [message()] }];
    let writes = 0;
    await sweepExpiredReceiveState({
      getRooms: () => rooms,
      getPeers: () => [current.peer],
      sweep: async () => [],
      readProgress: async () => {
        throw new Error("No candidate-only projection");
      },
      forgetKey: async () => {
        writes++;
        return true;
      },
      dropMessage: () => {
        writes++;
      },
    });
    expect(writes).toBe(0);
    expect(current.key[0]).toBe(7);
    expect(rooms[0]!.messages).toHaveLength(1);
  });

  test("recreated durable data after deletion suppresses both projection and retirement", async () => {
    const roomId = `expiry-${++sequence}`;
    const current = edge(roomId);
    const rooms = [{ id: roomId, messages: [message()] }];
    let dropped = false;
    await sweepExpiredReceiveState({
      getRooms: () => rooms,
      getPeers: () => [current.peer],
      sweep: async () => [{ merkleRoot: ROOT, roomId, fromPeerId: "peer" }],
      readProgress: async () => ({ savedSize: 1 }) as MessageData,
      forgetKey: realRetirement,
      dropMessage: () => {
        dropped = true;
      },
    });
    expect(dropped).toBe(false);
    expect(current.key[0]).toBe(7);
  });

  test("a queued completion or same-root replacement keeps its new view", async () => {
    for (const savedSize of [1, 10]) {
      const roomId = `expiry-${++sequence}`;
      const current = edge(roomId);
      let rooms = [{ id: roomId, messages: [message()] }];
      let dropped = false;
      await sweepExpiredReceiveState({
        getRooms: () => rooms,
        getPeers: () => [current.peer],
        sweep: async () => {
          rooms = [{ id: roomId, messages: [message({ savedSize })] }];
          return [{ merkleRoot: ROOT, roomId, fromPeerId: "peer" }];
        },
        readProgress: async () => undefined,
        forgetKey: realRetirement,
        dropMessage: () => {
          dropped = true;
        },
      });
      expect(dropped).toBe(false);
      expect(current.key[0]).toBe(7);
      expect(rooms[0]!.messages[0]!.savedSize).toBe(savedSize);
    }
  });

  test("a new receive binding while retirement waits on the crypto lock survives", async () => {
    const roomId = `expiry-${++sequence}`;
    const current = edge(roomId);
    const snapshot = captureReceiveMessageKey(current.peer, ROOT)!;
    let release!: () => void;
    let entered!: () => void;
    const enteredPromise = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const holding = withEdgeCryptoMutationLock(current.peer, async () => {
      entered();
      await new Promise<void>((resolve) => {
        release = resolve;
      });
      // Even an identical cached header represents a new receive admission.
      bindReceiveMessageKey(current.peer, ROOT, current.cacheKey);
    });
    await enteredPromise;
    const retiring = realRetirement(snapshot, async () => true);
    release();
    await holding;
    expect(await retiring).toBe(false);
    expect(current.key[0]).toBe(7);
    expect(current.peer.messageKeyByMerkleRoot!.has(ROOT)).toBe(true);
  });

  test("gate replacement during the absence read cannot retire the new generation", async () => {
    const roomId = `expiry-${++sequence}`;
    const current = edge(roomId);
    const snapshot = captureReceiveMessageKey(current.peer, ROOT)!;
    const retired = await realRetirement(snapshot, async () => {
      resetRatchetGate(roomId, "peer");
      current.peer.ratchetGateLease = claimRatchetGate(roomId, "peer");
      openRatchetGate(roomId, "peer", current.peer.ratchetGateLease);
      return true;
    });
    expect(retired).toBe(false);
    expect(current.key[0]).toBe(7);
    expect(current.peer.messageKeyByMerkleRoot!.has(ROOT)).toBe(true);
  });
});
