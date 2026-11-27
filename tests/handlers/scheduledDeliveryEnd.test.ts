import { afterEach, beforeAll, describe, expect, test } from "bun:test";

import { loadTestModule } from "../../src/cryptography/testModule";
import { getMerkleRoot } from "../../src/cryptography/merkle";
import { initRatchet, ratchetEncrypt } from "../../src/cryptography/ratchet";
import { crypto_hash_sha512_BYTES } from "../../src/cryptography/interfaces";
import { CoverRuntime } from "../../src/handlers/coverRuntime";
import { SparsePqHealingState } from "../../src/handlers/pqHealingRuntime";
import { hashMerkleLeafWasm } from "../../src/utils/leafHash";
import { serializeMetadata } from "../../src/utils/metadata";
import { MessageType } from "../../src/utils/messageTypes";
import { uint8ArrayToHex } from "../../src/utils/uint8array";
import {
  CHUNK_LEN,
  RATCHET_ROOT_SUITE_MLKEM512,
  WIRE_CHUNK_FRAME_LEN,
} from "../../src/utils/constants";
import {
  DEFAULT_ROOM_POLICY_V1,
  type RoomPolicyV1,
} from "../../src/roomPolicy";

import type { LibCrypto } from "../../src/cryptography/libcrypto";
import type { IRTCPeerConnection } from "../../src/api/webrtc/interfaces";
import type { CoverLaneChannel } from "../../src/handlers/coverRuntime";
import type {
  CoverClock,
  CoverJobInterruption,
  CoverJobResult,
  CoverSchedulerStatus,
} from "../../src/handlers/coverScheduler";
import type { NewChunk } from "../../src/db/types";

// handleSendMessage reaches the Redux store, whose keyPair slice reads
// localStorage at module initialisation.
const localStorageMemory: Record<string, string> = {};
(globalThis as unknown as { localStorage?: Storage }).localStorage ??= {
  getItem: (key: string) =>
    key in localStorageMemory ? localStorageMemory[key] : null,
  setItem: (key: string, value: string) => {
    localStorageMemory[key] = String(value);
  },
  removeItem: (key: string) => {
    delete localStorageMemory[key];
  },
  clear: () => {
    for (const key of Object.keys(localStorageMemory))
      delete localStorageMemory[key];
  },
  key: () => null,
  length: 0,
} as Storage;

type SendModule = typeof import("../../src/handlers/handleSendMessage");
let sendScheduled: SendModule["sendScheduled"];
let withOutboundMessage: SendModule["withOutboundMessage"];
let clearTransfer: (typeof import("../../src/handlers/reconcile"))["clearTransfer"];
let compileChannelMessageLabel: (typeof import("../../src/utils/channelLabel"))["compileChannelMessageLabel"];

let module: LibCrypto;

beforeAll(async () => {
  module = await loadTestModule();
  await import("../../src/store");
  ({ sendScheduled, withOutboundMessage } =
    await import("../../src/handlers/handleSendMessage"));
  ({ clearTransfer } = await import("../../src/handlers/reconcile"));
  ({ compileChannelMessageLabel } =
    await import("../../src/utils/channelLabel"));
});

const ROOM = "room-a4-settle";
const PEER = "peer-a4-settle";
const TRANSFER_ID = "a5".repeat(32);
const HASH_HEX = "e5".repeat(64);

const rand = (n: number): Uint8Array =>
  crypto.getRandomValues(new Uint8Array(n));

const cleanups: (() => void)[] = [];
afterEach(() => {
  while (cleanups.length > 0) cleanups.pop()?.();
  clearTransfer(ROOM, PEER, TRANSFER_ID);
});

/** Timers the test advances; the scheduler arms every slot on it. */
class FakeClock implements CoverClock {
  private time = 0;
  private nextId = 1;
  private readonly timers = new Map<
    number,
    { id: number; at: number; callback: () => void }
  >();

  now(): number {
    return this.time;
  }

  setTimeout(callback: () => void, delayMs: number): number {
    const id = this.nextId++;
    this.timers.set(id, { id, at: this.time + delayMs, callback });
    return id;
  }

  clearTimeout(handle: unknown): void {
    if (typeof handle === "number") this.timers.delete(handle);
  }

  get armed(): number {
    return this.timers.size;
  }

  async advanceTo(target: number): Promise<void> {
    for (;;) {
      for (let i = 0; i < 8; i++) await Promise.resolve();
      const due = [...this.timers.values()]
        .filter(({ at }) => at <= target)
        .sort((a, b) => a.at - b.at || a.id - b.id)[0];
      if (!due) break;
      this.time = Math.max(this.time, due.at);
      this.timers.delete(due.id);
      due.callback();
    }
    this.time = target;
    for (let i = 0; i < 8; i++) await Promise.resolve();
  }
}

class FakeLane implements CoverLaneChannel {
  readonly label: string;
  readyState = "open";
  bufferedAmount = 0;
  sent = 0;
  constructor(
    label: string,
    private readonly onSend: () => void,
  ) {
    this.label = label;
  }
  send(): void {
    this.sent++;
    this.onSend();
  }
  close(): void {
    this.readyState = "closed";
  }
}

// 2 lanes × 2 frames: four slots per 400 ms cycle, two cells per lane.
const SCHEDULE = {
  coverCadenceMs: 400,
  coverLanes: 2,
  coverFramesPerCell: 2,
  coverDurationEpochs: 1,
};
const policy: RoomPolicyV1 = {
  ...DEFAULT_ROOM_POLICY_V1,
  coverMode: "scheduled",
  ...SCHEDULE,
};

interface Edge {
  readonly epc: IRTCPeerConnection;
  readonly runtime: CoverRuntime;
  readonly clock: FakeClock;
  readonly lanes: FakeLane[];
  readonly statuses: CoverSchedulerStatus[];
  readonly interruptions: CoverJobInterruption[];
  readonly results: CoverJobResult[];
  nextSlotResult: () => Promise<void>;
}

/** An authenticated edge with a real scheduled-cover runtime on a fake clock. */
const makeEdge = (): Edge => {
  const pq = new SparsePqHealingState({
    module,
    pqMode: "hybrid-mlkem512",
    rootSuite: RATCHET_ROOT_SUITE_MLKEM512,
    binding: new Uint8Array(32).fill(0x42),
    rootKey: new Uint8Array(32).fill(0x19),
    nextOfferer: "local",
    amInitiator: true,
    now: 0,
  });
  const epc = {
    roomId: ROOM,
    withPeerId: PEER,
    withPeerPublicKey: "aa".repeat(32),
    connectionState: "connected",
    pqHealingState: pq,
    ratchetState: initRatchet(
      rand(32),
      true,
      initRatchet(rand(32), false, null, module).dhSelfPub,
      module,
    ),
  } as unknown as IRTCPeerConnection;
  const clock = new FakeClock();
  const lanes: FakeLane[] = [];
  let slot = Promise.withResolvers<void>();
  const reportSlot = () => {
    slot.resolve();
    slot = Promise.withResolvers<void>();
  };
  const statuses: CoverSchedulerStatus[] = [];
  const interruptions: CoverJobInterruption[] = [];
  const results: CoverJobResult[] = [];
  const runtime = new CoverRuntime({
    epc,
    roomId: ROOM,
    module,
    amInitiator: true,
    schedule: SCHEDULE,
    policyHash: new Uint8Array(32),
    laneLabelName: "chat",
    openLaneChannel: (label) => {
      const lane = new FakeLane(label, reportSlot);
      lanes.push(lane);
      return lane;
    },
    onStatusChange: ({ status }) => {
      statuses.push(status);
      if (status === "degraded") reportSlot();
    },
    onJobInterrupted: (interruption) => interruptions.push(interruption),
    onJobResult: (result) => results.push(result),
    maxTimerDriftMs: 0,
    clock,
  });
  epc.coverRuntime = runtime;
  cleanups.push(() => {
    runtime.destroy();
    pq.destroy();
  });
  return {
    epc,
    runtime,
    clock,
    lanes,
    statuses,
    interruptions,
    results,
    nextSlotResult: () => slot.promise,
  };
};

/** A two-cell staged message, and a store whose reads the test can hold. */
const stageMessage = async () => {
  const totalChunks = 2;
  const hash = rand(crypto_hash_sha512_BYTES);
  const rows = new Map<number, NewChunk>();
  const leaves = new Uint8Array(totalChunks * crypto_hash_sha512_BYTES);
  for (let i = 0; i < totalChunks; i++) {
    const data = rand(CHUNK_LEN);
    const leaf = hashMerkleLeafWasm(data, module);
    leaves.set(leaf, i * crypto_hash_sha512_BYTES);
    rows.set(i, {
      transferId: TRANSFER_ID,
      hash: HASH_HEX,
      merkleRoot: "",
      chunkIndex: i,
      leafHash: uint8ArrayToHex(leaf),
      receiptToken: "",
      data: data.buffer as ArrayBuffer,
      metadata: serializeMetadata({
        schemaVersion: 1,
        messageType: MessageType.Text,
        hash,
        name: "a4",
        totalSize: totalChunks * 100,
        date: new Date(0),
        chunkStartIndex: 10,
        chunkEndIndex: 110,
        chunkIndex: i,
      }).buffer as ArrayBuffer,
      merkleProof: new ArrayBuffer(0),
    });
  }
  const merkleRoot = await getMerkleRoot(leaves, module);
  let holdReads = false;
  let released: () => void = () => undefined;
  let readHeld: () => void = () => undefined;
  const readIsHeld = new Promise<void>((resolve) => {
    readHeld = resolve;
  });
  const store = {
    get: async (_transferId: string, index: number) => {
      if (holdReads) {
        readHeld();
        await new Promise<void>((resolve) => {
          released = resolve;
        });
      }
      const row = rows.get(index);
      return row ? structuredClone(row) : undefined;
    },
    put: async (chunk: NewChunk) => {
      rows.set(chunk.chunkIndex, structuredClone(chunk));
    },
  };
  return {
    params: {
      transferId: TRANSFER_ID,
      hashHex: HASH_HEX,
      merkleRoot,
      totalChunks,
      chunkHashes: leaves,
      merkleModule: module,
      store,
    },
    merkleRootHex: uint8ArrayToHex(merkleRoot),
    holdNextRead: () => {
      holdReads = true;
    },
    readIsHeld,
    releaseRead: () => {
      holdReads = false;
      released();
    },
  };
};

/** The send's ratchet steps, with their keys kept so a wipe is visible. */
const steppingRatchet = () => {
  const keys: Uint8Array[] = [];
  const pqRoots: Uint8Array[] = [];
  return {
    keys,
    pqRoots,
    ratchetStep: async (epc: IRTCPeerConnection) => {
      const stepped = ratchetEncrypt(epc.ratchetState!, module);
      const live = epc.pqHealingState!.currentMessageContext();
      const pqContext = {
        rootKey: Uint8Array.from(live.rootKey),
        binding: Uint8Array.from(live.binding),
        rootSuite: live.rootSuite,
        epoch: live.epoch,
      };
      keys.push(stepped.messageKey);
      pqRoots.push(pqContext.rootKey);
      return {
        messageKey: stepped.messageKey,
        header: stepped.header,
        pqContext,
      };
    },
  };
};

const allZero = (bytes: Uint8Array): boolean => bytes.every((b) => b === 0);

describe("a scheduled delivery that ends leaves the edge's schedule intact", () => {
  test("closing a message while a scheduled cell is being read does not degrade the edge", async () => {
    const edge = makeEdge();
    const staged = await stageMessage();
    const label = await compileChannelMessageLabel(
      "chat",
      staged.merkleRootHex,
    );
    const { ratchetStep } = steppingRatchet();
    edge.runtime.start();

    // Another message's job on the same edge, admitted to the other lane.
    const otherJob = edge.runtime.randomLaneLabel();
    edge.runtime.enqueue({
      id: otherJob,
      kind: "control",
      declaredCellCount: 2,
      nextCell: () => new Uint8Array(WIRE_CHUNK_FRAME_LEN),
    });

    // The receiver confirms the message while this send's first cell is
    // still being read from storage.
    staged.holdNextRead();
    const delivery = withOutboundMessage(staged.params, (message) =>
      sendScheduled(
        ROOM,
        "chat",
        policy,
        [{ peerId: PEER, epc: edge.epc }],
        message,
        module,
        undefined,
        undefined,
        [edge.epc],
        {
          waitForGate: async () => undefined,
          ratchetStep,
          waitForDelivery: async () => {
            await staged.readIsHeld;
            return true;
          },
        },
      ),
    );

    let t = 0;
    let settled = false;
    void delivery.then(() => {
      settled = true;
    });
    while (!settled && t < 4_000) {
      t += 25;
      await edge.clock.advanceTo(t);
    }
    expect(settled).toBe(true);
    expect((await delivery).outcomes).toEqual([
      { peerId: PEER, status: "delivered" },
    ]);
    // The message is closed and its job settled; the read is still held.
    expect(edge.results).toContainEqual({ jobId: label, outcome: "completed" });

    // The read completes after the delivery ended.
    staged.releaseRead();
    for (let i = 0; i < 20; i++) await Promise.resolve();
    // Run the rest of this cycle and the whole next one.
    await edge.clock.advanceTo(t + 800);

    // The schedule never degraded, and nothing on the edge was requeued.
    expect(edge.statuses).not.toContain("degraded");
    expect(edge.interruptions).toEqual([]);
    expect(edge.runtime.status).toBe("active");
    // The other job sent both its cells and settled as completed.
    expect(edge.results).toContainEqual({
      jobId: otherJob,
      outcome: "completed",
    });
    // Slots stayed armed: every lane kept sending one cell per slot, so two
    // cycles' worth of cells (C × F × D × 2) went out after the first opened.
    const sent = edge.lanes.reduce((total, lane) => total + lane.sent, 0);
    expect(sent).toBeGreaterThanOrEqual(8);
    expect(edge.clock.armed).toBeGreaterThan(0);
  });
});

describe("a job settled under an in-flight cell leaves the edge's schedule intact", () => {
  test("a job settled while its cell is being read does not degrade the edge", async () => {
    // The resume path settles a retired job on a runtime that stays live (a
    // PQ re-derive on the same edge) while the delivery, and its message,
    // carry on. A cell in flight then finds its key wiped.
    const edge = makeEdge();
    const staged = await stageMessage();
    const label = await compileChannelMessageLabel(
      "chat",
      staged.merkleRootHex,
    );
    const stepping = steppingRatchet();
    edge.runtime.start();
    staged.holdNextRead();
    const lanesSent = (): number =>
      edge.lanes.reduce((total, lane) => total + lane.sent, 0);

    const delivery = withOutboundMessage(staged.params, (message) =>
      sendScheduled(
        ROOM,
        "chat",
        policy,
        [{ peerId: PEER, epc: edge.epc }],
        message,
        module,
        undefined,
        undefined,
        [edge.epc],
        {
          waitForGate: async () => undefined,
          ratchetStep: stepping.ratchetStep,
          waitForDelivery: async () => {
            await staged.readIsHeld;
            edge.runtime.complete(label);
            expect(allZero(stepping.keys[0])).toBe(true);
            expect(message.closed).toBe(false);
            const sentBefore = lanesSent();
            const pendingSlot = edge.nextSlotResult();
            staged.releaseRead();
            // Keep the delivery (and its message) open until the scheduler has
            // answered the slot whose cell was in flight: a cell on the lane,
            // or a degraded schedule.
            await pendingSlot;
            expect(lanesSent()).toBeGreaterThan(sentBefore);
            return true;
          },
        },
      ),
    );
    let t = 0;
    let settled = false;
    void delivery.then(() => {
      settled = true;
    });
    while (!settled && t < 4_000) {
      // Preparation is asynchronous; sending occurs on the next scheduled
      // slot. Advance the fake clock while the delivery waits on that event.
      t += 25;
      await edge.clock.advanceTo(t);
      await new Promise((resolve) => setImmediate(resolve));
    }
    expect(settled).toBe(true);
    await edge.clock.advanceTo(t + 800);
    expect(edge.statuses).not.toContain("degraded");
    expect(edge.interruptions).toEqual([]);
    expect(edge.runtime.status).toBe("active");
  });

  test("a send cancelled while its cell is being read does not degrade the edge", async () => {
    // The user cancels while a cell is being read. The send has not yet
    // unwound (its message is still open, its job not yet cancelled), so the
    // cell in flight meets the abort first.
    const controller = new AbortController();
    const edge = makeEdge();
    const staged = await stageMessage();
    const stepping = steppingRatchet();
    edge.runtime.start();
    staged.holdNextRead();
    const lanesSent = (): number =>
      edge.lanes.reduce((total, lane) => total + lane.sent, 0);

    const delivery = withOutboundMessage(staged.params, (message) =>
      sendScheduled(
        ROOM,
        "chat",
        policy,
        [{ peerId: PEER, epc: edge.epc }],
        message,
        module,
        controller.signal,
        undefined,
        [edge.epc],
        {
          waitForGate: async () => undefined,
          ratchetStep: stepping.ratchetStep,
          waitForDelivery: async () => {
            await staged.readIsHeld;
            controller.abort(new Error("Message transfer cancelled"));
            expect(message.closed).toBe(false);
            const sentBefore = lanesSent();
            const pendingSlot = edge.nextSlotResult();
            staged.releaseRead();
            // Keep the delivery (and its message) open until the scheduler has
            // answered the slot whose cell was in flight: a cell on the lane,
            // or a degraded schedule.
            await pendingSlot;
            expect(lanesSent()).toBeGreaterThan(sentBefore);
            return false;
          },
        },
      ),
    );
    let t = 0;
    let settled = false;
    void delivery.then(() => {
      settled = true;
    });
    while (!settled && t < 4_000) {
      // Preparation is asynchronous; sending occurs on the next scheduled
      // slot. Advance the fake clock while the delivery waits on that event.
      t += 25;
      await edge.clock.advanceTo(t);
      await new Promise((resolve) => setImmediate(resolve));
    }
    expect(settled).toBe(true);
    await edge.clock.advanceTo(t + 800);
    expect(edge.statuses).not.toContain("degraded");
    expect(edge.interruptions).toEqual([]);
    expect(edge.runtime.status).toBe("active");
  });
});

describe("a delivered scheduled job is settled at delivery", () => {
  test("a delivered scheduled job settles as completed and wipes its keys at once", async () => {
    const edge = makeEdge();
    const staged = await stageMessage();
    const label = await compileChannelMessageLabel(
      "chat",
      staged.merkleRootHex,
    );
    const stepping = steppingRatchet();
    edge.runtime.start();

    let queuedWhileWaiting = false;
    let keyLiveWhileWaiting = false;
    const result = await withOutboundMessage(staged.params, (message) =>
      sendScheduled(
        ROOM,
        "chat",
        policy,
        [{ peerId: PEER, epc: edge.epc }],
        message,
        module,
        undefined,
        undefined,
        [edge.epc],
        {
          waitForGate: async () => undefined,
          ratchetStep: stepping.ratchetStep,
          // Confirmed before the cycle that would admit it even opens.
          waitForDelivery: async () => {
            queuedWhileWaiting = edge.runtime.getQueuedJobIds().includes(label);
            keyLiveWhileWaiting = !allZero(stepping.keys[0]);
            return true;
          },
        },
      ),
    );

    expect(result.outcomes).toEqual([{ peerId: PEER, status: "delivered" }]);
    expect(queuedWhileWaiting).toBe(true);
    expect(keyLiveWhileWaiting).toBe(true);
    // At delivery, with no clock time elapsed: completed, not left to be
    // retired as capacity-exhausted at a cycle boundary, and its secrets gone.
    expect(edge.clock.now()).toBe(0);
    expect(edge.results).toEqual([{ jobId: label, outcome: "completed" }]);
    expect(edge.runtime.getJobProgress(label)).toBeUndefined();
    expect(allZero(stepping.keys[0])).toBe(true);
    expect(allZero(stepping.pqRoots[0])).toBe(true);

    // A later cycle neither admits it nor settles it a second time.
    await edge.clock.advanceTo(1_200);
    expect(edge.results).toEqual([{ jobId: label, outcome: "completed" }]);
    expect(edge.statuses).not.toContain("degraded");
  });
});
