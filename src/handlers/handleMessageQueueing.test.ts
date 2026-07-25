import { describe, expect, test } from "bun:test";

import {
  shouldSendImmediateTerminalReceipt,
  createReceiptProcessingQueue,
  enqueue,
  enqueueReceipt,
  MAX_QUEUED_BYTES_PER_EDGE,
  MAX_QUEUED_FRAMES_PER_CHANNEL,
  MAX_QUEUED_RECEIPTS_PER_CHANNEL,
  MAX_QUEUED_RECEIPTS_PER_EDGE,
  releaseQueuedMessageFrames,
  releaseQueuedReceipts,
  waitForQueuedMessageFrames,
} from "./handleMessageQueueing";

import type { LibCrypto } from "../cryptography/libcrypto";

const inertArgs = {
  api: {} as Parameters<typeof enqueue>[4],
  roomId: "room",
  peerId: "peer",
  channelLabel: "chat",
  merkleRootHex: "00".repeat(64),
  merkleRoot: new Uint8Array(64),
  extChannel: undefined,
  epc: undefined,
  module: {} as LibCrypto,
};

const add = (
  data: Uint8Array,
  queue: Uint8Array[],
  seen: Set<string>,
  drainingRef = { value: true },
  signal?: AbortSignal,
): boolean =>
  enqueue(
    data,
    queue,
    seen,
    drainingRef,
    inertArgs.api,
    inertArgs.roomId,
    inertArgs.peerId,
    inertArgs.channelLabel,
    inertArgs.merkleRootHex,
    inertArgs.merkleRoot,
    inertArgs.extChannel,
    inertArgs.epc,
    inertArgs.module,
    signal,
  );

describe("message receive queue budgets", () => {
  test("caps queued frames on one channel", () => {
    const queue: Uint8Array[] = [];
    const seen = new Set<string>();
    for (let i = 0; i < MAX_QUEUED_FRAMES_PER_CHANNEL; i++) {
      const frame = new Uint8Array(128);
      new DataView(frame.buffer).setUint32(0, i);
      expect(add(frame, queue, seen)).toBe(true);
    }
    const overflow = new Uint8Array(129);
    overflow[overflow.length - 1] = 0xff;
    expect(add(overflow, queue, seen)).toBe(false);
    expect(queue).toHaveLength(MAX_QUEUED_FRAMES_PER_CHANNEL);
    releaseQueuedMessageFrames(queue, inertArgs.roomId, inertArgs.peerId);
  });

  test("caps aggregate queued bytes across channels on one edge", () => {
    const queues: Uint8Array[][] = [];
    const frameBytes = 1024 * 1024;
    const accepted = MAX_QUEUED_BYTES_PER_EDGE / frameBytes;
    for (let i = 0; i < accepted; i++) {
      const queue: Uint8Array[] = [];
      const frame = new Uint8Array(frameBytes);
      new DataView(frame.buffer).setUint32(0, i);
      expect(add(frame, queue, new Set())).toBe(true);
      queues.push(queue);
    }
    const overflow = new Uint8Array(frameBytes);
    overflow[overflow.length - 1] = 0xff;
    expect(add(overflow, [], new Set())).toBe(false);
    for (const queue of queues)
      releaseQueuedMessageFrames(queue, inertArgs.roomId, inertArgs.peerId);
  });

  test("release aborts queued work and settles channel quiescence", async () => {
    const queue: Uint8Array[] = [];
    const seen = new Set<string>();
    const state = { value: false };
    const controller = new AbortController();
    controller.abort();

    expect(
      add(new Uint8Array(128), queue, seen, state, controller.signal),
    ).toBe(false);
    expect(queue).toHaveLength(0);

    state.value = true;
    queue.push(new Uint8Array(64));
    const idle = waitForQueuedMessageFrames(queue, state);
    releaseQueuedMessageFrames(
      queue,
      inertArgs.roomId,
      inertArgs.peerId,
      state,
    );
    let settled = false;
    void idle.then(() => {
      settled = true;
    });
    await Promise.resolve();
    expect(settled).toBe(false);

    state.value = false;
    // A second idempotent release observes that the active handler has now
    // exited and resolves the quiescence waiter.
    releaseQueuedMessageFrames(
      queue,
      inertArgs.roomId,
      inertArgs.peerId,
      state,
    );
    await idle;
    expect(settled).toBe(true);
  });
});

const waitUntil = async (condition: () => boolean): Promise<void> => {
  const deadline = Date.now() + 2_000;
  while (!condition()) {
    if (Date.now() >= deadline) throw new Error("Timed out waiting for queue");
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
};

describe("receipt processing queue", () => {
  test("deduplicates and serializes receipts on one edge", async () => {
    const state = createReceiptProcessingQueue("room-rx", "peer-rx");
    let releaseFirst!: () => void;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let active = 0;
    let maxActive = 0;
    let processed = 0;
    const process = async () => {
      active++;
      maxActive = Math.max(maxActive, active);
      processed++;
      if (processed === 1) await firstGate;
      active--;
    };
    const first = new Uint8Array(64).fill(1);
    const second = new Uint8Array(64).fill(2);

    expect(enqueueReceipt(first, state, process)).toBe(true);
    expect(enqueueReceipt(first, state, process)).toBe(true);
    expect(enqueueReceipt(second, state, process)).toBe(true);
    await waitUntil(() => processed === 1);
    expect(state.pending).toHaveLength(1);
    releaseFirst();
    await waitUntil(() => processed === 2);

    expect(maxActive).toBe(1);
    expect(processed).toBe(2);
    releaseQueuedReceipts(state);
  });

  test("caps an authenticated receipt flood without spawning one worker per frame", async () => {
    const state = createReceiptProcessingQueue("room-flood", "peer-flood");
    let releaseWorker!: () => void;
    const workerGate = new Promise<void>((resolve) => {
      releaseWorker = resolve;
    });
    let workersStarted = 0;
    const process = async () => {
      workersStarted++;
      await workerGate;
    };

    expect(
      enqueueReceipt(new Uint8Array(64), state, process),
    ).toBe(true);
    await waitUntil(() => workersStarted === 1);
    for (let i = 0; i < MAX_QUEUED_RECEIPTS_PER_CHANNEL; i++) {
      const receipt = new Uint8Array(64);
      new DataView(receipt.buffer).setUint32(0, i + 1);
      expect(enqueueReceipt(receipt, state, process)).toBe(true);
    }
    const overflow = new Uint8Array(64);
    overflow.fill(0xff);
    expect(enqueueReceipt(overflow, state, process)).toBe(false);
    expect(state.pending).toHaveLength(MAX_QUEUED_RECEIPTS_PER_CHANNEL);
    expect(workersStarted).toBe(1);

    releaseQueuedReceipts(state);
    releaseWorker();
  });

  test("caps aggregate receipt backlog across channels on one edge", async () => {
    const states = Array.from({ length: 5 }, () =>
      createReceiptProcessingQueue("room-edge-cap", "peer-edge-cap"),
    );
    let releaseWorker!: () => void;
    const workerGate = new Promise<void>((resolve) => {
      releaseWorker = resolve;
    });
    const process = async () => {
      await workerGate;
    };

    const channelsToFill =
      MAX_QUEUED_RECEIPTS_PER_EDGE / MAX_QUEUED_RECEIPTS_PER_CHANNEL;
    expect(Number.isInteger(channelsToFill)).toBe(true);
    for (let channelIndex = 0; channelIndex < channelsToFill; channelIndex++) {
      // The first receipt becomes the one bounded active/waiting operation for
      // this channel; the remaining cap is plain queued data.
      const active = new Uint8Array(64);
      new DataView(active.buffer).setUint32(0, channelIndex + 1);
      active[63] = 1;
      expect(enqueueReceipt(active, states[channelIndex], process)).toBe(true);
      for (let i = 0; i < MAX_QUEUED_RECEIPTS_PER_CHANNEL; i++) {
        const receipt = new Uint8Array(64);
        const view = new DataView(receipt.buffer);
        view.setUint32(0, channelIndex + 1);
        view.setUint32(4, i + 1);
        expect(
          enqueueReceipt(receipt, states[channelIndex], process),
        ).toBe(true);
      }
    }
    const overflow = new Uint8Array(64).fill(0xee);
    expect(enqueueReceipt(overflow, states[4], process)).toBe(false);

    for (const state of states) releaseQueuedReceipts(state);
    releaseWorker();
  });

  test("serializes worker execution across channels on the same peer edge", async () => {
    const first = createReceiptProcessingQueue("room-edge", "peer-edge");
    const second = createReceiptProcessingQueue("room-edge", "peer-edge");
    let releaseFirst!: () => void;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let active = 0;
    let maxActive = 0;
    let started = 0;
    const process = async () => {
      active++;
      maxActive = Math.max(maxActive, active);
      started++;
      if (started === 1) await firstGate;
      active--;
    };

    enqueueReceipt(new Uint8Array(64).fill(3), first, process);
    enqueueReceipt(new Uint8Array(64).fill(4), second, process);
    await waitUntil(() => started === 1);
    expect(maxActive).toBe(1);
    releaseFirst();
    await waitUntil(() => started === 2);
    expect(maxActive).toBe(1);

    releaseQueuedReceipts(first);
    releaseQueuedReceipts(second);
  });
});

describe("terminal receipt emission", () => {
  test("immediate mode sends the terminal receipt as a frame", () => {
    expect(shouldSendImmediateTerminalReceipt(undefined)).toBe(true);
    expect(shouldSendImmediateTerminalReceipt({})).toBe(true);
  });

  test("scheduled mode never emits an immediate terminal receipt", () => {
    // The scheduled terminal receipt is queued as a cover cell instead. An
    // immediate 65-byte frame here would be an off-schedule packet emitted at
    // the exact moment a real transfer completed — perfectly correlated with
    // the event the cover schedule exists to conceal, and a different size
    // from the 65,490-byte cells around it.
    const withCover = {
      coverRuntime: {} as unknown as NonNullable<
        Parameters<typeof shouldSendImmediateTerminalReceipt>[0]
      >["coverRuntime"],
    };
    expect(shouldSendImmediateTerminalReceipt(withCover)).toBe(false);
  });
});
