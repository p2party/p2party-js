import { beforeAll, describe, expect, test } from "bun:test";

import { CoverRuntime } from "../../src/handlers/coverRuntime";
import { createCoverScheduler } from "../../src/handlers/coverScheduler";
import {
  buildScheduledSendJob,
  queueScheduledChunkReceipt,
} from "../../src/handlers/coverTransfer";
import { openCoverCell } from "../../src/cryptography/coverCell";
import { createMessageChunkSealer } from "../../src/handlers/messageChunkCrypto";
import { SparsePqHealingState } from "../../src/handlers/pqHealingRuntime";
import { loadTestModule } from "../../src/cryptography/testModule";
import { compileChannelMessageLabel } from "../../src/utils/channelLabel";
import { uint8ArrayToHex } from "../../src/utils/uint8array";
import {
  DECRYPTED_LEN,
  FRAME_TYPE_CHUNK,
  FRAME_TYPE_COVER,
  RATCHET_ROOT_SUITE_MLKEM512,
  WIRE_CHUNK_FRAME_LEN,
} from "../../src/utils/constants";
import { CoverTimeline } from "./coverTimerFakes";

import type { CoverLaneChannel } from "../../src/handlers/coverRuntime";
import type {
  CoverClock,
  CoverSchedule,
  CoverSchedulerStatus,
} from "../../src/handlers/coverScheduler";
import type { LibCrypto } from "../../src/cryptography/libcrypto";
import type { IRTCPeerConnection } from "../../src/api/webrtc/interfaces";

// A scheduled cell's send time must not show whether it is real (transport
// audit 2026-11, A12). The cell for a slot is produced during the slot before,
// and the slot's wake-up only sends it. Measured in Chromium before the change
// (docs/e2e/cover-timers/, sealed mode), a real chunk read from the outbox
// store, its receipt token written back and sealed, left about 2 ms later than
// a dummy at the median, and 38 % of them later than 99 % of dummies.
//
// Everything here runs on one virtual clock (CoverTimeline): the runtime's own
// timer-worker clock, and the "store read" each real cell waits for, a page
// timer on the same timeline. So an offset from the slot time is exact.

let module: LibCrypto;
beforeAll(async () => {
  module = await loadTestModule();
});

const ROOM_ID = "00000000-0000-4000-8000-0000000000a1";

/** 2 lanes x 2 frames per 400 ms cycle: a slot every 100 ms, at 50 mod 100. */
const SCHEDULE = {
  coverCadenceMs: 400,
  coverLanes: 2,
  coverFramesPerCell: 2,
  coverDurationEpochs: 1,
};
const SLOT_SPACING_MS = 100;
const FIRST_SLOT_MS = 50;

interface Sent {
  readonly at: number;
  readonly frame: Uint8Array;
}

class RecordingLane implements CoverLaneChannel {
  readonly label: string;
  readyState: string = "open";
  bufferedAmount = 0;
  readonly sent: Sent[] = [];

  constructor(
    label: string,
    private readonly timeline: CoverTimeline,
    private readonly onSend?: () => void,
  ) {
    this.label = label;
  }

  send(data: ArrayBuffer): void {
    this.onSend?.();
    this.sent.push({ at: this.timeline.time, frame: new Uint8Array(data) });
  }

  close(): void {
    this.readyState = "closed";
  }
}

const makePq = (): SparsePqHealingState =>
  new SparsePqHealingState({
    module,
    pqMode: "hybrid-mlkem512",
    rootSuite: RATCHET_ROOT_SUITE_MLKEM512,
    binding: new Uint8Array(32).fill(0x42),
    rootKey: new Uint8Array(32).fill(0x24),
    nextOfferer: "local",
    amInitiator: true,
    now: 0,
  });

const makeRig = (
  timeline: CoverTimeline,
  schedule: typeof SCHEDULE = SCHEDULE,
  hooks: { readonly onOpen?: () => void; readonly onSend?: () => void } = {},
  policyHash: Uint8Array = new Uint8Array(32),
) => {
  const pq = makePq();
  const epc = {
    roomId: ROOM_ID,
    pqHealingState: pq,
  } as unknown as IRTCPeerConnection;
  const lanes: RecordingLane[] = [];
  const statuses: Array<[CoverSchedulerStatus, string]> = [];
  const runtime = new CoverRuntime({
    epc,
    roomId: ROOM_ID,
    module,
    amInitiator: true,
    schedule,
    policyHash,
    laneLabelName: "party",
    openLaneChannel: (label) => {
      hooks.onOpen?.();
      const lane = new RecordingLane(label, timeline, hooks.onSend);
      lanes.push(lane);
      return lane;
    },
    onStatusChange: ({ status, reason }) =>
      statuses.push([status, reason ?? ""]),
    timerEnvironment: timeline.env,
  });
  const sentOn = (label: string): Sent[] =>
    lanes
      .filter((lane) => lane.label === label)
      .flatMap((lane) => lane.sent)
      .sort((left, right) => left.at - right.at);
  const allSent = (): Sent[] => lanes.flatMap((lane) => lane.sent);
  return { pq, runtime, lanes, statuses, sentOn, allSent };
};

/** A store read: resolves after `ms` on the timeline, as a page task. */
const storeRead = (timeline: CoverTimeline, ms: number): Promise<void> =>
  new Promise((resolve) => timeline.env.setTimeout(resolve, ms));

const merkleRootOf = (seed: number): Uint8Array =>
  new Uint8Array(64).fill(seed);

/**
 * A scheduled send job of `cells` real chunks whose cells come out of the real
 * message sealer, each after a store read of `readMs(call)` on the timeline.
 */
const realJob = async (
  rig: ReturnType<typeof makeRig>,
  timeline: CoverTimeline,
  cells: number,
  readMs: (call: number) => number,
) => {
  const merkleRoot = merkleRootOf(0x5a);
  const label = await compileChannelMessageLabel(
    "party",
    uint8ArrayToHex(merkleRoot),
  );
  const context = rig.pq.currentMessageContext();
  const sealer = createMessageChunkSealer(
    new Uint8Array(32).fill(0x31),
    { dhPub: new Uint8Array(32).fill(0x07), N: 0, PN: 0 },
    {
      ...context,
      rootKey: Uint8Array.from(context.rootKey),
      binding: Uint8Array.from(context.binding),
    },
    module,
  );
  let calls = 0;
  const job = buildScheduledSendJob({
    runtime: rig.runtime,
    channelMessageLabel: label,
    totalChunks: cells,
    merkleRoot,
    sealSlotCell: async (chunkIndex) => {
      await storeRead(timeline, readMs(calls++));
      return sealer.seal(
        new Uint8Array(DECRYPTED_LEN).fill(chunkIndex + 1),
        merkleRoot,
      );
    },
  });
  return { job, label, wipe: () => sealer.wipe() };
};

/** A clock for the scheduler alone: timers, and values that resolve later. */
const manualClock = () => {
  let time = 0;
  let nextId = 1;
  const timers = new Map<number, { at: number; run: () => void }>();
  const clock: CoverClock = {
    now: () => time,
    setTimeout: (callback, delayMs) => {
      const id = nextId++;
      timers.set(id, { at: time + delayMs, run: callback });
      return id;
    },
    clearTimeout: (handle) => {
      timers.delete(handle as number);
    },
  };
  const advanceTo = async (target: number): Promise<void> => {
    for (;;) {
      for (let i = 0; i < 8; i++) await Promise.resolve();
      const due = [...timers.entries()]
        .filter(([, timer]) => timer.at <= target)
        .sort(([a, left], [b, right]) => left.at - right.at || a - b)[0];
      if (!due) break;
      timers.delete(due[0]);
      time = due[1].at;
      due[1].run();
    }
    time = target;
    for (let i = 0; i < 8; i++) await Promise.resolve();
  };
  /** A value that resolves `ms` from now on this clock. */
  const after = <T>(ms: number, value: T): Promise<T> =>
    new Promise((resolve) => {
      clock.setTimeout(() => resolve(value), ms);
    });
  return { clock, advanceTo, after };
};

describe("a cover cell's send time does not show what it carries", () => {
  test("a real cell and a dummy leave at the same offset from the slot time", async () => {
    const timeline = new CoverTimeline();
    const rig = makeRig(timeline);
    // Every real cell waits 30 ms for the store, then is sealed.
    const real = await realJob(rig, timeline, 2, () => 30);
    try {
      rig.runtime.enqueue(real.job);
      rig.runtime.start();
      await timeline.advanceTo(2 * SCHEDULE.coverCadenceMs - 1);

      const realCells = rig.sentOn(real.label);
      expect(realCells.map(({ at }) => at)).toEqual([50, 250]);
      expect(
        realCells.every(({ frame }) => frame[0] === FRAME_TYPE_CHUNK),
      ).toBe(true);
      const dummies = rig
        .allSent()
        .filter(({ frame }) => frame[0] === FRAME_TYPE_COVER);
      expect(dummies).toHaveLength(6);
      // Every cell, real or dummy, left exactly at its slot time.
      for (const { at } of rig.allSent())
        expect((at - FIRST_SLOT_MS) % SLOT_SPACING_MS).toBe(0);
      expect(rig.statuses.map(([status]) => status)).toEqual([
        "starting",
        "active",
      ]);
    } finally {
      rig.runtime.destroy();
      real.wipe();
      rig.pq.destroy();
    }
  });

  test("a cell not ready at its wake-up is replaced by a dummy on time, and its chunk goes in a later slot", async () => {
    const timeline = new CoverTimeline();
    const rig = makeRig(timeline);
    // The job's first cell is produced at the cycle open, half a slot before
    // its slot at 50 ms: a 70 ms read is not ready when the slot comes.
    const real = await realJob(rig, timeline, 2, (call) =>
      call === 0 ? 70 : 0,
    );
    try {
      rig.runtime.enqueue(real.job);
      rig.runtime.start();
      await timeline.advanceTo(3 * SCHEDULE.coverCadenceMs - 1);

      // Every slot of every cycle sent a cell, on the slot grid.
      expect(rig.allSent()).toHaveLength(12);
      for (const { at } of rig.allSent())
        expect((at - FIRST_SLOT_MS) % SLOT_SPACING_MS).toBe(0);
      // Nothing degraded: the slot went out with its dummy, on time.
      expect(rig.statuses.map(([status]) => status)).toEqual([
        "starting",
        "active",
      ]);
      // The job's lane: a dummy at 50, its first chunk in its next slot, its
      // second in the next cycle (it was requeued), then dummies.
      const lane = rig.sentOn(real.label);
      expect(lane.map(({ at, frame }) => [at, frame[0]])).toEqual([
        [50, FRAME_TYPE_COVER],
        [250, FRAME_TYPE_CHUNK],
        [450, FRAME_TYPE_CHUNK],
        [650, FRAME_TYPE_COVER],
      ]);
    } finally {
      rig.runtime.destroy();
      real.wipe();
      rig.pq.destroy();
    }
  });

  test("a slot's work before production is the same whether it will carry a chunk or a dummy", async () => {
    const clock = manualClock();
    const log: string[] = [];
    const scheduler = createCoverScheduler({
      schedule: { ...SCHEDULE, phaseOffsetMs: 0 },
      clock: clock.clock,
      makeDummy: (slot) => {
        log.push(`dummy for ${String(slot.deadlineMs)}`);
        return new Uint8Array(8).fill(0xdd);
      },
      laneFactory: () => ({ send: () => undefined, close: () => undefined }),
    });
    let next = 0;
    scheduler.enqueue({
      id: "chunks",
      kind: "real",
      declaredCellCount: 2,
      nextCell: (slot) => {
        log.push(`chunk for ${String(slot.deadlineMs)}`);
        return new Uint8Array(8).fill(++next);
      },
    });
    scheduler.start();
    await clock.advanceTo(SCHEDULE.coverCadenceMs - 1);
    // Lane 0 carries the job (50, 250), lane 1 nothing (150, 350). Each slot
    // gets one dummy, sealed before anything else is produced for it.
    expect(log).toEqual([
      "dummy for 50",
      "chunk for 50",
      "dummy for 150",
      "dummy for 250",
      "chunk for 250",
      "dummy for 350",
    ]);
    scheduler.stop();
  });

  test("a job that lost a slot to a dummy is requeued, not failed", async () => {
    const clock = manualClock();
    const sent: string[] = [];
    const results: string[] = [];
    const interruptions: string[] = [];
    // One lane of two slots a cycle (50 and 150 in each 200 ms).
    const scheduler = createCoverScheduler({
      schedule: {
        phaseOffsetMs: 0,
        coverCadenceMs: 200,
        coverLanes: 1,
        coverFramesPerCell: 2,
        coverDurationEpochs: 1,
      },
      clock: clock.clock,
      makeDummy: () => new Uint8Array(8).fill(0xdd),
      laneFactory: () => ({
        send: (request) => {
          sent.push(`${String(clock.clock.now())} ${request.source}`);
        },
        close: () => undefined,
      }),
      onJobResult: ({ outcome, reason }) =>
        results.push(`${outcome}${reason ? ` ${reason}` : ""}`),
      onJobInterrupted: ({ reason }) => interruptions.push(reason),
    });
    let calls = 0;
    scheduler.enqueue({
      id: "two-cells",
      kind: "real",
      declaredCellCount: 2,
      // Its first cell takes 80 ms, past its slot at 50.
      nextCell: () =>
        calls++ === 0
          ? clock.after(80, new Uint8Array(8).fill(1))
          : new Uint8Array(8).fill(2),
    });
    scheduler.start();
    await clock.advanceTo(400);

    expect(sent).toEqual(["50 dummy", "150 real", "250 real", "350 dummy"]);
    expect(interruptions).toEqual(["missed-deadline"]);
    expect(results).toEqual(["completed"]);
    expect(scheduler.getStatus()).toBe("active");
    scheduler.stop();
  });

  test("a cell produced but not sent is not lost and not sent twice", async () => {
    // 2 lanes x 3 frames per 600 ms: the job's lane sends at 50, 250 and 450
    // in each cycle. Its second cell's read takes 500 ms, so its slot at 250
    // gives up on it, and a suspension and resume at 260/270 brings the job
    // back into the next cycle while that read is still running.
    const schedule = {
      ...SCHEDULE,
      coverCadenceMs: 600,
      coverFramesPerCell: 3,
    };
    const timeline = new CoverTimeline();
    const rig = makeRig(timeline, schedule);
    const merkleRoot = merkleRootOf(0x6b);
    const label = await compileChannelMessageLabel(
      "party",
      uint8ArrayToHex(merkleRoot),
    );
    let calls = 0;
    const job = buildScheduledSendJob({
      runtime: rig.runtime,
      channelMessageLabel: label,
      totalChunks: 3,
      merkleRoot,
      sealSlotCell: async (chunkIndex) => {
        await storeRead(timeline, calls++ === 1 ? 500 : 0);
        // A cell that names its chunk.
        return new Uint8Array(WIRE_CHUNK_FRAME_LEN).fill(chunkIndex + 1);
      },
    });
    try {
      rig.runtime.enqueue(job);
      rig.runtime.start();
      await timeline.advanceTo(260);
      rig.runtime.suspend("freeze");
      await timeline.advanceTo(270);
      rig.runtime.resume();
      await timeline.advanceTo(4 * schedule.coverCadenceMs - 1);

      // The job's lane: its three chunks, each once and in order; the rest
      // of its slots carried dummies.
      const chunks = rig
        .sentOn(label)
        .map(({ frame }) => frame[0])
        .filter((first) => first !== FRAME_TYPE_COVER);
      expect(chunks).toEqual([1, 2, 3]);
      for (const { at } of rig.allSent())
        expect((at - FIRST_SLOT_MS) % SLOT_SPACING_MS).toBe(0);
    } finally {
      rig.runtime.destroy();
      rig.pq.destroy();
    }
  });

  test("every edge sends its cell for a slot before any edge produces its next one", async () => {
    // Two edges of one room on one page: one slot grid, one timer worker.
    // Each edge's next cell is produced right after its send; were that done
    // before the other edge's wake-up for the same slot ran, the other edge's
    // send (or, at a cycle open, its lane opens) would wait on what this
    // edge's next cell carries. Measured in Chromium with the production
    // started inside each edge's own wake-up, the real cells of one edge left
    // 0.5 ms later than the dummies at the median, from the edges before it.
    const timeline = new CoverTimeline();
    const log: string[] = [];
    const edges = await Promise.all(
      ["A", "B"].map(async (name, index) => {
        const rig = makeRig(timeline, SCHEDULE, {
          onOpen: () => log.push(`${String(timeline.time)} ${name} opens`),
          onSend: () => log.push(`${String(timeline.time)} ${name} sends`),
        });
        const merkleRoot = merkleRootOf(0x20 + index);
        const label = await compileChannelMessageLabel(
          "party",
          uint8ArrayToHex(merkleRoot),
        );
        rig.runtime.enqueue(
          buildScheduledSendJob({
            runtime: rig.runtime,
            channelMessageLabel: label,
            totalChunks: 2,
            merkleRoot,
            sealSlotCell: (chunkIndex) => {
              log.push(`${String(timeline.time)} ${name} produces`);
              return new Uint8Array(WIRE_CHUNK_FRAME_LEN).fill(chunkIndex + 1);
            },
          }),
        );
        return { name, rig };
      }),
    );
    try {
      for (const { rig } of edges) rig.runtime.start();
      await timeline.advanceTo(SCHEDULE.coverCadenceMs - 1);

      const at = (time: number) =>
        log.filter((line) => line.startsWith(`${String(time)} `));
      // At the cycle open both edges open their lanes before either produces.
      expect(at(0)).toEqual([
        "0 A opens",
        "0 A opens",
        "0 B opens",
        "0 B opens",
        "0 A produces",
        "0 B produces",
      ]);
      expect(at(50)).toEqual(["50 A sends", "50 B sends"]);
      expect(at(150)).toEqual([
        "150 A sends",
        "150 B sends",
        "150 A produces",
        "150 B produces",
      ]);
      expect(at(250)).toEqual(["250 A sends", "250 B sends"]);
    } finally {
      for (const { rig } of edges) {
        rig.runtime.destroy();
        rig.pq.destroy();
      }
    }
  });

  test("a production does not start inside another grid's wake-up window", async () => {
    // Two rooms on one page: grid B's slots fall 2 ms after grid A's, within
    // the bound of a production's first synchronous work. A's production of
    // its next cell, due right after its send at 150, waits until B's
    // wake-up at 152 has run.
    const timeline = new CoverTimeline();
    const log: string[] = [];
    const a = makeRig(timeline, SCHEDULE, {
      onSend: () => log.push(`${String(timeline.time)} A sends`),
    });
    const shifted = new Uint8Array(32);
    shifted[7] = 2;
    const b = makeRig(
      timeline,
      SCHEDULE,
      { onSend: () => log.push(`${String(timeline.time)} B sends`) },
      shifted,
    );
    const merkleRoot = merkleRootOf(0x4e);
    const label = await compileChannelMessageLabel(
      "party",
      uint8ArrayToHex(merkleRoot),
    );
    a.runtime.enqueue(
      buildScheduledSendJob({
        runtime: a.runtime,
        channelMessageLabel: label,
        totalChunks: 2,
        merkleRoot,
        sealSlotCell: (chunkIndex) => {
          log.push(`${String(timeline.time)} A produces`);
          return new Uint8Array(WIRE_CHUNK_FRAME_LEN).fill(chunkIndex + 1);
        },
      }),
    );
    try {
      a.runtime.start();
      b.runtime.start();
      await timeline.advanceTo(SCHEDULE.coverCadenceMs - 1);

      const window = log.filter((line) => {
        const at = Number(line.split(" ")[0]);
        return at >= 150 && at < 200;
      });
      expect(window).toEqual(["150 A sends", "152 B sends", "152 A produces"]);
      // Both still send every slot, on their own grids.
      expect(a.allSent()).toHaveLength(4);
      expect(b.allSent()).toHaveLength(4);
    } finally {
      a.runtime.destroy();
      b.runtime.destroy();
      a.pq.destroy();
      b.pq.destroy();
    }
  });

  test("teardown zeroes a produced but unsent cell", async () => {
    const timeline = new CoverTimeline();
    const rig = makeRig(timeline);
    const merkleRoot = merkleRootOf(0x7c);
    const label = await compileChannelMessageLabel(
      "party",
      uint8ArrayToHex(merkleRoot),
    );
    const produced: Uint8Array[] = [];
    const job = buildScheduledSendJob({
      runtime: rig.runtime,
      channelMessageLabel: label,
      totalChunks: 2,
      merkleRoot,
      sealSlotCell: (chunkIndex) => {
        const cell = new Uint8Array(WIRE_CHUNK_FRAME_LEN).fill(chunkIndex + 1);
        produced.push(cell);
        return cell;
      },
    });
    try {
      rig.runtime.enqueue(job);
      rig.runtime.start();
      await timeline.advanceTo(1);
      // The job's lane is not open yet when its first slot comes: the cell is
      // produced, then refused for backpressure, and kept for a later slot.
      const realLane = rig.lanes.find((lane) => lane.label === label);
      expect(realLane).toBeDefined();
      realLane!.readyState = "connecting";
      await timeline.advanceTo(200);
      expect(realLane!.sent).toHaveLength(0);
      expect(produced).toHaveLength(1);
      expect(produced[0].some((byte) => byte !== 0)).toBe(true);

      rig.runtime.destroy();

      expect(produced[0].every((byte) => byte === 0)).toBe(true);
    } finally {
      rig.runtime.destroy();
      rig.pq.destroy();
    }
  });

  test("teardown zeroes a real cell produced ahead for the next slot", async () => {
    const timeline = new CoverTimeline();
    const rig = makeRig(timeline);
    const merkleRoot = merkleRootOf(0x7d);
    const label = await compileChannelMessageLabel(
      "party",
      uint8ArrayToHex(merkleRoot),
    );
    const produced: Uint8Array[] = [];
    rig.runtime.enqueue(
      buildScheduledSendJob({
        runtime: rig.runtime,
        channelMessageLabel: label,
        totalChunks: 2,
        merkleRoot,
        sealSlotCell: (chunkIndex) => {
          const cell = new Uint8Array(WIRE_CHUNK_FRAME_LEN).fill(
            chunkIndex + 1,
          );
          produced.push(cell);
          return cell;
        },
      }),
    );
    try {
      rig.runtime.start();
      // The first cell went at 50; the second, for 250, was produced at 150.
      await timeline.advanceTo(160);
      expect(rig.sentOn(label)).toHaveLength(1);
      expect(produced).toHaveLength(2);
      expect(produced[1].every((byte) => byte === 2)).toBe(true);

      rig.runtime.destroy();

      expect(produced[1].every((byte) => byte === 0)).toBe(true);
    } finally {
      rig.runtime.destroy();
      rig.pq.destroy();
    }
  });

  test("a receipt cell produced before a rekey is sealed again under the new epoch", async () => {
    const timeline = new CoverTimeline();
    const contextFor = (epoch: bigint, seed: number) => ({
      rootSuite: RATCHET_ROOT_SUITE_MLKEM512,
      rootKey: new Uint8Array(32).fill(seed),
      binding: new Uint8Array(32).fill(0x42),
      epoch,
    });
    let context = contextFor(1n, 0x11);
    const epc = {
      roomId: ROOM_ID,
      pqHealingState: { currentMessageContext: () => context },
    } as unknown as IRTCPeerConnection;
    const lanes: RecordingLane[] = [];
    const runtime = new CoverRuntime({
      epc,
      roomId: ROOM_ID,
      module,
      amInitiator: true,
      schedule: SCHEDULE,
      policyHash: new Uint8Array(32),
      laneLabelName: "party",
      openLaneChannel: (label) => {
        const lane = new RecordingLane(label, timeline);
        lanes.push(lane);
        return lane;
      },
      timerEnvironment: timeline.env,
    });
    (epc as unknown as { coverRuntime: CoverRuntime }).coverRuntime = runtime;
    const open = (frame: Uint8Array, at: typeof context) =>
      openCoverCell({
        module,
        rootSuite: at.rootSuite,
        rootKey: at.rootKey,
        binding: at.binding,
        direction: "initiator-to-responder",
        keyEpoch: at.epoch,
        frame,
      });
    try {
      runtime.start();
      await timeline.advanceTo(10);
      const root = merkleRootOf(0x3c);
      const token = new Uint8Array(64).fill(0x5e);
      expect(queueScheduledChunkReceipt(epc, root, token)).toBe(true);
      // The drain job is admitted at 400 and its cell for 450 produced then,
      // under epoch 1. The epoch changes before that slot.
      await timeline.advanceTo(420);
      const retired = context;
      context = contextFor(2n, 0x22);
      runtime.onPqEpochChanged();
      await timeline.advanceTo(460);

      const atSlot = lanes.flatMap((lane) =>
        lane.sent.filter(({ at }) => at === 450),
      );
      expect(atSlot).toHaveLength(1);
      const opened = open(atSlot[0].frame, context);
      expect(opened.content.subtype).toBe("chunk-receipts");
      expect(() => open(atSlot[0].frame, retired)).toThrow();
    } finally {
      runtime.destroy();
    }
  });

  test("teardown zeroes the dummy produced for the next slot, and only it", async () => {
    const { clock, advanceTo } = manualClock();
    const dummies: Uint8Array[] = [];
    const sent = new Set<Uint8Array>();
    const schedule: CoverSchedule = { ...SCHEDULE, phaseOffsetMs: 0 };
    const scheduler = createCoverScheduler({
      schedule,
      clock,
      makeDummy: () => {
        const cell = new Uint8Array(8).fill(0xdd);
        dummies.push(cell);
        return cell;
      },
      laneFactory: () => ({
        send: (request) => {
          sent.add(request.cell);
        },
        close: () => undefined,
      }),
    });
    scheduler.start();
    await advanceTo(160);
    expect(sent.size).toBe(2);
    // The slot at 250 has its cell already.
    const unsent = dummies.filter((cell) => !sent.has(cell));
    expect(unsent).toHaveLength(1);

    scheduler.stop();

    expect(unsent[0].every((byte) => byte === 0)).toBe(true);
    for (const cell of sent)
      expect(cell.every((byte) => byte === 0xdd)).toBe(true);
  });

  test("a job completed after its next cell was produced sends no more of its cells", async () => {
    const timeline = new CoverTimeline();
    const rig = makeRig(timeline);
    const real = await realJob(rig, timeline, 2, () => 0);
    try {
      rig.runtime.enqueue(real.job);
      rig.runtime.start();
      // The first cell went at 50. The second, for 250, was produced at 150,
      // right after the slot before it.
      await timeline.advanceTo(160);
      expect(rig.sentOn(real.label)).toHaveLength(1);
      // The receiver confirms everything (its terminal receipt) meanwhile.
      rig.runtime.complete(real.label);
      await timeline.advanceTo(SCHEDULE.coverCadenceMs - 1);

      const lane = rig.sentOn(real.label);
      expect(lane.map(({ at }) => at)).toEqual([50, 250]);
      expect(lane[0].frame[0]).toBe(FRAME_TYPE_CHUNK);
      // The lane keeps its slot with a dummy, on time.
      expect(lane[1].frame[0]).toBe(FRAME_TYPE_COVER);
    } finally {
      rig.runtime.destroy();
      real.wipe();
      rig.pq.destroy();
    }
  });
});
