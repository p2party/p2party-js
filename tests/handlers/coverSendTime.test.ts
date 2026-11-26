import { beforeAll, describe, expect, test } from "bun:test";

import { CoverRuntime } from "../../src/handlers/coverRuntime";
import { createCoverScheduler } from "../../src/handlers/coverScheduler";
import { buildScheduledSendJob } from "../../src/handlers/coverTransfer";
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
    policyHash: new Uint8Array(32),
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

  test("a store read slower than the offset is handled as a late slot, not as a late send", async () => {
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

      // Nothing left off the slot grid: the slow cell was not sent late.
      for (const { at } of rig.allSent())
        expect((at - FIRST_SLOT_MS) % SLOT_SPACING_MS).toBe(0);
      // Its slot was a late slot: the cycle degraded, as a late wake-up does.
      expect(rig.statuses).toContainEqual(["degraded", "missed-deadline"]);
      expect(rig.allSent().filter(({ at }) => at < 400)).toHaveLength(0);
      // And the cell was not lost: the next cycle carried both, in order.
      const realCells = rig.sentOn(real.label);
      expect(realCells.map(({ at }) => at)).toEqual([450, 650]);
    } finally {
      rig.runtime.destroy();
      real.wipe();
      rig.pq.destroy();
    }
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

  test("teardown zeroes the dummy produced for the next slot, and only it", async () => {
    let time = 0;
    const timers = new Map<number, { at: number; run: () => void }>();
    let nextId = 1;
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
    };
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
