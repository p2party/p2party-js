import { describe, expect, test } from "bun:test";

import {
  buildScheduledSendJob,
  cancelScheduledTransfer,
  queueScheduledReceipt,
  releaseScheduledReceipts,
  syntheticScheduledLabel,
} from "./coverTransfer";
import { compileChannelMessageLabel } from "../utils/channelLabel";
import { WIRE_CHUNK_FRAME_LEN } from "../utils/constants";

import type { CoverRuntime } from "./coverRuntime";
import type { CoverJob, CoverJobSlot } from "./coverScheduler";
import type { CoverCellContent } from "../cryptography/coverCell";
import type { IRTCPeerConnection } from "../api/webrtc/interfaces";

const uniformCell = (fill: number): Uint8Array =>
  new Uint8Array(WIRE_CHUNK_FRAME_LEN).fill(fill);

const fakeSlot = (): CoverJobSlot =>
  ({
    deadlineMs: 0,
    cycleIndex: 0,
    cycleStartMs: 0,
    cycleEndMs: 0,
    epochIndex: 0,
    epochInCycle: 0,
    laneIndex: 0,
    frameIndex: 0,
    laneSlotIndex: 0,
    jobId: "job",
    jobKind: "real",
    jobCellIndex: 0,
  }) as CoverJobSlot;

interface FakeRuntime {
  readonly runtime: CoverRuntime;
  readonly enqueued: CoverJob[];
  readonly sealed: CoverCellContent[];
  readonly cancels: string[];
  settleCallbacks: Map<string, () => void>;
  cancelResult: "not-found" | "cancelled-before-admission" | "cancel-pending";
}

const fakeRuntime = (capacity = 8): FakeRuntime => {
  const enqueued: CoverJob[] = [];
  const sealed: CoverCellContent[] = [];
  const cancels: string[] = [];
  const settleCallbacks = new Map<string, () => void>();
  const state: FakeRuntime = {
    enqueued,
    sealed,
    cancels,
    settleCallbacks,
    cancelResult: "cancel-pending",
    runtime: {
      cellsPerLanePerCycle: () => capacity,
      randomLaneLabel: () => `${"00".repeat(32)}~${"11".repeat(64)}`,
      sealCoverContent: (content: CoverCellContent) => {
        sealed.push(content);
        return uniformCell(0xcc);
      },
      enqueue: (job: CoverJob) => {
        enqueued.push(job);
      },
      onJobSettled: (jobId: string, callback: () => void) => {
        settleCallbacks.set(jobId, callback);
      },
      cancel: (label: string) => {
        cancels.push(label);
        return state.cancelResult;
      },
    } as unknown as CoverRuntime,
  };
  return state;
};

const fakeEpc = (runtime?: CoverRuntime): IRTCPeerConnection =>
  ({ coverRuntime: runtime }) as unknown as IRTCPeerConnection;

describe("scheduled-transfer send job", () => {
  test("seals one chunk per slot in order and dummy-substitutes when exhausted", async () => {
    const fake = fakeRuntime(8);
    const sealed: number[] = [];
    const job = buildScheduledSendJob({
      runtime: fake.runtime,
      channelMessageLabel: "msg-label",
      totalChunks: 3,
      sealSlotCell: (index) => {
        sealed.push(index);
        return uniformCell(index);
      },
    });
    expect(job.id).toBe("msg-label");
    expect(job.kind).toBe("real");
    expect(job.declaredCellCount).toBe(3);

    const first = await job.nextCell(fakeSlot());
    const second = await job.nextCell(fakeSlot());
    const third = await job.nextCell(fakeSlot());
    expect(sealed).toEqual([0, 1, 2]);
    expect(first).toHaveLength(WIRE_CHUNK_FRAME_LEN);
    // A fourth slot has no un-acked real work left → dummy substitution.
    const fourth = await job.nextCell(fakeSlot());
    expect(fourth).toBeNull();
    expect(second).not.toBeNull();
    expect(third).not.toBeNull();
  });

  test("refuses admission when the message exceeds the room F×D capacity", () => {
    const fake = fakeRuntime(2);
    expect(() =>
      buildScheduledSendJob({
        runtime: fake.runtime,
        channelMessageLabel: "too-big",
        totalChunks: 3,
        sealSlotCell: () => uniformCell(1),
      }),
    ).toThrow(/exceeds the room/);
  });

  test("one job-run offers each un-acked real exactly once and dummy-tails the rest", async () => {
    const fake = fakeRuntime(8);
    const acked = new Set<number>([2]); // chunk 2 already acked before this run
    const offered: number[] = [];
    const job = buildScheduledSendJob({
      runtime: fake.runtime,
      channelMessageLabel: "reconcile",
      totalChunks: 3,
      getAckedChunks: () => acked,
      sealSlotCell: (index) => {
        offered.push(index);
        return uniformCell(index);
      },
    });
    const a = await job.nextCell(fakeSlot()); // 0
    acked.add(0); // acked mid-run: does not retroactively re-offer 0
    const b = await job.nextCell(fakeSlot()); // 1 (2 skipped as pre-acked)
    const c = await job.nextCell(fakeSlot()); // exhausted → dummy
    expect(a).not.toBeNull();
    expect(b).not.toBeNull();
    expect(c).toBeNull();
    expect(offered).toEqual([0, 1]);
  });

  test("a non-uniform sealed cell is rejected before it reaches the lane", async () => {
    const fake = fakeRuntime(8);
    const job = buildScheduledSendJob({
      runtime: fake.runtime,
      channelMessageLabel: "bad",
      totalChunks: 1,
      sealSlotCell: () => new Uint8Array(10),
    });
    await expect(job.nextCell(fakeSlot())).rejects.toThrow(
      /uniform length/,
    );
  });
});

describe("scheduled receipts and cancellation", () => {
  test("receipts enqueue a control drain job that seals receipt cells one per slot", async () => {
    const fake = fakeRuntime(4);
    const epc = fakeEpc(fake.runtime);
    const root = new Uint8Array(64).fill(0xaa);
    const token = new Uint8Array(64).fill(0xbb);

    expect(queueScheduledReceipt(epc, root, token)).toBe(true);
    expect(fake.enqueued).toHaveLength(1);
    const job = fake.enqueued[0];
    expect(job.kind).toBe("control");
    expect(job.declaredCellCount).toBe(1);

    const cell = await job.nextCell(fakeSlot());
    expect(cell).toHaveLength(WIRE_CHUNK_FRAME_LEN);
    expect(fake.sealed[0].subtype).toBe("receipt");
    // An empty queue produces a dummy substitution.
    expect(await job.nextCell(fakeSlot())).toBeNull();

    releaseScheduledReceipts(epc);
  });

  test("immediate-mode edges reject scheduled receipts so the caller falls back", () => {
    const epc = fakeEpc(undefined);
    expect(
      queueScheduledReceipt(
        epc,
        new Uint8Array(64),
        new Uint8Array(64),
      ),
    ).toBe(false);
  });

  test("a settled drain job re-arms while receipts remain queued", async () => {
    const fake = fakeRuntime(1); // one receipt per cycle
    const epc = fakeEpc(fake.runtime);
    queueScheduledReceipt(epc, new Uint8Array(64).fill(1), new Uint8Array(64).fill(2));
    queueScheduledReceipt(epc, new Uint8Array(64).fill(3), new Uint8Array(64).fill(4));
    // Capacity 1 → the first job declares one cell; the second receipt waits.
    expect(fake.enqueued).toHaveLength(1);
    const firstJob = fake.enqueued[0];
    // Settling the first job re-arms a second drain job for the remainder.
    fake.settleCallbacks.get(firstJob.id)?.();
    expect(fake.enqueued).toHaveLength(2);
    releaseScheduledReceipts(epc);
  });

  test("scheduled cancel routes to the scheduler, never a channel close", async () => {
    const fake = fakeRuntime();
    const epc = fakeEpc(fake.runtime);
    const merkleRootHex = "ab".repeat(64);
    const routed = await cancelScheduledTransfer(epc, "chat", merkleRootHex);
    expect(routed).toBe(true);
    const expectedLabel = await compileChannelMessageLabel("chat", merkleRootHex);
    expect(fake.cancels).toEqual([expectedLabel]);

    // An immediate-mode edge does not route a scheduled cancel.
    expect(
      await cancelScheduledTransfer(fakeEpc(undefined), "chat", merkleRootHex),
    ).toBe(false);
  });

  test("cancel reports not-found as no routed transfer", async () => {
    const fake = fakeRuntime();
    fake.cancelResult = "not-found";
    const epc = fakeEpc(fake.runtime);
    expect(
      await cancelScheduledTransfer(epc, "chat", "cd".repeat(64)),
    ).toBe(false);
  });

  test("synthetic scheduled label carries the merkle root for receipt routing", () => {
    const label = syntheticScheduledLabel("ef".repeat(64));
    expect(label).toBe(`${"00".repeat(32)}~${"ef".repeat(64)}`);
  });
});
