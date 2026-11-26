import { describe, expect, test } from "bun:test";

import {
  buildScheduledSendJob,
  cancelScheduledTransfer,
  queueScheduledReceipt,
  queueScheduledChunkReceipt,
  queueScheduledCancel,
  releaseScheduledReceipts,
  syntheticScheduledLabel,
} from "../../src/handlers/coverTransfer";
import { cancelScheduledSend } from "../../src/handlers/coverEdge";
import { compileChannelMessageLabel } from "../../src/utils/channelLabel";
import { uint8ArrayToHex } from "../../src/utils/uint8array";
import { WIRE_CHUNK_FRAME_LEN } from "../../src/utils/constants";
import { createCoverScheduler } from "../../src/handlers/coverScheduler";

import type { CoverRuntime } from "../../src/handlers/coverRuntime";
import type {
  CoverClock,
  CoverJob,
  CoverJobSlot,
} from "../../src/handlers/coverScheduler";
import type { CoverCellContent } from "../../src/cryptography/coverCell";
import type { IRTCPeerConnection } from "../../src/api/webrtc/interfaces";

const uniformCell = (fill: number): Uint8Array =>
  new Uint8Array(WIRE_CHUNK_FRAME_LEN).fill(fill);

// A compiled channel-message label: 32-byte name element, separator, 64-byte
// transfer root. The label IS the scheduled-send job id.
const LABEL_ROOT_HEX = "7c".repeat(64);
const LABEL = `${"00".repeat(32)}~${LABEL_ROOT_HEX}`;

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
  /** Override what sealCoverContent returns (non-uniform-length cases). */
  sealedCell?: Uint8Array;
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
        // The real runtime serializes the content into the frame before it
        // returns, so the caller is free to wipe its buffers straight after.
        // Snapshot here for the same reason, or an assertion later reads the
        // zeros the producer left behind rather than what was sealed.
        sealed.push(structuredClone(content));
        return state.sealedCell ?? uniformCell(0xcc);
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

class ReceiptClock implements CoverClock {
  private time = 0;
  private sequence = 0;
  private timers = new Map<number, { at: number; callback: () => void }>();

  now = (): number => this.time;
  setTimeout = (callback: () => void, delay: number): number => {
    const id = ++this.sequence;
    this.timers.set(id, { at: this.time + delay, callback });
    return id;
  };
  clearTimeout = (id: unknown): void => {
    this.timers.delete(id as number);
  };

  async advanceTo(target: number): Promise<void> {
    while (true) {
      for (let i = 0; i < 16; i++) await Promise.resolve();
      const next = [...this.timers.entries()]
        .filter(([, timer]) => timer.at <= target)
        .sort((a, b) => a[1].at - b[1].at || a[0] - b[0])[0];
      if (!next) break;
      this.time = next[1].at;
      this.timers.delete(next[0]);
      next[1].callback();
    }
    this.time = target;
  }
}

describe("scheduled-transfer send job", () => {
  test("selective resume checks membership in O(1) and preserves original chunk indices", async () => {
    const fake = fakeRuntime(8),
      acked = new Set([0, 2]),
      emitted: number[] = [];
    const options = {
      runtime: fake.runtime,
      channelMessageLabel: LABEL,
      totalChunks: 4,
      merkleRoot: new Uint8Array(64),
      isChunkAcked: (index: number) => acked.has(index),
      getAckedChunks: (): ReadonlySet<number> => {
        throw new Error("must not clone the have-set per cell");
      },
      sealSlotCell: (index: number) => {
        emitted.push(index);
        return uniformCell(index);
      },
    };
    const initial = buildScheduledSendJob(options);
    await initial.nextCell(fakeSlot());
    acked.add(1);
    const resumed = buildScheduledSendJob(options);
    await resumed.nextCell(fakeSlot());
    expect(await resumed.nextCell(fakeSlot())).toBeNull();
    expect(resumed.exhausted?.()).toBe(true);
    expect(emitted).toEqual([1, 3]);
    expect([...acked]).toEqual([0, 2, 1]);
  });
  test("a failed asynchronous sealer retries the same missing index", async () => {
    const fake = fakeRuntime(8);
    const indices: number[] = [];
    const job = buildScheduledSendJob({
      runtime: fake.runtime,
      channelMessageLabel: LABEL,
      merkleRoot: new Uint8Array(64),
      totalChunks: 3,
      sealSlotCell: async (index) => {
        indices.push(index);
        if (indices.length === 1) throw new Error("temporary worker failure");
        return uniformCell(index);
      },
    });
    await expect(job.nextCell(fakeSlot())).rejects.toThrow(
      "temporary worker failure",
    );
    await job.nextCell(fakeSlot());
    expect(indices).toEqual([0, 0]);
  });

  test("seals one chunk per slot in order and dummy-substitutes when exhausted", async () => {
    const fake = fakeRuntime(8);
    const sealed: number[] = [];
    const job = buildScheduledSendJob({
      runtime: fake.runtime,
      channelMessageLabel: "msg-label",
      merkleRoot: new Uint8Array(64),
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
        merkleRoot: new Uint8Array(64),
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
      merkleRoot: new Uint8Array(64),
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
      merkleRoot: new Uint8Array(64),
      totalChunks: 1,
      sealSlotCell: () => new Uint8Array(10),
    });
    await expect(job.nextCell(fakeSlot())).rejects.toThrow(/uniform length/);
  });
});

describe("scheduled receipts and cancellation", () => {
  test.each([1, 16])(
    "completion supersedes its chunk ACK in the first reverse cycle at 70s cadence, F%d",
    async (frames) => {
      const fake = fakeRuntime(frames),
        epc = fakeEpc(fake.runtime),
        root = new Uint8Array(64).fill(1),
        clock = new ReceiptClock(),
        wire: { at: number; source: string }[] = [];
      const scheduler = createCoverScheduler({
        schedule: {
          phaseOffsetMs: 0,
          coverCadenceMs: 70_000,
          coverLanes: 1,
          coverFramesPerCell: frames,
          coverDurationEpochs: 1,
        },
        clock,
        makeDummy: () => uniformCell(0xdd),
        laneFactory: () => ({
          send: (request) => {
            wire.push({ at: clock.now(), source: request.source });
          },
          close: () => undefined,
        }),
        onJobResult: ({ jobId }) => fake.settleCallbacks.get(jobId)?.(),
      });
      fake.runtime.enqueue = (job) => {
        fake.enqueued.push(job);
        scheduler.enqueue(job);
      };
      scheduler.start();
      try {
        await clock.advanceTo(1_000);
        // The receive path queues a chunk ACK immediately before discovering
        // terminal completion. Both must use the already queued reverse job.
        queueScheduledChunkReceipt(epc, root, new Uint8Array(64).fill(2));
        queueScheduledReceipt(epc, root, root);
        expect(fake.enqueued).toHaveLength(1);
        expect(fake.enqueued[0].declaredCellCount).toBe(1);
        await clock.advanceTo(140_000);
        expect(fake.sealed.map((cell) => cell.subtype)).toEqual(["receipt"]);
        expect(wire.filter((cell) => cell.source === "control")).toEqual([
          { at: 70_000 + Math.floor(35_000 / frames), source: "control" },
        ]);
        await clock.advanceTo(210_000);
        expect(fake.enqueued).toHaveLength(1);
        expect(fake.sealed).toHaveLength(1);
        expect(wire).toHaveLength(3 * frames);
      } finally {
        releaseScheduledReceipts(epc);
        scheduler.stop();
      }
    },
  );

  test("terminal supersession clears every batch, deduplicates completion and preserves other roots and CANCEL order", async () => {
    const fake = fakeRuntime(1),
      epc = fakeEpc(fake.runtime),
      root = new Uint8Array(64).fill(1),
      other = new Uint8Array(64).fill(2),
      token = (index: number): Uint8Array => {
        const value = new Uint8Array(64);
        new DataView(value.buffer).setUint32(0, index);
        return value;
      };
    for (let i = 0; i < 130; i++)
      queueScheduledChunkReceipt(epc, root, token(i));
    queueScheduledChunkReceipt(epc, other, token(200));
    queueScheduledCancel(epc, syntheticScheduledLabel(uint8ArrayToHex(root)));
    queueScheduledReceipt(epc, root, root);
    queueScheduledReceipt(epc, root, root);
    for (let i = 0; i < 3; i++) {
      await fake.enqueued[i].nextCell(fakeSlot());
      fake.enqueued[i].cellSent?.(); // the scheduler sent it
      fake.settleCallbacks.get(fake.enqueued[i].id)!();
    }
    expect(
      fake.sealed.map((cell) => [
        cell.subtype,
        cell.subtype === "dummy" ? -1 : cell.merkleRoot[0],
      ]),
    ).toEqual([
      ["chunk-receipts", 2],
      ["cancel", 1],
      ["receipt", 1],
    ]);
    expect(fake.enqueued).toHaveLength(3);
    // A later retry must create a live batch, never append to a removed one.
    queueScheduledChunkReceipt(epc, root, token(201));
    await fake.enqueued[3].nextCell(fakeSlot());
    fake.enqueued[3].cellSent?.(); // the scheduler sent it
    expect(fake.sealed[3].subtype).toBe("chunk-receipts");
    expect(root[0]).toBe(1);
    releaseScheduledReceipts(epc);
  });

  test("superseded token accounting preserves other receipts at the flood bound", async () => {
    const fake = fakeRuntime(1),
      epc = fakeEpc(fake.runtime),
      completed = new Uint8Array(64).fill(1),
      survivor = new Uint8Array(64).fill(2),
      later = new Uint8Array(64).fill(3);
    const add = (root: Uint8Array, count: number): void => {
      for (let i = 0; i < count; i++) {
        const token = new Uint8Array(64);
        new DataView(token.buffer).setUint32(0, i);
        queueScheduledChunkReceipt(epc, root, token);
      }
    };
    add(completed, 4095);
    add(survivor, 1);
    queueScheduledReceipt(epc, completed, completed);
    add(later, 4094); // one survivor + one completion + 4094 = the 4096 cap
    for (let i = 0; i < 2; i++) {
      await fake.enqueued[i].nextCell(fakeSlot());
      fake.enqueued[i].cellSent?.(); // the scheduler sent it
      fake.settleCallbacks.get(fake.enqueued[i].id)!();
    }
    expect(
      fake.sealed.map((cell) => [
        cell.subtype,
        cell.subtype === "dummy" ? -1 : cell.merkleRoot[0],
      ]),
    ).toEqual([
      ["chunk-receipts", 2],
      ["receipt", 1],
    ]);
    releaseScheduledReceipts(epc);
  });

  test("a mismatched terminal token cannot discard valid selective receipts", async () => {
    const fake = fakeRuntime(1),
      epc = fakeEpc(fake.runtime),
      root = new Uint8Array(64).fill(1),
      token = new Uint8Array(64).fill(2);
    queueScheduledChunkReceipt(epc, root, token);
    expect(queueScheduledReceipt(epc, root, token)).toBe(false);
    await fake.enqueued[0].nextCell(fakeSlot());
    fake.enqueued[0].cellSent?.(); // the scheduler sent it
    expect(fake.sealed[0].subtype).toBe("chunk-receipts");
    fake.settleCallbacks.get(fake.enqueued[0].id)!();
    expect(fake.enqueued).toHaveLength(1);
    releaseScheduledReceipts(epc);
  });

  test("batches 64 chunk tokens per fixed slot and preserves root/token boundaries", async () => {
    const fake = fakeRuntime(8),
      epc = fakeEpc(fake.runtime),
      root = new Uint8Array(64).fill(1);
    for (let i = 0; i < 66; i++) {
      const token = new Uint8Array(64);
      new DataView(token.buffer).setUint32(0, i + 1);
      expect(queueScheduledChunkReceipt(epc, root, token)).toBe(true);
      expect(queueScheduledChunkReceipt(epc, root, token)).toBe(true);
    }
    expect(fake.enqueued).toHaveLength(1);
    await fake.enqueued[0].nextCell(fakeSlot());
    fake.enqueued[0].cellSent?.(); // the scheduler sent it
    const first = fake.sealed[0];
    expect(first.subtype).toBe("chunk-receipts");
    if (first.subtype !== "chunk-receipts") throw new Error("wrong subtype");
    expect(first.tokens).toHaveLength(64);
    expect(first.merkleRoot).toEqual(root);
    fake.settleCallbacks.get(fake.enqueued[0].id)!();
    await fake.enqueued[1].nextCell(fakeSlot());
    fake.enqueued[1].cellSent?.(); // the scheduler sent it
    const second = fake.sealed[1];
    if (second.subtype !== "chunk-receipts") throw new Error("wrong subtype");
    expect(second.tokens).toHaveLength(2);
    expect(new DataView(second.tokens[0].buffer).getUint32(0)).toBe(65);
    releaseScheduledReceipts(epc);
  });

  test("chunk batches for different roots never merge", async () => {
    const fake = fakeRuntime(),
      epc = fakeEpc(fake.runtime),
      token = new Uint8Array(64).fill(3);
    queueScheduledChunkReceipt(epc, new Uint8Array(64).fill(1), token);
    queueScheduledChunkReceipt(epc, new Uint8Array(64).fill(2), token);
    await fake.enqueued[0].nextCell(fakeSlot());
    fake.enqueued[0].cellSent?.(); // the scheduler sent it
    fake.settleCallbacks.get(fake.enqueued[0].id)!();
    await fake.enqueued[1].nextCell(fakeSlot());
    fake.enqueued[1].cellSent?.(); // the scheduler sent it
    expect(
      fake.sealed.map((cell) =>
        cell.subtype === "chunk-receipts" ? cell.merkleRoot[0] : -1,
      ),
    ).toEqual([1, 2]);
    releaseScheduledReceipts(epc);
  });

  test("receipts enqueue a control drain job that seals receipt cells one per slot", async () => {
    const fake = fakeRuntime(4);
    const epc = fakeEpc(fake.runtime);
    const root = new Uint8Array(64).fill(0xaa);
    const token = Uint8Array.from(root);

    expect(queueScheduledReceipt(epc, root, token)).toBe(true);
    expect(fake.enqueued).toHaveLength(1);
    const job = fake.enqueued[0];
    expect(job.kind).toBe("control");
    expect(job.declaredCellCount).toBe(1);

    const cell = await job.nextCell(fakeSlot());
    job.cellSent?.(); // the scheduler sent it
    expect(cell).toHaveLength(WIRE_CHUNK_FRAME_LEN);
    expect(fake.sealed[0].subtype).toBe("receipt");
    // An empty queue produces a dummy substitution.
    expect(await job.nextCell(fakeSlot())).toBeNull();

    releaseScheduledReceipts(epc);
  });

  test("a receipt cell discarded before it is sent is sealed again from the same receipt", async () => {
    const fake = fakeRuntime(4);
    const epc = fakeEpc(fake.runtime);
    const root = new Uint8Array(64).fill(0xab);
    expect(queueScheduledReceipt(epc, root, Uint8Array.from(root))).toBe(true);
    const job = fake.enqueued[0];

    // Produced a slot ahead, then discarded (a rekey): nothing was sent.
    await job.nextCell(fakeSlot());
    job.cellDiscarded?.();
    const again = await job.nextCell(fakeSlot());
    expect(again).toHaveLength(WIRE_CHUNK_FRAME_LEN);
    expect(fake.sealed.map((cell) => cell.subtype)).toEqual([
      "receipt",
      "receipt",
    ]);
    // Sent: nothing is left to seal.
    job.cellSent?.();
    expect(await job.nextCell(fakeSlot())).toBeNull();
    expect(fake.sealed).toHaveLength(2);
    releaseScheduledReceipts(epc);
  });

  test("immediate-mode edges reject scheduled receipts so the caller falls back", () => {
    const epc = fakeEpc(undefined);
    expect(
      queueScheduledReceipt(epc, new Uint8Array(64), new Uint8Array(64)),
    ).toBe(false);
  });

  test("a settled drain job re-arms while receipts remain queued", async () => {
    const fake = fakeRuntime(1); // one receipt per cycle
    const epc = fakeEpc(fake.runtime);
    queueScheduledReceipt(
      epc,
      new Uint8Array(64).fill(1),
      new Uint8Array(64).fill(1),
    );
    queueScheduledReceipt(
      epc,
      new Uint8Array(64).fill(3),
      new Uint8Array(64).fill(3),
    );
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
    const expectedLabel = await compileChannelMessageLabel(
      "chat",
      merkleRootHex,
    );
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
    expect(await cancelScheduledTransfer(epc, "chat", "cd".repeat(64))).toBe(
      false,
    );
  });

  test("synthetic scheduled label carries the merkle root for receipt routing", () => {
    const label = syntheticScheduledLabel("ef".repeat(64));
    expect(label).toBe(`${"00".repeat(32)}~${"ef".repeat(64)}`);
  });

  test("a scheduled send job can be cancelled after admission", async () => {
    // Before C3, buildScheduledSendJob defined no cancelCell, so
    // CoverScheduler.cancel threw for any admitted job and the failure path
    // could not tell the receiver anything: it kept an unfillable partial
    // forever while the sender deleted its only resend source.
    const fake = fakeRuntime();
    const merkleRoot = new Uint8Array(64).fill(0x5a);
    const job = buildScheduledSendJob({
      runtime: fake.runtime,
      channelMessageLabel: LABEL,
      totalChunks: 4,
      sealSlotCell: () => new Uint8Array(WIRE_CHUNK_FRAME_LEN),
      merkleRoot,
    });
    expect(typeof job.cancelCell).toBe("function");
    const cell = await job.cancelCell!(fakeSlot());
    expect(cell.length).toBe(WIRE_CHUNK_FRAME_LEN);
    expect(fake.sealed[0].subtype).toBe("cancel");
    expect((fake.sealed[0] as { merkleRoot: Uint8Array }).merkleRoot).toEqual(
      merkleRoot,
    );
  });

  test("a cancel cell that is not the uniform length never reaches the lane", async () => {
    const fake = fakeRuntime();
    fake.sealedCell = new Uint8Array(9);
    const job = buildScheduledSendJob({
      runtime: fake.runtime,
      channelMessageLabel: LABEL,
      totalChunks: 1,
      sealSlotCell: () => new Uint8Array(WIRE_CHUNK_FRAME_LEN),
      merkleRoot: new Uint8Array(64),
    });
    await expect(job.cancelCell!(fakeSlot())).rejects.toThrow(
      /sealed cancel cell is not the uniform length/,
    );
  });
});

describe("cancelling a scheduled send that the scheduler no longer holds", () => {
  test("an admitted job's cancel rides its own next slot", () => {
    const fake = fakeRuntime();
    fake.cancelResult = "cancel-pending";
    const epc = fakeEpc(fake.runtime);
    expect(cancelScheduledSend(epc, LABEL)).toBe("cancel-pending");
    expect(fake.cancels).toEqual([LABEL]);
    // Nothing extra is enqueued: the job's own cancelCell carries the CANCEL.
    expect(fake.enqueued).toHaveLength(0);
  });

  test("a job cancelled before admission emitted nothing, so nothing is queued", () => {
    const fake = fakeRuntime();
    fake.cancelResult = "cancelled-before-admission";
    const epc = fakeEpc(fake.runtime);
    expect(cancelScheduledSend(epc, LABEL)).toBe("cancelled-before-admission");
    expect(fake.enqueued).toHaveLength(0);
  });

  test("a settled job still gets its CANCEL to the receiver on a control cell", () => {
    // The dominant C3 failure: by the time the delivery bound expires the send
    // job has usually emitted every declared cell and settled "completed", so
    // CoverScheduler.cancel answers "not-found" and the job's own cancelCell
    // can never run. Without a standalone CANCEL the receiver keeps its
    // partial forever — a re-send cannot fill it, because decoy chunks are
    // fresh randomness and the Merkle root differs.
    const fake = fakeRuntime();
    fake.cancelResult = "not-found";
    const epc = fakeEpc(fake.runtime);
    expect(cancelScheduledSend(epc, LABEL)).toBe("cancel-pending");
    expect(fake.enqueued).toHaveLength(1);
    expect(fake.enqueued[0].kind).toBe("control");
    releaseScheduledReceipts(epc);
  });

  test("the standalone CANCEL carries the transfer root parsed from the job label", async () => {
    const fake = fakeRuntime();
    fake.cancelResult = "not-found";
    const epc = fakeEpc(fake.runtime);
    expect(cancelScheduledSend(epc, LABEL)).toBe("cancel-pending");
    const cell = await fake.enqueued[0].nextCell(fakeSlot());
    expect(cell).toHaveLength(WIRE_CHUNK_FRAME_LEN);
    expect(fake.sealed[0].subtype).toBe("cancel");
    expect(
      uint8ArrayToHex(
        (fake.sealed[0] as { merkleRoot: Uint8Array }).merkleRoot,
      ),
    ).toBe(LABEL_ROOT_HEX);
    releaseScheduledReceipts(epc);
  });

  test("an immediate-mode edge has nothing to cancel", () => {
    expect(cancelScheduledSend(fakeEpc(undefined), LABEL)).toBe("not-found");
  });

  test("a label with no transfer root cannot be turned into a wire CANCEL", () => {
    const fake = fakeRuntime();
    fake.cancelResult = "not-found";
    const epc = fakeEpc(fake.runtime);
    expect(cancelScheduledSend(epc, "not-a-compiled-label")).toBe("not-found");
    expect(fake.enqueued).toHaveLength(0);
  });
});
