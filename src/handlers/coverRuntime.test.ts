import { beforeAll, describe, expect, test } from "bun:test";

import { CoverRuntime, deriveCoverPhaseOffsetMs } from "./coverRuntime";
import { SparsePqHealingState } from "./pqHealingRuntime";
import { loadTestModule } from "../cryptography/testModule";
import {
  FRAME_TYPE_COVER,
  MAX_BUFFERED_AMOUNT,
  RATCHET_ROOT_SUITE_MLKEM512,
  WIRE_CHUNK_FRAME_LEN,
} from "../utils/constants";

import type { CoverLaneChannel, CoverRuntimeOptions } from "./coverRuntime";
import type {
  CoverClock,
  CoverJob,
  CoverJobInterruption,
  CoverSchedulerStatus,
} from "./coverScheduler";
import type { LibCrypto } from "../cryptography/libcrypto";
import type { IRTCPeerConnection } from "../api/webrtc/interfaces";

let module: LibCrypto;

beforeAll(async () => {
  module = await loadTestModule();
});

interface FakeTimer {
  readonly id: number;
  readonly at: number;
  readonly callback: () => void;
}

class FakeClock implements CoverClock {
  private time: number;
  private nextId = 1;
  private readonly timers = new Map<number, FakeTimer>();

  constructor(now = 0) {
    this.time = now;
  }

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

  private nextDue(target: number): FakeTimer | undefined {
    return [...this.timers.values()]
      .filter(({ at }) => at <= target)
      .sort((left, right) => left.at - right.at || left.id - right.id)[0];
  }

  private async flush(): Promise<void> {
    for (let i = 0; i < 8; i++) await Promise.resolve();
  }

  async advanceTo(target: number): Promise<void> {
    if (target < this.time) throw new Error("fake clock cannot go backwards");
    while (true) {
      await this.flush();
      const timer = this.nextDue(target);
      if (!timer) break;
      this.time = Math.max(this.time, timer.at);
      this.timers.delete(timer.id);
      timer.callback();
    }
    this.time = target;
    await this.flush();
  }
}

class FakeChannel implements CoverLaneChannel {
  readonly label: string;
  readyState: string = "open";
  bufferedAmount = 0;
  readonly sent: Uint8Array[] = [];
  closes = 0;

  constructor(label: string) {
    this.label = label;
  }

  send(data: ArrayBuffer): void {
    this.sent.push(new Uint8Array(data));
  }

  close(): void {
    this.closes += 1;
    this.readyState = "closed";
  }
}

const POLICY_HASH = new Uint8Array(32); // zero hash → phase offset 0
const LANE_NAME = "party";

const makePqRuntime = (amInitiator: boolean): SparsePqHealingState =>
  new SparsePqHealingState({
    module,
    pqMode: "hybrid-mlkem512",
    rootSuite: RATCHET_ROOT_SUITE_MLKEM512,
    binding: new Uint8Array(32).fill(0x42),
    rootKey: new Uint8Array(32).fill(0x19),
    nextOfferer: amInitiator ? "local" : "remote",
    amInitiator,
    now: 0,
  });

interface Harness {
  readonly runtime: CoverRuntime;
  readonly pq: SparsePqHealingState;
  readonly clock: FakeClock;
  readonly channels: FakeChannel[];
  readonly statuses: CoverSchedulerStatus[];
  readonly interruptions: CoverJobInterruption["reason"][];
  readonly cancels: string[];
  readonly receipts: { root: string; token: Uint8Array }[];
}

const makeHarness = (
  amInitiator: boolean,
  overrides: Partial<CoverRuntimeOptions> = {},
): Harness => {
  const pq = makePqRuntime(amInitiator);
  const epc = { pqHealingState: pq } as unknown as IRTCPeerConnection;
  const clock = new FakeClock(0);
  const channels: FakeChannel[] = [];
  const statuses: CoverSchedulerStatus[] = [];
  const interruptions: CoverJobInterruption["reason"][] = [];
  const cancels: string[] = [];
  const receipts: { root: string; token: Uint8Array }[] = [];
  const runtime = new CoverRuntime({
    epc,
    roomId: "cover-room",
    module,
    amInitiator,
    schedule: {
      coverCadenceMs: 400,
      coverLanes: 2,
      coverFramesPerCell: 2,
      coverDurationEpochs: 1,
    },
    policyHash: POLICY_HASH,
    laneLabelName: LANE_NAME,
    openLaneChannel: (label) => {
      const channel = new FakeChannel(label);
      channels.push(channel);
      return channel;
    },
    onStatusChange: ({ status }) => statuses.push(status),
    onJobInterrupted: ({ reason }) => interruptions.push(reason),
    onRemoteCancel: (root) => cancels.push(root),
    onScheduledReceipt: (root, token) =>
      receipts.push({ root, token: Uint8Array.from(token) }),
    clock,
    ...overrides,
  });
  return {
    runtime,
    pq,
    clock,
    channels,
    statuses,
    interruptions,
    cancels,
    receipts,
  };
};

const LABEL_SHAPE = /^[0-9a-f]{64}~[0-9a-f]{128}$/;

describe("CoverRuntime (scheduled-cover WebRTC adapter)", () => {
  test("the absolute phase derives deterministically from the policy hash", () => {
    const hash = new Uint8Array(32);
    hash[0] = 0x12;
    hash[7] = 0x34;
    const offset = deriveCoverPhaseOffsetMs(hash, 10_000);
    expect(offset).toBe(deriveCoverPhaseOffsetMs(hash, 10_000));
    expect(offset).toBeGreaterThanOrEqual(0);
    expect(offset).toBeLessThan(10_000);
    expect(deriveCoverPhaseOffsetMs(new Uint8Array(32), 400)).toBe(0);
  });

  test("an idle cycle opens exactly C constant-shape lanes, sends exactly C×F×D authenticated dummies, and closes only at the boundary", async () => {
    const sender = makeHarness(true);
    const receiver = makeHarness(false);
    sender.runtime.start();
    await sender.clock.advanceTo(399);

    // Cycle 0: exactly two lanes, both with the constant label shape and the
    // shared name element.
    expect(sender.channels).toHaveLength(2);
    const nameElement = sender.channels[0].label.split("~")[0];
    for (const channel of sender.channels) {
      expect(channel.label).toMatch(LABEL_SHAPE);
      expect(channel.label.split("~")[0]).toBe(nameElement);
      expect(channel.closes).toBe(0);
    }
    // Distinct random roots per dummy lane.
    expect(sender.channels[0].label).not.toBe(sender.channels[1].label);

    // Exactly C × F × D = 2 × 2 × 1 uniform cells for the whole cycle.
    const cycleCells = sender.channels.flatMap((channel) => channel.sent);
    expect(cycleCells).toHaveLength(4);
    for (const cell of cycleCells) {
      expect(cell).toHaveLength(WIRE_CHUNK_FRAME_LEN);
      expect(cell[0]).toBe(FRAME_TYPE_COVER);
    }

    // The boundary closes cycle-0 lanes and opens fresh cycle-1 lanes.
    await sender.clock.advanceTo(400);
    expect(sender.channels[0].closes).toBe(1);
    expect(sender.channels[1].closes).toBe(1);
    expect(sender.channels).toHaveLength(4);

    // The receiving edge authenticates every dummy; replays fail closed.
    for (const cell of cycleCells)
      expect(receiver.runtime.processInboundCoverCell(cell)).toBe(true);
    expect(receiver.runtime.processInboundCoverCell(cycleCells[0])).toBe(
      false,
    );
    expect(receiver.cancels).toHaveLength(0);
    expect(receiver.receipts).toHaveLength(0);

    sender.runtime.destroy();
    receiver.runtime.destroy();
    sender.pq.destroy();
    receiver.pq.destroy();
  });

  test("CANCEL and receipt cells dispatch only after authentication, bound to their transfer root", () => {
    const sender = makeHarness(true);
    const receiver = makeHarness(false);
    const merkleRoot = new Uint8Array(64).fill(0xaa);
    const token = new Uint8Array(64).fill(0xbb);

    const cancelCell = sender.runtime.sealCoverContent({
      subtype: "cancel",
      merkleRoot,
    });
    const receiptCell = sender.runtime.sealCoverContent({
      subtype: "receipt",
      merkleRoot,
      token,
    });

    // Tampering makes the cell vanish without dispatching anything.
    const tampered = Uint8Array.from(cancelCell);
    tampered[WIRE_CHUNK_FRAME_LEN - 1] ^= 1;
    expect(receiver.runtime.processInboundCoverCell(tampered)).toBe(false);
    expect(receiver.cancels).toHaveLength(0);

    expect(receiver.runtime.processInboundCoverCell(cancelCell)).toBe(true);
    expect(receiver.cancels).toEqual(["aa".repeat(64)]);
    expect(receiver.runtime.processInboundCoverCell(receiptCell)).toBe(true);
    expect(receiver.receipts).toHaveLength(1);
    expect(receiver.receipts[0].root).toBe("aa".repeat(64));
    expect(Buffer.from(receiver.receipts[0].token)).toEqual(
      Buffer.from(token),
    );

    // A replayed CANCEL is rejected by the counter floor.
    expect(receiver.runtime.processInboundCoverCell(cancelCell)).toBe(false);
    expect(receiver.cancels).toHaveLength(1);

    // The opposite direction cannot inject cells back to the sender.
    expect(sender.runtime.processInboundCoverCell(cancelCell)).toBe(false);

    sender.runtime.destroy();
    receiver.runtime.destroy();
    sender.pq.destroy();
    receiver.pq.destroy();
  });

  test("a real lane reuses its job's exact label and carries the job's cells", async () => {
    const sender = makeHarness(true);
    const jobLabel = `${"cd".repeat(32)}~${"ef".repeat(64)}`;
    const jobCells = [
      sender.runtime.sealCoverContent({ subtype: "dummy" }),
      sender.runtime.sealCoverContent({ subtype: "dummy" }),
    ];
    let next = 0;
    const job: CoverJob = {
      id: jobLabel,
      kind: "real",
      declaredCellCount: 2,
      nextCell: () => jobCells[next++] ?? null,
    };
    sender.runtime.enqueue(job);
    sender.runtime.start();
    await sender.clock.advanceTo(399);

    const jobLane = sender.channels.find(
      (channel) => channel.label === jobLabel,
    );
    expect(jobLane).toBeDefined();
    expect(jobLane!.sent.length).toBe(2);
    expect(Buffer.from(jobLane!.sent[0])).toEqual(Buffer.from(jobCells[0]));
    sender.runtime.destroy();
    sender.pq.destroy();
  });

  test("backpressure degrades without a catch-up burst and a non-uniform cell is refused at the lane boundary", async () => {
    const sender = makeHarness(true);
    const shortCell: CoverJob = {
      id: `${"12".repeat(32)}~${"34".repeat(64)}`,
      kind: "real",
      declaredCellCount: 1,
      nextCell: () => new Uint8Array(10),
    };
    sender.runtime.enqueue(shortCell);
    sender.runtime.start();
    await sender.clock.advanceTo(120);
    // The malformed cell was refused at the adapter boundary; the job is
    // interrupted rather than a non-uniform frame reaching the wire.
    expect(sender.interruptions.length).toBeGreaterThan(0);
    for (const channel of sender.channels)
      for (const cell of channel.sent)
        expect(cell).toHaveLength(WIRE_CHUNK_FRAME_LEN);

    // Backpressure on a lane refuses the slot without a later burst.
    const before = sender.channels.reduce(
      (total, channel) => total + channel.sent.length,
      0,
    );
    for (const channel of sender.channels)
      channel.bufferedAmount = MAX_BUFFERED_AMOUNT;
    await sender.clock.advanceTo(399);
    const after = sender.channels.reduce(
      (total, channel) => total + channel.sent.length,
      0,
    );
    expect(after).toBe(before);
    expect(sender.statuses).toContain("degraded");
    sender.runtime.destroy();
    sender.pq.destroy();
  });

  test("suspension closes at the boundary and resume targets a strictly future cycle", async () => {
    const sender = makeHarness(true);
    sender.runtime.start();
    await sender.clock.advanceTo(150);
    expect(sender.channels).toHaveLength(2);

    sender.runtime.suspend("test-suspension");
    expect(sender.statuses).toContain("suspended");
    // The open cycle's lanes still close at their fixed boundary, not early.
    expect(sender.channels[0].closes).toBe(0);
    await sender.clock.advanceTo(400);
    expect(sender.channels[0].closes).toBe(1);
    // No new lanes while suspended.
    await sender.clock.advanceTo(1150);
    expect(sender.channels).toHaveLength(2);

    sender.runtime.resume();
    await sender.clock.advanceTo(1600);
    // Resume opened lanes only at a strictly future boundary.
    expect(sender.channels.length).toBeGreaterThan(2);
    expect(sender.statuses[sender.statuses.length - 1]).not.toBe("suspended");
    sender.runtime.destroy();
    sender.pq.destroy();
  });
});
