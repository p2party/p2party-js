import { beforeAll, describe, expect, test } from "bun:test";

// The production state-row deletion dispatches into the real Redux store,
// whose browser identity slice reads localStorage at module initialization.
// Only the one test that drives the shipped default imports it, and it does so
// dynamically — but the shim has to exist before that import runs.
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

import {
  cancelScheduledSend,
  installCoverEdge,
  teardownCoverEdge,
} from "../../src/handlers/coverEdge";
import { CoverRuntime } from "../../src/handlers/coverRuntime";
import {
  buildScheduledSendJob,
  scheduledCoverIsSuspended,
  scheduledSendProgress,
  waitForScheduledDelivery,
} from "../../src/handlers/coverTransfer";
import {
  productionInboundTransferSweepDeps,
  shouldSweepCancelledInboundTransfer,
  sweepCancelledInboundTransfer,
} from "../../src/handlers/inboundTransferSweep";
import { SparsePqHealingState } from "../../src/handlers/pqHealingRuntime";
import { loadTestModule } from "../../src/cryptography/testModule";
import {
  RATCHET_ROOT_SUITE_MLKEM512,
  WIRE_CHUNK_FRAME_LEN,
} from "../../src/utils/constants";
import {
  DEFAULT_ROOM_POLICY_V1,
  type RoomPolicyV1,
} from "../../src/roomPolicy";

import type { InboundTransferSweepDeps } from "../../src/handlers/inboundTransferSweep";
import type { CoverLaneChannel } from "../../src/handlers/coverRuntime";
import type { CoverClock } from "../../src/handlers/coverScheduler";
import type { LibCrypto } from "../../src/cryptography/libcrypto";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../../src/api/webrtc/interfaces";
import type { MessageData } from "../../src/db/types";
import { waitForEdgeReceiveQuiescence } from "../../src/handlers/handleMessageQueueing";

let module: LibCrypto;
beforeAll(async () => {
  module = await loadTestModule();
});

const PEER_ID = "peer-a";
const ROOM_ID = "room-1";
const ROOT_HEX = "cd".repeat(64);
const ROOT = new Uint8Array(64).fill(0xcd);

const flush = async (): Promise<void> => {
  for (let i = 0; i < 16; i++) await Promise.resolve();
};

// ── deterministic storage double ─────────────────────────────────────────────
//
// The production deps go through the IndexedDB Worker; the sweep takes them as
// a parameter (the same convention forgetMappedReceiveMessageKey already uses)
// so a test can hand it a synchronous store and read what it did.

interface SweepSpy {
  readonly deps: InboundTransferSweepDeps;
  readonly rows: Map<string, MessageData>;
  readonly reads: (string | undefined)[];
  readonly deleted: string[];
  readonly forgotten: string[];
  /** (roomId, merkleRootHex) pairs handed to the in-memory state deletion. */
  readonly stateDropped: string[];
}

const rowFor = (overrides: Partial<MessageData> = {}): MessageData => ({
  roomId: ROOM_ID,
  timestamp: 0,
  fromPeerId: PEER_ID,
  channelLabel: "chat",
  hash: "ab".repeat(64),
  merkleRoot: ROOT_HEX,
  filename: "big.bin",
  messageType: 1,
  savedSize: 40,
  totalSize: 100,
  ...overrides,
});

const makeSweepSpy = (rows: Record<string, MessageData> = {}): SweepSpy => {
  const store = new Map<string, MessageData>(Object.entries(rows));
  const reads: (string | undefined)[] = [];
  const deleted: string[] = [];
  const forgotten: string[] = [];
  const stateDropped: string[] = [];
  return {
    rows: store,
    reads,
    deleted,
    forgotten,
    stateDropped,
    deps: {
      waitForReceiveIdle: async () => undefined,
      dropStateRow: (roomId: string, merkleRootHex: string) => {
        stateDropped.push(`${roomId}/${merkleRootHex}`);
      },
      readProgress: async (merkleRootHex?: string) => {
        reads.push(merkleRootHex);

        return merkleRootHex === undefined
          ? undefined
          : store.get(merkleRootHex);
      },
      forgetKey: async (
        _epc: IRTCPeerConnection,
        _roomId: string,
        merkleRootHex: string,
      ) => {
        forgotten.push(merkleRootHex);
        return true;
      },
      deleteReceive: async (merkleRootHex: string) => {
        deleted.push(merkleRootHex);
        store.delete(merkleRootHex);
      },
    } as InboundTransferSweepDeps,
  };
};

// ── cover-edge harness ───────────────────────────────────────────────────────

class FakeChannel implements CoverLaneChannel {
  readonly label: string;
  readyState: string = "open";
  bufferedAmount = 0;
  readonly sent: Uint8Array[] = [];
  closes = 0;
  binaryType = "arraybuffer";
  withPeerId = PEER_ID;
  roomIds: [string] = [ROOM_ID];

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

  addEventListener(): void {
    /* the registry only needs close notification, which these tests never use */
  }
}

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

  private async drain(): Promise<void> {
    for (let i = 0; i < 8; i++) await Promise.resolve();
  }

  async advanceTo(target: number): Promise<void> {
    if (target < this.time) throw new Error("fake clock cannot go backwards");
    for (;;) {
      await this.drain();
      const timer = this.nextDue(target);
      if (!timer) break;
      this.time = Math.max(this.time, timer.at);
      this.timers.delete(timer.id);
      timer.callback();
    }
    this.time = target;
    await this.drain();
  }
}

const makePq = (amInitiator: boolean): SparsePqHealingState =>
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

// A cadence far longer than any test run, so the receiver's real-timer edge
// never opens a cycle: these tests only need it to authenticate inbound cells.
const receiverPolicy = (): RoomPolicyV1 => ({
  ...DEFAULT_ROOM_POLICY_V1,
  coverMode: "scheduled",
  coverCadenceMs: 600_000,
  coverLanes: 2,
  coverFramesPerCell: 2,
  coverDurationEpochs: 1,
});

interface Receiver {
  readonly epc: IRTCPeerConnection;
  readonly pq: SparsePqHealingState;
  readonly spy: SweepSpy;
  readonly outboundAborts: string[];
  destroy(): void;
}

const makeReceiver = (spy: SweepSpy): Receiver => {
  const pq = makePq(false); // responder: opens the initiator's cells
  const outboundAborts: string[] = [];
  const epc = {
    withPeerId: PEER_ID,
    pqHealingState: pq,
    createDataChannel: (label: string) =>
      new FakeChannel(label) as unknown as IRTCDataChannel,
  } as unknown as IRTCPeerConnection;
  installCoverEdge({
    epc,
    roomId: ROOM_ID,
    policy: receiverPolicy(),
    policyHash: new Uint8Array(32),
    amInitiator: false,
    module,
    onRemoteCancel: (root) => outboundAborts.push(root),
    inboundSweepDeps: spy.deps,
  });
  return {
    epc,
    pq,
    spy,
    outboundAborts,
    destroy: () => {
      teardownCoverEdge(epc);
      pq.destroy();
    },
  };
};

/** The peer's runtime, used only to seal authentic CANCEL cells. */
const makeSender = (): { runtime: CoverRuntime; pq: SparsePqHealingState } => {
  const pq = makePq(true);
  const epc = { pqHealingState: pq } as unknown as IRTCPeerConnection;
  const runtime = new CoverRuntime({
    epc,
    roomId: ROOM_ID,
    module,
    amInitiator: true,
    schedule: {
      coverCadenceMs: 600_000,
      coverLanes: 2,
      coverFramesPerCell: 2,
      coverDurationEpochs: 1,
    },
    policyHash: new Uint8Array(32),
    laneLabelName: "party",
    openLaneChannel: (label) => new FakeChannel(label),
  });
  return { runtime, pq };
};

describe("shouldSweepCancelledInboundTransfer (what a CANCEL may destroy)", () => {
  test("only an incomplete receive from the cancelling peer", () => {
    expect(shouldSweepCancelledInboundTransfer(rowFor(), PEER_ID)).toBe(true);
  });

  test("never a completed message", () => {
    expect(
      shouldSweepCancelledInboundTransfer(
        rowFor({ savedSize: 100, totalSize: 100 }),
        PEER_ID,
      ),
    ).toBe(false);
  });

  test("never another peer's transfer", () => {
    expect(
      shouldSweepCancelledInboundTransfer(
        rowFor({ fromPeerId: "peer-b" }),
        PEER_ID,
      ),
    ).toBe(false);
  });

  test("never a row this device sent (transferId marks our own copy)", () => {
    expect(
      shouldSweepCancelledInboundTransfer(
        rowFor({ transferId: "ff".repeat(32) }),
        PEER_ID,
      ),
    ).toBe(false);
  });

  test("never an unknown root", () => {
    expect(shouldSweepCancelledInboundTransfer(undefined, PEER_ID)).toBe(false);
  });
});

describe("sweepCancelledInboundTransfer", () => {
  test("a final chunk already being processed completes before cancellation is assessed", async () => {
    const spy = makeSweepSpy({ [ROOT_HEX]: rowFor() });
    const epc = { withPeerId: PEER_ID } as unknown as IRTCPeerConnection;
    let release: () => void = () => undefined;
    const pendingReceive = new Promise<void>((resolve) => {
      release = resolve;
    });
    const drains: string[] = [];
    const deps = {
      ...spy.deps,
      waitForReceiveIdle: async (roomId: string, peerId: string) => {
        drains.push(`${roomId}/${peerId}`);
        await pendingReceive;
        spy.rows.set(ROOT_HEX, rowFor({ savedSize: 100 }));
      },
    };
    const swept = sweepCancelledInboundTransfer(epc, ROOM_ID, ROOT_HEX, deps);
    await flush();
    const readsWhileReceiving = [...spy.reads];
    release();
    expect(await swept).toBe(false);
    expect(readsWhileReceiving).toEqual([]);
    expect(drains).toEqual([`${ROOM_ID}/${PEER_ID}`]);
    expect(spy.deleted).toEqual([]);
    expect(spy.forgotten).toEqual([]);
    expect(productionInboundTransferSweepDeps.waitForReceiveIdle).toBe(
      waitForEdgeReceiveQuiescence,
    );
  });

  test("never deletes the same peer's partial in a different room", async () => {
    const spy = makeSweepSpy({ [ROOT_HEX]: rowFor({ roomId: "other-room" }) });
    const epc = { withPeerId: PEER_ID } as unknown as IRTCPeerConnection;
    expect(
      await sweepCancelledInboundTransfer(epc, ROOM_ID, ROOT_HEX, spy.deps),
    ).toBe(false);
    expect(spy.forgotten).toEqual([]);
    expect(spy.deleted).toEqual([]);
    expect(spy.stateDropped).toEqual([]);
  });

  test("forgets the receive key before deleting the partial", async () => {
    const spy = makeSweepSpy({ [ROOT_HEX]: rowFor() });
    const epc = { withPeerId: PEER_ID } as unknown as IRTCPeerConnection;
    expect(
      await sweepCancelledInboundTransfer(epc, ROOM_ID, ROOT_HEX, spy.deps),
    ).toBe(true);
    expect(spy.forgotten).toEqual([ROOT_HEX]);
    expect(spy.deleted).toEqual([ROOT_HEX]);
  });

  // ── finding 4: parity with immediate mode is the WHOLE deletion ────────────
  //
  // Both immediate-mode cancels do two things: the worker's cancelReceiveTransfer
  // removes chunks, the messageData row and the pre-sized OPFS file, and the
  // caller then dispatches deleteMessage so the in-memory room state loses the
  // message too (disconnectFromPeerChannelLabelQuery, disconnectFromChannelLabelQuery).
  // Doing only the durable half leaves the user looking at a partial whose
  // bytes no longer exist and which no re-send can ever fill.
  test("the in-memory state row goes too, exactly as immediate mode does", async () => {
    const spy = makeSweepSpy({ [ROOT_HEX]: rowFor() });
    const epc = { withPeerId: PEER_ID } as unknown as IRTCPeerConnection;
    expect(
      await sweepCancelledInboundTransfer(epc, ROOM_ID, ROOT_HEX, spy.deps),
    ).toBe(true);
    expect(spy.stateDropped).toEqual([`${ROOM_ID}/${ROOT_HEX}`]);
  });

  test("a refused sweep leaves the state row exactly where it is", async () => {
    // Deletion is irreversible in the store as well as on disk: every refusal
    // in shouldSweepCancelledInboundTransfer must cover BOTH halves.
    const spy = makeSweepSpy({
      [ROOT_HEX]: rowFor({ savedSize: 100, totalSize: 100 }),
    });
    const epc = { withPeerId: PEER_ID } as unknown as IRTCPeerConnection;
    expect(
      await sweepCancelledInboundTransfer(epc, ROOM_ID, ROOT_HEX, spy.deps),
    ).toBe(false);
    expect(spy.deleted).toEqual([]);
    expect(spy.stateDropped).toEqual([]);
  });

  test("a durable delete that throws never drops the state row", async () => {
    // The state row is the last thing to go, because it is the only remaining
    // evidence a partial exists: a reconnect can still resume what is on disk.
    const spy = makeSweepSpy({ [ROOT_HEX]: rowFor() });
    const failing: InboundTransferSweepDeps = {
      ...spy.deps,
      deleteReceive: () => Promise.reject(new Error("worker is gone")),
    };
    const epc = { withPeerId: PEER_ID } as unknown as IRTCPeerConnection;
    expect(
      await sweepCancelledInboundTransfer(epc, ROOM_ID, ROOT_HEX, failing),
    ).toBe(false);
    // It really did get as far as the durable delete before failing, so the
    // empty list below is a refusal and not a path that never ran.
    expect(spy.forgotten).toEqual([ROOT_HEX]);
    expect(spy.stateDropped).toEqual([]);
  });

  test("the PRODUCTION dropStateRow really removes the message from live state", async () => {
    // The deps seam exists so a test can watch the sweep; it must not be the
    // reason the shipped path does nothing. This drives the default straight
    // into the real store.
    const { store } = await import("../../src/store");
    const { setMessage, setRoom } =
      await import("../../src/reducers/roomSlice");
    const roomUrl = "5".repeat(64);
    store.dispatch(setRoom({ url: roomUrl, id: "" }));
    const roomId = store
      .getState()
      .rooms.find(({ url }) => url === roomUrl)?.id;
    expect(typeof roomId).toBe("string");
    store.dispatch(
      setMessage({
        roomId: roomId!,
        merkleRootHex: ROOT_HEX,
        sha512Hex: "ab".repeat(64),
        chunkSize: 1,
        totalSize: 100,
        // setMessage refuses a non-UUID sender.
        fromPeerId: "11111111-1111-4111-8111-111111111111",
        filename: "big.bin",
        messageType: 1,
        channelLabel: "chat",
      }),
    );
    const holdsMessage = (): boolean =>
      store
        .getState()
        .rooms.find(({ id }) => id === roomId)
        ?.messages.some((m) => m.merkleRootHex === ROOT_HEX) === true;

    expect(holdsMessage()).toBe(true);
    await productionInboundTransferSweepDeps.dropStateRow(roomId!, ROOT_HEX);
    expect(holdsMessage()).toBe(false);
  });

  test("a malformed root is never handed to storage", async () => {
    const spy = makeSweepSpy({ [ROOT_HEX]: rowFor() });
    const epc = { withPeerId: PEER_ID } as unknown as IRTCPeerConnection;
    expect(
      await sweepCancelledInboundTransfer(epc, ROOM_ID, "not-a-root", spy.deps),
    ).toBe(false);
    // Refused before the Worker is asked anything at all — a well-formed root
    // DOES reach it, so this is the guard and not an empty store.
    expect(spy.reads).toEqual([]);
    expect(spy.deleted).toEqual([]);
    await sweepCancelledInboundTransfer(epc, ROOM_ID, ROOT_HEX, spy.deps);
    expect(spy.reads).toEqual([ROOT_HEX]);
  });
});

describe("an authenticated remote CANCEL sweeps the inbound partial (finding B)", () => {
  test("the receiver's partial is deleted, and the caller's outbound abort still runs", async () => {
    const spy = makeSweepSpy({ [ROOT_HEX]: rowFor() });
    const receiver = makeReceiver(spy);
    const sender = makeSender();

    const cancelCell = sender.runtime.sealCoverContent({
      subtype: "cancel",
      merkleRoot: ROOT,
    });
    expect(receiver.epc.coverRuntime!.processInboundCoverCell(cancelCell)).toBe(
      true,
    );
    await flush();

    expect(receiver.outboundAborts).toEqual([ROOT_HEX]);
    expect(spy.deleted).toEqual([ROOT_HEX]);
    expect(spy.rows.has(ROOT_HEX)).toBe(false);
    // ...and the in-memory row goes with it, exactly as immediate mode does.
    expect(spy.stateDropped).toEqual([`${ROOM_ID}/${ROOT_HEX}`]);

    receiver.destroy();
    sender.runtime.destroy();
    sender.pq.destroy();
  });

  test("a CANCEL never destroys a completed message or another peer's transfer", async () => {
    const otherRoot = "ee".repeat(64);
    const spy = makeSweepSpy({
      [ROOT_HEX]: rowFor({ savedSize: 100, totalSize: 100 }),
      [otherRoot]: rowFor({ merkleRoot: otherRoot, fromPeerId: "peer-b" }),
    });
    const receiver = makeReceiver(spy);
    const sender = makeSender();

    for (const root of [ROOT, new Uint8Array(64).fill(0xee)]) {
      const cell = sender.runtime.sealCoverContent({
        subtype: "cancel",
        merkleRoot: root,
      });
      expect(receiver.epc.coverRuntime!.processInboundCoverCell(cell)).toBe(
        true,
      );
    }
    await flush();

    expect(spy.deleted).toEqual([]);
    expect(spy.rows.size).toBe(2);

    receiver.destroy();
    sender.runtime.destroy();
    sender.pq.destroy();
  });

  test("a forged CANCEL sweeps nothing, because it never authenticates", async () => {
    const spy = makeSweepSpy({ [ROOT_HEX]: rowFor() });
    const receiver = makeReceiver(spy);
    const sender = makeSender();

    const cell = sender.runtime.sealCoverContent({
      subtype: "cancel",
      merkleRoot: ROOT,
    });
    cell[WIRE_CHUNK_FRAME_LEN - 1] ^= 1;
    expect(receiver.epc.coverRuntime!.processInboundCoverCell(cell)).toBe(
      false,
    );
    await flush();

    expect(spy.deleted).toEqual([]);
    expect(spy.rows.has(ROOT_HEX)).toBe(true);

    receiver.destroy();
    sender.runtime.destroy();
    sender.pq.destroy();
  });
});

describe("A + B together: a healthy in-progress transfer survives", () => {
  // A cadence wide enough that ONE job spans most of a cycle, so a bound can
  // expire while the transfer is genuinely mid-flight — the only situation in
  // which a spurious cancellation can destroy data.
  const SEND_SCHEDULE = {
    coverCadenceMs: 4_000,
    coverLanes: 2,
    coverFramesPerCell: 20,
    coverDurationEpochs: 1,
  };
  const CYCLE_MS =
    SEND_SCHEDULE.coverCadenceMs * SEND_SCHEDULE.coverDurationEpochs;
  // coverTransfer.scheduledDeliveryTimeoutMs without its fixed 20 s head-room,
  // which exists to absorb real-world jitter and would swamp a scaled clock:
  // 2 x cycle + the last lane's first slot. This IS the arithmetic floor the
  // shipped bound is built from, and treating it as a deadline is finding A.
  const ARITHMETIC_FLOOR_MS =
    2 * CYCLE_MS +
    Math.ceil(
      ((2 * SEND_SCHEDULE.coverLanes - 1) * SEND_SCHEDULE.coverCadenceMs) /
        (2 * SEND_SCHEDULE.coverLanes * SEND_SCHEDULE.coverFramesPerCell),
    );
  const CELLS = SEND_SCHEDULE.coverFramesPerCell;

  interface SendRig {
    readonly epc: IRTCPeerConnection;
    readonly runtime: CoverRuntime;
    readonly pq: SparsePqHealingState;
    readonly clock: FakeClock;
    readonly lanes: FakeChannel[];
    readonly jobLabel: string;
  }

  const makeSendRig = (): SendRig => {
    const pq = makePq(true);
    const clock = new FakeClock(0);
    const lanes: FakeChannel[] = [];
    const epc = { pqHealingState: pq } as unknown as IRTCPeerConnection;
    const runtime = new CoverRuntime({
      epc,
      roomId: ROOM_ID,
      module,
      amInitiator: true,
      schedule: SEND_SCHEDULE,
      policyHash: new Uint8Array(32),
      laneLabelName: "party",
      openLaneChannel: (label) => {
        const lane = new FakeChannel(label);
        lanes.push(lane);
        return lane;
      },
      maxTimerDriftMs: 0,
      clock,
    });
    epc.coverRuntime = runtime;

    // Four other messages ahead of ours on a two-lane edge, so ours is admitted
    // only at the third cycle open — after the arithmetic floor assumes it was
    // already confirmed. Exactly the contention of finding A.
    for (let i = 0; i < 4; i++)
      runtime.enqueue({
        id: `${(i + 1).toString(16).repeat(64)}~${(i + 1).toString(16).repeat(128)}`,
        kind: "real",
        declaredCellCount: CELLS,
        nextCell: () => runtime.sealCoverContent({ subtype: "dummy" }),
      });
    const jobLabel = `${"ab".repeat(32)}~${ROOT_HEX}`;
    runtime.enqueue(
      buildScheduledSendJob({
        runtime,
        channelMessageLabel: jobLabel,
        totalChunks: CELLS,
        merkleRoot: ROOT,
        // Real chunk cells are sealed under the message key; sealing them as
        // authentic dummy cover cells lets the receiver ingest every byte this
        // send puts on the wire and prove no CANCEL is among them.
        sealSlotCell: () => runtime.sealCoverContent({ subtype: "dummy" }),
      }),
    );
    runtime.start();
    return { epc, runtime, pq, clock, lanes, jobLabel };
  };

  const feedEverythingSent = (rig: SendRig, receiver: Receiver): void => {
    for (const lane of rig.lanes)
      for (const cell of lane.sent)
        receiver.epc.coverRuntime!.processInboundCoverCell(cell);
  };

  test("the progress-gated wait never cancels a send that is still emitting, so the receiver keeps its partial", async () => {
    const spy = makeSweepSpy({ [ROOT_HEX]: rowFor() });
    const receiver = makeReceiver(spy);
    const rig = makeSendRig();

    let receiptLanded = false;
    const delivered = await waitForScheduledDelivery({
      isComplete: () => receiptLanded,
      progress: () => scheduledSendProgress(rig.runtime, rig.jobLabel),
      idleTimeoutMs: ARITHMETIC_FLOOR_MS,
      pollMs: 50,
      now: () => rig.clock.now(),
      sleep: async (ms) => {
        await rig.clock.advanceTo(rig.clock.now() + ms);
        // The terminal receipt can only exist once every cell is out; model it
        // as the job leaving the scheduler.
        if (rig.runtime.getJobProgress(rig.jobLabel) === undefined)
          receiptLanded = true;
      },
    });

    expect(delivered).toBe(true);
    // Confirmed well past the deadline the arithmetic bound would have set.
    expect(rig.clock.now()).toBeGreaterThan(ARITHMETIC_FLOOR_MS);

    // The whole message reached the wire, so the receiver's partial was
    // filling the entire time the old bound would have been cancelling it.
    const jobLane = rig.lanes.find((lane) => lane.label === rig.jobLabel);
    expect(jobLane?.sent.length).toBe(CELLS);

    // Production cancels only when delivery was NOT confirmed. It was, so every
    // cell this send emitted reaches the receiver and none of them is a CANCEL.
    feedEverythingSent(rig, receiver);
    await flush();
    expect(receiver.outboundAborts).toEqual([]);
    expect(spy.deleted).toEqual([]);
    expect(spy.rows.get(ROOT_HEX)?.savedSize).toBe(40);

    rig.runtime.destroy();
    rig.pq.destroy();
    receiver.destroy();
  });

  test("CONTROL: the same floor used as a DEADLINE cancels mid-flight, and the receiver's partial IS destroyed", async () => {
    const spy = makeSweepSpy({ [ROOT_HEX]: rowFor() });
    const receiver = makeReceiver(spy);
    const rig = makeSendRig();

    const delivered = await waitForScheduledDelivery({
      isComplete: () => false,
      // The pre-fix bound: elapsed time only, blind to the job's own advance.
      progress: () => undefined,
      idleTimeoutMs: ARITHMETIC_FLOOR_MS,
      pollMs: 50,
      now: () => rig.clock.now(),
      sleep: async (ms) => {
        await rig.clock.advanceTo(rig.clock.now() + ms);
      },
    });
    expect(delivered).toBe(false);

    // The job was admitted and part-way through emitting when the deadline
    // expired: the receiver is holding a partial that is still filling.
    const midFlight = rig.runtime.getJobProgress(rig.jobLabel);
    expect(midFlight?.state).toBe("admitted");
    expect(midFlight!.sentCells).toBeGreaterThan(0);
    expect(midFlight!.sentCells).toBeLessThan(CELLS);

    // Exactly what sendScheduled does on a failed delivery.
    expect(cancelScheduledSend(rig.epc, rig.jobLabel)).toBe("cancel-pending");
    await rig.clock.advanceTo(rig.clock.now() + CYCLE_MS);

    feedEverythingSent(rig, receiver);
    await flush();
    expect(receiver.outboundAborts).toEqual([ROOT_HEX]);
    expect(spy.deleted).toEqual([ROOT_HEX]);
    expect(spy.rows.has(ROOT_HEX)).toBe(false);

    rig.runtime.destroy();
    rig.pq.destroy();
    receiver.destroy();
  });

  // ── finding 1: a suspended job is not a stalled job ────────────────────────
  //
  // CoverRuntime suspends the scheduler on visibilitychange→hidden, pagehide,
  // freeze and offline. `CoverScheduler.suspend` REQUEUES but KEEPS the job, so
  // the sender's only progress signal freezes while the send is perfectly
  // healthy. Spending the idle budget through that gap abandons a live send,
  // and `sendScheduled`'s CANCEL then deletes the receiver's partial — an
  // ordinary user action (backgrounding a tab) destroying the peer's download.
  describe("a backgrounded tab is not a stalled send (finding 1)", () => {
    // Three whole budgets hidden: far beyond anything the idle bound tolerates
    // when it cannot tell "paused" from "stuck".
    const HIDDEN_MS = 3 * ARITHMETIC_FLOOR_MS;

    /** Every cell this send's lanes have put on the wire, across all cycles. */
    const jobCellsOnWire = (rig: SendRig): number =>
      rig.lanes
        .filter((lane) => lane.label === rig.jobLabel)
        .reduce((total, lane) => total + lane.sent.length, 0);

    interface HiddenTabRun {
      readonly delivered: boolean;
      readonly hiddenUntilMs: number;
      readonly cellsAtResume: number;
    }

    /**
     * Admit the send, emit part of it, background the tab, and wait. The tab
     * returns to the foreground HIDDEN_MS later, from inside the wait's own
     * sleep — so a wait that gave up before then never saw it come back.
     */
    const runHiddenTab = async (
      rig: SendRig,
      isSuspended: () => boolean,
    ): Promise<HiddenTabRun> => {
      // Cycle 0 and 1 admit the four fillers; ours is admitted at cycle 2 and
      // is part-way through emitting when the tab is hidden.
      await rig.clock.advanceTo(2 * CYCLE_MS + Math.floor(CYCLE_MS / 2));
      const midFlight = rig.runtime.getJobProgress(rig.jobLabel);
      expect(midFlight?.state).toBe("admitted");
      expect(midFlight!.sentCells).toBeGreaterThan(0);
      expect(midFlight!.sentCells).toBeLessThan(CELLS);

      rig.runtime.suspend("page-hidden");
      expect(rig.runtime.status).toBe("suspended");
      // Suspension keeps the job: this is a live send, not a lost one.
      expect(rig.runtime.getJobProgress(rig.jobLabel)).toBeDefined();

      const hiddenUntilMs = rig.clock.now() + HIDDEN_MS;
      let cellsAtResume = -1;
      let receiptLanded = false;
      const delivered = await waitForScheduledDelivery({
        isComplete: () => receiptLanded,
        progress: () => scheduledSendProgress(rig.runtime, rig.jobLabel),
        isSuspended,
        idleTimeoutMs: ARITHMETIC_FLOOR_MS,
        pollMs: 50,
        now: () => rig.clock.now(),
        sleep: async (ms) => {
          await rig.clock.advanceTo(rig.clock.now() + ms);
          if (
            rig.clock.now() >= hiddenUntilMs &&
            rig.runtime.status === "suspended"
          ) {
            cellsAtResume = jobCellsOnWire(rig);
            rig.runtime.resume();
          }
          // The terminal receipt cannot exist before every cell is out; model
          // it as the job leaving the scheduler.
          if (rig.runtime.getJobProgress(rig.jobLabel) === undefined)
            receiptLanded = true;
        },
      });
      return { delivered, hiddenUntilMs, cellsAtResume };
    };

    test("the send survives the hidden interval and the receiver keeps its partial", async () => {
      const spy = makeSweepSpy({ [ROOT_HEX]: rowFor() });
      const receiver = makeReceiver(spy);
      const rig = makeSendRig();

      const run = await runHiddenTab(rig, () =>
        scheduledCoverIsSuspended(rig.runtime),
      );

      expect(run.delivered).toBe(true);
      // It waited out the whole hidden interval instead of giving up inside it.
      expect(rig.clock.now()).toBeGreaterThan(run.hiddenUntilMs);
      // ...and the transfer really did continue once the tab came back.
      expect(run.cellsAtResume).toBeGreaterThan(0);
      expect(jobCellsOnWire(rig)).toBeGreaterThan(run.cellsAtResume);

      // Production cancels only when delivery was NOT confirmed. It was, so
      // every cell this send emitted reaches the receiver and none is a CANCEL.
      feedEverythingSent(rig, receiver);
      await flush();
      expect(receiver.outboundAborts).toEqual([]);
      expect(spy.deleted).toEqual([]);
      expect(spy.rows.get(ROOT_HEX)?.savedSize).toBe(40);

      rig.runtime.destroy();
      rig.pq.destroy();
      receiver.destroy();
    });

    test("CONTROL: without the suspension gate the budget expires, and the returning tab's CANCEL destroys the partial", async () => {
      const spy = makeSweepSpy({ [ROOT_HEX]: rowFor() });
      const receiver = makeReceiver(spy);
      const rig = makeSendRig();

      // The ONE expression under repair, flipped back: the budget accrues
      // through a browser-imposed suspension exactly as it did before.
      const run = await runHiddenTab(rig, () => false);
      expect(run.delivered).toBe(false);
      // It gave up while the tab was still hidden and the job still healthy.
      expect(rig.clock.now()).toBeLessThan(run.hiddenUntilMs);
      expect(rig.runtime.status).toBe("suspended");

      // Exactly what sendScheduled does on a failed delivery. The scheduler is
      // suspended, so the CANCEL cell does not fly until the tab comes back —
      // which is when the user's peer loses the file.
      expect(cancelScheduledSend(rig.epc, rig.jobLabel)).toBe("cancel-pending");
      rig.runtime.resume();
      await rig.clock.advanceTo(rig.clock.now() + 2 * CYCLE_MS);

      feedEverythingSent(rig, receiver);
      await flush();
      expect(receiver.outboundAborts).toEqual([ROOT_HEX]);
      expect(spy.deleted).toEqual([ROOT_HEX]);
      expect(spy.rows.has(ROOT_HEX)).toBe(false);

      rig.runtime.destroy();
      rig.pq.destroy();
      receiver.destroy();
    });
  });
});
