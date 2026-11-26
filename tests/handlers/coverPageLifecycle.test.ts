import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  spyOn,
  test,
} from "bun:test";

import { CoverRuntime } from "../../src/handlers/coverRuntime";
import { SparsePqHealingState } from "../../src/handlers/pqHealingRuntime";
import { loadTestModule } from "../../src/cryptography/testModule";
import { setDebugLogging } from "../../src/utils/debug";
import { RATCHET_ROOT_SUITE_MLKEM512 } from "../../src/utils/constants";

import type { CoverLaneChannel } from "../../src/handlers/coverRuntime";
import type {
  CoverClock,
  CoverSchedulerStatus,
} from "../../src/handlers/coverScheduler";
import type { LibCrypto } from "../../src/cryptography/libcrypto";
import type { IRTCPeerConnection } from "../../src/api/webrtc/interfaces";

// The page lifecycle as scheduled cover sees it (transport audit 2026-11, item
// 15 and its `freeze` note):
//
// - A hidden page used to SUSPEND cover. A network observer then reads tab
//   visibility straight off the wire as cover on/off, and a hidden receiver
//   stops acknowledging, so its sender's idle budget runs out. A hidden page
//   now keeps its schedule armed; the browser may throttle the timers, and a
//   diagnostic says so.
// - The Page Lifecycle `freeze` and `resume` events fire on `document`, not
//   on `window`, so a `freeze` listener on window never ran.

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
  private time = 0;
  private nextId = 1;
  private readonly timers = new Map<number, FakeTimer>();

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

  armedTimerCount(): number {
    return this.timers.size;
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

  /** Throttled timers: everything due by `target` fires late, AT `target`. */
  async jumpTo(target: number): Promise<void> {
    if (target < this.time) throw new Error("fake clock cannot go backwards");
    this.time = target;
    await this.advanceTo(target);
  }
}

class FakeLane implements CoverLaneChannel {
  readonly label: string;
  readyState: string = "open";
  bufferedAmount = 0;
  readonly sent: Uint8Array[] = [];

  constructor(label: string) {
    this.label = label;
  }

  send(data: ArrayBuffer): void {
    this.sent.push(new Uint8Array(data));
  }

  close(): void {
    this.readyState = "closed";
  }
}

/** An event target that records which event types have a listener. */
class FakeEventTarget {
  private readonly listeners = new Map<string, Set<EventListener>>();

  addEventListener(type: string, listener: EventListener): void {
    let set = this.listeners.get(type);
    if (!set) {
      set = new Set();
      this.listeners.set(type, set);
    }
    set.add(listener);
  }

  removeEventListener(type: string, listener: EventListener): void {
    this.listeners.get(type)?.delete(listener);
  }

  dispatchEvent(event: Event): boolean {
    for (const listener of [...(this.listeners.get(event.type) ?? [])])
      listener(event);
    return true;
  }

  listenedTypes(): string[] {
    return [...this.listeners]
      .filter(([, set]) => set.size > 0)
      .map(([type]) => type)
      .sort();
  }
}

class FakeDocument extends FakeEventTarget {
  visibilityState: DocumentVisibilityState = "visible";
}

const ROOM_ID = "00000000-0000-4000-8000-0000000000e7";
const PEER_ID = "00000000-0000-4000-8000-000000000002";

let fakeDocument: FakeDocument;
let fakeWindow: FakeEventTarget;
const globals = globalThis as unknown as {
  document?: unknown;
  window?: unknown;
};
let hadDocument = false;
let hadWindow = false;
let previousDocument: unknown;
let previousWindow: unknown;

beforeEach(() => {
  hadDocument = "document" in globals;
  hadWindow = "window" in globals;
  previousDocument = globals.document;
  previousWindow = globals.window;
  fakeDocument = new FakeDocument();
  fakeWindow = new FakeEventTarget();
  globals.document = fakeDocument;
  globals.window = fakeWindow;
});

afterEach(() => {
  if (hadDocument) globals.document = previousDocument;
  else delete globals.document;
  if (hadWindow) globals.window = previousWindow;
  else delete globals.window;
  setDebugLogging(false);
});

const makeRuntime = () => {
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
    roomId: ROOM_ID,
    withPeerId: PEER_ID,
    pqHealingState: pq,
  } as unknown as IRTCPeerConnection;
  const clock = new FakeClock();
  const lanes: FakeLane[] = [];
  const statuses: { status: CoverSchedulerStatus; reason?: string }[] = [];
  const runtime = new CoverRuntime({
    epc,
    roomId: ROOM_ID,
    module,
    amInitiator: true,
    schedule: {
      coverCadenceMs: 400,
      coverLanes: 2,
      coverFramesPerCell: 2,
      coverDurationEpochs: 1,
    },
    policyHash: new Uint8Array(32),
    laneLabelName: "party",
    openLaneChannel: (label) => {
      const lane = new FakeLane(label);
      lanes.push(lane);
      return lane;
    },
    onStatusChange: ({ status, reason }) => statuses.push({ status, reason }),
    clock,
  });
  const sentCells = (): number =>
    lanes.reduce((total, lane) => total + lane.sent.length, 0);
  return { runtime, clock, statuses, sentCells };
};

describe("scheduled cover across the page lifecycle", () => {
  test("freeze listener is on document", async () => {
    const { runtime, clock } = makeRuntime();
    runtime.start();
    await clock.advanceTo(100);
    expect(runtime.status).toBe("active");

    // The browser fires `freeze` at the document.
    fakeDocument.dispatchEvent(new Event("freeze"));
    expect(runtime.status).toBe("suspended");

    // `resume` (also on document) lifts it at a strictly future boundary.
    fakeDocument.dispatchEvent(new Event("resume"));
    expect(runtime.status).toBe("starting");
    await clock.advanceTo(500);
    expect(runtime.status).toBe("active");

    // A `freeze` on window is not the Page Lifecycle event and changes nothing.
    fakeWindow.dispatchEvent(new Event("freeze"));
    expect(runtime.status).toBe("active");

    // Which target carries which Page Lifecycle listener.
    expect(fakeDocument.listenedTypes()).toEqual(
      ["freeze", "resume", "visibilitychange"].sort(),
    );
    expect(fakeWindow.listenedTypes()).not.toContain("freeze");
    expect(fakeWindow.listenedTypes()).not.toContain("resume");

    runtime.destroy();
    expect(fakeDocument.listenedTypes()).toEqual([]);
    expect(fakeWindow.listenedTypes()).toEqual([]);
  });

  test("cover stays armed while hidden", async () => {
    setDebugLogging(true);
    const log = spyOn(console, "log").mockImplementation(() => undefined);
    try {
      const { runtime, clock, statuses, sentCells } = makeRuntime();
      runtime.start();
      await clock.advanceTo(399);
      expect(runtime.status).toBe("active");
      const cellsBeforeHidden = sentCells();
      expect(cellsBeforeHidden).toBe(4);

      fakeDocument.visibilityState = "hidden";
      fakeDocument.dispatchEvent(new Event("visibilitychange"));

      expect(runtime.status).toBe("active");
      expect(statuses.map(({ status }) => status)).not.toContain("suspended");
      expect(clock.armedTimerCount()).toBe(1);

      // The next cycle opens and fills while the page is hidden: exactly
      // C x F x D = 4 more cells, on schedule.
      await clock.advanceTo(799);
      expect(sentCells()).toBe(cellsBeforeHidden + 4);
      expect(runtime.status).toBe("active");

      // The diagnostic says timers may be throttled, and names no peer and no
      // room.
      const lines = log.mock.calls.map((args) => args.map(String).join(" "));
      const diagnostics = lines.filter((line) => /throttl/i.test(line));
      expect(diagnostics).toHaveLength(1);
      expect(diagnostics[0]).not.toContain(ROOM_ID);
      expect(diagnostics[0]).not.toContain(PEER_ID);

      runtime.destroy();
    } finally {
      log.mockRestore();
    }
  });

  test("a throttled timer on a hidden page degrades the cycle and re-arms instead of parking", async () => {
    const { runtime, clock, statuses, sentCells } = makeRuntime();
    runtime.start();
    await clock.advanceTo(399);
    fakeDocument.visibilityState = "hidden";
    fakeDocument.dispatchEvent(new Event("visibilitychange"));
    const cellsBeforeStall = sentCells();

    // The boundary due at 400 is delivered at 1000: far past the drift
    // tolerance, the way a hidden tab's clamped timers arrive.
    await clock.jumpTo(1000);
    expect(runtime.status).toBe("degraded");
    expect(statuses.at(-1)).toEqual({
      status: "degraded",
      reason: "timer-drift",
    });
    // Not parked: the next strictly-future boundary (1200) is armed.
    expect(clock.armedTimerCount()).toBe(1);
    // The gap is not claimed: nothing was sent for the missed time.
    expect(sentCells()).toBe(cellsBeforeStall);

    // Still hidden, the next cycle runs in full once timers are on time again.
    await clock.advanceTo(1599);
    expect(runtime.status).toBe("active");
    expect(sentCells()).toBe(cellsBeforeStall + 4);
    expect(statuses.map(({ status }) => status)).not.toContain("suspended");

    runtime.destroy();
  });

  test("the hidden-page diagnostic is silent unless debug logging is on", () => {
    const log = spyOn(console, "log").mockImplementation(() => undefined);
    try {
      const { runtime } = makeRuntime();
      runtime.start();
      fakeDocument.visibilityState = "hidden";
      fakeDocument.dispatchEvent(new Event("visibilitychange"));
      expect(log).not.toHaveBeenCalled();
      runtime.destroy();
    } finally {
      log.mockRestore();
    }
  });

  test("pagehide and offline still suspend, and a visible page or online resumes", async () => {
    const { runtime, clock } = makeRuntime();
    runtime.start();
    await clock.advanceTo(100);

    fakeWindow.dispatchEvent(new Event("pagehide"));
    expect(runtime.status).toBe("suspended");
    fakeDocument.visibilityState = "visible";
    fakeDocument.dispatchEvent(new Event("visibilitychange"));
    expect(runtime.status).toBe("starting");

    await clock.advanceTo(500);
    fakeWindow.dispatchEvent(new Event("offline"));
    expect(runtime.status).toBe("suspended");
    fakeWindow.dispatchEvent(new Event("online"));
    expect(runtime.status).toBe("starting");

    runtime.destroy();
  });
});
