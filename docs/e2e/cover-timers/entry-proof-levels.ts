// Browser entry for the proof-level build measurement (driver.mjs
// --mode=proof-levels; see docs/e2e/README.md, "Proof-level build"). A
// message's Merkle proof levels are built once, on the page, when its first
// cell without a stored proof is produced. This measures how long that build
// holds the page's thread, what it holds in memory, and what it does to the
// cover slots that fall due while it runs.
//
// Phase "alone", on a page that runs nothing else: for each size in `sizes`
// (leaves; random, as the build reads nothing but the leaves), `repeats`
// builds for each slice budget in `slices` (ms; a synchronous build has no
// budget and runs the same build each time). A probe posts itself a
// MessageChannel message whenever it runs: the longest gap between two probe
// runs during a build is the longest the build held the page's thread.
//
// Phase "grid": `edges` real CoverRuntimes on one grid (`cadence`, `lanes`,
// `frames`; the page's one shared timer worker; real PQ runtimes and real
// dummies). Edge 0 sends, one after another, one scheduled job per size in
// `gridSizes`, each the first send of a fresh message of that many leaves, of
// which the job sends `cells`. Its cells come from the real slot sealer
// (makeScheduledSlotSealer: the outbox read through the real database worker,
// cellPlaintext, which builds the proof levels on the job's first cell, then
// the seal). Every wake-up and every cell of every edge is recorded, with each
// job cell's production, so the slots due while a build runs can be compared
// with the others. The messages are staged, and their roots computed, before
// the grid starts.
//
// Every time is page-side: performance.timeOrigin + performance.now(), against
// the scheduler's slot deadlines (page Date.now()).
import libcrypto from "../../../src/cryptography/libcrypto";
import { buildMerkleProofLevels } from "../../../src/cryptography/merkle";
import { CoverRuntime } from "../../../src/handlers/coverRuntime";
import { SparsePqHealingState } from "../../../src/handlers/pqHealingRuntime";
import {
  browserCoverTimerEnvironment,
  createCoverTimerClock,
} from "../../../src/handlers/coverTimerWorker";
import { buildScheduledSendJob } from "../../../src/handlers/coverTransfer";
import {
  OutboundMessage,
  makeScheduledSlotSealer,
} from "../../../src/handlers/handleSendMessage";
import { createMessageChunkSealer } from "../../../src/handlers/messageChunkCrypto";
import { setDBNewChunk } from "../../../src/db/api";
import { serializeMetadata } from "../../../src/utils/metadata";
import { hashMerkleLeaf } from "../../../src/utils/leafHash";
import { compileChannelMessageLabel } from "../../../src/utils/channelLabel";
import { uint8ArrayToHex } from "../../../src/utils/uint8array";
import { MessageType } from "../../../src/utils/messageTypes";
import {
  CHUNK_LEN,
  RATCHET_ROOT_SUITE_MLKEM512,
} from "../../../src/utils/constants";

import type { LibCrypto } from "../../../src/cryptography/libcrypto";
import type { MerkleProofLevels } from "../../../src/cryptography/merkle";
import type { IRTCPeerConnection } from "../../../src/api/webrtc/interfaces";
import type {
  CoverClock,
  CoverTimerKind,
} from "../../../src/handlers/coverScheduler";
import type { CoverLaneChannel } from "../../../src/handlers/coverRuntime";

const query = new URLSearchParams(location.search);
const list = (name: string, fallback: string): number[] =>
  (query.get(name) ?? fallback)
    .split(",")
    .filter((value) => value !== "")
    .map(Number);
const SIZES = list("sizes", "1600,16000,160000,1600000");
const REPEATS = Number(query.get("repeats") ?? 3);
const SLICES = list("slices", "1,2,4");
const GRID_SIZES = list("gridSizes", "16000,160000,1600000");
const CADENCE_MS = Number(query.get("cadence") ?? 250);
const LANES = Number(query.get("lanes") ?? 2);
const FRAMES = Number(query.get("frames") ?? 5);
const EDGES = Number(query.get("edges") ?? 3);
const CELLS = Math.min(FRAMES, Number(query.get("cells") ?? FRAMES));
// Idle grid time before the first job, and between one job's result and the
// next job.
const LEAD_MS = Number(query.get("lead") ?? 3_000);
const PAUSE_MS = Number(query.get("pause") ?? 2_000);
const SPACING_MS = CADENCE_MS / (LANES * FRAMES);
const MAX_TIMER_DRIFT_MS = Math.max(
  0,
  Math.min(Math.floor(SPACING_MS) - 1, 500),
);

const progress = (text: string): void => {
  (window as unknown as Record<string, unknown>).__proofLevelsProgress = text;
};
const perfEpoch = (): number => performance.timeOrigin + performance.now();
const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));
const random = (length: number): Uint8Array => {
  const bytes = new Uint8Array(length);
  // getRandomValues fills at most 65,536 bytes a call.
  for (let offset = 0; offset < length; offset += 65_536)
    crypto.getRandomValues(bytes.subarray(offset, offset + 65_536));
  return bytes;
};

const loadModule = async (): Promise<LibCrypto> => {
  const wasmBinary = await (await fetch("/libcrypto.wasm")).arrayBuffer();
  return (await (
    libcrypto as unknown as (options: unknown) => Promise<unknown>
  )({
    wasmBinary,
    wasmMemory: new WebAssembly.Memory({ initial: 32, maximum: 32 }),
    getRandomValue: () => crypto.getRandomValues(new Uint32Array(1))[0] >>> 0,
  })) as LibCrypto;
};

// The build under test. Before the change it returns the levels; after it, a
// promise of them, and it takes the slice budget. Awaiting covers both.
type AnyBuild = (
  leaves: Uint8Array,
  module: LibCrypto,
  options?: { readonly sliceMs?: number },
) => MerkleProofLevels | Promise<MerkleProofLevels>;
const build = buildMerkleProofLevels as unknown as AnyBuild;

interface Held {
  readonly totalMs: number;
  /** The longest gap between two probe runs inside the build. */
  readonly longestHoldMs: number;
  /** How many times the probe ran inside the build. */
  readonly probeRuns: number;
}

/** Run `work` while a MessageChannel probe records when the page was free. */
const probed = async <T>(
  work: () => T | Promise<T>,
): Promise<{ value: T; held: Held }> => {
  const channel = new MessageChannel();
  const stamps: number[] = [];
  let running = true;
  channel.port1.onmessage = () => {
    stamps.push(performance.now());
    if (running) channel.port2.postMessage(0);
  };
  channel.port2.postMessage(0);
  await sleep(20);
  const started = performance.now();
  const value = await work();
  const ended = performance.now();
  running = false;
  channel.port1.close();
  channel.port2.close();
  const inside = [
    started,
    ...stamps.filter((at) => at > started && at < ended),
    ended,
  ];
  let longestHoldMs = 0;
  for (let i = 1; i < inside.length; i++)
    longestHoldMs = Math.max(longestHoldMs, inside[i] - inside[i - 1]);
  return {
    value,
    held: {
      totalMs: ended - started,
      longestHoldMs,
      probeRuns: inside.length - 2,
    },
  };
};

interface AloneRecord {
  readonly leaves: number;
  /** The budget asked for; null for a synchronous build, which takes none. */
  readonly sliceMs: number | null;
  readonly totalMs: number;
  readonly longestHoldMs: number;
  readonly probeRuns: number;
  /** What the levels hold above the leaves, as MerkleProofLevels reports it. */
  readonly levelBytes: number;
  readonly leafBytes: number;
}

const measureAlone = async (module: LibCrypto): Promise<AloneRecord[]> => {
  const records: AloneRecord[] = [];
  // A first build warms the code path, as a page that has sent before has.
  (await build(random(1_600 * 64), module)).release();
  for (const leaves of SIZES) {
    const tree = random(leaves * 64);
    for (const sliceMs of SLICES)
      for (let repeat = 0; repeat < REPEATS; repeat++) {
        progress(
          `alone: ${String(leaves)} leaves, slice ${String(sliceMs)} ms, ${String(repeat + 1)} of ${String(REPEATS)}`,
        );
        let synchronous = false;
        const { value: levels, held } = await probed(() => {
          const built = build(tree, module, { sliceMs });
          synchronous = !(built instanceof Promise);
          return built;
        });
        records.push({
          leaves,
          sliceMs: synchronous ? null : sliceMs,
          ...held,
          levelBytes: levels.byteLength,
          leafBytes: tree.byteLength,
        });
        levels.release();
        await sleep(50);
      }
  }
  return records;
};

interface StagedMessage {
  readonly leaves: number;
  readonly message: OutboundMessage;
  readonly label: string;
}

const stageMessage = async (
  module: LibCrypto,
  leaves: number,
  index: number,
): Promise<StagedMessage> => {
  const transferId = uint8ArrayToHex(random(32));
  const hash = random(64);
  const hashHex = uint8ArrayToHex(hash);
  const realBytes = Math.ceil(CHUNK_LEN * 0.9);
  const date = new Date();
  // Only the cells the job sends are staged; the other leaves are random, as
  // nothing reads them but the proof-level build.
  const chunkHashes = random(leaves * 64);
  for (let chunkIndex = 0; chunkIndex < CELLS; chunkIndex++) {
    const data = random(CHUNK_LEN);
    const leaf = await hashMerkleLeaf(data);
    chunkHashes.set(leaf, chunkIndex * 64);
    await setDBNewChunk({
      transferId,
      hash: hashHex,
      merkleRoot: "",
      chunkIndex,
      leafHash: uint8ArrayToHex(leaf),
      receiptToken: "",
      data: data.buffer as ArrayBuffer,
      metadata: serializeMetadata({
        schemaVersion: 1,
        messageType: MessageType.Text,
        hash,
        totalSize: leaves * realBytes,
        date,
        name: "proof-levels",
        chunkStartIndex: 0,
        chunkEndIndex: realBytes,
        chunkIndex,
      }).buffer as ArrayBuffer,
      merkleProof: new ArrayBuffer(0),
    });
  }
  // The root over every leaf. Computed now, before the grid starts.
  const levels = await build(chunkHashes, module);
  const merkleRoot = levels.root();
  levels.release();
  return {
    leaves,
    message: new OutboundMessage({
      transferId,
      hashHex,
      merkleRoot,
      totalChunks: leaves,
      chunkHashes,
      merkleModule: module,
    }),
    label: await compileChannelMessageLabel(
      `proof-levels-${String(index)}`,
      uint8ArrayToHex(merkleRoot),
    ),
  };
};

interface EdgeRecording {
  /** [slot deadline, wake-up ran, send called, lane label, first byte]. */
  readonly cells: Array<[number, number, number, string, number]>;
  /** [due, ran, kind] of every scheduler wake-up. */
  readonly wakeUps: Array<[number, number, CoverTimerKind | ""]>;
  /** [at, status, reason]. */
  readonly statuses: Array<[number, string, string]>;
}

interface JobRecording {
  readonly leaves: number;
  readonly label: string;
  enqueuedAt: number;
  settledAt: number;
  outcome: string;
  /** [chunk index, production start, production end, produced a cell]. */
  readonly productions: Array<[number, number, number, boolean]>;
}

// Everything the SDK reports while the run goes, kept with the recording.
const consoleLines: Array<[number, string, string]> = [];
for (const level of ["warn", "error"] as const) {
  const original = console[level].bind(console);
  console[level] = (...args: unknown[]) => {
    consoleLines.push([Date.now(), level, args.map(String).join(" ")]);
    original(...args);
  };
}
addEventListener("error", (event: ErrorEvent) =>
  consoleLines.push([Date.now(), "uncaught", String(event.message)]),
);
addEventListener("unhandledrejection", (event: PromiseRejectionEvent) =>
  consoleLines.push([Date.now(), "unhandled", String(event.reason)]),
);

const runGrid = async (module: LibCrypto) => {
  const staged: StagedMessage[] = [];
  for (const [index, leaves] of GRID_SIZES.entries()) {
    progress(`grid: staging a message of ${String(leaves)} leaves`);
    staged.push(await stageMessage(module, leaves, index));
  }

  const roomId = "00000000-0000-4000-8000-0000000000a1";
  const edges: EdgeRecording[] = [];
  const runtimes: CoverRuntime[] = [];
  const pqs: SparsePqHealingState[] = [];
  const jobs: JobRecording[] = [];
  let settleCurrent: ((outcome: string) => void) | undefined;

  for (let edge = 0; edge < EDGES; edge++) {
    const recording: EdgeRecording = { cells: [], wakeUps: [], statuses: [] };
    edges.push(recording);
    const pq = new SparsePqHealingState({
      module,
      pqMode: "hybrid-mlkem512",
      rootSuite: RATCHET_ROOT_SUITE_MLKEM512,
      binding: random(32),
      rootKey: random(32),
      nextOfferer: "local",
      amInitiator: true,
      now: Date.now(),
    });
    pqs.push(pq);
    const epc = {
      roomId,
      withPeerId: `00000000-0000-4000-8000-0000000000${String(edge).padStart(2, "0")}`,
      pqHealingState: pq,
    } as unknown as IRTCPeerConnection;
    // The page's shared timer-worker clock, instrumented: the wake-up that
    // ran last for this edge is the one its next send belongs to.
    const timerClock = createCoverTimerClock(browserCoverTimerEnvironment());
    let lastWake = 0;
    let lastSlotDue = 0;
    const clock: CoverClock = {
      now: () => timerClock.now(),
      setTimeout: (callback, delayMs, kind) => {
        const due = timerClock.now() + delayMs;
        return timerClock.setTimeout(
          () => {
            lastWake = perfEpoch();
            recording.wakeUps.push([due, lastWake, kind ?? ""]);
            if (kind === "slot") lastSlotDue = due;
            callback();
          },
          delayMs,
          kind,
        );
      },
      clearTimeout: (handle) => timerClock.clearTimeout(handle),
    };
    const runtime = new CoverRuntime({
      epc,
      roomId,
      module,
      amInitiator: true,
      schedule: {
        coverCadenceMs: CADENCE_MS,
        coverLanes: LANES,
        coverFramesPerCell: FRAMES,
        coverDurationEpochs: 1,
      },
      policyHash: new Uint8Array(32),
      laneLabelName: "party",
      openLaneChannel: (label): CoverLaneChannel => {
        let readyState = "open";
        return {
          label,
          get readyState() {
            return readyState;
          },
          bufferedAmount: 0,
          send: (data: ArrayBuffer) => {
            recording.cells.push([
              lastSlotDue,
              lastWake,
              perfEpoch(),
              label,
              new Uint8Array(data)[0],
            ]);
          },
          close: () => {
            readyState = "closed";
          },
        };
      },
      onStatusChange: ({ status, reason }) =>
        recording.statuses.push([Date.now(), status, reason ?? ""]),
      onJobResult: ({ outcome, reason }) =>
        settleCurrent?.(`${outcome}${reason ? ` ${reason}` : ""}`),
      clock,
    });
    (epc as unknown as { coverRuntime: CoverRuntime }).coverRuntime = runtime;
    runtimes.push(runtime);
  }

  const visibility: Array<[number, DocumentVisibilityState]> = [
    [Date.now(), document.visibilityState],
  ];
  document.addEventListener("visibilitychange", () =>
    visibility.push([Date.now(), document.visibilityState]),
  );
  const startedAt = Date.now();
  for (const runtime of runtimes) runtime.start();
  progress("grid: idle lead");
  await sleep(LEAD_MS);

  for (const message of staged) {
    progress(`grid: a job of ${String(message.leaves)} leaves`);
    const context = pqs[0].currentMessageContext();
    const chunkSealer = createMessageChunkSealer(
      random(32),
      { dhPub: random(32), N: 0, PN: 0 },
      {
        ...context,
        rootKey: Uint8Array.from(context.rootKey),
        binding: Uint8Array.from(context.binding),
      },
      module,
    );
    const sealSlotCell = makeScheduledSlotSealer(
      message.message,
      chunkSealer,
      () => false,
    );
    const recording: JobRecording = {
      leaves: message.leaves,
      label: message.label,
      enqueuedAt: 0,
      settledAt: 0,
      outcome: "",
      productions: [],
    };
    jobs.push(recording);
    const settled = new Promise<string>((resolve) => {
      settleCurrent = resolve;
    });
    recording.enqueuedAt = perfEpoch();
    runtimes[0].enqueue(
      buildScheduledSendJob({
        runtime: runtimes[0],
        channelMessageLabel: message.label,
        totalChunks: CELLS,
        merkleRoot: message.message.merkleRoot,
        sealSlotCell: async (chunkIndex) => {
          const start = perfEpoch();
          const cell = await sealSlotCell(chunkIndex);
          recording.productions.push([
            chunkIndex,
            start,
            perfEpoch(),
            cell !== null,
          ]);
          return cell;
        },
        isChunkAcked: () => false,
        realChunkIndices: Array.from({ length: CELLS }, (_, index) => index),
      }),
    );
    recording.outcome = await settled;
    recording.settledAt = perfEpoch();
    settleCurrent = undefined;
    chunkSealer.wipe();
    message.message.close();
    await sleep(PAUSE_MS);
  }

  for (const runtime of runtimes) runtime.destroy();
  for (const pq of pqs) pq.destroy();
  return {
    startedAt,
    endedAt: Date.now(),
    visibility,
    schedule: {
      phaseOffsetMs: 0,
      coverCadenceMs: CADENCE_MS,
      coverLanes: LANES,
      coverFramesPerCell: FRAMES,
      coverDurationEpochs: 1,
    },
    maxTimerDriftMs: MAX_TIMER_DRIFT_MS,
    edges,
    jobs,
  };
};

const run = async (): Promise<void> => {
  progress("loading the WASM");
  const module = await loadModule();
  const startedAt = Date.now();
  const alone = await measureAlone(module);
  const grid = await runGrid(module);
  (window as unknown as Record<string, unknown>).__proofLevels = {
    mode: "proof-levels",
    userAgent: navigator.userAgent,
    startedAt,
    query: Object.fromEntries(query.entries()),
    clockOffsetMs: perfEpoch() - Date.now(),
    alone,
    grid,
    console: consoleLines,
    done: true,
  };
};

run().catch((error: unknown) => {
  (window as unknown as Record<string, unknown>).__proofLevelsError = String(
    error instanceof Error ? error.stack : error,
  );
});
