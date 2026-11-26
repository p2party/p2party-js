// Browser entry for the cover-cell send-time measurement (driver.mjs
// --mode=sealed; see docs/e2e/README.md). Where entry.ts measures when the
// schedule's wake-ups land, this measures what happens between a slot's
// wake-up and `channel.send` for each kind of cell, with the real sealers.
//
// It runs `edges` real CoverRuntimes (the edges of one page: one room grid, so
// their slots coincide, and the page's one shared timer worker), each with a
// real PQ runtime and the real libcrypto WASM, and recorder channels in place
// of RTCDataChannels (no WebRTC). Each edge carries at most one job per cycle,
// in rotation (the last `idle` edges none); its other lanes stay dummy:
//
//  - "store-write": a freshly staged message (rows as splitToChunks stages
//    them: no proof, no receipt token). Each cell reads its row from the
//    outbox store through the real database worker, derives the receipt token
//    (crypto.subtle), writes the row back with token and proof, and seals: the
//    first pass of a scheduled send.
//  - "control": a control job whose cells are sealed in memory, as the
//    receipt drain job's are (sealCoverContent of a chunk-receipt batch).
//  - "store-read": the same message again, whose rows now carry token and
//    proof: one store read, then the seal (a re-send).
//
// The slot sealer below is a copy of handleSendMessage.ts's
// makeScheduledSlotSealer (read, cellPlaintext, seal), instrumented, without
// an outbox lease. Every record is page-side: performance.timeOrigin +
// performance.now() for sub-millisecond times, against the scheduler's slot
// deadlines (page Date.now()).
import libcrypto from "../../../src/cryptography/libcrypto";
import { CoverRuntime } from "../../../src/handlers/coverRuntime";
import { SparsePqHealingState } from "../../../src/handlers/pqHealingRuntime";
import {
  browserCoverTimerEnvironment,
  createCoverTimerClock,
} from "../../../src/handlers/coverTimerWorker";
import { buildScheduledSendJob } from "../../../src/handlers/coverTransfer";
import { OutboundMessage } from "../../../src/handlers/handleSendMessage";
import { createMessageChunkSealer } from "../../../src/handlers/messageChunkCrypto";
import { setDBNewChunk } from "../../../src/db/api";
import { serializeMetadata } from "../../../src/utils/metadata";
import { hashMerkleLeaf } from "../../../src/utils/leafHash";
import { getMerkleRoot } from "../../../src/cryptography/merkle";
import { compileChannelMessageLabel } from "../../../src/utils/channelLabel";
import { uint8ArrayToHex } from "../../../src/utils/uint8array";
import { MessageType } from "../../../src/utils/messageTypes";
import {
  CHUNK_LEN,
  RATCHET_ROOT_SUITE_MLKEM512,
} from "../../../src/utils/constants";

import type { LibCrypto } from "../../../src/cryptography/libcrypto";
import type { IRTCPeerConnection } from "../../../src/api/webrtc/interfaces";
import type {
  CoverClock,
  CoverJob,
  CoverTimerKind,
} from "../../../src/handlers/coverScheduler";
import type { CoverLaneChannel } from "../../../src/handlers/coverRuntime";

type Kind = "store-write" | "control" | "store-read";

const query = new URLSearchParams(location.search);
const CADENCE_MS = Number(query.get("cadence") ?? 1_000);
const LANES = Number(query.get("lanes") ?? 2);
const FRAMES = Number(query.get("frames") ?? 5);
const EDGES = Number(query.get("edges") ?? 3);
// The last IDLE edges carry no job: every cell they send is a dummy, beside
// the other edges' real and dummy cells in the same slots (the cross-edge
// effect).
const IDLE = Number(query.get("idle") ?? 1);
// Fresh messages staged per edge before the run: one is used per rotation.
const POOL = Number(query.get("pool") ?? 120);
const CELLS_PER_JOB = FRAMES; // one epoch per cycle: a lane's F x D slots
const SPACING_MS = CADENCE_MS / (LANES * FRAMES);
const MAX_TIMER_DRIFT_MS = Math.max(
  0,
  Math.min(Math.floor(SPACING_MS) - 1, 500),
);

const perfEpoch = (): number => performance.timeOrigin + performance.now();
const random = (length: number): Uint8Array => {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
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

interface StagedMessage {
  readonly message: OutboundMessage;
  readonly rootHex: string;
}

const stageMessage = async (module: LibCrypto): Promise<StagedMessage> => {
  const transferId = uint8ArrayToHex(random(32));
  const hash = random(64);
  const hashHex = uint8ArrayToHex(hash);
  const realBytes = Math.ceil(CHUNK_LEN * 0.9);
  const totalSize = CELLS_PER_JOB * realBytes;
  const date = new Date();
  const chunkHashes = new Uint8Array(CELLS_PER_JOB * 64);
  for (let index = 0; index < CELLS_PER_JOB; index++) {
    const data = random(CHUNK_LEN);
    const leaf = await hashMerkleLeaf(data);
    chunkHashes.set(leaf, index * 64);
    const metadata = serializeMetadata({
      schemaVersion: 1,
      messageType: MessageType.Text,
      hash,
      totalSize,
      date,
      name: "cover-send-time",
      chunkStartIndex: 0,
      chunkEndIndex: realBytes,
      chunkIndex: index,
    });
    await setDBNewChunk({
      transferId,
      hash: hashHex,
      merkleRoot: "",
      chunkIndex: index,
      leafHash: uint8ArrayToHex(leaf),
      receiptToken: "",
      data: data.buffer as ArrayBuffer,
      metadata: metadata.buffer as ArrayBuffer,
      merkleProof: new ArrayBuffer(0),
    });
  }
  const merkleRoot = await getMerkleRoot(chunkHashes, module);
  return {
    message: new OutboundMessage({
      transferId,
      hashHex,
      merkleRoot,
      totalChunks: CELLS_PER_JOB,
      chunkHashes,
      merkleModule: module,
    }),
    rootHex: uint8ArrayToHex(merkleRoot),
  };
};

interface EdgeRecording {
  /** [slot deadline, wake-up ran, channel.send called, lane label]. */
  readonly cells: Array<[number, number, number, string]>;
  /** [due, ran, kind] of every scheduler wake-up. */
  readonly wakeUps: Array<[number, number, CoverTimerKind | ""]>;
  /** [at, status, reason]. */
  readonly statuses: Array<[number, string, string]>;
  /** [kind, read start, read end, plaintext end, seal end] per real cell. */
  readonly productions: Array<[Kind, number, number, number, number]>;
  /** lane label -> the job kind it carried (absent: a dummy lane). */
  readonly labels: Record<string, Kind>;
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
addEventListener("error", (event) =>
  consoleLines.push([Date.now(), "uncaught", String(event.message)]),
);
addEventListener("unhandledrejection", (event) =>
  consoleLines.push([Date.now(), "unhandled", String(event.reason)]),
);

const run = async (): Promise<void> => {
  (window as unknown as Record<string, unknown>).__coverTimersProgress =
    "loading the WASM";
  const module = await loadModule();
  const roomId = "00000000-0000-4000-8000-0000000000a1";
  const edges: EdgeRecording[] = [];
  const runtimes: CoverRuntime[] = [];
  const pools: StagedMessage[][] = [];
  const timerClocks: Array<ReturnType<typeof createCoverTimerClock>> = [];
  for (let edge = 0; edge < EDGES; edge++) {
    const pool: StagedMessage[] = [];
    for (let index = 0; index < (edge < EDGES - IDLE ? POOL : 0); index++) {
      pool.push(await stageMessage(module));
      (window as unknown as Record<string, unknown>).__coverTimersProgress =
        `staged ${String(edge * POOL + index + 1)} of ${String((EDGES - IDLE) * POOL)} messages`;
    }
    pools.push(pool);
  }

  for (let edge = 0; edge < EDGES; edge++) {
    const recording: EdgeRecording = {
      cells: [],
      wakeUps: [],
      statuses: [],
      productions: [],
      labels: {},
    };
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
    const epc = {
      roomId,
      withPeerId: `00000000-0000-4000-8000-0000000000${String(edge).padStart(2, "0")}`,
      pqHealingState: pq,
    } as unknown as IRTCPeerConnection;

    // The page's shared timer-worker clock, instrumented: the wake-up that
    // ran last for this edge is the one its next send belongs to.
    const timerClock = createCoverTimerClock(browserCoverTimerEnvironment());
    timerClocks.push(timerClock);
    let lastWake = 0;
    const clock: CoverClock = {
      now: () => timerClock.now(),
      setTimeout: (callback, delayMs, kind) => {
        const due = timerClock.now() + delayMs;
        return timerClock.setTimeout(
          () => {
            lastWake = perfEpoch();
            recording.wakeUps.push([due, lastWake, kind ?? ""]);
            callback();
          },
          delayMs,
          kind,
        );
      },
      clearTimeout: (handle) => timerClock.clearTimeout(handle),
    };
    const openLaneChannel = (label: string): CoverLaneChannel => {
      let readyState = "open";
      return {
        label,
        get readyState() {
          return readyState;
        },
        bufferedAmount: 0,
        send: () => {
          const sentAt = perfEpoch();
          recording.cells.push([pendingDeadline, lastWake, sentAt, label]);
        },
        close: () => {
          readyState = "closed";
        },
      };
    };
    // The slot deadline of the send in progress: the scheduler arms one
    // wake-up at a time, so it is the due time of the last slot wake-up.
    let pendingDeadline = 0;
    const slotDue = (): number => {
      for (let i = recording.wakeUps.length - 1; i >= 0; i--)
        if (recording.wakeUps[i][2] === "slot") return recording.wakeUps[i][0];
      return 0;
    };

    const rotation: Kind[] = ["store-write", "control", "store-read"];
    let turn = edge % rotation.length;
    let lastWritten: StagedMessage | undefined;
    let jobSequence = 0;
    let currentJob = "";

    const makeSealer =
      (staged: StagedMessage, kind: Kind) =>
      async (chunkIndex: number): Promise<Uint8Array | null> => {
        const context = pq.currentMessageContext();
        const sealer = createMessageChunkSealer(
          random(32),
          { dhPub: random(32), N: 0, PN: 0 },
          {
            ...context,
            rootKey: Uint8Array.from(context.rootKey),
            binding: Uint8Array.from(context.binding),
          },
          module,
        );
        try {
          const readStart = perfEpoch();
          const row = await staged.message.read(chunkIndex);
          const readEnd = perfEpoch();
          if (!row) return null;
          const chunk = await staged.message.cellPlaintext(row);
          const plaintextEnd = perfEpoch();
          const cell = sealer.seal(chunk, staged.message.merkleRoot);
          recording.productions.push([
            kind,
            readStart,
            readEnd,
            plaintextEnd,
            perfEpoch(),
          ]);
          return cell;
        } finally {
          sealer.wipe();
        }
      };

    let runtime: CoverRuntime;
    const enqueueNext = async (): Promise<void> => {
      let kind = rotation[turn];
      turn = (turn + 1) % rotation.length;
      if (kind === "store-write" && pools[edge].length === 0)
        kind = "store-read";
      if (kind === "store-read" && !lastWritten) kind = "control";
      jobSequence += 1;
      let job: CoverJob;
      if (kind === "control") {
        const id = runtime.randomLaneLabel();
        job = {
          id,
          kind: "control",
          declaredCellCount: CELLS_PER_JOB,
          nextCell: () =>
            runtime.sealCoverContent({
              subtype: "chunk-receipts",
              merkleRoot: random(64),
              tokens: [random(64)],
            }),
        };
      } else {
        const staged =
          kind === "store-write" ? pools[edge].shift()! : lastWritten!;
        if (kind === "store-write") lastWritten = staged;
        const label = await compileChannelMessageLabel(
          `${kind}-${String(jobSequence)}`,
          staged.rootHex,
        );
        job = buildScheduledSendJob({
          runtime,
          channelMessageLabel: label,
          totalChunks: CELLS_PER_JOB,
          merkleRoot: staged.message.merkleRoot,
          sealSlotCell: makeSealer(staged, kind),
          isChunkAcked: () => false,
        });
      }
      recording.labels[job.id] = kind;
      currentJob = job.id;
      runtime.enqueue(job);
    };

    runtime = new CoverRuntime({
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
      openLaneChannel: (label) => {
        const channel = openLaneChannel(label);
        const send = channel.send.bind(channel);
        return {
          ...channel,
          get readyState() {
            return channel.readyState;
          },
          send: (data: ArrayBuffer) => {
            pendingDeadline = slotDue();
            send(data);
          },
        };
      },
      onStatusChange: ({ status, reason }) =>
        recording.statuses.push([Date.now(), status, reason ?? ""]),
      onJobResult: ({ jobId }) => {
        if (jobId === currentJob) void enqueueNext();
      },
      clock,
    });
    (epc as unknown as { coverRuntime: CoverRuntime }).coverRuntime = runtime;
    runtimes.push(runtime);
    if (edge < EDGES - IDLE) await enqueueNext();
  }

  const visibility: Array<[number, DocumentVisibilityState]> = [
    [Date.now(), document.visibilityState],
  ];
  document.addEventListener("visibilitychange", () =>
    visibility.push([Date.now(), document.visibilityState]),
  );
  for (const runtime of runtimes) runtime.start();
  (window as unknown as Record<string, unknown>).__coverTimers = {
    mode: "sealed",
    schedule: {
      phaseOffsetMs: 0,
      coverCadenceMs: CADENCE_MS,
      coverLanes: LANES,
      coverFramesPerCell: FRAMES,
      coverDurationEpochs: 1,
    },
    maxTimerDriftMs: MAX_TIMER_DRIFT_MS,
    edgesCount: EDGES,
    idleEdges: IDLE,
    poolPerEdge: POOL,
    userAgent: navigator.userAgent,
    startedAt: Date.now(),
    visibility,
    console: consoleLines,
    edges,
    // The runtimes run on these clocks, not on clocks of their own.
    workerSource: () => timerClocks[0].source,
  };
};

run().catch((error: unknown) => {
  (window as unknown as Record<string, unknown>).__coverTimersError = String(
    error instanceof Error ? error.stack : error,
  );
});
