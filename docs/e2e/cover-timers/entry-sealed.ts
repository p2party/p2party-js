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
// `phases` gives each edge its room's phase offset in ms (default all 0): an
// edge with another phase is another room's grid on the same page, its slots
// a few ms off the first grid's. `leaves` makes each message that many cells
// (default one lane's F x D): the job still sends F x D of them, but the
// message's Merkle proof levels, built once on its first send, cover all of
// them, as a large file's do. `cells` makes a job send fewer than its lane's
// slots; `gap` leaves that many cycles between one job and the next, so the
// same slots carry a job in some cycles and dummies in others: jobs go in
// every (gap + 1)-th cycle of the grid, on every busy edge alike, enqueued by
// a page timer that fires in the middle of every cycle, job cycle or not.
// Every cell a job's producer made is fingerprinted (its AEAD tag), so each
// sent cell is recorded with what made it.
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
import {
  buildMerkleProofLevels,
  getMerkleRoot,
} from "../../../src/cryptography/merkle";
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
// Cells a job sends: by default a lane's F x D slots (one epoch per cycle);
// fewer leaves the rest of its lane's slots to dummies.
const CELLS_PER_JOB = Math.min(FRAMES, Number(query.get("cells") ?? FRAMES));
const LEAVES = Math.max(CELLS_PER_JOB, Number(query.get("leaves") ?? 0));
// Cycles an edge waits after a job before its next one, so the same slots of
// its lane carry a job in some cycles and dummies in others.
const GAP_CYCLES = Number(query.get("gap") ?? 0);
const PHASES = Array.from(
  { length: EDGES },
  (_, edge) => Number((query.get("phases") ?? "").split(",")[edge] ?? 0) || 0,
);
const SPACING_MS = CADENCE_MS / (LANES * FRAMES);
const MAX_TIMER_DRIFT_MS = Math.max(
  0,
  Math.min(Math.floor(SPACING_MS) - 1, 500),
);

const perfEpoch = (): number => performance.timeOrigin + performance.now();
const random = (length: number): Uint8Array => {
  const bytes = new Uint8Array(length);
  // getRandomValues fills at most 65,536 bytes a call.
  for (let offset = 0; offset < length; offset += 65_536)
    crypto.getRandomValues(bytes.subarray(offset, offset + 65_536));
  return bytes;
};

// Each slot's offset from its cycle's start, as the scheduler places it.
const SLOT_OFFSETS = Array.from({ length: LANES * FRAMES }, (_, within) =>
  Math.floor(((2 * within + 1) * CADENCE_MS) / (2 * LANES * FRAMES)),
);

/** The slot deadline of this grid nearest to `at`. */
const snapToSlot = (at: number, phase: number): number => {
  const cycleStart =
    at - ((((at - phase) % CADENCE_MS) + CADENCE_MS) % CADENCE_MS);
  let best = cycleStart + SLOT_OFFSETS[0];
  for (const start of [
    cycleStart - CADENCE_MS,
    cycleStart,
    cycleStart + CADENCE_MS,
  ])
    for (const offset of SLOT_OFFSETS)
      if (Math.abs(start + offset - at) < Math.abs(best - at))
        best = start + offset;
  return best;
};

/** A sealed cell's last 16 bytes (its AEAD tag): what identifies it. */
const fingerprint = (cell: Uint8Array): string =>
  uint8ArrayToHex(cell.subarray(cell.length - 16));
// Every cell a job's producer made, by fingerprint: a sent cell that is not
// here is a dummy (the lane's dummy tail, or the slot's dummy in place of a
// job cell that was not ready).
const producedBy = new Map<string, Kind>();
const noteProduced = (cell: Uint8Array, kind: Kind): Uint8Array => {
  producedBy.set(fingerprint(cell), kind);
  return cell;
};

/** A policy hash whose derived phase offset is `phaseMs` (CoverRuntime). */
const phaseHash = (phaseMs: number): Uint8Array => {
  const hash = new Uint8Array(32);
  new DataView(hash.buffer).setBigUint64(0, BigInt(phaseMs), false);
  return hash;
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
  const totalSize = LEAVES * realBytes;
  const date = new Date();
  // Only the cells a job sends are staged; the others' leaves are random, as
  // nothing reads them but the proof-level build.
  const chunkHashes = random(LEAVES * 64);
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
      totalChunks: LEAVES,
      chunkHashes,
      merkleModule: module,
    }),
    rootHex: uint8ArrayToHex(merkleRoot),
  };
};

interface EdgeRecording {
  /**
   * [slot deadline, wake-up ran, channel.send called, lane label, the cell's
   * first byte (its frame type: 2 a chunk, 4 a cover cell), what it was: the
   * job kind whose producer made it, or "dummy"].
   */
  readonly cells: Array<[number, number, number, string, number, string]>;
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
addEventListener("error", (event: ErrorEvent) =>
  consoleLines.push([Date.now(), "uncaught", String(event.message)]),
);
addEventListener("unhandledrejection", (event: PromiseRejectionEvent) =>
  consoleLines.push([Date.now(), "unhandled", String(event.reason)]),
);

/** performance.timeOrigin + now() minus Date.now(), sampled: the two clocks. */
const clockOffsetSamples = (): number[] => {
  const samples: number[] = [];
  for (let i = 0; i < 200; i++) samples.push(perfEpoch() - Date.now());
  return samples.sort((a, b) => a - b);
};
const summariseOffset = (samples: number[]) => ({
  min: samples[0],
  median: samples[Math.floor(samples.length / 2)],
  max: samples[samples.length - 1],
});

const run = async (): Promise<void> => {
  (window as unknown as Record<string, unknown>).__coverTimersProgress =
    "loading the WASM";
  const module = await loadModule();
  // The proof-level build a message of LEAVES cells pays once (in slices
  // since 2026-11-27: this is the whole build, start to end).
  const proofLevelBuildMs: number[] = [];
  for (let i = 0; i < 10; i++) {
    const leaves = random(LEAVES * 64);
    const started = performance.now();
    (await buildMerkleProofLevels(leaves, module)).release();
    proofLevelBuildMs.push(performance.now() - started);
  }
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
        send: (data: ArrayBuffer) => {
          const sentAt = perfEpoch();
          const bytes = new Uint8Array(data);
          recording.cells.push([
            pendingDeadline,
            lastWake,
            sentAt,
            label,
            bytes[0],
            producedBy.get(fingerprint(bytes)) ?? "dummy",
          ]);
        },
        close: () => {
          readyState = "closed";
        },
      };
    };
    // The slot deadline of the send in progress: the scheduler arms one
    // wake-up at a time, so it is the due time of the last slot wake-up.
    let pendingDeadline = 0;
    // The due time a wake-up was armed for can be a millisecond off its slot
    // (two reads of Date.now() straddling a tick): snap it to this edge's grid.
    const slotDue = (): number => {
      for (let i = recording.wakeUps.length - 1; i >= 0; i--)
        if (recording.wakeUps[i][2] === "slot")
          return snapToSlot(recording.wakeUps[i][0], PHASES[edge] % CADENCE_MS);
      return 0;
    };

    const rotation: Kind[] = ["store-write", "control", "store-read"];
    let turn = edge % rotation.length;
    let lastWritten: StagedMessage | undefined;
    let jobSequence = 0;
    let currentJob = "";
    let waiting: CoverJob | undefined;

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
          return noteProduced(cell, kind);
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
            noteProduced(
              runtime.sealCoverContent({
                subtype: "chunk-receipts",
                merkleRoot: random(64),
                tokens: [random(64)],
              }),
              "control",
            ),
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
          realChunkIndices: Array.from(
            { length: CELLS_PER_JOB },
            (_, index) => index,
          ),
        });
      }
      recording.labels[job.id] = kind;
      if (GAP_CYCLES > 0) {
        // Admitted by the next cycle tick before a job cycle.
        waiting = job;
        return;
      }
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
      policyHash: phaseHash(PHASES[edge]),
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
    // With gaps, jobs go in every (GAP_CYCLES + 1)-th cycle of the grid, the
    // same cycles on every busy edge. A page timer in the middle of every
    // cycle, job cycle or not, enqueues the waiting job before a job cycle;
    // the job itself was built when the one before it settled.
    if (GAP_CYCLES > 0 && edge < EDGES - IDLE) {
      const phase = PHASES[edge] % CADENCE_MS;
      const tick = (): void => {
        const now = Date.now();
        const cycle = Math.floor((now - phase) / CADENCE_MS);
        if (waiting && (cycle + 1) % (GAP_CYCLES + 1) === 0) {
          currentJob = waiting.id;
          runtime.enqueue(waiting);
          waiting = undefined;
        }
        const next = phase + (cycle + 1) * CADENCE_MS + CADENCE_MS / 2;
        setTimeout(tick, next - now);
      };
      const now = Date.now();
      const cycle = Math.floor((now - phase) / CADENCE_MS);
      setTimeout(tick, phase + cycle * CADENCE_MS + CADENCE_MS * 1.5 - now);
    }
  }

  const visibility: Array<[number, DocumentVisibilityState]> = [
    [Date.now(), document.visibilityState],
  ];
  document.addEventListener("visibilitychange", () =>
    visibility.push([Date.now(), document.visibilityState]),
  );
  const clockOffsetStart = summariseOffset(clockOffsetSamples());
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
    edgePhasesMs: PHASES.map((phase) => phase % CADENCE_MS),
    leavesPerMessage: LEAVES,
    cellsPerJob: CELLS_PER_JOB,
    gapCycles: GAP_CYCLES,
    proofLevelBuildMs,
    clockOffsetMs: { start: clockOffsetStart } as Record<string, unknown>,
    // The driver calls this before it reads the recording.
    sampleClockOffset: function (this: {
      clockOffsetMs: Record<string, unknown>;
    }) {
      this.clockOffsetMs.end = summariseOffset(clockOffsetSamples());
    },
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
