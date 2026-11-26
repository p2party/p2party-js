// Browser entry for the cover-timer measurement (see driver.mjs and
// docs/e2e/README.md). It runs two real CoverSchedulers side by side on one
// page with the same schedule: one woken by page timers (the clock scheduled
// cover used before the timer worker), one by the timer-worker clock
// (createCoverTimerClock, what CoverRuntime now builds in a browser). Lanes are
// recorders, cells a constant buffer: what is measured is when wake-ups land
// and which cells the schedule actually sends, not cell sealing.
import { createCoverScheduler } from "../../../src/handlers/coverScheduler";
import {
  browserCoverTimerEnvironment,
  createCoverTimerClock,
} from "../../../src/handlers/coverTimerWorker";
import { WIRE_CHUNK_FRAME_LEN } from "../../../src/utils/constants";

import type {
  CoverClock,
  CoverSchedule,
  CoverSchedulerStatus,
} from "../../../src/handlers/coverScheduler";

// By default one cycle a second, 2 lanes x 5 frames: a slot every 100 ms.
// `?cadence=<ms>` widens the cycle (and so the slot spacing). The drift
// tolerance is what CoverRuntime derives for the spacing: one ms under a slot,
// at most 500 ms.
const query = new URLSearchParams(location.search);
const SCHEDULE: CoverSchedule = {
  phaseOffsetMs: 0,
  coverCadenceMs: Number(query.get("cadence") ?? 1_000),
  coverLanes: 2,
  coverFramesPerCell: 5,
  coverDurationEpochs: 1,
};
const MAX_TIMER_DRIFT_MS = Math.max(
  0,
  Math.min(
    Math.floor(
      SCHEDULE.coverCadenceMs /
        (SCHEDULE.coverLanes * SCHEDULE.coverFramesPerCell),
    ) - 1,
    500,
  ),
);
const CELL = new Uint8Array(WIRE_CHUNK_FRAME_LEN);

interface Recording {
  /** [due, firedAt] of every wake-up, page Date.now() for both. */
  readonly wakeUps: Array<[number, number]>;
  /** [slot deadline, sentAt] of every cell the schedule sent. */
  readonly cells: Array<[number, number]>;
  /** [at, status] of every status change. */
  readonly statuses: Array<[number, CoverSchedulerStatus]>;
  source?: string;
}

const instrument = (clock: CoverClock, recording: Recording): CoverClock => ({
  now: () => clock.now(),
  setTimeout: (callback, delayMs) => {
    const due = clock.now() + delayMs;
    return clock.setTimeout(() => {
      recording.wakeUps.push([due, clock.now()]);
      callback();
    }, delayMs);
  },
  clearTimeout: (handle) => clock.clearTimeout(handle),
});

const pageClock: CoverClock = {
  now: () => Date.now(),
  setTimeout: (callback, delayMs) => setTimeout(callback, delayMs),
  clearTimeout: (handle) =>
    clearTimeout(handle as Parameters<typeof clearTimeout>[0]),
};

const run = (name: string, clock: CoverClock): Recording => {
  const recording: Recording = { wakeUps: [], cells: [], statuses: [] };
  const scheduler = createCoverScheduler({
    schedule: SCHEDULE,
    maxTimerDriftMs: MAX_TIMER_DRIFT_MS,
    clock: instrument(clock, recording),
    laneFactory: () => ({
      send: (request) => {
        recording.cells.push([request.slot.deadlineMs, Date.now()]);
        return true;
      },
      close: () => undefined,
    }),
    makeDummy: () => CELL,
    onStatusChange: ({ status }) =>
      recording.statuses.push([Date.now(), status]),
  });
  scheduler.start();
  (window as unknown as Record<string, unknown>)[`__${name}Scheduler`] =
    scheduler;
  return recording;
};

const workerClock = createCoverTimerClock(browserCoverTimerEnvironment());
const visibility: Array<[number, DocumentVisibilityState]> = [
  [Date.now(), document.visibilityState],
];
document.addEventListener("visibilitychange", () =>
  visibility.push([Date.now(), document.visibilityState]),
);

const page = run("page", pageClock);
const worker = run("worker", workerClock);
worker.source = workerClock.source;

(window as unknown as Record<string, unknown>).__coverTimers = {
  schedule: SCHEDULE,
  maxTimerDriftMs: MAX_TIMER_DRIFT_MS,
  userAgent: navigator.userAgent,
  startedAt: Date.now(),
  visibility,
  page,
  worker,
  workerSource: () => workerClock.source,
};
