// Summary of an entry-proof-levels.ts recording (driver.mjs
// --mode=proof-levels). Also runs on a saved raw recording:
//   node docs/e2e/cover-timers/summarise-proof-levels.mjs <raw.json> <summary.json>
// (it then keeps the summary's other fields and replaces its results).
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const FRAME_TYPE_CHUNK = 2;
const FRAME_TYPE_COVER = 4;

const round = (value) =>
  value === null || value === undefined ? null : Number(value.toFixed(2));

const distribution = (values) => {
  if (values.length === 0) return { n: 0 };
  const sorted = [...values].sort((a, b) => a - b);
  const at = (p) =>
    sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
  return {
    n: sorted.length,
    min: round(sorted[0]),
    p50: round(at(50)),
    p90: round(at(90)),
    p99: round(at(99)),
    max: round(sorted[sorted.length - 1]),
  };
};

const mean = (values) =>
  values.length === 0
    ? null
    : values.reduce((sum, value) => sum + value, 0) / values.length;

/**
 * Two-sample Kolmogorov–Smirnov distance, and its 5 % critical value. It
 * assumes independent samples; slots of one instant share its lateness, so
 * it overstates significance here.
 */
const ks = (a, b) => {
  const left = [...a].sort((x, y) => x - y);
  const right = [...b].sort((x, y) => x - y);
  let i = 0;
  let j = 0;
  let distance = 0;
  while (i < left.length && j < right.length) {
    const at = Math.min(left[i], right[j]);
    while (i < left.length && left[i] <= at) i++;
    while (j < right.length && right[j] <= at) j++;
    distance = Math.max(distance, Math.abs(i / left.length - j / right.length));
  }
  return {
    distance: Number(distance.toFixed(3)),
    critical5: Number(
      (
        1.358 *
        Math.sqrt((left.length + right.length) / (left.length * right.length))
      ).toFixed(3),
    ),
  };
};

const summariseAlone = (records) => {
  const groups = new Map();
  for (const record of records) {
    const key = `${String(record.leaves)} ${String(record.sliceMs)}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(record);
  }
  return [...groups.values()].map((group) => {
    const [first] = group;
    return {
      leaves: first.leaves,
      sliceMs: first.sliceMs,
      builds: group.length,
      totalMs: distribution(group.map((record) => record.totalMs)),
      longestHoldMs: distribution(group.map((record) => record.longestHoldMs)),
      probeRuns: distribution(group.map((record) => record.probeRuns)),
      levelBytes: first.levelBytes,
      leafBytes: first.leafBytes,
      levelBytesPerLeaf: round(first.levelBytes / first.leaves),
    };
  });
};

/**
 * Per job: its first production (the one that builds the proof levels) is the
 * build window. The slots of every edge that fell due inside it are compared
 * with the slots due outside every job's window.
 */
const summariseGrid = (grid, clockOffsetMs) => {
  const cycleMs = grid.schedule.coverCadenceMs;
  const perCycle = grid.schedule.coverLanes * grid.schedule.coverFramesPerCell;
  // Slot deadlines are page Date.now(); the rest is performance time.
  const toPerf = (deadline) => deadline + clockOffsetMs;
  const settleFrom = grid.startedAt + 2_000;
  const windows = grid.jobs.map((job) => {
    const first = job.productions[0];
    return first ? [first[1], first[2]] : [job.enqueuedAt, job.enqueuedAt];
  });
  const windowOf = (at) =>
    windows.findIndex(([from, to]) => at >= from && at < to);
  const outsideLateness = [];
  // Every slot wake-up after the first two seconds: [edge, due (ms from the
  // grid's start), lateness (ms), the job whose build it fell in, or ""].
  const slotRows = [];
  grid.edges.forEach((edge, edgeIndex) => {
    for (const [due, ran, kind] of edge.wakeUps) {
      if (kind !== "slot" || due < settleFrom || due >= grid.endedAt) continue;
      const lateness = ran - toPerf(due);
      const job = windowOf(toPerf(due));
      slotRows.push([
        edgeIndex,
        due - grid.startedAt,
        round(lateness),
        job < 0 ? "" : grid.jobs[job].leaves,
      ]);
      if (job < 0) outsideLateness.push(lateness);
    }
  });

  const jobs = grid.jobs.map((job, index) => {
    const [from, to] = windows[index];
    const lateness = [];
    let late = 0;
    for (const edge of grid.edges)
      for (const [due, ran, kind] of edge.wakeUps)
        if (kind === "slot" && toPerf(due) >= from && toPerf(due) < to) {
          lateness.push(ran - toPerf(due));
          if (ran - toPerf(due) > grid.maxTimerDriftMs) late += 1;
        }
    // The cycles the build overlapped, whole: what each edge should have sent
    // in them and what it sent.
    const firstCycle = Math.floor((from - clockOffsetMs) / cycleMs);
    const lastCycle = Math.floor((to - clockOffsetMs) / cycleMs);
    const cycles = lastCycle - firstCycle + 1;
    const cellsSent = grid.edges.map(
      (edge) =>
        edge.cells.filter(([deadline]) => {
          const cycle = Math.floor(deadline / cycleMs);
          return cycle >= firstCycle && cycle <= lastCycle;
        }).length,
    );
    const degrades = grid.edges.flatMap((edge, edgeIndex) =>
      edge.statuses
        .filter(
          ([at, status]) =>
            status === "degraded" &&
            at >= from - clockOffsetMs &&
            at < to - clockOffsetMs + cycleMs,
        )
        .map(([, , reason]) => `edge ${String(edgeIndex)}: ${reason}`),
    );
    // The job's lane during the build: its slot's dummy in place of a chunk
    // not ready yet.
    const laneDuring = grid.edges[0].cells.filter(
      ([deadline, , , label]) =>
        label === job.label &&
        toPerf(deadline) >= from &&
        toPerf(deadline) < to,
    );
    const laneAll = grid.edges[0].cells.filter(
      ([, , , label]) => label === job.label,
    );
    return {
      leaves: job.leaves,
      outcome: job.outcome,
      buildWindowMs: round(to - from),
      productionsMs: job.productions.map(([, start, end]) =>
        round(end - start),
      ),
      slotsDueDuringBuild: lateness.length,
      slotsLateBeyondTolerance: late,
      slotLatenessDuringBuildMs: distribution(lateness),
      versusSlotsOutsideBuilds:
        lateness.length < 2
          ? null
          : {
              medianShiftMs: round(
                distribution(lateness).p50 - distribution(outsideLateness).p50,
              ),
              meanShiftMs: round(mean(lateness) - mean(outsideLateness)),
              ks: ks(lateness, outsideLateness),
            },
      overlappedCycles: cycles,
      cellsExpectedPerEdge: cycles * perCycle,
      cellsSentPerEdge: cellsSent,
      degradedWhileBuilding: degrades,
      jobLaneDuringBuild: {
        dummies: laneDuring.filter(
          ([, , , , first]) => first === FRAME_TYPE_COVER,
        ).length,
        chunks: laneDuring.filter(
          ([, , , , first]) => first === FRAME_TYPE_CHUNK,
        ).length,
      },
      jobLaneChunksSent: laneAll.filter(
        ([, , , , first]) => first === FRAME_TYPE_CHUNK,
      ).length,
    };
  });

  const statuses = grid.edges.map((edge) =>
    edge.statuses.map(([at, status, reason]) => [
      at - grid.startedAt,
      status,
      reason,
    ]),
  );
  return {
    schedule: grid.schedule,
    maxTimerDriftMs: grid.maxTimerDriftMs,
    edges: grid.edges.length,
    visibility: grid.visibility.map(([at, state]) => [
      at - grid.startedAt,
      state,
    ]),
    slotLatenessOutsideBuildsMs: distribution(outsideLateness),
    jobs,
    statusesByEdge: statuses,
    slotRows,
  };
};

export const summariseProofLevels = (data) => ({
  alone: summariseAlone(data.alone),
  grid: summariseGrid(data.grid, data.clockOffsetMs),
  console: data.console,
});

/**
 * Write a proof-level summary and, beside it (`.slots.tsv`), every slot
 * wake-up of its grid phase, one per line, taken out of the JSON.
 */
export const writeProofLevelSummary = (summaryPath, summary) => {
  const lines = [
    "# edge\tslot due (ms from the grid's start, page Date.now())\twake-up lateness (ms; performance.timeOrigin + now() minus the due time)\tleaves of the message whose proof-level build it fell in (empty: none)",
    ...summary.results.grid.slotRows.map((row) => row.join("\t")),
  ];
  delete summary.results.grid.slotRows;
  const tsvPath = summaryPath.replace(/\.json$/, "") + ".slots.tsv";
  summary.slotsFile = tsvPath.split("/").pop();
  writeFileSync(tsvPath, `${lines.join("\n")}\n`);
  writeFileSync(summaryPath, `${JSON.stringify(summary, null, 2)}\n`);
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [rawPath, summaryPath] = process.argv.slice(2);
  const data = JSON.parse(readFileSync(rawPath, "utf8"));
  const summary = JSON.parse(readFileSync(summaryPath, "utf8"));
  summary.results = summariseProofLevels(data);
  // Rewritten from the raw recording by this file, named by its hash.
  summary.resummarisedBy = createHash("sha256")
    .update(readFileSync(fileURLToPath(import.meta.url)))
    .digest("hex");
  writeProofLevelSummary(summaryPath, summary);
}
