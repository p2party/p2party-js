// Per-phase summary of an entry-sealed.ts recording (driver.mjs --mode=sealed).
// Also runnable on a saved raw recording:
//   node docs/e2e/cover-timers/summarise-sealed.mjs <raw.json> <summary.json>
// which keeps the summary's run metadata and recomputes its phases. Either way
// every cell of the visible and hidden phases is written beside the summary,
// one per line, in <summary>.offsets.tsv: phase, edge, kind, slot deadline,
// cycle, slot position, offset.
//
// For every cell sent in a phase (by slot deadline):
//   production = channel.send − the wake-up that ran last for the edge, ms;
//   offset     = channel.send − slot deadline, ms. This is what an observer of
//                the sender's packets sees against the slot grid, before the
//                (content-independent) path from channel.send to the wire.
// For each kind of real cell against the dummies of the same phase:
//   medianShiftMs   the difference of the offset medians;
//   ks              the two-sample Kolmogorov-Smirnov distance of the offsets
//                   (0: same distribution, 1: no overlap);
//   flaggedAtReferenceP99   the share of that kind's cells whose offset is
//                   above the dummies' 99th percentile: what an observer
//                   flagging "later than 99 % of dummies" catches, at a 1 %
//                   false-alarm rate on dummies.
// The 5 % critical KS distances assume independent cells; the cells of one
// instant share its lateness, so they overstate significance. Cycles are the
// unit of "cyclesWithAJobAgainstWithout": a permutation test over cycles that
// carried a job and cycles that did not (fixed seed, 10,000 permutations).
// "dummyBesideReal" are an idle edge's dummy cells whose slot a busy edge of
// the same grid filled with a real cell, against "dummyBesideDummy": the
// cross-edge effect. "crossGrid" compares an idle edge of another grid (another
// phase), by what the busy grid was producing at that moment. Kinds are
// compared on the busy grid only. "byEdge" gives each edge's degraded cycles
// by the scheduler's status reason. A store-backed job's lane that sent a dummy (the dummy in place
// of a cell not ready, or the lane's dummy tail) counts as "fallback-dummy" in
// older recordings and "lane-dummy" in newer ones, which name the producer of
// every cell; both are left out of the kind comparisons.
//
// "...AtSamePosition" compares offsets taken against the median of the busy
// grid's idle edge's dummies at the same slot position in the cycle: the first
// slot of a cycle is armed half a slot ahead and was measured to run earlier
// than the others, and real cells ride their lane's slots, so a pooled
// comparison partly compares positions.
//
// Offsets subtract the scheduler's slot deadline (page Date.now()) from
// performance.timeOrigin + now(): their absolute value includes the offset
// between those two clocks (recorded as clockOffsetMs); comparisons between
// kinds on one page do not.
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const round = (value) =>
  value === null || value === undefined ? null : Number(value.toFixed(3));

const percentile = (sorted, p) =>
  sorted.length === 0
    ? null
    : sorted[
        Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))
      ];

const stats = (values) => {
  const sorted = [...values].sort((a, b) => a - b);
  return {
    n: sorted.length,
    p50: round(percentile(sorted, 50)),
    p90: round(percentile(sorted, 90)),
    p99: round(percentile(sorted, 99)),
    max: round(sorted.length ? sorted[sorted.length - 1] : null),
  };
};

const ks = (left, right) => {
  if (left.length === 0 || right.length === 0) return null;
  const a = [...left].sort((x, y) => x - y);
  const b = [...right].sort((x, y) => x - y);
  let i = 0;
  let j = 0;
  let distance = 0;
  while (i < a.length && j < b.length) {
    const value = Math.min(a[i], b[j]);
    while (i < a.length && a[i] <= value) i++;
    while (j < b.length && b[j] <= value) j++;
    distance = Math.max(distance, Math.abs(i / a.length - j / b.length));
  }
  return round(distance);
};

const shareAbove = (values, threshold) =>
  values.length === 0 || threshold === null
    ? null
    : round(values.filter((value) => value > threshold).length / values.length);

const KINDS = ["dummy", "control", "store-read", "store-write"];
const FRAME_TYPE_COVER = 4;
// The phases whose every cell offset is kept, so the statistics can be
// recomputed from the summary.
const KEEP_OFFSETS = new Set(["visible", "hiddenAll"]);

// A fixed-seed generator (mulberry32), so a permutation test gives the same
// p on every run of this tool.
const seeded = (seed) => () => {
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const PERMUTATIONS = 10_000;
const PERMUTATION_SEED = 12_345;

const mean = (values) =>
  values.reduce((total, value) => total + value, 0) / values.length;
const variance = (values) => {
  const m = mean(values);
  return (
    values.reduce((total, value) => total + (value - m) ** 2, 0) /
    (values.length - 1)
  );
};
// The standard normal distribution function (Abramowitz and Stegun 7.1.26).
const normalCdf = (x) => {
  const t = 1 / (1 + 0.3275911 * (Math.abs(x) / Math.SQRT2));
  const erf =
    1 -
    ((((1.061405429 * t - 1.453152027) * t + 1.421413741) * t - 0.284496736) *
      t +
      0.254829592) *
      t *
      Math.exp(-(x * x) / 2);
  return x >= 0 ? (1 + erf) / 2 : (1 - erf) / 2;
};

/**
 * Cycles as the unit: the mean of a cycle's values in cycles that carried a
 * job against cycles that did not, with a two-sided permutation test over the
 * cycles' labels.
 */
const cycleComparison = (jobCycleMeans, otherCycleMeans, random) => {
  if (jobCycleMeans.length < 2 || otherCycleMeans.length < 2) return null;
  const all = [...jobCycleMeans, ...otherCycleMeans];
  const observed = mean(jobCycleMeans) - mean(otherCycleMeans);
  let extreme = 0;
  const labels = all.map((_, index) => index < jobCycleMeans.length);
  for (let round = 0; round < PERMUTATIONS; round++) {
    for (let i = labels.length - 1; i > 0; i--) {
      const j = Math.floor(random() * (i + 1));
      [labels[i], labels[j]] = [labels[j], labels[i]];
    }
    let jobTotal = 0;
    let otherTotal = 0;
    for (let i = 0; i < all.length; i++)
      if (labels[i]) jobTotal += all[i];
      else otherTotal += all[i];
    const difference =
      jobTotal / jobCycleMeans.length - otherTotal / otherCycleMeans.length;
    if (Math.abs(difference) >= Math.abs(observed)) extreme += 1;
  }
  const sd = Math.sqrt(
    (variance(jobCycleMeans) + variance(otherCycleMeans)) / 2,
  );
  const dPrime = sd > 0 ? observed / sd : null;
  return {
    jobCycles: jobCycleMeans.length,
    otherCycles: otherCycleMeans.length,
    differenceMs: round(observed),
    permutationP: round((extreme + 1) / (PERMUTATIONS + 1)),
    perCycleSdMs: round(sd),
    dPrime: dPrime === null ? null : round(dPrime),
    // If the difference were real: the cycles of each kind an observer needs
    // to tell them apart (one-sided 5 %, power 80 %), and how often one cycle
    // alone is classified right.
    cyclesNeededPerClass: dPrime
      ? Math.ceil(2 * ((1.645 + 0.842) / Math.abs(dPrime)) ** 2)
      : null,
    singleCycleAccuracy:
      dPrime === null ? null : round(normalCdf(Math.abs(dPrime) / 2)),
  };
};

const compare = (subject, reference) => {
  if (subject.length === 0 || reference.length === 0) return null;
  const sortedSubject = [...subject].sort((a, b) => a - b);
  const sortedReference = [...reference].sort((a, b) => a - b);
  const p99 = percentile(sortedReference, 99);
  return {
    medianShiftMs: round(
      percentile(sortedSubject, 50) - percentile(sortedReference, 50),
    ),
    ks: ks(subject, reference),
    // The two-sample KS distance a difference needs to show at the 5 % level.
    ksCritical5pct: round(
      1.36 *
        Math.sqrt(
          (subject.length + reference.length) /
            (subject.length * reference.length),
        ),
    ),
    flaggedAtReferenceP99: shareAbove(subject, p99),
  };
};

export const summariseSealed = (data, from, to, phaseName = "") => {
  const { schedule, maxTimerDriftMs } = data;
  const cycleMs = schedule.coverCadenceMs * schedule.coverDurationEpochs;
  const perCycle =
    schedule.coverLanes *
    schedule.coverFramesPerCell *
    schedule.coverDurationEpochs;
  const edgeCount = data.edges.length;
  const slotsPerEpoch = schedule.coverLanes * schedule.coverFramesPerCell;
  // The offset of every slot from its cycle's start, as the scheduler places it.
  const slotOffsets = new Map();
  for (let ordinal = 0; ordinal < perCycle; ordinal++) {
    const epoch = Math.floor(ordinal / slotsPerEpoch);
    const within = ordinal % slotsPerEpoch;
    slotOffsets.set(
      epoch * schedule.coverCadenceMs +
        Math.floor(
          ((2 * within + 1) * schedule.coverCadenceMs) / (2 * slotsPerEpoch),
        ),
      ordinal,
    );
  }
  const idle = data.idleEdges ?? 0;
  const phases = data.edgePhasesMs ?? data.edges.map(() => 0);
  const roleOf = (edge) => (edge < edgeCount - idle ? "busy" : "idle");
  // Grid 0 is the busy edges' grid; an idle edge with another phase is
  // another room's grid on the same page.
  const gridPhase = phases[0];
  const onGrid = (edge) => phases[edge] === gridPhase;

  const kindOf = (edge, label, firstByte, recorded) => {
    // Newer recordings say which producer made each cell.
    if (recorded !== undefined) {
      if (recorded !== "dummy") return recorded;
      const lane = data.edges[edge].labels[label];
      // A store-backed job's lane sending a dummy before its job completed.
      return lane?.startsWith("store-") && firstByte === FRAME_TYPE_COVER
        ? "lane-dummy"
        : "dummy";
    }
    const kind = data.edges[edge].labels[label] ?? "dummy";
    // A job's lane that sent its slot's dummy because the job's cell was not
    // ready (cover frame type on a store-backed job's lane).
    if (kind.startsWith("store-") && firstByte === FRAME_TYPE_COVER)
      return "fallback-dummy";
    return kind;
  };

  const production = Object.fromEntries(KINDS.map((kind) => [kind, []]));
  const offset = Object.fromEntries(KINDS.map((kind) => [kind, []]));
  // Every cell of a kept phase: [edge, kind, deadline, cycle, position, offset].
  const cellRows = [];
  // Every cell by the busy grid's cycle its deadline falls in.
  const byGridCycle = [];
  const gridCycleOf = (at) => Math.floor((at - phases[0]) / cycleMs);
  const dummyBesideReal = [];
  const dummyBesideDummy = [];
  const slotLateness = [];
  const stages = {};
  let fallbackDummies = 0;
  let cycles = 0;
  let degradedCycles = 0;
  let cellsSent = 0;
  const byEdge = [];

  // What the busy grid sent at each of its slots: "real" if any busy edge's
  // cell there was not a dummy.
  const busySlots = new Map();
  data.edges.forEach((edge, edgeIndex) => {
    if (roleOf(edgeIndex) !== "busy" || !onGrid(edgeIndex)) return;
    for (const [deadline, , , label, firstByte, recorded] of edge.cells) {
      const kind = kindOf(edgeIndex, label, firstByte, recorded);
      const real = KINDS.includes(kind) && kind !== "dummy";
      busySlots.set(
        deadline,
        busySlots.get(deadline) === "real" || real ? "real" : "dummy",
      );
    }
  });
  const busyDeadlines = [...busySlots.keys()].sort((a, b) => a - b);
  /** What the busy grid is producing at `at`: its next slot's cell. */
  const busyProducing = (at) => {
    let low = 0;
    let high = busyDeadlines.length;
    while (low < high) {
      const mid = (low + high) >> 1;
      if (busyDeadlines[mid] <= at) low = mid + 1;
      else high = mid;
    }
    const next = busyDeadlines[low];
    return next === undefined ? undefined : busySlots.get(next);
  };
  const crossGrid = {};
  // For comparisons at the same slot position: each cell's offset minus the
  // median of the reference cells at that position in the cycle (the first
  // slot of a cycle is armed half a slot ahead, not a whole one, and was
  // measured to run earlier).
  const positioned = [];
  const positionedBeside = [];
  const adjust = (cells, isReference) => {
    const byPosition = new Map();
    for (const cell of cells)
      if (isReference(cell))
        (
          byPosition.get(cell.position) ??
          byPosition.set(cell.position, []).get(cell.position)
        ).push(cell.value);
    const medians = new Map(
      [...byPosition].map(([position, values]) => [
        position,
        percentile(
          [...values].sort((a, b) => a - b),
          50,
        ),
      ]),
    );
    return cells
      .filter((cell) => medians.has(cell.position))
      .map((cell) => ({
        ...cell,
        value: cell.value - medians.get(cell.position),
      }));
  };

  data.edges.forEach((edge, edgeIndex) => {
    const phase = phases[edgeIndex];
    const cycleOf = (at) => Math.floor((at - phase) / cycleMs);
    const sent = new Map();
    for (const [
      deadline,
      wokeAt,
      sentAt,
      label,
      firstByte,
      recorded,
    ] of edge.cells) {
      sent.set(cycleOf(deadline), (sent.get(cycleOf(deadline)) ?? 0) + 1);
      if (deadline < from || deadline >= to) continue;
      const kind = kindOf(edgeIndex, label, firstByte, recorded);
      const value = sentAt - deadline;
      const position = slotOffsets.get(
        (((deadline - phase) % cycleMs) + cycleMs) % cycleMs,
      );
      if (KEEP_OFFSETS.has(phaseName))
        cellRows.push([
          edgeIndex,
          kind,
          deadline,
          cycleOf(deadline),
          position,
          Number(value.toFixed(2)),
        ]);
      byGridCycle.push({
        edge: edgeIndex,
        kind,
        cycle: gridCycleOf(deadline),
        value,
      });
      if (kind === "fallback-dummy" || kind === "lane-dummy") {
        fallbackDummies += 1;
        continue;
      }
      if (onGrid(edgeIndex)) {
        production[kind].push(sentAt - wokeAt);
        offset[kind].push(value);
        positioned.push({
          kind,
          position,
          value,
          idleDummy: kind === "dummy" && roleOf(edgeIndex) === "idle",
          busy: roleOf(edgeIndex) === "busy",
        });
        if (kind === "dummy" && roleOf(edgeIndex) === "idle") {
          const besideReal = busySlots.get(deadline) === "real";
          (besideReal ? dummyBesideReal : dummyBesideDummy).push(value);
          positionedBeside.push({ besideReal, position, value });
        }
      } else if (roleOf(edgeIndex) === "idle") {
        const entry = (crossGrid[phase] ??= {
          real: [],
          dummy: [],
          positioned: [],
        });
        const producing = busyProducing(deadline);
        if (producing) {
          entry[producing].push(value);
          entry.positioned.push({ producing, position, value });
        }
      }
    }

    // Degrades of this edge, by the status reason the scheduler gave.
    const degradeEvents = {};
    const reasonsByCycle = new Map();
    for (const [at, status, reason] of edge.statuses) {
      if (status !== "degraded" || at < from || at >= to) continue;
      degradeEvents[reason] = (degradeEvents[reason] ?? 0) + 1;
      if (!reasonsByCycle.has(cycleOf(at)))
        reasonsByCycle.set(cycleOf(at), reason);
    }
    const firstCycle = Math.ceil((from - phase) / cycleMs);
    const lastCycle = Math.floor((to - phase) / cycleMs) - 1;
    let edgeCycles = 0;
    let edgeDegraded = 0;
    let edgeCells = 0;
    const degradedCyclesByReason = {};
    for (let cycle = firstCycle; cycle <= lastCycle; cycle++) {
      edgeCycles += 1;
      const count = sent.get(cycle) ?? 0;
      edgeCells += count;
      if (count < perCycle) {
        edgeDegraded += 1;
        const reason =
          reasonsByCycle.get(cycle) ??
          reasonsByCycle.get(cycle - 1) ??
          "(no degrade event in this or the cycle before)";
        degradedCyclesByReason[reason] =
          (degradedCyclesByReason[reason] ?? 0) + 1;
      }
    }
    cycles += edgeCycles;
    degradedCycles += edgeDegraded;
    cellsSent += edgeCells;
    byEdge.push({
      edge: edgeIndex,
      role: roleOf(edgeIndex),
      phaseMs: phase,
      cycles: edgeCycles,
      degradedCycles: edgeDegraded,
      cellsSent: edgeCells,
      cellsExpected: edgeCycles * perCycle,
      degradeEvents,
      degradedCyclesByReason,
    });

    for (const [due, ranAt, kind] of edge.wakeUps)
      if (kind === "slot" && due >= from && due < to)
        slotLateness.push(ranAt - due);
    for (const [
      kind,
      readStart,
      readEnd,
      plaintextEnd,
      sealEnd,
    ] of edge.productions ?? []) {
      if (readStart < from || readStart >= to) continue;
      stages[kind] ??= { read: [], plaintext: [], seal: [], total: [] };
      stages[kind].read.push(readEnd - readStart);
      stages[kind].plaintext.push(plaintextEnd - readEnd);
      stages[kind].seal.push(sealEnd - plaintextEnd);
      stages[kind].total.push(sealEnd - readStart);
    }
  });

  const versusDummy = {};
  for (const kind of KINDS.slice(1)) {
    const compared = compare(offset[kind], offset.dummy);
    if (compared) versusDummy[kind] = compared;
  }
  // The reference at each position is the busy grid's idle edge's dummies
  // there: a busy edge's own dummies at a job lane's positions come only from
  // cycles without a job, which would bias the reference.
  const adjusted = adjust(positioned, (cell) => cell.idleDummy);
  const versusDummyAtSamePosition = {};
  for (const kind of KINDS.slice(1)) {
    const compared = compare(
      adjusted
        .filter((cell) => cell.busy && cell.kind === kind)
        .map((cell) => cell.value),
      adjusted.filter((cell) => cell.idleDummy).map((cell) => cell.value),
    );
    if (compared) versusDummyAtSamePosition[kind] = compared;
  }

  // Cycles that carried a job against cycles that did not. A cycle is the
  // busy grid's; it counts when the grid's idle edge sent all its slots. Its
  // value is the mean of its cells' offsets, each taken against its edge's
  // median; per edge, the mean of that edge's cells.
  const gridIdle = data.edges.findIndex(
    (_, edge) => roleOf(edge) === "idle" && onGrid(edge),
  );
  const jobCycles = new Set(
    byGridCycle
      .filter(
        ({ edge, kind }) =>
          roleOf(edge) === "busy" &&
          onGrid(edge) &&
          KINDS.includes(kind) &&
          kind !== "dummy",
      )
      .map(({ cycle }) => cycle),
  );
  const idleCount = new Map();
  for (const { edge, cycle } of byGridCycle)
    if (edge === gridIdle)
      idleCount.set(cycle, (idleCount.get(cycle) ?? 0) + 1);
  const fullCycles = new Set(
    [...idleCount].filter(([, n]) => n === perCycle).map(([cycle]) => cycle),
  );
  const edgeMedians = new Map();
  for (let edge = 0; edge < edgeCount; edge++) {
    const values = byGridCycle
      .filter((cell) => cell.edge === edge)
      .map((cell) => cell.value)
      .sort((a, b) => a - b);
    if (values.length) edgeMedians.set(edge, percentile(values, 50));
  }
  const cycleValues = new Map();
  const edgeCycleValues = new Map();
  for (const { edge, cycle, value } of byGridCycle) {
    if (!fullCycles.has(cycle)) continue;
    (cycleValues.get(cycle) ?? cycleValues.set(cycle, []).get(cycle)).push(
      value - edgeMedians.get(edge),
    );
    const key = `${String(edge)}:${String(cycle)}`;
    (edgeCycleValues.get(key) ?? edgeCycleValues.set(key, []).get(key)).push(
      value,
    );
  }
  const random = seeded(PERMUTATION_SEED);
  const sortedCycles = [...cycleValues.keys()].sort((a, b) => a - b);
  const byCycle =
    gridIdle === -1
      ? null
      : {
          page: cycleComparison(
            sortedCycles
              .filter((cycle) => jobCycles.has(cycle))
              .map((cycle) => mean(cycleValues.get(cycle))),
            sortedCycles
              .filter((cycle) => !jobCycles.has(cycle))
              .map((cycle) => mean(cycleValues.get(cycle))),
            random,
          ),
          byEdge: Object.fromEntries(
            Array.from({ length: edgeCount }, (_, edge) => {
              const of = (wanted) =>
                sortedCycles
                  .filter((cycle) => jobCycles.has(cycle) === wanted)
                  .map((cycle) =>
                    edgeCycleValues.get(`${String(edge)}:${String(cycle)}`),
                  )
                  .filter((values) => values?.length)
                  .map(mean);
              return [
                `${String(edge)} (${roleOf(edge)}, phase ${String(phases[edge])} ms)`,
                cycleComparison(of(true), of(false), random),
              ];
            }),
          ),
        };
  const dummyByPosition = {};
  for (const { kind, position, value } of positioned)
    if (kind === "dummy") (dummyByPosition[position] ??= []).push(value);
  const besideAdjusted = adjust(positionedBeside, (cell) => !cell.besideReal);

  return {
    cycles,
    degradedCycles,
    cellsSent,
    cellsExpected: cycles * perCycle,
    byEdge,
    slotWakeUpLatenessMs: {
      ...stats(slotLateness),
      beyondToleranceShare:
        slotLateness.length === 0
          ? null
          : round(
              slotLateness.filter((ms) => ms > maxTimerDriftMs).length /
                slotLateness.length,
            ),
    },
    // Kinds, on the busy edges' grid (its idle edges included).
    productionMs: Object.fromEntries(
      KINDS.map((kind) => [kind, stats(production[kind])]),
    ),
    offsetMs: Object.fromEntries(
      KINDS.map((kind) => [kind, stats(offset[kind])]),
    ),
    versusDummy,
    // The busy edges' kinds, each offset taken against the median of the
    // grid's idle edge's dummies at its slot position: what is left once the
    // slot position is set aside.
    versusDummyAtSamePosition,
    // Cycles as the unit (see cycleComparison).
    cyclesWithAJobAgainstWithout: byCycle,
    dummyMedianByPositionMs: Object.fromEntries(
      Object.entries(dummyByPosition).map(([position, values]) => [
        position,
        round(
          percentile(
            [...values].sort((a, b) => a - b),
            50,
          ),
        ),
      ]),
    ),
    fallbackDummies,
    crossEdge: {
      dummyBesideDummy: stats(dummyBesideDummy),
      dummyBesideReal: stats(dummyBesideReal),
      ...compare(dummyBesideReal, dummyBesideDummy),
      atSamePosition: compare(
        besideAdjusted.filter((cell) => cell.besideReal).map((c) => c.value),
        besideAdjusted.filter((cell) => !cell.besideReal).map((c) => c.value),
      ),
    },
    // An idle grid's cells, by what the busy grid was producing then (the
    // cell for its next slot): real or dummy.
    crossGrid: Object.fromEntries(
      Object.entries(crossGrid).map(([phase, { real, dummy, positioned }]) => {
        const shifted = adjust(
          positioned,
          (cell) => cell.producing === "dummy",
        );
        return [
          `phase ${phase} ms`,
          {
            whileBusyProducesReal: stats(real),
            whileBusyProducesDummy: stats(dummy),
            ...compare(real, dummy),
            atSamePosition: compare(
              shifted
                .filter((cell) => cell.producing === "real")
                .map((cell) => cell.value),
              shifted
                .filter((cell) => cell.producing === "dummy")
                .map((cell) => cell.value),
            ),
          },
        ];
      }),
    ),
    realCellStagesMs: Object.fromEntries(
      Object.entries(stages).map(([kind, parts]) => [
        kind,
        Object.fromEntries(
          Object.entries(parts).map(([part, values]) => [part, stats(values)]),
        ),
      ]),
    ),
    ...(KEEP_OFFSETS.has(phaseName) ? { cellRows } : {}),
  };
};

/**
 * Write a sealed-mode summary and, beside it (`.offsets.tsv`), every cell of
 * its kept phases, one per line, taken out of the JSON.
 */
export const writeSealedSummary = (summaryPath, summary) => {
  const lines = [
    "# phase\tedge\tkind\tdeadline (page Date.now() ms)\tcycle (of its edge's grid)\tslot position in the cycle\tslot-to-send offset (ms; performance.timeOrigin + now() minus the deadline)",
  ];
  for (const [phase, values] of Object.entries(summary.sealed ?? {})) {
    for (const row of values.cellRows ?? [])
      lines.push([phase, ...row].join("\t"));
    delete values.cellRows;
  }
  const tsvPath = summaryPath.replace(/\.json$/, "") + ".offsets.tsv";
  if (lines.length > 1) {
    summary.cellOffsetsFile = tsvPath.split("/").pop();
    writeFileSync(tsvPath, `${lines.join("\n")}\n`);
  }
  writeFileSync(summaryPath, `${JSON.stringify(summary, null, 2)}\n`);
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [rawPath, summaryPath] = process.argv.slice(2);
  const data = JSON.parse(readFileSync(rawPath, "utf8"));
  const summary = JSON.parse(readFileSync(summaryPath, "utf8"));
  for (const [name, [from, to]] of Object.entries(summary.phasesMs))
    if (to > from)
      summary.sealed[name] = summariseSealed(
        data,
        from + data.startedAt,
        to + data.startedAt,
        name,
      );
  writeSealedSummary(summaryPath, summary);
}
