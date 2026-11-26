// Per-phase summary of an entry-sealed.ts recording (driver.mjs --mode=sealed).
// Also runnable on a saved raw recording:
//   node docs/e2e/cover-timers/summarise-sealed.mjs <raw.json> <summary.json>
// which keeps the summary's run metadata and recomputes its phases.
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
//   flaggedAtDummyP99 / P90   the share of that kind's cells whose offset is
//                   above the dummies' 99th / 90th percentile: what an
//                   observer flagging "later than 99 % of dummies" catches,
//                   at a 1 % (10 %) false-alarm rate on dummies.
// "dummyBesideReal" are an idle edge's dummy cells whose slot a busy edge of
// the same grid filled with a real cell, against "dummyBesideDummy": the
// cross-edge effect. "crossGrid" compares an idle edge of another grid (another
// phase), by what the busy grid was producing at that moment. Kinds are
// compared on the busy grid only. "byEdge" gives each edge's degraded cycles
// by the scheduler's status reason. For the visible and hidden phases every
// cell's offset is kept (offsetsMsByEdgeAndKind), so all of it can be
// recomputed. A store-backed job's lane that sent a dummy (the dummy in place
// of a cell not ready, or the lane's dummy tail) counts as "fallback-dummy" in
// older recordings and "lane-dummy" in newer ones, which name the producer of
// every cell; both are left out of the kind comparisons.
//
// "...AtSamePosition" compares offsets taken against the reference median at
// the same slot position in the cycle: the first slot of a cycle is armed half
// a slot ahead and was measured to run earlier than the others, and real cells
// ride their lane's slots, so a pooled comparison partly compares positions.
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

const roundAll = (values) => values.map((value) => Number(value.toFixed(2)));

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
  const keptOffsets = {};
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
    const kept = {};
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
      (kept[kind] ??= []).push(value);
      if (kind === "fallback-dummy" || kind === "lane-dummy") {
        fallbackDummies += 1;
        continue;
      }
      if (onGrid(edgeIndex)) {
        production[kind].push(sentAt - wokeAt);
        offset[kind].push(value);
        positioned.push({ kind, position, value });
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
    if (KEEP_OFFSETS.has(phaseName))
      keptOffsets[edgeIndex] = Object.fromEntries(
        Object.entries(kept).map(([kind, values]) => [kind, roundAll(values)]),
      );

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
  const adjusted = adjust(positioned, (cell) => cell.kind === "dummy");
  const versusDummyAtSamePosition = {};
  for (const kind of KINDS.slice(1)) {
    const compared = compare(
      adjusted.filter((cell) => cell.kind === kind).map((cell) => cell.value),
      adjusted
        .filter((cell) => cell.kind === "dummy")
        .map((cell) => cell.value),
    );
    if (compared) versusDummyAtSamePosition[kind] = compared;
  }
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
    // The same, each offset taken against the dummies' median at its slot
    // position: what is left once the slot position is set aside.
    versusDummyAtSamePosition,
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
    ...(KEEP_OFFSETS.has(phaseName)
      ? { offsetsMsByEdgeAndKind: keptOffsets }
      : {}),
  };
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
  writeFileSync(summaryPath, `${JSON.stringify(summary, null, 2)}\n`);
}
