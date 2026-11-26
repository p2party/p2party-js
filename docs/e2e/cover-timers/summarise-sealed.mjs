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
// "dummyBesideReal" are an edge's dummy cells whose slot another edge filled
// with a real cell, against "dummyBesideDummy": the cross-edge effect.
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

export const summariseSealed = (data, from, to) => {
  const { schedule, maxTimerDriftMs } = data;
  const cycleMs = schedule.coverCadenceMs * schedule.coverDurationEpochs;
  const perCycle =
    schedule.coverLanes *
    schedule.coverFramesPerCell *
    schedule.coverDurationEpochs;
  const firstCycle = Math.ceil(from / cycleMs);
  const lastCycle = Math.floor(to / cycleMs) - 1;

  const production = Object.fromEntries(KINDS.map((kind) => [kind, []]));
  const offset = Object.fromEntries(KINDS.map((kind) => [kind, []]));
  const dummyBesideReal = [];
  const dummyBesideDummy = [];
  const slotLateness = [];
  const stages = {};
  let cycles = 0;
  let degradedCycles = 0;
  let cellsSent = 0;

  // Which slots (by deadline) carried a non-dummy cell, per edge.
  const realSlots = data.edges.map(
    (edge) =>
      new Set(
        edge.cells
          .filter(([, , , label]) => edge.labels[label] !== undefined)
          .map(([deadline]) => deadline),
      ),
  );

  data.edges.forEach((edge, edgeIndex) => {
    const sent = new Map();
    for (const [deadline, wokeAt, sentAt, label] of edge.cells) {
      const cycle = Math.floor(deadline / cycleMs);
      sent.set(cycle, (sent.get(cycle) ?? 0) + 1);
      if (deadline < from || deadline >= to) continue;
      const kind = edge.labels[label] ?? "dummy";
      production[kind].push(sentAt - wokeAt);
      offset[kind].push(sentAt - deadline);
      if (kind === "dummy") {
        const besideReal = realSlots.some(
          (slots, other) => other !== edgeIndex && slots.has(deadline),
        );
        (besideReal ? dummyBesideReal : dummyBesideDummy).push(
          sentAt - deadline,
        );
      }
    }
    for (let cycle = firstCycle; cycle <= lastCycle; cycle++) {
      cycles += 1;
      const count = sent.get(cycle) ?? 0;
      cellsSent += count;
      if (count < perCycle) degradedCycles += 1;
    }
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

  const dummyOffsets = [...offset.dummy].sort((a, b) => a - b);
  const dummyP99 = percentile(dummyOffsets, 99);
  const dummyP90 = percentile(dummyOffsets, 90);
  const dummyMedian = percentile(dummyOffsets, 50);
  const versusDummy = {};
  for (const kind of KINDS.slice(1)) {
    if (offset[kind].length === 0) continue;
    const sorted = [...offset[kind]].sort((a, b) => a - b);
    versusDummy[kind] = {
      medianShiftMs: round(percentile(sorted, 50) - dummyMedian),
      ks: ks(offset[kind], offset.dummy),
      flaggedAtDummyP99: shareAbove(offset[kind], dummyP99),
      flaggedAtDummyP90: shareAbove(offset[kind], dummyP90),
    };
  }

  return {
    cycles,
    degradedCycles,
    cellsSent,
    cellsExpected: cycles * perCycle,
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
    productionMs: Object.fromEntries(
      KINDS.map((kind) => [kind, stats(production[kind])]),
    ),
    offsetMs: Object.fromEntries(
      KINDS.map((kind) => [kind, stats(offset[kind])]),
    ),
    versusDummy,
    crossEdge: {
      dummyBesideDummy: stats(dummyBesideDummy),
      dummyBesideReal: stats(dummyBesideReal),
      ks: ks(dummyBesideReal, dummyBesideDummy),
    },
    realCellStagesMs: Object.fromEntries(
      Object.entries(stages).map(([kind, parts]) => [
        kind,
        Object.fromEntries(
          Object.entries(parts).map(([part, values]) => [part, stats(values)]),
        ),
      ]),
    ),
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
      );
  writeFileSync(summaryPath, `${JSON.stringify(summary, null, 2)}\n`);
}
