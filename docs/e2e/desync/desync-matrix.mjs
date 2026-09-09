// Run the Task 12 acceptance matrix with disjoint local port pairs. Results
// remain per-driver artifacts; the summary never converts a failure to a pass.
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import {
  createWriteStream,
  existsSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { desyncProbeBudget } from "./desync-probe-budget.mjs";

const dir = path.dirname(fileURLToPath(import.meta.url));
const runs = path.resolve(dir, "../runs");
const arms = [
  ["baseline", "initiator"],
  ["ws-drop", "initiator"],
  ["proc-freeze-20", "initiator", "--udpflood=1"],
  ["proc-freeze-20", "responder", "--udpflood=1"],
  ["proc-freeze-20", "initiator", "--udpflood=1", "--socket=keep"],
  ["proc-freeze-20", "responder", "--udpflood=1", "--socket=keep"],
  ["proc-freeze-20", "initiator", "--udpflood=1", "--socket=stranded"],
  ["proc-freeze-20", "responder", "--udpflood=1", "--socket=stranded"],
  ["proc-freeze-45", "initiator", "--udpflood=1"],
  ["proc-freeze-20", "initiator", "--udpflood=1", "--transfer=A2B:8"],
  ["proc-freeze-20", "initiator", "--udpflood=1", "--transfer=B2A:8"],
  ["proc-freeze-20", "responder", "--udpflood=1", "--transfer=A2B:8"],
  ["ws-drop-nofocus", "initiator", "--observe=150"],
  ["ws-drop-nofocus", "responder", "--observe=150"],
  ["pin-typo", "initiator", "--observe=120"],
  ["two-tabs", "responder", "--observe=300"],
  ["two-tabs", "initiator", "--observe=300"],
  [
    "cover-stall",
    "initiator",
    "--mode=scheduled",
    "--cadence=10000",
    "--observe=180",
  ],
  [
    "baseline",
    "initiator",
    "--mode=scheduled",
    "--cadence=70000",
    "--observe=300",
  ],
  [
    "proc-freeze-20",
    "initiator",
    "--udpflood=1",
    "--mode=scheduled",
    "--cadence=10000",
    "--transfer=A2B:0.5",
    "--observe=240",
    "--transferdeadline=200",
  ],
  [
    "proc-freeze-20",
    "responder",
    "--udpflood=1",
    "--transfer=A2B:8",
    "--cpuslow=A:6",
    "--observe=180",
    "--transferdeadline=150",
  ],
  ["proc-freeze-20", "initiator", "--udpflood=1"],
  ["two-tabs", "responder", "--observe=300"],
];
const options = Object.fromEntries(
  process.argv.slice(2).map((a) => {
    const match = a.match(/^--(arms|jobs|runbase|portbase)=(.+)$/);
    if (!match) throw new Error(`Unknown option: ${a}`);
    return [match[1], match[2]];
  }),
);
const jobs = Number(options.jobs ?? 2);
const runbase = Number(options.runbase ?? 800);
const portbase = Number(options.portbase ?? 5860);
if (!Number.isInteger(jobs) || jobs < 1 || jobs > 3)
  throw new Error("jobs must be 1..3");
if (!Number.isInteger(runbase) || runbase < 1)
  throw new Error("runbase must be positive");
if (
  !Number.isInteger(portbase) ||
  portbase < 5001 ||
  portbase + jobs * 2 > 65535 ||
  (portbase <= 5432 && portbase + jobs * 2 > 5432)
)
  throw new Error("Invalid port range");
const selected = options.arms
  ? options.arms.split(",").map(Number)
  : arms.map((_, i) => i + 1);
if (
  new Set(selected).size !== selected.length ||
  selected.some((i) => !Number.isInteger(i) || !arms[i - 1])
)
  throw new Error("arms must be distinct indices in 1..23");
const digest = (name) =>
  createHash("sha256")
    .update(readFileSync(path.join(dir, name)))
    .digest("hex");
const inputs = [
  "app-bundle.js",
  "worker-inject.js",
  "libcrypto.wasm",
  "desync-driver.mjs",
  "desync-verdict.mjs",
  "desync-probe-budget.mjs",
  "relay.ts",
  "app.html",
  "plain.html",
];
const hashes = () =>
  Object.fromEntries(inputs.map((name) => [name, digest(name)]));
const report = {
  started: new Date().toISOString(),
  inputs: hashes(),
  jobs,
  arms: [],
};
const summaryPath = path.join(runs, `matrix-${runbase}.json`);
const save = () =>
  writeFileSync(summaryPath, JSON.stringify(report, null, 2) + "\n");
if (existsSync(summaryPath))
  throw new Error(`Refusing to overwrite ${summaryPath}`);
for (const id of selected) {
  const args = arms[id - 1];
  if (existsSync(path.join(runs, `${args[0]}-${args[1]}-${runbase + id}.json`)))
    throw new Error(`Run ${runbase + id} already exists`);
}
save();
const queue = selected.filter((id) => id !== 21);
const active = new Set();
let interrupted = false;
for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    interrupted = true;
    queue.length = 0;
    report.interrupted = signal;
    save();
    for (const child of active) child.kill("SIGTERM");
  });
}
async function runArm(id, slot) {
  if (JSON.stringify(hashes()) !== JSON.stringify(report.inputs))
    throw new Error(
      "Harness inputs changed during matrix; rebuild and start a new run",
    );
  const args = [
    ...arms[id - 1],
    `--port=${portbase + slot * 2}`,
    `--n=${runbase + id}`,
  ];
  const stripGeneration = id >= 22;
  const stem = `${args[0]}-${args[1]}-${runbase + id}`;
  const entry = {
    id,
    args,
    stripGeneration,
    expectedResidual: id === 23,
    started: new Date().toISOString(),
  };
  console.log(
    `START arm ${id}: ${stripGeneration ? "pre-generation server " : ""}${args.join(" ")}`,
  );
  const log = createWriteStream(path.join(runs, `${stem}.driver.log`));
  const child = spawn(
    process.execPath,
    [path.join(dir, "desync-driver.mjs"), ...args],
    {
      cwd: dir,
      env: {
        ...process.env,
        RELAY_STRIP_SOCKET_GENERATION: stripGeneration ? "1" : "0",
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  child.stdout.pipe(log, { end: false });
  child.stderr.pipe(log, { end: false });
  active.add(child);
  const observe = Number(
    args.find((a) => a.startsWith("--observe="))?.split("=")[1] ?? 120,
  );
  const freeze = Number(args[0].match(/^proc-freeze-(\d+)$/)?.[1] ?? 0);
  const mode =
    args.find((a) => a.startsWith("--mode="))?.split("=")[1] ?? "immediate";
  const cadence = Number(
    args.find((a) => a.startsWith("--cadence="))?.split("=")[1] ?? 2000,
  );
  const probe = desyncProbeBudget(mode, cadence);
  const overheadMs = Math.max(
    300000,
    2 * probe.roundTripMs + probe.finalI4DrainMs + 120000,
  );
  // Startup, healthy-link probes, final diagnostic budgets and cleanup are
  // separate from the advertised observation window. A hang still terminates.
  const deadline = setTimeout(
    () => {
      entry.timedOut = true;
      child.kill("SIGTERM");
    },
    (observe + freeze) * 1000 + overheadMs,
  );
  try {
    entry.exitCode = await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => {
        entry.signal = signal;
        resolve(code);
      });
    });
  } finally {
    clearTimeout(deadline);
    active.delete(child);
    log.end();
  }
  entry.finished = new Date().toISOString();
  const artifact = path.join(runs, `${stem}.json`);
  if (existsSync(artifact)) {
    const result = JSON.parse(readFileSync(artifact, "utf8"));
    entry.artifact = path.basename(artifact);
    entry.invariants = result.invariants;
    entry.problems = result.problems;
    entry.transfer = result.transfer?.verdict;
    entry.twoTabs = result.twoTabs ?? result.fault?.twoTabs;
  } else entry.problems = ["Driver produced no JSON evidence"];
  entry.pass =
    !entry.timedOut &&
    !interrupted &&
    entry.exitCode === 0 &&
    entry.problems?.length === 0;
  report.arms.push(entry);
  save();
  console.log(
    `DONE arm ${id}: ${entry.pass ? "PASS" : entry.expectedResidual ? "NON-PASS (inspect expected residual)" : "FAIL"}; I2=${entry.invariants?.firstSatisfiedSinceClear?.I2} I4=${entry.invariants?.firstSatisfiedSinceClear?.I4}; ${(entry.problems ?? []).join(" | ")}`,
  );
}
const workers = Array.from({ length: jobs }, (_, slot) =>
  (async () => {
    while (queue.length) await runArm(queue.shift(), slot);
  })(),
);
try {
  await Promise.all(workers);
  // Keep the CPU-throttling measurement isolated from other browser arms.
  if (!interrupted && selected.includes(21)) await runArm(21, 0);
} catch (error) {
  interrupted = true;
  queue.length = 0;
  report.fatalError = String(error?.stack ?? error);
  for (const child of active) child.kill("SIGTERM");
  await Promise.allSettled(workers);
}
report.finished = new Date().toISOString();
report.inputsUnchanged =
  JSON.stringify(hashes()) === JSON.stringify(report.inputs);
save();
console.log(`Matrix evidence: ${summaryPath}`);
if (
  interrupted ||
  !report.inputsUnchanged ||
  report.arms.some((arm) => !arm.pass)
)
  process.exitCode = 1;
