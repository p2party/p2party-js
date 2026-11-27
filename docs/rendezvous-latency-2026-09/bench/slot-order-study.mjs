// Run from the SDK checkout after building the two-store browser harness.
// stdout is JSONL, one completed exchange per line. Logs stay in memory.
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const harness = "docs/e2e/blind-two-store/run.mjs";
const phases = [350, 1650, 2350];
let pair = 0;
let failed = false;
for (const delay of [0, 800]) {
  for (const phase of phases) {
    const orders =
      pair++ % 2 ? ["critical-later", "pinned"] : ["pinned", "critical-later"];
    for (const order of orders) {
      process.stderr.write(`phase=${phase} delay=${delay} profile=${order}\n`);
      const trial = spawnSync(
        process.execPath,
        [
          harness,
          "--scenario=healthy",
          "--window-ms=4000",
          `--slot-order=${order}`,
          `--start-phase-ms=${phase}`,
          `--chunk-reply-delay-ms=${delay}`,
          "--store-port-base=18410",
          "--page-port=18422",
        ],
        { cwd: root, encoding: "utf8", maxBuffer: 8 * 1024 * 1024 },
      );
      const line = trial.stdout
        ?.split("\n")
        .find((s) => s.startsWith("TIMING_SAMPLE "));
      if (!line) {
        // Preserve evidence of interrupted or setup-failed runs without copying
        // ephemeral room identifiers or arbitrary diagnostics into the dataset.
        console.log(
          JSON.stringify({
            slotOrder: order,
            requestedPhaseMs: phase,
            chunkReplyDelayMs: delay,
            passed: false,
            status: trial.status,
            error: trial.error?.code ?? "no timing sample",
          }),
        );
        process.exit(1);
      }
      const sample = JSON.parse(line.slice("TIMING_SAMPLE ".length));
      if (!sample.passed || trial.status !== 0) failed = true;
      console.log(JSON.stringify(sample));
    }
  }
}
process.exitCode = failed ? 1 : 0;
