import { readdirSync } from "node:fs";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

// Bun respects the order of explicit files. Keep them in one process so leaked
// globals, timers and module replacements still affect the next file.
function testFiles(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    return entry.isDirectory()
      ? testFiles(path)
      : /\.(?:test|spec)\.[cm]?[jt]sx?$/.test(entry.name)
        ? ["./" + path]
        : [];
  });
}
const paths = testFiles("tests").sort();
const [order, seedText, extra] = process.argv.slice(2);
if (order === "--reverse" && seedText === undefined) paths.reverse();
else if (order === "--seed" && !extra && /^\d+$/.test(seedText ?? "")) {
  let seed = Number(seedText);
  if (!Number.isInteger(seed) || seed < 1 || seed > 0xffffffff)
    throw new Error("Expected a nonzero 32-bit seed");
  for (let i = paths.length - 1; i > 0; i--) {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    const j = (seed >>> 0) % (i + 1);
    [paths[i], paths[j]] = [paths[j], paths[i]];
  }
} else throw new Error("Expected --reverse or --seed <number>");
const result = spawnSync("bun", ["test", ...paths], { stdio: "inherit" });
if (result.error) throw result.error;
process.exitCode = result.status ?? 1;
