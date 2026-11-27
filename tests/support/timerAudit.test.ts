import { afterAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const dir = mkdtempSync(join(tmpdir(), "p2party-test-timers-"));
const preload = fileURLToPath(
  new URL("./timerAudit.preload.ts", import.meta.url),
);
afterAll(() => rmSync(dir, { recursive: true, force: true }));
describe("file timer ownership", () => {
  for (const [name, body, pass] of [
    ["referenced", "setTimeout(() => {}, 60000);", false],
    ["unreferenced", "setInterval(() => {}, 60000).unref();", false],
    [
      "released",
      "clearTimeout(setTimeout(() => {},60000)); clearInterval(setInterval(() => {},60000));",
      true,
    ],
  ] as const) {
    test(name, () => {
      const path = join(dir, name + ".test.ts");
      writeFileSync(
        path,
        `import { test } from "bun:test"; test("fixture", () => { ${body} });`,
      );
      const result = Bun.spawnSync(
        [process.execPath, "test", "--preload", preload, path],
        { cwd: dir, stdout: "pipe", stderr: "pipe", timeout: 3000 },
      );
      expect(result.exitCode).toBe(pass ? 0 : 1);
      if (!pass) {
        expect(result.stderr.toString()).toContain(
          name + ".test.ts left a timer pending",
        );
      }
    });
  }
});
