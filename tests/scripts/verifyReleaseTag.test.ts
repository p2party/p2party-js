import { describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const verifier = fileURLToPath(
  new URL("../../scripts/verifyReleaseTag.mjs", import.meta.url),
);

describe("public tag verification", () => {
  for (const [version, tag, passes] of [
    ["0.15.0", "v0.15.0", true],
    ["0.15.0", "v0.14.10", false],
    ["0.15.0-rc.0", "v0.15.0-rc.0", false],
    ["0.15.0-rc.0", "v0.15.0", false],
  ] as const) {
    test(`${tag} with package ${version} ${passes ? "passes" : "fails"}`, () => {
      const cwd = mkdtempSync(join(tmpdir(), "p2party-tag-test-"));
      try {
        writeFileSync(join(cwd, "package.json"), JSON.stringify({ version }));
        const result = spawnSync(process.execPath, [verifier], {
          cwd,
          env: { ...process.env, GITHUB_REF_NAME: tag },
        });
        expect(result.status === 0).toBe(passes);
      } finally {
        rmSync(cwd, { recursive: true, force: true });
      }
    });
  }
});
