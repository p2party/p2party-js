import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "bun:test";

/** The repository root: this file is `tests/blindRendezvous/<name>`. */
const ROOT = join(import.meta.dir, "..", "..");

/**
 * A path in someone's home directory: `/Users/<name>/` (macOS) or
 * `/home/<name>/` (Linux). A document that is published must not carry the
 * account name of the machine it was written on.
 */
const LOCAL_HOME = /\/(?:Users|home)\/[^/\s]+\//;

/** Every tracked file under `docs/`, from git itself; no git, no answer. */
const trackedDocuments = (): string[] => {
  const listed = Bun.spawnSync(["git", "ls-files", "-z", "docs"], {
    cwd: ROOT,
    stdout: "pipe",
    stderr: "pipe",
  });
  if (listed.exitCode !== 0)
    throw new Error(
      `git ls-files docs failed (exit ${String(listed.exitCode)}): ${listed.stderr.toString()}`,
    );
  const files = listed.stdout.toString().split("\0").filter(Boolean);
  if (files.length === 0)
    throw new Error("git ls-files docs listed no file: nothing was checked");
  return files;
};

describe("tracked documents", () => {
  test("no tracked document names a local home directory", () => {
    const offending: string[] = [];
    for (const file of trackedDocuments()) {
      const lines = readFileSync(join(ROOT, file), "utf8").split("\n");
      lines.forEach((line, index) => {
        if (LOCAL_HOME.test(line))
          offending.push(`${file}:${String(index + 1)}: ${line.trim()}`);
      });
    }
    expect(offending).toEqual([]);
  });
});
