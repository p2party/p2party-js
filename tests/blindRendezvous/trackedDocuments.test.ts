import { lstatSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "bun:test";

/** The repository root: this file is `tests/blindRendezvous/<name>`. */
const ROOT = join(import.meta.dir, "..", "..");

/**
 * A path in someone's home directory: `/Users/<name>` (macOS) or
 * `/home/<name>` (Linux), whether a slash follows the name or not, so one
 * that ends a code span or a sentence is found too. A file that is published
 * must not carry the account name of the machine it was written on.
 */
const LOCAL_HOME = /\/(?:Users|home)\/[A-Za-z0-9._-]+/;

/** How far into a file a NUL byte marks it as binary, as git decides it. */
const BINARY_PROBE_BYTES = 8_000;

/** Every tracked file of the repository, from git itself; no git, no answer. */
const trackedFiles = (): string[] => {
  const listed = Bun.spawnSync(["git", "ls-files", "-z"], {
    cwd: ROOT,
    stdout: "pipe",
    stderr: "pipe",
  });
  if (listed.exitCode !== 0)
    throw new Error(
      `git ls-files failed (exit ${String(listed.exitCode)}): ${listed.stderr.toString()}`,
    );
  const files = listed.stdout.toString().split("\0").filter(Boolean);
  if (files.length === 0)
    throw new Error("git ls-files listed no file: nothing was checked");
  return files;
};

/** A regular file with no NUL byte where git looks for one. */
const textOf = (file: string): string | null => {
  const path = join(ROOT, file);
  // A symbolic link (a copy's `node_modules`, say) is not a file's text.
  if (!lstatSync(path).isFile()) return null;
  const bytes = readFileSync(path);
  if (bytes.subarray(0, BINARY_PROBE_BYTES).includes(0)) return null;
  return bytes.toString("utf8");
};

describe("tracked documents", () => {
  test("no tracked document names a local home directory", () => {
    const offending: string[] = [];
    let read = 0;
    for (const file of trackedFiles()) {
      const text = textOf(file);
      if (text === null) continue;
      read += 1;
      text.split("\n").forEach((line, index) => {
        if (LOCAL_HOME.test(line))
          offending.push(`${file}:${String(index + 1)}: ${line.trim()}`);
      });
    }
    // Not vacuous: the repository's own sources were read.
    expect(read).toBeGreaterThan(100);
    expect(offending).toEqual([]);
  });

  test("the home-directory pattern finds both forms, and no placeholder", () => {
    // Built here, not written out: this file is tracked, and is read above.
    const home = (root: string, name: string): string => `/${root}/${name}`;
    for (const found of [
      `see ${home("Users", "someone")}/Desktop/notes.md`,
      `the checkout lives in \`${home("Users", "someone")}\``,
      `run it from ${home("home", "ci-runner")}.`,
    ])
      expect([found, LOCAL_HOME.test(found)]).toEqual([found, true]);
    for (const clean of [
      "`/Users/<name>/` (macOS)",
      "https://example.org/",
      "/Users/",
    ])
      expect([clean, LOCAL_HOME.test(clean)]).toEqual([clean, false]);
  });
});
