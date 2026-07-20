import { describe, expect, test } from "bun:test";

import {
  markChunkAcked,
  getAckedChunks,
  markTransferComplete,
  isTransferComplete,
  clearTransfer,
  waitForCompletion,
} from "./reconcile";

describe("reconcile state (selective retransmit / resume)", () => {
  test("accumulates acked chunk indices per (peer, message)", () => {
    clearTransfer("p", "h");
    markChunkAcked("p", "h", 0);
    markChunkAcked("p", "h", 2);
    markChunkAcked("p", "h", 0); // idempotent
    expect([...getAckedChunks("p", "h")].sort()).toEqual([0, 2]);
    expect(getAckedChunks("p", "other").size).toBe(0);
    clearTransfer("p", "h");
    expect(getAckedChunks("p", "h").size).toBe(0);
  });

  test("getAckedChunks returns a copy (caller cannot mutate internal state)", () => {
    clearTransfer("p", "h");
    markChunkAcked("p", "h", 1);
    const snap = getAckedChunks("p", "h");
    snap.add(99);
    expect(getAckedChunks("p", "h").has(99)).toBe(false);
    clearTransfer("p", "h");
  });

  test("tracks completion and waits for it", async () => {
    clearTransfer("p2", "h");
    expect(isTransferComplete("p2", "h")).toBe(false);
    setTimeout(() => markTransferComplete("p2", "h"), 120);
    const done = await waitForCompletion("p2", "h", 5000);
    expect(done).toBe(true);
    clearTransfer("p2", "h");
  });

  test("waitForCompletion returns false after timeout if never complete", async () => {
    clearTransfer("p3", "h");
    expect(await waitForCompletion("p3", "h", 150)).toBe(false);
  });
});
