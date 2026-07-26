import { describe, expect, test } from "bun:test";

import {
  markChunkAcked,
  getAckedChunks,
  markTransferComplete,
  isTransferComplete,
  clearTransfer,
  getPeerTransferOutcome,
  getTransferAcks,
  waitForCompletion,
} from "../../src/handlers/reconcile";

describe("reconcile state (selective retransmit / resume)", () => {
  test("accumulates acked chunk indices per (peer, message)", () => {
    clearTransfer("r", "p", "h");
    expect(markChunkAcked("r", "p", "h", 0)).toBe(true);
    expect(markChunkAcked("r", "p", "h", 2)).toBe(true);
    expect(markChunkAcked("r", "p", "h", 0)).toBe(false);
    expect([...getAckedChunks("r", "p", "h")].sort()).toEqual([0, 2]);
    expect(getAckedChunks("r", "p", "other").size).toBe(0);
    clearTransfer("r", "p", "h");
    expect(getAckedChunks("r", "p", "h").size).toBe(0);
  });

  test("getAckedChunks returns a copy (caller cannot mutate internal state)", () => {
    clearTransfer("r", "p", "h");
    markChunkAcked("r", "p", "h", 1);
    const snap = getAckedChunks("r", "p", "h");
    snap.add(99);
    expect(getAckedChunks("r", "p", "h").has(99)).toBe(false);
    clearTransfer("r", "p", "h");
  });

  test("identical content uses independent transfer identities", () => {
    const first = "aa".repeat(32);
    const second = "bb".repeat(32);
    markChunkAcked("r", "p", first, 1);
    markTransferComplete("r", "p", first);

    expect(getAckedChunks("r", "p", first).has(1)).toBe(true);
    expect(getAckedChunks("r", "p", second).size).toBe(0);
    expect(isTransferComplete("r", "p", second)).toBe(false);

    clearTransfer("r", "p", first);
    clearTransfer("r", "p", second);
  });

  test("completion and acknowledgements stay scoped to one peer", () => {
    clearTransfer("r", "peer-a", "transfer");
    clearTransfer("r", "peer-b", "transfer");
    expect(markChunkAcked("r", "peer-a", "transfer", 7)).toBe(true);
    expect(markTransferComplete("r", "peer-a", "transfer")).toBe(true);
    expect(markTransferComplete("r", "peer-a", "transfer")).toBe(false);

    const a = getPeerTransferOutcome("r", "peer-a", "transfer");
    const b = getPeerTransferOutcome("r", "peer-b", "transfer");
    expect(a.complete).toBe(true);
    expect([...a.ackedChunks]).toEqual([7]);
    expect(b.complete).toBe(false);
    expect(b.ackedChunks.size).toBe(0);

    clearTransfer("r", "peer-a", "transfer");
    clearTransfer("r", "peer-b", "transfer");
  });

  test("tracks completion and waits for it", async () => {
    clearTransfer("r", "p2", "h");
    expect(isTransferComplete("r", "p2", "h")).toBe(false);
    setTimeout(() => markTransferComplete("r", "p2", "h"), 120);
    const done = await waitForCompletion("r", "p2", "h", 5000);
    expect(done).toBe(true);
    clearTransfer("r", "p2", "h");
  });

  test("waitForCompletion returns false after timeout if never complete", async () => {
    clearTransfer("r", "p3", "h");
    expect(await waitForCompletion("r", "p3", "h", 150)).toBe(false);
  });

  test("waitForCompletion stops polling after cancellation", async () => {
    clearTransfer("r", "p4", "h");
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 25);
    const start = Date.now();
    expect(
      await waitForCompletion("r", "p4", "h", 5000, controller.signal),
    ).toBe(false);
    expect(Date.now() - start).toBeLessThan(500);
    clearTransfer("r", "p4", "h");
  });

  test("getTransferAcks reports every peer edge of one transfer", () => {
    for (const peer of ["alice", "bob"]) clearTransfer("room1", peer, "t1");
    clearTransfer("room1", "alice", "t2");
    clearTransfer("room2", "alice", "t1");

    markChunkAcked("room1", "alice", "t1", 0);
    markChunkAcked("room1", "alice", "t1", 1);
    markChunkAcked("room1", "bob", "t1", 5);
    markTransferComplete("room1", "bob", "t1");
    // Same room, different send; and same send, different room. Neither may
    // leak into the answer -- a transfer ID is only unique with its room.
    markChunkAcked("room1", "alice", "t2", 9);
    markChunkAcked("room2", "alice", "t1", 9);

    const acks = getTransferAcks("room1", "t1");
    expect(acks.length).toBe(2);
    const byPeer = Object.fromEntries(acks.map((a) => [a.peerId, a]));
    expect(byPeer.alice.ackedChunks).toBe(2);
    expect(byPeer.alice.complete).toBe(false);
    expect(byPeer.bob.ackedChunks).toBe(1);
    expect(byPeer.bob.complete).toBe(true);

    for (const peer of ["alice", "bob"]) clearTransfer("room1", peer, "t1");
    clearTransfer("room1", "alice", "t2");
    clearTransfer("room2", "alice", "t1");
    expect(getTransferAcks("room1", "t1")).toEqual([]);
  });

  test("a peer id containing the separator cannot forge another edge", () => {
    // The key is roomId\u0000peerId\u0000transferId, so a peer id carrying a
    // NUL could otherwise split the key and be mis-attributed.
    clearTransfer("r", "evil\u0000t9", "t1");
    clearTransfer("r", "plain", "t1");
    markChunkAcked("r", "evil\u0000t9", "t1", 0);
    markChunkAcked("r", "plain", "t1", 0);

    const acks = getTransferAcks("r", "t1");
    expect(acks.map((a) => a.peerId).sort()).toEqual(["evil\u0000t9", "plain"]);

    clearTransfer("r", "evil\u0000t9", "t1");
    clearTransfer("r", "plain", "t1");
  });
});
