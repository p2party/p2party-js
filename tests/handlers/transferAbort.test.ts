import { describe, expect, test } from "bun:test";

import {
  abortAllTransfers,
  abortRoomTransfers,
  abortTransfer,
  beginTransfer,
  claimTransfer,
  createTransferId,
  isRemoteCancelClose,
  throwIfTransferAborted,
  waitWithTransferAbort,
} from "../../src/handlers/transferAbort";

describe("message-scoped transfer cancellation", () => {
  test("an authenticated channel close deletes only that peer's incomplete receive", () => {
    const partial = {
      fromPeerId: "peer-a",
      savedSize: 10,
      totalSize: 20,
    };
    expect(isRemoteCancelClose(partial, "peer-a", true)).toBe(true);
    expect(isRemoteCancelClose(partial, "peer-b", true)).toBe(false);
    expect(isRemoteCancelClose(partial, "peer-a", false)).toBe(false);
    expect(
      isRemoteCancelClose({ ...partial, savedSize: 20 }, "peer-a", true),
    ).toBe(false);
  });

  test("allocates independent random 32-byte transfer IDs", () => {
    const first = createTransferId();
    const second = createTransferId();
    expect(first).toMatch(/^[0-9a-f]{64}$/);
    expect(second).toMatch(/^[0-9a-f]{64}$/);
    expect(first).not.toBe(second);
  });

  test("cancels only the selected room/message", () => {
    const first = beginTransfer("room-a");
    const second = beginTransfer("room-a");
    const otherRoom = beginTransfer("room-b");
    first.bindHash("11".repeat(64));
    second.bindHash("22".repeat(64));
    otherRoom.bindHash("11".repeat(64));

    expect(
      abortTransfer("room-a", { hashHex: "11".repeat(64) }),
    ).toBe(1);
    expect(first.signal.aborted).toBe(true);
    expect(second.signal.aborted).toBe(false);
    expect(otherRoom.signal.aborted).toBe(false);
    expect(() => throwIfTransferAborted(first.signal)).toThrow("cancelled");

    first.finish();
    second.finish();
    otherRoom.finish();
  });

  test("binds a Merkle root later and supports room/all teardown", () => {
    const first = beginTransfer("room-c");
    const second = beginTransfer("room-c");
    const third = beginTransfer("room-d");
    first.bindMerkleRoot("aa".repeat(64));

    expect(
      abortTransfer("room-c", { merkleRootHex: "aa".repeat(64) }),
    ).toBe(1);
    expect(first.signal.aborted).toBe(true);
    expect(second.signal.aborted).toBe(false);
    expect(abortRoomTransfers("room-c")).toBe(2);
    expect(second.signal.aborted).toBe(true);
    expect(abortAllTransfers()).toBe(3);
    expect(third.signal.aborted).toBe(true);

    first.finish();
    second.finish();
    third.finish();
  });

  test("interrupts an otherwise pending wait", async () => {
    const transfer = beginTransfer("room-e");
    transfer.bindHash("33".repeat(64));
    const pending = waitWithTransferAbort(
      new Promise<void>(() => {}),
      transfer.signal,
    );
    abortTransfer("room-e", { hashHex: "33".repeat(64) });
    await expect(pending).rejects.toThrow("cancelled");
    transfer.finish();
  });

  test("identical content hashes remain independently cancellable", () => {
    const transferIdA = "aa".repeat(32);
    const transferIdB = "bb".repeat(32);
    const first = beginTransfer("room-f", transferIdA);
    const second = beginTransfer("room-f", transferIdB);
    first.bindHash("44".repeat(64));
    second.bindHash("44".repeat(64));

    expect(() =>
      abortTransfer("room-f", { hashHex: "44".repeat(64) }),
    ).toThrow("ambiguous");
    expect(first.signal.aborted).toBe(false);
    expect(second.signal.aborted).toBe(false);

    expect(abortTransfer("room-f", { transferId: transferIdA })).toBe(1);
    expect(first.signal.aborted).toBe(true);
    expect(second.signal.aborted).toBe(false);

    first.finish();
    second.finish();
  });

  test("public registration is claimable by the async send pipeline", () => {
    const transferId = "cc".repeat(32);
    const publicHandle = beginTransfer("room-g", transferId);
    const pipelineHandle = claimTransfer("room-g", transferId);
    abortTransfer("room-g", { transferId });

    expect(publicHandle.signal).toBe(pipelineHandle.signal);
    expect(pipelineHandle.signal.aborted).toBe(true);
    pipelineHandle.finish();
    publicHandle.finish();
  });
});
