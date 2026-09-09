import { afterEach, describe, expect, test } from "bun:test";
import {
  acceptScheduledReceipt,
  acceptScheduledCancellation,
  type ScheduledReceiptDependencies,
  type ScheduledReceiptOwner,
} from "../../src/handlers/scheduledReceiptAcceptance";
import {
  clearTransfer,
  getAckedChunks,
  hasChunkAcked,
  isTransferComplete,
  isTransferCancelled,
} from "../../src/handlers/reconcile";

const owner: ScheduledReceiptOwner = {
  roomId: "selective-room",
  peerId: "selective-peer",
  peerPublicKey: "77".repeat(32),
  transferId: "88".repeat(32),
  merkleRootHex: "99".repeat(64),
};
const token = new Uint8Array(64).fill(0xaa);
const tokenHex = "aa".repeat(64);
const rootToken = new Uint8Array(64).fill(0x99);
const chunk = () => ({
  transferId: owner.transferId,
  merkleRoot: owner.merkleRootHex,
  receiptToken: tokenHex,
  chunkIndex: 3,
});
const writes: Array<ScheduledReceiptOwner & { readonly chunkIndex?: number }> =
  [];
const deps = (
  overrides: Partial<ScheduledReceiptDependencies> = {},
): ScheduledReceiptDependencies => ({
  getChunk: async (root, receipt) =>
    root === owner.merkleRootHex && receipt === tokenHex ? chunk() : undefined,
  persist: async (receipt) => {
    writes.push(receipt);
    return (
      receipt.roomId === owner.roomId &&
      receipt.peerId === owner.peerId &&
      receipt.peerPublicKey === owner.peerPublicKey
    );
  },
  ...overrides,
});
afterEach(() => {
  clearTransfer(owner.roomId, owner.peerId, owner.transferId);
  writes.length = 0;
});

describe("durable scheduled receipt acceptance", () => {
  test("a durable recipient refusal is terminal only for its scoped edge and rejects later ACKs", async () => {
    let current = true;
    let finish!: (accepted: boolean) => void;
    let cancellations = 0;
    const dependencies = deps({
      persistCancellation: () => {
        cancellations++;
        return new Promise<boolean>((resolve) => {
          finish = resolve;
        });
      },
    });
    const pending = acceptScheduledCancellation(
      owner,
      () => current,
      dependencies,
    );
    expect(
      isTransferCancelled(owner.roomId, owner.peerId, owner.transferId),
    ).toBe(false);
    finish(true);
    expect(await pending).toBe(true);
    expect(
      isTransferCancelled(owner.roomId, owner.peerId, owner.transferId),
    ).toBe(true);
    expect(
      isTransferCancelled("other-room", owner.peerId, owner.transferId),
    ).toBe(false);
    expect(
      isTransferCancelled(owner.roomId, "other-peer", owner.transferId),
    ).toBe(false);
    expect(
      isTransferCancelled(owner.roomId, owner.peerId, "other-transfer"),
    ).toBe(false);
    expect(
      await acceptScheduledCancellation(owner, () => current, dependencies),
    ).toBe(true);
    expect(cancellations).toBe(1);
    expect(
      await acceptScheduledReceipt(
        owner,
        token,
        "chunk",
        () => current,
        deps(),
      ),
    ).toBe(false);
    expect(
      await acceptScheduledReceipt(
        owner,
        rootToken,
        "terminal",
        () => current,
        deps(),
      ),
    ).toBe(false);
    expect(writes).toHaveLength(0);
    current = false;
    expect(
      await acceptScheduledCancellation(owner, () => current, dependencies),
    ).toBe(false);
  });

  test("refused or retired cancellation cannot wake the live sender", async () => {
    for (const accepted of [false, true]) {
      let current = true;
      expect(
        await acceptScheduledCancellation(
          owner,
          () => current,
          deps({
            persistCancellation: async () => {
              if (accepted) current = false;
              return accepted;
            },
          }),
        ),
      ).toBe(false);
      expect(
        isTransferCancelled(owner.roomId, owner.peerId, owner.transferId),
      ).toBe(false);
    }
  });
  test("ACK is visible only after persistence and duplicate tokens remain monotonic", async () => {
    let durable!: (accepted: boolean) => void;
    const pending = acceptScheduledReceipt(
      owner,
      token,
      "chunk",
      () => true,
      deps({
        persist: () =>
          new Promise<boolean>((resolve) => {
            durable = resolve;
          }),
      }),
    );
    for (let i = 0; i < 8 && !durable; i++) await Promise.resolve();
    expect(hasChunkAcked(owner.roomId, owner.peerId, owner.transferId, 3)).toBe(
      false,
    );
    durable(true);
    expect(await pending).toBe(true);
    expect(
      await acceptScheduledReceipt(owner, token, "chunk", () => true, deps()),
    ).toBe(true);
    expect(
      getAckedChunks(owner.roomId, owner.peerId, owner.transferId),
    ).toEqual(new Set([3]));
    expect(writes).toHaveLength(0); // replay did not need another durable write
    expect(
      isTransferComplete(owner.roomId, owner.peerId, owner.transferId),
    ).toBe(false);
  });

  test("terminal root token persists completion; chunk tokens never complete", async () => {
    expect(
      await acceptScheduledReceipt(
        owner,
        token,
        "terminal",
        () => true,
        deps(),
      ),
    ).toBe(false);
    expect(writes).toHaveLength(0);
    expect(
      await acceptScheduledReceipt(
        owner,
        rootToken,
        "terminal",
        () => true,
        deps(),
      ),
    ).toBe(true);
    expect(writes).toEqual([owner]);
    expect(
      isTransferComplete(owner.roomId, owner.peerId, owner.transferId),
    ).toBe(true);
  });

  test("room, peer identity, root, transfer and chunk index are independent admission checks", async () => {
    for (const changed of [
      { roomId: "other-room" },
      { peerId: "other-peer" },
      { peerPublicKey: "ab".repeat(32) },
      { transferId: "ab".repeat(32) },
      { merkleRootHex: "ab".repeat(64) },
    ]) {
      const other = { ...owner, ...changed };
      expect(
        await acceptScheduledReceipt(other, token, "chunk", () => true, deps()),
      ).toBe(false);
      expect(
        getAckedChunks(other.roomId, other.peerId, other.transferId).size,
      ).toBe(0);
      clearTransfer(other.roomId, other.peerId, other.transferId);
    }
    for (const changed of [
      { transferId: "other" },
      { merkleRoot: "other" },
      { receiptToken: "other" },
      { chunkIndex: -1 },
      { chunkIndex: 1.5 },
    ]) {
      expect(
        await acceptScheduledReceipt(
          owner,
          token,
          "chunk",
          () => true,
          deps({ getChunk: async () => ({ ...chunk(), ...changed }) }),
        ),
      ).toBe(false);
    }
    expect(hasChunkAcked(owner.roomId, owner.peerId, owner.transferId, 3)).toBe(
      false,
    );
  });

  test("a retired owner cannot gain live ACKs while a worker response is outstanding", async () => {
    let current = true;
    const result = await acceptScheduledReceipt(
      owner,
      token,
      "chunk",
      () => current,
      deps({
        persist: async () => {
          current = false;
          return true;
        },
      }),
    );
    expect(result).toBe(false);
    expect(hasChunkAcked(owner.roomId, owner.peerId, owner.transferId, 3)).toBe(
      false,
    );
  });

  test("failed or refused persistence never advances chunk or terminal state", async () => {
    for (const kind of ["chunk", "terminal"] as const) {
      const value = kind === "chunk" ? token : rootToken;
      expect(
        await acceptScheduledReceipt(
          owner,
          value,
          kind,
          () => true,
          deps({ persist: async () => false }),
        ),
      ).toBe(false);
      await expect(
        acceptScheduledReceipt(
          owner,
          value,
          kind,
          () => true,
          deps({
            persist: async () => {
              throw new Error("disk full");
            },
          }),
        ),
      ).rejects.toThrow("disk full");
    }
    expect(
      getAckedChunks(owner.roomId, owner.peerId, owner.transferId).size,
    ).toBe(0);
    expect(
      isTransferComplete(owner.roomId, owner.peerId, owner.transferId),
    ).toBe(false);
  });
});
