import { describe, expect, spyOn, test } from "bun:test";
import {
  discardPendingSelection,
  pendingMessageView,
  startOutboxSession,
  stopOutboxOwners,
} from "../../src/handlers/outbox";
import type { OutboxManifest, OutboxRequest } from "../../src/db/outboxTypes";

describe("outbox ownership and public cancellation boundaries", () => {
  test("a suspended tab observes expired ownership before its next wire operation", () => {
    let now = 1000;
    const clock = spyOn(Date, "now").mockImplementation(() => now);
    const session = startOutboxSession(
      { transferId: "a", owner: "tab-a", fence: 1 },
      "room-a",
      2000,
      new AbortController().signal,
      () => true,
    );
    try {
      expect(session.signal.aborted).toBe(false);
      now = 2001;
      expect(session.signal.aborted).toBe(true);
      expect(session.signal.reason.name).toBe("OutboxOwnershipLostError");
    } finally {
      session.finish();
      clock.mockRestore();
    }
  });

  test("terminal owner stop is scoped to the selected room", () => {
    const a = startOutboxSession(
      { transferId: "a", owner: "tab-a", fence: 1 },
      "room-a",
      Date.now() + 30000,
      new AbortController().signal,
      () => true,
    );
    const b = startOutboxSession(
      { transferId: "b", owner: "tab-a", fence: 1 },
      "room-b",
      Date.now() + 30000,
      new AbortController().signal,
      () => true,
    );
    try {
      stopOutboxOwners("left", "room-a");
      expect(a.signal.aborted).toBe(true);
      expect(b.signal.aborted).toBe(false);
      stopOutboxOwners("terminal signaling close");
      expect(b.signal.aborted).toBe(true);
    } finally {
      a.finish();
      b.finish();
    }
  });

  test("identity/policy revocation and explicit cancellation retain distinct reasons", () => {
    let authorized = true;
    const parent = new AbortController();
    const session = startOutboxSession(
      { transferId: "a", owner: "tab-a", fence: 1 },
      "room-a",
      Date.now() + 30000,
      parent.signal,
      () => authorized,
    );
    try {
      authorized = false;
      expect(session.signal.aborted).toBe(true);
      expect(session.signal.reason.name).toBe("OutboxOwnershipLostError");
    } finally {
      session.finish();
    }
    const explicit = new AbortController();
    const next = startOutboxSession(
      { transferId: "b", owner: "tab-a", fence: 1 },
      "room-a",
      Date.now() + 30000,
      explicit.signal,
      () => true,
    );
    try {
      const reason = new Error("Message transfer cancelled");
      explicit.abort(reason);
      expect(next.signal.reason).toBe(reason);
    } finally {
      next.finish();
    }
  });

  test("exact transfer cancellation aborts before its first database await", async () => {
    const events: string[] = [];
    await discardPendingSelection(
      { roomId: "room-a", senderPublicKey: "sender", transferId: "id-a" },
      () => events.push("abort"),
      async (request) => {
        events.push(request.kind);
        return { accepted: true };
      },
    );
    expect(events).toEqual(["abort", "remove"]);
  });

  test("ambiguous same-content deletion has no live or durable side effects", async () => {
    const requests: OutboxRequest[] = [];
    let aborted = false;
    await expect(
      discardPendingSelection(
        { roomId: "room-a", senderPublicKey: "sender", hashHex: "hash" },
        () => {
          aborted = true;
        },
        async (request) => {
          requests.push(request);
          return {
            accepted: true,
            manifests: [
              { transferId: "a", hashHex: "hash" },
              { transferId: "b", hashHex: "hash" },
            ] as OutboxManifest[],
          };
        },
      ),
    ).rejects.toThrow("ambiguous");
    expect(aborted).toBe(false);
    expect(requests.map((request) => request.kind)).toEqual(["list"]);
  });

  test("delete and cancel select one room-bound durable transfer before dropping history", async () => {
    const requests: OutboxRequest[] = [];
    await discardPendingSelection(
      { roomId: "room-a", senderPublicKey: "sender", merkleRootHex: "root-a" },
      () => undefined,
      async (request) => {
        requests.push(request);
        return {
          accepted: true,
          manifests: [
            { transferId: "a", merkleRootHex: "root-a" },
            { transferId: "b", merkleRootHex: "root-b" },
          ] as OutboxManifest[],
        };
      },
    );
    expect(requests[1]).toEqual({
      kind: "remove",
      transferId: "a",
      roomId: "room-a",
    });
  });

  test("pending UI exposes only remaining recipients and contains no owner or identity secrets", () => {
    const view = pendingMessageView({
      transferId: "a",
      roomId: "r",
      channelLabel: "chat",
      filename: "file.bin",
      totalSize: 10,
      totalChunks: 2,
      merkleRootHex: "root",
      createdAt: 10,
      updatedAt: 11,
      expiresAt: Date.now() + 30000,
      phase: "pending",
      leaseUntil: 0,
      senderPublicKey: "sender",
      identityRevision: 7n,
      owner: "tab-secret",
      recipients: [
        { peerId: "a", publicKey: "key-a", delivered: true },
        { peerId: "b", publicKey: "key-b", delivered: false, cancelled: true },
        { peerId: "c", publicKey: "key-c", delivered: false },
      ],
    } as OutboxManifest);
    expect(view.remainingRecipients).toEqual([
      { peerId: "c", publicKey: "key-c" },
    ]);
    expect(view.retryable).toBe(true);
    expect(Object.keys(view)).not.toContain("owner");
    expect(Object.keys(view)).not.toContain("identityRevision");
  });
});
