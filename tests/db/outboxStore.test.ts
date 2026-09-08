import "fake-indexeddb/auto";
import { IDBFactory } from "fake-indexeddb";
import { afterEach, beforeEach, describe, expect, spyOn, test } from "bun:test";
import { getDB } from "../../src/db/src/getDB";
import {
  executeOutbox,
  storeOutboxChunk,
  MAX_PENDING_OUTBOX,
  OUTBOX_LEASE_MS,
  OUTBOX_RETENTION_MS,
  OUTBOX_STAGING_RETENTION_MS,
} from "../../src/db/outboxStore";
import {
  DEFAULT_ROOM_POLICY_V1,
  encodeRoomPolicyV1,
} from "../../src/roomPolicy";
import { uint8ArrayToHex } from "../../src/utils/uint8array";
import type { OutboxCreate, OutboxLease } from "../../src/db/outboxTypes";
import type { NewChunk } from "../../src/db/types";

const sender = "11".repeat(32),
  recipient = "22".repeat(32),
  secondRecipient = "33".repeat(32);
const root = "aa".repeat(64),
  hash = "bb".repeat(64);
const policyHex = uint8ArrayToHex(encodeRoomPolicyV1(DEFAULT_ROOM_POLICY_V1));
let now = 1_800_000_000_000;
let clock: ReturnType<typeof spyOn>;
beforeEach(async () => {
  globalThis.indexedDB = new IDBFactory();
  now = 1_800_000_000_000;
  clock = spyOn(Date, "now").mockImplementation(() => now);
  const db = await getDB();
  await db.put(
    "meta",
    {
      version: 1,
      pub: new Uint8Array(32).fill(0x11).buffer,
      wrappedSecret: new Uint8Array(80).fill(0xcc).buffer,
      recordRevision: 1n,
    },
    "identityEd25519",
  );
  db.close();
});
afterEach(() => {
  clock.mockRestore();
});

const input = (sequence = 1): OutboxCreate => ({
  transferId: sequence.toString(16).padStart(64, "0"),
  owner: "worker-a",
  senderPublicKey: sender,
  roomId: "room-a",
  roomUrl: "44".repeat(32),
  policyHex,
  channelLabel: "chat",
  filename: "file.bin",
  totalSize: 8,
  totalChunks: 2,
  stagedBytes: 8192,
  recipients: [
    { peerId: "peer-a", publicKey: recipient },
    { peerId: "peer-b", publicKey: secondRecipient },
  ],
});
const chunk = (transferId: string, chunkIndex: number): NewChunk => ({
  transferId,
  chunkIndex,
  hash,
  merkleRoot: "",
  leafHash: "ab".repeat(64),
  receiptToken: "",
  data: new Uint8Array([1, 2, 3, 4]).buffer,
  metadata: new Uint8Array(128).buffer,
  merkleProof: new ArrayBuffer(0),
});
const create = async (sequence = 1): Promise<OutboxLease> =>
  (await executeOutbox({ kind: "create", input: input(sequence) })).lease!;
const prepare = async (sequence = 1): Promise<OutboxLease> => {
  const lease = await create(sequence);
  await storeOutboxChunk(chunk(lease.transferId, 0), lease);
  await storeOutboxChunk(chunk(lease.transferId, 1), lease);
  for (let index = 0; index < 2; index++)
    await executeOutbox({
      kind: "selfChunk",
      lease,
      chunk: {
        merkleRoot: root,
        hash,
        chunkIndex: index,
        mimeType: "application/octet-stream",
        data: new Uint8Array([1, 2, 3, 4]).buffer,
      },
    });
  await executeOutbox({
    kind: "selfMessage",
    lease,
    message: {
      roomId: "room-a",
      fromPeerId: "sender-session",
      channelLabel: "chat",
      transferId: lease.transferId,
      merkleRoot: root,
      hash,
      filename: "file.bin",
      messageType: 1,
      timestamp: now,
      savedSize: 8,
      totalSize: 8,
    },
  });
  await executeOutbox({
    kind: "publish",
    lease,
    merkleRootHex: root,
    hashHex: hash,
    chunkHashes: new Uint8Array(128).fill(0xab).buffer,
  });
  return lease;
};
const claim = (
  lease: OutboxLease,
  owner = "worker-b",
  override: Partial<OutboxCreate> = {},
) =>
  executeOutbox({
    kind: "claim",
    transferId: lease.transferId,
    owner,
    senderPublicKey: sender,
    roomId: "room-a",
    roomUrl: "44".repeat(32),
    policyHex,
    ...override,
  });

describe("durable outbox transactions across worker lifetimes", () => {
  test("partial staging cannot publish or claim, and expiration removes its bytes", async () => {
    const lease = await create();
    await storeOutboxChunk(chunk(lease.transferId, 0), lease);
    await expect(
      executeOutbox({
        kind: "publish",
        lease,
        merkleRootHex: root,
        hashHex: hash,
        chunkHashes: new Uint8Array(128).buffer,
      }),
    ).rejects.toThrow("incomplete");
    now += OUTBOX_LEASE_MS + 1;
    expect((await claim(lease)).accepted).toBe(false);
    now += OUTBOX_STAGING_RETENTION_MS;
    await executeOutbox({ kind: "sweep" });
    const db = await getDB();
    expect(await db.count("outbox")).toBe(0);
    expect(await db.count("newChunks")).toBe(0);
    expect(await db.count("outboxTrees")).toBe(0);
    db.close();
  });

  test("exhaustion releases ownership while preserving exact staged cells/tree for reload", async () => {
    const lease = await prepare();
    await executeOutbox({
      kind: "release",
      lease,
      lastError: "reconnect budget exhausted",
    });
    const resumed = await claim(lease);
    expect(resumed.accepted).toBe(true);
    expect(resumed.manifest?.merkleRootHex).toBe(root);
    expect(resumed.manifest?.lastError).toContain("exhausted");
    expect(resumed.chunkHashes).toEqual(new Uint8Array(128).fill(0xab).buffer);
    const db = await getDB();
    expect((await db.get("newChunks", [lease.transferId, 0]))?.data).toEqual(
      new Uint8Array([1, 2, 3, 4]).buffer,
    );
    const row = await db.get("outbox", lease.transferId);
    expect(Object.keys(row!)).not.toContain("secret");
    expect(Object.keys(row!)).not.toContain("pin");
    expect(Object.keys(row!)).not.toContain("chunkHashes"); // ACK writes never clone a file-sized tree.
    db.close();
  });

  test("two independent IDB claim transactions admit exactly one tab", async () => {
    const lease = await prepare();
    now += OUTBOX_LEASE_MS + 1;
    const claims = await Promise.all([
      claim(lease, "tab-b"),
      claim(lease, "tab-c"),
    ]);
    expect(claims.filter((result) => result.accepted)).toHaveLength(1);
    expect(claims.find((result) => result.accepted)?.lease?.fence).toBe(2);
    await expect(executeOutbox({ kind: "renew", lease })).rejects.toThrow(
      "ownership",
    );
    await expect(
      storeOutboxChunk(chunk(lease.transferId, 0), lease),
    ).rejects.toThrow("ownership");
    expect(
      (await executeOutbox({ kind: "list", senderPublicKey: sender }))
        .manifests,
    ).toHaveLength(1);
  });

  test("cancel fences a queued write rather than allowing orphan staging to resurrect", async () => {
    const lease = await prepare();
    let unblock!: () => void;
    const queued = new Promise<void>((resolve) => {
      unblock = resolve;
    }).then(() => storeOutboxChunk(chunk(lease.transferId, 0), lease));
    await executeOutbox({
      kind: "remove",
      transferId: lease.transferId,
      roomId: "room-a",
    });
    unblock();
    await expect(queued).rejects.toThrow("ownership");
    const db = await getDB();
    expect(await db.count("newChunks")).toBe(0);
    expect(await db.count("outbox")).toBe(0);
    db.close();
  });

  test("a stale owner cannot remove the replacement tab's committed resend source", async () => {
    const lease = await prepare();
    now += OUTBOX_LEASE_MS + 1;
    const resumed = await claim(lease);
    await executeOutbox({
      kind: "remove",
      transferId: lease.transferId,
      lease,
    });
    expect(
      (await executeOutbox({ kind: "renew", lease: resumed.lease! })).accepted,
    ).toBe(true);
    const db = await getDB();
    expect(await db.count("newChunks")).toBe(2);
    db.close();
  });

  test("room, canonical policy and durable identity revision are immutable claim bindings", async () => {
    const lease = await prepare();
    await executeOutbox({ kind: "release", lease });
    for (const override of [
      { roomId: "room-b" },
      { roomUrl: "55".repeat(32) },
      { policyHex: "00".repeat(32) },
      { senderPublicKey: recipient },
    ])
      expect((await claim(lease, "tab-b", override)).accepted).toBe(false);
    const db = await getDB();
    await db.put(
      "meta",
      {
        version: 1,
        pub: new Uint8Array(32).fill(0x11).buffer,
        wrappedSecret: new Uint8Array(80).buffer,
        recordRevision: 2n,
      },
      "identityEd25519",
    );
    db.close();
    expect((await claim(lease)).accepted).toBe(false);
    await executeOutbox({ kind: "sweep" });
    expect(
      (await executeOutbox({ kind: "list", senderPublicKey: sender }))
        .manifests,
    ).toHaveLength(0);
  });

  test("receipts persist exact recipient-scoped bits and idempotent per-peer completion", async () => {
    const lease = await prepare();
    const receipt = {
      transferId: lease.transferId,
      roomId: "room-a",
      peerId: "new-session-a",
      peerPublicKey: recipient,
      merkleRootHex: root,
      chunkIndex: 1,
    };
    expect(
      (
        await executeOutbox({
          kind: "receipt",
          receipt: { ...receipt, peerPublicKey: "55".repeat(32) },
        })
      ).accepted,
    ).toBe(false);
    expect(
      (
        await executeOutbox({
          kind: "receipt",
          receipt: { ...receipt, merkleRootHex: hash },
        })
      ).accepted,
    ).toBe(false);
    expect(
      (
        await executeOutbox({
          kind: "receipt",
          receipt: { ...receipt, chunkIndex: 2 },
        })
      ).accepted,
    ).toBe(false);
    await executeOutbox({ kind: "receipt", receipt });
    await executeOutbox({ kind: "receipt", receipt });
    await executeOutbox({
      kind: "receipt",
      receipt: { ...receipt, chunkIndex: undefined },
    });
    await executeOutbox({
      kind: "receipt",
      receipt: { ...receipt, chunkIndex: undefined },
    });
    await executeOutbox({ kind: "release", lease });
    const resumed = await claim(lease);
    expect(resumed.acknowledgments).toHaveLength(1);
    expect(resumed.acknowledgments?.[0].bitmap).toEqual(new Uint8Array([2]));
    expect(resumed.manifest?.recipients).toEqual([
      { publicKey: recipient, peerId: "new-session-a", delivered: true },
      { publicKey: secondRecipient, peerId: "peer-b", delivered: false },
    ]);
  });

  test("all-peer completion releases resend bytes but keeps the local completed history", async () => {
    const lease = await prepare();
    const db = await getDB();
    await db.put("chunks", {
      merkleRoot: root,
      hash,
      chunkIndex: 0,
      mimeType: "application/octet-stream",
      data: new Uint8Array([9]).buffer,
    });
    db.close();
    for (const peerPublicKey of [recipient, secondRecipient])
      await executeOutbox({
        kind: "receipt",
        receipt: {
          roomId: "room-a",
          peerId: "peer-a",
          peerPublicKey,
          transferId: lease.transferId,
          merkleRootHex: root,
        },
      });
    await executeOutbox({ kind: "release", lease });
    const after = await getDB();
    expect(await after.count("outbox")).toBe(0);
    expect(await after.count("outboxTrees")).toBe(0);
    expect(await after.count("newChunks")).toBe(0);
    expect(await after.count("chunks")).toBe(2);
    after.close();
  });

  test("expiry skips a live owner, then collects its expired pending payload after release", async () => {
    const lease = await prepare();
    now += OUTBOX_RETENTION_MS + 1;
    // Simulate an owner that renewed throughout a long scheduled send without
    // waiting a day in the test. Expiry and active ownership are independent.
    const db = await getDB();
    const row = (await db.get("outbox", lease.transferId))!;
    await db.put("outbox", { ...row, leaseUntil: now + OUTBOX_LEASE_MS });
    db.close();
    await executeOutbox({ kind: "sweep" });
    const during = await getDB();
    expect(await during.count("newChunks")).toBe(2);
    during.close();
    await executeOutbox({ kind: "release", lease });
    await executeOutbox({ kind: "sweep" });
    const after = await getDB();
    expect(await after.count("newChunks")).toBe(0);
    after.close();
  });

  test("bounded admission rejects excess work without evicting a pending transfer", async () => {
    for (let i = 1; i <= MAX_PENDING_OUTBOX; i++) await create(i);
    await expect(create(MAX_PENDING_OUTBOX + 1)).rejects.toThrow(
      "budget exhausted",
    );
    const db = await getDB();
    expect(await db.count("outbox")).toBe(MAX_PENDING_OUTBOX);
    db.close();
  });

  test("actual padded bytes cannot exceed the reservation even with a small advertised file", async () => {
    const lease = await create();
    await expect(
      storeOutboxChunk(
        { ...chunk(lease.transferId, 0), data: new Uint8Array(8192).buffer },
        lease,
      ),
    ).rejects.toThrow("reservation");
    const db = await getDB();
    expect(await db.count("newChunks")).toBe(0);
    expect((await db.get("outbox", lease.transferId))?.writtenBytes).toBe(0);
    db.close();
  });

  test("queued sender self-copy and metadata commits are fenced after cancellation", async () => {
    const lease = await create();
    const selfChunk = {
      merkleRoot: root,
      hash,
      chunkIndex: 0,
      mimeType: "text/plain",
      data: new Uint8Array([1, 2, 3, 4]).buffer,
    };
    await executeOutbox({ kind: "selfChunk", lease, chunk: selfChunk });
    await executeOutbox({ kind: "remove", transferId: lease.transferId });
    await expect(
      executeOutbox({
        kind: "selfChunk",
        lease,
        chunk: { ...selfChunk, chunkIndex: 1 },
      }),
    ).rejects.toThrow("ownership");
    await expect(
      executeOutbox({
        kind: "selfMessage",
        lease,
        message: {
          roomId: "room-a",
          fromPeerId: "sender-session",
          channelLabel: "chat",
          transferId: lease.transferId,
          merkleRoot: root,
          hash,
          filename: "file.bin",
          messageType: 1,
          timestamp: now,
          savedSize: 8,
          totalSize: 8,
        },
      }),
    ).rejects.toThrow("ownership");
    const db = await getDB();
    expect(await db.count("chunks")).toBe(0);
    expect(await db.count("messageData")).toBe(0);
    db.close();
  });

  test("a recipient's explicit refusal is durable and does not mark it delivered or cancel the other peer", async () => {
    const lease = await prepare();
    await executeOutbox({
      kind: "receipt",
      receipt: {
        roomId: "room-a",
        peerId: "peer-a",
        peerPublicKey: recipient,
        transferId: lease.transferId,
        merkleRootHex: root,
        cancelled: true,
      },
    });
    await executeOutbox({ kind: "release", lease });
    const resumed = await claim(lease);
    expect(resumed.manifest?.recipients[0]).toMatchObject({
      publicKey: recipient,
      cancelled: true,
      delivered: false,
    });
    expect(resumed.manifest?.recipients[1]).toEqual({
      publicKey: secondRecipient,
      peerId: "peer-b",
      delivered: false,
    });
  });

  test("same transfer id in another room cannot be cancelled through a mismatched room selector", async () => {
    const lease = await prepare();
    await executeOutbox({
      kind: "remove",
      transferId: lease.transferId,
      roomId: "other-room",
    });
    expect((await executeOutbox({ kind: "renew", lease })).accepted).toBe(true);
  });
});
