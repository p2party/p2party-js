import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  mock,
  test,
} from "bun:test";

import { expectDatabaseCall } from "../support/databaseCall";
import { loadTestModule } from "../../src/cryptography/testModule";
import { getMerkleRoot } from "../../src/cryptography/merkle";
import { initRatchet } from "../../src/cryptography/ratchet";
import { crypto_hash_sha512_BYTES } from "../../src/cryptography/interfaces";
import { SparsePqHealingState } from "../../src/handlers/pqHealingRuntime";
import { hashMerkleLeafWasm } from "../../src/utils/leafHash";
import { serializeMetadata } from "../../src/utils/metadata";
import { MessageType } from "../../src/utils/messageTypes";
import { uint8ArrayToHex } from "../../src/utils/uint8array";
import {
  CHUNK_LEN,
  RATCHET_ROOT_SUITE_MLKEM512,
  WIRE_CHUNK_FRAME_LEN,
} from "../../src/utils/constants";
import {
  DEFAULT_ROOM_POLICY_V1,
  encodeRoomPolicyV1,
  type RoomPolicyV1,
} from "../../src/roomPolicy";

import type { LibCrypto } from "../../src/cryptography/libcrypto";
import type { IRTCPeerConnection } from "../../src/api/webrtc/interfaces";
import type { CoverJob, CoverJobSlot } from "../../src/handlers/coverScheduler";
import type { CoverRuntime } from "../../src/handlers/coverRuntime";
import type { NewChunk } from "../../src/db/types";
import type {
  OutboxManifest,
  OutboxRequest,
  OutboxResponse,
} from "../../src/db/outboxTypes";
import type { BaseQueryApi } from "@reduxjs/toolkit/query";

// handleSendMessage reaches the Redux store, whose keyPair slice reads
// localStorage at module initialisation.
const localStorageMemory: Record<string, string> = {};
(globalThis as unknown as { localStorage?: Storage }).localStorage ??= {
  getItem: (key: string) =>
    key in localStorageMemory ? localStorageMemory[key] : null,
  setItem: (key: string, value: string) => {
    localStorageMemory[key] = String(value);
  },
  removeItem: (key: string) => {
    delete localStorageMemory[key];
  },
  clear: () => {
    for (const key of Object.keys(localStorageMemory))
      delete localStorageMemory[key];
  },
  key: () => null,
  length: 0,
} as Storage;

// The DB worker bundle is not inlined in a unit run, so every worker call
// rejects. Stand in for the outbox, the staged cells and the ratchet row while
// a test is armed; otherwise every call reaches the real module, so other test
// files see no change. Everything else on the send path is the real code.
const realDb = { ...(await import("../../src/db/api")) };
const db: {
  armed: boolean;
  rows: Map<number, NewChunk>;
  claim?: OutboxResponse;
  requests: string[];
  reads: number;
} = { armed: false, rows: new Map(), requests: [], reads: 0 };

mock.module("../../src/db/api", () => ({
  ...realDb,
  outboxRequest: async (request: OutboxRequest): Promise<OutboxResponse> => {
    if (!db.armed) return await realDb.outboxRequest(request);
    db.requests.push(request.kind);
    if (request.kind === "claim") return db.claim!;
    return { accepted: true, manifest: db.claim!.manifest };
  },
  getDBNewChunk: async (transferId: string, chunkIndex: number) => {
    if (!db.armed) return await realDb.getDBNewChunk(transferId, chunkIndex);
    db.reads++;
    const row = db.rows.get(chunkIndex);
    return row ? structuredClone(row) : undefined;
  },
  setDBNewChunk: async (
    chunk: NewChunk,
    lease?: Parameters<typeof realDb.setDBNewChunk>[1],
  ) => {
    if (!db.armed) return await realDb.setDBNewChunk(chunk, lease);
    db.rows.set(chunk.chunkIndex, structuredClone(chunk));
  },
}));

afterAll(() => {
  mock.module("../../src/db/api", () => realDb);
});

type SendModule = typeof import("../../src/handlers/handleSendMessage");
let handleSendMessage: SendModule["handleSendMessage"];
let claimRatchetGate: (typeof import("../../src/handlers/ratchetGate"))["claimRatchetGate"];
let openRatchetGate: (typeof import("../../src/handlers/ratchetGate"))["openRatchetGate"];
let resetRatchetGate: (typeof import("../../src/handlers/ratchetGate"))["resetRatchetGate"];
let claimRatchetGeneration: (typeof import("../../src/handlers/ratchetPersist"))["claimRatchetGeneration"];
let markTransferComplete: (typeof import("../../src/handlers/reconcile"))["markTransferComplete"];
let clearTransfer: (typeof import("../../src/handlers/reconcile"))["clearTransfer"];

let module: LibCrypto;

beforeAll(async () => {
  module = await loadTestModule();
  await import("../../src/store");
  ({ handleSendMessage } =
    await import("../../src/handlers/handleSendMessage"));
  ({ claimRatchetGate, openRatchetGate, resetRatchetGate } =
    await import("../../src/handlers/ratchetGate"));
  ({ claimRatchetGeneration } =
    await import("../../src/handlers/ratchetPersist"));
  ({ markTransferComplete, clearTransfer } =
    await import("../../src/handlers/reconcile"));
});

const ROOM = "room-a4-e2e";
const PEER = "peer-a4-e2e";
const PEER_PUBLIC_KEY = "bb".repeat(32);
const SELF_PUBLIC_KEY = "cc".repeat(32);
const TRANSFER_ID = "e2".repeat(32);
const HASH_HEX = "e3".repeat(64);

const rand = (n: number): Uint8Array =>
  crypto.getRandomValues(new Uint8Array(n));

const cleanups: (() => void)[] = [];
afterEach(() => {
  while (cleanups.length > 0) cleanups.pop()?.();
  db.armed = false;
  db.rows.clear();
  db.requests = [];
  db.reads = 0;
  db.claim = undefined;
  clearTransfer(ROOM, PEER, TRANSFER_ID);
  resetRatchetGate(ROOM, PEER);
});

// Cadence far longer than the test, so the delivery wait never times out.
const policy: RoomPolicyV1 = {
  ...DEFAULT_ROOM_POLICY_V1,
  coverMode: "scheduled",
  coverCadenceMs: 600_000,
  coverLanes: 2,
  coverFramesPerCell: 2,
  coverDurationEpochs: 1,
};

const countingModule = () => {
  const counts = { sha512Init: 0 };
  const counted = new Proxy(module, {
    get(object, property, receiver) {
      if (property === "_sha512_init")
        return (state: number) => {
          counts.sha512Init++;
          return object._sha512_init(state);
        };
      return Reflect.get(object, property, receiver) as unknown;
    },
  });
  return { module: counted, counts };
};

/** Stage a pending message in the stand-in outbox, as a reload finds it. */
const stagePendingMessage = async (
  totalChunks: number,
): Promise<{ merkleRootHex: string }> => {
  const totalSize = totalChunks * 100;
  const hash = rand(crypto_hash_sha512_BYTES);
  const leaves = new Uint8Array(totalChunks * crypto_hash_sha512_BYTES);
  for (let i = 0; i < totalChunks; i++) {
    const data = rand(CHUNK_LEN);
    const leaf = hashMerkleLeafWasm(data, module);
    leaves.set(leaf, i * crypto_hash_sha512_BYTES);
    db.rows.set(i, {
      transferId: TRANSFER_ID,
      hash: HASH_HEX,
      merkleRoot: "",
      chunkIndex: i,
      leafHash: uint8ArrayToHex(leaf),
      receiptToken: "",
      data: data.buffer as ArrayBuffer,
      metadata: serializeMetadata({
        schemaVersion: 1,
        messageType: MessageType.Text,
        hash,
        name: "a4",
        totalSize,
        date: new Date(0),
        chunkStartIndex: 10,
        chunkEndIndex: 110,
        chunkIndex: i,
      }).buffer as ArrayBuffer,
      merkleProof: new ArrayBuffer(0),
    });
  }
  const merkleRootHex = uint8ArrayToHex(await getMerkleRoot(leaves, module));
  const now = Date.now();
  const manifest: OutboxManifest = {
    transferId: TRANSFER_ID,
    senderPublicKey: SELF_PUBLIC_KEY,
    identityRevision: 0n,
    roomId: ROOM,
    roomUrl: "dd".repeat(32),
    policyHex: uint8ArrayToHex(encodeRoomPolicyV1(policy)),
    channelLabel: "chat",
    filename: "a4",
    totalSize,
    totalChunks,
    stagedBytes: totalChunks * 70_000,
    writtenBytes: totalChunks * 70_000,
    localBytes: totalSize,
    createdAt: now,
    updatedAt: now,
    expiresAt: now + 86_400_000,
    phase: "pending",
    merkleRootHex,
    hashHex: HASH_HEX,
    recipients: [
      { peerId: PEER, publicKey: PEER_PUBLIC_KEY, delivered: false },
    ],
    owner: "owner",
    fence: 1,
    leaseUntil: now + 600_000,
  };
  db.claim = {
    accepted: true,
    manifest,
    lease: { transferId: TRANSFER_ID, owner: "owner", fence: 1 },
    chunkHashes: leaves.slice().buffer as ArrayBuffer,
    acknowledgments: [],
  };
  return { merkleRootHex };
};

const fakeApi = (): BaseQueryApi =>
  ({
    dispatch: () => undefined,
    getState: () => ({
      keyPair: { publicKey: SELF_PUBLIC_KEY, peerId: "self" },
      rooms: [
        {
          id: ROOM,
          url: "dd".repeat(32),
          signalingActive: true,
          policy,
          channels: [],
          peers: [{ peerId: PEER, peerPublicKey: PEER_PUBLIC_KEY }],
          knownPeers: [],
          messages: [],
        },
      ],
    }),
  }) as unknown as BaseQueryApi;

/** An authenticated scheduled edge whose cover runtime hands its job over. */
const scheduledEdge = (): {
  epc: IRTCPeerConnection;
  enqueued: Promise<CoverJob>;
} => {
  let deliverJob!: (job: CoverJob) => void;
  const enqueued = new Promise<CoverJob>((resolve) => {
    deliverJob = resolve;
  });
  const runtime = {
    status: "active",
    cellsPerLanePerCycle: () => 1_000_000,
    enqueue: (job: CoverJob) => {
      deliverJob(job);
    },
    onJobSettled: () => undefined,
    complete: () => undefined,
    cancel: () => "cancel-pending" as const,
    getJobProgress: () => undefined,
  } as unknown as CoverRuntime;
  const pq = new SparsePqHealingState({
    module,
    pqMode: "hybrid-mlkem512",
    rootSuite: RATCHET_ROOT_SUITE_MLKEM512,
    binding: new Uint8Array(32).fill(0x42),
    rootKey: new Uint8Array(32).fill(0x19),
    nextOfferer: "local",
    amInitiator: true,
    now: 0,
  });
  cleanups.push(() => {
    pq.destroy();
  });
  const epc = {
    roomId: ROOM,
    withPeerId: PEER,
    withPeerPublicKey: PEER_PUBLIC_KEY,
    connectionState: "connected",
    pqHealingState: pq,
    ratchetState: initRatchet(
      rand(32),
      true,
      initRatchet(rand(32), false, null, module).dhSelfPub,
      module,
    ),
    coverRuntime: runtime,
  } as unknown as IRTCPeerConnection;
  const lease = claimRatchetGate(ROOM, PEER);
  openRatchetGate(ROOM, PEER, lease);
  epc.ratchetGateLease = lease;
  claimRatchetGeneration(epc, ROOM);
  return { epc, enqueued };
};

describe("handleSendMessage closes the message's proof levels when the delivery settles", () => {
  test("an unarmed chunk read reaches the real database client", async () => {
    const transfer = "ef".repeat(32);
    const api = await import("../../src/db/api");
    await expectDatabaseCall("getDBNewChunk", [transfer, 7], () =>
      api.getDBNewChunk(transfer, 7),
    );
  });

  test("after the receiver's final receipt nothing reads, rebuilds or seals another cell", async () => {
    const totalChunks = 6;
    const { merkleRootHex } = await stagePendingMessage(totalChunks);
    db.armed = true;
    const { epc, enqueued } = scheduledEdge();
    const { module: merkleModule, counts } = countingModule();

    // A resume after a reload: no data, the outbox claim supplies the leaves.
    const sending = handleSendMessage(
      undefined,
      fakeApi(),
      "chat",
      ROOM,
      [epc],
      [],
      module,
      merkleModule,
      TRANSFER_ID,
    );

    const job = await enqueued;
    const slot = {} as CoverJobSlot;
    const first = await job.nextCell(slot);
    const second = await job.nextCell(slot);
    expect(first?.length).toBe(WIRE_CHUNK_FRAME_LEN);
    expect(second?.length).toBe(WIRE_CHUNK_FRAME_LEN);
    // The leaves came from the claim and were built into levels once.
    expect(counts.sha512Init).toBe(totalChunks - 1);

    // The receiver's terminal receipt settles the scheduled delivery.
    markTransferComplete(ROOM, PEER, TRANSFER_ID);
    const result = await sending;
    expect(result?.merkleRootHex).toBe(merkleRootHex);
    expect(result?.outcomes).toEqual([{ peerId: PEER, status: "delivered" }]);
    expect(db.requests).toContain("release");

    // The job is still held by the runtime (a delivered job is not settled by
    // the sender). Asked for a cell now, it has nothing to send: no read, no
    // rebuild, no sealed frame.
    const readsBefore = db.reads;
    expect(await job.nextCell(slot)).toBeNull();
    expect(db.reads).toBe(readsBefore);
    expect(counts.sha512Init).toBe(totalChunks - 1);
  });
});
