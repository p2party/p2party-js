import { afterEach, beforeAll, describe, expect, test } from "bun:test";

import { loadTestModule } from "../../src/cryptography/testModule";
import {
  getMerkleRoot,
  verifyMerkleProof,
} from "../../src/cryptography/merkle";
import { crypto_hash_sha512_BYTES } from "../../src/cryptography/interfaces";
import { CoverRuntime } from "../../src/handlers/coverRuntime";
import { buildScheduledSendJob } from "../../src/handlers/coverTransfer";
import { createMessageChunkSealer } from "../../src/handlers/messageChunkCrypto";
import { SparsePqHealingState } from "../../src/handlers/pqHealingRuntime";
import { compileChannelMessageLabel } from "../../src/utils/channelLabel";
import { hashMerkleLeafWasm } from "../../src/utils/leafHash";
import { createChunkReceiptToken } from "../../src/utils/receiptToken";
import {
  deserializeMetadata,
  serializeMetadata,
} from "../../src/utils/metadata";
import { MessageType } from "../../src/utils/messageTypes";
import { uint8ArrayToHex } from "../../src/utils/uint8array";
import * as constants from "../../src/utils/constants";
import {
  CHUNK_LEN,
  DECRYPTED_LEN,
  FRAME_TYPE_CHUNK,
  FRAME_TYPE_COVER,
  METADATA_LEN,
  PROOF_LEN,
  RATCHET_ROOT_SUITE_MLKEM512,
} from "../../src/utils/constants";
import { CoverTimeline } from "./coverTimerFakes";

import type { LibCrypto } from "../../src/cryptography/libcrypto";
import type { IRTCPeerConnection } from "../../src/api/webrtc/interfaces";
import type { CoverLaneChannel } from "../../src/handlers/coverRuntime";
import type { CoverSchedulerStatus } from "../../src/handlers/coverScheduler";
import type { NewChunk } from "../../src/db/types";

// The proof levels of an outgoing message are built once, on its first cell
// without a stored proof: N − 1 hashes, about 2.5 µs each in Chromium (3.9 s
// for 1,600,000 leaves in one call before this, docs/e2e/cover-timers/). Here
// the build's clock is one only its own hashes move, so how long it holds the
// thread, and what a cover slot due meanwhile does, are exact.

// handleSendMessage reaches the Redux store, whose keyPair slice reads
// localStorage at module initialisation (same preamble as
// outboundMessage.test.ts).
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

type SendModule = typeof import("../../src/handlers/handleSendMessage");
let OutboundMessage: SendModule["OutboundMessage"];
let makeScheduledSlotSealer: SendModule["makeScheduledSlotSealer"];
type Message = InstanceType<SendModule["OutboundMessage"]>;

let module: LibCrypto;
beforeAll(async () => {
  module = await loadTestModule();
  await import("../../src/store");
  ({ OutboundMessage, makeScheduledSlotSealer } =
    await import("../../src/handlers/handleSendMessage"));
});

// Read at run time, so this file loads where the constant is not defined.
const SLICE_MS = (constants as Record<string, unknown>)
  .PROOF_LEVEL_BUILD_SLICE_MS as number;

const TRANSFER_ID = "a4b".repeat(21) + "0";
const HASH_HEX = "4b".repeat(64);

const rand = (n: number): Uint8Array =>
  crypto.getRandomValues(new Uint8Array(n));

const cleanups: (() => void)[] = [];
afterEach(() => {
  while (cleanups.length > 0) cleanups.pop()?.();
});

/**
 * A message of `leafCount` cells whose first `staged` rows are in the store
 * (the rest are leaves only: nothing reads them but the build). With
 * `withTokens` its rows already carry their receipt tokens, as a re-send's
 * do, so producing a cell awaits nothing but the build and the store.
 */
const stageMessage = async (
  leafCount: number,
  staged = leafCount,
  withTokens = false,
) => {
  const hash = rand(crypto_hash_sha512_BYTES);
  const leaves = rand(leafCount * crypto_hash_sha512_BYTES);
  const rows = new Map<number, NewChunk>();
  for (let index = 0; index < staged; index++) {
    const data = rand(CHUNK_LEN);
    const leaf = hashMerkleLeafWasm(data, module);
    leaves.set(leaf, index * crypto_hash_sha512_BYTES);
    rows.set(index, {
      transferId: TRANSFER_ID,
      hash: HASH_HEX,
      merkleRoot: "",
      chunkIndex: index,
      leafHash: uint8ArrayToHex(leaf),
      receiptToken: "",
      data: data.buffer as ArrayBuffer,
      metadata: serializeMetadata({
        schemaVersion: 1,
        messageType: MessageType.Text,
        hash,
        name: "a4b",
        totalSize: leafCount * 100,
        date: new Date(0),
        chunkStartIndex: 10,
        chunkEndIndex: 110,
        chunkIndex: index,
      }).buffer as ArrayBuffer,
      merkleProof: new ArrayBuffer(0),
    });
  }
  const merkleRoot = await getMerkleRoot(leaves, module);
  if (withTokens)
    for (const row of rows.values()) {
      row.merkleRoot = uint8ArrayToHex(merkleRoot);
      row.receiptToken = uint8ArrayToHex(
        await createChunkReceiptToken(
          merkleRoot,
          row.chunkIndex,
          hashMerkleLeafWasm(new Uint8Array(row.data), module),
        ),
      );
    }
  return {
    leaves,
    merkleRoot,
    store: {
      get: async (_transferId: string, index: number) => {
        await Promise.resolve();
        const row = rows.get(index);
        return row ? structuredClone(row) : undefined;
      },
      put: async (chunk: NewChunk) => {
        await Promise.resolve();
        rows.set(chunk.chunkIndex, structuredClone(chunk));
      },
    },
  };
};

/**
 * The module with its node hashes counted, and the build's clock: each hash
 * costs `costMs` of it, and nothing else moves it. `onHash` runs before each.
 */
const countingBuild = (costMs: number, onHash?: (hashes: number) => void) => {
  const state = { now: 0, hashes: 0 };
  const counted = new Proxy(module, {
    get(object, property, receiver) {
      if (property === "_sha512_init")
        return (statePtr: number) => {
          onHash?.(state.hashes);
          state.hashes++;
          state.now += costMs;
          return object._sha512_init(statePtr);
        };
      return Reflect.get(object, property, receiver) as unknown;
    },
  });
  return { module: counted, state, now: () => state.now };
};

/** Hand-backs between slices that the test releases one at a time. */
const manualHandBacks = () => {
  const waiting: (() => void)[] = [];
  let taken = 0;
  return {
    yieldToEventLoop: (): Promise<void> =>
      new Promise((resolve) => {
        taken++;
        waiting.push(resolve);
      }),
    get pending(): number {
      return waiting.length;
    },
    get taken(): number {
      return taken;
    },
    release: (): void => {
      waiting.shift()?.();
    },
  };
};

/** Event-loop turns until `ready()`; a bounded count, never a wall clock. */
const turnsUntil = async (ready: () => boolean): Promise<void> => {
  for (let turn = 0; !ready(); turn++) {
    if (turn > 10_000) throw new Error("never became ready");
    await new Promise((resolve) => setImmediate(resolve));
  }
};

/**
 * How `promise` settled, waited for over a bounded number of turns: a cell
 * still waiting on a build nobody drives fails the test instead of hanging it.
 */
const outcome = async <T>(
  promise: Promise<T>,
): Promise<{ readonly value?: T; readonly error?: unknown }> => {
  let settled: { value?: T; error?: unknown } | undefined;
  promise.then(
    (value) => {
      settled = { value };
    },
    (error: unknown) => {
      settled = { error };
    },
  );
  await turnsUntil(() => settled !== undefined);
  return settled!;
};

/** The error `promise` was rejected with; a failure if it resolved. */
const rejection = async (promise: Promise<unknown>): Promise<Error> => {
  const { error } = await outcome(promise);
  expect(error).toBeInstanceOf(Error);
  return error as Error;
};

/** Release hand-backs until every promise has settled. */
const driveUntilSettled = async (
  handBacks: ReturnType<typeof manualHandBacks>,
  promises: readonly Promise<unknown>[],
): Promise<void> => {
  let settled = 0;
  for (const promise of promises)
    promise.then(
      () => settled++,
      () => settled++,
    );
  await turnsUntil(() => {
    if (settled === promises.length) return true;
    handBacks.release();
    return false;
  });
};

/** A cell's proof, as the receiver reads it, verified against the root. */
const proofVerifies = async (
  cell: Uint8Array,
  data: Uint8Array,
  merkleRoot: Uint8Array,
): Promise<boolean> => {
  expect(cell.length).toBe(DECRYPTED_LEN);
  const framed = cell.subarray(METADATA_LEN, METADATA_LEN + PROOF_LEN);
  const length = new DataView(framed.buffer, framed.byteOffset, 4).getUint32(
    0,
    false,
  );
  return verifyMerkleProof(
    data,
    merkleRoot,
    framed.slice(4, 4 + length),
    module,
  );
};

const messageOver = (
  staged: Awaited<ReturnType<typeof stageMessage>>,
  build: ReturnType<typeof countingBuild>,
  handBacks: ReturnType<typeof manualHandBacks>,
  leaves: Uint8Array = staged.leaves,
): Message => {
  const message = new OutboundMessage({
    transferId: TRANSFER_ID,
    hashHex: HASH_HEX,
    merkleRoot: staged.merkleRoot,
    totalChunks: leaves.length / crypto_hash_sha512_BYTES,
    chunkHashes: leaves,
    merkleModule: build.module,
    store: staged.store,
    proofLevelBuild: {
      now: build.now,
      yieldToEventLoop: handBacks.yieldToEventLoop,
    },
  });
  cleanups.push(() => {
    message.close();
  });
  return message;
};

describe("the proof-level build of an outgoing message runs in slices", () => {
  test("cells of one delivery that ask during the build share it", async () => {
    const leafCount = 41;
    // Calculate receipt tokens before the test starts advancing build slices.
    const staged = await stageMessage(leafCount, 18, true);
    // Two hashes a slice: 40 hashes, 20 slices.
    const build = countingBuild(SLICE_MS / 2);
    const handBacks = manualHandBacks();
    const message = messageOver(staged, build, handBacks);

    const first = await message.read(3);
    const asked = [message.cellPlaintext(first!)];
    await turnsUntil(() => handBacks.pending === 1);
    // The build is under way: one slice done, its levels so far held.
    expect(build.state.hashes).toBe(2);
    expect(message.proofLevelBytes).toBeGreaterThan(0);
    // Another cell, and the same cell for another peer, ask meanwhile.
    const second = await message.read(17);
    const again = await message.read(3);
    asked.push(message.cellPlaintext(second!), message.cellPlaintext(again!));
    await driveUntilSettled(handBacks, asked);

    const cells = await Promise.all(
      asked.map(async (cell) => (await outcome(cell)).value!),
    );
    // One build for all three: N − 1 hashes in 20 slices.
    expect(build.state.hashes).toBe(leafCount - 1);
    expect(handBacks.taken).toBe(19);
    const dataOf = (cell: Uint8Array) =>
      cell.subarray(METADATA_LEN + PROOF_LEN);
    for (const [cell, index] of [
      [cells[0], 3],
      [cells[1], 17],
      [cells[2], 3],
    ] as const) {
      expect(
        deserializeMetadata(cell.subarray(0, METADATA_LEN)).chunkIndex,
      ).toBe(index);
      expect(await proofVerifies(cell, dataOf(cell), staged.merkleRoot)).toBe(
        true,
      );
    }
  });

  test("closing a delivery during the build stops it and releases the levels", async () => {
    const leafCount = 41;
    const staged = await stageMessage(leafCount);
    const build = countingBuild(SLICE_MS / 2);
    const handBacks = manualHandBacks();
    const message = messageOver(staged, build, handBacks);
    const slot = makeScheduledSlotSealer(
      message,
      {
        seal: () => {
          throw new Error("nothing is sealed after the delivery ended");
        },
        wipe: () => undefined,
      },
      () => false,
    );

    const first = await message.read(0);
    const producing = message.cellPlaintext(first!);
    producing.catch(() => undefined);
    // A scheduled slot's cell waits on the same build.
    const slotCell = slot(1);
    await turnsUntil(() => handBacks.pending === 1);
    expect(build.state.hashes).toBe(2);
    const heldWhileBuilding = message.proofLevelBytes;
    expect(heldWhileBuilding).toBeGreaterThan(0);

    message.close();
    // It stops at its next slice: until that runs it still holds them.
    expect(message.proofLevelBytes).toBe(heldWhileBuilding);
    handBacks.release();
    expect((await rejection(producing)).message).toContain("already ended");
    // The slot gets no cell (its dummy goes), and no error that would
    // degrade the edge.
    expect(await outcome(slotCell)).toEqual({ value: null });
    expect(build.state.hashes).toBe(2);
    expect(handBacks.pending).toBe(0);
    expect(handBacks.taken).toBe(1);
    expect(message.proofLevelBytes).toBe(0);
  });

  test("a failed build is reported once and not retried", async () => {
    const leafCount = 41;
    const staged = await stageMessage(leafCount);
    const build = countingBuild(SLICE_MS / 2);
    // The fifth node hash fails, in the build's third slice.
    const failing = new Proxy(build.module, {
      get(object, property, receiver) {
        if (property === "_sha512_final")
          return (statePtr: number, outPtr: number) =>
            build.state.hashes === 5
              ? -1
              : object._sha512_final(statePtr, outPtr);
        return Reflect.get(object, property, receiver) as unknown;
      },
    });
    const handBacks = manualHandBacks();
    const message = messageOver(
      staged,
      { ...build, module: failing },
      handBacks,
    );

    const asked = [message.cellPlaintext((await message.read(0))!)];
    await turnsUntil(() => handBacks.pending === 1);
    asked.push(message.cellPlaintext((await message.read(9))!));
    await driveUntilSettled(handBacks, asked);
    const errors = await Promise.all(asked.map(rejection));
    expect(errors[0].message).toBe("Could not calculate hash.");
    // One failure, the same error to every cell that waited on it.
    expect(errors[1]).toBe(errors[0]);
    expect(build.state.hashes).toBe(5);
    expect(handBacks.taken).toBe(2);

    // A later cell gets it too, without a hash or a slice.
    const later = message.cellPlaintext((await message.read(20))!);
    expect(await rejection(later)).toBe(errors[0]);
    expect(build.state.hashes).toBe(5);
    expect(handBacks.taken).toBe(2);
    expect(message.proofLevelBytes).toBe(0);
  });

  test("leaves that do not reach the root are refused after a sliced build", async () => {
    const leafCount = 41;
    const staged = await stageMessage(leafCount);
    // A resume's leaves from the outbox, one of them wrong (not a staged
    // row's own, so every cell's leaf check would still pass).
    const wrong = staged.leaves.slice();
    wrong[30 * crypto_hash_sha512_BYTES] ^= 1;
    const build = countingBuild(SLICE_MS / 2);
    const handBacks = manualHandBacks();
    const message = messageOver(staged, build, handBacks, wrong);

    const asked = [message.cellPlaintext((await message.read(2))!)];
    await turnsUntil(() => handBacks.pending === 1);
    asked.push(message.cellPlaintext((await message.read(11))!));
    await driveUntilSettled(handBacks, asked);
    for (const cell of asked)
      expect((await rejection(cell)).message).toContain(
        "do not reach its Merkle root",
      );
    // Built whole, in its 20 slices, once.
    expect(build.state.hashes).toBe(leafCount - 1);
    expect(handBacks.taken).toBe(19);
    expect(message.proofLevelBytes).toBe(0);
    expect(
      (await rejection(message.cellPlaintext((await message.read(12))!)))
        .message,
    ).toContain("do not reach its Merkle root");
    expect(build.state.hashes).toBe(leafCount - 1);
  });
});

// ── a cover slot while the build runs ──────────────────────────────────────

/** The shortest slots a schedule may have: 2 lanes x 5 frames per 250 ms. */
const SCHEDULE = {
  coverCadenceMs: 250,
  coverLanes: 2,
  coverFramesPerCell: 5,
  coverDurationEpochs: 1,
};
const SLOT_SPACING_MS = 25;
// Slot k of a cycle at ⌊(2k + 1) × 250 / 20⌋: 12, 37, 62, ... ms.
const FIRST_SLOT_MS = 12;
const ROOM_ID = "00000000-0000-4000-8000-0000000000b4";

interface Sent {
  readonly at: number;
  readonly label: string;
  readonly frameType: number;
}

describe("a cover slot does not wait for the proof-level build", () => {
  test("a cover slot due during a proof-level build leaves on time", async () => {
    const timeline = new CoverTimeline();
    const pq = new SparsePqHealingState({
      module,
      pqMode: "hybrid-mlkem512",
      rootSuite: RATCHET_ROOT_SUITE_MLKEM512,
      binding: new Uint8Array(32).fill(0x42),
      rootKey: new Uint8Array(32).fill(0x4b),
      nextOfferer: "local",
      amInitiator: true,
      now: 0,
    });
    const sent: Sent[] = [];
    const statuses: CoverSchedulerStatus[] = [];
    const runtime = new CoverRuntime({
      epc: {
        roomId: ROOM_ID,
        pqHealingState: pq,
      } as unknown as IRTCPeerConnection,
      roomId: ROOM_ID,
      module,
      amInitiator: true,
      schedule: SCHEDULE,
      policyHash: new Uint8Array(32),
      laneLabelName: "party",
      openLaneChannel: (label): CoverLaneChannel => ({
        label,
        readyState: "open",
        bufferedAmount: 0,
        send: (data: ArrayBuffer) => {
          sent.push({
            at: timeline.time,
            label,
            frameType: new Uint8Array(data)[0],
          });
        },
        close: () => undefined,
      }),
      onStatusChange: ({ status }) => statuses.push(status),
      timerEnvironment: timeline.env,
    });

    // A message of 401 leaves, the job sending its first five cells. The
    // build is 400 hashes of 0.5 ms each on the page's thread: 200 ms, eight
    // slots, from the cycle open. The page is busy while a hash runs: the
    // worker's wake-ups queue for it meanwhile.
    const leafCount = 401;
    const staged = await stageMessage(leafCount, 5, true);
    const hashTimes: number[] = [];
    const build = countingBuild(0, () => {
      hashTimes.push(timeline.time);
      timeline.busyPage(0.5);
    });
    const message = new OutboundMessage({
      transferId: TRANSFER_ID,
      hashHex: HASH_HEX,
      merkleRoot: staged.merkleRoot,
      totalChunks: leafCount,
      chunkHashes: staged.leaves,
      merkleModule: build.module,
      store: staged.store,
      proofLevelBuild: {
        now: () => timeline.time,
        // A task on the page, behind whatever queued during the slice.
        yieldToEventLoop: () =>
          new Promise((resolve) => {
            timeline.deliverToPage(resolve);
          }),
      },
    });
    const context = pq.currentMessageContext();
    const sealer = createMessageChunkSealer(
      new Uint8Array(32).fill(0x31),
      { dhPub: new Uint8Array(32).fill(0x07), N: 0, PN: 0 },
      {
        ...context,
        rootKey: Uint8Array.from(context.rootKey),
        binding: Uint8Array.from(context.binding),
      },
      module,
    );
    const label = await compileChannelMessageLabel(
      "party",
      uint8ArrayToHex(staged.merkleRoot),
    );
    try {
      runtime.enqueue(
        buildScheduledSendJob({
          runtime,
          channelMessageLabel: label,
          totalChunks: 5,
          merkleRoot: staged.merkleRoot,
          sealSlotCell: makeScheduledSlotSealer(message, sealer, () => false),
        }),
      );
      runtime.start();
      await timeline.advanceTo(2 * SCHEDULE.coverCadenceMs - 1);

      // The build ran across several slots of the grid.
      expect(hashTimes).toHaveLength(leafCount - 1);
      const buildFrom = hashTimes[0];
      const buildTo = hashTimes[hashTimes.length - 1] + 0.5;
      expect(buildTo - buildFrom).toBeGreaterThanOrEqual(6 * SLOT_SPACING_MS);
      const slotOf = (at: number) =>
        at - ((at - FIRST_SLOT_MS) % SLOT_SPACING_MS);
      const during = sent.filter(
        ({ at }) => slotOf(at) >= buildFrom && slotOf(at) < buildTo,
      );
      expect(during.length).toBeGreaterThanOrEqual(6);

      // Every slot of both cycles sent its cell, each at most one slice after
      // its slot time, and nothing degraded.
      expect(sent).toHaveLength(20);
      expect(new Set(sent.map(({ at }) => slotOf(at))).size).toBe(20);
      for (const { at } of sent)
        expect(at - slotOf(at)).toBeLessThanOrEqual(SLICE_MS);
      expect(statuses).toEqual(["starting", "active"]);
      // While the build ran, the job's lane sent its slot's dummies; its five
      // chunks went after.
      const lane = sent.filter((cell) => cell.label === label);
      expect(
        lane
          .filter(({ at }) => slotOf(at) < buildTo)
          .every(({ frameType }) => frameType === FRAME_TYPE_COVER),
      ).toBe(true);
      expect(
        lane.filter(({ frameType }) => frameType === FRAME_TYPE_CHUNK),
      ).toHaveLength(5);
    } finally {
      runtime.destroy();
      sealer.wipe();
      message.close();
      pq.destroy();
    }
  });
});
