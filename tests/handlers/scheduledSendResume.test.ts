import { afterEach, beforeAll, describe, expect, test } from "bun:test";

import { loadTestModule } from "../../src/cryptography/testModule";
import {
  initRatchet,
  ratchetEncrypt,
  type RatchetState,
} from "../../src/cryptography/ratchet";
import { getMerkleProof, getMerkleRoot } from "../../src/cryptography/merkle";
import { hashMerkleLeafWasm } from "../../src/utils/leafHash";
import { serializeMetadata } from "../../src/utils/metadata";
import { MessageType } from "../../src/utils/messageTypes";
import { crypto_hash_sha512_BYTES } from "../../src/cryptography/interfaces";
import { SparsePqHealingState } from "../../src/handlers/pqHealingRuntime";
import {
  CHUNK_LEN,
  DECRYPTED_LEN,
  METADATA_LEN,
  PROOF_LEN,
  RATCHET_ROOT_SUITE_MLKEM512,
} from "../../src/utils/constants";
import {
  DEFAULT_ROOM_POLICY_V1,
  type RoomPolicyV1,
} from "../../src/roomPolicy";
import { uint8ArrayToHex } from "../../src/utils/uint8array";

import type { LibCrypto } from "../../src/cryptography/libcrypto";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../../src/api/webrtc/interfaces";
import type { CoverRuntime } from "../../src/handlers/coverRuntime";

// The live send orchestration imports the Redux store, whose browser identity
// slice reads localStorage at module initialization. Install the minimal
// browser shim before dynamically importing it under Bun (same preamble as
// handleSendMessage.test.ts).
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

let module: LibCrypto;

let installCoverEdge: (typeof import("../../src/handlers/coverEdge"))["installCoverEdge"];
let teardownCoverEdge: (typeof import("../../src/handlers/coverEdge"))["teardownCoverEdge"];
let coverEdgeGeneration: (typeof import("../../src/handlers/coverEdge"))["coverEdgeGeneration"];
let waitForCoverEdgeGeneration: (typeof import("../../src/handlers/coverEdge"))["waitForCoverEdgeGeneration"];
let sendScheduled: (typeof import("../../src/handlers/handleSendMessage"))["sendScheduled"];
let claimRatchetGate: (typeof import("../../src/handlers/ratchetGate"))["claimRatchetGate"];
let openRatchetGate: (typeof import("../../src/handlers/ratchetGate"))["openRatchetGate"];
let resetRatchetGate: (typeof import("../../src/handlers/ratchetGate"))["resetRatchetGate"];
let clearTransfer: (typeof import("../../src/handlers/reconcile"))["clearTransfer"];
let isTransferComplete: (typeof import("../../src/handlers/reconcile"))["isTransferComplete"];
let sealChunk: (typeof import("../../src/handlers/messageChunkCrypto"))["sealChunk"];
let decryptMessageChunk: (typeof import("../../src/handlers/messageChunkCrypto"))["decryptMessageChunk"];
let handleReceiveMessage: (typeof import("../../src/handlers/handleReceiveMessage"))["handleReceiveMessage"];
let MAX_SCHEDULED_SEND_RESUMES: number;

beforeAll(async () => {
  module = await loadTestModule();
  // Enter the store/API cycle through its normal application root first.
  await import("../../src/store");
  ({
    coverEdgeGeneration,
    installCoverEdge,
    teardownCoverEdge,
    waitForCoverEdgeGeneration,
  } = await import("../../src/handlers/coverEdge"));
  ({ sendScheduled } = await import("../../src/handlers/handleSendMessage"));
  ({ claimRatchetGate, openRatchetGate, resetRatchetGate } =
    await import("../../src/handlers/ratchetGate"));
  ({ clearTransfer, isTransferComplete } =
    await import("../../src/handlers/reconcile"));
  ({ decryptMessageChunk, sealChunk } =
    await import("../../src/handlers/messageChunkCrypto"));
  ({ handleReceiveMessage } =
    await import("../../src/handlers/handleReceiveMessage"));
  ({ MAX_SCHEDULED_SEND_RESUMES } = await import("../../src/utils/constants"));
});

const rand = (n: number): Uint8Array => {
  const u = new Uint8Array(n);
  crypto.getRandomValues(u);
  return u;
};

class FakeChannel {
  label: string;
  readyState = "open";
  bufferedAmount = 0;
  binaryType = "arraybuffer";
  withPeerId = "peer";
  roomIds: [string] = ["room"];
  readonly sent: Uint8Array[] = [];
  private listeners = new Map<string, Array<() => void>>();
  constructor(label: string) {
    this.label = label;
  }
  send(data: ArrayBuffer): void {
    this.sent.push(new Uint8Array(data));
  }
  close(): void {
    this.readyState = "closed";
    for (const l of this.listeners.get("close") ?? []) l();
  }
  addEventListener(type: string, cb: () => void): void {
    const arr = this.listeners.get(type) ?? [];
    arr.push(cb);
    this.listeners.set(type, arr);
  }
}

const makePq = (amInitiator: boolean): SparsePqHealingState =>
  new SparsePqHealingState({
    module,
    pqMode: "hybrid-mlkem512",
    rootSuite: RATCHET_ROOT_SUITE_MLKEM512,
    binding: new Uint8Array(32).fill(0x42),
    rootKey: new Uint8Array(32).fill(0x19),
    nextOfferer: amInitiator ? "local" : "remote",
    amInitiator,
    now: 0,
  });

// A cadence far longer than any test run, so the real-timer scheduler never
// opens a cycle: every enqueued job stays "queued" and nothing is emitted, so
// these tests observe admission alone.
const scheduledPolicy = (): RoomPolicyV1 => ({
  ...DEFAULT_ROOM_POLICY_V1,
  coverMode: "scheduled",
  coverCadenceMs: 600_000,
  coverLanes: 2,
  coverFramesPerCell: 2,
  coverDurationEpochs: 1,
});

const ROOM = "room-c8";
const PEER = "peer-c8";
const ROOT_HEX = "ab".repeat(64);
const TRANSFER_ID = "cd".repeat(16);

interface Edge {
  readonly epc: IRTCPeerConnection;
  readonly pq: SparsePqHealingState;
  readonly runtime: CoverRuntime;
}

const cleanups: (() => void)[] = [];

/** The compiled channel-message label, which is also the cover job's id. */
const jobLabel = (): string => {
  const namePadded = new Uint8Array(32);
  namePadded.set(new TextEncoder().encode("chat"));
  return `${uint8ArrayToHex(namePadded)}~${ROOT_HEX}`;
};

/** Make this connection the edge's current authenticated transport. */
const makeCurrent = (epc: IRTCPeerConnection): void => {
  resetRatchetGate(ROOM, PEER);
  const lease = claimRatchetGate(ROOM, PEER);
  openRatchetGate(ROOM, PEER, lease);
  epc.ratchetGateLease = lease;
};

/** Build one authenticated scheduled-cover edge and make its gate current. */
const makeEdge = (ratchetState: RatchetState): Edge => {
  const pq = makePq(true); // local side is the initiator
  const epc = {
    roomId: ROOM,
    withPeerId: PEER,
    withPeerPublicKey: "aa".repeat(32),
    connectionState: "connected",
    pqHealingState: pq,
    ratchetState,
    createDataChannel: (label: string) =>
      new FakeChannel(label) as unknown as IRTCDataChannel,
  } as unknown as IRTCPeerConnection;
  installCoverEdge({
    epc,
    roomId: ROOM,
    policy: scheduledPolicy(),
    policyHash: new Uint8Array(32),
    amInitiator: true,
    module,
  });
  // A fresh handshake replaces the gate; the sender's resume only adopts a
  // transport whose gate is open on its OWN lease.
  makeCurrent(epc);
  const edge: Edge = { epc, pq, runtime: epc.coverRuntime as CoverRuntime };
  cleanups.push(() => {
    teardownCoverEdge(epc);
    pq.destroy();
  });
  return edge;
};

afterEach(() => {
  while (cleanups.length > 0) cleanups.pop()?.();
  clearTransfer(ROOM, PEER, TRANSFER_ID);
  resetRatchetGate(ROOM, PEER);
});

describe("the cover edge publishes a generation the sender can watch", () => {
  test("every installed runtime is a new generation; a teardown is not", () => {
    const before = coverEdgeGeneration(ROOM, PEER);
    const first = makeEdge(initRatchet(rand(32), false, null, module));
    const afterFirst = coverEdgeGeneration(ROOM, PEER);
    expect(afterFirst).toBeGreaterThan(before);

    // Teardown alone must NOT advance the generation: the resume adopts a
    // REPLACEMENT runtime, and an edge that only died has nothing to adopt.
    teardownCoverEdge(first.epc);
    expect(coverEdgeGeneration(ROOM, PEER)).toBe(afterFirst);

    makeEdge(initRatchet(rand(32), false, null, module));
    expect(coverEdgeGeneration(ROOM, PEER)).toBeGreaterThan(afterFirst);
  });

  test("an immediate-mode room publishes no cover generation at all", () => {
    const pq = makePq(true);
    cleanups.push(() => pq.destroy());
    const epc = {
      roomId: "immediate-room",
      withPeerId: "immediate-peer",
      pqHealingState: pq,
      createDataChannel: (label: string) =>
        new FakeChannel(label) as unknown as IRTCDataChannel,
    } as unknown as IRTCPeerConnection;
    installCoverEdge({
      epc,
      roomId: "immediate-room",
      policy: DEFAULT_ROOM_POLICY_V1,
      policyHash: new Uint8Array(32),
      amInitiator: true,
      module,
    });
    expect(epc.coverRuntime).toBeUndefined();
    expect(coverEdgeGeneration("immediate-room", "immediate-peer")).toBe(0);
  });

  test("a waiter resolves on the next install and times out when none comes", async () => {
    const since = coverEdgeGeneration(ROOM, PEER);
    const waited = waitForCoverEdgeGeneration(ROOM, PEER, since, 5_000);
    setTimeout(() => {
      makeEdge(initRatchet(rand(32), false, null, module));
    }, 10);
    expect(await waited).toBeGreaterThan(since);

    const now = coverEdgeGeneration(ROOM, PEER);
    expect(await waitForCoverEdgeGeneration(ROOM, PEER, now, 40)).toBe(now);
  });

  test("a generation that already advanced resolves without waiting", async () => {
    // The sender reaches this call one whole delivery idle budget after the
    // replacement usually happened, so the advance is nearly always already
    // published. Waiting the resume budget out again before noticing would add
    // that budget to every recovery for nothing.
    const since = coverEdgeGeneration(ROOM, PEER);
    makeEdge(initRatchet(rand(32), false, null, module));
    const started = Date.now();
    expect(await waitForCoverEdgeGeneration(ROOM, PEER, since, 5_000)).toBe(
      coverEdgeGeneration(ROOM, PEER),
    );
    expect(Date.now() - started).toBeLessThan(1_000);
  });
});

interface RunOptions {
  /** Called before each injected delivery wait resolves false/true. */
  readonly onWait: (attempt: number) => Promise<boolean> | boolean;
  readonly peerConnections: IRTCPeerConnection[];
  readonly steppedOn: IRTCPeerConnection[];
  /** LIVE message-key buffers, so a wipe is observable through them. */
  readonly keys: Uint8Array[];
  /** Their hex at derivation time, so the values can still be compared. */
  readonly keyHexes: string[];
  readonly ratchet: { state: RatchetState };
}

const runSend = async (options: RunOptions) => {
  let attempt = 0;
  return sendScheduled(
    ROOM,
    "chat",
    scheduledPolicy(),
    [{ peerId: PEER, epc: options.peerConnections[0] }],
    2,
    new Uint8Array(0),
    new Uint8Array(64).fill(0xab),
    ROOT_HEX,
    TRANSFER_ID,
    "ef".repeat(64),
    module,
    module,
    undefined,
    undefined,
    options.peerConnections,
    {
      waitForGate: async () => undefined,
      ratchetStep: async (epc) => {
        options.steppedOn.push(epc);
        const stepped = ratchetEncrypt(options.ratchet.state, module);
        options.keys.push(stepped.messageKey);
        options.keyHexes.push(uint8ArrayToHex(stepped.messageKey));
        return {
          messageKey: stepped.messageKey,
          header: stepped.header,
          pqContext: null,
        };
      },
      waitForDelivery: async () => {
        attempt += 1;
        return await options.onWait(attempt);
      },
      resumeWaitMs: 300,
    },
  );
};

describe("an in-flight scheduled send survives an edge replacement (C8)", () => {
  test("the send is re-derived and re-enqueued on the replacement runtime", async () => {
    const bob = initRatchet(rand(32), false, null, module);
    const first = makeEdge(
      initRatchet(Uint8Array.from(rand(32)), true, bob.dhSelfPub, module),
    );
    const peerConnections: IRTCPeerConnection[] = [first.epc];
    const steppedOn: IRTCPeerConnection[] = [];
    const keys: Uint8Array[] = [];
    const keyHexes: string[] = [];
    const ratchet = { state: first.epc.ratchetState as RatchetState };
    let second: Edge | undefined;
    const label = jobLabel();

    const result = await runSend({
      peerConnections,
      steppedOn,
      keys,
      keyHexes,
      ratchet,
      onWait: (attempt) => {
        if (attempt === 1) {
          // The C8 event, exactly as baseQuery performs it: tear the cover
          // edge down, splice the retired connection out, hand the peer a
          // replacement whose fresh handshake owns an unrelated ratchet.
          expect(first.runtime.getQueuedJobIds()).toContain(label);
          teardownCoverEdge(first.epc);
          peerConnections.splice(0, 1);
          second = makeEdge(
            initRatchet(Uint8Array.from(rand(32)), true, bob.dhSelfPub, module),
          );
          ratchet.state = second.epc.ratchetState as RatchetState;
          peerConnections.push(second.epc);
          return false;
        }
        return true;
      },
    });

    expect(second).toBeDefined();
    expect(result.startedTransfers).toBe(1);
    expect(result.outcomes).toEqual([{ peerId: PEER, status: "delivered" }]);
    // Re-derived on the replacement edge, not replayed from the retired one.
    expect(steppedOn).toEqual([first.epc, second!.epc]);
    expect(keyHexes).toHaveLength(2);
    expect(keyHexes[0]).not.toBe(keyHexes[1]);
    // ...and actually re-offered on the replacement runtime.
    expect(second!.runtime.getQueuedJobIds()).toContain(label);
  });

  test("the retired job is settled and its key wiped before the resume enqueues", async () => {
    const bob = initRatchet(rand(32), false, null, module);
    const first = makeEdge(
      initRatchet(Uint8Array.from(rand(32)), true, bob.dhSelfPub, module),
    );
    const peerConnections: IRTCPeerConnection[] = [first.epc];
    const keys: Uint8Array[] = [];
    const keyHexes: string[] = [];
    const ratchet = { state: first.epc.ratchetState as RatchetState };
    let keyAtResume: string | undefined;

    await runSend({
      peerConnections,
      steppedOn: [],
      keys,
      keyHexes,
      ratchet,
      onWait: (attempt) => {
        if (attempt === 1) {
          teardownCoverEdge(first.epc);
          peerConnections.splice(0, 1);
          const second = makeEdge(
            initRatchet(Uint8Array.from(rand(32)), true, bob.dhSelfPub, module),
          );
          ratchet.state = second.epc.ratchetState as RatchetState;
          peerConnections.push(second.epc);
          return false;
        }
        keyAtResume = uint8ArrayToHex(keys[0]);
        return true;
      },
    });

    // Task 10's settlement wipe fires on the teardown; nothing the resume does
    // may keep the retired generation's key alive.
    expect(keyHexes[0]).not.toBe("00".repeat(keys[0].length));
    expect(keyAtResume).toBe("00".repeat(keys[0].length));
    expect(uint8ArrayToHex(keys[1])).not.toBe("00".repeat(keys[1].length));
  });

  test("no replacement edge means no resume: one attempt, one cancel, unchanged", async () => {
    const bob = initRatchet(rand(32), false, null, module);
    const first = makeEdge(
      initRatchet(Uint8Array.from(rand(32)), true, bob.dhSelfPub, module),
    );
    const peerConnections: IRTCPeerConnection[] = [first.epc];
    const steppedOn: IRTCPeerConnection[] = [];
    const ratchet = { state: first.epc.ratchetState as RatchetState };

    const result = await runSend({
      peerConnections,
      steppedOn,
      keys: [],
      keyHexes: [],
      ratchet,
      onWait: () => false,
    });

    expect(steppedOn).toEqual([first.epc]);
    expect(result.startedTransfers).toBe(1);
    expect(result.outcomes[0].status).toBe("failed");
  });

  test("a flapping edge cannot re-send the whole message forever", async () => {
    const bob = initRatchet(rand(32), false, null, module);
    let current = makeEdge(
      initRatchet(Uint8Array.from(rand(32)), true, bob.dhSelfPub, module),
    );
    const peerConnections: IRTCPeerConnection[] = [current.epc];
    const steppedOn: IRTCPeerConnection[] = [];
    const ratchet = { state: current.epc.ratchetState as RatchetState };

    const result = await runSend({
      peerConnections,
      steppedOn,
      keys: [],
      keyHexes: [],
      ratchet,
      onWait: () => {
        teardownCoverEdge(current.epc);
        peerConnections.splice(0, peerConnections.length);
        current = makeEdge(
          initRatchet(Uint8Array.from(rand(32)), true, bob.dhSelfPub, module),
        );
        ratchet.state = current.epc.ratchetState as RatchetState;
        peerConnections.push(current.epc);
        return false;
      },
    });

    // Scheduled mode emits no per-chunk receipts, so every resume is a full
    // re-send: the budget is what stops an endless one. The expected count is
    // written out rather than derived from the constant -- deriving it would
    // move the assertion with any change to the cap and assert nothing.
    expect(steppedOn).toHaveLength(3);
    expect(MAX_SCHEDULED_SEND_RESUMES).toBe(2);
    expect(result.outcomes[0].status).toBe("failed");
  });

  test("a replacement that leaves the old runtime alive still retires the old job", async () => {
    // Not every edge replacement destroys the previous runtime first, and a
    // retired job that is still admitted keeps emitting cells under a key the
    // peer's new generation cannot open -- and keeps that key alive. The resume
    // settles it explicitly, WITHOUT a wire CANCEL: a CANCEL here would delete
    // the very partial the resume exists to finish filling.
    const bob = initRatchet(rand(32), false, null, module);
    const first = makeEdge(
      initRatchet(Uint8Array.from(rand(32)), true, bob.dhSelfPub, module),
    );
    const peerConnections: IRTCPeerConnection[] = [first.epc];
    const keys: Uint8Array[] = [];
    const ratchet = { state: first.epc.ratchetState as RatchetState };
    const label = jobLabel();
    let progressAtResume: unknown = "unset";

    await runSend({
      peerConnections,
      steppedOn: [],
      keys,
      keyHexes: [],
      ratchet,
      onWait: (attempt) => {
        if (attempt === 1) {
          expect(first.runtime.getJobProgress(label)).toBeDefined();
          // The replacement is installed while the previous runtime is still
          // live and still holding the job.
          const second = makeEdge(
            initRatchet(Uint8Array.from(rand(32)), true, bob.dhSelfPub, module),
          );
          ratchet.state = second.epc.ratchetState as RatchetState;
          peerConnections.splice(0, 1, second.epc);
          return false;
        }
        progressAtResume = first.runtime.getJobProgress(label);
        return true;
      },
    });

    expect(progressAtResume).toBeUndefined();
    expect(uint8ArrayToHex(keys[0])).toBe("00".repeat(keys[0].length));
  });

  test("a stale sibling runtime that merely became current is not resumed onto", async () => {
    // The resume adopts only a runtime installed AFTER this attempt was
    // admitted. A connection whose cover runtime predates the attempt is not a
    // replacement, however authenticated it has since become; treating it as
    // one spends a resume (a full re-send) on nothing.
    const bob = initRatchet(rand(32), false, null, module);
    const sibling = makeEdge(
      initRatchet(Uint8Array.from(rand(32)), true, bob.dhSelfPub, module),
    );
    const first = makeEdge(
      initRatchet(Uint8Array.from(rand(32)), true, bob.dhSelfPub, module),
    );
    const peerConnections: IRTCPeerConnection[] = [first.epc];
    const steppedOn: IRTCPeerConnection[] = [];
    const ratchet = { state: first.epc.ratchetState as RatchetState };

    const result = await runSend({
      peerConnections,
      steppedOn,
      keys: [],
      keyHexes: [],
      ratchet,
      onWait: () => {
        // No new install: the generation does not move. The older sibling
        // simply becomes the current authenticated transport.
        makeCurrent(sibling.epc);
        peerConnections.splice(0, 1, sibling.epc);
        return false;
      },
    });

    expect(steppedOn).toEqual([first.epc]);
    expect(result.outcomes[0].status).toBe("failed");
  });

  test("a resume never re-admits onto the very runtime the job is already on", async () => {
    // The generation advanced, but the transport that is current again is the
    // one this attempt was already admitted to. Re-admitting there would settle
    // a live job and enqueue a duplicate of it on the same runtime.
    const bob = initRatchet(rand(32), false, null, module);
    const first = makeEdge(
      initRatchet(Uint8Array.from(rand(32)), true, bob.dhSelfPub, module),
    );
    const peerConnections: IRTCPeerConnection[] = [first.epc];
    const steppedOn: IRTCPeerConnection[] = [];
    const ratchet = { state: first.epc.ratchetState as RatchetState };

    const result = await runSend({
      peerConnections,
      steppedOn,
      keys: [],
      keyHexes: [],
      ratchet,
      onWait: () => {
        // Something installed a runtime for this edge (the generation moves)...
        makeEdge(
          initRatchet(Uint8Array.from(rand(32)), true, bob.dhSelfPub, module),
        );
        // ...but the transport we are already on is the one that is current.
        makeCurrent(first.epc);
        peerConnections.splice(0, peerConnections.length, first.epc);
        return false;
      },
    });

    expect(steppedOn).toEqual([first.epc]);
    expect(result.outcomes[0].status).toBe("failed");
  });

  test("the replacement edge's terminal receipt still settles the send", async () => {
    const bob = initRatchet(rand(32), false, null, module);
    const first = makeEdge(
      initRatchet(Uint8Array.from(rand(32)), true, bob.dhSelfPub, module),
    );
    const peerConnections: IRTCPeerConnection[] = [first.epc];
    const ratchet = { state: first.epc.ratchetState as RatchetState };

    // The remote receiver's cover runtime, used only to seal an authentic
    // terminal receipt cell (responder direction).
    const remotePq = makePq(false);
    cleanups.push(() => remotePq.destroy());
    const { CoverRuntime: Runtime } =
      await import("../../src/handlers/coverRuntime");
    const remote = new Runtime({
      epc: { pqHealingState: remotePq } as unknown as IRTCPeerConnection,
      roomId: ROOM,
      module,
      amInitiator: false,
      schedule: {
        coverCadenceMs: 600_000,
        coverLanes: 2,
        coverFramesPerCell: 2,
        coverDurationEpochs: 1,
      },
      policyHash: new Uint8Array(32),
      laneLabelName: "p2party-cover",
      openLaneChannel: (l: string) => new FakeChannel(l),
    });
    cleanups.push(() => remote.destroy());

    const result = await runSend({
      peerConnections,
      steppedOn: [],
      keys: [],
      keyHexes: [],
      ratchet,
      onWait: (attempt) => {
        if (attempt === 1) {
          teardownCoverEdge(first.epc);
          peerConnections.splice(0, 1);
          const second = makeEdge(
            initRatchet(Uint8Array.from(rand(32)), true, bob.dhSelfPub, module),
          );
          ratchet.state = second.epc.ratchetState as RatchetState;
          peerConnections.push(second.epc);
          return false;
        }
        // The receiver confirms the whole message on the REPLACEMENT edge. If
        // the resume did not re-register the root -> transferId mapping on the
        // new connection, this receipt settles nothing and the send fails.
        const root = new Uint8Array(64).fill(0xab);
        const cell = remote.sealCoverContent({
          subtype: "receipt",
          merkleRoot: root,
          token: root,
        });
        expect(
          peerConnections[0].coverRuntime!.processInboundCoverCell(cell),
        ).toBe(true);
        return isTransferComplete(ROOM, PEER, TRANSFER_ID);
      },
    });

    expect(result.outcomes).toEqual([{ peerId: PEER, status: "delivered" }]);
  });
});

// ── the proof that killed the previous design ────────────────────────────────

const buildChunk = async (data: Uint8Array) => {
  const other = rand(CHUNK_LEN);
  const leaves = new Uint8Array(2 * crypto_hash_sha512_BYTES);
  leaves.set(hashMerkleLeafWasm(data, module), 0);
  leaves.set(hashMerkleLeafWasm(other, module), crypto_hash_sha512_BYTES);
  const root = await getMerkleRoot(leaves, module);
  const proof = await getMerkleProof(
    leaves,
    hashMerkleLeafWasm(data, module),
    module,
    PROOF_LEN,
  );
  const plaintext = new Uint8Array(DECRYPTED_LEN);
  plaintext.set(
    serializeMetadata({
      schemaVersion: 1,
      messageType: MessageType.Text,
      hash: rand(crypto_hash_sha512_BYTES),
      totalSize: 8,
      date: new Date(1),
      name: "",
      chunkStartIndex: 0,
      chunkEndIndex: 8,
      chunkIndex: 0,
    }),
  );
  plaintext.set(proof, METADATA_LEN);
  plaintext.set(data, METADATA_LEN + PROOF_LEN);
  return { root, plaintext };
};

describe("the peer can decrypt what a resumed send emits", () => {
  test("old generation opens, is rejected on the new one, and the re-derived cell opens", async () => {
    const data = rand(CHUNK_LEN);
    const { root, plaintext } = await buildChunk(data);

    // Generation 1 — live when the send started.
    const seed1 = rand(32);
    const bob1 = initRatchet(seed1, false, null, module);
    const alice1 = initRatchet(
      Uint8Array.from(seed1),
      true,
      bob1.dhSelfPub,
      module,
    );
    const g1 = ratchetEncrypt(alice1, module);
    const frame1 = sealChunk(g1.messageKey, g1.header, plaintext, root, module);

    // POSITIVE CONTROL: the generation that sealed it opens it.
    const onGen1 = decryptMessageChunk(
      bob1,
      frame1,
      new Map<string, Uint8Array>(),
      root,
      module,
    );
    expect(onGen1.ok).toBe(true);

    // Generation 2 — what a replacement handshake installs on both sides.
    const seed2 = rand(32);
    const bob2 = initRatchet(seed2, false, null, module);
    const alice2 = initRatchet(
      Uint8Array.from(seed2),
      true,
      bob2.dhSelfPub,
      module,
    );

    // Replaying the retired generation's cell — the design this task rejected.
    const replayed = decryptMessageChunk(
      bob2,
      frame1,
      new Map<string, Uint8Array>(),
      root,
      module,
    );
    expect(replayed.ok).toBe(false);
    expect(replayed.decrypted).toBeNull();

    // Re-deriving on the new generation — the design this task implements.
    const g2 = ratchetEncrypt(alice2, module);
    const frame2 = sealChunk(g2.messageKey, g2.header, plaintext, root, module);
    const resumed = decryptMessageChunk(
      bob2,
      frame2,
      new Map<string, Uint8Array>(),
      root,
      module,
    );
    expect(resumed.ok).toBe(true);
    expect(resumed.decrypted).not.toBeNull();
    expect(
      uint8ArrayToHex(resumed.decrypted!.subarray(METADATA_LEN + PROOF_LEN)),
    ).toBe(uint8ArrayToHex(data));
  });
});

describe("a resumed send is idempotent at the receiver", () => {
  test("the same chunk re-sealed on a new generation decrypts to the same leaf", async () => {
    const data = rand(CHUNK_LEN);
    const { root, plaintext } = await buildChunk(data);

    const open = (seed: Uint8Array) => {
      const bob = initRatchet(seed, false, null, module);
      const alice = initRatchet(
        Uint8Array.from(seed),
        true,
        bob.dhSelfPub,
        module,
      );
      const stepped = ratchetEncrypt(alice, module);
      const frame = sealChunk(
        stepped.messageKey,
        stepped.header,
        plaintext,
        root,
        module,
      );
      const out = decryptMessageChunk(
        bob,
        frame,
        new Map<string, Uint8Array>(),
        root,
        module,
      );
      expect(out.ok).toBe(true);
      return out.decrypted!;
    };

    // The receiver's have-set is the LEAF HASH, and the transfer identity is
    // the Merkle root; both are functions of the plaintext, never of the
    // cipher generation. So a resumed pass re-offers bytes the receiver
    // recognises as ones it already holds (dedup), and a full pass covers
    // every index, so nothing it never got is dropped.
    const leafOf = (decrypted: Uint8Array): string =>
      uint8ArrayToHex(
        decrypted.subarray(
          METADATA_LEN,
          METADATA_LEN + crypto_hash_sha512_BYTES,
        ),
      );
    const generationOne = open(rand(32));
    const generationTwo = open(rand(32));
    expect(leafOf(generationTwo)).toBe(leafOf(generationOne));
    expect(
      uint8ArrayToHex(generationTwo.subarray(METADATA_LEN + PROOF_LEN)),
    ).toBe(uint8ArrayToHex(generationOne.subarray(METADATA_LEN + PROOF_LEN)));
  });

  test("a duplicate chunk of an already-complete transfer still earns a terminal receipt", async () => {
    const data = rand(CHUNK_LEN);
    const { root, plaintext } = await buildChunk(data);
    const seed = rand(32);
    const bob = initRatchet(seed, false, null, module);
    const alice = initRatchet(
      Uint8Array.from(seed),
      true,
      bob.dhSelfPub,
      module,
    );
    const stepped = ratchetEncrypt(alice, module);
    const frame = sealChunk(
      stepped.messageKey,
      stepped.header,
      plaintext,
      root,
      module,
    );

    const epc = {
      withPeerId: PEER,
      withPeerPublicKey: "aa".repeat(32),
      ratchetState: bob,
      messageKeyCache: new Map<string, Uint8Array>(),
    } as unknown as IRTCPeerConnection;

    // The store reports the authoritative distinct-byte completion for the
    // WHOLE transfer, not "this call inserted something": a duplicate of an
    // already-complete message is `stored: false, complete: true`.
    const result = await handleReceiveMessage(
      frame,
      ROOM,
      "chat",
      epc,
      root,
      module,
      undefined,
      {
        persistRatchetState: async () => undefined,
        storeReceiveChunk: async () => ({
          stored: false,
          savedSize: 8,
          complete: true,
        }),
      },
    );

    expect(result.chunkAlreadyExists).toBe(true);
    expect(result.receivedFullSize).toBe(true);
  });
});
