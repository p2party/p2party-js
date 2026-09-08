import { beforeAll, describe, expect, test } from "bun:test";

import {
  installCoverEdge,
  enqueueScheduledSend,
  trackScheduledSend,
  teardownCoverEdge,
} from "../../src/handlers/coverEdge";
import {
  isTransferComplete,
  isTransferCancelled,
  clearTransfer,
  getAckedChunks,
} from "../../src/handlers/reconcile";
import { waitForEdgeReceiveQuiescence } from "../../src/handlers/handleMessageQueueing";
import { SparsePqHealingState } from "../../src/handlers/pqHealingRuntime";
import { openCoverCell, sealCoverCell } from "../../src/cryptography/coverCell";
import { loadTestModule } from "../../src/cryptography/testModule";
import {
  FRAME_TYPE_COVER,
  RATCHET_ROOT_SUITE_MLKEM512,
  WIRE_CHUNK_FRAME_LEN,
} from "../../src/utils/constants";
import {
  DEFAULT_ROOM_POLICY_V1,
  type RoomPolicyV1,
} from "../../src/roomPolicy";

import type { LibCrypto } from "../../src/cryptography/libcrypto";
import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../../src/api/webrtc/interfaces";

let module: LibCrypto;
beforeAll(async () => {
  module = await loadTestModule();
});

// A fake DataChannel that records sends and lets the test drive readyState.
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

const scheduledPolicy = (): RoomPolicyV1 => ({
  ...DEFAULT_ROOM_POLICY_V1,
  coverMode: "scheduled",
  coverCadenceMs: 400,
  coverLanes: 2,
  coverFramesPerCell: 2,
  coverDurationEpochs: 1,
});

const makePqRuntime = (amInitiator: boolean): SparsePqHealingState =>
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

describe("scheduled cover edge (installCoverEdge)", () => {
  test("authenticates selective tokens before scoped durable ACKs and rejects replay/tampering", async () => {
    const pq = makePqRuntime(true),
      root = new Uint8Array(64).fill(0x61),
      rootHex = "61".repeat(64);
    const transferId = "selective-edge",
      writes: number[] = [];
    const epc = {
      roomId: "room",
      withPeerId: "peer",
      withPeerPublicKey: "33".repeat(32),
      pqHealingState: pq,
      createDataChannel: (label: string) =>
        new FakeChannel(label) as unknown as IRTCDataChannel,
    } as unknown as IRTCPeerConnection;
    installCoverEdge({
      epc,
      roomId: "room",
      policy: scheduledPolicy(),
      policyHash: new Uint8Array(32),
      amInitiator: true,
      module,
      receiptDependencies: {
        getChunk: async (r, t) =>
          r === rootHex && ["71".repeat(64), "72".repeat(64)].includes(t)
            ? {
                merkleRoot: rootHex,
                receiptToken: t,
                transferId,
                chunkIndex: t.startsWith("71") ? 1 : 2,
              }
            : undefined,
        persist: async (receipt) => {
          writes.push(receipt.chunkIndex ?? -1);
          return true;
        },
        persistCancellation: async (owner) => {
          expect(owner).toEqual({
            roomId: "room",
            peerId: "peer",
            peerPublicKey: "33".repeat(32),
            transferId,
            merkleRootHex: rootHex,
          });
          writes.push(-2);
          return true;
        },
      },
      inboundSweepDeps: {
        waitForReceiveIdle: waitForEdgeReceiveQuiescence,
        readProgress: async () => undefined,
        forgetKey: async () => true,
        deleteReceive: async () => true,
        dropStateRow: () => {},
      },
    });
    trackScheduledSend(epc, "room", "peer", rootHex, transferId);
    const frame = sealCoverCell({
      module,
      rootSuite: RATCHET_ROOT_SUITE_MLKEM512,
      rootKey: pq.currentMessageContext().rootKey,
      binding: pq.currentMessageContext().binding,
      direction: "responder-to-initiator",
      keyEpoch: 0n,
      counter: 1n,
      content: {
        subtype: "chunk-receipts",
        merkleRoot: root,
        tokens: [new Uint8Array(64).fill(0x71), new Uint8Array(64).fill(0x72)],
      },
    });
    try {
      const forged = Uint8Array.from(frame);
      forged[200] ^= 1;
      expect(epc.coverRuntime!.processInboundCoverCell(forged)).toBe(false);
      expect(writes).toHaveLength(0);
      expect(epc.coverRuntime!.processInboundCoverCell(frame)).toBe(true);
      expect(epc.coverRuntime!.processInboundCoverCell(frame)).toBe(false);
      await new Promise((resolve) => setTimeout(resolve, 0));
      expect(writes).toEqual([1, 2]);
      expect(getAckedChunks("room", "peer", transferId)).toEqual(
        new Set([1, 2]),
      );
      expect(isTransferComplete("room", "peer", transferId)).toBe(false);
      const cancel = sealCoverCell({
        module,
        rootSuite: RATCHET_ROOT_SUITE_MLKEM512,
        rootKey: pq.currentMessageContext().rootKey,
        binding: pq.currentMessageContext().binding,
        direction: "responder-to-initiator",
        keyEpoch: 0n,
        counter: 2n,
        content: { subtype: "cancel", merkleRoot: root },
      });
      expect(epc.coverRuntime!.processInboundCoverCell(cancel)).toBe(true);
      expect(epc.coverRuntime!.processInboundCoverCell(cancel)).toBe(false);
      await waitForEdgeReceiveQuiescence("room", "peer");
      expect(writes).toEqual([1, 2, -2]);
      expect(isTransferCancelled("room", "peer", transferId)).toBe(true);
      expect(isTransferCancelled("room", "other-peer", transferId)).toBe(false);
      expect(isTransferCancelled("other-room", "peer", transferId)).toBe(false);
      expect(isTransferComplete("room", "peer", transferId)).toBe(false);
    } finally {
      teardownCoverEdge(epc);
      clearTransfer("room", "peer", transferId);
      pq.destroy();
    }
  });

  test("a scheduled chunk token cannot masquerade as terminal completion", async () => {
    const pq = makePqRuntime(true);
    const epc = {
      roomId: "room",
      withPeerId: "peer",
      withPeerPublicKey: "33".repeat(32),
      pqHealingState: pq,
      createDataChannel: (label: string) =>
        new FakeChannel(label) as unknown as IRTCDataChannel,
    } as unknown as IRTCPeerConnection;
    installCoverEdge({
      epc,
      roomId: "room",
      policy: scheduledPolicy(),
      policyHash: new Uint8Array(32),
      amInitiator: true,
      module,
    });
    const root = new Uint8Array(64).fill(0x11);
    const rootHex = "11".repeat(64);
    trackScheduledSend(epc, "room", "peer", rootHex, "strict-terminal");
    // Exercise the production callback after authenticating a peer's cover cell.
    const frame = sealCoverCell({
      module,
      rootSuite: RATCHET_ROOT_SUITE_MLKEM512,
      rootKey: pq.currentMessageContext().rootKey,
      binding: pq.currentMessageContext().binding,
      direction: "responder-to-initiator",
      keyEpoch: 0n,
      counter: 1n,
      content: {
        subtype: "receipt",
        merkleRoot: root,
        token: new Uint8Array(64).fill(0x22),
      },
    });
    try {
      expect(epc.coverRuntime!.processInboundCoverCell(frame)).toBe(true);
      await waitForEdgeReceiveQuiescence("room", "peer");
      expect(isTransferComplete("room", "peer", "strict-terminal")).toBe(false);
    } finally {
      teardownCoverEdge(epc);
      clearTransfer("room", "peer", "strict-terminal");
      pq.destroy();
    }
  });

  test("installs a runtime whose dummy cells the peer authenticates (real lane timing is covered by the browser test)", () => {
    const pq = makePqRuntime(true); // sender (initiator → i2r)
    const epc = {
      withPeerId: "peer",
      pqHealingState: pq,
      createDataChannel: (label: string) =>
        new FakeChannel(label) as unknown as IRTCDataChannel,
    } as unknown as IRTCPeerConnection;

    installCoverEdge({
      epc,
      roomId: "room",
      policy: scheduledPolicy(),
      policyHash: new Uint8Array(32),
      amInitiator: true,
      module,
    });
    expect(epc.coverRuntime).toBeDefined();

    // The runtime seals dummy cells under the current PQ epoch; the responder
    // (opposite direction, same suite/binding/epoch) authenticates them.
    const dummy = epc.coverRuntime!.sealCoverContent({ subtype: "dummy" });
    expect(dummy).toHaveLength(WIRE_CHUNK_FRAME_LEN);
    expect(dummy[0]).toBe(FRAME_TYPE_COVER);

    const responderPq = makePqRuntime(false);
    const opened = openCoverCell({
      module,
      rootSuite: RATCHET_ROOT_SUITE_MLKEM512,
      rootKey: responderPq.currentMessageContext().rootKey,
      binding: responderPq.currentMessageContext().binding,
      direction: "initiator-to-responder",
      keyEpoch: 0n,
      frame: dummy,
    });
    expect(opened.content.subtype).toBe("dummy");

    epc.coverRuntime!.destroy();
    pq.destroy();
    responderPq.destroy();
  });

  test("enqueueScheduledSend refuses a message that exceeds the F×D capacity, admits one that fits", () => {
    const pq = makePqRuntime(true);
    const epc = {
      withPeerId: "peer",
      pqHealingState: pq,
      createDataChannel: (label: string) =>
        new FakeChannel(label) as unknown as IRTCDataChannel,
    } as unknown as IRTCPeerConnection;
    installCoverEdge({
      epc,
      roomId: "room",
      policy: scheduledPolicy(), // F×D = 2
      policyHash: new Uint8Array(32),
      amInitiator: true,
      module,
    });

    expect(() =>
      enqueueScheduledSend({
        epc,
        channelMessageLabel: `${"00".repeat(32)}~${"11".repeat(64)}`,
        totalChunks: 3, // > F×D=2
        merkleRoot: new Uint8Array(64).fill(0x11),
        sealSlotCell: async () => new Uint8Array(WIRE_CHUNK_FRAME_LEN),
      }),
    ).toThrow(/exceeds the room/);

    expect(
      enqueueScheduledSend({
        epc,
        channelMessageLabel: `${"00".repeat(32)}~${"22".repeat(64)}`,
        totalChunks: 2,
        merkleRoot: new Uint8Array(64).fill(0x22),
        sealSlotCell: async () => new Uint8Array(WIRE_CHUNK_FRAME_LEN),
      }),
    ).toBe(true);

    epc.coverRuntime!.destroy();
    pq.destroy();
  });

  test("an immediate-mode policy installs no cover runtime", () => {
    const pq = makePqRuntime(true);
    const epc = {
      withPeerId: "peer",
      pqHealingState: pq,
      createDataChannel: (label: string) =>
        new FakeChannel(label) as unknown as IRTCDataChannel,
    } as unknown as IRTCPeerConnection;
    installCoverEdge({
      epc,
      roomId: "room",
      policy: DEFAULT_ROOM_POLICY_V1, // immediate
      policyHash: new Uint8Array(32),
      amInitiator: true,
      module,
    });
    expect(epc.coverRuntime).toBeUndefined();
    pq.destroy();
  });
});
