import { beforeAll, describe, expect, test } from "bun:test";

import { installCoverEdge, enqueueScheduledSend } from "../../src/handlers/coverEdge";
import { SparsePqHealingState } from "../../src/handlers/pqHealingRuntime";
import { openCoverCell } from "../../src/cryptography/coverCell";
import { loadTestModule } from "../../src/cryptography/testModule";
import {
  FRAME_TYPE_COVER,
  RATCHET_ROOT_SUITE_MLKEM512,
  WIRE_CHUNK_FRAME_LEN,
} from "../../src/utils/constants";
import { DEFAULT_ROOM_POLICY_V1, type RoomPolicyV1 } from "../../src/roomPolicy";

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
        sealSlotCell: async () => new Uint8Array(WIRE_CHUNK_FRAME_LEN),
      }),
    ).toThrow(/exceeds the room/);

    expect(
      enqueueScheduledSend({
        epc,
        channelMessageLabel: `${"00".repeat(32)}~${"22".repeat(64)}`,
        totalChunks: 2,
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
