import { beforeAll, describe, expect, test } from "bun:test";

import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../api/webrtc/interfaces";
import type { LibCrypto } from "../cryptography/libcrypto";
import type { RatchetHeader } from "../cryptography/ratchet";

// The live send orchestration imports the Redux store, whose browser identity
// slice reads localStorage at module initialization. Install the minimal browser
// shim before dynamically importing it under Bun.
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

type BindTransferCipherToConnection =
  typeof import("./handleSendMessage")["bindTransferCipherToConnection"];
let bindTransferCipherToConnection: BindTransferCipherToConnection;
let isAuthenticatedPeerCancel: typeof import("./handleSendMessage")["isAuthenticatedPeerCancel"];
let closeTransferChannel: typeof import("./handleSendMessage")["closeTransferChannel"];
let runPeerSendFanout: typeof import("./handleSendMessage")["runPeerSendFanout"];
let shouldDeleteLocalMessageAfterFailure: typeof import("./handleSendMessage")["shouldDeleteLocalMessageAfterFailure"];

beforeAll(async () => {
  // Enter the store/API cycle through its normal application root. Importing
  // handleSendMessage first would reverse that cycle and observe webrtcApi before
  // its createApi initializer has run.
  await import("../store");
  ({
    bindTransferCipherToConnection,
    closeTransferChannel,
    isAuthenticatedPeerCancel,
    runPeerSendFanout,
    shouldDeleteLocalMessageAfterFailure,
  } = await import("./handleSendMessage"));
});

describe("per-message DataChannel close semantics", () => {
  test("terminal cleanup releases a still-connecting channel before closing it", () => {
    const events: string[] = [];
    let readyState = "connecting";
    const channel = {
      get readyState() {
        return readyState;
      },
      releaseProtocolResources: () => events.push("release"),
      close() {
        events.push("close");
        readyState = "closed";
      },
    } as unknown as IRTCDataChannel;

    closeTransferChannel(channel);
    closeTransferChannel(channel);

    expect(events).toEqual(["release", "close", "release"]);
  });

  test("same connected authenticated PC means peer cancel", () => {
    const current = {
      ...fakeConnection("peer"),
      roomId: "room",
      connectionState: "connected",
    } as IRTCPeerConnection;
    expect(
      isAuthenticatedPeerCancel(current, [current], "room", "peer"),
    ).toBe(true);
  });

  test("a replacement or failed PC remains eligible for resume", () => {
    const old = {
      ...fakeConnection("peer"),
      roomId: "room",
      connectionState: "closed",
    } as IRTCPeerConnection;
    const replacement = {
      ...fakeConnection("peer"),
      roomId: "room",
      connectionState: "connected",
    } as IRTCPeerConnection;
    expect(
      isAuthenticatedPeerCancel(old, [replacement], "room", "peer"),
    ).toBe(false);
  });
});

const fakeConnection = (
  peerId: string,
  withRatchet = true,
): IRTCPeerConnection =>
  ({
    withPeerId: peerId,
    ratchetState: withRatchet ? {} : undefined,
  }) as IRTCPeerConnection;

const header = (marker: number): RatchetHeader => ({
  dhPub: new Uint8Array(32).fill(marker),
  N: marker,
  PN: 0,
});

const connectedAuthenticatedPeer = (
  peerId: string,
): IRTCPeerConnection =>
  ({
    ...fakeConnection(peerId),
    roomId: "room",
    connectionState: "connected",
    withPeerPublicKey: "ab".repeat(32),
  }) as IRTCPeerConnection;

describe("room-mesh send fanout", () => {
  test("a later setup failure cannot strand an earlier send or erase mixed delivery status", async () => {
    const firstPeer = connectedAuthenticatedPeer("peer-1");
    const secondPeer = connectedAuthenticatedPeer("peer-2");
    const thirdPeer = connectedAuthenticatedPeer("peer-3");
    const channels = new Map(
      [firstPeer, secondPeer, thirdPeer].map((epc) => [
        epc.withPeerId,
        { label: epc.withPeerId } as IRTCDataChannel,
      ]),
    );
    const events: string[] = [];
    let finishFirstPeer!: () => void;
    const firstPeerInFlight = new Promise<void>((resolve) => {
      finishFirstPeer = resolve;
    });

    const fanoutPromise = runPeerSendFanout(
      [
        { peerId: firstPeer.withPeerId, epc: firstPeer },
        { peerId: secondPeer.withPeerId, epc: secondPeer },
        { peerId: thirdPeer.withPeerId, epc: thirdPeer },
      ],
      async ({ peerId }) => {
        events.push(`open:${peerId}`);
        if (peerId === secondPeer.withPeerId)
          throw new Error("later open failed");
        return channels.get(peerId) as IRTCDataChannel;
      },
      async ({ peerId }) => {
        events.push(`send:${peerId}`);
        if (peerId === firstPeer.withPeerId) return firstPeerInFlight;
        throw new Error("third peer transfer failed");
      },
    );
    let reachedSharedCleanup = false;
    void fanoutPromise.then(() => {
      reachedSharedCleanup = true;
      events.push("shared-cleanup");
    });

    // Let all three setup attempts run. The fanout must remain pending because
    // peer-1's already-started transfer still owns the shared staged chunks.
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(events).toEqual([
      "open:peer-1",
      "send:peer-1",
      "open:peer-2",
      "open:peer-3",
      "send:peer-3",
    ]);
    expect(reachedSharedCleanup).toBe(false);

    finishFirstPeer();
    const result = await fanoutPromise;
    await Promise.resolve();

    expect(reachedSharedCleanup).toBe(true);
    expect(events.at(-1)).toBe("shared-cleanup");
    expect(result.startedTransfers).toBe(2);
    expect(
      result.outcomes.map((outcome) => ({
        peerId: outcome.peerId,
        status: outcome.status,
        phase: outcome.status === "failed" ? outcome.phase : undefined,
      })),
    ).toEqual([
      { peerId: "peer-1", status: "delivered", phase: undefined },
      { peerId: "peer-2", status: "failed", phase: "setup" },
      { peerId: "peer-3", status: "failed", phase: "transfer" },
    ]);
  });

  test("only pre-commit failure or explicit local cancellation removes sender history", () => {
    expect(
      shouldDeleteLocalMessageAfterFailure(false, false, false),
    ).toBe(true);
    expect(
      shouldDeleteLocalMessageAfterFailure(true, false, false),
    ).toBe(false);
    expect(
      shouldDeleteLocalMessageAfterFailure(false, true, false),
    ).toBe(false);
    expect(
      shouldDeleteLocalMessageAfterFailure(true, true, true),
    ).toBe(true);
  });
});

describe("in-flight message cipher follows the cryptographic transport", () => {
  test("reopening a DataChannel on the same PC reuses the message cipher", async () => {
    const epc = fakeConnection("peer");
    const messageKey = new Uint8Array(32).fill(7);
    const original = { epc, messageKey, header: header(1) };
    let gateCalls = 0;
    let stepCalls = 0;

    const rebound = await bindTransferCipherToConnection(
      original,
      epc,
      "room",
      {} as LibCrypto,
      async () => {
        gateCalls++;
      },
      async () => {
        stepCalls++;
        return { messageKey: new Uint8Array(32), header: header(2) };
      },
    );

    expect(rebound).toBe(original);
    expect(messageKey.every((byte) => byte === 7)).toBe(true);
    expect(gateCalls).toBe(0);
    expect(stepCalls).toBe(0);
  });

  test("replacement PC waits for its gate, ratchets once, and wipes the old key", async () => {
    const oldEpc = fakeConnection("peer");
    const replacement = fakeConnection("peer");
    const oldKey = new Uint8Array(32).fill(9);
    const newKey = new Uint8Array(32).fill(4);
    const events: string[] = [];

    const rebound = await bindTransferCipherToConnection(
      { epc: oldEpc, messageKey: oldKey, header: header(1) },
      replacement,
      "room",
      {} as LibCrypto,
      async (roomId, peerId) => {
        events.push(`gate:${roomId}:${peerId}`);
      },
      async (epc, roomId) => {
        events.push(
          `step:${roomId}:${String(epc === replacement)}`,
        );
        return { messageKey: newKey, header: header(2) };
      },
    );

    expect(events).toEqual(["gate:room:peer", "step:room:true"]);
    expect(oldKey.every((byte) => byte === 0)).toBe(true);
    expect(rebound.epc).toBe(replacement);
    expect(rebound.messageKey).toBe(newKey);
    expect(rebound.header.N).toBe(2);
  });

  test("replacement without an established ratchet fails without erasing the caller-owned key", async () => {
    const oldKey = new Uint8Array(32).fill(5);
    let stepCalled = false;

    await expect(
      bindTransferCipherToConnection(
        {
          epc: fakeConnection("peer"),
          messageKey: oldKey,
          header: header(1),
        },
        fakeConnection("peer", false),
        "room",
        {} as LibCrypto,
        async () => {},
        async () => {
          stepCalled = true;
          return { messageKey: new Uint8Array(32), header: header(2) };
        },
      ),
    ).rejects.toThrow("replacement connection has no ratchet state");

    expect(stepCalled).toBe(false);
    expect(oldKey.every((byte) => byte === 5)).toBe(true);
  });
});
