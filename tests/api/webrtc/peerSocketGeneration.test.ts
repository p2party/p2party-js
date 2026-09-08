import { afterEach, describe, expect, test } from "bun:test";

import {
  clearRetiredPeerSocketGenerations,
  comparePeerSocketGeneration,
  isCanonicalSocketGeneration,
  isPeerSocketGenerationRetired,
  markPeerSocketGenerationRetired,
  shouldRetireTransportForSocketGeneration,
} from "../../../src/api/webrtc/peerSocketGeneration";

const G1 = "11111111-1111-4111-8111-111111111111";
const G2 = "22222222-2222-4222-8222-222222222222";
const G3 = "33333333-3333-4333-8333-333333333333";

const ROOM = "00000000-0000-4000-8000-0000000000a1";
const PEER = "00000000-0000-4000-8000-0000000000a2";

afterEach(() => {
  clearRetiredPeerSocketGenerations(ROOM, PEER);
});

describe("peer socket generation", () => {
  test("only a UUIDv4 counts", () => {
    expect(isCanonicalSocketGeneration(G1)).toBe(true);
    expect(isCanonicalSocketGeneration("")).toBe(false);
    expect(isCanonicalSocketGeneration(undefined)).toBe(false);
    expect(isCanonicalSocketGeneration(42)).toBe(false);
    expect(isCanonicalSocketGeneration("not-a-uuid")).toBe(false);
    // A v1 UUID is not what the server mints and must not be trusted as one.
    expect(
      isCanonicalSocketGeneration("11111111-1111-1111-8111-111111111111"),
    ).toBe(false);
  });

  test("the same generation is unchanged", () => {
    expect(comparePeerSocketGeneration(G1, G1)).toBe("unchanged");
  });

  // C1: this verdict is what makes the peer rebuild against the live session.
  test("a different generation is changed", () => {
    expect(comparePeerSocketGeneration(G1, G2)).toBe("changed");
  });

  test("a pre-generation server (or a malformed value) is unknown, never changed", () => {
    // Old server -> new client: the field is absent. The client must behave
    // exactly as 0.14.7 does rather than tearing edges down on every frame.
    expect(comparePeerSocketGeneration(G1, undefined)).toBe("unknown");
    expect(comparePeerSocketGeneration(G1, "")).toBe("unknown");
    expect(comparePeerSocketGeneration(G1, "garbage")).toBe("unknown");
    expect(comparePeerSocketGeneration(undefined, G1)).toBe("unknown");
    expect(comparePeerSocketGeneration(undefined, undefined)).toBe("unknown");
  });
});

describe("retired peer socket generations", () => {
  test("a generation is retired per room/peer edge and does not leak", () => {
    const otherPeer = "00000000-0000-4000-8000-0000000000a3";
    expect(isPeerSocketGenerationRetired(ROOM, PEER, G1)).toBe(false);
    markPeerSocketGenerationRetired(ROOM, PEER, G1);
    expect(isPeerSocketGenerationRetired(ROOM, PEER, G1)).toBe(true);
    expect(isPeerSocketGenerationRetired(ROOM, otherPeer, G1)).toBe(false);
    clearRetiredPeerSocketGenerations(ROOM, PEER);
    expect(isPeerSocketGenerationRetired(ROOM, PEER, G1)).toBe(false);
  });

  test("a non-canonical generation is never recorded as retired", () => {
    markPeerSocketGenerationRetired(ROOM, PEER, "");
    markPeerSocketGenerationRetired(ROOM, PEER, undefined);
    expect(isPeerSocketGenerationRetired(ROOM, PEER, "")).toBe(false);
    expect(isPeerSocketGenerationRetired(ROOM, PEER, undefined)).toBe(false);
  });
});

describe("shouldRetireTransportForSocketGeneration", () => {
  const observe = (
    overrides: Partial<
      Parameters<typeof shouldRetireTransportForSocketGeneration>[0]
    > = {},
  ) =>
    shouldRetireTransportForSocketGeneration({
      roomId: ROOM,
      peerId: PEER,
      recorded: G1,
      observed: G2,
      source: "connection",
      connectionState: "connected",
      ...overrides,
    });

  // C1: only the `connection` frame proves a genuinely fresh remote transport.
  // It is emitted from exactly one path (handleConnectToPeer's connectWithPeer)
  // and that path is reachable only after the peer built a new transport.
  test("a connection frame naming a new generation retires even a connected transport", () => {
    expect(observe()).toBe(true);
  });

  // C4 REGRESSION GUARD. Roster introductions are re-sent on join, on redial
  // AND on reconcile, and signaling reconnect is now automatic, so a healthy
  // session routinely sees a changed generation in a roster it did not need.
  // Acting on it there is exactly the bug the reconnect work just fixed.
  test("a roster frame naming a new generation leaves a connected transport alone", () => {
    expect(observe({ source: "roster" })).toBe(false);
  });

  test("an unattributed frame is treated as a roster frame", () => {
    expect(observe({ source: undefined })).toBe(false);
  });

  // The stranded responder of C1: no channel, no description, nothing watching.
  test("a roster frame naming a new generation retires a transport that is not connected", () => {
    for (const connectionState of [
      "new",
      "connecting",
      "disconnected",
      "failed",
      "closed",
    ] as RTCPeerConnectionState[])
      expect(observe({ source: "roster", connectionState })).toBe(true);
  });

  test("an absent or malformed generation never retires anything", () => {
    expect(observe({ observed: undefined })).toBe(false);
    expect(observe({ observed: "" })).toBe(false);
    expect(observe({ observed: "garbage" })).toBe(false);
    expect(observe({ recorded: undefined })).toBe(false);
    expect(observe({ recorded: "", observed: G2 })).toBe(false);
  });

  test("the same generation never retires anything", () => {
    expect(observe({ observed: G1 })).toBe(false);
  });

  // handlePeerConnection can deliver one introduction twice (directly and via
  // pub/sub) and frames can arrive out of order, so a bare `recorded !==
  // observed` would tear the replacement down again on the way back. The
  // generation is a UUIDv4: nothing about it says which one is newer.
  test("a frame naming an already-retired generation is ignored", () => {
    markPeerSocketGenerationRetired(ROOM, PEER, G1);
    expect(observe({ recorded: G2, observed: G1 })).toBe(false);
    // ... while a genuinely new third generation still retires.
    expect(observe({ recorded: G2, observed: G3 })).toBe(true);
  });
});
