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

  // The bound is load-bearing in both directions and is pinned to a LITERAL
  // here. Too small and the memory of an eviction burst — handlePeerConnection
  // delivers each introduction twice, and the roster is re-sent on join, on
  // re-dial and on reconcile — falls out before the last stale frame lands, so
  // the replacement is torn down again. Too large and a long-lived edge keeps
  // growing a set it never reads. A test that read the constant back would
  // move with any edit to it and could never fail.
  test("an edge remembers exactly eight retired generations", () => {
    const generation = (n: number): string =>
      `${n.toString(16).padStart(8, "0")}-0000-4000-8000-000000000000`;

    for (let i = 0; i < 8; i++)
      markPeerSocketGenerationRetired(ROOM, PEER, generation(i));
    for (let i = 0; i < 8; i++)
      expect(isPeerSocketGenerationRetired(ROOM, PEER, generation(i))).toBe(
        true,
      );

    // The ninth evicts the OLDEST, and only the oldest.
    markPeerSocketGenerationRetired(ROOM, PEER, generation(8));
    expect(isPeerSocketGenerationRetired(ROOM, PEER, generation(0))).toBe(
      false,
    );
    for (let i = 1; i <= 8; i++)
      expect(isPeerSocketGenerationRetired(ROOM, PEER, generation(i))).toBe(
        true,
      );
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
  // "disconnected" is deliberately absent -- see the grace-window test below.
  test("a roster frame naming a new generation retires a transport that is not connected", () => {
    for (const connectionState of [
      "new",
      "connecting",
      "failed",
      "closed",
    ] as RTCPeerConnectionState[])
      expect(observe({ source: "roster", connectionState })).toBe(true);
  });

  // "disconnected" is not a dead edge. handleConnectToPeer answers it with an
  // ICE restart and only tears the transport down if it is STILL disconnected
  // 8 s later, and that repair usually succeeds. A peer's ordinary signaling
  // reconnect lands a changed roster generation constantly, so acting on one
  // inside that window would discard a transport that was about to heal itself
  // -- the same over-eagerness as C4, one state further along.
  test("a roster frame leaves a transport inside the ICE-repair grace window alone", () => {
    expect(observe({ source: "roster", connectionState: "disconnected" })).toBe(
      false,
    );
    // A `connection` frame still retires it: that one proves the peer really
    // did build a fresh transport, so there is nothing left to repair.
    expect(
      observe({ source: "connection", connectionState: "disconnected" }),
    ).toBe(true);
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
