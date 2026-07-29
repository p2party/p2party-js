import { describe, expect, test } from "bun:test";

import {
  base64urlNoPad,
  pairEdgeId,
} from "../../src/blindRendezvous/derivations";
import {
  assertPlannerStateRoomBindingV1,
  decodePlannerAndExplicitStateV1,
  encodePlannerAndExplicitStateV1,
  validateAndCopyPlannerAndExplicitStateV1,
} from "../../src/blindRendezvous/plannerState";

import type {
  ActiveStableTopologyEdgeV1,
  ConnectionPlannerPolicyV1,
  PlannerAndExplicitStateV1,
  PlannerStateValidationLimitsV1,
  ProvisionalTopologyEdgeV1,
} from "../../src/blindRendezvous/plannerState";

const ROOM_CONTEXT_ID = new Uint8Array(32).fill(0x11);
const LIMITS: PlannerStateValidationLimitsV1 = {
  maxRoomMembers: 8,
  maxPairLedgerEntriesPerRoom: 8,
};

const bytes32 = (value: number): Uint8Array => new Uint8Array(32).fill(value);

const localPeerId = (value: number): string =>
  `peer.v1.${base64urlNoPad(bytes32(value))}`;

const POLICY: ConnectionPlannerPolicyV1 = {
  version: 1,
  mode: "sparse-ring",
  sparseRadius: 1,
  maxProvisionalEdges: 4,
  maxActiveStableEdges: 3,
  fullMeshMaxMembers: 4,
  allowOnDemandEdges: true,
};

const state = (
  overrides: Partial<PlannerAndExplicitStateV1> = {},
): PlannerAndExplicitStateV1 => ({
  version: 1,
  roomContextId: Uint8Array.from(ROOM_CONTEXT_ID),
  plannerPolicy: POLICY,
  requestedExplicitPeerIds: [localPeerId(0x40)],
  provisionalEdges: [],
  activeStableEdges: [],
  ...overrides,
});

const provisional = async (
  roomContextId: Uint8Array,
  first: number,
  second: number,
): Promise<ProvisionalTopologyEdgeV1> => {
  const endpoints = [bytes32(first), bytes32(second)] as const;
  return {
    pairEdgeId: await pairEdgeId(roomContextId, endpoints[0], endpoints[1]),
    endpointPresenceOperationIds: endpoints,
    remoteLocalPeerId: localPeerId(second),
  };
};

const active = (
  stableEdgeIdByte: number,
  remotePeerByte: number,
): ActiveStableTopologyEdgeV1 => ({
  stableEdgeId: bytes32(stableEdgeIdByte),
  remoteLocalPeerId: localPeerId(remotePeerByte),
});

describe("canonical planner and topology state", () => {
  test("round-trips canonical durable bytes and owns every caller byte", async () => {
    const edge = await provisional(ROOM_CONTEXT_ID, 0x20, 0x30);
    const input = state({
      provisionalEdges: [edge],
      activeStableEdges: [active(0x60, 0x70)],
    });
    const encoded = encodePlannerAndExplicitStateV1(input, LIMITS);
    const expected = Uint8Array.from(encoded);
    const restored = decodePlannerAndExplicitStateV1(encoded, LIMITS);

    edge.pairEdgeId.fill(0xff);
    edge.endpointPresenceOperationIds[0].fill(0xff);
    input.roomContextId.fill(0xff);
    input.activeStableEdges[0].stableEdgeId.fill(0xff);
    encoded.fill(0xff);

    expect(encodePlannerAndExplicitStateV1(restored, LIMITS)).toEqual(expected);
    expect(
      await assertPlannerStateRoomBindingV1(restored, ROOM_CONTEXT_ID, LIMITS),
    ).toEqual(restored);

    const malformed = Uint8Array.from(expected);
    malformed[0] ^= 0xff;
    expect(() => decodePlannerAndExplicitStateV1(malformed, LIMITS)).toThrow();
    expect(() =>
      decodePlannerAndExplicitStateV1(new Uint8Array(0), LIMITS),
    ).toThrow("must not be empty");
  });

  test("enforces every contextual planner-policy inequality", () => {
    const invalidPolicies: readonly [
      Partial<ConnectionPlannerPolicyV1>,
      string,
    ][] = [
      [{ sparseRadius: 8 }, "sparseRadius must be below"],
      [{ maxActiveStableEdges: 8 }, "must be below maxRoomMembers"],
      [
        { sparseRadius: 2, maxActiveStableEdges: 3 },
        "cannot realize sparseRadius",
      ],
      [
        { maxActiveStableEdges: 4, maxProvisionalEdges: 3 },
        "must not exceed maxProvisionalEdges",
      ],
      [{ maxProvisionalEdges: 9 }, "exceeds maxPairLedgerEntriesPerRoom"],
      [{ fullMeshMaxMembers: 5 }, "exceeds the stable-edge or room cap"],
      [{ sparseRadius: 0 }, "positive safe integer"],
    ];

    for (const [override, message] of invalidPolicies) {
      expect(() =>
        validateAndCopyPlannerAndExplicitStateV1(
          state({ plannerPolicy: { ...POLICY, ...override } }),
          LIMITS,
        ),
      ).toThrow(message);
    }

    expect(
      validateAndCopyPlannerAndExplicitStateV1(
        state({ plannerPolicy: { ...POLICY, mode: "explicit" } }),
        LIMITS,
      ).plannerPolicy.mode,
    ).toBe("explicit");
  });

  test("rejects malformed peers, duplicate topology subjects, and over-cap state", async () => {
    const first = await provisional(ROOM_CONTEXT_ID, 0x20, 0x30);
    const second = await provisional(ROOM_CONTEXT_ID, 0x20, 0x40);

    expect(() =>
      validateAndCopyPlannerAndExplicitStateV1(
        state({ requestedExplicitPeerIds: ["peer.v1.invalid"] }),
        LIMITS,
      ),
    ).toThrow("canonical peer.v1");

    expect(() =>
      validateAndCopyPlannerAndExplicitStateV1(
        state({
          provisionalEdges: [
            first,
            { ...second, pairEdgeId: first.pairEdgeId },
          ],
        }),
        LIMITS,
      ),
    ).toThrow("unique pairEdgeId");

    expect(() =>
      validateAndCopyPlannerAndExplicitStateV1(
        state({
          activeStableEdges: [active(0x50, 0x70), active(0x60, 0x70)],
        }),
        LIMITS,
      ),
    ).toThrow("unique remote local peer IDs");
    expect(() =>
      validateAndCopyPlannerAndExplicitStateV1(
        state({
          activeStableEdges: [active(0x50, 0x70), active(0x50, 0x71)],
        }),
        LIMITS,
      ),
    ).toThrow("unique stableEdgeId");

    const getterState = Object.defineProperty(
      { ...state() },
      "provisionalEdges",
      {
        enumerable: true,
        get: () => [],
      },
    );
    expect(() =>
      validateAndCopyPlannerAndExplicitStateV1(getterState, LIMITS),
    ).toThrow();
  });

  test("binds empty, active-only, and provisional rows to one exact room", async () => {
    const room = bytes32(0x11);
    const otherRoom = bytes32(0x12);
    const activeOnly = state({
      roomContextId: room,
      activeStableEdges: [active(0x60, 0x70)],
    });
    await expect(
      assertPlannerStateRoomBindingV1(activeOnly, otherRoom, LIMITS),
    ).rejects.toThrow("another room context");

    const edge = await provisional(room, 0x20, 0x30);
    const input = state({
      roomContextId: room,
      provisionalEdges: [edge],
    });
    const pending = assertPlannerStateRoomBindingV1(input, room, LIMITS);
    edge.pairEdgeId.fill(0xff);
    edge.endpointPresenceOperationIds[0].fill(0xff);
    room.fill(0xff);
    expect((await pending).provisionalEdges).toHaveLength(1);

    const boundRoom = bytes32(0x11);
    const wrongPair = state({
      roomContextId: boundRoom,
      provisionalEdges: [
        {
          ...(await provisional(boundRoom, 0x20, 0x30)),
          pairEdgeId: bytes32(0x99),
        },
      ],
    });
    await expect(
      assertPlannerStateRoomBindingV1(wrongPair, boundRoom, LIMITS),
    ).rejects.toThrow("wrong room pairEdgeId");
  });
});
