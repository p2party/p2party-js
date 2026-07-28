import { describe, expect, test } from "bun:test";

import {
  reducePairOpenBudgetV1,
  validatePairOpenBudgetSnapshotV1,
} from "../../src/blindRendezvous/pairOpenBudget";

import type {
  PairOpenBudgetChargeV1,
  PairOpenBudgetLimitsV1,
  PairOpenBudgetSnapshotV1,
} from "../../src/blindRendezvous/pairOpenBudget";

const LOCAL_ROOM_ID = "A".repeat(43);
const LOCAL_PRESENCE_ID = new Uint8Array(32).fill(0x31);

const charge = (
  capturedReferenceWindow = 10n,
  completeEnvelopeBytes = 4_096,
): PairOpenBudgetChargeV1 => ({
  localRoomId: LOCAL_ROOM_ID,
  localPresenceOperationId: Uint8Array.from(LOCAL_PRESENCE_ID),
  capturedReferenceWindow,
  completeEnvelopeBytes,
});

const limits = (
  maxPairOpenTrialsPerPresenceWindow = 2,
  maxPairOpenBytesPerPresenceWindow = 8_192,
): PairOpenBudgetLimitsV1 => ({
  maxPairOpenTrialsPerPresenceWindow,
  maxPairOpenBytesPerPresenceWindow,
});

const prepare = (
  previous: PairOpenBudgetSnapshotV1 | null,
  nextCharge = charge(),
  nextLimits = limits(),
): PairOpenBudgetSnapshotV1 => {
  const result = reducePairOpenBudgetV1(previous, nextCharge, nextLimits);
  expect(result.result).toBe("prepared");
  if (result.result !== "prepared") throw new Error("expected preparation");
  return result.next;
};

describe("durable pair-open work budget", () => {
  test("creates the first row and charges the complete envelope", () => {
    const result = reducePairOpenBudgetV1(null, charge(), limits());
    expect(result).toEqual({
      result: "prepared",
      next: {
        version: 1,
        coordinate: {
          localRoomId: LOCAL_ROOM_ID,
          localPresenceOperationId: LOCAL_PRESENCE_ID,
          budgetLogicalWindow: 10n,
        },
        budgetRevision: 1n,
        reservedTrialCount: 1,
        reservedEnvelopeBytes: 4_096n,
        saturated: false,
      },
    });
  });

  test("accepts exact count and byte caps, then persists sticky saturation", () => {
    const first = prepare(null);
    const second = prepare(first);
    expect(second.reservedTrialCount).toBe(2);
    expect(second.reservedEnvelopeBytes).toBe(8_192n);

    const saturated = reducePairOpenBudgetV1(second, charge(), limits());
    expect(saturated.result).toBe("saturated");
    if (saturated.next === null) throw new Error("expected saturation write");
    expect(saturated.next).toEqual({
      ...second,
      budgetRevision: 3n,
      saturated: true,
    });

    expect(
      reducePairOpenBudgetV1(saturated.next, charge(), limits(10, 1_000_000)),
    ).toEqual({ result: "saturated", next: null });
  });

  test("an oversized first candidate saturates without consuming counters", () => {
    const saturated = reducePairOpenBudgetV1(
      null,
      charge(10n, 69_632),
      limits(2, 69_631),
    );
    expect(saturated.result).toBe("saturated");
    if (saturated.next === null) throw new Error("expected saturation write");
    expect(saturated.next.reservedTrialCount).toBe(0);
    expect(saturated.next.reservedEnvelopeBytes).toBe(0n);
    expect(saturated.next.saturated).toBe(true);
  });

  test("a newer window resets sticky saturation before applying its charge", () => {
    const saturated = reducePairOpenBudgetV1(
      null,
      charge(10n, 69_632),
      limits(2, 69_631),
    );
    if (saturated.next === null) throw new Error("expected saturation write");

    const resetAndSaturated = reducePairOpenBudgetV1(
      saturated.next,
      charge(11n, 69_632),
      limits(2, 69_631),
    );
    expect(resetAndSaturated).toEqual({
      result: "saturated",
      next: {
        ...saturated.next,
        coordinate: {
          ...saturated.next.coordinate,
          budgetLogicalWindow: 11n,
        },
        budgetRevision: 2n,
      },
    });
  });

  test("every repeated expensive trial is charged again", () => {
    const first = prepare(null, charge(), limits(3, 12_288));
    const retry = prepare(first, charge(), limits(3, 12_288));
    expect(retry.reservedTrialCount).toBe(2);
    expect(retry.reservedEnvelopeBytes).toBe(8_192n);
  });

  test("equal and older captures never reset, while one newer window does", () => {
    const first = prepare(null);
    const equal = prepare(first, charge(10n), limits(3, 12_288));
    const older = prepare(equal, charge(9n), limits(4, 16_384));
    expect(older.coordinate.budgetLogicalWindow).toBe(10n);
    expect(older.reservedTrialCount).toBe(3);

    const saturated = reducePairOpenBudgetV1(
      older,
      charge(10n),
      limits(3, 12_288),
    );
    if (saturated.next === null) throw new Error("expected saturation write");
    const reset = prepare(
      saturated.next,
      charge(11n, 69_632),
      limits(1, 69_632),
    );
    expect(reset.coordinate.budgetLogicalWindow).toBe(11n);
    expect(reset.budgetRevision).toBe(5n);
    expect(reset.reservedTrialCount).toBe(1);
    expect(reset.reservedEnvelopeBytes).toBe(69_632n);
    expect(reset.saturated).toBe(false);
  });

  test("binds a row to one room and local presence", () => {
    const first = prepare(null);
    expect(() =>
      reducePairOpenBudgetV1(
        first,
        {
          ...charge(),
          localPresenceOperationId: new Uint8Array(32).fill(0x32),
        },
        limits(),
      ),
    ).toThrow("another room or local presence");
    expect(() =>
      reducePairOpenBudgetV1(
        first,
        { ...charge(), localRoomId: "B".repeat(42) + "E" },
        limits(),
      ),
    ).toThrow("another room or local presence");
  });

  test("owns persisted and returned bytes across caller mutation", () => {
    const inputPresenceId = Uint8Array.from(LOCAL_PRESENCE_ID);
    const first = prepare(null, {
      ...charge(),
      localPresenceOperationId: inputPresenceId,
    });
    inputPresenceId.fill(0xff);
    expect(first.coordinate.localPresenceOperationId).toEqual(
      LOCAL_PRESENCE_ID,
    );

    const validated = validatePairOpenBudgetSnapshotV1(first);
    first.coordinate.localPresenceOperationId.fill(0xee);
    expect(validated.coordinate.localPresenceOperationId).toEqual(
      LOCAL_PRESENCE_ID,
    );
  });

  test("rejects malformed IDs, versions, limits, and revision overflow", () => {
    expect(() =>
      reducePairOpenBudgetV1(
        null,
        { ...charge(), localRoomId: "A".repeat(42) + "B" },
        limits(),
      ),
    ).toThrow("canonical base64url");
    expect(() => reducePairOpenBudgetV1(null, charge(), limits(0, 1))).toThrow(
      "positive safe integer",
    );
    expect(() =>
      reducePairOpenBudgetV1(null, charge(10n, 1), limits()),
    ).toThrow("must equal an operation payload class");
    expect(() =>
      reducePairOpenBudgetV1(null, charge(10n, 4_095), limits()),
    ).toThrow("must equal an operation payload class");
    expect(() =>
      validatePairOpenBudgetSnapshotV1({
        ...prepare(null),
        version: 2,
      }),
    ).toThrow("snapshot.version must be 1");
    expect(() =>
      validatePairOpenBudgetSnapshotV1({
        ...prepare(null),
        budgetRevision: 0n,
      }),
    ).toThrow("at least one");

    const maximumRevision = {
      ...prepare(null),
      budgetRevision: 0xffffffffffffffffn,
    };
    expect(() =>
      reducePairOpenBudgetV1(maximumRevision, charge(), limits(3, 12_288)),
    ).toThrow("budgetRevision overflow");
    expect(() =>
      reducePairOpenBudgetV1(maximumRevision, charge(11n), limits(3, 12_288)),
    ).toThrow("budgetRevision overflow");
  });

  test("rejects every unreachable persisted counter shape", () => {
    const first = prepare(null);
    const impossible = [
      {
        ...first,
        reservedTrialCount: 1,
        reservedEnvelopeBytes: 0n,
      },
      {
        ...first,
        reservedTrialCount: 0,
        reservedEnvelopeBytes: 4_096n,
      },
      {
        ...first,
        reservedTrialCount: 0,
        reservedEnvelopeBytes: 0n,
        saturated: false,
      },
      {
        ...first,
        reservedTrialCount: 1,
        reservedEnvelopeBytes: 4_097n,
      },
      {
        ...first,
        reservedTrialCount: 2,
        reservedEnvelopeBytes: 73_729n,
      },
      {
        ...first,
        reservedTrialCount: 2,
        reservedEnvelopeBytes: 8_192n,
      },
      {
        ...first,
        saturated: true,
      },
    ];

    for (const snapshot of impossible)
      expect(() => validatePairOpenBudgetSnapshotV1(snapshot)).toThrow(
        /reachable|prepared trial/,
      );

    expect(
      validatePairOpenBudgetSnapshotV1({
        ...first,
        reservedTrialCount: 0,
        reservedEnvelopeBytes: 0n,
        saturated: true,
      }),
    ).toEqual({
      ...first,
      reservedTrialCount: 0,
      reservedEnvelopeBytes: 0n,
      saturated: true,
    });
    expect(
      validatePairOpenBudgetSnapshotV1({
        ...first,
        reservedTrialCount: 2,
        reservedEnvelopeBytes: 73_728n,
        budgetRevision: 2n,
      }),
    ).toEqual({
      ...first,
      reservedTrialCount: 2,
      reservedEnvelopeBytes: 73_728n,
      budgetRevision: 2n,
    });
    expect(
      validatePairOpenBudgetSnapshotV1({
        ...first,
        coordinate: {
          ...first.coordinate,
          budgetLogicalWindow: 11n,
        },
        budgetRevision: 9n,
      }),
    ).toEqual({
      ...first,
      coordinate: {
        ...first.coordinate,
        budgetLogicalWindow: 11n,
      },
      budgetRevision: 9n,
    });
  });
});
