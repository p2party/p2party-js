import { describe, expect, test } from "bun:test";

import {
  consumedPairRoutingTagsV1,
  createEmptyPairAcceptedSlotLedgerV1,
  pairEdgeIsStalledV1,
  previewAuthenticatedPairSlotV1,
  recordAcceptedPairSlotV1,
  restorePairAcceptedSlotLedgerV1,
  snapshotPairAcceptedSlotLedgerV1,
} from "../../src/blindRendezvous/pairLedger";

import type {
  PairAcceptedSlotLedgerV1,
  PairAcceptedSlotLedgerSnapshotV1,
  PairSlotAcceptanceCandidateV1,
} from "../../src/blindRendezvous/pairLedger";
import type { PairStepKindV1 } from "../../src/blindRendezvous/pairPlaintext";

const bytes = (first: number, length = 32): Uint8Array =>
  Uint8Array.from({ length }, (_, index) => (first + index) & 0xff);

const hex = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const ENDPOINT_A = new Uint8Array(32).fill(0x10);
const ENDPOINT_B = new Uint8Array(32).fill(0x20);

interface CandidateOptions {
  readonly edge?: number;
  readonly operation?: number;
  readonly tag?: number;
  readonly response?: number | null;
  readonly kind?: PairStepKindV1;
  readonly direction?: 0 | 1;
  readonly pairSequence?: bigint;
  readonly acceptedLogicalWindow?: bigint;
  readonly retainThroughLogicalWindow?: bigint;
}

const candidate = (
  options: CandidateOptions = {},
): PairSlotAcceptanceCandidateV1 => {
  const operationId = new Uint8Array(32).fill(options.operation ?? 0x40);
  const exactOperationBytes = bytes(options.operation ?? 0x40, 80);
  return {
    coordinate: {
      pairEdgeId: new Uint8Array(32).fill(options.edge ?? 0x30),
      endpointPresenceOperationIds: [ENDPOINT_A, ENDPOINT_B],
      direction: options.direction ?? 0,
      pairSequence: options.pairSequence ?? 0n,
    },
    kind: options.kind ?? "IDENTITY_HELLO",
    acceptedOperationId: operationId,
    exactOperationBytes,
    acceptedLogicalWindow: options.acceptedLogicalWindow ?? 10n,
    retainThroughLogicalWindow: options.retainThroughLogicalWindow ?? 20n,
    routingTag: new Uint8Array(32).fill(options.tag ?? 0x50),
    authorChainPrefix: [
      {
        operationId,
        exactOperationBytes,
      },
    ],
    cachedExactResponse:
      options.response === null ? null : bytes(options.response ?? 0x60, 48),
  };
};

const accept = (
  ledger: PairAcceptedSlotLedgerV1,
  value: PairSlotAcceptanceCandidateV1,
): PairAcceptedSlotLedgerV1 => {
  const result = recordAcceptedPairSlotV1(ledger, value);
  expect(result.result).toBe("accepted");
  return result.ledger;
};

describe("pair accepted-slot ledger", () => {
  test("previews a new HELLO without persistence, then requires its exact response", () => {
    const ledger = createEmptyPairAcceptedSlotLedgerV1();
    const pendingHello = candidate({
      operation: 0x41,
      response: null,
    });

    expect(previewAuthenticatedPairSlotV1(ledger, pendingHello)).toEqual({
      result: "unoccupied",
    });
    expect(snapshotPairAcceptedSlotLedgerV1(ledger).entries).toEqual([]);
    expect(() => recordAcceptedPairSlotV1(ledger, pendingHello)).toThrow(
      "non-null for durable IDENTITY_HELLO acceptance",
    );
    expect(snapshotPairAcceptedSlotLedgerV1(ledger).entries).toEqual([]);

    const completedHello = {
      ...pendingHello,
      cachedExactResponse: bytes(0x71, 48),
    };
    const accepted = recordAcceptedPairSlotV1(ledger, completedHello);
    expect(accepted.result).toBe("accepted");
    expect(
      snapshotPairAcceptedSlotLedgerV1(accepted.ledger).entries,
    ).toHaveLength(1);
  });

  test("replays an exact accepted ID with freshly owned exact response bytes", () => {
    const value = candidate({ operation: 0x41, response: 0x71 });
    const accepted = accept(createEmptyPairAcceptedSlotLedgerV1(), value);
    const preview = previewAuthenticatedPairSlotV1(accepted, {
      ...value,
      cachedExactResponse: null,
    });
    expect(preview.result).toBe("replay");
    if (preview.result !== "replay") throw new Error("expected replay");
    expect(preview.cachedExactResponse).toEqual(value.cachedExactResponse);

    preview.cachedExactResponse?.fill(0xee);
    const secondPreview = previewAuthenticatedPairSlotV1(accepted, value);
    if (secondPreview.result !== "replay") throw new Error("expected replay");
    expect(secondPreview.cachedExactResponse).toEqual(
      value.cachedExactResponse,
    );

    const firstReplay = recordAcceptedPairSlotV1(accepted, value);
    expect(firstReplay.result).toBe("replay");
    expect(firstReplay.ledger).toBe(accepted);
    if (firstReplay.result !== "replay") throw new Error("expected replay");
    expect(firstReplay.cachedExactResponse).toEqual(value.cachedExactResponse);

    firstReplay.cachedExactResponse?.fill(0xff);
    const secondReplay = recordAcceptedPairSlotV1(accepted, value);
    if (secondReplay.result !== "replay") throw new Error("expected replay");
    expect(secondReplay.cachedExactResponse).toEqual(value.cachedExactResponse);
    expect(secondReplay.cachedExactResponse).not.toBe(
      firstReplay.cachedExactResponse,
    );
  });

  test("previews forks and stalls without materializing either state", () => {
    const first = candidate({
      operation: 0x21,
      kind: "PQ_CONTROL",
      pairSequence: 2n,
    });
    const conflicting = candidate({
      operation: 0x81,
      kind: "PAIR_CHECKPOINT",
      response: null,
      pairSequence: 2n,
    });
    const later = candidate({
      operation: 0x82,
      kind: "PQ_CONTROL",
      pairSequence: 3n,
      tag: 0x52,
    });
    const ledger = accept(createEmptyPairAcceptedSlotLedgerV1(), first);
    const before = snapshotPairAcceptedSlotLedgerV1(ledger);

    const preview = previewAuthenticatedPairSlotV1(ledger, conflicting);
    expect(preview.result).toBe("fork");
    if (preview.result !== "fork") throw new Error("expected fork");
    const expectedProof = preview.forkProofOperationIds.map(hex);
    preview.forkProofOperationIds[0].fill(0xff);

    const repeatedPreview = previewAuthenticatedPairSlotV1(ledger, conflicting);
    if (repeatedPreview.result !== "fork")
      throw new Error("expected repeated fork");
    expect(repeatedPreview.forkProofOperationIds.map(hex)).toEqual(
      expectedProof,
    );
    expect(snapshotPairAcceptedSlotLedgerV1(ledger)).toEqual(before);
    expect(pairEdgeIsStalledV1(ledger, first.coordinate.pairEdgeId)).toBe(
      false,
    );
    expect(previewAuthenticatedPairSlotV1(ledger, later)).toEqual({
      result: "unoccupied",
    });

    const recordedFork = recordAcceptedPairSlotV1(ledger, conflicting);
    if (recordedFork.result !== "fork") throw new Error("expected fork");
    expect(previewAuthenticatedPairSlotV1(recordedFork.ledger, later)).toEqual({
      result: "edge-stalled",
    });
  });

  test("preserves a null cached response on exact replay", () => {
    const value = candidate({
      operation: 0x42,
      kind: "PAIR_CHECKPOINT",
      response: null,
      pairSequence: 8n,
    });
    const accepted = accept(createEmptyPairAcceptedSlotLedgerV1(), value);
    const replay = recordAcceptedPairSlotV1(accepted, value);
    expect(replay.result).toBe("replay");
    if (replay.result !== "replay") throw new Error("expected replay");
    expect(replay.cachedExactResponse).toBeNull();
    expect(replay.ledger).toBe(accepted);
  });

  test("excludes kind from the coordinate and stores an order-independent fork proof", () => {
    const low = candidate({
      operation: 0x21,
      kind: "PQ_CONTROL",
      pairSequence: 2n,
    });
    const highDifferentKind = candidate({
      operation: 0x81,
      kind: "PAIR_CHECKPOINT",
      response: null,
      pairSequence: 2n,
    });

    const lowThenHigh = recordAcceptedPairSlotV1(
      accept(createEmptyPairAcceptedSlotLedgerV1(), low),
      highDifferentKind,
    );
    const highThenLow = recordAcceptedPairSlotV1(
      accept(createEmptyPairAcceptedSlotLedgerV1(), highDifferentKind),
      low,
    );
    expect(lowThenHigh.result).toBe("fork");
    expect(highThenLow.result).toBe("fork");
    if (lowThenHigh.result !== "fork" || highThenLow.result !== "fork")
      throw new Error("expected forks");
    expect(lowThenHigh.forkProofOperationIds).toEqual(
      highThenLow.forkProofOperationIds,
    );
    expect(lowThenHigh.forkProofOperationIds.map(hex)).toEqual([
      hex(low.acceptedOperationId),
      hex(highDifferentKind.acceptedOperationId),
    ]);
    expect(
      pairEdgeIsStalledV1(lowThenHigh.ledger, low.coordinate.pairEdgeId),
    ).toBe(true);
    expect(
      pairEdgeIsStalledV1(highThenLow.ledger, low.coordinate.pairEdgeId),
    ).toBe(true);
  });

  test("retains the bytewise-lowest two fork IDs when a third ID arrives", () => {
    const high = candidate({
      operation: 0x90,
      kind: "PQ_CONTROL",
      pairSequence: 2n,
    });
    const middle = candidate({
      operation: 0x50,
      kind: "PAIR_CHECKPOINT",
      response: null,
      pairSequence: 2n,
    });
    const low = candidate({
      operation: 0x10,
      kind: "HEAL_COMPLETE",
      pairSequence: 2n,
    });
    const firstFork = recordAcceptedPairSlotV1(
      accept(createEmptyPairAcceptedSlotLedgerV1(), high),
      middle,
    );
    if (firstFork.result !== "fork") throw new Error("expected fork");
    const secondFork = recordAcceptedPairSlotV1(firstFork.ledger, low);
    expect(secondFork.result).toBe("fork");
    if (secondFork.result !== "fork") throw new Error("expected fork");
    expect(secondFork.forkProofOperationIds.map(hex)).toEqual([
      hex(low.acceptedOperationId),
      hex(middle.acceptedOperationId),
    ]);
    const stored = snapshotPairAcceptedSlotLedgerV1(secondFork.ledger);
    expect(stored.entries[0].forkProofOperationIds?.map(hex)).toEqual([
      hex(low.acceptedOperationId),
      hex(middle.acceptedOperationId),
    ]);
  });

  test("stalls only the forked edge in a room-global ledger", () => {
    const edgeA = candidate({
      edge: 0x31,
      operation: 0x41,
      kind: "PQ_CONTROL",
      pairSequence: 2n,
    });
    const edgeAFork = candidate({
      edge: 0x31,
      operation: 0x42,
      kind: "PAIR_CHECKPOINT",
      response: null,
      pairSequence: 2n,
    });
    const edgeB = candidate({ edge: 0x32, operation: 0x51, tag: 0x61 });
    const edgeANext = candidate({
      edge: 0x31,
      operation: 0x43,
      pairSequence: 3n,
      kind: "PQ_CONTROL",
    });

    const fork = recordAcceptedPairSlotV1(
      accept(createEmptyPairAcceptedSlotLedgerV1(), edgeA),
      edgeAFork,
    );
    if (fork.result !== "fork") throw new Error("expected fork");
    const blocked = recordAcceptedPairSlotV1(fork.ledger, edgeANext);
    expect(blocked).toEqual({ result: "edge-stalled", ledger: fork.ledger });

    const acceptedOther = recordAcceptedPairSlotV1(fork.ledger, edgeB);
    expect(acceptedOther.result).toBe("accepted");
    expect(
      pairEdgeIsStalledV1(acceptedOther.ledger, edgeA.coordinate.pairEdgeId),
    ).toBe(true);
    expect(
      pairEdgeIsStalledV1(acceptedOther.ledger, edgeB.coordinate.pairEdgeId),
    ).toBe(false);
  });

  test("derives canonical consumed tags solely from accepted entries", () => {
    const highTag = candidate({
      edge: 0x41,
      operation: 0x61,
      tag: 0x80,
    });
    const lowTag = candidate({
      edge: 0x42,
      operation: 0x62,
      tag: 0x20,
    });
    let ledger = createEmptyPairAcceptedSlotLedgerV1();
    ledger = accept(ledger, highTag);
    ledger = accept(ledger, lowTag);

    expect(consumedPairRoutingTagsV1(ledger).map(hex)).toEqual([
      hex(lowTag.routingTag),
      hex(highTag.routingTag),
    ]);
    expect(Object.keys(snapshotPairAcceptedSlotLedgerV1(ledger))).toEqual([
      "version",
      "entries",
    ]);
  });

  test("preview and record share strict candidate and ledger validation", () => {
    const ledger = createEmptyPairAcceptedSlotLedgerV1();
    const malformed = {
      ...candidate(),
      exactOperationBytes: new Uint8Array(0),
    };

    expect(() => previewAuthenticatedPairSlotV1(ledger, malformed)).toThrow(
      "exactOperationBytes must not be empty",
    );
    expect(() => recordAcceptedPairSlotV1(ledger, malformed)).toThrow(
      "exactOperationBytes must not be empty",
    );
    expect(() =>
      previewAuthenticatedPairSlotV1(
        {} as PairAcceptedSlotLedgerV1,
        candidate(),
      ),
    ).toThrow("genuine process-local handle");
  });

  test("rejects operation-ID or one-use-tag reuse across coordinates", () => {
    const first = candidate({ edge: 0x21, operation: 0x31, tag: 0x41 });
    const accepted = accept(createEmptyPairAcceptedSlotLedgerV1(), first);
    const reusedOperationId = candidate({
      edge: 0x22,
      operation: 0x31,
      tag: 0x42,
    });
    const reusedRoutingTag = candidate({
      edge: 0x22,
      operation: 0x32,
      tag: 0x41,
    });

    expect(() =>
      previewAuthenticatedPairSlotV1(accepted, reusedOperationId),
    ).toThrow("one operation ID must not bind two");
    expect(() => recordAcceptedPairSlotV1(accepted, reusedOperationId)).toThrow(
      "one operation ID must not bind two",
    );
    expect(() =>
      previewAuthenticatedPairSlotV1(accepted, reusedRoutingTag),
    ).toThrow("one-use routing tags must be unique");
    expect(() => recordAcceptedPairSlotV1(accepted, reusedRoutingTag)).toThrow(
      "one-use routing tags must be unique",
    );
  });

  test("owns candidate, snapshot, proof, and replay bytes across mutation", () => {
    const value = candidate({ operation: 0x45, response: 0x65 });
    const expectedOperationId = Uint8Array.from(value.acceptedOperationId);
    const expectedResponse = Uint8Array.from(
      value.cachedExactResponse ?? new Uint8Array(0),
    );
    const accepted = accept(createEmptyPairAcceptedSlotLedgerV1(), value);

    value.acceptedOperationId.fill(0xff);
    value.exactOperationBytes.fill(0xff);
    value.routingTag.fill(0xff);
    value.authorChainPrefix[0].operationId.fill(0xff);
    value.cachedExactResponse?.fill(0xff);

    const firstSnapshot = snapshotPairAcceptedSlotLedgerV1(accepted);
    expect(firstSnapshot.entries[0].acceptedOperationId).toEqual(
      expectedOperationId,
    );
    firstSnapshot.entries[0].acceptedOperationId.fill(0xee);
    firstSnapshot.entries[0].exactOperationBytes.fill(0xee);
    firstSnapshot.entries[0].authorChainPrefix[0].operationId.fill(0xee);
    firstSnapshot.entries[0].cachedExactResponse?.fill(0xee);

    const secondSnapshot = snapshotPairAcceptedSlotLedgerV1(accepted);
    expect(secondSnapshot.entries[0].acceptedOperationId).toEqual(
      expectedOperationId,
    );
    expect(secondSnapshot.entries[0].cachedExactResponse).toEqual(
      expectedResponse,
    );

    const replayCandidate = candidate({ operation: 0x45, response: 0x99 });
    const replay = recordAcceptedPairSlotV1(accepted, replayCandidate);
    if (replay.result !== "replay") throw new Error("expected replay");
    expect(replay.cachedExactResponse).toEqual(expectedResponse);
  });

  test("strictly restores only canonical, internally consistent snapshots", () => {
    const first = candidate({ edge: 0x21, operation: 0x31 });
    const second = candidate({
      edge: 0x22,
      operation: 0x32,
      tag: 0x52,
    });
    let ledger = createEmptyPairAcceptedSlotLedgerV1();
    ledger = accept(ledger, second);
    ledger = accept(ledger, first);
    const snapshot = snapshotPairAcceptedSlotLedgerV1(ledger);
    const restored = restorePairAcceptedSlotLedgerV1(snapshot);
    expect(snapshotPairAcceptedSlotLedgerV1(restored)).toEqual(snapshot);

    const helloWithoutResponse: PairAcceptedSlotLedgerSnapshotV1 = {
      version: 1,
      entries: [
        {
          version: 1,
          ...candidate({ operation: 0x61, response: null }),
          forkProofOperationIds: null,
        },
      ],
    };
    expect(() => restorePairAcceptedSlotLedgerV1(helloWithoutResponse)).toThrow(
      "non-null for durable IDENTITY_HELLO acceptance",
    );

    const reversed: PairAcceptedSlotLedgerSnapshotV1 = {
      ...snapshot,
      entries: [...snapshot.entries].reverse(),
    };
    expect(() => restorePairAcceptedSlotLedgerV1(reversed)).toThrow(
      "canonically sorted",
    );

    const invalidWindow: PairAcceptedSlotLedgerSnapshotV1 = {
      ...snapshot,
      entries: [
        {
          ...snapshot.entries[0],
          retainThroughLogicalWindow: (1n << 64n) + 1n,
        },
        ...snapshot.entries.slice(1),
      ],
    };
    expect(() => restorePairAcceptedSlotLedgerV1(invalidWindow)).toThrow(
      "unsigned 64-bit range",
    );

    const duplicateTag: PairAcceptedSlotLedgerSnapshotV1 = {
      ...snapshot,
      entries: [
        snapshot.entries[0],
        {
          ...snapshot.entries[1],
          routingTag: snapshot.entries[0].routingTag,
        },
      ],
    };
    expect(() => restorePairAcceptedSlotLedgerV1(duplicateTag)).toThrow(
      "one-use routing tags must be unique",
    );

    const duplicateOperationId: PairAcceptedSlotLedgerSnapshotV1 = {
      ...snapshot,
      entries: [
        snapshot.entries[0],
        {
          ...snapshot.entries[1],
          acceptedOperationId: snapshot.entries[0].acceptedOperationId,
          authorChainPrefix: [
            {
              operationId: snapshot.entries[0].acceptedOperationId,
              exactOperationBytes: snapshot.entries[1].exactOperationBytes,
            },
          ],
        },
      ],
    };
    expect(() => restorePairAcceptedSlotLedgerV1(duplicateOperationId)).toThrow(
      "one operation ID must not bind two",
    );

    const fork = recordAcceptedPairSlotV1(
      accept(createEmptyPairAcceptedSlotLedgerV1(), first),
      candidate({ edge: 0x21, operation: 0x32, tag: 0x41 }),
    );
    if (fork.result !== "fork") throw new Error("expected fork");
    const forkSnapshot = snapshotPairAcceptedSlotLedgerV1(fork.ledger);
    const shortProof: PairAcceptedSlotLedgerSnapshotV1 = {
      ...forkSnapshot,
      entries: [
        {
          ...forkSnapshot.entries[0],
          forkProofOperationIds: [
            forkSnapshot.entries[0].forkProofOperationIds?.[0] ??
              new Uint8Array(32),
          ] as unknown as readonly [Uint8Array, Uint8Array],
        },
      ],
    };
    expect(() => restorePairAcceptedSlotLedgerV1(shortProof)).toThrow(
      "must contain exactly two IDs",
    );
  });
});
