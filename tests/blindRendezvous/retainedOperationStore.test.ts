import { describe, expect, test } from "bun:test";

import {
  RetainedOperationStoreError,
  decodeRetainedOperationWindowManifestV1,
  encodeRetainedOperationWindowManifestV1,
  planRetainedOperationAdmissionV1,
  prepareRetainedOperationWindowInitializationV1,
  validateAndCopyRetainedOperationContentRowV1,
  validateAndCopyRetainedOperationWindowExactCaptureV1,
} from "../../src/blindRendezvous/retainedOperationStore";
import {
  deriveOperationId,
  encodeOperation,
} from "../../src/blindRendezvous/operation";

import type { AuthenticatedRoomOperationV1 } from "../../src/blindRendezvous/operation";
import type {
  RetainedOperationAdmissionPlanV1,
  RetainedOperationContentRowV1,
  RetainedOperationStoreCasRequestV1,
  RetainedOperationWindowExactCaptureV1,
  RetainedOperationWindowManifestV1,
} from "../../src/blindRendezvous/retainedOperationStore";

const U64_MAX = 0xffffffffffffffffn;
const ROOM_ID = new Uint8Array(32).fill(0x31);
const OTHER_ROOM_ID = new Uint8Array(32).fill(0x32);
const REFERENCE_WINDOW = 1_000n;
const RETAIN_THROUGH_WINDOW = 1_100n;

const compareBytes = (left: Uint8Array, right: Uint8Array): number => {
  for (let index = 0; index < Math.min(left.length, right.length); index++) {
    const difference = left[index] - right[index];
    if (difference !== 0) return difference;
  }
  return left.length - right.length;
};

const expectBytesEqual = (left: Uint8Array, right: Uint8Array): void => {
  expect([...left]).toEqual([...right]);
};

const hex = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const operationFor = (marker: number): AuthenticatedRoomOperationV1 => ({
  version: 1,
  roomContextConfirmation: new Uint8Array(32).fill(marker ^ 0x11),
  logicalWindow: REFERENCE_WINDOW,
  expiresAfterWindow: REFERENCE_WINDOW + 10n,
  lifetime: "WINDOW_TRANSIENT",
  authorEpochEd25519Key: new Uint8Array(32).fill(marker ^ 0x22),
  authorSequence: 0n,
  previousAuthorOperationId: null,
  kind: "STORE_HINT",
  semanticSlot: new Uint8Array(32).fill(marker ^ 0x33),
  dependencies: [],
  operationPayloadClass: 0,
  fixedPayload: Uint8Array.of(marker),
  operationPadding: new Uint8Array(),
  // Intentionally not a valid signature. The retained store proves content
  // addressing only; ordinary operation validation remains the sole verifier.
  authorSignature: new Uint8Array(64).fill(marker ^ 0x44),
});

const contentRow = async (
  marker: number,
  roomContextId: Uint8Array = ROOM_ID,
): Promise<RetainedOperationContentRowV1> => {
  const operation = operationFor(marker);
  return {
    version: 1,
    roomContextId: Uint8Array.from(roomContextId),
    operationId: await deriveOperationId(operation),
    exactOperationBytes: encodeOperation(operation),
  };
};

const sortedRows = (
  rows: readonly RetainedOperationContentRowV1[],
): readonly RetainedOperationContentRowV1[] =>
  [...rows].sort((left, right) =>
    compareBytes(left.operationId, right.operationId),
  );

const manifestFor = (
  rows: readonly RetainedOperationContentRowV1[],
  overrides: Partial<RetainedOperationWindowManifestV1> = {},
): RetainedOperationWindowManifestV1 => {
  const sorted = sortedRows(rows);
  return {
    version: 1,
    roomContextId: Uint8Array.from(ROOM_ID),
    referenceWindow: REFERENCE_WINDOW,
    retainThroughLogicalWindow: RETAIN_THROUGH_WINDOW,
    completeness: "complete",
    operationIds: sorted.map((row) => Uint8Array.from(row.operationId)),
    retainedOperationCount: sorted.length,
    retainedOperationBytes: sorted.reduce(
      (total, row) => total + BigInt(row.exactOperationBytes.length),
      0n,
    ),
    maxRetainedValidOperationsPerRoom: 32,
    maxRetainedValidOperationBytesPerRoom: 1_000_000n,
    firstRejectedOperationId: null,
    ...overrides,
  };
};

const captureFor = (
  rows: readonly RetainedOperationContentRowV1[],
  overrides: Partial<RetainedOperationWindowManifestV1> = {},
  recordRevision = 7n,
): RetainedOperationWindowExactCaptureV1 => {
  const sorted = sortedRows(rows);
  return {
    manifest: {
      kind: "present",
      exactManifestBytes: encodeRetainedOperationWindowManifestV1(
        manifestFor(sorted, overrides),
      ),
      recordRevision,
    },
    operations: sorted.map((row) => ({
      version: 1,
      roomContextId: Uint8Array.from(row.roomContextId),
      operationId: Uint8Array.from(row.operationId),
      exactOperationBytes: Uint8Array.from(row.exactOperationBytes),
    })),
  };
};

const exactNextManifestBytes = (
  request: RetainedOperationStoreCasRequestV1,
): Uint8Array => request.mutation.exactNextManifestBytes;

const applyPreparedRequest = (
  current: RetainedOperationWindowExactCaptureV1,
  request: RetainedOperationStoreCasRequestV1,
  recordRevision: bigint,
): RetainedOperationWindowExactCaptureV1 => {
  const operations =
    request.mutation.kind === "insert-operation-and-replace-manifest"
      ? sortedRows([...current.operations, request.mutation.operation])
      : current.operations;
  return {
    manifest: {
      kind: "present",
      exactManifestBytes: Uint8Array.from(exactNextManifestBytes(request)),
      recordRevision,
    },
    operations: operations.map((row) => ({
      version: 1,
      roomContextId: Uint8Array.from(row.roomContextId),
      operationId: Uint8Array.from(row.operationId),
      exactOperationBytes: Uint8Array.from(row.exactOperationBytes),
    })),
  };
};

const initializedCapture = (
  overrides: Partial<{
    maxRetainedValidOperationsPerRoom: number;
    maxRetainedValidOperationBytesPerRoom: bigint;
  }> = {},
): RetainedOperationWindowExactCaptureV1 => {
  const request = prepareRetainedOperationWindowInitializationV1({
    roomContextId: ROOM_ID,
    referenceWindow: REFERENCE_WINDOW,
    retainThroughLogicalWindow: RETAIN_THROUGH_WINDOW,
    maxRetainedValidOperationsPerRoom:
      overrides.maxRetainedValidOperationsPerRoom ?? 32,
    maxRetainedValidOperationBytesPerRoom:
      overrides.maxRetainedValidOperationBytesPerRoom ?? 1_000_000n,
  });
  return {
    manifest: {
      kind: "present",
      exactManifestBytes: Uint8Array.from(exactNextManifestBytes(request)),
      recordRevision: 0n,
    },
    operations: [],
  };
};

const requireRequest = (
  plan: RetainedOperationAdmissionPlanV1,
  kind: "accept-operation" | "mark-incomplete-overcapacity",
): RetainedOperationStoreCasRequestV1 => {
  expect(plan.kind).toBe(kind);
  if (
    plan.kind !== "accept-operation" &&
    plan.kind !== "mark-incomplete-overcapacity"
  )
    throw new Error(`expected a prepared request, received ${plan.kind}`);
  return plan.request;
};

const withCustomPrototype = (value: object, onRead: () => void): object => {
  const prototype = Object.defineProperty({}, "trap", {
    enumerable: true,
    get: () => {
      onRead();
      return true;
    },
  });
  return Object.create(prototype, Object.getOwnPropertyDescriptors(value));
};

describe("retained-operation local persistence foundation", () => {
  test("canonically round-trips one deterministic local manifest without exporting its descriptor", async () => {
    const row = await contentRow(0x10);
    const manifest = manifestFor([row]);
    const first = encodeRetainedOperationWindowManifestV1(manifest);
    const second = encodeRetainedOperationWindowManifestV1({
      ...manifest,
      roomContextId: Uint8Array.from(manifest.roomContextId),
      operationIds: manifest.operationIds.map((id) => Uint8Array.from(id)),
    });
    expectBytesEqual(first, second);

    const decoded = decodeRetainedOperationWindowManifestV1(first);
    expect(decoded).toEqual(manifest);
    expect(decoded).not.toBe(manifest);
    expect(decoded.roomContextId).not.toBe(manifest.roomContextId);
    expect(decoded.operationIds[0]).not.toBe(manifest.operationIds[0]);

    const exports =
      await import("../../src/blindRendezvous/retainedOperationStore");
    expect("retainedOperationWindowManifestV1Schema" in exports).toBe(false);
    expect("coreReduce" in exports).toBe(false);
  });

  test("strict manifest encoding rejects noncanonical sets, shapes, and accessors without reading getters", async () => {
    const first = await contentRow(0x11);
    const second = await contentRow(0x12);
    const orderedIds = sortedRows([first, second]).map((row) =>
      Uint8Array.from(row.operationId),
    );
    let getterReads = 0;
    const base = manifestFor([first, second]);
    const accessor = { ...base };
    Object.defineProperty(accessor, "retainedOperationCount", {
      enumerable: true,
      get: () => {
        getterReads += 1;
        return 2;
      },
    });

    const malformed: readonly unknown[] = [
      { ...base, operationIds: [...orderedIds].reverse() },
      { ...base, operationIds: [orderedIds[0], orderedIds[0]] },
      { ...base, unexpected: true },
      accessor,
      withCustomPrototype(base, () => {
        getterReads += 1;
      }),
    ];
    for (const value of malformed)
      expect(() =>
        encodeRetainedOperationWindowManifestV1(
          value as RetainedOperationWindowManifestV1,
        ),
      ).toThrow();
    expect(getterReads).toBe(0);
  });

  test("manifest semantics reject false completeness and invalid resource witnesses", async () => {
    const first = await contentRow(0x13);
    const base = manifestFor([first]);
    const rejectedId = (await contentRow(0x14)).operationId;
    const malformed: readonly RetainedOperationWindowManifestV1[] = [
      { ...base, retainedOperationCount: 0 },
      { ...base, retainedOperationBytes: 0n },
      {
        ...manifestFor([]),
        retainedOperationBytes: 1n,
      },
      {
        ...base,
        maxRetainedValidOperationsPerRoom: base.retainedOperationCount,
      },
      {
        ...base,
        maxRetainedValidOperationBytesPerRoom: base.retainedOperationBytes,
      },
      {
        ...base,
        firstRejectedOperationId: Uint8Array.from(rejectedId),
      },
      {
        ...base,
        completeness: "incomplete-overcapacity",
        firstRejectedOperationId: null,
      },
      {
        ...base,
        completeness: "incomplete-overcapacity",
        firstRejectedOperationId: Uint8Array.from(first.operationId),
      },
      {
        ...base,
        referenceWindow: RETAIN_THROUGH_WINDOW + 1n,
      },
      {
        ...base,
        maxRetainedValidOperationsPerRoom: 0,
      },
      {
        ...base,
        maxRetainedValidOperationsPerRoom: 0x1_0000,
      },
      {
        ...base,
        maxRetainedValidOperationBytesPerRoom: 0n,
      },
    ];
    for (const value of malformed)
      expect(() => encodeRetainedOperationWindowManifestV1(value)).toThrow(
        RetainedOperationStoreError,
      );

    const incomplete = {
      ...base,
      completeness: "incomplete-overcapacity" as const,
      firstRejectedOperationId: Uint8Array.from(rejectedId),
    };
    expect(
      decodeRetainedOperationWindowManifestV1(
        encodeRetainedOperationWindowManifestV1(incomplete),
      ),
    ).toEqual(incomplete);
  });

  test("accepts exact u64 endpoints and rejects non-u64 manifest fields and trailing bytes", () => {
    const maximum = manifestFor([], {
      referenceWindow: U64_MAX,
      retainThroughLogicalWindow: U64_MAX,
      maxRetainedValidOperationBytesPerRoom: U64_MAX,
    });
    const exact = encodeRetainedOperationWindowManifestV1(maximum);
    expect(decodeRetainedOperationWindowManifestV1(exact)).toEqual(maximum);

    for (const bad of [-1n, U64_MAX + 1n]) {
      expect(() =>
        encodeRetainedOperationWindowManifestV1({
          ...maximum,
          referenceWindow: bad,
        }),
      ).toThrow();
      expect(() =>
        encodeRetainedOperationWindowManifestV1({
          ...maximum,
          maxRetainedValidOperationBytesPerRoom: bad,
        }),
      ).toThrow();
    }
    expect(() =>
      decodeRetainedOperationWindowManifestV1(Uint8Array.from([...exact, 0])),
    ).toThrow("trailing bytes");
  });

  test("prepares explicit absence-to-empty initialization and never infers absence as completeness", async () => {
    const request = prepareRetainedOperationWindowInitializationV1({
      roomContextId: ROOM_ID,
      referenceWindow: REFERENCE_WINDOW,
      retainThroughLogicalWindow: RETAIN_THROUGH_WINDOW,
      maxRetainedValidOperationsPerRoom: 2,
      maxRetainedValidOperationBytesPerRoom: 10_000n,
    });
    expect(request).toMatchObject({
      version: 1,
      locator: { version: 1, referenceWindow: REFERENCE_WINDOW },
      expected: { manifest: { kind: "absent" }, operations: [] },
      candidateOperationId: null,
      mutation: { kind: "initialize-window" },
    });
    const manifest = decodeRetainedOperationWindowManifestV1(
      exactNextManifestBytes(request),
    );
    expect(hex(exactNextManifestBytes(request))).toBe(
      "013131313131313131313131313131313131313131313131313131313131313131" +
        "00000000000003e8" +
        "000000000000044c" +
        "00" +
        "0000" +
        "00000000" +
        "0000000000000000" +
        "00000002" +
        "0000000000002710" +
        "00",
    );
    expect(manifest).toMatchObject({
      completeness: "complete",
      operationIds: [],
      retainedOperationCount: 0,
      retainedOperationBytes: 0n,
      firstRejectedOperationId: null,
    });

    const absent = await validateAndCopyRetainedOperationWindowExactCaptureV1({
      manifest: { kind: "absent" },
      operations: [],
    });
    expect(absent).toEqual({ kind: "unavailable" });
    expect(
      await planRetainedOperationAdmissionV1(
        { manifest: { kind: "absent" }, operations: [] },
        null,
      ),
    ).toEqual({ kind: "unavailable" });
  });

  test("initialization validates exact shape, count geometry, positive bytes, and window order", () => {
    const base = {
      roomContextId: ROOM_ID,
      referenceWindow: REFERENCE_WINDOW,
      retainThroughLogicalWindow: RETAIN_THROUGH_WINDOW,
      maxRetainedValidOperationsPerRoom: 2,
      maxRetainedValidOperationBytesPerRoom: 10_000n,
    };
    const malformed: readonly unknown[] = [
      { ...base, unexpected: true },
      { ...base, roomContextId: new Uint8Array(31) },
      { ...base, referenceWindow: -1n },
      {
        ...base,
        retainThroughLogicalWindow: REFERENCE_WINDOW - 1n,
      },
      { ...base, maxRetainedValidOperationsPerRoom: 0 },
      { ...base, maxRetainedValidOperationsPerRoom: 1.5 },
      { ...base, maxRetainedValidOperationsPerRoom: 0x1_0000 },
      { ...base, maxRetainedValidOperationBytesPerRoom: 0n },
      { ...base, maxRetainedValidOperationBytesPerRoom: U64_MAX + 1n },
    ];
    for (const value of malformed)
      expect(() =>
        prepareRetainedOperationWindowInitializationV1(value),
      ).toThrow(RetainedOperationStoreError);
  });

  test("content rows own bytes before await and prove addressing without pretending to validate signatures", async () => {
    const source = await contentRow(0x21);
    const expected = structuredClone(source);
    const pending = validateAndCopyRetainedOperationContentRowV1(source);
    source.roomContextId.fill(0xee);
    source.operationId.fill(0xee);
    source.exactOperationBytes.fill(0xee);

    const owned = await pending;
    expect(owned).toEqual(expected);
    expect(owned).not.toBe(source);
    expect(owned.roomContextId).not.toBe(source.roomContextId);
    expect(owned.operationId).not.toBe(source.operationId);
    expect(owned.exactOperationBytes).not.toBe(source.exactOperationBytes);
    // The fixture signature is deliberately invalid; successful addressing
    // is not a signature-validity or Core provenance claim.
    expect(operationFor(0x21).authorSignature.every((byte) => byte !== 0)).toBe(
      true,
    );
  });

  test("content rows reject wrong IDs, noncanonical bytes, and hostile shapes without invoking getters", async () => {
    const row = await contentRow(0x22);
    const wrongId = {
      ...row,
      operationId: new Uint8Array(32).fill(0xff),
    };
    const trailing = {
      ...row,
      exactOperationBytes: Uint8Array.from([...row.exactOperationBytes, 0]),
    };
    let getterReads = 0;
    const accessor = { ...row };
    Object.defineProperty(accessor, "operationId", {
      enumerable: true,
      get: () => {
        getterReads += 1;
        return row.operationId;
      },
    });
    const malformed: readonly unknown[] = [
      wrongId,
      trailing,
      { ...row, version: 2 },
      { ...row, roomContextId: new Uint8Array(31) },
      { ...row, exactOperationBytes: new Uint8Array() },
      { ...row, unexpected: true },
      accessor,
      withCustomPrototype(row, () => {
        getterReads += 1;
      }),
    ];
    for (const value of malformed)
      await expect(
        validateAndCopyRetainedOperationContentRowV1(value),
      ).rejects.toThrow();
    expect(getterReads).toBe(0);
  });

  test("validates and deeply owns an exact complete capture before hashing rows", async () => {
    const first = await contentRow(0x31);
    const second = await contentRow(0x32);
    const raw = captureFor([first, second], {}, U64_MAX);
    const original = structuredClone(raw);
    const pending = validateAndCopyRetainedOperationWindowExactCaptureV1(raw);

    if (raw.manifest.kind !== "present")
      throw new Error("fixture requires a present manifest");
    raw.manifest.exactManifestBytes.fill(0xee);
    for (const row of raw.operations) {
      row.roomContextId.fill(0xee);
      row.operationId.fill(0xee);
      row.exactOperationBytes.fill(0xee);
    }

    const validated = await pending;
    expect(validated.kind).toBe("available");
    if (validated.kind !== "available")
      throw new Error("fixture requires an available capture");
    expect(validated.exactManifestRow.recordRevision).toBe(U64_MAX);
    expect(validated.operations).toEqual(original.operations);
    expect(validated.operations[0]).not.toBe(raw.operations[0]);
    expect(validated.operations[0].operationId).not.toBe(
      raw.operations[0].operationId,
    );
  });

  test("capture validation rejects missing, extra, duplicate, unsorted, cross-room, and mis-accounted rows", async () => {
    const first = await contentRow(0x33);
    const second = await contentRow(0x34);
    const third = await contentRow(0x35);
    const base = captureFor([first, second]);
    const sorted = sortedRows([first, second]);

    const missing = {
      ...base,
      operations: [base.operations[0]],
    };
    const extra = {
      ...base,
      operations: [...base.operations, third],
    };
    const duplicate = {
      ...base,
      operations: [base.operations[0], base.operations[0]],
    };
    const unsorted = {
      ...base,
      operations: [...base.operations].reverse(),
    };
    const crossRoomRows = sorted.map((row, index) => ({
      ...row,
      roomContextId:
        index === 0 ? Uint8Array.from(OTHER_ROOM_ID) : row.roomContextId,
    }));
    const crossRoom = {
      ...base,
      operations: crossRoomRows,
    };
    const wrongBytes = captureFor([first, second], {
      retainedOperationBytes:
        manifestFor([first, second]).retainedOperationBytes + 1n,
    });
    const wrongCount = captureFor([first, second]);
    if (wrongCount.manifest.kind !== "present")
      throw new Error("fixture requires a present manifest");
    // Preserve a canonically decodable u32 while contradicting the two exact
    // IDs. The strict manifest encoder correctly refuses to build this state,
    // so model corrupted persisted bytes after encoding.
    const retainedCountOffset =
      1 + // version
      32 + // roomContextId
      8 + // referenceWindow
      8 + // retainThroughLogicalWindow
      1 + // completeness
      2 + // operationIds count prefix
      2 * 32; // two operation IDs
    wrongCount.manifest.exactManifestBytes.set(
      Uint8Array.of(0, 0, 0, 1),
      retainedCountOffset,
    );
    const absentWithRows = {
      manifest: { kind: "absent" },
      operations: [first],
    };

    for (const value of [
      missing,
      extra,
      duplicate,
      unsorted,
      crossRoom,
      wrongBytes,
      wrongCount,
      absentWithRows,
    ])
      await expect(
        validateAndCopyRetainedOperationWindowExactCaptureV1(value),
      ).rejects.toThrow(RetainedOperationStoreError);
  });

  test("capture validation rejects a row whose named ID does not address its exact bytes", async () => {
    const first = await contentRow(0x36);
    const second = await contentRow(0x37);
    const sorted = sortedRows([first, second]);
    const forgedRows = sorted.map((row) => ({
      ...row,
      exactOperationBytes: Uint8Array.from(row.exactOperationBytes),
    }));
    forgedRows[0].exactOperationBytes = Uint8Array.from(
      forgedRows[1].exactOperationBytes,
    );
    const capture = captureFor(sorted);
    const forgedCapture = {
      ...capture,
      operations: forgedRows,
    };
    await expect(
      validateAndCopyRetainedOperationWindowExactCaptureV1(forgedCapture),
    ).rejects.toThrow("does not address");
  });

  test("capture rows require exact u64 revisions and strict plain outer shapes", async () => {
    const row = await contentRow(0x38);
    const base = captureFor([row]);
    for (const recordRevision of [-1n, U64_MAX + 1n, 0]) {
      if (base.manifest.kind !== "present")
        throw new Error("fixture requires a present manifest");
      await expect(
        validateAndCopyRetainedOperationWindowExactCaptureV1({
          ...base,
          manifest: { ...base.manifest, recordRevision },
        }),
      ).rejects.toThrow("unsigned 64-bit");
    }
    await expect(
      validateAndCopyRetainedOperationWindowExactCaptureV1({
        ...base,
        unexpected: true,
      }),
    ).rejects.toThrow("exactly manifest and operations");
  });

  test("accepts a new unique row under both caps and prepares one exact closed CAS mutation", async () => {
    const candidate = await contentRow(0x41);
    const sourceCandidate = structuredClone(candidate);
    const capture = initializedCapture({
      maxRetainedValidOperationsPerRoom: 2,
      maxRetainedValidOperationBytesPerRoom:
        BigInt(candidate.exactOperationBytes.length) + 1n,
    });
    const pending = planRetainedOperationAdmissionV1(capture, candidate);
    candidate.roomContextId.fill(0xee);
    candidate.operationId.fill(0xee);
    candidate.exactOperationBytes.fill(0xee);
    const plan = await pending;
    const request = requireRequest(plan, "accept-operation");
    expect(request).toMatchObject({
      version: 1,
      locator: { version: 1, referenceWindow: REFERENCE_WINDOW },
      expected: { operations: [] },
      mutation: { kind: "insert-operation-and-replace-manifest" },
    });
    expectBytesEqual(
      request.candidateOperationId!,
      sourceCandidate.operationId,
    );
    if (request.mutation.kind !== "insert-operation-and-replace-manifest")
      throw new Error("fixture requires an insert mutation");
    expect(request.mutation.operation).toEqual(sourceCandidate);
    expect(request.mutation.operation).not.toBe(candidate);

    expect(request.mutation.operation).toEqual(sourceCandidate);

    const next = decodeRetainedOperationWindowManifestV1(
      request.mutation.exactNextManifestBytes,
    );
    expect(next).toMatchObject({
      completeness: "complete",
      retainedOperationCount: 1,
      retainedOperationBytes: BigInt(
        sourceCandidate.exactOperationBytes.length,
      ),
      firstRejectedOperationId: null,
    });
    expectBytesEqual(next.operationIds[0], sourceCandidate.operationId);
  });

  test("keeps operation IDs sorted and charges each shared content row exactly once", async () => {
    const first = await contentRow(0x42);
    const second = await contentRow(0x43);
    const firstPlan = await planRetainedOperationAdmissionV1(
      initializedCapture(),
      first,
    );
    const firstRequest = requireRequest(firstPlan, "accept-operation");
    const afterFirst = applyPreparedRequest(
      initializedCapture(),
      firstRequest,
      1n,
    );
    const secondPlan = await planRetainedOperationAdmissionV1(
      afterFirst,
      second,
    );
    const secondRequest = requireRequest(secondPlan, "accept-operation");
    const finalManifest = decodeRetainedOperationWindowManifestV1(
      exactNextManifestBytes(secondRequest),
    );
    const expectedIds = sortedRows([first, second]).map(
      (row) => row.operationId,
    );
    expect(finalManifest.operationIds).toEqual(expectedIds);
    expect(finalManifest.retainedOperationCount).toBe(2);
    expect(finalManifest.retainedOperationBytes).toBe(
      BigInt(first.exactOperationBytes.length) +
        BigInt(second.exactOperationBytes.length),
    );

    const afterSecond = applyPreparedRequest(afterFirst, secondRequest, 2n);
    expect(await planRetainedOperationAdmissionV1(afterSecond, first)).toEqual({
      kind: "duplicate",
    });
  });

  test("a duplicate has zero delta even at the next count boundary", async () => {
    const row = await contentRow(0x44);
    const capture = captureFor([row], {
      maxRetainedValidOperationsPerRoom: 2,
      maxRetainedValidOperationBytesPerRoom:
        BigInt(row.exactOperationBytes.length) + 1n,
    });
    expect(await planRetainedOperationAdmissionV1(capture, row)).toEqual({
      kind: "duplicate",
    });
  });

  test("equality at the configured count cap fails closed without storing the rejected row", async () => {
    const candidate = await contentRow(0x45);
    const capture = initializedCapture({
      maxRetainedValidOperationsPerRoom: 1,
    });
    const plan = await planRetainedOperationAdmissionV1(capture, candidate);
    const request = requireRequest(plan, "mark-incomplete-overcapacity");
    expect(request.mutation.kind).toBe("mark-incomplete-overcapacity");
    const next = decodeRetainedOperationWindowManifestV1(
      exactNextManifestBytes(request),
    );
    expect(next).toMatchObject({
      completeness: "incomplete-overcapacity",
      operationIds: [],
      retainedOperationCount: 0,
      retainedOperationBytes: 0n,
    });
    expectBytesEqual(next.firstRejectedOperationId!, candidate.operationId);
    expect(request.expected.operations).toEqual([]);
  });

  test("equality at the configured byte cap fails closed while one byte of headroom accepts", async () => {
    const candidate = await contentRow(0x46);
    const exactSize = BigInt(candidate.exactOperationBytes.length);
    const equalPlan = await planRetainedOperationAdmissionV1(
      initializedCapture({
        maxRetainedValidOperationBytesPerRoom: exactSize,
      }),
      candidate,
    );
    requireRequest(equalPlan, "mark-incomplete-overcapacity");

    const headroomPlan = await planRetainedOperationAdmissionV1(
      initializedCapture({
        maxRetainedValidOperationBytesPerRoom: exactSize + 1n,
      }),
      candidate,
    );
    requireRequest(headroomPlan, "accept-operation");
  });

  test("incomplete-overcapacity is sticky and preserves the first compact witness without parsing later candidates", async () => {
    const firstRejected = await contentRow(0x47);
    const mark = await planRetainedOperationAdmissionV1(
      initializedCapture({ maxRetainedValidOperationsPerRoom: 1 }),
      firstRejected,
    );
    const markRequest = requireRequest(mark, "mark-incomplete-overcapacity");
    const incompleteCapture = applyPreparedRequest(
      initializedCapture({ maxRetainedValidOperationsPerRoom: 1 }),
      markRequest,
      1n,
    );

    let getterReads = 0;
    const hostileCandidate = Object.defineProperty({}, "operationId", {
      enumerable: true,
      get: () => {
        getterReads += 1;
        throw new Error("must not inspect candidates after saturation");
      },
    });
    const sticky = await planRetainedOperationAdmissionV1(
      incompleteCapture,
      hostileCandidate,
    );
    expect(sticky.kind).toBe("sticky-incomplete-overcapacity");
    if (sticky.kind !== "sticky-incomplete-overcapacity")
      throw new Error("fixture requires sticky overcapacity");
    expectBytesEqual(
      sticky.firstRejectedOperationId,
      firstRejected.operationId,
    );
    expect(getterReads).toBe(0);

    const another = await contentRow(0x48);
    const stillSticky = await planRetainedOperationAdmissionV1(
      incompleteCapture,
      another,
    );
    expect(stillSticky.kind).toBe("sticky-incomplete-overcapacity");
    if (stillSticky.kind !== "sticky-incomplete-overcapacity")
      throw new Error("fixture requires sticky overcapacity");
    expectBytesEqual(
      stillSticky.firstRejectedOperationId,
      firstRejected.operationId,
    );
  });

  test("planner rejects cross-room and misaddressed candidates before preparing a mutation", async () => {
    const crossRoom = await contentRow(0x49, OTHER_ROOM_ID);
    await expect(
      planRetainedOperationAdmissionV1(initializedCapture(), crossRoom),
    ).rejects.toThrow("another room");

    const candidate = await contentRow(0x4a);
    const misaddressed = {
      ...candidate,
      operationId: new Uint8Array(32).fill(0xff),
    };
    await expect(
      planRetainedOperationAdmissionV1(initializedCapture(), misaddressed),
    ).rejects.toThrow("does not address");
  });
});
