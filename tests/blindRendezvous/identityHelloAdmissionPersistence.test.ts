import { describe, expect, test } from "bun:test";

import {
  IDENTITY_HELLO_ADMISSION_CAS_FENCE_ORDER_V1,
  IdentityHelloAdmissionPersistenceError,
  validateAndCopyIdentityHelloAdmissionExactCaptureRowsV1,
} from "../../src/blindRendezvous/identityHelloAdmissionPersistence";

import type {
  ExactIdentityHelloAdmissionRowV1,
  IdentityHelloAdmissionExactCaptureRowsV1,
} from "../../src/blindRendezvous/identityHelloAdmissionPersistence";

const U64_MAX = 0xffffffffffffffffn;

type PresentRow = Extract<
  ExactIdentityHelloAdmissionRowV1,
  { kind: "present" }
>;

const presentRow = (marker: number): PresentRow => ({
  kind: "present",
  exactBytes: Uint8Array.of(marker, marker ^ 0xff),
});

const CAPTURE_FIELDS = [
  "initializedRoom",
  "currentCore",
  "historicalEvidence",
  "receiverKey",
  "localPresenceOwnership",
  "frontendControls",
  "authorityCustody",
  "plannerAndExplicitState",
  "localIdentityKey",
  "localAuthorHead",
  "pairLedger",
  "provisionalPair",
  "identityBootstrapOutbox",
  "resourceState",
] as const;

const ROW_FIELDS = [
  "initializedRoom",
  "currentCore",
  "historicalEvidence",
  "localPresenceOwnership",
  "frontendControls",
  "authorityCustody",
  "plannerAndExplicitState",
  "localAuthorHead",
  "pairLedger",
  "provisionalPair",
  "identityBootstrapOutbox",
  "resourceState",
] as const;

const REVISION_FIELDS = ["receiverKey", "localIdentityKey"] as const;

const validCapture = (): IdentityHelloAdmissionExactCaptureRowsV1 => ({
  initializedRoom: presentRow(0x01),
  currentCore: presentRow(0x02),
  historicalEvidence: presentRow(0x03),
  receiverKey: { kind: "present", recordRevision: 4n },
  localPresenceOwnership: presentRow(0x05),
  frontendControls: presentRow(0x06),
  authorityCustody: presentRow(0x07),
  plannerAndExplicitState: presentRow(0x08),
  localIdentityKey: { kind: "present", recordRevision: 9n },
  localAuthorHead: presentRow(0x0a),
  pairLedger: presentRow(0x0b),
  provisionalPair: presentRow(0x0c),
  identityBootstrapOutbox: presentRow(0x0d),
  resourceState: presentRow(0x0e),
});

const captureWith = (
  field: (typeof CAPTURE_FIELDS)[number],
  value: unknown,
): unknown => ({
  ...validCapture(),
  [field]: value,
});

const withCustomPrototype = (value: object, onGetter: () => void): object => {
  const prototype = Object.defineProperty({}, "trap", {
    enumerable: true,
    get: () => {
      onGetter();
      return "must not be read";
    },
  });
  return Object.create(prototype, Object.getOwnPropertyDescriptors(value));
};

describe("identity HELLO admission persistence SSOT", () => {
  test("publishes one immutable normative 14-fence CAS order", () => {
    expect(IDENTITY_HELLO_ADMISSION_CAS_FENCE_ORDER_V1).toEqual([
      "initialized-room",
      "current-core",
      "historical-evidence",
      "receiver-key",
      "local-presence-ownership",
      "frontend-controls",
      "authority-custody",
      "planner-and-explicit-state",
      "local-identity-key",
      "local-author-head",
      "pair-ledger",
      "provisional-pair",
      "identity-bootstrap-outbox",
      "resource-state",
    ]);
    expect(IDENTITY_HELLO_ADMISSION_CAS_FENCE_ORDER_V1).toHaveLength(14);
    expect(Object.isFrozen(IDENTITY_HELLO_ADMISSION_CAS_FENCE_ORDER_V1)).toBe(
      true,
    );
    expect(
      Reflect.set(
        IDENTITY_HELLO_ADMISSION_CAS_FENCE_ORDER_V1,
        "0",
        "resource-state",
      ),
    ).toBe(false);
  });

  test("deeply owns every captured byte row", () => {
    const sharedBytes = Uint8Array.of(0x71, 0x72);
    const source: IdentityHelloAdmissionExactCaptureRowsV1 = {
      ...validCapture(),
      initializedRoom: { kind: "present", exactBytes: sharedBytes },
      currentCore: { kind: "present", exactBytes: sharedBytes },
    };
    const original = structuredClone(source);
    const owned =
      validateAndCopyIdentityHelloAdmissionExactCaptureRowsV1(source);

    expect(Reflect.ownKeys(owned)).toEqual([...CAPTURE_FIELDS]);
    expect(owned).toEqual(original);
    expect(owned).not.toBe(source);
    for (const field of ROW_FIELDS) {
      const borrowedRow = source[field];
      const ownedRow = owned[field];
      expect(ownedRow).not.toBe(borrowedRow);
      if (borrowedRow.kind === "present" && ownedRow.kind === "present")
        expect(ownedRow.exactBytes).not.toBe(borrowedRow.exactBytes);
    }
    for (const field of REVISION_FIELDS)
      expect(owned[field]).not.toBe(source[field]);

    for (const field of ROW_FIELDS) {
      const row = source[field];
      if (row.kind === "present") row.exactBytes.fill(0xee);
    }
    expect(owned).toEqual(original);

    if (
      owned.initializedRoom.kind !== "present" ||
      owned.currentCore.kind !== "present"
    )
      throw new Error("ownership fixture requires present rows");
    expect(owned.initializedRoom.exactBytes).not.toBe(
      owned.currentCore.exactBytes,
    );
    owned.initializedRoom.exactBytes.fill(0xaa);
    expect(owned.currentCore.exactBytes).toEqual(
      original.currentCore.kind === "present"
        ? original.currentCore.exactBytes
        : new Uint8Array(),
    );
  });

  test("rejects non-exact shapes and prototypes without invoking getters", () => {
    let getterReads = 0;
    const onGetter = (): void => {
      getterReads += 1;
    };

    const missingCapture = validCapture() as unknown as Record<string, unknown>;
    Reflect.deleteProperty(missingCapture, "resourceState");
    const extraCapture = {
      ...validCapture(),
      untrustedAvailability: true,
    };
    const accessorCapture = { ...validCapture() };
    Object.defineProperty(accessorCapture, "currentCore", {
      enumerable: true,
      get: () => {
        onGetter();
        return presentRow(0x20);
      },
    });
    const prototypeCapture = withCustomPrototype(validCapture(), onGetter);

    const accessorRow = Object.defineProperties(
      {},
      {
        kind: {
          enumerable: true,
          get: () => {
            onGetter();
            return "present";
          },
        },
        exactBytes: {
          enumerable: true,
          value: Uint8Array.of(0x21),
        },
      },
    );
    const accessorRevision = Object.defineProperties(
      {},
      {
        kind: { enumerable: true, value: "present" },
        recordRevision: {
          enumerable: true,
          get: () => {
            onGetter();
            return 1n;
          },
        },
      },
    );

    const malformed: readonly unknown[] = [
      missingCapture,
      extraCapture,
      accessorCapture,
      prototypeCapture,
      captureWith("currentCore", { kind: "present" }),
      captureWith("currentCore", {
        ...presentRow(0x22),
        unexpected: true,
      }),
      captureWith("currentCore", accessorRow),
      captureWith(
        "currentCore",
        withCustomPrototype(presentRow(0x23), onGetter),
      ),
      captureWith("receiverKey", { kind: "present" }),
      captureWith("receiverKey", {
        kind: "present",
        recordRevision: 1n,
        unexpected: true,
      }),
      captureWith("receiverKey", accessorRevision),
      captureWith(
        "receiverKey",
        withCustomPrototype({ kind: "present", recordRevision: 1n }, onGetter),
      ),
    ];

    for (const value of malformed)
      expect(() =>
        validateAndCopyIdentityHelloAdmissionExactCaptureRowsV1(value),
      ).toThrow(IdentityHelloAdmissionPersistenceError);
    expect(getterReads).toBe(0);
  });

  test("rejects an empty present byte string at every byte-row fence", () => {
    for (const field of ROW_FIELDS)
      expect(() =>
        validateAndCopyIdentityHelloAdmissionExactCaptureRowsV1(
          captureWith(field, {
            kind: "present",
            exactBytes: new Uint8Array(),
          }),
        ),
      ).toThrow("must not be empty");
  });

  test("accepts both u64 endpoints and rejects values outside them", () => {
    for (const field of REVISION_FIELDS) {
      for (const recordRevision of [0n, U64_MAX]) {
        const result = validateAndCopyIdentityHelloAdmissionExactCaptureRowsV1(
          captureWith(field, { kind: "present", recordRevision }),
        );
        expect(result[field]).toEqual({
          kind: "present",
          recordRevision,
        });
      }
      for (const recordRevision of [-1n, U64_MAX + 1n, 0]) {
        expect(() =>
          validateAndCopyIdentityHelloAdmissionExactCaptureRowsV1(
            captureWith(field, { kind: "present", recordRevision }),
          ),
        ).toThrow("exact present/absent u64 revision");
      }
    }
  });
});
