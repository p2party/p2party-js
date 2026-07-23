import { describe, expect, test } from "bun:test";

import {
  DEFAULT_ROOM_POLICY_V1,
  ROOM_POLICY_V1_ENCODED_LEN,
  ROOM_POLICY_V1_HASH_LEN,
  canonicalizeRoomPolicyV1,
  decodeRoomPolicyV1,
  encodeRoomPolicyV1,
  hashRoomPolicyV1,
  roomPoliciesEqualV1,
} from "./roomPolicy";

import type { RoomPolicyV1 } from "./roomPolicy";

const hex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

describe("canonical room policy V1", () => {
  test("default immediate/legacy policy has a fixed-width encoding and hash KAT", async () => {
    const encoded = encodeRoomPolicyV1(DEFAULT_ROOM_POLICY_V1);
    expect(encoded.length).toBe(ROOM_POLICY_V1_ENCODED_LEN);
    expect(hex(encoded)).toBe(
      "5032525001030001000000000000000000000000000000000000000000000000",
    );

    const hash = await hashRoomPolicyV1(DEFAULT_ROOM_POLICY_V1);
    expect(hash.length).toBe(ROOM_POLICY_V1_HASH_LEN);
    expect(hex(hash)).toBe(
      "36c2d01051b69f270ac93f971a97ffe7911e87f313e6ffeab739bc4970f9c501",
    );
  });

  test("scheduled PIN + hybrid-PQ policy round-trips byte-exact", () => {
    const policy: RoomPolicyV1 = {
      version: 1,
      revision: 17,
      wireVersion: 3,
      authMode: "pin",
      pqMode: "hybrid-mlkem768",
      rendezvousMode: "blind-meeting-point",
      coverMode: "scheduled",
      coverCadenceMs: 10_000,
      coverLanes: 2,
      coverFramesPerCell: 16,
      coverDurationEpochs: 4,
    };
    const encoded = encodeRoomPolicyV1(policy);
    const decoded = decodeRoomPolicyV1(encoded);

    expect(decoded).toEqual(policy);
    expect(hex(encodeRoomPolicyV1(decoded))).toBe(hex(encoded));
    expect(canonicalizeRoomPolicyV1(policy)).not.toBe(policy);
  });

  test("policy mismatches are visible in both equality and transcript hash", async () => {
    const pinPolicy: RoomPolicyV1 = {
      ...DEFAULT_ROOM_POLICY_V1,
      authMode: "pin",
    };

    expect(roomPoliciesEqualV1(DEFAULT_ROOM_POLICY_V1, pinPolicy)).toBe(false);
    expect(hex(await hashRoomPolicyV1(DEFAULT_ROOM_POLICY_V1))).not.toBe(
      hex(await hashRoomPolicyV1(pinPolicy)),
    );
  });

  test("rejects noncanonical bytes, unknown values, and out-of-range schedules", () => {
    const encoded = encodeRoomPolicyV1(DEFAULT_ROOM_POLICY_V1);

    expect(() => decodeRoomPolicyV1(encoded.subarray(0, 31))).toThrow(
      "invalid encoded policy length",
    );

    const reserved = Uint8Array.from(encoded);
    reserved[31] = 1;
    expect(() => decodeRoomPolicyV1(reserved)).toThrow(
      "non-zero reserved policy byte",
    );

    const unknownAuth = Uint8Array.from(encoded);
    unknownAuth[6] = 9;
    expect(() => decodeRoomPolicyV1(unknownAuth)).toThrow(
      "unsupported auth mode",
    );

    const classicalV3 = Uint8Array.from(encoded);
    classicalV3[7] = 0;
    expect(() => decodeRoomPolicyV1(classicalV3)).toThrow(
      "v3 requires hybrid ML-KEM-768",
    );

    const noncanonicalImmediate = Uint8Array.from(encoded);
    new DataView(noncanonicalImmediate.buffer).setUint32(14, 10_000, false);
    expect(() => decodeRoomPolicyV1(noncanonicalImmediate)).toThrow(
      "immediate cover mode requires zero schedule fields",
    );

    expect(() =>
      encodeRoomPolicyV1({
        ...DEFAULT_ROOM_POLICY_V1,
        coverMode: "scheduled",
        coverCadenceMs: 999,
        coverLanes: 1,
        coverFramesPerCell: 1,
        coverDurationEpochs: 1,
      }),
    ).toThrow("scheduled cover cadence is out of range");
  });

  test("PIN bytes cannot be silently included in a policy object", () => {
    const withPin = {
      ...DEFAULT_ROOM_POLICY_V1,
      authMode: "pin",
      pin: new Uint8Array([1, 2, 3, 4]),
    };
    expect(() =>
      encodeRoomPolicyV1(withPin as unknown as RoomPolicyV1),
    ).toThrow("PIN bytes are never policy fields");

    const withHiddenPin = { ...DEFAULT_ROOM_POLICY_V1 };
    Object.defineProperty(withHiddenPin, "pin", {
      value: new Uint8Array([1, 2, 3, 4]),
      enumerable: false,
    });
    expect(() =>
      encodeRoomPolicyV1(withHiddenPin as unknown as RoomPolicyV1),
    ).toThrow("PIN bytes are never policy fields");
  });

  test("rejects accessors and non-plain policy records", () => {
    const withAccessor = { ...DEFAULT_ROOM_POLICY_V1 };
    Object.defineProperty(withAccessor, "revision", {
      get: () => 0,
      enumerable: true,
    });
    expect(() =>
      encodeRoomPolicyV1(withAccessor as unknown as RoomPolicyV1),
    ).toThrow("policy fields must be enumerable data properties");

    class PolicyRecord {
      version = 1 as const;
      revision = 0;
      wireVersion = 3 as const;
      authMode = "nopin" as const;
      pqMode = "hybrid-mlkem768" as const;
      rendezvousMode = "legacy-signaling" as const;
      coverMode = "immediate" as const;
      coverCadenceMs = 0;
      coverLanes = 0;
      coverFramesPerCell = 0;
      coverDurationEpochs = 0;
    }
    expect(() => encodeRoomPolicyV1(new PolicyRecord())).toThrow(
      "policy must be a plain record",
    );
  });
});
