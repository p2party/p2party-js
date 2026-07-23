import { PROTOCOL_VERSION } from "./utils/constants";

/**
 * Canonical, non-secret room policy descriptor.
 *
 * The PIN is deliberately not a field: only the fact that CPace/PIN
 * authentication is required is authenticated with the policy. PIN bytes live
 * exclusively in the transient roomPinVault module.
 */
export type RoomAuthMode = "nopin" | "pin";
export type RoomPqMode = "hybrid-mlkem768";
export type RoomRendezvousMode =
  "legacy-signaling" | "opaque-token" | "blind-meeting-point";
export type RoomCoverMode = "immediate" | "scheduled";

export interface RoomPolicyV1 {
  version: 1;
  revision: number;
  wireVersion: 3;
  authMode: RoomAuthMode;
  pqMode: RoomPqMode;
  rendezvousMode: RoomRendezvousMode;
  coverMode: RoomCoverMode;
  coverCadenceMs: number;
  coverLanes: number;
  coverFramesPerCell: number;
  coverDurationEpochs: number;
}

export const ROOM_POLICY_V1_ENCODED_LEN = 32;
export const ROOM_POLICY_V1_HASH_LEN = 32;

export const MIN_COVER_CADENCE_MS = 1_000;
export const MAX_COVER_CADENCE_MS = 3_600_000;
export const MAX_COVER_LANES = 64;
export const MAX_COVER_FRAMES_PER_CELL = 1_024;

const MAGIC = new Uint8Array([0x50, 0x32, 0x52, 0x50]); // "P2RP"
const POLICY_FORMAT_VERSION = 1;
const RESERVED_START = 24;
const POLICY_HASH_DOMAIN = new TextEncoder().encode(
  "p2party/room-policy/v1\u0000",
);

const POLICY_KEYS = new Set([
  "version",
  "revision",
  "wireVersion",
  "authMode",
  "pqMode",
  "rendezvousMode",
  "coverMode",
  "coverCadenceMs",
  "coverLanes",
  "coverFramesPerCell",
  "coverDurationEpochs",
]);

const AUTH_MODE_TO_BYTE: Record<RoomAuthMode, number> = {
  nopin: 0,
  pin: 1,
};
const PQ_MODE_TO_BYTE: Record<RoomPqMode, number> = {
  "hybrid-mlkem768": 1,
};
const RENDEZVOUS_MODE_TO_BYTE: Record<RoomRendezvousMode, number> = {
  "legacy-signaling": 0,
  "opaque-token": 1,
  "blind-meeting-point": 2,
};
const COVER_MODE_TO_BYTE: Record<RoomCoverMode, number> = {
  immediate: 0,
  scheduled: 1,
};

const byteToAuthMode = (value: number): RoomAuthMode => {
  if (value === 0) return "nopin";
  if (value === 1) return "pin";
  throw new Error("roomPolicy: unsupported auth mode");
};

const byteToPqMode = (value: number): RoomPqMode => {
  if (value === 1) return "hybrid-mlkem768";
  if (value === 0)
    throw new Error("roomPolicy: v3 requires hybrid ML-KEM-768");
  throw new Error("roomPolicy: unsupported PQ mode");
};

const byteToRendezvousMode = (value: number): RoomRendezvousMode => {
  if (value === 0) return "legacy-signaling";
  if (value === 1) return "opaque-token";
  if (value === 2) return "blind-meeting-point";
  throw new Error("roomPolicy: unsupported rendezvous mode");
};

const byteToCoverMode = (value: number): RoomCoverMode => {
  if (value === 0) return "immediate";
  if (value === 1) return "scheduled";
  throw new Error("roomPolicy: unsupported cover mode");
};

const assertUnsignedInteger = (
  name: string,
  value: number,
  max: number,
): void => {
  if (!Number.isSafeInteger(value) || value < 0 || value > max)
    throw new Error(`roomPolicy: ${name} is out of range`);
};

const assertExactShape = (policy: RoomPolicyV1): void => {
  if (policy === null || typeof policy !== "object" || Array.isArray(policy))
    throw new Error("roomPolicy: policy must be an object");

  const prototype = Object.getPrototypeOf(policy);
  if (prototype !== Object.prototype && prototype !== null)
    throw new Error("roomPolicy: policy must be a plain record");

  const keys = Reflect.ownKeys(policy);
  if (
    keys.length !== POLICY_KEYS.size ||
    keys.some((key) => typeof key !== "string" || !POLICY_KEYS.has(key))
  )
    throw new Error(
      "roomPolicy: policy has missing or unexpected fields (PIN bytes are never policy fields)",
    );

  for (const key of POLICY_KEYS) {
    const descriptor = Object.getOwnPropertyDescriptor(policy, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      !descriptor.enumerable
    )
      throw new Error(
        "roomPolicy: policy fields must be enumerable data properties",
      );
  }
};

function assertKnownStringValue<T extends string>(
  name: string,
  value: unknown,
  table: Record<T, number>,
): asserts value is T {
  if (typeof value !== "string" || !Object.hasOwn(table, value))
    throw new Error(`roomPolicy: unsupported ${name}`);
}

export const validateRoomPolicyV1 = (policy: RoomPolicyV1): void => {
  assertExactShape(policy);

  if (policy.version !== POLICY_FORMAT_VERSION)
    throw new Error("roomPolicy: unsupported policy version");
  if (policy.wireVersion !== PROTOCOL_VERSION)
    throw new Error("roomPolicy: unsupported wire version");

  assertUnsignedInteger("revision", policy.revision, 0xffffffff);
  assertKnownStringValue("auth mode", policy.authMode, AUTH_MODE_TO_BYTE);
  assertKnownStringValue("PQ mode", policy.pqMode, PQ_MODE_TO_BYTE);
  assertKnownStringValue(
    "rendezvous mode",
    policy.rendezvousMode,
    RENDEZVOUS_MODE_TO_BYTE,
  );
  assertKnownStringValue("cover mode", policy.coverMode, COVER_MODE_TO_BYTE);

  assertUnsignedInteger("cover cadence", policy.coverCadenceMs, 0xffffffff);
  assertUnsignedInteger("cover lanes", policy.coverLanes, 0xffff);
  assertUnsignedInteger(
    "cover frames per cell",
    policy.coverFramesPerCell,
    0xffff,
  );
  assertUnsignedInteger(
    "cover duration epochs",
    policy.coverDurationEpochs,
    0xffff,
  );

  if (policy.coverMode === "immediate") {
    if (
      policy.coverCadenceMs !== 0 ||
      policy.coverLanes !== 0 ||
      policy.coverFramesPerCell !== 0 ||
      policy.coverDurationEpochs !== 0
    )
      throw new Error(
        "roomPolicy: immediate cover mode requires zero schedule fields",
      );
    return;
  }

  if (
    policy.coverCadenceMs < MIN_COVER_CADENCE_MS ||
    policy.coverCadenceMs > MAX_COVER_CADENCE_MS
  )
    throw new Error("roomPolicy: scheduled cover cadence is out of range");
  if (policy.coverLanes < 1 || policy.coverLanes > MAX_COVER_LANES)
    throw new Error("roomPolicy: scheduled cover lanes are out of range");
  if (
    policy.coverFramesPerCell < 1 ||
    policy.coverFramesPerCell > MAX_COVER_FRAMES_PER_CELL
  )
    throw new Error(
      "roomPolicy: scheduled cover frames per cell are out of range",
    );
  if (policy.coverDurationEpochs < 1)
    throw new Error(
      "roomPolicy: scheduled cover duration epochs are out of range",
    );
};

/**
 * Fixed-width V1 wire form (all integers big-endian):
 *
 *   magic(4) | format(1) | wire(1) | auth(1) | pq(1) |
 *   rendezvous(1) | cover(1) | revision(4) | cadence_ms(4) |
 *   lanes(2) | frames_per_cell(2) | duration_epochs(2) | reserved_zero(8)
 */
export const encodeRoomPolicyV1 = (policy: RoomPolicyV1): Uint8Array => {
  validateRoomPolicyV1(policy);

  const encoded = new Uint8Array(ROOM_POLICY_V1_ENCODED_LEN);
  encoded.set(MAGIC, 0);
  encoded[4] = POLICY_FORMAT_VERSION;
  encoded[5] = policy.wireVersion;
  encoded[6] = AUTH_MODE_TO_BYTE[policy.authMode];
  encoded[7] = PQ_MODE_TO_BYTE[policy.pqMode];
  encoded[8] = RENDEZVOUS_MODE_TO_BYTE[policy.rendezvousMode];
  encoded[9] = COVER_MODE_TO_BYTE[policy.coverMode];

  const view = new DataView(
    encoded.buffer,
    encoded.byteOffset,
    encoded.byteLength,
  );
  view.setUint32(10, policy.revision, false);
  view.setUint32(14, policy.coverCadenceMs, false);
  view.setUint16(18, policy.coverLanes, false);
  view.setUint16(20, policy.coverFramesPerCell, false);
  view.setUint16(22, policy.coverDurationEpochs, false);
  return encoded;
};

export const decodeRoomPolicyV1 = (encoded: Uint8Array): RoomPolicyV1 => {
  if (!(encoded instanceof Uint8Array))
    throw new Error("roomPolicy: encoded policy must be a Uint8Array");
  if (encoded.length !== ROOM_POLICY_V1_ENCODED_LEN)
    throw new Error("roomPolicy: invalid encoded policy length");
  for (let i = 0; i < MAGIC.length; i++) {
    if (encoded[i] !== MAGIC[i])
      throw new Error("roomPolicy: invalid policy magic");
  }
  for (let i = RESERVED_START; i < encoded.length; i++) {
    if (encoded[i] !== 0)
      throw new Error("roomPolicy: non-zero reserved policy byte");
  }

  const view = new DataView(
    encoded.buffer,
    encoded.byteOffset,
    encoded.byteLength,
  );
  const policy: RoomPolicyV1 = {
    version: encoded[4] as 1,
    wireVersion: encoded[5] as 3,
    authMode: byteToAuthMode(encoded[6]),
    pqMode: byteToPqMode(encoded[7]),
    rendezvousMode: byteToRendezvousMode(encoded[8]),
    coverMode: byteToCoverMode(encoded[9]),
    revision: view.getUint32(10, false),
    coverCadenceMs: view.getUint32(14, false),
    coverLanes: view.getUint16(18, false),
    coverFramesPerCell: view.getUint16(20, false),
    coverDurationEpochs: view.getUint16(22, false),
  };

  // Re-validation enforces semantic canonicality (including zero schedule
  // fields in immediate mode) and rejects unsupported format/wire versions.
  validateRoomPolicyV1(policy);
  return policy;
};

/** Validate and return a detached plain-object copy suitable for Redux state. */
export const canonicalizeRoomPolicyV1 = (policy: RoomPolicyV1): RoomPolicyV1 =>
  decodeRoomPolicyV1(encodeRoomPolicyV1(policy));

export const roomPoliciesEqualV1 = (
  left: RoomPolicyV1,
  right: RoomPolicyV1,
): boolean => {
  const a = encodeRoomPolicyV1(left);
  const b = encodeRoomPolicyV1(right);
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i];
  return difference === 0;
};

/** SHA-256(domain || canonical fixed-width policy); suitable for transcript CI. */
export const hashRoomPolicyV1 = async (
  policy: RoomPolicyV1,
): Promise<Uint8Array> => {
  const encoded = encodeRoomPolicyV1(policy);
  const input = new Uint8Array(POLICY_HASH_DOMAIN.length + encoded.length);
  input.set(POLICY_HASH_DOMAIN, 0);
  input.set(encoded, POLICY_HASH_DOMAIN.length);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", input);
  return new Uint8Array(digest);
};

/**
 * Current v3 behavior: no PIN, mandatory hybrid ML-KEM-768, legacy
 * signaling rendezvous, and immediate/no-cover delivery.
 */
export const DEFAULT_ROOM_POLICY_V1: Readonly<RoomPolicyV1> = Object.freeze({
  version: 1,
  revision: 0,
  wireVersion: 3,
  authMode: "nopin",
  pqMode: "hybrid-mlkem768",
  rendezvousMode: "legacy-signaling",
  coverMode: "immediate",
  coverCadenceMs: 0,
  coverLanes: 0,
  coverFramesPerCell: 0,
  coverDurationEpochs: 0,
});
