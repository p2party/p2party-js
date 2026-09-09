import {
  DEFAULT_ROOM_POLICY_V1,
  canonicalizeRoomPolicyV1,
  roomPoliciesEqualV1,
} from "../roomPolicy";

import type { RoomPolicyV1 } from "../roomPolicy";

export interface RoomConnectAdmissionInput {
  readonly existingPolicy?: RoomPolicyV1;
  readonly persistedPolicy?: RoomPolicyV1;
  readonly requestedPolicy?: RoomPolicyV1;
  readonly providedPin?: unknown;
  readonly hasTransientPin: boolean;
}

/**
 * One pure admission decision for every public room-connect entry point.
 *
 * In particular, an empty Redux store does not imply a new no-PIN room when
 * IndexedDB retains an immutable PIN policy for the same capability.
 */
export const resolveRoomConnectAdmission = ({
  existingPolicy,
  persistedPolicy,
  requestedPolicy,
  providedPin,
  hasTransientPin,
}: RoomConnectAdmissionInput): RoomPolicyV1 => {
  if (
    persistedPolicy &&
    requestedPolicy &&
    !roomPoliciesEqualV1(persistedPolicy, requestedPolicy)
  )
    throw new Error("Persisted room policy is immutable");

  const policy = canonicalizeRoomPolicyV1(
    requestedPolicy ??
      existingPolicy ??
      persistedPolicy ??
      DEFAULT_ROOM_POLICY_V1,
  );
  if (policy.rendezvousMode !== "legacy-signaling")
    throw new Error("Private rendezvous room connections are not wired yet");

  if (policy.authMode === "pin") {
    if (providedPin !== undefined) {
      if (!(providedPin instanceof Uint8Array) || providedPin.length === 0)
        throw new Error("roomPinVault: PIN must be a non-empty Uint8Array");
    } else if (!hasTransientPin) {
      throw new Error("PIN room connection requires a PIN");
    }
  } else if (providedPin !== undefined) {
    throw new Error("PIN must not be provided for a no-PIN room");
  }

  return policy;
};
