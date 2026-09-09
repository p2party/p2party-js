/**
 * Version-safe invitation parsing.
 *
 * REQ-001 keeps the user-facing flow identical — one capability, one `/r`
 * link, one QR code — while making the rendezvous version explicit in the
 * fragment. Every deployed form (compact, `v1.`, 24-word, legacy hex) keeps its
 * legacy-signaling meaning forever; blind rendezvous uses `v2.`.
 *
 * The two versions must never be silently interchangeable in either
 * direction: an old client rejects `v2.` as unsupported rather than joining a
 * different room, and a new client executes `v1.` only through the separately
 * installed legacy-signaling adapter.
 *
 * This module deliberately does not parse whole URLs. The page extracts
 * `location.hash` and passes the fragment in, exactly as today.
 */

import {
  decodeRoomCapability,
  decodeRoomCapabilityBase64Url,
  encodeRoomCapabilityBase64Url,
} from "../roomInvite";
import { base64urlNoPad, base64urlNoPadDecode } from "./derivations";
import {
  copyBlindDefaultPolicy,
  decodeRoomPolicyV4,
  encodeRoomPolicyV4,
} from "./roomPolicyV4";

import type { RoomPolicyV4 } from "./roomPolicyV4";

export const BLIND_ROOM_INVITE_VERSION = 2;
export const BLIND_ROOM_INVITE_PREFIX = "v2.";

/**
 * Bound on the canonical policy carried by a policy-bearing v2 fragment.
 *
 * Status: PROPOSED. The release registry freezes the final value together with
 * the binary policy codec; this bound only has to be large enough for a valid
 * `RoomPolicyV4` and small enough to keep a shared link scannable as a QR code.
 */
export const MAX_INVITE_POLICY_BYTES = 512;

export type LegacyRoomInviteV1 = {
  version: 1;
  capability: Uint8Array;
};

export type BlindRoomInviteV2 =
  | { version: 2; form: "default"; capability: Uint8Array }
  | {
      version: 2;
      form: "room-policy";
      capability: Uint8Array;
      roomPolicy: RoomPolicyV4;
    };

export type ParsedRoomInvite = LegacyRoomInviteV1 | BlindRoomInviteV2;

export class RoomInviteParseError extends Error {
  override readonly name = "RoomInviteParseError";

  constructor(message: string) {
    super(`roomInvite: ${message}`);
  }
}

/**
 * Thrown when a v1 invitation is executed in a build without the optional
 * legacy-signaling adapter. It is raised before any adapter or network work
 * and before capability or identity disclosure, and it never maps v1 to v2.
 */
export class LegacySignalingAdapterUnavailableError extends Error {
  override readonly name = "LegacySignalingAdapterUnavailableError";
  readonly code = "legacy-signaling-adapter-unavailable";
  readonly inviteVersion = 1;

  constructor() {
    super(
      "This build has no legacy-signaling adapter, so a v1 invitation cannot be joined.",
    );
  }
}

/**
 * Thrown when the legacy-named `signalingServerUrl` option is supplied with a
 * v2 invitation but no exact trusted alias maps it to a signed store
 * descriptor. Failing here is deliberate: silently ignoring the value or
 * substituting the default store would send the user somewhere they did not
 * ask for.
 */
export class BlindStoreAliasResolutionError extends Error {
  override readonly name = "BlindStoreAliasResolutionError";
  readonly code = "blind-store-alias-unmapped";
  readonly option = "signalingServerUrl";

  constructor() {
    super(
      "No trusted store descriptor is configured for the supplied signalingServerUrl.",
    );
  }
}

const fail = (message: string): never => {
  throw new RoomInviteParseError(message);
};

const CAPABILITY_COMPONENT_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const POLICY_COMPONENT_PATTERN = /^[A-Za-z0-9_-]+$/u;

const stripLeadingHash = (value: string): string =>
  value.startsWith("#") ? value.slice(1) : value;

/**
 * Parse a fragment into a closed versioned result, preserving the version.
 *
 * A leading `#` is accepted here and only here; it is not part of the
 * canonical invitation.
 */
export const parseRoomInvite = (fragment: string): ParsedRoomInvite => {
  if (typeof fragment !== "string") fail("invitation must be a string");
  const value = stripLeadingHash(fragment);

  if (value.startsWith(BLIND_ROOM_INVITE_PREFIX))
    return parseBlindRoomInviteV2(value);

  // Everything else keeps its deployed legacy-signaling meaning. The legacy
  // decoder owns those forms; this module does not restate them.
  return {
    version: 1,
    capability: decodeLegacyCapability(value),
  };
};

const decodeLegacyCapability = (value: string): Uint8Array => {
  const separator = value.indexOf(".");
  const version = separator > 0 ? value.slice(0, separator) : "";
  if (/^v\d+$/u.test(version) && version !== "v1")
    fail(`unsupported room invite version "${version}"`);
  // Routed through the deployed decoder so v1, compact, and legacy-hex forms
  // stay byte-identical.
  return decodeRoomCapability(value);
};

const parseBlindRoomInviteV2 = (value: string): BlindRoomInviteV2 => {
  const body = value.slice(BLIND_ROOM_INVITE_PREFIX.length);
  const components = body.split(".");
  if (components.length > 2)
    fail("a v2 invitation has at most a capability and a policy component");

  const [capabilityComponent, policyComponent] = components;
  if (!CAPABILITY_COMPONENT_PATTERN.test(capabilityComponent))
    fail("v2 capability must be exactly 43 unpadded base64url characters");
  // The deployed decoder also rejects alternate encodings of the same 32 bytes.
  const capability = decodeRoomCapabilityBase64Url(capabilityComponent);

  if (policyComponent === undefined)
    return { version: 2, form: "default", capability };

  if (policyComponent.length === 0)
    fail("v2 policy component must not be empty");
  if (!POLICY_COMPONENT_PATTERN.test(policyComponent))
    fail("v2 policy component must be unpadded base64url");

  const policyBytes = base64urlNoPadDecode(policyComponent);
  if (policyBytes.length > MAX_INVITE_POLICY_BYTES)
    fail("v2 policy component exceeds the invitation policy bound");
  if (base64urlNoPad(policyBytes) !== policyComponent)
    fail("v2 policy component is not canonically encoded");

  // decodeRoomPolicyV4 proves the bytes are the unique canonical encoding and
  // that the nested session policy selects blind-meeting-point.
  const roomPolicy = decodeRoomPolicyV4(policyBytes);
  return { version: 2, form: "room-policy", capability, roomPolicy };
};

/** The capability-only default fragment: `v2.<43-character-base64url>`. */
export const encodeBlindRoomInviteV2Default = (
  capability: Uint8Array,
): string =>
  `${BLIND_ROOM_INVITE_PREFIX}${encodeRoomCapabilityBase64Url(capability)}`;

/**
 * The policy-bearing fragment used by the advanced-room flow, so a PIN, PQ, or
 * cover choice survives sharing without appearing in an HTTP query.
 */
export const encodeBlindRoomInviteV2WithPolicy = (
  capability: Uint8Array,
  roomPolicy: RoomPolicyV4,
): string => {
  const policyBytes = encodeRoomPolicyV4(roomPolicy);
  if (policyBytes.length > MAX_INVITE_POLICY_BYTES)
    fail("canonical room policy exceeds the invitation policy bound");
  return `${encodeBlindRoomInviteV2Default(capability)}.${base64urlNoPad(policyBytes)}`;
};

/**
 * The room policy an invitation resolves to.
 *
 * A bare v2 invitation resolves to the frozen default rather than to whatever
 * the current application default happens to be; a policy-bearing invitation
 * resolves to its exact decoded policy with no defaults merged in.
 */
export const resolveInviteRoomPolicy = (
  invite: BlindRoomInviteV2,
): RoomPolicyV4 =>
  invite.form === "default"
    ? // A fresh copy per call. `Object.freeze` cannot protect the bytes inside
      // `sessionPolicyV1`, so returning the module singleton would let any
      // holder mutate the byte-frozen default — and every later bare-v2 invite
      // on that client would then resolve to a different room than the same
      // link resolves to everywhere else.
      copyBlindDefaultPolicy()
    : invite.roomPolicy;
