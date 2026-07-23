import { PROTOCOL_VERSION } from "./constants";

/**
 * The signaling version is a fail-closed compatibility check, not a suite
 * negotiation mechanism. Missing, malformed, older, and newer values all fail.
 */
export const isProtocolVersionCompatible = (
  peerProtocolVersion?: number,
): boolean =>
  typeof peerProtocolVersion === "number" &&
  Number.isInteger(peerProtocolVersion) &&
  peerProtocolVersion === PROTOCOL_VERSION;
