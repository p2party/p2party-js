import { SIGNALING_PROTOCOL_VERSION } from "./constants";

export class SignalingVersionMismatchError extends Error {
  constructor() {
    super(
      "The signaling server and this SDK use incompatible protocol versions",
    );
    this.name = "SignalingVersionMismatchError";
  }
}

export const isSignalingVersionRefusal = (
  code: number,
  reason: string,
): boolean =>
  code === 1003 &&
  /^Unsupported signaling protocol version(?:;|$)/.test(reason);

/**
 * The signaling version is a fail-closed compatibility check, not a suite
 * negotiation mechanism. Missing, malformed, older, and newer values all fail.
 */
export const isProtocolVersionCompatible = (
  peerProtocolVersion?: number,
): boolean =>
  typeof peerProtocolVersion === "number" &&
  Number.isInteger(peerProtocolVersion) &&
  peerProtocolVersion === SIGNALING_PROTOCOL_VERSION;
