import { getMlKemSuite } from "../cryptography/mlkem";
import { roomPqModeToParameterSet } from "../roomPolicy";

import type { RoomPqMode } from "../roomPolicy";

/**
 * Internal handshake sub-frame tags carried inside FRAME_TYPE_HANDSHAKE.
 * The tag byte is also the causal step number.
 */
export const HANDSHAKE_STEP = Object.freeze({
  HELLO: 0x01,
  CONFIRM: 0x02,
  FINISH: 0x03,
} as const);

export type HandshakeStep =
  (typeof HANDSHAKE_STEP)[keyof typeof HANDSHAKE_STEP];

const HELLO_FIXED_BYTES = 1 + 32 + 32 + 32 + 32 + 64;
const CONFIRM_BYTES = 1 + 32 + 64;
const FINISH_BYTES = 1 + 64;

const payloadLengthsForMode = (
  pqMode: RoomPqMode,
): Readonly<Record<HandshakeStep, number>> => {
  const suite = getMlKemSuite(roomPqModeToParameterSet(pqMode));
  return Object.freeze({
    [HANDSHAKE_STEP.HELLO]:
      HELLO_FIXED_BYTES + suite.publicKeyBytes + suite.ciphertextBytes,
    [HANDSHAKE_STEP.CONFIRM]: CONFIRM_BYTES,
    [HANDSHAKE_STEP.FINISH]: FINISH_BYTES,
  });
};

/** Exact handshake payload lengths, including the one-byte step tag. */
export const HANDSHAKE_PAYLOAD_LENGTHS = Object.freeze({
  "hybrid-mlkem512": payloadLengthsForMode("hybrid-mlkem512"),
  "hybrid-mlkem768": payloadLengthsForMode("hybrid-mlkem768"),
  "hybrid-mlkem1024": payloadLengthsForMode("hybrid-mlkem1024"),
} satisfies Record<RoomPqMode, Readonly<Record<HandshakeStep, number>>>);

export const handshakePayloadLengthForStep = (
  step: HandshakeStep,
  pqMode: RoomPqMode = "hybrid-mlkem768",
): number => HANDSHAKE_PAYLOAD_LENGTHS[pqMode][step];

/** Source-derived upper bound across every step and supported room PQ mode. */
export const MAX_HANDSHAKE_PAYLOAD_LENGTH = Math.max(
  ...Object.values(HANDSHAKE_PAYLOAD_LENGTHS).flatMap((lengths) =>
    Object.values(lengths),
  ),
);

/**
 * Fail-closed pre-auth framing check used before a payload enters a handshake
 * inbox. The crypto core repeats this check when parsing each flight.
 */
export const isHandshakePayloadForStep = (
  payload: Uint8Array,
  step: HandshakeStep,
  pqMode: RoomPqMode = "hybrid-mlkem768",
): boolean =>
  payload.length === handshakePayloadLengthForStep(step, pqMode) &&
  payload[0] === step;
