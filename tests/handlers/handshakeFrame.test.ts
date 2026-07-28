import { describe, expect, test } from "bun:test";

import {
  HANDSHAKE_PAYLOAD_LENGTHS as CORE_HANDSHAKE_PAYLOAD_LENGTHS,
  HANDSHAKE_STEP as CORE_HANDSHAKE_STEP,
  MAX_HANDSHAKE_PAYLOAD_LENGTH as CORE_MAX_HANDSHAKE_PAYLOAD_LENGTH,
  handshakePayloadLengthForStep as coreHandshakePayloadLengthForStep,
  isHandshakePayloadForStep as coreIsHandshakePayloadForStep,
} from "../../src/handlers/handshakeCore";
import {
  HANDSHAKE_PAYLOAD_LENGTHS,
  HANDSHAKE_STEP,
  MAX_HANDSHAKE_PAYLOAD_LENGTH,
  handshakePayloadLengthForStep,
  isHandshakePayloadForStep,
} from "../../src/handlers/handshakeFrame";

import type { RoomPqMode } from "../../src/roomPolicy";

const MODES = [
  ["hybrid-mlkem512", 1_761],
  ["hybrid-mlkem768", 2_465],
  ["hybrid-mlkem1024", 3_329],
] as const satisfies ReadonlyArray<readonly [RoomPqMode, number]>;

const STEPS = [
  HANDSHAKE_STEP.HELLO,
  HANDSHAKE_STEP.CONFIRM,
  HANDSHAKE_STEP.FINISH,
] as const;

describe("handshake frame geometry", () => {
  test("derives exact HELLO, CONFIRM, and FINISH lengths for every room suite", () => {
    for (const [pqMode, helloLength] of MODES) {
      expect(handshakePayloadLengthForStep(HANDSHAKE_STEP.HELLO, pqMode)).toBe(
        helloLength,
      );
      expect(
        handshakePayloadLengthForStep(HANDSHAKE_STEP.CONFIRM, pqMode),
      ).toBe(97);
      expect(handshakePayloadLengthForStep(HANDSHAKE_STEP.FINISH, pqMode)).toBe(
        65,
      );

      expect(HANDSHAKE_PAYLOAD_LENGTHS[pqMode]).toEqual({
        [HANDSHAKE_STEP.HELLO]: helloLength,
        [HANDSHAKE_STEP.CONFIRM]: 97,
        [HANDSHAKE_STEP.FINISH]: 65,
      });
    }

    expect(handshakePayloadLengthForStep(HANDSHAKE_STEP.HELLO)).toBe(2_465);
    expect(MAX_HANDSHAKE_PAYLOAD_LENGTH).toBe(3_329);
  });

  test("accepts only the exact tag and length for the requested causal step", () => {
    for (const [pqMode] of MODES) {
      for (const step of STEPS) {
        const expectedLength = handshakePayloadLengthForStep(step, pqMode);
        const valid = new Uint8Array(expectedLength);
        valid[0] = step;
        expect(isHandshakePayloadForStep(valid, step, pqMode)).toBe(true);

        const wrongTag = valid.slice();
        wrongTag[0] = step === HANDSHAKE_STEP.FINISH ? 0 : step + 1;
        expect(isHandshakePayloadForStep(wrongTag, step, pqMode)).toBe(false);

        const truncated = new Uint8Array(expectedLength - 1);
        truncated[0] = step;
        expect(isHandshakePayloadForStep(truncated, step, pqMode)).toBe(false);

        const extended = new Uint8Array(expectedLength + 1);
        extended[0] = step;
        expect(isHandshakePayloadForStep(extended, step, pqMode)).toBe(false);
      }
    }
  });

  test("handshakeCore preserves the original import surface by re-exporting the registry", () => {
    expect(CORE_HANDSHAKE_STEP).toBe(HANDSHAKE_STEP);
    expect(CORE_HANDSHAKE_PAYLOAD_LENGTHS).toBe(HANDSHAKE_PAYLOAD_LENGTHS);
    expect(CORE_MAX_HANDSHAKE_PAYLOAD_LENGTH).toBe(
      MAX_HANDSHAKE_PAYLOAD_LENGTH,
    );
    expect(coreHandshakePayloadLengthForStep).toBe(
      handshakePayloadLengthForStep,
    );
    expect(coreIsHandshakePayloadForStep).toBe(isHandshakePayloadForStep);
  });
});
