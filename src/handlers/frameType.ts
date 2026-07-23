import {
  FRAME_TYPE_LEN,
  FRAME_TYPE_RECEIPT,
  WIRE_RECEIPT_FRAME_LEN,
} from "../utils/constants";

export interface ClassifiedFrame {
  type: number;
  payload: Uint8Array;
}

/**
 * Reads the protocol-v3 1-byte frame tag and returns it together with a
 * zero-copy view of the remaining bytes. An empty frame is reported as type -1
 * so the caller can log-and-drop rather than throw.
 */
export const classifyFrame = (data: Uint8Array): ClassifiedFrame => {
  const candidate = data.length >= FRAME_TYPE_LEN ? data[0] : -1;
  // A raw 64-byte legacy receipt can happen to begin with 0x03. Never accept
  // that as v3: receipt routing requires tag(1) || token(64), exactly.
  const type =
    candidate === FRAME_TYPE_RECEIPT &&
    data.length !== WIRE_RECEIPT_FRAME_LEN
      ? -1
      : candidate;
  return {
    type,
    payload:
      type === -1 ? data.subarray(data.length) : data.subarray(FRAME_TYPE_LEN),
  };
};
