import { FRAME_TYPE_LEN } from "../utils/constants";

export interface ClassifiedFrame {
  type: number;
  payload: Uint8Array;
}

/**
 * Reads the protocol-v3 1-byte frame tag and returns it together with a
 * zero-copy view of the remaining bytes. An empty frame is reported as type -1
 * so the caller can log-and-drop rather than throw.
 */
export const classifyFrame = (data: Uint8Array): ClassifiedFrame => ({
  type: data.length >= FRAME_TYPE_LEN ? data[0] : -1,
  payload: data.subarray(FRAME_TYPE_LEN),
});
