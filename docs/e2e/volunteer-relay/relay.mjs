import { PROTOCOL_VERSION, WIRE_CHUNK_FRAME_LEN } from "./session.mjs";

// One single-chunk P2Party message. No addresses, routing fields or commands.
const tag = Uint8Array.of(0x50, 0x32, 0x52, 1, PROTOCOL_VERSION);
const frameAt = tag.length + 64; // authenticated SHA-512 Merkle root
export const recordBytes = frameAt + WIRE_CHUNK_FRAME_LEN;
export const grantBytes = 2 * recordBytes;
export const grantMs = 2_000;

export function isRecord(data) {
  if (!(data instanceof ArrayBuffer) || data.byteLength !== recordBytes)
    return false;
  const bytes = new Uint8Array(data);
  return tag.every((value, i) => bytes[i] === value) && bytes[frameAt] === 2; // v4 chunk
}

export function encode({ protocolVersion, root, frames }) {
  if (
    protocolVersion !== PROTOCOL_VERSION ||
    root.length !== 64 ||
    frames.length !== 1 ||
    frames[0].length !== WIRE_CHUNK_FRAME_LEN
  )
    throw new Error("Expected a single-chunk P2Party message");
  const record = new Uint8Array(recordBytes);
  record.set(tag);
  record.set(root, tag.length);
  record.set(frames[0], frameAt);
  return record.buffer;
}

export function decode(data) {
  if (!isRecord(data)) throw new Error("Unsupported relay record");
  const bytes = new Uint8Array(data);
  return {
    protocolVersion: PROTOCOL_VERSION,
    root: bytes.subarray(tag.length, frameAt),
    frames: [bytes.subarray(frameAt)],
  };
}

// The volunteer only forwards to the channel supplied at setup. Each call
// decides synchronously. Nothing is held for retry or for a later grant.
export function volunteer(egress) {
  let state = "disabled",
    expires = 0,
    used = 0,
    timer;
  const stop = (reason = "stopped") => {
    clearTimeout(timer);
    state = reason;
  };
  return {
    enable() {
      if (state === "enabled") return;
      used = 0;
      state = "enabled";
      expires = performance.now() + grantMs;
      timer = setTimeout(() => stop("expired"), grantMs);
    },
    stop,
    forward(data) {
      if (state === "enabled" && performance.now() >= expires) stop("expired");
      if (state !== "enabled") return state;
      if (!isRecord(data)) return "unsupported";
      if (data.byteLength > grantBytes - used) {
        stop("exhausted");
        return state;
      }
      if (egress.readyState !== "open" || egress.bufferedAmount > 0)
        return "unavailable";
      try {
        egress.send(data);
      } catch {
        stop("unavailable");
        return state;
      }
      used += data.byteLength;
      if (used === grantBytes) stop("exhausted");
      return "forwarded";
    },
    get state() {
      return state;
    },
    get used() {
      return used;
    },
  };
}
