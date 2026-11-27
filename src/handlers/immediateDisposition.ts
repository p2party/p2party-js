import type { IRTCDataChannel } from "../api/webrtc/interfaces";

/** The opener promises that a close may pause a transfer. Legacy `raw` keeps its close-as-cancel contract. */
export const IMMEDIATE_RESUME_PROTOCOL = "p2party-resume-v1";
export const FRAME_TYPE_IMMEDIATE_DISPOSITION = 6;
const ROOT_BYTES = 64;
const FRAME_BYTES = 2 + ROOT_BYTES;
const CAPABILITY = 0;
const CANCEL = 1;

interface Binding {
  root: Uint8Array;
  authenticated: () => boolean;
  peerSupportsPause: boolean;
  cancelledByPeer: boolean;
  cancelSent: boolean;
}
const bindings = new WeakMap<IRTCDataChannel, Binding>();

export const bindImmediateDisposition = (
  channel: IRTCDataChannel,
  root: Uint8Array,
  incoming: boolean,
  authenticated: () => boolean,
): void => {
  if (
    channel.protocol !== IMMEDIATE_RESUME_PROTOCOL ||
    root.length !== ROOT_BYTES
  )
    return;
  bindings.set(channel, {
    root: root.slice(),
    authenticated,
    peerSupportsPause: incoming,
    cancelledByPeer: false,
    cancelSent: false,
  });
};

export const peerSupportsImmediateResume = (channel?: IRTCDataChannel): boolean =>
  channel !== undefined && bindings.get(channel)?.peerSupportsPause === true;

export const hasImmediateRemoteCancel = (channel?: IRTCDataChannel): boolean =>
  channel !== undefined && bindings.get(channel)?.cancelledByPeer === true;

const frame = (kind: number, root: Uint8Array): ArrayBuffer => {
  const bytes = new Uint8Array(FRAME_BYTES);
  bytes[0] = FRAME_TYPE_IMMEDIATE_DISPOSITION;
  bytes[1] = kind;
  bytes.set(root, 2);
  return bytes.buffer;
};

/** Echo only on marked incoming message channels, after the DTLS-bound identity gate opens. */
export const sendImmediateResumeCapability = (
  channel: IRTCDataChannel,
): void => {
  const binding = bindings.get(channel);
  if (
    binding &&
    peerSupportsImmediateResume(channel) &&
    binding.authenticated() &&
    channel.readyState === "open"
  )
    channel.send(frame(CAPABILITY, binding.root));
};

/**
 * No signaling relay carries this control: the authenticated concrete SCTP
 * channel and its fixed Merkle root are the scope. Unknown, stale, cross-root,
 * pre-authentication and malformed controls have no effect.
 */
export const acceptImmediateDisposition = (
  channel: IRTCDataChannel,
  bytes: Uint8Array,
): "capability" | "cancel" | undefined => {
  const binding = bindings.get(channel);
  if (
    !binding ||
    !binding.authenticated() ||
    bytes.length !== FRAME_BYTES ||
    bytes[0] !== FRAME_TYPE_IMMEDIATE_DISPOSITION
  )
    return;
  if (bytes[1] !== CAPABILITY && bytes[1] !== CANCEL) return;
  for (let i = 0; i < ROOT_BYTES; i++)
    if (bytes[i + 2] !== binding.root[i]) return;
  if (bytes[1] === CAPABILITY) {
    binding.peerSupportsPause = true;
    return "capability";
  }
  if (binding.cancelledByPeer) return;
  binding.cancelledByPeer = true;
  return "cancel";
};

/** Queue explicit user cancellation before terminal close; an interrupted attempt sends no CANCEL. */
export const sendImmediateCancel = async (
  channel: IRTCDataChannel,
): Promise<void> => {
  const binding = bindings.get(channel);
  if (
    !binding ||
    binding.cancelSent ||
    !binding.authenticated() ||
    channel.readyState !== "open"
  )
    return;
  binding.cancelSent = true;
  try {
    channel.send(frame(CANCEL, binding.root));
  } catch {
    // The channel can fail between readyState and send. Local cancellation
    // must still discard its pending state and release transport resources.
    return;
  }
  // Closing immediately can discard this control along with queued chunks.
  // Existing terminal cleanup owns the close; this wait only drains its frame.
  const deadline = Date.now() + 5000;
  while (
    channel.readyState === "open" &&
    channel.bufferedAmount > 0 &&
    Date.now() < deadline
  )
    await new Promise<void>((resolve) => setTimeout(resolve, 25));
};
