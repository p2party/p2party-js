import type { IRTCDataChannel } from "./interfaces";

/**
 * Record that THIS side closed the channel.
 *
 * Immediate mode has no CANCEL frame — one DataChannel is one logical message,
 * so its close IS the peer's cancel signal. Without this marker a close our own
 * guard performed is indistinguishable from that signal: the transport is still
 * connected, the gate lease is still current and the connection is still
 * registered, so every check in `isAuthenticatedPeerCancel` legitimately passes
 * and the sender destroys its staging for a cancel nobody sent (C7).
 */
export const markChannelClosedLocally = (channel: IRTCDataChannel): void => {
  channel.closedLocally = true;
};

export const wasChannelClosedLocally = (
  channel: IRTCDataChannel | undefined,
): boolean => channel?.closedLocally === true;
