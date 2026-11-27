import { afterEach } from "bun:test";
import type { IRTCPeerConnection } from "../../src/api/webrtc/interfaces";

/** Each fake connection is owned by its test, including native-handler timers. */
export function ownTestTransports() {
  const connections = new Set<IRTCPeerConnection>();
  afterEach(async () => {
    const { clearRebindAuthenticationDeadline } =
      await import("../../src/api/webrtc/rebindDeadline");
    for (const pc of connections) {
      pc.clearTransportTimers?.();
      clearRebindAuthenticationDeadline(pc);
    }
    connections.clear();
  });
  return (pc: object) => connections.add(pc as IRTCPeerConnection);
}
