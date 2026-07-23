type IceRestartTarget = Pick<
  RTCPeerConnection,
  "connectionState" | "signalingState" | "restartIce"
>;

export type IceCandidateRepairResult = "restarted" | "disconnected";

/**
 * Repair a candidate-add failure without ever calling restartIce() after
 * teardown. Active PCs restart in place; closed PCs, or PCs whose restart
 * throws because they closed concurrently, take the room-scoped disconnect
 * path instead.
 */
export const repairIceTransportAfterCandidateFailure = async (
  target: IceRestartTarget,
  disconnect: () => void | Promise<void>,
): Promise<IceCandidateRepairResult> => {
  const isClosed =
    target.connectionState === "closed" ||
    (target.signalingState as string) === "closed";

  if (!isClosed) {
    try {
      target.restartIce();
      return "restarted";
    } catch {
      // The connection can close between the state check and restartIce().
    }
  }

  await disconnect();
  return "disconnected";
};
