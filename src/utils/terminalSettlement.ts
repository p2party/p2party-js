export type TerminalSettlementStep = () => void | Promise<void>;

/**
 * Run every fail-closed teardown step in order, even when an earlier storage or
 * transport cleanup fails. The caller receives all failures only after the
 * local terminal state has been attempted everywhere.
 */
export const runTerminalSettlement = async (
  message: string,
  steps: readonly TerminalSettlementStep[],
): Promise<void> => {
  const failures: unknown[] = [];
  for (const step of steps) {
    try {
      await step();
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.length > 0) throw new AggregateError(failures, message);
};

export interface IdentityPurgeSettlement {
  readonly disconnectSignaling: TerminalSettlementStep;
  readonly clearRoomPins: TerminalSettlementStep;
  readonly resetIdentity: TerminalSettlementStep;
  /**
   * Close every authenticated WebRTC transport before awaiting either identity
   * deletion. A slow or failed database worker must never leave a live channel
   * able to receive under already-reset identity state.
   */
  readonly teardownRooms: TerminalSettlementStep;
  readonly deleteIdentityX25519: TerminalSettlementStep;
  readonly deleteIdentityEd25519: TerminalSettlementStep;
}

/**
 * SSOT for identity-purge ordering. The X25519 wrapper is still removed before
 * the Ed25519 identity that authenticates it, but transport termination comes
 * first and every step settles even when another one fails.
 */
export const runIdentityPurgeSettlement = async (
  steps: IdentityPurgeSettlement,
): Promise<void> =>
  runTerminalSettlement("Identity purge did not fully settle", [
    steps.disconnectSignaling,
    steps.clearRoomPins,
    steps.resetIdentity,
    steps.teardownRooms,
    steps.deleteIdentityX25519,
    steps.deleteIdentityEd25519,
  ]);

export interface RoomPurgeSettlement {
  /**
   * Tombstoning happens before this orchestrator. Close local RTC first; this
   * step is awaited before any network revocation attempt begins.
   */
  readonly closeLocalTransport: TerminalSettlementStep;
  /**
   * Starts immediately after local transport termination and may remain
   * pending while durable local cleanup proceeds.
   */
  readonly startRemoteRevocation: () => Promise<void>;
  readonly deleteLocalData: TerminalSettlementStep;
  readonly clearPinAttempts: TerminalSettlementStep;
}

/**
 * SSOT for a single-room purge completion boundary. Every local terminal step
 * settles even on storage/network failure; a lone typed remote-revocation
 * error is rethrown directly so callers can narrow it without unpacking an
 * AggregateError.
 */
export const runRoomPurgeSettlement = async (
  steps: RoomPurgeSettlement,
): Promise<void> => {
  const failures: unknown[] = [];
  try {
    await steps.closeLocalTransport();
  } catch (error) {
    failures.push(error);
  }

  let remoteOutcome: Promise<
    { readonly confirmed: true } | { readonly confirmed: false; error: unknown }
  >;
  try {
    remoteOutcome = Promise.resolve(steps.startRemoteRevocation()).then(
      () => ({ confirmed: true as const }),
      (error: unknown) => ({ confirmed: false as const, error }),
    );
  } catch (error) {
    remoteOutcome = Promise.resolve({ confirmed: false as const, error });
  }

  for (const step of [steps.deleteLocalData, steps.clearPinAttempts]) {
    try {
      await step();
    } catch (error) {
      failures.push(error);
    }
  }

  const remote = await remoteOutcome;
  if (!remote.confirmed) failures.push(remote.error);

  if (failures.length === 1) throw failures[0];
  if (failures.length > 1)
    throw new AggregateError(failures, "Room purge did not fully settle");
};
