import { deriveRoomLocator } from "./roomLocator";

export interface PurgeMembershipResult {
  /** Local room IDs, or the public locator while an ID is still pending. */
  unacknowledgedRoomIds: string[];
  /** False if the saved-room list could not be read before the deadline. */
  roomInventoryComplete: boolean;
}

interface SavedMembership {
  roomId: string;
  roomUrl: string;
  signalingServerUrl?: string;
  membershipPublicKey?: string;
}

/** Start all correlated leaves while the old socket and key still own them.
 * Older saved rooms do not identify their server, so only an active join
 * can establish their authority. Never send a locator to a guessed server.
 */
export const leaveMembershipsForPurge = async (
  activeRooms: readonly {
    id: string;
    url: string;
    signalingActive?: boolean;
  }[],
  serverUrl: string,
  publicKey: string,
  readSavedRooms: () => Promise<readonly SavedMembership[]>,
  leave: (url: string, remainingMs: number) => Promise<void>,
  timeoutMs = 3_000,
): Promise<PurgeMembershipResult> => {
  const deadline = performance.now() + timeoutMs;
  const seen = new Set<string>();
  const unacknowledged = new Set<string>();
  const otherAuthorities = new Set<string>();
  const requests: Promise<void>[] = [];
  let inventoryComplete = false;
  let hasInvalidRoom = false;
  let ended = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const request = (url: string, id: string, sameServer: boolean) => {
    if (ended || seen.has(url)) return;
    seen.add(url);
    if (!/^[0-9a-f]{64}$/.test(url)) {
      hasInvalidRoom = true;
      return;
    }
    const roomId = id || deriveRoomLocator(url);
    unacknowledged.add(roomId);
    const remaining = Math.ceil(deadline - performance.now());
    if (!sameServer || remaining <= 0) return;
    requests.push(
      (async () => {
        try {
          await leave(url, remaining);
          if (!ended) unacknowledged.delete(roomId);
        } catch {
          // Keep the room on the list. The other leaves and local purge continue.
        }
      })(),
    );
  };
  try {
    const elapsed = new Promise<void>((resolve) => {
      timer = setTimeout(resolve, timeoutMs);
    });
    for (const room of activeRooms) {
      if (room.signalingActive !== false) request(room.url, room.id, true);
    }
    const settled = (async () => {
      try {
        const saved = await readSavedRooms();
        if (ended) return;
        for (const room of saved) {
          // An active join proves the current authority for a legacy record.
          // A positively different authority is a separate membership, even
          // when the local capability URL happens to be the same.
          if (
            (room.signalingServerUrl &&
              room.signalingServerUrl !== serverUrl) ||
            (room.membershipPublicKey && room.membershipPublicKey !== publicKey)
          ) {
            otherAuthorities.add(
              room.roomId || deriveRoomLocator(room.roomUrl),
            );
            continue;
          }
          request(
            room.roomUrl,
            room.roomId,
            Boolean(serverUrl && publicKey) &&
              serverUrl === room.signalingServerUrl &&
              publicKey === room.membershipPublicKey,
          );
        }
        inventoryComplete = true;
      } catch {
        // An unreadable inventory cannot establish that every room was left.
      }
      await Promise.all(requests);
    })();
    await Promise.race([elapsed, settled]);
    return {
      unacknowledgedRoomIds: [
        ...new Set([...unacknowledged, ...otherAuthorities]),
      ].sort(),
      roomInventoryComplete: inventoryComplete && !hasInvalidRoom,
    };
  } finally {
    ended = true;
    if (timer !== undefined) clearTimeout(timer);
  }
};
