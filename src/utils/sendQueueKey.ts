/** Scope the legacy IndexedDB send-queue key to one room without changing its schema. */
export const roomSendQueueLabel = (roomId: string, label: string): string =>
  `${roomId}\u0000${label}`;
