export interface SignalingRoomStatus {
  readonly url: string;
  readonly id?: string;
  readonly signalingActive?: boolean;
}

/** Inbound signaling is routable only to an exact, locally active room id. */
export const findActiveSignalingRoomIndex = (
  rooms: readonly SignalingRoomStatus[],
  roomId: string,
): number =>
  rooms.findIndex(
    (room) => room.id === roomId && room.signalingActive !== false,
  );
