export interface ConnectedRoomPeer {
  id: string;
  roomId: string;
  publicKey: string;
  createdAt: Date;
  updatedAt: Date;
}

export const getConnectedRoomPeers = async (
  roomUrl: string,
  httpServerUrl = "http://localhost:3001",
) => {
  if (roomUrl.length === 0) return [] as ConnectedRoomPeer[];

  const getRoomPeers = await fetch(`${httpServerUrl}/room/${roomUrl}/peers`, {
    method: "GET",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
  });

  try {
    const c: ConnectedRoomPeer[] = await getRoomPeers.json();

    return c;
  } catch (e) {
    console.warn(e);

    return [] as ConnectedRoomPeer[];
  }
};
