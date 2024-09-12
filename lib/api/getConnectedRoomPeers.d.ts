export interface ConnectedRoomPeer {
    id: string;
    roomId: string;
    publicKey: string;
    createdAt: Date;
    updatedAt: Date;
}
export declare const getConnectedRoomPeers: (roomUrl: string, httpServerUrl?: string) => Promise<ConnectedRoomPeer[]>;
//# sourceMappingURL=getConnectedRoomPeers.d.ts.map