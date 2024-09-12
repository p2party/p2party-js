import type { RoomState } from "../store/room";
export interface IRTCPeerConnection extends RTCPeerConnection {
    peerIsInitiator: boolean;
    withPeerId: string;
    makingOffer: boolean;
}
export interface IRTCIceCandidate extends RTCIceCandidate {
    withPeerId: string;
}
export interface IRTCSessionDescription extends RTCSessionDescription {
    withPeerId: string;
}
export interface SetPeerArgs {
    roomId: string;
    peerId: string;
    peerPublicKey: string;
    initiate: boolean;
    rtcConfig?: RTCConfiguration;
}
export interface SetPeerDescriptionArgs {
    peerId: string;
    roomId: string;
    description: RTCSessionDescription;
    rtcConfig?: RTCConfiguration;
}
export interface SetIceCandidateArgs {
    peerId: string;
    roomId: string;
    candidate: RTCIceCandidate;
}
export interface SetPeerChannelArgs {
    label: string;
    roomId: string;
    withPeerId: string;
}
export interface DeletePeerArgs {
    peerId: string;
}
export interface Peer {
    connectionIndex: number;
    id: string;
    publicKey: string;
}
export declare const setPeer: import("@reduxjs/toolkit").ActionCreatorWithPayload<SetPeerArgs, "peers/setPeer">, setDescription: import("@reduxjs/toolkit").ActionCreatorWithPayload<SetPeerDescriptionArgs, "peers/setDescription">, setCandidate: import("@reduxjs/toolkit").ActionCreatorWithPayload<SetIceCandidateArgs, "peers/setCandidate">, setPeerChannel: import("@reduxjs/toolkit").ActionCreatorWithPayload<SetPeerChannelArgs, "peers/setPeerChannel">, deletePeer: import("@reduxjs/toolkit").ActionCreatorWithPayload<DeletePeerArgs, "peers/deletePeer">, deleteAllPeers: import("@reduxjs/toolkit").ActionCreatorWithoutPayload<"peers/deleteAllPeers">;
export declare const peersSelector: (state: RoomState) => Peer[];
declare const _default: import("redux").Reducer<Peer[]>;
export default _default;
//# sourceMappingURL=peersSlice.d.ts.map