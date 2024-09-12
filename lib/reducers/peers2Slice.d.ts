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
export interface AddPeerArgs {
  peerId: string;
  peerPublicKey: string;
  initiate: boolean;
  rtcConfig?: RTCConfiguration;
}
export interface DeletePeerArgs {
  peerId: string;
}
export interface Peer {
  connectionIndex: number;
  id: string;
  publicKey: string;
}
export declare const setPeer: import("@reduxjs/toolkit").ActionCreatorWithPayload<
    AddPeerArgs,
    "peers2/setPeer"
  >,
  deletePeer: import("@reduxjs/toolkit").ActionCreatorWithPayload<
    DeletePeerArgs,
    "peers2/deletePeer"
  >,
  deleteAllPeers: import("@reduxjs/toolkit").ActionCreatorWithoutPayload<"peers2/deleteAllPeers">;
export declare const peer2Selector: (state: RoomState) => Peer[];
declare const _default: import("redux").Reducer<Peer[]>;
export default _default;
//# sourceMappingURL=peers2Slice.d.ts.map
