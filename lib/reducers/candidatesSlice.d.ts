import type { RoomState } from "../store/room";
export interface IRTCIceCandidate extends RTCIceCandidate {
  withPeerId: string;
}
export interface DeleteCandidatesArgs {
  indexes: number[];
}
export declare const setCandidate: import("@reduxjs/toolkit").ActionCreatorWithPayload<
    IRTCIceCandidate,
    "candidates/setCandidate"
  >,
  deleteCandidates: import("@reduxjs/toolkit").ActionCreatorWithPayload<
    DeleteCandidatesArgs,
    "candidates/deleteCandidates"
  >;
export declare const candidateSelector: (
  state: RoomState,
) => import("./peers2Slice").Peer[];
declare const _default: import("redux").Reducer<IRTCIceCandidate[]>;
export default _default;
//# sourceMappingURL=candidatesSlice.d.ts.map
