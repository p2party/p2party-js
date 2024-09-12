import type { RoomState } from "../store/room";
export interface RoomDetails {
  roomUrl: string;
  roomId: string;
  signalingServerUrl: string;
}
export declare const setRoomUrl: import("@reduxjs/toolkit").ActionCreatorWithPayload<
    string,
    "roomDetails/setRoomUrl"
  >,
  setRoomId: import("@reduxjs/toolkit").ActionCreatorWithPayload<
    string,
    "roomDetails/setRoomId"
  >,
  setRoomSignalingServerUrl: import("@reduxjs/toolkit").ActionCreatorWithPayload<
    string,
    "roomDetails/setRoomSignalingServerUrl"
  >;
export declare const roomDetailsSelector: (state: RoomState) => RoomDetails;
declare const _default: import("redux").Reducer<RoomDetails>;
export default _default;
//# sourceMappingURL=roomDetailsSlice.d.ts.map
