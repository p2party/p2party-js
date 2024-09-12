import type { RoomState } from "../store/room";
export declare const setRoomId: import("@reduxjs/toolkit").ActionCreatorWithOptionalPayload<
  string | undefined,
  "roomId/setRoomId"
>;
export declare const roomIdSelector: (state: RoomState) => string;
declare const _default: import("redux").Reducer<string>;
export default _default;
//# sourceMappingURL=roomIdSlice.d.ts.map
