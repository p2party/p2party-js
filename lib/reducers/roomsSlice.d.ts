import type { RoomState } from "../store/room";
export interface Room {
    url: string;
    id?: string;
}
export declare const setRoom: import("@reduxjs/toolkit").ActionCreatorWithPayload<Room, "rooms/setRoom">, setRoomUrl: import("@reduxjs/toolkit").ActionCreatorWithPayload<string, "rooms/setRoomUrl">;
export declare const roomsSelector: (state: RoomState) => Room[];
declare const _default: import("redux").Reducer<Room[]>;
export default _default;
//# sourceMappingURL=roomsSlice.d.ts.map