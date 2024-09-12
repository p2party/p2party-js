import type { RoomState } from "../store/room";
export interface KeyPair {
    peerId: string;
    publicKey: string;
    secretKey: string;
}
export interface SetKeyPair {
    publicKey: string;
    secretKey: string;
}
export interface SetPeerId {
    peerId: string;
}
export declare const setKeyPair: import("@reduxjs/toolkit").ActionCreatorWithPayload<SetKeyPair, "keyPair/setKeyPair">, setPeerId: import("@reduxjs/toolkit").ActionCreatorWithPayload<SetPeerId, "keyPair/setPeerId">;
export declare const keyPairSelector: (state: RoomState) => KeyPair;
declare const _default: import("redux").Reducer<KeyPair>;
export default _default;
//# sourceMappingURL=keyPairSlice.d.ts.map