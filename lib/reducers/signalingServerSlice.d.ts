import type { PayloadAction } from "@reduxjs/toolkit";
import type { RoomState } from "../store/room";
export interface SignalingState {
    isEstablishingConnection: boolean;
    isConnected: boolean;
    serverUrl: string;
}
export declare const signalingServerActions: import("@reduxjs/toolkit").CaseReducerActions<{
    startConnecting: (state: import("immer").WritableDraft<SignalingState>, action: PayloadAction<string | undefined>) => void;
    connectionEstablished: (state: import("immer").WritableDraft<SignalingState>) => void;
    disconnect: (state: import("immer").WritableDraft<SignalingState>) => void;
    sendMessage: (state: import("immer").WritableDraft<SignalingState>, _action: PayloadAction<{
        content: unknown;
    }>) => import("immer").WritableDraft<SignalingState>;
}, "signalingServer">;
export declare const signalingServerSelector: (state: RoomState) => SignalingState;
declare const _default: import("redux").Reducer<SignalingState>;
export default _default;
//# sourceMappingURL=signalingServerSlice.d.ts.map