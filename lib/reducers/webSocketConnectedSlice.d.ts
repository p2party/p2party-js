import type { RoomState } from "../store/room";
export type WebSocketConnectedStatus =
  | "connecting"
  | "disconnecting"
  | "connected"
  | "open"
  | "closed"
  | "error";
export interface WebSocketConnectData {
  roomUrl?: string;
  signalingServerUrl?: string;
  rtcConfig?: RTCConfiguration;
}
export interface DescriptionSendArgs {
  type: "description";
  description: RTCSessionDescription;
  toClientId: string;
}
export interface CandidateSendArgs {
  type: "candidate";
  candidate: RTCIceCandidate;
  toClientId: string;
}
export interface ChallengeSendArgs {
  type: "challenge";
  challenge: string;
  signature: string;
}
export interface WebSocketConnectionStatusChangePayload {
  status: WebSocketConnectedStatus;
  data?: WebSocketConnectData;
}
export interface WebSocketMessagePayloadData {
  status: "open";
  data: DescriptionSendArgs | CandidateSendArgs | ChallengeSendArgs;
}
export declare const setWebSocketConnectionStatus: import("@reduxjs/toolkit").ActionCreatorWithPayload<
    WebSocketConnectionStatusChangePayload,
    "webSocketConnectedStatus/setWebSocketConnectionStatus"
  >,
  sendWebSocketMessage: import("@reduxjs/toolkit").ActionCreatorWithPayload<
    WebSocketMessagePayloadData,
    "webSocketConnectedStatus/sendWebSocketMessage"
  >;
export declare const webSocketConnectedStatusSelector: (
  state: RoomState,
) => string;
declare const _default: import("redux").Reducer<string>;
export default _default;
//# sourceMappingURL=webSocketConnectedSlice.d.ts.map
