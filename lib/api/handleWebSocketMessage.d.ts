import type {
  DescriptionSendArgs,
  CandidateSendArgs,
} from "../reducers/webSocketConnectedSlice";
import type { IRTCPeerConnection } from "../reducers/peersSlice";
export interface ClientId {
  type: "clientId";
  clientId: string;
  challenge: string;
  message: string;
}
export interface Description extends DescriptionSendArgs {
  fromClientId: string;
  roomId: string;
}
export interface Candidate extends CandidateSendArgs {
  fromClientId: string;
  roomId: string;
}
export declare const handleWebSocketMessage: (
  event: MessageEvent<any>,
  socketSend: (data: string) => void,
  peers?: IRTCPeerConnection[],
  isSettingRemoteAnswerPending?: boolean,
  rtcConfig?: RTCConfiguration,
) => Promise<void>;
//# sourceMappingURL=handleWebSocketMessage.d.ts.map
