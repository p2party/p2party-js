import type { IRTCPeerConnection } from "../reducers/peersSlice";
export declare const rtcConnectWithPeer: (
  withClientId: string,
  initiator?: boolean,
  rtcConfig?: RTCConfiguration,
) => Promise<IRTCPeerConnection>;
export declare const rtcConnectWithRoom: (
  starConfig?: boolean,
  rtcConfig?: RTCConfiguration,
) => Promise<void>;
//# sourceMappingURL=rtcConnect.d.ts.map
