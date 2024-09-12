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
export interface PeerId {
  type: "peerId";
  peerId: string;
  challenge: string;
  message: string;
}
export interface ChallengeSendArgs {
  type: "challenge";
  challenge: string;
  signature: string;
  fromPeerId: string;
}
export interface Description extends DescriptionSendArgs {
  fromClientId: string;
  roomId: string;
}
export interface Candidate extends CandidateSendArgs {
  fromClientId: string;
  roomId: string;
}
export declare const signalingApi: import("@reduxjs/toolkit/query").Api<
  import("@reduxjs/toolkit/query").BaseQueryFn<any, unknown, unknown, {}, {}>,
  {
    sendSignal: import("@reduxjs/toolkit/query").MutationDefinition<
      {
        type: string;
        data: any;
      },
      import("@reduxjs/toolkit/query").BaseQueryFn<
        any,
        unknown,
        unknown,
        {},
        {}
      >,
      never,
      void,
      "signalingApi"
    >;
  },
  "signalingApi",
  never,
  typeof import("@reduxjs/toolkit/query").coreModuleName
>;
export declare const reconnectWebSocket: (signalingServerUrl: string) => void;
export declare const connectWebSocket: (
  signalingServerUrl: string,
  _roomUrl?: string,
  rtcConfig?: RTCConfiguration,
) => Promise<void>;
//# sourceMappingURL=signalingApi.d.ts.map
