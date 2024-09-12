import type { PeerId, Description, Candidate } from "../utils/interfaces";
export declare const sendSignalingServerMessage: (data: any) => void;
export declare const signalingServerApi: import("@reduxjs/toolkit/query").Api<
  import("@reduxjs/toolkit/query").BaseQueryFn<
    string | import("@reduxjs/toolkit/query").FetchArgs,
    unknown,
    import("@reduxjs/toolkit/query").FetchBaseQueryError,
    {},
    import("@reduxjs/toolkit/query").FetchBaseQueryMeta
  >,
  {
    sendSignalingServerMessage: import("@reduxjs/toolkit/query").MutationDefinition<
      {
        message: PeerId | Description | Candidate;
        signalingServerUrl?: string;
      },
      import("@reduxjs/toolkit/query").BaseQueryFn<
        string | import("@reduxjs/toolkit/query").FetchArgs,
        unknown,
        import("@reduxjs/toolkit/query").FetchBaseQueryError,
        {},
        import("@reduxjs/toolkit/query").FetchBaseQueryMeta
      >,
      never,
      string,
      "signalingServerApi"
    >;
    connectToSignalingServer: import("@reduxjs/toolkit/query").QueryDefinition<
      {
        signalingServerUrl: string;
        rtcConfig?: RTCConfiguration;
      },
      import("@reduxjs/toolkit/query").BaseQueryFn<
        string | import("@reduxjs/toolkit/query").FetchArgs,
        unknown,
        import("@reduxjs/toolkit/query").FetchBaseQueryError,
        {},
        import("@reduxjs/toolkit/query").FetchBaseQueryMeta
      >,
      never,
      Promise<boolean>,
      "signalingServerApi"
    >;
  },
  "signalingServerApi",
  never,
  typeof import("@reduxjs/toolkit/query").coreModuleName
>;
//# sourceMappingURL=signalingServerApi.d.ts.map
