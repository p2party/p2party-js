interface Event<Data> {
  name: string;
  data: Data;
}
export declare const webSocketApi: import("@reduxjs/toolkit/query").Api<
  (options: Event<any>) => Promise<{
    data: Event<any>;
  }>,
  {
    sendEvent: import("@reduxjs/toolkit/query").MutationDefinition<
      string,
      (options: Event<any>) => Promise<{
        data: Event<any>;
      }>,
      never,
      Event<any>,
      "socker"
    >;
    events: import("@reduxjs/toolkit/query").QueryDefinition<
      string,
      (options: Event<any>) => Promise<{
        data: Event<any>;
      }>,
      never,
      {
        value: number;
      }[],
      "socker"
    >;
  },
  "socker",
  never,
  typeof import("@reduxjs/toolkit/query").coreModuleName
>;
export declare const useSendEventMutation: any, useEventsQuery: any;
export {};
//# sourceMappingURL=webSocketApi.d.ts.map
