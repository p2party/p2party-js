import type { MiddlewareAPI } from "@reduxjs/toolkit";
export declare const reconnectWebSocketOld: (
  ws: WebSocket,
  url: string,
  listenerApi: MiddlewareAPI,
) => void;
export declare const connectWebSocketOld: (
  ws: WebSocket | undefined,
  signalingServerUrl: string,
  listenerApi: MiddlewareAPI,
  roomUrl?: string,
  rtcConfig?: RTCConfiguration,
) => Promise<void>;
//# sourceMappingURL=connectWebSocket.d.ts.map
