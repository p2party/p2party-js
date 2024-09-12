import type { IRTCPeerConnection } from "../reducers/peersSlice";
import type { IRTCDataChannel } from "../reducers/channelsSlice";
export declare const openDataChannel: (
  c: string | RTCDataChannel,
  epc: IRTCPeerConnection,
) => Promise<IRTCDataChannel>;
//# sourceMappingURL=openDataChannel.d.ts.map
