export interface DescriptionSendArgs {
    type: "description";
    description: RTCSessionDescription;
    toPeerId: string;
}
export interface CandidateSendArgs {
    type: "candidate";
    candidate: RTCIceCandidate;
    toPeerId: string;
}
export interface PeerId {
    type: "peerId";
    peerId: string;
    challenge: string;
    message: string;
}
export interface RoomId {
    type: "roomId";
    roomId: string;
    roomUrl: string;
}
export interface ChallengeSendArgs {
    type: "challenge";
    challenge: string;
    signature: string;
    fromPeerId: string;
}
export interface Description extends DescriptionSendArgs {
    fromPeerId: string;
    roomId: string;
}
export interface Candidate extends CandidateSendArgs {
    fromPeerId: string;
    roomId: string;
}
export interface BaseQueryFnArgs {
    signalingServerUrl: string;
    rtcConfig: RTCConfiguration;
}
//# sourceMappingURL=interfaces.d.ts.map