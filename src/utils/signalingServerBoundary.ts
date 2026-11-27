const parseSignalingServerUrl = (value: string): URL => {
  const url = new URL(value);
  if (url.protocol !== "ws:" && url.protocol !== "wss:")
    throw new Error("Signaling server URL must use ws: or wss:");
  if (url.searchParams.has("publickey"))
    throw new Error("The signaling URL must not contain a public key");
  return url;
};

export const canonicalSignalingServerUrl = (value: string): string =>
  parseSignalingServerUrl(value).toString();

export interface SignalingServerSelection {
  requestedServerUrl: string;
  currentServerUrl: string;
  hasActiveRooms: boolean;
  isConnected: boolean;
  isEstablishingConnection: boolean;
}

/** Enforce the SDK's one-server provenance for every retained active room. */
export const selectSignalingServerUrl = ({
  requestedServerUrl,
  currentServerUrl,
  hasActiveRooms,
  isConnected,
  isEstablishingConnection,
}: SignalingServerSelection): string => {
  const requested = canonicalSignalingServerUrl(requestedServerUrl);
  if (
    (hasActiveRooms || isConnected || isEstablishingConnection) &&
    canonicalSignalingServerUrl(currentServerUrl) !== requested
  )
    throw new Error(
      "Cannot join a room through a different active signaling server",
    );
  return requested;
};
