import { assertCanonicalEd25519Identity } from "./identityRole";

/**
 * Final transport-construction gate after every preceding async operation.
 * A purge/reset or identity rotation invalidates the captured constructor.
 */
export const assertTransportIdentityCurrent = (
  initialPublicKey: string,
  currentPublicKey: string,
): void => {
  assertCanonicalEd25519Identity(
    currentPublicKey,
    "Current self Ed25519 identity",
  );
  if (currentPublicKey !== initialPublicKey)
    throw new Error("Identity changed during WebRTC transport creation");
};
