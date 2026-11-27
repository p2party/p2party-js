import { hexToUint8Array, uint8ArrayToHex } from "../utils/uint8array";
import { sign } from "../cryptography/ed25519";
import { SIGNALING_PROTOCOL_VERSION } from "../utils/constants";
import type { KeyPair } from "../reducers/keyPairSlice";
import type { WebSocketMessageChallengeResponse } from "../utils/interfaces";

/** Sign the nonce for the WebSocket the client actually opened. */
export const handleChallenge = async (
  keyPair: KeyPair,
  socketUrl: string,
  challenge: string,
): Promise<WebSocketMessageChallengeResponse> => {
  if (!/^[0-9a-f]{64}$/.test(challenge)) throw new Error("Invalid challenge");
  const host = new URL(socketUrl).host.toLowerCase();
  const prefix = new TextEncoder().encode(
    `p2party-signaling-auth-v2\0${host}\0`,
  );
  const message = new Uint8Array(prefix.length + 32);
  message.set(prefix);
  message.set(hexToUint8Array(challenge), prefix.length);
  const secretKey = hexToUint8Array(keyPair.secretKey);
  try {
    return {
      type: "challenge",
      publicKey: keyPair.publicKey,
      challenge,
      signature: uint8ArrayToHex(await sign(message, secretKey)),
      protocolVersion: SIGNALING_PROTOCOL_VERSION,
    };
  } finally {
    secretKey.fill(0);
  }
};
