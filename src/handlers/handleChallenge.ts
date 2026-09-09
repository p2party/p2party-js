import { setPeerData } from "../reducers/keyPairSlice";

import { hexToUint8Array } from "../utils/uint8array";

import { sign } from "../cryptography/ed25519";
import { PROTOCOL_VERSION } from "../utils/constants";

import type { MiddlewareAPI } from "@reduxjs/toolkit";
import type { KeyPair } from "../reducers/keyPairSlice";
import type { WebSocketMessageChallengeResponse } from "../utils/interfaces";

export const handleChallenge = async (
  keyPair: KeyPair,
  peerId: string,
  challenge: string,
  store: MiddlewareAPI,
  isCurrentSocket: () => boolean = () => true,
): Promise<WebSocketMessageChallengeResponse | null> => {
  const secretKey = hexToUint8Array(keyPair.secretKey);
  try {
    const matches = challenge.match(/.{1,2}/g);
    if (!matches) throw new Error("Invalid challenge format");
    const nonce = Uint8Array.from(
      matches.map((byte: string) => parseInt(byte, 16)),
    );

    const sig = await sign(nonce, secretKey);

    const signature = [...new Uint8Array(sig)]
      .map((x) => x.toString(16).padStart(2, "0"))
      .join("");

    if (!isCurrentSocket()) return null;
    store.dispatch(
      setPeerData({
        peerId,
        challenge,
        signature,
      }),
    );
    return {
      type: "challenge",
      fromPeerId: peerId,
      challenge,
      signature,
      protocolVersion: PROTOCOL_VERSION,
    };
  } finally {
    secretKey.fill(0);
  }
};
