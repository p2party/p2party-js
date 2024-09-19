import { importPrivateKey } from "../utils/importPEMKeys";

import { setPeerData } from "../reducers/keyPairSlice";
import { signalingServerActions } from "../reducers/signalingServerSlice";

import type { MiddlewareAPI, Dispatch, UnknownAction } from "@reduxjs/toolkit";
import type { KeyPair } from "../reducers/keyPairSlice";
import type { WebSocketMessageChallengeResponse } from "../utils/interfaces";

const handleChallenge = async (
  keyPair: KeyPair,
  peerId: string,
  challenge: string,
  store: MiddlewareAPI<Dispatch<UnknownAction>, any>,
) => {
  try {
    const secretKey = await importPrivateKey(keyPair.secretKey);

    const nonce = Uint8Array.from(
      challenge.match(/.{1,2}/g)!.map((byte: string) => parseInt(byte, 16)),
    );

    const sig = await window.crypto.subtle.sign(
      {
        name: "RSA-PSS",
        saltLength: 32,
      },
      secretKey,
      nonce,
    );

    const signature = [...new Uint8Array(sig)]
      .map((x) => x.toString(16).padStart(2, "0"))
      .join("");

    store.dispatch(
      setPeerData({
        peerId,
        challenge,
        signature,
      }),
    );

    store.dispatch(
      signalingServerActions.sendMessage({
        content: {
          type: "challenge",
          fromPeerId: peerId,
          challenge,
          signature,
        } as WebSocketMessageChallengeResponse,
      }),
    );
  } catch (error) {
    throw error;
  }
};

export default handleChallenge;
