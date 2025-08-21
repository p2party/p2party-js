import { setPeerData } from "../reducers/keyPairSlice";

import { hexToUint8Array } from "../utils/uint8array";

import { sign } from "../cryptography/ed25519";

import type { MiddlewareAPI, Dispatch, UnknownAction } from "@reduxjs/toolkit";
import type { KeyPair } from "../reducers/keyPairSlice";

const handleChallenge = async (
  keyPair: KeyPair,
  peerId: string,
  challenge: string,
  store: MiddlewareAPI<Dispatch<UnknownAction>, any>,
) => {
  const secretKey = hexToUint8Array(keyPair.secretKey);

  const nonce = Uint8Array.from(
    challenge.match(/.{1,2}/g)!.map((byte: string) => parseInt(byte, 16)),
  );

  const sig = await sign(nonce, secretKey);

  // const sig = await window.crypto.subtle.sign(
  //   {
  //     name: "RSA-PSS",
  //     saltLength: 32,
  //   },
  //   secretKey,
  //   nonce,
  // );

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
};

export default handleChallenge;
