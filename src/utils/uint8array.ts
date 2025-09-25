import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";

const HEX = "0123456789abcdef";
const Array32 = new Array(64);
const Array64 = new Array(128);

/**
 * Turns an array of Uint8Arrays into one Uint8Array.
 */
export const concatUint8Arrays = (
  arrays: Uint8Array[],
): Promise<Uint8Array> => {
  return new Promise((resolve) => {
    let len = 0;
    const arraysLen = arrays.length;
    for (let i = 0; i < arraysLen; i++) len += arrays[i].length;
    const result = new Uint8Array(len);

    let offset = 0;
    for (const arr of arrays) {
      result.set(arr, offset);
      offset += arr.length;
    }

    resolve(result);
  });
};

/**
 * Compares two Uint8Arrays.
 */
export const uint8ArraysAreEqual = (
  array1: Uint8Array,
  array2: Uint8Array,
): Promise<boolean> => {
  return new Promise((resolve) => {
    const arrLen = array1.length;
    if (arrLen !== array2.length) resolve(false);

    for (let i = 0; i < arrLen; i++) {
      if (array1[i] !== array2[i]) resolve(false);
    }

    resolve(true);
  });
};

/**
 * Converts Uint8Array to hex string.
 */
export const uint8ArrayToHex = (array: Uint8Array) => {
  const len = array.length;
  const out =
    len === crypto_hash_sha512_BYTES
      ? Array64
      : len === 32
        ? Array32
        : new Array(len * 2);
  let j = 0;
  for (let i = 0; i < len; i++) {
    const v = array[i];
    out[j++] = HEX[v >> 4];
    out[j++] = HEX[v & 0x0f];
  }

  return out.join("");
};

/**
 * Converts hex string to Uint8Array.
 */
export const hexToUint8Array = (hexString: string) => {
  // remove the leading 0x
  hexString = hexString.replace(/^0x/, "");

  // ensure even number of characters
  if (hexString.length % 2 != 0) hexString = "0" + hexString;

  // check for some non-hex characters
  const bad = /[G-Z\s]/i.exec(hexString);
  if (bad) throw new Error(`Found non-hex characters ${bad[0]}`);

  // split the string into pairs of octets
  const pairs = hexString.match(/[\dA-F]{2}/gi);
  if (!pairs) throw new Error("No hex characters in string");

  const len = pairs.length;
  const result = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    result[i] = parseInt(pairs[i], 16);
  }

  return result;
};
