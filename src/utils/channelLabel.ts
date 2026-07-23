import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";
import { hexToUint8Array, uint8ArrayToHex } from "./uint8array";

export const LABEL_ELEMENTS = 2; // 3;

const LABEL_SERIALIZED_LEN =
  32 + // label name
  // 64 + // hash
  64; // merkle root

// +3 for separators and the rest is hex
export const LABEL_STRING_LEN = LABEL_SERIALIZED_LEN * 2 + 1; // + 2;

export const LABEL_ELEMENTS_SEPARATOR = "~";

export const compileChannelMessageLabel = (
  channelLabel: string,
  merkleRoot: string | Uint8Array,
  // hash: string | Uint8Array,
): Promise<string> => {
  return new Promise((resolve, reject) => {
    try {
      const nameBytes = new TextEncoder().encode(channelLabel);
      if (nameBytes.length <= 0 || nameBytes.length > 32)
        throw new Error("Channel label must be between 1 and 32 UTF-8 bytes");

      if (
        typeof merkleRoot === "string" &&
        !/^[0-9a-f]{128}$/.test(merkleRoot)
      ) {
        throw new Error(
          "Merkle root hex should be 128 canonical lowercase characters",
        );
      } else if (
        typeof merkleRoot !== "string" &&
        merkleRoot.length !== crypto_hash_sha512_BYTES
      ) {
        throw new Error("Merkle root should be 64 bytes");
      }

      // if (
      //   typeof hash === "string" &&
      //   hash.length !== crypto_hash_sha512_BYTES * 2
      // ) {
      //   reject(new Error("Hash hex should be 128 bytes"));
      // } else if (
      //   typeof hash !== "string" &&
      //   hash.length !== crypto_hash_sha512_BYTES
      // ) {
      //   reject(new Error("Hash should be 64 bytes"));
      // }

      let label = "";

      // name (256 bytes)
      const namePadded = new Uint8Array(32);
      namePadded.set(nameBytes.subarray(0, Math.min(32, nameBytes.length)));

      label += uint8ArrayToHex(namePadded);
      label += LABEL_ELEMENTS_SEPARATOR;

      if (typeof merkleRoot === "string") {
        label += merkleRoot;
        // label += LABEL_ELEMENTS_SEPARATOR;
      } else {
        label += uint8ArrayToHex(merkleRoot);
        // label += LABEL_ELEMENTS_SEPARATOR;
      }

      // if (typeof hash === "string") {
      //   label += hash;
      // } else {
      //   label += uint8ArrayToHex(hash);
      // }

      resolve(label);
    } catch (error) {
      reject(error as Error);
    }
  });
};

export const decompileChannelMessageLabel = (
  channelMessageLabel: string,
): Promise<{
  channelLabel: string;
  merkleRootHex: string;
  merkleRoot: Uint8Array;
  // hashHex: string;
  // hash: Uint8Array;
}> => {
  return new Promise((resolve, reject) => {
    try {
      // if (channelMessageLabel.length !== LABEL_STRING_LEN)
      //   reject(new Error("Wrong channel message label size"));

      const split = channelMessageLabel.split(LABEL_ELEMENTS_SEPARATOR);
      const splitLen = split.length;
      if (splitLen === 1) {
        resolve({
          channelLabel: channelMessageLabel,
          merkleRootHex: "",
          merkleRoot: new Uint8Array(),
          // hashHex: "",
          // hash: new Uint8Array(),
        });
        return;
      }
      if (
        splitLen !== LABEL_ELEMENTS ||
        channelMessageLabel.length !== LABEL_STRING_LEN
      )
        throw new Error(
          `Channel message label needs exactly ${String(LABEL_ELEMENTS)} bounded components.`,
        );
      if (!/^[0-9a-f]{64}~[0-9a-f]{128}$/.test(channelMessageLabel))
        throw new Error("Channel message label must use canonical lowercase hex");

      const channelLabelUint8 = hexToUint8Array(split[0]);
      if (channelLabelUint8.length !== 32)
        throw new Error("Channel label is not 32 bytes long.");
      const channelLabel = new TextDecoder()
        .decode(channelLabelUint8)
        .replace(/\0+$/, "");

      const merkleRoot = hexToUint8Array(split[1]);
      if (merkleRoot.length !== crypto_hash_sha512_BYTES)
        throw new Error("Merkle root has invalid length");

      // const hash = hexToUint8Array(split[2]);
      // if (hash.length !== crypto_hash_sha512_BYTES)
      //   reject(new Error("Message hash has invalid length"));

      resolve({
        channelLabel,
        merkleRoot,
        merkleRootHex: split[1],
        // hash,
        // hashHex: split[2],
      });
    } catch (error) {
      reject(error as Error);
    }
  });
};
