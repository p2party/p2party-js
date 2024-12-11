import { crypto_hash_sha512_BYTES } from "../cryptography/interfaces";
import { hexToUint8Array, uint8ArrayToHex } from "./uint8array";

export const LABEL_ELEMENTS = 4;

const LABEL_SERIALIZED_LEN =
  32 + // label name
  64 + // merkle root
  64 + // hash
  8; // date

// +3 for separators and the rest is hex
export const LABEL_STRING_LEN = LABEL_SERIALIZED_LEN * 2 + 3;

export const LABEL_ELEMENTS_SEPARATOR = "~";

export const compileChannelMessageLabel = (
  channelLabel: string,
  merkleRoot: string | Uint8Array,
  hash: string | Uint8Array,
  date = new Date(Date.now()),
): Promise<string> => {
  return new Promise((resolve, reject) => {
    try {
      if (channelLabel.length <= 0 || channelLabel.length > 32)
        reject(new Error("Label larger than 128 characters"));

      if (
        typeof merkleRoot === "string" &&
        merkleRoot.length !== crypto_hash_sha512_BYTES * 2
      ) {
        reject(new Error("Merkle root hex should be 128 bytes"));
      } else if (
        typeof merkleRoot !== "string" &&
        merkleRoot.length !== crypto_hash_sha512_BYTES
      ) {
        reject(new Error("Merkle root should be 64 bytes"));
      }

      if (
        typeof hash === "string" &&
        hash.length !== crypto_hash_sha512_BYTES * 2
      ) {
        reject(new Error("Hash hex should be 128 bytes"));
      } else if (
        typeof hash !== "string" &&
        hash.length !== crypto_hash_sha512_BYTES
      ) {
        reject(new Error("Hash should be 64 bytes"));
      }

      let label = "";

      // name (256 bytes)
      const nameBytes = new TextEncoder().encode(channelLabel);
      const namePadded = new Uint8Array(32);
      namePadded.set(nameBytes.subarray(0, Math.min(32, nameBytes.length)));

      label += uint8ArrayToHex(namePadded);
      label += LABEL_ELEMENTS_SEPARATOR;

      if (typeof merkleRoot === "string") {
        label += merkleRoot;
        label += LABEL_ELEMENTS_SEPARATOR;
      } else {
        label += uint8ArrayToHex(merkleRoot);
        label += LABEL_ELEMENTS_SEPARATOR;
      }

      if (typeof hash === "string") {
        label += hash;
        label += LABEL_ELEMENTS_SEPARATOR;
      } else {
        label += uint8ArrayToHex(hash);
        label += LABEL_ELEMENTS_SEPARATOR;
      }

      const bigintUint8 = new Uint8Array(8);

      const dateView = new DataView(bigintUint8.buffer, 0, 8);
      dateView.setBigInt64(0, BigInt(date.getTime()), false);

      label += uint8ArrayToHex(bigintUint8);

      resolve(label);
    } catch (error) {
      reject(error);
    }
  });
};

export const decompileChannelMessageLabel = (
  channelMessageLabel: string,
): Promise<{
  channelLabel: string;
  merkleRootHex: string;
  merkleRoot: Uint8Array;
  hashHex: string;
  hash: Uint8Array;
  date: Date;
}> => {
  return new Promise((resolve, reject) => {
    try {
      if (channelMessageLabel.length !== LABEL_STRING_LEN)
        reject(new Error("Wrong channel message label size"));

      const split = channelMessageLabel.split(LABEL_ELEMENTS_SEPARATOR);
      const splitLen = split.length;
      if (splitLen !== LABEL_ELEMENTS && splitLen > 1) {
        reject(
          new Error(
            `Channel message label needs to have ${LABEL_ELEMENTS} components.`,
          ),
        );
      } else if (splitLen === 1) {
        resolve({
          channelLabel: channelMessageLabel,
          merkleRootHex: "",
          merkleRoot: new Uint8Array(),
          hashHex: "",
          hash: new Uint8Array(),
          date: new Date(),
        });
      }

      const channelLabelUint8 = hexToUint8Array(split[0]);
      if (channelLabelUint8.length !== 32)
        reject(new Error("Channel label is not 128 bytes long."));
      const channelLabel = new TextDecoder()
        .decode(channelLabelUint8)
        .replace(/\0+$/, "");

      const merkleRoot = hexToUint8Array(split[1]);
      if (merkleRoot.length !== crypto_hash_sha512_BYTES)
        reject(new Error("Merkle root has invalid length"));

      const hash = hexToUint8Array(split[2]);
      if (hash.length !== crypto_hash_sha512_BYTES)
        reject(new Error("Message hash has invalid length"));

      const dateUint8 = hexToUint8Array(split[3]);
      const dateView = new DataView(dateUint8.buffer, dateUint8.byteOffset, 8);
      const date = new Date(Number(dateView.getBigUint64(0, false))); // Big-endian

      resolve({
        channelLabel,
        merkleRoot,
        merkleRootHex: split[1],
        hash,
        hashHex: split[2],
        date,
      });
    } catch (error) {
      reject(error);
    }
  });
};
