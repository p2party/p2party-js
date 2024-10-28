import { uint8ToHex, hexToUint8 } from "../utils/hexString";

export const str2ab = (str: string) => {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }

  return buf;
};

export const importPrivateKey = async (pemKey: string): Promise<CryptoKey> => {
  try {
    const pemHeader = "-----BEGIN PRIVATE KEY-----";
    const pemFooter = "-----END PRIVATE KEY-----";
    const pemContents = pemKey.substring(
      pemHeader.length,
      pemKey.length - pemFooter.length,
    );

    // base64 decode the string to get the binary data
    const binaryDerString = window.atob(pemContents);

    // convert from a binary string to an ArrayBuffer
    const binaryDer = str2ab(binaryDerString);

    return await window.crypto.subtle.importKey(
      "pkcs8",
      binaryDer,
      {
        name: "RSA-PSS",
        hash: "SHA-256",
      },
      true,
      ["sign"],
    );
  } catch (error) {
    throw error;
  }
};

export const importPublicKey = async (hexKey: string): Promise<CryptoKey> => {
  try {
    // const pemHeader = "-----BEGIN PUBLIC KEY-----";
    // const pemFooter = "-----END PUBLIC KEY-----";
    // const pemContents = pemKey.substring(
    //   pemHeader.length,
    //   pemKey.length - pemFooter.length,
    // );
    //
    // // base64 decode the string to get the binary data
    // const binaryDerString = window.atob(pemContents);
    //
    // // convert from a binary string to an ArrayBuffer
    // const binaryDer = str2ab(binaryDerString);

    const publicKeyUint8 = hexToUint8(hexKey);
    const binaryDer = publicKeyUint8.buffer;

    return await window.crypto.subtle.importKey(
      "spki",
      binaryDer,
      {
        name: "RSA-PSS",
        hash: "SHA-256",
      },
      true,
      ["verify"],
    );
  } catch (error) {
    throw error;
  }
};

const exportPublicKey = async (keys: CryptoKeyPair): Promise<string> => {
  const exported = await window.crypto.subtle.exportKey("spki", keys.publicKey);
  const exportedAsBase64 = window.btoa(
    String.fromCharCode(...new Uint8Array(exported)),
  );
  const pemExported = `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;

  return pemExported;
};

const exportPrivateKey = async (keys: CryptoKeyPair): Promise<string> => {
  const exported = await window.crypto.subtle.exportKey(
    "pkcs8",
    keys.privateKey,
  );
  const exportedAsBase64 = window.btoa(
    String.fromCharCode(...new Uint8Array(exported)),
  );
  const pemExported = `-----BEGIN PRIVATE KEY-----\n${exportedAsBase64}\n-----END PRIVATE KEY-----`;

  return pemExported;
};

export const exportPublicKeyToHex = async (publicKey: CryptoKey) => {
  const spki = await window.crypto.subtle.exportKey("spki", publicKey);

  return uint8ToHex(new Uint8Array(spki));
  // const result = [...new Uint8Array(spki)]
  //   .map((x) => x.toString(16).padStart(2, "0"))
  //   .join("");

  // return result.toLowerCase();
};

export const exportPemKeys = async (keys: CryptoKeyPair) => {
  try {
    const publicKey = await exportPublicKey(keys);
    const secretKey = await exportPrivateKey(keys);

    return { publicKey, secretKey };
  } catch (error) {
    throw error;
  }
};

export const encryptMessage = async (
  senderSecretKeyPem: string, // PEM format
  receiverPublicKeyHex: string, // hex format
  message: string | Uint8Array,
  iv?: Uint8Array,
) => {
  if (iv && iv.length !== 16) throw new Error("IV too small");

  const secretKey = await importPrivateKey(senderSecretKeyPem);
  const publicKey = await importPublicKey(receiverPublicKeyHex);

  const encodedMessage =
    typeof message === "string" ? new TextEncoder().encode(message) : message;
  iv = iv ?? window.crypto.getRandomValues(new Uint8Array(16)); // Initialization vector

  const key = await window.crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: publicKey,
    },
    secretKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"],
  );

  const ciphertext = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    key,
    encodedMessage,
  );

  const ciphertextHex = uint8ToHex(new Uint8Array(ciphertext));
  const ivHex = uint8ToHex(iv);

  return ciphertextHex + "-" + ivHex;
};

export const decryptMessageString = async (
  senderPublicKeyHex: string,
  receiverSecretKeyPem: string,
  messageHex: string,
) => {
  const publicKey = await importPublicKey(senderPublicKeyHex);
  const secretKey = await importPrivateKey(receiverSecretKeyPem);

  const splitIndex = messageHex.length - 32;
  const ciphertextHex = messageHex.slice(0, splitIndex - 1); // remove "-"
  const ivHex = messageHex.slice(splitIndex);

  const ciphertext = hexToUint8(ciphertextHex);
  const iv = hexToUint8(ivHex);

  const key = await window.crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: publicKey,
    },
    secretKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"],
  );

  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv,
    },
    key,
    ciphertext,
  );

  return new TextDecoder().decode(decrypted);
};

export const decryptMessageUint8Array = async (
  senderPublicKeyHex: string,
  receiverSecretKeyPem: string,
  messageHex: string,
) => {
  const publicKey = await importPublicKey(senderPublicKeyHex);
  const secretKey = await importPrivateKey(receiverSecretKeyPem);

  const splitIndex = messageHex.length - 32;
  const ciphertextHex = messageHex.slice(0, splitIndex - 1); // remove "-"
  const ivHex = messageHex.slice(splitIndex);

  const ciphertext = hexToUint8(ciphertextHex);
  const iv = hexToUint8(ivHex);

  const key = await window.crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: publicKey,
    },
    secretKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"],
  );

  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv,
    },
    key,
    ciphertext,
  );

  return new Uint8Array(decrypted);
};
