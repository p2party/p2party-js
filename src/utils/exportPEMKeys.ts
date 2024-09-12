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
  const result = [...new Uint8Array(spki)]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");

  return "0x" + result.toLowerCase();
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
