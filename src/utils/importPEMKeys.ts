const str2ab = (str: string) => {
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

export const importPublicKey = async (pemKey: string): Promise<CryptoKey> => {
  try {
    const pemHeader = "-----BEGIN PUBLIC KEY-----";
    const pemFooter = "-----END PUBLIC KEY-----";
    const pemContents = pemKey.substring(
      pemHeader.length,
      pemKey.length - pemFooter.length,
    );

    // base64 decode the string to get the binary data
    const binaryDerString = window.atob(pemContents);

    // convert from a binary string to an ArrayBuffer
    const binaryDer = str2ab(binaryDerString);

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
