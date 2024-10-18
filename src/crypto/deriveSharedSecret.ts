export const deriveSharedSecret = async (
  publicKey: CryptoKey,
  privateKey: CryptoKey,
) => {
  return await window.crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: publicKey,
    },
    privateKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"],
  );
};
