export const decryptMessage = async (
  key: CryptoKey,
  ciphertext: ArrayBuffer,
  iv: Uint8Array,
) => {
  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    key,
    ciphertext,
  );

  return new TextDecoder().decode(decrypted);
};
