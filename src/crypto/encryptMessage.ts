export const encryptMessage = async (key: CryptoKey, plaintext: string) => {
  const encodedMessage = new TextEncoder().encode(plaintext);
  const iv = window.crypto.getRandomValues(new Uint8Array(12)); // Initialization vector
  const ciphertext = await window.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    key,
    encodedMessage,
  );

  return { ciphertext, iv };
};
