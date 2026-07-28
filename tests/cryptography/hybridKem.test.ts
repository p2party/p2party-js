import { describe, expect, test } from "bun:test";

import {
  HybridKemInvalidCiphertextError,
  createMlKem768X25519Backend,
  MLKEM768_X25519_CIPHERTEXT_BYTES,
  MLKEM768_X25519_PUBLIC_KEY_BYTES,
  MLKEM768_X25519_RANDOM_BYTES,
  MLKEM768_X25519_SEED_BYTES,
  MLKEM768_X25519_SHARED_SECRET_BYTES,
  MLKEM768_X25519_SUITE,
} from "../../src/cryptography/hybridKem";
import { loadTestModule } from "../../src/cryptography/testModule";

const hexToBytes = (hex: string): Uint8Array =>
  Uint8Array.from(Buffer.from(hex, "hex"));

const sha256Hex = async (bytes: Uint8Array): Promise<string> =>
  Buffer.from(
    await globalThis.crypto.subtle.digest("SHA-256", bytes.slice().buffer),
  ).toString("hex");

const shadowByteSurfaces = (
  bytes: Uint8Array,
  claimedLength = 0,
): Uint8Array => {
  const shadowed = Uint8Array.from(bytes);
  Object.defineProperty(shadowed, "length", { value: claimedLength });
  Object.defineProperty(shadowed, Symbol.iterator, {
    value: (): never => {
      throw new Error("hostile iterator must not run");
    },
  });
  return shadowed;
};

const proxiedBytes = (length: number): Uint8Array =>
  new Proxy(new Uint8Array(length), {
    get(): never {
      throw new Error("hostile proxy surface must not run");
    },
  });

interface OfficialVector {
  readonly id: number;
  readonly seed: string;
  readonly randomness: string;
  readonly publicKeySha256: string;
  readonly ciphertextSha256: string;
  readonly sharedSecret: string;
}

/**
 * All MLKEM768-X25519 vectors from concrete-hybrid-kems-04, pinned at:
 * e76e1939fb5bec71d3d6c206de20ca2c008f1f80
 *
 * Upstream test-vectors.json SHA-256:
 * 08b47d9fe5c827f7ceb20dd10a59bc853a949d6eaf0ad835405e86d833f92bad
 *
 * Hashing ek/ct keeps this fixture compact while comparing every output byte.
 */
const OFFICIAL_VECTORS: readonly OfficialVector[] = [
  {
    id: 0,
    seed: "0000000000000000000000000000000000000000000000000000000000000000",
    randomness:
      "6464646464646464646464646464646464646464646464646464646464646464" +
      "6464646464646464646464646464646464646464646464646464646464646464",
    publicKeySha256:
      "3bb0b003f553f49f38bab31546b7f4fdd323c74cbf4aaf97d9703ede4e83eff7",
    ciphertextSha256:
      "89ef4ccf41483c6fa62744d23a0fd6072a2e637f74564db7f618d1516ed8a6cd",
    sharedSecret:
      "e5ba94031ea6efd69c09c254f6d9783136ba6037e2d4c43bcccf19d6f3f4343a",
  },
  {
    id: 1,
    seed: "0101010101010101010101010101010101010101010101010101010101010101",
    randomness:
      "6565656565656565656565656565656565656565656565656565656565656565" +
      "6565656565656565656565656565656565656565656565656565656565656565",
    publicKeySha256:
      "f37b99b2db732a7df55f61fa442606133b1aeea462df9f8225fb5c82674523db",
    ciphertextSha256:
      "bb0f04a0f45979d8b398d71ba4302639ac354cfe384fff4c95ebacf1a4da1688",
    sharedSecret:
      "750300db25bff9620e893c2c6fcab9bf04d7f2e543b5b39420485626fa274908",
  },
  {
    id: 2,
    seed: "0202020202020202020202020202020202020202020202020202020202020202",
    randomness:
      "6666666666666666666666666666666666666666666666666666666666666666" +
      "6666666666666666666666666666666666666666666666666666666666666666",
    publicKeySha256:
      "01eba7f63ebe3bde984385c499280859aac9a8c403804fe47ebbf31982d74353",
    ciphertextSha256:
      "f848429823954ce959cce81de71f65f6a55335b9792d528ba852611b41e0b7da",
    sharedSecret:
      "87292f18b2e7af74bb8839ddee15e832d2f4bfac14dc84f824906d951436aafa",
  },
  {
    id: 3,
    seed: "0303030303030303030303030303030303030303030303030303030303030303",
    randomness:
      "6767676767676767676767676767676767676767676767676767676767676767" +
      "6767676767676767676767676767676767676767676767676767676767676767",
    publicKeySha256:
      "5b8e64e6709228bd7e4ed2942858a210fa08a85e83ee31c65ef17e119f77755c",
    ciphertextSha256:
      "82dc3c66ad732607ff6ec73b7463039aede7b946f14a0e957c20b776e706e41a",
    sharedSecret:
      "38c469d91f19aeb79dbf1aaae4d1195216c86186b00a798ea3a6e544cf9c074a",
  },
  {
    id: 4,
    seed: "0404040404040404040404040404040404040404040404040404040404040404",
    randomness:
      "6868686868686868686868686868686868686868686868686868686868686868" +
      "6868686868686868686868686868686868686868686868686868686868686868",
    publicKeySha256:
      "bb4ce870113dc866909cc20bb80054c0b811cd3d20ad40ee0e60d9e256188509",
    ciphertextSha256:
      "133677580de2007af9e00b2de832a2eb76f6a8f2f37b9d9c797432945e96985f",
    sharedSecret:
      "a638747e2b93607e6a651d528435afe07e8733ccd150507b96b639f6ff4a10ee",
  },
  {
    id: 5,
    seed: "0505050505050505050505050505050505050505050505050505050505050505",
    randomness:
      "6969696969696969696969696969696969696969696969696969696969696969" +
      "6969696969696969696969696969696969696969696969696969696969696969",
    publicKeySha256:
      "ceb8809f4271307be44f8593fa698810057cfba2164a6dc772fea43223ea7e51",
    ciphertextSha256:
      "42b31d85164d1b3215cc60e6f99965f080c2e5766ff8d0c3ac346aebe6d02c89",
    sharedSecret:
      "0594af7fe7a398ffe68f37a9f73506d6a3f7fd82b24e26f4b93269684ed47172",
  },
  {
    id: 6,
    seed: "0606060606060606060606060606060606060606060606060606060606060606",
    randomness: "6a".repeat(64),
    publicKeySha256:
      "01402bf2cd8c09854fc80f9e07259f9c7ca840f6e0fc498e7a3999c4ee9aaebb",
    ciphertextSha256:
      "e8da3a6c8c32f2768311c309573f5670cbab84dba561075eae5da8fe086f5a83",
    sharedSecret:
      "d11018de4d36cb4544612190b4613a7b76c703fc4cb782fb26de49adde017e97",
  },
  {
    id: 7,
    seed: "0707070707070707070707070707070707070707070707070707070707070707",
    randomness: "6b".repeat(64),
    publicKeySha256:
      "74943b4ecd441ec7f92d22c3fb377a29cd7fb96687efda8fae74ae2219a1c279",
    ciphertextSha256:
      "55b3619873d0c800e832fc9a7fd98f4d7c58d397748f3b22061b75632689e39b",
    sharedSecret:
      "eae6cff2b4d6971efa91c6333986693db4f5c46207af27ce6f5964c0eb4aef50",
  },
  {
    id: 8,
    seed: "0808080808080808080808080808080808080808080808080808080808080808",
    randomness: "6c".repeat(64),
    publicKeySha256:
      "d3fb4ce4f463fd1f51172cc01526d7ec8b0950b762b05933d15d646ebf7d7ccd",
    ciphertextSha256:
      "33da7e954dc18a7dea221771abac5d82ef783178775c30875bf1bec23680fe75",
    sharedSecret:
      "83ec9c8227c5306cb0e60bdf12678a5de9e24fe51855290a64f49e9795415661",
  },
  {
    id: 9,
    seed: "0909090909090909090909090909090909090909090909090909090909090909",
    randomness: "6d".repeat(64),
    publicKeySha256:
      "22572a534ca03a68e5cacdc1ed7527ea136db8793e20138eebb0e5ae2a5e2fb9",
    ciphertextSha256:
      "26595ec53499e7ea9d12924431aeaf84978d9108f270a6d42653b6323752722d",
    sharedSecret:
      "d1b5f13316ff420d4ca22c9a8e3f93d27f735d1da53ebc979cce23f9747e3261",
  },
];

describe("MLKEM768-X25519", () => {
  test("freezes the draft-04 suite geometry", () => {
    expect(MLKEM768_X25519_SUITE.specification).toBe(
      "draft-irtf-cfrg-concrete-hybrid-kems-04",
    );
    expect(MLKEM768_X25519_SEED_BYTES).toBe(32);
    expect(MLKEM768_X25519_PUBLIC_KEY_BYTES).toBe(1_216);
    expect(MLKEM768_X25519_CIPHERTEXT_BYTES).toBe(1_120);
    expect(MLKEM768_X25519_SHARED_SECRET_BYTES).toBe(32);
    expect(MLKEM768_X25519_RANDOM_BYTES).toBe(64);
  });

  test("matches every pinned official keygen, encapsulation, and decapsulation vector", async () => {
    const backend = createMlKem768X25519Backend(await loadTestModule());

    for (const vector of OFFICIAL_VECTORS) {
      const seed = hexToBytes(vector.seed);
      const randomness = hexToBytes(vector.randomness);
      const expectedSharedSecret = hexToBytes(vector.sharedSecret);
      const keyPair = await backend.deriveKeyPair(seed);
      const encapsulation = await backend.encapsulateDeterministically(
        keyPair.publicKey,
        randomness,
      );
      const decapsulation = await backend.decapsulate(
        encapsulation.ciphertext,
        keyPair.secretKey,
      );

      expect(keyPair.secretKey, `vector ${String(vector.id)} dk`).toEqual(seed);
      expect(
        await sha256Hex(keyPair.publicKey),
        `vector ${String(vector.id)} ek`,
      ).toBe(vector.publicKeySha256);
      expect(
        await sha256Hex(encapsulation.ciphertext),
        `vector ${String(vector.id)} ct`,
      ).toBe(vector.ciphertextSha256);
      expect(
        encapsulation.sharedSecret,
        `vector ${String(vector.id)} ss encaps`,
      ).toEqual(expectedSharedSecret);
      expect(
        decapsulation.sharedSecret,
        `vector ${String(vector.id)} ss decaps`,
      ).toEqual(expectedSharedSecret);
      expect(seed).toEqual(hexToBytes(vector.seed));
      expect(randomness).toEqual(hexToBytes(vector.randomness));

      decapsulation.destroy();
      encapsulation.destroy();
      keyPair.destroy();
    }
  });

  test("snapshots every borrowed deterministic input before yielding", async () => {
    const vector = OFFICIAL_VECTORS[0];
    const backend = createMlKem768X25519Backend(await loadTestModule());
    const seed = hexToBytes(vector.seed);
    const keyPairPromise = backend.deriveKeyPair(seed);
    seed.fill(0xff);
    const keyPair = await keyPairPromise;
    expect(await sha256Hex(keyPair.publicKey)).toBe(vector.publicKeySha256);

    const publicKey = Uint8Array.from(keyPair.publicKey);
    const randomness = hexToBytes(vector.randomness);
    const encapsulationPromise = backend.encapsulateDeterministically(
      publicKey,
      randomness,
    );
    publicKey.fill(0xff);
    randomness.fill(0xff);
    const encapsulation = await encapsulationPromise;
    expect(await sha256Hex(encapsulation.ciphertext)).toBe(
      vector.ciphertextSha256,
    );

    const ciphertext = Uint8Array.from(encapsulation.ciphertext);
    const secretKey = Uint8Array.from(keyPair.secretKey);
    const decapsulationPromise = backend.decapsulate(ciphertext, secretKey);
    ciphertext.fill(0xff);
    secretKey.fill(0xff);
    const decapsulation = await decapsulationPromise;
    expect(decapsulation.sharedSecret).toEqual(hexToBytes(vector.sharedSecret));

    decapsulation.destroy();
    encapsulation.destroy();
    keyPair.destroy();
  });

  test("random key generation and encapsulation round trip", async () => {
    const backend = createMlKem768X25519Backend(await loadTestModule());
    const keyPair = await backend.generateKeyPair();
    const encapsulation = await backend.encapsulate(keyPair.publicKey);
    const decapsulation = await backend.decapsulate(
      encapsulation.ciphertext,
      keyPair.secretKey,
    );

    expect(keyPair.publicKey).toHaveLength(1_216);
    expect(keyPair.secretKey).toHaveLength(32);
    expect(encapsulation.ciphertext).toHaveLength(1_120);
    expect(encapsulation.sharedSecret).toHaveLength(32);
    expect(decapsulation.sharedSecret).toEqual(encapsulation.sharedSecret);

    decapsulation.destroy();
    encapsulation.destroy();
    keyPair.destroy();
  });

  test("rejects wrong types and non-exact lengths synchronously", async () => {
    const backend = createMlKem768X25519Backend(await loadTestModule());
    const publicKey = new Uint8Array(1_216);
    const ciphertext = new Uint8Array(1_120);
    const secretKey = new Uint8Array(32);
    const randomness = new Uint8Array(64);

    expect(() =>
      backend.deriveKeyPair("seed" as unknown as Uint8Array),
    ).toThrow("seed must be a Uint8Array");
    expect(() => backend.deriveKeyPair(new Uint8Array(31))).toThrow(
      "seed must be exactly 32 bytes",
    );
    expect(() => backend.encapsulate(new Uint8Array(1_215))).toThrow(
      "public key must be exactly 1216 bytes",
    );
    expect(() =>
      backend.encapsulateDeterministically(publicKey, new Uint8Array(63)),
    ).toThrow("encapsulation randomness must be exactly 64 bytes");
    expect(() => backend.decapsulate(new Uint8Array(1_119), secretKey)).toThrow(
      "ciphertext must be exactly 1120 bytes",
    );
    expect(() => backend.decapsulate(ciphertext, new Uint8Array(31))).toThrow(
      "secret key must be exactly 32 bytes",
    );

    expect(publicKey).toEqual(new Uint8Array(1_216));
    expect(ciphertext).toEqual(new Uint8Array(1_120));
    expect(secretKey).toEqual(new Uint8Array(32));
    expect(randomness).toEqual(new Uint8Array(64));
  });

  test("rejects proxied byte inputs synchronously", async () => {
    const backend = createMlKem768X25519Backend(await loadTestModule());
    const publicKey = new Uint8Array(MLKEM768_X25519_PUBLIC_KEY_BYTES);
    const ciphertext = new Uint8Array(MLKEM768_X25519_CIPHERTEXT_BYTES);
    const secretKey = new Uint8Array(MLKEM768_X25519_SEED_BYTES);

    expect(() =>
      backend.deriveKeyPair(proxiedBytes(MLKEM768_X25519_SEED_BYTES)),
    ).toThrow("seed must be a Uint8Array");
    expect(() =>
      backend.encapsulate(proxiedBytes(MLKEM768_X25519_PUBLIC_KEY_BYTES)),
    ).toThrow("public key must be a Uint8Array");
    expect(() =>
      backend.encapsulateDeterministically(
        publicKey,
        proxiedBytes(MLKEM768_X25519_RANDOM_BYTES),
      ),
    ).toThrow("encapsulation randomness must be a Uint8Array");
    expect(() =>
      backend.decapsulate(
        proxiedBytes(MLKEM768_X25519_CIPHERTEXT_BYTES),
        secretKey,
      ),
    ).toThrow("ciphertext must be a Uint8Array");
    expect(() =>
      backend.decapsulate(ciphertext, proxiedBytes(MLKEM768_X25519_SEED_BYTES)),
    ).toThrow("secret key must be a Uint8Array");

    expect(publicKey).toEqual(new Uint8Array(MLKEM768_X25519_PUBLIC_KEY_BYTES));
    expect(ciphertext).toEqual(
      new Uint8Array(MLKEM768_X25519_CIPHERTEXT_BYTES),
    );
    expect(secretKey).toEqual(new Uint8Array(MLKEM768_X25519_SEED_BYTES));
  });

  test("uses intrinsic bytes despite shadowed length and iteration", async () => {
    const vector = OFFICIAL_VECTORS[0];
    const backend = createMlKem768X25519Backend(await loadTestModule());
    const keyPair = await backend.deriveKeyPair(
      shadowByteSurfaces(hexToBytes(vector.seed), 1_000),
    );
    expect(await sha256Hex(keyPair.publicKey)).toBe(vector.publicKeySha256);

    const deterministic = await backend.encapsulateDeterministically(
      shadowByteSurfaces(keyPair.publicKey),
      shadowByteSurfaces(hexToBytes(vector.randomness), 1_000),
    );
    expect(await sha256Hex(deterministic.ciphertext)).toBe(
      vector.ciphertextSha256,
    );

    const decapsulation = await backend.decapsulate(
      shadowByteSurfaces(deterministic.ciphertext),
      shadowByteSurfaces(keyPair.secretKey, 1_000),
    );
    expect(decapsulation.sharedSecret).toEqual(hexToBytes(vector.sharedSecret));

    const random = await backend.encapsulate(
      shadowByteSurfaces(keyPair.publicKey, 1_000),
    );
    const randomDecapsulation = await backend.decapsulate(
      random.ciphertext,
      keyPair.secretKey,
    );
    expect(randomDecapsulation.sharedSecret).toEqual(random.sharedSecret);

    randomDecapsulation.destroy();
    random.destroy();
    decapsulation.destroy();
    deterministic.destroy();
    keyPair.destroy();
  });

  test("destroy is idempotent and wipes every returned secret", async () => {
    const backend = createMlKem768X25519Backend(await loadTestModule());
    const keyPair = await backend.generateKeyPair();
    const encapsulation = await backend.encapsulate(keyPair.publicKey);
    const decapsulation = await backend.decapsulate(
      encapsulation.ciphertext,
      keyPair.secretKey,
    );

    keyPair.destroy();
    keyPair.destroy();
    encapsulation.destroy();
    encapsulation.destroy();
    decapsulation.destroy();
    decapsulation.destroy();

    expect(keyPair.destroyed).toBe(true);
    expect(encapsulation.destroyed).toBe(true);
    expect(decapsulation.destroyed).toBe(true);
    expect(keyPair.secretKey.every((byte) => byte === 0)).toBe(true);
    expect(encapsulation.sharedSecret.every((byte) => byte === 0)).toBe(true);
    expect(decapsulation.sharedSecret.every((byte) => byte === 0)).toBe(true);
  });

  test("rejects low-order X25519 recipient keys and attacker ciphertexts", async () => {
    const backend = createMlKem768X25519Backend(await loadTestModule());
    const vector = OFFICIAL_VECTORS[0];
    const keyPair = await backend.deriveKeyPair(hexToBytes(vector.seed));
    const randomness = hexToBytes(vector.randomness);
    const encapsulation = await backend.encapsulateDeterministically(
      keyPair.publicKey,
      randomness,
    );

    for (const lowOrderU of [0, 1] as const) {
      const invalidPublicKey = Uint8Array.from(keyPair.publicKey);
      invalidPublicKey.fill(0, 1_184);
      invalidPublicKey[1_184] = lowOrderU;
      await expect(
        backend.encapsulateDeterministically(
          invalidPublicKey,
          hexToBytes(vector.randomness),
        ),
      ).rejects.toThrow("x25519_dh failed (identity point)");

      const invalidCiphertext = Uint8Array.from(encapsulation.ciphertext);
      invalidCiphertext.fill(0, 1_088);
      invalidCiphertext[1_088] = lowOrderU;
      await expect(
        backend.decapsulate(invalidCiphertext, keyPair.secretKey),
      ).rejects.toThrow(HybridKemInvalidCiphertextError);
    }

    encapsulation.destroy();
    keyPair.destroy();
  });
});
