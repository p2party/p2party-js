import { describe, expect, test } from "bun:test";

import {
  deriveHpkeRecipientKeyPair,
  HPKE_CHACHA20POLY1305_AEAD_ID,
  HPKE_HASH_BYTES,
  HPKE_HKDF_SHA256_KDF_ID,
  HPKE_KEY_BYTES,
  HPKE_MAX_EXPORT_BYTES,
  HPKE_MLKEM768_X25519_KEM_ID,
  HPKE_MLKEM768_X25519_SUITE,
  HPKE_MODE_PSK,
  HPKE_NONCE_BYTES,
  HPKE_PAIR_PSK_BYTES,
  HPKE_PAIR_PSK_ID_BYTES,
  HPKE_TAG_BYTES,
  setupHpkeBaseSenderForConformance,
  setupHpkePskRecipient,
  setupHpkePskSenderDeterministically,
} from "../../src/cryptography/hpke";
import { loadTestModule } from "../../src/cryptography/testModule";

const fromHex = (hex: string): Uint8Array =>
  Uint8Array.from(Buffer.from(hex, "hex"));

const sha256Hex = async (bytes: Uint8Array): Promise<string> =>
  Buffer.from(
    await globalThis.crypto.subtle.digest("SHA-256", bytes.slice().buffer),
  ).toString("hex");

const expectBytesEqual = (actual: Uint8Array, expected: Uint8Array): void => {
  expect(Buffer.from(actual)).toEqual(Buffer.from(expected));
};

const proxiedBytes = (length: number): Uint8Array =>
  new Proxy(new Uint8Array(length), {
    get(target, property) {
      return Reflect.get(target, property, target) as unknown;
    },
  });

const OFFICIAL_VECTOR = Object.freeze({
  /**
   * draft-ietf-hpke-pq-05 test-vectors.json at:
   * 6433c8fce0b8b749dfc86c1095081a88698ccfab
   *
   * Upstream file SHA-256:
   * 35c59f4a0132e5631e50ac039d8ca3a72e99f5e92dfd94d45338d6ae243f613c
   */
  ikmR: "c8575d137deab99ac98fb0873048c83c3a1f47ef5b409f609c0ca652f58c83e0",
  recipientSecretKey:
    "b6bfa0299b955e85224df2e468f29eeab377ff3b96d4462b39447a22d32b91be",
  recipientPublicKeySha256:
    "ad42b3d8669605eb351273b945e2f4bfe62986517b411e606c225d96d4de9099",
  recipientX25519PublicKey:
    "641763ebe08e7add5686b0ed1d1e7053982aa616130939d0a09462df7dc74d05",
  ikmE:
    "c82228383c9fb887f7d8b332c28262024eda5b6b0ecd2325fe662daffc0594fa" +
    "d4990e7c8d13812137d06ba7017453de675ab0388d418853617f3ca58cc5daf3",
  encapsulatedKeySha256:
    "1797094252fe99a0326cf71b3a61448803efc34eef46ebec36d8ceeeb386c614",
  encapsulatedX25519PublicKey:
    "17c35fe4c5c802e43349d7bc95c8b40c001449d3251c1d92ff6d5c3b08c4b27c",
  info:
    "3466363436353230366636653230363132303437373236353633363936313665" +
    "3230353537323665",
  plaintext:
    "3432363536313735373437393230363937333230373437323735373436383263" +
    "3230373437323735373436383230363236353631373537343739",
  firstAad: "436f756e742d30",
  firstCiphertext:
    "a4ab74475a498ed725f685421f67c09a4783fe76f67bd251e1e73db8eb1452df" +
    "ad4df3c6453f7edecc7bb055dde561e2efd54d73a3d4f1f2f02eac90ba1e9b84" +
    "ded66d43aee6393524db",
  secondAad: "436f756e742d31",
  secondCiphertext:
    "9a38169c711afe09f0e470779b137ab236a2559faf61d55e417eaf06d48fe623" +
    "64643e95ca68382a281c04c67bd88f311939955a14f5f8c64344e4c103e1d94f" +
    "3084f122671fc7c0cd7e",
  additionalEncryptions: Object.freeze([
    Object.freeze({
      aad: "436f756e742d32",
      ciphertext:
        "0f2a23afb6d94feccf5e151cc5cac46e686325dbf34def1394d157448c420376" +
        "cee6d3c8aa4f3862edcc16fb4c3a9ef8a7ca1054d13fd9b1cfc4a5a47198ffb3" +
        "b97372295c894dded976",
    }),
    Object.freeze({
      aad: "436f756e742d33",
      ciphertext:
        "e5bad2306fccb51b100ce45fba5f88947d7853d66478099011de84bd2a5b9de3" +
        "37efdf9c459da7edee76cd07db9b7cddbc9a512fa45ee8f121531660861818ddd" +
        "a7d9d2b53d3f257d36a",
    }),
    Object.freeze({
      aad: "436f756e742d34",
      ciphertext:
        "923c933cbdc5955d34bf6134f1ad5e3c36f2acc9d9fb41dd8b4e0eba2101a05a" +
        "d5fe7a895e683176381b9baba7ced24498e87766a14fec8c256c7df2802371a5d" +
        "29d2faf03d9b4bbcaa9",
    }),
    Object.freeze({
      aad: "436f756e742d35",
      ciphertext:
        "0dd329bc293f83ac756c3fd052c2e52a8082a0a41069764736319127fb222a644" +
        "f6c28155bfab1bd7763d34ab09907ead4f497c9b14d729c75c8bb6f4acfdd596" +
        "f39c2e9872557802821",
    }),
    Object.freeze({
      aad: "436f756e742d36",
      ciphertext:
        "ae092db4f524c459e04a2453c92b59edef2ed07d08138f3582e7cfcb735d2377" +
        "2aa223baad29cc2dfe2e6d2935d7c593828413eaabd7eb6cb2b20d6e9fb82ab52" +
        "1d25f80fb93190260cc",
    }),
    Object.freeze({
      aad: "436f756e742d37",
      ciphertext:
        "299434544769a352047b82f0f74cd7f832dbb47b8b3d8500476f95e07d13502e" +
        "4b748296f19f51c4b35f4c8f80607d087f6e0632e68bad401e4153c95ceb380c" +
        "9b6e1a50477069d68345",
    }),
    Object.freeze({
      aad: "436f756e742d38",
      ciphertext:
        "6f09ad8f28a51f7f3e34eb99ac25e9b1e4a09ca063babb7c462a7ac7f65310a" +
        "a2d4a1eb3b629fba0606793c10a469af0b2407aac02e6073fa8b070d9aab532a" +
        "8349f884fd97cc5041b2b",
    }),
    Object.freeze({
      aad: "436f756e742d39",
      ciphertext:
        "90eb1a4fc6e9f6b5cb142d60d905ad221135aab544c8a20484c249d5417bd2eb" +
        "97c655ba8f15feda2adaab1a6bb5c06d0d7b17a6a6d298c9df95681d5ed131d7" +
        "c703918397e302620c6a",
    }),
  ]),
  exporterContext: "70736575646f72616e646f6d30",
  exportedValue:
    "14b64c194571a8e6fc16cb4d22754c79391081174b6001cd8050142f928defbb",
  additionalExports: Object.freeze([
    Object.freeze({
      context: "70736575646f72616e646f6d31",
      value: "7152f82449d4cd8137afb9b514fab6791e0938ba7734cb62228b8385003f32a6",
    }),
    Object.freeze({
      context: "70736575646f72616e646f6d32",
      value: "e3759bd609d81501bdac23863795a37437e804dd3274f0ed3964f82e8a6f97e5",
    }),
    Object.freeze({
      context: "70736575646f72616e646f6d33",
      value: "3e9e46c25af47fe02c149de2d3d8300881bb59fdb5b07c6b46d001918945cffa",
    }),
    Object.freeze({
      context: "70736575646f72616e646f6d34",
      value: "0dc9bd0216b18caa75d0188cab85d7fdef4b405c340da75b50e052b889fb2f78",
    }),
  ]),
});

/**
 * Project-owned exact-suite PSK fixture, independently derived with Node's
 * HMAC-SHA256 and ChaCha20-Poly1305 from the official vector's KEM result.
 * It is deliberately not described as an official HPKE interoperability
 * vector because hpke-pq-05 publishes only base-mode vectors.
 */
const LOCAL_PSK_VECTOR = Object.freeze({
  psk: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  pskId: "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
  ciphertext:
    "7aefba81287242c2cadb4cb4a0c3f99e7a260e55cefc412606d672478bd19597" +
    "373491f8bf53787149220e3286cfd309e43e3a031fe74b7ae07b32083cfacfcc" +
    "34cc67bd1752109ac1d8",
  exportedValue:
    "99ee96ae4d25c640b8ba683a9cd7cdeb0473e4a35d49a38118d09ca5727ad5bc",
});

const module = await loadTestModule();

describe("fixed MLKEM768-X25519 HPKE suite", () => {
  test("freezes the complete suite geometry and identifiers", () => {
    expect(HPKE_MLKEM768_X25519_KEM_ID).toBe(0x647a);
    expect(HPKE_HKDF_SHA256_KDF_ID).toBe(0x0001);
    expect(HPKE_CHACHA20POLY1305_AEAD_ID).toBe(0x0003);
    expect(HPKE_MODE_PSK).toBe(0x01);
    expect(HPKE_HASH_BYTES).toBe(32);
    expect(HPKE_KEY_BYTES).toBe(32);
    expect(HPKE_NONCE_BYTES).toBe(12);
    expect(HPKE_TAG_BYTES).toBe(16);
    expect(HPKE_PAIR_PSK_BYTES).toBe(32);
    expect(HPKE_PAIR_PSK_ID_BYTES).toBe(32);
    expect(HPKE_MAX_EXPORT_BYTES).toBe(8_160);
    expect(HPKE_MLKEM768_X25519_SUITE).toEqual({
      specification: {
        kem: "draft-ietf-hpke-pq-05",
        kemKeyDerivation: "draft-ietf-hpke-hpke-03",
        keySchedule: "RFC 9180",
      },
      kemId: 0x647a,
      kdfId: 0x0001,
      aeadId: 0x0003,
      publicKeyBytes: 1_216,
      secretKeyBytes: 32,
      encapsulatedKeyBytes: 1_120,
      sharedSecretBytes: 32,
      keyBytes: 32,
      nonceBytes: 12,
      tagBytes: 16,
      pskBytes: 32,
      pskIdBytes: 32,
    });
  });

  test("matches the complete official exact-suite base transcript", async () => {
    const ikmR = fromHex(OFFICIAL_VECTOR.ikmR);
    const ikmE = fromHex(OFFICIAL_VECTOR.ikmE);
    const info = fromHex(OFFICIAL_VECTOR.info);
    const originalIkmR = Uint8Array.from(ikmR);
    const originalIkmE = Uint8Array.from(ikmE);
    const originalInfo = Uint8Array.from(info);

    const keyPair = await deriveHpkeRecipientKeyPair(ikmR, module);
    expect(keyPair.secretKey).toEqual(
      fromHex(OFFICIAL_VECTOR.recipientSecretKey),
    );
    expect(await sha256Hex(keyPair.publicKey)).toBe(
      OFFICIAL_VECTOR.recipientPublicKeySha256,
    );
    expectBytesEqual(
      keyPair.publicKey.slice(-32),
      fromHex(OFFICIAL_VECTOR.recipientX25519PublicKey),
    );

    const setup = await setupHpkeBaseSenderForConformance({
      module,
      recipientPublicKey: keyPair.publicKey,
      info,
      encapsulationRandomness: ikmE,
    });
    expect(await sha256Hex(setup.encapsulatedKey)).toBe(
      OFFICIAL_VECTOR.encapsulatedKeySha256,
    );
    expectBytesEqual(
      setup.encapsulatedKey.slice(-32),
      fromHex(OFFICIAL_VECTOR.encapsulatedX25519PublicKey),
    );
    expect(
      setup.context.seal(
        fromHex(OFFICIAL_VECTOR.firstAad),
        fromHex(OFFICIAL_VECTOR.plaintext),
      ),
    ).toEqual(fromHex(OFFICIAL_VECTOR.firstCiphertext));
    expect(
      setup.context.seal(
        fromHex(OFFICIAL_VECTOR.secondAad),
        fromHex(OFFICIAL_VECTOR.plaintext),
      ),
    ).toEqual(fromHex(OFFICIAL_VECTOR.secondCiphertext));
    for (const encryption of OFFICIAL_VECTOR.additionalEncryptions)
      expect(
        setup.context.seal(
          fromHex(encryption.aad),
          fromHex(OFFICIAL_VECTOR.plaintext),
        ),
      ).toEqual(fromHex(encryption.ciphertext));
    expect(setup.context.sequence).toBe(10n);
    expect(
      await setup.context.exportSecret(
        fromHex(OFFICIAL_VECTOR.exporterContext),
        32,
      ),
    ).toEqual(fromHex(OFFICIAL_VECTOR.exportedValue));
    for (const exported of OFFICIAL_VECTOR.additionalExports)
      expect(
        await setup.context.exportSecret(fromHex(exported.context), 32),
      ).toEqual(fromHex(exported.value));

    // Every API borrows rather than consumes caller-owned input.
    expect(ikmR).toEqual(originalIkmR);
    expect(ikmE).toEqual(originalIkmE);
    expect(info).toEqual(originalInfo);

    setup.context.destroy();
    keyPair.destroy();
  });

  test("matches the independently derived PSK fixture and round-trips", async () => {
    const keyPair = await deriveHpkeRecipientKeyPair(
      fromHex(OFFICIAL_VECTOR.ikmR),
      module,
    );
    const recipientPublicKey = Uint8Array.from(keyPair.publicKey);
    const info = fromHex(OFFICIAL_VECTOR.info);
    const psk = fromHex(LOCAL_PSK_VECTOR.psk);
    const pskId = fromHex(LOCAL_PSK_VECTOR.pskId);
    const randomness = fromHex(OFFICIAL_VECTOR.ikmE);

    const setupPromise = setupHpkePskSenderDeterministically({
      module,
      recipientPublicKey,
      info,
      psk,
      pskId,
      encapsulationRandomness: randomness,
    });
    // Prove every borrowed view was snapshotted before the returned promise.
    recipientPublicKey.fill(0xff);
    info.fill(0xff);
    psk.fill(0xff);
    pskId.fill(0xff);
    randomness.fill(0xff);
    const sender = await setupPromise;

    const recipientEnc = Uint8Array.from(sender.encapsulatedKey);
    const recipientSecret = Uint8Array.from(keyPair.secretKey);
    const recipientInfo = fromHex(OFFICIAL_VECTOR.info);
    const recipientPsk = fromHex(LOCAL_PSK_VECTOR.psk);
    const recipientPskId = fromHex(LOCAL_PSK_VECTOR.pskId);
    const recipientPromise = setupHpkePskRecipient({
      module,
      encapsulatedKey: recipientEnc,
      recipientSecretKey: recipientSecret,
      info: recipientInfo,
      psk: recipientPsk,
      pskId: recipientPskId,
    });
    recipientEnc.fill(0xff);
    recipientSecret.fill(0xff);
    recipientInfo.fill(0xff);
    recipientPsk.fill(0xff);
    recipientPskId.fill(0xff);
    const recipient = await recipientPromise;

    const plaintext = fromHex(OFFICIAL_VECTOR.plaintext);
    const firstAad = fromHex(OFFICIAL_VECTOR.firstAad);
    const firstCiphertext = sender.context.seal(firstAad, plaintext);
    expect(firstCiphertext).toEqual(fromHex(LOCAL_PSK_VECTOR.ciphertext));
    expect(recipient.open(firstAad, firstCiphertext)).toEqual(plaintext);
    expect(sender.context.sequence).toBe(1n);
    expect(recipient.sequence).toBe(1n);

    const exported = await sender.context.exportSecret(
      fromHex(OFFICIAL_VECTOR.exporterContext),
      32,
    );
    expect(exported).toEqual(fromHex(LOCAL_PSK_VECTOR.exportedValue));
    expect(
      await recipient.exportSecret(
        fromHex(OFFICIAL_VECTOR.exporterContext),
        32,
      ),
    ).toEqual(exported);

    const secondAad = fromHex(OFFICIAL_VECTOR.secondAad);
    const secondCiphertext = sender.context.seal(secondAad, plaintext);
    const tampered = Uint8Array.from(secondCiphertext);
    tampered[tampered.length - 1] ^= 1;
    expect(recipient.open(secondAad, tampered)).toBeNull();
    expect(recipient.sequence).toBe(1n);
    expect(recipient.open(secondAad, secondCiphertext)).toEqual(plaintext);
    expect(recipient.sequence).toBe(2n);

    // Export snapshots its state before returning, so immediate destruction
    // cannot alter an already-started derivation.
    const pendingExport = sender.context.exportSecret(
      fromHex(OFFICIAL_VECTOR.exporterContext),
      32,
    );
    sender.context.destroy();
    expect(await pendingExport).toEqual(
      fromHex(LOCAL_PSK_VECTOR.exportedValue),
    );
    expect(sender.context.destroyed).toBe(true);
    expect(() => sender.context.seal(firstAad, plaintext)).toThrow(
      "HPKE context is destroyed",
    );
    expect(() =>
      sender.context.exportSecret(fromHex(OFFICIAL_VECTOR.exporterContext), 32),
    ).toThrow("HPKE context is destroyed");
    sender.context.destroy();

    recipient.destroy();
    expect(recipient.destroyed).toBe(true);
    expect(() => recipient.open(firstAad, firstCiphertext)).toThrow(
      "HPKE context is destroyed",
    );
    recipient.destroy();
    keyPair.destroy();
  });

  test("rejects invalid profile inputs synchronously", () => {
    const validSender = {
      module,
      recipientPublicKey: new Uint8Array(1_216),
      info: new Uint8Array(0),
      psk: new Uint8Array(32),
      pskId: new Uint8Array(32),
      encapsulationRandomness: new Uint8Array(64),
    };

    expect(() =>
      setupHpkePskSenderDeterministically({
        ...validSender,
        recipientPublicKey: new Uint8Array(1_215),
      }),
    ).toThrow("recipientPublicKey must be exactly 1216 bytes");
    expect(() =>
      setupHpkePskSenderDeterministically({
        ...validSender,
        info: "info" as unknown as Uint8Array,
      }),
    ).toThrow("info must be a Uint8Array");
    expect(() =>
      setupHpkePskSenderDeterministically({
        ...validSender,
        psk: new Uint8Array(31),
      }),
    ).toThrow("psk must be exactly 32 bytes");
    expect(() =>
      setupHpkePskSenderDeterministically({
        ...validSender,
        pskId: new Uint8Array(31),
      }),
    ).toThrow("pskId must be exactly 32 bytes");
    expect(() =>
      setupHpkePskSenderDeterministically({
        ...validSender,
        encapsulationRandomness: new Uint8Array(63),
      }),
    ).toThrow("encapsulationRandomness must be exactly 64 bytes");
    expect(() =>
      setupHpkePskSenderDeterministically({
        ...validSender,
        psk: proxiedBytes(32),
      }),
    ).toThrow("psk must be a Uint8Array");
    expect(() =>
      setupHpkePskSenderDeterministically({
        ...validSender,
        info: new Uint8Array(65_536),
      }),
    ).toThrow("HPKE info exceeds the supported length");
    expect(() =>
      setupHpkePskRecipient({
        module,
        encapsulatedKey: new Uint8Array(1_119),
        recipientSecretKey: new Uint8Array(32),
        info: new Uint8Array(0),
        psk: new Uint8Array(32),
        pskId: new Uint8Array(32),
      }),
    ).toThrow("encapsulatedKey must be exactly 1120 bytes");
    expect(() =>
      deriveHpkeRecipientKeyPair(new Uint8Array(31), module),
    ).toThrow("recipient key IKM must be exactly 32 bytes");
  });
});
