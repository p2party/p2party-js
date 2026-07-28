import { describe, expect, test } from "bun:test";

import {
  CARRIER_AEAD_SUITE_1_NONCE_BYTES,
  CarrierAeadUnavailableError,
  buildCarrierPlaintext,
  decodeCarrierEnvelope,
  deriveCarrierObjectId,
  encodeCarrierEnvelope,
  envelopesAreCarrierSeparated,
  openCarrierEnvelope,
  sealCarrierEnvelope,
} from "../../src/blindRendezvous/carrierEnvelope";
import {
  carrierAad,
  carrierKey,
  policyHash,
  roomRoot,
} from "../../src/blindRendezvous/derivations";
import { DEFAULT_BLIND_POLICY_V4_0 } from "../../src/blindRendezvous/roomPolicyV4";

import type {
  CarrierAeadProvider,
  CarrierEnvelopeV1,
} from "../../src/blindRendezvous/carrierEnvelope";
import type { CarrierEnvelopeCoordinates } from "../../src/blindRendezvous/derivations";

const hex = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

/**
 * A test double standing in for the missing XChaCha20-Poly1305 build export.
 *
 * It is deliberately NOT an AEAD: it is a keyed stream XOR with a tag, good
 * enough to prove framing, key separation, AAD binding, and fail-closed
 * behavior, and useless as evidence about the real construction. Nothing in
 * `src/` may use it.
 */
const stubProvider = (): CarrierAeadProvider => {
  const keystream = (key: Uint8Array, nonce: Uint8Array, length: number) => {
    const output = new Uint8Array(length);
    for (let index = 0; index < length; index++)
      output[index] =
        key[index % key.length] ^ nonce[index % nonce.length] ^ (index & 0xff);
    return output;
  };
  const tagOf = (
    key: Uint8Array,
    nonce: Uint8Array,
    aad: Uint8Array,
    body: Uint8Array,
  ) => {
    const tag = new Uint8Array(16);
    for (const [source, salt] of [
      [key, 1],
      [nonce, 2],
      [aad, 3],
      [body, 5],
    ] as const)
      for (let index = 0; index < source.length; index++)
        tag[index % 16] ^= source[index] ^ ((salt * (index + 1)) % 251);
    return tag;
  };

  return {
    suite: 1,
    seal: async (key, nonce, aad, plaintext) => {
      const body = plaintext.map(
        (byte, index) => byte ^ keystream(key, nonce, plaintext.length)[index],
      );
      const output = new Uint8Array(body.length + 16);
      output.set(body);
      output.set(tagOf(key, nonce, aad, body), body.length);
      return output;
    },
    open: async (key, nonce, aad, sealed) => {
      if (sealed.length < 16) return null;
      const body = sealed.subarray(0, sealed.length - 16);
      const tag = sealed.subarray(sealed.length - 16);
      const expected = tagOf(key, nonce, aad, body);
      let difference = 0;
      for (let index = 0; index < 16; index++)
        difference |= tag[index] ^ expected[index];
      if (difference !== 0) return null;
      const stream = keystream(key, nonce, body.length);
      return body.map((byte, index) => byte ^ stream[index]);
    },
  };
};

const capability = new Uint8Array(32).fill(0x55);
const root = await roomRoot(
  capability,
  await policyHash(DEFAULT_BLIND_POLICY_V4_0),
);

const coordinates: CarrierEnvelopeCoordinates = {
  deliveryProfileHash: new Uint8Array(32).fill(0x10),
  carrierContextId: new Uint8Array(32).fill(0x20),
  ingressWindow: 77n,
  sizeClass: 0,
};

const nonce = new Uint8Array(CARRIER_AEAD_SUITE_1_NONCE_BYTES).fill(0x01);
const operationBytes = Uint8Array.from({ length: 64 }, (_, i) => i);

describe("the specified AEAD is absent and nothing substitutes for it", () => {
  test("sealing and opening fail closed with a typed error", async () => {
    await expect(
      sealCarrierEnvelope(
        root,
        coordinates,
        nonce,
        buildCarrierPlaintext(operationBytes, 4096),
        null,
      ),
    ).rejects.toBeInstanceOf(CarrierAeadUnavailableError);

    const envelope: CarrierEnvelopeV1 = {
      version: 1,
      deliveryProfileHash: coordinates.deliveryProfileHash,
      ingressWindow: coordinates.ingressWindow,
      sizeClass: coordinates.sizeClass,
      carrierContextId: coordinates.carrierContextId,
      nonce,
      ciphertextAndTag: new Uint8Array(64),
    };
    await expect(
      openCarrierEnvelope(root, envelope, null),
    ).rejects.toBeInstanceOf(CarrierAeadUnavailableError);
  });

  test("a provider announcing another suite is refused", async () => {
    const wrongSuite = {
      ...stubProvider(),
      suite: 2,
    } as unknown as CarrierAeadProvider;
    await expect(
      sealCarrierEnvelope(
        root,
        coordinates,
        nonce,
        buildCarrierPlaintext(operationBytes, 4096),
        wrongSuite,
      ),
    ).rejects.toBeInstanceOf(CarrierAeadUnavailableError);
  });
});

describe("framing, key schedule, and identifiers", () => {
  const provider = stubProvider();

  test("a sealed envelope round-trips and pads to the size class", async () => {
    const plaintext = buildCarrierPlaintext(operationBytes, 4096);
    const envelope = await sealCarrierEnvelope(
      root,
      coordinates,
      nonce,
      plaintext,
      provider,
    );
    const opened = await openCarrierEnvelope(root, envelope, provider);
    expect(opened).not.toBeNull();
    expect(hex(opened!.operationBytes)).toBe(hex(operationBytes));
    expect(opened!.carrierPadding.every((byte) => byte === 0)).toBe(true);

    const encoded = encodeCarrierEnvelope(envelope);
    expect(hex(encodeCarrierEnvelope(decodeCarrierEnvelope(encoded)))).toBe(
      hex(encoded),
    );
  });

  test("every real object of one size class has one fixed length", async () => {
    const short = buildCarrierPlaintext(operationBytes.subarray(0, 8), 4096);
    const long = buildCarrierPlaintext(operationBytes, 4096);
    const sealedShort = await sealCarrierEnvelope(
      root,
      coordinates,
      nonce,
      short,
      provider,
    );
    const sealedLong = await sealCarrierEnvelope(
      root,
      coordinates,
      nonce,
      long,
      provider,
    );
    expect(encodeCarrierEnvelope(sealedShort).length).toBe(
      encodeCarrierEnvelope(sealedLong).length,
    );
  });

  test("an operation larger than the size class is refused, not truncated", () => {
    expect(() => buildCarrierPlaintext(new Uint8Array(5000), 4096)).toThrow(
      "does not fit this profile's carrier size class",
    );
  });

  test("the key schedule separates carrier contexts and windows", async () => {
    const base = await carrierKey(root, coordinates, nonce);
    const otherContext = await carrierKey(
      root,
      { ...coordinates, carrierContextId: new Uint8Array(32).fill(0x21) },
      nonce,
    );
    const otherWindow = await carrierKey(
      root,
      { ...coordinates, ingressWindow: 78n },
      nonce,
    );
    const otherNonce = await carrierKey(
      root,
      coordinates,
      new Uint8Array(24).fill(0x02),
    );
    for (const derived of [otherContext, otherWindow, otherNonce])
      expect(hex(derived)).not.toBe(hex(base));
  });

  test("the AAD binds the public coordinates and omits the nonce", () => {
    // Compared byte-wise: a hex-substring search would false-positive on
    // nibble-shifted repeats of a patterned value.
    const containsBytes = (
      haystack: Uint8Array,
      needle: Uint8Array,
    ): boolean => {
      outer: for (
        let start = 0;
        start + needle.length <= haystack.length;
        start++
      ) {
        for (let index = 0; index < needle.length; index++)
          if (haystack[start + index] !== needle[index]) continue outer;
        return true;
      }
      return false;
    };

    const distinctiveNonce = Uint8Array.from({ length: 24 }, (_, i) => i + 100);
    const aad = carrierAad(1, coordinates);
    expect(containsBytes(aad, distinctiveNonce)).toBe(false);
    expect(containsBytes(aad, coordinates.deliveryProfileHash)).toBe(true);
    expect(containsBytes(aad, coordinates.carrierContextId)).toBe(true);
    expect(hex(carrierAad(1, { ...coordinates, sizeClass: 1 }))).not.toBe(
      hex(aad),
    );
  });

  test("tampering with the sealed body yields null, not a plaintext", async () => {
    const envelope = await sealCarrierEnvelope(
      root,
      coordinates,
      nonce,
      buildCarrierPlaintext(operationBytes, 4096),
      provider,
    );
    const tampered: CarrierEnvelopeV1 = {
      ...envelope,
      ciphertextAndTag: Uint8Array.from(envelope.ciphertextAndTag),
    };
    tampered.ciphertextAndTag[0] ^= 0xff;
    expect(await openCarrierEnvelope(root, tampered, provider)).toBeNull();
  });

  test("another room's key opens nothing, which is how a dummy reads", async () => {
    const envelope = await sealCarrierEnvelope(
      root,
      coordinates,
      nonce,
      buildCarrierPlaintext(operationBytes, 4096),
      provider,
    );
    const otherRoot = await roomRoot(
      new Uint8Array(32).fill(0x66),
      await policyHash(DEFAULT_BLIND_POLICY_V4_0),
    );
    expect(await openCarrierEnvelope(otherRoot, envelope, provider)).toBeNull();
  });

  test("two carrier contexts receive different bytes and object ids", async () => {
    const plaintext = buildCarrierPlaintext(operationBytes, 4096);
    const first = await sealCarrierEnvelope(
      root,
      coordinates,
      nonce,
      plaintext,
      provider,
    );
    const second = await sealCarrierEnvelope(
      root,
      { ...coordinates, carrierContextId: new Uint8Array(32).fill(0x30) },
      new Uint8Array(24).fill(0x09),
      plaintext,
      provider,
    );
    expect(envelopesAreCarrierSeparated(first, second)).toBe(true);
    expect(hex(await deriveCarrierObjectId(first))).not.toBe(
      hex(await deriveCarrierObjectId(second)),
    );
  });
});
