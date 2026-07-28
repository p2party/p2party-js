#!/usr/bin/env node

/**
 * Independent suite-1 pair-crypto vector generator.
 *
 * It intentionally imports no p2party source. Canonical bytes are assembled
 * directly from the specification. Bootstrap uses the exact published
 * MLKEM768-X25519 KEM transcript from the pinned hpke-pq-05 vector, then
 * independently applies RFC 9180 PSK scheduling and Node's ChaCha20-Poly1305.
 * Established flights use RFC 5869 plus XChaCha20-Poly1305 reconstructed as
 * HChaCha20 and Node's independently implemented ChaCha20-Poly1305.
 */

import { createCipheriv, createHash, createHmac } from "node:crypto";
import { Buffer } from "node:buffer";

const ascii = (value) => Buffer.from(value, "ascii");
const filled = (value, length = 32) => Buffer.alloc(length, value);
const u8 = (value) => Buffer.from([value]);
const u16 = (value) => {
  const output = Buffer.alloc(2);
  output.writeUInt16BE(value);
  return output;
};
const u32 = (value) => {
  const output = Buffer.alloc(4);
  output.writeUInt32BE(value);
  return output;
};
const u64 = (value) => {
  const output = Buffer.alloc(8);
  output.writeBigUInt64BE(value);
  return output;
};
const concat = (...parts) => Buffer.concat(parts);
const sha256 = (value) => createHash("sha256").update(value).digest();
const hmac = (key, value) => createHmac("sha256", key).update(value).digest();

const hkdfExpand = (pseudorandomKey, info, length) => {
  const blocks = [];
  let previous = Buffer.alloc(0);
  for (let counter = 1; Buffer.concat(blocks).length < length; counter++) {
    previous = hmac(pseudorandomKey, concat(previous, info, u8(counter)));
    blocks.push(previous);
  }
  return Buffer.concat(blocks).subarray(0, length);
};

const hkdfExtract = (salt, inputKeyMaterial) =>
  hmac(salt.length === 0 ? Buffer.alloc(32) : salt, inputKeyMaterial);

const rotateLeft = (value, count) =>
  ((value << count) | (value >>> (32 - count))) >>> 0;

const quarterRound = (state, a, b, c, d) => {
  state[a] = (state[a] + state[b]) >>> 0;
  state[d] = rotateLeft(state[d] ^ state[a], 16);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotateLeft(state[b] ^ state[c], 12);
  state[a] = (state[a] + state[b]) >>> 0;
  state[d] = rotateLeft(state[d] ^ state[a], 8);
  state[c] = (state[c] + state[d]) >>> 0;
  state[b] = rotateLeft(state[b] ^ state[c], 7);
};

const hchacha20 = (key, noncePrefix) => {
  if (key.length !== 32 || noncePrefix.length !== 16)
    throw new Error("invalid HChaCha20 input");
  const constants = ascii("expand 32-byte k");
  const state = new Uint32Array(16);
  for (let index = 0; index < 4; index++)
    state[index] = constants.readUInt32LE(index * 4);
  for (let index = 0; index < 8; index++)
    state[index + 4] = key.readUInt32LE(index * 4);
  for (let index = 0; index < 4; index++)
    state[index + 12] = noncePrefix.readUInt32LE(index * 4);

  for (let round = 0; round < 10; round++) {
    quarterRound(state, 0, 4, 8, 12);
    quarterRound(state, 1, 5, 9, 13);
    quarterRound(state, 2, 6, 10, 14);
    quarterRound(state, 3, 7, 11, 15);
    quarterRound(state, 0, 5, 10, 15);
    quarterRound(state, 1, 6, 11, 12);
    quarterRound(state, 2, 7, 8, 13);
    quarterRound(state, 3, 4, 9, 14);
  }

  const output = Buffer.alloc(32);
  const words = [0, 1, 2, 3, 12, 13, 14, 15];
  for (let index = 0; index < words.length; index++)
    output.writeUInt32LE(state[words[index]], index * 4);
  return output;
};

const xchacha20Poly1305Seal = (key, nonce, plaintext, aad) => {
  const subkey = hchacha20(key, nonce.subarray(0, 16));
  const ietfNonce = concat(Buffer.alloc(4), nonce.subarray(16));
  const cipher = createCipheriv("chacha20-poly1305", subkey, ietfNonce, {
    authTagLength: 16,
  });
  cipher.setAAD(aad, { plaintextLength: plaintext.length });
  const ciphertext = concat(cipher.update(plaintext), cipher.final());
  return concat(ciphertext, cipher.getAuthTag());
};

const chacha20Poly1305Seal = (key, nonce, plaintext, aad) => {
  const cipher = createCipheriv("chacha20-poly1305", key, nonce, {
    authTagLength: 16,
  });
  cipher.setAAD(aad, { plaintextLength: plaintext.length });
  const ciphertext = concat(cipher.update(plaintext), cipher.final());
  return concat(ciphertext, cipher.getAuthTag());
};

/*
 * draft-ietf-hpke-pq-05 test-vectors.json at:
 * 6433c8fce0b8b749dfc86c1095081a88698ccfab
 *
 * Upstream file SHA-256:
 * 35c59f4a0132e5631e50ac039d8ca3a72e99f5e92dfd94d45338d6ae243f613c
 *
 * This is the one KEM=0x647a, KDF=1, AEAD=3 transcript. The KEM output is
 * independent of HPKE mode and application info, so the published
 * encapsulated key and shared secret can ground both local PSK-mode fixtures.
 */
const OFFICIAL_HYBRID_KEM = Object.freeze({
  recipientSecretKey:
    "b6bfa0299b955e85224df2e468f29eeab377ff3b96d4462b39447a22d32b91be",
  encapsulatedKeyBase64:
    "qzVN1Yn3TuDqt3GKYwy+xd8dCQWOF3zW3RQdiDRQ3dcMBQ2IvtPQfM4jQVyrQREI" +
    "zDCQZIKnGtyxNKVul4phUqjgY7JKzRU08mTxBFgVKp7U8fMrPUgMTyRTt/3qdyAU" +
    "az7pLPihOkhAB29oyRHGX6PbUFP7Cqv3nmTNXnqnGyuWQecT7H31UuF9UCD4ch7k" +
    "SbQsiI4qP4fP2W46mMPnxM2PZH+JlXD1lr8X0rb6LK0ZcG2cw88JST4cf/oOsqRV" +
    "muHZQP2++XvtOD5sz9tEjZ8agYBRZrMsKvLhaHjG3EarQzI+2cE2uSUjl4LjwynDG" +
    "lzyqA+vAlqAdm4kRgXCev5LYk2djKmbbvVDntGtBEtRjENDhazUnxNp3tZiSigypX" +
    "HM3XDQizwEyxzTE2Fm+aSF9Tb2nsZvApPoQAJcyqxC+OX3ycuBgHbCcnlwR/XlDB" +
    "6fHauBz7SP5MSZiyQn8AlwKxRfNK2NvD561OQCMFe6Mc0CxMBUXr9x6wJTPo6qKy" +
    "8mkO4UB78fZtxfTYNsRbgvELcg33LSN0iKmvG237R0H9YTN5wuIR539/rms3NK2B" +
    "3i1FIAUzSFfEo8vIKvx0KP5RBJWWmyltJOGnQx9VfUhXjPkq6GwDkvC6c3VanlRl" +
    "yONJXkzSqC1GMkQ0HjlBTibJskLzHSzw5Gsq6xHdXlbsRINDUNFRNEIp5BD6/ysq" +
    "zlybP6ElcdsdKNoscTNJJ4HaxBt6fiusImD9EvVpOQM1h4JMnfsX1Bs7zupTdjGT" +
    "q+DHwYTV3hYe9TEvMfq0JHjJoZO4aOTSmyt2JPPr50Dzk9A9hDzVMnKGpXn9Km43" +
    "rKW2T5MWEV1hLHeB5wTqfRgnAcUBmXXK0U+/SrOQTUo1rK8L4y1xah711xiPxBiu" +
    "nmB0QyWj6AAWVbdW35TCQDHDzjK9kMDs2sUsoUD9rX9E0EvQp+KnJsVM+Xk/h4S" +
    "iMpb2XaP9HLwYMA1QPFsnvpm5sOMtILNhTcipmfMMJ3ndeIbP1IbcHJPrz1F7UhC" +
    "kNZ2foYBTgfDyJh/0feAd5VXZi8GjDdpVeoMAe2Fjarr5BB+WiQ8PVl7vxFhZ+80" +
    "y2RsgMhVUEiek/MPZW+LdsHAoeMqiDy2mLE/5/jOvWRuh7CQfviII4EgPixzKFnn" +
    "Alvj1oCoz6d9EWzJ0rBErQ9UVEBNc0/UyozeekLt/DLQ3F+kFVbsagJJMxpV3RVa" +
    "HzOubFhDAWDlUHoetg9ee8/8krOGTTPvpiWkZWdk6xIxxa2crNw3UwUTKHjJQhwe" +
    "m74qim1V1mz0FTFa+4bqm9BuEufw/1oGhoVKOrFeBQVKYNqKd2hUBpJuiRVNnJW0" +
    "v5vdOu3TvmkmpSkxs0d0JgQ8Om/+mndjJTSJtCyl3sRo1OCiIlhAEpExg/WAun/Q" +
    "nEofpJAupYUZRW5252mA3Wu6v6sHut2T666zRl98ngXw1/kxcgC5DNJ17yVyLQMA" +
    "BRJ0yUcHZL/bVw7CMSyfA==",
  encapsulatedKeySha256:
    "1797094252fe99a0326cf71b3a61448803efc34eef46ebec36d8ceeeb386c614",
  sharedSecret:
    "e059d39125d1f09a7232413a13ec5cb18a37417675442c962700d59da46d105a",
});

const HPKE_VERSION_LABEL = ascii("HPKE-v1");
const HPKE_SUITE_ID = concat(
  ascii("HPKE"),
  u16(0x647a),
  u16(0x0001),
  u16(0x0003),
);

const hpkeLabeledExtract = (salt, label, inputKeyMaterial) =>
  hkdfExtract(
    salt,
    concat(HPKE_VERSION_LABEL, HPKE_SUITE_ID, ascii(label), inputKeyMaterial),
  );

const hpkeLabeledExpand = (pseudorandomKey, label, info, length) =>
  hkdfExpand(
    pseudorandomKey,
    concat(u16(length), HPKE_VERSION_LABEL, HPKE_SUITE_ID, ascii(label), info),
    length,
  );

const hpkePskContext = (sharedSecret, info, psk, pskId) => {
  const pskIdHash = hpkeLabeledExtract(Buffer.alloc(0), "psk_id_hash", pskId);
  const infoHash = hpkeLabeledExtract(Buffer.alloc(0), "info_hash", info);
  const keyScheduleContext = concat(u8(1), pskIdHash, infoHash);
  const secret = hpkeLabeledExtract(sharedSecret, "secret", psk);
  const key = hpkeLabeledExpand(secret, "key", keyScheduleContext, 32);
  const baseNonce = hpkeLabeledExpand(
    secret,
    "base_nonce",
    keyScheduleContext,
    12,
  );
  const exporterSecret = hpkeLabeledExpand(
    secret,
    "exp",
    keyScheduleContext,
    32,
  );
  return {
    key,
    baseNonce,
    exporterSecret,
    exportSecret: (context, length = 32) =>
      hpkeLabeledExpand(exporterSecret, "sec", context, length),
  };
};

const BOOTSTRAP_ENCAPSULATED_KEY = Buffer.from(
  OFFICIAL_HYBRID_KEM.encapsulatedKeyBase64,
  "base64",
);
const BOOTSTRAP_SHARED_SECRET = Buffer.from(
  OFFICIAL_HYBRID_KEM.sharedSecret,
  "hex",
);

if (BOOTSTRAP_ENCAPSULATED_KEY.length !== 1_120)
  throw new Error("pinned hybrid KEM encapsulated key has the wrong length");
if (
  sha256(BOOTSTRAP_ENCAPSULATED_KEY).toString("hex") !==
  OFFICIAL_HYBRID_KEM.encapsulatedKeySha256
)
  throw new Error("pinned hybrid KEM encapsulated key hash disagrees");

const bootstrapHeader = concat(u8(1), u8(1), BOOTSTRAP_ENCAPSULATED_KEY);
const bootstrapHeaderHash = sha256(bootstrapHeader);

const bootstrapInfo = (accept) =>
  concat(
    u8(1),
    u8(1),
    filled(0x10),
    filled(0x11),
    u8(accept ? 1 : 0),
    u64(accept ? 8n : 7n),
    u64(15n),
    filled(accept ? 0x13 : 0x12),
    u64(0n),
    u8(0),
    u8(0),
    u8(accept ? 1 : 0),
    u8(accept ? 1 : 0),
    filled(accept ? 0x80 : 0x30),
  );

const bootstrapPrebinding = (accept) =>
  concat(
    u8(1),
    filled(0x10),
    filled(0x11),
    u64(accept ? 8n : 7n),
    u64(15n),
    u8(2), // PAIR_CAUSAL
    filled(accept ? 0x13 : 0x12),
    u64(0n),
    u8(0),
    u8(2), // PAIR_STEP
    u16(0),
    u8(0),
    bootstrapHeaderHash,
    u8(0),
  );

const bootstrapPlaintext = (accept) => {
  const prefix = accept
    ? concat(
        u8(1),
        u8(1), // IDENTITY_ACCEPT
        filled(0x40),
        u16(2),
        filled(0x20),
        filled(0x30),
        u8(1),
        u64(0n),
        u8(0),
        u16(1),
        filled(0x80),
        u8(1), // body union tag
        u8(1), // body kind
        u8(1),
        filled(0x46),
        filled(0x47),
        filled(0x48, 64),
        filled(0x49),
        u8(0),
        filled(0x4a, 64),
      )
    : concat(
        u8(1),
        u8(0), // IDENTITY_HELLO
        filled(0x40),
        u16(2),
        filled(0x20),
        filled(0x30),
        u8(0),
        u64(0n),
        u8(0),
        u16(0),
        u8(0), // body union tag
        u8(0), // body kind
        u8(1),
        u8(0), // planner
        filled(0x41),
        filled(0x42),
        filled(0x43, 64),
        filled(0x44),
        u8(0),
        filled(0x5b, 1_216),
        filled(0x45, 64),
      );
  const paddingLength = 2_919 - (prefix.length + 4);
  if (paddingLength < 0)
    throw new Error("bootstrap plaintext exceeds the class-0 target");
  return {
    bytes: concat(prefix, u32(paddingLength), Buffer.alloc(paddingLength)),
    paddingLength,
  };
};

const bootstrapPskId = (accept) =>
  sha256(
    concat(
      ascii(
        accept
          ? "p2party/identity-accept-psk-id/v1"
          : "p2party/identity-hello-psk-id/v1",
      ),
      filled(0x11),
      filled(accept ? 0x80 : 0x30),
    ),
  );

const bootstrapFixture = (accept) => {
  const info = bootstrapInfo(accept);
  const psk = filled(accept ? 0x61 : 0x60);
  const pskId = bootstrapPskId(accept);
  const hpke = hpkePskContext(BOOTSTRAP_SHARED_SECRET, info, psk, pskId);
  const prebinding = bootstrapPrebinding(accept);
  const tagExporterContext = concat(
    ascii("p2party/bootstrap-tag/v1"),
    prebinding,
  );
  const routingTag = hpke.exportSecret(tagExporterContext);
  const semanticSlot = sha256(
    concat(ascii("p2party/pair-slot/v1"), routingTag),
  );
  const binding = concat(prebinding, routingTag, semanticSlot);
  const aad = concat(ascii("p2party/pair-aad/v1"), binding);
  const plaintext = bootstrapPlaintext(accept);
  const ciphertextAndTag = chacha20Poly1305Seal(
    hpke.key,
    hpke.baseNonce,
    plaintext.bytes,
    aad,
  );
  const rootExporterContext = concat(
    ascii(
      accept
        ? "p2party/validated-accept-root/v1"
        : "p2party/validated-hello-root/v1",
    ),
    sha256(plaintext.bytes),
  );
  const bootstrapRoot = hpke.exportSecret(rootExporterContext);

  return {
    info: summarize(info),
    infoHex: info.toString("hex"),
    psk: psk.toString("hex"),
    pskId: pskId.toString("hex"),
    bootstrapHeaderHash: bootstrapHeaderHash.toString("hex"),
    prebinding: summarize(prebinding),
    prebindingHex: prebinding.toString("hex"),
    tagExporterContext: summarize(tagExporterContext),
    routingTag: routingTag.toString("hex"),
    semanticSlot: semanticSlot.toString("hex"),
    aad: summarize(aad),
    plaintext: {
      ...summarize(plaintext.bytes),
      paddingLength: plaintext.paddingLength,
    },
    ciphertextAndTag: {
      ...summarize(ciphertextAndTag),
      base64: ciphertextAndTag.toString("base64"),
    },
    rootExporterContext: summarize(rootExporterContext),
    bootstrapRoot: bootstrapRoot.toString("hex"),
    hpke: {
      key: hpke.key.toString("hex"),
      baseNonce: hpke.baseNonce.toString("hex"),
      exporterSecret: hpke.exporterSecret.toString("hex"),
    },
  };
};

const prebinding = concat(
  u8(1),
  filled(0x50),
  filled(0x51),
  u64(20n),
  u64(30n),
  u8(2), // PAIR_CAUSAL
  filled(0x52),
  u64(1n),
  u8(1),
  filled(0x53),
  u8(2), // PAIR_STEP
  u16(0),
  u8(0),
  Buffer.alloc(32),
  u8(1),
  filled(0x54, 24),
);

const pairSlot = concat(u8(9), u8(0), u64(2n));
const baseSecret = filled(0x70);
const flightRoot = hkdfExpand(
  baseSecret,
  concat(ascii("p2party/pair-flight-root/v1"), pairSlot),
  32,
);
const flightSecret = hkdfExpand(
  flightRoot,
  concat(ascii("p2party/pair-flight/v1"), u8(9), prebinding),
  32,
);
const routingTag = hmac(flightSecret, ascii("p2party/pair-flight-tag/v1"));
const semanticSlot = sha256(concat(ascii("p2party/pair-slot/v1"), routingTag));
const binding = concat(prebinding, routingTag, semanticSlot);
const aeadKey = hkdfExpand(
  flightSecret,
  concat(ascii("p2party/pair-flight-key/v1"), binding),
  32,
);
const aad = concat(ascii("p2party/pair-aad/v1"), binding);

const plaintextPrefix = concat(
  u8(1),
  u8(9), // PAIR_CHECKPOINT
  filled(0x40),
  u16(2),
  filled(0x20),
  filled(0x30),
  u8(0),
  u64(2n),
  u8(1),
  filled(0x55),
  u16(1),
  filled(0x56),
  u8(9), // body union tag
  u8(9), // body kind
  u8(1),
  u64(3n),
);
const paddingLength = 4_017 - (plaintextPrefix.length + 4);
const plaintext = concat(
  plaintextPrefix,
  u32(paddingLength),
  Buffer.alloc(paddingLength),
);
const ciphertextAndTag = xchacha20Poly1305Seal(
  aeadKey,
  filled(0x54, 24),
  plaintext,
  aad,
);

const summarize = (value) => ({
  length: value.length,
  sha256: sha256(value).toString("hex"),
  prefixHex: value.subarray(0, 32).toString("hex"),
  suffixHex: value.subarray(-32).toString("hex"),
});

console.log(
  JSON.stringify(
    {
      prebinding: summarize(prebinding),
      flightRoot: flightRoot.toString("hex"),
      flightSecret: flightSecret.toString("hex"),
      routingTag: routingTag.toString("hex"),
      semanticSlot: semanticSlot.toString("hex"),
      aeadKey: aeadKey.toString("hex"),
      aad: summarize(aad),
      plaintext: {
        ...summarize(plaintext),
        paddingLength,
      },
      ciphertextAndTag: summarize(ciphertextAndTag),
      bootstrap: {
        source: {
          specification: "draft-ietf-hpke-pq-05",
          pinnedCommit: "6433c8fce0b8b749dfc86c1095081a88698ccfab",
          upstreamFileSha256:
            "35c59f4a0132e5631e50ac039d8ca3a72e99f5e92dfd94d45338d6ae243f613c",
          recipientSecretKey: OFFICIAL_HYBRID_KEM.recipientSecretKey,
          encapsulatedKeyBase64: OFFICIAL_HYBRID_KEM.encapsulatedKeyBase64,
          encapsulatedKeySha256: OFFICIAL_HYBRID_KEM.encapsulatedKeySha256,
          sharedSecret: OFFICIAL_HYBRID_KEM.sharedSecret,
        },
        hello: bootstrapFixture(false),
        accept: bootstrapFixture(true),
      },
    },
    null,
    2,
  ),
);
