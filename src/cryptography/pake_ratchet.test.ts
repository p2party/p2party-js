import { describe, expect, test, beforeAll } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { hkdfSync } from "node:crypto";

// Bun exposes Web Crypto on globalThis but the emscripten glue probes
// globalThis.window in a couple of spots; alias it (mirrors utils.test.ts).
(globalThis as unknown as { window: typeof globalThis }).window = globalThis;

// eslint-disable-next-line @typescript-eslint/no-var-requires
import libcrypto from "./libcrypto";
import type { LibCrypto } from "./libcrypto";

const hexToBytes = (h: string): Uint8Array =>
  Uint8Array.from(h.match(/.{1,2}/g)!.map((b) => parseInt(b, 16)));
const bytesToHex = (u: Uint8Array): string =>
  [...u].map((b) => b.toString(16).padStart(2, "0")).join("");

// 32 pages == 2 MB == INITIAL_MEMORY; growth is off so initial === maximum.
const PAGES = 32;

let mod: LibCrypto;
let mem: WebAssembly.Memory;

const put = (bytes: Uint8Array): number => {
  const ptr = mod._malloc(bytes.length);
  new Uint8Array(mem.buffer, ptr, bytes.length).set(bytes);
  return ptr;
};
const view = (ptr: number, len: number): Uint8Array =>
  new Uint8Array(mem.buffer, ptr, len).slice();

beforeAll(async () => {
  mem = new WebAssembly.Memory({ initial: PAGES, maximum: PAGES });
  // The emscripten factory's wasmBinary is typed ArrayBuffer; readFileSync
  // returns a Buffer, so copy the bytes into a fresh ArrayBuffer (type-correct
  // for `tsc`, and WebAssembly.instantiate accepts an ArrayBuffer at runtime).
  const fileBytes = readFileSync(join(import.meta.dir, "libcrypto.wasm"));
  const wasmBinary = new ArrayBuffer(fileBytes.byteLength);
  new Uint8Array(wasmBinary).set(fileBytes);
  mod = (await libcrypto({
    wasmBinary,
    wasmMemory: mem,
  })) as unknown as LibCrypto;
});

describe("Ristretto255 (CPace primitives)", () => {
  // libsodium test/default/core_ristretto255.{c,exp}: from_hash KAT[0].
  test("from_hash known-answer", () => {
    const h = hexToBytes(
      "5d1be09e3d0c82fc538112490e35701979d99e06ca3e2b5b54bffe8b4dc772c1" +
        "4d98b696a1bbfb5ca32c436cc61c16563790306c79eaca7705668b47dffe5bb6",
    );
    const hp = put(h);
    const op = mod._malloc(32);
    mod._cpace_ristretto255_from_hash(op, hp);
    expect(bytesToHex(view(op, 32))).toBe(
      "3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46",
    );
    mod._free(hp);
    mod._free(op);
  });

  // libsodium test/default/scalarmult_ristretto255.{c,exp}: 2*B.
  test("scalarmult known-answer (2*B)", () => {
    const B = hexToBytes(
      "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
    );
    const scalar = new Uint8Array(32);
    scalar[0] = 2; // little-endian 2
    const bp = put(B);
    const sp = put(scalar);
    const op = mod._malloc(32);
    expect(mod._cpace_ristretto255_scalarmult(op, sp, bp)).toBe(0);
    expect(bytesToHex(view(op, 32))).toBe(
      "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919",
    );
    mod._free(bp);
    mod._free(sp);
    mod._free(op);
  });

  // scalar_random + from_hash + scalarmult exercised via CPace correctness:
  // K1 = y1*(y2*G) == K2 = y2*(y1*G).
  test("CPace exchange agrees (Y = y*G, K = y*Y_peer)", () => {
    const hp = put(new Uint8Array(64).fill(7)); // any 64-byte hash → G
    const gp = mod._malloc(32);
    mod._cpace_ristretto255_from_hash(gp, hp);

    const y1 = mod._malloc(32);
    const y2 = mod._malloc(32);
    mod._cpace_ristretto255_scalar_random(y1);
    mod._cpace_ristretto255_scalar_random(y2);

    const Y1 = mod._malloc(32);
    const Y2 = mod._malloc(32);
    expect(mod._cpace_ristretto255_scalarmult(Y1, y1, gp)).toBe(0);
    expect(mod._cpace_ristretto255_scalarmult(Y2, y2, gp)).toBe(0);

    const K1 = mod._malloc(32);
    const K2 = mod._malloc(32);
    expect(mod._cpace_ristretto255_scalarmult(K1, y1, Y2)).toBe(0);
    expect(mod._cpace_ristretto255_scalarmult(K2, y2, Y1)).toBe(0);

    const k1 = bytesToHex(view(K1, 32));
    const k2 = bytesToHex(view(K2, 32));
    expect(k1).toBe(k2);
    expect(k1).not.toBe("00".repeat(32));
    [hp, gp, y1, y2, Y1, Y2, K1, K2].forEach((p) => mod._free(p));
  });
});

describe("X25519 DH ratchet primitives", () => {
  // RFC 7748 §5.2 single-iteration vector.
  test("x25519_dh known-answer", () => {
    const sk = hexToBytes(
      "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
    );
    const pk = hexToBytes(
      "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
    );
    const skp = put(sk);
    const pkp = put(pk);
    const op = mod._malloc(32);
    expect(mod._x25519_dh(op, skp, pkp)).toBe(0);
    expect(bytesToHex(view(op, 32))).toBe(
      "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
    );
    [skp, pkp, op].forEach((p) => mod._free(p));
  });

  test("keypair + dh agree (DH(a,B) == DH(b,A))", () => {
    const pkA = mod._malloc(32);
    const skA = mod._malloc(32);
    const pkB = mod._malloc(32);
    const skB = mod._malloc(32);
    expect(mod._x25519_keypair(pkA, skA)).toBe(0);
    expect(mod._x25519_keypair(pkB, skB)).toBe(0);
    const s1 = mod._malloc(32);
    const s2 = mod._malloc(32);
    expect(mod._x25519_dh(s1, skA, pkB)).toBe(0);
    expect(mod._x25519_dh(s2, skB, pkA)).toBe(0);
    expect(bytesToHex(view(s1, 32))).toBe(bytesToHex(view(s2, 32)));
    expect(bytesToHex(view(pkA, 32))).not.toBe(bytesToHex(view(pkB, 32)));
    [pkA, skA, pkB, skB, s1, s2].forEach((p) => mod._free(p));
  });
});

describe("HKDF-SHA512", () => {
  test("extract+expand matches node crypto.hkdfSync('sha512')", () => {
    const ikm = hexToBytes("0b".repeat(22));
    const salt = hexToBytes("000102030405060708090a0b0c");
    const info = hexToBytes("f0f1f2f3f4f5f6f7f8f9");
    const L = 137;

    const ikmp = put(ikm);
    const saltp = put(salt);
    const infop = put(info);
    const prkp = mod._malloc(64);
    expect(
      mod._hkdf_sha512_extract(prkp, saltp, salt.length, ikmp, ikm.length),
    ).toBe(0);

    const outp = mod._malloc(L);
    expect(mod._hkdf_sha512_expand(outp, L, prkp, infop, info.length)).toBe(0);

    const got = bytesToHex(view(outp, L));
    const ref = bytesToHex(
      new Uint8Array(hkdfSync("sha512", ikm, salt, info, L)),
    );
    expect(got).toBe(ref);
    [ikmp, saltp, infop, prkp, outp].forEach((p) => mod._free(p));
  });
});

describe("Symmetric AEAD (message-key path)", () => {
  // RFC 8439 §2.8.2 AEAD_CHACHA20_POLY1305 test vector (value cross-checked
  // with node createCipheriv; Bun lacks that cipher so the answer is pinned).
  test("encrypt_chachapoly_symmetric known-answer (ciphertext||tag)", () => {
    const key = hexToBytes(
      "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    );
    const nonce = hexToBytes("070000004041424344454647");
    const aad = hexToBytes("50515253c0c1c2c3c4c5c6c7");
    const pt = hexToBytes(
      "4c616469657320616e642047656e746c656d656e206f662074686520636c6173" +
        "73206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
        "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" +
        "637265656e20776f756c642062652069742e",
    );
    const expected =
      "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6" +
      "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36" +
      "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc" +
      "3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd060" +
      "0691";
    const ptp = put(pt);
    const keyp = put(key);
    const noncep = put(nonce);
    const aadp = put(aad);
    const outp = mod._malloc(pt.length + 16);
    expect(
      mod._encrypt_chachapoly_symmetric(
        outp,
        ptp,
        pt.length,
        keyp,
        noncep,
        aadp,
        aad.length,
      ),
    ).toBe(0);
    expect(bytesToHex(view(outp, pt.length + 16))).toBe(expected);
    [ptp, keyp, noncep, aadp, outp].forEach((p) => mod._free(p));
  });
});

describe("receive_message_with_key (smoke: exported, links, callable)", () => {
  const MESSAGE_LEN = 64 * 1024;
  test("garbage frame returns a negative error (AEAD auth fails)", () => {
    const msgp = mod._malloc(MESSAGE_LEN);
    new Uint8Array(mem.buffer, msgp, MESSAGE_LEN).fill(0);
    const decp = mod._malloc(MESSAGE_LEN); // upper bound on DECRYPTED_LEN
    const rootp = put(new Uint8Array(64).fill(0));
    const keyp = put(new Uint8Array(32).fill(0));
    const r = mod._receive_message_with_key(decp, msgp, rootp, keyp);
    expect(r).toBeLessThan(0);
    [msgp, decp, rootp, keyp].forEach((p) => mod._free(p));
  });
});
