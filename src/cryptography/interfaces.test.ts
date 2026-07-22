import { describe, expect, test } from "bun:test";
import {
  crypto_core_ristretto255_BYTES,
  crypto_core_ristretto255_HASHBYTES,
  crypto_core_ristretto255_SCALARBYTES,
  crypto_scalarmult_ristretto255_BYTES,
  crypto_scalarmult_curve25519_BYTES,
  crypto_scalarmult_curve25519_SCALARBYTES,
  crypto_auth_hmacsha512_BYTES,
  crypto_auth_hmacsha512_KEYBYTES,
} from "./interfaces";

describe("v3 crypto primitive byte sizes", () => {
  test("ristretto255 sizes", () => {
    expect(crypto_core_ristretto255_BYTES).toBe(32);
    expect(crypto_core_ristretto255_HASHBYTES).toBe(64);
    expect(crypto_core_ristretto255_SCALARBYTES).toBe(32);
    expect(crypto_scalarmult_ristretto255_BYTES).toBe(32);
  });
  test("x25519 sizes", () => {
    expect(crypto_scalarmult_curve25519_BYTES).toBe(32);
    expect(crypto_scalarmult_curve25519_SCALARBYTES).toBe(32);
  });
  test("hkdf/hmac sizes (PRK = 64, key = 32)", () => {
    expect(crypto_auth_hmacsha512_BYTES).toBe(64);
    expect(crypto_auth_hmacsha512_KEYBYTES).toBe(32);
  });
});
