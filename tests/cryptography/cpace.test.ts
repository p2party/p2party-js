import { describe, expect, test } from "bun:test";

import { loadTestModule } from "../../src/cryptography/testModule";
import {
  cpaceFinish,
  cpaceStart,
  deriveGenerator,
  encodeCpaceLength,
} from "../../src/cryptography/cpace";

const enc = new TextEncoder();
const hex = (value: string): Uint8Array =>
  Uint8Array.from(Buffer.from(value.replace(/\s/g, ""), "hex"));
const rand = (n: number): Uint8Array => {
  const value = new Uint8Array(n);
  crypto.getRandomValues(value);
  return value;
};

const OFFICIAL = {
  pin: enc.encode("Password"),
  ci: hex("0b415f696e69746961746f720b425f726573706f6e646572"),
  sid: hex("7e4b4791d6a8ef019b936c79fb7f2c57"),
  generator: hex(
    "222b6b195fe84b1652badb6f6a3ae3d24341e7306967f0b8115b40d5698c7e56",
  ),
  ya: hex(
    "da3d23700a9e5699258aef94dc060dfda5ebb61f02a5ea77fad53f4ff0976d08",
  ),
  Ya: hex(
    "d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0eec482b9157",
  ),
  yb: hex(
    "d2316b454718c35362d83d69df6320f38578ed5984651435e2949762d900b80d",
  ),
  Yb: hex(
    "3ea7e0b19560d7c0b0f5734f63b955286dfa8232b5ebe63324e2d9e7433f7258",
  ),
  isk: hex(
    "b69effbf61b51d56401c0f65601abe428de8206feaaf0e32198896dcae7b35cd" +
      "2b38950a39dfd5d4a79164614c2984f7daa460b588c1e80c3fa2068af7900447",
  ),
};

describe("CPACE-RISTR255-SHA512 draft-21", () => {
  test("uses unsigned LEB128 prepend_len", () => {
    expect(Buffer.from(encodeCpaceLength(0)).toString("hex")).toBe("00");
    expect(Buffer.from(encodeCpaceLength(127)).toString("hex")).toBe("7f");
    expect(Buffer.from(encodeCpaceLength(128)).toString("hex")).toBe("8001");
  });

  test("matches the official Ristretto255 generator vector", async () => {
    const module = await loadTestModule();
    const generator = deriveGenerator(
      OFFICIAL.pin,
      OFFICIAL.sid,
      OFFICIAL.ci,
      module,
    );
    expect(Buffer.from(generator)).toEqual(Buffer.from(OFFICIAL.generator));
  });

  test("matches the official initiator/responder ISK vector without exposing K", async () => {
    const module = await loadTestModule();
    const ADa = enc.encode("ADa");
    const ADb = enc.encode("ADb");
    const common = {
      sid: OFFICIAL.sid,
      initiatorShare: OFFICIAL.Ya,
      responderShare: OFFICIAL.Yb,
      initiatorAssociatedData: ADa,
      responderAssociatedData: ADb,
    };

    const initiatorIsk = cpaceFinish(
      { ...common, y: OFFICIAL.ya, peerShare: OFFICIAL.Yb },
      module,
    );
    const responderIsk = cpaceFinish(
      { ...common, y: OFFICIAL.yb, peerShare: OFFICIAL.Ya },
      module,
    );

    expect(Buffer.from(initiatorIsk)).toEqual(Buffer.from(OFFICIAL.isk));
    expect(Buffer.from(responderIsk)).toEqual(Buffer.from(OFFICIAL.isk));
  });

  test("two honest parties with the same PIN reach the same ISK", async () => {
    const module = await loadTestModule();
    const pin = enc.encode("123456");
    const sid = rand(16);
    const ci = rand(64);
    const generator = deriveGenerator(pin, sid, ci, module);
    const a = cpaceStart(generator, module);
    const b = cpaceStart(generator, module);
    const transcript = {
      sid,
      initiatorShare: a.Y,
      responderShare: b.Y,
    };

    const aIsk = cpaceFinish(
      { ...transcript, y: a.y, peerShare: b.Y },
      module,
    );
    const bIsk = cpaceFinish(
      { ...transcript, y: b.y, peerShare: a.Y },
      module,
    );
    expect(Buffer.from(aIsk)).toEqual(Buffer.from(bIsk));
    expect(aIsk).toHaveLength(64);
  });

  test("a wrong PIN yields a different generator and mismatched ISK", async () => {
    const module = await loadTestModule();
    const sid = rand(16);
    const ci = rand(64);
    const generatorA = deriveGenerator(enc.encode("123456"), sid, ci, module);
    const generatorB = deriveGenerator(enc.encode("000000"), sid, ci, module);
    const a = cpaceStart(generatorA, module);
    const b = cpaceStart(generatorB, module);
    const transcript = {
      sid,
      initiatorShare: a.Y,
      responderShare: b.Y,
    };

    const aIsk = cpaceFinish(
      { ...transcript, y: a.y, peerShare: b.Y },
      module,
    );
    const bIsk = cpaceFinish(
      { ...transcript, y: b.y, peerShare: a.Y },
      module,
    );
    expect(Buffer.from(generatorA)).not.toEqual(Buffer.from(generatorB));
    expect(Buffer.from(aIsk)).not.toEqual(Buffer.from(bIsk));
  });

  test("aborts on invalid or identity peer encodings", async () => {
    const module = await loadTestModule();
    const common = {
      y: OFFICIAL.ya,
      sid: OFFICIAL.sid,
      initiatorShare: OFFICIAL.Ya,
      responderShare: OFFICIAL.Yb,
    };

    expect(() =>
      cpaceFinish(
        { ...common, peerShare: new Uint8Array(32) },
        module,
      ),
    ).toThrow("invalid or the identity");
    expect(() =>
      cpaceFinish(
        { ...common, peerShare: new Uint8Array(32).fill(0xff) },
        module,
      ),
    ).toThrow("invalid or the identity");
  });
});
