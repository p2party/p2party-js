import { describe, expect, test } from "bun:test";

import { loadTestModule } from "./testModule";
import { x25519Keypair } from "./x25519";
import { x3dhDeriveSecret } from "./x3dh";

describe("x3dh", () => {
  test("initiator and responder derive the same 32-byte secret", async () => {
    const module = await loadTestModule();

    const IKa = x25519Keypair(module);
    const IKb = x25519Keypair(module);
    const EKa = x25519Keypair(module);
    const EKb = x25519Keypair(module);

    const sa = x3dhDeriveSecret(
      IKa.secretKey,
      IKb.publicKey,
      EKa.secretKey,
      EKb.publicKey,
      true,
      module,
    );
    const sb = x3dhDeriveSecret(
      IKb.secretKey,
      IKa.publicKey,
      EKb.secretKey,
      EKa.publicKey,
      false,
      module,
    );

    expect(sa.length).toBe(32);
    expect(Buffer.from(sa)).toEqual(Buffer.from(sb));
  });

  test("a substituted peer identity breaks agreement", async () => {
    const module = await loadTestModule();
    const IKa = x25519Keypair(module);
    const IKb = x25519Keypair(module);
    const IKevil = x25519Keypair(module);
    const EKa = x25519Keypair(module);
    const EKb = x25519Keypair(module);

    const sa = x3dhDeriveSecret(IKa.secretKey, IKevil.publicKey, EKa.secretKey, EKb.publicKey, true, module);
    const sb = x3dhDeriveSecret(IKb.secretKey, IKa.publicKey, EKb.secretKey, EKa.publicKey, false, module);
    expect(Buffer.from(sa)).not.toEqual(Buffer.from(sb));
  });

  test("a substituted initiator identity breaks agreement", async () => {
    const module = await loadTestModule();
    const IKa = x25519Keypair(module);
    const IKb = x25519Keypair(module);
    const IKevil = x25519Keypair(module);
    const EKa = x25519Keypair(module);
    const EKb = x25519Keypair(module);

    const sa = x3dhDeriveSecret(IKevil.secretKey, IKb.publicKey, EKa.secretKey, EKb.publicKey, true, module);
    const sb = x3dhDeriveSecret(IKb.secretKey, IKa.publicKey, EKb.secretKey, EKa.publicKey, false, module);
    expect(Buffer.from(sa)).not.toEqual(Buffer.from(sb));
  });
});
