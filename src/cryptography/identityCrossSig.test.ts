import { describe, expect, test } from "bun:test";

import { loadTestModule } from "./testModule";
import { newX25519KeyPair } from "./x25519";
import { newKeyPair, sign } from "./ed25519";
import {
  identityCrossSignMessage,
  crossSignIdentityX25519,
  verifyIdentityCrossSig,
} from "./identityCrossSig";
import { IDENTITY_CROSS_SIGN_DOMAIN_BYTES } from "../utils/constants";

describe("identity X25519 cross-signature (domain-separated, SECURITY-1)", () => {
  test("cross-sign then verify passes for a genuine binding", async () => {
    const module = await loadTestModule();
    const ed = await newKeyPair(module);
    const x = await newX25519KeyPair(module);

    const crossSig = await crossSignIdentityX25519(
      x.publicKey,
      ed.secretKey,
      module,
    );
    expect(
      await verifyIdentityCrossSig(x.publicKey, crossSig, ed.publicKey, module),
    ).toBe(true);
  });

  test("verify fails for a different X25519 pub or a different Ed25519 identity", async () => {
    const module = await loadTestModule();
    const ed = await newKeyPair(module);
    const edOther = await newKeyPair(module);
    const x = await newX25519KeyPair(module);
    const xOther = await newX25519KeyPair(module);

    const crossSig = await crossSignIdentityX25519(
      x.publicKey,
      ed.secretKey,
      module,
    );
    expect(
      await verifyIdentityCrossSig(
        xOther.publicKey,
        crossSig,
        ed.publicKey,
        module,
      ),
    ).toBe(false);
    expect(
      await verifyIdentityCrossSig(
        x.publicKey,
        crossSig,
        edOther.publicKey,
        module,
      ),
    ).toBe(false);
  });

  test("SECURITY-1 regression: an oracle-harvested BARE signature (no domain prefix) fails cross-sig verify", async () => {
    const module = await loadTestModule();
    const ed = await newKeyPair(module);
    const x = await newX25519KeyPair(module);

    // Model the login-challenge oracle: a malicious server sends the chosen X25519
    // pub AS the 32-byte challenge and the victim signs it with the Ed25519 identity
    // secret — a BARE sign over the pub, with no IDENTITY_CROSS_SIGN_DOMAIN prefix.
    const oracleSig = await sign(x.publicKey, ed.secretKey, module);

    // It must NOT pass as a cross-signature — the verifier requires the domain prefix.
    expect(
      await verifyIdentityCrossSig(x.publicKey, oracleSig, ed.publicKey, module),
    ).toBe(false);

    // The real cross-sig covers a domain-prefixed transcript, not the bare pub.
    const msg = identityCrossSignMessage(x.publicKey);
    expect(msg.length).toBe(
      IDENTITY_CROSS_SIGN_DOMAIN_BYTES.length + x.publicKey.length,
    );
    expect([...msg.subarray(0, IDENTITY_CROSS_SIGN_DOMAIN_BYTES.length)]).toEqual(
      [...IDENTITY_CROSS_SIGN_DOMAIN_BYTES],
    );
  });
});
