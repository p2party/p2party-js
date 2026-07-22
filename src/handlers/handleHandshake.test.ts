import { describe, expect, test } from "bun:test";

import {
  buildChannelInput,
  parseFingerprintFromSdp,
  verifyDtlsFingerprints,
} from "./handleHandshake";
import { PQ_TAG } from "../utils/constants";
import type { IRTCPeerConnection } from "../api/webrtc/interfaces";

const CHANNEL_ID = new TextEncoder().encode("main"); // 4 bytes

describe("buildChannelInput (CI)", () => {
  test("concatenates channelId ‖ IK_a ‖ IK_b ‖ fp_a ‖ fp_b ‖ PQ_TAG", () => {
    const ikA = new Uint8Array(32).fill(1);
    const ikB = new Uint8Array(32).fill(2);
    const fpA = new Uint8Array(32).fill(3);
    const fpB = new Uint8Array(32).fill(4);
    const ci = buildChannelInput({
      channelId: CHANNEL_ID,
      ikInitiator: ikA,
      ikResponder: ikB,
      fpInitiator: fpA,
      fpResponder: fpB,
    });
    expect(ci.length).toBe(4 + 32 + 32 + 32 + 32 + PQ_TAG.length);
    expect([...ci.subarray(0, 4)]).toEqual([...CHANNEL_ID]);
    expect(ci[4]).toBe(1);
    expect(ci[4 + 32]).toBe(2);
    expect(ci[4 + 64]).toBe(3);
    expect(ci[4 + 96]).toBe(4);
    expect(ci[ci.length - 1]).toBe(0); // PQ_TAG
  });

  test("role ordering matters: swapping a/b yields a different CI", () => {
    const one = buildChannelInput({
      channelId: CHANNEL_ID,
      ikInitiator: new Uint8Array(32).fill(1),
      ikResponder: new Uint8Array(32).fill(2),
      fpInitiator: new Uint8Array(32).fill(3),
      fpResponder: new Uint8Array(32).fill(4),
    });
    const swapped = buildChannelInput({
      channelId: CHANNEL_ID,
      ikInitiator: new Uint8Array(32).fill(2),
      ikResponder: new Uint8Array(32).fill(1),
      fpInitiator: new Uint8Array(32).fill(4),
      fpResponder: new Uint8Array(32).fill(3),
    });
    expect([...one]).not.toEqual([...swapped]);
  });
});

describe("parseFingerprintFromSdp", () => {
  const sdp =
    "v=0\r\n" +
    "a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:" +
    "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n" +
    "a=setup:actpass\r\n";

  test("extracts the 32 raw bytes of a sha-256 fingerprint", () => {
    const fp = parseFingerprintFromSdp(sdp);
    expect(fp.length).toBe(32);
    expect(fp[0]).toBe(0xaa);
    expect(fp[1]).toBe(0xbb);
    expect(fp[31]).toBe(0x99);
  });

  test("throws when no sha-256 fingerprint is present", () => {
    expect(() => parseFingerprintFromSdp("v=0\r\n")).toThrow();
  });
});

describe("verifyDtlsFingerprints", () => {
  const fpHex = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:" +
    "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99";
  const sdpWith = (fp: string) => `v=0\r\na=fingerprint:sha-256 ${fp}\r\n`;

  const mockEpc = (localFp: string, remoteFp: string, statsFp: string) =>
    ({
      localDescription: { sdp: sdpWith(localFp) },
      remoteDescription: { sdp: sdpWith(remoteFp) },
      getStats: async () =>
        new Map<string, any>([
          ["T", { type: "transport", localCertificateId: "LC", remoteCertificateId: "RC" }],
          ["LC", { type: "certificate", fingerprint: localFp, fingerprintAlgorithm: "sha-256" }],
          ["RC", { type: "certificate", fingerprint: statsFp, fingerprintAlgorithm: "sha-256" }],
        ]),
    }) as unknown as IRTCPeerConnection;

  test("resolves when the live cert fp matches the SDP-bound fp", async () => {
    await verifyDtlsFingerprints(mockEpc(fpHex, fpHex, fpHex));
  });

  test("throws when getStats reports a different remote fingerprint (MITM)", async () => {
    const tampered = fpHex.replace(/^AA/, "BB");
    await expect(
      verifyDtlsFingerprints(mockEpc(fpHex, fpHex, tampered)),
    ).rejects.toThrow(/fingerprint/i);
  });

  test("throws (fails closed) when the remote certificate stat is missing/unverifiable", async () => {
    // Transport reports a remoteCertificateId, but no matching "certificate"
    // stat exists in the report (e.g. an attacker-influenced or truncated
    // stats report) — SDPs both parse fine. The live remote fingerprint can
    // never be confirmed, so the tripwire must abort rather than resolve.
    const epc = {
      localDescription: { sdp: sdpWith(fpHex) },
      remoteDescription: { sdp: sdpWith(fpHex) },
      getStats: async () =>
        new Map<string, any>([
          [
            "T",
            {
              type: "transport",
              localCertificateId: "LC",
              remoteCertificateId: "RC",
            },
          ],
          [
            "LC",
            {
              type: "certificate",
              fingerprint: fpHex,
              fingerprintAlgorithm: "sha-256",
            },
          ],
          // Note: no "RC" certificate entry — the remote cert stat is absent.
        ]),
    } as unknown as IRTCPeerConnection;

    await expect(verifyDtlsFingerprints(epc)).rejects.toThrow(
      /fingerprint|MITM/i,
    );
  });
});
