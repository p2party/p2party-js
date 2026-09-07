/**
 * Pure transport-candidate helpers for the flagged two-store prototype.
 *
 * Section 4.12 keeps SDP inside the pair-encrypted, class-padded payload and
 * puts one strict parser in charge of bounds and RFC 8122 syntax: 1 through
 * 32,768 exact UTF-8 bytes with exactly one SHA-256 DTLS fingerprint, and no
 * semantic parse/reserialize "canonicalization" of the bytes. An offer holds
 * one to three candidates sorted by unique `TransportOfferCandidateId`, with
 * exactly one mandatory `operation-carrier`, at most one `webrtc-complete`,
 * and at most one `registered-local-link`.
 *
 * Nothing here touches a browser API, a peer connection, or an adapter
 * registry: the prototype offers only the mandatory carrier plus WebRTC, and
 * `registered-local-link` is deferred (Section 4.12 permits an offer without
 * one). Every check runs before any candidate reaches a transport.
 *
 * Status: PROTOTYPE. Nothing here is a v0.4 release byte.
 */

import { transportOfferCandidateId } from "../derivations";
import {
  MAX_PAIR_TRANSPORT_CANDIDATES_V1,
  MAX_PAIR_WEBRTC_SDP_BYTES_V1,
} from "../schemas";
import { parseFingerprintFromSdp } from "../../utils/sdpFingerprint";

import type { PairTransportCandidateV1 } from "../pairPlaintext";

export class TransportCandidateError extends Error {
  override readonly name = "TransportCandidateError";

  constructor(message: string) {
    super(`transportCandidates: ${message}`);
  }
}

const fail = (message: string): never => {
  throw new TransportCandidateError(message);
};

/*
 * `ignoreBOM` keeps the decoder from silently dropping a leading U+FEFF: the
 * SDP bytes are the conformance binding, so the parser must see every byte the
 * peer signed.
 */
const sdpDecoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

const FINGERPRINT_LINE = /a=fingerprint:sha-256\s+[0-9A-Fa-f:]+/g;

/**
 * Bytewise ordering shared by candidate sorting and the pair driver.
 *
 * @internal
 */
export const compareBytes = (left: Uint8Array, right: Uint8Array): number => {
  const shared = Math.min(left.length, right.length);
  for (let index = 0; index < shared; index += 1) {
    if (left[index] !== right[index])
      return left[index] < right[index] ? -1 : 1;
  }
  if (left.length === right.length) return 0;
  return left.length < right.length ? -1 : 1;
};

/** Decode exact SDP bytes without altering them. Invalid UTF-8 fails closed. */
export const decodeSdpUtf8 = (sdp: Uint8Array): string => {
  try {
    return sdpDecoder.decode(sdp);
  } catch {
    return fail("WebRTC SDP is not well-formed UTF-8");
  }
};

/**
 * The one strict parser: bounds, UTF-8, and exactly one SHA-256 fingerprint.
 *
 * Zero, multiple, or non-SHA-256 fingerprints fail here, before any handoff.
 */
export const validateWebRtcSdp = (
  sdp: Uint8Array,
): { readonly fingerprint: Uint8Array } => {
  if (!(sdp instanceof Uint8Array)) return fail("WebRTC SDP must be bytes");
  if (sdp.length === 0) return fail("WebRTC SDP must not be empty");
  if (sdp.length > MAX_PAIR_WEBRTC_SDP_BYTES_V1)
    return fail(
      `WebRTC SDP exceeds ${MAX_PAIR_WEBRTC_SDP_BYTES_V1} exact UTF-8 bytes`,
    );
  const text = decodeSdpUtf8(sdp);
  const matches = text.match(FINGERPRINT_LINE);
  if (matches === null || matches.length !== 1)
    return fail("WebRTC SDP must declare exactly one sha-256 DTLS fingerprint");
  try {
    return { fingerprint: parseFingerprintFromSdp(text) };
  } catch {
    return fail("WebRTC SDP declares a malformed sha-256 DTLS fingerprint");
  }
};

const identifiedCandidates = async (
  candidates: readonly PairTransportCandidateV1[],
): Promise<
  readonly {
    readonly candidate: PairTransportCandidateV1;
    readonly id: Uint8Array;
  }[]
> => {
  const identified: {
    readonly candidate: PairTransportCandidateV1;
    readonly id: Uint8Array;
  }[] = [];
  for (const candidate of candidates) {
    let id: Uint8Array;
    try {
      id = await transportOfferCandidateId(candidate);
    } catch {
      return fail("offer holds a noncanonical transport candidate");
    }
    identified.push({ candidate, id });
  }
  return identified;
};

/**
 * The prototype's complete offer set: the mandatory operation carrier plus the
 * WebRTC candidate, sorted by `TransportOfferCandidateId`.
 */
export const buildOfferCandidates = async (
  sdp: Uint8Array,
): Promise<readonly PairTransportCandidateV1[]> => {
  validateWebRtcSdp(sdp);
  const identified = await identifiedCandidates([
    { version: 1, kind: "operation-carrier" },
    { version: 1, kind: "webrtc-complete", exactSdpUtf8: Uint8Array.from(sdp) },
  ]);
  return [...identified]
    .sort((left, right) => compareBytes(left.id, right.id))
    .map((member) => member.candidate);
};

/**
 * Validate a received offer's composition and return the WebRTC candidate.
 *
 * Selection happens by exact candidate ID, so the caller can echo that ID in
 * its answer. Unknown kinds, a missing or duplicated ID, an out-of-order set,
 * or a noncanonical candidate fails before any adapter sees the bytes.
 */
export const selectWebRtcCandidate = async (
  candidates: readonly PairTransportCandidateV1[],
): Promise<{ readonly id: Uint8Array; readonly sdp: Uint8Array }> => {
  if (!Array.isArray(candidates))
    return fail("transport offer candidates must be an array");
  if (
    candidates.length < 1 ||
    candidates.length > MAX_PAIR_TRANSPORT_CANDIDATES_V1
  )
    return fail(
      `transport offer must hold 1..${MAX_PAIR_TRANSPORT_CANDIDATES_V1} candidates`,
    );

  const identified = await identifiedCandidates(candidates);
  for (let index = 1; index < identified.length; index += 1) {
    if (compareBytes(identified[index - 1].id, identified[index].id) >= 0)
      return fail("transport offer candidates are not sorted by unique id");
  }

  const countOf = (kind: PairTransportCandidateV1["kind"]): number =>
    candidates.filter((candidate) => candidate.kind === kind).length;
  if (countOf("operation-carrier") !== 1)
    return fail("transport offer must hold exactly one operation carrier");
  if (countOf("webrtc-complete") > 1)
    return fail("transport offer must hold at most one webrtc candidate");
  if (countOf("registered-local-link") > 1)
    return fail("transport offer must hold at most one local-link candidate");

  const webrtc = identified.find(
    (member) => member.candidate.kind === "webrtc-complete",
  );
  if (webrtc === undefined || webrtc.candidate.kind !== "webrtc-complete")
    return fail("transport offer advertises no webrtc candidate");
  const sdp = Uint8Array.from(webrtc.candidate.exactSdpUtf8);
  validateWebRtcSdp(sdp);
  return { id: webrtc.id, sdp };
};
