/**
 * Real WebRTC transport for the flagged two-store rendezvous prototype.
 *
 * This is the piece that turns the pair driver's abstract offer/answer exchange
 * (`TransportCandidateProvider`, `pairDriver.ts`) into an actual
 * `RTCPeerConnection` carrying one bootstrap `RTCDataChannel`, and then hands
 * that channel to the store-free protocol-v4 session API as a
 * `HandshakeTransport`.
 *
 * BROWSER ONLY. Nothing here may import the Redux store, `src/api/**`,
 * `src/reducers/**` or anything under `prototype/store/`: the prototype's
 * browser bundle is built from this module and must stay free of the app's
 * state machinery. `verifyCertificates` therefore *copies* the certificate
 * comparison of `src/handlers/handleHandshake.ts` (`verifyDtlsFingerprints`)
 * rather than importing it — that function reaches the store through its
 * `IRTCPeerConnection` wrappers. Its one runtime import is
 * `src/utils/constants.ts`, which imports only `cryptography/interfaces`; the
 * rest are types, which `verbatimModuleSyntax` erases at build time.
 *
 * Three properties of this file are load-bearing, and each one has cost a
 * debugging session before:
 *
 *   1. THE INITIATOR CREATES ITS DATA CHANNEL BEFORE THE OFFER. An SDP offer
 *      produced by a peer connection with no data channel negotiates no SCTP
 *      transport at all, so no channel can ever open afterwards — the peers
 *      connect at ICE/DTLS level and then sit there forever. The channel is
 *      therefore created in the constructor, before `createOffer()` can be
 *      called (see `docs/e2e/README.md`).
 *   2. COMPLETE GATHERING, NEVER TRICKLE. The blind profile carries one SDP
 *      blob inside a pair-encrypted, class-padded operation; there is no
 *      channel to trickle candidates over afterwards. Both `createOffer` and
 *      `acceptOffer` therefore wait for `iceGatheringState === "complete"`
 *      before reading the local description.
 *   3. EXACT BYTES. The SDP bytes returned here are what the peer signs over
 *      inside the pair transcript, and the DTLS fingerprint parsed out of them
 *      is bound into the protocol-v4 channel input. They are the UTF-8 encoding
 *      of `localDescription.sdp` verbatim — never re-serialized, never
 *      normalized — and remote SDP is decoded with a fatal UTF-8 decoder and
 *      handed to `setRemoteDescription` as-is.
 *
 * Status: PROTOTYPE. Nothing here is a v0.4 release byte.
 */

import {
  SEND_BUFFER_LOW_THRESHOLD,
  MAX_BUFFERED_AMOUNT,
  PROTOTYPE_APP_LANE_HIGH_WATER_BYTES,
  PROTOTYPE_APP_LANE_MAX_FRAMES,
  PROTOTYPE_CONTROL_LANE_HIGH_WATER_BYTES,
  PROTOTYPE_CONTROL_LANE_MAX_FRAMES,
} from "../../utils/constants";

import type { TransportCandidateProvider } from "./pairDriver";
import type { HandshakeTransport } from "../../session";

/** Label of the bootstrap channel that must exist before the first offer. */
const BOOTSTRAP_CHANNEL_LABEL = "p2party-blind";

/**
 * Complete-gathering deadline. Loopback host candidates land in milliseconds;
 * a STUN-configured connection behind a slow resolver can take seconds. 15 s is
 * long enough that a real network is never cut short and short enough that a
 * misconfigured `rtcConfig` fails visibly instead of hanging the rendezvous.
 */
const DEFAULT_GATHERING_TIMEOUT_MS = 15_000;

/** Lane tags of the one-byte framing on the single bootstrap channel. */
const TAG_CONTROL = 0;
const TAG_APP = 1;

const SHA256_FINGERPRINT_BYTES = 32;

/*
 * Outbound backpressure, on the one send buffer both lanes share: the data
 * channel's own `bufferedAmount`. A frame is handed to the channel only while
 * that buffer holds at most `MAX_BUFFERED_AMOUNT` (1 MiB, sixteen uniform
 * 65,490-byte chunk frames); above it, sends wait for `bufferedamountlow`,
 * which the channel fires once the buffer has drained to
 * `SEND_BUFFER_LOW_THRESHOLD`. Without the wait a large message would be
 * handed to the browser's finite send buffer all at once. Measured in
 * headless Chromium 159 (2026-11-26): `send()` threw `OperationError` ("send
 * queue is full") once 16 MiB were buffered, and the channel stayed open —
 * which is why a refused frame ends the lane here rather than waiting for a
 * close. The inbound bounds are the `PROTOTYPE_*_LANE_*` constants.
 */

const channelTransports = new WeakMap<RTCDataChannel, DataChannelTransport>();

const utf8Encoder = new TextEncoder();
/** Fatal: silently substituting U+FFFD would change the bytes the peer signed. */
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

/**
 * Why a `WebRtcProviderError` was raised, for a caller to switch on:
 *   - `"closed"`: the data channel closed in order — the peer's graceful
 *     close, or this end's after its send buffer drained — or was closing when
 *     a frame was to be sent.
 *   - `"errored"`: the data channel reported an error (an SCTP abort, a
 *     transport failure).
 *   - `"aborted"`: this endpoint ended the transport or the provider at once,
 *     or is closing it and refuses new work.
 *   - `"protocol"`: the peer broke the framing: a non-binary, empty,
 *     unknown-lane or oversized frame.
 *   - `"overflow"`: a lane's receive queue would pass its high-water mark;
 *     the reader fell too far behind its peer.
 *   - `"refused"`: the open channel refused a frame (`send()` threw); no later
 *     frame may follow it.
 *   - `"connecting"`: a frame was to be sent before the data channel opened;
 *     nothing was queued.
 *   - `"undrained"`: an orderly close ended with frames still unsent.
 *   - `"cancelled"`: a receive was withdrawn by its caller before it took a
 *     frame.
 *   - `"certificate"`: the live DTLS certificates do not match the SDP.
 *   - `"negotiation"`: offer/answer, ICE gathering, or a call this provider's
 *     state or role does not allow.
 */
export type WebRtcProviderErrorReason =
  | "closed"
  | "errored"
  | "aborted"
  | "protocol"
  | "overflow"
  | "refused"
  | "connecting"
  | "undrained"
  | "cancelled"
  | "certificate"
  | "negotiation";

/** Every failure raised by this module, so callers can tell it apart. */
export class WebRtcProviderError extends Error {
  readonly reason: WebRtcProviderErrorReason;

  constructor(reason: WebRtcProviderErrorReason, message: string) {
    super(`webrtcProvider: ${message}`);
    this.name = "WebRtcProviderError";
    this.reason = reason;
  }
}

export interface WebRtcProviderOptions {
  readonly rtcConfig: RTCConfiguration;
  readonly role: "initiator" | "responder";
  /** Complete-ICE-gathering deadline; defaults to 15,000 ms. */
  readonly gatheringTimeoutMs?: number;
}

/**
 * Shape of the entries `RTCStatsReport.forEach` hands back that this file
 * reads. `RTCStatsReport`'s DOM typing declares its `forEach` value as `any`
 * (there is no per-type stats union in `lib.dom.d.ts`), so this local interface
 * is what keeps `verifyCertificates` free of `any`.
 */
interface RTCStatEntry {
  type: string;
  id?: string;
  localCertificateId?: string;
  remoteCertificateId?: string;
  fingerprint?: string;
  fingerprintAlgorithm?: string;
}

const toHex = (bytes: Uint8Array): string => {
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
};

const normalizeFingerprintHex = (fingerprint: string): string =>
  fingerprint.replace(/:/g, "").toLowerCase();

const expectedFingerprintHex = (
  fingerprint: Uint8Array,
  label: string,
): string => {
  if (!(fingerprint instanceof Uint8Array))
    throw new WebRtcProviderError(
      "negotiation",
      `${label} must be a Uint8Array`,
    );
  if (fingerprint.length !== SHA256_FINGERPRINT_BYTES)
    throw new WebRtcProviderError(
      "negotiation",
      `${label} must be ${SHA256_FINGERPRINT_BYTES} bytes, got ${fingerprint.length}`,
    );
  return toHex(fingerprint);
};

const decodeSdp = (bytes: Uint8Array, label: string): string => {
  if (!(bytes instanceof Uint8Array))
    throw new WebRtcProviderError(
      "negotiation",
      `remote ${label} SDP must be a Uint8Array`,
    );
  if (bytes.length === 0)
    throw new WebRtcProviderError(
      "negotiation",
      `remote ${label} SDP is empty`,
    );
  try {
    return utf8Decoder.decode(bytes);
  } catch {
    throw new WebRtcProviderError(
      "negotiation",
      `remote ${label} SDP is not valid UTF-8`,
    );
  }
};

/**
 * One `RTCPeerConnection` plus its bootstrap data channel, driven by the pair
 * driver's complete-ICE offer/answer contract.
 */
export class WebRtcCandidateProvider implements TransportCandidateProvider {
  readonly peerConnection: RTCPeerConnection;
  readonly role: "initiator" | "responder";

  readonly #gatheringTimeoutMs: number;
  readonly #channelWaiters: Array<{
    resolve: (channel: RTCDataChannel) => void;
    reject: (error: Error) => void;
  }> = [];
  /** Aborts armed by in-flight gathering waits, so `close()` unblocks them. */
  readonly #gatheringAborts = new Set<() => void>();

  #channel: RTCDataChannel | null = null;
  #closed = false;
  #offerCreated = false;
  #offerAccepted = false;
  #answerAccepted = false;

  constructor(options: WebRtcProviderOptions) {
    if (!options || typeof options !== "object")
      throw new WebRtcProviderError("negotiation", "options are required");
    if (options.role !== "initiator" && options.role !== "responder")
      throw new WebRtcProviderError(
        "negotiation",
        'role must be "initiator" or "responder"',
      );
    const gatheringTimeoutMs =
      options.gatheringTimeoutMs ?? DEFAULT_GATHERING_TIMEOUT_MS;
    if (!Number.isFinite(gatheringTimeoutMs) || gatheringTimeoutMs <= 0)
      throw new WebRtcProviderError(
        "negotiation",
        "gatheringTimeoutMs must be a positive finite number of milliseconds",
      );

    this.role = options.role;
    this.#gatheringTimeoutMs = gatheringTimeoutMs;
    this.peerConnection = new RTCPeerConnection(options.rtcConfig);

    if (options.role === "initiator") {
      // MUST happen before createOffer(): an offer generated with no data
      // channel negotiates no SCTP transport, and then no channel can ever
      // open on this connection.
      const channel = this.peerConnection.createDataChannel(
        BOOTSTRAP_CHANNEL_LABEL,
        { ordered: true },
      );
      this.#adopt(channel);
    } else {
      this.peerConnection.ondatachannel = (event: RTCDataChannelEvent) => {
        // First channel wins: the pair exchange negotiates exactly one edge,
        // and a second inbound channel would race the first for the handshake.
        if (this.#channel || this.#closed) {
          event.channel.close();
          return;
        }
        this.#adopt(event.channel);
      };
    }
  }

  #adopt(channel: RTCDataChannel): void {
    channel.binaryType = "arraybuffer";
    // Capture messages immediately. The peer can finish getStats() and send
    // its HELLO before this endpoint has even entered certificate verification.
    // Buffering bytes does not authenticate them or start a session.
    dataChannelTransport(channel);
    this.#channel = channel;
    const waiters = this.#channelWaiters.splice(0);
    for (const waiter of waiters) waiter.resolve(channel);
  }

  #assertOpen(): void {
    if (this.#closed)
      throw new WebRtcProviderError("aborted", "provider is closed");
  }

  /**
   * The one bootstrap data channel of this edge: for the initiator the channel
   * it created in the constructor (resolved immediately, before it opens); for
   * the responder the channel `ondatachannel` delivers. Rejects if the provider
   * is closed. The caller waits for `readyState`.
   */
  channel(): Promise<RTCDataChannel> {
    if (this.#closed)
      return Promise.reject(
        new WebRtcProviderError("aborted", "provider is closed"),
      );
    if (this.#channel) return Promise.resolve(this.#channel);
    return new Promise<RTCDataChannel>((resolve, reject) => {
      this.#channelWaiters.push({ resolve, reject });
    });
  }

  /** Complete-ICE offer, bootstrap data channel already created. */
  async createOffer(): Promise<Uint8Array> {
    this.#assertOpen();
    if (this.role !== "initiator")
      throw new WebRtcProviderError(
        "negotiation",
        "only the initiator may create an offer",
      );
    if (this.#offerCreated)
      throw new WebRtcProviderError(
        "negotiation",
        "createOffer() may only be called once",
      );
    if (!this.#channel)
      throw new WebRtcProviderError(
        "negotiation",
        "the bootstrap data channel must exist before the offer",
      );
    this.#offerCreated = true;

    const offer = await this.peerConnection.createOffer();
    await this.peerConnection.setLocalDescription(offer);
    await this.#awaitCompleteGathering();
    return this.#localSdpBytes("offer");
  }

  /** Set the remote offer and return the complete-ICE answer. */
  async acceptOffer(remoteSdp: Uint8Array): Promise<Uint8Array> {
    this.#assertOpen();
    if (this.role !== "responder")
      throw new WebRtcProviderError(
        "negotiation",
        "only the responder may accept an offer",
      );
    if (this.#offerAccepted)
      throw new WebRtcProviderError(
        "negotiation",
        "acceptOffer() may only be called once",
      );
    const sdp = decodeSdp(remoteSdp, "offer");
    this.#offerAccepted = true;

    await this.peerConnection.setRemoteDescription({ type: "offer", sdp });
    const answer = await this.peerConnection.createAnswer();
    await this.peerConnection.setLocalDescription(answer);
    await this.#awaitCompleteGathering();
    return this.#localSdpBytes("answer");
  }

  /** Set the remote answer; completes the initiator's negotiation. */
  async acceptAnswer(remoteSdp: Uint8Array): Promise<void> {
    this.#assertOpen();
    if (this.role !== "initiator")
      throw new WebRtcProviderError(
        "negotiation",
        "only the initiator may accept an answer",
      );
    if (this.#answerAccepted)
      throw new WebRtcProviderError(
        "negotiation",
        "acceptAnswer() may only be called once",
      );
    const sdp = decodeSdp(remoteSdp, "answer");
    this.#answerAccepted = true;

    await this.peerConnection.setRemoteDescription({ type: "answer", sdp });
  }

  /**
   * Post-connect DTLS binding check, copied in substance from
   * `handleHandshake.ts`'s `verifyDtlsFingerprints`: the fingerprints the two
   * SDP blobs declared (and that the handshake transcript is bound to) must
   * equal the live certificates `getStats()` reports. A disagreement means the
   * DTLS transport terminates on a different certificate than the one that was
   * authenticated — i.e. someone rewrote SDP after the transcript was bound —
   * so it throws.
   *
   * Returns `"unsupported"` (not a failure) when the engine reports neither a
   * `transport` stat nor any `certificate` rows: that is Firefox, which
   * implements neither, and treating it as a mismatch would make every
   * rendezvous fail there. What survives without the check is what the
   * transcript already binds — both SDP fingerprints — so an attacker who
   * rewrites SDP still produces a transcript both peers reject. Where the
   * engine can answer, a disagreement stays fatal, and so does a certificate
   * that cannot be located at all: a tripwire that cannot confirm must abort.
   */
  async verifyCertificates(
    localFingerprint: Uint8Array,
    remoteFingerprint: Uint8Array,
  ): Promise<"verified" | "unsupported"> {
    // getStats() on a closed connection rejects with a DOMException; failing
    // here keeps every error out of this module shaped like this module's.
    this.#assertOpen();
    const expectedLocal = expectedFingerprintHex(
      localFingerprint,
      "localFingerprint",
    );
    const expectedRemote = expectedFingerprintHex(
      remoteFingerprint,
      "remoteFingerprint",
    );

    const stats = await this.peerConnection.getStats();

    // RTCStatsReport only exposes forEach (no `.get` in the DOM typings), and
    // per the webrtc-stats spec the Map key IS each report's own id — report.id
    // itself is not guaranteed to be echoed back on every implementation — so
    // matching is done against the forEach key, falling back to report.id.
    let localCertificateId: string | undefined;
    let remoteCertificateId: string | undefined;
    let reportsCertificates = false;
    stats.forEach((report: RTCStatEntry) => {
      if (report.type === "transport") {
        localCertificateId = report.localCertificateId ?? localCertificateId;
        remoteCertificateId = report.remoteCertificateId ?? remoteCertificateId;
      }
      if (report.type === "certificate") reportsCertificates = true;
    });

    if (!reportsCertificates && localCertificateId === undefined)
      return "unsupported";

    const liveFingerprint = (id: string | undefined): string | null => {
      if (!id) return null;
      let found: string | null = null;
      stats.forEach((report: RTCStatEntry, key: string) => {
        if (
          report.type === "certificate" &&
          (key === id || report.id === id) &&
          report.fingerprint &&
          // A certificate row that declares another digest cannot be compared
          // against a SHA-256 SDP fingerprint; skipping it fails closed below.
          (report.fingerprintAlgorithm === undefined ||
            report.fingerprintAlgorithm.toLowerCase() === "sha-256")
        )
          found = normalizeFingerprintHex(report.fingerprint);
      });
      return found;
    };

    const liveLocal = liveFingerprint(localCertificateId);
    const liveRemote = liveFingerprint(remoteCertificateId);

    if (liveLocal === null || liveLocal !== expectedLocal)
      throw new WebRtcProviderError(
        "certificate",
        "DTLS fingerprint mismatch: the local certificate was not found in the " +
          "stats report or does not match the local SDP fingerprint",
      );
    if (liveRemote === null || liveRemote !== expectedRemote)
      throw new WebRtcProviderError(
        "certificate",
        "DTLS fingerprint mismatch: the remote certificate was not found in the " +
          "stats report or does not match the remote SDP fingerprint (possible MITM)",
      );
    return "verified";
  }

  /** Idempotent teardown: unblocks every waiter, then closes channel and pc. */
  close(): void {
    if (this.#closed) return;
    this.#closed = true;

    const aborts = [...this.#gatheringAborts];
    this.#gatheringAborts.clear();
    for (const abort of aborts) abort();

    const waiters = this.#channelWaiters.splice(0);
    for (const waiter of waiters)
      waiter.reject(
        new WebRtcProviderError(
          "aborted",
          "provider closed before a data channel arrived",
        ),
      );

    // A local abort, before the channel closes: it rejects pending receives
    // and sends and discards buffered pre-verification bytes synchronously,
    // where the channel's own close event would read as an orderly close by
    // the peer and keep them readable.
    if (this.#channel) dataChannelTransport(this.#channel).close();
    this.peerConnection.ondatachannel = null;
    this.peerConnection.close();
  }

  #localSdpBytes(label: string): Uint8Array {
    const sdp = this.peerConnection.localDescription?.sdp;
    if (!sdp)
      throw new WebRtcProviderError(
        "negotiation",
        `no local ${label} SDP after ICE gathering completed`,
      );
    // Exactly what the peer signs over: the description's own UTF-8 bytes.
    return utf8Encoder.encode(sdp);
  }

  /**
   * Resolve once this connection has gathered every candidate it will gather.
   * `icegatheringstatechange` can fire between the synchronous state read and
   * the listener registration, so the state is re-checked once immediately
   * after subscribing rather than only on the next event.
   */
  #awaitCompleteGathering(): Promise<void> {
    const pc = this.peerConnection;
    if (pc.iceGatheringState === "complete") return Promise.resolve();

    return new Promise<void>((resolve, reject) => {
      let settled = false;

      // `settle` closes over `timer`, `onStateChange` and `abort`, all declared
      // below: nothing can call it before the executor finishes initializing
      // them (the listener, the timer and `close()` all run later).
      const settle = (error?: WebRtcProviderError): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        pc.removeEventListener("icegatheringstatechange", onStateChange);
        this.#gatheringAborts.delete(abort);
        if (error) reject(error);
        else resolve();
      };
      const onStateChange = (): void => {
        if (pc.iceGatheringState === "complete") settle();
      };
      const abort = (): void =>
        settle(
          new WebRtcProviderError(
            "aborted",
            "provider closed while gathering ICE",
          ),
        );

      const timer = setTimeout(
        () =>
          settle(
            new WebRtcProviderError(
              "negotiation",
              `ICE gathering did not complete within ${this.#gatheringTimeoutMs}ms`,
            ),
          ),
        this.#gatheringTimeoutMs,
      );
      this.#gatheringAborts.add(abort);
      pc.addEventListener("icegatheringstatechange", onStateChange);
      onStateChange();
    });
  }
}

/**
 * The two logical streams a rendezvous edge carries over its one data channel:
 * the protocol-v4 handshake control lane (`send` / `recv`, the
 * `HandshakeTransport` the session API consumes) and the application lane
 * (`sendApp` / `recvApp`) that carries encrypted chunk frames.
 */
export interface DataChannelTransport extends HandshakeTransport {
  /**
   * Resolves once the frame is in the data channel's send buffer, which is
   * not delivery. Frames of both lanes enter the channel in call order,
   * whether or not each call is awaited; a call made while the buffer is above
   * `MAX_BUFFERED_AMOUNT` waits for it to drain.
   *
   * A frame is `bytes` plus the one-byte lane tag, and must fit the channel's
   * `RTCSctpTransport.maxMessageSize`. Measured in headless Chromium 159
   * (2026-11-26): both peers' SDP set `max-message-size:262144`, so `bytes`
   * may be at most 262,143 bytes; a frame one byte larger made `send()` throw
   * `TypeError` ("Trying to send message larger than max-message-size"), which
   * rejects with reason `"refused"` and, since nothing may follow a lost
   * frame, refuses every later send. A uniform chunk frame is 65,490 bytes.
   */
  send(bytes: Uint8Array): Promise<void>;
  sendApp(bytes: Uint8Array): Promise<void>;
  /**
   * The next frame of the lane, in arrival order. Aborting `signal` before a
   * frame arrives withdraws the receive — it rejects with reason
   * `"cancelled"` and takes nothing, so the next frame goes to the next
   * receive. Without a signal a receive cannot be withdrawn: a caller that
   * stops waiting on it would let it take the next frame unseen.
   */
  recv(signal?: AbortSignal): Promise<Uint8Array>;
  recvApp(signal?: AbortSignal): Promise<Uint8Array>;
  /**
   * An orderly close. Receiving ends at once, as on `close()`, and new sends
   * are refused; the frames already queued keep leaving. Once the channel's
   * send buffer is empty the channel is closed, and the promise resolves on
   * its `close` event. It rejects with a `WebRtcProviderError` if the
   * transport ends first with frames still unsent — the peer closed, the
   * channel refused a frame, or `close()` aborted the wait — since those may
   * never reach the peer. It has no deadline of its own: the caller bounds it
   * and calls `close()` to stop waiting.
   */
  closeAfterSending(): Promise<void>;
  /**
   * A local abort: discards every queued frame, rejects every pending receive
   * and send, and closes the underlying channel at once.
   */
  close(): void;
  /**
   * Whether frames this transport accepted are not all out of the channel's
   * send buffer — still queued, still buffered, or lost to a refusal — or,
   * once the transport has ended, whether it ended so. After `close()` it
   * says whether that abort left frames behind.
   */
  hasUnsentFrames(): boolean;
}

interface Lane {
  readonly name: "control" | "app";
  readonly highWaterBytes: number;
  readonly maxFrames: number;
  readonly queue: Uint8Array[];
  bytes: number;
  readonly waiters: Array<{
    resolve: (bytes: Uint8Array) => void;
    reject: (error: Error) => void;
  }>;
}

interface PendingSend {
  readonly framed: Uint8Array<ArrayBuffer>;
  readonly resolve: () => void;
  readonly reject: (error: Error) => void;
}

interface GracefulClose {
  readonly promise: Promise<void>;
  readonly resolve: () => void;
  readonly reject: (error: Error) => void;
}

/**
 * Frame the two lanes over one `RTCDataChannel` as `[tag(1)][payload]`, the
 * same framing `docs/e2e/webrtc-e2e/entry.ts` proved against real Chromium.
 *
 * RECEIVING. Anything that arrives with no waiter is queued on its lane, and
 * waiters are served FIFO. Each lane has a byte high-water mark and a frame
 * count (`PROTOTYPE_*_LANE_*`), and a frame that would take its lane past
 * either ends the transport. `RTCDataChannel` delivers every message as an
 * event and has no way to pause that, and telling the peer to slow down would
 * need a frame this framing does not have, so a reader that falls more than
 * one high-water mark behind its peer loses the edge, with a typed error,
 * rather than the page's memory.
 *
 * ENDING. Who ends the transport decides what happens to queued frames:
 *   - The channel ends it (`close`, or `error` then `close`): frames already
 *     delivered stay readable, and a reader drains them before it observes the
 *     end. A peer that sends and then closes is the normal case. Measured in
 *     headless Chromium 159 over loopback (2026-11-26): a peer that called
 *     `RTCDataChannel.close()` with 8 MiB still buffered had all 512 of its
 *     messages dispatched here before the `close` event and none after; one
 *     that called `RTCPeerConnection.close()` instead had 2 of 512 arrive. A
 *     frame never arrives in part: a data channel message is whole or absent.
 *   - This endpoint ends it — `close()`, which `WebRtcCandidateProvider.close()`
 *     calls before it closes the connection, a lane past its bound, or a frame
 *     that breaks the framing: every queued frame is discarded and every
 *     pending receive rejects at once, so shutdown cannot later continue a
 *     handshake from stale input. A local abort after the channel ended still
 *     discards what that end kept.
 *   - `closeAfterSending()` ends receiving the same way, then lets the send
 *     buffer drain before it closes the channel.
 * Either way every pending and later send rejects with the same
 * `WebRtcProviderError`, and a frame still waiting to be sent never is.
 *
 * SENDING. Frames enter the channel in call order. Above the high-water mark
 * they wait for `bufferedamountlow`; the listener is registered when the
 * transport is installed, before any check of `bufferedAmount`, so no drain
 * goes unheard. A frame the channel refuses (its `send()` throws) fails that
 * send and every later one: the framing is positional, so nothing may follow a
 * lost frame. Receiving is not affected by that; a close of the channel then
 * ends it as above.
 *
 * A channel has exactly one transport. The provider installs it at channel
 * adoption; later callers receive that same transport and its buffered bytes.
 */
export const dataChannelTransport = (
  channel: RTCDataChannel,
): DataChannelTransport => {
  const existing = channelTransports.get(channel);
  if (existing) return existing;
  channel.binaryType = "arraybuffer";
  channel.bufferedAmountLowThreshold = SEND_BUFFER_LOW_THRESHOLD;

  const lane = (
    name: Lane["name"],
    highWaterBytes: number,
    maxFrames: number,
  ): Lane => ({
    name,
    highWaterBytes,
    maxFrames,
    queue: [],
    bytes: 0,
    waiters: [],
  });
  const control = lane(
    "control",
    PROTOTYPE_CONTROL_LANE_HIGH_WATER_BYTES,
    PROTOTYPE_CONTROL_LANE_MAX_FRAMES,
  );
  const app = lane(
    "app",
    PROTOTYPE_APP_LANE_HIGH_WATER_BYTES,
    PROTOTYPE_APP_LANE_MAX_FRAMES,
  );
  const outbox: PendingSend[] = [];
  /** Set once, when the transport ends. */
  let ended: WebRtcProviderError | null = null;
  /** Set once, when receiving ends; receives see it once their lane drained. */
  let receivingEnded: WebRtcProviderError | null = null;
  /** Set once, when the channel refused a frame; sends only. */
  let refused: WebRtcProviderError | null = null;
  /** True once a frame this transport accepted can no longer leave. */
  let lostFrames = false;
  /** Whether frames were still unsent when the transport ended. */
  let unsentAtEnd = false;
  /** The orderly close in progress, once `closeAfterSending()` was called. */
  let graceful: GracefulClose | null = null;
  /** True inside `flush`, which a channel may re-enter from its `send()`. */
  let flushing = false;

  const unsent = (): boolean =>
    lostFrames || outbox.length > 0 || channel.bufferedAmount > 0;

  const rejectSends = (error: WebRtcProviderError): void => {
    const pending = outbox.splice(0);
    if (pending.length > 0) lostFrames = true;
    for (const send of pending) send.reject(error);
  };

  const discardQueues = (): void => {
    for (const each of [control, app]) {
      each.queue.length = 0;
      each.bytes = 0;
    }
  };

  /** A lane has waiters only while its queue is empty: nothing left to drain. */
  const endReceiving = (error: WebRtcProviderError): void => {
    receivingEnded ??= error;
    for (const each of [control, app]) {
      const waiters = each.waiters.splice(0);
      for (const waiter of waiters) waiter.reject(error);
    }
  };

  const end = (error: WebRtcProviderError, discard: boolean): void => {
    if (discard) discardQueues();
    if (ended) return;
    ended = error;
    unsentAtEnd = unsent();
    channel.removeEventListener("message", onMessage);
    channel.removeEventListener("close", onClose);
    channel.removeEventListener("error", onError);
    channel.removeEventListener("bufferedamountlow", flush);
    endReceiving(error);
    rejectSends(error);
    if (graceful !== null) {
      if (unsentAtEnd)
        graceful.reject(
          new WebRtcProviderError(
            "undrained",
            `the transport ended with frames still unsent: ${error.message}`,
          ),
        );
      else graceful.resolve();
    }
    if (channel.readyState !== "closed" && channel.readyState !== "closing")
      channel.close();
  };
  const abort = (error: WebRtcProviderError): void => end(error, true);

  const deliver = (target: Lane, payload: Uint8Array): void => {
    const waiter = target.waiters.shift();
    if (waiter) {
      waiter.resolve(payload);
      return;
    }
    if (
      target.bytes + payload.length > target.highWaterBytes ||
      target.queue.length >= target.maxFrames
    ) {
      abort(
        new WebRtcProviderError(
          "overflow",
          `the ${target.name} lane receive queue would pass its high-water mark ` +
            `(${target.highWaterBytes} bytes, ${target.maxFrames} frames): ` +
            "the reader is too far behind the peer",
        ),
      );
      return;
    }
    target.queue.push(payload);
    target.bytes += payload.length;
  };

  const onMessage = (event: MessageEvent): void => {
    if (!(event.data instanceof ArrayBuffer)) {
      abort(
        new WebRtcProviderError(
          "protocol",
          "data channel delivered a non-binary frame; the lane framing is binary only",
        ),
      );
      return;
    }
    const bytes = new Uint8Array(event.data);
    if (bytes.length === 0) {
      abort(
        new WebRtcProviderError(
          "protocol",
          "data channel delivered an empty frame",
        ),
      );
      return;
    }
    const target =
      bytes[0] === TAG_CONTROL ? control : bytes[0] === TAG_APP ? app : null;
    if (target === null) {
      abort(
        new WebRtcProviderError(
          "protocol",
          `data channel frame carried unknown lane tag ${bytes[0]}`,
        ),
      );
      return;
    }
    if (bytes.length - 1 > target.highWaterBytes) {
      abort(
        new WebRtcProviderError(
          "protocol",
          `a ${bytes.length - 1}-byte ${target.name} frame exceeds the lane's ` +
            `${target.highWaterBytes}-byte high-water mark`,
        ),
      );
      return;
    }
    deliver(target, bytes.slice(1));
  };

  const onClose = (): void => {
    end(new WebRtcProviderError("closed", "data channel closed"), false);
  };
  const onError = (): void => {
    end(new WebRtcProviderError("errored", "data channel errored"), false);
  };

  /**
   * Hand queued frames to the channel, in order, while its buffer is at or
   * under the high-water mark, then close it if an orderly close is waiting
   * for that. Runs on every send and on every drain; an event that finds the
   * buffer still above the mark releases nothing. A call from inside the loop
   * returns at once: the loop re-reads the buffer before every frame, so it
   * misses no drain, and frames cannot overtake each other.
   */
  function flush(): void {
    if (flushing) return;
    flushing = true;
    try {
      flushQueued();
    } finally {
      flushing = false;
    }
    closeIfDrained();
  }

  function flushQueued(): void {
    while (outbox.length > 0 && ended === null && refused === null) {
      if (channel.bufferedAmount > MAX_BUFFERED_AMOUNT) return;
      if (channel.readyState !== "open") {
        refused = new WebRtcProviderError(
          "closed",
          `data channel is "${channel.readyState}", not "open"`,
        );
        rejectSends(refused);
        return;
      }
      // Taken off the queue before `send`: should the transport end from
      // inside it, the frame did enter the channel and its send resolves.
      const next = outbox.shift();
      if (next === undefined) return;
      try {
        channel.send(next.framed);
      } catch (error) {
        // A channel that stopped being open is closing; one that is still
        // open refused this frame itself.
        refused = new WebRtcProviderError(
          channel.readyState === "open" ? "refused" : "closed",
          `data channel refused a frame: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
        lostFrames = true;
        next.reject(refused);
        rejectSends(refused);
        return;
      }
      next.resolve();
    }
  }

  /**
   * The last step of an orderly close: once nothing is queued and the buffer
   * is empty, close the channel; its `close` event ends the transport and
   * settles the close. To hear the buffer reach zero, the threshold is lowered
   * first and the buffer read after, so a drain in between is not missed.
   */
  function closeIfDrained(): void {
    if (graceful === null || ended !== null) return;
    if (refused !== null) {
      abort(refused);
      return;
    }
    if (outbox.length > 0) return;
    if (channel.bufferedAmount > 0) {
      channel.bufferedAmountLowThreshold = 0;
      if (channel.bufferedAmount > 0) return;
    }
    channel.close();
    // A channel already closed fires no further `close` event.
    if (ended === null && channel.readyState === "closed") onClose();
  }

  channel.addEventListener("message", onMessage);
  channel.addEventListener("close", onClose);
  channel.addEventListener("error", onError);
  channel.addEventListener("bufferedamountlow", flush);
  if (channel.readyState === "closed" || channel.readyState === "closing")
    end(
      new WebRtcProviderError("closed", "data channel already closed"),
      false,
    );

  const sendTagged = (tag: number, bytes: Uint8Array): Promise<void> => {
    const refusal = ended ?? refused ?? (graceful ? receivingEnded : null);
    if (refusal) return Promise.reject(refusal);
    if (channel.readyState !== "open")
      return Promise.reject(
        new WebRtcProviderError(
          channel.readyState === "connecting" ? "connecting" : "closed",
          `data channel is "${channel.readyState}", not "open"`,
        ),
      );
    // Framed now, so the bytes sent are the bytes of this call even if the
    // caller reuses its buffer while the frame waits.
    const framed = new Uint8Array(1 + bytes.length);
    framed[0] = tag;
    framed.set(bytes, 1);
    return new Promise<void>((resolve, reject) => {
      outbox.push({ framed, resolve, reject });
      flush();
    });
  };

  const cancelled = (): WebRtcProviderError =>
    new WebRtcProviderError(
      "cancelled",
      "the receive was withdrawn before it took a frame",
    );

  const receive = (
    source: Lane,
    signal: AbortSignal | undefined,
  ): Promise<Uint8Array> => {
    if (signal?.aborted) return Promise.reject(cancelled());
    const queued = source.queue.shift();
    if (queued !== undefined) {
      source.bytes -= queued.length;
      return Promise.resolve(queued);
    }
    if (receivingEnded) return Promise.reject(receivingEnded);
    return new Promise<Uint8Array>((resolve, reject) => {
      // A withdrawn receive leaves the lane: the next frame then waits in the
      // queue for the next reader instead of settling this one. Once a frame
      // has settled it, the waiter is gone and withdrawing does nothing.
      const withdraw = (): void => {
        const index = source.waiters.indexOf(waiter);
        if (index < 0) return;
        source.waiters.splice(index, 1);
        reject(cancelled());
      };
      const waiter = {
        resolve: (bytes: Uint8Array): void => {
          signal?.removeEventListener("abort", withdraw);
          resolve(bytes);
        },
        reject: (error: Error): void => {
          signal?.removeEventListener("abort", withdraw);
          reject(error);
        },
      };
      source.waiters.push(waiter);
      signal?.addEventListener("abort", withdraw, { once: true });
    });
  };

  const closeAfterSending = (): Promise<void> => {
    if (graceful !== null) return graceful.promise;
    if (ended !== null)
      return unsentAtEnd
        ? Promise.reject(
            new WebRtcProviderError(
              "undrained",
              `the transport ended with frames still unsent: ${ended.message}`,
            ),
          )
        : Promise.resolve();
    // Receiving ends now, exactly as on a local abort; what arrives from here
    // on is dropped.
    const closing = new WebRtcProviderError("aborted", "transport closed");
    channel.removeEventListener("message", onMessage);
    discardQueues();
    endReceiving(closing);
    let resolve!: () => void;
    let reject!: (error: Error) => void;
    const promise = new Promise<void>((settle, fail) => {
      resolve = settle;
      reject = fail;
    });
    graceful = { promise, resolve, reject };
    closeIfDrained();
    return promise;
  };

  const transport: DataChannelTransport = {
    send: (bytes: Uint8Array): Promise<void> => sendTagged(TAG_CONTROL, bytes),
    recv: (signal?: AbortSignal): Promise<Uint8Array> =>
      receive(control, signal),
    sendApp: (bytes: Uint8Array): Promise<void> => sendTagged(TAG_APP, bytes),
    recvApp: (signal?: AbortSignal): Promise<Uint8Array> =>
      receive(app, signal),
    closeAfterSending,
    close: (): void => {
      abort(new WebRtcProviderError("aborted", "transport closed"));
    },
    hasUnsentFrames: (): boolean => (ended === null ? unsent() : unsentAtEnd),
  };
  channelTransports.set(channel, transport);
  return transport;
};
