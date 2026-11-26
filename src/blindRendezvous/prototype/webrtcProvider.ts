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
 * `IRTCPeerConnection` wrappers. The only import in this file is a type, which
 * `verbatimModuleSyntax` erases entirely at build time.
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

/**
 * Outbound backpressure, on the one send buffer both lanes share: the data
 * channel's own `bufferedAmount`. A frame is handed to the channel only while
 * that buffer holds at most `SEND_HIGH_WATER_BYTES`; above it, sends wait for
 * `bufferedamountlow`, which the channel fires once the buffer has drained to
 * `SEND_LOW_WATER_BYTES`. 1 MiB is sixteen uniform 65,490-byte chunk frames in
 * flight. A browser's send buffer is finite — the WebRTC specification has
 * `send()` throw `OperationError` when a frame does not fit — and without the
 * wait a large message would be handed to it all at once. Draining to half the
 * mark leaves the channel 512 KiB to send while the page refills it. Both
 * values are the main app's: `MAX_BUFFERED_AMOUNT` in `src/utils/constants.ts`
 * and half of it in `handleSendMessage.ts`.
 *
 * Exported for the tests. They belong in `src/utils/constants.ts`, which this
 * file does not import from: it has no runtime imports at all (see the header).
 */
export const SEND_HIGH_WATER_BYTES = 1024 * 1024;
export const SEND_LOW_WATER_BYTES = SEND_HIGH_WATER_BYTES / 2;

/**
 * Inbound bounds, one pair per lane. A remote endpoint may speak before local
 * certificate verification or session startup completes, and a reader may fall
 * behind its peer, so what arrives with no reader waiting is queued — up to
 * these bounds and no further.
 *
 * The control lane carries the protocol-v4 handshake alone: at most three
 * frames from the peer, the largest 3,329 bytes (an ML-KEM-1024 HELLO). The app
 * lane carries the message header and the uniform chunk frames; 16 MiB is 256
 * of them. The frame counts bound the per-frame overhead of tiny frames.
 */
export const CONTROL_LANE_HIGH_WATER_BYTES = 64 * 1024;
export const CONTROL_LANE_MAX_FRAMES = 16;
export const APP_LANE_HIGH_WATER_BYTES = 16 * 1024 * 1024;
export const APP_LANE_MAX_FRAMES = 1024;

const channelTransports = new WeakMap<RTCDataChannel, DataChannelTransport>();

const utf8Encoder = new TextEncoder();
/** Fatal: silently substituting U+FFFD would change the bytes the peer signed. */
const utf8Decoder = new TextDecoder("utf-8", { fatal: true });

/** Every failure raised by this module, so callers can tell it apart. */
export class WebRtcProviderError extends Error {
  constructor(message: string) {
    super(`webrtcProvider: ${message}`);
    this.name = "WebRtcProviderError";
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
    throw new WebRtcProviderError(`${label} must be a Uint8Array`);
  if (fingerprint.length !== SHA256_FINGERPRINT_BYTES)
    throw new WebRtcProviderError(
      `${label} must be ${SHA256_FINGERPRINT_BYTES} bytes, got ${fingerprint.length}`,
    );
  return toHex(fingerprint);
};

const decodeSdp = (bytes: Uint8Array, label: string): string => {
  if (!(bytes instanceof Uint8Array))
    throw new WebRtcProviderError(`remote ${label} SDP must be a Uint8Array`);
  if (bytes.length === 0)
    throw new WebRtcProviderError(`remote ${label} SDP is empty`);
  try {
    return utf8Decoder.decode(bytes);
  } catch {
    throw new WebRtcProviderError(`remote ${label} SDP is not valid UTF-8`);
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
      throw new WebRtcProviderError("options are required");
    if (options.role !== "initiator" && options.role !== "responder")
      throw new WebRtcProviderError('role must be "initiator" or "responder"');
    const gatheringTimeoutMs =
      options.gatheringTimeoutMs ?? DEFAULT_GATHERING_TIMEOUT_MS;
    if (!Number.isFinite(gatheringTimeoutMs) || gatheringTimeoutMs <= 0)
      throw new WebRtcProviderError(
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
    if (this.#closed) throw new WebRtcProviderError("provider is closed");
  }

  /**
   * The one bootstrap data channel of this edge: for the initiator the channel
   * it created in the constructor (resolved immediately, before it opens); for
   * the responder the channel `ondatachannel` delivers. Rejects if the provider
   * is closed. The caller waits for `readyState`.
   */
  channel(): Promise<RTCDataChannel> {
    if (this.#closed)
      return Promise.reject(new WebRtcProviderError("provider is closed"));
    if (this.#channel) return Promise.resolve(this.#channel);
    return new Promise<RTCDataChannel>((resolve, reject) => {
      this.#channelWaiters.push({ resolve, reject });
    });
  }

  /** Complete-ICE offer, bootstrap data channel already created. */
  async createOffer(): Promise<Uint8Array> {
    this.#assertOpen();
    if (this.role !== "initiator")
      throw new WebRtcProviderError("only the initiator may create an offer");
    if (this.#offerCreated)
      throw new WebRtcProviderError("createOffer() may only be called once");
    if (!this.#channel)
      throw new WebRtcProviderError(
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
      throw new WebRtcProviderError("only the responder may accept an offer");
    if (this.#offerAccepted)
      throw new WebRtcProviderError("acceptOffer() may only be called once");
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
      throw new WebRtcProviderError("only the initiator may accept an answer");
    if (this.#answerAccepted)
      throw new WebRtcProviderError("acceptAnswer() may only be called once");
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
        "DTLS fingerprint mismatch: the local certificate was not found in the " +
          "stats report or does not match the local SDP fingerprint",
      );
    if (liveRemote === null || liveRemote !== expectedRemote)
      throw new WebRtcProviderError(
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
        settle(new WebRtcProviderError("provider closed while gathering ICE"));

      const timer = setTimeout(
        () =>
          settle(
            new WebRtcProviderError(
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
   * Resolves once the frame is in the data channel's buffer. Frames of both
   * lanes enter the channel in call order, whether or not each call is
   * awaited; a call made while the buffer is above `SEND_HIGH_WATER_BYTES`
   * waits for it to drain.
   */
  send(bytes: Uint8Array): Promise<void>;
  sendApp(bytes: Uint8Array): Promise<void>;
  recvApp(): Promise<Uint8Array>;
  /**
   * A local abort: discards every queued frame, rejects every pending receive
   * and send, and closes the underlying channel.
   */
  close(): void;
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

/**
 * Frame the two lanes over one `RTCDataChannel` as `[tag(1)][payload]`, the
 * same framing `docs/e2e/webrtc-e2e/entry.ts` proved against real Chromium.
 *
 * RECEIVING. Anything that arrives with no waiter is queued on its lane, and
 * waiters are served FIFO. Each lane has a byte high-water mark and a frame
 * count (the `*_LANE_*` constants above), and a frame that would take its lane
 * past either ends the transport. `RTCDataChannel` delivers every message as
 * an event and has no way to pause that, and telling the peer to slow down
 * would need a frame this framing does not have, so a reader that falls more
 * than one high-water mark behind its peer loses the edge, with a typed error,
 * rather than the page's memory.
 *
 * ENDING. Who ends the transport decides what happens to queued frames:
 *   - The channel ends it (`close`, or `error` then `close`): frames already
 *     delivered stay readable, and a reader drains them before it observes the
 *     end. A peer that sends and then closes is the normal case: the messages
 *     this endpoint received before the close are dispatched before it. A
 *     frame never arrives in part: a data channel message is whole or absent.
 *   - This endpoint ends it — `close()`, which `WebRtcCandidateProvider.close()`
 *     calls before it closes the connection, a lane past its bound, or a frame
 *     that breaks the framing: every queued frame is discarded and every
 *     pending receive rejects at once, so shutdown cannot later continue a
 *     handshake from stale input. A local abort after the channel ended still
 *     discards what that end kept.
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
  channel.bufferedAmountLowThreshold = SEND_LOW_WATER_BYTES;

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
    CONTROL_LANE_HIGH_WATER_BYTES,
    CONTROL_LANE_MAX_FRAMES,
  );
  const app = lane("app", APP_LANE_HIGH_WATER_BYTES, APP_LANE_MAX_FRAMES);
  const outbox: PendingSend[] = [];
  /** Set once, when the transport ends; receives see it once drained. */
  let ended: WebRtcProviderError | null = null;
  /** Set once, when the channel refused a frame; sends only. */
  let refused: WebRtcProviderError | null = null;
  /** True inside `flush`, which a channel may re-enter from its `send()`. */
  let flushing = false;

  const rejectSends = (error: WebRtcProviderError): void => {
    const pending = outbox.splice(0);
    for (const send of pending) send.reject(error);
  };

  const end = (error: WebRtcProviderError, discard: boolean): void => {
    if (discard)
      for (const each of [control, app]) {
        each.queue.length = 0;
        each.bytes = 0;
      }
    if (ended) return;
    ended = error;
    channel.removeEventListener("message", onMessage);
    channel.removeEventListener("close", onClose);
    channel.removeEventListener("error", onError);
    channel.removeEventListener("bufferedamountlow", flush);
    // A lane has waiters only while its queue is empty, so these readers have
    // nothing left to drain.
    for (const each of [control, app]) {
      const waiters = each.waiters.splice(0);
      for (const waiter of waiters) waiter.reject(error);
    }
    rejectSends(error);
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
          "data channel delivered a non-binary frame; the lane framing is binary only",
        ),
      );
      return;
    }
    const bytes = new Uint8Array(event.data);
    if (bytes.length === 0) {
      abort(new WebRtcProviderError("data channel delivered an empty frame"));
      return;
    }
    const target =
      bytes[0] === TAG_CONTROL ? control : bytes[0] === TAG_APP ? app : null;
    if (target === null) {
      abort(
        new WebRtcProviderError(
          `data channel frame carried unknown lane tag ${bytes[0]}`,
        ),
      );
      return;
    }
    if (bytes.length - 1 > target.highWaterBytes) {
      abort(
        new WebRtcProviderError(
          `a ${bytes.length - 1}-byte ${target.name} frame exceeds the lane's ` +
            `${target.highWaterBytes}-byte high-water mark`,
        ),
      );
      return;
    }
    deliver(target, bytes.slice(1));
  };

  const onClose = (): void => {
    end(new WebRtcProviderError("data channel closed"), false);
  };
  const onError = (): void => {
    end(new WebRtcProviderError("data channel errored"), false);
  };

  /**
   * Hand queued frames to the channel, in order, while its buffer is at or
   * under the high-water mark. Runs on every send and on every drain; an event
   * that finds the buffer still above the mark releases nothing. A call from
   * inside the loop returns at once: the loop re-reads the buffer before every
   * frame, so it misses no drain, and frames cannot overtake each other.
   */
  function flush(): void {
    if (flushing) return;
    flushing = true;
    try {
      flushQueued();
    } finally {
      flushing = false;
    }
  }

  function flushQueued(): void {
    while (outbox.length > 0 && ended === null && refused === null) {
      if (channel.bufferedAmount > SEND_HIGH_WATER_BYTES) return;
      if (channel.readyState !== "open") {
        refused = new WebRtcProviderError(
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
        refused = new WebRtcProviderError(
          `data channel refused a frame: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
        next.reject(refused);
        rejectSends(refused);
        return;
      }
      next.resolve();
    }
  }

  channel.addEventListener("message", onMessage);
  channel.addEventListener("close", onClose);
  channel.addEventListener("error", onError);
  channel.addEventListener("bufferedamountlow", flush);
  if (channel.readyState === "closed" || channel.readyState === "closing")
    end(new WebRtcProviderError("data channel already closed"), false);

  const sendTagged = (tag: number, bytes: Uint8Array): Promise<void> => {
    const refusal = ended ?? refused;
    if (refusal) return Promise.reject(refusal);
    if (channel.readyState !== "open")
      return Promise.reject(
        new WebRtcProviderError(
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

  const receive = (source: Lane): Promise<Uint8Array> => {
    const queued = source.queue.shift();
    if (queued !== undefined) {
      source.bytes -= queued.length;
      return Promise.resolve(queued);
    }
    if (ended) return Promise.reject(ended);
    return new Promise<Uint8Array>((resolve, reject) => {
      source.waiters.push({ resolve, reject });
    });
  };

  const transport: DataChannelTransport = {
    send: (bytes: Uint8Array): Promise<void> => sendTagged(TAG_CONTROL, bytes),
    recv: (): Promise<Uint8Array> => receive(control),
    sendApp: (bytes: Uint8Array): Promise<void> => sendTagged(TAG_APP, bytes),
    recvApp: (): Promise<Uint8Array> => receive(app),
    close: (): void => {
      abort(new WebRtcProviderError("transport closed"));
    },
  };
  channelTransports.set(channel, transport);
  return transport;
};
