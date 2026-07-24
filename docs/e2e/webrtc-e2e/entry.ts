// Browser entry: exposes the store-free protocol-v4 session API + a real
// WebRTC mesh driver on window. Bundled with `bun build --target=browser`.
import {
  createSession,
  generateSessionIdentity,
  restoreSession,
  type P2PartySession,
  type GeneratedSessionIdentity,
  type HandshakeTransport,
} from "/Users/deliberative/Desktop/@p2party/p2party-js/src/session";

const te = new TextEncoder();
const td = new TextDecoder();

let wasmBinary: ArrayBuffer;
const loadWasm = async (): Promise<ArrayBuffer> => {
  if (!wasmBinary) {
    const res = await fetch("./libcrypto.wasm");
    wasmBinary = await res.arrayBuffer();
  }
  return wasmBinary;
};

// Parse the sha-256 DTLS fingerprint out of an SDP blob (32 raw bytes).
const fpFromSdp = (sdp: string): Uint8Array => {
  const m = /a=fingerprint:sha-256\s+([0-9A-Fa-f:]+)/.exec(sdp);
  if (!m) throw new Error("no sha-256 fingerprint in SDP");
  const bytes = m[1].split(":").map((b) => parseInt(b, 16));
  if (bytes.length !== 32) throw new Error("bad fingerprint length");
  return Uint8Array.from(bytes);
};

// Deterministic 32-byte channel id shared by both peers of an edge (sorted ids).
const channelIdFor = (a: string, b: string): Uint8Array => {
  const key = [a, b].sort().join("|");
  const out = new Uint8Array(32);
  const src = te.encode(key);
  out.set(src.subarray(0, 32));
  return out;
};

const b64 = (u: Uint8Array): string => btoa(String.fromCharCode(...u));

interface PeerEdge {
  pc: RTCPeerConnection;
  channel: RTCDataChannel | null;
  session: P2PartySession | null;
  recvWaiters: Array<(b: Uint8Array) => void>;
  recvQueue: Uint8Array[];
  appWaiters: Array<(b: Uint8Array) => void>;
  appQueue: Uint8Array[];
  remoteSet: boolean;
  pendingIce: RTCIceCandidateInit[];
}

interface PeerRuntime {
  id: string;
  identity: GeneratedSessionIdentity;
  edges: Map<string, PeerEdge>;
}

const peers = new Map<string, PeerRuntime>();
// Node-side signaling relay, injected by the driver via exposeFunction.
declare global {
  interface Window {
    __relaySignal: (from: string, to: string, payload: string) => void;
    __p2p: typeof api;
  }
}

const edge = (peer: PeerRuntime, other: string): PeerEdge => {
  let e = peer.edges.get(other);
  if (!e) {
    e = {
      pc: null as unknown as RTCPeerConnection,
      channel: null,
      session: null,
      recvWaiters: [],
      recvQueue: [],
      appWaiters: [],
      appQueue: [],
      remoteSet: false,
      pendingIce: [],
    };
    peer.edges.set(other, e);
  }
  return e;
};

// One control channel splits into two logical streams: length-prefixed
// [tag(1)][payload]. tag 0 = handshake/PQ-control bytes, tag 1 = app frame.
const TAG_CONTROL = 0;
const TAG_APP = 1;

const wireOnMessage = (e: PeerEdge, data: ArrayBuffer): void => {
  const bytes = new Uint8Array(data);
  const tag = bytes[0];
  const payload = bytes.subarray(1);
  if (tag === TAG_CONTROL) {
    const w = e.recvWaiters.shift();
    if (w) w(Uint8Array.from(payload));
    else e.recvQueue.push(Uint8Array.from(payload));
  } else {
    const w = e.appWaiters.shift();
    if (w) w(Uint8Array.from(payload));
    else e.appQueue.push(Uint8Array.from(payload));
  }
};

const sendTagged = (e: PeerEdge, tag: number, payload: Uint8Array): void => {
  const framed = new Uint8Array(1 + payload.length);
  framed[0] = tag;
  framed.set(payload, 1);
  e.channel!.send(framed.buffer);
};

const controlTransport = (e: PeerEdge): HandshakeTransport => ({
  send: (bytes: Uint8Array) => sendTagged(e, TAG_CONTROL, bytes),
  recv: (): Promise<Uint8Array> => {
    const queued = e.recvQueue.shift();
    if (queued) return Promise.resolve(queued);
    return new Promise((resolve) => e.recvWaiters.push(resolve));
  },
});

const recvApp = (e: PeerEdge): Promise<Uint8Array> => {
  const queued = e.appQueue.shift();
  if (queued) return Promise.resolve(queued);
  return new Promise((resolve) => e.appWaiters.push(resolve));
};

const waitOpen = (ch: RTCDataChannel): Promise<void> =>
  ch.readyState === "open"
    ? Promise.resolve()
    : new Promise((resolve) => {
        ch.onopen = () => resolve();
      });

const api = {
  async init(id: string): Promise<void> {
    const identity = await generateSessionIdentity({
      wasmBinary: await loadWasm(),
    });
    peers.set(id, { id, identity, edges: new Map() });
  },

  identityHex(id: string): string {
    const p = peers.get(id)!;
    return b64(p.identity.ed25519PublicKey);
  },

  // Called by the driver to hand this peer the OTHER peer's ed25519 pub.
  registerPeerIdentity(id: string, other: string, pubB64: string): void {
    (peers.get(id)! as unknown as { pubs?: Map<string, Uint8Array> }).pubs ??=
      new Map();
    (peers.get(id)! as unknown as { pubs: Map<string, Uint8Array> }).pubs.set(
      other,
      Uint8Array.from(atob(pubB64), (c) => c.charCodeAt(0)),
    );
  },

  // Create the RTCPeerConnection + channel wiring for one edge. Does NOT create
  // the offer yet, so BOTH peers can create their pc before any signal flows.
  connect(id: string, other: string, initiator: boolean): void {
    const peer = peers.get(id)!;
    const e = edge(peer, other);
    const pc = new RTCPeerConnection();
    e.pc = pc;
    pc.onicecandidate = (ev) => {
      if (ev.candidate)
        window.__relaySignal(id, other, JSON.stringify({ ice: ev.candidate }));
    };
    if (initiator) {
      const ch = pc.createDataChannel("p2p", { ordered: true });
      ch.binaryType = "arraybuffer";
      e.channel = ch;
      ch.onmessage = (m) => wireOnMessage(e, m.data as ArrayBuffer);
    } else {
      pc.ondatachannel = (ev) => {
        const ch = ev.channel;
        ch.binaryType = "arraybuffer";
        e.channel = ch;
        ch.onmessage = (m) => wireOnMessage(e, m.data as ArrayBuffer);
      };
    }
  },

  // Initiator side, called after BOTH peers have connect()ed: create + relay
  // the offer. Answers and ICE then flow into onSignal with both pcs live.
  async makeOffer(id: string, other: string): Promise<void> {
    const e = edge(peers.get(id)!, other);
    const offer = await e.pc.createOffer();
    await e.pc.setLocalDescription(offer);
    window.__relaySignal(id, other, JSON.stringify({ sdp: e.pc.localDescription }));
  },

  async onSignal(id: string, from: string, payloadJson: string): Promise<void> {
    const peer = peers.get(id)!;
    const e = edge(peer, from);
    const msg = JSON.parse(payloadJson) as {
      sdp?: RTCSessionDescriptionInit;
      ice?: RTCIceCandidateInit;
    };
    if (msg.sdp) {
      await e.pc.setRemoteDescription(msg.sdp);
      e.remoteSet = true;
      for (const ice of e.pendingIce)
        await e.pc.addIceCandidate(ice).catch(() => {});
      e.pendingIce = [];
      if (msg.sdp.type === "offer") {
        const answer = await e.pc.createAnswer();
        await e.pc.setLocalDescription(answer);
        window.__relaySignal(
          id,
          from,
          JSON.stringify({ sdp: e.pc.localDescription }),
        );
      }
    } else if (msg.ice) {
      if (e.remoteSet) await e.pc.addIceCandidate(msg.ice).catch(() => {});
      else e.pendingIce.push(msg.ice);
    }
  },

  // After the channel opens, run createSession over the real DataChannel and
  // return the negotiated PQ epoch (0).
  async handshake(id: string, other: string, initiator: boolean): Promise<number> {
    const peer = peers.get(id)!;
    const e = edge(peer, other);
    // Wait until the data channel exists and is open.
    while (!e.channel) await new Promise((r) => setTimeout(r, 10));
    await waitOpen(e.channel);
    const peerPub = (
      peer as unknown as { pubs: Map<string, Uint8Array> }
    ).pubs.get(other)!;
    const localFp = fpFromSdp(e.pc.localDescription!.sdp);
    const remoteFp = fpFromSdp(e.pc.remoteDescription!.sdp);
    e.session = await createSession({
      transport: controlTransport(e),
      role: initiator ? "initiator" : "responder",
      identity: peer.identity,
      peerIdentityEd25519PublicKey: peerPub,
      channel: {
        channelId: channelIdFor(id, other),
        localFingerprint: localFp,
        remoteFingerprint: remoteFp,
      },
      mode: "nopin",
      crypto: { wasmBinary: await loadWasm() },
    });
    return Number(e.session.pqEpoch);
  },

  // Send one app message; returns nothing (peer reads via recvMessage).
  async sendMessage(id: string, other: string, text: string): Promise<void> {
    const e = edge(peers.get(id)!, other);
    const env = await e.session!.encrypt(te.encode(text));
    // Ship the envelope as tagged app frames: [rootLen(2)][root][frameCount(2)]
    // then each frame length-prefixed. Reassembled by recvMessage.
    const parts: Uint8Array[] = [];
    const head = new Uint8Array(2 + env.root.length + 2);
    new DataView(head.buffer).setUint16(0, env.root.length, false);
    head.set(env.root, 2);
    new DataView(head.buffer).setUint16(2 + env.root.length, env.frames.length, false);
    parts.push(head);
    for (const f of env.frames) {
      const lp = new Uint8Array(4 + f.length);
      new DataView(lp.buffer).setUint32(0, f.length, false);
      lp.set(f, 4);
      parts.push(lp);
    }
    let total = 0;
    for (const p of parts) total += p.length;
    const blob = new Uint8Array(total);
    let off = 0;
    for (const p of parts) {
      blob.set(p, off);
      off += p.length;
    }
    // App frames can exceed the 64 KiB SCTP message ceiling, so chunk the blob
    // into <=16 KiB tagged pieces with a 4-byte total header on the first.
    const CHUNK = 16 * 1024;
    const withLen = new Uint8Array(4 + blob.length);
    new DataView(withLen.buffer).setUint32(0, blob.length, false);
    withLen.set(blob, 4);
    for (let i = 0; i < withLen.length; i += CHUNK)
      sendTagged(e, TAG_APP, withLen.subarray(i, Math.min(i + CHUNK, withLen.length)));
  },

  async recvMessage(id: string, other: string): Promise<string> {
    const e = edge(peers.get(id)!, other);
    // Reassemble the length-prefixed blob from tagged app chunks.
    const first = await recvApp(e);
    const totalLen = new DataView(first.buffer, first.byteOffset, 4).getUint32(0, false);
    const acc = new Uint8Array(4 + totalLen);
    acc.set(first, 0);
    let have = first.length;
    while (have < acc.length) {
      const next = await recvApp(e);
      acc.set(next, have);
      have += next.length;
    }
    const blob = acc.subarray(4);
    let off = 0;
    const rootLen = new DataView(blob.buffer, blob.byteOffset + off, 2).getUint16(0, false);
    off += 2;
    const root = blob.subarray(off, off + rootLen);
    off += rootLen;
    const frameCount = new DataView(blob.buffer, blob.byteOffset + off, 2).getUint16(0, false);
    off += 2;
    const frames: Uint8Array[] = [];
    for (let i = 0; i < frameCount; i++) {
      const fl = new DataView(blob.buffer, blob.byteOffset + off, 4).getUint32(0, false);
      off += 4;
      frames.push(blob.subarray(off, off + fl));
      off += fl;
    }
    const plain = await e.session!.decrypt({
      protocolVersion: 4,
      root: Uint8Array.from(root),
      frames: frames.map((f) => Uint8Array.from(f)),
    });
    return td.decode(plain);
  },

  // Start a background loop that owns the control stream after the handshake:
  // every inbound PQ control frame is authenticated and answered exactly, with
  // persist-before-send between mutation and dispatch. Both peers run this.
  startControlPump(id: string, other: string): void {
    const e = edge(peers.get(id)!, other);
    void (async () => {
      for (;;) {
        let frame: Uint8Array;
        try {
          frame = await controlTransport(e).recv();
        } catch {
          return;
        }
        try {
          const resp = await e.session!.acceptControlFrame(frame);
          if (resp.frame) {
            if (resp.requiresPersistBeforeSend) await e.session!.serialize();
            sendTagged(e, TAG_CONTROL, resp.frame);
          }
        } catch (err) {
          // A fork/forged frame fails the edge; record and stop pumping.
          (e as unknown as { pumpError?: string }).pumpError = String(err);
          return;
        }
      }
    })();
  },

  // The offerer initiates a due exchange; the background pumps on both sides
  // carry OFFER -> ADVANCE -> ACK to completion. Resolves at the new epoch.
  async heal(id: string, other: string): Promise<number> {
    const e = edge(peers.get(id)!, other);
    const out = await e.session!.prepareHealing();
    if (!out.frame) throw new Error("healing was not due");
    await e.session!.serialize(); // persist-before-send
    sendTagged(e, TAG_CONTROL, out.frame);
    const deadline = Date.now() + 15000;
    while (e.session!.pqEpoch === 0n && Date.now() < deadline)
      await new Promise((r) => setTimeout(r, 20));
    if (e.session!.pqEpoch === 0n) throw new Error("healing did not settle");
    // Give the peer's ACK-settle a moment to land.
    await new Promise((r) => setTimeout(r, 200));
    return Number(e.session!.pqEpoch);
  },

  epoch(id: string, other: string): number {
    return Number(edge(peers.get(id)!, other).session!.pqEpoch);
  },

  // Batch: send `count` app messages in-browser (minimizes node round-trips).
  async sendBurst(id: string, other: string, count: number): Promise<void> {
    for (let i = 0; i < count; i++)
      await this.sendMessage(id, other, `burst${i}`);
  },

  // Batch: receive `count` app messages in-browser; returns the last text.
  async recvBurst(id: string, other: string, count: number): Promise<string> {
    let last = "";
    for (let i = 0; i < count; i++) last = await this.recvMessage(id, other);
    return last;
  },

  connectionState(id: string, other: string): string {
    return edge(peers.get(id)!, other).pc.connectionState;
  },
};

window.__p2p = api;
