import { createSession, generateSessionIdentity } from "./session.mjs";
import { encode, decode, volunteer } from "./relay.mjs";

const role = location.hash.slice(1);
const cryptoOptions = {
  wasmBinary: await (await fetch("./libcrypto.wasm")).arrayBuffer(),
};
const identity = await generateSessionIdentity(cryptoOptions);
const sessions = new Map(),
  links = new Map(),
  inbox = new Map();
let gate, sample, lastForwarded;
const verdicts = [],
  received = [];
let rejected = 0;

function mailbox(name) {
  if (!inbox.has(name)) inbox.set(name, { data: [], waiting: null });
  return inbox.get(name);
}

window.peer = {
  publicKey: [...identity.ed25519PublicKey],
  handshakeInput({ name, bytes }) {
    const box = mailbox(name),
      message = Uint8Array.from(bytes);
    if (box.waiting) {
      box.waiting(message);
      box.waiting = null;
    } else box.data.push(message);
  },
  async establish({ name, side, pin, id, local, remote }) {
    const box = mailbox(name);
    const session = await createSession({
      role: side,
      identity,
      peerIdentityEd25519PublicKey: Uint8Array.from(pin),
      channel: {
        channelId: Uint8Array.from(id),
        localFingerprint: Uint8Array.from(local),
        remoteFingerprint: Uint8Array.from(remote),
      },
      mode: "nopin",
      pqMode: "hybrid-mlkem768",
      crypto: cryptoOptions,
      transport: {
        send: (bytes) => window.fixtureHandshake(name, [...bytes]),
        recv: () =>
          box.data.length
            ? Promise.resolve(box.data.shift())
            : new Promise((resolve) => {
                box.waiting = resolve;
              }),
      },
    });
    sessions.set(name, session);
    return session.canEncrypt;
  },
  openLink(name) {
    const pc = new RTCPeerConnection({ iceServers: [] });
    const dc = pc.createDataChannel("p2party-volunteer/1", {
      negotiated: true,
      id: 0,
    });
    dc.binaryType = "arraybuffer";
    links.set(name, { pc, dc });
    if (role === "B" && name === "BC") {
      gate = volunteer(dc);
      document.querySelector("#enable").onclick = () => gate.enable();
      document.querySelector("#stop").onclick = () => gate.stop();
    }
    if (role === "B" && name === "AB")
      dc.onmessage = ({ data }) => {
        const verdict = gate.forward(data);
        if (verdict === "forwarded") lastForwarded = data; // test observer for the wrong-key check
        if (verdicts.length < 32) verdicts.push(verdict);
      };
    if (role === "C")
      dc.onmessage = async ({ data }) => {
        try {
          received.push([...(await sessions.get("AC").decrypt(decode(data)))]);
        } catch {
          rejected++;
        }
      };
  },
  async description({ name, remote }) {
    const pc = links.get(name).pc;
    if (remote) await pc.setRemoteDescription(remote);
    if (remote?.type === "answer") return;
    const gathered = new Promise((resolve) =>
      pc.addEventListener("icecandidate", (e) => {
        if (!e.candidate) resolve();
      }),
    );
    await pc.setLocalDescription();
    await gathered;
    // Pass only IPv4 loopback UDP host candidates to the other browser.
    const sdp = pc.localDescription.sdp.split("\r\n");
    const local = sdp.filter((line) =>
      /^a=candidate:\S+ \d+ udp \d+ 127\.0\.0\.1 \d+ typ host\b/i.test(line),
    );
    if (!local.length)
      throw new Error("Chromium did not provide a loopback host candidate");
    const sanitized = sdp
      .filter(
        (line) => !line.startsWith("a=candidate:") || local.includes(line),
      )
      .map((line) =>
        line.startsWith("c=IN IP") ? "c=IN IP4 127.0.0.1" : line,
      );
    return { type: pc.localDescription.type, sdp: sanitized.join("\r\n") };
  },
  isOpen: (name) => links.get(name).dc.readyState === "open",
  async loopbackPair(name) {
    const { pc } = links.get(name);
    const stats = await pc.getStats();
    const transport = [...stats.values()].find(
      (item) => item.type === "transport",
    );
    const pair = stats.get(transport?.selectedCandidatePairId);
    return [
      stats.get(pair?.localCandidateId),
      stats.get(pair?.remoteCandidateId),
    ].every(
      (c) =>
        c?.address === "127.0.0.1" &&
        c.candidateType === "host" &&
        c.protocol === "udp",
    );
  },
  async prepare(bytes) {
    sample = encode(await sessions.get("AC").encrypt(Uint8Array.from(bytes)));
  },
  async diagnosticMessage() {
    return [
      ...new Uint8Array(
        encode(await sessions.get("AB").encrypt(Uint8Array.of(42))),
      ),
    ];
  },
  async openDiagnostic(bytes) {
    return [
      ...(await sessions
        .get("AB")
        .decrypt(decode(Uint8Array.from(bytes).buffer))),
    ];
  },
  send(kind) {
    let data = sample;
    if (kind === "text") data = "unsupported";
    if (kind === "short") data = new ArrayBuffer(4);
    if (kind === "version" || kind === "tampered") {
      data = sample.slice(0);
      new Uint8Array(data)[kind === "version" ? 3 : data.byteLength - 1] ^= 1;
    }
    links.get("AB").dc.send(data);
  },
  async canOpenAsVolunteer() {
    const diagnostic = sessions.get("AB");
    if (!lastForwarded || !diagnostic?.canEncrypt)
      throw new Error("Missing independent diagnostic session");
    try {
      await diagnostic.decrypt(decode(lastForwarded));
      return true;
    } catch {
      return false;
    }
  },
  snapshot: () => ({
    verdicts,
    received,
    rejected,
    state: gate?.state,
    used: gate?.used,
  }),
  async dispose() {
    gate?.stop();
    for (const { pc } of links.values()) pc.close();
    for (const session of sessions.values()) await session.destroy();
    identity.ed25519SecretKey.fill(0);
    identity.x25519SecretKey.fill(0);
  },
};
