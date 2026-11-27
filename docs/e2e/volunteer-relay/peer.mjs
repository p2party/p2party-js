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
let gate, sample, lastForwarded, sourceChannel, paidGrant;
const deliveryKey =
  role !== "A"
    ? await crypto.subtle.generateKey("Ed25519", false, ["sign", "verify"])
    : null;
let paidOrder, receivedRecordHash;
function joinBytes(...parts) {
  const out = new Uint8Array(parts.reduce((sum, p) => sum + p.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}
const domain = (label) =>
  new TextEncoder().encode("p2party/local-paid-relay/" + label + "/v1\0");
async function hash(label, bytes) {
  return new Uint8Array(
    await crypto.subtle.digest("SHA-512", joinBytes(domain(label), bytes)),
  );
}
async function attest(label, binding) {
  return hex(
    await crypto.subtle.sign(
      "Ed25519",
      deliveryKey.privateKey,
      joinBytes(domain(label), binding),
    ),
  );
}
const hex = (bytes) =>
  Array.from(new Uint8Array(bytes), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
const verdicts = [],
  received = [];
let rejected = 0;

function mailbox(name) {
  if (!inbox.has(name)) inbox.set(name, { data: [], waiting: null });
  return inbox.get(name);
}

window.peer = {
  publicKey: [...identity.ed25519PublicKey],
  async deliveryKey() {
    return hex(await crypto.subtle.exportKey("raw", deliveryKey.publicKey));
  },
  async acknowledge() {
    if (received.length !== 1 || received[0].length !== 1024)
      throw new Error("Missing authenticated delivery");
    const data = Uint8Array.from(received[0]);
    const binding = joinBytes(
      data.subarray(0, 96),
      await hash("content", data.subarray(96)),
      receivedRecordHash,
    );
    return {
      binding: hex(binding),
      signature: await attest("delivered", binding),
    };
  },
  async forwardingReceipt() {
    if (!paidOrder || !lastForwarded)
      throw new Error("No forwarding observation");
    const slot = new Uint8Array(8);
    new DataView(slot.buffer).setBigUint64(0, BigInt(paidOrder.index));
    const binding = joinBytes(
      Uint8Array.fromHex(paidOrder.id),
      slot,
      await hash("record", new Uint8Array(lastForwarded)),
    );
    return attest("forwarded", binding);
  },
  setPaidGrant({ bytes, id, index }) {
    if (
      gate ||
      paidOrder ||
      !Number.isSafeInteger(bytes) ||
      bytes <= 0 ||
      !/^[0-9a-f]{128}$/.test(id) ||
      !Number.isInteger(index) ||
      index < 0 ||
      index >= 8
    )
      throw new Error("Configure paid order before connecting");
    paidGrant = bytes;
    paidOrder = { id, index };
  },
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
    if (role === "A" && name.startsWith("A")) sourceChannel = dc;
    const intermediate = role !== "A" && role !== "C";
    if (intermediate && name.startsWith(role)) {
      gate = volunteer(dc, paidGrant);
      if (paidGrant)
        document.querySelector("#enable").textContent =
          "Enable forwarding for two seconds, one record at 1 test P2PARTY on delivery";
      document.querySelector("#enable").onclick = () => {
        if (gate.state !== "enabled") lastForwarded = null;
        gate.enable();
      };
      document.querySelector("#stop").onclick = () => gate.stop();
    }
    if (intermediate && name.endsWith(role))
      dc.onmessage = ({ data }) => {
        const verdict = gate?.forward(data) ?? "disabled";
        if (verdict === "forwarded") lastForwarded = data; // test observer for the wrong-key check
        if (verdicts.length < 32) verdicts.push(verdict);
      };
    if (role === "C")
      dc.onmessage = async ({ data }) => {
        try {
          const plaintext = await sessions.get("AC").decrypt(decode(data));
          receivedRecordHash = await hash("record", new Uint8Array(data));
          received.push([...plaintext]);
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
    return hex(await hash("record", new Uint8Array(sample)));
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
    sourceChannel.send(data);
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
