// Real-WebRTC scheduled-cover lane test: drives the ACTUAL CoverRuntime over
// real RTCDataChannels and verifies fixed C×F×D authenticated cover cells per
// cycle, plus a real (non-dummy) cell substituting into a slot.
import { CoverRuntime } from "/Users/deliberative/Desktop/@p2party/p2party-js/src/handlers/coverRuntime";
import { SparsePqHealingState } from "/Users/deliberative/Desktop/@p2party/p2party-js/src/handlers/pqHealingRuntime";
import libcrypto from "/Users/deliberative/Desktop/@p2party/p2party-js/src/cryptography/libcrypto";
import {
  RATCHET_ROOT_SUITE_MLKEM512,
  METADATA_LEN,
  PROOF_LEN,
  CHUNK_LEN,
  DECRYPTED_LEN,
} from "/Users/deliberative/Desktop/@p2party/p2party-js/src/utils/constants";
import {
  initRatchet,
  ratchetEncrypt,
  type RatchetState,
} from "/Users/deliberative/Desktop/@p2party/p2party-js/src/cryptography/ratchet";
import {
  sealChunk,
  decryptMessageChunk,
} from "/Users/deliberative/Desktop/@p2party/p2party-js/src/handlers/messageChunkCrypto";
import { parseChunkFrameHeader } from "/Users/deliberative/Desktop/@p2party/p2party-js/src/handlers/chunkFrame";
import {
  getMerkleRoot,
  getMerkleProof,
} from "/Users/deliberative/Desktop/@p2party/p2party-js/src/cryptography/merkle";
import { hashMerkleLeafWasm } from "/Users/deliberative/Desktop/@p2party/p2party-js/src/utils/leafHash";
import {
  compileChannelMessageLabel,
  decompileChannelMessageLabel,
} from "/Users/deliberative/Desktop/@p2party/p2party-js/src/utils/channelLabel";

const FRAME_TYPE_CHUNK = 2;
const b64e = (u: Uint8Array): string => btoa(String.fromCharCode(...u));
const b64d = (s: string): Uint8Array =>
  Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

let wasmBinary: ArrayBuffer;
let mod: unknown;
const loadModule = async (): Promise<unknown> => {
  if (!mod) {
    if (!wasmBinary) wasmBinary = await (await fetch("./libcrypto.wasm")).arrayBuffer();
    const wasmMemory = new WebAssembly.Memory({ initial: 32, maximum: 32 });
    mod = await (libcrypto as unknown as (a: unknown) => Promise<unknown>)({
      wasmBinary,
      wasmMemory,
      getRandomValue: () => {
        const b = new Uint32Array(1);
        crypto.getRandomValues(b);
        return b[0] >>> 0;
      },
    });
  }
  return mod;
};

interface CoverPeer {
  pc: RTCPeerConnection;
  pq: SparsePqHealingState;
  runtime: CoverRuntime | null;
  received: number; // authenticated inbound cover cells
  receivedReal: string[]; // decoded real-cell markers (via receipt subtype)
  remoteSet: boolean;
  pendingIce: RTCIceCandidateInit[];
  statuses: string[];
  laneOpens: number;
  laneSends: number;
  ratchet: RatchetState | null;
  receivedChunks: string[]; // b64 of decrypted chunk regions
  debug: string[];
}

const peers = new Map<string, CoverPeer>();
declare global {
  interface Window {
    __relaySignal: (from: string, to: string, payload: string) => void;
    __cover: typeof api;
  }
}
const inbox = new Map<string, CoverPeer>();

const api = {
  async init(id: string, amInitiator: boolean): Promise<void> {
    const module = await loadModule();
    const pq = new SparsePqHealingState({
      module: module as never,
      pqMode: "hybrid-mlkem512",
      rootSuite: RATCHET_ROOT_SUITE_MLKEM512,
      binding: new Uint8Array(32).fill(0x42),
      rootKey: new Uint8Array(32).fill(0x19),
      nextOfferer: amInitiator ? "local" : "remote",
      amInitiator,
      now: 0,
    });
    const peer: CoverPeer = {
      pc: null as unknown as RTCPeerConnection,
      pq,
      runtime: null,
      received: 0,
      receivedReal: [],
      remoteSet: false,
      pendingIce: [],
      statuses: [],
      laneOpens: 0,
      laneSends: 0,
      ratchet: null,
      receivedChunks: [],
      debug: [],
    };
    peers.set(id, peer);
    inbox.set(id, peer);
  },

  // Pair the Double Ratchet across the two pages. The responder is created
  // first (returns its DH pub); the initiator consumes it.
  async initRatchetResponder(id: string, seedB64: string): Promise<string> {
    const module = await loadModule();
    const peer = peers.get(id)!;
    peer.ratchet = initRatchet(b64d(seedB64), false, null, module as never, RATCHET_ROOT_SUITE_MLKEM512);
    return b64e(peer.ratchet.dhSelfPub);
  },
  async initRatchetInitiator(
    id: string,
    seedB64: string,
    peerDhPubB64: string,
  ): Promise<void> {
    const module = await loadModule();
    const peer = peers.get(id)!;
    peer.ratchet = initRatchet(
      b64d(seedB64),
      true,
      b64d(peerDhPubB64),
      module as never,
      RATCHET_ROOT_SUITE_MLKEM512,
    );
  },

  // Seal a real 1-chunk message and substitute it into a cover slot as a
  // FRAME_TYPE_CHUNK cell (the exact scheduled-send cell shape).
  async sendRealChunk(id: string, marker: string): Promise<string> {
    const module = await loadModule();
    const peer = peers.get(id)!;
    const data = new Uint8Array(CHUNK_LEN);
    data.set(new TextEncoder().encode(marker).subarray(0, CHUNK_LEN));
    const leaf = hashMerkleLeafWasm(data, module as never);
    const root = await getMerkleRoot(leaf, module as never);
    const proof = await getMerkleProof(leaf, leaf, module as never, PROOF_LEN);
    const plaintext = new Uint8Array(DECRYPTED_LEN);
    plaintext.set(proof, METADATA_LEN);
    plaintext.set(data, METADATA_LEN + PROOF_LEN);

    const stepped = ratchetEncrypt(peer.ratchet!, module as never);
    const context = peer.pq.currentMessageContext();
    const cell = sealChunk(
      stepped.messageKey,
      stepped.header,
      plaintext,
      root,
      module as never,
      context,
    );
    stepped.messageKey.fill(0);

    // The lane label encodes the transfer root, exactly as production compiles
    // it, so the receiver recovers the root to decrypt.
    const label = await compileChannelMessageLabel("msg", root);
    let sent = false;
    peer.runtime!.enqueue({
      id: label,
      kind: "real",
      declaredCellCount: 1,
      nextCell: () => {
        if (sent) return null;
        sent = true;
        return cell;
      },
    });
    return b64e(data);
  },

  connect(id: string, other: string, initiator: boolean): void {
    const peer = peers.get(id)!;
    const pc = new RTCPeerConnection();
    peer.pc = pc;
    // The initiator creates a bootstrap channel BEFORE the offer so the SDP
    // negotiates an SCTP transport; later cover lanes then open. (In production
    // the "main" channel plays this role.)
    if (initiator) pc.createDataChannel("bootstrap", { ordered: true });
    pc.onicecandidate = (ev) => {
      if (ev.candidate) window.__relaySignal(id, other, JSON.stringify({ ice: ev.candidate }));
    };
    // The RECEIVER wires incoming lanes to the cover runtime authenticator.
    pc.ondatachannel = (ev) => {
      const ch = ev.channel;
      ch.binaryType = "arraybuffer";
      const laneLabel = ch.label;
      ch.onmessage = (m) => {
        const frame = new Uint8Array(m.data as ArrayBuffer);
        if (!peer.runtime) return;
        // Route by cell type, exactly like the production receive path.
        if (frame[0] === FRAME_TYPE_CHUNK && peer.ratchet) {
          void (async () => {
            try {
              const { merkleRootHex } =
                await decompileChannelMessageLabel(laneLabel);
              const root = Uint8Array.from(
                merkleRootHex.match(/.{2}/g)!.map((h) => parseInt(h, 16)),
              );
              const module = await loadModule();
              const result = decryptMessageChunk(
                peer.ratchet!,
                frame,
                new Map(),
                root,
                module as never,
                (epoch: bigint) => peer.pq.resolveMessageContext(epoch),
              );
              peer.debug.push(
                `chunk: ok=${result.ok} advanced=${result.stateAdvanced} rootHex=${merkleRootHex.slice(0, 12)}`,
              );
              if (result.ok && result.decrypted) {
                const chunk = result.decrypted.subarray(
                  METADATA_LEN + PROOF_LEN,
                );
                peer.receivedChunks.push(
                  btoa(String.fromCharCode(...chunk)),
                );
              }
            } catch (e) {
              peer.debug.push(`chunk-error: ${String(e).slice(0, 120)}`);
            }
          })();
          return;
        }
        const before = peer.received;
        const ok = peer.runtime.processInboundCoverCell(frame);
        if (ok) peer.received = before + 1;
      };
    };
  },

  async makeOffer(id: string, other: string): Promise<void> {
    const peer = peers.get(id)!;
    const offer = await peer.pc.createOffer();
    await peer.pc.setLocalDescription(offer);
    window.__relaySignal(id, other, JSON.stringify({ sdp: peer.pc.localDescription }));
  },

  async onSignal(id: string, from: string, payloadJson: string): Promise<void> {
    const peer = peers.get(id)!;
    const msg = JSON.parse(payloadJson) as { sdp?: RTCSessionDescriptionInit; ice?: RTCIceCandidateInit };
    if (msg.sdp) {
      await peer.pc.setRemoteDescription(msg.sdp);
      peer.remoteSet = true;
      for (const ice of peer.pendingIce) await peer.pc.addIceCandidate(ice).catch(() => {});
      peer.pendingIce = [];
      if (msg.sdp.type === "offer") {
        const answer = await peer.pc.createAnswer();
        await peer.pc.setLocalDescription(answer);
        window.__relaySignal(id, from, JSON.stringify({ sdp: peer.pc.localDescription }));
      }
    } else if (msg.ice) {
      if (peer.remoteSet) await peer.pc.addIceCandidate(msg.ice).catch(() => {});
      else peer.pendingIce.push(msg.ice);
    }
  },

  // Start the cover runtime on this peer (it opens lanes via createDataChannel).
  async startCover(
    id: string,
    other: string,
    amInitiator: boolean,
    schedule: { coverCadenceMs: number; coverLanes: number; coverFramesPerCell: number; coverDurationEpochs: number },
  ): Promise<void> {
    const peer = peers.get(id)!;
    const module = await loadModule();
    const epc = {
      withPeerId: other,
      pqHealingState: peer.pq,
    } as unknown as Parameters<typeof CoverRuntime>[0]["epc"];
    peer.runtime = new CoverRuntime({
      epc,
      roomId: "room",
      module: module as never,
      amInitiator,
      schedule,
      policyHash: new Uint8Array(32),
      laneLabelName: "p2party-cover",
      onStatusChange: ({ status, reason }) => {
        peer.statuses.push(reason ? status + ":" + reason : status);
      },
      openLaneChannel: (label) => {
        peer.laneOpens += 1;
        const ch = peer.pc.createDataChannel(label, { ordered: true, protocol: "raw" });
        ch.binaryType = "arraybuffer";
        return {
          label: ch.label,
          get readyState() {
            return ch.readyState;
          },
          get bufferedAmount() {
            return ch.bufferedAmount;
          },
          send: (d) => { peer.laneSends += 1; ch.send(d); },
          close: () => {
            if (ch.readyState !== "closed") ch.close();
          },
        };
      },
      onScheduledReceipt: (root) => {
        peer.receivedReal.push(root);
      },
    });
    peer.runtime.start();
  },

  // Substitute a real (receipt-subtype) cell into the schedule as a "real" job.
  enqueueReal(id: string, marker: string): void {
    const peer = peers.get(id)!;
    const root = new Uint8Array(64);
    root.set(new TextEncoder().encode(marker).subarray(0, 64));
    const token = new Uint8Array(64).fill(0x7);
    let sent = false;
    peer.runtime!.enqueue({
      id: `${"00".repeat(32)}~${Array.from(root, (b) => b.toString(16).padStart(2, "0")).join("")}`,
      kind: "real",
      declaredCellCount: 1,
      nextCell: () => {
        if (sent) return null;
        sent = true;
        return peer.runtime!.sealCoverContent({ subtype: "receipt", merkleRoot: root, token });
      },
    });
  },

  received(id: string): number {
    return peers.get(id)!.received;
  },
  receivedChunks(id: string): string[] {
    return peers.get(id)!.receivedChunks;
  },
  debug(id: string): string[] {
    return peers.get(id)!.debug;
  },
  receivedReal(id: string): string[] {
    return peers.get(id)!.receivedReal;
  },
  status(id: string): string {
    return peers.get(id)!.runtime?.status ?? "none";
  },
  statuses(id: string): string[] {
    return peers.get(id)!.statuses;
  },
  laneStats(id: string): { opens: number; sends: number } {
    const p = peers.get(id)!;
    return { opens: p.laneOpens, sends: p.laneSends };
  },
  stop(id: string): void {
    peers.get(id)!.runtime?.destroy();
    peers.get(id)!.pq.destroy();
    peers.get(id)!.pc.close();
  },
};

window.__cover = api;
