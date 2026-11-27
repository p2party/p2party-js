import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  mock,
  test,
} from "bun:test";

import {
  claimRatchetGate,
  openRatchetGate,
  resetRatchetGate,
} from "../../src/handlers/ratchetGate";
import { expectDatabaseCall } from "../support/databaseCall";
import { markChannelClosedLocally } from "../../src/api/webrtc/localChannelClose";

import type {
  IRTCDataChannel,
  IRTCPeerConnection,
} from "../../src/api/webrtc/interfaces";
import type { RatchetGateLease } from "../../src/handlers/ratchetGate";
import type { MessageData } from "../../src/db/types";

// handleOpenChannel reaches the Redux store, whose keyPair slice reads
// localStorage at module initialisation.
const localStorageMemory: Record<string, string> = {};
(globalThis as unknown as { localStorage?: Storage }).localStorage ??= {
  getItem: (key: string) =>
    key in localStorageMemory ? localStorageMemory[key] : null,
  setItem: (key: string, value: string) => {
    localStorageMemory[key] = String(value);
  },
  removeItem: (key: string) => {
    delete localStorageMemory[key];
  },
  clear: () => {
    for (const key of Object.keys(localStorageMemory))
      delete localStorageMemory[key];
  },
  key: () => null,
  length: 0,
} as Storage;

// Model the incomplete file owned by this fixture. Other roots use the real
// database client, including calls from subsequent files.
const realDb = { ...(await import("../../src/db/api")) };
const dbState: {
  messageData: MessageData | undefined;
  deletedTransfers: string[];
} = { messageData: undefined, deletedTransfers: [] };

mock.module("../../src/db/api", () => ({
  ...realDb,
  getDBMessageData: async (
    ...args: Parameters<typeof realDb.getDBMessageData>
  ) =>
    args[0] === MERKLE_ROOT_HEX
      ? dbState.messageData
      : realDb.getDBMessageData(...args),
  getDBAllChunkLeafHashes: async (root: string) =>
    root === MERKLE_ROOT_HEX ? [] : realDb.getDBAllChunkLeafHashes(root),
  deleteReceiveTransfer: async (
    root: string,
    guard?: Parameters<typeof realDb.deleteReceiveTransfer>[1],
  ) => {
    if (root !== MERKLE_ROOT_HEX)
      return guard
        ? realDb.deleteReceiveTransfer(root, guard)
        : realDb.deleteReceiveTransfer(root);
    dbState.deletedTransfers.push(root);
    return guard ? true : undefined;
  },
}));

afterAll(() => {
  mock.module("../../src/db/api", () => realDb);
});

let handleOpenChannel: (typeof import("../../src/handlers/handleOpenChannel"))["handleOpenChannel"];
let compileChannelMessageLabel: (typeof import("../../src/utils/channelLabel"))["compileChannelMessageLabel"];
let DEFAULT_ROOM_POLICY_V1: (typeof import("../../src/roomPolicy"))["DEFAULT_ROOM_POLICY_V1"];

beforeAll(async () => {
  await import("../../src/store");
  ({ handleOpenChannel } =
    await import("../../src/handlers/handleOpenChannel"));
  ({ compileChannelMessageLabel } =
    await import("../../src/utils/channelLabel"));
  ({ DEFAULT_ROOM_POLICY_V1 } = await import("../../src/roomPolicy"));
});

const ROOM_ID = "00000000-0000-4000-8000-0000000000d1";
const PEER_ID = "00000000-0000-4000-8000-0000000000d2";
const SELF_PUBLIC_KEY = `${"00".repeat(31)}01`;
const PEER_PUBLIC_KEY = "ff".repeat(32);
const MERKLE_ROOT_HEX = "ab".repeat(64);

afterEach(() => {
  resetRatchetGate(ROOM_ID, PEER_ID);
  dbState.messageData = undefined;
  dbState.deletedTransfers = [];
});

const partialReceive = (): MessageData => ({
  roomId: ROOM_ID,
  timestamp: Date.now(),
  fromPeerId: PEER_ID,
  channelLabel: "chat",
  hash: "cd".repeat(64),
  merkleRoot: MERKLE_ROOT_HEX,
  filename: "holiday.mp4",
  messageType: 1,
  savedSize: 4_194_304,
  totalSize: 10_485_760,
});

const fakeApi = () =>
  ({
    dispatch: () => ({ unwrap: async () => undefined }),
    getState: () => ({
      keyPair: {
        peerId: "00000000-0000-4000-8000-000000000001",
        publicKey: SELF_PUBLIC_KEY,
        secretKey: "",
        challengeId: "",
        challenge: "",
        signature: "",
      },
      rooms: [
        {
          id: ROOM_ID,
          url: "cc".repeat(32),
          rtcConfig: { iceServers: [] },
          signalingActive: true,
          policy: DEFAULT_ROOM_POLICY_V1,
          peers: [{ peerId: PEER_ID, peerPublicKey: PEER_PUBLIC_KEY }],
          channels: [],
          messages: [],
        },
      ],
      signalingServer: {
        isConnected: true,
        isEstablishingConnection: false,
        isVerified: true,
        serverUrl: "wss://signal.example/ws",
      },
    }),
  }) as unknown as Parameters<typeof handleOpenChannel>[1];

/**
 * A receiver holding a partial file on a healthy, authenticated edge, with its
 * per-message channel already registered — exactly the state in which a close
 * is read as the peer cancelling.
 */
const openReceivingChannel = async (): Promise<{
  channel: IRTCDataChannel;
  epc: IRTCPeerConnection;
  lease: RatchetGateLease;
}> => {
  const lease = claimRatchetGate(ROOM_ID, PEER_ID);
  const epc = {
    roomId: ROOM_ID,
    withPeerId: PEER_ID,
    withPeerPublicKey: PEER_PUBLIC_KEY,
    connectionState: "connected",
    ratchetGateLease: lease,
    close: () => undefined,
  } as unknown as IRTCPeerConnection;
  const label = await compileChannelMessageLabel("chat", MERKLE_ROOT_HEX);
  let state: RTCDataChannelState = "open";
  const channel = {
    label,
    binaryType: "blob",
    withPeerId: PEER_ID,
    roomIds: [ROOM_ID],
    bufferedAmount: 0,
    get readyState() {
      return state;
    },
    send: () => undefined,
    close: () => {
      state = "closed";
    },
  } as unknown as IRTCDataChannel;
  const dataChannels: IRTCDataChannel[] = [];
  const opened = await handleOpenChannel(
    { channel, epc, roomId: ROOM_ID, dataChannels },
    fakeApi(),
  );
  dataChannels.push(opened);
  openRatchetGate(ROOM_ID, PEER_ID, lease);
  return { channel: opened, epc, lease };
};

const closeAndSettle = async (channel: IRTCDataChannel): Promise<void> => {
  channel.close();
  await (channel.onclose as unknown as () => Promise<void>)();
  for (let i = 0; i < 20; i++) await Promise.resolve();
  await new Promise((resolve) => setTimeout(resolve, 0));
};

describe("I-1: the receiver's own close is not the peer cancelling either", () => {
  test("an unrelated root reaches the real database client", async () => {
    const root = "ee".repeat(64);
    const db = await import("../../src/db/api");
    await expectDatabaseCall("getDBMessageData", [root, undefined], () =>
      db.getDBMessageData(root),
    );
  });

  test("a bare remote close on a live edge preserves the partial for resume", async () => {
    dbState.messageData = partialReceive();
    const { channel } = await openReceivingChannel();

    await closeAndSettle(channel);

    expect(dbState.deletedTransfers).toEqual([]);
  });

  test("a close THIS side performed does not delete a partial with recorded progress", async () => {
    dbState.messageData = partialReceive();
    const { channel } = await openReceivingChannel();

    // Exactly what the pre-authentication guard, the receipt-queue budget and
    // the receive-queue budget all do before closing.
    markChannelClosedLocally(channel);
    await closeAndSettle(channel);

    expect(dbState.deletedTransfers).toEqual([]);
  });

  // Control for the zero-progress branch: an authenticated key advanced before
  // the first storage write, so there is no progress row to consult.
  test("a bare remote close preserves a transfer that holds a key before its first write", async () => {
    dbState.messageData = undefined;
    const { channel, epc } = await openReceivingChannel();
    epc.messageKeyByMerkleRoot = new Map([[MERKLE_ROOT_HEX, "cache-key"]]);

    await closeAndSettle(channel);

    expect(dbState.deletedTransfers).toEqual([]);
  });

  test("a close THIS side performed does not delete a zero-byte transfer that holds a key", async () => {
    dbState.messageData = undefined;
    const { channel, epc } = await openReceivingChannel();
    epc.messageKeyByMerkleRoot = new Map([[MERKLE_ROOT_HEX, "cache-key"]]);

    markChannelClosedLocally(channel);
    await closeAndSettle(channel);

    expect(dbState.deletedTransfers).toEqual([]);
  });
});
