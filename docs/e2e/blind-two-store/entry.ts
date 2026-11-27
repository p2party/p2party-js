// Browser entry for the two-store blind-rendezvous end-to-end harness.
//
// Bundled with `bash docs/e2e/blind-two-store/build.sh` and driven from
// Playwright by `run.mjs`: one page per endpoint, both holding the same room
// capability, both pointed at the same store origins. Everything the run
// proves happens inside these pages — the driver only starts them, ferries
// text in and out, and reads the audit.
//
//   window.__blind.run(optionsJson)   // start this endpoint; resolves once armed
//   window.__blind.send(text)         // waits for handoff, then one encrypted message
//   window.__blind.recv(timeoutMs)    // one decrypted message, as text
//   window.__blind.audit()            // the room secrets the wire log must not hold
//   window.__blind.topology()         // "multi-store-union" | ... , as observed
//   window.__blind.faults()           // store faults, JSON-safe
//   window.__blind.counters()         // carrier counters (appends, scans, backfills)
//   window.__blind.events()           // every event so far, if the driver missed some
//   window.__blind.stop()
//
// Progress is pushed to `window.__blindEvent(json)` when the driver exposed
// one; the page still works standalone when it did not.
import { runBlindRendezvousPrototype } from "../../../src/blindRendezvous/prototype";

import type { CarrierCounters } from "../../../src/blindRendezvous/prototype/carrierRuntime";
import type { PrototypeDeliveryProfileName } from "../../../src/blindRendezvous/prototype/profile";
import type {
  PrototypeRun,
  PrototypeRunAudit,
  PrototypeRunEvent,
} from "../../../src/blindRendezvous/prototype";

/** Long enough to cross the five dependent delivery windows of a rendezvous. */
const DEFAULT_PHASE_TIMEOUT_MS = 180_000;

const te = new TextEncoder();
const td = new TextDecoder();

interface BlindRunOptionsJson {
  /** 32 bytes, as lowercase hex or standard base64. Exactly one is required. */
  readonly capabilityHex?: string;
  readonly capabilityBase64?: string;
  readonly storeOrigins: readonly string[];
  readonly rtcConfig?: RTCConfiguration;
  /** Decimal string or number; a bigint cannot travel through JSON. */
  readonly deliveryWindowMs?: string | number;
  readonly deliveryProfile?: PrototypeDeliveryProfileName;
  /** Defaults to the copy `build.sh` places beside the bundle. */
  readonly wasmUrl?: string;
}

interface BlindFaultJson {
  readonly storeIdHex: string;
  readonly kind: string;
  readonly window: string | null;
  readonly detail: string;
}

const fromHex = (value: string): Uint8Array => {
  if (value.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(value))
    throw new Error("capabilityHex is not hex");
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1)
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  return bytes;
};

const fromBase64 = (value: string): Uint8Array => {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1)
    bytes[index] = binary.charCodeAt(index);
  return bytes;
};

const capabilityOf = (options: BlindRunOptionsJson): Uint8Array => {
  if (options.capabilityHex !== undefined)
    return fromHex(options.capabilityHex);
  if (options.capabilityBase64 !== undefined)
    return fromBase64(options.capabilityBase64);
  throw new Error("run() needs capabilityHex or capabilityBase64");
};

const loadWasm = async (url: string): Promise<ArrayBuffer> => {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`${url} fetch failed: ${response.status}`);
  return response.arrayBuffer();
};

/* ------------------------------------------------------------------ *
 * One run per page
 * ------------------------------------------------------------------ */

let active: PrototypeRun | null = null;
const events: PrototypeRunEvent[] = [];

const activeRun = (): PrototypeRun => {
  if (active === null) throw new Error("__blind.run() has not been called");
  return active;
};

const publish = (event: PrototypeRunEvent): void => {
  events.push(event);
  const sink = window.__blindEvent;
  if (typeof sink !== "function") return;
  // Fire and forget: `exposeFunction` bindings are async, and a rendezvous
  // must never wait on its own instrumentation.
  void Promise.resolve(sink(JSON.stringify(event))).catch(() => undefined);
};

const run = async (optionsJson: string): Promise<{ started: true }> => {
  if (active !== null) throw new Error("__blind.run() was already called");
  const options = JSON.parse(optionsJson) as BlindRunOptionsJson;
  const wasmBinary = await loadWasm(options.wasmUrl ?? "./libcrypto.wasm");

  active = await runBlindRendezvousPrototype({
    capability: capabilityOf(options),
    storeOrigins: options.storeOrigins,
    wasmBinary,
    rtcConfig: options.rtcConfig ?? { iceServers: [] },
    ...(options.deliveryProfile === undefined
      ? {}
      : { deliveryProfile: options.deliveryProfile }),
    ...(options.deliveryWindowMs === undefined
      ? {}
      : { deliveryWindowMs: BigInt(options.deliveryWindowMs) }),
    onEvent: publish,
  });
  return { started: true };
};

const send = async (
  text: string,
  timeoutMs: number = DEFAULT_PHASE_TIMEOUT_MS,
): Promise<{ bytes: number }> => {
  const current = activeRun();
  // The pair exchange takes five delivery windows; a caller that says "send"
  // means "send once there is somewhere to send it".
  await current.waitForPhase("handoff", timeoutMs);
  const bytes = te.encode(text);
  await current.sendMessage(bytes, timeoutMs);
  return { bytes: bytes.length };
};

const recv = async (
  timeoutMs: number = DEFAULT_PHASE_TIMEOUT_MS,
): Promise<string> => td.decode(await activeRun().recvMessage(timeoutMs));

const audit = (): PrototypeRunAudit => activeRun().auditSecrets();

const topology = (): string => activeRun().storeTopology();

const faults = (): readonly BlindFaultJson[] =>
  activeRun()
    .faults()
    .map((fault) => ({
      storeIdHex: fault.storeIdHex,
      kind: fault.kind,
      window: fault.window === null ? null : String(fault.window),
      detail: fault.detail,
    }));

/**
 * The carrier runtime's own counters, so a scenario can assert on replication
 * rather than on a log line. `unreachable-b-for-one` needs `backfills`: it is
 * the only observable that says the page which reached both stores really did
 * carry the other page's operations to the store the other page never saw.
 * Every field is a plain `number`, so this crosses the Playwright bridge as is.
 */
const counters = (): CarrierCounters => activeRun().runtime.counters;

const stop = (): { stopped: true } => {
  active?.stop();
  return { stopped: true };
};

declare global {
  interface Window {
    __blind: {
      run: (optionsJson: string) => Promise<{ started: true }>;
      send: (text: string, timeoutMs?: number) => Promise<{ bytes: number }>;
      recv: (timeoutMs?: number) => Promise<string>;
      audit: () => PrototypeRunAudit;
      topology: () => string;
      faults: () => readonly BlindFaultJson[];
      counters: () => CarrierCounters;
      events: () => readonly PrototypeRunEvent[];
      stop: () => { stopped: true };
    };
    /** Exposed by the Playwright driver; absent when the page runs alone. */
    __blindEvent?: (json: string) => unknown;
  }
}

window.__blind = {
  run,
  send,
  recv,
  audit,
  topology,
  faults,
  counters,
  events: () => events,
  stop,
};
