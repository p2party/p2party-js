/// <reference types="bun" />
// Client-side cost of one window's whole scan: decode + trial-open of all 40
// carrier objects of the pinned profile, every open failing (which is what
// 39 of 40 objects in a real window are). Runs under bun, not Chromium.
import { loadTestModule } from "../../../src/cryptography/testModule";
import {
  CARRIER_AEAD_SUITE_1_NONCE_BYTES,
  buildCarrierPlaintext,
  createCarrierAeadProvider,
  decodeCarrierEnvelope,
  encodeCarrierEnvelope,
  openCarrierEnvelope,
  sealCarrierEnvelope,
} from "../../../src/blindRendezvous/carrierEnvelope";
import { PROTOTYPE_DELIVERY_PROFILE_V0 as P } from "../../../src/blindRendezvous/prototype/profile";

const module = await loadTestModule();
const aead = createCarrierAeadProvider(module);
const rnd = (n: number) => crypto.getRandomValues(new Uint8Array(n));

const PROFILE_HASH = rnd(32);
const CONTEXT = rnd(32);
const WINDOW = 447_215_000n;
const otherRoomRoot = rnd(32); // the bucket belongs to other rooms
const myRoomRoot = rnd(32); // ours opens nothing in it

const objects: { sizeClass: number; bytes: Uint8Array }[] = [];
for (const sc of P.sizeClasses)
  for (let i = 0; i < sc.publicChunksPerWindow * P.publicChunkObjectCount; i++)
    objects.push({
      sizeClass: sc.id,
      bytes: encodeCarrierEnvelope(
        await sealCarrierEnvelope(
          otherRoomRoot,
          {
            deliveryProfileHash: PROFILE_HASH,
            carrierContextId: CONTEXT,
            ingressWindow: WINDOW,
            sizeClass: sc.id,
          },
          rnd(CARRIER_AEAD_SUITE_1_NONCE_BYTES),
          buildCarrierPlaintext(rnd(64), sc.fixedCarrierObjectBytes),
          aead,
        ),
      ),
    });

const wire = objects.reduce((sum, o) => sum + o.bytes.length, 0);
console.log(
  `${String(objects.length)} objects, ${String(wire)} wire bytes per store`,
);

const N = Number(Bun.argv[2] ?? 20);
const samples: number[] = [];
for (let run = 0; run < N; run++) {
  const t0 = performance.now();
  let opened = 0;
  for (const object of objects) {
    const envelope = decodeCarrierEnvelope(object.bytes);
    if (
      envelope.ingressWindow !== WINDOW ||
      envelope.sizeClass !== object.sizeClass
    )
      throw new Error("header check failed");
    if ((await openCarrierEnvelope(myRoomRoot, envelope, aead)) !== null)
      opened++;
  }
  if (opened !== 0) throw new Error("an object opened; the benchmark is wrong");
  samples.push(performance.now() - t0);
}
samples.sort((a, b) => a - b);
const f = (x: number) => x.toFixed(2);
console.log(
  `scan of one store's window: n=${String(N)}  min ${f(samples[0])}  p50 ${f(samples[Math.floor(N / 2)])}  max ${f(samples[N - 1])} ms`,
);
