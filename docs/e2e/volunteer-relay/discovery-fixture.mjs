import { generateKeyPairSync } from "node:crypto";
import { discoverRoute, signOffer } from "./discovery.mjs";
import { paidRecordBytes, providerId } from "./payment-protocol.mjs";

// Loopback lab candidates. The graph is a configured test topology with the
// same synthetic link cost for each edge, not an observed Internet directory.
export function createLocalDirectory() {
  const scope = "loopback-bundle";
  const roles = ["B", "D", "E"];
  const keys = new Map(roles.map((r) => [r, generateKeyPairSync("ml-dsa-65")]));
  const ids = new Map(roles.map((r) => [providerId(keys.get(r).publicKey), r]));
  const pins = new Map([...ids].map(([id, r]) => [id, keys.get(r).publicKey]));
  const links = new Map(
    ["sender", ...ids.keys()].map((from) => [
      from,
      new Map(
        [...ids.keys(), "recipient"]
          .filter((to) => to !== from)
          .map((to) => [to, 1]),
      ),
    ]),
  );
  const advertisements = [...ids].map(([provider, r]) =>
    signOffer(
      {
        scope,
        provider,
        price: 1,
        availableBytes: paidRecordBytes,
        sequence: 1,
        expires: Date.now() + 300000,
      },
      keys.get(r).privateKey,
    ),
  );
  const uses = new Map();
  return {
    keys,
    recordDelivered(roles) {
      for (const r of roles) {
        const id = providerId(keys.get(r).publicKey);
        uses.set(id, (uses.get(id) ?? 0) + 1);
      }
    },
    find({ hops, cap }) {
      const result = discoverRoute(
        { scope, links, pins, advertisements, uses },
        { hops, cap, now: Date.now(), bytes: paidRecordBytes },
      );
      return (
        result && {
          chosen: result.providers.map((id) => ids.get(id)),
          cap,
          total: result.price,
        }
      );
    },
  };
}
