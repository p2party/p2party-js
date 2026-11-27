// Local pilot. The native ledger pays an identified input to a fresh output.
// The quote, ordered path, delivery challenge and acknowledgments stay off-chain.
import { createHash, createPublicKey, sign, verify } from "node:crypto";
import { DatabaseSync } from "node:sqlite";

export const paidRecordBytes = 65559;
const domain = (label) =>
  Buffer.from("p2party/local-paid-relay/" + label + "/v1\0");
export const digest = (label, ...parts) =>
  createHash("sha512")
    .update(Buffer.concat([domain(label), ...parts]))
    .digest("hex");

function bytes(hex, size) {
  if (
    typeof hex !== "string" ||
    hex.length !== size * 2 ||
    !/^[0-9a-f]+$/.test(hex)
  )
    throw new Error("Invalid fixed-width hex");
  return Buffer.from(hex, "hex");
}
function u64(n) {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error("Invalid integer");
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
}
function nativeHex(value, size) {
  if (typeof value !== "string" || !value.startsWith("0x"))
    throw new Error("Invalid native field");
  return bytes(value.slice(2), size);
}
function asKeyId(key) {
  if (key.type !== "public" || key.asymmetricKeyType !== "ml-dsa-65")
    throw new Error("Expected pinned ML-DSA-65 quote key");
  return digest("provider-key", key.export({ type: "spki", format: "der" }));
}
export { asKeyId as providerId };

export function routeId(r) {
  if (
    r.hops.length < 2 ||
    r.hops.length > 8 ||
    !Number.isSafeInteger(r.budget) ||
    r.budget < r.hops.length
  )
    throw new Error("Invalid route or budget");
  const parts = [
    nativeHex(r.chainId, 32),
    bytes(r.genesis, 32),
    bytes(r.nonce, 32),
    bytes(r.payer, 32),
    bytes(r.recipient, 32),
    bytes(r.receiptKey, 32),
    bytes(r.challengeHash, 64),
    bytes(r.contentHash, 64),
    u64(r.until),
    u64(r.expiryHeight),
    u64(r.budget),
    u64(paidRecordBytes),
    u64(r.hops.length),
  ];
  if (r.payer === r.recipient) throw new Error("Endpoints must be distinct");
  for (const field of [
    "provider",
    "browserKey",
    "witnessKey",
    "inputId",
    "commitment",
  ]) {
    if (new Set(r.hops.map((h) => h[field])).size !== r.hops.length)
      throw new Error("Each hop needs a distinct " + field);
  }
  for (const h of r.hops) {
    if (
      h.witnessKey === r.receiptKey ||
      h.browserKey === r.payer ||
      h.browserKey === r.recipient ||
      ![1, 2].includes(h.suite) ||
      h.reward !== 1
    )
      throw new Error("Invalid relay quote terms");
    parts.push(
      bytes(h.provider, 64),
      bytes(h.browserKey, 32),
      bytes(h.witnessKey, 32),
      nativeHex(h.inputId, 64),
      Buffer.from([h.suite]),
      nativeHex(h.commitment, 64),
      u64(h.reward),
    );
  }
  return digest("request", ...parts);
}
const quoteBytes = (id, index) =>
  Buffer.concat([domain("quote"), bytes(id, 64), u64(index)]);
export function signQuote(r, index, key) {
  if (
    !r.hops[index] ||
    r.hops[index].provider !== asKeyId(createPublicKey(key))
  )
    throw new Error("Quote provider mismatch");
  return sign(null, quoteBytes(routeId(r), index), key).toString("hex");
}
export function checkQuotes(r, quotes, pins) {
  const id = routeId(r);
  if (quotes.length !== r.hops.length || pins.length !== quotes.length)
    throw new Error("Incomplete route");
  for (const [i, h] of r.hops.entries()) {
    if (
      h.provider !== asKeyId(pins[i]) ||
      !verify(null, quoteBytes(id, i), pins[i], bytes(quotes[i], 3309))
    )
      throw new Error("Invalid signed relay quote");
  }
  return id;
}
function verifyReceipt(keyHex, label, binding, signature) {
  const key = createPublicKey({
    key: {
      kty: "OKP",
      crv: "Ed25519",
      x: bytes(keyHex, 32).toString("base64url"),
    },
    format: "jwk",
  });
  if (
    !verify(
      null,
      Buffer.concat([domain(label), binding]),
      key,
      bytes(signature, 64),
    )
  )
    throw new Error("Invalid " + label + " receipt");
}
export function verifyDelivery(r, ack, recordHash) {
  const binding = bytes(ack.binding, 224);
  if (
    routeId(r) !== binding.subarray(0, 64).toString("hex") ||
    digest("challenge", binding.subarray(64, 96)) !== r.challengeHash ||
    binding.subarray(96, 160).toString("hex") !== r.contentHash ||
    !binding.subarray(160).equals(bytes(recordHash, 64))
  )
    throw new Error("Wrong order, challenge, content or ciphertext");
  verifyReceipt(r.receiptKey, "delivered", binding, ack.signature);
}
export function verifyForwarding(r, recordHash, witnesses) {
  if (!Array.isArray(witnesses) || witnesses.length !== r.hops.length)
    throw new Error("Missing forwarding observations");
  const order = bytes(routeId(r), 64),
    record = bytes(recordHash, 64);
  for (const [i, h] of r.hops.entries()) {
    verifyReceipt(
      h.witnessKey,
      "forwarded",
      Buffer.concat([order, u64(i), record]),
      witnesses[i],
    );
  }
}

// FULL-synchronous, all-hop preparation precedes submission. After response
// loss the same signed native bytes can be retried, including from a new process.
export class PayoutJournal {
  constructor(file) {
    this.db = new DatabaseSync(file);
    this.db.exec(
      "PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS payments (route TEXT NOT NULL, hop INTEGER NOT NULL, input TEXT UNIQUE NOT NULL, recipient TEXT UNIQUE NOT NULL, wire TEXT NOT NULL, PRIMARY KEY(route, hop))",
    );
  }
  close() {
    this.db.close();
  }
  resume(route) {
    const rows = this.db
      .prepare(
        "SELECT hop, input, recipient, wire FROM payments WHERE route=? ORDER BY hop",
      )
      .all(routeId(route));
    if (
      rows.length !== route.hops.length ||
      rows.some(
        (row, i) =>
          row.hop !== i ||
          row.input !== route.hops[i].inputId ||
          row.recipient !== route.hops[i].commitment,
      )
    )
      throw new Error("No complete authorized purchase");
    return rows.map((row) => row.wire);
  }
  async prepare({
    route,
    quotes,
    pins,
    ack,
    recordHash,
    witnesses,
    signHop,
    now = Date.now(),
  }) {
    const id = checkQuotes(route, quotes, pins);
    verifyDelivery(route, ack, recordHash);
    verifyForwarding(route, recordHash, witnesses);
    const read = () =>
      this.db
        .prepare("SELECT wire FROM payments WHERE route=? ORDER BY hop")
        .all(id)
        .map((row) => row.wire);
    const previous = read();
    if (previous.length === route.hops.length) return previous;
    if (previous.length || now > route.until)
      throw new Error("Incomplete or expired purchase");
    const wires = await Promise.all(route.hops.map(signHop));
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const existing = read();
      if (existing.length === 0) {
        if (Date.now() > route.until)
          throw new Error("Purchase expired before authorization");
        for (const [i, h] of route.hops.entries())
          this.db
            .prepare("INSERT INTO payments VALUES (?,?,?,?,?)")
            .run(id, i, h.inputId, h.commitment, wires[i]);
      } else if (existing.length !== wires.length)
        throw new Error("Incomplete payout journal");
      this.db.exec("COMMIT");
      return existing.length ? existing : wires;
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
  }
}
