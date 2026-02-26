#!/usr/bin/env node
// ============================================================================
// Update the SRI integrity hash in wasmLoader.ts after emscripten rebuilds
// the WASM binary. Runs automatically as part of prebuild / predist.
// ============================================================================
import { readFileSync, writeFileSync } from "fs";
import { createHash } from "crypto";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const wasmPath = resolve(
  __dirname,
  "..",
  "src",
  "cryptography",
  "libcrypto.wasm",
);
const loaderPath = resolve(
  __dirname,
  "..",
  "src",
  "cryptography",
  "wasmLoader.ts",
);

const wasmBytes = readFileSync(wasmPath);
const sha384 = createHash("sha384").update(wasmBytes).digest("base64");
const newIntegrity = `sha384-${sha384}`;

let source = readFileSync(loaderPath, "utf-8");

const integrityRegex = /integrity:\s*\n?\s*"sha384-[A-Za-z0-9+/=]+"/;
if (!integrityRegex.test(source)) {
  // Also try single-line form
  const singleLine = /integrity:\s*"sha384-[A-Za-z0-9+/=]+"/;
  if (!singleLine.test(source)) {
    console.error("Could not find integrity field in wasmLoader.ts");
    process.exit(1);
  }
  source = source.replace(singleLine, `integrity: "${newIntegrity}"`);
} else {
  source = source.replace(
    integrityRegex,
    `integrity:\n      "${newIntegrity}"`,
  );
}

writeFileSync(loaderPath, source, "utf-8");
console.log(`Updated wasmLoader.ts integrity → ${newIntegrity}`);
