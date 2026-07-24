#!/usr/bin/env node

import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(scriptDirectory, "..");
const packageJsonPath = path.join(projectRoot, "package.json");
const packageJson = JSON.parse(readFileSync(packageJsonPath, "utf8"));
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const sourceDateEpoch = process.env.SOURCE_DATE_EPOCH ?? "0";
const expectedNodeMajor = 24;
const expectedEmscriptenVersion = "6.0.2";
const expectedLibsodiumCommit = "2ce4d906a68eae82b27b4867f3d4172ec508cb27";
const expectedLibsodiumTree = "2dabe17c708edd7334e3316b5094b753859395d9";
const expectedMlkemNativeCommit = "0ba906cb14b1c241476134d7403a811b382ca498";
const expectedMlkemNativeSourceTreeSha256 =
  "a2e15382a8dc0207752b3f5cdfc907886505fe304948183b4b61e99e7cb92ac6";
const expectedMlkemWrapperSha256 =
  "181160a16f22e30eafc85d7be7a3be47be41026da14b0488f120ededc36ea072";
const expectedRoomWordlistSha256 =
  "531238ede7be78f5fd444b3a4452b023f408f0146aa82bd9fe03aad902b3ff8e";
const releaseRoot = mkdtempSync(
  path.join(realpathSync(tmpdir()), "p2party-release-"),
);
const stageRoot = path.join(releaseRoot, "package");
const stageLib = path.join(stageRoot, "lib");
const packedRoot = path.join(releaseRoot, "packed");
const npmCache = path.join(releaseRoot, "npm-cache");
const emscriptenCache = path.join(releaseRoot, "emscripten-cache");
const releaseBuildEnvironment = {
  P2PARTY_ANALYZE: "false",
  P2PARTY_OUTPUT_DIR: stageLib,
};

const run = (command, args, options = {}) =>
  execFileSync(command, args, {
    cwd: options.cwd ?? projectRoot,
    env: {
      ...process.env,
      SOURCE_DATE_EPOCH: sourceDateEpoch,
      ...options.env,
    },
    maxBuffer: 64 * 1024 * 1024,
    stdio: options.capture ? ["ignore", "pipe", "inherit"] : "inherit",
    encoding: options.capture ? "utf8" : undefined,
  });

const sha = (algorithm, bytes) =>
  createHash(algorithm).update(bytes).digest("hex");

const sri = (bytes) =>
  `sha384-${createHash("sha384").update(bytes).digest("base64")}`;

const listFiles = (root, current = root) =>
  readdirSync(current, { withFileTypes: true })
    .flatMap((entry) => {
      const absolutePath = path.join(current, entry.name);
      return entry.isDirectory()
        ? listFiles(root, absolutePath)
        : [path.relative(root, absolutePath).split(path.sep).join("/")];
    })
    .sort();

const digestFiles = (root, relativePaths) => {
  const hash = createHash("sha256");
  for (const relativePath of relativePaths) {
    const bytes = readFileSync(path.join(root, relativePath));
    const byteLength = Buffer.alloc(8);
    byteLength.writeBigUInt64BE(BigInt(bytes.byteLength));
    hash.update(relativePath);
    hash.update(Buffer.from([0]));
    hash.update(byteLength);
    hash.update(bytes);
  }
  return hash.digest("hex");
};

const fail = (message) => {
  throw new Error(`release validation failed: ${message}`);
};

const requireFile = (relativePath) => {
  const absolutePath = path.join(stageRoot, relativePath);
  if (!existsSync(absolutePath)) fail(`missing ${relativePath}`);
  return absolutePath;
};

const exportedTargets = (exportsField) => {
  const targets = [];
  const visit = (value) => {
    if (typeof value === "string") {
      targets.push(value);
      return;
    }
    if (value && typeof value === "object")
      for (const nested of Object.values(value)) visit(nested);
  };
  visit(exportsField);
  return targets;
};

const validateWasmGlue = async (wasmBytes) => {
  const require = createRequire(import.meta.url);
  const gluePath = path.join(
    projectRoot,
    "src",
    "cryptography",
    "libcrypto.js",
  );
  delete require.cache[require.resolve(gluePath)];
  const factory = require(gluePath);
  const cryptoModule = await factory({
    wasmBinary: wasmBytes,
    wasmMemory: new WebAssembly.Memory({
      initial: 32,
      maximum: 16_384,
    }),
  });
  const requiredCryptoExports = [
    "_crypto_init",
    "_cpace_ristretto255_from_hash",
    "_cpace_ristretto255_scalarmult",
    "_cpace_ristretto255_scalar_random",
    "_x25519_keypair",
    "_x25519_dh",
    "_hkdf_sha512_extract",
    "_hkdf_sha512_expand",
    "_encrypt_chachapoly_symmetric",
    "_decrypt_chachapoly_symmetric",
    "_receive_message_with_key",
    "_mlkem512_keypair",
    "_mlkem512_encaps",
    "_mlkem512_decaps",
    "_mlkem768_keypair",
    "_mlkem768_encaps",
    "_mlkem768_decaps",
    "_mlkem1024_keypair",
    "_mlkem1024_encaps",
    "_mlkem1024_decaps",
  ];
  for (const name of requiredCryptoExports)
    if (typeof cryptoModule[name] !== "function")
      fail(`generated glue/WASM pair is missing ${name}`);
  if (cryptoModule._crypto_init() !== 0)
    fail("configured libsodium runtime did not initialize");
};

const validateCryptoProvenance = (provenance, wasmBytes) => {
  if (provenance.schemaVersion !== 1)
    fail("crypto provenance has an unsupported schema version");
  if (provenance.sources?.libsodium?.commit !== expectedLibsodiumCommit)
    fail("crypto provenance has an unexpected libsodium commit");
  if (provenance.sources?.libsodium?.tree !== expectedLibsodiumTree)
    fail("crypto provenance has an unexpected libsodium tree");
  if (provenance.sources?.libsodium?.configuredBuild !== true)
    fail("crypto provenance does not attest a configured libsodium build");
  if (provenance.sources?.mlkemNative?.commit !== expectedMlkemNativeCommit)
    fail("crypto provenance has an unexpected mlkem-native commit");
  if (
    provenance.sources?.mlkemNative?.sourceTreeSha256 !==
    expectedMlkemNativeSourceTreeSha256
  )
    fail("crypto provenance has an unexpected mlkem-native source-tree digest");
  if (
    provenance.sources?.mlkemNative?.wrapperSha256 !==
    expectedMlkemWrapperSha256
  )
    fail("crypto provenance has an unexpected ML-KEM wrapper digest");
  if (
    JSON.stringify(provenance.sources?.mlkemNative?.parameterSets) !==
    JSON.stringify([512, 768, 1024])
  )
    fail("crypto provenance does not attest all ML-KEM parameter sets");
  if (provenance.sources?.mlkemNative?.multilevel?.shared !== 768)
    fail("crypto provenance has an unexpected shared ML-KEM build");
  if (
    JSON.stringify(provenance.sources?.mlkemNative?.multilevel?.noShared) !==
    JSON.stringify([512, 1024])
  )
    fail("crypto provenance has unexpected no-shared ML-KEM builds");
  if (provenance.build?.mode !== "production")
    fail("crypto provenance is not for a production build");
  if (provenance.build?.linkTimeOptimization !== false)
    fail("crypto provenance does not attest that LTO is disabled");
  if (provenance.build?.publicSodiumApi !== true)
    fail("crypto provenance does not attest public libsodium API use");
  if (
    !new RegExp(
      `\\b${expectedEmscriptenVersion.replaceAll(".", "\\.")}(?:-git)?\\b`,
    ).test(provenance.toolchain?.emscripten ?? "")
  )
    fail("crypto provenance has an unexpected Emscripten version");
  if (provenance.artifact?.bytes !== wasmBytes.byteLength)
    fail("crypto provenance has an incorrect WASM byte length");
  if (provenance.artifact?.sha256 !== sha("sha256", wasmBytes))
    fail("crypto provenance has an incorrect WASM SHA-256");
  if (provenance.artifact?.sri !== sri(wasmBytes))
    fail("crypto provenance has an incorrect WASM SRI");
};

const validateBundle = (
  relativePath,
  expectedIntegrity,
  expectedPublicNames = [],
) => {
  const source = readFileSync(requireFile(relativePath), "utf8");
  if (!source.includes(packageJson.version))
    fail(
      `${relativePath} does not embed package version ${packageJson.version}`,
    );
  if (!source.includes(expectedIntegrity))
    fail(`${relativePath} does not embed the current WASM SRI`);
  for (const staleVersion of ["0.9.0", "0.9.1", "0.9.2", "0.10.0", "0.11.0"])
    if (source.includes(`cdn.p2party.com/@${staleVersion}/libcrypto.wasm`))
      fail(`${relativePath} embeds stale CDN version ${staleVersion}`);
  for (const name of [
    "_mlkem512_keypair",
    "_mlkem512_encaps",
    "_mlkem512_decaps",
    "_mlkem768_keypair",
    "_mlkem768_encaps",
    "_mlkem768_decaps",
    "_mlkem1024_keypair",
    "_mlkem1024_encaps",
    "_mlkem1024_decaps",
  ])
    if (!source.includes(name)) fail(`${relativePath} is missing ${name}`);
  for (const name of expectedPublicNames)
    if (!source.includes(name))
      fail(`${relativePath} is missing public API ${name}`);
};

const validateSessionSurface = async () => {
  const wasmBinary = readFileSync(requireFile("lib/libcrypto.wasm"));
  const esm = await import(
    `${pathToFileURL(requireFile("lib/session.mjs")).href}?release=${Date.now()}`
  );
  const require = createRequire(import.meta.url);
  const cjs = require(requireFile("lib/session.js"));
  for (const [format, module] of [
    ["ESM", esm],
    ["CommonJS", cjs],
  ])
    for (const name of [
      "createSession",
      "restoreSession",
      "generateSessionIdentity",
    ])
      if (typeof module[name] !== "function")
        fail(`${format} session export is missing ${name}`);

  for (const [format, module] of [
    ["ESM", esm],
    ["CommonJS", cjs],
  ]) {
    const identity = await module.generateSessionIdentity({ wasmBinary });
    if (
      identity.ed25519PublicKey?.byteLength !== 32 ||
      identity.ed25519SecretKey?.byteLength !== 64 ||
      identity.x25519PublicKey?.byteLength !== 32 ||
      identity.x25519SecretKey?.byteLength !== 32 ||
      identity.x25519CrossSignature?.byteLength !== 64
    )
      fail(`${format} session identity smoke returned malformed key material`);
    identity.ed25519SecretKey.fill(0);
    identity.x25519SecretKey.fill(0);
  }
};

const validatePackList = (packResult) => {
  const paths = new Set(packResult.files.map(({ path: filePath }) => filePath));
  const required = [
    "package.json",
    "README.md",
    "LICENSE.md",
    "THIRD_PARTY_NOTICES.md",
    "docs/getting-started.md",
    "docs/session-api.md",
    "docs/protocol-v3-security.md",
    "examples/standalone-e2ee.ts",
    "lib/index.js",
    "lib/index.mjs",
    "lib/index.min.js",
    "lib/index.d.ts",
    "lib/session.js",
    "lib/session.mjs",
    "lib/session.d.ts",
    "lib/db.worker.js",
    "lib/libcrypto.wasm",
    "lib/libcrypto.provenance.json",
  ];
  for (const requiredPath of required)
    if (!paths.has(requiredPath)) fail(`tarball is missing ${requiredPath}`);

  const exactFiles = new Set(required);
  for (const filePath of paths) {
    if (exactFiles.has(filePath)) continue;
    if (/^lib\/.+\.d\.ts$/u.test(filePath)) continue;
    fail(`tarball unexpectedly contains ${filePath}`);
  }
};

const runtimeArtifacts = [
  "db.worker.js",
  "index.js",
  "index.mjs",
  "index.min.js",
  "session.js",
  "session.mjs",
  "libcrypto.wasm",
  "libcrypto.provenance.json",
];

try {
  mkdirSync(stageLib, { recursive: true });
  mkdirSync(packedRoot, { recursive: true });
  mkdirSync(path.join(stageRoot, "docs"), { recursive: true });
  mkdirSync(path.join(stageRoot, "examples"), { recursive: true });

  const mlkemSourceRoot = path.join(
    projectRoot,
    "src",
    "cryptography",
    "vendor",
    "mlkem-native",
    "mlkem",
  );
  if (
    digestFiles(mlkemSourceRoot, listFiles(mlkemSourceRoot)) !==
    expectedMlkemNativeSourceTreeSha256
  )
    fail("the vendored mlkem-native source tree does not match its pin");
  const mlkemBuildRoot = path.join(projectRoot, "src", "cryptography");
  const mlkemWrapperFiles = [512, 768, 1024]
    .flatMap((parameterSet) => [
      `mlkem${parameterSet}.c`,
      `mlkem${parameterSet}.h`,
    ])
    .sort();
  if (
    digestFiles(mlkemBuildRoot, mlkemWrapperFiles) !==
    expectedMlkemWrapperSha256
  )
    fail("the p2party ML-KEM wrappers do not match their pin");
  if (
    sha(
      "sha256",
      readFileSync(path.join(projectRoot, "src", "utils", "wordlist.json")),
    ) !== expectedRoomWordlistSha256
  )
    fail("the BIP39 English room wordlist does not match its pin");

  const nodeMajor = Number.parseInt(process.versions.node, 10);
  if (nodeMajor !== expectedNodeMajor)
    fail(
      `Node ${expectedNodeMajor}.x is required; found ${process.versions.node}`,
    );
  const emscriptenBanner = run("emcc", ["--version"], { capture: true });
  if (
    !new RegExp(
      `\\b${expectedEmscriptenVersion.replaceAll(".", "\\.")}(?:-git)?\\b`,
    ).test(emscriptenBanner)
  )
    fail(
      `Emscripten ${expectedEmscriptenVersion} is required; found ${emscriptenBanner.split("\n", 1)[0]}`,
    );

  console.log("[1/6] Compile production WASM and update its pinned SRI");
  run(npm, ["run", "--silent", "predist"], {
    env: { EM_CACHE: emscriptenCache },
  });

  console.log("[2/6] Build the IndexedDB worker into a fresh staging tree");
  run(npm, ["run", "--silent", "dist:worker"], {
    env: releaseBuildEnvironment,
  });

  console.log("[3/6] Build root and store-free session packages");
  run(npm, ["run", "--silent", "dist:package"], {
    env: releaseBuildEnvironment,
  });

  console.log("[4/6] Copy and validate the exact WASM artifact");
  const sourceWasmPath = path.join(
    projectRoot,
    "src",
    "cryptography",
    "libcrypto.wasm",
  );
  const packagedWasmPath = path.join(stageLib, "libcrypto.wasm");
  const sourceProvenancePath = path.join(
    projectRoot,
    "src",
    "cryptography",
    "libcrypto.provenance.json",
  );
  const packagedProvenancePath = path.join(
    stageLib,
    "libcrypto.provenance.json",
  );
  const sourceWasm = readFileSync(sourceWasmPath);
  const sourceProvenanceBytes = readFileSync(sourceProvenancePath);
  const sourceProvenance = JSON.parse(sourceProvenanceBytes.toString("utf8"));
  validateCryptoProvenance(sourceProvenance, sourceWasm);
  copyFileSync(sourceWasmPath, packagedWasmPath);
  copyFileSync(sourceProvenancePath, packagedProvenancePath);
  const packagedWasm = readFileSync(packagedWasmPath);
  if (!sourceWasm.equals(packagedWasm))
    fail("packaged WASM differs from the just-compiled source artifact");

  const expectedIntegrity = sri(sourceWasm);
  const loaderSource = readFileSync(
    path.join(projectRoot, "src", "cryptography", "wasmLoader.ts"),
    "utf8",
  );
  if (!loaderSource.includes(expectedIntegrity))
    fail("wasmLoader.ts SRI does not match the just-compiled WASM");
  if (
    !loaderSource.includes(
      `process.env.P2PARTY_VERSION ?? "${packageJson.version}"`,
    )
  )
    fail("wasmLoader.ts fallback version does not match package.json");

  await validateWasmGlue(sourceWasm);

  for (const fileName of [
    "package.json",
    "README.md",
    "LICENSE.md",
    "THIRD_PARTY_NOTICES.md",
  ])
    copyFileSync(
      path.join(projectRoot, fileName),
      path.join(stageRoot, fileName),
    );

  for (const fileName of [
    "getting-started.md",
    "session-api.md",
    "protocol-v3-security.md",
  ])
    copyFileSync(
      path.join(projectRoot, "docs", fileName),
      path.join(stageRoot, "docs", fileName),
    );

  copyFileSync(
    path.join(projectRoot, "examples", "standalone-e2ee.ts"),
    path.join(stageRoot, "examples", "standalone-e2ee.ts"),
  );

  for (const target of exportedTargets(packageJson.exports)) {
    if (!target.startsWith("./"))
      fail(`package export is not relative: ${target}`);
    requireFile(target.slice(2));
  }

  for (const bundle of ["lib/index.js", "lib/index.mjs", "lib/index.min.js"])
    validateBundle(bundle, expectedIntegrity, ["setWasmSourceUrl"]);
  for (const bundle of ["lib/session.js", "lib/session.mjs"])
    validateBundle(bundle, expectedIntegrity);
  await validateSessionSurface();

  console.log("[5/6] Pack the validated staging tree");
  const packJson = run(
    npm,
    ["pack", "--json", "--ignore-scripts", "--pack-destination", packedRoot],
    {
      cwd: stageRoot,
      env: { npm_config_cache: npmCache },
      capture: true,
    },
  );
  const [packResult] = JSON.parse(packJson);
  if (!packResult || packResult.version !== packageJson.version)
    fail("npm pack reported an unexpected package version");
  validatePackList(packResult);

  console.log(
    "[6/6] Verify archived bytes and publish the validated artifacts",
  );
  const stagedTarball = path.join(packedRoot, packResult.filename);
  const archivedWasm = execFileSync(
    "tar",
    ["-xOf", stagedTarball, "package/lib/libcrypto.wasm"],
    { maxBuffer: 8 * 1024 * 1024 },
  );
  if (!sourceWasm.equals(archivedWasm))
    fail("WASM bytes changed while packing the tarball");
  const archivedProvenance = execFileSync(
    "tar",
    ["-xOf", stagedTarball, "package/lib/libcrypto.provenance.json"],
    { maxBuffer: 1024 * 1024 },
  );
  if (!sourceProvenanceBytes.equals(archivedProvenance))
    fail("crypto provenance changed while packing the tarball");

  const projectLib = path.join(projectRoot, "lib");
  mkdirSync(projectLib, { recursive: true });
  for (const fileName of runtimeArtifacts)
    copyFileSync(
      path.join(stageLib, fileName),
      path.join(projectLib, fileName),
    );

  const finalTarball = path.join(projectRoot, packResult.filename);
  copyFileSync(stagedTarball, finalTarball);
  const tarballBytes = readFileSync(finalTarball);

  console.log("");
  console.log(`Release package: ${finalTarball}`);
  console.log(`Package files: ${packResult.entryCount}`);
  console.log(`WASM bytes: ${sourceWasm.byteLength}`);
  console.log(`WASM SHA-256: ${sha("sha256", sourceWasm)}`);
  console.log(`WASM SRI: ${expectedIntegrity}`);
  console.log(`libsodium commit: ${expectedLibsodiumCommit}`);
  console.log(`libsodium tree: ${expectedLibsodiumTree}`);
  console.log(`Tarball SHA-256: ${sha("sha256", tarballBytes)}`);
  console.log(`Tarball SHA-512: ${sha("sha512", tarballBytes)}`);
} finally {
  rmSync(releaseRoot, { recursive: true, force: true });
}
