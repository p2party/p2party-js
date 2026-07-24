const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");

const { methodsPath, libsodiumRepositoryPath } = require("./paths");

const LIBSODIUM_COMMIT = "2ce4d906a68eae82b27b4867f3d4172ec508cb27";
const LIBSODIUM_TREE = "2dabe17c708edd7334e3316b5094b753859395d9";
const MLKEM_NATIVE_COMMIT = "0ba906cb14b1c241476134d7403a811b382ca498";

const buildPath = path.join(process.cwd(), "src", "cryptography");
const finalJsPath = path.join(buildPath, "libcrypto.js");
const finalWasmPath = path.join(buildPath, "libcrypto.wasm");
const finalTypesPath = path.join(buildPath, "libcrypto.d.ts");
const finalProvenancePath = path.join(buildPath, "libcrypto.provenance.json");
const stagingPath = fs.mkdtempSync(
  path.join(os.tmpdir(), "p2party-libcrypto-"),
);
const stagedJsPath = path.join(stagingPath, "libcrypto.js");
const stagedWasmPath = path.join(stagingPath, "libcrypto.wasm");
const stagedTypesPath = path.join(stagingPath, "libcrypto.d.ts");
const stagedProvenancePath = path.join(
  stagingPath,
  "libcrypto.provenance.json",
);
const libsodiumSourcePath = path.join(stagingPath, "libsodium-source");
const libsodiumInstallPath = path.join(stagingPath, "libsodium-install");
const libsodiumIncludePath = path.join(libsodiumInstallPath, "include");
const libsodiumArchivePath = path.join(
  libsodiumInstallPath,
  "lib",
  "libsodium.a",
);
const mlkem768Path = path.join(buildPath, "mlkem768.c");
const mlkem768IncludePath = path.join(
  buildPath,
  "vendor",
  "mlkem-native",
  "mlkem",
);
const typesPath = path.join(process.cwd(), "scripts", "libcrypto.d.ts");
const types = fs.readFileSync(typesPath);
const buildMode =
  process.env.NODE_ENV === "production" ? "production" : "development";

const run = (command, args, options = {}) =>
  execFileSync(command, args, {
    cwd: options.cwd ?? process.cwd(),
    env: options.env ?? process.env,
    input: options.input,
    maxBuffer: 64 * 1024 * 1024,
    stdio: options.capture
      ? ["ignore", "pipe", "inherit"]
      : options.input
        ? ["pipe", "inherit", "inherit"]
        : "inherit",
    encoding: options.capture ? "utf8" : undefined,
  });

const capture = (command, args, options = {}) =>
  run(command, args, { ...options, capture: true }).trim();

const assertEqual = (actual, expected, description) => {
  if (actual !== expected)
    throw new Error(
      `${description} mismatch: expected ${expected}, received ${actual}`,
    );
};

const sha = (algorithm, bytes, encoding = "hex") =>
  crypto.createHash(algorithm).update(bytes).digest(encoding);

const exportedFunctions = [
  "_malloc",
  "_free",
  "_crypto_init",
  "_sign",
  "_verify",
  "_get_merkle_proof",
  "_get_merkle_root",
  "_get_merkle_root_from_proof",
  "_verify_merkle_proof",
  "_keypair_from_seed",
  "_keypair_from_secret_key",
  "_argon2",
  "_sha512_init",
  "_sha512_update",
  "_sha512_final",
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
  "_mlkem768_keypair",
  "_mlkem768_encaps",
  "_mlkem768_decaps",
];

const emccArgs = [
  "--no-entry",
  "-fno-exceptions",
  "-fno-PIC",
  "-fPIE",
  "-fno-common",
  "-ffunction-sections",
  "-fdata-sections",
  "-fdelete-null-pointer-checks",
  "-fno-asm",
  "-ffinite-loops",
  "-fjump-tables",
  "-fno-keep-static-consts",
  "-fvectorize",
  "-s",
  "STRICT=1",
  "-s",
  "SINGLE_FILE=0",
  "-s",
  "FILESYSTEM=0",
  "-s",
  "SAFE_HEAP=1",
  "-s",
  "CHECK_NULL_WRITES=1",
  "-s",
  "ENVIRONMENT=web,worker",
  "-s",
  "INVOKE_RUN=0",
  "-s",
  "EXIT_RUNTIME=0",
  "-s",
  "IMPORTED_MEMORY=1",
  "-s",
  "ALLOW_MEMORY_GROWTH=1",
  "-s",
  "ABORTING_MALLOC=1",
  "-s",
  "INITIAL_MEMORY=2mb",
  "-s",
  "MAXIMUM_MEMORY=1gb",
  "-s",
  "STACK_SIZE=512kb",
  "-s",
  "GLOBAL_BASE=4096",
  "-s",
  "WASM=1",
  "-s",
  "MODULARIZE=1",
  "-s",
  'INCOMING_MODULE_JS_API=["wasmBinary","wasmMemory"]',
  "-s",
  "POLYFILL=0",
  "-s",
  "NO_DYNAMIC_EXECUTION=1",
  "-s",
  "WEBSOCKET_SUBPROTOCOL=null",
  "-s",
  "GL_EMULATE_GLES_VERSION_STRING_FORMAT=0",
  "-s",
  "GL_EXTENSIONS_IN_PREFIXED_FORMAT=0",
  "-s",
  "GL_SUPPORT_AUTOMATIC_ENABLE_EXTENSIONS=0",
  "-s",
  "GL_SUPPORT_SIMPLE_ENABLE_EXTENSIONS=0",
  "-s",
  "GL_TRACK_ERRORS=0",
  "-s",
  "GL_POOL_TEMP_BUFFERS=0",
  "-s",
  "MIN_WEBGL_VERSION=2",
  "-s",
  "MAX_WEBGL_VERSION=2",
  "-s",
  "GL_WORKAROUND_SAFARI_GETCONTEXT_BUG=0",
  "-s",
  "SUPPORT_LONGJMP=0",
  ...(buildMode === "production"
    ? ["-O3", "-s", "ASSERTIONS=0"]
    : [
        "-O0",
        "-g3",
        "--profiling",
        "-fsanitize=undefined",
        "-s",
        "ASSERTIONS=2",
        "-s",
        "SAFE_HEAP_LOG=1",
        "-s",
        "RUNTIME_DEBUG=1",
        "-s",
        "STACK_OVERFLOW_CHECK=2",
      ]),
  "-s",
  `EXPORTED_FUNCTIONS=${JSON.stringify(exportedFunctions)}`,
  "-s",
  "EXPORT_NAME=libcrypto",
  `-I${libsodiumIncludePath}`,
  `-I${mlkem768IncludePath}`,
  "-o",
  stagedJsPath,
  methodsPath,
  mlkem768Path,
  libsodiumArchivePath,
];

try {
  const resolvedCommit = capture("git", [
    "-C",
    libsodiumRepositoryPath,
    "rev-parse",
    `${LIBSODIUM_COMMIT}^{commit}`,
  ]);
  const resolvedTree = capture("git", [
    "-C",
    libsodiumRepositoryPath,
    "rev-parse",
    `${LIBSODIUM_COMMIT}^{tree}`,
  ]);
  assertEqual(resolvedCommit, LIBSODIUM_COMMIT, "libsodium commit");
  assertEqual(resolvedTree, LIBSODIUM_TREE, "libsodium tree");

  fs.mkdirSync(libsodiumSourcePath);
  const sourceArchive = execFileSync(
    "git",
    [
      "-C",
      libsodiumRepositoryPath,
      "archive",
      "--format=tar",
      LIBSODIUM_COMMIT,
    ],
    { maxBuffer: 64 * 1024 * 1024 },
  );
  run("tar", ["-xf", "-", "-C", libsodiumSourcePath], {
    input: sourceArchive,
  });

  const commonHeader = fs.readFileSync(
    path.join(
      libsodiumSourcePath,
      "src",
      "libsodium",
      "include",
      "sodium",
      "private",
      "common.h",
    ),
    "utf8",
  );
  if (!commonHeader.includes("!defined(DEV_MODE) && 0"))
    throw new Error("pinned libsodium export is not a stable source tree");

  const libsodiumBuildEnv = {
    ...process.env,
    CFLAGS: "-O3",
    CPPFLAGS: "",
    LDFLAGS: "",
  };
  run(
    "emconfigure",
    [
      "./configure",
      "--disable-shared",
      "--enable-static",
      "--disable-dependency-tracking",
      "--without-pthreads",
      "--disable-ssp",
      "--disable-asm",
      "--disable-pie",
      `--prefix=${libsodiumInstallPath}`,
    ],
    { cwd: libsodiumSourcePath, env: libsodiumBuildEnv },
  );
  run("emmake", ["make", "-j4", "install"], {
    cwd: libsodiumSourcePath,
    env: libsodiumBuildEnv,
  });

  for (const configuredOutput of [
    libsodiumArchivePath,
    path.join(libsodiumIncludePath, "sodium.h"),
  ])
    if (!fs.existsSync(configuredOutput))
      throw new Error(
        `Missing configured libsodium output: ${configuredOutput}`,
      );

  fs.writeFileSync(stagedTypesPath, types);
  run("emcc", emccArgs);

  for (const generatedPath of [stagedJsPath, stagedWasmPath, stagedTypesPath])
    if (!fs.existsSync(generatedPath))
      throw new Error(`Missing generated artifact: ${generatedPath}`);

  const wasmBytes = fs.readFileSync(stagedWasmPath);
  const emscriptenVersion = capture("emcc", ["--version"]).split("\n", 1)[0];
  const provenance = {
    schemaVersion: 1,
    sources: {
      libsodium: {
        releaseLine: "1.0.22-stable",
        commit: LIBSODIUM_COMMIT,
        tree: LIBSODIUM_TREE,
        extraction: "git-archive",
        configuredBuild: true,
      },
      mlkemNative: {
        release: "v1.2.0",
        commit: MLKEM_NATIVE_COMMIT,
        backend: "portable-c",
      },
    },
    toolchain: {
      emscripten: emscriptenVersion,
    },
    build: {
      mode: buildMode,
      linkTimeOptimization: false,
      publicSodiumApi: true,
    },
    artifact: {
      file: "libcrypto.wasm",
      bytes: wasmBytes.byteLength,
      sha256: sha("sha256", wasmBytes),
      sri: `sha384-${sha("sha384", wasmBytes, "base64")}`,
    },
  };
  fs.writeFileSync(
    stagedProvenancePath,
    `${JSON.stringify(provenance, null, 2)}\n`,
  );

  const outputs = [
    [stagedWasmPath, finalWasmPath],
    [stagedJsPath, finalJsPath],
    [stagedTypesPath, finalTypesPath],
    [stagedProvenancePath, finalProvenancePath],
  ];
  const publishSuffix = path.basename(stagingPath);
  const preparedOutputs = outputs.map(([stagedPath, finalPath], index) => {
    const preparedPath = `${finalPath}.${publishSuffix}-${index}.tmp`;
    fs.copyFileSync(stagedPath, preparedPath);
    return [preparedPath, finalPath];
  });
  const previousOutputs = outputs.map(([, finalPath]) =>
    fs.existsSync(finalPath)
      ? {
          bytes: fs.readFileSync(finalPath),
          mode: fs.statSync(finalPath).mode,
        }
      : null,
  );

  try {
    for (const [preparedPath, finalPath] of preparedOutputs)
      fs.renameSync(preparedPath, finalPath);
  } catch (error) {
    for (let i = 0; i < outputs.length; i++) {
      const [, finalPath] = outputs[i];
      const previous = previousOutputs[i];
      if (previous === null) {
        fs.rmSync(finalPath, { force: true });
      } else {
        const restorePath = `${finalPath}.${publishSuffix}-${i}.restore`;
        fs.writeFileSync(restorePath, previous.bytes, { mode: previous.mode });
        fs.renameSync(restorePath, finalPath);
      }
    }
    throw error;
  } finally {
    for (const [preparedPath] of preparedOutputs)
      fs.rmSync(preparedPath, { force: true });
  }

  console.log(
    `Successfully compiled c methods to Wasm from libsodium ${LIBSODIUM_COMMIT}.`,
  );
} finally {
  fs.rmSync(stagingPath, { recursive: true, force: true });
}
