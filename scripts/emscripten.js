const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const {
  methodsPath,
  libsodiumIncludePath,
  libsodiumIncludePrivatePath,
  libsodiumCodecsPath,
  libsodiumCorePath,
  libsodiumUtilsPath,
  libsodiumHashPath,
  libsodiumEd255191,
  libsodiumEd255192,
  libsodiumEd255193,
  libsodiumEd255194,
  libsodiumEd255195,
  libsodiumGenericHashMainPath,
  libsodiumGenericHash1Path,
  libsodiumGenericHash2Path,
  libsodiumGenericHash3Path,
  libsodiumPolyPath,
  libsodiumAuthPath,
  libsodiumChacha1,
  libsodiumChacha2,
  libsodiumChacha3,
  libsodiumChacha4,
  libsodiumKx1,
  libsodiumKx2,
  libsodiumKx3,
  libsodiumKx4,
  libsodiumKx5,
  libsodiumArgon1,
  libsodiumArgon2,
  libsodiumArgon3,
  libsodiumArgon4,
  libsodiumArgon5,
  libsodiumArgon6,
} = require("./paths");

const buildPath = path.join(process.cwd(), "src", "cryptography");
const wasmPath = path.join(buildPath, "libcrypto.js");

if (fs.existsSync(buildPath)) {
  fs.rmSync(wasmPath, { force: true });
  fs.rmSync(wasmPath.replace("pto.js", "pto.d.ts"), { force: true });
}
const typesPath = path.join(process.cwd(), "scripts", "libcrypto.d.ts");
const types = fs.readFileSync(typesPath);
fs.writeFileSync(wasmPath.replace("pto.js", "pto.d.ts"), types);

const withJS = ` \
-s WASM=1 \
-s MODULARIZE=1 \
-s MAIN_MODULE=2 \
-s BUILD_AS_WORKER=1 \
-s INCOMING_MODULE_JS_API=\[\"wasmMemory\"\] \
-s POLYFILL=0 \
-s NO_DYNAMIC_EXECUTION=1 \
-s WEBSOCKET_SUBPROTOCOL=null \
-s GL_EMULATE_GLES_VERSION_STRING_FORMAT=0 \
-s GL_EXTENSIONS_IN_PREFIXED_FORMAT=0 \
-s GL_SUPPORT_AUTOMATIC_ENABLE_EXTENSIONS=0 \
-s GL_SUPPORT_SIMPLE_ENABLE_EXTENSIONS=0 \
-s GL_TRACK_ERRORS=0 \
-s GL_POOL_TEMP_BUFFERS=0 \
-s MIN_WEBGL_VERSION=2 \
-s MAX_WEBGL_VERSION=2 \
-s GL_WORKAROUND_SAFARI_GETCONTEXT_BUG=0 \
-s SUPPORT_LONGJMP=0 \
`;

// const browser =
//   process.env.NODE_OR_BROWSER === "browser" ? ` \
// -s SINGLE_FILE=1 \
// -s ENVIRONMENT=\'web\' \
// ` : `\
// -s ENVIRONMENT=\'node\' \
// `;

const memory = `\
-s IMPORTED_MEMORY=1 \
-s ALLOW_MEMORY_GROWTH=1 \
-s INITIAL_MEMORY=2mb \
-s STACK_SIZE=512kb \
-s MEMORY_GROWTH_LINEAR_STEP=64kb \
-s GLOBAL_BASE=4096 \
`;

const emcc = `\
emcc \
--no-entry \
-fno-exceptions \
-fno-PIC \
-fPIE \
-fno-common \
-ffunction-sections \
-fdata-sections \
-fdelete-null-pointer-checks \
-fno-asm \
-ffinite-loops \
-fjump-tables \
-fno-keep-static-consts \
-fvectorize \
-s STRICT \
-s SINGLE_FILE=1 \
-s ENVIRONMENT=worker \
${memory} \
${withJS} \
-s NODEJS_CATCH_EXIT=0 \
-s NODEJS_CATCH_REJECTION=0 \
`;

const testing =
  process.env.NODE_ENV === "production"
    ? `\
-flto \
-O3 \
-s FILESYSTEM=0 \
-s ASSERTIONS=0 \
-s INVOKE_RUN=0 \
`
    : `\
-Og \
-g3 \
--profiling \
-fsanitize=undefined \
-s ASSERTIONS=2 \
-s RUNTIME_DEBUG=1 \
-s STACK_OVERFLOW_CHECK=2 \
-s EXIT_RUNTIME=1 \
`;

execSync(
  `\
${emcc} \
${testing} \
-s EXPORTED_FUNCTIONS=\
_malloc,\
_free,\
_sign,\
_verify,\
_encrypt_chachapoly_asymmetric,\
_decrypt_chachapoly_asymmetric,\
_get_merkle_proof,\
_get_merkle_root,\
_get_merkle_root_from_proof,\
_verify_merkle_proof,\
_keypair_from_seed,\
_keypair_from_secret_key,\
_argon2 \
-s EXPORT_NAME=libcrypto \
-I${libsodiumIncludePath} \
-I${libsodiumIncludePrivatePath} \
-o ${wasmPath} \
${methodsPath} \
${libsodiumCorePath} \
${libsodiumCodecsPath} \
${libsodiumUtilsPath} \
${libsodiumHashPath} \
${libsodiumEd255191} \
${libsodiumEd255192} \
${libsodiumEd255193} \
${libsodiumEd255194} \
${libsodiumEd255195} \
${libsodiumGenericHashMainPath} \
${libsodiumGenericHash1Path} \
${libsodiumGenericHash2Path} \
${libsodiumGenericHash3Path} \
${libsodiumPolyPath} \
${libsodiumAuthPath} \
${libsodiumChacha1} \
${libsodiumChacha2} \
${libsodiumChacha3} \
${libsodiumChacha4} \
${libsodiumKx1} \
${libsodiumKx2} \
${libsodiumKx3} \
${libsodiumKx4} \
${libsodiumKx5} \
${libsodiumArgon1} \
${libsodiumArgon2} \
${libsodiumArgon3} \
${libsodiumArgon4} \
${libsodiumArgon5} \
${libsodiumArgon6} \
`,
  { stdio: "inherit" },
);

let content = fs.readFileSync(wasmPath, "utf8");
fs.writeFileSync(wasmPath, content);

console.log("Successfully compiled c methods to Wasm.");
