const path = require("path");

const srcPath = path.join(process.cwd(), "src", "cryptography");
const methodsPath = path.join(srcPath, "libcrypto.c");

const libsodiumPath = path.join(process.cwd(), "libsodium", "src", "libsodium");
const libsodiumIncludePath = path.join(libsodiumPath, "include", "sodium");
const libsodiumIncludePrivatePath = path.join(libsodiumIncludePath, "private");

const libsodiumSodiumPath = path.join(libsodiumPath, "sodium");
const libsodiumCodecsPath = path.join(libsodiumSodiumPath, "codecs.c");
const libsodiumCorePath = path.join(libsodiumSodiumPath, "core.c");
const libsodiumUtilsPath = path.join(libsodiumSodiumPath, "utils.c");
// const libsodiumRandomBytesPath = path.join(libsodiumPath, "randombytes", "randombytes.c");

const libsodiumRandomBytesPath = path.join(srcPath, "utils", "random_bytes.c");

const libsodiumHashPath = path.join(
  libsodiumPath,
  "crypto_hash",
  "sha512",
  "cp",
  "hash_sha512_cp.c",
);

const libsodiumEd255191 = path.join(
  libsodiumPath,
  "crypto_core",
  "ed25519",
  "ref10",
  "ed25519_ref10.c",
);
const libsodiumSignPath = path.join(
  libsodiumPath,
  "crypto_sign",
  "ed25519",
  "ref10",
);
const libsodiumEd255192 = path.join(libsodiumSignPath, "keypair.c");
const libsodiumEd255193 = path.join(libsodiumSignPath, "open.c");
const libsodiumEd255194 = path.join(libsodiumSignPath, "sign.c");
const libsodiumEd255195 = path.join(libsodiumPath, "crypto_verify", "verify.c");

const libsodiumGenericHashPath = path.join(libsodiumPath, "crypto_generichash");
const libsodiumGenericHashMainPath = path.join(
  libsodiumGenericHashPath,
  "crypto_generichash.c",
);
const libsodiumGenericHash1Path = path.join(
  libsodiumGenericHashPath,
  "blake2b",
  "ref",
  "blake2b-compress-ref.c",
);
const libsodiumGenericHash2Path = path.join(
  libsodiumGenericHashPath,
  "blake2b",
  "ref",
  "blake2b-ref.c",
);
const libsodiumGenericHash3Path = path.join(
  libsodiumGenericHashPath,
  "blake2b",
  "ref",
  "generichash_blake2b.c",
);

const libsodiumPolyPath = path.join(
  libsodiumPath,
  "crypto_onetimeauth",
  "poly1305",
  "onetimeauth_poly1305.c",
);

const libsodiumAuthPath = path.join(
  libsodiumPath,
  "crypto_auth",
  "hmacsha512",
  "auth_hmacsha512.c",
);

const libsodiumChacha1 = path.join(
  libsodiumPath,
  "crypto_aead",
  "chacha20poly1305",
  "aead_chacha20poly1305.c",
);
const libsodiumChacha2 = path.join(
  libsodiumPath,
  "crypto_stream",
  "chacha20",
  "ref",
  "chacha20_ref.c",
);
const libsodiumChacha3 = path.join(
  libsodiumPath,
  "crypto_stream",
  "chacha20",
  "stream_chacha20.c",
);
const libsodiumChacha4 = path.join(
  libsodiumPath,
  "crypto_onetimeauth",
  "poly1305",
  "donna",
  "poly1305_donna.c",
);

const libsodiumKx1 = path.join(libsodiumPath, "crypto_kx", "crypto_kx.c");
const libsodiumKx2 = path.join(
  libsodiumPath,
  "crypto_scalarmult",
  "crypto_scalarmult.c",
);
const libsodiumKx3 = path.join(
  libsodiumPath,
  "crypto_scalarmult",
  "curve25519",
  "scalarmult_curve25519.c",
);
const libsodiumKx4 = path.join(
  libsodiumPath,
  "crypto_scalarmult",
  "curve25519",
  "ref10",
  "x25519_ref10.c",
);
const libsodiumKx5 = path.join(
  libsodiumPath,
  "crypto_scalarmult",
  "ed25519",
  "ref10",
  "scalarmult_ed25519_ref10.c",
);

module.exports = {
  methodsPath,

  libsodiumIncludePath,
  libsodiumIncludePrivatePath,

  libsodiumCodecsPath,
  libsodiumCorePath,
  libsodiumUtilsPath,
  libsodiumRandomBytesPath,

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
};
