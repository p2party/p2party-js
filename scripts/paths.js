const path = require("path");

const srcPath = path.join(process.cwd(), "src", "cryptography");
const methodsPath = path.join(srcPath, "libcrypto.c");
const libsodiumRepositoryPath = path.join(process.cwd(), "libsodium");

module.exports = {
  methodsPath,
  libsodiumRepositoryPath,
};
