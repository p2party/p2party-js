import {
  readFileSync,
  writeFileSync,
  readdirSync,
  mkdirSync,
  copyFileSync,
} from "fs";
import * as path from "path";
// import pkg from "../package.json" with { type: "json" };

// const typesFolderName = "definitelytyped";

// const newVersion = pkg.version; // your new version
const packagePath = path.resolve(
  process.cwd(),
  "..",
  "p2party-types",
  // typesFolderName,
  // "types",
  // "p2party",
  "package.json",
);

const pkgContent = readFileSync(packagePath, "utf8");
const current = JSON.parse(pkgContent);
// const [newMaj, newMin] = newVersion.split(".");
// const [curMaj, curMin] = current.version.split(".");

let finalVersion = current.version;

// if (newMaj !== curMaj || newMin !== curMin) {
//   finalVersion = newVersion;
// } else {
//   finalVersion = `${curMaj}.${curMin}.9999`;
// }

const updatedPkg = pkgContent.replace(
  /"version"\s*:\s*"[0-9]+\.[0-9]+\.[0-9]+"/,
  `"version": "${finalVersion}"`,
);

writeFileSync(packagePath, updatedPkg);
console.log("Updated version in types package.json");

// === 2. Copy all .d.ts files from ./src to ../src (or other target folder) ===

const srcRoot = path.resolve("lib");
const dstRoot = path.resolve(
  process.cwd(),
  "..",
  "p2party-types",
  "lib",
  // typesFolderName, "types", "p2party"
);

function copyDtsFilesRecursively(srcDir, dstDir) {
  const entries = readdirSync(srcDir, { withFileTypes: true });

  for (const entry of entries) {
    const srcPath = path.join(srcDir, entry.name);
    const dstPath = path.join(dstDir, entry.name);

    if (entry.isDirectory()) {
      mkdirSync(dstPath, { recursive: true });
      copyDtsFilesRecursively(srcPath, dstPath);
    } else if (entry.name.endsWith(".d.ts")) {
      mkdirSync(path.dirname(dstPath), { recursive: true });
      copyFileSync(srcPath, dstPath);
    }
  }

  writeFileSync(path.join(dstRoot, "index.cjs"), "module.exports = {};");
  writeFileSync(path.join(dstRoot, "index.mjs"), "export default {};");
}

copyDtsFilesRecursively(srcRoot, dstRoot);
