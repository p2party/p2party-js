import {
  copyFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import ts from "typescript";

const isDeclaration = (file) => /\.d\.[cm]?ts$/u.test(file);
const inside = (root, file) => {
  const relative = path.relative(root, file);
  return (
    !path.isAbsolute(relative) &&
    relative !== ".." &&
    !relative.startsWith(`..${path.sep}`)
  );
};
const declarations = (root) =>
  readdirSync(root, { withFileTypes: true }).flatMap((entry) => {
    const file = path.join(root, entry.name);
    return entry.isDirectory()
      ? declarations(file)
      : isDeclaration(file)
        ? [file]
        : [];
  });
const exportTargets = (value) =>
  typeof value === "string"
    ? [value]
    : value && typeof value === "object"
      ? Object.values(value).flatMap(exportTargets)
      : [];

const compilerOptions = {
  target: ts.ScriptTarget.ES2022,
  module: ts.ModuleKind.ESNext,
  moduleResolution: ts.ModuleResolutionKind.Bundler,
  lib: ["lib.es2022.d.ts", "lib.dom.d.ts"],
  types: [],
  strict: true,
  skipLibCheck: false,
  noEmit: true,
};

/** Copy declaration inputs omitted by TS emit, then retain the public closure. */
export const preparePackageDeclarations = ({ packageRoot, sourceRoot }) => {
  const libRoot = path.join(packageRoot, "lib");
  for (const source of declarations(sourceRoot)) {
    const target = path.join(libRoot, path.relative(sourceRoot, source));
    if (
      existsSync(target) &&
      !readFileSync(target).equals(readFileSync(source))
    )
      throw new Error(`Conflicting declaration input: ${target}`);
    mkdirSync(path.dirname(target), { recursive: true });
    copyFileSync(source, target);
  }
  const pkg = JSON.parse(
    readFileSync(path.join(packageRoot, "package.json"), "utf8"),
  );
  if (pkg.typesVersions)
    throw new Error(
      "Declaration pruning must account for typesVersions before enabling it",
    );
  const roots = [...exportTargets(pkg.exports), pkg.types, pkg.typings]
    .filter((target) => typeof target === "string" && isDeclaration(target))
    .map((target) => path.resolve(packageRoot, target));
  if (roots.length === 0)
    throw new Error("Package has no public declaration entry points");
  const retained = new Set();
  const visit = (file) => {
    if (!inside(libRoot, file) || !isDeclaration(file))
      throw new Error(
        `Public declaration escapes the packaged lib tree: ${file}`,
      );
    if (retained.has(file)) return;
    if (!existsSync(file))
      throw new Error(`Missing public declaration: ${file}`);
    retained.add(file);
    const info = ts.preProcessFile(readFileSync(file, "utf8"), true, true);
    for (const reference of info.referencedFiles)
      visit(path.resolve(path.dirname(file), reference.fileName));
    for (const reference of info.importedFiles) {
      const specifier = reference.fileName;
      const resolved = ts.resolveModuleName(
        specifier,
        file,
        compilerOptions,
        ts.sys,
      ).resolvedModule;
      if (resolved && inside(libRoot, resolved.resolvedFileName)) {
        visit(resolved.resolvedFileName);
      } else if (specifier.startsWith(".")) {
        throw new Error(
          `Unresolved or unpackaged declaration import ${specifier} in ${file}`,
        );
      }
    }
    for (const reference of info.typeReferenceDirectives) {
      const resolved = ts.resolveTypeReferenceDirective(
        reference.fileName,
        file,
        compilerOptions,
        ts.sys,
      ).resolvedTypeReferenceDirective;
      if (resolved && inside(libRoot, resolved.resolvedFileName))
        visit(resolved.resolvedFileName);
      else if (reference.fileName.startsWith("."))
        throw new Error(
          `Unresolved declaration type reference ${reference.fileName} in ${file}`,
        );
    }
  };
  for (const root of roots) visit(root);
  // Compute and validate the entire closure before deleting anything.
  const removed = declarations(libRoot).filter((file) => !retained.has(file));
  const removedBytes = removed.reduce(
    (sum, file) => sum + readFileSync(file).byteLength,
    0,
  );
  for (const file of removed) rmSync(file);
  return {
    retained: [...retained]
      .map((file) => path.relative(packageRoot, file).split(path.sep).join("/"))
      .sort(),
    removed: removed.length,
    removedBytes,
  };
};

/**
 * Check an extracted npm package without access to the checkout's dev types.
 * Copy only locked runtime dependencies; even when the fixture lives below the
 * checkout, the compiler host cannot fall back to ancestor node_modules.
 */
export const validatePackageDeclarations = ({
  packageRoot,
  projectRoot,
  consumerRoot,
}) => {
  mkdirSync(consumerRoot);
  consumerRoot = realpathSync(consumerRoot);
  const modules = path.join(consumerRoot, "node_modules");
  mkdirSync(modules);
  cpSync(packageRoot, path.join(modules, "p2party"), { recursive: true });
  const lock = JSON.parse(
    readFileSync(path.join(projectRoot, "package-lock.json"), "utf8"),
  );
  for (const [relative, metadata] of Object.entries(lock.packages)) {
    if (!relative || metadata.dev === true) continue;
    if (
      !relative.startsWith("node_modules/") ||
      !inside(projectRoot, path.resolve(projectRoot, relative))
    )
      throw new Error(`Unsupported runtime dependency location: ${relative}`);
    const destination = path.join(consumerRoot, relative);
    mkdirSync(path.dirname(destination), { recursive: true });
    cpSync(path.join(projectRoot, relative), destination, {
      recursive: true,
      // Nested runtime dependencies have their own lock entries; copying an
      // entire nested node_modules could accidentally expose development types.
      filter: (source) => path.basename(source) !== "node_modules",
    });
  }
  const fixture = path.join(consumerRoot, "consumer.ts");
  writeFileSync(
    fixture,
    `
import p2party from "p2party";
import * as session from "p2party/session";
type CryptoModule = NonNullable<Parameters<typeof p2party.sign>[2]>;
declare const crypto: CryptoModule;
const memory: WebAssembly.Memory = crypto.wasmMemory;
const pointer: number = crypto._malloc(32);
crypto._free(pointer);
const signature: Promise<Uint8Array> = p2party.sign(new Uint8Array(), new Uint8Array(64), crypto);
void [p2party, session, memory, signature];
// @ts-expect-error The public crypto API must retain real types, not any.
p2party.sign("invalid", new Uint8Array(64));
// @ts-expect-error Inherited allocation methods must remain typed.
crypto._malloc("invalid");
`,
  );
  const standardLibRoot = path.dirname(
    ts.getDefaultLibFilePath(compilerOptions),
  );
  const allowed = (file) =>
    inside(consumerRoot, file) || inside(standardLibRoot, file);
  const host = ts.createCompilerHost(compilerOptions);
  host.fileExists = (file) => allowed(file) && ts.sys.fileExists(file);
  host.readFile = (file) => (allowed(file) ? ts.sys.readFile(file) : undefined);
  host.directoryExists = (directory) =>
    allowed(directory) && ts.sys.directoryExists(directory);
  host.getCurrentDirectory = () => consumerRoot;
  host.getSourceFile = (file, languageVersion) => {
    const source = host.readFile(file);
    return source === undefined
      ? undefined
      : ts.createSourceFile(file, source, languageVersion);
  };
  const check = (ambientTypes) => {
    const program = ts.createProgram(
      [fixture],
      { ...compilerOptions, types: ambientTypes },
      host,
    );
    const diagnostics = ts.getPreEmitDiagnostics(program);
    if (diagnostics.length)
      throw new Error(
        ts.formatDiagnostics(diagnostics, {
          getCanonicalFileName: (file) => file,
          getCurrentDirectory: () => consumerRoot,
          getNewLine: () => "\n",
        }),
      );
    for (const file of program.getSourceFiles())
      if (!allowed(file.fileName))
        throw new Error(
          `Consumer resolved an unpackaged development file: ${file.fileName}`,
        );
  };
  check([]);
  // Also prove coexistence with the optional global upstream types: SDK types
  // are module-scoped and must not redeclare EmscriptenModuleFactory globally.
  const emscriptenTypes = path.join(modules, "@types", "emscripten");
  mkdirSync(path.dirname(emscriptenTypes), { recursive: true });
  cpSync(
    path.join(projectRoot, "node_modules", "@types", "emscripten"),
    emscriptenTypes,
    { recursive: true },
  );
  writeFileSync(
    fixture,
    readFileSync(fixture, "utf8") +
      `
const upstream: EmscriptenModule = crypto;
type Assert<T extends true> = T;
type AllInheritedMembersRemain = Assert<Exclude<keyof EmscriptenModule, keyof CryptoModule> extends never ? true : false>;
void upstream;
`,
  );
  check(["emscripten"]);
};
