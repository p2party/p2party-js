import { afterEach, describe, expect, test } from "bun:test";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  preparePackageDeclarations,
  validatePackageDeclarations,
} from "../../scripts/packageDeclarations.mjs";

const projectRoot = fileURLToPath(new URL("../../", import.meta.url));
const fixtures: string[] = [];
const createFixture = () => {
  const root = mkdtempSync(path.join(tmpdir(), "p2party-declarations-"));
  fixtures.push(root);
  const packageRoot = path.join(root, "package");
  const sourceRoot = path.join(root, "src");
  mkdirSync(sourceRoot);
  const put = (relative: string, source: string) => {
    const target = path.join(packageRoot, relative);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, source);
  };
  put(
    "package.json",
    JSON.stringify({
      name: "p2party",
      types: "lib/index.d.ts",
      exports: {
        ".": { types: "./lib/index.d.ts", default: "./lib/index.js" },
        "./session": {
          types: "./lib/session.d.ts",
          default: "./lib/session.js",
        },
      },
    }),
  );
  put("lib/session.d.ts", "export interface Session { id: string }");
  return { root, packageRoot, sourceRoot, put };
};

afterEach(() => {
  for (const fixture of fixtures.splice(0))
    rmSync(fixture, { recursive: true, force: true });
});

describe("public declaration packaging", () => {
  test("retains all reference forms, extension substitution and cycles while pruning private declarations", () => {
    const fixture = createFixture();
    fixture.put(
      "lib/index.d.ts",
      `
/// <reference path="./ambient.d.ts" />
import type { Input } from "./input.js";
import Legacy = require("./legacy");
export { Output } from "./output";
export type Lazy = import("./lazy").Lazy;
export type Result = Input & Legacy.Legacy & Ambient;
`,
    );
    fixture.put(
      "lib/input.d.ts",
      'export interface Input { input: number; cycle?: import("./output").Output }',
    );
    fixture.put(
      "lib/output.d.ts",
      'export interface Output { output: import("./input").Input }',
    );
    fixture.put(
      "lib/legacy/index.d.ts",
      "export interface Legacy { legacy: true }",
    );
    fixture.put("lib/lazy.d.ts", "export interface Lazy { lazy: true }");
    fixture.put("lib/ambient.d.ts", "interface Ambient { ambient: true }");
    fixture.put(
      "lib/internal/research.d.ts",
      "export interface Unreachable { private: true }",
    );
    fixture.put("lib/index.js", "export {};");
    const result = preparePackageDeclarations(fixture);
    expect(result.retained).toEqual([
      "lib/ambient.d.ts",
      "lib/index.d.ts",
      "lib/input.d.ts",
      "lib/lazy.d.ts",
      "lib/legacy/index.d.ts",
      "lib/output.d.ts",
      "lib/session.d.ts",
    ]);
    expect(result.removed).toBe(1);
    expect(
      existsSync(path.join(fixture.packageRoot, "lib/internal/research.d.ts")),
    ).toBe(false);
    expect(
      readFileSync(path.join(fixture.packageRoot, "lib/index.js"), "utf8"),
    ).toBe("export {};");
  });

  test("fails closed on a missing public dependency before pruning anything", () => {
    const fixture = createFixture();
    fixture.put(
      "lib/index.d.ts",
      'export type Missing = import("./missing").Missing;',
    );
    fixture.put("lib/private.d.ts", "export {};");
    expect(() => preparePackageDeclarations(fixture)).toThrow(
      "Unresolved or unpackaged declaration import",
    );
    expect(existsSync(path.join(fixture.packageRoot, "lib/private.d.ts"))).toBe(
      true,
    );
  });

  test("rejects declaration references outside the package lib tree", () => {
    const fixture = createFixture();
    fixture.put(
      "lib/index.d.ts",
      '/// <reference path="../private.d.ts" />\nexport {};',
    );
    fixture.put("private.d.ts", "interface Private {}");
    expect(() => preparePackageDeclarations(fixture)).toThrow(
      "escapes the packaged lib tree",
    );
  });

  test("copies the real LibCrypto inputs and strictly checks both exports without dev types or ambient conflicts", () => {
    const fixture = createFixture();
    mkdirSync(path.join(fixture.sourceRoot, "cryptography"));
    for (const name of ["libcrypto.d.ts", "emscripten.d.ts"])
      copyFileSync(
        path.join(projectRoot, "src/cryptography", name),
        path.join(fixture.sourceRoot, "cryptography", name),
      );
    fixture.put(
      "lib/index.d.ts",
      `
import type { LibCrypto } from "./cryptography/libcrypto";
export declare function sign(message: Uint8Array, key: Uint8Array, crypto?: LibCrypto): Promise<Uint8Array>;
declare const p2party: { sign: typeof sign };
export default p2party;
`,
    );
    const result = preparePackageDeclarations(fixture);
    expect(result.retained).toContain("lib/cryptography/libcrypto.d.ts");
    expect(result.retained).toContain("lib/cryptography/emscripten.d.ts");
    expect(() =>
      validatePackageDeclarations({
        ...fixture,
        projectRoot,
        consumerRoot: path.join(fixture.root, "consumer"),
      }),
    ).not.toThrow();
  });

  test("strict validation rejects an unresolved declaration even when skipLibCheck in the SDK is true", () => {
    const fixture = createFixture();
    fixture.put(
      "lib/index.d.ts",
      'export declare function sign(message: Uint8Array, key: Uint8Array, crypto?: import("./missing").Crypto): Promise<Uint8Array>; declare const p2party: { sign: typeof sign }; export default p2party;',
    );
    expect(() =>
      validatePackageDeclarations({
        ...fixture,
        projectRoot,
        consumerRoot: path.join(fixture.root, "consumer"),
      }),
    ).toThrow("Cannot find module './missing'");
  });
});
