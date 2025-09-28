import path from "path";
import fs from "fs";
import terser from "@rollup/plugin-terser";
import commonjs from "@rollup/plugin-commonjs";
import json from "@rollup/plugin-json";
import resolve from "@rollup/plugin-node-resolve";
import typescript from "@rollup/plugin-typescript";
import replace from "@rollup/plugin-replace";
import analyzer from "rollup-plugin-analyzer";

const dir = "lib";
const input = "src/index.ts";

const idbWorkerPath = path.resolve("lib", "db.worker.js");
const idbWorkerJs = fs.readFileSync(idbWorkerPath, { encoding: "utf-8" });

const isDist = process.env.NODE_ENV === "production";

const plugins = [
  replace({
    "process.env.INDEXEDDB_WORKER_JS": JSON.stringify(idbWorkerJs),
    "process.env.NODE_ENV": isDist
      ? JSON.stringify("production")
      : JSON.stringify("development"),
    preventAssignment: true,
  }),

  resolve({
    browser: true,
    preferBuiltins: false,
  }),

  commonjs(),

  json({
    compact: true,
    preferConst: true,
  }),

  typescript({
    sourceMap: true,
    inlineSources: false,
    declaration: true,
    declarationMap: true,
    exclude: ["playwright*", "rollup*"],
    outDir: `${dir}`,
  }),

  isDist &&
    terser({
      ecma: 2020,
      toplevel: true,
    }),

  analyzer(),
];

export default [
  // UMD
  {
    input,
    plugins: [
      ...plugins,
      replace({
        "process.env.NODE_ENV": JSON.stringify("production"),
        preventAssignment: true,
      }),
      terser({
        ecma: 2020,
        toplevel: true,
      }),
    ],
    output: {
      name: "p2party",
      file: `lib${path.sep}index.min.js`,
      format: "umd",
      esModule: false,
      interop: "default",
      extend: true,
      sourcemap: true,
      exports: "named",
    },
  },

  // ESM and CJS
  {
    input,
    plugins,
    external: ["module", "@reduxjs", "class-validator"],
    output: [
      {
        file: `lib${path.sep}index.mjs`,
        esModule: true,
        interop: "esModule",
        exports: "named",
        sourcemap: true,
      },
      {
        file: `lib${path.sep}index.js`,
        format: "cjs",
        esModule: false,
        interop: "auto",
        exports: "named",
        sourcemap: true,
      },
    ],
  },
];
