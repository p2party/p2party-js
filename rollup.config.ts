import path from "path";
// import copy from "rollup-plugin-copy";
import terser from "@rollup/plugin-terser";
import commonjs from "@rollup/plugin-commonjs";
import json from "@rollup/plugin-json";
import resolve from "@rollup/plugin-node-resolve";
import typescript from "@rollup/plugin-typescript";
import { importMetaAssets } from "@web/rollup-plugin-import-meta-assets";
import analyzer from "rollup-plugin-analyzer";

const dir = "lib";
const input = "src/index.ts";

const plugins = [
  resolve({
    // jsnext: true,
    // main: true,
    // module: true,
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
    // paths: {
    //   "@libdemos": [path.join(process.cwd(), "wasm", "libdemos")],
    // },
    outDir: `${dir}`,
  }),

  // copy({
  //   targets: [
  //     {
  //       src: 'src/cryptography/libcrypto.wasm',
  //       dest: 'lib',
  //     },
  //   ],
  // }),

  importMetaAssets(),

  analyzer(),
];

export default [
  // UMD
  {
    input,
    plugins: [
      ...plugins,
      terser({
        ecma: 2020,
        toplevel: true,
      }),
    ],
    output: {
      name: "p2party",
      // dir: "lib",
      file: `lib${path.sep}index.min.js`,
      format: "umd",
      esModule: false,
      interop: "default",
      extend: true,
      sourcemap: true,
      exports: "named",
      // preserveModules: true,
      //   paths: {
      //     "@libdemos": [path.join(process.cwd(), "wasm", "libdemos")],
      //   },
    },
  },

  // ESM and CJS
  {
    input,
    plugins,
    external: ["module"],
    output: [
      {
        // dir: "lib",
        file: `lib${path.sep}index.mjs`,
        // format: "esm",
        esModule: true,
        interop: "esModule",
        exports: "named",
        sourcemap: true,
        // preserveModules: true,
        // paths: {
        //   "@libdemos": [path.join(process.cwd(), "wasm", "libdemos")],
        // },
      },
      {
        // dir: "lib",
        file: `lib${path.sep}index.js`,
        format: "cjs",
        esModule: false,
        interop: "defaultOnly",
        exports: "named", // "default",
        sourcemap: true,
        // preserveModules: true,
        // paths: {
        //   "@libdemos": [path.join(process.cwd(), "wasm", "libdemos")],
        // },
      },
    ],
  },
];
