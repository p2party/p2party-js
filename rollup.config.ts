import path from "path";
import fs from "fs";
import terser from "@rollup/plugin-terser";
import commonjs from "@rollup/plugin-commonjs";
import json from "@rollup/plugin-json";
import resolve from "@rollup/plugin-node-resolve";
import typescript from "@rollup/plugin-typescript";
import replace from "@rollup/plugin-replace";
import analyzer from "rollup-plugin-analyzer";

const dir = process.env.P2PARTY_OUTPUT_DIR ?? "lib";
const rootInput = "src/index.ts";
const sessionInput = "src/session.ts";
const packageJson = JSON.parse(fs.readFileSync("package.json", "utf-8"));

const isDist = process.env.NODE_ENV === "production";
const isSessionOnly = process.env.P2PARTY_ROLLUP_TARGET === "session";
const shouldAnalyze = process.env.P2PARTY_ANALYZE !== "false";

const createPlugins = (includeIndexedDbWorker) => {
  const values = {
    ...(includeIndexedDbWorker
      ? {
          "process.env.INDEXEDDB_WORKER_JS": JSON.stringify(
            fs.readFileSync(path.resolve(dir, "db.worker.js"), {
              encoding: "utf-8",
            }),
          ),
        }
      : {}),
    "process.env.P2PARTY_VERSION": JSON.stringify(packageJson.version),
    "process.env.NODE_ENV": isDist
      ? JSON.stringify("production")
      : JSON.stringify("development"),
    preventAssignment: true,
  };

  return [
    replace(values),

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
      sourceMap: !isDist,
      inlineSources: false,
      declaration: true,
      declarationMap: !isDist,
      exclude: ["playwright*", "rollup*"],
      outDir: `${dir}`,
    }),

    isDist &&
      terser({
        ecma: 2020,
        toplevel: true,
      }),

    shouldAnalyze && analyzer(),
  ];
};

const sessionConfig = {
  input: sessionInput,
  plugins: createPlugins(false),
  external: ["module"],
  output: [
    {
      file: path.join(dir, "session.mjs"),
      format: "es",
      esModule: true,
      interop: "esModule",
      exports: "named",
      sourcemap: !isDist,
    },
    {
      file: path.join(dir, "session.js"),
      format: "cjs",
      esModule: false,
      interop: "auto",
      exports: "named",
      sourcemap: !isDist,
    },
  ],
};

const rootPlugins = isSessionOnly ? [] : createPlugins(true);
const rootConfigs = [
  // UMD
  {
    input: rootInput,
    plugins: [
      ...rootPlugins,
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
      file: path.join(dir, "index.min.js"),
      format: "umd",
      esModule: false,
      interop: "default",
      extend: true,
      sourcemap: !isDist,
      exports: "named",
    },
  },

  // ESM and CJS
  {
    input: rootInput,
    plugins: rootPlugins,
    external: ["module", "@reduxjs", "class-validator"],
    output: [
      {
        file: path.join(dir, "index.mjs"),
        esModule: true,
        interop: "esModule",
        exports: "named",
        sourcemap: !isDist,
      },
      {
        file: path.join(dir, "index.js"),
        format: "cjs",
        esModule: false,
        interop: "auto",
        exports: "named",
        sourcemap: !isDist,
      },
    ],
  },
];

export default isSessionOnly
  ? [sessionConfig]
  : [...rootConfigs, sessionConfig];
