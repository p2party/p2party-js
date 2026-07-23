// Node/bun shim for the browser globals p2party's modules touch at import time:
// the emscripten glue's web branch reads `globalThis.crypto` via a `window`
// alias, and the Redux keyPair slice reads `localStorage` at module-init. Imported
// for its side effects as the FIRST import of the example so it runs before the
// crypto/handshake modules are evaluated. In a real browser none of this is needed.
(globalThis as unknown as { window: typeof globalThis }).window ??= globalThis;

const mem: Record<string, string> = {};
(globalThis as unknown as { localStorage?: Storage }).localStorage ??= {
  getItem: (k: string) => (k in mem ? mem[k] : null),
  setItem: (k: string, v: string) => {
    mem[k] = String(v);
  },
  removeItem: (k: string) => {
    delete mem[k];
  },
  clear: () => {
    for (const k of Object.keys(mem)) delete mem[k];
  },
  key: () => null,
  length: 0,
} as Storage;
