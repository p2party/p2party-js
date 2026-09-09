import { describe, expect, test } from "bun:test";

describe("browser store privacy", () => {
  test("never connects identity actions or state to Redux DevTools", async () => {
    const storePath = new URL("../src/store.ts", import.meta.url).pathname;
    // The extension hook must exist before Redux Toolkit loads. A fresh process
    // also prevents this synthetic browser environment affecting other tests.
    const source = `
      let extensionConnections = 0;
      const observedStores = [];
      const compose = (...functions) => functions.length === 0
        ? value => value
        : functions.reduce((outer, inner) => (...args) => outer(inner(...args)));
      globalThis.window = {
        __REDUX_DEVTOOLS_EXTENSION_COMPOSE__: () => {
          extensionConnections++;
          return (...enhancers) => createStore => (...args) => {
            const store = compose(...enhancers)(createStore)(...args);
            observedStores.push(store);
            return store;
          };
        },
      };
      globalThis.localStorage = {
        getItem: () => null, setItem() {}, removeItem() {},
      };
      globalThis.Worker = class { postMessage() {} };
      const { store } = await import(${JSON.stringify(storePath)});
      const syntheticSecret = "11".repeat(64);
      store.dispatch({
        type: "keyPair/setKeyPair",
        payload: { publicKey: "00".repeat(32), secretKey: syntheticSecret },
      });
      const stateUpdated = store.getState().keyPair.secretKey === syntheticSecret;
      const secretObserved = observedStores.some(
        observed => observed.getState().keyPair.secretKey === syntheticSecret,
      );
      console.log(JSON.stringify({ extensionConnections, stateUpdated, secretObserved }));
    `;
    const child = Bun.spawn([process.execPath, "--no-env-file", "-e", source], {
      env: { ...process.env, NODE_ENV: "production" },
      stdout: "pipe",
      stderr: "pipe",
    });
    const [stdout, stderr, exit] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
      child.exited,
    ]);
    expect(stderr).toBe("");
    expect(exit).toBe(0);
    expect(JSON.parse(stdout)).toEqual({
      extensionConnections: 0,
      stateUpdated: true,
      secretObserved: false,
    });
  });
});
