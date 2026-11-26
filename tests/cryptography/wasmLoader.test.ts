import { describe, expect, spyOn, test } from "bun:test";
import { readFileSync } from "node:fs";

import type { Server } from "bun";

const PINNED_WASM = new Uint8Array(
  readFileSync(
    new URL("../../src/cryptography/libcrypto.wasm", import.meta.url),
  ),
);

// A loopback server on a port above 5000 that serves `bytes` for every path
// and counts the requests it answered. Never the real CDN.
const serveWasm = (
  bytes: Uint8Array<ArrayBuffer>,
): { server: Server<undefined>; requests: () => number } => {
  let requests = 0;
  for (let attempt = 0; attempt < 20; attempt++) {
    const port = 50_000 + Math.floor(Math.random() * 10_000);
    try {
      const server = Bun.serve({
        hostname: "127.0.0.1",
        port,
        fetch: () => {
          requests += 1;
          return new Response(bytes, {
            headers: { "content-type": "application/wasm" },
          });
        },
      });
      return { server, requests: () => requests };
    } catch {
      // Port in use; try another.
    }
  }
  throw new Error("no free loopback port above 5000");
};

// The loader keeps module state (a source can be pinned only before the
// first load), so every case imports its own instance.
let instance = 0;
const freshLoader = async (): Promise<
  typeof import("../../src/cryptography/wasmLoader")
> => {
  instance += 1;
  return (await import(
    `../../src/cryptography/wasmLoader.ts?case=${String(instance)}`
  )) as typeof import("../../src/cryptography/wasmLoader");
};

const memory = (): WebAssembly.Memory =>
  new WebAssembly.Memory({ initial: 32, maximum: 32 });

const tamperedWasm = (): Uint8Array<ArrayBuffer> => {
  const tampered = Uint8Array.from(PINNED_WASM);
  // The last byte lies in the data section, so the module still compiles:
  // only a digest check can stop it.
  tampered[tampered.length - 1] ^= 0x01;
  return tampered;
};

// Run `operation` as if on a page served from `href` (a Capacitor iOS page is
// capacitor://localhost). Bun has no `location`, so the property is installed
// for the call and removed afterwards.
const onPage = async <T>(
  href: string,
  operation: () => Promise<T> | T,
): Promise<T> => {
  const page = new URL(href);
  const holder = globalThis as { location?: unknown };
  const previous = Object.getOwnPropertyDescriptor(holder, "location");
  Object.defineProperty(holder, "location", {
    configurable: true,
    value: { href: page.href, protocol: page.protocol, host: page.host },
  });
  try {
    return await operation();
  } finally {
    if (previous) Object.defineProperty(holder, "location", previous);
    else delete holder.location;
  }
};

const CAPACITOR_WASM = "capacitor://localhost/vendor/p2party/libcrypto.wasm";

describe("wasmLoader checks the SHA-384 of the bytes it fetches", () => {
  test("rejects a tampered wasm from a pinned URL", async () => {
    const tampered = tamperedWasm();
    expect(WebAssembly.validate(tampered)).toBe(true);

    const { server, requests } = serveWasm(tampered);
    try {
      expect(server.port).toBeGreaterThan(5000);
      const { setWasmSourceUrl, wasmLoader } = await freshLoader();
      setWasmSourceUrl(
        `http://127.0.0.1:${String(server.port)}/libcrypto.wasm`,
      );
      await expect(wasmLoader(memory())).rejects.toThrow(
        "failed its SHA-384 integrity check",
      );
      expect(requests()).toBe(1);
    } finally {
      await server.stop(true);
    }
  });

  test("loads the pinned wasm from a pinned URL", async () => {
    const { server, requests } = serveWasm(PINNED_WASM);
    try {
      const { setWasmSourceUrl, wasmLoader } = await freshLoader();
      setWasmSourceUrl(
        `http://127.0.0.1:${String(server.port)}/libcrypto.wasm`,
      );
      const module = await wasmLoader(memory());
      expect(typeof module._malloc).toBe("function");
      expect(requests()).toBe(1);
    } finally {
      await server.stop(true);
    }
  });
});

describe("setWasmSourceUrl accepts http(s) or the page's own origin", () => {
  test("accepts a same-origin wasm URL on a non-http scheme", async () => {
    // The Capacitor iOS shell serves the page from capacitor://localhost.
    await onPage("capacitor://localhost/index.html", async () => {
      const { setWasmSourceUrl } = await freshLoader();
      expect(() => setWasmSourceUrl(CAPACITOR_WASM)).not.toThrow();
    });
    // Another host, or another custom scheme, is not the page's origin.
    await onPage("capacitor://localhost/index.html", async () => {
      const { setWasmSourceUrl } = await freshLoader();
      expect(() =>
        setWasmSourceUrl("capacitor://elsewhere/libcrypto.wasm"),
      ).toThrow(TypeError);
      expect(() =>
        setWasmSourceUrl("ionic://localhost/libcrypto.wasm"),
      ).toThrow(TypeError);
    });
    // With no page (Node, Bun) there is no origin to match: only http(s).
    const { setWasmSourceUrl } = await freshLoader();
    expect(() => setWasmSourceUrl(CAPACITOR_WASM)).toThrow(TypeError);
    expect(() =>
      setWasmSourceUrl("https://example.test/libcrypto.wasm"),
    ).not.toThrow();
  });

  test("refuses data, blob, javascript and file URLs", async () => {
    const refused = [
      "data:application/wasm;base64,AGFzbQEAAAA=",
      "blob:capacitor://localhost/0b5c1f1e-0000-4000-8000-000000000000",
      "javascript:void 0",
      "file:///var/mobile/libcrypto.wasm",
    ];
    // Refused on a custom-scheme page, on a page that is itself a file:,
    // and with no page at all.
    for (const page of [
      "capacitor://localhost/index.html",
      "file:///var/mobile/index.html",
      null,
    ]) {
      for (const source of refused) {
        const attempt = async (): Promise<void> => {
          const { setWasmSourceUrl } = await freshLoader();
          expect(() => setWasmSourceUrl(source)).toThrow(TypeError);
        };
        if (page === null) await attempt();
        else await onPage(page, attempt);
      }
    }
  });

  test("a same-origin non-http source is still hash-checked", async () => {
    // Bun cannot fetch capacitor:, so stand in for the shell's scheme
    // handler: answer that one URL with the given bytes.
    const serveFromScheme = (bytes: Uint8Array<ArrayBuffer>) =>
      spyOn(globalThis, "fetch").mockImplementation((async (
        input: string | URL | Request,
      ) => {
        const url = input instanceof Request ? input.url : String(input);
        if (url !== CAPACITOR_WASM) throw new Error(`unexpected fetch ${url}`);
        return new Response(Uint8Array.from(bytes), {
          headers: { "content-type": "application/wasm" },
        });
      }) as unknown as typeof fetch);

    await onPage("capacitor://localhost/index.html", async () => {
      const tampered = serveFromScheme(tamperedWasm());
      try {
        const { setWasmSourceUrl, wasmLoader } = await freshLoader();
        setWasmSourceUrl(CAPACITOR_WASM);
        await expect(wasmLoader(memory())).rejects.toThrow(
          "failed its SHA-384 integrity check",
        );
        expect(tampered).toHaveBeenCalledTimes(1);
      } finally {
        tampered.mockRestore();
      }

      // Control: the pinned bytes from the same source load.
      const pinned = serveFromScheme(PINNED_WASM);
      try {
        const { setWasmSourceUrl, wasmLoader } = await freshLoader();
        setWasmSourceUrl(CAPACITOR_WASM);
        const module = await wasmLoader(memory());
        expect(typeof module._malloc).toBe("function");
        expect(pinned).toHaveBeenCalledTimes(1);
      } finally {
        pinned.mockRestore();
      }
    });
  });
});
