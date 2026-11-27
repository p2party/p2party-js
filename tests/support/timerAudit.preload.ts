import { plugin } from "bun";
import { afterAll } from "bun:test";
import { relative } from "node:path";

// The next test file is loaded after the previous file's own afterAll hooks.
// Keep the first failure with its allocation site even if the timer fires later.
type TimerHandle = ReturnType<typeof setTimeout>;
interface TrackedTimer {
  file: string;
  stack: string;
}
const pending = new Map<object, TrackedTimer>();
const failures: string[] = [];
let file = "";
const realTimeout = globalThis.setTimeout;
const realInterval = globalThis.setInterval;
const clearTimeoutOriginal = globalThis.clearTimeout;
const clearIntervalOriginal = globalThis.clearInterval;
function track(handle: TimerHandle): void {
  const record = {
    file,
    stack: (new Error().stack ?? "")
      .split("\n")
      .slice(1)
      .filter((line) => !line.includes("timerAudit.preload"))
      .slice(0, 5)
      .join("\n"),
  };
  pending.set(handle, record);
  const originalClose = handle.close;
  handle.close = function () {
    pending.delete(handle);
    return originalClose.call(this);
  };
  const originalRefresh = handle.refresh;
  handle.refresh = function () {
    pending.set(handle, record);
    return originalRefresh.call(this);
  };
  const dispose = handle[Symbol.dispose];
  if (dispose)
    handle[Symbol.dispose] = function () {
      pending.delete(handle);
      dispose.call(this);
    };
}
function forget(handle: unknown): void {
  if (typeof handle === "number" || typeof handle === "string") {
    for (const timer of pending.keys()) {
      if (Number(timer) === Number(handle)) {
        pending.delete(timer);
        break;
      }
    }
  } else if (typeof handle === "object" && handle) pending.delete(handle);
}
globalThis.setTimeout = function (
  callback: (...args: unknown[]) => void,
  ms?: number,
  ...args: unknown[]
) {
  const timer = realTimeout(function (this: unknown) {
    pending.delete(timer);
    callback.apply(this, args);
  }, ms);
  track(timer);
  return timer;
} as typeof setTimeout;
globalThis.setInterval = function (
  callback: (...args: unknown[]) => void,
  ms?: number,
  ...args: unknown[]
) {
  const timer = realInterval(callback, ms, ...args);
  track(timer);
  return timer;
} as typeof setInterval;
globalThis.clearTimeout = function (handle) {
  forget(handle);
  Reflect.apply(clearTimeoutOriginal, globalThis, [handle]);
} as typeof clearTimeout;
globalThis.clearInterval = function (handle) {
  forget(handle);
  Reflect.apply(clearIntervalOriginal, globalThis, [handle]);
} as typeof clearInterval;
function finishFile(): void {
  for (const timer of pending.values()) {
    failures.push(
      `${relative(process.cwd(), timer.file) || "(preload)"} left a timer pending\n${timer.stack}`,
    );
  }
  pending.clear();
}
plugin({
  name: "test-file-timer-audit",
  setup(build) {
    build.onLoad({ filter: /\.(?:test|spec)\.[cm]?[jt]sx?$/ }, async (args) => {
      if (file) finishFile();
      file = args.path;
      const extension = args.path.split(".").pop() ?? "js";
      const loader = extension.endsWith("tsx")
        ? "tsx"
        : extension.endsWith("jsx")
          ? "jsx"
          : extension.endsWith("ts")
            ? "ts"
            : "js";
      return { contents: await Bun.file(args.path).text(), loader };
    });
  },
});
afterAll(() => {
  finishFile();
  if (failures.length)
    throw new Error(failures.join("\n\n").replaceAll(process.cwd() + "/", ""));
});
